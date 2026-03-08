#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pam_keybag_core.h"

#define MKB_FRAMEWORK_PATH "/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag"
#define MKB_UNLOCK_SYMBOL "MKBUnlockDevice"
#define MKB_VERIFY_SYMBOL "MKBVerifyPasswordWithContext"
#define MKB_MAX_PASSCODE_LENGTH 1024
#define DEVICE_OWNER_AUTH_POLICY 2

typedef int (*mkb_unlock_device_fn)(const void *passcode, const void *options);
typedef int (*mkb_verify_password_with_context_fn)(const void *options,
    const void *passcode, const void *context);

@interface LAContext (PAMKeybagPrivateSPI)
- (NSDictionary *)evaluatePolicy:(NSInteger)policy
                         options:(NSDictionary *)options
                           error:(NSError **)error;
- (void)evaluatePolicy:(NSInteger)policy
               options:(NSDictionary *)options
                 reply:(void (^)(NSDictionary *result, NSError *error))reply;
- (void)setOptionCallerName:(NSString *)callerName;
- (void)setOptionCallerIconBundlePath:(NSString *)bundlePath;
- (void)setOptionCallerPID:(NSNumber *)pid;
- (void)setOptionAuthenticationReason:(NSString *)reason;
@end

static NSString *
string_or_nil(const char *text)
{
    NSString *str = nil;

    if (text == NULL || text[0] == '\0') {
        return nil;
    }

    str = [NSString stringWithUTF8String:text];
    if (str != nil && str.length == 0) {
        return nil;
    }

    return str;
}

static void
apply_private_options(LAContext *context, NSString *reason,
    NSString *caller_name, NSString *caller_icon_bundle, int caller_pid)
{
    if (context == nil) {
        return;
    }

    if (reason != nil && reason.length > 0 &&
        [context respondsToSelector:@selector(setOptionAuthenticationReason:)]) {
        [context setOptionAuthenticationReason:reason];
    }

    if (caller_name != nil && caller_name.length > 0 &&
        [context respondsToSelector:@selector(setOptionCallerName:)]) {
        [context setOptionCallerName:caller_name];
    }

    if (caller_icon_bundle != nil && caller_icon_bundle.length > 0 &&
        [context respondsToSelector:@selector(setOptionCallerIconBundlePath:)]) {
        [context setOptionCallerIconBundlePath:caller_icon_bundle];
    }

    if (caller_pid > 0 &&
        [context respondsToSelector:@selector(setOptionCallerPID:)]) {
        [context setOptionCallerPID:@(caller_pid)];
    }
}

static BOOL
evaluate_with_spi_async(LAContext *context, NSInteger policy, NSError **error_out)
{
    __block BOOL success = NO;
    __block NSError *local_error = nil;
    dispatch_semaphore_t done = NULL;
    SEL selector = @selector(evaluatePolicy:options:reply:);

    if (context == nil || ![context respondsToSelector:selector]) {
        return NO;
    }

    done = dispatch_semaphore_create(0);
    [context evaluatePolicy:policy options:nil reply:^(NSDictionary *result, NSError *error) {
        success = (result != nil && error == nil);
        local_error = error;
        dispatch_semaphore_signal(done);
    }];

    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);

    if (error_out != NULL) {
        *error_out = local_error;
    }
    return success;
}

static BOOL
evaluate_with_spi_sync(LAContext *context, NSInteger policy, NSError **error_out)
{
    NSDictionary *result = nil;
    NSError *error = nil;
    SEL selector = @selector(evaluatePolicy:options:error:);

    if (context == nil || ![context respondsToSelector:selector]) {
        return NO;
    }

    result = [context evaluatePolicy:policy options:nil error:&error];
    if (error_out != NULL) {
        *error_out = error;
    }
    return (result != nil && error == nil);
}

static BOOL
evaluate_with_public_api(LAContext *context, NSInteger policy, NSString *reason,
    NSError **error_out)
{
    __block BOOL success = NO;
    __block NSError *local_error = nil;
    dispatch_semaphore_t done = NULL;

    if (context == nil) {
        return NO;
    }

    done = dispatch_semaphore_create(0);
    [context evaluatePolicy:(LAPolicy)policy localizedReason:reason reply:^(BOOL ok, NSError *error) {
        success = ok;
        local_error = error;
        dispatch_semaphore_signal(done);
    }];

    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);

    if (error_out != NULL) {
        *error_out = local_error;
    }
    return success;
}

PAM_KEYBAG_EXPORT int
pam_keybag_core_mkb_authenticate_bytes(const uint8_t *passcode,
    size_t passcode_len, int unlock_springboard, int *mkb_status_out)
{
    void *mkb_handle = NULL;
    mkb_unlock_device_fn mkb_unlock = NULL;
    mkb_verify_password_with_context_fn mkb_verify = NULL;
    NSData *passcode_data = nil;
    int mkb_status = -1;

    if (mkb_status_out != NULL) {
        *mkb_status_out = -1;
    }

    if (passcode == NULL || passcode_len > MKB_MAX_PASSCODE_LENGTH) {
        return PAM_KEYBAG_CORE_USAGE;
    }

    passcode_data = [NSData dataWithBytes:passcode length:passcode_len];
    if (passcode_data == nil) {
        return PAM_KEYBAG_CORE_FAILURE;
    }

    mkb_handle = dlopen(MKB_FRAMEWORK_PATH, RTLD_NOW | RTLD_LOCAL);
    if (mkb_handle == NULL) {
        return PAM_KEYBAG_CORE_UNAVAILABLE;
    }

    if (unlock_springboard != 0) {
        mkb_unlock = (mkb_unlock_device_fn)dlsym(mkb_handle, MKB_UNLOCK_SYMBOL);
        if (mkb_unlock == NULL) {
            dlclose(mkb_handle);
            return PAM_KEYBAG_CORE_UNAVAILABLE;
        }
        mkb_status = mkb_unlock((__bridge const void *)passcode_data, NULL);
    } else {
        mkb_verify = (mkb_verify_password_with_context_fn)dlsym(mkb_handle,
            MKB_VERIFY_SYMBOL);
        if (mkb_verify == NULL) {
            dlclose(mkb_handle);
            return PAM_KEYBAG_CORE_UNAVAILABLE;
        }
        mkb_status = mkb_verify(NULL, (__bridge const void *)passcode_data, NULL);
    }

    dlclose(mkb_handle);

    if (mkb_status_out != NULL) {
        *mkb_status_out = mkb_status;
    }

    return (mkb_status == 0)
        ? PAM_KEYBAG_CORE_SUCCESS
        : PAM_KEYBAG_CORE_FAILURE;
}

PAM_KEYBAG_EXPORT int
pam_keybag_core_ui_authenticate(const char *reason, const char *caller_name,
    const char *caller_icon_bundle, int caller_pid, int policy)
{
    @autoreleasepool {
        NSString *reason_ns = nil;
        NSString *caller_name_ns = nil;
        NSString *caller_icon_ns = nil;
        NSInteger policy_id = PAM_KEYBAG_CORE_DEFAULT_POLICY;
        LAContext *context = nil;
        NSError *error = nil;
        BOOL ok = NO;

        reason_ns = string_or_nil(reason);
        if (reason_ns == nil) {
            reason_ns = @"Authenticate to continue";
        }
        caller_name_ns = string_or_nil(caller_name);
        caller_icon_ns = string_or_nil(caller_icon_bundle);
        if (policy > 0) {
            policy_id = (NSInteger)policy;
        }

        context = [[LAContext alloc] init];
        if (context == nil) {
            return PAM_KEYBAG_CORE_UNAVAILABLE;
        }

        apply_private_options(context, reason_ns, caller_name_ns, caller_icon_ns,
            caller_pid);

        ok = evaluate_with_spi_async(context, policy_id, &error);
        if (!ok) {
            ok = evaluate_with_spi_sync(context, policy_id, &error);
        }

        if (!ok && policy_id != DEVICE_OWNER_AUTH_POLICY) {
            ok = evaluate_with_spi_async(context, DEVICE_OWNER_AUTH_POLICY, &error);
            if (!ok) {
                ok = evaluate_with_spi_sync(context, DEVICE_OWNER_AUTH_POLICY, &error);
            }
        }

        if (!ok) {
            ok = evaluate_with_public_api(context, DEVICE_OWNER_AUTH_POLICY,
                reason_ns, &error);
        }

        if (!ok && error != nil) {
            fprintf(stderr, "pam_keybag_core_ui: %s (%ld)\n",
                error.localizedDescription.UTF8String,
                (long)error.code);
        }

        return ok ? PAM_KEYBAG_CORE_SUCCESS : PAM_KEYBAG_CORE_FAILURE;
    }
}
