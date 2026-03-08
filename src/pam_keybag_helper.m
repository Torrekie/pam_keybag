/*
 * Thin helper for pam_keybag.
 *
 * All major logic lives in pam_keybag.so exports:
 * - pam_keybag_core_mkb_authenticate_bytes
 * - pam_keybag_core_ui_authenticate
 *
 * This helper only parses args/stdin and dispatches via dlopen/dlsym.
 */

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pam_keybag_core.h"

#ifndef PAM_KEYBAG_ROOT_PREFIX
#define PAM_KEYBAG_ROOT_PREFIX ""
#endif

#define MODULE_DEFAULT_PATH PAM_KEYBAG_ROOT_PREFIX "/usr/lib/pam/pam_keybag.2.so"
#define DEFAULT_REASON "Authenticate to continue"
#define MAX_PASSCODE_LENGTH 1024

enum helper_mode {
    HELPER_MODE_UI = 0,
    HELPER_MODE_VERIFY,
    HELPER_MODE_UNLOCK,
};

typedef int (*core_mkb_auth_fn)(const uint8_t *passcode,
    size_t passcode_len, int unlock_springboard, int *mkb_status_out);
typedef int (*core_ui_auth_fn)(const char *reason, const char *caller_name,
    const char *caller_icon_bundle, int caller_pid, int policy);

static void
secure_memzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    if (p == NULL) {
        return;
    }
    while (len-- > 0) {
        *p++ = 0;
    }
}

static void
print_usage(const char *progname)
{
    /* This really shouldn't be provided */
    fprintf(stderr,
        "usage: %s [--mode ui|verify|unlock] [--module path] [--reason text] [--policy number] "
        "[--caller-name text] [--caller-icon-bundle path] [--caller-pid number]\n",
        progname);
    fprintf(stderr,
        "       verify/unlock mode reads passcode bytes from stdin\n");
}

static bool
parse_integer(const char *text, int *out_value)
{
    char *end = NULL;
    long long value = 0;

    if (text == NULL || out_value == NULL) {
        return false;
    }

    value = strtoll(text, &end, 0);
    if (end == text || *end != '\0' || value < INT_MIN || value > INT_MAX) {
        return false;
    }

    *out_value = (int)value;
    return true;
}

static bool
parse_mode(const char *text, enum helper_mode *out_mode)
{
    if (text == NULL || out_mode == NULL) {
        return false;
    }

    if (strcmp(text, "ui") == 0) {
        *out_mode = HELPER_MODE_UI;
        return true;
    }
    if (strcmp(text, "verify") == 0) {
        *out_mode = HELPER_MODE_VERIFY;
        return true;
    }
    if (strcmp(text, "unlock") == 0) {
        *out_mode = HELPER_MODE_UNLOCK;
        return true;
    }

    return false;
}

static int
read_stdin_all(uint8_t **out_buf, size_t *out_len)
{
    uint8_t *buf = NULL;
    size_t cap = 0;
    size_t len = 0;

    if (out_buf == NULL || out_len == NULL) {
        return PAM_KEYBAG_CORE_USAGE;
    }

    *out_buf = NULL;
    *out_len = 0;

    for (;;) {
        uint8_t tmp[256];
        ssize_t n = read(STDIN_FILENO, tmp, sizeof(tmp));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(buf);
            return PAM_KEYBAG_CORE_FAILURE;
        }
        if (n == 0) {
            break;
        }

        if (len + (size_t)n > MAX_PASSCODE_LENGTH) {
            if (buf != NULL) {
                secure_memzero(buf, len);
                free(buf);
            }
            return PAM_KEYBAG_CORE_FAILURE;
        }

        if (len + (size_t)n > cap) {
            size_t new_cap = cap == 0 ? 256 : cap;
            while (new_cap < len + (size_t)n) {
                new_cap *= 2;
            }

            uint8_t *new_buf = realloc(buf, new_cap);
            if (new_buf == NULL) {
                if (buf != NULL) {
                    secure_memzero(buf, len);
                    free(buf);
                }
                return PAM_KEYBAG_CORE_FAILURE;
            }
            buf = new_buf;
            cap = new_cap;
        }

        memcpy(buf + len, tmp, (size_t)n);
        len += (size_t)n;
    }

    if (len == 0) {
        buf = calloc(1, 1);
        if (buf == NULL) {
            return PAM_KEYBAG_CORE_FAILURE;
        }
    }

    *out_buf = buf;
    *out_len = len;
    return PAM_KEYBAG_CORE_SUCCESS;
}

static const char *
resolve_module_path(const char *module_path)
{
    if (module_path != NULL && module_path[0] != '\0') {
        return module_path;
    }

    return MODULE_DEFAULT_PATH;
}

static int
run_mkb_mode(const char *module_path, int unlock)
{
    const char *resolved_path = NULL;
    void *module_handle = NULL;
    core_mkb_auth_fn core_mkb_auth = NULL;
    uint8_t *passcode = NULL;
    size_t passcode_len = 0;
    int mkb_status = -1;
    int rc = PAM_KEYBAG_CORE_FAILURE;

    rc = read_stdin_all(&passcode, &passcode_len);
    if (rc != PAM_KEYBAG_CORE_SUCCESS) {
        return rc;
    }

    resolved_path = resolve_module_path(module_path);
    module_handle = dlopen(resolved_path, RTLD_NOW | RTLD_LOCAL);
    if (module_handle == NULL) {
        rc = PAM_KEYBAG_CORE_UNAVAILABLE;
        goto out;
    }

    core_mkb_auth = (core_mkb_auth_fn)dlsym(module_handle,
        "pam_keybag_core_mkb_authenticate_bytes");
    if (core_mkb_auth == NULL) {
        rc = PAM_KEYBAG_CORE_UNAVAILABLE;
        goto out;
    }

    rc = core_mkb_auth(passcode, passcode_len, unlock, &mkb_status);

out:
    if (module_handle != NULL) {
        dlclose(module_handle);
    }
    if (passcode != NULL) {
        secure_memzero(passcode, passcode_len == 0 ? 1 : passcode_len);
        free(passcode);
    }

    return rc;
}

static int
run_ui_mode(const char *module_path, const char *reason,
    const char *caller_name, const char *caller_icon_bundle,
    int caller_pid, int policy)
{
    const char *resolved_path = NULL;
    void *module_handle = NULL;
    core_ui_auth_fn core_ui_auth = NULL;

    resolved_path = resolve_module_path(module_path);
    module_handle = dlopen(resolved_path, RTLD_NOW | RTLD_LOCAL);
    if (module_handle == NULL) {
        return PAM_KEYBAG_CORE_UNAVAILABLE;
    }

    core_ui_auth = (core_ui_auth_fn)dlsym(module_handle,
        "pam_keybag_core_ui_authenticate");
    if (core_ui_auth == NULL) {
        dlclose(module_handle);
        return PAM_KEYBAG_CORE_UNAVAILABLE;
    }

    int rc = core_ui_auth(reason, caller_name, caller_icon_bundle,
        caller_pid, policy);
    dlclose(module_handle);
    return rc;
}

int
main(int argc, const char *argv[])
{
    @autoreleasepool {
        const char *reason = DEFAULT_REASON;
        const char *module_path = NULL;
        const char *caller_name = NULL;
        const char *caller_icon_bundle = NULL;
        int policy = PAM_KEYBAG_CORE_DEFAULT_POLICY;
        int caller_pid = (int)getppid();
        enum helper_mode mode = HELPER_MODE_UI;
        int i = 0;

        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--mode") == 0) {
                i++;
                if (i >= argc || !parse_mode(argv[i], &mode)) {
                    print_usage(argv[0]);
                    return PAM_KEYBAG_CORE_USAGE;
                }
                continue;
            }

            if (strcmp(argv[i], "--module") == 0) {
                i++;
                if (i >= argc) {
                    print_usage(argv[0]);
                    return PAM_KEYBAG_CORE_USAGE;
                }
                module_path = argv[i];
                continue;
            }

            if (strcmp(argv[i], "--reason") == 0) {
                i++;
                if (i >= argc) {
                    print_usage(argv[0]);
                    return PAM_KEYBAG_CORE_USAGE;
                }
                reason = argv[i];
                if (reason[0] == '\0') {
                    reason = DEFAULT_REASON;
                }
                continue;
            }

            if (strcmp(argv[i], "--policy") == 0) {
                i++;
                if (i >= argc || !parse_integer(argv[i], &policy)) {
                    print_usage(argv[0]);
                    return PAM_KEYBAG_CORE_USAGE;
                }
                continue;
            }

            if (strcmp(argv[i], "--caller-name") == 0) {
                i++;
                if (i >= argc) {
                    print_usage(argv[0]);
                    return PAM_KEYBAG_CORE_USAGE;
                }
                caller_name = argv[i];
                continue;
            }

            if (strcmp(argv[i], "--caller-icon-bundle") == 0) {
                i++;
                if (i >= argc) {
                    print_usage(argv[0]);
                    return PAM_KEYBAG_CORE_USAGE;
                }
                caller_icon_bundle = argv[i];
                continue;
            }

            if (strcmp(argv[i], "--caller-pid") == 0) {
                i++;
                if (i >= argc || !parse_integer(argv[i], &caller_pid)) {
                    print_usage(argv[0]);
                    return PAM_KEYBAG_CORE_USAGE;
                }
                continue;
            }

            if (strcmp(argv[i], "--help") == 0) {
                print_usage(argv[0]);
                return 0;
            }

            print_usage(argv[0]);
            return PAM_KEYBAG_CORE_USAGE;
        }

        if (mode == HELPER_MODE_VERIFY || mode == HELPER_MODE_UNLOCK) {
            return run_mkb_mode(module_path, mode == HELPER_MODE_UNLOCK ? 1 : 0);
        }

        return run_ui_mode(module_path, reason, caller_name,
            caller_icon_bundle, caller_pid, policy);
    }
}
