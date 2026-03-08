#ifndef PAM_KEYBAG_CORE_H
#define PAM_KEYBAG_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PAM_KEYBAG_CORE_SUCCESS 0
#define PAM_KEYBAG_CORE_FAILURE 1
#define PAM_KEYBAG_CORE_USAGE 2
#define PAM_KEYBAG_CORE_UNAVAILABLE 3


#define PAM_KEYBAG_CORE_POLICY_TRUST_COMPUTER	1007
/* Use "Trust Computer" for now, before we find better one */
#define PAM_KEYBAG_CORE_DEFAULT_POLICY		PAM_KEYBAG_CORE_POLICY_TRUST_COMPUTER

#if defined(__GNUC__)
#define PAM_KEYBAG_EXPORT __attribute__((visibility("default")))
#else
#define PAM_KEYBAG_EXPORT
#endif

PAM_KEYBAG_EXPORT int
pam_keybag_core_mkb_authenticate_bytes(const uint8_t *passcode,
    size_t passcode_len, int unlock_springboard, int *mkb_status_out);

PAM_KEYBAG_EXPORT int
pam_keybag_core_ui_authenticate(const char *reason, const char *caller_name,
    const char *caller_icon_bundle, int caller_pid, int policy);

#ifdef __cplusplus
}
#endif

#endif /* PAM_KEYBAG_CORE_H */
