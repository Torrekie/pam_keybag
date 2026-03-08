pam_keybag
===============

Validates the PAM authentication token against MobileKeyBag.

This module allows you to use your iOS password with PAM.

Supported options
-----------------

- `user=name1,name2,...`
  Comma-separated allowlist. Defaults to `mobile` if omitted.
- `prompt=text`
  Custom terminal prompt (default: `Mobile passcode: `).
- `use_first_pass`
  Require pre-existing `PAM_AUTHTOK` from an earlier PAM module.
  If missing or invalid, fail without prompting.
- `try_first_pass`
  Try pre-existing `PAM_AUTHTOK` first.
  If missing or invalid, fall back to interactive prompt.
- `nullok`
  Allow empty token to be passed to MobileKeyBag verify/unlock path.
- `nullok_secure`
  Like `nullok`, but only for local requests (ignored for remote requests).
- `unlock_springboard`
  Use `MKBUnlockDevice` instead of verify-only API, which also unlocks the device.
- `direct_mode`
  Disable helper usage and call APIs directly from `pam_keybag.so`.
  This requires the PAM client process itself to have the required entitlements.
- `allow_remote`
  Allow remote PAM requests (for example ssh). Remote is denied by default.
- `prefer_ui_prompt`
  Start LocalAuthentication UI prompt in parallel with terminal prompt.
- `ui_reason=text`
  Reason string passed to UI prompt.
  If omitted, default is a ps-like line with PID and full command line.

Building
--------

Build with `bmake`:

    bmake
    bmake sign
    bmake install

Build for rootless (`/var/jb` prefix):

    bmake ROOTLESS=1
    bmake ROOTLESS=1 sign
    bmake ROOTLESS=1 install
