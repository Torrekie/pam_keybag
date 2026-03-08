#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <libproc.h>
#endif

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "Logging.h"
#include "pam_keybag_core.h"

#ifdef PAM_USE_OS_LOG
PAM_DEFINE_LOG(keybag)
#define PAM_LOG PAM_LOG_keybag()
#endif

extern char **environ;

#define MODULE_NAME		"pam_keybag"
#define PAM_OPT_USE_FIRST_PASS	"use_first_pass"
#define PAM_OPT_TRY_FIRST_PASS	"try_first_pass"
#define PAM_OPT_NULLOK		"nullok"
#define PAM_OPT_NULLOK_SECURE	"nullok_secure"
#define PAM_OPT_DIRECT_MODE	"direct_mode"
#define DEFAULT_ALLOWED_USERS	"mobile"
#define DEFAULT_PROMPT		"Mobile passcode: "
#define MAX_PASSCODE_LENGTH	1024

#ifndef PAM_KEYBAG_ROOT_PREFIX
#define PAM_KEYBAG_ROOT_PREFIX ""
#endif

#define UI_HELPER_DEFAULT_PATH	PAM_KEYBAG_ROOT_PREFIX "/usr/libexec/pam_keybag_helper"
#define MODULE_DEFAULT_PATH	PAM_KEYBAG_ROOT_PREFIX "/usr/lib/pam/pam_keybag.2.so"
#define UI_HELPER_FALLBACK_REASON "Authenticate to continue"
#define UI_REASON_MAX		1024
#define UI_CALLER_NAME_MAX	256

#define UI_CALLER_ICON_BUNDLE_MAX 1024

#define HELPER_ARG_MODE		"--mode"
#define HELPER_ARG_MODULE	"--module"
#define HELPER_MODE_UI		"ui"
#define HELPER_MODE_VERIFY	"verify"
#define HELPER_MODE_UNLOCK	"unlock"
#define HELPER_EXIT_SUCCESS	0
#define HELPER_EXIT_UNAVAILABLE	3

enum tty_passcode_result {
    TTY_PASSCODE_ERROR = -1,
    TTY_PASSCODE_INPUT = 0,
    TTY_PASSCODE_UI_SUCCESS = 1,
};

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

static bool
user_in_csv_list(const char *csv, const char *user)
{
    char *copy = NULL;
    char *cursor = NULL;
    char *token = NULL;
    bool matched = false;
    size_t user_len = 0;

    if (csv == NULL || user == NULL) {
        return false;
    }

    user_len = strlen(user);
    copy = strdup(csv);
    if (copy == NULL) {
        return false;
    }

    cursor = copy;
    while ((token = strsep(&cursor, ",")) != NULL) {
        char *start = token;
        char *end = NULL;

        while (*start != '\0' && isspace((unsigned char)*start)) {
            start++;
        }

        end = start + strlen(start);
        while (end > start && isspace((unsigned char)end[-1])) {
            end--;
        }
        *end = '\0';

        if (start[0] == '\0') {
            continue;
        }
        if (strlen(start) == user_len && strcmp(start, user) == 0) {
            matched = true;
            break;
        }
    }

    free(copy);
    return matched;
}

static int
user_is_allowed(pam_handle_t *pamh, const char *user)
{
    const char *allowed_users = NULL;

    allowed_users = openpam_get_option(pamh, "user");
    if (allowed_users == NULL || allowed_users[0] == '\0') {
        allowed_users = DEFAULT_ALLOWED_USERS;
    }

    if (!user_in_csv_list(allowed_users, user)) {
        _LOG_DEFAULT(MODULE_NAME ": refusing user '%s' (allowed='%s')",
            user, allowed_users);
        return PAM_USER_UNKNOWN;
    }

    return PAM_SUCCESS;
}

static bool
request_is_remote(pam_handle_t *pamh)
{
    const void *item = NULL;
    const char *rhost = NULL;
#ifdef PAM_TTY
    const char *tty = NULL;
#endif

    if (pam_get_item(pamh, PAM_RHOST, &item) == PAM_SUCCESS && item != NULL) {
        rhost = (const char *)item;
        if (rhost[0] != '\0') {
            return true;
        }
    }

#ifdef PAM_TTY
    item = NULL;
    if (pam_get_item(pamh, PAM_TTY, &item) == PAM_SUCCESS && item != NULL) {
        tty = (const char *)item;
        if (strstr(tty, "ssh") != NULL) {
            return true;
        }
    }
#endif

    return false;
}

static bool
is_empty_passcode_allowed(pam_handle_t *pamh, int flags, bool is_remote_request)
{
    if ((flags & PAM_DISALLOW_NULL_AUTHTOK) != 0) {
        return false;
    }
    if (openpam_get_option(pamh, PAM_OPT_NULLOK) != NULL) {
        return true;
    }
    if (!is_remote_request &&
        openpam_get_option(pamh, PAM_OPT_NULLOK_SECURE) != NULL) {
        return true;
    }

    return false;
}

static int
write_all(int fd, const uint8_t *data, size_t len)
{
    size_t written = 0;

    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        written += (size_t)n;
    }

    return 0;
}

static const char *
get_helper_path(pam_handle_t *pamh)
{
    const char *helper_path = NULL;

    helper_path = openpam_get_option(pamh, "ui_helper");
    if (helper_path == NULL || helper_path[0] == '\0') {
        helper_path = UI_HELPER_DEFAULT_PATH;
    }

    return helper_path;
}

static const char *
get_module_path(pam_handle_t *pamh)
{
    const char *module_path = NULL;

    module_path = openpam_get_option(pamh, "module_path");
    if (module_path == NULL || module_path[0] == '\0') {
        module_path = MODULE_DEFAULT_PATH;
    }

    return module_path;
}

static int
mkb_authenticate_passcode_direct(const char *passcode, bool unlock_springboard,
    bool allow_empty_passcode, int *mkb_status_out)
{
    size_t passcode_len = 0;
    int rc = PAM_KEYBAG_CORE_FAILURE;

    if (passcode == NULL) {
        return PAM_AUTH_ERR;
    }

    passcode_len = strnlen(passcode, MAX_PASSCODE_LENGTH + 1);
    if (passcode_len > MAX_PASSCODE_LENGTH) {
        return PAM_AUTH_ERR;
    }
    if (passcode_len == 0 && !allow_empty_passcode) {
        return PAM_AUTH_ERR;
    }

    rc = pam_keybag_core_mkb_authenticate_bytes((const uint8_t *)passcode,
        passcode_len, unlock_springboard ? 1 : 0, mkb_status_out);
    if (rc == PAM_KEYBAG_CORE_SUCCESS) {
        return PAM_SUCCESS;
    }
    if (rc == PAM_KEYBAG_CORE_UNAVAILABLE) {
        return PAM_IGNORE;
    }
    if (rc == PAM_KEYBAG_CORE_USAGE) {
        return PAM_AUTH_ERR;
    }

    return PAM_AUTH_ERR;
}

static int
mkb_authenticate_passcode_with_helper(pam_handle_t *pamh, const char *passcode,
    bool unlock_springboard, bool allow_empty_passcode, int *mkb_status_out)
{
    size_t passcode_len = 0;
    int pipefd[2] = { -1, -1 };
    int status = 0;
    int helper_exit = -1;
    int spawn_rc = 0;
    int action_rc = 0;
    pid_t pid = -1;
    const char *helper_path = NULL;
    const char *module_path = NULL;
    posix_spawn_file_actions_t file_actions;
    char *helper_argv[] = {
        NULL,
        (char *)HELPER_ARG_MODE,
        (char *)(unlock_springboard ? HELPER_MODE_UNLOCK : HELPER_MODE_VERIFY),
        (char *)HELPER_ARG_MODULE,
        NULL,
        NULL
    };

    if (passcode == NULL) {
        return PAM_AUTH_ERR;
    }

    passcode_len = strnlen(passcode, MAX_PASSCODE_LENGTH + 1);
    if (passcode_len > MAX_PASSCODE_LENGTH) {
        return PAM_AUTH_ERR;
    }
    if (passcode_len == 0 && !allow_empty_passcode) {
        return PAM_AUTH_ERR;
    }

    if (mkb_status_out != NULL) {
        *mkb_status_out = -1;
    }

    helper_path = get_helper_path(pamh);
    module_path = get_module_path(pamh);
    if (pipe(pipefd) != 0) {
        _LOG_ERROR(MODULE_NAME ": pipe() failed for helper: %s", strerror(errno));
        return PAM_AUTHINFO_UNAVAIL;
    }

    action_rc = posix_spawn_file_actions_init(&file_actions);
    if (action_rc != 0) {
        _LOG_ERROR(MODULE_NAME ": posix_spawn_file_actions_init() failed: %s",
            strerror(action_rc));
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return PAM_AUTHINFO_UNAVAIL;
    }
    action_rc = posix_spawn_file_actions_adddup2(&file_actions, pipefd[0], STDIN_FILENO);
    if (action_rc == 0) {
        action_rc = posix_spawn_file_actions_addclose(&file_actions, pipefd[0]);
    }
    if (action_rc == 0) {
        action_rc = posix_spawn_file_actions_addclose(&file_actions, pipefd[1]);
    }
    if (action_rc != 0) {
        _LOG_ERROR(MODULE_NAME ": posix_spawn_file_actions setup failed: %s",
            strerror(action_rc));
        (void)posix_spawn_file_actions_destroy(&file_actions);
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return PAM_AUTHINFO_UNAVAIL;
    }

    helper_argv[0] = (char *)helper_path;
    helper_argv[4] = (char *)module_path;
    spawn_rc = posix_spawn(&pid, helper_path, &file_actions, NULL, helper_argv, environ);
    (void)posix_spawn_file_actions_destroy(&file_actions);
    if (spawn_rc != 0) {
        _LOG_ERROR(MODULE_NAME ": posix_spawn(%s) failed: %s",
            helper_path, strerror(spawn_rc));
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return PAM_IGNORE;
    }

    (void)close(pipefd[0]);
    if (passcode_len > 0 && write_all(pipefd[1], (const uint8_t *)passcode, passcode_len) != 0) {
        _LOG_ERROR(MODULE_NAME ": write() failed for helper stdin: %s",
            strerror(errno));
    }
    (void)close(pipefd[1]);
    pipefd[1] = -1;

    for (;;) {
        if (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            _LOG_ERROR(MODULE_NAME ": waitpid(%d) failed: %s",
                pid, strerror(errno));
            return PAM_AUTHINFO_UNAVAIL;
        }
        break;
    }

    if (!WIFEXITED(status)) {
        return PAM_AUTH_ERR;
    }

    helper_exit = WEXITSTATUS(status);
    if (mkb_status_out != NULL) {
        *mkb_status_out = helper_exit;
    }

    if (helper_exit == HELPER_EXIT_SUCCESS) {
        return PAM_SUCCESS;
    }
    if (helper_exit == HELPER_EXIT_UNAVAILABLE) {
        return PAM_IGNORE;
    }

    return PAM_AUTH_ERR;
}

static int
mkb_authenticate_passcode(pam_handle_t *pamh, const char *passcode, bool unlock_springboard,
    bool allow_empty_passcode, bool direct_mode, int *mkb_status_out)
{
    if (direct_mode) {
        return mkb_authenticate_passcode_direct(passcode, unlock_springboard,
            allow_empty_passcode, mkb_status_out);
    }

    return mkb_authenticate_passcode_with_helper(pamh, passcode, unlock_springboard,
        allow_empty_passcode, mkb_status_out);
}

static void
set_string_if_empty(char *dst, size_t dst_len, const char *src)
{
    if (dst == NULL || dst_len == 0 || src == NULL || src[0] == '\0') {
        return;
    }
    if (dst[0] != '\0') {
        return;
    }

    (void)strlcpy(dst, src, dst_len);
}

static int
get_process_cmdline(pid_t pid, char *dst, size_t dst_len)
{
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, 0 };
    char *procargs = NULL;
    char *cursor = NULL;
    char *end = NULL;
    size_t argmax = 0;
    size_t argmax_len = sizeof(argmax);
    size_t size = 0;
    size_t used = 0;
    int argc = 0;
    int argi = 0;

    if (dst == NULL || dst_len == 0 || pid <= 0) {
        return -1;
    }
    dst[0] = '\0';

    if (sysctlbyname("kern.argmax", &argmax, &argmax_len, NULL, 0) != 0 ||
        argmax <= sizeof(int)) {
        return -1;
    }

    procargs = calloc(1, argmax);
    if (procargs == NULL) {
        return -1;
    }

    mib[2] = (int)pid;
    size = argmax;
    if (sysctl(mib, 3, procargs, &size, NULL, 0) != 0 || size <= sizeof(int)) {
        free(procargs);
        return -1;
    }

    memcpy(&argc, procargs, sizeof(argc));
    if (argc <= 0) {
        free(procargs);
        return -1;
    }

    cursor = procargs + sizeof(int);
    end = procargs + size;

    while (cursor < end && *cursor != '\0') {
        cursor++;
    }
    while (cursor < end && *cursor == '\0') {
        cursor++;
    }

    for (argi = 0; argi < argc && cursor < end; argi++) {
        size_t max_len = (size_t)(end - cursor);
        size_t arg_len = strnlen(cursor, max_len);
        size_t j = 0;

        if (arg_len == 0) {
            cursor++;
            continue;
        }

        if (used > 0 && used + 1 < dst_len) {
            dst[used++] = ' ';
        }

        for (j = 0; j < arg_len && used + 1 < dst_len; j++) {
            unsigned char ch = (unsigned char)cursor[j];
            if (ch == '\n' || ch == '\r' || ch == '\t') {
                dst[used++] = ' ';
            } else if (isprint(ch)) {
                dst[used++] = (char)ch;
            } else {
                dst[used++] = '?';
            }
        }

        cursor += arg_len;
        while (cursor < end && *cursor == '\0') {
            cursor++;
        }
    }

    dst[used] = '\0';
    free(procargs);
    return used > 0 ? 0 : -1;
}

static void
build_default_ui_reason(char *dst, size_t dst_len)
{
    char cmdline[UI_REASON_MAX] = "";
    char proc_path[PROC_PIDPATHINFO_MAXSIZE];
    int proc_path_len = 0;
    pid_t pid = getpid();

    if (dst == NULL || dst_len == 0) {
        return;
    }
    dst[0] = '\0';

    if (get_process_cmdline(pid, cmdline, sizeof(cmdline)) != 0) {
        proc_path_len = proc_pidpath((int)pid, proc_path, sizeof(proc_path));
        if (proc_path_len > 0) {
            proc_path[(proc_path_len >= (int)sizeof(proc_path))
                ? ((int)sizeof(proc_path) - 1) : proc_path_len] = '\0';
            (void)strlcpy(cmdline, proc_path, sizeof(cmdline));
        } else {
            (void)strlcpy(cmdline, "process", sizeof(cmdline));
        }
    }

    (void)snprintf(dst, dst_len, "%ld %s", (long)pid, cmdline);
}

static const char *
resolve_ui_reason(pam_handle_t *pamh, char *default_reason, size_t default_reason_len)
{
    const char *reason = NULL;

    reason = openpam_get_option(pamh, "ui_reason");
    if (reason != NULL && reason[0] != '\0') {
        return reason;
    }

    if (default_reason != NULL && default_reason_len > 0) {
        build_default_ui_reason(default_reason, default_reason_len);
        if (default_reason[0] != '\0') {
            return default_reason;
        }
    }

    return UI_HELPER_FALLBACK_REASON;
}

static void
derive_caller_metadata(pam_handle_t *pamh, char *caller_name, size_t caller_name_len,
    char *caller_icon_bundle, size_t caller_icon_bundle_len)
{
    char proc_path[PROC_PIDPATHINFO_MAXSIZE];
    int proc_path_len = 0;
    const char *service = NULL;

    if (caller_name != NULL && caller_name_len > 0) {
        caller_name[0] = '\0';
    }
    if (caller_icon_bundle != NULL && caller_icon_bundle_len > 0) {
        caller_icon_bundle[0] = '\0';
    }

    proc_path_len = proc_pidpath(getpid(), proc_path, sizeof(proc_path));
    if (proc_path_len > 0) {
        const char *base = NULL;
        const char *app_marker = NULL;

        proc_path[(proc_path_len >= (int)sizeof(proc_path))
            ? ((int)sizeof(proc_path) - 1) : proc_path_len] = '\0';

        base = strrchr(proc_path, '/');
        set_string_if_empty(caller_name, caller_name_len,
            (base != NULL && base[1] != '\0') ? base + 1 : proc_path);

        app_marker = strstr(proc_path, ".app/");
        if (app_marker != NULL && caller_icon_bundle != NULL && caller_icon_bundle_len > 0) {
            size_t bundle_len = (size_t)(app_marker - proc_path) + strlen(".app");
            if (bundle_len < caller_icon_bundle_len) {
                memcpy(caller_icon_bundle, proc_path, bundle_len);
                caller_icon_bundle[bundle_len] = '\0';
            }
        }
    }

    if (pamh != NULL &&
        pam_get_item(pamh, PAM_SERVICE, (const void **)&service) == PAM_SUCCESS &&
        service != NULL) {
        set_string_if_empty(caller_name, caller_name_len, service);
    }
}

static int
ui_authenticate_direct(pam_handle_t *pamh)
{
    const char *reason = NULL;
    char default_reason[UI_REASON_MAX];
    char caller_name[UI_CALLER_NAME_MAX];
    char caller_icon_bundle[UI_CALLER_ICON_BUNDLE_MAX];
    int rc = PAM_KEYBAG_CORE_FAILURE;

    reason = resolve_ui_reason(pamh, default_reason, sizeof(default_reason));

    caller_name[0] = '\0';
    caller_icon_bundle[0] = '\0';
    derive_caller_metadata(pamh, caller_name, sizeof(caller_name),
        caller_icon_bundle, sizeof(caller_icon_bundle));

    rc = pam_keybag_core_ui_authenticate(reason,
        caller_name[0] != '\0' ? caller_name : NULL,
        caller_icon_bundle[0] != '\0' ? caller_icon_bundle : NULL,
        (int)getpid(),
        PAM_KEYBAG_CORE_DEFAULT_POLICY);
    if (rc == PAM_KEYBAG_CORE_SUCCESS) {
        return PAM_SUCCESS;
    }
    if (rc == PAM_KEYBAG_CORE_UNAVAILABLE) {
        return PAM_IGNORE;
    }

    return PAM_AUTH_ERR;
}

static pid_t
spawn_ui_prompt_helper(pam_handle_t *pamh)
{
    const char *helper_path = NULL;
    const char *module_path = NULL;
    const char *reason = NULL;
    char default_reason[UI_REASON_MAX];
    char caller_name[UI_CALLER_NAME_MAX];
    char caller_icon_bundle[UI_CALLER_ICON_BUNDLE_MAX];
    char caller_pid[32];
    char *helper_argv[16];
    size_t helper_argc = 0;
    int spawn_rc = 0;
    pid_t pid = -1;

    helper_path = get_helper_path(pamh);
    module_path = get_module_path(pamh);

    reason = resolve_ui_reason(pamh, default_reason, sizeof(default_reason));

    caller_name[0] = '\0';
    caller_icon_bundle[0] = '\0';
    derive_caller_metadata(pamh, caller_name, sizeof(caller_name),
        caller_icon_bundle, sizeof(caller_icon_bundle));
    (void)snprintf(caller_pid, sizeof(caller_pid), "%ld", (long)getpid());

    helper_argv[helper_argc++] = (char *)helper_path;
    helper_argv[helper_argc++] = (char *)HELPER_ARG_MODE;
    helper_argv[helper_argc++] = (char *)HELPER_MODE_UI;
    helper_argv[helper_argc++] = (char *)"--reason";
    helper_argv[helper_argc++] = (char *)reason;
    helper_argv[helper_argc++] = (char *)HELPER_ARG_MODULE;
    helper_argv[helper_argc++] = (char *)module_path;

    if (caller_name[0] != '\0') {
        helper_argv[helper_argc++] = (char *)"--caller-name";
        helper_argv[helper_argc++] = caller_name;
    }
    if (caller_icon_bundle[0] != '\0') {
        helper_argv[helper_argc++] = (char *)"--caller-icon-bundle";
        helper_argv[helper_argc++] = caller_icon_bundle;
    }

    helper_argv[helper_argc++] = (char *)"--caller-pid";
    helper_argv[helper_argc++] = caller_pid;
    helper_argv[helper_argc] = NULL;

    spawn_rc = posix_spawn(&pid, helper_path, NULL, NULL, helper_argv, environ);
    if (spawn_rc != 0) {
        _LOG_ERROR(MODULE_NAME ": posix_spawn(%s) failed: %s",
            helper_path, strerror(spawn_rc));
        return -1;
    }

    return pid;
}

static int
poll_ui_prompt(pid_t *pid, bool *ui_success)
{
    int status = 0;
    pid_t rc = 0;

    if (pid == NULL || *pid <= 0) {
        return 0;
    }

    rc = waitpid(*pid, &status, WNOHANG);
    if (rc == 0) {
        return 0;
    }
    if (rc < 0) {
        if (errno == EINTR) {
            return 0;
        }
        if (errno == ECHILD) {
            *pid = -1;
            return 1;
        }
        _LOG_ERROR(MODULE_NAME ": waitpid(%d) failed: %s", *pid,
            strerror(errno));
        *pid = -1;
        return -1;
    }

    *pid = -1;
    if (ui_success != NULL) {
        *ui_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    return 1;
}

static int
wait_ui_prompt_blocking(pid_t *pid, bool *ui_success)
{
    int status = 0;
    pid_t rc = 0;

    if (pid == NULL || *pid <= 0) {
        return 0;
    }

    for (;;) {
        rc = waitpid(*pid, &status, 0);
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    if (rc < 0) {
        _LOG_ERROR(MODULE_NAME ": waitpid(%d) failed: %s", *pid,
            strerror(errno));
        *pid = -1;
        return -1;
    }

    *pid = -1;
    if (ui_success != NULL) {
        *ui_success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    return 1;
}

static void
cancel_ui_prompt(pid_t *pid)
{
    if (pid == NULL || *pid <= 0) {
        return;
    }

    (void)kill(*pid, SIGTERM);
    (void)waitpid(*pid, NULL, 0);
    *pid = -1;
}

static int
read_tty_passcode_with_ui(const char *prompt, pid_t *ui_pid,
    char *passcode_buf, size_t passcode_buf_len)
{
    int fd = -1;
    struct termios old_termios;
    struct termios new_termios;
    bool termios_changed = false;
    size_t passcode_len = 0;
    int result = TTY_PASSCODE_ERROR;

    if (passcode_buf == NULL || passcode_buf_len < 2) {
        return TTY_PASSCODE_ERROR;
    }

    passcode_buf[0] = '\0';

    fd = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (fd < 0) {
        return TTY_PASSCODE_ERROR;
    }

    if (tcgetattr(fd, &old_termios) != 0) {
        goto out;
    }

    new_termios = old_termios;
    new_termios.c_lflag &= ~(ECHO | ICANON);
    new_termios.c_cc[VMIN] = 0;
    new_termios.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSAFLUSH, &new_termios) != 0) {
        goto out;
    }
    termios_changed = true;

    if (prompt != NULL && prompt[0] != '\0') {
        (void)write(fd, prompt, strlen(prompt));
    }

    for (;;) {
        struct pollfd pfd;
        bool ui_success = false;
        int ui_state = 0;
        int poll_rc = 0;

        ui_state = poll_ui_prompt(ui_pid, &ui_success);
        if (ui_state == 1 && ui_success) {
            result = TTY_PASSCODE_UI_SUCCESS;
            break;
        }

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        poll_rc = poll(&pfd, 1, 200);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto out;
        }
        if (poll_rc == 0) {
            continue;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            goto out;
        }
        if ((pfd.revents & POLLIN) != 0) {
            char ch = '\0';
            ssize_t n = read(fd, &ch, 1);

            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                goto out;
            }
            if (n == 0) {
                goto out;
            }

            if (ch == '\r' || ch == '\n') {
                if (passcode_len > 0) {
                    result = TTY_PASSCODE_INPUT;
                }
                break;
            }
            if (ch == 0x7f || ch == '\b') {
                if (passcode_len > 0) {
                    passcode_len--;
                    (void)write(fd, "\b \b", 3);
                }
                continue;
            }
            if (ch == 0x03 || ch == 0x04) {
                goto out;
            }
            if ((unsigned char)ch < 0x20) {
                continue;
            }

            if (passcode_len + 1 < passcode_buf_len) {
                passcode_buf[passcode_len++] = ch;
                passcode_buf[passcode_len] = '\0';
            }
        }
    }

out:
    if (prompt != NULL && prompt[0] != '\0') {
        (void)write(fd, "\n", 1);
    }
    if (termios_changed) {
        (void)tcsetattr(fd, TCSANOW, &old_termios);
    }
    if (fd >= 0) {
        (void)close(fd);
    }

    return result;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *user = NULL;
    const char *passcode = NULL;
    const void *stacked_token = NULL;
    const char *prompt = NULL;
    char tty_passcode[MAX_PASSCODE_LENGTH + 1];
    bool passcode_from_tty = false;
    bool passcode_from_first_pass = false;
    bool allow_remote = false;
    bool is_remote_request = false;
    bool allow_empty_passcode = false;
    bool unlock_springboard = false;
    bool prefer_ui_prompt = false;
    bool direct_mode = false;
    bool use_first_pass = false;
    bool try_first_pass = false;
    int retval = PAM_AUTH_ERR;
    int mkb_status = -1;
    pid_t ui_pid = -1;

    (void)argc;
    (void)argv;

    tty_passcode[0] = '\0';

    _LOG_DEBUG(MODULE_NAME ": pam_sm_authenticate");

    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS || user == NULL) {
        _LOG_ERROR(MODULE_NAME ": unable to obtain username");
        return PAM_AUTHINFO_UNAVAIL;
    }

    retval = user_is_allowed(pamh, user);
    if (retval != PAM_SUCCESS) {
        return retval;
    }

    allow_remote = (openpam_get_option(pamh, "allow_remote") != NULL);
    is_remote_request = request_is_remote(pamh);
    if (!allow_remote && is_remote_request) {
        _LOG_DEFAULT(MODULE_NAME ": remote request for '%s' denied by default",
            user);
        return PAM_IGNORE;
    }
    allow_empty_passcode = is_empty_passcode_allowed(pamh, flags,
        is_remote_request);

    prompt = openpam_get_option(pamh, "prompt");
    if (prompt == NULL || prompt[0] == '\0') {
        prompt = DEFAULT_PROMPT;
    }

    unlock_springboard = (openpam_get_option(pamh, "unlock_springboard") != NULL);
    prefer_ui_prompt = (openpam_get_option(pamh, "prefer_ui_prompt") != NULL);
    direct_mode = (openpam_get_option(pamh, PAM_OPT_DIRECT_MODE) != NULL);
    use_first_pass = (openpam_get_option(pamh, PAM_OPT_USE_FIRST_PASS) != NULL);
    try_first_pass = (openpam_get_option(pamh, PAM_OPT_TRY_FIRST_PASS) != NULL);
    if (use_first_pass && try_first_pass) {
        _LOG_DEBUG(MODULE_NAME ": both %s and %s set; treating as %s",
            PAM_OPT_USE_FIRST_PASS, PAM_OPT_TRY_FIRST_PASS,
            PAM_OPT_USE_FIRST_PASS);
    }

    if (use_first_pass || try_first_pass) {
        retval = pam_get_item(pamh, PAM_AUTHTOK, &stacked_token);
        if (retval == PAM_SUCCESS && stacked_token != NULL) {
            passcode = (const char *)stacked_token;
            passcode_from_first_pass = true;
            _LOG_DEBUG(MODULE_NAME ": using existing PAM_AUTHTOK");
        } else if (use_first_pass) {
            _LOG_DEFAULT(MODULE_NAME ": %s set but no existing PAM_AUTHTOK for '%s'",
                PAM_OPT_USE_FIRST_PASS, user);
            return PAM_AUTH_ERR;
        }
    }

    if (prefer_ui_prompt && direct_mode) {
        retval = ui_authenticate_direct(pamh);
        if (retval == PAM_SUCCESS) {
            _LOG_DEFAULT(MODULE_NAME ": UI authentication succeeded for '%s'",
                user);
            return PAM_SUCCESS;
        }
        if (retval == PAM_IGNORE) {
            _LOG_DEFAULT(MODULE_NAME ": UI path unavailable for '%s' in %s mode",
                user, PAM_OPT_DIRECT_MODE);
        }
    } else if (prefer_ui_prompt) {
        ui_pid = spawn_ui_prompt_helper(pamh);
    }

    if (passcode_from_first_pass) {
        retval = mkb_authenticate_passcode(pamh, passcode, unlock_springboard,
            allow_empty_passcode, direct_mode, &mkb_status);
        if (retval == PAM_SUCCESS) {
            cancel_ui_prompt(&ui_pid);
            _LOG_DEFAULT(MODULE_NAME ": authentication succeeded for '%s' (path=%s)",
                user, unlock_springboard ? "unlock" : "verify");
            return PAM_SUCCESS;
        }

        if (use_first_pass) {
            if (ui_pid > 0) {
                bool ui_success = false;
                int ui_state = wait_ui_prompt_blocking(&ui_pid, &ui_success);
                if (ui_state == 1 && ui_success) {
                    _LOG_DEFAULT(MODULE_NAME ": UI authentication succeeded for '%s'",
                        user);
                    return PAM_SUCCESS;
                }
            }

            cancel_ui_prompt(&ui_pid);
            _LOG_DEFAULT(MODULE_NAME
                ": %s authentication failed for '%s' (result=%d mode=%s)",
                PAM_OPT_USE_FIRST_PASS, user, mkb_status,
                direct_mode ? "direct" : "helper");
            return retval;
        }

        passcode = NULL;
        passcode_from_first_pass = false;
    }

    if (prefer_ui_prompt && ui_pid > 0 && passcode == NULL) {
        int tty_result = read_tty_passcode_with_ui(prompt, &ui_pid,
            tty_passcode, sizeof(tty_passcode));
        if (tty_result == TTY_PASSCODE_UI_SUCCESS) {
            _LOG_DEFAULT(MODULE_NAME ": UI authentication succeeded for '%s'",
                user);
            secure_memzero(tty_passcode, sizeof(tty_passcode));
            return PAM_SUCCESS;
        }
        if (tty_result == TTY_PASSCODE_INPUT) {
            passcode = tty_passcode;
            passcode_from_tty = true;
        }
    }

    if (passcode == NULL) {
        retval = pam_get_authtok(pamh, PAM_AUTHTOK, &passcode, prompt);
        if (retval != PAM_SUCCESS || passcode == NULL) {
            _LOG_ERROR(MODULE_NAME ": unable to obtain passcode token: %d", retval);

            if (ui_pid > 0) {
                bool ui_success = false;
                int ui_state = wait_ui_prompt_blocking(&ui_pid, &ui_success);
                if (ui_state == 1 && ui_success) {
                    _LOG_DEFAULT(MODULE_NAME ": UI authentication succeeded for '%s'",
                        user);
                    secure_memzero(tty_passcode, sizeof(tty_passcode));
                    return PAM_SUCCESS;
                }
            }

            cancel_ui_prompt(&ui_pid);
            secure_memzero(tty_passcode, sizeof(tty_passcode));
            return (retval == PAM_SUCCESS) ? PAM_AUTHTOK_ERR : retval;
        }

        if (ui_pid > 0 && passcode[0] == '\0' && !allow_empty_passcode) {
            bool ui_success = false;
            int ui_state = wait_ui_prompt_blocking(&ui_pid, &ui_success);

            secure_memzero(tty_passcode, sizeof(tty_passcode));
            if (ui_state == 1 && ui_success) {
                _LOG_DEFAULT(MODULE_NAME ": UI authentication succeeded for '%s'",
                    user);
                return PAM_SUCCESS;
            }

            return PAM_AUTH_ERR;
        }

        if (ui_pid > 0) {
            bool ui_success = false;
            if (poll_ui_prompt(&ui_pid, &ui_success) == 1 && ui_success) {
                _LOG_DEFAULT(MODULE_NAME ": UI authentication succeeded for '%s'",
                    user);
                secure_memzero(tty_passcode, sizeof(tty_passcode));
                return PAM_SUCCESS;
            }
        }
    }

    retval = mkb_authenticate_passcode(pamh, passcode, unlock_springboard,
        allow_empty_passcode, direct_mode, &mkb_status);

    cancel_ui_prompt(&ui_pid);

    if (retval == PAM_SUCCESS) {
        _LOG_DEFAULT(MODULE_NAME ": authentication succeeded for '%s' (path=%s)",
            user, unlock_springboard ? "unlock" : "verify");
    } else {
        _LOG_DEFAULT(MODULE_NAME ": authentication failed for '%s' (result=%d mode=%s)",
            user, mkb_status, direct_mode ? "direct" : "helper");
    }

    if (passcode_from_tty) {
        secure_memzero(tty_passcode, sizeof(tty_passcode));
    }

    return retval;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
