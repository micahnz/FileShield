#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>

#include "notify.h"
#include "fanotify.h"
#include "session.h"
#include "utils.h"

/* UID of the desktop user whose session was detected. 0 = not found. */
static uid_t g_session_uid = 0;

/*
 * Fanotify fd stored here so run_kdialog_3choice() can pump pending events
 * while waiting for the dialog child (prevents mount-mark deadlock).
 */
static int g_fan_fd = -1;

/* Total wall-clock budget for a dialog, slightly longer than the inner
 * "timeout 30" the child enforces. */
#define DIALOG_OUTER_TIMEOUT_S 40

/* ------------------------------------------------------------------ */
/*  user session environment forwarding                                */
/* ------------------------------------------------------------------ */
/*
 * The daemon runs as root from systemd with a bare environment, so a
 * kdialog child would miss the user's desktop session variables and Qt
 * falls back to the generic light theme instead of the user's theme
 * (on Plasma, KDE_FULL_SESSION / XDG_CURRENT_DESKTOP drive platform
 * theme selection).  Forward a fixed whitelist of cosmetic variables
 * from the user's own session.
 *
 * Deliberately NOT forwarded:
 *   - DISPLAY / WAYLAND_DISPLAY / XAUTHORITY / DBUS_SESSION_BUS_ADDRESS:
 *     the prompt must stay on the display FileShield detected, never one
 *     a malicious process points at.
 *   - LD_* / PATH / QT_PLUGIN_PATH / QT_QPA_PLATFORM*: no code loading or
 *     platform override.
 * The forwarded values are cosmetic only and length-capped; a malicious
 * value can at worst make the dialog look wrong or fail, which still
 * fails closed.
 */
static const char *const g_dialog_env_keys[] = {
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
    "XDG_SESSION_TYPE",
    "KDE_FULL_SESSION",
    "KDE_SESSION_VERSION",
    "KDE_APPLICATIONS_AS_SCOPE",
    "QT_QPA_PLATFORMTHEME",
    "QT_STYLE_OVERRIDE",
    "QT_AUTO_SCREEN_SCALE_FACTOR",
    "QT_SCALE_FACTOR",
    "QT_SCREEN_SCALE_FACTORS",
    "QT_FONT_DPI",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "XCURSOR_THEME",
    "XCURSOR_SIZE",
    "GTK_THEME",
    NULL};

#define DIALOG_ENV_MAX 24
#define DIALOG_ENV_KEY_MAX 32
#define DIALOG_ENV_VALUE_MAX 256
#define DIALOG_ENV_FILE_MAX (128 * 1024)

typedef struct
{
    char key[DIALOG_ENV_KEY_MAX];
    char value[DIALOG_ENV_VALUE_MAX];
} DialogEnvSetting;

static int dialog_env_key_allowed(const char *key)
{
    for (int i = 0; g_dialog_env_keys[i] != NULL; i++)
    {
        if (strcmp(g_dialog_env_keys[i], key) == 0)
            return 1;
    }
    return 0;
}

static int dialog_env_collected(const DialogEnvSetting *out, int count,
                                const char *key)
{
    for (int i = 0; i < count; i++)
    {
        if (strcmp(out[i].key, key) == 0)
            return 1;
    }
    return 0;
}

/* Merge NUL-separated KEY=VALUE entries from a /proc environ buffer. */
static int merge_proc_environ(const char *buf, size_t len,
                              DialogEnvSetting *out, int count, int max)
{
    size_t pos = 0;

    while (pos < len && count < max)
    {
        const char *entry = buf + pos;
        size_t entry_len = strnlen(entry, len - pos);
        const char *eq = memchr(entry, '=', entry_len);

        if (eq != NULL && (size_t)(eq - entry) < DIALOG_ENV_KEY_MAX)
        {
            char key[DIALOG_ENV_KEY_MAX];
            size_t klen = (size_t)(eq - entry);

            memcpy(key, entry, klen);
            key[klen] = '\0';

            if (dialog_env_key_allowed(key) &&
                !dialog_env_collected(out, count, key))
            {
                size_t vlen = entry_len - klen - 1;
                if (vlen >= DIALOG_ENV_VALUE_MAX)
                    vlen = DIALOG_ENV_VALUE_MAX - 1;
                snprintf(out[count].key, sizeof(out[count].key), "%s", key);
                memcpy(out[count].value, eq + 1, vlen);
                out[count].value[vlen] = '\0';
                count++;
            }
        }
        pos += entry_len + 1;
    }
    return count;
}

static int read_proc_environ(pid_t pid, char *buf, size_t bufsz)
{
    char path[64];
    int fd;
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%d/environ", (int)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}

/*
 * Collect the whitelisted variables for requester.  The session leader
 * (the user's shell) holds the authoritative session environment; the
 * requester fills any gaps.  Returns the number of settings found.
 */
static int collect_dialog_env(pid_t requester, DialogEnvSetting *out, int max)
{
    char *buf = malloc(DIALOG_ENV_FILE_MAX);
    pid_t leader = 0;
    int count = 0;
    int n;

    if (buf == NULL)
        return 0;

    if (session_id_of(requester, &leader, NULL) == 0 && leader > 0)
    {
        n = read_proc_environ(leader, buf, DIALOG_ENV_FILE_MAX);
        if (n > 0)
            count = merge_proc_environ(buf, (size_t)n, out, count, max);
    }

    if (count < max && requester != leader)
    {
        n = read_proc_environ(requester, buf, DIALOG_ENV_FILE_MAX);
        if (n > 0)
            count = merge_proc_environ(buf, (size_t)n, out, count, max);
    }

    free(buf);
    return count;
}

/* Called in the dialog child after dropping to the desktop user. */
static void apply_dialog_env(const DialogEnvSetting *env, int count)
{
    for (int i = 0; i < count; i++)
        setenv(env[i].key, env[i].value, 1);
}

void notify_set_fan_fd(int fd)
{
    g_fan_fd = fd;
}

/*
 * find_wayland_session: look for an active Wayland session owned by
 * uid_val under /run/user/<uid>.  On success exports WAYLAND_DISPLAY,
 * XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS, records g_session_uid,
 * and returns 1.
 */
static int find_wayland_session(unsigned long uid_val)
{
    char user_dir[PATH_MAX];
    DIR *d;
    struct dirent *ent;
    char wayland_sock[256] = "";

    snprintf(user_dir, sizeof(user_dir), "/run/user/%lu", uid_val);

    d = opendir(user_dir);
    if (!d)
        return 0;

    while ((ent = readdir(d)) != NULL)
    {
        if (strncmp(ent->d_name, "wayland-", 8) == 0 &&
            strstr(ent->d_name, ".lock") == NULL)
        {
            snprintf(wayland_sock, sizeof(wayland_sock), "%s", ent->d_name);
            break;
        }
    }
    closedir(d);

    if (wayland_sock[0] == '\0')
        return 0;

    setenv("WAYLAND_DISPLAY", wayland_sock, 1);
    setenv("XDG_RUNTIME_DIR", user_dir, 1);
    char dbus[PATH_MAX + 32];
    snprintf(dbus, sizeof(dbus), "unix:path=%s/bus", user_dir);
    setenv("DBUS_SESSION_BUS_ADDRESS", dbus, 1);
    g_session_uid = (uid_t)uid_val;
    return 1;
}

/*
 * setup_display_env: determine which desktop session should show the
 * prompt.  Preference order:
 *   1. Environment already provides WAYLAND_DISPLAY/DISPLAY (derive the
 *      session uid from XDG_RUNTIME_DIR ownership).
 *   2. The requesting process's own uid (preferred_uid): the prompt must
 *      be shown to the user whose process triggered it.
 *   3. As a last resort for unknown requesters, the first active non-root
 *      Wayland session found under /run/user.
 * The dialog child drops to g_session_uid; if no non-root session can be
 * determined, notify_ask() refuses to run a GUI as root.
 */
static void setup_display_env(uid_t preferred_uid)
{
    if (getenv("WAYLAND_DISPLAY") || getenv("DISPLAY"))
    {
        const char *xdg = getenv("XDG_RUNTIME_DIR");
        if (xdg)
        {
            struct stat st;
            if (stat(xdg, &st) == 0 && st.st_uid != 0)
                g_session_uid = st.st_uid;
        }
        return;
    }

    if (preferred_uid != (uid_t)-1 && preferred_uid != 0)
    {
        if (find_wayland_session((unsigned long)preferred_uid))
            return;
        log_msg(LOG_WARNING,
                "no active Wayland session for uid %d; not prompting another user",
                (int)preferred_uid);
        return;
    }

    DIR *top = opendir("/run/user");
    if (!top)
        return;

    struct dirent *uid_ent;
    while ((uid_ent = readdir(top)) != NULL)
    {
        if (uid_ent->d_name[0] == '.')
            continue;

        char *endptr;
        unsigned long uid_val = strtoul(uid_ent->d_name, &endptr, 10);
        if (*endptr != '\0' || uid_val == 0)
            continue;

        if (find_wayland_session(uid_val))
            break;
    }
    closedir(top);
}

/*
 * drop_to_session_user: called in the dialog child after fork().
 * Switches uid/gid to the desktop user (including supplementary groups)
 * so the dialog can connect to their compositor and D-Bus session.
 */
static void drop_to_session_user(void)
{
    if (g_session_uid == 0 || getuid() != 0)
        return;

    struct passwd *pw = getpwuid(g_session_uid);
    if (!pw)
        _exit(127);

    /* Drop supplementary groups first, then gid, then uid. */
    if (initgroups(pw->pw_name, pw->pw_gid) < 0)
        _exit(127);
    if (setgid(pw->pw_gid) < 0)
        _exit(127);
    if (setuid(g_session_uid) < 0)
        _exit(127);
    setenv("HOME", pw->pw_dir, 1);
}

/*
 * sanitize_text: replace control characters (including newlines) with
 * '?' and bound the length so attacker-controlled file names, comm names
 * and cmdlines cannot spoof extra dialog content.
 */
static void sanitize_text(const char *in, char *out, size_t outsz)
{
    size_t j = 0;

    if (outsz == 0)
        return;
    if (!in)
    {
        out[0] = '\0';
        return;
    }
    for (size_t i = 0; in[i] != '\0' && j + 1 < outsz; i++)
    {
        unsigned char c = (unsigned char)in[i];
        out[j++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
    }
    out[j] = '\0';
}

/* Kill the dialog process group and reap with a bounded wait. */
static void kill_and_reap(pid_t pid, int *status, int *child_exited)
{
    kill(-pid, SIGKILL);
    for (int i = 0; i < 100 && !*child_exited; i++) /* up to ~10s */
    {
        pid_t wr = waitpid(pid, status, WNOHANG);
        if (wr == pid)
            *child_exited = 1;
        else if (wr < 0 && errno != EINTR)
            break;
        usleep(100000);
    }
    if (!*child_exited)
        log_msg(LOG_ERR,
                "[dialog] pid=%d did not exit after SIGKILL; abandoning it",
                (int)pid);
}

/*
 * run_kdialog_3choice: display a kdialog --yesnocancel prompt with custom
 * button labels and return the chosen button:
 *   0 = yes, 1 = no, 2 = cancel/window close, -1 = failure/timeout.
 *
 * kdialog is wrapped in timeout(1) so a hung compositor cannot block the
 * event loop forever.  While waiting, pending fanotify events are pumped:
 * kdialog opens its own config files, which can generate FAN_OPEN_PERM
 * events on mount-marked filesystems and would otherwise deadlock the
 * helper behind the daemon's blocked event.
 */
static int run_kdialog_3choice(const DialogEnvSetting *env, int env_count,
                               const char *text, const char *yes_label,
                               const char *no_label, const char *cancel_label)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_ERR, "fork failed for kdialog: %m");
        return -1;
    }
    log_msg(LOG_DEBUG, "[dialog] forked kdialog child pid=%d", (int)pid);

    if (pid == 0)
    {
        /* Own process group so the timeout kill cannot touch the daemon
         * and so events from every dialog helper can be recognized. */
        setpgid(0, 0);
        drop_to_session_user();
        /* Let kdialog see the user's theme/font/scale/locale settings. */
        apply_dialog_env(env, env_count);
        close_fds_from(3);

        execl("/usr/bin/timeout", "timeout", "30",
              "/usr/bin/kdialog", "kdialog",
              "--title", "FileShield",
              "--yesnocancel", text,
              "--yes-label", yes_label,
              "--no-label", no_label,
              "--cancel-label", cancel_label,
              (char *)NULL);
        _exit(127);
    }

    log_msg(LOG_DEBUG, "[dialog] parent waiting for kdialog (pid=%d)", (int)pid);
    int child_exited = 0;
    int status = 0;
    time_t deadline = time(NULL) + DIALOG_OUTER_TIMEOUT_S;

    while (!child_exited && time(NULL) < deadline)
    {
        struct pollfd pfd;
        int nfds = 0;

        if (g_fan_fd >= 0)
        {
            pfd.fd = g_fan_fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            nfds = 1;
        }

        int ret = poll(nfds ? &pfd : NULL, (nfds_t)nfds, 200); /* 200 ms tick */
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        /* Pump fanotify first so the dialog child is never stalled. */
        if (nfds && (pfd.revents & POLLIN))
            fanotify_pump(g_fan_fd, pid);

        /* Non-blocking child-exit check. */
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid)
        {
            child_exited = 1;
        }
        else if (wr < 0 && errno != EINTR)
        {
            log_msg(LOG_ERR, "waitpid failed: %m");
            return -1;
        }
    }

    if (!child_exited)
    {
        log_msg(LOG_WARNING, "[dialog] kdialog outer timeout, killing pid=%d",
                (int)pid);
        kill_and_reap(pid, &status, &child_exited);
    }

    log_msg(LOG_DEBUG, "[dialog] kdialog exited status=0x%x ec=%d",
            status, WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* A child killed by the outer timeout, an exec failure (127) or any
     * unexpected exit code is a failure: the caller fails closed. */
    if (!child_exited || !WIFEXITED(status))
        return -1;

    int ec = WEXITSTATUS(status);

    if (ec == 124) /* coreutils timeout(1) */
    {
        log_msg(LOG_WARNING, "[dialog] kdialog timed out (30s)");
        return -1;
    }
    if (ec == 0)
        return 0; /* Yes */
    if (ec == 1)
        return 1; /* No */
    if (ec == 2)
        return 2; /* Cancel / window close / Escape */
    return -1;
}

int notify_ask(const char *comm, pid_t pid, pid_t ppid,
               const char *comm_parent, const char *exe,
               const char *cmdline, const char *path, uid_t user_uid)
{
    /* Return values: NOTIFY_ALLOW_ONCE, NOTIFY_DENY,
     *                NOTIFY_ALLOW_SESSION, NOTIFY_DENY_SESSION,
     *                NOTIFY_ALLOW_ALWAYS, NOTIFY_DENY_ALWAYS. */
    char msg[2048];
    char msg2[1024];
    char comm_s[64];
    char pcomm_s[64];
    char cmd_s[256];
    char exe_s[512];
    char path_s[512];

    /* Attacker-controlled strings (file names, comm, cmdline) are
     * sanitized so control characters cannot forge dialog content. */
    sanitize_text(comm, comm_s, sizeof(comm_s));
    sanitize_text(comm_parent, pcomm_s, sizeof(pcomm_s));
    sanitize_text(exe ? exe : "(unknown)", exe_s, sizeof(exe_s));
    sanitize_text(path, path_s, sizeof(path_s));
    sanitize_text(cmdline && cmdline[0] != '\0' ? cmdline : "(unknown)",
                  cmd_s, sizeof(cmd_s));

    if (exe && strlen(exe) >= sizeof(exe_s) - 1)
        memcpy(exe_s + sizeof(exe_s) - 4, "...", 4);
    if (path && strlen(path) >= sizeof(path_s) - 1)
        memcpy(path_s + sizeof(path_s) - 4, "...", 4);
    if (cmdline && strlen(cmdline) >= sizeof(cmd_s) - 1)
        memcpy(cmd_s + sizeof(cmd_s) - 4, "...", 4);

    snprintf(msg, sizeof(msg),
             "Process %s (PID %d, parent: %s (PID %d)) wants to read:\n"
             "%s\n\n"
             "Binary:   %s\n"
             "Command:  %s\n\n"
             "\xe2\x80\xa2 Allow Once \xe2\x80\x94 this file, for the configured user_ttl\n"
             "\xe2\x80\xa2 Allow      \xe2\x80\x94 choose session or permanent access\n"
             "\xe2\x80\xa2 Deny       \xe2\x80\x94 choose a session or permanent block",
             comm_s, (int)pid, pcomm_s, (int)ppid,
             path_s, exe_s, cmd_s);

    /* Auto-detect the active graphical session if env vars are not set. */
    setup_display_env(user_uid);
    log_msg(LOG_DEBUG,
            "[notify_ask] display env: WAYLAND=%s DISPLAY=%s uid=%d",
            getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "(none)",
            getenv("DISPLAY") ? getenv("DISPLAY") : "(none)",
            (int)g_session_uid);

    /* Never run a security prompt as a root GUI process. */
    if (getuid() == 0 && g_session_uid == 0)
    {
        log_msg(LOG_ERR,
                "no non-root desktop session found; denying access to %s",
                path_s);
        return NOTIFY_DENY;
    }

    /* Forward the user's theme/font/scale/locale environment so kdialog
     * renders like the rest of their desktop. */
    DialogEnvSetting dialog_env[DIALOG_ENV_MAX];
    int dialog_env_count = collect_dialog_env(pid, dialog_env, DIALOG_ENV_MAX);
    log_msg(LOG_DEBUG, "[dialog] forwarding %d session variables",
            dialog_env_count);

    /* First dialog: Allow Once / Allow / Deny. */
    int r = run_kdialog_3choice(dialog_env, dialog_env_count, msg,
                                "Allow Once", "Allow", "Deny");

    if (r == 0)
        return NOTIFY_ALLOW_ONCE;

    if (r == 1)
    {
        /* Allow: choose how broad/long the grant should be.  Allow Always
         * is on the No button per the approved UX; a broken kdialog that
         * exits 1 without user interaction is a known accepted risk. */
        snprintf(msg2, sizeof(msg2),
                 "Allow access to:\n"
                 "%s\n\n"
                 "\xe2\x80\xa2 Allow Session \xe2\x80\x94 this file until this session closes\n"
                 "\xe2\x80\xa2 Allow Always  \xe2\x80\x94 this file permanently\n"
                 "                  (re-prompts if the binary changes)\n"
                 "\xe2\x80\xa2 Cancel        \xe2\x80\x94 deny this time",
                 path_s);

        int r2 = run_kdialog_3choice(dialog_env, dialog_env_count, msg2,
                                     "Allow Session", "Allow Always", "Cancel");
        if (r2 == 0)
            return NOTIFY_ALLOW_SESSION;
        if (r2 == 1)
            return NOTIFY_ALLOW_ALWAYS;
        return NOTIFY_DENY;
    }

    /* A failed first dialog (timeout, exec error) denies once without a
     * follow-up prompt; only an explicit Deny click opens the deny
     * dialog. */
    if (r != 2)
    {
        log_msg(LOG_WARNING, "[dialog] no valid kdialog choice; denying once");
        return NOTIFY_DENY;
    }

    snprintf(msg2, sizeof(msg2),
             "Deny access to:\n"
             "%s\n\n"
             "\xe2\x80\xa2 Deny Session \xe2\x80\x94 this file until this session closes\n"
             "\xe2\x80\xa2 Deny Always  \xe2\x80\x94 this file permanently\n"
             "                 (runtime-denylist.json)\n"
             "\xe2\x80\xa2 Deny         \xe2\x80\x94 this time only",
             path_s);

    int r3 = run_kdialog_3choice(dialog_env, dialog_env_count, msg2,
                                 "Deny Session", "Deny Always", "Deny");
    if (r3 == 0)
        return NOTIFY_DENY_SESSION;
    if (r3 == 1)
        return NOTIFY_DENY_ALWAYS;
    return NOTIFY_DENY;
}
