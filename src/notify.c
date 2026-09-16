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

/* Monotonic milliseconds: wall-clock steps must not extend a deadline. */
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Fanotify fd stored here so run_kdialog() can pump pending events
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
 *     the prompt must stay on the display Fileshield detected, never one
 *     a malicious process points at.
 *   - LD_* / PATH / QT_PLUGIN_PATH / QT_QPA_PLATFORM*: no code loading or
 *     platform override.  QT_QPA_PLATFORMTHEME is the one deliberate
 *     exception: it names an installed theme plugin by key (Qt resolves it
 *     without QT_PLUGIN_PATH), not a platform or a code path.
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

/* Test seam (notify.h): the dialog environment whitelist. */
int notify_test_env_key_allowed(const char *key)
{
    return dialog_env_key_allowed(key);
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
    unsigned long long leader_start = 0;
    int count = 0;
    int n;

    if (buf == NULL)
        return 0;

    if (session_id_of(requester, &leader, &leader_start) == 0 && leader > 0)
    {
        unsigned long long now_start = 0;

        /* Read the leader's environment only while it is still the process
         * the SID was resolved to: a recycled leader PID must not feed the
         * dialog from an unrelated process. */
        if (proc_stat_session(leader, NULL, &now_start) == 0 &&
            now_start == leader_start)
        {
            n = read_proc_environ(leader, buf, DIALOG_ENV_FILE_MAX);
            if (n > 0)
                count = merge_proc_environ(buf, (size_t)n, out, count, max);
        }
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
 * Desktop session selected for one prompt.  Detection never mutates the
 * daemon's environment: the values are applied inside the dialog child
 * after it drops to the desktop user, so a prompt is always shown on the
 * display detected for that user and cannot leak into later, unrelated
 * requests (or into forked helpers such as sha512sum).
 */
typedef struct
{
    uid_t uid;                 /* desktop user; 0 = none found            */
    char wayland_display[256]; /* "" when unset                           */
    char display[256];         /* X11 DISPLAY from the unit, "" when unset */
    char xdg_runtime_dir[PATH_MAX];
    char dbus_address[PATH_MAX + 32];
} DisplaySession;

/*
 * find_wayland_session: look for an active Wayland session owned by
 * uid_val under /run/user/<uid>.  The runtime directory and the socket
 * are both validated (real directory / socket, owned by the user) so a
 * planted regular file or another user's endpoint cannot capture the
 * prompt.  On success fills *out and returns 1.
 */
static int find_wayland_session(unsigned long uid_val, DisplaySession *out)
{
    char user_dir[PATH_MAX];
    struct stat st;
    DIR *d;
    const struct dirent *ent;
    char sock[256] = "";

    snprintf(user_dir, sizeof(user_dir), "/run/user/%lu", uid_val);

    if (lstat(user_dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != (uid_t)uid_val)
        return 0;

    d = opendir(user_dir);
    if (!d)
        return 0;

    while ((ent = readdir(d)) != NULL)
    {
        if (strncmp(ent->d_name, "wayland-", 8) != 0)
            continue;
        if (strstr(ent->d_name, ".lock") != NULL)
            continue;

        char full[PATH_MAX];
        if (snprintf(full, sizeof(full), "%s/%s", user_dir, ent->d_name) >=
            (int)sizeof(full))
            continue;

        struct stat sst;
        if (lstat(full, &sst) != 0)
            continue;
        /* Only a socket owned by the user can serve a Wayland session. */
        if (!S_ISSOCK(sst.st_mode) || sst.st_uid != (uid_t)uid_val)
            continue;

        snprintf(sock, sizeof(sock), "%s", ent->d_name);
        break;
    }
    closedir(d);

    if (sock[0] == '\0')
        return 0;

    memset(out, 0, sizeof(*out));
    out->uid = (uid_t)uid_val;
    snprintf(out->wayland_display, sizeof(out->wayland_display), "%s", sock);
    snprintf(out->xdg_runtime_dir, sizeof(out->xdg_runtime_dir), "%s",
             user_dir);
    snprintf(out->dbus_address, sizeof(out->dbus_address), "unix:path=%s/bus",
             user_dir);
    return 1;
}

/*
 * user_runtime_dir: validate /run/user/<uid> (real directory owned by the
 * user, mirroring find_wayland_session's checks) and fill the session's
 * runtime dir and bus address from it.  Returns 1 on success.
 */
static int user_runtime_dir(unsigned long uid_val, DisplaySession *out)
{
    char user_dir[PATH_MAX];
    struct stat st;

    snprintf(user_dir, sizeof(user_dir), "/run/user/%lu", uid_val);
    if (lstat(user_dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != (uid_t)uid_val)
        return 0;

    snprintf(out->xdg_runtime_dir, sizeof(out->xdg_runtime_dir), "%s",
             user_dir);
    snprintf(out->dbus_address, sizeof(out->dbus_address), "unix:path=%s/bus",
             user_dir);
    out->uid = (uid_t)uid_val;
    return 1;
}

/*
 * detect_display_session: determine which desktop session should show the
 * prompt.  Preference order:
 *   1. Environment already provides WAYLAND_DISPLAY/DISPLAY (systemd
 *      override or a manual run); derive the session uid from
 *      XDG_RUNTIME_DIR ownership when it is usable, otherwise from the
 *      requester's uid (a systemd service normally has no
 *      XDG_RUNTIME_DIR, and the shipped unit's X11 guidance sets only
 *      DISPLAY).
 *   2. The requesting process's own uid (preferred_uid): the prompt must
 *      be shown to the user whose process triggered it.
 *   3. As a last resort for unknown requesters, the first active non-root
 *      Wayland session found under /run/user.
 * Returns 1 when a non-root session was found; the dialog child then
 * drops to out->uid.  Returns 0 when no such session exists, in which
 * case notify_ask() refuses to run a GUI as root (fail closed).
 */
static int detect_display_session(uid_t preferred_uid, DisplaySession *out)
{
    memset(out, 0, sizeof(*out));

    const char *env_wayland = getenv("WAYLAND_DISPLAY");
    const char *env_display = getenv("DISPLAY");

    if (env_wayland || env_display)
    {
        if (env_wayland)
            snprintf(out->wayland_display, sizeof(out->wayland_display), "%s",
                     env_wayland);
        if (env_display)
            snprintf(out->display, sizeof(out->display), "%s", env_display);

        const char *xdg = getenv("XDG_RUNTIME_DIR");
        struct stat st;
        if (xdg && stat(xdg, &st) == 0 && st.st_uid != 0)
        {
            out->uid = st.st_uid;
            snprintf(out->xdg_runtime_dir, sizeof(out->xdg_runtime_dir), "%s",
                     xdg);

            /* An explicitly configured bus address wins; otherwise derive
             * it from the runtime directory, as the auto-detection path
             * does. */
            const char *dbus_env = getenv("DBUS_SESSION_BUS_ADDRESS");
            if (dbus_env && dbus_env[0] != '\0')
                snprintf(out->dbus_address, sizeof(out->dbus_address), "%s",
                         dbus_env);
            else
                snprintf(out->dbus_address, sizeof(out->dbus_address),
                         "unix:path=%s/bus", xdg);
            return 1;
        }

        /* No usable XDG_RUNTIME_DIR: derive the runtime dir from the
         * requester's uid — the prompt belongs to the user whose process
         * triggered it anyway.  uid 0 or unknown requesters must not be
         * pointed at an arbitrary desktop user, so they refuse (fail
         * closed) instead of scanning /run/user. */
        if (preferred_uid != (uid_t)-1 && preferred_uid != 0 &&
            user_runtime_dir((unsigned long)preferred_uid, out))
        {
            log_msg(LOG_WARNING,
                    "XDG_RUNTIME_DIR unset or root-owned; using the "
                    "requester's runtime dir for uid %d",
                    (int)preferred_uid);
            return 1;
        }
        log_msg(LOG_WARNING,
                "env display set but no usable XDG_RUNTIME_DIR and no "
                "promptable requester uid; refusing a GUI prompt");
        return 0;
    }

    if (preferred_uid != (uid_t)-1 && preferred_uid != 0)
    {
        if (find_wayland_session((unsigned long)preferred_uid, out))
            return 1;
        log_msg(LOG_WARNING,
                "no active Wayland session for uid %d; not prompting another user",
                (int)preferred_uid);
        return 0;
    }

    DIR *top = opendir("/run/user");
    if (!top)
        return 0;

    const struct dirent *uid_ent;
    while ((uid_ent = readdir(top)) != NULL)
    {
        if (uid_ent->d_name[0] == '.')
            continue;

        char *endptr;
        unsigned long uid_val = strtoul(uid_ent->d_name, &endptr, 10);
        if (*endptr != '\0' || uid_val == 0)
            continue;

        if (find_wayland_session(uid_val, out))
        {
            closedir(top);
            return 1;
        }
    }
    closedir(top);
    return 0;
}

/*
 * apply_display_env: called in the dialog child after dropping to the
 * desktop user.  Exports the detected session so kdialog reaches the
 * right compositor.  Deliberately never called in the daemon: a session
 * must not leak across prompts or into unrelated forked helpers.
 */
static void apply_display_env(const DisplaySession *session)
{
    if (session->wayland_display[0] != '\0')
        setenv("WAYLAND_DISPLAY", session->wayland_display, 1);
    if (session->display[0] != '\0')
        setenv("DISPLAY", session->display, 1);
    if (session->xdg_runtime_dir[0] != '\0')
        setenv("XDG_RUNTIME_DIR", session->xdg_runtime_dir, 1);
    if (session->dbus_address[0] != '\0')
        setenv("DBUS_SESSION_BUS_ADDRESS", session->dbus_address, 1);
}

/*
 * drop_to_session_user: called in the dialog child after fork().
 * Switches uid/gid to the desktop user (including supplementary groups)
 * so the dialog can connect to their compositor and D-Bus session.
 */
static void drop_to_session_user(const DisplaySession *session)
{
    if (session->uid == 0 || getuid() != 0)
        return;

    struct passwd *pw = getpwuid(session->uid);
    if (!pw)
        _exit(127);

    /* Drop supplementary groups first, then gid, then uid. */
    if (initgroups(pw->pw_name, pw->pw_gid) < 0)
        _exit(127);
    if (setgid(pw->pw_gid) < 0)
        _exit(127);
    if (setuid(session->uid) < 0)
        _exit(127);

    /* The child must not inherit root's HOME/USER/PATH when the daemon was
     * started outside systemd; PATH is a fixed trusted value so nothing
     * from the requesting process can steer helper lookup. */
    if (pw->pw_dir)
        setenv("HOME", pw->pw_dir, 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("PATH",
           "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
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

/*
 * sanitize_ellipsized: sanitize src into out (bounded) and, when content
 * was actually cut, mark the cut by replacing the tail with "...".
 * A value that fits exactly is left untouched.
 */
static void sanitize_ellipsized(const char *in, char *out, size_t outsz)
{
    sanitize_text(in, out, outsz);
    if (!in || strlen(in) <= outsz - 1)
        return; /* nothing was cut */
    if (outsz >= 4)
        memcpy(out + outsz - 4, "...", 4);
}

/* Test seam (notify.h): bounded prompt-text sanitizing with the cut
 * marker, shared with the real prompt builder. */
void notify_test_sanitize_ellipsized(const char *in, char *out, size_t outsz)
{
    sanitize_ellipsized(in, out, outsz);
}

/* Kill the dialog process group and reap with a bounded wait. */
static void kill_and_reap(pid_t pid, int *status, int *child_exited)
{
    /* The PID may have been recycled between the last WNOHANG check and
     * this kill: confirm the process still leads this group before
     * signaling it, and fall back to the single pid when it does not. */
    if (getpgid(pid) == pid)
        kill(-pid, SIGKILL);
    else
        kill(pid, SIGKILL);
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
 * run_kdialog: show a kdialog --yesnocancel prompt with custom button
 * labels and return 0 = yes, 1 = no, 2 = cancel/window close,
 * -1 = failure/timeout.
 *
 * kdialog is wrapped in timeout(1) so a hung compositor cannot block the
 * event loop forever.  While waiting, pending fanotify events are pumped:
 * kdialog opens its own config files, which can generate FAN_OPEN_PERM
 * events on mount-marked filesystems and would otherwise deadlock the
 * helper behind the daemon's blocked event.
 *
 * kdialog returns 1 both for a deliberate No click and for some runtime
 * errors.  The stage-2 scope dialogs map No to the permanent "Always"
 * choice by explicit UX decision (documented trade-off in the README);
 * timeouts, exec failures and Cancel/window close always deny.
 */
static int run_kdialog(const DisplaySession *session,
                       const DialogEnvSetting *env, int env_count,
                       const char *text, const char *yes_label,
                       const char *no_label, const char *cancel_label)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_ERR, "fork failed for kdialog: %m");
        return -1;
    }

    if (pid == 0)
    {
        /* Own process group so the timeout kill cannot touch the daemon
         * and so events from every dialog helper can be recognized. */
        setpgid(0, 0);
        drop_to_session_user(session);
        /* Export the detected display only here, in the child: the daemon
         * environment stays untouched so one user's session cannot leak
         * into another prompt or into unrelated helpers. */
        apply_display_env(session);
        /* Let kdialog see the user's theme/font/scale/locale settings. */
        apply_dialog_env(env, env_count);
        close_fds_from(3);

        /* exec resets only caught/default dispositions, so the daemon's
         * SIG_IGN would leak into kdialog/timeout as ignored SIGPIPE. */
        signal(SIGPIPE, SIG_DFL);

        execl("/usr/bin/timeout", "timeout", "30",
              "/usr/bin/kdialog", "kdialog",
              "--title", "Fileshield",
              "--yesnocancel", text,
              "--yes-label", yes_label,
              "--no-label", no_label,
              "--cancel-label", cancel_label,
              (char *)NULL);
        _exit(127);
    }

    /* Parent-only: the child never reaches here (it execs or exits), so
     * logging before the branch would double-log and stamp the journal
     * with a second, confusing fileshield[pid]. */
    log_msg(LOG_DEBUG, "[dialog] forked kdialog child pid=%d", (int)pid);

    log_msg(LOG_DEBUG, "[dialog] parent waiting for kdialog (pid=%d)", (int)pid);
    int child_exited = 0;
    int status = 0;
    long long deadline = now_ms() + DIALOG_OUTER_TIMEOUT_S * 1000;

    while (!child_exited && now_ms() < deadline)
    {
        if (!g_running || g_fatal)
        {
            /* Shutdown while a dialog is open: stop waiting so the daemon
             * terminates promptly (bounded shutdown latency). */
            log_msg(LOG_WARNING,
                    "[dialog] shutdown while a dialog is open; denying it");
            break;
        }

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
            /* Do not leak the child: it may still be on screen, and an
             * unreaped zombie would linger. */
            kill_and_reap(pid, &status, &child_exited);
            return -1;
        }
    }

    if (!child_exited)
    {
        log_msg(LOG_WARNING,
                "[dialog] kdialog timeout or shutdown, killing pid=%d",
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
        return 1; /* No click, or a runtime error: see the comment above */
    if (ec == 2)
        return 2; /* Cancel / window close / Escape */
    return -1;
}

const char *notify_decision_name(int decision)
{
    switch (decision)
    {
    case NOTIFY_ALLOW_ONCE:
        return "Allow Once";
    case NOTIFY_ALLOW_SESSION:
        return "Allow Session";
    case NOTIFY_ALLOW_ALWAYS:
        return "Allow Always";
    case NOTIFY_DENY_SESSION:
        return "Deny Session";
    case NOTIFY_DENY_ALWAYS:
        return "Deny Always";
    case NOTIFY_DENY:
        return "Deny";
    default:
        return "Unknown";
    }
}

/*
 * Sanitized, bounded copies of the requester fields, safe to place in a
 * dialog: control characters cannot forge extra lines.
 */
typedef struct
{
    char comm[64];
    char pcomm[64];
    char cmd[256];
    char exe[512];
    char path[512];
    char note[280]; /* hash-unavailable note; empty when the hash is known */
} PromptText;

/*
 * Stage 2 after "Allow": pick the grant scope.  Returns a NOTIFY_* code.
 *
 * Button mapping (as specified): Yes = Allow Session, No = Allow Always,
 * Cancel = deny this attempt.  kdialog returns 1 both for a deliberate No
 * and for some runtime errors, so a dialog that fails with exit 1 can
 * create a permanent rule; timeouts (124), exec failures (127) and
 * Cancel/window close (2) all deny, and the trade-off is documented in
 * the README.  "Allow Session" matches the POSIX session + this binary
 * (+ its SHA-512) + this exact file, so the body spells that out rather
 * than implying the file is unlocked for everyone.
 */
static int ask_grant_scope(const DisplaySession *session,
                           const DialogEnvSetting *env, int env_count,
                           const PromptText *t, pid_t pid, int session_ttl)
{
    char body[3072];
    char session_bullet[160];

    if (session_ttl > 0)
        snprintf(session_bullet, sizeof(session_bullet),
                 "\xe2\x80\xa2 Allow Session \xe2\x80\x94 this binary and file "
                 "for up to %d seconds", session_ttl);
    else
        snprintf(session_bullet, sizeof(session_bullet),
                 "\xe2\x80\xa2 Allow Session \xe2\x80\x94 this binary and file "
                 "until this session ends");

    snprintf(body, sizeof(body),
             "Allow access to:\n"
             "%s\n\n"
             "Requested by: %s (PID %d)\n"
             "Binary:   %s\n"
             "Command:  %s\n\n"
             "%s\n"
             "\xe2\x80\xa2 Allow Always \xe2\x80\x94 this file, this command and "
             "its call chain, permanently\n"
             "\xe2\x80\xa2 Deny         \xe2\x80\x94 deny this time%s",
             t->path, t->comm, (int)pid, t->exe, t->cmd, session_bullet,
             t->note);

    int r = run_kdialog(session, env, env_count, body,
                            "Allow Session", "Allow Always", "Deny");
    if (r == 0)
        return NOTIFY_ALLOW_SESSION;
    if (r == 1)
        return NOTIFY_ALLOW_ALWAYS;
    return NOTIFY_DENY; /* Cancel, window close or failure */
}

/*
 * Stage 2 after an explicit "Deny": pick the deny scope.  Returns a
 * NOTIFY_* code; Yes = Deny Session, No = Deny Always, Cancel = deny
 * once.  Denial is always the safe direction, so any failure denies.
 */
static int ask_deny_scope(const DisplaySession *session,
                          const DialogEnvSetting *env, int env_count,
                          const PromptText *t, pid_t pid, int session_ttl)
{
    char body[2048];
    char session_bullet[160];

    if (session_ttl > 0)
        snprintf(session_bullet, sizeof(session_bullet),
                 "\xe2\x80\xa2 Deny Session \xe2\x80\x94 this binary and file "
                 "for up to %d seconds", session_ttl);
    else
        snprintf(session_bullet, sizeof(session_bullet),
                 "\xe2\x80\xa2 Deny Session \xe2\x80\x94 this binary and file "
                 "until this session ends");

    snprintf(body, sizeof(body),
             "Deny access to:\n"
             "%s\n\n"
             "Requested by: %s (PID %d)\n"
             "Binary:   %s\n"
             "Command:  %s\n\n"
             "%s\n"
             "\xe2\x80\xa2 Deny Always \xe2\x80\x94 this file, this command and "
             "its call chain, permanently\n"
             "\xe2\x80\xa2 Deny Once   \xe2\x80\x94 block this attempt",
             t->path, t->comm, (int)pid, t->exe, t->cmd, session_bullet);

    int r = run_kdialog(session, env, env_count, body,
                            "Deny Session", "Deny Always", "Deny Once");
    if (r == 0)
        return NOTIFY_DENY_SESSION;
    if (r == 1)
        return NOTIFY_DENY_ALWAYS;
    return NOTIFY_DENY;
}

int notify_ask(const NotifyRequest *req)
{
    /* Return values: NOTIFY_ALLOW_ONCE, NOTIFY_DENY,
     *                NOTIFY_ALLOW_SESSION, NOTIFY_DENY_SESSION,
     *                NOTIFY_ALLOW_ALWAYS, NOTIFY_DENY_ALWAYS. */
    if (!req)
        return NOTIFY_DENY;

    PromptText t;
    char msg[3072];
    char once_bullet[160];

    /* Attacker-controlled strings (file names, comm, cmdline) are
     * sanitized so control characters cannot forge dialog content. */
    sanitize_text(req->comm, t.comm, sizeof(t.comm));
    sanitize_text(req->comm_parent, t.pcomm, sizeof(t.pcomm));
    sanitize_ellipsized(req->exe && req->exe[0] != '\0' ? req->exe : "(unknown)",
                        t.exe, sizeof(t.exe));
    sanitize_ellipsized(req->path, t.path, sizeof(t.path));
    sanitize_ellipsized(req->cmdline && req->cmdline[0] != '\0'
                            ? req->cmdline
                            : "(unknown)",
                        t.cmd, sizeof(t.cmd));

    /* An unavailable digest cannot back a persistent grant: say so before
     * the user picks, and point at the deliberate escape hatch.  The
     * reason string is daemon-generated (sha512.c), never requester text. */
    t.note[0] = '\0';
    if (req->hash_unavailable)
        snprintf(t.note, sizeof(t.note),
                 "\n\nNote: the binary SHA-512 is unavailable (%s). "
                 "\"Allow Always\" cannot persist for this binary - add it "
                 "to [unsafe_allowlist] in fileshield.conf if it needs a "
                 "permanent grant.",
                 req->hash_failure && req->hash_failure[0] != '\0'
                     ? req->hash_failure
                     : "hashing failed");

    /* "Allow once" is keyed by PID + binary + file for user_ttl. */
    if (req->user_ttl > 0)
        snprintf(once_bullet, sizeof(once_bullet),
                 "\xe2\x80\xa2 Allow Once \xe2\x80\x94 this file for %d seconds "
                 "(this process)", req->user_ttl);
    else
        snprintf(once_bullet, sizeof(once_bullet),
                 "\xe2\x80\xa2 Allow Once \xe2\x80\x94 this file (this process)");

    /* Stage 1: everything known about the requester and the access, plus
     * what each button does.  No grant is bound to a non-Yes outcome:
     * "Allow..." only opens the scope dialog, and a failed dialog denies. */
    snprintf(msg, sizeof(msg),
             "Process %s (PID %d, parent: %s (PID %d)) wants to read:\n"
             "%s\n\n"
             "Binary:   %s\n"
             "Command:  %s\n\n"
             "%s\n"
             "\xe2\x80\xa2 Allow      \xe2\x80\x94 choose session or permanent "
             "access\n"
             "\xe2\x80\xa2 Deny       \xe2\x80\x94 choose this time, session or "
             "permanent%s",
             t.comm, (int)req->pid, t.pcomm, (int)req->ppid,
             t.path, t.exe, t.cmd, once_bullet, t.note);

    /* Auto-detect the active graphical session if env vars are not set.
     * The daemon itself is never modified: the session is applied by the
     * dialog child, per prompt. */
    DisplaySession session;
    int have_session = detect_display_session(req->user_uid, &session);
    log_msg(LOG_DEBUG,
            "[notify_ask] session: uid=%d wayland=%s display=%s",
            (int)session.uid,
            session.wayland_display[0] ? session.wayland_display : "(none)",
            session.display[0] ? session.display : "(none)");

    /* Never run a security prompt as a root GUI process. */
    if (getuid() == 0 && !have_session)
    {
        log_msg(LOG_ERR,
                "no non-root desktop session found; denying access to %s",
                t.path);
        return NOTIFY_DENY;
    }

    /* Forward the user's theme/font/scale/locale environment so kdialog
     * renders like the rest of their desktop. */
    DialogEnvSetting dialog_env[DIALOG_ENV_MAX];
    int dialog_env_count = collect_dialog_env(req->pid, dialog_env,
                                              DIALOG_ENV_MAX);
    log_msg(LOG_DEBUG, "[dialog] forwarding %d session variables",
            dialog_env_count);

    int r = run_kdialog(&session, dialog_env, dialog_env_count, msg,
                            "Allow Once", "Allow\xe2\x80\xa6",
                            "Deny\xe2\x80\xa6");
    if (r == 0)
        return NOTIFY_ALLOW_ONCE;
    if (r == 1)
        return ask_grant_scope(&session, dialog_env, dialog_env_count, &t,
                               req->pid, req->session_ttl);
    if (r == 2)
        return ask_deny_scope(&session, dialog_env, dialog_env_count, &t,
                              req->pid, req->session_ttl);

    log_msg(LOG_WARNING, "[dialog] no valid kdialog choice; denying once");
    return NOTIFY_DENY;
}

/*
 * Prompt for a changed [allowlist] binary hash.  One decision only:
 * Yes = "Update & Allow" (the caller persists new_hash and grants the
 * access), No/Cancel/window close/timeout/failure = deny this attempt
 * with the old pin kept.  The two-stage grant flow is deliberately not
 * involved: the change already names one rule, one binary and one file.
 *
 * Rate limiting is the caller's job (see notify.h): the pipeline must
 * reject dialog_rate_limited() binaries before calling so a tampered
 * binary cannot flood prompts.
 */
int notify_ask_hash_change(const NotifyHashChange *req)
{
    if (!req)
        return NOTIFY_DENY;

    char rule[512];
    char exe[512];
    char cmd[256];
    char path[512];
    char old_hash[64];
    char new_hash[64];
    char body[4096];

    /* Sanitized, bounded copies: even the rule pattern and the digests
     * are treated as untrusted so control characters cannot forge dialog
     * lines. */
    sanitize_text(req->rule_pattern, rule, sizeof(rule));
    sanitize_ellipsized(req->exe && req->exe[0] != '\0' ? req->exe : "(unknown)",
                        exe, sizeof(exe));
    sanitize_ellipsized(req->path, path, sizeof(path));
    sanitize_ellipsized(req->cmdline && req->cmdline[0] != '\0'
                            ? req->cmdline
                            : "(unknown)",
                        cmd, sizeof(cmd));
    sanitize_text(req->old_hash && req->old_hash[0] != '\0' ? req->old_hash
                                                            : "(unknown)",
                  old_hash, sizeof(old_hash));
    sanitize_text(req->new_hash && req->new_hash[0] != '\0' ? req->new_hash
                                                            : "(unknown)",
                  new_hash, sizeof(new_hash));

    /* Full digests are journal-logged by the caller; the prompt shows
     * only the 16-hex prefixes a human can compare at a glance. */
    snprintf(body, sizeof(body),
             "SHA-512 changed for allowlist rule:\n"
             "%s\n\n"
             "Binary:   %s\n"
             "Target:   %s\n"
             "Command:  %s\n\n"
             "Old SHA-512: %.16s\xe2\x80\xa6\n"
             "New SHA-512: %.16s\xe2\x80\xa6\n\n"
             "Update & Allow trusts the new binary and records the new "
             "hash.\n"
             "Deny / Cancel blocks this attempt and keeps the old hash.",
             rule, exe, path, cmd, old_hash, new_hash);

    DisplaySession session;
    int have_session = detect_display_session(req->user_uid, &session);
    log_msg(LOG_DEBUG,
            "[notify_hash_change] session: uid=%d wayland=%s display=%s",
            (int)session.uid,
            session.wayland_display[0] ? session.wayland_display : "(none)",
            session.display[0] ? session.display : "(none)");

    /* Never run a security prompt as a root GUI process. */
    if (getuid() == 0 && !have_session)
    {
        log_msg(LOG_ERR,
                "no non-root desktop session found; denying hash update "
                "for %s",
                exe);
        return NOTIFY_DENY;
    }

    /* Cosmetic session variables only, same whitelist as notify_ask(). */
    DialogEnvSetting dialog_env[DIALOG_ENV_MAX];
    int dialog_env_count = collect_dialog_env(req->pid, dialog_env,
                                              DIALOG_ENV_MAX);
    log_msg(LOG_DEBUG, "[dialog] forwarding %d session variables",
            dialog_env_count);

    int r = run_kdialog(&session, dialog_env, dialog_env_count, body,
                        "Update & Allow", "Deny", "Cancel");
    if (r == 0)
    {
        log_msg(LOG_WARNING,
                "hash change approved for allowlist rule %s (%s); "
                "new hash pinned by caller",
                rule, exe);
        return NOTIFY_ALLOW_ALWAYS;
    }

    log_msg(LOG_WARNING,
            "hash change denied for allowlist rule %s (%s); old pin kept",
            rule, exe);
    return NOTIFY_DENY;
}

/* ------------------------------------------------------------------ */
/*  config-rule desktop notifications (notify-send)                    */
/* ------------------------------------------------------------------ */
/*
 * Bounded, spoof-proof tripwire for config-rule hits.  An attacker can
 * trigger these notifications, so flood control is mandatory: identical
 * (kind, binary, target) hits are deduplicated for the configured window,
 * and a global cap bounds a stream of distinct keys.  Both counters are
 * best-effort side channels, never inputs to the access decision.
 */
#define NOTIFY_DEDUP_MAX 128
/* Defensive fallback only: the effective cap comes from [settings] notify_max. */
#define NOTIFY_GLOBAL_MAX NOTIFY_MAX_DEFAULT
#define NOTIFY_GLOBAL_WINDOW_S 60
#define NOTIFY_SEND_PATH "/usr/bin/notify-send"

typedef struct
{
    int kind;
    char binary[PATH_MAX];
    char target[PATH_MAX];
    time_t last;
} NotifyDedupEntry;

static NotifyDedupEntry g_notify_dedup[NOTIFY_DEDUP_MAX];
static int g_notify_dedup_count = 0;
static int g_notify_dedup_next = 0;

static int g_notify_window_count = 0;
static time_t g_notify_window_start = 0;
static int g_notify_window_logged = 0;

static int g_notify_send_checked = 0;
static int g_notify_send_ok = 0;

/* 1 = this hit may be delivered (and is counted / remembered). */
static int notify_rate_allow(int kind, const char *binary, const char *target,
                             int dedup_seconds, int max_per_window)
{
    time_t now = time(NULL);
    int cap = max_per_window > 0 ? max_per_window : NOTIFY_GLOBAL_MAX;

    if (now - g_notify_window_start >= NOTIFY_GLOBAL_WINDOW_S)
    {
        g_notify_window_start = now;
        g_notify_window_count = 0;
        g_notify_window_logged = 0;
    }

    if (g_notify_window_count >= cap)
    {
        if (!g_notify_window_logged)
        {
            log_msg(LOG_WARNING,
                    "notification flood: more than %d in %ds; suppressing "
                    "further rule notifications for the window",
                    cap, NOTIFY_GLOBAL_WINDOW_S);
            g_notify_window_logged = 1;
        }
        return 0;
    }

    /*
     * Unsafe hits are gated once per process by the caller, so the
     * per-key window must not suppress a *different* process using the
     * same rule; the global cap below still bounds any burst.
     */
    if (kind != NOTIFY_HIT_UNSAFE && dedup_seconds > 0)
    {
        for (int i = 0; i < g_notify_dedup_count; i++)
        {
            NotifyDedupEntry *e = &g_notify_dedup[i];
            if (e->kind == kind && strcmp(e->binary, binary) == 0 &&
                strcmp(e->target, target) == 0)
            {
                if (now - e->last < dedup_seconds)
                    return 0;
                e->last = now;
                g_notify_window_count++;
                return 1;
            }
        }

        int slot;
        if (g_notify_dedup_count < NOTIFY_DEDUP_MAX)
            slot = g_notify_dedup_count++;
        else
        {
            slot = g_notify_dedup_next;
            g_notify_dedup_next = (g_notify_dedup_next + 1) % NOTIFY_DEDUP_MAX;
        }
        NotifyDedupEntry *e = &g_notify_dedup[slot];
        memset(e, 0, sizeof(*e));
        e->kind = kind;
        snprintf(e->binary, sizeof(e->binary), "%s", binary);
        snprintf(e->target, sizeof(e->target), "%s", target);
        e->last = now;
    }

    g_notify_window_count++;
    return 1;
}

void notify_rule_hit(const NotifyHit *hit)
{
    char title[128];
    char rule[512], bin[512], comm[64], target[512];
    char body[2048];
    const char *urgency;
    const char *icon;

    if (!hit || hit->uid == (uid_t)-1 || hit->uid == 0)
        return;

    /* Availability first: a missing notify-send must not spend the dedup
     * or flood budget on notifications that are never shown. */
    if (!g_notify_send_ok)
    {
        g_notify_send_ok = access(NOTIFY_SEND_PATH, X_OK) == 0;
        if (!g_notify_send_ok)
        {
            if (!g_notify_send_checked)
            {
                g_notify_send_checked = 1;
                log_msg(LOG_WARNING,
                        "notify_rule_hit: %s not found; rule notifications "
                        "disabled (see README)",
                        NOTIFY_SEND_PATH);
            }
            return;
        }
    }

    /* Deliverability before budget: a uid with no desktop session must
     * not spend the dedup or flood budget (the global cap is shared by
     * every user) on notifications that are never shown. */
    DisplaySession session;
    if (!detect_display_session(hit->uid, &session))
    {
        log_msg(LOG_DEBUG,
                "notify_rule_hit: no desktop session for uid %d; "
                "notification skipped",
                (int)hit->uid);
        return;
    }

    if (!notify_rate_allow(hit->kind, hit->binary ? hit->binary : "",
                           hit->target ? hit->target : "",
                           hit->dedup_seconds, hit->max_per_window))
        return;

    /* Per-field sanitation: newlines inside fields must not forge lines. */
    sanitize_text(hit->rule ? hit->rule : "(unknown)", rule, sizeof(rule));
    sanitize_text(hit->binary ? hit->binary : "(unknown)", bin, sizeof(bin));
    sanitize_text(hit->comm ? hit->comm : "", comm, sizeof(comm));
    sanitize_text(hit->target ? hit->target : "(unknown)", target,
                  sizeof(target));

    if (hit->kind == NOTIFY_HIT_UNSAFE)
    {
        /* notify-send only knows low/normal/critical urgency: a warning
         * is normal urgency with the warning icon, so it stands out
         * without the persistence of a critical notification. */
        snprintf(title, sizeof(title),
                 "Fileshield: unsafe allowlist rule used");
        urgency = "normal";
        icon = "dialog-warning";
    }
    else if (hit->kind == NOTIFY_HIT_DENY)
    {
        snprintf(title, sizeof(title),
                 "Fileshield: denylist blocked an access");
        urgency = "critical";
        icon = "security-high";
    }
    else
    {
        snprintf(title, sizeof(title), "Fileshield: allowlist rule used");
        urgency = "normal";
        icon = "dialog-information";
    }

    snprintf(body, sizeof(body),
             "rule:   %s\nbinary: %s (pid %d%s%s)\ntarget: %s",
             rule, bin, (int)hit->pid, comm[0] != '\0' ? ", " : "", comm,
             target);

    /*
     * Double fork: the grandchild is reparented to init and delivers the
     * notification, the intermediate exits immediately, and the daemon
     * only reaps the intermediate (no zombie, no event-loop stall).
     */
    pid_t pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_WARNING, "notify_rule_hit: fork failed: %m");
        return;
    }

    if (pid == 0)
    {
        pid_t g = fork();
        if (g < 0)
            _exit(127);
        if (g > 0)
            _exit(0);

        setsid();
        drop_to_session_user(&session);
        apply_display_env(&session);
        close_fds_from(3);
        execl(NOTIFY_SEND_PATH, "notify-send", "-a", "Fileshield",
              "-u", urgency, "-i", icon, title, body, (char *)NULL);
        _exit(127);
    }

    /* Bounded reap: the intermediate exits immediately in practice, but
     * the single-threaded event loop must never block on it. */
    int st = 0;
    int reaped = 0;
    for (int i = 0; i < 100; i++) /* up to ~1 s */
    {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid)
        {
            reaped = 1;
            break;
        }
        if (w < 0 && errno != EINTR)
        {
            log_msg(LOG_WARNING, "notify_rule_hit: waitpid: %m");
            return;
        }
        usleep(10000);
    }
    if (!reaped)
    {
        log_msg(LOG_WARNING,
                "notify_rule_hit: intermediate %d did not exit; killing it",
                (int)pid);
        kill(pid, SIGKILL);
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
            ;
    }
    /* A 127 exit means exec failed: notify-send may have been removed
     * since the cached check.  Drop the flag so the next hit re-checks
     * instead of paying a doomed double fork forever. */
    if (WIFEXITED(st) && WEXITSTATUS(st) == 127)
        g_notify_send_ok = 0;
}

int notify_test_hit_rate(int kind, const char *binary, const char *target,
                         int dedup_seconds, int max_per_window)
{
    return notify_rate_allow(kind, binary ? binary : "",
                             target ? target : "", dedup_seconds,
                             max_per_window);
}

void notify_test_reset_rate(void)
{
    memset(g_notify_dedup, 0, sizeof(g_notify_dedup));
    g_notify_dedup_count = 0;
    g_notify_dedup_next = 0;
    g_notify_window_count = 0;
    g_notify_window_start = 0;
    g_notify_window_logged = 0;
}
