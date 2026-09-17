#include "control.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include "fanotify.h"
#include "pin.h"
#include "session.h"
#include "utils.h"

/*
 * Server half of the control protocol (see control.h and
 * control_client.h): the root-only listener, request parsing and the
 * dispatch into the mutation modules.  The JSON field encoder is shared
 * with fileshield-cli through control_client.c, so this file never
 * duplicates the escaping convention.
 */

/*
 * The session snapshot mirrors session.c's table capacity (256).  A
 * SessionRecord is PATH_MAX-sized twice over, so a full-size stack array
 * is not an option; single-threaded access makes one static scratch
 * buffer safe and keeps the daemon allocation-free.
 */
#define CONTROL_SESSION_MAX 256

/* Connections served per readable event; a connection storm must not
 * starve the fanotify queue. */
#define CONTROL_ACCEPT_MAX 8

/* Source bytes escaped per chunk.  A 32-byte chunk expands to at most
 * 192 bytes of JSON plus the NUL, so the scratch stays tiny while a
 * PATH_MAX-sized field is streamed chunk by chunk. */
#define CONTROL_ESCAPE_CHUNK 32

/*
 * Path bound by the last successful control_setup_at().  teardown()
 * unlinks exactly this, so it can never unlink a caller-supplied or
 * never-bound path (unlink(2) on a socket fails harmlessly for a bound
 * one, but the type/owner checks must stay in setup).
 */
static char g_bound_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

/* ------------------------------------------------------------------ */
/* Request parsing                                                    */
/* ------------------------------------------------------------------ */

/*
 * Per-verb argument shape.  Argument indices exclude the verb: list_arg
 * is the argument holding the list selector (-1 = none) and first_id the
 * first argument holding an ID (-1 = none); every ID argument is filled
 * into ControlRequest.ids in order.
 */
typedef struct
{
    const char *name;
    ControlVerb verb;
    int min_args;
    int max_args;
    int list_arg;
    int first_id;
    int list_both; /* the list selector also accepts "both" */
} ControlVerbSpec;

static const ControlVerbSpec g_verb_specs[] = {
    {"PING", CONTROL_PING, 0, 0, -1, -1, 0},
    {"RELOAD", CONTROL_RELOAD, 0, 0, -1, -1, 0},
    {"SESSION_LIST", CONTROL_SESSION_LIST, 1, 1, 0, -1, 0},
    {"SESSION_REMOVE", CONTROL_SESSION_REMOVE, 2, 2, 0, 1, 0},
    {"SESSION_CLEAR", CONTROL_SESSION_CLEAR, 1, 1, 0, -1, 1},
    {"RULE_REMOVE", CONTROL_RULE_REMOVE, 2, 1 + CONTROL_MAX_IDS, 0, 1, 0},
    {"RULE_CLEAR", CONTROL_RULE_CLEAR, 1, 1, 0, -1, 0},
    {"PRUNE", CONTROL_PRUNE, 1, 1, 0, -1, 1},
    {"PIN_REMOVE", CONTROL_PIN_REMOVE, 1, CONTROL_MAX_IDS, -1, 0, 0},
    {"PIN_CLEAR", CONTROL_PIN_CLEAR, 0, 0, -1, -1, 0},
};

int control_request_parse(char *line, ControlRequest *out)
{
    const char *fields[CONTROL_MAX_IDS + 2]; /* verb + list + 16 IDs */
    const ControlVerbSpec *spec = NULL;
    char *p;
    int n = 0;
    int args;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->list = -1;
    out->error = "invalid request";
    if (!line)
        return -1;

    /* Split on TAB in place; the line was already stripped of its
     * newline by the caller. */
    p = line;
    for (;;)
    {
        char *tab;

        if (n == (int)(sizeof(fields) / sizeof(fields[0])))
        {
            out->error = "too many arguments";
            return -1;
        }
        fields[n++] = p;
        tab = strchr(p, '\t');
        if (!tab)
            break;
        *tab = '\0';
        p = tab + 1;
    }

    for (size_t i = 0; i < sizeof(g_verb_specs) / sizeof(g_verb_specs[0]); i++)
    {
        if (strcmp(fields[0], g_verb_specs[i].name) == 0)
        {
            spec = &g_verb_specs[i];
            break;
        }
    }
    if (!spec)
    {
        out->error = "unknown command";
        return -1;
    }

    args = n - 1;
    if (args < spec->min_args)
    {
        out->error = "missing argument";
        return -1;
    }
    if (args > spec->max_args)
    {
        out->error = "too many arguments";
        return -1;
    }

    if (spec->list_arg >= 0)
    {
        const char *value = fields[1 + spec->list_arg];

        if (strcmp(value, "allow") == 0)
            out->list = 0;
        else if (strcmp(value, "deny") == 0)
            out->list = 1;
        else if (spec->list_both && strcmp(value, "both") == 0)
            out->list = -1;
        else
        {
            out->error = "invalid list";
            return -1;
        }
    }

    /* Publish the verb only once every check passed: a failed parse
     * always reports CONTROL_VERB_INVALID. */
    out->verb = spec->verb;

    if (spec->first_id >= 0)
    {
        for (int i = spec->first_id; i < args; i++)
            out->ids[out->id_count++] = fields[1 + i];
    }

    out->error = NULL;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Response writing                                                   */
/* ------------------------------------------------------------------ */

/*
 * Write every byte or fail.  The response fd is non-blocking: EAGAIN
 * means the client stopped reading, and the daemon must abandon the
 * response rather than wait for it.  MSG_NOSIGNAL keeps a vanished peer
 * from raising SIGPIPE.  EINTR is the one retryable condition.
 */
static int write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len)
    {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

/* "OK\n<lines>\n": <lines> is the number of payload lines that follow. */
static int reply_header(int fd, int lines)
{
    char hdr[32];
    int n = snprintf(hdr, sizeof(hdr), "OK\n%d\n", lines);

    if (n < 0 || (size_t)n >= sizeof(hdr))
        return -1;
    return write_all(fd, hdr, (size_t)n);
}

/* "ERR\n<message>\n".  message must be a single line without newlines. */
static int reply_err(int fd, const char *message)
{
    if (write_all(fd, "ERR\n", 4) < 0)
        return -1;
    if (message && message[0] != '\0' &&
        write_all(fd, message, strlen(message)) < 0)
        return -1;
    return write_all(fd, "\n", 1);
}

/* OK with one payload line holding a decimal result. */
static int reply_scalar(int fd, long value)
{
    char line[32];
    int n = snprintf(line, sizeof(line), "%ld\n", value);

    if (n < 0 || (size_t)n >= sizeof(line))
        return -1;
    if (reply_header(fd, 1) < 0)
        return -1;
    return write_all(fd, line, (size_t)n);
}

/*
 * Stream one JSON-escaped field.  The escape is applied in small chunks
 * so the scratch buffer stays bounded regardless of the field length
 * (paths can be PATH_MAX-sized and expand sixfold).  Splitting a UTF-8
 * sequence across chunks is harmless: control_encode_field() only
 * rewrites bytes below 0x20, so multi-byte sequences pass through
 * unchanged.
 */
static int write_escaped_field(int fd, const char *src)
{
    char out[CONTROL_ESCAPE_CHUNK * 6 + 8];
    char piece[CONTROL_ESCAPE_CHUNK + 1];

    if (!src)
        return -1;

    while (*src != '\0')
    {
        size_t take = 0;
        int n;

        while (take < CONTROL_ESCAPE_CHUNK && src[take] != '\0')
            take++;
        memcpy(piece, src, take);
        piece[take] = '\0';

        n = control_encode_field(piece, out, sizeof(out));
        if (n < 0 || write_all(fd, out, (size_t)n) < 0)
            return -1;
        src += take;
    }
    return 0;
}

/* Copy an untrusted token for an ERR line, replacing control bytes that
 * would break the one-line shape. */
static void scrub_token(const char *src, char *dst, size_t dst_size)
{
    size_t j = 0;

    if (dst_size == 0)
        return;
    if (src)
    {
        for (; *src != '\0' && j + 1 < dst_size; src++)
        {
            unsigned char c = (unsigned char)*src;
            dst[j++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
        }
    }
    dst[j] = '\0';
}

/*
 * "ERR\nremoved N of M: <reason> <id>\n" -- the partial-removal error a
 * multi-ID RULE_REMOVE / PIN_REMOVE reports.  Entries removed before the
 * failing ID stay removed (the user confirmed them), so the count is the
 * actionable part of the message.
 */
static int reply_partial_error(int fd, int removed, int total,
                               const char *reason, const char *id)
{
    char msg[512];
    char safe[64];
    int n;

    scrub_token(id, safe, sizeof(safe));
    n = snprintf(msg, sizeof(msg), "removed %d of %d: %s %s", removed, total,
                 reason, safe);
    if (n < 0 || (size_t)n >= sizeof(msg))
        return reply_err(fd, "request failed");
    return reply_err(fd, msg);
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                           */
/* ------------------------------------------------------------------ */

static int dispatch_session_list(int fd, int deny)
{
    /* One snapshot buffer for all connections; the daemon is
     * single-threaded and control_handle never re-enters. */
    static SessionRecord records[CONTROL_SESSION_MAX];
    int total = 0;
    int n = session_snapshot(deny, records, CONTROL_SESSION_MAX, &total);

    if (n < 0)
        return reply_err(fd, "cannot snapshot session rules");
    /* The snapshot capacity mirrors the table, so a short read means the
     * two constants drifted apart; refuse rather than list silently
     * incomplete state. */
    if (total > n)
        return reply_err(fd, "session table too large for one snapshot");
    if (reply_header(fd, n) < 0)
        return -1;

    for (int i = 0; i < n; i++)
    {
        const SessionRecord *rec = &records[i];
        char sid[16];
        char start[32];
        char ttl[16];
        const char *fields[6];
        int w;

        w = snprintf(sid, sizeof(sid), "%ld", (long)rec->sid);
        if (w < 0 || (size_t)w >= sizeof(sid))
            return -1;
        w = snprintf(start, sizeof(start), "%llu", rec->leader_start);
        if (w < 0 || (size_t)w >= sizeof(start))
            return -1;
        w = snprintf(ttl, sizeof(ttl), "%ld", rec->ttl_remaining);
        if (w < 0 || (size_t)w >= sizeof(ttl))
            return -1;

        fields[0] = rec->rule_id;
        fields[1] = sid;
        fields[2] = start;
        fields[3] = rec->binary;
        fields[4] = rec->target;
        fields[5] = ttl;

        for (int f = 0; f < 6; f++)
        {
            char sep = (f == 5) ? '\n' : '\t';

            if (write_escaped_field(fd, fields[f]) < 0)
                return -1;
            if (write_all(fd, &sep, 1) < 0)
                return -1;
        }
    }
    return 0;
}

static int dispatch_session_remove(int fd, int deny, const char *id)
{
    int rc = session_remove_by_id(deny, id);

    if (rc == 1)
        return reply_header(fd, 0);
    if (rc == 0)
        return reply_err(fd, "no matching session rule");
    if (rc == -2)
        return reply_err(fd, "ambiguous rule ID");
    return reply_err(fd, "invalid rule ID or daemon refusal");
}

static int dispatch_session_clear(int fd, int list)
{
    if (list < 0)
        session_clear();
    else
        session_clear_list(list);
    log_msg(LOG_INFO, "control: session %s rules cleared",
            list < 0 ? "allow and deny" : (list ? "deny" : "allow"));
    return reply_header(fd, 0);
}

static int dispatch_rule_remove(int fd, int deny, const char *const *ids,
                                int id_count)
{
    int removed = 0;

    for (int i = 0; i < id_count; i++)
    {
        int rc = fanotify_remove_dyn_entry(deny, ids[i]);

        if (rc == 1)
        {
            removed++;
            continue;
        }
        if (rc == 0)
            return reply_partial_error(fd, removed, id_count,
                                       "no rule matches", ids[i]);
        if (rc == -2)
            return reply_partial_error(fd, removed, id_count,
                                       "ambiguous rule ID", ids[i]);
        return reply_partial_error(fd, removed, id_count,
                                   "invalid rule ID or write failure", ids[i]);
    }
    return reply_scalar(fd, removed);
}

static int dispatch_rule_clear(int fd, int deny)
{
    int removed = fanotify_clear_dyn_list(deny);

    if (removed < 0)
        return reply_err(fd, "failed to clear rules (state file write failed)");
    return reply_scalar(fd, removed);
}

static int dispatch_prune(int fd, int list)
{
    int total = 0;
    int removed = 0;

    if (list != 1) /* allow: selected alone (0) or together with deny (-1) */
    {
        if (fanotify_prune_dyn_list(0, &removed) < 0)
            return reply_err(fd, "failed to prune always-allow rules");
        total += removed;
    }
    if (list != 0) /* deny: selected alone (1) or together with allow (-1) */
    {
        removed = 0;
        if (fanotify_prune_dyn_list(1, &removed) < 0)
        {
            /* A both-list request may already have pruned the allow side;
             * say so rather than reporting a blanket failure. */
            if (list == -1 && total > 0)
            {
                char msg[96];

                snprintf(msg, sizeof(msg),
                         "pruned %d always-allow rule(s), then failed to "
                         "prune always-deny rules",
                         total);
                return reply_err(fd, msg);
            }
            return reply_err(fd, "failed to prune always-deny rules");
        }
        total += removed;
    }
    return reply_scalar(fd, total);
}

static int dispatch_pin_remove(int fd, const char *const *ids, int id_count)
{
    int removed = 0;

    for (int i = 0; i < id_count; i++)
    {
        int rc = pin_remove_by_id(ids[i]);

        if (rc == 1)
        {
            removed++;
            continue;
        }
        if (rc == 0)
            return reply_partial_error(fd, removed, id_count,
                                       "no pin matches", ids[i]);
        if (rc == -2)
            return reply_partial_error(fd, removed, id_count,
                                       "ambiguous pin ID", ids[i]);
        return reply_partial_error(fd, removed, id_count,
                                   "invalid pin ID or write failure", ids[i]);
    }
    return reply_scalar(fd, removed);
}

static int dispatch_pin_clear(int fd)
{
    if (pin_clear() < 0)
        return reply_err(fd,
                         "failed to clear pins (damaged or unwritable state file)");
    return reply_header(fd, 0);
}

static int dispatch(int fd, const ControlRequest *req)
{
    switch (req->verb)
    {
    case CONTROL_PING:
        return reply_header(fd, 0);

    case CONTROL_RELOAD:
        g_need_reload = 1;
        log_msg(LOG_INFO, "control: config reload requested");
        return reply_header(fd, 0);

    case CONTROL_SESSION_LIST:
        return dispatch_session_list(fd, req->list);

    case CONTROL_SESSION_REMOVE:
        return dispatch_session_remove(fd, req->list, req->ids[0]);

    case CONTROL_SESSION_CLEAR:
        return dispatch_session_clear(fd, req->list);

    case CONTROL_RULE_REMOVE:
        return dispatch_rule_remove(fd, req->list, req->ids, req->id_count);

    case CONTROL_RULE_CLEAR:
        return dispatch_rule_clear(fd, req->list);

    case CONTROL_PRUNE:
        return dispatch_prune(fd, req->list);

    case CONTROL_PIN_REMOVE:
        return dispatch_pin_remove(fd, req->ids, req->id_count);

    case CONTROL_PIN_CLEAR:
        return dispatch_pin_clear(fd);

    default:
        return reply_err(fd, "invalid request");
    }
}

/* ------------------------------------------------------------------ */
/* Socket lifecycle                                                   */
/* ------------------------------------------------------------------ */

int control_setup_at(const char *path)
{
    struct sockaddr_un addr;
    struct stat st;
    mode_t old_mask;
    size_t path_len;
    int fd;

    /* g_bound_path is deliberately NOT cleared here: a failed call (for
     * example the live-listener refusal) must not make a later
     * control_teardown() of a still-live listener forget the path it
     * owns.  A successful bind overwrites it below. */
    if (!path || path[0] == '\0')
    {
        log_msg(LOG_ERR, "control: empty socket path");
        return -1;
    }
    path_len = strlen(path);
    if (path_len >= sizeof(addr.sun_path))
    {
        log_msg(LOG_ERR, "control: socket path too long");
        return -1;
    }

    /* Never displace an object that is not our own stale socket: a
     * regular file, directory or symlink at the path belongs to an
     * administrator or an attacker, not to a crashed daemon. */
    if (lstat(path, &st) == 0)
    {
        if (!S_ISSOCK(st.st_mode))
        {
            log_msg(LOG_ERR,
                    "control: %s exists and is not a socket; refusing", path);
            return -1;
        }
        if (st.st_uid != geteuid())
        {
            log_msg(LOG_ERR,
                    "control: stale socket %s is owned by uid %u, not %u; "
                    "refusing",
                    path, (unsigned)st.st_uid, (unsigned)geteuid());
            return -1;
        }

        /* A socket we own may still have a live listener: a second
         * daemon must not silently take over the path, because the CLI
         * would then manage a process whose in-memory lists are not the
         * ones enforcing.  Probe with a non-blocking connect: refused or
         * absent means stale; a successful connect (or any other errno,
         * including a full backlog) means a listener and startup fails
         * closed. */
        {
            int probe = socket(AF_UNIX,
                               SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
            struct sockaddr_un paddr;
            int prc;
            int saved;

            if (probe < 0)
            {
                log_msg(LOG_ERR, "control: probe socket: %s", strerror(errno));
                return -1;
            }
            memset(&paddr, 0, sizeof(paddr));
            paddr.sun_family = AF_UNIX;
            memcpy(paddr.sun_path, path, path_len + 1);
            prc = connect(probe, (struct sockaddr *)&paddr, sizeof(paddr));
            saved = errno;
            close(probe);
            errno = saved;
            if (prc == 0 || (errno != ECONNREFUSED && errno != ENOENT))
            {
                log_msg(LOG_ERR,
                        "control: another daemon is already listening on %s; "
                        "refusing to take over",
                        path);
                return -1;
            }
        }

        if (unlink(path) < 0)
        {
            log_msg(LOG_ERR, "control: cannot remove stale socket %s: %s",
                    path, strerror(errno));
            return -1;
        }
    }
    else if (errno != ENOENT)
    {
        log_msg(LOG_ERR, "control: cannot stat %s: %s", path, strerror(errno));
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
    {
        log_msg(LOG_ERR, "control: socket: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, path_len + 1);

    /* Bind under umask 0077 so the socket is never briefly world- or
     * group-accessible before the explicit chmod; restore the process
     * mask even when bind fails. */
    old_mask = umask(0077);
    {
        int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
        int saved = errno;
        umask(old_mask);
        errno = saved;
        if (rc < 0)
        {
            log_msg(LOG_ERR, "control: bind %s: %s", path, strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (chmod(path, 0600) < 0)
    {
        log_msg(LOG_ERR, "control: chmod %s: %s", path, strerror(errno));
        unlink(path);
        close(fd);
        return -1;
    }

    if (listen(fd, 8) < 0)
    {
        log_msg(LOG_ERR, "control: listen %s: %s", path, strerror(errno));
        unlink(path);
        close(fd);
        return -1;
    }

    /* The pre-check above proved this fits. */
    memcpy(g_bound_path, path, path_len + 1);
    log_msg(LOG_INFO, "control: listening on %s", g_bound_path);
    return fd;
}

int control_setup(void)
{
    return control_setup_at(CONTROL_SOCKET_PATH);
}

void control_teardown(int fd)
{
    if (fd >= 0)
        close(fd);
    if (g_bound_path[0] != '\0')
    {
        unlink(g_bound_path);
        g_bound_path[0] = '\0';
    }
}

void control_handle(int listen_fd)
{
    for (int i = 0; i < CONTROL_ACCEPT_MAX; i++)
    {
        int fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);

        if (fd < 0)
        {
            if (errno == EINTR)
                continue; /* retry inside the same accept budget */
            if (errno != EAGAIN && errno != EWOULDBLOCK &&
                errno != ECONNABORTED)
                log_msg(LOG_WARNING, "control: accept: %s", strerror(errno));
            break;
        }
        control_handle_client(fd);
    }
}

int control_handle_client(int fd)
{
    char line[CONTROL_REQ_MAX];
    ControlRequest req;
    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    char *nl;
    ssize_t n;
    int flags;

    if (fd < 0)
        return -1;

    /* Non-blocking from the first instruction: no later read or write
     * may ever wait for this client. */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        close(fd);
        return -1;
    }

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0 ||
        cred_len != sizeof(cred))
    {
        close(fd);
        return -1;
    }
    if (cred.uid != geteuid())
    {
        log_msg(LOG_WARNING, "control: rejected client uid %u (expected %u)",
                (unsigned)cred.uid, (unsigned)geteuid());
        close(fd);
        return 0;
    }

    do
    {
        n = read(fd, line, sizeof(line) - 1);
    } while (n < 0 && errno == EINTR);

    if (n <= 0)
    {
        close(fd); /* EAGAIN: connected but silent; never wait */
        return 0;
    }
    if (memchr(line, '\0', (size_t)n) != NULL)
    {
        close(fd); /* a request line cannot carry NUL bytes */
        return 0;
    }
    nl = memchr(line, '\n', (size_t)n);
    if (!nl)
    {
        close(fd); /* partial or oversized: the CLI writes one whole line */
        return 0;
    }
    *nl = '\0';

    if (control_request_parse(line, &req) < 0)
    {
        reply_err(fd, req.error ? req.error : "invalid request");
        close(fd);
        return 0;
    }

    /* A failed response write only means the client went away; there is
     * nothing left to report and nothing to clean up beyond the close. */
    (void)dispatch(fd, &req);
    close(fd);
    return 0;
}
