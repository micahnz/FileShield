#ifndef FILESHIELD_CONTROL_H
#define FILESHIELD_CONTROL_H

#include "control_client.h"

/*
 * control: server half of the control socket -- the root-only listener,
 * the bounded request parser and the dispatch into the mutation modules.
 *
 * The client half (wire constants, ControlResponse, the JSON field
 * codec, response parsing and control_client_call()) lives in
 * control_client.h, which this header includes so one include still
 * provides the full API to the daemon and to test_control.  Unlike the
 * client half, this half links the daemon's state modules and may be
 * used only inside the daemon.
 *
 * The daemon creates the socket 0600 (owned by its effective uid -- root
 * in production), accepts at most a handful of connections per poll
 * wake, and checks SO_PEERCRED: a peer whose uid differs from geteuid()
 * is closed without a response.  A request is one bounded, non-blocking
 * read; a slow client is never waited for.  See control_client.h for the
 * request/response wire format.
 */

/*
 * Request verbs.  CONTROL_VERB_INVALID is never a valid request; the
 * parser sets it together with ControlRequest.error.
 */
typedef enum
{
    CONTROL_VERB_INVALID = 0,
    CONTROL_PING,           /* no arguments                            */
    CONTROL_RELOAD,         /* no arguments                            */
    CONTROL_SESSION_LIST,   /* <allow|deny>                            */
    CONTROL_SESSION_REMOVE, /* <allow|deny> <id>                       */
    CONTROL_SESSION_CLEAR,  /* <allow|deny|both>                       */
    CONTROL_RULE_REMOVE,    /* <allow|deny> <id>...    (up to 16)      */
    CONTROL_RULE_CLEAR,     /* <allow|deny>                            */
    CONTROL_PRUNE,          /* <allow|deny|both>                       */
    CONTROL_PIN_REMOVE,     /* <id>...                 (up to 16)      */
    CONTROL_PIN_CLEAR       /* no arguments                            */
} ControlVerb;

/*
 * Parsed request.  ids[] point into the caller's (mutable) line buffer,
 * which control_request_parse() splits in place; they stay valid until
 * that buffer is reused.  On a parse failure verb is
 * CONTROL_VERB_INVALID and error is a static reason string; on success
 * error is NULL.
 */
typedef struct
{
    ControlVerb verb;
    int list;          /* 0 = allow, 1 = deny, -1 = both / not applicable */
    int id_count;      /* 0..CONTROL_MAX_IDS entries in ids[]             */
    const char *ids[CONTROL_MAX_IDS];
    const char *error; /* static reason when verb == CONTROL_VERB_INVALID */
} ControlRequest;

/* ------------------------------------------------------------------ */
/* Server lifecycle                                                   */
/* ------------------------------------------------------------------ */

/*
 * Create the control socket at CONTROL_SOCKET_PATH and return the
 * non-blocking listening fd, or -1 (already logged) on failure:
 *   - a path that exists but is not a socket owned by geteuid() is
 *     refused and never unlinked (a regular file or symlink at the path
 *     is an administrator's or an attacker's object, not ours);
 *   - a stale socket owned by us is unlinked first;
 *   - bind/chmod/listen failures close the fd and fail.
 * The socket is bound under umask 0077 and chmodded to 0600.
 */
int control_setup(void);

/*
 * Test seam: same as control_setup() with an explicit path, so the
 * unprivileged suite can exercise stale-socket cleanup, the type/owner
 * refusal and the socket mode in a temp directory.  Production uses
 * control_setup().
 */
int control_setup_at(const char *path);

/*
 * Close 'fd' and unlink the path the last successful setup bound
 * (g_bound_path).  Errors are ignored: teardown runs on shutdown paths
 * where there is nothing left to report to.  A never-bound process
 * unlinks nothing.
 */
void control_teardown(int fd);

/*
 * Accept and serve pending connections on the listening fd.  Called by
 * the daemon's poll loop when the fd is readable.  Accepts at most 8
 * connections per call (accept4, so each serves one request and closes),
 * then returns: a connection storm must not starve the fanotify queue.
 */
void control_handle(int listen_fd);

/*
 * Serve one accepted connection and close it.
 *
 * The fd is made non-blocking immediately, the peer uid is verified
 * against geteuid() (mismatch: LOG_WARNING, close, no response), and
 * exactly ONE bounded read is attempted.  A request without a newline, a
 * partial or oversized one, an EAGAIN, or a NUL byte in the line closes
 * the connection without a response -- a slow or stuck client can never
 * block the single-threaded daemon.  A parsed request is dispatched and
 * the response written; a write that would block (EAGAIN) abandons the
 * response and closes, so the client sees a truncated response and
 * reports a transport failure instead of holding the daemon.
 *
 * Returns 0 when the client was handled (including rejected/dropped),
 * -1 on an internal failure (bad fd, fcntl/getsockopt error).
 */
int control_handle_client(int fd);

/*
 * Parse one request line in place (TABs become NULs).  The line must be
 * NUL-terminated and must NOT include the trailing newline (the server
 * strips it).  Returns 0 on success, -1 on a malformed request (unknown
 * verb, missing/extra arguments, bad list name, too many IDs); on
 * failure out->verb is CONTROL_VERB_INVALID and out->error names a
 * static reason.
 */
int control_request_parse(char *line, ControlRequest *out);

#endif /* FILESHIELD_CONTROL_H */
