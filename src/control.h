#ifndef FILESHIELD_CONTROL_H
#define FILESHIELD_CONTROL_H

#include <stddef.h>

/*
 * control: root-only control socket and bounded line protocol.
 *
 * fileshield-cli manages the daemon's runtime state through an AF_UNIX
 * stream socket at CONTROL_SOCKET_PATH.  The daemon creates the socket
 * 0600 (owned by its effective uid -- root in production), accepts at
 * most a handful of connections per poll wake, and checks SO_PEERCRED:
 * a peer whose uid differs from geteuid() is closed without a response.
 *
 * The protocol is deliberately fail closed and non-blocking on the
 * server side:
 *
 *   request:   VERB[\tARG]...\n
 *              One TAB-separated line.  Free-text arguments would be
 *              JSON-escaped with control_encode_field() (the current
 *              verbs carry only IDs and list names, which are raw);
 *              IDs and list names are never escaped.
 *
 *   response:  OK\n<count>\n          followed by exactly <count>
 *              <payload line>\n ...   payload lines, each '\n'-ended
 *   or         ERR\n<message>\n       with no payload lines
 *
 * The client reads to EOF: after writing the single response the server
 * closes the connection.  <count> is the number of payload lines, never a
 * command result, and control_response_parse() rejects a mismatch.
 *
 * SESSION_LIST is the only verb that enumerates: it sends one payload
 * line per live session entry with the TAB-separated, JSON-escaped
 * fields rule_id, sid, leader_start, binary, target and ttl_remaining.
 * Verbs with a scalar result (RULE_REMOVE, RULE_CLEAR, PRUNE,
 * PIN_REMOVE) report it as their single payload line, so their response
 * is OK\n1\n<number>\n; control_response_scalar() reads it back.
 *
 * Never trust a response line to be small: payload fields can hold
 * PATH_MAX-sized, escape-expanded paths, so the server streams every
 * field with a bounded write loop instead of building a response-sized
 * buffer.
 */

/* Root-owned socket the daemon listens on. */
#define CONTROL_SOCKET_PATH "/run/fileshield.sock"

/*
 * Maximum request size, including the terminating newline (one bounded
 * read attempt reads up to CONTROL_REQ_MAX - 1 bytes).  A request that
 * does not fit, or that arrives without a newline, is closed without a
 * response: the CLI writes its single line up front.
 */
#define CONTROL_REQ_MAX 4096

/* Maximum number of IDs in one RULE_REMOVE / PIN_REMOVE request. */
#define CONTROL_MAX_IDS 16

/* Maximum payload lines one response may carry (mirrors session.c's
 * 256-entry table; also the bound of ControlResponse.lines). */
#define CONTROL_PAYLOAD_MAX 256

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

/*
 * Parsed response.  message/lines point into the response text, which is
 * modified in place ('\n' becomes '\0') and must stay alive while the
 * struct is used.  On success count == the number of valid lines[].
 */
typedef struct
{
    int ok;                 /* 1 = OK, 0 = ERR                          */
    int count;              /* payload lines (OK only)                  */
    const char *message;    /* ERR message (pointer into the text)      */
    char *lines[CONTROL_PAYLOAD_MAX]; /* payload lines into the text    */
} ControlResponse;

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

/* ------------------------------------------------------------------ */
/* Pure codec functions (no I/O; unit-testable)                       */
/* ------------------------------------------------------------------ */

/*
 * JSON-escape one field into dst (bounded, NUL-terminated), exactly the
 * persist_json_escape() encoding: quotes, backslashes and control bytes.
 * Returns the bytes written (without the NUL) or -1 when src/dst is NULL
 * or the result does not fit.
 */
int control_encode_field(const char *src, char *dst, size_t dst_size);

/*
 * Decode one control_encode_field() field: \" \\ \/ \b \f \n \r \t and
 * \uXXXX (UTF-8 encoded; surrogate pairs are combined, lone surrogates
 * and unknown escapes are rejected).  Raw control bytes inside the
 * value, a NUL code point (\u0000) and a result that does not fit are
 * errors.  Returns the decoded length or -1.
 */
int control_decode_field(const char *src, char *dst, size_t dst_size);

/*
 * Parse one request line in place (TABs become NULs).  The line must be
 * NUL-terminated and must NOT include the trailing newline (the server
 * strips it).  Returns 0 on success, -1 on a malformed request (unknown
 * verb, missing/extra arguments, bad list name, too many IDs); on
 * failure out->verb is CONTROL_VERB_INVALID and out->error names a
 * static reason.
 */
int control_request_parse(char *line, ControlRequest *out);

/*
 * Parse a whole response text of 'len' bytes in place.  text must be
 * writable; it needs no NUL terminator (the parser works within len).
 * On success exactly one of the OK or ERR shapes was found and every
 * declared payload line was present (no more, no less).  Returns 0 on
 * success, -1 on any malformed or truncated response.
 */
int control_response_parse(char *text, size_t len, ControlResponse *out);

/*
 * Scalar result of the verbs that report one (RULE_REMOVE, RULE_CLEAR,
 * PRUNE, PIN_REMOVE): the decimal value of the single payload line.
 * Returns -1 when the response is not OK with exactly one numeric line
 * (an ERR, an empty payload or a non-numeric line).
 */
long control_response_scalar(const ControlResponse *resp);

/* ------------------------------------------------------------------ */
/* Client helper for fileshield-cli                                   */
/* ------------------------------------------------------------------ */

/*
 * Send one request and read the whole response.
 *
 * Connects to sock_path (AF_UNIX), writes 'request' plus the terminating
 * newline (pass the line WITHOUT one), half-closes the write side and
 * reads to EOF into resp_buf (always NUL-terminated).  A response that
 * would not fit in resp_size bytes (including the NUL) is a failure, not
 * a truncation.  No retries: the caller decides what an unreachable
 * daemon means.
 *
 * Returns 0 when a complete response was read and parsed into out, -1 on
 * any transport failure, a too-large response or a malformed response.
 * errno is preserved across the internal close so the caller can
 * distinguish ENOENT/ECONNREFUSED (no listener) from EACCES and friends.
 *
 * One request per call; a caller that prefers per-ID requests simply
 * loops, while the multi-ID request forms (RULE_REMOVE / PIN_REMOVE) let
 * it remove several entries with one round trip.
 */
int control_client_call(const char *sock_path, const char *request,
                        char *resp_buf, size_t resp_size,
                        ControlResponse *out);

#endif /* FILESHIELD_CONTROL_H */
