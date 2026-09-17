/*
 * test_control: the control socket protocol and dispatch.
 *
 * All tests run unprivileged.  The pure codec functions are exercised
 * directly; the server side runs over socketpair(AF_UNIX) so the real
 * control_handle_client() path is used without /run or root (the
 * SO_PEERCRED check passes because the socketpair peer is this process).
 * A control_setup_at() test seam covers the socket lifecycle in a temp
 * directory; control_client_call() is tested against a canned fork()
 * server so the connect/send/read-to-EOF path is real.
 *
 * Tests link the real mutation modules: the dispatch assertions check
 * the fanotify/session/pin APIs' side effects, not just response text.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/control.h"
#include "../src/fanotify.h"
#include "../src/persist.h"
#include "../src/pin.h"
#include "../src/ruleid.h"
#include "../src/session.h"
#include "../src/utils.h"

/* Globals referenced by fanotify.c/control.c (normally defined in main.c). */
volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;
volatile sig_atomic_t g_fatal = 0;

static int failures = 0;
static char g_tmp[256];

#define ASSERT(cond, msg)                       \
    do                                          \
    {                                           \
        if (!(cond))                            \
        {                                       \
            fprintf(stderr, "FAIL: %s\n", msg); \
            failures++;                         \
        }                                       \
    } while (0)

/* 128 hex characters: the digest fields are pass-through strings here. */
#define TEST_SHA_A                                                             \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"         \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define TEST_SHA_B                                                             \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"         \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

/* ------------------------------------------------------------------ */
/* Harness helpers                                                    */
/* ------------------------------------------------------------------ */

static int write_all_fd(int fd, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len)
    {
        ssize_t n = write(fd, buf + off, len - off);
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

/* Copy 'path' into addr->sun_path; 0 when it fits, -1 otherwise. */
static int fill_sun_path(struct sockaddr_un *addr, const char *path)
{
    size_t len = strlen(path);

    if (len >= sizeof(addr->sun_path))
        return -1;
    memcpy(addr->sun_path, path, len + 1);
    return 0;
}

/*
 * Send 'request' bytes over a socketpair, serve it with the real handler
 * and read the raw response to EOF.  A receive timeout turns a handler
 * bug (leaving the peer open) into a failed assertion instead of a hung
 * suite.  Any request that carries no newline is closed by the handler
 * without a response, so resp ends up empty -- which is exactly what the
 * slow-client tests assert.
 */
static void run_request_bytes(const char *request, size_t len, int shutdown_write,
                              char *resp, size_t resp_size)
{
    int sv[2];
    struct timeval tv;
    int sndbuf = 65536;
    size_t used = 0;
    ssize_t n;

    if (resp_size == 0)
        return;
    resp[0] = '\0';

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    {
        fprintf(stderr, "FAIL: socketpair\n");
        failures++;
        return;
    }
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    (void)setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    /* The over-long request is written before the handler runs; make sure
     * the peer buffer takes it without blocking. */
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    if (write_all_fd(sv[0], request, len) < 0)
    {
        fprintf(stderr, "FAIL: write request\n");
        failures++;
        close(sv[0]);
        close(sv[1]);
        return;
    }
    if (shutdown_write)
        (void)shutdown(sv[0], SHUT_WR);

    if (control_handle_client(sv[1]) != 0)
    {
        fprintf(stderr, "FAIL: control_handle_client returned nonzero\n");
        failures++;
    }

    while (used + 1 < resp_size)
    {
        n = read(sv[0], resp + used, resp_size - 1 - used);
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    resp[used] = '\0';
    close(sv[0]);
}

static void run_request(const char *request, char *resp, size_t resp_size)
{
    run_request_bytes(request, strlen(request), 0, resp, resp_size);
}

/* Split a NUL-terminated line on TABs in place; returns the field count. */
static int split_tabs(char *line, char *fields[], int max)
{
    int n = 0;
    char *p = line;

    while (n < max)
    {
        char *tab;

        fields[n++] = p;
        tab = strchr(p, '\t');
        if (!tab)
            break;
        *tab = '\0';
        p = tab + 1;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* Field codec                                                        */
/* ------------------------------------------------------------------ */

static void test_field_codec(void)
{
    static const char *const cases[] = {
        "",
        "plain",
        "quote\" backslash\\ slash/",
        "line\nbreak\ttab\rreturn",
        "\b\f",
        "\x01\x1f control",
        "utf8 caf\xc3\xa9",
        "0123456789abcdef0123456789abcdef",
    };
    char enc[512];
    char dec[512];

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        int en = control_encode_field(cases[i], enc, sizeof(enc));
        int dn = -1;

        ASSERT(en >= 0, "encode case");
        if (en >= 0)
        {
            dn = control_decode_field(enc, dec, sizeof(dec));
            ASSERT(dn >= 0, "decode case");
        }
        if (dn >= 0)
            ASSERT(strcmp(dec, cases[i]) == 0, "field roundtrip");
    }

    ASSERT(control_encode_field("a\tb\nc", enc, sizeof(enc)) > 0,
           "encode escapes");
    ASSERT(strchr(enc, '\t') == NULL, "no raw tab in escaped field");
    ASSERT(strchr(enc, '\n') == NULL, "no raw newline in escaped field");
    ASSERT(strstr(enc, "\\t") != NULL && strstr(enc, "\\n") != NULL,
           "escape sequences present");

    ASSERT(control_encode_field("aaaa", dec, 2) == -1, "encode too small");
    ASSERT(control_decode_field("aaaa", dec, 4) == -1, "decode too small");
    ASSERT(control_encode_field(NULL, dec, sizeof(dec)) == -1, "encode NULL src");
}

static void test_field_decode_errors(void)
{
    char out[64];

    ASSERT(control_decode_field("\\q", out, sizeof(out)) == -1,
           "unknown escape rejected");
    ASSERT(control_decode_field("abc\\", out, sizeof(out)) == -1,
           "trailing backslash rejected");
    ASSERT(control_decode_field("\\u12", out, sizeof(out)) == -1,
           "short \\u escape rejected");
    ASSERT(control_decode_field("\\u12g4", out, sizeof(out)) == -1,
           "bad hex in \\u escape rejected");
    ASSERT(control_decode_field("\\u0000", out, sizeof(out)) == -1,
           "NUL code point rejected");
    ASSERT(control_decode_field("\\ud800", out, sizeof(out)) == -1,
           "lone high surrogate rejected");
    ASSERT(control_decode_field("\\udc00", out, sizeof(out)) == -1,
           "lone low surrogate rejected");
    ASSERT(control_decode_field("\\ud800x", out, sizeof(out)) == -1,
           "high surrogate without low half rejected");
    ASSERT(control_decode_field("\\ud800\\u0041", out, sizeof(out)) == -1,
           "high surrogate with non-low half rejected");
    ASSERT(control_decode_field("\x01", out, sizeof(out)) == -1,
           "raw control byte rejected");

    {
        int n = control_decode_field("\\ud83d\\ude00", out, sizeof(out));

        ASSERT(n == 4, "surrogate pair decodes");
        if (n == 4)
            ASSERT(memcmp(out, "\xF0\x9F\x98\x80", 4) == 0,
                   "surrogate pair is U+1F600");
    }

    {
        int n = control_decode_field("\\u001f", out, sizeof(out));

        ASSERT(n == 1, "escaped control decodes");
        if (n == 1)
            ASSERT(out[0] == 0x1f, "escaped control value");
    }

    ASSERT(control_decode_field(NULL, out, sizeof(out)) == -1,
           "NULL src rejected");
    ASSERT(control_decode_field("x", NULL, 0) == -1, "NULL dst rejected");
}

/* ------------------------------------------------------------------ */
/* Request parsing                                                    */
/* ------------------------------------------------------------------ */

static void test_request_parse_ok(void)
{
    char line[1024];
    ControlRequest req;

    snprintf(line, sizeof(line), "PING");
    ASSERT(control_request_parse(line, &req) == 0, "parse PING");
    ASSERT(req.verb == CONTROL_PING, "PING verb");
    ASSERT(req.id_count == 0 && req.list == -1, "PING takes no arguments");
    ASSERT(req.error == NULL, "success clears the parse error");

    snprintf(line, sizeof(line), "RELOAD");
    ASSERT(control_request_parse(line, &req) == 0 &&
               req.verb == CONTROL_RELOAD,
           "parse RELOAD");

    snprintf(line, sizeof(line), "SESSION_LIST\tallow");
    ASSERT(control_request_parse(line, &req) == 0, "parse SESSION_LIST");
    ASSERT(req.verb == CONTROL_SESSION_LIST && req.list == 0,
           "SESSION_LIST allow");

    snprintf(line, sizeof(line), "SESSION_REMOVE\tdeny\t01234567");
    ASSERT(control_request_parse(line, &req) == 0, "parse SESSION_REMOVE");
    ASSERT(req.verb == CONTROL_SESSION_REMOVE && req.list == 1,
           "SESSION_REMOVE deny");
    ASSERT(req.id_count == 1 && strcmp(req.ids[0], "01234567") == 0,
           "SESSION_REMOVE id");

    snprintf(line, sizeof(line), "SESSION_CLEAR\tboth");
    ASSERT(control_request_parse(line, &req) == 0, "parse SESSION_CLEAR");
    ASSERT(req.verb == CONTROL_SESSION_CLEAR && req.list == -1,
           "SESSION_CLEAR both");

    snprintf(line, sizeof(line), "RULE_REMOVE\tallow\taaaaaaaa\tbbbbbbbb");
    ASSERT(control_request_parse(line, &req) == 0, "parse RULE_REMOVE");
    ASSERT(req.verb == CONTROL_RULE_REMOVE && req.id_count == 2,
           "RULE_REMOVE ids");
    ASSERT(strcmp(req.ids[0], "aaaaaaaa") == 0 &&
               strcmp(req.ids[1], "bbbbbbbb") == 0,
           "RULE_REMOVE id values");

    snprintf(line, sizeof(line), "RULE_CLEAR\tdeny");
    ASSERT(control_request_parse(line, &req) == 0 &&
               req.verb == CONTROL_RULE_CLEAR && req.list == 1,
           "parse RULE_CLEAR");

    snprintf(line, sizeof(line), "PRUNE\tboth");
    ASSERT(control_request_parse(line, &req) == 0 &&
               req.verb == CONTROL_PRUNE && req.list == -1,
           "parse PRUNE both");

    snprintf(line, sizeof(line), "PIN_REMOVE\taaaaaaaa");
    ASSERT(control_request_parse(line, &req) == 0 &&
               req.verb == CONTROL_PIN_REMOVE && req.id_count == 1,
           "parse PIN_REMOVE");

    snprintf(line, sizeof(line), "PIN_CLEAR");
    ASSERT(control_request_parse(line, &req) == 0 &&
               req.verb == CONTROL_PIN_CLEAR && req.id_count == 0,
           "parse PIN_CLEAR");

    /* The maximum ID count is accepted for a multi-ID verb. */
    {
        size_t off = (size_t)snprintf(line, sizeof(line), "PIN_REMOVE");

        for (int i = 0; i < CONTROL_MAX_IDS; i++)
            off += (size_t)snprintf(line + off, sizeof(line) - off, "\t%08x",
                                    (unsigned)i);
        ASSERT(control_request_parse(line, &req) == 0,
               "parse 16 PIN_REMOVE ids");
        ASSERT(req.id_count == CONTROL_MAX_IDS, "16 ids parsed");
        ASSERT(strcmp(req.ids[0], "00000000") == 0 &&
                   strcmp(req.ids[15], "0000000f") == 0,
               "id values");
    }
}

static void test_request_parse_errors(void)
{
    char line[1024];
    ControlRequest req;

    line[0] = '\0';
    ASSERT(control_request_parse(line, &req) == -1, "empty request rejected");
    ASSERT(req.verb == CONTROL_VERB_INVALID && req.error != NULL,
           "parse error set");

    snprintf(line, sizeof(line), "FROBNICATE");
    ASSERT(control_request_parse(line, &req) == -1, "unknown verb rejected");

    snprintf(line, sizeof(line), "ping");
    ASSERT(control_request_parse(line, &req) == -1,
           "verbs are case-sensitive");

    snprintf(line, sizeof(line), "PING\textra");
    ASSERT(control_request_parse(line, &req) == -1,
           "extra argument rejected");

    snprintf(line, sizeof(line), "PING\t");
    ASSERT(control_request_parse(line, &req) == -1, "trailing tab rejected");

    snprintf(line, sizeof(line), "SESSION_LIST");
    ASSERT(control_request_parse(line, &req) == -1, "missing list rejected");

    snprintf(line, sizeof(line), "SESSION_LIST\tall");
    ASSERT(control_request_parse(line, &req) == -1, "bad list name rejected");
    ASSERT(req.verb == CONTROL_VERB_INVALID, "bad list leaves verb invalid");

    snprintf(line, sizeof(line), "SESSION_CLEAR\tsideways");
    ASSERT(control_request_parse(line, &req) == -1,
           "bad both-list name rejected");

    snprintf(line, sizeof(line), "RULE_REMOVE\tallow");
    ASSERT(control_request_parse(line, &req) == -1, "missing id rejected");

    snprintf(line, sizeof(line), "RULE_REMOVE\tboth\taaaaaaaa");
    ASSERT(control_request_parse(line, &req) == -1,
           "rules never accept both");

    /* 17 IDs exceed CONTROL_MAX_IDS. */
    {
        size_t off = (size_t)snprintf(line, sizeof(line), "PIN_REMOVE");

        for (int i = 0; i <= CONTROL_MAX_IDS; i++)
            off += (size_t)snprintf(line + off, sizeof(line) - off, "\t%08x",
                                    (unsigned)i);
        ASSERT(control_request_parse(line, &req) == -1, "too many ids rejected");
        ASSERT(req.error != NULL && strcmp(req.error, "too many arguments") == 0,
               "too-many error reason");
    }

    ASSERT(control_request_parse(NULL, &req) == -1, "NULL line rejected");
    ASSERT(control_request_parse(line, NULL) == -1, "NULL out rejected");
}

/* ------------------------------------------------------------------ */
/* Response parsing                                                   */
/* ------------------------------------------------------------------ */

static void test_response_parse(void)
{
    char buf[512];
    ControlResponse r;

    strcpy(buf, "OK\n0\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == 0, "parse OK 0");
    ASSERT(r.ok == 1 && r.count == 0, "OK 0 fields");

    strcpy(buf, "OK\n2\na\tb\nc\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == 0, "parse OK 2");
    ASSERT(r.ok == 1 && r.count == 2, "OK 2 count");
    if (r.ok == 1 && r.count == 2)
        ASSERT(strcmp(r.lines[0], "a\tb") == 0 && strcmp(r.lines[1], "c") == 0,
               "OK payload lines");

    strcpy(buf, "OK\n2\nonly\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "short payload rejected");
    strcpy(buf, "OK\n1\nx\ny\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "trailing data rejected");
    strcpy(buf, "OK\n1\nx");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "unterminated payload rejected");
    strcpy(buf, "OK\nx\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "non-numeric count rejected");
    strcpy(buf, "OK\n257\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "count over payload max rejected");
    strcpy(buf, "OK\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "missing count rejected");
    strcpy(buf, "OK\n0\njunk");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "trailing bytes rejected");

    strcpy(buf, "ERR\nno matching session rule\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == 0, "parse ERR");
    ASSERT(r.ok == 0 && r.count == 0, "ERR fields");
    if (r.message != NULL)
        ASSERT(strcmp(r.message, "no matching session rule") == 0,
               "ERR message");

    strcpy(buf, "ERR\nmessage");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "ERR without newline rejected");
    strcpy(buf, "ERR\nmsg\nextra\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "ERR trailing data rejected");
    strcpy(buf, "garbage\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == -1,
           "garbage rejected");
    ASSERT(control_response_parse(buf, 0, &r) == -1, "empty text rejected");

    strcpy(buf, "OK\n1\n42\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == 0, "parse scalar");
    ASSERT(control_response_scalar(&r) == 42, "scalar 42");

    strcpy(buf, "OK\n0\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == 0, "parse OK 0 again");
    ASSERT(control_response_scalar(&r) == -1, "scalar requires one line");

    strcpy(buf, "ERR\nx\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == 0, "parse ERR again");
    ASSERT(control_response_scalar(&r) == -1, "no scalar on ERR");

    strcpy(buf, "OK\n1\n4x\n");
    ASSERT(control_response_parse(buf, strlen(buf), &r) == 0, "parse non-numeric");
    ASSERT(control_response_scalar(&r) == -1, "non-numeric scalar rejected");
}

/* ------------------------------------------------------------------ */
/* Socketpair dispatch: basics                                        */
/* ------------------------------------------------------------------ */

static void test_ping_reload(void)
{
    char resp[128];

    run_request("PING\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n0\n") == 0, "PING -> OK 0");

    g_need_reload = 0;
    run_request("RELOAD\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n0\n") == 0, "RELOAD -> OK 0");
    ASSERT(g_need_reload == 1, "RELOAD sets g_need_reload");
    g_need_reload = 0;
}

static void test_bad_requests(void)
{
    char resp[256];

    run_request("FROBNICATE\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "ERR\nunknown command\n") == 0,
           "unknown verb -> ERR");

    run_request("SESSION_LIST\tsideways\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "ERR\ninvalid list\n") == 0, "bad list -> ERR");

    run_request("SESSION_REMOVE\tallow\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "ERR\nmissing argument\n") == 0, "missing arg -> ERR");

    run_request("PING\tx\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "ERR\ntoo many arguments\n") == 0, "extra arg -> ERR");
}

/*
 * A slow or partial client must never make control_handle_client() wait:
 * it makes exactly one bounded read attempt and closes.
 */
static void test_slow_clients(void)
{
    char resp[128];

    /* Nothing written: the handler sees EAGAIN and closes. */
    {
        int sv[2];
        struct timeval tv = {2, 0};
        ssize_t n;

        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        (void)setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ASSERT(control_handle_client(sv[1]) == 0, "silent client handled");
        n = read(sv[0], resp, sizeof(resp));
        ASSERT(n == 0, "silent client gets no response");
        close(sv[0]);
    }

    /* Partial line, writer gone: no newline, no response, no wait. */
    run_request_bytes("PIN", 3, 1, resp, sizeof(resp));
    ASSERT(resp[0] == '\0', "partial request gets no response");

    /* An invalid fd is an internal failure, not a client rejection. */
    ASSERT(control_handle_client(-1) == -1, "bad fd is an internal failure");

    /* NUL byte inside the line. */
    run_request_bytes("PING\0junk\n", 10, 0, resp, sizeof(resp));
    ASSERT(resp[0] == '\0', "NUL in request gets no response");

    /* Over-long line: the newline lies past the bounded read. */
    {
        char big[CONTROL_REQ_MAX + 256];

        memset(big, 'A', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\n';
        run_request_bytes(big, sizeof(big), 0, resp, sizeof(resp));
        ASSERT(resp[0] == '\0', "over-long request gets no response");
    }

    /* A line whose newline is exactly at the read cap is still read. */
    {
        char fits[CONTROL_REQ_MAX];

        memset(fits, 'X', sizeof(fits));
        memcpy(fits, "PING\t", 5);
        fits[sizeof(fits) - 2] = '\n';
        fits[sizeof(fits) - 1] = '\0';
        run_request_bytes(fits, sizeof(fits) - 1, 0, resp, sizeof(resp));
        ASSERT(strcmp(resp, "ERR\ntoo many arguments\n") == 0,
               "request at the size cap is read");
    }
}

/* ------------------------------------------------------------------ */
/* Rule dispatch (fanotify dynamic lists)                             */
/* ------------------------------------------------------------------ */

static void make_entry(PersistEntry *e, const char *rule_id, const char *target,
                       long created_at)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->rule_id, sizeof(e->rule_id), "%s", rule_id);
    snprintf(e->binary, sizeof(e->binary), "%s", "/usr/bin/demo");
    snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", TEST_SHA_A);
    snprintf(e->target_path, sizeof(e->target_path), "%s", target);
    snprintf(e->cmdline, sizeof(e->cmdline), "%s", "demo --flag");
    snprintf(e->cmdline_sha512, sizeof(e->cmdline_sha512), "%s", TEST_SHA_B);
    e->chain_depth = 0;
    e->created_at = created_at;
}

static int allow_matches(const PersistEntry *e)
{
    return fanotify_test_dyn_allow_match(e->binary, e->binary_sha512,
                                         e->target_path, e->cmdline_sha512);
}

static int deny_matches(const PersistEntry *e)
{
    return fanotify_test_dyn_deny_match(e->binary, e->binary_sha512,
                                        e->target_path, e->cmdline_sha512);
}

static void test_rule_dispatch(void)
{
    char allow_path[PATH_MAX];
    char deny_path[PATH_MAX];
    PersistEntry entries[2];
    PersistEntry deny_entry;
    char resp[512];

    snprintf(allow_path, sizeof(allow_path), "%s/allow.json", g_tmp);
    snprintf(deny_path, sizeof(deny_path), "%s/deny.json", g_tmp);
    unlink(allow_path);
    unlink(deny_path);
    fanotify_set_state_files(allow_path, deny_path);
    fanotify_load_dyn_allowlist(NULL, 0);
    fanotify_load_dyn_denylist(NULL, 0);

    make_entry(&entries[0], "0123456789abcdef", "/home/u/secret-a", 1700000000);
    make_entry(&entries[1], "fedcba9876543210", "/home/u/secret-b", 1700000001);
    fanotify_load_dyn_allowlist(entries, 2);
    ASSERT(allow_matches(&entries[0]) == 1, "allow fixture matches");

    run_request("RULE_REMOVE\tallow\t01234567\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n1\n1\n") == 0, "RULE_REMOVE reports the count");
    ASSERT(allow_matches(&entries[0]) == 0, "removed rule no longer matches");
    ASSERT(allow_matches(&entries[1]) == 1, "other rule untouched");

    run_request("RULE_REMOVE\tallow\t01234567\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "ERR\nremoved 0 of 1: no rule matches 01234567\n") == 0,
           "no-match error message");

    run_request("RULE_REMOVE\tallow\tzz\n", resp, sizeof(resp));
    ASSERT(strncmp(resp, "ERR\n", 4) == 0 &&
               strstr(resp, "invalid rule ID") != NULL,
           "invalid ID error");

    /* Partial removal: the first ID is confirmed by the user and stays
     * removed when a later ID fails. */
    fanotify_load_dyn_allowlist(entries, 2);
    run_request("RULE_REMOVE\tallow\t01234567\tffffffff\n", resp, sizeof(resp));
    ASSERT(strncmp(resp, "ERR\nremoved 1 of 2:", 19) == 0,
           "partial removal error");
    ASSERT(allow_matches(&entries[0]) == 0, "confirmed removal kept");
    ASSERT(allow_matches(&entries[1]) == 1, "later rule not touched");

    run_request("RULE_CLEAR\tallow\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n1\n1\n") == 0, "RULE_CLEAR reports the count");
    ASSERT(allow_matches(&entries[1]) == 0, "clear emptied the list");
    run_request("RULE_CLEAR\tallow\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n1\n0\n") == 0, "clearing an empty list is OK 0");

    /* Prune collapses two identical rules (same key, different IDs and
     * timestamps) to the newest. */
    make_entry(&entries[0], "1111111111111111", "/home/u/dup", 1700000001);
    make_entry(&entries[1], "2222222222222222", "/home/u/dup", 1700000002);
    fanotify_load_dyn_allowlist(entries, 2);
    run_request("PRUNE\tallow\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n1\n1\n") == 0, "PRUNE removes one duplicate");
    run_request("PRUNE\tallow\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n1\n0\n") == 0, "second PRUNE removes nothing");

    /* Prune both: one duplicate in each list. */
    make_entry(&entries[0], "3333333333333333", "/home/u/dup", 1700000003);
    make_entry(&entries[1], "4444444444444444", "/home/u/dup", 1700000004);
    fanotify_load_dyn_allowlist(entries, 2);
    {
        PersistEntry pair[2];

        make_entry(&pair[0], "5555555555555555", "/home/u/deny-dup", 1700000005);
        make_entry(&pair[1], "6666666666666666", "/home/u/deny-dup", 1700000006);
        fanotify_load_dyn_denylist(pair, 2);
    }
    run_request("PRUNE\tboth\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n1\n2\n") == 0, "PRUNE both sums both lists");

    /* Deny removal. */
    make_entry(&deny_entry, "abcdef0123456789", "/home/u/deny-x", 1700000007);
    fanotify_load_dyn_denylist(&deny_entry, 1);
    ASSERT(deny_matches(&deny_entry) == 1, "deny fixture matches");
    run_request("RULE_REMOVE\tdeny\tabcdef01\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n1\n1\n") == 0, "RULE_REMOVE deny");
    ASSERT(deny_matches(&deny_entry) == 0, "deny rule removed");
}

/* ------------------------------------------------------------------ */
/* Session dispatch                                                   */
/* ------------------------------------------------------------------ */

/* Fork a child that becomes a session leader and sleeps until killed
 * (same fixture as test_session.c). */
static pid_t spawn_leader(void)
{
    int sync_pipe[2];
    char token = 'x';

    if (pipe(sync_pipe) != 0)
        return -1;

    {
        pid_t pid = fork();

        if (pid == 0)
        {
            close(sync_pipe[0]);
            if (setsid() < 0)
                _exit(1);
            {
                ssize_t ignored = write(sync_pipe[1], &token, 1);
                (void)ignored;
            }
            close(sync_pipe[1]);
            for (;;)
                pause();
        }

        close(sync_pipe[1]);
        {
            ssize_t n = read(sync_pipe[0], &token, 1);
            close(sync_pipe[0]);
            if (n != 1)
            {
                if (pid > 0)
                {
                    kill(pid, SIGKILL);
                    waitpid(pid, NULL, 0);
                }
                return -1;
            }
        }
        return pid;
    }
}

static void stop_leader(pid_t pid)
{
    if (pid > 0)
    {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
}

static void test_session_dispatch(void)
{
    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    char resp[2048];
    char req[128];
    ControlResponse parsed;

    if (leader <= 0 || session_id_of(leader, &sid, &start) != 0)
    {
        ASSERT(0, "session fixture");
        stop_leader(leader);
        return;
    }
    session_clear();
    session_allow_add(sid, start, "/usr/bin/demo", TEST_SHA_A,
                      "/home/u/session-secret", 60);

    run_request("SESSION_LIST\tallow\n", resp, sizeof(resp));
    ASSERT(control_response_parse(resp, strlen(resp), &parsed) == 0,
           "session list parses");
    ASSERT(parsed.ok == 1 && parsed.count == 1, "one allow entry");
    if (parsed.count == 1)
    {
        char *fields[6];
        char decoded[PATH_MAX];
        char expect[64];
        long ttl;
        int nf = split_tabs(parsed.lines[0], fields, 6);

        ASSERT(nf == 6, "six fields per entry");
        if (nf < 6)
        {
            /* Do not read fields[] past what split_tabs() produced. */
            session_clear();
            stop_leader(leader);
            return;
        }
        ASSERT(strlen(fields[0]) == RULEID_HEX_LEN,
               "full rule id in payload");

        snprintf(expect, sizeof(expect), "%d", (int)leader);
        ASSERT(strcmp(fields[1], expect) == 0, "payload sid");
        snprintf(expect, sizeof(expect), "%llu", start);
        ASSERT(strcmp(fields[2], expect) == 0, "payload leader start");
        ASSERT(control_decode_field(fields[3], decoded, sizeof(decoded)) >= 0,
               "decode payload binary");
        ASSERT(strcmp(decoded, "/usr/bin/demo") == 0, "payload binary");
        ASSERT(control_decode_field(fields[4], decoded, sizeof(decoded)) >= 0,
               "decode payload target");
        ASSERT(strcmp(decoded, "/home/u/session-secret") == 0,
               "payload target");
        ttl = strtol(fields[5], NULL, 10);
        ASSERT(ttl >= 1 && ttl <= 60, "payload ttl");

        snprintf(req, sizeof(req), "SESSION_REMOVE\tallow\t%.8s\n", fields[0]);
        run_request(req, resp, sizeof(resp));
        ASSERT(strcmp(resp, "OK\n0\n") == 0, "SESSION_REMOVE -> OK");
        run_request("SESSION_LIST\tallow\n", resp, sizeof(resp));
        ASSERT(control_response_parse(resp, strlen(resp), &parsed) == 0 &&
                   parsed.count == 0,
               "session entry removed");
    }

    run_request("SESSION_REMOVE\tallow\tdeadbeef\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "ERR\nno matching session rule\n") == 0,
           "session no-match error");
    run_request("SESSION_REMOVE\tallow\tzz\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "ERR\ninvalid rule ID or daemon refusal\n") == 0,
           "session invalid-id error");

    /* The deny list lists with a session-lifetime TTL of -1. */
    session_deny_add(sid, start, "/usr/bin/denybin", TEST_SHA_B,
                     "/home/u/session-secret", 0);
    run_request("SESSION_LIST\tdeny\n", resp, sizeof(resp));
    ASSERT(control_response_parse(resp, strlen(resp), &parsed) == 0,
           "deny list parses");
    ASSERT(parsed.ok == 1 && parsed.count == 1, "one deny entry");
    if (parsed.count == 1)
    {
        char *fields[6];
        int nf = split_tabs(parsed.lines[0], fields, 6);

        ASSERT(nf == 6, "deny six fields");
        if (nf == 6)
            ASSERT(strcmp(fields[5], "-1") == 0,
                   "session-lifetime ttl is -1");
    }

    session_allow_add(sid, start, "/usr/bin/demo", TEST_SHA_A,
                      "/home/u/session-secret", 60);
    run_request("SESSION_CLEAR\tboth\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n0\n") == 0, "SESSION_CLEAR -> OK");
    run_request("SESSION_LIST\tallow\n", resp, sizeof(resp));
    ASSERT(control_response_parse(resp, strlen(resp), &parsed) == 0 &&
               parsed.count == 0,
           "allow cleared");
    run_request("SESSION_LIST\tdeny\n", resp, sizeof(resp));
    ASSERT(control_response_parse(resp, strlen(resp), &parsed) == 0 &&
               parsed.count == 0,
           "deny cleared");

    session_clear();
    stop_leader(leader);
}

/* ------------------------------------------------------------------ */
/* Pin dispatch                                                       */
/* ------------------------------------------------------------------ */

static void test_pin_dispatch(void)
{
    char pin_path[PATH_MAX];
    char req[128];
    char resp[256];
    char id1[RULEID_HEX_LEN + 1];
    char id2[RULEID_HEX_LEN + 1];
    const char *p1 = "/usr/bin/pin-demo-a";
    const char *p2 = "/usr/bin/pin-demo-b";

    snprintf(pin_path, sizeof(pin_path), "%s/pins.json", g_tmp);
    unlink(pin_path);
    pin_set_state_file(pin_path);
    ASSERT(pin_load(pin_path) == 0, "clean pin table");

    ASSERT(pin_store(p1, TEST_SHA_A) == 0, "store pin 1");
    ASSERT(ruleid_pin(p1, id1) == 0, "pin id 1");

    snprintf(req, sizeof(req), "PIN_REMOVE\t%.8s\n", id1);
    run_request(req, resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n1\n1\n") == 0, "PIN_REMOVE reports the count");
    ASSERT(pin_remove_by_id(id1) == 0, "pin is gone");

    snprintf(req, sizeof(req), "PIN_REMOVE\t%.8s\n", id1);
    run_request(req, resp, sizeof(resp));
    ASSERT(strncmp(resp, "ERR\nremoved 0 of 1:", 19) == 0 &&
               strstr(resp, "no pin matches") != NULL,
           "pin no-match error");

    run_request("PIN_REMOVE\tzz\n", resp, sizeof(resp));
    ASSERT(strncmp(resp, "ERR\nremoved 0 of 1:", 19) == 0 &&
               strstr(resp, "invalid pin ID") != NULL,
           "pin invalid-id error");

    /* Partial removal keeps the confirmed removal. */
    ASSERT(pin_store(p1, TEST_SHA_A) == 0, "store pin 1 again");
    ASSERT(pin_store(p2, TEST_SHA_B) == 0, "store pin 2");
    ASSERT(ruleid_pin(p1, id1) == 0, "pin id 1 again");
    ASSERT(ruleid_pin(p2, id2) == 0, "pin id 2");
    snprintf(req, sizeof(req), "PIN_REMOVE\t%.8s\tdeadbeef\n", id1);
    run_request(req, resp, sizeof(resp));
    ASSERT(strncmp(resp, "ERR\nremoved 1 of 2:", 19) == 0,
           "pin partial removal error");
    ASSERT(pin_remove_by_id(id1) == 0, "first pin removed");
    ASSERT(pin_remove_by_id(id2) == 1, "second pin kept");

    /* Clear writes an empty table. */
    ASSERT(pin_store(p1, TEST_SHA_A) == 0, "store pin before clear");
    run_request("PIN_CLEAR\n", resp, sizeof(resp));
    ASSERT(strcmp(resp, "OK\n0\n") == 0, "PIN_CLEAR -> OK");
    ASSERT(ruleid_pin(p1, id1) == 0, "pin id before empty check");
    ASSERT(pin_remove_by_id(id1) == 0, "pin table is empty");
    ASSERT(pin_load(pin_path) == 0, "empty pin file loads clean");
}

/* ------------------------------------------------------------------ */
/* Socket lifecycle                                                   */
/* ------------------------------------------------------------------ */

static void test_setup_teardown(void)
{
    char sock[PATH_MAX];
    struct stat st;
    int fd;

    snprintf(sock, sizeof(sock), "%s/ctl.sock", g_tmp);
    unlink(sock);

    fd = control_setup_at(sock);
    ASSERT(fd >= 0, "control_setup_at");
    if (fd >= 0)
    {
        ASSERT(lstat(sock, &st) == 0 && S_ISSOCK(st.st_mode),
               "socket path is a socket");
        ASSERT((st.st_mode & 0777) == 0600, "socket mode is 0600");
        ASSERT(st.st_uid == geteuid(), "socket owner is the effective uid");
        control_teardown(fd);
        ASSERT(lstat(sock, &st) != 0 && errno == ENOENT,
               "teardown unlinks the socket");
    }

    /* A stale socket owned by us is replaced. */
    fd = control_setup_at(sock);
    ASSERT(fd >= 0, "setup for stale test");
    if (fd >= 0)
    {
        close(fd); /* leave the bound path behind */
        fd = control_setup_at(sock);
        ASSERT(fd >= 0, "stale socket replaced");
        if (fd >= 0)
            control_teardown(fd);
        ASSERT(lstat(sock, &st) != 0, "socket gone after teardown");
    }

    /* A regular file is never unlinked. */
    fd = open(sock, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT(fd >= 0, "create regular file");
    if (fd >= 0)
        close(fd);
    ASSERT(control_setup_at(sock) == -1, "refuses a regular file");
    ASSERT(lstat(sock, &st) == 0 && S_ISREG(st.st_mode),
           "regular file untouched");
    unlink(sock);

    /* A symlink is never unlinked either. */
    ASSERT(symlink("/tmp", sock) == 0, "create symlink");
    ASSERT(control_setup_at(sock) == -1, "refuses a symlink");
    ASSERT(lstat(sock, &st) == 0 && S_ISLNK(st.st_mode),
           "symlink untouched");
    unlink(sock);

    ASSERT(control_setup_at("") == -1, "empty path refused");
    ASSERT(control_setup_at(NULL) == -1, "NULL path refused");

    {
        char toolong[256];

        memset(toolong, 'x', sizeof(toolong) - 1);
        toolong[sizeof(toolong) - 1] = '\0';
        ASSERT(control_setup_at(toolong) == -1, "over-long path refused");
    }
}

/* control_handle() accepts and serves a connection on a real listener. */
static void test_handle_accept(void)
{
    char sock[PATH_MAX];
    struct sockaddr_un addr;
    struct timeval tv = {2, 0};
    char resp[128];
    size_t used = 0;
    int lfd;
    int cfd;
    ssize_t n;

    snprintf(sock, sizeof(sock), "%s/listen.sock", g_tmp);
    unlink(sock);

    lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    ASSERT(lfd >= 0, "listener socket");
    if (lfd < 0)
        return;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    ASSERT(fill_sun_path(&addr, sock) == 0, "listener path fits");
    ASSERT(bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) == 0, "bind");
    ASSERT(listen(lfd, 8) == 0, "listen");

    cfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT(cfd >= 0, "client socket");
    if (cfd < 0)
    {
        close(lfd);
        return;
    }
    ASSERT(connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) == 0,
           "connect");
    ASSERT(write_all_fd(cfd, "PING\n", 5) == 0, "write ping");
    (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    control_handle(lfd);

    while (used + 1 < sizeof(resp))
    {
        n = read(cfd, resp + used, sizeof(resp) - 1 - used);
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    resp[used] = '\0';
    ASSERT(strcmp(resp, "OK\n0\n") == 0, "control_handle serves a client");

    close(cfd);
    close(lfd);
    unlink(sock);
}

/* ------------------------------------------------------------------ */
/* Client helper                                                      */
/* ------------------------------------------------------------------ */

/*
 * Canned server: bind 'path', listen, signal readiness over the pipe and
 * serve exactly one connection: read the request to EOF, require it to
 * end in a newline, write 'response', close.  Exit codes let the parent
 * tell a protocol violation from a transport one.
 */
static pid_t serve_once(const char *path, const char *response, int *sync_fd)
{
    int p[2];
    pid_t pid;

    if (pipe(p) != 0)
        return -1;

    pid = fork();
    if (pid < 0)
    {
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (pid == 0)
    {
        struct sockaddr_un addr;
        char req[CONTROL_REQ_MAX];
        size_t used = 0;
        size_t rn;
        size_t off;
        int lfd;
        int cfd;

        close(p[0]);
        /* The parent may abandon an oversized response; SIGPIPE must not
         * kill the child before it exits cleanly. */
        signal(SIGPIPE, SIG_IGN);

        lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (lfd < 0)
            _exit(2);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (fill_sun_path(&addr, path) < 0)
            _exit(2);
        if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            _exit(2);
        if (listen(lfd, 1) < 0)
            _exit(2);
        if (write(p[1], "x", 1) != 1)
            _exit(2);
        close(p[1]);

        cfd = accept(lfd, NULL, NULL);
        if (cfd < 0)
            _exit(2);
        while (used < sizeof(req) - 1)
        {
            ssize_t r = read(cfd, req + used, sizeof(req) - 1 - used);

            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
                break;
            used += (size_t)r;
        }
        req[used] = '\0';
        if (used == 0 || req[used - 1] != '\n')
            _exit(3); /* the request must be one newline-terminated line */

        rn = strlen(response);
        off = 0;
        while (off < rn)
        {
            ssize_t w = write(cfd, response + off, rn - off);

            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0)
                _exit(4);
            off += (size_t)w;
        }
        close(cfd);
        close(lfd);
        _exit(0);
    }

    close(p[1]);
    *sync_fd = p[0];
    return pid;
}

static void test_client_call(void)
{
    char sock[PATH_MAX];
    char buf[256];
    ControlResponse r;
    pid_t pid;
    int syncfd;
    char token;
    int status;

    snprintf(sock, sizeof(sock), "%s/client.sock", g_tmp);

    /* Happy path: request accepted, response parsed. */
    unlink(sock);
    pid = serve_once(sock, "OK\n1\nhello\n", &syncfd);
    ASSERT(pid > 0, "spawn canned server");
    if (pid > 0)
    {
        int rc;

        ASSERT(read(syncfd, &token, 1) == 1, "server ready");
        close(syncfd);
        rc = control_client_call(sock, "PING", buf, sizeof(buf), &r);
        ASSERT(rc == 0, "client call succeeds");
        if (rc == 0)
            ASSERT(r.ok == 1 && r.count == 1 &&
                       strcmp(r.lines[0], "hello") == 0,
                   "client response parsed");
        ASSERT(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
                   WEXITSTATUS(status) == 0,
               "server saw a newline-terminated request");
        unlink(sock);
    }

    /* ERR response. */
    pid = serve_once(sock, "ERR\nnope\n", &syncfd);
    ASSERT(pid > 0, "spawn ERR server");
    if (pid > 0)
    {
        int rc;

        ASSERT(read(syncfd, &token, 1) == 1, "ERR server ready");
        close(syncfd);
        rc = control_client_call(sock, "PIN_CLEAR", buf, sizeof(buf), &r);
        ASSERT(rc == 0, "ERR transport succeeds");
        if (rc == 0)
            ASSERT(r.ok == 0 && strcmp(r.message, "nope") == 0, "ERR parsed");
        ASSERT(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
                   WEXITSTATUS(status) == 0,
               "ERR server exits cleanly");
        unlink(sock);
    }

    /* A response too large for the caller's buffer is a transport
     * failure, not a silent truncation. */
    {
        char response[640];
        char filler[600];
        char missing[PATH_MAX];

        memset(filler, 'a', sizeof(filler) - 1);
        filler[sizeof(filler) - 1] = '\0';
        snprintf(response, sizeof(response), "OK\n1\n%.*s\n", 590, filler);
        pid = serve_once(sock, response, &syncfd);
        ASSERT(pid > 0, "spawn oversized server");
        if (pid > 0)
        {
            ASSERT(read(syncfd, &token, 1) == 1, "oversized server ready");
            close(syncfd);
            ASSERT(control_client_call(sock, "PING", buf, 32, &r) == -1,
                   "oversized response rejected");
            (void)waitpid(pid, &status, 0);
            unlink(sock);
        }

        /* No listener: errno must survive for the CLI's fallback. */
        snprintf(missing, sizeof(missing), "%s/missing.sock", g_tmp);
        errno = 0;
        ASSERT(control_client_call(missing, "PING", buf, sizeof(buf), &r) == -1,
               "missing socket fails");
        ASSERT(errno == ENOENT, "connect errno preserved");
    }
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_control ===\n");

    snprintf(g_tmp, sizeof(g_tmp), "/tmp/fileshield_control_XXXXXX");
    if (!mkdtemp(g_tmp))
    {
        fprintf(stderr, "FAIL: cannot create a temp directory\n");
        return 1;
    }

    test_field_codec();
    test_field_decode_errors();
    test_request_parse_ok();
    test_request_parse_errors();
    test_response_parse();
    test_ping_reload();
    test_bad_requests();
    test_slow_clients();
    test_rule_dispatch();
    test_session_dispatch();
    test_pin_dispatch();
    test_setup_teardown();
    test_handle_accept();
    test_client_call();

    {
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "%s/allow.json", g_tmp);
        unlink(path);
        snprintf(path, sizeof(path), "%s/deny.json", g_tmp);
        unlink(path);
        snprintf(path, sizeof(path), "%s/pins.json", g_tmp);
        unlink(path);
        snprintf(path, sizeof(path), "%s/ctl.sock", g_tmp);
        unlink(path);
    }
    rmdir(g_tmp);

    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
