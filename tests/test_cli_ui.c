#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/cli_ui.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } \
} while (0)

/* Fill a fully populated rule entry with a 3-level chain whose last
 * digest is empty, so describes must render "(not recorded)". */
static void fill_entry(PersistEntry *e)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->rule_id, sizeof(e->rule_id), "%s", "0123456789abcdef");
    snprintf(e->binary, sizeof(e->binary), "%s", "/usr/bin/code");
    snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", "BSHA");
    snprintf(e->cmdline, sizeof(e->cmdline), "%s", "/usr/bin/code --foo");
    snprintf(e->cmdline_sha512, sizeof(e->cmdline_sha512), "%s", "CSHA");
    snprintf(e->target_path, sizeof(e->target_path), "%s",
             "/home/u/.ssh/id_rsa");
    snprintf(e->chain_comm[0], sizeof(e->chain_comm[0]), "%s", "code-oss");
    snprintf(e->chain_comm[1], sizeof(e->chain_comm[1]), "%s", "electron");
    snprintf(e->chain_comm[2], sizeof(e->chain_comm[2]), "%s", "zsh");
    snprintf(e->chain_sha512[0], sizeof(e->chain_sha512[0]), "%s", "S0");
    snprintf(e->chain_sha512[1], sizeof(e->chain_sha512[1]), "%s", "S1");
    e->chain_depth = 3;
    e->created_at = 1000000000; /* 2001-09-09 01:46:40 UTC */
}

static void test_sanitize(void)
{
    char out[64];
    char guarded[8];

    cli_ui_sanitize("a\x01\x1f\x7fz", out, sizeof(out));
    ASSERT(strcmp(out, "a???z") == 0, "control bytes and DEL become '?'");

    cli_ui_sanitize("h\xc3\xa9llo", out, sizeof(out));
    ASSERT(strcmp(out, "h\xc3\xa9llo") == 0, "high bytes are preserved");

    cli_ui_sanitize("abcdef", out, 4);
    ASSERT(strcmp(out, "abc") == 0, "sanitize truncates to the buffer");

    cli_ui_sanitize("", out, sizeof(out));
    ASSERT(strcmp(out, "") == 0, "empty input gives empty output");
    cli_ui_sanitize(NULL, out, sizeof(out));
    ASSERT(strcmp(out, "") == 0, "NULL input gives empty output");

    memset(guarded, 'X', sizeof(guarded));
    cli_ui_sanitize("abcdef", guarded, 4);
    ASSERT(guarded[3] == '\0' && guarded[4] == 'X',
           "sanitize never writes past dst_size");
}

static void test_truncate_tail(void)
{
    char out[128];
    char tiny[5];

    cli_ui_truncate_tail("abc", 10, out, sizeof(out));
    ASSERT(strcmp(out, "abc") == 0, "shorter than width is unchanged");

    cli_ui_truncate_tail("abcdefghij", 10, out, sizeof(out));
    ASSERT(strcmp(out, "abcdefghij") == 0,
           "exactly width is unchanged");

    cli_ui_truncate_tail("/path/to/secret.txt", 16, out, sizeof(out));
    ASSERT(strcmp(out, "...to/secret.txt") == 0,
           "long value keeps the end with a leading ellipsis");
    ASSERT(strlen(out) == 16, "truncated value is exactly width chars");

    cli_ui_truncate_tail("0123456789abcdef", 8, out, sizeof(out));
    ASSERT(strcmp(out, "...bcdef") == 0,
           "ellipsis plus the last width-3 chars");

    cli_ui_truncate_tail("abcdef", 3, out, sizeof(out));
    ASSERT(strcmp(out, "...") == 0, "width 3 is all ellipsis");

    cli_ui_truncate_tail("abcdef", 2, out, sizeof(out));
    ASSERT(strcmp(out, "ef") == 0, "width below the ellipsis keeps the tail");

    cli_ui_truncate_tail("abcdef", 0, out, sizeof(out));
    ASSERT(strcmp(out, "") == 0, "width 0 yields an empty cell");

    cli_ui_truncate_tail("abcdef\x01\x02", 5, out, sizeof(out));
    ASSERT(strcmp(out, "...??") == 0,
           "control chars are sanitized before truncation");

    cli_ui_truncate_tail("a\x01" "bc", 5, out, sizeof(out));
    ASSERT(strcmp(out, "a?bc") == 0,
           "a fitting value is sanitized without truncation");

    cli_ui_truncate_tail(NULL, 5, out, sizeof(out));
    ASSERT(strcmp(out, "") == 0, "NULL value yields an empty cell");

    cli_ui_truncate_tail("abcdefghijkl", 20, tiny, sizeof(tiny));
    ASSERT(strcmp(tiny, "...l") == 0,
           "dst_size bounds the result even when width is larger");
    ASSERT(strlen(tiny) == 4, "clipped result never overflows");
}

static void test_arg_column(void)
{
    char out[PERSIST_CMDLINE_MAX];

    cli_ui_arg_column("/usr/bin/code --foo bar", out, sizeof(out));
    ASSERT(strcmp(out, "--foo bar") == 0,
           "args are everything after the first space");

    cli_ui_arg_column("bin", out, sizeof(out));
    ASSERT(strcmp(out, "") == 0, "a command without a space has no args");

    cli_ui_arg_column("", out, sizeof(out));
    ASSERT(strcmp(out, "(none)") == 0, "empty cmdline renders (none)");

    cli_ui_arg_column(NULL, out, sizeof(out));
    ASSERT(strcmp(out, "(none)") == 0, "NULL cmdline renders (none)");

    cli_ui_arg_column("bin  spaced", out, sizeof(out));
    ASSERT(strcmp(out, " spaced") == 0,
           "only the first token is stripped");

    cli_ui_arg_column("bin \x01" "arg", out, sizeof(out));
    ASSERT(strcmp(out, "?arg") == 0, "args are sanitized");
}

static void test_chain_column(void)
{
    char comms_buf[PERSIST_CHAIN_MAX][CLI_UI_COMM_MAX];
    /* The API takes const char (*)[N] (real callers pass a const
     * PersistEntry).  C99 rejects the implicit char -> const char array
     * conversion at a pedantic level, so name the const view once. */
    const char (*comms)[CLI_UI_COMM_MAX] =
        (const char (*)[CLI_UI_COMM_MAX])comms_buf;
    char out[128];

    memset(comms_buf, 0, sizeof(comms_buf));
    cli_ui_chain_column(comms, 0, out, sizeof(out));
    ASSERT(strcmp(out, "(none)") == 0, "depth 0 renders (none)");
    cli_ui_chain_column(NULL, 0, out, sizeof(out));
    ASSERT(strcmp(out, "(none)") == 0, "NULL comms renders (none)");

    snprintf(comms_buf[0], sizeof(comms_buf[0]), "%s", "sh");
    cli_ui_chain_column(comms, 1, out, sizeof(out));
    ASSERT(strcmp(out, "sh") == 0, "one level renders the comm");

    snprintf(comms_buf[1], sizeof(comms_buf[1]), "%s", "code-oss");
    snprintf(comms_buf[2], sizeof(comms_buf[2]), "%s", "zsh");
    cli_ui_chain_column(comms, 3, out, sizeof(out));
    ASSERT(strcmp(out, "sh > code-oss > zsh") == 0,
           "three levels are joined with >");

    comms_buf[0][0] = '\0';
    cli_ui_chain_column(comms, 3, out, sizeof(out));
    ASSERT(strcmp(out, "code-oss > zsh") == 0, "empty comms are skipped");

    memset(comms_buf, 0, sizeof(comms_buf));
    cli_ui_chain_column(comms, 3, out, sizeof(out));
    ASSERT(strcmp(out, "(none)") == 0,
           "all-empty comms render (none)");

    snprintf(comms_buf[0], sizeof(comms_buf[0]), "%s", "a\x01");
    cli_ui_chain_column(comms, 1, out, sizeof(out));
    ASSERT(strcmp(out, "a?") == 0, "comm control chars are sanitized");

    cli_ui_chain_column(comms, 1, out, 3);
    ASSERT(strlen(out) < 3, "chain rendering respects dst_size");
}

static void test_terminal_width(void)
{
    FILE *devnull = fopen("/dev/null", "w");

    ASSERT(devnull != NULL, "open /dev/null");
    if (devnull)
    {
        ASSERT(cli_ui_terminal_width(devnull) == CLI_UI_FALLBACK_WIDTH,
               "non-tty stream falls back to 120");
        fclose(devnull);
    }
    ASSERT(cli_ui_terminal_width(NULL) == CLI_UI_FALLBACK_WIDTH,
           "NULL stream falls back to 120");
}

static void test_rule_table(void)
{
    PersistEntry e;
    CliRuleRow row;
    char *buf = NULL;
    size_t len = 0;
    FILE *ms;

    memset(&e, 0, sizeof(e));
    snprintf(e.binary, sizeof(e.binary), "%s", "sh");
    snprintf(e.cmdline, sizeof(e.cmdline), "%s", "sh");
    snprintf(e.target_path, sizeof(e.target_path), "%s", "t");

    memset(&row, 0, sizeof(row));
    snprintf(row.id, sizeof(row.id), "%s", "dd8bf55d01234567");
    row.entry = &e;

    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the rule table");
    if (ms)
    {
        static const char expect[] =
            "ID" "      " "  " "Rule" " " "  " "Binary" "  " "ARG" "  "
            "TARGET" "  " "CHAIN\n"
            "dd8bf55d" "  " "ALLOW" "  " "sh" "      " "     "
            "t" "       " "(none)\n";

        cli_ui_render_rules(ms, &row, 1, 200, 0);
        fclose(ms);
        ASSERT(buf != NULL && strcmp(buf, expect) == 0,
               "rule table golden header + row");
        free(buf);
    }

    /* A header-only table (no rows) is still rendered. */
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the empty rule table");
    if (ms)
    {
        static const char expect_header[] =
            "ID" "      " "  " "Rule" " " "  " "Binary" "  " "ARG" "  "
            "TARGET" "  " "CHAIN\n";

        cli_ui_render_rules(ms, NULL, 0, 200, 0);
        fclose(ms);
        ASSERT(buf != NULL && strcmp(buf, expect_header) == 0,
               "empty rule table renders the header only");
        free(buf);
    }

    /* Narrow terminal: binary/args/target keep their end. */
    memset(&e, 0, sizeof(e));
    snprintf(e.binary, sizeof(e.binary), "%s", "/aaaa/bbbb/cccc/dddd");
    snprintf(e.cmdline, sizeof(e.cmdline), "%s",
             "/bin/code --with some very long argument list here");
    snprintf(e.target_path, sizeof(e.target_path), "%s", "/long/target/path");
    row.entry = &e;

    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the narrow rule table");
    if (ms)
    {
        cli_ui_render_rules(ms, &row, 1, 60, 0);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "...cc/dddd") != NULL,
               "narrow binary keeps its tail");
        ASSERT(buf != NULL && strstr(buf, "...st here") != NULL,
               "narrow args keep their tail");
        ASSERT(buf != NULL && strstr(buf, "...et/path") != NULL,
               "narrow target keeps its tail");
        ASSERT(buf != NULL && strstr(buf, "/aaaa/bbbb") == NULL,
               "narrow binary is actually truncated");
        ASSERT(buf != NULL && strstr(buf, "dd8bf55d") != NULL &&
                   strstr(buf, "dd8bf55d0") == NULL,
               "narrow ID is 8 chars");
        free(buf);
    }

    /* Wide: no truncation of binary/args/target, ID doubled to 16. */
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the wide rule table");
    if (ms)
    {
        cli_ui_render_rules(ms, &row, 1, 40, 1);
        fclose(ms);
        ASSERT(buf != NULL &&
                   strstr(buf, "/aaaa/bbbb/cccc/dddd") != NULL,
               "--wide keeps the full binary");
        ASSERT(buf != NULL &&
                   strstr(buf, "--with some very long argument list here") !=
                       NULL,
               "--wide keeps the full args");
        ASSERT(buf != NULL && strstr(buf, "/long/target/path") != NULL,
               "--wide keeps the full target");
        ASSERT(buf != NULL && strstr(buf, "dd8bf55d01234567") != NULL,
               "--wide shows the full 16-char ID");
        free(buf);
    }
}

static void test_pin_table(void)
{
    CliPinRow pin;
    char *buf = NULL;
    size_t len = 0;
    FILE *ms;

    memset(&pin, 0, sizeof(pin));
    snprintf(pin.id, sizeof(pin.id), "%s", "c54d92c0aabbccdd");
    pin.pattern = "sh";
    pin.sha512 = "PINHASH";
    pin.updated_at = 1000000000; /* 2001-09-09 01:46:40 UTC */

    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the pin table");
    if (ms)
    {
        static const char expect[] =
            "ID" "      " "  " "Binary" "  " "Last Updated\n"
            "c54d92c0" "  " "sh" "      " "2001-09-09 01:46:40\n";

        cli_ui_render_pins(ms, &pin, 1, 200, 0);
        fclose(ms);
        ASSERT(buf != NULL && strcmp(buf, expect) == 0,
               "pin table golden header + row");
        free(buf);
    }

    /* Narrow terminal truncates the pattern, keeping its end. */
    pin.pattern = "/nix/store/verylongname/bin/doctl";
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the narrow pin table");
    if (ms)
    {
        cli_ui_render_pins(ms, &pin, 1, 41, 0);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "...n/doctl") != NULL,
               "narrow pattern keeps its tail");
        ASSERT(buf != NULL && strstr(buf, "/nix/store/verylongname") == NULL,
               "narrow pattern is actually truncated");
        free(buf);
    }
}

static void test_session_table(void)
{
    CliSessionRow rows[3];
    char *buf = NULL;
    size_t len = 0;
    FILE *ms;

    memset(rows, 0, sizeof(rows));

    snprintf(rows[0].id, sizeof(rows[0].id), "%s", "aaaaaaaaaaaaaaaa");
    rows[0].is_deny = 0;
    rows[0].sid = 4242;
    rows[0].binary = "/bin/bash";
    rows[0].target = "/home/u/.ssh/id_rsa";
    rows[0].ttl_remaining = -1;

    snprintf(rows[1].id, sizeof(rows[1].id), "%s", "bbbbbbbbbbbbbbbb");
    rows[1].is_deny = 1;
    rows[1].sid = 777;
    rows[1].binary = "/usr/bin/curl";
    rows[1].target = "/etc/shadow";
    rows[1].ttl_remaining = 61;

    snprintf(rows[2].id, sizeof(rows[2].id), "%s", "cccccccccccccccc");
    rows[2].is_deny = 0;
    rows[2].sid = 9;
    rows[2].binary = "/usr/bin/ssh";
    rows[2].target = "/home/u/.ssh/config";
    rows[2].ttl_remaining = 5;

    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the session table");
    if (ms)
    {
        cli_ui_render_sessions(ms, rows, 3, 200, 0, 1000000000);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "ID") != NULL &&
                   strstr(buf, "Rule") != NULL && strstr(buf, "SID") != NULL,
               "session header: ID Rule SID");
        ASSERT(buf != NULL && strstr(buf, "Binary") != NULL &&
                   strstr(buf, "Target") != NULL &&
                   strstr(buf, "Expires") != NULL,
               "session header: Binary Target Expires");
        ASSERT(buf != NULL && strstr(buf, "ALLOW") != NULL &&
                   strstr(buf, "DENY") != NULL,
               "session rows carry their rule type");
        ASSERT(buf != NULL && strstr(buf, "4242") != NULL &&
                   strstr(buf, "777") != NULL,
               "session rows carry their SID");
        ASSERT(buf != NULL && strstr(buf, "until session ends") != NULL,
               "negative TTL renders until session ends");
        ASSERT(buf != NULL &&
                   strstr(buf, "2001-09-09 01:47:41 (in 1m 1s)") != NULL,
               "minute TTL renders deadline plus remaining time");
        ASSERT(buf != NULL &&
                   strstr(buf, "2001-09-09 01:46:45 (in 5s)") != NULL,
               "second TTL renders deadline plus remaining seconds");
        free(buf);
    }
}

static void assert_totals(const char *want, int allow, int deny, int pins,
                          unsigned sections, const char *msg)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *ms = open_memstream(&buf, &len);

    if (!ms)
    {
        ASSERT(0, "open_memstream for totals");
        return;
    }
    cli_ui_render_totals(ms, allow, deny, pins, sections);
    fclose(ms);
    /* A render that writes nothing leaves *buf NULL on glibc. */
    ASSERT(strcmp(buf ? buf : "", want) == 0, msg);
    free(buf);
}

static void test_totals(void)
{
    assert_totals("3 allow, 1 deny, 12 pins\n", 3, 1, 12,
                  CLI_UI_SECTION_RULES | CLI_UI_SECTION_PINS,
                  "all three sections render in order");
    assert_totals("3 allow, 1 deny\n", 3, 1, 0, CLI_UI_SECTION_RULES,
                  "rules-only totals omit pins");
    assert_totals("1 pin\n", 0, 0, 1, CLI_UI_SECTION_PINS,
                  "a single pin is singular");
    assert_totals("3 allow\n", 3, 0, 0, CLI_UI_SECTION_ALLOW,
                  "a single requested section stands alone");
    assert_totals("", 3, 1, 12, 0,
                  "no requested section prints nothing");
}

static void test_describe(void)
{
    PersistEntry e;
    CliRuleRow row;
    CliPinRow pin;
    char *buf = NULL;
    size_t len = 0;
    FILE *ms;

    fill_entry(&e);
    memset(&row, 0, sizeof(row));
    snprintf(row.id, sizeof(row.id), "%s", "0123456789abcdef");
    row.entry = &e;

    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for rule describe");
    if (ms)
    {
        cli_ui_render_rule_describe(ms, &row);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "ID:") != NULL &&
                   strstr(buf, "0123456789abcdef") != NULL,
               "describe prints the full 16-char ID");
        ASSERT(buf != NULL && strstr(buf, "Type:") != NULL &&
                   strstr(buf, "ALLOW") != NULL,
               "describe prints the rule type");
        ASSERT(buf != NULL && strstr(buf, "Binary:") != NULL &&
                   strstr(buf, "/usr/bin/code") != NULL &&
                   strstr(buf, "Binary SHA-512:") != NULL &&
                   strstr(buf, "BSHA") != NULL,
               "describe prints the binary and its digest");
        ASSERT(buf != NULL && strstr(buf, "Command:") != NULL &&
                   strstr(buf, "/usr/bin/code --foo") != NULL &&
                   strstr(buf, "Command SHA-512:") != NULL &&
                   strstr(buf, "CSHA") != NULL,
               "describe prints the command and its digest");
        ASSERT(buf != NULL && strstr(buf, "Target:") != NULL &&
                   strstr(buf, "/home/u/.ssh/id_rsa") != NULL,
               "describe prints the target");
        ASSERT(buf != NULL && strstr(buf, "Chain:") != NULL &&
                   strstr(buf, "code-oss") != NULL &&
                   strstr(buf, "electron") != NULL &&
                   strstr(buf, "zsh") != NULL &&
                   strstr(buf, "(not recorded)") != NULL,
               "describe prints each chain level and the missing digest");
        ASSERT(buf != NULL && strstr(buf, "Created:") != NULL &&
                   strstr(buf, "2001-09-09 01:46:40") != NULL,
               "describe prints the creation time");
        free(buf);
    }

    /* An empty chain says so instead of printing nothing. */
    e.chain_depth = 0;
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for empty-chain describe");
    if (ms)
    {
        cli_ui_render_rule_describe(ms, &row);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "Chain:") != NULL &&
                   strstr(buf, "(none)") != NULL,
               "empty chain renders (none)");
        free(buf);
    }

    memset(&pin, 0, sizeof(pin));
    snprintf(pin.id, sizeof(pin.id), "%s", "c54d92c0aabbccdd");
    pin.pattern = "/usr/bin/code";
    pin.sha512 = "PINHASH";
    pin.updated_at = 1000000000;

    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for pin describe");
    if (ms)
    {
        cli_ui_render_pin_describe(ms, &pin);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "ID:") != NULL &&
                   strstr(buf, "c54d92c0aabbccdd") != NULL &&
                   strstr(buf, "Pattern:") != NULL &&
                   strstr(buf, "/usr/bin/code") != NULL,
               "pin describe prints ID and pattern");
        ASSERT(buf != NULL && strstr(buf, "SHA-512:") != NULL &&
                   strstr(buf, "PINHASH") != NULL &&
                   strstr(buf, "Last Updated:") != NULL &&
                   strstr(buf, "2001-09-09 01:46:40") != NULL,
               "pin describe prints digest and update time");
        free(buf);
    }

    /* Missing digests are named, not silently blank. */
    pin.sha512 = "";
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for empty-digest pin describe");
    if (ms)
    {
        cli_ui_render_pin_describe(ms, &pin);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "(not recorded)") != NULL,
               "empty pin digest renders (not recorded)");
        free(buf);
    }
}

static void test_json(void)
{
    static const char nasty[] = "/tmp/a\"b\\c\nd";
    PersistEntry e;
    CliRuleRow rows[2];
    CliPinRow pin;
    CliSessionRow srows[2];
    char *buf = NULL;
    size_t len = 0;
    FILE *ms;

    fill_entry(&e);
    memset(rows, 0, sizeof(rows));
    snprintf(rows[0].id, sizeof(rows[0].id), "%s", "0123456789abcdef");
    rows[0].entry = &e;
    snprintf(rows[1].id, sizeof(rows[1].id), "%s", "fedcba9876543210");
    rows[1].entry = &e;
    rows[1].is_deny = 1;

    memset(&pin, 0, sizeof(pin));
    snprintf(pin.id, sizeof(pin.id), "%s", "c54d92c0aabbccdd");
    pin.pattern = nasty;
    pin.sha512 = "AB";
    pin.updated_at = 1000000000;

    /* Rules + pins: one object, only the requested sections. */
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for list JSON");
    if (ms)
    {
        cli_ui_render_list_json(ms, CLI_UI_SECTION_RULES | CLI_UI_SECTION_PINS,
                                rows, 2, &pin, 1, NULL, 0, 1000000000);
        fclose(ms);
        ASSERT(buf != NULL && buf[0] == '{', "list JSON is one object");
        ASSERT(buf != NULL && strstr(buf, "\"allow\": [") != NULL &&
                   strstr(buf, "\"deny\": [") != NULL,
               "rules split into allow and deny arrays");
        ASSERT(buf != NULL && strstr(buf, "\"pins\": [") != NULL,
               "requested pins section present");
        ASSERT(buf != NULL && strstr(buf, "\"sessions\"") == NULL,
               "unrequested sections are omitted");
        ASSERT(buf != NULL &&
                   strstr(buf, "\"id\": \"0123456789abcdef\"") != NULL &&
                   strstr(buf, "\"created_at\": 1000000000") != NULL,
               "rule fields are complete (full ID, epoch time)");
        ASSERT(buf != NULL && strstr(buf, "\"type\": \"allow\"") != NULL &&
                   strstr(buf, "\"type\": \"deny\"") != NULL,
               "each rule carries its type");
        ASSERT(buf != NULL &&
                   strstr(buf, "\"chain\": [") != NULL &&
                   strstr(buf, "\"comm\": \"code-oss\"") != NULL &&
                   strstr(buf, "\"sha512\": \"\"") != NULL,
               "the call chain is rendered as objects");
        ASSERT(buf != NULL && strstr(buf, "/tmp/a\\\"b\\\\c\\nd") != NULL,
               "quotes, backslashes and newlines are JSON-escaped");
        ASSERT(buf != NULL && strstr(buf, "\"updated_at\": 1000000000") != NULL,
               "pin fields are complete");
        ASSERT(buf != NULL && strlen(buf) > 2 &&
                   buf[strlen(buf) - 1] == '\n',
               "list JSON ends with a newline");
        free(buf);
    }

    /* Pins only: the rules keys disappear entirely. */
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for pins-only JSON");
    if (ms)
    {
        cli_ui_render_list_json(ms, CLI_UI_SECTION_PINS, NULL, 0, &pin, 1,
                                NULL, 0, 0);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "\"pins\": [") != NULL &&
                   strstr(buf, "\"allow\"") == NULL,
               "pins-only JSON omits the rules arrays");
        free(buf);
    }

    /* No sections: an empty object. */
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for empty JSON");
    if (ms)
    {
        cli_ui_render_list_json(ms, 0, NULL, 0, NULL, 0, NULL, 0, 0);
        fclose(ms);
        ASSERT(buf != NULL && strcmp(buf, "{}\n") == 0,
               "no sections renders an empty object");
        free(buf);
    }

    /* Sessions: TTL -1 is a null deadline, TTL 61 an epoch deadline. */
    memset(srows, 0, sizeof(srows));
    snprintf(srows[0].id, sizeof(srows[0].id), "%s", "aaaaaaaaaaaaaaaa");
    srows[0].sid = 4242;
    srows[0].binary = "/bin/bash";
    srows[0].target = "/home/u/.ssh/id_rsa";
    srows[0].ttl_remaining = -1;
    snprintf(srows[1].id, sizeof(srows[1].id), "%s", "bbbbbbbbbbbbbbbb");
    srows[1].is_deny = 1;
    srows[1].sid = 777;
    srows[1].binary = "/usr/bin/curl";
    srows[1].target = "/etc/shadow";
    srows[1].ttl_remaining = 61;

    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for session JSON");
    if (ms)
    {
        cli_ui_render_list_json(ms, CLI_UI_SECTION_SESSIONS, NULL, 0, NULL, 0,
                                srows, 2, 1000000000);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "\"sessions\": [") != NULL &&
                   strstr(buf, "\"sid\": 4242") != NULL,
               "session array carries ids");
        ASSERT(buf != NULL && strstr(buf, "\"ttl_remaining\": -1") != NULL &&
                   strstr(buf, "\"expires_at\": null") != NULL,
               "session lifetime renders a null deadline");
        ASSERT(buf != NULL && strstr(buf, "\"expires_at\": 1000000061") != NULL,
               "session TTL renders the epoch deadline");
        free(buf);
    }

    /* Describe JSON: one object each. */
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for rule describe JSON");
    if (ms)
    {
        cli_ui_render_rule_describe_json(ms, &rows[0]);
        fclose(ms);
        ASSERT(buf != NULL && buf[0] == '{' &&
                   strstr(buf, "\"id\": \"0123456789abcdef\"") != NULL &&
                   strstr(buf, "\"created_at\": 1000000000") != NULL,
               "rule describe JSON has the complete fields");
        ASSERT(buf != NULL &&
                   strcmp(buf + strlen(buf) - 2, "}\n") == 0,
               "rule describe JSON ends with the closing brace");
        free(buf);
    }

    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for pin describe JSON");
    if (ms)
    {
        cli_ui_render_pin_describe_json(ms, &pin);
        fclose(ms);
        ASSERT(buf != NULL && buf[0] == '{' &&
                   strstr(buf, "\"pattern\": ") != NULL &&
                   strstr(buf, "\"updated_at\": 1000000000") != NULL,
               "pin describe JSON has the complete fields");
        free(buf);
    }
}

static void test_confirm(void)
{
    ASSERT(cli_confirm_allowed(1, 0) == 1,
           "a tty may prompt without --yes");
    ASSERT(cli_confirm_allowed(0, 0) == 0,
           "a non-tty without --yes is refused");
    ASSERT(cli_confirm_allowed(1, 1) == 1, "a tty with --yes proceeds");
    ASSERT(cli_confirm_allowed(0, 1) == 1, "a non-tty with --yes proceeds");

    ASSERT(cli_confirm_parse("y\n") == 1, "y confirms");
    ASSERT(cli_confirm_parse("Y\n") == 1, "Y confirms");
    ASSERT(cli_confirm_parse(" y \n") == 1, "padded y confirms");
    ASSERT(cli_confirm_parse("yes\n") == 0, "yes is not y (strict)");
    ASSERT(cli_confirm_parse("n\n") == 0, "n declines");
    ASSERT(cli_confirm_parse("") == 0, "empty input declines");
    ASSERT(cli_confirm_parse(NULL) == 0, "NULL input declines");
    ASSERT(cli_confirm_parse("true") == 0, "arbitrary input declines");

    ASSERT(cli_confirm("delete?", 1) == 1, "--yes bypasses the prompt");

    /* A non-tty stdin without --yes refuses without reading.  The setup
     * failure must be visible: silently passing because stdin could not
     * be redirected would hide a broken check. */
    {
        int saved = dup(STDIN_FILENO);
        int devnull = open("/dev/null", O_RDONLY);

        if (saved < 0 || devnull < 0 || dup2(devnull, STDIN_FILENO) < 0)
        {
            printf("SKIP: could not redirect stdin for the non-tty "
                   "confirmation check\n");
        }
        else
        {
            int got = cli_confirm("delete?", 0);

            ASSERT(got == 0, "non-tty stdin without --yes refuses");
            ASSERT(dup2(saved, STDIN_FILENO) >= 0, "restore stdin");
        }
        if (saved >= 0)
            close(saved);
        if (devnull >= 0)
            close(devnull);
    }
}

/*
 * C1 regression: the confirmation listing shapes its dynamic fields
 * exactly like table cells.  Control bytes become '?', long cells are
 * tail-truncated per the equal-share cap (never below CLI_UI_COL_MIN),
 * and --wide disables only truncation, never sanitization.
 */
static void test_confirm_line(void)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *ms;

    /* Single-field golden shape. */
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the single-field confirm line");
    if (ms)
    {
        cli_ui_render_confirm_line(ms, "0123456789abcdef", "/usr/bin/tool",
                                   NULL, 200, 1);
        fclose(ms);
        ASSERT(buf != NULL &&
                   strcmp(buf, "  0123456789abcdef: /usr/bin/tool\n") == 0,
               "single-field confirm line golden");
        free(buf);
    }

    /* Two-field golden shape with an over-long id: it is clipped to the
     * stored-ID width. */
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the two-field confirm line");
    if (ms)
    {
        cli_ui_render_confirm_line(ms, "0123456789abcdefZZZZ",
                                   "/usr/bin/tool", "/home/u/secret", 200, 1);
        fclose(ms);
        ASSERT(buf != NULL &&
                   strcmp(buf, "  0123456789abcdef: /usr/bin/tool -> "
                               "/home/u/secret\n") == 0,
               "two-field confirm line clips the ID and keeps the arrow");
        free(buf);
    }

    /* Escapes in from/to are neutralized: raw control bytes never reach
     * the terminal even with --wide. */
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the escaped confirm line");
    if (ms)
    {
        cli_ui_render_confirm_line(ms, "0123456789abcdef",
                                   "/bin/a\x1b[31mb", "/t/\x01x", 200, 1);
        fclose(ms);
        ASSERT(buf != NULL && strchr(buf, '\x1b') == NULL,
               "no raw escape byte in the confirm line");
        ASSERT(buf != NULL && strchr(buf, '\x01') == NULL,
               "no raw control byte in the confirm line");
        ASSERT(buf != NULL && strstr(buf, "?[31mb") != NULL &&
                   strstr(buf, "/t/?x") != NULL,
               "control bytes become '?'");
        free(buf);
    }

    /*
     * Narrow terminal: each dynamic cell is capped at an equal share
     * (width 40, two fields, 24 fixed columns -> cap 8), so only the
     * informative tail survives; a width below the fixed parts floors
     * the cap at CLI_UI_COL_MIN (4).
     */
    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the narrow confirm line");
    if (ms)
    {
        cli_ui_render_confirm_line(ms, "0123456789abcdef",
                                   "/from/abcdef", "/to/uvwxyz", 40, 0);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "...bcdef") != NULL &&
                   strstr(buf, "...vwxyz") != NULL,
               "narrow confirm line keeps the cell tails");
        ASSERT(buf != NULL && strstr(buf, "/from/abcdef") == NULL &&
                   strstr(buf, "/to/uvwxyz") == NULL,
               "narrow confirm line actually truncates");
        free(buf);
    }

    buf = NULL;
    len = 0;
    ms = open_memstream(&buf, &len);
    ASSERT(ms != NULL, "open_memstream for the over-narrow confirm line");
    if (ms)
    {
        cli_ui_render_confirm_line(ms, "0123456789abcdef", "abcdefgh",
                                   "ijklmnop", 10, 0);
        fclose(ms);
        ASSERT(buf != NULL && strstr(buf, "...h") != NULL &&
                   strstr(buf, "...p") != NULL,
               "cap floors at CLI_UI_COL_MIN on an over-narrow terminal");
        free(buf);
    }
}

/*
 * C5 regression: a damaged PersistEntry may carry chain_depth beyond
 * PERSIST_CHAIN_MAX.  Every chain renderer must clamp it, so rendering
 * never reads past the stored arrays.  The sentinels placed right after
 * the arrays are what a pre-fix over-read would print (chain_comm is
 * immediately followed by chain_sha512 in PersistEntry).
 */
static void test_chain_depth_clamp(void)
{
    struct
    {
        char comms[PERSIST_CHAIN_MAX][CLI_UI_COMM_MAX];
        char sentinel[CLI_UI_COMM_MAX];
    } buf;
    const char (*comms)[CLI_UI_COMM_MAX] =
        (const char (*)[CLI_UI_COMM_MAX])buf.comms;
    char out[256];
    int i;

    memset(&buf, 0, sizeof(buf));
    for (i = 0; i < PERSIST_CHAIN_MAX; i++)
        snprintf(buf.comms[i], sizeof(buf.comms[i]), "c%d", i);
    snprintf(buf.sentinel, sizeof(buf.sentinel), "%s", "SENTINEL-COMM");

    cli_ui_chain_column(comms, PERSIST_CHAIN_MAX + 4, out, sizeof(out));
    ASSERT(strcmp(out, "c0 > c1 > c2") == 0,
           "chain_column renders only the stored levels");
    ASSERT(strstr(out, "SENTINEL-COMM") == NULL,
           "chain_column never reads past the array");

    /* The rule table's CHAIN cell takes the same path. */
    {
        PersistEntry e;
        CliRuleRow row;
        char *rendered = NULL;
        size_t rlen = 0;
        FILE *ms;

        memset(&e, 0, sizeof(e));
        snprintf(e.binary, sizeof(e.binary), "%s", "sh");
        snprintf(e.cmdline, sizeof(e.cmdline), "%s", "sh");
        snprintf(e.target_path, sizeof(e.target_path), "%s", "t");
        for (i = 0; i < PERSIST_CHAIN_MAX; i++)
            snprintf(e.chain_comm[i], sizeof(e.chain_comm[i]), "c%d", i);
        snprintf(e.chain_sha512[0], sizeof(e.chain_sha512[0]), "%s",
                 "SENTINEL-SHA");
        e.chain_depth = PERSIST_CHAIN_MAX + 4;

        memset(&row, 0, sizeof(row));
        row.entry = &e;
        ms = open_memstream(&rendered, &rlen);
        ASSERT(ms != NULL, "open_memstream for the clamped rule table");
        if (ms)
        {
            cli_ui_render_rules(ms, &row, 1, 200, 0);
            fclose(ms);
            ASSERT(rendered != NULL &&
                       strstr(rendered, "SENTINEL-SHA") == NULL,
                   "rule table chain cell never reads past the array");
            ASSERT(rendered != NULL &&
                       strstr(rendered, "c0 > c1 > c2") != NULL,
                   "rule table renders the clamped chain");
            free(rendered);
        }
    }

    /* The JSON chain array uses the same clamped depth. */
    {
        PersistEntry e;
        CliRuleRow row;
        char *rendered = NULL;
        size_t rlen = 0;
        FILE *ms;
        int comms_seen = 0;
        const char *p;

        memset(&e, 0, sizeof(e));
        snprintf(e.binary, sizeof(e.binary), "%s", "sh");
        for (i = 0; i < PERSIST_CHAIN_MAX; i++)
            snprintf(e.chain_comm[i], sizeof(e.chain_comm[i]), "c%d", i);
        snprintf(e.chain_sha512[0], sizeof(e.chain_sha512[0]), "%s",
                 "SENTINEL-SHA");
        e.chain_depth = PERSIST_CHAIN_MAX + 4;

        memset(&row, 0, sizeof(row));
        row.entry = &e;
        ms = open_memstream(&rendered, &rlen);
        ASSERT(ms != NULL, "open_memstream for the clamped JSON");
        if (ms)
        {
            cli_ui_render_rule_describe_json(ms, &row);
            fclose(ms);
            ASSERT(rendered != NULL &&
                       strstr(rendered, "\"comm\": \"SENTINEL-SHA\"") == NULL,
                   "JSON chain never renders a sentinel as a comm");
            for (p = rendered; p != NULL &&
                               (p = strstr(p, "\"comm\":")) != NULL; p++)
                comms_seen++;
            ASSERT(comms_seen == PERSIST_CHAIN_MAX,
                   "JSON chain array holds exactly PERSIST_CHAIN_MAX levels");
            free(rendered);
        }
    }
}

int main(void)
{
    /* Describes and tables format local time; pin the zone so the
     * golden timestamps are machine-independent. */
    setenv("TZ", "UTC", 1);
    tzset();

    printf("=== test_cli_ui ===\n");
    test_sanitize();
    test_truncate_tail();
    test_arg_column();
    test_chain_column();
    test_chain_depth_clamp();
    test_terminal_width();
    test_rule_table();
    test_pin_table();
    test_session_table();
    test_totals();
    test_describe();
    test_json();
    test_confirm();
    test_confirm_line();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
