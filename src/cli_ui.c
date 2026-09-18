#include <limits.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "cli_ui.h"

/* Rendered chain cell bound: PERSIST_CHAIN_MAX levels of CLI_UI_COMM_MAX-1
 * chars plus " > " separators and the NUL. */
#define CLI_UI_CHAIN_TEXT_MAX (PERSIST_CHAIN_MAX * CLI_UI_COMM_MAX + 8)

/* "%Y-%m-%d %H:%M:%S" needs 20 bytes; leave slack for future formats. */
#define CLI_UI_TIME_TEXT_MAX 32

/* A session Expires cell: timestamp (19) + " (in 12345m 59s)" + NUL. */
#define CLI_UI_EXPIRES_TEXT_MAX 64

/* Describe labels are aligned to this width (kubectl-style). */
#define CLI_UI_LABEL_WIDTH 16

/*
 * Wall-clock timestamp in local time, the one time format shared by the
 * tables and describes.  A time_t the libc cannot convert (out of range)
 * renders as "(unknown)" instead of failing the whole listing.
 */
static void format_epoch(time_t t, char *dst, size_t dst_size)
{
    struct tm tm;

    if (localtime_r(&t, &tm) != NULL &&
        strftime(dst, dst_size, "%Y-%m-%d %H:%M:%S", &tm) > 0)
        return;
    snprintf(dst, dst_size, "%s", "(unknown)");
}

/*
 * Session Expires cell: a negative ttl means the entry lives until the
 * session leader exits.  Otherwise it shows the wall-clock deadline plus
 * the remaining time; minutes are not folded into hours so the format
 * stays exactly the two documented shapes.
 */
static void format_expires(long ttl, time_t now, char *dst, size_t dst_size)
{
    char when[CLI_UI_TIME_TEXT_MAX];

    if (ttl < 0)
    {
        snprintf(dst, dst_size, "%s", "until session ends");
        return;
    }
    format_epoch(now + (time_t)ttl, when, sizeof(when));
    if (ttl >= 60)
        snprintf(dst, dst_size, "%s (in %ldm %lds)", when, ttl / 60, ttl % 60);
    else
        snprintf(dst, dst_size, "%s (in %lds)", when, ttl);
}

/* Width of the ARG cell without building it; control chars do not change
 * lengths, so raw strlen is the display width. */
static int arg_text_width(const char *cmdline)
{
    const char *space;

    if (!cmdline || cmdline[0] == '\0')
        return (int)strlen("(none)");
    space = strchr(cmdline, ' ');
    return (int)strlen(space ? space + 1 : "");
}

/* Width of the CHAIN cell: non-empty comms joined with " > ". */
static int chain_text_width(const char (*comms)[CLI_UI_COMM_MAX], int depth)
{
    int i;
    int width = 0;
    int parts = 0;

    for (i = 0; comms != NULL && i < depth; i++)
    {
        if (comms[i][0] == '\0')
            continue;
        if (parts > 0)
            width += (int)strlen(" > ");
        width += (int)strlen(comms[i]);
        parts++;
    }
    return parts > 0 ? width : (int)strlen("(none)");
}

/* Decimal display width of a sid (pid_t is an int; the sign is handled
 * only so a synthetic negative test value cannot corrupt the layout). */
static int sid_width(pid_t sid)
{
    long v = (long)sid;
    int width = 1;

    if (v < 0)
    {
        width = 2;
        v = -v;
    }
    while (v >= 10)
    {
        v /= 10;
        width++;
    }
    return width;
}

/* Append src to dst with control bytes sanitized and hard bounds. */
static void append_sanitized(char *dst, size_t dst_size, size_t *used,
                             const char *src)
{
    for (; *src != '\0' && *used + 1 < dst_size; src++)
    {
        unsigned char c = (unsigned char)*src;

        dst[(*used)++] = (c < 0x20 || c == 0x7f) ? '?' : *src;
    }
    dst[*used] = '\0';
}

void cli_ui_sanitize(const char *src, char *dst, size_t dst_size)
{
    size_t i;

    if (!dst || dst_size == 0)
        return;
    if (!src)
        src = "";
    for (i = 0; src[i] != '\0' && i + 1 < dst_size; i++)
    {
        unsigned char c = (unsigned char)src[i];

        dst[i] = (c < 0x20 || c == 0x7f) ? '?' : src[i];
    }
    dst[i] = '\0';
}

void cli_ui_truncate_tail(const char *src, int width, char *dst,
                          size_t dst_size)
{
    size_t len;
    size_t cap;
    size_t keep;

    if (!dst || dst_size == 0)
        return;
    if (!src)
        src = "";
    if (width < 0)
        width = 0;

    len = strlen(src);
    cap = (size_t)width;
    if (cap > dst_size - 1)
        cap = dst_size - 1;

    if (len <= cap)
    {
        /* Fits: only the sanitize pass is needed. */
        cli_ui_sanitize(src, dst, cap + 1);
        return;
    }

    if (cap < CLI_UI_ELLIPSIS)
    {
        /* Too narrow for "...": keep the last bytes, still sanitized. */
        memcpy(dst, src + (len - cap), cap);
        dst[cap] = '\0';
        cli_ui_sanitize(dst, dst, cap + 1);
        return;
    }

    keep = cap - CLI_UI_ELLIPSIS;
    dst[0] = '.';
    dst[1] = '.';
    dst[2] = '.';
    memcpy(dst + CLI_UI_ELLIPSIS, src + (len - keep), keep);
    dst[cap] = '\0';
    cli_ui_sanitize(dst, dst, cap + 1);
}

void cli_ui_arg_column(const char *cmdline, char *dst, size_t dst_size)
{
    const char *space;

    if (!dst || dst_size == 0)
        return;
    if (!cmdline || cmdline[0] == '\0')
    {
        cli_ui_sanitize("(none)", dst, dst_size);
        return;
    }
    space = strchr(cmdline, ' ');
    cli_ui_sanitize(space ? space + 1 : "", dst, dst_size);
}

void cli_ui_chain_column(const char (*comms)[CLI_UI_COMM_MAX], int depth,
                         char *dst, size_t dst_size)
{
    int i;
    size_t used = 0;

    if (!dst || dst_size == 0)
        return;
    dst[0] = '\0';

    for (i = 0; comms != NULL && i < depth; i++)
    {
        if (comms[i][0] == '\0')
            continue;
        if (used > 0)
            append_sanitized(dst, dst_size, &used, " > ");
        append_sanitized(dst, dst_size, &used, comms[i]);
    }

    if (used == 0)
        cli_ui_sanitize("(none)", dst, dst_size);
}

/*
 * Equal-share width cap for 'count' flexible columns after 'fixed' bytes
 * of never-shrinking columns and gaps are subtracted.  Too-narrow
 * terminals give every flexible column CLI_UI_COL_MIN so the header
 * still lines up (the line overflows instead).
 */
static int flexible_cap(int width, int fixed, int count)
{
    int avail = width - fixed;

    if (avail < count * CLI_UI_COL_MIN)
        avail = count * CLI_UI_COL_MIN;
    return avail / count;
}

/* A measured column width, capped and never below its own header. */
static int clamp_col(int measured, int cap, int header)
{
    if (measured > cap)
        measured = cap;
    if (measured < header)
        measured = header;
    return measured;
}

int cli_ui_terminal_width(FILE *out)
{
    int fd = -1;

    if (out)
        fd = fileno(out);
    if (fd >= 0 && isatty(fd))
    {
        struct winsize ws;

        if (ioctl(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
            return (int)ws.ws_col;
    }
    return CLI_UI_FALLBACK_WIDTH;
}

int cli_confirm_allowed(int stdin_is_tty, int yes_flag)
{
    return yes_flag != 0 || stdin_is_tty != 0;
}

int cli_confirm_parse(const char *line)
{
    const char *p = line;

    if (!p)
        return 0;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != 'y' && *p != 'Y')
        return 0;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return *p == '\0';
}

int cli_confirm(const char *prompt, int yes_flag)
{
    char line[128];

    if (!cli_confirm_allowed(isatty(STDIN_FILENO), yes_flag))
    {
        fprintf(stderr,
                "error: refusing to prompt on a non-terminal; "
                "use -y/--yes\n");
        return 0;
    }
    if (yes_flag)
        return 1;

    printf("%s [y/N] ", prompt ? prompt : "");
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin))
        return 0; /* EOF/error is never consent */
    return cli_confirm_parse(line);
}

void cli_ui_render_rules(FILE *out, const CliRuleRow *rows, int count,
                         int width, int wide)
{
    int i;
    int id_w = wide ? CLI_UI_ID_WIDE : CLI_UI_ID_NARROW;
    int rule_w = (int)strlen("ALLOW");
    int bin_w = (int)strlen("Binary");
    int arg_w = (int)strlen("ARG");
    int tgt_w = (int)strlen("TARGET");
    int chain_w = (int)strlen("CHAIN");

    if (!out)
        return;
    if (!rows || count < 0)
        count = 0;

    for (i = 0; i < count; i++)
    {
        const PersistEntry *e = rows[i].entry;
        int w;

        if (!e)
            continue;
        w = (int)strlen(e->binary);
        if (w > bin_w)
            bin_w = w;
        w = arg_text_width(e->cmdline);
        if (w > arg_w)
            arg_w = w;
        w = (int)strlen(e->target_path);
        if (w > tgt_w)
            tgt_w = w;
        w = chain_text_width(e->chain_comm, e->chain_depth);
        if (w > chain_w)
            chain_w = w;
    }

    if (!wide)
    {
        /* Binary, ARG and TARGET share the leftover width equally; ID,
         * Rule and CHAIN never shrink. */
        int cap = flexible_cap(width, id_w + rule_w + chain_w + 5 * CLI_UI_GAP,
                               3);

        bin_w = clamp_col(bin_w, cap, (int)strlen("Binary"));
        arg_w = clamp_col(arg_w, cap, (int)strlen("ARG"));
        tgt_w = clamp_col(tgt_w, cap, (int)strlen("TARGET"));
    }

    fprintf(out, "%-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
            id_w, "ID", rule_w, "Rule", bin_w, "Binary", arg_w, "ARG",
            tgt_w, "TARGET", "CHAIN");

    for (i = 0; i < count; i++)
    {
        const CliRuleRow *r = &rows[i];
        const PersistEntry *e = r->entry;
        char idbuf[CLI_UI_ID_MAX];
        char binbuf[PATH_MAX];
        char argraw[PERSIST_CMDLINE_MAX];
        char argbuf[PERSIST_CMDLINE_MAX];
        char tgtbuf[PATH_MAX];
        char chainbuf[CLI_UI_CHAIN_TEXT_MAX];

        if (!e)
            continue;

        snprintf(idbuf, sizeof(idbuf), "%.*s", id_w, r->id);
        cli_ui_truncate_tail(e->binary, bin_w, binbuf, sizeof(binbuf));
        cli_ui_arg_column(e->cmdline, argraw, sizeof(argraw));
        cli_ui_truncate_tail(argraw, arg_w, argbuf, sizeof(argbuf));
        cli_ui_truncate_tail(e->target_path, tgt_w, tgtbuf, sizeof(tgtbuf));
        cli_ui_chain_column(e->chain_comm, e->chain_depth, chainbuf,
                            sizeof(chainbuf));

        fprintf(out, "%-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
                id_w, idbuf, rule_w, r->is_deny ? "DENY" : "ALLOW",
                bin_w, binbuf, arg_w, argbuf, tgt_w, tgtbuf, chainbuf);
    }
}

void cli_ui_render_pins(FILE *out, const CliPinRow *rows, int count,
                        int width, int wide)
{
    int i;
    int id_w = wide ? CLI_UI_ID_WIDE : CLI_UI_ID_NARROW;
    int bin_w = (int)strlen("Binary");
    int upd_w = (int)strlen("Last Updated");

    if (!out)
        return;
    if (!rows || count < 0)
        count = 0;

    for (i = 0; i < count; i++)
    {
        int w = rows[i].pattern ? (int)strlen(rows[i].pattern) : 0;

        if (w > bin_w)
            bin_w = w;
    }
    if (count > 0)
        upd_w = (int)strlen("0000-00-00 00:00:00");

    if (!wide)
    {
        int cap = flexible_cap(width, id_w + upd_w + 2 * CLI_UI_GAP, 1);

        bin_w = clamp_col(bin_w, cap, (int)strlen("Binary"));
    }

    fprintf(out, "%-*s  %-*s  %s\n", id_w, "ID", bin_w, "Binary",
            "Last Updated");

    for (i = 0; i < count; i++)
    {
        char idbuf[CLI_UI_ID_MAX];
        char patbuf[PATH_MAX];
        char timebuf[CLI_UI_TIME_TEXT_MAX];

        snprintf(idbuf, sizeof(idbuf), "%.*s", id_w, rows[i].id);
        cli_ui_truncate_tail(rows[i].pattern ? rows[i].pattern : "", bin_w,
                             patbuf, sizeof(patbuf));
        format_epoch(rows[i].updated_at, timebuf, sizeof(timebuf));
        fprintf(out, "%-*s  %-*s  %s\n", id_w, idbuf, bin_w, patbuf,
                timebuf);
    }
}

void cli_ui_render_sessions(FILE *out, const CliSessionRow *rows, int count,
                            int width, int wide, time_t now)
{
    int i;
    int id_w = wide ? CLI_UI_ID_WIDE : CLI_UI_ID_NARROW;
    int rule_w = (int)strlen("ALLOW");
    int sid_w = (int)strlen("SID");
    int bin_w = (int)strlen("Binary");
    int tgt_w = (int)strlen("Target");
    int exp_w = (int)strlen("Expires");

    if (!out)
        return;
    if (!rows || count < 0)
        count = 0;

    for (i = 0; i < count; i++)
    {
        char expbuf[CLI_UI_EXPIRES_TEXT_MAX];
        int w;

        w = sid_width(rows[i].sid);
        if (w > sid_w)
            sid_w = w;
        w = rows[i].binary ? (int)strlen(rows[i].binary) : 0;
        if (w > bin_w)
            bin_w = w;
        w = rows[i].target ? (int)strlen(rows[i].target) : 0;
        if (w > tgt_w)
            tgt_w = w;
        format_expires(rows[i].ttl_remaining, now, expbuf, sizeof(expbuf));
        w = (int)strlen(expbuf);
        if (w > exp_w)
            exp_w = w;
    }

    if (!wide)
    {
        /* Binary and Target share the leftover width; SID and Expires
         * are bounded by their content. */
        int cap = flexible_cap(width,
                               id_w + rule_w + sid_w + exp_w + 5 * CLI_UI_GAP,
                               2);

        bin_w = clamp_col(bin_w, cap, (int)strlen("Binary"));
        tgt_w = clamp_col(tgt_w, cap, (int)strlen("Target"));
    }

    fprintf(out, "%-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
            id_w, "ID", rule_w, "Rule", sid_w, "SID", bin_w, "Binary",
            tgt_w, "Target", "Expires");

    for (i = 0; i < count; i++)
    {
        const CliSessionRow *r = &rows[i];
        char idbuf[CLI_UI_ID_MAX];
        char sidbuf[32];
        char binbuf[PATH_MAX];
        char tgtbuf[PATH_MAX];
        char expbuf[CLI_UI_EXPIRES_TEXT_MAX];

        snprintf(idbuf, sizeof(idbuf), "%.*s", id_w, r->id);
        snprintf(sidbuf, sizeof(sidbuf), "%ld", (long)r->sid);
        cli_ui_truncate_tail(r->binary ? r->binary : "", bin_w, binbuf,
                             sizeof(binbuf));
        cli_ui_truncate_tail(r->target ? r->target : "", tgt_w, tgtbuf,
                             sizeof(tgtbuf));
        format_expires(r->ttl_remaining, now, expbuf, sizeof(expbuf));

        fprintf(out, "%-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
                id_w, idbuf, rule_w, r->is_deny ? "DENY" : "ALLOW",
                sid_w, sidbuf, bin_w, binbuf, tgt_w, tgtbuf, expbuf);
    }
}

/* Append a totals part, inserting ", " only when the whole part fits. */
static void totals_append(char *buf, size_t size, size_t *used,
                          const char *text)
{
    size_t len = strlen(text);
    size_t need = len + (*used > 0 ? 2 : 0);

    if (*used + need + 1 > size)
        return;
    if (*used > 0)
    {
        buf[(*used)++] = ',';
        buf[(*used)++] = ' ';
    }
    memcpy(buf + *used, text, len);
    *used += len;
    buf[*used] = '\0';
}

void cli_ui_render_totals(FILE *out, int allow, int deny, int pins,
                          unsigned sections)
{
    char buf[160];
    char part[64];
    size_t used = 0;

    if (!out)
        return;
    buf[0] = '\0';

    if ((sections & CLI_UI_SECTION_ALLOW) != 0)
    {
        snprintf(part, sizeof(part), "%d allow", allow);
        totals_append(buf, sizeof(buf), &used, part);
    }
    if ((sections & CLI_UI_SECTION_DENY) != 0)
    {
        snprintf(part, sizeof(part), "%d deny", deny);
        totals_append(buf, sizeof(buf), &used, part);
    }
    if ((sections & CLI_UI_SECTION_PINS) != 0)
    {
        snprintf(part, sizeof(part), "%d %s", pins,
                 pins == 1 ? "pin" : "pins");
        totals_append(buf, sizeof(buf), &used, part);
    }

    if (used > 0)
        fprintf(out, "%s\n", buf);
}

/* One aligned describe line; the value is sanitized for terminal safety. */
static void describe_field(FILE *out, const char *label, const char *value)
{
    char safe[PATH_MAX];

    cli_ui_sanitize(value, safe, sizeof(safe));
    fprintf(out, "%-*s %s\n", CLI_UI_LABEL_WIDTH, label, safe);
}

void cli_ui_render_rule_describe(FILE *out, const CliRuleRow *row)
{
    const PersistEntry *e;
    char timebuf[CLI_UI_TIME_TEXT_MAX];
    int i;

    if (!out || !row || !row->entry)
        return;
    e = row->entry;

    describe_field(out, "ID:", row->id);
    describe_field(out, "Type:", row->is_deny ? "DENY" : "ALLOW");
    describe_field(out, "Binary:", e->binary);
    describe_field(out, "Binary SHA-512:", e->binary_sha512);
    describe_field(out, "Command:", e->cmdline);
    describe_field(out, "Command SHA-512:", e->cmdline_sha512);
    describe_field(out, "Target:", e->target_path);

    if (e->chain_depth <= 0)
    {
        describe_field(out, "Chain:", "(none)");
    }
    else
    {
        int levels = e->chain_depth > PERSIST_CHAIN_MAX
                         ? PERSIST_CHAIN_MAX
                         : e->chain_depth;

        fputs("Chain:\n", out);
        for (i = 0; i < levels; i++)
        {
            char comm[CLI_UI_COMM_MAX];
            char sha[129];

            cli_ui_sanitize(e->chain_comm[i][0] != '\0' ? e->chain_comm[i]
                                                        : "(unknown)",
                            comm, sizeof(comm));
            cli_ui_sanitize(e->chain_sha512[i][0] != '\0'
                                ? e->chain_sha512[i]
                                : "(not recorded)",
                            sha, sizeof(sha));
            fprintf(out, "  %-*s %s\n", CLI_UI_LABEL_WIDTH, comm, sha);
        }
    }

    format_epoch(e->created_at, timebuf, sizeof(timebuf));
    describe_field(out, "Created:", timebuf);
}

void cli_ui_render_pin_describe(FILE *out, const CliPinRow *row)
{
    char timebuf[CLI_UI_TIME_TEXT_MAX];

    if (!out || !row)
        return;

    describe_field(out, "ID:", row->id);
    describe_field(out, "Pattern:", row->pattern ? row->pattern : "");
    describe_field(out, "SHA-512:",
                   (row->sha512 && row->sha512[0] != '\0')
                       ? row->sha512
                       : "(not recorded)");
    format_epoch(row->updated_at, timebuf, sizeof(timebuf));
    describe_field(out, "Last Updated:", timebuf);
}

/*
 * Write one JSON string.  persist_json_escape() is the single escaping
 * path; a value that cannot fit the shared bound (impossible for the
 * state struct fields the bound is sized for) becomes null instead of
 * unescaped bytes.
 */
static void json_escaped(FILE *out, const char *s)
{
    char esc[JSON_ESCAPED_MAX];

    if (!s)
        s = "";
    if (persist_json_escape(s, esc, sizeof(esc)) < 0)
        fputs("null", out);
    else
        fprintf(out, "\"%s\"", esc);
}

/* One "key": value pair followed by a comma and a newline. */
static void json_str_field(FILE *out, const char *indent, const char *key,
                           const char *value)
{
    fprintf(out, "%s  \"%s\": ", indent, key);
    json_escaped(out, value);
    fputs(",\n", out);
}

static void json_rule_object(FILE *out, const CliRuleRow *row,
                             const char *indent)
{
    const PersistEntry *e = row->entry;
    int i;

    fprintf(out, "%s{\n", indent);
    json_str_field(out, indent, "id", row->id);
    json_str_field(out, indent, "type", row->is_deny ? "deny" : "allow");
    json_str_field(out, indent, "binary", e ? e->binary : "");
    json_str_field(out, indent, "binary_sha512", e ? e->binary_sha512 : "");
    json_str_field(out, indent, "target_path", e ? e->target_path : "");
    json_str_field(out, indent, "cmdline", e ? e->cmdline : "");
    json_str_field(out, indent, "cmdline_sha512", e ? e->cmdline_sha512 : "");

    fprintf(out, "%s  \"chain\": [", indent);
    if (e && e->chain_depth > 0)
    {
        int levels = e->chain_depth > PERSIST_CHAIN_MAX
                         ? PERSIST_CHAIN_MAX
                         : e->chain_depth;

        fputc('\n', out);
        for (i = 0; i < levels; i++)
        {
            fprintf(out, "%s    {\"comm\": ", indent);
            json_escaped(out, e->chain_comm[i]);
            fputs(", \"sha512\": ", out);
            json_escaped(out, e->chain_sha512[i]);
            fprintf(out, "}%s\n", i + 1 < levels ? "," : "");
        }
        fprintf(out, "%s  ]", indent);
    }
    else
    {
        fputc(']', out);
    }
    fputs(",\n", out);

    fprintf(out, "%s  \"created_at\": %lld\n", indent,
            (long long)(e ? e->created_at : (time_t)0));
    fprintf(out, "%s}", indent);
}

static void json_pin_object(FILE *out, const CliPinRow *row,
                            const char *indent)
{
    fprintf(out, "%s{\n", indent);
    json_str_field(out, indent, "id", row->id);
    json_str_field(out, indent, "pattern", row->pattern);
    json_str_field(out, indent, "sha512", row->sha512);
    fprintf(out, "%s  \"updated_at\": %lld\n", indent,
            (long long)row->updated_at);
    fprintf(out, "%s}", indent);
}

static void json_session_object(FILE *out, const CliSessionRow *row,
                                const char *indent, time_t now)
{
    fprintf(out, "%s{\n", indent);
    json_str_field(out, indent, "id", row->id);
    json_str_field(out, indent, "type", row->is_deny ? "deny" : "allow");
    fprintf(out, "%s  \"sid\": %ld,\n", indent, (long)row->sid);
    json_str_field(out, indent, "binary", row->binary);
    json_str_field(out, indent, "target", row->target);
    fprintf(out, "%s  \"ttl_remaining\": %ld,\n", indent, row->ttl_remaining);
    if (row->ttl_remaining >= 0)
        fprintf(out, "%s  \"expires_at\": %lld\n", indent,
                (long long)(now + (time_t)row->ttl_remaining));
    else
        fprintf(out, "%s  \"expires_at\": null\n", indent);
    fprintf(out, "%s}", indent);
}

/*
 * An array of rule objects filtered by is_deny (0 = allow, 1 = deny),
 * pretty-printed.  'indent' is the indentation of the enclosing key and
 * 'child' the object indentation.
 */
static void json_rule_array(FILE *out, const char *indent, const char *child,
                            const CliRuleRow *rows, int count, int want_deny)
{
    int i;
    int any = 0;
    int started = 0;

    for (i = 0; i < count && rows != NULL; i++)
    {
        if ((rows[i].is_deny != 0) == (want_deny != 0))
        {
            any = 1;
            break;
        }
    }

    fputc('[', out);
    if (any)
        fputc('\n', out);
    for (i = 0; i < count && rows != NULL; i++)
    {
        if ((rows[i].is_deny != 0) != (want_deny != 0))
            continue;
        if (started)
            fputs(",\n", out);
        json_rule_object(out, &rows[i], child);
        started = 1;
    }
    if (any)
    {
        fputc('\n', out);
        fprintf(out, "%s]", indent);
    }
    else
    {
        fputc(']', out);
    }
}

void cli_ui_render_list_json(FILE *out, unsigned sections,
                             const CliRuleRow *rules, int n_rules,
                             const CliPinRow *pins, int n_pins,
                             const CliSessionRow *sessions, int n_sessions,
                             time_t now)
{
    int first = 1;
    int i;

    if (!out)
        return;
    if ((sections & (CLI_UI_SECTION_ALLOW | CLI_UI_SECTION_DENY |
                     CLI_UI_SECTION_PINS | CLI_UI_SECTION_SESSIONS)) == 0)
    {
        fputs("{}\n", out);
        return;
    }

    fputs("{\n", out);

    if ((sections & CLI_UI_SECTION_ALLOW) != 0)
    {
        fputs("  \"allow\": ", out);
        json_rule_array(out, "  ", "    ", rules, n_rules, 0);
        first = 0;
    }
    if ((sections & CLI_UI_SECTION_DENY) != 0)
    {
        if (!first)
            fputs(",\n", out);
        fputs("  \"deny\": ", out);
        json_rule_array(out, "  ", "    ", rules, n_rules, 1);
        first = 0;
    }
    if ((sections & CLI_UI_SECTION_PINS) != 0)
    {
        if (!first)
            fputs(",\n", out);
        fputs("  \"pins\": [", out);
        if (pins != NULL && n_pins > 0)
            fputc('\n', out);
        for (i = 0; i < n_pins && pins != NULL; i++)
        {
            if (i > 0)
                fputs(",\n", out);
            json_pin_object(out, &pins[i], "    ");
        }
        if (pins != NULL && n_pins > 0)
            fputs("\n  ", out);
        fputc(']', out);
        first = 0;
    }
    if ((sections & CLI_UI_SECTION_SESSIONS) != 0)
    {
        if (!first)
            fputs(",\n", out);
        fputs("  \"sessions\": [", out);
        if (sessions != NULL && n_sessions > 0)
            fputc('\n', out);
        for (i = 0; i < n_sessions && sessions != NULL; i++)
        {
            if (i > 0)
                fputs(",\n", out);
            json_session_object(out, &sessions[i], "    ", now);
        }
        if (sessions != NULL && n_sessions > 0)
            fputs("\n  ", out);
        fputc(']', out);
    }

    fputs("\n}\n", out);
}

void cli_ui_render_rule_describe_json(FILE *out, const CliRuleRow *row)
{
    if (!out || !row)
        return;
    json_rule_object(out, row, "");
    fputc('\n', out);
}

void cli_ui_render_pin_describe_json(FILE *out, const CliPinRow *row)
{
    if (!out || !row)
        return;
    json_pin_object(out, row, "");
    fputc('\n', out);
}
