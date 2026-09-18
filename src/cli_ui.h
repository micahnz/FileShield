#ifndef FILESHIELD_CLI_UI_H
#define FILESHIELD_CLI_UI_H

#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include "persist.h"

/*
 * cli_ui: pure formatting and rendering for fileshield-cli.
 *
 * The module owns no state and performs no I/O beyond the FILE * it is
 * handed: it never opens a state file, never talks to the control socket
 * and never allocates.  Every renderer writes to a caller-supplied
 * stream so the CLI decides where output goes and tests can capture it
 * with open_memstream().  The row structs are display views: cli.c fills
 * them from persist_load()/the pin file API/session_snapshot() and hands
 * rows in final order (rules oldest created_at first, pins oldest
 * updated_at first, sessions soonest expiry first with session-lifetime
 * rows last).
 *
 * Display conventions:
 *  - The ID column shows the first 8 chars of the stored 16-char ID, or
 *    all 16 with --wide ("--wide only doubles the ID size").
 *  - Binary/ARG/TARGET cells are tail-truncated with a leading "..." on
 *    a narrow terminal (the end is the informative part of a path);
 *    control characters become '?' first.  --wide disables truncation
 *    of binary/args/target.  ID/Rule/SID/Expires are never truncated.
 *  - Confirmation listings (cli_ui_render_confirm_line()) shape their
 *    dynamic fields with the same cell shaping the tables use, so the
 *    [y/N] listing can never echo raw bytes and shows exactly what the
 *    table would have shown.
 *  - Column widths are natural (header and content) when the line fits
 *    the terminal; otherwise the flexible columns are capped so the
 *    table fits.  A table always prints its header, even with no rows.
 *  - Describes are kubectl-style plain text with ~16-char aligned
 *    labels and print the full 16-char ID and every digest.
 *  - JSON list output is one object with the requested sections as
 *    arrays ("allow", "deny", "pins", "sessions"); every dynamic string
 *    goes through persist_json_escape().
 */

/* Width used when the stream is not a tty or ioctl(TIOCGWINSZ) fails. */
#define CLI_UI_FALLBACK_WIDTH 120

/* Stored rule IDs are 16 lowercase hex chars; the display default is the
 * first 8, --wide shows all 16.  CLI_UI_ID_MAX holds 16 chars + NUL. */
#define CLI_UI_ID_LEN 16
#define CLI_UI_ID_MAX 17
#define CLI_UI_ID_NARROW 8
#define CLI_UI_ID_WIDE 16

/* Width of the leading "..." in a truncated cell. */
#define CLI_UI_ELLIPSIS 3

/* Minimum width of a flexible column; a narrower terminal lets the table
 * overflow instead of hiding the column names. */
#define CLI_UI_COL_MIN 4

/* Spaces between table columns. */
#define CLI_UI_GAP 2

/* Size of one PersistEntry chain_comm[] element.  cli_ui_chain_column()
 * takes a 2-D array of these so entry->chain_comm passes directly. */
#define CLI_UI_COMM_MAX 256

/* cli_ui_render_list_json() section selector: ALLOW/DENY filter rule
 * rows by type, PINS/SESSIONS select the other arrays.
 * CLI_UI_SECTION_RULES is the rules list as `list rules` shows it. */
#define CLI_UI_SECTION_ALLOW 0x1u
#define CLI_UI_SECTION_DENY 0x2u
#define CLI_UI_SECTION_PINS 0x4u
#define CLI_UI_SECTION_SESSIONS 0x8u
#define CLI_UI_SECTION_RULES (CLI_UI_SECTION_ALLOW | CLI_UI_SECTION_DENY)

/*
 * Display rows.  All const char * members are borrowed for the duration
 * of the render call; the renderers never free or modify them.
 */
typedef struct
{
    char id[CLI_UI_ID_MAX]; /* full stored rule ID (cli.c copies
                             * PersistEntry.rule_id), "" when unknown */
    int is_deny;            /* 0 = allow, 1 = deny */
    const PersistEntry *entry;
} CliRuleRow;

typedef struct
{
    char id[CLI_UI_ID_MAX]; /* first 16 hex of SHA-512(pattern) */
    const char *pattern;    /* canonical binary pattern (pin key) */
    const char *sha512;     /* pinned digest, "" when unknown */
    time_t updated_at;
} CliPinRow;

typedef struct
{
    char id[CLI_UI_ID_MAX];
    int is_deny;            /* 0 = allow, 1 = deny */
    pid_t sid;
    const char *binary;
    const char *target;
    /* Seconds left; negative means the entry lives until the session
     * leader exits (the design's TTL 0; cli.c maps 0 to -1). */
    long ttl_remaining;
} CliSessionRow;

/* ------------------------------------------------------------------ */
/* Text shaping (pure, no rendering)                                  */
/* ------------------------------------------------------------------ */

/*
 * Copy src into dst, replacing every control byte (< 0x20 and 0x7f)
 * with '?'.  Output is always NUL-terminated and bounded by dst_size;
 * a value longer than the buffer is truncated.  Safe with src == dst.
 */
void cli_ui_sanitize(const char *src, char *dst, size_t dst_size);

/*
 * Tail-truncate src into dst: when src is longer than 'width' the result
 * is exactly 'width' chars shaped as "..." + the last width-3 chars (the
 * informative end of a path survives).  Control characters are sanitized
 * before measuring, so the output never carries terminal escapes.  A
 * 'width' below CLI_UI_ELLIPSIS keeps the last 'width' chars instead (no
 * room for the marker), and width <= 0 yields "".  Writes at most
 * min(width, dst_size - 1) chars plus NUL.
 */
void cli_ui_truncate_tail(const char *src, int width, char *dst,
                          size_t dst_size);

/*
 * Create the ARG cell for a raw command line: everything after the first
 * space (the binary token is already shown in the Binary column).  A
 * command line with no space has no arguments (""); a NULL/empty command
 * line has no recorded arguments ("(none)").  Control characters are
 * sanitized.
 */
void cli_ui_arg_column(const char *cmdline, char *dst, size_t dst_size);

/*
 * Create the CHAIN cell: "comm1 > comm2 > comm3" from the first 'depth'
 * entries of comms with empty entries skipped.  'depth' is clamped to
 * PERSIST_CHAIN_MAX inside the renderer (a damaged entry may carry a
 * larger value), so it can never index past comms[PERSIST_CHAIN_MAX-1].
 * Depth 0 (or every entry empty) renders "(none)".  Control characters
 * are sanitized.
 */
void cli_ui_chain_column(const char (*comms)[CLI_UI_COMM_MAX], int depth,
                         char *dst, size_t dst_size);

/* ------------------------------------------------------------------ */
/* Terminal                                                           */
/* ------------------------------------------------------------------ */

/*
 * Terminal width in columns for 'out': ioctl(TIOCGWINSZ) when the
 * stream is a tty, CLI_UI_FALLBACK_WIDTH when it is not a tty, the
 * ioctl fails, or 'out' is NULL.
 */
int cli_ui_terminal_width(FILE *out);

/* ------------------------------------------------------------------ */
/* Confirmation                                                       */
/* ------------------------------------------------------------------ */

/*
 * Pure confirmation gate: 1 when the caller may proceed (either -y was
 * given, or stdin is a terminal and the user can be asked).  This is the
 * whole policy without I/O; cli_confirm() adds the prompt and the read.
 */
int cli_confirm_allowed(int stdin_is_tty, int yes_flag);

/*
 * Pure line parser for cli_confirm(): 1 only when the input is "y"/"Y"
 * after trimming surrounding whitespace (so "yes", "n" and an empty
 * line all decline).  NULL declines.
 */
int cli_confirm_parse(const char *line);

/*
 * Ask the user to confirm 'prompt'.  With yes_flag the answer is yes
 * without touching the terminal.  Without a tty on stdin it refuses
 * (message on stderr, return 0, fail closed) instead of reading EOF or
 * a pipe as consent.  Otherwise it writes "[prompt] [y/N] " to stdout
 * and reads one line from stdin: only y/Y confirms.
 */
int cli_confirm(const char *prompt, int yes_flag);

/*
 * One confirmation-listing line, printed before a [y/N] prompt:
 *
 *   "  <id>: <from>"
 *   "  <id>: <from> -> <to>"    (only when 'to' is non-NULL)
 *
 * Dynamic (attacker-influenced) fields are shaped exactly like table
 * cells through cli_ui_truncate_tail(): control bytes become '?' and a
 * value longer than the cell cap is tail-truncated behind a leading
 * "...".  A confirmation listing therefore cannot echo raw terminal
 * escapes, and a long path keeps its informative end.  'id' is printed
 * at CLI_UI_ID_WIDE (16) chars.  'wide' non-zero disables truncation
 * (sanitization stays), matching --wide tables; otherwise each cell is
 * capped at an equal share of 'width' (see cli_ui_terminal_width()) left
 * after the fixed line parts, never below CLI_UI_COL_MIN.  A NULL 'from'
 * renders as an empty cell; nothing is written when out is NULL.
 */
void cli_ui_render_confirm_line(FILE *out, const char *id, const char *from,
                                const char *to, int width, int wide);

/* ------------------------------------------------------------------ */
/* Tables                                                             */
/* ------------------------------------------------------------------ */

/*
 * Render the merged allow+deny rule table with headers
 *   ID  Rule  Binary  ARG  TARGET  CHAIN
 * and a Rule value of ALLOW/DENY per row.  'width' is the terminal width
 * (see cli_ui_terminal_width()); 'wide' non-zero disables binary/args/
 * target truncation.  rows may be NULL when count is 0.
 */
void cli_ui_render_rules(FILE *out, const CliRuleRow *rows, int count,
                         int width, int wide);

/*
 * Render the pin table with headers
 *   ID  Binary  Last Updated
 * Binary is the pinned pattern; timestamps are local time.  rows may be
 * NULL when count is 0.
 */
void cli_ui_render_pins(FILE *out, const CliPinRow *rows, int count,
                        int width, int wide);

/*
 * Render the session table with headers
 *   ID  Rule  SID  Binary  Target  Expires
 * Expires is "until session ends" for a negative ttl_remaining, else the
 * wall-clock time (now + ttl) plus "(in Xm Ys)"/"(in Xs)".  'now' is
 * passed in so the output is a pure function of its inputs (cli.c passes
 * time(NULL)).  rows may be NULL when count is 0.
 */
void cli_ui_render_sessions(FILE *out, const CliSessionRow *rows, int count,
                            int width, int wide, time_t now);

/*
 * Totals footer, e.g. "3 allow, 1 deny, 12 pins" plus a newline.  Only
 * the requested CLI_UI_SECTION_* parts are printed; with no section
 * selected (or out == NULL) nothing is written.  "pin" is singular for
 * a count of one.
 */
void cli_ui_render_totals(FILE *out, int allow, int deny, int pins,
                          unsigned sections);

/* ------------------------------------------------------------------ */
/* Describe (plain text, kubectl-style)                               */
/* ------------------------------------------------------------------ */

/*
 * Full rule description: ID, Type, Binary, Binary SHA-512, Command,
 * Command SHA-512, Target, Chain (one line per level: comm + SHA-512,
 * "(not recorded)" for an empty digest) and Created.  No-op when row or
 * row->entry is NULL.
 */
void cli_ui_render_rule_describe(FILE *out, const CliRuleRow *row);

/* Pin description: ID, Pattern, SHA-512, Last Updated. */
void cli_ui_render_pin_describe(FILE *out, const CliPinRow *row);

/* ------------------------------------------------------------------ */
/* JSON                                                               */
/* ------------------------------------------------------------------ */

/*
 * One JSON object holding the requested sections as arrays.  The keys
 * are "allow"/"deny" (rule rows filtered by is_deny), "pins" and
 * "sessions"; unrequested sections are omitted, {} when none is
 * requested.  Fields are complete (full ids, paths, hashes and epoch
 * times) and every dynamic string is escaped with persist_json_escape().
 */
void cli_ui_render_list_json(FILE *out, unsigned sections,
                             const CliRuleRow *rules, int n_rules,
                             const CliPinRow *pins, int n_pins,
                             const CliSessionRow *sessions, int n_sessions,
                             time_t now);

/* One JSON object for a single rule / pin, same fields as the describe. */
void cli_ui_render_rule_describe_json(FILE *out, const CliRuleRow *row);
void cli_ui_render_pin_describe_json(FILE *out, const CliPinRow *row);

#endif
