#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>

#include "persist.h"

#define CLI_VERSION "1.0.0"

static void print_usage(FILE *f, const char *prog)
{
    fprintf(f,
            "Usage: %s <command> [options]\n"
            "\n"
            "Commands:\n"
            "  list [allow|deny]         List entries (default: both)\n"
            "  remove allow|deny BINARY SHA512 [TARGET]\n"
            "                            Remove entries by key.  With TARGET,\n"
            "                            only that file; without, every file\n"
            "                            recorded for the binary+sha pair\n"
            "  clear allow|deny           Delete all entries\n"
            "  -h, --help                 Show this help\n"
            "  -v, --version              Show version\n"
            "\n"
            "State files:\n"
            "  " PERSIST_STATE_FILE "\n"
            "  " PERSIST_DENY_STATE_FILE "\n"
            "\n"
            "After changes, reload the daemon:\n"
            "  systemctl reload fileshield\n",
            prog);
}

/*
 * Print a 16-char SHA-512 fingerprint.
 */
static const char *sha_finger(const char *sha512)
{
    static char buf[17];
    if (!sha512 || strlen(sha512) < 16)
        return "N/A";
    memcpy(buf, sha512, 16);
    buf[16] = '\0';
    return buf;
}

/*
 * Render the call chain as "comm1 -> comm2 -> comm3" (skipping empty)
 * into out.
 */
static void format_chain(const PersistEntry *e, char *out, size_t outsz)
{
    size_t used = 0;
    int printed = 0;

    if (outsz == 0)
        return;
    out[0] = '\0';

    for (int i = 0; i < e->chain_depth && i < PERSIST_CHAIN_MAX; i++)
    {
        if (!e->chain_comm[i][0])
            continue;
        int n = snprintf(out + used, outsz - used, "%s%s",
                         printed ? " -> " : "", e->chain_comm[i]);
        if (n < 0 || (size_t)n >= outsz - used)
            break;
        used += (size_t)n;
        printed = 1;
    }
    if (!printed)
        snprintf(out, outsz, "(none)");
}

/*
 * Render a table cell: control characters become '?', the text is capped
 * at max_len characters with a trailing "...".  The state file keeps the
 * full value.
 */
static void format_cell(const char *in, char *out, size_t outsz,
                        size_t max_len)
{
    size_t j = 0;

    if (outsz == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;

    for (size_t i = 0; in[i] != '\0' && j < max_len && j + 4 < outsz; i++)
    {
        unsigned char c = (unsigned char)in[i];
        out[j++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
    }
    if (in[j] != '\0')
    {
        out[j++] = '.';
        out[j++] = '.';
        out[j++] = '.';
    }
    out[j] = '\0';
}

/*
 * Render a path cell: like format_cell(), but long paths keep their tail
 * (usually the file name) behind a "~" marker so the column stays useful.
 */
static void format_path_cell(const char *in, char *out, size_t outsz,
                             size_t max_len)
{
    size_t len;
    char tail[128];

    if (outsz == 0)
        return;
    out[0] = '\0';
    if (!in || in[0] == '\0' || max_len == 0)
        return;

    len = strlen(in);
    if (len <= max_len)
    {
        format_cell(in, out, outsz, max_len);
        return;
    }

    snprintf(tail, sizeof(tail), "~%s", in + len - (max_len - 1));
    format_cell(tail, out, outsz, max_len);
}

/*
 * Print one list with a header.
 */
static void print_list(const char *label, const char *filepath)
{
    /* Heap-allocated: PersistEntry is ~9 KB, and 256 of them would need a
     * ~2.3 MB stack frame. */
    PersistEntry *entries = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    int count;

    if (!entries)
    {
        fprintf(stderr, "Error: out of memory reading %s\n", filepath);
        return;
    }

    count = persist_load(filepath, entries, PERSIST_MAX_ENTRIES);
    if (count < 0)
    {
        fprintf(stderr, "Error reading %s\n", filepath);
        free(entries);
        return;
    }

    printf("=== %s (%s) ===\n", label, filepath);
    printf("Total entries: %d\n\n", count);

    if (count == 0)
    {
        printf("(empty)\n\n");
        free(entries);
        return;
    }

    printf(" %-3s %-20s %-30s %-43s %-24s %s\n",
           "ID", "Binary", "Target", "Command", "Call chain", "SHA-512");
    printf(" %-3s %-20s %-30s %-43s %-24s %s\n",
           "---", "------------------", "-----------------------------",
           "-------------------------------------------",
           "------------------------", "------------------");

    for (int i = 0; i < count; i++)
    {
        const PersistEntry *e = &entries[i];
        const char *bin = e->binary;
        size_t bin_len = strlen(bin);
        char target[64];
        char command[64];
        char chain[1024];
        char chain_display[64];

        format_path_cell(e->target_path[0] ? e->target_path : "(any)", target,
                         sizeof(target), 30);
        format_cell(e->cmdline[0] ? e->cmdline : "(none)", command,
                    sizeof(command), 40);
        format_chain(e, chain, sizeof(chain));
        format_cell(chain, chain_display, sizeof(chain_display), 24);

        if (bin_len > 19)
        {
            const char *bin_display = bin + bin_len - 19;
            printf(" %-2d ~%-19s %-30s %-43s %-24s %s\n",
                   i, bin_display, target, command, chain_display,
                   sha_finger(e->binary_sha512));
        }
        else
        {
            printf(" %-2d %-20s %-30s %-43s %-24s %s\n",
                   i, bin, target, command, chain_display,
                   sha_finger(e->binary_sha512));
        }
    }
    printf("\n");
    free(entries);
}

int main(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "hv", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'h':
            print_usage(stdout, argv[0]);
            return 0;
        case 'v':
            printf("fileshield-cli %s\n", CLI_VERSION);
            return 0;
        default:
            print_usage(stderr, argv[0]);
            return 1;
        }
    }

    if (optind >= argc)
    {
        print_usage(stderr, argv[0]);
        return 1;
    }

    const char *cmd = argv[optind++];

    /* ── list ── */
    if (strcmp(cmd, "list") == 0)
    {
        int show_allow = 1, show_deny = 1;

        if (optind < argc)
        {
            if (strcmp(argv[optind], "allow") == 0)
                show_deny = 0;
            else if (strcmp(argv[optind], "deny") == 0)
                show_allow = 0;
            else
            {
                fprintf(stderr, "Unknown filter: %s (expected allow|deny)\n",
                        argv[optind]);
                return 1;
            }
        }

        if (show_allow)
            print_list("Allowlist", PERSIST_STATE_FILE);
        if (show_deny)
            print_list("Denylist", PERSIST_DENY_STATE_FILE);
        return 0;
    }

    /* ── remove ── */
    if (strcmp(cmd, "remove") == 0)
    {
        if (optind + 2 >= argc)
        {
            fprintf(stderr,
                    "Usage: %s remove allow|deny <binary> <sha512> [target]\n",
                    argv[0]);
            return 1;
        }

        const char *type = argv[optind++];
        const char *binary = argv[optind++];
        const char *sha512 = argv[optind++];
        const char *target = (optind < argc) ? argv[optind++] : NULL;

        const char *filepath;
        const char *label;

        if (strcmp(type, "allow") == 0)
        {
            filepath = PERSIST_STATE_FILE;
            label = "allowlist";
        }
        else if (strcmp(type, "deny") == 0)
        {
            filepath = PERSIST_DENY_STATE_FILE;
            label = "denylist";
        }
        else
        {
            fprintf(stderr, "Unknown type: %s (expected allow|deny)\n", type);
            return 1;
        }

        int r = persist_remove_key(filepath, binary, sha512, target);
        if (r < 0)
        {
            fprintf(stderr, "Error: failed to update %s\n", label);
            return 1;
        }
        if (r == 1)
        {
            fprintf(stderr,
                    "No matching entry in %s for binary=%s sha512=%s\n",
                    label, binary, sha512);
            return 1;
        }

        printf("Removed entry from %s:\n", label);
        printf("  binary:  %s\n", binary);
        printf("  sha512:  %s\n", sha512);
        if (target)
            printf("  target:  %s\n", target);
        else
            printf("  target:  (all files for this binary+sha)\n");
        printf("\nRun 'systemctl reload fileshield' to apply changes.\n");
        return 0;
    }

    /* ── clear ── */
    if (strcmp(cmd, "clear") == 0)
    {
        if (optind >= argc)
        {
            fprintf(stderr,
                    "Usage: %s clear allow|deny\n", argv[0]);
            return 1;
        }

        const char *type = argv[optind++];
        const char *filepath;
        const char *label;

        if (strcmp(type, "allow") == 0)
        {
            filepath = PERSIST_STATE_FILE;
            label = "allowlist";
        }
        else if (strcmp(type, "deny") == 0)
        {
            filepath = PERSIST_DENY_STATE_FILE;
            label = "denylist";
        }
        else
        {
            fprintf(stderr, "Unknown type: %s (expected allow|deny)\n", type);
            return 1;
        }

        /* Check if file exists before trying to delete. */
        FILE *fp = fopen(filepath, "r");
        if (!fp && errno == ENOENT)
        {
            printf("%s is already empty.\n", label);
            return 0;
        }
        if (fp)
            fclose(fp);

        if (persist_delete(filepath) < 0)
        {
            fprintf(stderr, "Error: failed to clear %s\n", label);
            return 1;
        }

        printf("Cleared entire %s.\n", label);
        printf("Run 'systemctl reload fileshield' to apply changes.\n");
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    print_usage(stderr, argv[0]);
    return 1;
}
