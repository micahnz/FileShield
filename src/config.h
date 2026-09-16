#ifndef FILESHIELD_CONFIG_H
#define FILESHIELD_CONFIG_H

#include <limits.h>
#include <sys/types.h>

#define MAX_PATHS 1024
#define MAX_RULES 128 /* per section: [allowlist], [unsafe_allowlist], [denylist] */

/*
 * One [protected_paths] entry.  Exact entries keep the historical
 * "equal or under" prefix semantics; glob entries ('*' present) are
 * matched by glob_match_path() after a path_under_len() prefilter on
 * the canonical wildcard-free base.
 */
typedef struct
{
    char path[PATH_MAX]; /* canonical pattern (exact path when !is_glob) */
    int is_glob;
    int is_exclude;      /* '!' entry: subtracts protection, never marks */
    int base_len;        /* wildcard-free prefix length; strlen(path) when exact */
} ProtectedPath;

/*
 * One [allowlist], [unsafe_allowlist] or [denylist] line: a binary
 * optionally scoped to a target file or directory.  An empty target_path
 * means the rule is global: it covers every protected path the binary
 * touches.  A binary may appear on multiple lines with different targets
 * when it needs exceptions for more than one file or folder.
 *
 * Either side may be a glob ('*' / '**', same engine as [protected_paths]):
 * the stored path is the canonical wildcard-free base followed by the
 * verbatim suffix, with the base length recorded in *_base_len.  Exact
 * sides keep their historical semantics — binary by strcmp, target by
 * path_under() (equal or under) — and carry is_glob = 0 with
 * base_len = strlen(path).  A global rule has an empty target_path with
 * target_base_len 0.
 */
typedef struct
{
    char binary[PATH_MAX];
    char target_path[PATH_MAX];
    int binary_is_glob;
    int binary_base_len; /* wildcard-free prefix length; strlen(binary) when exact */
    int target_is_glob;
    int target_base_len; /* wildcard-free prefix length; strlen(target_path) when exact, 0 when global */
} RuleEntry;

typedef struct
{
    ProtectedPath protected[MAX_PATHS];
    int protected_count; /* positives + exclusions                            */
    int exclude_count;   /* entries in protected[] flagged is_exclude         */
    int exclude_idx[MAX_PATHS]; /* protected[] indexes of the exclusions      */
    RuleEntry allowlist[MAX_RULES];
    int allowlist_count;
    RuleEntry unsafe_allowlist[MAX_RULES];
    int unsafe_allowlist_count;
    RuleEntry denylist[MAX_RULES];
    int denylist_count;
    int user_ttl_seconds;    /* "Allow Once" TTL; 0 = not cached (the shipped
                                config sets 300)                              */
    int session_ttl_seconds; /* TTL cap for session decisions; 0 = for as long
                                as the session leader (shell) lives          */
} Config;

int config_load(const char *path, Config *cfg);
void config_reset(Config *cfg);

extern Config *g_config;

#endif
