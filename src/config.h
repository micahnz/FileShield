#ifndef FILESHIELD_CONFIG_H
#define FILESHIELD_CONFIG_H

#include <limits.h>
#include <sys/types.h>

#define MAX_PATHS 1024
#define MAX_RULES 128 /* per section: [allowlist] and [denylist] */

typedef struct
{
    char path[PATH_MAX];
} ProtectedPath;

/*
 * One [allowlist] or [denylist] line: a binary optionally scoped to a
 * target file or directory.  An empty target_path means the rule is
 * global: it covers every protected path the binary touches.  A binary
 * may appear on multiple lines with different targets when it needs
 * exceptions for more than one file or folder.
 */
typedef struct
{
    char binary[PATH_MAX];
    char target_path[PATH_MAX];
} RuleEntry;

typedef struct
{
    ProtectedPath protected[MAX_PATHS];
    int protected_count;
    RuleEntry allowlist[MAX_RULES];
    int allowlist_count;
    RuleEntry denylist[MAX_RULES];
    int denylist_count;
    int user_ttl_seconds;    /* TTL for user-approved accesses (default 300) */
    int session_ttl_seconds; /* TTL cap for session decisions; 0 = for as long
                                as the session leader (shell) lives          */
} Config;

int config_load(const char *path, Config *cfg);
void config_reset(Config *cfg);

extern Config *g_config;

#endif
