#ifndef FILESHIELD_CONFIG_H
#define FILESHIELD_CONFIG_H

#include <limits.h>
#include <sys/types.h>

#define MAX_PATHS 1024
#define MAX_ALLOWLIST 128

typedef struct
{
    char path[PATH_MAX];
} ProtectedPath;

typedef struct
{
    char binary[PATH_MAX];
    int ttl_seconds;
} AllowlistEntry;

typedef struct
{
    ProtectedPath protected[MAX_PATHS];
    int protected_count;
    AllowlistEntry allowlist[MAX_ALLOWLIST];
    int allowlist_count;
    char denylist[MAX_ALLOWLIST][PATH_MAX];
    int denylist_count;
    int user_ttl_seconds;    /* TTL for "Allow Once" (default 300) */
    int session_ttl_seconds; /* cap for "Allow Session"; 0 = until session ends */
} Config;

int config_load(const char *path, Config *cfg);
void config_reset(Config *cfg);

extern Config *g_config;

#endif
