#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <syslog.h>

#include "fanotify.h"
#include "utils.h"
#include "config.h"
#include "cache.h"
#include "session.h"
#include "notify.h"
#include "sha512.h"
#include "persist.h"

extern volatile sig_atomic_t g_running;
extern volatile sig_atomic_t g_need_reload;
extern volatile sig_atomic_t g_fatal;
extern Config *g_config;

#define BUF_SIZE 4096

/* Defined later in this file; declared early for the call-chain hasher. */
static int is_path_under_protected(const char *path);

/* Defined later; the decision stages respond through this. */
static int fanotify_respond(int fd, const struct fanotify_event_metadata *ev,
                            unsigned int response);

/* ------------------------------------------------------------------ */
/*  proc helpers                                                       */
/* ------------------------------------------------------------------ */
/* get_ppid(), read_comm() and the display-form read_cmdline() live in
 * utils.c (unit-tested there); the command-line fingerprint stays here
 * because it is part of the event-matching contract. */

/*
 * Resolve the path of a fanotify event fd.
 * ev->fd is an open fd in the DAEMON's fd table (not the target process's).
 * We must read /proc/self/fd/<fd_num>, not /proc/<target_pid>/fd/<fd_num>.
 */
static char *resolve_fd_path(int fd_num)
{
    char link[64];
    char *buf;
    ssize_t len;

    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd_num);
    buf = malloc(PATH_MAX);
    if (!buf)
        return NULL;
    len = readlink(link, buf, PATH_MAX - 1);
    if (len < 0)
    {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/*
 * Upper bound for the raw command line consumed by the fingerprint.  The
 * display form is capped at 512 bytes, but the fingerprint must cover the
 * full invocation: hashing only a prefix let one approved command cover a
 * different command that shared that prefix (e.g. a padded argument
 * followed by a different URL).  64 KB is far beyond any practical
 * invocation while keeping the read and hash bounded.
 */
#define CMDLINE_FP_MAX (64 * 1024)

/*
 * Fingerprint the FULL raw command line of pid (bounded by
 * CMDLINE_FP_MAX).  The NUL-separated bytes are hashed as-is, so two
 * invocations that differ anywhere inside the bound get different
 * fingerprints.  Returns 0 on success, -1 when the cmdline is unreadable
 * or empty (callers fail closed).
 */
static int read_cmdline_fingerprint(pid_t pid, char hex_out[129])
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    char *buf = malloc(CMDLINE_FP_MAX);
    if (!buf)
    {
        close(fd);
        return -1;
    }

    size_t total = 0;
    while (total < CMDLINE_FP_MAX)
    {
        ssize_t n = read(fd, buf + total, CMDLINE_FP_MAX - total);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            total = 0;
            break;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }
    close(fd);

    int rc = (total > 0) ? sha512_buf(buf, total, hex_out) : -1;
    free(buf);
    return rc;
}

/*
 * Config rule matching.  A rule matches when the binary path is equal and
 * the opened target is equal to or under the rule's target path; a rule
 * with an empty target_path is global and matches every protected path.
 * path_under() from utils provides the equal-or-under semantics.
 */
static int rule_matches(const RuleEntry *e, const char *binary,
                        const char *target)
{
    if (strcmp(e->binary, binary) != 0)
        return 0;
    return e->target_path[0] == '\0' || path_under(target, e->target_path);
}

/*
 * Config [allowlist]: an explicit admin opt-in.  On a match, grant_target
 * receives the rule's target for the file-cache insert, or NULL for a
 * global rule (wildcard cache entry).
 */
static int allowlist_match(const char *binary, const char *target,
                           const char **grant_target)
{
    if (!g_config)
        return 0;
    for (int i = 0; i < g_config->allowlist_count; i++)
    {
        const RuleEntry *e = &g_config->allowlist[i];
        if (rule_matches(e, binary, target))
        {
            *grant_target = e->target_path[0] ? e->target_path : NULL;
            return 1;
        }
    }
    return 0;
}

/* Config [denylist]: static admin-denied binary/target pairs, checked
 * before every grant so a denial always wins. */
static int denylist_match(const char *binary, const char *target)
{
    if (!g_config)
        return 0;
    for (int i = 0; i < g_config->denylist_count; i++)
    {
        if (rule_matches(&g_config->denylist[i], binary, target))
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Executable hash cache                                             */
/* ------------------------------------------------------------------ */
/*
 * Hashing forks sha512sum and runs on the event-loop critical path while
 * the requesting process is suspended, so repeat lookups of the same
 * binary reuse the cached digest.  Keyed by (dev, ino, size, mtime); any
 * metadata change invalidates the entry.
 */
#define HASH_CACHE_MAX 64

typedef struct
{
    dev_t dev;
    ino_t ino;
    off_t size;
    time_t mtime_sec;
    long mtime_nsec;
    char hex[129];
} HashCacheEntry;

static HashCacheEntry g_hash_cache[HASH_CACHE_MAX];
static int g_hash_cache_count = 0;
static int g_hash_cache_next = 0;

static int cached_sha512_proc_exe(pid_t pid, char hex_out[129])
{
    char proc_path[64];
    struct stat st;
    char hex[129];
    int r;

    int n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", (int)pid);
    if (n < 0 || (size_t)n >= sizeof(proc_path))
        return -1;

    if (stat(proc_path, &st) != 0)
        return sha512_proc_exe(pid, hex_out);

    for (int i = 0; i < g_hash_cache_count; i++)
    {
        const HashCacheEntry *e = &g_hash_cache[i];
        if (e->dev == st.st_dev && e->ino == st.st_ino &&
            e->size == st.st_size &&
            e->mtime_sec == st.st_mtim.tv_sec &&
            e->mtime_nsec == st.st_mtim.tv_nsec)
        {
            memcpy(hex_out, e->hex, sizeof(e->hex));
            return 0;
        }
    }

    r = sha512_proc_exe(pid, hex);
    if (r < 0)
        return -1;

    int slot;
    if (g_hash_cache_count < HASH_CACHE_MAX)
        slot = g_hash_cache_count++;
    else
    {
        slot = g_hash_cache_next;
        g_hash_cache_next = (g_hash_cache_next + 1) % HASH_CACHE_MAX;
    }
    g_hash_cache[slot].dev = st.st_dev;
    g_hash_cache[slot].ino = st.st_ino;
    g_hash_cache[slot].size = st.st_size;
    g_hash_cache[slot].mtime_sec = st.st_mtim.tv_sec;
    g_hash_cache[slot].mtime_nsec = st.st_mtim.tv_nsec;
    memcpy(g_hash_cache[slot].hex, hex, sizeof(hex));
    memcpy(hex_out, hex, sizeof(hex));
    return 0;
}

/* ------------------------------------------------------------------ */
/*  process call-chain (parent → grandparent → great-grandparent)     */
/* ------------------------------------------------------------------ */

typedef struct
{
    pid_t pid[PERSIST_CHAIN_MAX];
    char comm[PERSIST_CHAIN_MAX][256];
    char sha512[PERSIST_CHAIN_MAX][129]; /* lowercase hex SHA-512 of each ancestor exe */
    int depth;                           /* how many ancestors were captured            */
} ProcChain;

static void build_proc_chain(pid_t start_pid, ProcChain *c)
{
    memset(c, 0, sizeof(*c));
    pid_t cur = start_pid;
    for (int i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        pid_t p = get_ppid(cur);
        if (p <= 1)
            break;
        c->pid[i] = p;
        read_comm(p, c->comm[i], sizeof(c->comm[i]));
        char *exe = proc_exe_path(p);
        if (exe)
        {
            /* Hash via /proc/<pid>/exe so containerised binaries
             * (Podman/Docker) are reachable even if their path doesn't
             * exist on the host.  Never open a protected path to hash it:
             * the daemon would intercept its own helper. */
            if (!is_path_under_protected(exe))
                cached_sha512_proc_exe(p, c->sha512[i]); /* best-effort */
            free(exe);
        }
        c->depth = i + 1;
        cur = p;
    }
}

/* ------------------------------------------------------------------ */
/*  runtime dynamic allowlist / denylist ("Always" decisions)         */
/* ------------------------------------------------------------------ */

#define DYN_MAX 256

typedef struct
{
    char binary[PATH_MAX];
    char binary_sha512[129];
    char target_path[PATH_MAX];              /* exact file this entry applies to */
    char cmdline[PERSIST_CMDLINE_MAX];       /* raw command line (audit/display) */
    char cmdline_sha512[129];                /* command-line matching key        */
    char chain_comm[PERSIST_CHAIN_MAX][256];
    char chain_sha512[PERSIST_CHAIN_MAX][129];
    int chain_depth;
} DynEntry;

static DynEntry g_dyn_allow[DYN_MAX];
static int g_dyn_allow_count = 0;

static DynEntry g_dyn_deny[DYN_MAX];
static int g_dyn_deny_count = 0;

/* ------------------------------------------------------------------ */
/*  Dialog rate limiting                                              */
/* ------------------------------------------------------------------ */
/*
 * A process can exec itself repeatedly (new PID each time) so that the
 * per-PID cache never helps, flooding the user with dialogs while each
 * open is suspended.  Bound prompts per binary path and fail closed
 * (deny) for a cooldown window once the bound is exceeded.
 */
#define DIALOG_RATE_MAX 16
#define DIALOG_RATE_PROMPTS 20
#define DIALOG_RATE_WINDOW_S 60
#define DIALOG_RATE_COOLDOWN_S 30

typedef struct
{
    char binary[PATH_MAX];
    time_t window_start;
    int prompts;
    time_t blocked_until;
} DialogRateEntry;

static DialogRateEntry g_dialog_rate[DIALOG_RATE_MAX];
static int g_dialog_rate_count = 0;
static int g_dialog_rate_next = 0;

/* Returns 1 when the dialog should be skipped (deny) to bound flooding. */
static int dialog_rate_limited(const char *binary)
{
    time_t now = time(NULL);
    DialogRateEntry *e = NULL;

    for (int i = 0; i < g_dialog_rate_count; i++)
    {
        if (strcmp(g_dialog_rate[i].binary, binary) == 0)
        {
            e = &g_dialog_rate[i];
            break;
        }
    }

    if (!e)
    {
        int slot;
        if (g_dialog_rate_count < DIALOG_RATE_MAX)
            slot = g_dialog_rate_count++;
        else
        {
            slot = g_dialog_rate_next;
            g_dialog_rate_next = (g_dialog_rate_next + 1) % DIALOG_RATE_MAX;
        }
        e = &g_dialog_rate[slot];
        memset(e, 0, sizeof(*e));
        snprintf(e->binary, sizeof(e->binary), "%s", binary);
        e->window_start = now;
    }

    if (now < e->blocked_until)
        return 1;

    if (now - e->window_start > DIALOG_RATE_WINDOW_S)
    {
        e->window_start = now;
        e->prompts = 0;
    }

    if (++e->prompts > DIALOG_RATE_PROMPTS)
    {
        e->blocked_until = now + DIALOG_RATE_COOLDOWN_S;
        log_msg(LOG_WARNING,
                "dialog rate limit: %s exceeded %d prompts in %ds; "
                "denying further prompts for %ds",
                binary, DIALOG_RATE_PROMPTS, DIALOG_RATE_WINDOW_S,
                DIALOG_RATE_COOLDOWN_S);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  shared persistence helpers for allowlist / denylist               */
/* ------------------------------------------------------------------ */

/* Copy DynEntry entries into a PersistEntry array.  Returns count. */
static int dyn_to_persist(const DynEntry *entries, int count,
                          PersistEntry *out, int max)
{
    int n = count < max ? count : max;
    memset(out, 0, sizeof(*out) * max);
    for (int i = 0; i < n; i++)
    {
        const DynEntry *src = &entries[i];
        PersistEntry *dst = &out[i];
        memcpy(dst->binary, src->binary, sizeof(src->binary));
        dst->binary[sizeof(dst->binary) - 1] = '\0';
        memcpy(dst->binary_sha512, src->binary_sha512, sizeof(src->binary_sha512));
        dst->binary_sha512[sizeof(dst->binary_sha512) - 1] = '\0';
        memcpy(dst->target_path, src->target_path, sizeof(src->target_path));
        dst->target_path[sizeof(dst->target_path) - 1] = '\0';
        memcpy(dst->cmdline, src->cmdline, sizeof(src->cmdline));
        dst->cmdline[sizeof(dst->cmdline) - 1] = '\0';
        memcpy(dst->cmdline_sha512, src->cmdline_sha512,
               sizeof(src->cmdline_sha512));
        dst->cmdline_sha512[sizeof(dst->cmdline_sha512) - 1] = '\0';
        dst->chain_depth = src->chain_depth;
        for (int j = 0; j < src->chain_depth; j++)
        {
            memcpy(dst->chain_comm[j], src->chain_comm[j], sizeof(src->chain_comm[j]));
            dst->chain_comm[j][sizeof(dst->chain_comm[j]) - 1] = '\0';
            memcpy(dst->chain_sha512[j], src->chain_sha512[j], sizeof(src->chain_sha512[j]));
            dst->chain_sha512[j][sizeof(dst->chain_sha512[j]) - 1] = '\0';
        }
    }
    return n;
}

/* Copy a DynEntry array to PersistEntry, stamp created_at, write to disk. */
static void persist_dyn_list(const char *filepath, const DynEntry *entries,
                             int count, const char *name)
{
    PersistEntry *buf = calloc(DYN_MAX, sizeof(PersistEntry));
    if (!buf)
    {
        log_msg(LOG_ERR, "out of memory persisting %s", name);
        return;
    }

    int n = dyn_to_persist(entries, count, buf, DYN_MAX);
    time_t now = time(NULL);
    for (int i = 0; i < n; i++)
        buf[i].created_at = now;

    if (persist_save(filepath, buf, n) < 0)
        log_msg(LOG_WARNING, "persist_save failed; %s entry not persisted", name);
    free(buf);
}

/*
 * Load PersistEntry entries into a DynEntry array.
 * When require_binary_sha512 is set, entries without a binary SHA-512 are
 * dropped (fail closed): a permanent grant that cannot prove which binary
 * was approved must never be trusted as a wildcard.
 * When require_target_path is set, entries without a target path are
 * dropped (fail closed): file-scoped matching cannot honour a wildcard
 * grant from an old or hand-edited state file.
 * When require_cmdline is set, entries without a raw command line or
 * without its matching digest are dropped too: an entry that cannot pin
 * the exact invocation would silently cover every command of that binary,
 * and one that cannot show the invocation is not auditable.
 */
static void load_dyn_list(DynEntry *list, int *list_count,
                          const PersistEntry *entries, int count,
                          const char *name, int require_binary_sha512,
                          int require_target_path, int require_cmdline)
{
    /* Always replace the in-memory list so a removed state file or a
     * corrupt/unreadable one cannot leave stale grants or denies active
     * in the running daemon. */
    memset(list, 0, sizeof(DynEntry) * DYN_MAX);
    *list_count = 0;

    if (!entries || count <= 0)
    {
        log_msg(LOG_DEBUG, "cleared persisted %s entries", name);
        return;
    }
    if (count > DYN_MAX)
        count = DYN_MAX;
    int n = 0;
    for (int i = 0; i < count; i++)
    {
        const PersistEntry *src = &entries[i];
        DynEntry *dst = &list[n];
        snprintf(dst->binary, sizeof(dst->binary), "%s", src->binary);
        snprintf(dst->binary_sha512, sizeof(dst->binary_sha512), "%s", src->binary_sha512);
        snprintf(dst->target_path, sizeof(dst->target_path), "%s", src->target_path);
        snprintf(dst->cmdline, sizeof(dst->cmdline), "%s", src->cmdline);
        snprintf(dst->cmdline_sha512, sizeof(dst->cmdline_sha512), "%s", src->cmdline_sha512);
        int depth = src->chain_depth;
        if (depth < 0)
            depth = 0;
        if (depth > PERSIST_CHAIN_MAX)
            depth = PERSIST_CHAIN_MAX;
        dst->chain_depth = depth;
        for (int j = 0; j < depth; j++)
        {
            snprintf(dst->chain_comm[j], sizeof(dst->chain_comm[j]), "%s", src->chain_comm[j]);
            snprintf(dst->chain_sha512[j], sizeof(dst->chain_sha512[j]), "%s", src->chain_sha512[j]);
        }
        if (require_binary_sha512 && dst->binary_sha512[0] == '\0')
        {
            log_msg(LOG_WARNING,
                    "dropping %s entry \"%s\": no binary SHA-512 recorded "
                    "(fail closed)",
                    name, dst->binary);
            continue;
        }
        if (require_target_path && dst->target_path[0] == '\0')
        {
            log_msg(LOG_WARNING,
                    "dropping %s entry \"%s\": no target path recorded "
                    "(fail closed)",
                    name, dst->binary);
            continue;
        }
        if (require_cmdline &&
            (dst->cmdline[0] == '\0' || dst->cmdline_sha512[0] == '\0'))
        {
            log_msg(LOG_WARNING,
                    "dropping %s entry \"%s\": incomplete command-line record "
                    "(fail closed)",
                    name, dst->binary);
            continue;
        }
        n++;
    }
    *list_count = n;
    log_msg(LOG_INFO, "loaded %d persisted %s entries", n, name);
}

/* ------------------------------------------------------------------ */
/*  runtime matching functions                                        */
/* ------------------------------------------------------------------ */

/*
 * Shared matcher for the runtime allow/deny lists.  Entries are scoped to
 * the exact file and the exact invocation that triggered the dialog:
 * approving a plugin's "kubectl config view" must not silently grant a
 * later "kubectl get secrets" from the same shell.
 *
 * Every recorded key must match; an unverifiable key never matches.  The
 * two lists differ in exactly one admission point, require_binary_sha:
 *   - allow (1): an entry without a binary SHA-512 is skipped -- a grant
 *     must prove which binary was approved or it would act as a wildcard.
 *   - deny  (0): a legacy entry without a binary SHA-512 still matches; a
 *     missing *current* hash skips the entry (re-prompt) instead of
 *     denying on an unverified identity.
 * The command-line fingerprint is compared, not recomputed: the caller
 * produces it lazily so unrelated events never pay for the hash.
 */
static int dyn_match(const DynEntry *list, int count,
                     const char *binary, const char *bin_sha512,
                     const ProcChain *chain, const char *target,
                     const char *cmdline_fp, int require_binary_sha)
{
    if (!target || target[0] == '\0')
        return 0;

    for (int i = 0; i < count; i++)
    {
        const DynEntry *e = &list[i];

        /* Cheap keys first: path equality before any hash comparison. */
        if (strcmp(e->binary, binary) != 0)
            continue;
        if (strcmp(e->target_path, target) != 0)
            continue;

        if (e->binary_sha512[0] == '\0')
        {
            if (require_binary_sha)
                continue;
        }
        else
        {
            /* A stored hash with no usable current hash cannot be
             * verified, so the entry does not match (fail secure). */
            if (bin_sha512[0] == '\0')
                continue;
            if (strcmp(e->binary_sha512, bin_sha512) != 0)
                continue;
        }

        if (e->chain_depth != chain->depth)
            continue;

        int ok = 1;
        for (int j = 0; j < chain->depth; j++)
        {
            if (strcmp(e->chain_comm[j], chain->comm[j]) != 0)
            {
                ok = 0;
                break;
            }
            /* Ancestor hashes are checked only when the entry recorded
             * one; a stored hash with no current hash fails the match. */
            if (e->chain_sha512[j][0] != '\0')
            {
                if (chain->sha512[j][0] == '\0')
                {
                    ok = 0;
                    break;
                }
                if (strcmp(e->chain_sha512[j], chain->sha512[j]) != 0)
                {
                    ok = 0;
                    break;
                }
            }
        }
        if (!ok)
            continue;

        /* An entry without a command fingerprint can never match, and an
         * unavailable current fingerprint is re-prompted (fail closed). */
        if (e->cmdline_sha512[0] == '\0')
            continue;
        if (!cmdline_fp || cmdline_fp[0] == '\0')
            continue;
        if (strcmp(e->cmdline_sha512, cmdline_fp) != 0)
            continue;
        return 1;
    }
    return 0;
}

/* "Always Allow" lookup: grants are strict (see dyn_match). */
static int dyn_allow_match(const char *binary, const char *bin_sha512,
                           const ProcChain *chain, const char *target,
                           const char *cmdline_fp)
{
    return dyn_match(g_dyn_allow, g_dyn_allow_count, binary, bin_sha512,
                     chain, target, cmdline_fp, 1);
}

/*
 * Append one runtime entry, dropping the oldest when the list is full.
 * Shared by the allow and deny sides; each caller keeps its own admission
 * policy (the allow side refuses entries it cannot pin to a binary).
 */
static void dyn_add(DynEntry *list, int *count, const char *binary,
                    const char *bin_sha512, const ProcChain *chain,
                    const char *target, const char *cmdline,
                    const char *cmdline_sha512, const char *name)
{
    if (*count >= DYN_MAX)
    {
        log_msg(LOG_WARNING, "dynamic %s full (%d); dropping oldest entry",
                name, DYN_MAX);
        memmove(&list[0], &list[1], sizeof(DynEntry) * (DYN_MAX - 1));
        *count = DYN_MAX - 1;
    }

    DynEntry *e = &list[(*count)++];
    memset(e, 0, sizeof(*e));
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", bin_sha512);
    if (target)
        snprintf(e->target_path, sizeof(e->target_path), "%s", target);
    snprintf(e->cmdline, sizeof(e->cmdline), "%s", cmdline);
    snprintf(e->cmdline_sha512, sizeof(e->cmdline_sha512), "%s",
             cmdline_sha512);
    e->chain_depth = chain->depth;
    for (int i = 0; i < chain->depth; i++)
    {
        snprintf(e->chain_comm[i], sizeof(e->chain_comm[i]), "%s", chain->comm[i]);
        snprintf(e->chain_sha512[i], sizeof(e->chain_sha512[i]), "%s", chain->sha512[i]);
    }
}

/* First 16 hex chars of a digest for log lines; the state file has the
 * full hash.  An empty digest logs as "????????????????". */
static void sha_prefix(const char *sha512, char out[17])
{
    memcpy(out, "????????????????", 17);
    if (sha512[0] != '\0')
        memcpy(out, sha512, 16);
    out[16] = '\0';
}

static void dyn_allow_add(const char *binary, const char *bin_sha512,
                          const ProcChain *chain, const char *target,
                          const char *cmdline, const char *cmdline_sha512)
{
    /* Fail closed at creation: a permanent grant is only recorded when the
     * binary's SHA-512 was actually computed.  Without it the entry would
     * match any binary at this path forever. */
    if (bin_sha512[0] == '\0')
    {
        log_msg(LOG_WARNING,
                "refusing permanent allow for %s: binary SHA-512 unavailable; "
                "granting one-time access only (re-prompt will occur)",
                binary);
        return;
    }

    /* Likewise the exact invocation must be pinned and recorded; without
     * it the entry would cover every command of that binary, and an entry
     * nobody can identify is not usable for review. */
    if (!cmdline || cmdline[0] == '\0' ||
        !cmdline_sha512 || cmdline_sha512[0] == '\0')
    {
        log_msg(LOG_WARNING,
                "refusing permanent allow for %s: command line could not be "
                "recorded and fingerprinted; granting one-time access only",
                binary);
        return;
    }

    dyn_add(g_dyn_allow, &g_dyn_allow_count, binary, bin_sha512, chain,
            target, cmdline, cmdline_sha512, "allowlist");

    char sha_short[17];
    sha_prefix(bin_sha512, sha_short);
    log_msg(LOG_INFO,
            "always-allow added: %s (sha512: %s...) chain-depth=%d -> %s",
            binary, sha_short, chain->depth, target ? target : "(unknown)");

    persist_dyn_list(PERSIST_STATE_FILE, g_dyn_allow, g_dyn_allow_count,
                     "allowlist");
}

/*
 * "Always Deny" lookup: denials may be broader than grants (legacy
 * entries without a binary hash still apply) but never match on an
 * identity that cannot be verified -- see dyn_match.
 */
static int dyn_deny_match(const char *binary, const char *bin_sha512,
                          const ProcChain *chain, const char *target,
                          const char *cmdline_fp)
{
    return dyn_match(g_dyn_deny, g_dyn_deny_count, binary, bin_sha512,
                     chain, target, cmdline_fp, 0);
}

static void dyn_deny_add(const char *binary, const char *bin_sha512,
                         const ProcChain *chain, const char *target,
                         const char *cmdline, const char *cmdline_sha512)
{
    /* Without the exact invocation the entry could never match; refuse
     * to create a misleading permanent denial. */
    if (!cmdline || cmdline[0] == '\0' ||
        !cmdline_sha512 || cmdline_sha512[0] == '\0')
    {
        log_msg(LOG_WARNING,
                "refusing permanent deny for %s: command line could not be "
                "recorded and fingerprinted; denying this attempt only",
                binary);
        return;
    }

    dyn_add(g_dyn_deny, &g_dyn_deny_count, binary, bin_sha512, chain,
            target, cmdline, cmdline_sha512, "denylist");

    char sha_short[17];
    sha_prefix(bin_sha512, sha_short);
    log_msg(LOG_INFO,
            "always-deny added: %s (sha512: %s...) chain-depth=%d -> %s",
            binary, sha_short, chain->depth, target ? target : "(unknown)");

    persist_dyn_list(PERSIST_DENY_STATE_FILE, g_dyn_deny, g_dyn_deny_count,
                     "denylist");
}

/* ------------------------------------------------------------------ */
/*  Protected inode table  (hard-link bypass detection)               */
/* ------------------------------------------------------------------ */

typedef struct
{
    dev_t dev;
    ino_t ino;
} ProtectedInode;

#define MAX_INODE_TABLE (MAX_PATHS * 32)
#define MAX_INODE_WALK_DEPTH 8 /* max recursion depth for protected-directory inode enumeration */
static ProtectedInode g_inode_table[MAX_INODE_TABLE];
static int g_inode_count = 0;

/* One FAN_MARK_MOUNT per unique filesystem device */
#define MAX_MOUNTS 32
typedef struct
{
    dev_t dev;
    char path[PATH_MAX]; /* any path on that mount, used for mark removal */
} MountEntry;
static MountEntry g_mounts[MAX_MOUNTS];
static int g_mount_count = 0;

static void inode_table_add(dev_t dev, ino_t ino)
{
    for (int i = 0; i < g_inode_count; i++)
        if (g_inode_table[i].dev == dev && g_inode_table[i].ino == ino)
            return;
    if (g_inode_count >= MAX_INODE_TABLE)
    {
        log_msg(LOG_WARNING, "inode table full; hard-link detection may be incomplete");
        return;
    }
    g_inode_table[g_inode_count].dev = dev;
    g_inode_table[g_inode_count].ino = ino;
    g_inode_count++;
}

static int inode_is_protected(dev_t dev, ino_t ino)
{
    for (int i = 0; i < g_inode_count; i++)
        if (g_inode_table[i].dev == dev && g_inode_table[i].ino == ino)
            return 1;
    return 0;
}

/* Recursively walk a directory and add inodes of all regular files.
 * Stays on the same device (no cross-mount traversal).
 * Depth is capped at MAX_INODE_WALK_DEPTH to bound worst-case traversal time. */
static void inode_walk_dir(const char *dirpath, dev_t dev, int depth)
{
    if (depth > MAX_INODE_WALK_DEPTH)
        return;
    DIR *d = opendir(dirpath);
    if (!d)
    {
        log_msg(LOG_WARNING, "inode_walk_dir: cannot open %s: %s", dirpath,
                strerror(errno));
        return;
    }
    const struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[PATH_MAX];
        if (snprintf(child, sizeof(child), "%s/%s", dirpath, ent->d_name) >= (int)sizeof(child))
            continue;
        struct stat st;
        if (lstat(child, &st) != 0)
            continue;
        if (st.st_dev != dev) /* skip bind mounts / nested filesystems */
            continue;
        if (S_ISREG(st.st_mode))
            inode_table_add(st.st_dev, st.st_ino);
        else if (S_ISDIR(st.st_mode))
            inode_walk_dir(child, dev, depth + 1);
    }
    closedir(d);
}

/*
 * Returns 1 if `path` falls under any currently protected path.
 * Used to distinguish events from directory marks vs. mount marks (hard-link).
 * Delegates the boundary math to the shared path_under() helper.
 */
static int is_path_under_protected(const char *path)
{
    if (!g_config)
        return 0;
    for (int i = 0; i < g_config->protected_count; i++)
    {
        if (path_under(path, g_config->protected[i].path))
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  mark bookkeeping                                                  */
/* ------------------------------------------------------------------ */
/*
 * fanotify_mark() removal needs the same event mask that was used to add
 * the mark (file and directory marks differ), so the mask is recorded per
 * path.  The table also tracks directory marks auto-added for directories
 * created inside protected trees, and lets a reload remove every mark the
 * daemon installed.
 */
#define MAX_MARK_TABLE 4096
#define MAX_AUTO_MARKS 1024

typedef struct
{
    char *path; /* strdup'd */
    unsigned int mask;
} MarkEntry;

static MarkEntry g_marks[MAX_MARK_TABLE];
static int g_mark_count = 0;
static int g_auto_mark_count = 0;

static MarkEntry *mark_find(const char *path)
{
    for (int i = 0; i < g_mark_count; i++)
        if (strcmp(g_marks[i].path, path) == 0)
            return &g_marks[i];
    return NULL;
}

static void mark_table_add(const char *path, unsigned int mask)
{
    MarkEntry *e = mark_find(path);
    if (e)
    {
        e->mask = mask;
        return;
    }
    if (g_mark_count >= MAX_MARK_TABLE)
    {
        log_msg(LOG_WARNING, "mark table full; cannot track %s", path);
        return;
    }
    char *copy = strdup(path);
    if (!copy)
    {
        log_msg(LOG_WARNING, "out of memory tracking mark %s", path);
        return;
    }
    g_marks[g_mark_count].path = copy;
    g_marks[g_mark_count].mask = mask;
    g_mark_count++;
}

/*
 * Event mask used for file and directory marks.
 *
 * Directory-entry events (FAN_CREATE, FAN_DELETE, FAN_MOVED_FROM,
 * FAN_MOVED_TO, FAN_ATTRIB, FAN_DELETE_SELF) are deliberately absent:
 * they require a group initialized with FAN_REPORT_FID, and adding them
 * to this fd-based group makes fanotify_mark() fail with EINVAL
 * (fanotify_mark(2): "The group was initialized without FAN_REPORT_FID
 * but one or more event types specified in the mask require it").
 * Post-start files are therefore matched by canonical path; FID-based
 * create tracking is a planned follow-up.
 */
unsigned int fanotify_mark_mask(void)
{
    return FAN_OPEN_PERM | FAN_EVENT_ON_CHILD;
}

/* ------------------------------------------------------------------ */
/*  public API                                                         */
/* ------------------------------------------------------------------ */

int fanotify_setup(void)
{
    /*
     * FAN_UNLIMITED_QUEUE is required for fail-closed semantics.  With a
     * bounded queue, fsnotify_insert_event() reports "queue overflown",
     * fanotify_handle_event() drops the permission event and returns 0,
     * and the filesystem operation proceeds without a listener decision
     * (see fs/notify/fanotify/fanotify.c).  Only an event-allocation
     * failure denies.  Event volume is kept down by the mount-mark fast
     * path and the bounded pending queue; FAN_Q_OVERFLOW is still handled
     * fail-closed if it ever appears.
     */
    int fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE,
                           O_RDONLY | O_LARGEFILE);
    if (fd < 0)
    {
        log_msg(LOG_ERR, "fanotify_init: %s", strerror(errno));
        return -1;
    }
    log_msg(LOG_INFO, "fanotify fd %d created", fd);
    return fd;
}

/* Add a FAN_MARK_MOUNT for the filesystem containing st, if not already
 * tracked.  "path" may be any existing path on that filesystem; it is
 * remembered for mark removal. */
static void add_mount_mark_if_needed(int fd, const struct stat *st,
                                     const char *path)
{
    for (int i = 0; i < g_mount_count; i++)
    {
        if (g_mounts[i].dev == st->st_dev)
            return;
    }

    if (g_mount_count >= MAX_MOUNTS)
    {
        log_msg(LOG_WARNING, "mount table full; hard-link detection limited");
        return;
    }

    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                      FAN_OPEN_PERM, AT_FDCWD, path) == 0)
    {
        g_mounts[g_mount_count].dev = st->st_dev;
        snprintf(g_mounts[g_mount_count].path,
                 sizeof(g_mounts[g_mount_count].path), "%s", path);
        g_mount_count++;
        log_msg(LOG_INFO, "fanotify mount mark added (dev %lu) for hard-link detection",
                (unsigned long)st->st_dev);
    }
    else
    {
        log_msg(LOG_WARNING,
                "fanotify mount mark failed for %s: %s "
                "(hard-link detection disabled for this filesystem)",
                path, strerror(errno));
    }
}

/*
 * A configured path that does not exist yet cannot be marked directly.
 * Walk up to the nearest existing ancestor and make sure its filesystem
 * carries a mount mark, so an open of the path after it is created is
 * still intercepted and matched by is_path_under_protected().
 */
static void ensure_mount_mark_for_missing(int fd, const char *path)
{
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", path);

    char *slash;
    while ((slash = strrchr(buf, '/')) != NULL && slash != buf)
    {
        *slash = '\0';
        struct stat st;
        if (stat(buf, &st) == 0)
        {
            add_mount_mark_if_needed(fd, &st, buf);
            return;
        }
    }

    struct stat st;
    if (stat("/", &st) == 0)
        add_mount_mark_if_needed(fd, &st, "/");
}

int fanotify_add_mark(int fd, const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0)
    {
        if (errno == ENOENT)
        {
            /* Not an error: the secret file simply does not exist yet.
             * The mount mark keeps the path monitored once it appears. */
            ensure_mount_mark_for_missing(fd, path);
            log_msg(LOG_WARNING,
                    "protected path does not exist yet, skipping direct mark: %s",
                    path);
            return 1;
        }
        log_msg(LOG_ERR, "stat %s: %s", path, strerror(errno));
        return -1;
    }

    unsigned int mask = fanotify_mark_mask();
    if (fanotify_mark(fd, FAN_MARK_ADD, mask, AT_FDCWD, path) < 0)
    {
        log_msg(LOG_ERR, "fanotify_mark ADD %s: %s", path, strerror(errno));
        return -1;
    }
    mark_table_add(path, mask);
    log_msg(LOG_INFO, "fanotify mark added: %s", path);

    if (S_ISREG(st.st_mode))
        inode_table_add(st.st_dev, st.st_ino);
    else if (S_ISDIR(st.st_mode))
        inode_walk_dir(path, st.st_dev, 0);

    add_mount_mark_if_needed(fd, &st, path);
    return 0;
}

/* Non-zero when at least one file/directory or mount mark is active. */
int fanotify_any_mark_active(void)
{
    return g_mark_count > 0 || g_mount_count > 0;
}

/*
 * Newly created directories inside a protected tree need their own mark:
 * directory marks are not recursive, and this keeps path matching (and
 * hard-link inode tracking) effective for their contents.  Bounded by
 * MAX_AUTO_MARKS so a runaway create storm cannot exhaust marks.
 */
static void auto_mark_created_path(int fan_fd, const char *path)
{
    if (g_auto_mark_count >= MAX_AUTO_MARKS)
        return;
    if (mark_find(path))
        return;
    if (fanotify_add_mark(fan_fd, path) == 0)
    {
        g_auto_mark_count++;
        log_msg(LOG_INFO, "auto-marked created object: %s", path);
    }
}

/*
 * Notification events (FAN_CREATE / FAN_MOVED_TO) are not permission
 * events: no response is written, but the event fd must be closed and the
 * created object's inode is recorded so hard links to it stay protected.
 *
 * The current fd-based group cannot produce these events (they require
 * FAN_REPORT_FID and would make fanotify_mark() fail EINVAL); the branch
 * is kept so a future FID-enabled group still gets inode tracking.
 */
static void handle_notification_event(int fan_fd,
                                      const struct fanotify_event_metadata *ev)
{
    if (!(ev->mask & (FAN_CREATE | FAN_MOVED_TO)))
    {
        if (ev->fd != FAN_NOFD)
            close((int)ev->fd);
        return;
    }

    if (ev->fd == FAN_NOFD)
        return;

    struct stat st;
    if (fstat((int)ev->fd, &st) == 0)
    {
        inode_table_add(st.st_dev, st.st_ino);
        if (S_ISDIR(st.st_mode))
        {
            char *created = resolve_fd_path((int)ev->fd);
            if (created)
            {
                auto_mark_created_path(fan_fd, created);
                free(created);
            }
        }
    }
    close((int)ev->fd);
}

/* ------------------------------------------------------------------ */
/*  Recent-decision deduplication cache                               */
/* ------------------------------------------------------------------ */
/*
 * When both a directory mark and a mount mark are active, the kernel fires
 * two separate FAN_OPEN_PERM events for the same file open (one per mark).
 * The cache records the (pid, dev, ino) → decision for the most recent
 * RECENT_CACHE_MAX events so the second identical event is resolved
 * instantly without showing a second dialog.
 *
 * Entries expire after RECENT_CACHE_TTL_MS milliseconds.
 */
#define RECENT_CACHE_MAX 32
#define RECENT_CACHE_TTL_MS 2000

typedef struct
{
    pid_t pid;
    dev_t dev;
    ino_t ino;
    int fan_decision; /* FAN_ALLOW or FAN_DENY */
    struct timespec ts;
} RecentDecision;

static RecentDecision g_recent[RECENT_CACHE_MAX];
static int g_recent_count = 0;
static int g_recent_head = 0; /* ring-buffer write head */

static void recent_cache_insert(pid_t pid, dev_t dev, ino_t ino, int decision)
{
    int slot = g_recent_head % RECENT_CACHE_MAX;
    g_recent[slot].pid = pid;
    g_recent[slot].dev = dev;
    g_recent[slot].ino = ino;
    g_recent[slot].fan_decision = decision;
    clock_gettime(CLOCK_MONOTONIC, &g_recent[slot].ts);
    g_recent_head++;
    if (g_recent_count < RECENT_CACHE_MAX)
        g_recent_count++;
}

/* Returns FAN_ALLOW, FAN_DENY, or -1 (not found / expired). */
static int recent_cache_lookup(pid_t pid, dev_t dev, ino_t ino)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = 0; i < g_recent_count; i++)
    {
        RecentDecision *e = &g_recent[i];
        if (e->pid != pid || e->dev != dev || e->ino != ino)
            continue;
        long age_ms = (now.tv_sec - e->ts.tv_sec) * 1000L + (now.tv_nsec - e->ts.tv_nsec) / 1000000L;
        if (age_ms > RECENT_CACHE_TTL_MS)
            continue; /* expired: a newer entry for this key may follow */
        return e->fan_decision;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  deferred permission events                                        */
/* ------------------------------------------------------------------ */
/*
 * fanotify_pump() runs while a dialog is displayed.  It may read events it
 * cannot decide (protected paths); those are copied here with their event
 * fd left open and replayed by the main loop once the dialog is finished.
 * Closing the event fd without a response would leave the caller's open()
 * blocked forever and leak a kernel permission event.
 */
#define PENDING_MAX 256

typedef struct
{
    struct fanotify_event_metadata meta;
} PendingEvent;

static PendingEvent g_pending[PENDING_MAX];
static int g_pending_count = 0;

/*
 * Queue a read-but-undecided permission event for replay by the main
 * loop.  The kernel event fd must stay open: the kernel keeps the
 * permission event pending until a response is written, so closing it
 * here would block the caller's open() forever and leak the event.
 * Returns 0 when queued, -1 when the pending queue is full — the caller
 * must then respond fail-closed (FAN_DENY) and close the event fd.
 */
int fanotify_defer_event(const struct fanotify_event_metadata *ev)
{
    if (g_pending_count >= PENDING_MAX)
        return -1;
    g_pending[g_pending_count].meta = *ev;
    g_pending_count++;
    return 0;
}

/* Real uid of the requesting process, or (uid_t)-1 when unknown. */
static uid_t proc_uid(pid_t pid)
{
    char path[64], line[256];
    FILE *f;
    unsigned int uid = 0;
    int found = 0;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return (uid_t)-1;
    while (fgets(line, sizeof(line), f))
    {
        if (sscanf(line, "Uid:\t%u", &uid) == 1)
        {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? (uid_t)uid : (uid_t)-1;
}

/*
 * Returns 1 if pid is the dialog child, a direct child of it (timeout(1)
 * execs kdialog), or in the dialog's process group (the dialog child calls
 * setpgid(0,0) before exec).
 */
static int process_in_dialog_group(pid_t pid, pid_t dialog_pid)
{
    if (dialog_pid <= 0)
        return 0;
    if (pid == dialog_pid)
        return 1;
    if (get_ppid(pid) == dialog_pid)
        return 1;

    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    if (!fgets(buf, sizeof(buf), f))
    {
        fclose(f);
        return 0;
    }
    fclose(f);

    const char *p = strrchr(buf, ')');
    if (!p)
        return 0;
    p++;
    long pgrp = 0;
    if (sscanf(p, " %*c %*d %ld", &pgrp) != 1)
        return 0;
    return (pid_t)pgrp == dialog_pid;
}

/*
 * Full decision path for a FAN_OPEN_PERM event.  Takes ownership of ev->fd:
 * every path responds and closes the event fd, or (in the pump) defers it.
 */
/* ------------------------------------------------------------------ */
/*  per-event decision context                                         */
/* ------------------------------------------------------------------ */
/*
 * Everything the decision stages need for one FAN_OPEN_PERM event.
 * Identity fields are gathered once while the requesting process is
 * kernel-suspended (its /proc entry cannot change under us), then
 * threaded through the stages in fixed decision order.
 */
typedef struct
{
    int fan_fd;
    const struct fanotify_event_metadata *ev;
    int fd_num;
    int close_fd; /* 0 only for FAN_NOFD: there is no descriptor to close */

    char *binary; /* /proc/<pid>/exe, malloc'd    */
    char *target; /* /proc/self/fd/<fd>, malloc'd */
    dev_t ev_dev;
    ino_t ev_ino;

    /* Cached prefix verdict: the target path needs it in the fast path,
     * the hard-link classification and the prompt policy, and the
     * protected set can hold hundreds of entries. */
    int path_protected;

    /* Set when a protected inode is opened through a path outside every
     * protected prefix (hard link / unverifiable path): grants are then
     * skipped and the user is prompted for this exact path. */
    int hardlink_event;

    /* Requester identity, gathered after the pre-hash deny checks. */
    pid_t ppid;
    char comm[256];
    char pcomm[256];
    char cmdline[512];        /* display form (NUL-collapsed, bounded)     */
    char bin_sha512[129];
    char cmdline_sha512[129]; /* full raw cmdline, computed lazily          */
    int cmdline_sha_state;    /* 0 = not computed, 1 = computed, -1 = failed */
    ProcChain chain;
    pid_t sid;
    unsigned long long sid_start;
    int have_sid;
} EventCtx;

/*
 * Lazily fingerprint the requester's full command line.  Only the runtime
 * matchers and permanent-decision recording call it, so cache/session
 * hits never pay for the /proc read or the hash.  Returns the digest, or
 * "" when it cannot be computed (callers fail closed).  The requesting
 * process is kernel-suspended for the whole event, so its /proc entry
 * stays valid between this read and the decision.
 */
static const char *event_cmdline_fp(EventCtx *c)
{
    if (c->cmdline_sha_state == 0)
    {
        if (read_cmdline_fingerprint(c->ev->pid, c->cmdline_sha512) < 0)
        {
            c->cmdline_sha512[0] = '\0';
            c->cmdline_sha_state = -1;
        }
        else
            c->cmdline_sha_state = 1;
    }
    return c->cmdline_sha512;
}

/*
 * Every deciding stage funnels through here so the dedup-cache insert
 * and the kernel response always happen together, in that order.
 */
static void ctx_respond(EventCtx *c, unsigned int response)
{
    recent_cache_insert(c->ev->pid, c->ev_dev, c->ev_ino, (int)response);
    fanotify_respond(c->fan_fd, c->ev, response);
}

/*
 * Stage 1: sanity-check the event fd and resolve the target path from
 * the daemon's fd table.  Returns 1 when the event was decided here
 * (FAN_NOFD or an unresolvable path — both deny, fail closed).
 */
static int event_resolve(EventCtx *c)
{
    if (c->fd_num == FAN_NOFD)
    {
        log_msg(LOG_WARNING, "[event] FAN_NOFD for pid=%d, denying",
                (int)c->ev->pid);
        fanotify_respond(c->fan_fd, c->ev, FAN_DENY);
        return 1;
    }

    c->target = resolve_fd_path(c->fd_num);
    if (!c->target)
    {
        log_msg(LOG_WARNING,
                "[event] resolve_fd_path failed for pid=%d fd=%d, denying",
                (int)c->ev->pid, c->fd_num);
        fanotify_respond(c->fan_fd, c->ev, FAN_DENY);
        return 1;
    }
    /* Compute the protected-prefix verdict once; three later stages use it. */
    c->path_protected = is_path_under_protected(c->target);
    log_msg(LOG_DEBUG, "[event] resolved target: pid=%d target=%s",
            (int)c->ev->pid, c->target);
    return 0;
}

/*
 * Stage 2: cheap pre-identity checks.
 *   - Mount-mark fast path: neither the inode nor the path is protected,
 *     so the event is mount-mark noise and is allowed instantly.
 *   - Deduplication: directory + mount marks can fire twice for one
 *     open; the recent-decision cache answers the duplicate instantly.
 */
static int event_fastpath(EventCtx *c)
{
    if (g_mount_count > 0)
    {
        struct stat st;
        if (fstat(c->fd_num, &st) == 0 &&
            !inode_is_protected(st.st_dev, st.st_ino) &&
            !c->path_protected)
        {
            log_msg(LOG_DEBUG, "[fast-path] ALLOW pid=%d target=%s (mount-mark noise)",
                    (int)c->ev->pid, c->target);
            fanotify_respond(c->fan_fd, c->ev, FAN_ALLOW);
            return 1;
        }
    }

    struct stat st;
    if (fstat(c->fd_num, &st) == 0)
    {
        c->ev_dev = st.st_dev;
        c->ev_ino = st.st_ino;
        int cached = recent_cache_lookup(c->ev->pid, c->ev_dev, c->ev_ino);
        if (cached != -1)
        {
            log_msg(LOG_DEBUG,
                    "[dedup] reusing cached decision=%s for pid=%d target=%s",
                    cached == (int)FAN_ALLOW ? "ALLOW" : "DENY",
                    (int)c->ev->pid, c->target);
            fanotify_respond(c->fan_fd, c->ev, (unsigned int)cached);
            return 1;
        }
    }
    return 0;
}

/*
 * Stage 3: requester identity that needs no hashing, plus the config
 * denylist.  Returns 1 when the event was decided (unresolvable binary
 * or a config denylist hit — both deny, fail closed).
 */
static int event_load_binary(EventCtx *c)
{
    c->binary = proc_exe_path(c->ev->pid);
    if (!c->binary)
    {
        fanotify_respond(c->fan_fd, c->ev, FAN_DENY);
        return 1;
    }

    /* Hard-link bypass attempt: a path outside every protected prefix
     * means the event came from the mount mark rather than a directory
     * mark.  Flag it so the grant stages skip every rule and the user is
     * asked about this exact path; denies below and in the caller still
     * win, so this only removes silently-inherited grants. */
    if (!c->path_protected)
    {
        c->hardlink_event = 1;
        log_msg(LOG_WARNING,
                "hard-link bypass attempt: %s (pid %d) opened "
                "protected inode via unprotected path \"%s\"",
                c->binary, (int)c->ev->pid, c->target);
    }

    /* Config denylist: a static admin denial always wins over every
     * grant.  Checked before hashing so denied binaries never pay for
     * binary/ancestor SHA-512 computation. */
    if (denylist_match(c->binary, c->target))
    {
        log_msg(LOG_INFO, "config denylist hit: %s (pid %d) -> %s",
                c->binary, (int)c->ev->pid, c->target);
        ctx_respond(c, FAN_DENY);
        return 1;
    }
    return 0;
}

/*
 * Stage 4: gather everything the session/runtime checks match on.
 * Hashing and chain building happen while the target process is
 * kernel-suspended so its /proc entry is still valid.  Hashing a path
 * that is itself protected would make the daemon intercept its own
 * helper, so it is skipped and the path+chain decision stands alone.
 */
static void event_gather_identity(EventCtx *c)
{
    pid_t pid = c->ev->pid;

    read_comm(pid, c->comm, sizeof(c->comm));
    c->ppid = get_ppid(pid);
    if (c->ppid > 0)
        read_comm(c->ppid, c->pcomm, sizeof(c->pcomm));
    read_cmdline(pid, c->cmdline, sizeof(c->cmdline));

    int sha_ok = -1;
    if (!is_path_under_protected(c->binary))
        sha_ok = cached_sha512_proc_exe(pid, c->bin_sha512);
    if (sha_ok < 0)
        log_msg(LOG_WARNING, "SHA-512 unavailable for %s (pid %d); "
                             "\"Always Allow\" will not persist for this "
                             "decision (access will be re-prompted)",
                c->binary, (int)pid);

    build_proc_chain(pid, &c->chain);

    /* Session identity, best effort.  Without it session-scoped decisions
     * cannot be matched or recorded (they degrade to one-time decisions). */
    c->have_sid = session_id_of(pid, &c->sid, &c->sid_start) == 0;
    if (!c->have_sid)
        log_msg(LOG_WARNING,
                "cannot determine session for pid=%d; session decisions "
                "unavailable for %s",
                (int)pid, c->binary);
}

/*
 * Stage 5: denials that require the binary/call-chain hashes, in order:
 * session denylist (runtime "Deny Session"), then dynamic denylist
 * (runtime "Deny Always").  Returns 1 when the event was denied.
 */
static int event_runtime_denied(EventCtx *c)
{
    if (c->have_sid &&
        session_deny_match(c->sid, c->binary, c->bin_sha512, c->target))
    {
        log_msg(LOG_INFO, "session denylist hit: %s (pid %d, sid %d) -> %s",
                c->binary, (int)c->ev->pid, (int)c->sid, c->target);
        ctx_respond(c, FAN_DENY);
        return 1;
    }

    if (g_dyn_deny_count > 0 &&
        dyn_deny_match(c->binary, c->bin_sha512, &c->chain, c->target,
                       event_cmdline_fp(c)))
    {
        log_msg(LOG_INFO, "dynamic denylist hit: %s (pid %d) -> %s",
                c->binary, (int)c->ev->pid, c->target);
        ctx_respond(c, FAN_DENY);
        return 1;
    }
    return 0;
}

/*
 * Stage 6: grants, in order: file cache ("Allow Once" and fast paths),
 * session allowlist, dynamic allowlist ("Allow Always"), config
 * allowlist.  The config allowlist is last: a denial always wins, and
 * the deny checks above needed the hashes gathered in stage 4.
 * Returns 1 when the event was allowed.
 */
static int event_runtime_allowed(EventCtx *c)
{
    /*
     * A hard-link/unprotected-path event must not be resolved by a rule
     * scoped to a different path (or by a wildcard grant): force the
     * prompt so the user decides for this exact path.  Denials were
     * already evaluated by the caller, so this strips grants only.
     */
    if (c->hardlink_event)
        return 0;

    if (cache_lookup(c->ev->pid, c->binary, c->target) > 0)
    {
        ctx_respond(c, FAN_ALLOW);
        return 1;
    }

    if (c->have_sid &&
        session_allow_match(c->sid, c->binary, c->bin_sha512, c->target))
    {
        log_msg(LOG_INFO, "session allowlist hit: %s (pid %d, sid %d) -> %s",
                c->binary, (int)c->ev->pid, (int)c->sid, c->target);
        ctx_respond(c, FAN_ALLOW);
        return 1;
    }

    if (g_dyn_allow_count > 0 &&
        dyn_allow_match(c->binary, c->bin_sha512, &c->chain, c->target,
                        event_cmdline_fp(c)))
    {
        int user_ttl = g_config ? g_config->user_ttl_seconds : 300;
        cache_insert(c->ev->pid, c->binary, c->target, user_ttl);
        log_msg(LOG_INFO, "dynamic allowlist hit: %s (pid %d) -> %s",
                c->binary, (int)c->ev->pid, c->target);
        ctx_respond(c, FAN_ALLOW);
        return 1;
    }

    /* Config allowlist: an explicit admin opt-in, scoped to a target
     * file/folder or global for a bare entry.  A global rule inserts a
     * wildcard cache entry (grant == NULL). */
    {
        const char *grant = NULL;
        if (allowlist_match(c->binary, c->target, &grant))
        {
            int user_ttl = g_config ? g_config->user_ttl_seconds : 300;
            cache_insert(c->ev->pid, c->binary, grant, user_ttl);
            log_msg(LOG_INFO, "config allowlist hit: %s (pid %d) -> %s",
                    c->binary, (int)c->ev->pid, c->target);
            ctx_respond(c, FAN_ALLOW);
            return 1;
        }
    }
    return 0;
}

/*
 * Record an allow decision the user made in the dialog.  Returns the
 * fanotify response (always FAN_ALLOW; session decisions degrade to a
 * one-time cache grant when the session is unknown).
 */
static unsigned int record_allow_decision(EventCtx *c, int decision)
{
    int user_ttl = g_config ? g_config->user_ttl_seconds : 300;
    int session_ttl = g_config ? g_config->session_ttl_seconds : 0;

    if (decision == NOTIFY_ALLOW_ONCE)
    {
        cache_insert(c->ev->pid, c->binary, c->target, user_ttl);
    }
    else if (decision == NOTIFY_ALLOW_SESSION)
    {
        if (c->have_sid)
        {
            session_allow_add(c->sid, c->sid_start, c->binary, c->bin_sha512,
                              c->target, session_ttl);
        }
        else
        {
            log_msg(LOG_WARNING,
                    "session unavailable; degrading Allow Session to "
                    "Allow Once for %s",
                    c->binary);
            cache_insert(c->ev->pid, c->binary, c->target, user_ttl);
        }
    }
    else /* NOTIFY_ALLOW_ALWAYS */
    {
        const char *cmdline_fp = event_cmdline_fp(c);
        if (cmdline_fp[0] != '\0')
        {
            dyn_allow_add(c->binary, c->bin_sha512, &c->chain, c->target,
                          c->cmdline, cmdline_fp);
        }
        else
        {
            /* Without the exact invocation the persistent entry would
             * cover every command of this binary; degrade to a
             * one-time cached grant instead. */
            log_msg(LOG_WARNING,
                    "cannot fingerprint the command line for %s; "
                    "degrading Allow Always to Allow Once",
                    c->binary);
            cache_insert(c->ev->pid, c->binary, c->target, user_ttl);
        }
    }
    return FAN_ALLOW;
}

/*
 * Record a deny decision from the dialog.  Deny Session degrades to a
 * one-time deny when the session is unknown; Deny Always degrades to a
 * one-time deny when the command line cannot be fingerprinted.
 */
static unsigned int record_deny_decision(EventCtx *c, int decision)
{
    if (decision == NOTIFY_DENY_SESSION)
    {
        int session_ttl = g_config ? g_config->session_ttl_seconds : 0;

        if (c->have_sid)
        {
            session_deny_add(c->sid, c->sid_start, c->binary, c->bin_sha512,
                             c->target, session_ttl);
        }
        else
        {
            log_msg(LOG_WARNING,
                    "session unavailable; denying %s for this attempt only",
                    c->binary);
        }
    }
    else /* NOTIFY_DENY_ALWAYS */
    {
        const char *cmdline_fp = event_cmdline_fp(c);
        if (cmdline_fp[0] != '\0')
        {
            dyn_deny_add(c->binary, c->bin_sha512, &c->chain, c->target,
                         c->cmdline, cmdline_fp);
        }
        else
        {
            log_msg(LOG_WARNING,
                    "cannot fingerprint the command line for %s; "
                    "denying this attempt only",
                    c->binary);
        }
    }
    return FAN_DENY;
}

/*
 * Stage 7: no rule matched — rate-limit the dialog flood risk, then ask
 * the user and record their decision.
 */
static void event_ask_user(EventCtx *c)
{
    if (dialog_rate_limited(c->binary))
    {
        ctx_respond(c, FAN_DENY);
        return;
    }

    log_msg(LOG_INFO, "[dialog] asking user: pid=%d binary=%s target=%s comm=%s",
            (int)c->ev->pid, c->binary, c->target, c->comm);
    int decision = notify_ask(c->comm, c->ev->pid, c->ppid, c->pcomm,
                              c->binary, c->cmdline, c->target,
                              proc_uid(c->ev->pid));
    log_msg(LOG_INFO, "[dialog] user chose %s for %s (pid %d) -> %s",
            notify_decision_name(decision), c->binary, (int)c->ev->pid,
            c->target);

    unsigned int response = FAN_DENY;
    if (decision == NOTIFY_ALLOW_ONCE || decision == NOTIFY_ALLOW_SESSION ||
        decision == NOTIFY_ALLOW_ALWAYS)
        response = record_allow_decision(c, decision);
    else if (decision == NOTIFY_DENY_SESSION || decision == NOTIFY_DENY_ALWAYS)
        response = record_deny_decision(c, decision);

    ctx_respond(c, response);
}

/*
 * Full decision path for a FAN_OPEN_PERM event.  Takes ownership of ev->fd:
 * every path responds and closes the event fd (except FAN_NOFD), or (in
 * the pump) defers it.
 *
 * The stages below are pure structure: each one was a block inside this
 * function, and every respond/close/cache side effect happens in the
 * same order.  The decision order is (a denial always wins over a grant):
 *   config deny -> session deny -> permanent deny -> file cache
 *   -> session allow -> permanent allow -> config allow
 *   -> rate limit -> dialog
 * The config allowlist sits after the runtime grants because every deny
 * must be evaluated first, which requires the hashes from stage 4.
 */
static void process_open_perm(int fan_fd, const struct fanotify_event_metadata *ev)
{
    EventCtx c;
    memset(&c, 0, sizeof(c));
    c.fan_fd = fan_fd;
    c.ev = ev;
    c.fd_num = (int)ev->fd;
    c.close_fd = (c.fd_num != FAN_NOFD);

    log_msg(LOG_DEBUG, "[event] FAN_OPEN_PERM pid=%d fd=%d",
            (int)ev->pid, c.fd_num);

    if (event_resolve(&c))
        goto out;
    if (event_fastpath(&c))
        goto out;
    if (event_load_binary(&c))
        goto out;
    event_gather_identity(&c);
    if (event_runtime_denied(&c))
        goto out;
    if (event_runtime_allowed(&c))
        goto out;
    event_ask_user(&c);

out:
    if (c.close_fd)
        close(c.fd_num);
    free(c.binary);
    free(c.target);
}

/* ------------------------------------------------------------------ */
/*  fanotify_pump: drain pending events while dialog child is running */
/* ------------------------------------------------------------------ */
/*
 * Called by notify.c in a poll loop while waiting for the dialog child.
 * Reads all currently available FAN_OPEN_PERM events non-blocking and
 * responds to them:
 *   - Events FROM dialog_child_pid: FAN_ALLOW (dialog needs to open files).
 *   - Events that pass the mount-mark fast-path: FAN_ALLOW.
 *   - Everything else: left for the main event loop (NOT responded to here),
 *     so the caller must not close fan_fd.
 *
 * Returns number of events responded to.
 */
/*
 * Decide one permission event read while a dialog is open.
 * Returns 1 when the event was responded to (the caller counts it) and 0
 * when it was deferred to the main loop with its event fd left open.
 * Fail closed: a full pending queue denies rather than hanging the caller.
 */
static int pump_decide_permission(int fan_fd,
                                  const struct fanotify_event_metadata *ev,
                                  pid_t dialog_child_pid)
{
    int fd_num = (int)ev->fd;
    int allow = 0;

    if (dialog_child_pid > 0 &&
        process_in_dialog_group(ev->pid, dialog_child_pid))
    {
        log_msg(LOG_DEBUG, "[pump] ALLOW fd=%d pid=%d (dialog group)",
                fd_num, (int)ev->pid);
        allow = 1;
    }
    else if (get_ppid(ev->pid) == getpid())
    {
        /* Direct child of the daemon (sha512sum hashing for the event
         * being handled) must never stall. */
        log_msg(LOG_DEBUG, "[pump] ALLOW fd=%d pid=%d (daemon child)",
                fd_num, (int)ev->pid);
        allow = 1;
    }
    else
    {
        /* Fast path: allow if neither the inode nor the path is
         * protected. */
        struct stat st;
        if (fstat(fd_num, &st) == 0 &&
            !inode_is_protected(st.st_dev, st.st_ino))
        {
            char *tgt = resolve_fd_path(fd_num);
            if (tgt)
            {
                if (!is_path_under_protected(tgt))
                {
                    log_msg(LOG_DEBUG,
                            "[pump] ALLOW fd=%d pid=%d path=%s (non-protected)",
                            fd_num, (int)ev->pid, tgt);
                    allow = 1;
                }
                else
                {
                    log_msg(LOG_DEBUG,
                            "[pump] QUEUE fd=%d pid=%d path=%s (protected)",
                            fd_num, (int)ev->pid, tgt);
                }
                free(tgt);
            }
            else
            {
                /* Can't resolve path; allow to avoid stalling. */
                log_msg(LOG_DEBUG,
                        "[pump] ALLOW fd=%d pid=%d (path unresolvable)",
                        fd_num, (int)ev->pid);
                allow = 1;
            }
        }
    }

    if (allow)
    {
        fanotify_respond(fan_fd, ev, FAN_ALLOW);
        close(fd_num);
        return 1;
    }
    if (fanotify_defer_event(ev) == 0)
        return 0; /* deferred; event fd stays open for the main loop */

    log_msg(LOG_WARNING, "[pump] pending queue full; denying fd=%d pid=%d",
            fd_num, (int)ev->pid);
    fanotify_respond(fan_fd, ev, FAN_DENY);
    close(fd_num);
    return 1;
}

int fanotify_pump(int fan_fd, pid_t dialog_child_pid)
{
    char buf[BUF_SIZE]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));

    int responded = 0;

    while (1)
    {
        /* Non-blocking read: set O_NONBLOCK transiently.  If the flag
         * cannot be set, stop pumping instead of risking a blocking read
         * that would let the dialog child (and the user's opens behind it)
         * stall until the dialog times out: notify.c re-enters the pump
         * whenever poll(2) reports the group fd readable. */
        int flags = fcntl(fan_fd, F_GETFL, 0);
        if (flags < 0)
            break;
        if (fcntl(fan_fd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            log_msg(LOG_WARNING,
                    "[pump] cannot set non-blocking mode: %s; "
                    "deferring to the main loop",
                    strerror(errno));
            break;
        }
        ssize_t n = read(fan_fd, buf, sizeof(buf));
        if (fcntl(fan_fd, F_SETFL, flags) < 0)
            log_msg(LOG_WARNING, "[pump] cannot restore blocking mode: %s",
                    strerror(errno));

        if (n <= 0)
            break;

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)buf;
        ssize_t remaining = n;

        while (FAN_EVENT_OK(ev, (size_t)remaining))
        {
            if (ev->vers != FANOTIFY_METADATA_VERSION)
            {
                /* Defensive parity with the main loop: an event we cannot
                 * interpret is not acted on. */
                if (ev->fd != FAN_NOFD)
                    close((int)ev->fd);
            }
            else if ((ev->mask & FAN_OPEN_PERM) && ev->fd != FAN_NOFD)
            {
                responded += pump_decide_permission(fan_fd, ev,
                                                    dialog_child_pid);
            }
            else if (ev->mask & (FAN_CREATE | FAN_MOVED_TO))
            {
                handle_notification_event(fan_fd, ev);
            }
            else if (ev->mask & FAN_Q_OVERFLOW)
            {
                /* Saturation while a dialog is open: fail closed by denying
                 * every deferred permission event immediately rather than
                 * holding them against state whose events were lost. */
                log_msg(LOG_WARNING,
                        "[pump] fanotify queue overflow; denying %d deferred "
                        "permission events (fail closed)",
                        g_pending_count);
                fanotify_flush_pending(fan_fd);
            }
            else if (ev->fd != FAN_NOFD)
            {
                close((int)ev->fd);
            }

            if (ev->event_len == 0)
                break;
            remaining -= ev->event_len;
            ev = (const struct fanotify_event_metadata *)((const char *)ev +
                                                          ev->event_len);
        }
    }

    return responded;
}

void fanotify_clear_marks(int fd)
{
    /* Remove every mark this daemon installed (tracked in g_marks),
     * including auto-added directory marks, then the mount marks, and
     * clear the in-memory tables.  Called before a config reload so the
     * tables are rebuilt cleanly by the subsequent fanotify_add_mark()
     * calls.  Any deferred permission event is denied first (fail closed). */
    fanotify_flush_pending(fd);

    for (int i = g_mark_count - 1; i >= 0; i--)
    {
        if (fanotify_mark(fd, FAN_MARK_REMOVE, g_marks[i].mask,
                          AT_FDCWD, g_marks[i].path) < 0)
        {
            log_msg(LOG_WARNING, "fanotify mark remove failed for %s: %s",
                    g_marks[i].path, strerror(errno));
        }
        free(g_marks[i].path);
        g_marks[i].path = NULL;
    }
    g_mark_count = 0;
    g_auto_mark_count = 0;

    for (int i = 0; i < g_mount_count; i++)
    {
        if (fanotify_mark(fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                          FAN_OPEN_PERM, AT_FDCWD, g_mounts[i].path) < 0)
        {
            log_msg(LOG_WARNING, "fanotify mount mark remove failed for dev %lu: %s",
                    (unsigned long)g_mounts[i].dev, strerror(errno));
        }
    }
    g_mount_count = 0;
    g_inode_count = 0;
    log_msg(LOG_INFO, "marks and inode table cleared");
}

static int fanotify_respond(int fd, const struct fanotify_event_metadata *ev,
                            unsigned int response)
{
    struct fanotify_response resp;

    resp.fd = ev->fd;
    resp.response = response;
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(resp))
    {
        ssize_t w = write(fd, (char *)&resp + total, sizeof(resp) - (size_t)total);
        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            log_msg(LOG_ERR, "fanotify write response: %s", strerror(errno));
            return -1;
        }
        total += w;
    }
    return 0;
}

/* Decide all permission events that fanotify_pump() had to defer. */
static int fanotify_process_pending(int fan_fd)
{
    int processed = 0;

    while (g_pending_count > 0)
    {
        PendingEvent ev = g_pending[0];
        memmove(&g_pending[0], &g_pending[1],
                sizeof(PendingEvent) * (size_t)(g_pending_count - 1));
        g_pending_count--;
        process_open_perm(fan_fd, &ev.meta);
        processed++;
    }
    return processed;
}

/* Deny and close every deferred event (reload/shutdown, fail closed). */
void fanotify_flush_pending(int fan_fd)
{
    for (int i = 0; i < g_pending_count; i++)
    {
        fanotify_respond(fan_fd, &g_pending[i].meta, FAN_DENY);
        close((int)g_pending[i].meta.fd);
    }
    if (g_pending_count > 0)
        log_msg(LOG_WARNING, "denied %d pending permission events",
                g_pending_count);
    g_pending_count = 0;
}

void fanotify_loop(int fd)
{
    char buf[BUF_SIZE]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    const struct fanotify_event_metadata *ev;
    int event_cnt = 0;
    time_t last_expire = time(NULL);

    while (g_running && !g_need_reload)
    {
        /* Replay events deferred while a dialog was open. */
        if (g_pending_count > 0)
        {
            fanotify_process_pending(fd);
            if (!g_running || g_need_reload || g_fatal)
                break;
        }

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EOVERFLOW)
            {
                /* Saturation reported as a read error instead of an event:
                 * same fail-closed path — deny deferred events, keep going. */
                log_msg(LOG_WARNING,
                        "fanotify read: EOVERFLOW (queue overflow); denying "
                        "%d deferred permission events (fail closed)",
                        g_pending_count);
                fanotify_flush_pending(fd);
                continue;
            }
            log_msg(LOG_ERR, "fanotify read: %s", strerror(errno));
            g_fatal = 1;
            break;
        }

        ev = (const struct fanotify_event_metadata *)buf;
        {
            ssize_t remaining = n;

            while (FAN_EVENT_OK(ev, (size_t)remaining))
            {
                if (ev->vers != FANOTIFY_METADATA_VERSION)
                {
                    /* Unknown layout: nothing can be interpreted safely. */
                    if (ev->fd != FAN_NOFD)
                        close((int)ev->fd);
                }
                else if (ev->mask & FAN_OPEN_PERM)
                {
                    process_open_perm(fd, ev);
                }
                else if (ev->mask & (FAN_CREATE | FAN_MOVED_TO))
                {
                    handle_notification_event(fd, ev);
                }
                else if (ev->mask & FAN_Q_OVERFLOW)
                {
                    /* Saturation: events were dropped.  Fail closed by
                     * denying every permission event we had deferred —
                     * their opens are still suspended and must not wait
                     * on decisions made against lost state. */
                    log_msg(LOG_WARNING,
                            "fanotify queue overflow; events were lost — "
                            "denying %d deferred permission events (fail closed)",
                            g_pending_count);
                    fanotify_flush_pending(fd);
                }
                else if (ev->fd != FAN_NOFD)
                {
                    close((int)ev->fd);
                }

                if (ev->event_len == 0)
                    break;
                remaining -= ev->event_len;
                ev = (const struct fanotify_event_metadata *)((const char *)ev +
                                                              ev->event_len);
            }
        }

        if (!g_running || g_need_reload || g_fatal)
            break;

        /* periodic cache expiry — every 100 events or 10 seconds */
        event_cnt++;
        {
            time_t now = time(NULL);
            if (event_cnt >= 100 || difftime(now, last_expire) >= 10.0)
            {
                cache_expire();
                event_cnt = 0;
                last_expire = now;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Public API: dynamic allowlist / denylist persistence              */
/* ------------------------------------------------------------------ */

void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count)
{
    load_dyn_list(g_dyn_allow, &g_dyn_allow_count, entries, count,
                  "always-allow", 1, 1, 1);
}

void fanotify_load_dyn_denylist(const PersistEntry *entries, int count)
{
    load_dyn_list(g_dyn_deny, &g_dyn_deny_count, entries, count,
                  "always-deny", 0, 1, 1);
}

/* ------------------------------------------------------------------ */
/*  Test seams (see fanotify.h)                                       */
/* ------------------------------------------------------------------ */

int fanotify_test_dyn_allow_match(const char *binary, const char *bin_sha512,
                                  const char *target, const char *cmdline_fp)
{
    ProcChain chain;
    memset(&chain, 0, sizeof(chain));
    return dyn_allow_match(binary, bin_sha512, &chain, target, cmdline_fp);
}

int fanotify_test_dyn_deny_match(const char *binary, const char *bin_sha512,
                                 const char *target, const char *cmdline_fp)
{
    ProcChain chain;
    memset(&chain, 0, sizeof(chain));
    return dyn_deny_match(binary, bin_sha512, &chain, target, cmdline_fp);
}

int fanotify_test_cmdline_fingerprint(pid_t pid, char hex_out[129])
{
    return read_cmdline_fingerprint(pid, hex_out);
}
