/*
 * bench_hotpath: microbenchmarks for the per-event hot path.
 *
 * Not part of `make test` — built and run by `make bench`.  The hot path
 * is the work process_open_perm() does per protected open; the pieces
 * reachable from outside fanotify.c are timed here:
 *
 *   cache_lookup/insert   PID-keyed allow cache (scan + /proc read)
 *   path_under            boundary primitive behind all rule matching
 *   proc_stat_session     /proc/<pid>/stat parse (PID-reuse check)
 *   sha512_string         command-line fingerprints (in-process)
 *   dyn matchers          runtime allow/deny entry matching (fanotify.c)
 *   cmdline fingerprint   /proc/<pid>/cmdline read + hash (fanotify.c)
 *   inode set / fastpath  mount-mark noise classification (inode.c,
 *                         fanotify_test_fastpath_allows)
 *
 * Run an optimization's before/after here; keep the change only if it
 * wins.  Results belong in the commit message and as comments at the
 * changed site.
 */
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/cache.h"
#include "../src/config.h"
#include "../src/inode.h"
#include "../src/utils.h"
#include "../src/sha512.h"
#include "../src/fanotify.h"

/* The bench links the daemon objects; provide the signal globals the
 * daemon normally defines (same contract as test_fanotify). */
volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;
volatile sig_atomic_t g_fatal = 0;

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/*
 * Time one pass of fn (which loops over its workload internally) after
 * a single warmup pass, and report microseconds per workload-iteration.
 * The iteration count lives in *arg; report() must NOT loop around fn
 * or the workload becomes quadratic.
 */
static void report(const char *name, void (*fn)(void *), void *arg,
                   int iters)
{
    fn(arg); /* warmup */

    double start = now_ms();
    fn(arg);
    double elapsed_ms = now_ms() - start;

    printf("%-30s %10.3f us/iter  (%d iters, %.1f ms total)\n",
           name, elapsed_ms * 1000.0 / iters, iters, elapsed_ms);
}

/* ------------------------------------------------------------------ */
/*  cache benches                                                      */
/* ------------------------------------------------------------------ */

enum { BENCH_FILL = 128 }; /* realistic mid-size cache population */

static void bench_cache_lookup_hit(void *arg)
{
    int iters = *(int *)arg;
    char target[64];

    for (int i = 0; i < iters; i++)
    {
        snprintf(target, sizeof(target), "/tmp/bench/f%d", i % BENCH_FILL);
        cache_lookup((pid_t)(100 + (i % BENCH_FILL)), "/bin/bench", target);
    }
}

static void bench_cache_lookup_miss(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        cache_lookup((pid_t)999999, "/bin/absent", "/tmp/bench/none");
}

static void bench_cache_insert(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        /* Refresh the same entry: measures the scan-to-existing-slot
         * path, not table growth. */
        cache_insert((pid_t)100, "/bin/bench", "/tmp/bench/refresh", 60);
}

static void bench_cache_setup(void)
{
    char target[64];

    cache_expire();
    for (int i = 0; i < BENCH_FILL; i++)
    {
        snprintf(target, sizeof(target), "/tmp/bench/f%d", i);
        cache_insert((pid_t)(100 + i), "/bin/bench", target, 60);
    }
}

/* ------------------------------------------------------------------ */
/*  path matching / proc benches                                       */
/* ------------------------------------------------------------------ */

enum { RULE_COUNT = 8 };

static const char *g_rules[RULE_COUNT] = {
    "/home/u/.aws", "/home/u/.ssh", "/home/u/.kube", "/home/u/.gnupg",
    "/home/u/.password-store", "/etc/ssl/private", "/var/lib/vault",
    "/opt/secrets"};

static void bench_path_under(void *arg)
{
    int iters = *(int *)arg;
    char path[128];

    for (int i = 0; i < iters; i++)
    {
        snprintf(path, sizeof(path), "/home/u/.ssh/id_rsa%d", i);
        for (int r = 0; r < RULE_COUNT; r++)
            (void)path_under(path, g_rules[r]);
    }
}

static void bench_proc_stat_session(void *arg)
{
    int iters = *(int *)arg;
    unsigned long long start = 0;

    for (int i = 0; i < iters; i++)
        proc_stat_session(getpid(), NULL, &start);
}

/* ------------------------------------------------------------------ */
/*  inode set / fast-path verdict benches                              */
/* ------------------------------------------------------------------ */

/*
 * The fast path runs for every open on a mount-marked filesystem, so its
 * cost is dominated by the inode-set lookup and the protected-prefix
 * scan.  Fill the set to the sizes a real config can reach and classify a
 * protected path (worst case for the prefix scan) and mount-mark noise.
 */
static int g_inode_fill = 0;

static Config g_bench_cfg; /* static: Config is several MB */

static void bench_fastpath_setup(void)
{
    static const char *const prefixes[] = {
        "/home/u/.aws", "/home/u/.azure", "/home/u/.config/gcloud",
        "/home/u/.kube", "/home/u/.ssh", "/home/u/.gnupg",
        "/home/u/.config/sops", "/home/u/.password-store",
        "/home/u/.config/op", "/home/u/.vault-token", "/home/u/.config/vault",
        "/home/u/.docker", "/home/u/.config/helm", "/home/u/.terraform.d",
        "/home/u/.terraformrc", "/home/u/.config/gh", "/home/u/.netrc",
        "/home/u/.env", "/etc/ssl/private", "/var/lib/vault",
        "/opt/secrets", "/srv/keys", "/etc/keys", "/root/.aws",
        "/home/u/projects", "/home/u/work", "/home/u/data",
        "/home/u/.config", "/home/u/bin", "/var/backups",
        "/home/u/.local", "/home/u/.cache"};

    g_bench_cfg.protected_count = 0;
    g_bench_cfg.exclude_count = 0;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
    {
        snprintf(g_bench_cfg.protected[g_bench_cfg.protected_count].path,
                 PATH_MAX, "%s", prefixes[i]);
        g_bench_cfg.protected_count++;
    }

    /* Glob entries mirroring the shipped cloudflared rules, so the
     * fastpath benches below include the prefilter + matcher cost. */
    static const char *const globs[] = {
        "/home/u/.cloudflared/*.json",
        "/home/u/.cloudflared/**/*.json"};

    for (size_t i = 0; i < sizeof(globs) / sizeof(globs[0]); i++)
    {
        ProtectedPath *pp = &g_bench_cfg.protected[g_bench_cfg.protected_count];
        snprintf(pp->path, PATH_MAX, "%s", globs[i]);
        pp->is_glob = 1;
        pp->base_len = (int)strlen("/home/u/.cloudflared");
        g_bench_cfg.protected_count++;
    }

    /* One exclusion mirrors the shipped ssh rule: deny-wins costs an
     * exclusion scan only after a positive entry matches. */
    {
        ProtectedPath *pp = &g_bench_cfg.protected[g_bench_cfg.protected_count];
        snprintf(pp->path, PATH_MAX, "%s", "/home/u/.ssh/*.pub");
        pp->is_glob = 1;
        pp->is_exclude = 1;
        pp->base_len = (int)strlen("/home/u/.ssh");
        g_bench_cfg.protected_count++;
        g_bench_cfg.exclude_count = 1;
    }

    g_config = &g_bench_cfg;
}

static void bench_inode_fill(int n)
{
    inode_set_clear();
    for (int i = 0; i < n; i++)
        inode_set_add(3, (ino_t)i);
    g_inode_fill = n;
}

static void bench_inode_contains(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
    {
        /* Stride across the populated range: average-case lookup, not a
         * cache-friendly sequential walk. */
        unsigned idx = (unsigned)(i * 2654435761u) % (unsigned)g_inode_fill;
        (void)inode_set_contains(3, (ino_t)idx);
    }
}

/* Mount-mark noise: inode miss plus a path under no prefix (full scan). */
static void bench_fastpath_noise(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        (void)fanotify_test_fastpath_allows(3, 999999,
                                            "/home/u/projects/src/main.c");
}

/* Real protected access: inode miss plus a matching prefix. */
static void bench_fastpath_protected(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        (void)fanotify_test_fastpath_allows(3, 999999,
                                            "/home/u/.ssh/id_rsa");
}

/*
 * Glob entry, non-matching file under the base: rejected by the
 * path_under_len() prefilter (mount-mark noise cost).
 */
static void bench_fastpath_glob_noise(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        (void)fanotify_test_fastpath_allows(3, 999999,
                                            "/home/u/.cloudflared/cert.pem");
}

/* Glob entry, matching nested file: prefilter + full segment matcher. */
static void bench_fastpath_glob_match(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        (void)fanotify_test_fastpath_allows(3, 999999,
                                            "/home/u/.cloudflared/team/abc.json");
}

/* Exclusion hit: positive .ssh match, then the !*.pub exclusion wins. */
static void bench_fastpath_excluded(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        (void)fanotify_test_fastpath_allows(3, 999999,
                                            "/home/u/.ssh/id_ed25519.pub");
}

/* ------------------------------------------------------------------ */
/*  event path resolution benches                                      */
/* ------------------------------------------------------------------ */

/*
 * resolve_fd_path() runs once per event.  It used to malloc a PATH_MAX
 * buffer per call; the variant below measures the heap/free cost against
 * the caller-provided (stack) buffer the event pipeline uses now.
 */
static int g_resolve_fd = -1;

static void bench_resolve_setup(void)
{
    g_resolve_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
}

static void bench_resolve_path_heap(void *arg)
{
    int iters = *(int *)arg;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", g_resolve_fd);

    for (int i = 0; i < iters; i++)
    {
        char *buf = malloc(PATH_MAX);
        if (!buf)
            continue;
        ssize_t len = readlink(link, buf, PATH_MAX - 1);
        if (len >= 0)
            buf[len] = '\0';
        free(buf);
    }
}

static void bench_resolve_path_stack(void *arg)
{
    int iters = *(int *)arg;
    char link[64];
    char buf[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", g_resolve_fd);

    for (int i = 0; i < iters; i++)
    {
        ssize_t len = readlink(link, buf, sizeof(buf) - 1);
        if (len >= 0)
            buf[len] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/*  sha512 + dyn matcher benches                                       */
/* ------------------------------------------------------------------ */

static void bench_sha512_string(void *arg)
{
    int iters = *(int *)arg;
    char hex[129];
    const char *cmd = "kubectl get pods -n kube-system "
                      "--field-selector spec.nodeName=ip-10-0-1-23";

    for (int i = 0; i < iters; i++)
        sha512_string(cmd, hex);
}

#define BENCH_SHA                                                            \
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"       \
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

/* Precomputed fingerprints: the matcher seams take the digest, so these
 * benches measure matching, not hashing. */
static char g_bench_cmd_fp[129];
static char g_bench_cmd2_fp[129];

static void bench_dyn_allow_match_hit(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        fanotify_test_dyn_allow_match("/usr/bin/kubectl", BENCH_SHA,
                                      "/home/u/.kube/config", g_bench_cmd_fp);
}

static void bench_dyn_allow_match_miss(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        fanotify_test_dyn_allow_match("/usr/bin/other", BENCH_SHA,
                                      "/home/u/.other/file", BENCH_SHA);
}

/*
 * Binary, hash, target and chain all match; only the command differs, so
 * this measures the fingerprint comparison a near-miss pays.
 */
static void bench_dyn_allow_match_cmd_miss(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        fanotify_test_dyn_allow_match("/usr/bin/kubectl", BENCH_SHA,
                                      "/home/u/.kube/config", g_bench_cmd2_fp);
}

/*
 * Production fingerprint cost: read the full /proc/<pid>/cmdline and hash
 * it.  Computed lazily per event, only when a runtime list can match.
 * Uses the bench process itself (short cmdline), so the /proc read and
 * the digest dominate.
 */
static void bench_cmdline_fingerprint(void *arg)
{
    int iters = *(int *)arg;
    char fp[129];
    pid_t self = getpid();

    for (int i = 0; i < iters; i++)
        fanotify_test_cmdline_fingerprint(self, fp);
}

/* Load one runtime allow entry so the dyn matchers have work to do. */
static void bench_dyn_setup(void)
{
    PersistEntry e[1];
    memset(e, 0, sizeof(e));
    snprintf(e[0].binary, sizeof(e->binary), "/usr/bin/kubectl");
    snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", BENCH_SHA);
    snprintf(e->target_path, sizeof(e->target_path), "/home/u/.kube/config");
    snprintf(e->cmdline, sizeof(e->cmdline), "kubectl config view --minify");
    /* Fingerprint the same command line the hit bench passes, so the hit
     * is a true full match.  (It previously stored an unrelated constant
     * and therefore measured a mismatch.) */
    if (sha512_string("kubectl config view --minify", g_bench_cmd_fp) != 0)
        g_bench_cmd_fp[0] = '\0';
    if (sha512_string("kubectl get secrets", g_bench_cmd2_fp) != 0)
        g_bench_cmd2_fp[0] = '\0';
    snprintf(e->cmdline_sha512, sizeof(e->cmdline_sha512), "%s",
             g_bench_cmd_fp);
    /* A pre-assigned ID (and creation time) keeps the load from migrating
     * and persisting to the real state directory: the bench must not have
     * side effects on /var/lib/fileshield. */
    snprintf(e->rule_id, sizeof(e->rule_id), "0123456789abcdef");
    e->created_at = 1;
    fanotify_load_dyn_allowlist(e, 1);
}

int main(void)
{
    printf("=== bench_hotpath ===\n");

    /* Cache benches share one populated table. */
    bench_cache_setup();
    int iters_lookup = 200000;
    report("cache_lookup hit (128 entries)", bench_cache_lookup_hit,
           &iters_lookup, iters_lookup);
    report("cache_lookup miss (128 entries)", bench_cache_lookup_miss,
           &iters_lookup, iters_lookup);
    int iters_insert = 200000;
    report("cache_insert refresh", bench_cache_insert, &iters_insert,
           iters_insert);
    cache_expire();

    int iters_path = 1000000;
    report("path_under x8 rules", bench_path_under, &iters_path, iters_path);

    int iters_stat = 20000;
    report("proc_stat_session (own pid)", bench_proc_stat_session,
           &iters_stat, iters_stat);

    /* Inode set + fast-path verdict (mount-mark noise classification). */
    bench_fastpath_setup();
    int iters_inode = 50000;
    bench_inode_fill(1024);
    report("inode lookup (1k)", bench_inode_contains, &iters_inode,
           iters_inode);
    bench_inode_fill(8192);
    iters_inode = 20000;
    report("inode lookup (8k)", bench_inode_contains, &iters_inode,
           iters_inode);
    report("fastpath verdict (noise)", bench_fastpath_noise, &iters_inode,
           iters_inode);
    report("fastpath verdict (protected)", bench_fastpath_protected,
           &iters_inode, iters_inode);
    report("fastpath glob (noise under base)", bench_fastpath_glob_noise,
           &iters_inode, iters_inode);
    report("fastpath glob (matching file)", bench_fastpath_glob_match,
           &iters_inode, iters_inode);
    report("fastpath excluded (ssh pub key)", bench_fastpath_excluded,
           &iters_inode, iters_inode);
    bench_inode_fill(INODE_SET_MAX);
    iters_inode = 5000;
    report("inode lookup (32k)", bench_inode_contains, &iters_inode,
           iters_inode);
    inode_set_clear();

    /* Event path resolution: heap buffer vs caller stack buffer. */
    bench_resolve_setup();
    int iters_resolve = 100000;
    report("resolve path (heap)", bench_resolve_path_heap, &iters_resolve,
           iters_resolve);
    report("resolve path (stack)", bench_resolve_path_stack, &iters_resolve,
           iters_resolve);

    int iters_sha = 5000; /* in-process: no fork, safe to run many */
    report("sha512_string (in-process)", bench_sha512_string, &iters_sha,
           iters_sha);

    bench_dyn_setup();
    int iters_match_hit = 200000;
    report("dyn_allow_match full hit", bench_dyn_allow_match_hit,
           &iters_match_hit, iters_match_hit);
    int iters_match_miss = 200000;
    report("dyn_allow_match early miss", bench_dyn_allow_match_miss,
           &iters_match_miss, iters_match_miss);
    int iters_cmd_miss = 200000;
    report("dyn_allow_match cmd mismatch", bench_dyn_allow_match_cmd_miss,
           &iters_cmd_miss, iters_cmd_miss);
    int iters_fp = 20000;
    report("cmdline fingerprint (own pid)", bench_cmdline_fingerprint,
           &iters_fp, iters_fp);

    return 0;
}
