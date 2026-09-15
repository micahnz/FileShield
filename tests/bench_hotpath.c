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
 *   sha512_string         command-line fingerprints (fork + sha512sum)
 *   dyn matchers          runtime allow/deny entry matching (fanotify.c)
 *
 * Run an optimization's before/after here; keep the change only if it
 * wins.  Results belong in the commit message and as comments at the
 * changed site.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/cache.h"
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

static void bench_dyn_allow_match_hit(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        fanotify_test_dyn_allow_match("/usr/bin/kubectl", BENCH_SHA,
                                      "/home/u/.kube/config",
                                      "kubectl config view --minify");
}

static void bench_dyn_allow_match_miss(void *arg)
{
    int iters = *(int *)arg;

    for (int i = 0; i < iters; i++)
        fanotify_test_dyn_allow_match("/usr/bin/other", BENCH_SHA,
                                      "/home/u/.other/file", "other cmd");
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
    snprintf(e->cmdline_sha512, sizeof(e->cmdline_sha512), "%s", BENCH_SHA);
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

    int iters_sha = 5000; /* in-process: no fork, safe to run many */
    report("sha512_string (in-process)", bench_sha512_string, &iters_sha,
           iters_sha);

    bench_dyn_setup();
    int iters_match_hit = 200; /* full match forks sha512sum per iter */
    report("dyn_allow_match full hit", bench_dyn_allow_match_hit,
           &iters_match_hit, iters_match_hit);
    int iters_match_miss = 200000;
    report("dyn_allow_match early miss", bench_dyn_allow_match_miss,
           &iters_match_miss, iters_match_miss);

    return 0;
}
