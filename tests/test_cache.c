#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>

#include "../src/cache.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

static void test_insert_lookup(void) {
    cache_insert(42, "/usr/bin/evil", "/home/u/.ssh/id_rsa", 60);
    ASSERT(cache_lookup(42, "/usr/bin/evil", "/home/u/.ssh/id_rsa") > 0,
           "lookup after insert");
    ASSERT(cache_lookup(42, "/usr/bin/other", "/home/u/.ssh/id_rsa") == 0,
           "lookup wrong binary");
    ASSERT(cache_lookup(99, "/usr/bin/evil", "/home/u/.ssh/id_rsa") == 0,
           "lookup wrong pid");
    cache_expire();
    ASSERT(cache_lookup(42, "/usr/bin/evil", "/home/u/.ssh/id_rsa") > 0,
           "lookup still valid after expire");
}

static void test_target_scoping(void) {
    cache_insert(600, "/bin/scope", "/home/u/.kube/config", 60);
    ASSERT(cache_lookup(600, "/bin/scope", "/home/u/.kube/config") > 0,
           "exact target matches");
    ASSERT(cache_lookup(600, "/bin/scope", "/home/u/.ssh/id_rsa") == 0,
           "other target does not match");
    ASSERT(cache_lookup(600, "/bin/scope", NULL) == 0,
           "file-scoped entry does not match a wildcard lookup");
    cache_expire();
}

static void test_wildcard(void) {
    cache_insert(700, "/usr/bin/git", NULL, 60);
    ASSERT(cache_lookup(700, "/usr/bin/git", "/any/path") > 0,
           "wildcard matches any target");
    ASSERT(cache_lookup(700, "/usr/bin/git", NULL) > 0,
           "wildcard matches a NULL target");
    ASSERT(cache_lookup(700, "/usr/bin/git2", "/any/path") == 0,
           "wildcard is still binary-scoped");
    cache_expire();
}

static void test_ttl_expiry(void) {
    cache_insert(100, "/bin/ls", "/tmp/a", 1);
    ASSERT(cache_lookup(100, "/bin/ls", "/tmp/a") > 0, "lookup before expiry");
    sleep(2);
    ASSERT(cache_lookup(100, "/bin/ls", "/tmp/a") == 0, "lookup after expiry");
}

/*
 * An expired file-scoped entry must not shadow a live wildcard entry for
 * the same (pid, binary): the lookup has to keep scanning instead of
 * reporting a miss on the first expired match.
 */
static void test_expired_scoped_falls_through(void) {
    pid_t pid = getpid();
    const char *bin = "/bin/fallthrough";

    cache_insert(pid, bin, "/tmp/fallthrough", 1);
    cache_insert(pid, bin, NULL, 60);
    sleep(2);
    ASSERT(cache_lookup(pid, bin, "/tmp/fallthrough") > 0,
           "expired scoped entry falls through to the live wildcard");
    ASSERT(cache_lookup(pid, bin, "/tmp/other") > 0,
           "the wildcard still covers other targets");
    cache_expire();
}

static void test_overwrite(void) {
    cache_insert(200, "/bin/a", "/tmp/a", 60);
    cache_insert(200, "/bin/a", "/tmp/a", 120);
    int ttl = cache_lookup(200, "/bin/a", "/tmp/a");
    ASSERT(ttl > 90, "overwrite refreshes ttl");

    /* A different target is a distinct entry, not an overwrite: both
     * lookups must stay valid side by side. */
    cache_insert(200, "/bin/a", "/tmp/b", 60);
    ASSERT(cache_lookup(200, "/bin/a", "/tmp/b") > 0,
           "different target inserts a new cache entry");
    ASSERT(cache_lookup(200, "/bin/a", "/tmp/a") > 0,
           "original target entry survives alongside the new one");
}

static void test_null_binary(void) {
    cache_insert(400, NULL, "/tmp/x", 60);
    ASSERT(cache_lookup(400, NULL, "/tmp/x") == 0, "null binary not inserted");
}

static void test_pid_starttime(void) {
    /* A real PID must carry a verifiable start time and still match. */
    cache_insert(getpid(), "/bin/real", "/tmp/real", 60);
    ASSERT(cache_lookup(getpid(), "/bin/real", "/tmp/real") > 0,
           "lookup real pid with starttime");
    cache_expire();
}

static void test_pid_reuse(void) {
    /* A recycled PID (different start time) must be rejected and evicted. */
    cache_test_insert_with_starttime(300, 111, "/bin/stale", "/tmp/stale", 60);
    ASSERT(cache_lookup(300, "/bin/stale", "/tmp/stale") == 0,
           "different start time is rejected as PID reuse");

    /* Control: a fresh insert afterwards matches again. */
    cache_insert(300, "/bin/stale", "/tmp/stale", 60);
    ASSERT(cache_lookup(300, "/bin/stale", "/tmp/stale") > 0,
           "fresh insert after eviction matches");
    cache_expire();
}

static void test_ttl_clamp(void) {
    /* Absurd TTLs must be clamped so expiry arithmetic cannot overflow
     * into the past on any time_t width. */
    cache_insert(500, "/bin/huge", "/tmp/huge", INT_MAX);
    int ttl = cache_lookup(500, "/bin/huge", "/tmp/huge");
    ASSERT(ttl > 0, "clamped entry still valid");
    ASSERT(ttl <= (365 * 24 * 60 * 60), "clamped TTL bounded to one year");
    cache_expire();
}

int main(void) {
    printf("=== test_cache ===\n");
    test_insert_lookup();
    test_target_scoping();
    test_wildcard();
    test_ttl_expiry();
    test_expired_scoped_falls_through();
    test_overwrite();
    test_null_binary();
    test_pid_starttime();
    test_pid_reuse();
    test_ttl_clamp();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
