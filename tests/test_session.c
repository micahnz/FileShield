/*
 * test_session: session-scoped allow/deny entries keyed by POSIX session
 * id + session-leader start time, with optional TTL and binary hash
 * verification.
 *
 * Each test spawns its own session leader child (setsid + pause) so the
 * tests do not depend on the harness being attached to a live terminal.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/session.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

static void stop_leader(pid_t pid)
{
    if (pid > 0)
    {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
}

/* Fork a child that becomes a new session leader and sleeps until killed.
 * A pipe synchronizes so the parent only reads its /proc entry after
 * setsid() has taken effect (otherwise the recorded SID could still be the
 * harness's session). */
static pid_t spawn_leader(void)
{
    int sync_pipe[2];
    char token = 'x';

    if (pipe(sync_pipe) != 0)
        return -1;

    pid_t pid = fork();
    if (pid == 0)
    {
        close(sync_pipe[0]);
        if (setsid() < 0)
            _exit(1);
        ssize_t ignored = write(sync_pipe[1], &token, 1);
        (void)ignored;
        close(sync_pipe[1]);
        for (;;)
            pause();
    }

    close(sync_pipe[1]);
    ssize_t n = read(sync_pipe[0], &token, 1);
    close(sync_pipe[0]);
    if (n != 1)
    {
        stop_leader(pid);
        return -1;
    }
    return pid;
}

/* Resolve the fixture session; returns 0 on success. */
static int fixture_session(pid_t leader, pid_t *sid, unsigned long long *start)
{
    if (leader <= 0)
        return -1;
    return session_id_of(leader, sid, start);
}

static void test_session_id_of(void)
{
    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;

    ASSERT(leader > 0, "fork session leader");
    ASSERT(fixture_session(leader, &sid, &start) == 0, "session_id_of leader");
    ASSERT(sid == leader, "leader's session id is its own pid");
    ASSERT(start > 0, "leader start time captured");

    pid_t self_sid = getsid(0);
    ASSERT(session_id_of(getpid(), &sid, &start) == 0, "session_id_of self");
    ASSERT(sid == self_sid, "self session id matches getsid(0)");

    ASSERT(session_id_of((pid_t)99999999, &sid, &start) == -1,
           "session_id_of missing pid fails");

    stop_leader(leader);
}

static void test_allow_match(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    const char *bin = "/usr/bin/kubectl";
    const char *hash = "aaaaaaaaaaaaaaaa";
    const char *target = "/home/u/.kube/config";

    session_allow_add(sid, start, bin, hash, target, 0);

    ASSERT(session_allow_match(sid, bin, hash, target) == 1,
           "allow match on exact key");
    ASSERT(session_allow_match(sid, bin, hash, "/home/u/.kube/other") == 0,
           "other target does not match");
    ASSERT(session_allow_match(sid, "/usr/bin/other", hash, target) == 0,
           "other binary does not match");
    ASSERT(session_allow_match(sid + 12345, bin, hash, target) == 0,
           "other session does not match");
    ASSERT(session_allow_match(sid, bin, "", target) == 0,
           "missing current hash fails closed");
    ASSERT(session_allow_match(sid, bin, "bbbbbbbbbbbbbbbb", target) == 0,
           "wrong hash does not match");

    /* An entry recorded without a hash matches any provided hash. */
    session_clear();
    session_allow_add(sid, start, bin, "", target, 0);
    ASSERT(session_allow_match(sid, bin, "cccccccccccccccc", target) == 1,
           "hashless entry matches without verification");

    stop_leader(leader);
}

static void test_ttl_expiry(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    const char *bin = "/usr/bin/aws";
    const char *hash = "dddddddddddddddd";
    const char *target = "/home/u/.aws/credentials";

    session_allow_add(sid, start, bin, hash, target, 1);
    ASSERT(session_allow_match(sid, bin, hash, target) == 1,
           "match before TTL expiry");

    sleep(2);
    ASSERT(session_allow_match(sid, bin, hash, target) == 0,
           "match after TTL expiry");

    stop_leader(leader);
}

static void test_dead_leader(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    session_allow_add(sid, start, "/usr/bin/gh", "eeeeeeeeeeeeeeee",
                      "/home/u/.config/gh/hosts.yml", 0);
    ASSERT(session_allow_match(sid, "/usr/bin/gh", "eeeeeeeeeeeeeeee",
                               "/home/u/.config/gh/hosts.yml") == 1,
           "match while leader alive");

    stop_leader(leader);

    ASSERT(session_allow_match(sid, "/usr/bin/gh", "eeeeeeeeeeeeeeee",
                               "/home/u/.config/gh/hosts.yml") == 0,
           "dead leader does not match");
}

/*
 * M7 regression: the matchers now drop dead leaders only on the
 * full-key-match path (no per-event /proc storm), so entries whose
 * leaders died OUTSIDE their own session linger as used.  Reclaiming
 * them is the table-full sweep's job: an add at capacity must reuse a
 * dead slot rather than memmove-evict a live entry.
 */
static void test_full_table_reclaims_dead(void)
{
    int cap = session_test_max();
    session_clear();

    pid_t dead = spawn_leader();
    pid_t live = spawn_leader();
    pid_t dsid = 0, lsid = 0;
    unsigned long long dstart = 0, lstart = 0;
    ASSERT(fixture_session(dead, &dsid, &dstart) == 0, "doomed session");
    ASSERT(fixture_session(live, &lsid, &lstart) == 0, "live session");
    if (dead <= 0 || live <= 0) {
        stop_leader(dead);
        stop_leader(live);
        return;
    }

    /* Slot 0: an entry whose leader dies before the fill below. */
    session_allow_add(dsid, dstart, "/bin/doomed", "", "/doomed", 0);
    stop_leader(dead);

    /* Fill the remaining slots with live-session entries. */
    char target[64];
    for (int i = 1; i < cap; i++) {
        snprintf(target, sizeof(target), "/live/%d", i);
        session_allow_add(lsid, lstart, "/bin/live", "", target, 0);
    }
    ASSERT(session_allow_match(lsid, "/bin/live", "", "/live/1") == 1,
           "oldest live entry matches before overflow (memmove victim)");

    /* The overflow add: the sweep must reclaim the doomed slot, keeping
     * every live entry in place. */
    session_allow_add(lsid, lstart, "/bin/live", "", "/live/extra", 0);

    ASSERT(session_allow_match(lsid, "/bin/live", "", "/live/extra") == 1,
           "overflow entry stored via dead-slot reclaim");
    ASSERT(session_allow_match(lsid, "/bin/live", "", "/live/1") == 1,
           "oldest live entry survived the overflow add");
    ASSERT(session_allow_match(lsid, "/bin/live", "", "/live/2") == 1,
           "second live entry survived the overflow add");
    ASSERT(session_allow_match(dsid, "/bin/doomed", "", "/doomed") == 0,
           "doomed entry matches nothing (its session is dead)");

    session_clear();
    stop_leader(live);
}

static void test_deny(void)
{
    session_clear();

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    const char *bin = "/usr/bin/terraform";
    const char *hash = "ffffffffffffffff";
    const char *target = "/home/u/.terraform.d/credentials.tfrc.json";

    session_deny_add(sid, start, bin, hash, target, 0);

    ASSERT(session_deny_match(sid, bin, hash, target) == 1,
           "deny match on exact key");
    ASSERT(session_deny_match(sid, bin, hash, "/home/u/other") == 0,
           "deny does not match another target");
    ASSERT(session_deny_match(sid, bin, "", target) == 0,
           "hash-protected deny cannot be verified without hash");
    ASSERT(session_deny_match(sid, bin, "0000000000000000", target) == 0,
           "deny match with wrong hash");

    /* Hashless deny matches even when no current hash is available. */
    session_clear();
    session_deny_add(sid, start, bin, "", target, 0);
    ASSERT(session_deny_match(sid, bin, "", target) == 1,
           "hashless deny matches without hash");

    stop_leader(leader);
}

/*
 * Observable state checks without count helpers: clear empties the
 * lists (matches fail), adds make them match again, and a live entry
 * survives an expiry sweep because nothing expires it.
 */
static void test_clear_and_entries(void)
{
    session_clear();
    ASSERT(session_allow_match((pid_t)1, "/bin/a", "", "/tmp/a") == 0,
           "no match after clear (allow)");
    ASSERT(session_deny_match((pid_t)1, "/bin/b", "", "/tmp/b") == 0,
           "no match after clear (deny)");

    pid_t leader = spawn_leader();
    pid_t sid = 0;
    unsigned long long start = 0;
    ASSERT(fixture_session(leader, &sid, &start) == 0, "fixture session");
    if (leader <= 0)
        return;

    session_allow_add(sid, start, "/bin/a", "", "/tmp/a", 0);
    session_deny_add(sid, start, "/bin/b", "", "/tmp/b", 0);
    ASSERT(session_allow_match(sid, "/bin/a", "", "/tmp/a") == 1,
           "allow entry present after add");
    ASSERT(session_deny_match(sid, "/bin/b", "", "/tmp/b") == 1,
           "deny entry present after add");

    session_clear();
    ASSERT(session_allow_match(sid, "/bin/a", "", "/tmp/a") == 0,
           "clear removes allow entries");
    ASSERT(session_deny_match(sid, "/bin/b", "", "/tmp/b") == 0,
           "clear removes deny entries");

    stop_leader(leader);
}

int main(void)
{
    printf("=== test_session ===\n");
    test_session_id_of();
    test_allow_match();
    test_ttl_expiry();
    test_dead_leader();
    test_full_table_reclaims_dead();
    test_deny();
    test_clear_and_entries();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
