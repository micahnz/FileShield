/*
 * test_prune.c -- unit tests for the offline duplicate-rule grouping and
 * removal in src/prune.c.  The module is pure, so these tests need no
 * files, no root and no kernel: they exercise grouping, ordering,
 * boundary and error paths directly on PersistEntry arrays.
 */

#include <stdio.h>
#include <string.h>

#include "../src/prune.h"

#define TEST_FAIL(msg)                      \
    do                                      \
    {                                       \
        fprintf(stderr, "FAIL: %s\n", msg); \
        return 1;                           \
    } while (0)

#define TEST_PASS(msg)                      \
    do                                      \
    {                                       \
        fprintf(stdout, "PASS: %s\n", msg); \
    } while (0)

#define ASSERT(cond, msg)   \
    do                      \
    {                       \
        if (!(cond))        \
            TEST_FAIL(msg); \
    } while (0)

/*
 * Build an entry whose key fields are the visible ones.  Digest fields
 * start zero; tests that need to prove which member survived write a
 * distinguishing marker into binary_sha512 (never part of the key).
 */
static void make_entry(PersistEntry *e, const char *binary, const char *target,
                       const char *cmdline, int depth)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    snprintf(e->target_path, sizeof(e->target_path), "%s", target);
    snprintf(e->cmdline, sizeof(e->cmdline), "%s", cmdline);
    e->chain_depth = depth;
}

static void set_comm(PersistEntry *e, int level, const char *comm)
{
    snprintf(e->chain_comm[level], sizeof(e->chain_comm[level]), "%s", comm);
}

/* Run prune_find with worst-case buffers; returns the group count or -1. */
static int count_groups(const PersistEntry *entries, int count)
{
    PruneGroup groups[PERSIST_MAX_ENTRIES];
    int removals[PERSIST_MAX_ENTRIES];
    int removal_count = -1;

    return prune_find(entries, count, groups, PERSIST_MAX_ENTRIES,
                      removals, PERSIST_MAX_ENTRIES, &removal_count);
}

/* ------------------------------------------------------------------ */
/*  distinct entries form no group and need no removal                 */
/* ------------------------------------------------------------------ */

static int test_prune_no_duplicates(void)
{
    PersistEntry entries[3];
    PruneGroup groups[3];
    int removals[3];
    int removal_count = -1;
    int n;

    make_entry(&entries[0], "/usr/bin/git", "/home/u/.ssh/id_rsa", "git status", 1);
    set_comm(&entries[0], 0, "bash");
    make_entry(&entries[1], "/usr/bin/ssh", "/home/u/.ssh/id_rsa", "ssh host", 1);
    set_comm(&entries[1], 0, "bash");
    make_entry(&entries[2], "/usr/bin/git", "/home/u/.ssh/id_ed25519", "git status", 1);
    set_comm(&entries[2], 0, "bash");

    n = prune_find(entries, 3, groups, 3, removals, 3, &removal_count);
    ASSERT(n == 0, "distinct rules form no group");
    ASSERT(removal_count == 0, "distinct rules have no removals");

    TEST_PASS("no duplicates");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  one group of two: newest (last) member kept, older removed         */
/* ------------------------------------------------------------------ */

static int test_prune_one_group_pair(void)
{
    PersistEntry entries[2];
    PruneGroup groups[2];
    int removals[2];
    int removal_count = -1;
    int new_count = -1;
    int n;

    make_entry(&entries[0], "/usr/bin/git", "/home/u/.ssh/id_rsa", "git status", 1);
    set_comm(&entries[0], 0, "bash");
    snprintf(entries[0].binary_sha512, sizeof(entries[0].binary_sha512), "old");
    make_entry(&entries[1], "/usr/bin/git", "/home/u/.ssh/id_rsa", "git status", 1);
    set_comm(&entries[1], 0, "bash");
    snprintf(entries[1].binary_sha512, sizeof(entries[1].binary_sha512), "new");

    n = prune_find(entries, 2, groups, 2, removals, 2, &removal_count);
    ASSERT(n == 1, "identical pair forms one group");
    ASSERT(removal_count == 1, "identical pair removes one entry");
    ASSERT(groups[0].member_count == 2, "group has two members");
    ASSERT(groups[0].keep_index == 1, "newest (last) entry is kept");
    ASSERT(groups[0].remove_count == 1, "group reports one removal");
    ASSERT(groups[0].remove_offset == 0, "removal list starts at offset 0");
    ASSERT(removals[0] == 0, "older entry is the removal");

    ASSERT(prune_apply(entries, 2, removals, removal_count, &new_count) == 1,
           "apply removes one entry");
    ASSERT(new_count == 1, "apply reports the new count");
    ASSERT(strcmp(entries[0].binary_sha512, "new") == 0,
           "the newest entry survived");

    TEST_PASS("one group of two");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  one group of three interleaved with unrelated entries              */
/* ------------------------------------------------------------------ */

static int test_prune_interleaved_group(void)
{
    PersistEntry entries[5];
    PruneGroup groups[5];
    int removals[5];
    int removal_count = -1;
    int new_count = -1;
    int n;

    /* Key A at 0, 2 and 4; unrelated rules at 1 and 3. */
    make_entry(&entries[0], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&entries[0], 0, "bash");
    snprintf(entries[0].binary_sha512, sizeof(entries[0].binary_sha512), "a0");
    make_entry(&entries[1], "/usr/bin/other", "/protected/g", "other run", 0);
    snprintf(entries[1].binary_sha512, sizeof(entries[1].binary_sha512), "b1");
    make_entry(&entries[2], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&entries[2], 0, "bash");
    snprintf(entries[2].binary_sha512, sizeof(entries[2].binary_sha512), "a2");
    make_entry(&entries[3], "/usr/bin/third", "/protected/h", "third run", 0);
    snprintf(entries[3].binary_sha512, sizeof(entries[3].binary_sha512), "c3");
    make_entry(&entries[4], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&entries[4], 0, "bash");
    snprintf(entries[4].binary_sha512, sizeof(entries[4].binary_sha512), "a4");

    n = prune_find(entries, 5, groups, 5, removals, 5, &removal_count);
    ASSERT(n == 1, "one interleaved group found");
    ASSERT(removal_count == 2, "both older members are removals");
    ASSERT(groups[0].keep_index == 4, "newest member kept");
    ASSERT(groups[0].member_count == 3, "group has three members");
    ASSERT(groups[0].remove_count == 2, "group reports two removals");
    ASSERT(groups[0].remove_offset == 0, "removals start at offset 0");
    ASSERT(removals[0] == 0 && removals[1] == 2,
           "removals are the older members in ascending order");

    ASSERT(prune_apply(entries, 5, removals, removal_count, &new_count) == 2,
           "apply removes exactly the group's older members");
    ASSERT(new_count == 3, "apply reports three survivors");
    ASSERT(strcmp(entries[0].binary_sha512, "b1") == 0, "first survivor order");
    ASSERT(strcmp(entries[1].binary_sha512, "c3") == 0, "second survivor order");
    ASSERT(strcmp(entries[2].binary_sha512, "a4") == 0, "newest member survived");

    TEST_PASS("interleaved group of three");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  each key field splits groups: cmdline, chain comm, depth, target   */
/* ------------------------------------------------------------------ */

static int test_prune_key_fields_separate(void)
{
    PersistEntry e[2];

    /* Same everything but the raw command line. */
    make_entry(&e[0], "/usr/bin/tool", "/protected/f", "tool --one", 1);
    set_comm(&e[0], 0, "bash");
    make_entry(&e[1], "/usr/bin/tool", "/protected/f", "tool --two", 1);
    set_comm(&e[1], 0, "bash");
    ASSERT(count_groups(e, 2) == 0, "different cmdline is not a duplicate");

    /* Same everything but the deepest chain comm. */
    make_entry(&e[0], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&e[0], 0, "bash");
    make_entry(&e[1], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&e[1], 0, "zsh");
    ASSERT(count_groups(e, 2) == 0, "different chain comm is not a duplicate");

    /* Same comms but a different recorded call-chain depth. */
    make_entry(&e[0], "/usr/bin/tool", "/protected/f", "tool run", 2);
    set_comm(&e[0], 0, "bash");
    set_comm(&e[0], 1, "zsh");
    make_entry(&e[1], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&e[1], 0, "bash");
    set_comm(&e[1], 1, "zsh");
    ASSERT(count_groups(e, 2) == 0, "different chain depth is not a duplicate");

    /* Same everything but the target file. */
    make_entry(&e[0], "/usr/bin/tool", "/protected/a", "tool run", 1);
    set_comm(&e[0], 0, "bash");
    make_entry(&e[1], "/usr/bin/tool", "/protected/b", "tool run", 1);
    set_comm(&e[1], 0, "bash");
    ASSERT(count_groups(e, 2) == 0, "different target is not a duplicate");

    TEST_PASS("key fields separate groups");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  digest fields are not keys: a changed binary still groups          */
/* ------------------------------------------------------------------ */

static int test_prune_hash_fields_not_key(void)
{
    PersistEntry entries[3];
    PruneGroup groups[3];
    int removals[3];
    int removal_count = -1;
    int n;

    for (int i = 0; i < 3; i++)
    {
        make_entry(&entries[i], "/usr/bin/tool", "/protected/f", "tool run", 1);
        set_comm(&entries[i], 0, "bash");
        snprintf(entries[i].binary_sha512, sizeof(entries[i].binary_sha512),
                 "%011d", i);
        snprintf(entries[i].cmdline_sha512, sizeof(entries[i].cmdline_sha512),
                 "%011d", i + 10);
        snprintf(entries[i].chain_sha512[0], sizeof(entries[i].chain_sha512[0]),
                 "%011d", i + 20);
        entries[i].created_at = (time_t)(100 + i);
    }

    n = prune_find(entries, 3, groups, 3, removals, 3, &removal_count);
    ASSERT(n == 1, "digest differences do not split a group");
    ASSERT(removal_count == 2, "both older entries are removals");
    ASSERT(groups[0].keep_index == 2, "newest entry kept across digest changes");
    ASSERT(removals[0] == 0 && removals[1] == 1,
           "older entries listed for removal in order");

    TEST_PASS("digest fields are not keys");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  empty array and single entry                                       */
/* ------------------------------------------------------------------ */

static int test_prune_empty_and_single(void)
{
    PersistEntry one[1];
    int removal_count = -1;

    ASSERT(prune_find(NULL, 0, NULL, 0, NULL, 0, &removal_count) == 0,
           "empty input reports no groups");
    ASSERT(removal_count == 0, "empty input reports no removals");

    make_entry(&one[0], "/usr/bin/only", "/protected/f", "only run", 0);
    removal_count = -1;
    ASSERT(prune_find(one, 1, NULL, 0, NULL, 0, &removal_count) == 0,
           "single entry forms no group");
    ASSERT(removal_count == 0, "single entry reports no removals");

    TEST_PASS("empty and single-entry arrays");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  malformed entries are never grouped or removed                     */
/* ------------------------------------------------------------------ */

static int test_prune_malformed_never_grouped(void)
{
    PersistEntry e[13];
    PruneGroup groups[13];
    int removals[13];
    int removal_count = -1;
    int n;

    /* 0/1: empty binary. 2/3: empty target. 4/5: empty cmdline.
     * 6/8: a valid duplicate pair (8 is the newest). 7: unrelated.
     * 9/10 and 11/12: chain_depth out of range. */
    make_entry(&e[0], "", "/protected/a", "run", 1);
    make_entry(&e[1], "", "/protected/a", "run", 1);
    make_entry(&e[2], "/usr/bin/notarget", "", "run", 1);
    make_entry(&e[3], "/usr/bin/notarget", "", "run", 1);
    make_entry(&e[4], "/usr/bin/nocmdline", "/protected/b", "", 1);
    make_entry(&e[5], "/usr/bin/nocmdline", "/protected/b", "", 1);
    make_entry(&e[6], "/usr/bin/tool", "/protected/c", "run", 1);
    make_entry(&e[7], "/usr/bin/other", "/protected/d", "other run", 1);
    make_entry(&e[8], "/usr/bin/tool", "/protected/c", "run", 1);
    make_entry(&e[9], "/usr/bin/depthneg", "/protected/e", "run", -1);
    make_entry(&e[10], "/usr/bin/depthneg", "/protected/e", "run", -1);
    make_entry(&e[11], "/usr/bin/depthhuge", "/protected/e", "run",
               PERSIST_CHAIN_MAX + 1);
    make_entry(&e[12], "/usr/bin/depthhuge", "/protected/e", "run",
               PERSIST_CHAIN_MAX + 1);

    n = prune_find(e, 13, groups, 13, removals, 13, &removal_count);
    ASSERT(n == 1, "only the well-formed pair forms a group");
    ASSERT(removal_count == 1, "only the older well-formed duplicate is removed");
    ASSERT(groups[0].keep_index == 8, "well-formed pair keeps the newest entry");
    ASSERT(removals[0] == 6, "malformed entries are never removal candidates");

    TEST_PASS("malformed entries are never grouped");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  chain boundary: compare exactly chain_depth comm levels            */
/* ------------------------------------------------------------------ */

static int test_prune_chain_depth_boundary(void)
{
    PersistEntry stale[2];
    PersistEntry depth[2];
    PruneGroup groups[2];
    int removals[2];
    int removal_count = -1;
    int n;

    /* Stale contents beyond chain_depth must not split a group. */
    make_entry(&stale[0], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&stale[0], 0, "bash");
    set_comm(&stale[0], 1, "stale-one");
    set_comm(&stale[0], 2, "stale-one-deeper");
    make_entry(&stale[1], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&stale[1], 0, "bash");
    set_comm(&stale[1], 1, "stale-two");
    set_comm(&stale[1], 2, "stale-two-deeper");

    n = prune_find(stale, 2, groups, 2, removals, 2, &removal_count);
    ASSERT(n == 1, "stale comm slots beyond depth are ignored");
    ASSERT(groups[0].keep_index == 1, "newest entry kept");
    ASSERT(removal_count == 1 && removals[0] == 0, "older entry removed");

    /* chain_depth itself is a key field. */
    make_entry(&depth[0], "/usr/bin/tool", "/protected/f", "tool run", 2);
    set_comm(&depth[0], 0, "bash");
    set_comm(&depth[0], 1, "zsh");
    make_entry(&depth[1], "/usr/bin/tool", "/protected/f", "tool run", 1);
    set_comm(&depth[1], 0, "bash");
    set_comm(&depth[1], 1, "zsh");

    ASSERT(count_groups(depth, 2) == 0, "different depth does not group");

    TEST_PASS("chain depth boundary");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  find reports without mutating the input array                      */
/* ------------------------------------------------------------------ */

static int test_prune_find_does_not_mutate(void)
{
    PersistEntry entries[4];
    PersistEntry before[4];
    PruneGroup groups[2];
    int removals[4];
    int removal_count = -1;
    int n;

    /* Two independent groups interleaved: A at 0/2, B at 1/3. */
    make_entry(&entries[0], "/usr/bin/a", "/protected/a", "a run", 0);
    snprintf(entries[0].binary_sha512, sizeof(entries[0].binary_sha512), "a0");
    make_entry(&entries[1], "/usr/bin/b", "/protected/b", "b run", 0);
    snprintf(entries[1].binary_sha512, sizeof(entries[1].binary_sha512), "b1");
    make_entry(&entries[2], "/usr/bin/a", "/protected/a", "a run", 0);
    snprintf(entries[2].binary_sha512, sizeof(entries[2].binary_sha512), "a2");
    make_entry(&entries[3], "/usr/bin/b", "/protected/b", "b run", 0);
    snprintf(entries[3].binary_sha512, sizeof(entries[3].binary_sha512), "b3");
    memcpy(before, entries, sizeof(entries));

    n = prune_find(entries, 4, groups, 2, removals, 4, &removal_count);
    ASSERT(n == 2, "two groups found");
    ASSERT(removal_count == 2, "one removal per group");
    ASSERT(groups[0].keep_index == 2 && groups[0].remove_count == 1 &&
               groups[0].remove_offset == 0,
           "first group describes its own removal slice");
    ASSERT(groups[1].keep_index == 3 && groups[1].remove_count == 1 &&
               groups[1].remove_offset == 1,
           "second group describes its own removal slice");
    ASSERT(removals[0] == 0 && removals[1] == 1,
           "flat removal list is ascending");
    ASSERT(memcmp(entries, before, sizeof(entries)) == 0,
           "find leaves the input array untouched");

    TEST_PASS("find does not mutate");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  interleaved groups: the flat removal list follows group order      */
/* ------------------------------------------------------------------ */

static int test_prune_interleaved_flat_order(void)
{
    PersistEntry e[5];
    PruneGroup groups[2];
    int removals[5];
    int removal_count = -1;
    int new_count = -1;
    int n;

    /* A at 0,2,3 and B at 1,4: group A's slice [0,2] precedes group B's
     * [1], so the flat list is [0,2,1] -- deliberately not ascending.
     * Consumers that assumed global order silently pruned the wrong
     * set; apply must treat the list as a set of indices. */
    make_entry(&e[0], "/usr/bin/a", "/p/a", "a run", 0);
    make_entry(&e[1], "/usr/bin/b", "/p/b", "b run", 0);
    make_entry(&e[2], "/usr/bin/a", "/p/a", "a run", 0);
    make_entry(&e[3], "/usr/bin/a", "/p/a", "a run", 0);
    make_entry(&e[4], "/usr/bin/b", "/p/b", "b run", 0);

    n = prune_find(e, 5, groups, 2, removals, 5, &removal_count);
    ASSERT(n == 2, "two interleaved groups");
    ASSERT(removal_count == 3, "three removals");
    ASSERT(removals[0] == 0 && removals[1] == 2 && removals[2] == 1,
           "flat list follows group order, not global order");
    ASSERT(groups[0].keep_index == 3 && groups[0].remove_offset == 0 &&
               groups[0].remove_count == 2,
           "group A owns its slice");
    ASSERT(groups[1].keep_index == 4 && groups[1].remove_offset == 2 &&
               groups[1].remove_count == 1,
           "group B owns its slice");

    ASSERT(prune_apply(e, 5, removals, removal_count, &new_count) == 3,
           "apply accepts the grouped list");
    ASSERT(new_count == 2, "two survivors");
    ASSERT(strcmp(e[0].binary, "/usr/bin/a") == 0 &&
               strcmp(e[1].binary, "/usr/bin/b") == 0,
           "the kept members survive in order");

    TEST_PASS("interleaved flat removal order");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  capacity handling: fail, never truncate                            */
/* ------------------------------------------------------------------ */

static int test_prune_capacity_errors(void)
{
    PersistEntry pair[2];
    PersistEntry single[1];
    PruneGroup groups[1];
    int removals[1];
    int removal_count = -1;

    make_entry(&pair[0], "/usr/bin/tool", "/protected/f", "tool run", 0);
    make_entry(&pair[1], "/usr/bin/tool", "/protected/f", "tool run", 0);

    ASSERT(prune_find(pair, 2, NULL, 0, removals, 1, &removal_count) == -1,
           "too few group slots fails instead of truncating");
    ASSERT(prune_find(pair, 2, groups, 1, NULL, 0, &removal_count) == -1,
           "too few removal slots fails instead of truncating");

    removal_count = -1;
    ASSERT(prune_find(pair, 2, groups, 1, removals, 1, &removal_count) == 1,
           "exact capacity succeeds");
    ASSERT(removal_count == 1, "exact capacity reports the removal");

    make_entry(&single[0], "/usr/bin/only", "/protected/f", "only run", 0);
    removal_count = -1;
    ASSERT(prune_find(single, 1, NULL, 0, NULL, 0, &removal_count) == 0,
           "no duplicates need no output buffers");

    TEST_PASS("capacity errors");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  apply compacts in order and reports the new count                  */
/* ------------------------------------------------------------------ */

static int test_prune_apply_compacts(void)
{
    PersistEntry e[5];
    const int removals[2] = {1, 3};
    int new_count = -1;

    make_entry(&e[0], "/usr/bin/a", "/p/a", "a run", 0);
    snprintf(e[0].binary_sha512, sizeof(e[0].binary_sha512), "A");
    make_entry(&e[1], "/usr/bin/b", "/p/b", "b run", 0);
    snprintf(e[1].binary_sha512, sizeof(e[1].binary_sha512), "B");
    make_entry(&e[2], "/usr/bin/c", "/p/c", "c run", 0);
    snprintf(e[2].binary_sha512, sizeof(e[2].binary_sha512), "C");
    make_entry(&e[3], "/usr/bin/d", "/p/d", "d run", 0);
    snprintf(e[3].binary_sha512, sizeof(e[3].binary_sha512), "D");
    make_entry(&e[4], "/usr/bin/e", "/p/e", "e run", 0);
    snprintf(e[4].binary_sha512, sizeof(e[4].binary_sha512), "E");

    ASSERT(prune_apply(e, 5, removals, 2, &new_count) == 2,
           "apply reports the removed count");
    ASSERT(new_count == 3, "apply reports the new count");
    ASSERT(strcmp(e[0].binary_sha512, "A") == 0, "survivor A kept its position");
    ASSERT(strcmp(e[1].binary_sha512, "C") == 0, "survivor C moved down in order");
    ASSERT(strcmp(e[2].binary_sha512, "E") == 0, "survivor E moved down in order");

    ASSERT(prune_apply(e, 3, NULL, 0, &new_count) == 0,
           "empty removal list is a no-op");
    ASSERT(new_count == 3, "no-op keeps the count");

    TEST_PASS("apply compacts");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  apply rejects malformed removal lists without touching entries     */
/* ------------------------------------------------------------------ */

static int test_prune_apply_rejects_bad_input(void)
{
    PersistEntry e[3];
    PersistEntry before[3];
    const int unsorted[2] = {2, 1};
    const int duplicate[2] = {1, 1};
    const int out_of_range[1] = {3};
    const int negative[1] = {-1};
    int new_count = -1;

    make_entry(&e[0], "/usr/bin/a", "/p/a", "a run", 0);
    make_entry(&e[1], "/usr/bin/b", "/p/b", "b run", 0);
    make_entry(&e[2], "/usr/bin/c", "/p/c", "c run", 0);
    memcpy(before, e, sizeof(e));

    /* prune_find emits per-group slices, so the flat list is not
     * globally sorted when groups interleave; apply must treat it as a
     * set.  This check mutates e, so restore it before the rejection
     * cases below. */
    ASSERT(prune_apply(e, 3, unsorted, 2, &new_count) == 2,
           "unsorted (set) removal indices accepted");
    ASSERT(new_count == 1 && strcmp(e[0].binary, "/usr/bin/a") == 0,
           "set apply keeps the surviving entry");
    memcpy(e, before, sizeof(e));

    ASSERT(prune_apply(e, 3, duplicate, 2, &new_count) == -1,
           "duplicate removal indices rejected");
    ASSERT(prune_apply(e, 3, out_of_range, 1, &new_count) == -1,
           "out-of-range removal index rejected");
    ASSERT(prune_apply(e, 3, negative, 1, &new_count) == -1,
           "negative removal index rejected");
    ASSERT(prune_apply(e, 3, NULL, 1, &new_count) == -1,
           "NULL removal list rejected");
    ASSERT(memcmp(e, before, sizeof(e)) == 0,
           "rejected apply leaves entries untouched");

    TEST_PASS("apply validates removal sets");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  invalid arguments                                                  */
/* ------------------------------------------------------------------ */

static int test_prune_invalid_args(void)
{
    PersistEntry e[1];
    PruneGroup groups[1];
    int removals[1];
    int removal_count = -1;
    int new_count = -1;

    make_entry(&e[0], "/usr/bin/tool", "/protected/f", "tool run", 0);

    ASSERT(prune_find(e, -1, groups, 1, removals, 1, &removal_count) == -1,
           "find rejects a negative count");
    ASSERT(prune_find(NULL, 1, groups, 1, removals, 1, &removal_count) == -1,
           "find rejects NULL entries with a non-zero count");
    ASSERT(prune_find(e, 1, NULL, 1, removals, 1, &removal_count) == -1,
           "find rejects NULL groups with a non-zero capacity");
    ASSERT(prune_find(e, 1, groups, -1, removals, 1, &removal_count) == -1,
           "find rejects a negative group capacity");
    ASSERT(prune_find(e, 1, groups, 1, removals, 1, NULL) == -1,
           "find requires the removal count output");

    ASSERT(prune_apply(e, -1, NULL, 0, &new_count) == -1,
           "apply rejects a negative count");
    ASSERT(prune_apply(NULL, 1, NULL, 0, &new_count) == -1,
           "apply rejects NULL entries with a non-zero count");
    ASSERT(prune_apply(e, 1, removals, 0, NULL) == -1,
           "apply requires the new-count output");

    TEST_PASS("invalid arguments");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    int failed = 0;

    fprintf(stdout, "=== test_prune ===\n");

    failed |= test_prune_no_duplicates();
    failed |= test_prune_one_group_pair();
    failed |= test_prune_interleaved_group();
    failed |= test_prune_key_fields_separate();
    failed |= test_prune_hash_fields_not_key();
    failed |= test_prune_empty_and_single();
    failed |= test_prune_malformed_never_grouped();
    failed |= test_prune_chain_depth_boundary();
    failed |= test_prune_find_does_not_mutate();
    failed |= test_prune_interleaved_flat_order();
    failed |= test_prune_capacity_errors();
    failed |= test_prune_apply_compacts();
    failed |= test_prune_apply_rejects_bad_input();
    failed |= test_prune_invalid_args();

    if (failed)
    {
        fprintf(stdout, "FAIL\n");
        return 1;
    }
    fprintf(stdout, "PASS\n");
    return 0;
}
