/*
 * test_inode: the protected-inode set used for hard-link detection.
 * Covers exact-key lookup, duplicate adds, clearing and the documented
 * overflow degradation (entries past capacity are dropped; existing
 * entries stay findable).
 */
#include <stdio.h>
#include <sys/types.h>

#include "../src/inode.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

static void test_add_contains(void)
{
    inode_set_clear();

    ASSERT(inode_set_contains(1, 100) == 0, "empty set contains nothing");
    inode_set_add(1, 100);
    ASSERT(inode_set_contains(1, 100) == 1, "exact key found");
    ASSERT(inode_set_contains(1, 101) == 0, "different inode not found");
    ASSERT(inode_set_contains(2, 100) == 0, "different device not found");

    inode_set_clear();
}

static void test_duplicate_and_clear(void)
{
    inode_set_clear();

    inode_set_add(5, 50);
    inode_set_add(5, 50);
    ASSERT(inode_set_contains(5, 50) == 1, "duplicate add stays findable");

    inode_set_clear();
    ASSERT(inode_set_contains(5, 50) == 0, "clear forgets entries");
}

static void test_overflow_degrades(void)
{
    inode_set_clear();

    for (int i = 0; i < INODE_SET_MAX + 1; i++)
        inode_set_add(7, (ino_t)(1000 + i));

    ASSERT(inode_set_contains(7, 1000) == 1,
           "first entry retained at capacity");
    ASSERT(inode_set_contains(7, (ino_t)(1000 + INODE_SET_MAX - 1)) == 1,
           "last stored entry retained");
    ASSERT(inode_set_contains(7, (ino_t)(1000 + INODE_SET_MAX)) == 0,
           "entry past capacity is dropped");

    inode_set_clear();
}

int main(void)
{
    printf("=== test_inode ===\n");
    test_add_contains();
    test_duplicate_and_clear();
    test_overflow_degrades();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
