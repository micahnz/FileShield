#include "inode.h"
#include "utils.h"

#include <stdint.h>
#include <string.h>
#include <syslog.h>

/*
 * Open-addressing hash set keyed by (dev, ino).  The slot count is twice
 * the entry cap, so linear probing stays short (load factor <= 0.5) and
 * an empty slot always exists: contains() can never loop forever, and
 * there is no deletion path, only clear().
 *
 * Baseline for this replacement (bench_hotpath, linear scan -> hash):
 *   inode lookup  1k: 0.208 us -> 0.002 us
 *   inode lookup  8k: 1.609 us -> 0.002 us
 *   inode lookup 32k: 8.536 us -> 0.002 us
 *   fastpath verdict (noise, 8k entries): 4.552 us -> 0.242 us
 * The fast path runs for every open on a mount-marked filesystem, so the
 * linear scan was a system-wide CPU tax proportional to the table size.
 */

#define INODE_SLOT_COUNT 65536

/* Compile-time guard: load factor must stay <= 0.5. */
typedef char inode_slot_capacity_ok
    [(INODE_SET_MAX * 2 <= (int)INODE_SLOT_COUNT) ? 1 : -1];

typedef struct
{
    dev_t dev;
    ino_t ino;
} InodeKey;

static InodeKey g_slots[INODE_SLOT_COUNT];
static unsigned char g_used[INODE_SLOT_COUNT]; /* 1 = slot holds a key */
static int g_inode_count = 0;

/* FNV-1a over the two key words, folded to the table mask. */
static uint32_t inode_hash(dev_t dev, ino_t ino)
{
    uint64_t h = 1469598103934665603ULL; /* FNV offset basis */
    h ^= (uint64_t)dev;
    h *= 1099511628211ULL; /* FNV prime */
    h ^= (uint64_t)ino;
    h *= 1099511628211ULL;
    h ^= h >> 32; /* mix the high bits into the masked low bits */
    return (uint32_t)h & (INODE_SLOT_COUNT - 1);
}

void inode_set_add(dev_t dev, ino_t ino)
{
    uint32_t idx = inode_hash(dev, ino);

    for (;;)
    {
        if (!g_used[idx])
            break;
        if (g_slots[idx].dev == dev && g_slots[idx].ino == ino)
            return; /* already recorded */
        idx = (idx + 1) & (INODE_SLOT_COUNT - 1);
    }

    if (g_inode_count >= INODE_SET_MAX)
    {
        log_msg(LOG_ERR,
                "inode table full (max %d); hard-link detection is "
                "incomplete",
                INODE_SET_MAX);
        return;
    }
    g_slots[idx].dev = dev;
    g_slots[idx].ino = ino;
    g_used[idx] = 1;
    g_inode_count++;
}

int inode_set_contains(dev_t dev, ino_t ino)
{
    uint32_t idx = inode_hash(dev, ino);

    while (g_used[idx])
    {
        if (g_slots[idx].dev == dev && g_slots[idx].ino == ino)
            return 1;
        idx = (idx + 1) & (INODE_SLOT_COUNT - 1);
    }
    return 0;
}

void inode_set_clear(void)
{
    memset(g_used, 0, sizeof(g_used));
    g_inode_count = 0;
}
