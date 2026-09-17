#ifndef FILESHIELD_PRUNE_H
#define FILESHIELD_PRUNE_H

#include "persist.h"

/*
 * Offline "prune" of duplicate entries in the persisted runtime
 * allow/deny lists (fileshield-cli prune; the daemon applies the same
 * report to its in-memory lists).
 *
 * Pure and offline by design: no file I/O, no hashing, no allocation and
 * no path is ever opened.  That matters because prune is also reachable
 * through the daemon, whose marks intercept protected-path opens -- the
 * grouping only ever inspects the entry arrays the caller already holds.
 *
 * A duplicate group shares one key: binary + target_path + the raw
 * command line (compared byte-for-byte) + the call chain (chain_depth
 * and chain_comm[0..chain_depth-1]).  The digest fields are deliberately
 * NOT part of the key: the case prune exists for is a binary that
 * changed on disk, which changes binary_sha512 (and with it
 * chain_sha512) while the logical rule stays the same.
 *
 * Entries are appended chronologically by every writer and loader
 * (dyn_add() appends; an overflow memmoves the oldest entry off the
 * head; persist_save() writes list order, persist_load() preserves it),
 * so within a group the NEWEST entry is the one with the highest index.
 * It is kept and the older ones are removed; created_at is display /
 * tie-break information only and never decides the keep.
 *
 * An entry missing a key field (empty binary, empty target_path or
 * empty cmdline) or with a chain_depth outside [0, PERSIST_CHAIN_MAX] is
 * never a prune candidate: it forms no group and is never removed.  A
 * damaged or hand-edited entry must not be able to drag a valid rule
 * into a removal set (fail closed); such entries stay for the loaders to
 * repair or drop.
 */

typedef struct
{
    int keep_index;    /* newest member: the entry retained             */
    int member_count;  /* entries sharing the key; always >= 2          */
    int remove_offset; /* first index into the flat removals array      */
    int remove_count;  /* older members; member_count == remove_count+1 */
} PruneGroup;

/*
 * Find duplicate groups in entries[0..count) without modifying them.
 *
 * groups/max_groups and removals/max_removals are caller-supplied
 * buffers.  On success groups[0..returned-1] describes each duplicate
 * group (ordered by its first member) and removals[0..*removal_count_out-1]
 * lists every doomed index in ascending order; group g's removals are
 * removals[remove_offset .. remove_offset+remove_count-1].  A caller
 * sizing for the worst case needs count/2 groups (each group keeps one
 * member) and count-1 removals; capacities that are too small fail the
 * call instead of truncating silently.
 *
 * Returns the number of groups on success (0 when nothing is a
 * duplicate, including count == 0), or -1 on invalid arguments or
 * insufficient capacity.  On failure the output arrays are unspecified
 * and *removal_count_out is 0.
 */
int prune_find(const PersistEntry *entries, int count,
               PruneGroup *groups, int max_groups,
               int *removals, int max_removals,
               int *removal_count_out);

/*
 * Remove the reported entries from entries[0..count) in place, moving
 * the survivors down in their original relative order.  removals holds
 * the indices reported by prune_find (any strictly ascending list of
 * unique, in-range indices is accepted); entries[new_count..count) are
 * left unspecified.  An empty list is a no-op.
 *
 * Every index is validated before anything is modified, so a rejected
 * call leaves entries untouched.  Returns the number of entries removed
 * (0 for a no-op), or -1 on invalid arguments (NULL entries/output,
 * count < 0, out-of-range, duplicate or unsorted indices).
 */
int prune_apply(PersistEntry *entries, int count, const int *removals,
                int removal_count, int *new_count_out);

#endif
