/*
 * prune.c -- duplicate-rule grouping for the persisted runtime lists
 * (see prune.h).  No I/O, no allocation: grouping runs over the caller's
 * array and a handful of index scans, so the module is safe to call
 * from the CLI (over a state file it already read) and from the daemon
 * (while its marks are live and a protected-path open would deadlock).
 */

#include "prune.h"

#include <string.h>

/*
 * A prune candidate must have every key field recorded.  Empty fields
 * name nothing that can be compared reliably and an out-of-range
 * chain_depth cannot be compared without reading stale array slots;
 * such entries stay untouched so a damaged or hand-edited entry can
 * never drag a valid rule into a removal set (fail closed).
 */
static int entry_prunable(const PersistEntry *e)
{
    if (e->binary[0] == '\0' || e->target_path[0] == '\0' ||
        e->cmdline[0] == '\0')
        return 0;
    return e->chain_depth >= 0 && e->chain_depth <= PERSIST_CHAIN_MAX;
}

/*
 * Key equality: binary + target + raw cmdline (byte-for-byte) + the
 * call chain's comm names up to chain_depth.  The digest fields are not
 * part of the key -- a binary that changed on disk changes every digest
 * while describing the same logical rule, which is the case prune
 * exists for.  Only the first chain_depth comm entries are compared:
 * stale contents beyond the recorded depth must neither split nor merge
 * a group.
 */
static int same_key(const PersistEntry *a, const PersistEntry *b)
{
    if (!entry_prunable(a) || !entry_prunable(b))
        return 0;
    if (strcmp(a->binary, b->binary) != 0)
        return 0;
    if (strcmp(a->target_path, b->target_path) != 0)
        return 0;
    if (strcmp(a->cmdline, b->cmdline) != 0)
        return 0;
    if (a->chain_depth != b->chain_depth)
        return 0;
    for (int i = 0; i < a->chain_depth; i++)
    {
        if (strcmp(a->chain_comm[i], b->chain_comm[i]) != 0)
            return 0;
    }
    return 1;
}

int prune_find(const PersistEntry *entries, int count,
               PruneGroup *groups, int max_groups,
               int *removals, int max_removals,
               int *removal_count_out)
{
    int group_count = 0;
    int removal_count = 0;

    if (count < 0 || !removal_count_out)
        return -1;
    if (count > 0 && !entries)
        return -1;
    if (max_groups < 0 || max_removals < 0)
        return -1;
    if ((!groups && max_groups > 0) || (!removals && max_removals > 0))
        return -1;
    *removal_count_out = 0;

    for (int i = 0; i < count; i++)
    {
        if (!entry_prunable(&entries[i]))
            continue;

        /* The first prunable entry of a key owns its group: every later
         * occurrence is collected by this scan, so a second pass over
         * the same key finds it already handled. */
        int earlier = 0;
        for (int j = 0; j < i; j++)
        {
            if (same_key(&entries[j], &entries[i]))
            {
                earlier = 1;
                break;
            }
        }
        if (earlier)
            continue;

        /* List order is insertion order, so the newest member is the
         * last entry carrying this key. */
        int keep = -1;
        int member_count = 1;
        for (int j = i + 1; j < count; j++)
        {
            if (same_key(&entries[i], &entries[j]))
            {
                keep = j;
                member_count++;
            }
        }
        if (member_count < 2)
            continue;

        /* Refuse rather than truncate: a caller that sized its buffers
         * too small must notice, and the outputs written so far are
         * documented as unspecified on failure.  The pointer terms are
         * defensive (a positive capacity was validated to have a
         * buffer) and keep the analysis of the writes below local. */
        if (!removals || !groups ||
            group_count >= max_groups ||
            member_count - 1 > max_removals - removal_count)
            return -1;

        int offset = removal_count;
        for (int j = i; j < keep; j++)
        {
            if (same_key(&entries[i], &entries[j]))
                removals[removal_count++] = j;
        }
        groups[group_count].keep_index = keep;
        groups[group_count].member_count = member_count;
        groups[group_count].remove_offset = offset;
        groups[group_count].remove_count = member_count - 1;
        group_count++;
    }

    *removal_count_out = removal_count;
    return group_count;
}

int prune_apply(PersistEntry *entries, int count, const int *removals,
                int removal_count, int *new_count_out)
{
    int kept = 0;

    if (count < 0 || !new_count_out || removal_count < 0)
        return -1;
    if (count > 0 && !entries)
        return -1;

    /* Validate everything before mutating: a mutation either applies in
     * full or not at all, so a rejected call cannot leave a half-pruned
     * list behind.  prune_find() emits removals as per-group slices, so
     * the flat list is NOT globally ascending when two groups interleave
     * (e.g. A,B,A,A,B) -- only range and uniqueness are constraints.
     * The O(count * removal_count) membership scan is bounded by the
     * 256-entry state files, and prune must stay allocation-free. */
    for (int t = 0; t < removal_count; t++)
    {
        if (!removals || removals[t] < 0 || removals[t] >= count)
            return -1;
        for (int u = 0; u < t; u++)
        {
            if (removals[u] == removals[t])
                return -1;
        }
    }

    for (int i = 0; i < count; i++)
    {
        int drop = 0;

        for (int t = 0; t < removal_count; t++)
        {
            if (removals[t] == i)
            {
                drop = 1;
                break;
            }
        }
        if (drop)
            continue;
        if (kept != i)
            memmove(&entries[kept], &entries[i], sizeof(PersistEntry));
        kept++;
    }

    *new_count_out = kept;
    return removal_count;
}
