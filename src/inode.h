#ifndef FILESHIELD_INODE_H
#define FILESHIELD_INODE_H

#include <sys/types.h>

#include "config.h" /* INODE_SET_MAX is sized from MAX_PATHS */

/*
 * Protected-inode set: records the (device, inode) pair of every file
 * under a protected path, so a hard link opened through an unprotected
 * path can still be recognized as protected.  The mount mark delivers
 * the event; this set decides whether it matters.
 *
 * Fixed capacity, no allocation, single-threaded like the rest of the
 * daemon.  Overflow degrades hard-link detection (logged), it never
 * blocks access.
 */
#define INODE_SET_MAX (MAX_PATHS * 32)

/* Record a protected inode; duplicates are ignored, overflow is logged
 * and the entry dropped. */
void inode_set_add(dev_t dev, ino_t ino);

/* Non-zero when the (dev, ino) pair was recorded. */
int inode_set_contains(dev_t dev, ino_t ino);

/* Forget every entry (config reload, tests). */
void inode_set_clear(void);

#endif
