#ifndef FILESHIELD_SHA512_H
#define FILESHIELD_SHA512_H

#include <sys/types.h>
/*
 * Compute the SHA-512 digest of the file at 'path' by running sha512sum(1)
 * (part of GNU coreutils, always available on Linux systems).
 *
 * On success, writes exactly 128 lower-case hex characters followed by a NUL
 * into hex_out[129] and returns 0.
 *
 * Returns -1 on error (binary not found, unreadable file, unexpected output).
 * hex_out is left untouched on error.
 */
int sha512_file(const char *path, char hex_out[129]);

/*
 * Compute the SHA-512 digest of the executable of process 'pid' by hashing
 * /proc/<pid>/exe directly.  This works even when the process runs inside a
 * container (Podman, Docker) and its binary path does not exist on the host
 * filesystem.
 *
 * Same return semantics as sha512_file().
 */
int sha512_proc_exe(pid_t pid, char hex_out[129]);

/*
 * Compute the SHA-512 digest of an in-memory string (used to fingerprint
 * command lines without persisting potentially secret arguments).
 * Same return semantics as sha512_file().
 */
int sha512_string(const char *str, char hex_out[129]);

/*
 * Compute the SHA-512 digest of a length-delimited memory buffer.  Unlike
 * sha512_string(), the buffer may contain NUL bytes: the raw
 * /proc/<pid>/cmdline bytes are NUL-separated, and fingerprinting them
 * as-is keeps the digest independent of any display truncation.
 * 'data' must be non-NULL (len may be 0).  Same return semantics as
 * sha512_file().
 */
int sha512_buf(const void *data, size_t len, char hex_out[129]);

#endif /* FILESHIELD_SHA512_H */
