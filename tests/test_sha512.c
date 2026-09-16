/*
 * test_sha512: digest helpers used for binary identity and command-line
 * fingerprints.  The known-answer vectors come from FIPS 180-4.
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../src/sha512.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

static void test_string_vector(void)
{
    char hex[129];
    const char *want =
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    ASSERT(sha512_string("abc", hex) == 0, "sha512_string computes");
    ASSERT(strcmp(hex, want) == 0, "sha512_string matches the known vector");
}

static void test_string_empty(void)
{
    char hex[129];
    const char *want =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    ASSERT(sha512_string("", hex) == 0, "sha512_string empty computes");
    ASSERT(strcmp(hex, want) == 0, "sha512_string empty digest correct");
}

static void test_string_differs(void)
{
    char a[129], b[129];

    ASSERT(sha512_string("kubectl get pods", a) == 0, "first digest");
    ASSERT(sha512_string("kubectl get secrets", b) == 0, "second digest");
    ASSERT(strcmp(a, b) != 0, "different command lines differ");
    ASSERT(strlen(a) == 128, "digest is 128 hex chars");
}

static void test_string_multiblock(void)
{
    char hex[129];
    /* FIPS 180-4 two-block vector (105 bytes) exercises block chaining. */
    const char *msg =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqrlmnopqrsmnopqrstnopqrstu";
    const char *want =
        "84456dbc64e67596d06bca52fcff37e6559394725c13103cbfef17c745607760"
        "1de43e836476729bbde050bffdb3978f814bb7a94f391098debc53a70cf63763";

    ASSERT(sha512_string(msg, hex) == 0, "multiblock computes");
    ASSERT(strcmp(hex, want) == 0, "multiblock matches known vector");
}

static void test_string_invalid(void)
{
    char hex[129];

    ASSERT(sha512_string(NULL, hex) == -1, "NULL input fails");
}

/*
 * sha512_buf hashes length-delimited data, so embedded NUL bytes (the raw
 * /proc/<pid>/cmdline separators) are part of the digest and cannot
 * truncate it the way a string hash would.
 */
static void test_buf_nul_bytes(void)
{
    char with_nul[129], truncated[129];

    ASSERT(sha512_buf("abc\0def", 7, with_nul) == 0, "buffer digest computes");
    ASSERT(sha512_string("abc", truncated) == 0, "prefix digest computes");
    ASSERT(strcmp(with_nul, truncated) != 0,
           "embedded NUL bytes are hashed, not treated as a terminator");
    ASSERT(strlen(with_nul) == 128, "buffer digest is 128 hex chars");
    ASSERT(sha512_buf(NULL, 0, with_nul) == -1, "NULL buffer fails");
}

/*
 * Differential test for raw bytes: sha512_buf must agree with sha512sum
 * on content that contains NUL bytes.
 */
static void test_buf_differential(void)
{
    static const char raw[] = {'a', 'b', 'c', '\0', 'd', 'e', 'f'};
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/tmp/fileshield_sha512_bufdiff_%d",
             (int)getpid());

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT(fd >= 0, "open buffer differential temp file");
    if (fd < 0)
        return;
    ASSERT(write(fd, raw, sizeof(raw)) == (ssize_t)sizeof(raw),
           "write raw sample");
    close(fd);

    char hex_file[129], hex_buf[129];
    ASSERT(sha512_file(path, hex_file) == 0, "helper digest (raw bytes)");
    ASSERT(sha512_buf(raw, sizeof(raw), hex_buf) == 0,
           "buffer digest (raw bytes)");
    ASSERT(strcmp(hex_file, hex_buf) == 0,
           "buffer digest matches sha512sum for raw bytes");

    unlink(path);
}

/*
 * Differential test: the in-process string digest must agree with
 * sha512sum (exercised through sha512_file's helper path) for the same
 * bytes, at lengths that span block boundaries.
 */
static void test_string_differential(void)
{
    const char *samples[] = {
        "",
        "Fileshield differential test payload 0123456789",
        "a",                     /* block interior              */
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqrlmnopqrsmnopqrstnopqrstu", /* 105 bytes  */
        "0123456789012345678901234567890123456789012345678901234567890123"
        "4567890123456789012345678901234567890123456789012345678901234567"
        "8901234567890123456789012345678901234567890123456789012345678901"
        "2345",                  /* 352 bytes, three blocks     */
    };

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/tmp/fileshield_sha512_diff_%d", (int)getpid());

    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++)
    {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        ASSERT(fd >= 0, "open differential temp file");
        if (fd < 0)
            return;
        size_t len = strlen(samples[i]);
        ASSERT(write(fd, samples[i], len) == (ssize_t)len, "write sample");
        close(fd);

        char hex_file[129], hex_str[129];
        ASSERT(sha512_file(path, hex_file) == 0, "helper digest");
        ASSERT(sha512_string(samples[i], hex_str) == 0, "in-process digest");
        ASSERT(strcmp(hex_file, hex_str) == 0,
               "in-process digest matches sha512sum");
    }
    unlink(path);
}

static void test_file_digest(void)
{
    char hex[129];

    /* /proc/self/exe resolves inside the helper (sha512sum), which is a
     * valid file.  Only the format is asserted, not a specific digest. */
    ASSERT(sha512_file("/proc/self/exe", hex) == 0, "hash own executable");
    ASSERT(strlen(hex) == 128, "file digest is 128 hex chars");
    ASSERT(sha512_file("/nonexistent/fileshield/sha512", hex) == -1,
           "missing file fails");
}

/*
 * Failure reasons: a failed file hash records a human-readable reason for
 * the prompt/diagnostic path, and the next successful hash clears it.
 */
static void test_file_failure_reason(void)
{
    char hex[129];

    ASSERT(sha512_file("/nonexistent/fileshield/sha512", hex) == -1,
           "missing file fails");
    ASSERT(sha512_last_failure()[0] != '\0',
           "failure reason is recorded after a failed hash");

    ASSERT(sha512_file("/proc/self/exe", hex) == 0, "hash own executable");
    ASSERT(sha512_last_failure()[0] == '\0',
           "failure reason is cleared after a successful hash");
}

/*
 * GNU sha512sum prefixes its output line with a backslash when the
 * printed filename contains a backslash or newline; the digest must
 * still parse for such paths.
 */
static void test_file_backslash_path(void)
{
    char path[PATH_MAX];
    char hex[129];

    snprintf(path, sizeof(path), "/tmp/fileshield_sha512_back\\slash_%d",
             (int)getpid());
    unlink(path);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT(fd >= 0, "create backslash-named file");
    if (fd >= 0)
    {
        ASSERT(write(fd, "backslash", 9) == 9, "write backslash-named file");
        close(fd);
        ASSERT(sha512_file(path, hex) == 0,
               "digest parses for a backslash-named file");
        ASSERT(strlen(hex) == 128, "digest is 128 hex chars");
        unlink(path);
    }
}

int main(void)
{
    printf("=== test_sha512 ===\n");
    test_string_vector();
    test_string_empty();
    test_string_differs();
    test_string_multiblock();
    test_string_invalid();
    test_buf_nul_bytes();
    test_buf_differential();
    test_string_differential();
    test_file_digest();
    test_file_failure_reason();
    test_file_backslash_path();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
