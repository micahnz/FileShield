/*
 * test_sha512: digest helpers used for binary identity and command-line
 * fingerprints.  The known-answer vectors come from FIPS 180-4.
 */
#include <stdio.h>
#include <string.h>

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

static void test_string_invalid(void)
{
    char hex[129];

    ASSERT(sha512_string(NULL, hex) == -1, "NULL input fails");
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

int main(void)
{
    printf("=== test_sha512 ===\n");
    test_string_vector();
    test_string_empty();
    test_string_differs();
    test_string_invalid();
    test_file_digest();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
