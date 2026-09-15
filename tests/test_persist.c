#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include "../src/persist.h"

/* All tests write to a temp directory under /tmp to avoid needing root. */
static char g_test_dir[256];

static void make_test_path(char *out, size_t sz, const char *name)
{
    snprintf(out, sz, "%s/%s", g_test_dir, name);
}

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

/* Pre-counted SHA-512 test values (62 hex chars, within 128-char limit) */
#define SHA_GIT "aaaa1111111111111111111111111111111111111111111111111111111111"
#define SHA_VIM "bbbb2222222222222222222222222222222222222222222222222222222222"
#define SHA_SSH "cccc3333333333333333333333333333333333333333333333333333333333"

static int test_persist_roundtrip(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "roundtrip.json");
    unlink(path);

    PersistEntry in[2];
    memset(in, 0, sizeof(in));

    /* Entry 0: chain depth 2 */
    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/git");
    snprintf(in[0].binary_sha512, sizeof(in[0].binary_sha512),
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(in[0].target_path, sizeof(in[0].target_path), "/home/user/.ssh/id_rsa");
    snprintf(in[0].cmdline, sizeof(in[0].cmdline), "git status --short");
    snprintf(in[0].cmdline_sha512, sizeof(in[0].cmdline_sha512),
             "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
             "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    in[0].chain_depth = 2;
    snprintf(in[0].chain_comm[0], sizeof(in[0].chain_comm[0]), "code");
    snprintf(in[0].chain_sha512[0], sizeof(in[0].chain_sha512[0]),
             "1111111111111111111111111111111111111111111111111111111111111111"
             "1111111111111111111111111111111111111111111111111111111111111111");
    snprintf(in[0].chain_comm[1], sizeof(in[0].chain_comm[1]), "systemd");
    snprintf(in[0].chain_sha512[1], sizeof(in[0].chain_sha512[1]),
             "2222222222222222222222222222222222222222222222222222222222222222"
             "2222222222222222222222222222222222222222222222222222222222222222");
    in[0].created_at = (time_t)1700000000;

    /* Entry 1: chain depth 1 */
    snprintf(in[1].binary, sizeof(in[1].binary), "/usr/bin/ssh");
    snprintf(in[1].binary_sha512, sizeof(in[1].binary_sha512),
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    snprintf(in[1].target_path, sizeof(in[1].target_path), "/etc/ssl/private/key.pem");
    in[1].chain_depth = 1;
    snprintf(in[1].chain_comm[0], sizeof(in[1].chain_comm[0]), "bash");
    snprintf(in[1].chain_sha512[0], sizeof(in[1].chain_sha512[0]),
             "3333333333333333333333333333333333333333333333333333333333333333"
             "3333333333333333333333333333333333333333333333333333333333333333");
    in[1].created_at = (time_t)1700001000;

    ASSERT(persist_save(path, in, 2) == 0, "persist_save returned 0");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 2, "persist_load returned 2 entries");

    ASSERT(strcmp(out[0].binary, "/usr/bin/git") == 0, "entry0 binary");
    ASSERT(strcmp(out[0].binary_sha512, in[0].binary_sha512) == 0, "entry0 sha512");
    ASSERT(strcmp(out[0].target_path, "/home/user/.ssh/id_rsa") == 0, "entry0 target_path");
    ASSERT(strcmp(out[0].cmdline, "git status --short") == 0, "entry0 cmdline");
    ASSERT(strcmp(out[0].cmdline_sha512, in[0].cmdline_sha512) == 0,
           "entry0 cmdline_sha512");
    ASSERT(out[0].chain_depth == 2, "entry0 chain_depth");
    ASSERT(strcmp(out[0].chain_comm[0], "code") == 0, "entry0 chain_comm[0]");
    ASSERT(strcmp(out[0].chain_comm[1], "systemd") == 0, "entry0 chain_comm[1]");
    ASSERT(strcmp(out[0].chain_sha512[0], in[0].chain_sha512[0]) == 0,
           "entry0 chain_sha512[0]");
    ASSERT(strcmp(out[0].chain_sha512[1], in[0].chain_sha512[1]) == 0,
           "entry0 chain_sha512[1]");
    ASSERT(out[0].created_at == (time_t)1700000000, "entry0 created_at");

    ASSERT(strcmp(out[1].binary, "/usr/bin/ssh") == 0, "entry1 binary");
    ASSERT(strcmp(out[1].target_path, "/etc/ssl/private/key.pem") == 0, "entry1 target_path");
    ASSERT(out[1].chain_depth == 1, "entry1 chain_depth");
    ASSERT(strcmp(out[1].chain_comm[0], "bash") == 0, "entry1 chain_comm[0]");

    unlink(path);
    TEST_PASS("roundtrip save/load");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: max chain depth (depth == PERSIST_CHAIN_MAX)                */
/*  Exercises the formerly-broken chain_comm/sha512[PERSIST_CHAIN_MAX-1] */
/* ------------------------------------------------------------------ */

static int test_persist_max_chain_depth(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "maxchain.json");
    unlink(path);

    PersistEntry in[1];
    memset(in, 0, sizeof(in));

    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/kubectl");
    snprintf(in[0].target_path, sizeof(in[0].target_path), "/var/run/secrets/tls.crt");
    in[0].chain_depth = PERSIST_CHAIN_MAX;
    for (int j = 0; j < PERSIST_CHAIN_MAX; j++)
    {
        snprintf(in[0].chain_comm[j], sizeof(in[0].chain_comm[j]), "ancestor%d", j);
        memset(in[0].chain_sha512[j], '0' + j, 128);
        in[0].chain_sha512[j][128] = '\0';
    }

    ASSERT(persist_save(path, in, 1) == 0, "persist_save max chain");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "persist_load max chain returns 1");
    ASSERT(out[0].chain_depth == PERSIST_CHAIN_MAX, "chain_depth == PERSIST_CHAIN_MAX");
    ASSERT(strcmp(out[0].target_path, "/var/run/secrets/tls.crt") == 0, "max chain target_path");

    for (int j = 0; j < PERSIST_CHAIN_MAX; j++)
    {
        char expected_comm[32];
        snprintf(expected_comm, sizeof(expected_comm), "ancestor%d", j);
        char msg[64];
        snprintf(msg, sizeof(msg), "chain_comm[%d] correct", j);
        ASSERT(strcmp(out[0].chain_comm[j], expected_comm) == 0, msg);
        snprintf(msg, sizeof(msg), "chain_sha512[%d] correct", j);
        ASSERT(strcmp(out[0].chain_sha512[j], in[0].chain_sha512[j]) == 0, msg);
    }

    unlink(path);
    TEST_PASS("max chain depth roundtrip");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: load from nonexistent file returns 0                        */
/* ------------------------------------------------------------------ */

static int test_persist_load_nonexistent(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "nonexistent.json");
    unlink(path);

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "load nonexistent returns 0");

    TEST_PASS("load nonexistent file");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: save zero entries, reload returns 0                         */
/* ------------------------------------------------------------------ */

static int test_persist_save_empty(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "empty.json");
    unlink(path);

    PersistEntry dummy[1];
    memset(dummy, 0, sizeof(dummy));
    ASSERT(persist_save(path, dummy, 0) == 0, "persist_save 0 entries");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "persist_load after empty save returns 0");

    unlink(path);
    TEST_PASS("save empty entries");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: chain depth variations (1..PERSIST_CHAIN_MAX)               */
/* ------------------------------------------------------------------ */

static int test_persist_chain_depths(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "chains.json");
    unlink(path);

    PersistEntry in[PERSIST_CHAIN_MAX];
    memset(in, 0, sizeof(in));

    for (int i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        snprintf(in[i].binary, sizeof(in[i].binary), "/usr/bin/chain%d", i);
        snprintf(in[i].target_path, sizeof(in[i].target_path), "/etc/target%d.conf", i);
        in[i].chain_depth = i + 1;
        for (int j = 0; j <= i; j++)
            snprintf(in[i].chain_comm[j], sizeof(in[i].chain_comm[j]), "proc%d", j);
    }

    ASSERT(persist_save(path, in, PERSIST_CHAIN_MAX) == 0, "persist_save chain depths");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == PERSIST_CHAIN_MAX, "persist_load chain depths count");

    for (int i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        char msg[64];
        snprintf(msg, sizeof(msg), "entry %d chain_depth", i);
        ASSERT(out[i].chain_depth == i + 1, msg);
        char expected_target[64];
        snprintf(expected_target, sizeof(expected_target), "/etc/target%d.conf", i);
        snprintf(msg, sizeof(msg), "entry %d target_path", i);
        ASSERT(strcmp(out[i].target_path, expected_target) == 0, msg);
        for (int j = 0; j <= i; j++)
        {
            char expected[32];
            snprintf(expected, sizeof(expected), "proc%d", j);
            snprintf(msg, sizeof(msg), "entry %d chain_comm[%d]", i, j);
            ASSERT(strcmp(out[i].chain_comm[j], expected) == 0, msg);
        }
    }

    unlink(path);
    TEST_PASS("chain depth variations");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: JSON special characters are escaped and restored            */
/*  Values are decoded escape-aware, so quotes and backslashes round-  */
/*  trip even though a naive %[^"] scan would stop at the first quote. */
/* ------------------------------------------------------------------ */

static int test_persist_json_escaping(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "escape.json");
    unlink(path);

    PersistEntry in[1];
    memset(in, 0, sizeof(in));

    /* A backslash in a binary path: unusual but valid on Linux. */
    snprintf(in[0].binary, sizeof(in[0].binary), "/usr/bin/my\\tool");
    /* A command line with escaped quotes and a backslash, as produced
     * by `sh -c "..."` invocations. */
    snprintf(in[0].cmdline, sizeof(in[0].cmdline),
             "sh -c \"echo \\\"hi\\\" > /tmp/x\"");
    in[0].chain_depth = 1;
    snprintf(in[0].chain_comm[0], sizeof(in[0].chain_comm[0]), "normalproc");

    ASSERT(persist_save(path, in, 1) == 0, "persist_save escaped chars");

    PersistEntry out[PERSIST_MAX_ENTRIES];
    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "persist_load escaped chars returns 1");
    ASSERT(strcmp(out[0].binary, "/usr/bin/my\\tool") == 0,
           "binary backslash roundtrip");
    ASSERT(strcmp(out[0].cmdline, "sh -c \"echo \\\"hi\\\" > /tmp/x\"") == 0,
           "cmdline quotes and backslash roundtrip");
    ASSERT(strcmp(out[0].chain_comm[0], "normalproc") == 0,
           "chain_comm normal name roundtrip");

    unlink(path);
    TEST_PASS("JSON special character escaping");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: malformed state files (negative / oversized chain_depth)    */
/*  Regression test for OOB write in persist_load().                  */
/* ------------------------------------------------------------------ */

static int write_raw_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");
    if (!fp)
        return -1;
    fputs(content, fp);
    fclose(fp);
    return 0;
}

static int test_persist_malformed_depth(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "malformed_depth.json");
    unlink(path);

    const char *negative =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": -1000000,\n"
        "      \"created_at\": 1\n"
        "    }\n  ]\n}\n";

    ASSERT(write_raw_file(path, negative) == 0, "write negative depth file");

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc negative depth output");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "negative depth entry still loads");
    ASSERT(out[0].chain_depth == 0, "negative depth clamped to 0");
    free(out);

    const char *huge =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": 999999,\n"
        "      \"created_at\": 1\n"
        "    }\n  ]\n}\n";

    ASSERT(write_raw_file(path, huge) == 0, "write huge depth file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc huge depth output");

    n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "huge depth entry still loads");
    ASSERT(out[0].chain_depth == PERSIST_CHAIN_MAX, "huge depth clamped");
    free(out);

    const char *garbage =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": \"not-a-number\",\n"
        "      \"created_at\": 1\n"
        "    }\n  ]\n}\n";

    ASSERT(write_raw_file(path, garbage) == 0, "write garbage depth file");

    out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc garbage depth output");

    n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 1, "garbage depth entry still loads");
    ASSERT(out[0].chain_depth == 0, "garbage depth ignored");
    free(out);

    unlink(path);
    TEST_PASS("malformed chain_depth handling");
    return 0;
}

static int test_persist_truncated(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "truncated.json");
    unlink(path);

    /* No closing braces: parser must not crash and must report 0 entries. */
    const char *truncated =
        "{\n  \"entries\": [\n    {\n"
        "      \"binary\": \"/usr/bin/evil\",\n"
        "      \"chain_depth\": 2";

    ASSERT(write_raw_file(path, truncated) == 0, "write truncated file");

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc truncated output");

    int n = persist_load(path, out, PERSIST_MAX_ENTRIES);
    ASSERT(n == 0, "truncated file yields 0 entries");

    free(out);
    unlink(path);
    TEST_PASS("truncated state file");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: over-cap truncation                                           */
/*  A state file with more entries than the caller's cap loads exactly  */
/*  cap entries instead of crashing or miscounting.                     */
/* ------------------------------------------------------------------ */

static int test_persist_over_cap(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "overcap.json");
    unlink(path);

    PersistEntry in[4];
    memset(in, 0, sizeof(in));
    for (int i = 0; i < 4; i++)
    {
        snprintf(in[i].binary, sizeof(in[i].binary), "/usr/bin/bin%d", i);
        snprintf(in[i].binary_sha512, sizeof(in[i].binary_sha512),
                 "sha%d", i);
    }
    ASSERT(persist_save(path, in, 4) == 0, "persist_save 4 entries");

    PersistEntry *out = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    ASSERT(out != NULL, "alloc over-cap output");

    int n = persist_load(path, out, 2);
    ASSERT(n == 2, "load with cap 2 returns exactly 2 entries");
    ASSERT(strcmp(out[0].binary, "/usr/bin/bin0") == 0, "first entry kept");
    ASSERT(strcmp(out[1].binary, "/usr/bin/bin1") == 0, "second entry kept");

    free(out);
    unlink(path);
    TEST_PASS("over-cap truncation");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  test: state file removal                                           */
/* ------------------------------------------------------------------ */

static int test_persist_remove(void)
{
    char path[PATH_MAX];
    make_test_path(path, sizeof(path), "delete_me.json");
    unlink(path);

    PersistEntry dummy[1];
    memset(dummy, 0, sizeof(dummy));
    ASSERT(persist_save(path, dummy, 0) == 0, "persist_save for remove test");
    ASSERT(unlink(path) == 0, "remove existing state file");
    ASSERT(unlink(path) != 0 && errno == ENOENT,
           "removing a missing state file reports ENOENT");

    TEST_PASS("state file removal");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    int failed = 0;

    fprintf(stdout, "=== test_persist ===\n");

    /* Per-run temp directory avoids the need for root access. */
    snprintf(g_test_dir, sizeof(g_test_dir), "/tmp/fileshield_test_%d", (int)getpid());
    if (mkdir(g_test_dir, 0700) < 0 && errno != EEXIST)
    {
        fprintf(stderr, "FAIL: could not create temp dir %s: %s\n",
                g_test_dir, strerror(errno));
        return 1;
    }

    failed |= test_persist_load_nonexistent();
    failed |= test_persist_roundtrip();
    failed |= test_persist_max_chain_depth();
    failed |= test_persist_save_empty();
    failed |= test_persist_chain_depths();
    failed |= test_persist_json_escaping();
    failed |= test_persist_malformed_depth();
    failed |= test_persist_truncated();
    failed |= test_persist_over_cap();
    failed |= test_persist_remove();

    rmdir(g_test_dir);

    if (failed)
    {
        fprintf(stdout, "FAIL\n");
        return 1;
    }
    fprintf(stdout, "PASS\n");
    return 0;
}
