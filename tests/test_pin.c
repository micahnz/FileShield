#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/pin.h"

/* All tests run unprivileged against a per-pid temp directory. */
#define TEST_FILE_BUF (512 * 1024)
#define TPATH (PATH_MAX + 64) /* a state file path built from g_test_dir */
#define TTBUF (PATH_MAX + 96) /* path + ".tmp.<pid>"                    */

#define SHA_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SHA_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SHA_BAD \
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" \
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"

static char g_test_dir[256];
static char g_file_buf[TEST_FILE_BUF];

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

static void make_test_path(char *out, size_t sz, const char *name)
{
    snprintf(out, sz, "%s/%s", g_test_dir, name);
}

static void make_tmp_path(char *out, size_t sz, const char *path)
{
    snprintf(out, sz, "%s.tmp.%d", path, (int)getpid());
}

static int write_raw_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");

    if (!fp)
        return -1;
    fputs(content, fp);
    if (ferror(fp))
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

/* Read a whole state file into g_file_buf (NUL-terminated). */
static long read_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    size_t n;

    if (!fp)
        return -1;
    n = fread(g_file_buf, 1, sizeof(g_file_buf) - 1, fp);
    fclose(fp);
    g_file_buf[n] = '\0';
    return (long)n;
}

/* Point the module at 'path' and start from a missing file (clean). */
static int reset_pins(const char *path)
{
    unlink(path);
    pin_set_state_file(path);
    return pin_load(path);
}

static void build_valid_json(char *out, size_t sz, const char *pattern,
                             const char *sha, long updated_at)
{
    snprintf(out, sz,
             "{\n"
             "  \"pins\": [\n"
             "    {\n"
             "      \"pattern\": \"%s\",\n"
             "      \"sha512\": \"%s\",\n"
             "      \"updated_at\": %ld\n"
             "    }\n"
             "  ]\n"
             "}\n",
             pattern, sha, updated_at);
}

static int expect_damaged(const char *path, const char *content,
                          const char *what)
{
    if (write_raw_file(path, content) != 0)
    {
        fprintf(stderr, "FAIL: %s: cannot write test file\n", what);
        return 1;
    }
    if (pin_load(path) != -1)
    {
        fprintf(stderr, "FAIL: %s: pin_load did not fail\n", what);
        return 1;
    }
    if (pin_damaged() != 1)
    {
        fprintf(stderr, "FAIL: %s: pin_damaged not set\n", what);
        return 1;
    }
    return 0;
}

/* A PIN_MAX-entry table; the killed entry gets updated_at 1 or all
 * entries share one timestamp (tie-break case). */
static int write_full_pin_file(const char *path, int victim, int all_equal)
{
    FILE *fp = fopen(path, "w");
    int i;

    if (!fp)
        return -1;
    fputs("{\n  \"pins\": [\n", fp);
    for (i = 0; i < PIN_MAX; i++)
    {
        long updated = all_equal
                           ? 1000L
                           : ((i == victim) ? 1L : 100000L + i);

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"pattern\": \"/usr/bin/gen-%03d\",\n", i);
        fprintf(fp, "      \"sha512\": \"" SHA_A "\",\n");
        fprintf(fp, "      \"updated_at\": %ld\n", updated);
        fprintf(fp, "    }%s\n", i + 1 < PIN_MAX ? "," : "");
    }
    fputs("  ]\n}\n", fp);
    if (ferror(fp))
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int write_over_cap_file(const char *path, int entries)
{
    FILE *fp = fopen(path, "w");
    int i;

    if (!fp)
        return -1;
    fputs("{\n  \"pins\": [\n", fp);
    for (i = 0; i < entries; i++)
    {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"pattern\": \"/usr/bin/over-%03d\",\n", i);
        fprintf(fp, "      \"sha512\": \"" SHA_A "\",\n");
        fprintf(fp, "      \"updated_at\": %d\n", 1000 + i);
        fprintf(fp, "    }%s\n", i + 1 < entries ? "," : "");
    }
    fputs("  ]\n}\n", fp);
    if (ferror(fp))
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  a pattern with quotes/backslashes survives the JSON escaping      */
/* ------------------------------------------------------------------ */

static int test_pattern_escaping(void)
{
    char path[TPATH];
    char old[129];
    const char *pattern = "/usr/bin/weird\"name\\x";

    make_test_path(path, sizeof(path), "escape.json");
    ASSERT(reset_pins(path) == 0, "reset");
    ASSERT(pin_store(pattern, SHA_A) == 0, "store an escaped pattern");
    ASSERT(read_file(path) > 0, "escaped state file readable");
    ASSERT(strstr(g_file_buf, "weird\\\"name\\\\x") != NULL,
           "state file escapes the quote and backslash");
    ASSERT(pin_load(path) == 0, "reload escaped state");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "escaped pattern roundtrips");

    unlink(path);
    TEST_PASS("pattern escaping roundtrip");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  missing file = clean, empty table (normal first use)              */
/* ------------------------------------------------------------------ */

static int test_missing_file(void)
{
    char path[TPATH];
    char old[129];

    make_test_path(path, sizeof(path), "missing.json");
    pin_set_state_file(path);
    unlink(path);

    ASSERT(pin_load(path) == 0, "missing file loads as empty");
    ASSERT(pin_damaged() == 0, "missing file is not damaged");
    ASSERT(pin_check("/usr/bin/git", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "empty table reports first use");
    ASSERT(old[0] == '\0', "old_out cleared on first use");

    TEST_PASS("missing file = clean empty table");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  store -> immediate file -> fresh load -> check roundtrip          */
/* ------------------------------------------------------------------ */

static int test_store_roundtrip(void)
{
    char path[TPATH];
    char tmp[TTBUF];
    char old[129];
    struct stat st;
    const char *pattern = "/tmp/.mount_*/openchamber";

    make_test_path(path, sizeof(path), "roundtrip.json");
    ASSERT(reset_pins(path) == 0, "reset to a missing state file");
    ASSERT(pin_store(pattern, SHA_A) == 0, "pin_store succeeds");

    ASSERT(read_file(path) > 0, "state file readable right after store");
    ASSERT(strstr(g_file_buf, "\"pins\"") != NULL, "state has a pins array");
    ASSERT(strstr(g_file_buf, pattern) != NULL, "state has the pattern");
    ASSERT(strstr(g_file_buf, SHA_A) != NULL, "state has the digest");
    ASSERT(strstr(g_file_buf, "\"updated_at\":") != NULL,
           "state has updated_at");

    ASSERT(stat(path, &st) == 0, "stat the state file");
    ASSERT((st.st_mode & 0777) == 0600, "state file mode is 0600");

    make_tmp_path(tmp, sizeof(tmp), path);
    ASSERT(access(tmp, F_OK) != 0, "no temp file left behind");

    /* A fresh load sees the same pin; NULL uses the pin_set_state_file
     * override. */
    ASSERT(pin_load(NULL) == 0, "fresh pin_load of the state file");
    ASSERT(pin_damaged() == 0, "fresh load is clean");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "roundtrip match");
    ASSERT(old[0] == '\0', "old_out cleared on match");

    ASSERT(pin_check(pattern, SHA_B, old) == PIN_CHECK_CHANGED,
           "changed digest reports 2");
    ASSERT(strcmp(old, SHA_A) == 0, "old_out holds the stored digest");
    ASSERT(old[128] == '\0', "old_out is NUL-terminated");

    ASSERT(pin_check("/usr/bin/other", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "unknown pattern is first use");

    unlink(path);
    TEST_PASS("store/roundtrip/check");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  check contract: invalid arguments and side-effect freedom         */
/* ------------------------------------------------------------------ */

static int test_check_contract(void)
{
    char path[TPATH];
    char old[129];
    char big[PATH_MAX + 16];

    make_test_path(path, sizeof(path), "checkargs.json");
    ASSERT(reset_pins(path) == 0, "reset");

    ASSERT(pin_check(NULL, SHA_A, old) == PIN_CHECK_DAMAGED,
           "NULL pattern reports damaged/cannot-check");
    ASSERT(pin_check("/usr/bin/git", NULL, old) == PIN_CHECK_DAMAGED,
           "NULL sha reports damaged/cannot-check");
    ASSERT(pin_check("/usr/bin/git", "abc", old) == PIN_CHECK_DAMAGED,
           "short sha reports damaged/cannot-check");
    ASSERT(pin_check("", SHA_A, old) == PIN_CHECK_DAMAGED,
           "empty pattern reports damaged/cannot-check");
    ASSERT(old[0] == '\0', "old_out cleared for invalid arguments");

    /* Side-effect free: a valid store/check afterwards still works. */
    ASSERT(pin_store("/usr/bin/git", SHA_A) == 0, "store after bad checks");
    ASSERT(pin_check("/usr/bin/git", SHA_A, old) == PIN_CHECK_MATCH,
           "valid check unaffected by the invalid calls");

    ASSERT(pin_store(NULL, SHA_A) == -1, "store NULL pattern refused");
    ASSERT(pin_store("/usr/bin/git", "xyz") == -1, "store short sha refused");
    memset(big, 'a', sizeof(big) - 1);
    big[0] = '/';
    big[sizeof(big) - 1] = '\0';
    ASSERT(pin_store(big, SHA_A) == -1, "store overlong pattern refused");

    unlink(path);
    TEST_PASS("check argument/damage contract");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  damaged file: fail closed, never a silent reset, store refuses    */
/* ------------------------------------------------------------------ */

static int test_damaged_semantics(void)
{
    char path[TPATH];
    char json[PATH_MAX + 512];
    char old[129];
    long stored;
    const char *pattern = "/usr/bin/damaged-pin";

    make_test_path(path, sizeof(path), "damaged_semantics.json");
    ASSERT(reset_pins(path) == 0, "reset");
    ASSERT(pin_store(pattern, SHA_A) == 0, "store a pin to damage later");
    ASSERT(pin_load(path) == 0, "clean load");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "pin matches before damage");

    /* Damage the file: the loaded table must not silently reset. */
    ASSERT(write_raw_file(path, "garbage, not json\n") == 0,
           "corrupt the file");
    ASSERT(pin_load(path) == -1, "damaged file returns -1");
    ASSERT(pin_damaged() == 1, "damage flag set");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_DAMAGED,
           "damaged table refuses to check");

    /* pin_store must not overwrite the damaged file. */
    stored = read_file(path);
    ASSERT(stored > 0, "damaged file readable");
    ASSERT(pin_store("/usr/bin/new", SHA_B) == -1,
           "store refuses while damaged");
    ASSERT(read_file(path) == stored &&
           strcmp(g_file_buf, "garbage, not json\n") == 0,
           "damaged file left untouched");

    /* Repairing and reloading clears the damage. */
    build_valid_json(json, sizeof(json), pattern, SHA_A, 42);
    ASSERT(write_raw_file(path, json) == 0, "repair the file");
    ASSERT(pin_load(path) == 0, "repaired file loads");
    ASSERT(pin_damaged() == 0, "damage cleared");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "repaired pin matches again");

    unlink(path);
    TEST_PASS("damaged file fail-closed semantics");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  malformed JSON / entries mark the WHOLE file damaged              */
/* ------------------------------------------------------------------ */

struct bad_case
{
    const char *what;
    const char *content;
};

static int test_malformed_files(void)
{
    char path[TPATH];
    char old[129];
    int i;

    static const struct bad_case cases[] = {
        {"garbage text", "not json at all\n"},
        {"wrong top-level array",
         "{\n  \"entries\": [\n  ]\n}\n"},
        {"missing sha512",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"updated_at\": 5\n    }\n  ]\n}\n"},
        {"missing pattern",
         "{\n  \"pins\": [\n    {\n      \"sha512\": \"" SHA_A "\",\n"
         "      \"updated_at\": 5\n    }\n  ]\n}\n"},
        {"missing updated_at",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\"\n    }\n  ]\n}\n"},
        {"relative pattern",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"relative/path\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"empty pattern",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"short sha512",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"abc123\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"non-hex sha512",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_BAD "\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"string updated_at",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": \"5\"\n"
         "    }\n  ]\n}\n"},
        {"negative updated_at",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": -5\n"
         "    }\n  ]\n}\n"},
        {"junk after updated_at",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5x\n"
         "    }\n  ]\n}\n"},
        {"numeric pattern",
         "{\n  \"pins\": [\n    {\n      \"pattern\": 5,\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"numeric sha512",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": 5,\n      \"updated_at\": 5\n"
         "    }\n  ]\n}\n"},
        {"truncated file",
         "{\n  \"pins\": [\n    {\n      \"pattern\": \"/usr/bin/x\",\n"
         "      \"sha512\": \"" SHA_A "\",\n      \"updated_at\": 5\n"},
        {"compact one-line entry",
         "{\"pins\": [{\"pattern\": \"/x\", \"sha512\": \"" SHA_A "\", "
         "\"updated_at\": 5}]}\n"},
        {"content after the outer object",
         "{\n  \"pins\": [\n  ]\n}\n\"junk\": 1\n"},
    };

    make_test_path(path, sizeof(path), "malformed.json");
    pin_set_state_file(path);

    for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++)
    {
        if (expect_damaged(path, cases[i].content, cases[i].what) != 0)
            return 1;
    }

    /* Over-cap and at-cap boundary. */
    ASSERT(write_over_cap_file(path, PIN_MAX + 1) == 0,
           "write over-cap file");
    ASSERT(pin_load(path) == -1, "over-cap file is damaged");
    ASSERT(pin_damaged() == 1, "over-cap sets damaged");

    ASSERT(write_over_cap_file(path, PIN_MAX) == 0, "write at-cap file");
    ASSERT(pin_load(path) == 0, "at-cap file loads");
    ASSERT(pin_damaged() == 0, "at-cap file is clean");
    ASSERT(pin_check("/usr/bin/over-000", SHA_A, old) == PIN_CHECK_MATCH,
           "at-cap first entry loaded");
    ASSERT(pin_check("/usr/bin/over-042", SHA_A, old) == PIN_CHECK_MATCH,
           "at-cap middle entry loaded");

    unlink(path);
    TEST_PASS("malformed files mark the whole file damaged");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  unknown keys and comments are tolerated                           */
/* ------------------------------------------------------------------ */

static int test_unknown_keys_ignored(void)
{
    char path[TPATH];
    char old[129];
    static const char content[] =
        "{\n"
        "  # a comment before the table\n"
        "  \"version\": 2,\n"
        "  \"pins\": [\n"
        "    # a comment inside the array\n"
        "    {\n"
        "      \"pattern\": \"/usr/bin/future\",\n"
        "      \"sha512\": \"" SHA_A "\",\n"
        "      \"updated_at\": 1234,\n"
        "      \"algorithm\": \"sha512\",\n"
        "      \"note_count\": 7\n"
        "    }\n"
        "  ]\n"
        "}\n";

    make_test_path(path, sizeof(path), "unknown.json");
    pin_set_state_file(path);

    ASSERT(write_raw_file(path, content) == 0, "write file with extras");
    ASSERT(pin_load(path) == 0, "unknown keys load cleanly");
    ASSERT(pin_damaged() == 0, "unknown keys do not damage");
    ASSERT(pin_check("/usr/bin/future", SHA_A, old) == PIN_CHECK_MATCH,
           "pin with unknown siblings matches");

    unlink(path);
    TEST_PASS("unknown keys/comments ignored");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  refresh updates the digest and updated_at                         */
/* ------------------------------------------------------------------ */

static int test_updated_at_refresh(void)
{
    char path[TPATH];
    char json[PATH_MAX + 512];
    char old[129];
    char *u;
    long before = 1000;
    long after;
    const char *pattern = "/usr/bin/refresh";

    make_test_path(path, sizeof(path), "refresh.json");
    ASSERT(reset_pins(path) == 0, "reset");
    build_valid_json(json, sizeof(json), pattern, SHA_A, before);
    ASSERT(write_raw_file(path, json) == 0, "write initial pin");
    ASSERT(pin_load(path) == 0, "load initial pin");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_MATCH,
           "initial digest matches");

    ASSERT(pin_store(pattern, SHA_B) == 0, "refresh with the new digest");
    ASSERT(pin_check(pattern, SHA_B, old) == PIN_CHECK_MATCH,
           "new digest matches");
    ASSERT(pin_check(pattern, SHA_A, old) == PIN_CHECK_CHANGED,
           "old digest reports changed");
    ASSERT(strcmp(old, SHA_B) == 0, "old_out holds the refreshed digest");

    ASSERT(read_file(path) > 0, "refreshed file readable");
    u = strstr(g_file_buf, "\"updated_at\":");
    ASSERT(u != NULL, "updated_at present after refresh");
    after = strtol(u + strlen("\"updated_at\":"), NULL, 10);
    ASSERT(after > before, "updated_at refreshed");
    ASSERT(strstr(g_file_buf, SHA_B) != NULL, "file holds the new digest");
    ASSERT(strstr(g_file_buf, SHA_A) == NULL, "file no longer holds the old");

    unlink(path);
    TEST_PASS("updated_at refresh on change");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  cap: PIN_MAX + 1 stores evict the oldest insertion                */
/* ------------------------------------------------------------------ */

static int test_cap_eviction_by_store(void)
{
    char path[TPATH];
    char pat[64];
    char old[129];
    char *p;
    int i;
    int count = 0;

    make_test_path(path, sizeof(path), "evict_store.json");
    ASSERT(reset_pins(path) == 0, "reset");

    for (i = 0; i <= PIN_MAX; i++) /* PIN_MAX + 1 inserts */
    {
        snprintf(pat, sizeof(pat), "/usr/bin/evict-%03d", i);
        ASSERT(pin_store(pat, SHA_A) == 0, "bulk pin_store");
    }

    ASSERT(pin_check("/usr/bin/evict-000", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "oldest inserted entry was evicted");
    snprintf(pat, sizeof(pat), "/usr/bin/evict-%03d", PIN_MAX);
    ASSERT(pin_check(pat, SHA_A, old) == PIN_CHECK_MATCH,
           "newest entry survives");

    ASSERT(read_file(path) > 0, "state file readable");
    for (p = strstr(g_file_buf, "\"pattern\":"); p != NULL;
         p = strstr(p + 1, "\"pattern\":"))
        count++;
    ASSERT(count == PIN_MAX, "file never exceeds PIN_MAX entries");

    unlink(path);
    TEST_PASS("cap eviction on insert");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  eviction uses the smallest updated_at, not file order             */
/* ------------------------------------------------------------------ */

static int test_eviction_smallest_updated_at(void)
{
    char path[TPATH];
    char old[129];

    make_test_path(path, sizeof(path), "evict_smallest.json");
    pin_set_state_file(path);
    unlink(path);

    ASSERT(write_full_pin_file(path, 7, 0) == 0, "write full table");
    ASSERT(pin_load(path) == 0, "load full table");
    ASSERT(pin_check("/usr/bin/gen-007", SHA_A, old) == PIN_CHECK_MATCH,
           "victim present before store");
    ASSERT(pin_store("/usr/bin/gen-new", SHA_A) == 0, "insert beyond the cap");

    ASSERT(pin_check("/usr/bin/gen-007", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "smallest updated_at evicted");
    ASSERT(pin_check("/usr/bin/gen-000", SHA_A, old) == PIN_CHECK_MATCH,
           "other entries survive");
    ASSERT(pin_check("/usr/bin/gen-new", SHA_A, old) == PIN_CHECK_MATCH,
           "new entry stored");

    unlink(path);
    TEST_PASS("eviction keeps the largest updated_at");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  eviction tie-break: oldest store order goes first                 */
/* ------------------------------------------------------------------ */

static int test_eviction_tie_break(void)
{
    char path[TPATH];
    char old[129];

    make_test_path(path, sizeof(path), "evict_tie.json");
    pin_set_state_file(path);
    unlink(path);

    ASSERT(write_full_pin_file(path, -1, 1) == 0, "write tied table");
    ASSERT(pin_load(path) == 0, "load tied table");
    ASSERT(pin_store("/usr/bin/gen-new", SHA_A) == 0, "insert beyond the cap");

    ASSERT(pin_check("/usr/bin/gen-000", SHA_A, old) == PIN_CHECK_FIRST_USE,
           "first stored entry evicted on an updated_at tie");
    ASSERT(pin_check("/usr/bin/gen-255", SHA_A, old) == PIN_CHECK_MATCH,
           "last stored entry survives");
    ASSERT(pin_check("/usr/bin/gen-new", SHA_A, old) == PIN_CHECK_MATCH,
           "new entry stored");

    unlink(path);
    TEST_PASS("eviction tie-break by store order");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  a failed write keeps the in-memory entry (LOG_WARNING only)       */
/* ------------------------------------------------------------------ */

static int test_write_failure_keeps_memory(void)
{
    char path[TPATH];
    char blocker[TPATH];
    char bad[TTBUF];
    char old[129];

    make_test_path(path, sizeof(path), "writefail.json");
    ASSERT(reset_pins(path) == 0, "reset");

    /* A regular file where the parent directory should be: the atomic
     * write cannot even create its temp file. */
    make_test_path(blocker, sizeof(blocker), "writefail_blocker");
    unlink(blocker);
    ASSERT(write_raw_file(blocker, "not a directory") == 0,
           "create blocker file");
    snprintf(bad, sizeof(bad), "%s/state.json", blocker);
    pin_set_state_file(bad);

    ASSERT(pin_store("/usr/bin/kept", SHA_A) == -1,
           "store fails when the path is un-writable");
    ASSERT(pin_check("/usr/bin/kept", SHA_A, old) == PIN_CHECK_MATCH,
           "entry kept in memory after write failure");
    ASSERT(access(bad, F_OK) != 0, "no state file left after failure");

    /* An open error other than ENOENT is damage, not first use. */
    ASSERT(pin_load(bad) == -1, "unreadable path is damaged, not missing");
    ASSERT(pin_damaged() == 1, "unreadable path sets damaged");

    pin_set_state_file(path);
    unlink(blocker);
    unlink(path);
    TEST_PASS("write failure keeps the in-memory entry");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  unwritable parent directory (skipped for root, which bypasses it) */
/* ------------------------------------------------------------------ */

static int test_unwritable_dir_non_root(void)
{
    char dir[TPATH];
    char path[TTBUF];
    char old[129];

    if (geteuid() == 0)
    {
        TEST_PASS("unwritable-dir store failure skipped as root");
        return 0;
    }

    make_test_path(dir, sizeof(dir), "ro_dir");
    rmdir(dir);
    ASSERT(mkdir(dir, 0555) == 0, "create read-only dir");
    snprintf(path, sizeof(path), "%s/sub/state.json", dir);
    pin_set_state_file(path);

    ASSERT(pin_load(path) == 0, "missing nested file loads clean");
    ASSERT(pin_store("/usr/bin/ro", SHA_A) == -1,
           "store inside an unwritable dir fails");
    ASSERT(pin_check("/usr/bin/ro", SHA_A, old) == PIN_CHECK_MATCH,
           "entry kept in memory");

    ASSERT(chmod(dir, 0700) == 0, "restore dir mode");
    rmdir(dir);
    TEST_PASS("unwritable directory store failure");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int main(void)
{
    int failed = 0;

    fprintf(stdout, "=== test_pin ===\n");

    /* Per-run temp directory avoids the need for root access. */
    snprintf(g_test_dir, sizeof(g_test_dir), "/tmp/fileshield_test_pin_%d",
             (int)getpid());
    if (mkdir(g_test_dir, 0700) < 0 && errno != EEXIST)
    {
        fprintf(stderr, "FAIL: could not create temp dir %s: %s\n",
                g_test_dir, strerror(errno));
        return 1;
    }

    failed |= test_missing_file();
    failed |= test_store_roundtrip();
    failed |= test_pattern_escaping();
    failed |= test_check_contract();
    failed |= test_damaged_semantics();
    failed |= test_malformed_files();
    failed |= test_unknown_keys_ignored();
    failed |= test_updated_at_refresh();
    failed |= test_cap_eviction_by_store();
    failed |= test_eviction_smallest_updated_at();
    failed |= test_eviction_tie_break();
    failed |= test_write_failure_keeps_memory();
    failed |= test_unwritable_dir_non_root();

    rmdir(g_test_dir);

    if (failed)
    {
        fprintf(stdout, "FAIL\n");
        return 1;
    }
    fprintf(stdout, "PASS\n");
    return 0;
}
