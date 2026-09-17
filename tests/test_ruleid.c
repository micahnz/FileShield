/*
 * test_ruleid: canonical rule-ID hashing, collision nonces, pin IDs and
 * the prefix matcher.  Expected digests are rebuilt here from the
 * documented canonical layout and compared through sha512_buf(), so a
 * field-order or separator regression cannot hide behind the module's own
 * code path.
 */
#include <stdio.h>
#include <string.h>

#include "../src/ruleid.h"
#include "../src/sha512.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while (0)

/*
 * One representative identity with realistic digest lengths; tests copy it
 * and change one field at a time.
 */
typedef struct
{
    RuleIdentity id;
    char bin_sha[129];
    char cmd_sha[129];
    char chain_sha[PERSIST_CHAIN_MAX][129];
} Fixture;

static void fill_hex(char *out, size_t len, unsigned seed)
{
    static const char HEX[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++)
        out[i] = HEX[(seed + i) % 16];
    out[len] = '\0';
}

static void fixture_init(Fixture *f)
{
    fill_hex(f->bin_sha, 128, 1);
    fill_hex(f->cmd_sha, 128, 2);
    for (int i = 0; i < PERSIST_CHAIN_MAX; i++)
        fill_hex(f->chain_sha[i], 128, (unsigned)(3 + i));

    memset(&f->id, 0, sizeof(f->id));
    f->id.binary = "/usr/bin/doctl";
    f->id.binary_sha512 = f->bin_sha;
    f->id.target_path = "/home/alice/Documents/secrets/credentials.txt";
    f->id.cmdline_sha512 = f->cmd_sha;
    f->id.chain_depth = 1;
    f->id.chain_comm[0] = "code-oss";
    f->id.chain_sha512[0] = f->chain_sha[0];
    f->id.created_at = 1757600000L;
}

static int id_is_hex16(const char *id)
{
    if (strlen(id) != RULEID_HEX_LEN)
        return 0;
    for (int i = 0; i < RULEID_HEX_LEN; i++)
    {
        char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

static size_t buf_append(char *buf, size_t pos, const char *s)
{
    size_t len = strlen(s);

    if (pos > 0)
        buf[pos++] = '\0';
    memcpy(buf + pos, s, len);
    return pos + len;
}

/*
 * Rebuild the canonical buffer exactly as documented (NUL between
 * adjacent fields, no trailing separator) and hash it with sha512_buf().
 */
static void expected_digest(const RuleIdentity *id, const char *nonce,
                            char out[129])
{
    char buf[2048];
    char depth[16];
    char created[32];
    size_t pos = 0;

    ASSERT(snprintf(depth, sizeof(depth), "%d", id->chain_depth) > 0,
           "format depth");
    ASSERT(snprintf(created, sizeof(created), "%ld", id->created_at) > 0,
           "format created_at");

    pos = buf_append(buf, pos, id->binary);
    pos = buf_append(buf, pos, id->binary_sha512);
    pos = buf_append(buf, pos, id->target_path);
    pos = buf_append(buf, pos, id->cmdline_sha512);
    pos = buf_append(buf, pos, depth);
    for (int i = 0; i < id->chain_depth; i++)
    {
        pos = buf_append(buf, pos, id->chain_comm[i]);
        pos = buf_append(buf, pos, id->chain_sha512[i]);
    }
    pos = buf_append(buf, pos, created);
    if (nonce)
        pos = buf_append(buf, pos, nonce);

    ASSERT(sha512_buf(buf, pos, out) == 0, "expected digest computes");
}

static void test_determinism(void)
{
    Fixture f;
    char a[RULEID_HEX_LEN + 1];
    char b[RULEID_HEX_LEN + 1];

    fixture_init(&f);

    ASSERT(ruleid_make(&f.id, 0, a) == 0, "ruleid_make computes");
    ASSERT(ruleid_make(&f.id, 0, b) == 0, "ruleid_make repeats");
    ASSERT(strcmp(a, b) == 0, "same identity -> same ID");
    ASSERT(id_is_hex16(a), "ID is 16 lower-case hex chars");

    ASSERT(ruleid_make_unique(&f.id, NULL, 0, b) == 0,
           "make_unique computes");
    ASSERT(strcmp(a, b) == 0, "no collision yields the canonical ID");
}

static void test_canonical_layout(void)
{
    Fixture f;
    char got[RULEID_HEX_LEN + 1];
    char want[129];
    char nonce[32];

    fixture_init(&f);

    expected_digest(&f.id, NULL, want);
    ASSERT(ruleid_make(&f.id, 0, got) == 0, "plain ID computes");
    ASSERT(strncmp(got, want, RULEID_HEX_LEN) == 0,
           "plain ID is the first 16 hex of the canonical digest");

    expected_digest(&f.id, "n=1", want);
    ASSERT(ruleid_make(&f.id, 1, got) == 0, "nonce ID computes");
    ASSERT(strncmp(got, want, RULEID_HEX_LEN) == 0,
           "nonce field is appended and hashed");

    snprintf(nonce, sizeof(nonce), "n=%u", 4294967295u);
    expected_digest(&f.id, nonce, want);
    ASSERT(ruleid_make(&f.id, 4294967295u, got) == 0,
           "max nonce computes");
    ASSERT(strncmp(got, want, RULEID_HEX_LEN) == 0,
           "nonce is the full decimal value");
}

static void test_field_boundaries(void)
{
    Fixture f;
    RuleIdentity split;
    char a[RULEID_HEX_LEN + 1];
    char b[RULEID_HEX_LEN + 1];

    fixture_init(&f);
    f.id.binary = "abc";
    f.id.binary_sha512 = "def";

    split = f.id;
    split.binary = "ab";
    split.binary_sha512 = "cdef";

    ASSERT(ruleid_make(&f.id, 0, a) == 0, "first split computes");
    ASSERT(ruleid_make(&split, 0, b) == 0, "second split computes");
    ASSERT(strcmp(a, b) != 0, "field separators are part of the digest");
}

static void assert_field_changes_id(const RuleIdentity *changed,
                                    const char *base, const char *field)
{
    char out[RULEID_HEX_LEN + 1];
    char msg[96];

    snprintf(msg, sizeof(msg), "changing %s changes the ID", field);
    ASSERT(ruleid_make(changed, 0, out) == 0, "changed identity computes");
    ASSERT(strcmp(out, base) != 0, msg);
}

static void test_field_sensitivity(void)
{
    Fixture f;
    RuleIdentity other;
    char base[RULEID_HEX_LEN + 1];

    fixture_init(&f);
    ASSERT(ruleid_make(&f.id, 0, base) == 0, "base ID computes");

    other = f.id;
    other.binary = "/usr/bin/other";
    assert_field_changes_id(&other, base, "binary");

    other = f.id;
    other.binary_sha512 = "changed-binary-sha";
    assert_field_changes_id(&other, base, "binary SHA-512");

    other = f.id;
    other.target_path = "/tmp/other";
    assert_field_changes_id(&other, base, "target");

    other = f.id;
    other.cmdline_sha512 = "changed-cmdline-sha";
    assert_field_changes_id(&other, base, "cmdline SHA-512");

    other = f.id;
    other.chain_comm[0] = "zsh";
    assert_field_changes_id(&other, base, "chain comm");

    other = f.id;
    other.chain_sha512[0] = "changed-chain-sha";
    assert_field_changes_id(&other, base, "chain SHA-512");

    other = f.id;
    other.chain_depth = 0;
    assert_field_changes_id(&other, base, "chain depth");

    other = f.id;
    other.chain_depth = 2;
    other.chain_comm[1] = "electron";
    other.chain_sha512[1] = f.chain_sha[1];
    assert_field_changes_id(&other, base, "deeper chain");

    other = f.id;
    other.created_at = f.id.created_at + 1;
    assert_field_changes_id(&other, base, "created_at");
}

static void test_chain_depth(void)
{
    Fixture f;
    RuleIdentity deep;
    RuleIdentity shallow_tail;
    char d0[RULEID_HEX_LEN + 1];
    char d1[RULEID_HEX_LEN + 1];
    char d3[RULEID_HEX_LEN + 1];
    char tail_a[RULEID_HEX_LEN + 1];
    char tail_b[RULEID_HEX_LEN + 1];

    fixture_init(&f);

    f.id.chain_depth = 0;
    ASSERT(ruleid_make(&f.id, 0, d0) == 0, "depth 0 computes");

    f.id.chain_depth = 1;
    ASSERT(ruleid_make(&f.id, 0, d1) == 0, "depth 1 computes");
    ASSERT(strcmp(d0, d1) != 0, "depth 0 and depth 1 differ");

    deep = f.id;
    deep.chain_depth = PERSIST_CHAIN_MAX;
    deep.chain_comm[1] = "electron";
    deep.chain_sha512[1] = f.chain_sha[1];
    deep.chain_comm[2] = "zsh";
    deep.chain_sha512[2] = f.chain_sha[2];
    ASSERT(ruleid_make(&deep, 0, d3) == 0, "max depth computes");
    ASSERT(strcmp(d1, d3) != 0, "depth 1 and max depth differ");
    ASSERT(strcmp(d0, d3) != 0, "depth 0 and max depth differ");

    /*
     * Levels at or above chain_depth are ignored, so a caller can hash a
     * shallower chain while stale tail entries are still present.
     */
    shallow_tail = f.id;
    shallow_tail.chain_comm[1] = "electron";
    shallow_tail.chain_sha512[1] = f.chain_sha[1];
    ASSERT(ruleid_make(&shallow_tail, 0, tail_a) == 0, "tail A computes");
    shallow_tail.chain_comm[1] = "zsh";
    shallow_tail.chain_sha512[1] = f.chain_sha[2];
    ASSERT(ruleid_make(&shallow_tail, 0, tail_b) == 0, "tail B computes");
    ASSERT(strcmp(tail_a, tail_b) == 0, "beyond-depth levels are ignored");

    shallow_tail = f.id;
    shallow_tail.chain_depth = -1;
    ASSERT(ruleid_make(&shallow_tail, 0, tail_a) == -1,
           "negative depth fails closed");

    shallow_tail.chain_depth = PERSIST_CHAIN_MAX + 1;
    ASSERT(ruleid_make(&shallow_tail, 0, tail_a) == -1,
           "depth over max fails closed");

    shallow_tail = f.id;
    shallow_tail.chain_comm[0] = NULL;
    ASSERT(ruleid_make(&shallow_tail, 0, tail_a) == -1,
           "NULL comm below depth fails closed");

    shallow_tail = f.id;
    shallow_tail.chain_sha512[0] = NULL;
    ASSERT(ruleid_make(&shallow_tail, 0, tail_a) == -1,
           "NULL chain SHA-512 fails closed");

    shallow_tail = f.id;
    shallow_tail.chain_depth = 0;
    shallow_tail.chain_comm[0] = NULL;
    ASSERT(ruleid_make(&shallow_tail, 0, tail_a) == 0,
           "NULL tail entries at depth 0 are ignored");
}

static void test_nonce_unique(void)
{
    Fixture f;
    char base[RULEID_HEX_LEN + 1];
    char first[RULEID_HEX_LEN + 1];
    char repeat[RULEID_HEX_LEN + 1];
    char second[RULEID_HEX_LEN + 1];
    char nonce_one[RULEID_HEX_LEN + 1];
    char nonce_one_again[RULEID_HEX_LEN + 1];
    char out[RULEID_HEX_LEN + 1];
    const char *existing[2];
    const char *unrelated[1] = {"ffffffffffffffff"};

    fixture_init(&f);

    ASSERT(ruleid_make(&f.id, 0, base) == 0, "base computes");
    ASSERT(ruleid_make_unique(&f.id, NULL, 0, out) == 0,
           "empty list computes");
    ASSERT(strcmp(out, base) == 0, "empty list keeps the plain ID");

    /* First collision: the caller's list already holds the canonical ID. */
    existing[0] = base;
    ASSERT(ruleid_make_unique(&f.id, existing, 1, first) == 0,
           "first collision resolves");
    ASSERT(strcmp(first, base) != 0, "collision result differs");
    ASSERT(id_is_hex16(first), "collision result shape");

    /* Deterministic for the same list: the resolver restarts at nonce 1. */
    ASSERT(ruleid_make_unique(&f.id, existing, 1, repeat) == 0,
           "first collision resolves again");
    ASSERT(strcmp(first, repeat) == 0, "collision result is deterministic");
    ASSERT(ruleid_make(&f.id, 1, nonce_one) == 0, "nonce 1 computes");
    ASSERT(strcmp(first, nonce_one) == 0, "first retry uses nonce 1");
    ASSERT(ruleid_make(&f.id, 1, nonce_one_again) == 0,
           "nonce 1 repeats");
    ASSERT(strcmp(nonce_one, nonce_one_again) == 0,
           "nonce variant is deterministic");

    /* Second collision: both the plain ID and the first retry are taken. */
    existing[1] = first;
    ASSERT(ruleid_make_unique(&f.id, existing, 2, second) == 0,
           "second collision resolves");
    ASSERT(strcmp(second, base) != 0 && strcmp(second, first) != 0,
           "second collision result is new");

    /* An unrelated entry never forces a nonce. */
    ASSERT(ruleid_make_unique(&f.id, unrelated, 1, out) == 0,
           "unrelated entry computes");
    ASSERT(strcmp(out, base) == 0, "unrelated entry keeps the plain ID");

    /* Invalid arguments fail closed. */
    ASSERT(ruleid_make_unique(NULL, NULL, 0, out) == -1, "NULL id fails");
    ASSERT(ruleid_make_unique(&f.id, NULL, 0, NULL) == -1, "NULL out fails");
    ASSERT(ruleid_make_unique(&f.id, NULL, 1, out) == -1,
           "NULL list with count fails");
    ASSERT(ruleid_make_unique(&f.id, NULL, -1, out) == -1,
           "negative count fails");
    existing[0] = NULL;
    ASSERT(ruleid_make_unique(&f.id, existing, 1, out) == -1,
           "NULL list entry fails");
}

static void test_pin_id(void)
{
    char a[RULEID_HEX_LEN + 1];
    char b[RULEID_HEX_LEN + 1];
    char full[129];

    ASSERT(ruleid_pin("/nix/store/abc/bin/doctl", a) == 0, "pin computes");
    ASSERT(id_is_hex16(a), "pin ID shape");
    ASSERT(ruleid_pin("/nix/store/abc/bin/doctl", b) == 0, "pin repeats");
    ASSERT(strcmp(a, b) == 0, "pin ID is deterministic");
    ASSERT(ruleid_pin("/nix/store/def/bin/doctl", b) == 0,
           "second pin computes");
    ASSERT(strcmp(a, b) != 0, "different patterns differ");

    ASSERT(sha512_string("/nix/store/abc/bin/doctl", full) == 0,
           "pattern digest computes");
    ASSERT(strncmp(a, full, RULEID_HEX_LEN) == 0,
           "pin ID is the SHA-512 prefix of the pattern");

    ASSERT(ruleid_pin(NULL, a) == -1, "NULL pattern fails");
    ASSERT(ruleid_pin("pattern", NULL) == -1, "NULL out fails");
}

static void test_prefix_match(void)
{
    const char *stored = "0123456789abcdef";

    ASSERT(ruleid_prefix_match(stored, "01234567") == 1,
           "8-char prefix matches");
    ASSERT(ruleid_prefix_match(stored, "012345678") == 1,
           "9-char prefix matches");
    ASSERT(ruleid_prefix_match(stored, "0123456789abcd") == 1,
           "14-char prefix matches");
    ASSERT(ruleid_prefix_match(stored, "0123456789abcde") == 1,
           "15-char prefix matches");
    ASSERT(ruleid_prefix_match(stored, stored) == 1, "full ID matches");

    ASSERT(ruleid_prefix_match(stored, "0123456") == -1,
           "7-char prefix rejected");
    ASSERT(ruleid_prefix_match(stored, "") == -1, "empty rejected");
    ASSERT(ruleid_prefix_match(stored, "0123456789abcdef0") == -1,
           "17-char input rejected");
    ASSERT(ruleid_prefix_match(stored, "fedcba98") == 0,
           "valid non-matching prefix");
    ASSERT(ruleid_prefix_match(stored, "0123456g") == -1,
           "non-hex rejected");
    ASSERT(ruleid_prefix_match(stored, "0123456G") == -1,
           "upper-case input rejected");
    ASSERT(ruleid_prefix_match(stored, "0123 567") == -1, "space rejected");

    ASSERT(ruleid_prefix_match("0123456789abcde", "01234567") == -1,
           "short stored ID rejected");
    ASSERT(ruleid_prefix_match("0123456789ABCDEF", "01234567") == -1,
           "upper-case stored ID rejected");
    ASSERT(ruleid_prefix_match("g123456789abcdef", "01234567") == -1,
           "non-hex stored ID rejected");
    ASSERT(ruleid_prefix_match(NULL, "01234567") == -1,
           "NULL stored ID rejected");
    ASSERT(ruleid_prefix_match(stored, NULL) == -1, "NULL input rejected");
}

static void test_finder(void)
{
    const char *ids[2] = {"0123456789abcdef", "0123456789abcdee"};
    const char *unique[2] = {"0123456789abcdef", "fedcba9876543210"};
    const char *damaged[1] = {"0123456789abcde"};
    const char *with_null[1] = {NULL};
    int ambiguous = -1;

    ASSERT(ruleid_find(ids, 2, "01234567", &ambiguous) == -1,
           "ambiguous prefix fails");
    ASSERT(ambiguous == 1, "ambiguity flag is set");

    ASSERT(ruleid_find(ids, 2, "0123456789abcdef", &ambiguous) == 0,
           "full ID finds the first entry");
    ASSERT(ambiguous == 0, "full ID is unambiguous");
    ASSERT(ruleid_find(ids, 2, "0123456789abcdee", &ambiguous) == 1,
           "full ID finds the second entry");

    ASSERT(ruleid_find(ids, 2, "fedcba98", &ambiguous) == -1,
           "unknown prefix returns -1");
    ASSERT(ambiguous == 0, "unknown prefix is not ambiguous");

    ASSERT(ruleid_find(ids, 2, "0123456", &ambiguous) == -1,
           "invalid input returns -1");
    ASSERT(ambiguous == 0, "invalid input is not ambiguous");

    ASSERT(ruleid_find(unique, 2, "01234567", &ambiguous) == 0,
           "unique prefix finds its entry");
    ASSERT(ambiguous == 0, "unique prefix is unambiguous");

    ASSERT(ruleid_find(NULL, 0, "01234567", &ambiguous) == -1,
           "empty list returns -1");
    ASSERT(ruleid_find(damaged, 1, "01234567", &ambiguous) == -1,
           "damaged stored ID fails closed");
    ASSERT(ruleid_find(with_null, 1, "01234567", &ambiguous) == -1,
           "NULL stored ID fails closed");
    ASSERT(ruleid_find(ids, -1, "01234567", &ambiguous) == -1,
           "negative count fails");
    ASSERT(ruleid_find(NULL, 2, "01234567", &ambiguous) == -1,
           "NULL list fails");

    /* The ambiguity report is optional; ambiguity is still an error. */
    ASSERT(ruleid_find(ids, 2, "01234567", NULL) == -1,
           "NULL ambiguous_out is accepted");
}

static void test_invalid_identity(void)
{
    Fixture f;
    RuleIdentity bad;
    char out[RULEID_HEX_LEN + 1];

    fixture_init(&f);

    ASSERT(ruleid_make(NULL, 0, out) == -1, "NULL identity fails");
    ASSERT(ruleid_make(&f.id, 0, NULL) == -1, "NULL output fails");

    bad = f.id;
    bad.binary = NULL;
    ASSERT(ruleid_make(&bad, 0, out) == -1, "NULL binary fails");

    bad = f.id;
    bad.binary_sha512 = NULL;
    ASSERT(ruleid_make(&bad, 0, out) == -1, "NULL binary SHA-512 fails");

    bad = f.id;
    bad.target_path = NULL;
    ASSERT(ruleid_make(&bad, 0, out) == -1, "NULL target fails");

    bad = f.id;
    bad.cmdline_sha512 = NULL;
    ASSERT(ruleid_make(&bad, 0, out) == -1, "NULL cmdline SHA-512 fails");
}

static void test_output_shape(void)
{
    Fixture f;
    char out[RULEID_HEX_LEN + 1];

    fixture_init(&f);

    for (unsigned nonce = 0; nonce < 4; nonce++)
    {
        ASSERT(ruleid_make(&f.id, nonce, out) == 0, "make computes");
        ASSERT(id_is_hex16(out), "make output is 16 lower-case hex");
    }
    ASSERT(ruleid_make_unique(&f.id, NULL, 0, out) == 0,
           "make_unique computes");
    ASSERT(id_is_hex16(out), "make_unique output shape");
    ASSERT(ruleid_pin("some/binary", out) == 0, "pin computes");
    ASSERT(id_is_hex16(out), "pin output shape");
}

int main(void)
{
    printf("=== test_ruleid ===\n");
    test_determinism();
    test_canonical_layout();
    test_field_boundaries();
    test_field_sensitivity();
    test_chain_depth();
    test_nonce_unique();
    test_pin_id();
    test_prefix_match();
    test_finder();
    test_invalid_identity();
    test_output_shape();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
