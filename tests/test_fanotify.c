/*
 * test_fanotify: mark mask, bounded event queue + fail-closed saturation
 * handling.
 *
 * Part 0 (runs unprivileged): the mark mask must be free of FID-requiring
 * directory-entry events.  Regression guard for EINVAL on every directory
 * mark when FAN_CREATE/FAN_MOVED_TO were added to this fd-based group.
 *
 * Part 1 (runs unprivileged): the deferred-event boundary.  A pipe stands
 * in for the fanotify group fd — fanotify_respond() only writes a
 * struct fanotify_response to it, so the flush contract (one FAN_DENY
 * response per deferred event, deferred fds closed) is verifiable
 * without a real fanotify group.
 *
 * Part 2 (needs CAP_SYS_ADMIN; skips otherwise): a real kernel fanotify
 * group created WITHOUT FAN_UNLIMITED_QUEUE must report FAN_Q_OVERFLOW
 * once the bounded queue saturates.  This uses notification events only:
 * permission-event saturation cannot be exercised without deliberately
 * blocking a listener, and note that a *bounded* permission queue is
 * fail-open (the kernel drops the event and allows the access), which is
 * why the daemon itself uses FAN_UNLIMITED_QUEUE.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/fanotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/fanotify.h"
#include "../src/config.h"
#include "../src/inode.h"
#include "../src/notify.h"
#include "../src/pin.h"
#include "../src/session.h"
#include "../src/sha512.h"
#include "../src/utils.h"

/* Globals referenced by fanotify.c (normally defined in main.c). */
volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;
volatile sig_atomic_t g_fatal = 0;

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

/*
 * Convenience wrappers for the matcher seams: fingerprint the command
 * line the way an event would, then run the matcher.  The seams take a
 * precomputed fingerprint so the benchmark can measure matcher cost
 * without the hash.
 */
static int test_match_allow(const char *binary, const char *sha,
                            const char *target, const char *cmdline)
{
    char fp[129];
    if (!cmdline || sha512_string(cmdline, fp) != 0)
        return 0;
    return fanotify_test_dyn_allow_match(binary, sha, target, fp);
}

static int test_match_deny(const char *binary, const char *sha,
                           const char *target, const char *cmdline)
{
    char fp[129];
    if (!cmdline || sha512_string(cmdline, fp) != 0)
        return 0;
    return fanotify_test_dyn_deny_match(binary, sha, target, fp);
}

/*
 * Part 0: the mark mask must not contain FID-requiring directory-entry
 * events.  Adding FAN_CREATE/FAN_MOVED_TO to a group initialized without
 * FAN_REPORT_FID makes fanotify_mark() fail with EINVAL, which breaks
 * every directory mark (fanotify_mark(2), ERRORS).
 */
static void test_mark_mask_rejects_fid_events(void) {
    const unsigned int mask = fanotify_mark_mask();
    const unsigned int fid_only =
        FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO |
        FAN_ATTRIB | FAN_DELETE_SELF;

    ASSERT((mask & FAN_OPEN_PERM) != 0, "mark mask includes FAN_OPEN_PERM");
    ASSERT((mask & FAN_EVENT_ON_CHILD) != 0,
           "mark mask includes FAN_EVENT_ON_CHILD");
    ASSERT((mask & fid_only) == 0,
           "mark mask contains no FID-requiring dirent events");
}

/*
 * Part 0b: a configured path that does not exist is skipped (returns 1)
 * rather than treated as a fatal mark failure, and skipping registers no
 * mark state.  The default config lists many secrets paths that may not
 * exist on a given machine; those must not crash the daemon.
 */
static void test_missing_path_is_skipped(void) {
    ASSERT(fanotify_any_mark_active() == 0, "no mark state before skip test");
    int rc = fanotify_add_mark(-1, "/nonexistent/fileshield/missing-secret");
    ASSERT(rc == 1, "missing configured path is skipped (rc 1)");
    ASSERT(fanotify_any_mark_active() == 0, "skipped path adds no mark state");

    /* An existing path with an unusable group fd is a real failure. */
    rc = fanotify_add_mark(-1, "/");
    ASSERT(rc == -1, "existing path mark failure is fatal (rc -1)");
    ASSERT(fanotify_any_mark_active() == 0, "failed mark adds no state");
}

/*
 * Part 0c: glob entries protect through the fast-path verdict.
 * fanotify_test_fastpath_allows() is the same classification the mount
 * fast path uses: 0 means "protected, needs a decision", 1 means
 * "mount-mark noise, allow instantly".
 */
static void test_glob_protected_verdict(void) {
    static Config cfg;
    const char *base = "/home/u/.cloudflared";

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path),
             "%s", "/home/u/.cloudflared/*.json");
    cfg.protected[0].is_glob = 1;
    cfg.protected[0].base_len = (int)strlen(base);
    snprintf(cfg.protected[1].path, sizeof(cfg.protected[1].path),
             "%s", "/home/u/.cloudflared/**/*.json");
    cfg.protected[1].is_glob = 1;
    cfg.protected[1].base_len = (int)strlen(base);
    snprintf(cfg.protected[2].path, sizeof(cfg.protected[2].path),
             "%s", "/home/u/.ssh");
    cfg.protected[2].is_glob = 0;
    cfg.protected[2].base_len = (int)strlen(cfg.protected[2].path);
    cfg.protected_count = 3;

    Config *saved = g_config;
    g_config = &cfg;
    inode_set_clear();

    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflared/abc.json") == 0,
           "glob matches a direct child");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflared/a/b/c.json") == 0,
           "globstar matches nested files");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflared/cert.pem") == 1,
           "non-matching file under the base is mount-mark noise");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflared/sub/abc.txt") == 1,
           "non-matching nested file is mount-mark noise");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.cloudflaredX/abc.json") == 1,
           "glob base boundary is respected");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/other/abc.json") == 1,
           "path outside the base is not protected");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_rsa") == 0,
           "exact entry still protects its subtree");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.sshd/x") == 1,
           "exact entry boundary unchanged");

    g_config = saved;
    inode_set_clear();
}

/*
 * Part 0d: a glob entry whose base does not exist is skipped like a
 * missing exact path (rc 1, no mark state), keeping startup's skipped
 * accounting and the mount-mark fallback intact.
 */
static void test_glob_missing_base_is_skipped(void) {
    ProtectedPath pp;
    memset(&pp, 0, sizeof(pp));
    snprintf(pp.path, sizeof(pp.path),
             "/nonexistent/fileshield/globbase_%d/*.json", (int)getpid());
    pp.is_glob = 1;
    pp.base_len = (int)(strlen(pp.path) - strlen("/*.json"));

    int rc = fanotify_add_protected(-1, &pp);
    ASSERT(rc == 1, "missing glob base is skipped (rc 1)");
    ASSERT(fanotify_any_mark_active() == 0, "missing glob base adds no mark state");

    ProtectedPath exact;
    memset(&exact, 0, sizeof(exact));
    snprintf(exact.path, sizeof(exact.path),
             "/nonexistent/fileshield/missing-exact_%d", (int)getpid());
    exact.base_len = (int)strlen(exact.path);

    rc = fanotify_add_protected(-1, &exact);
    ASSERT(rc == 1, "missing exact entry is skipped (rc 1)");
    ASSERT(fanotify_any_mark_active() == 0, "missing exact entry adds no state");
}

/*
 * Part 0e: the kernel reports unlinked-but-open fds as
 * "/path (deleted)"; resolve_fd_path() strips the marker so a deleted
 * protected file still resolves to (and matches) its real path.
 */
static void test_deleted_suffix_stripped(void) {
    char dir[] = "/tmp/fileshield_del_XXXXXX";
    char path[PATH_MAX];
    char link[64];
    char raw[PATH_MAX];
    char resolved[PATH_MAX];

    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp for deleted-suffix test: %s\n",
                strerror(errno));
        failures++;
        return;
    }

    snprintf(path, sizeof(path), "%s/secret", dir);
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    ASSERT(fd >= 0, "create file for deleted-suffix test");
    if (fd < 0) {
        rmdir(dir);
        return;
    }
    ASSERT(unlink(path) == 0, "unlink the open file");

    /* The kernel must report the marker, or the strip is untested. */
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, raw, sizeof(raw) - 1);
    ASSERT(n > 0, "readlink the deleted fd");
    if (n > 0) {
        raw[n] = '\0';
        ASSERT(strlen(raw) >= sizeof(" (deleted)") - 1 &&
               strcmp(raw + strlen(raw) - (sizeof(" (deleted)") - 1),
                      " (deleted)") == 0,
               "kernel reports the deleted marker");
    }

    ASSERT(fanotify_test_resolve_path(fd, resolved, sizeof(resolved)) == 0,
           "resolve the deleted fd path");
    ASSERT(strstr(resolved, " (deleted)") == NULL, "deleted marker stripped");
    ASSERT(strstr(resolved, "secret") != NULL, "real path preserved");

    close(fd);
    rmdir(dir);
}

/*
 * Part 0f: '!' exclusions are deny-wins and order-independent.  The
 * exclusion is listed before the positive to prove that config order
 * does not matter.
 */
static void test_exclusions_deny_wins(void) {
    static Config cfg;
    const char *base = "/home/u/.ssh";

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path),
             "%s", "/home/u/.ssh/*.pub");
    cfg.protected[0].is_glob = 1;
    cfg.protected[0].is_exclude = 1;
    cfg.protected[0].base_len = (int)strlen(base);
    snprintf(cfg.protected[1].path, sizeof(cfg.protected[1].path),
             "%s", base);
    cfg.protected[1].is_glob = 0;
    cfg.protected[1].base_len = (int)strlen(base);
    cfg.protected_count = 2;
    cfg.exclude_count = 1;

    Config *saved = g_config;
    g_config = &cfg;
    inode_set_clear();

    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_ed25519") == 0,
           "private key stays protected");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_ed25519.pub") == 1,
           "excluded public key is allowed as mount-mark noise");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/sub/id_ed25519.pub") == 0,
           "single '*' exclusion does not cross segments");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_ed25519.pub.bak") == 0,
           "exclusion requires the full file-name match");

    /* A '**' exclusion reaches nested files and zero segments. */
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path),
             "%s", "/home/u/.ssh/**/*.pub");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/id_ed25519.pub") == 1,
           "globstar exclusion matches zero segments");
    ASSERT(fanotify_test_fastpath_allows(0, 0, "/home/u/.ssh/sub/id_ed25519.pub") == 1,
           "globstar exclusion matches nested files");

    g_config = saved;
    inode_set_clear();
}

/*
 * Part 0g: an exclusion entry is never marked: fanotify_add_protected()
 * returns 0 without touching the mark table or the inode set.
 */
static void test_exclusion_is_not_marked(void) {
    ProtectedPath pp;
    memset(&pp, 0, sizeof(pp));
    snprintf(pp.path, sizeof(pp.path), "%s", "/home/u/.ssh/*.pub");
    pp.is_glob = 1;
    pp.is_exclude = 1;
    pp.base_len = (int)strlen("/home/u/.ssh");

    int rc = fanotify_add_protected(-1, &pp);
    ASSERT(rc == 0, "exclusion adds no mark (rc 0)");
    ASSERT(fanotify_any_mark_active() == 0, "exclusion adds no mark state");
}

/*
 * Part 0h: config rule matching.  [allowlist], [unsafe_allowlist] and
 * [denylist] accept globs on either side through the same engine as
 * [protected_paths] (covered above).  Three seams expose the matcher
 * without a kernel event:
 *   - fanotify_test_config_allow_match(binary, target, &grant) returns
 *     the matched LHS pattern (the hash-pin key) or NULL and reports
 *     the grant scope (NULL for a global rule);
 *   - fanotify_test_unsafe_allow_match() matches [unsafe_allowlist] only;
 *   - fanotify_test_config_deny_match() returns the [denylist] verdict.
 * Covers all four binary/target combinations, the exact-side regression
 * guarantees (strcmp binary, equal-or-under target), glob boundaries and
 * section independence.
 */

/* Build one rule side the way config_load() does: exact copy with
 * base_len = strlen(); glob with the wildcard-free base length.  The
 * patterns used here are already canonical, so no resolution is needed. */
static void set_rule_side(char *dst, size_t dstsz, int *is_glob,
                          int *base_len, const char *pattern)
{
    snprintf(dst, dstsz, "%s", pattern);
    *is_glob = strchr(dst, '*') != NULL;
    *base_len = *is_glob ? glob_base_len(dst) : (int)strlen(dst);
}

/* Fill one rule; a NULL/empty target leaves a global (bare-line) rule. */
static void set_rule(RuleEntry *e, const char *binary, const char *target)
{
    memset(e, 0, sizeof(*e));
    set_rule_side(e->binary, sizeof(e->binary), &e->binary_is_glob,
                  &e->binary_base_len, binary);
    if (target && target[0] != '\0')
        set_rule_side(e->target_path, sizeof(e->target_path),
                      &e->target_is_glob, &e->target_base_len, target);
}

static void test_config_rule_matching(void) {
    static Config cfg;
    const char *grant;
    const char *m;

    memset(&cfg, 0, sizeof(cfg));

    /*
     * [allowlist]
     *   0 exact binary + exact target  (historical regression case)
     *   1 glob binary  + exact target  (AppImage-style mount pattern)
     *   2 exact binary + glob target
     *   3 glob binary  + glob target
     *   4 exact binary + global
     *   5 glob binary  + global
     */
    set_rule(&cfg.allowlist[0], "/usr/bin/opencode", "/home/u/.local");
    set_rule(&cfg.allowlist[1], "/tmp/.mount_*/openchamber",
             "/home/u/.local/share/opencode");
    set_rule(&cfg.allowlist[2], "/usr/bin/glob-target-tool",
             "/home/u/.local/**");
    set_rule(&cfg.allowlist[3], "/tmp/.mount_*/widget", "/srv/data/**");
    set_rule(&cfg.allowlist[4], "/usr/bin/global-tool", NULL);
    set_rule(&cfg.allowlist[5], "/opt/global_*/tool", NULL);
    cfg.allowlist_count = 6;

    /* [unsafe_allowlist]: separate section, never hash-pinned. */
    set_rule(&cfg.unsafe_allowlist[0], "/opt/unsafe-tool", "/etc/unsafe");
    set_rule(&cfg.unsafe_allowlist[1], "/opt/cache_*/plugin", NULL);
    cfg.unsafe_allowlist_count = 2;

    /* [denylist]: globs on both sides, no hashing involved. */
    set_rule(&cfg.denylist[0], "/usr/bin/curl", NULL);
    set_rule(&cfg.denylist[1], "/tmp/.mount_*/evil", "/etc/**");
    cfg.denylist_count = 2;

    Config *saved = g_config;
    g_config = &cfg;

    /* exact + exact: strcmp binary, equal-or-under target (regression) */
    grant = NULL;
    m = fanotify_test_config_allow_match("/usr/bin/opencode",
                                         "/home/u/.local/share/x", &grant);
    ASSERT(m != NULL && strcmp(m, "/usr/bin/opencode") == 0,
           "exact+exact returns the configured binary pattern");
    ASSERT(grant != NULL && strcmp(grant, "/home/u/.local") == 0,
           "exact target is returned as the grant target");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/opencode",
                                            "/home/u/.local", &grant) != NULL,
           "exact target matches the target directory itself");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/opencode-helper",
                                            "/home/u/.local/share/x",
                                            &grant) == NULL,
           "exact binary is strcmp-strict (no prefix match)");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/opencode",
                                            "/home/u/.localX/y",
                                            &grant) == NULL,
           "exact target rejects a sibling prefix");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/opencode",
                                            "/home/u/other", &grant) == NULL,
           "exact target rejects an unrelated path");

    /* glob binary + exact target */
    grant = NULL;
    m = fanotify_test_config_allow_match(
            "/tmp/.mount_Ab3xY/openchamber",
            "/home/u/.local/share/opencode/config.json", &grant);
    ASSERT(m != NULL && strcmp(m, "/tmp/.mount_*/openchamber") == 0,
           "glob binary returns the configured pattern (pin key)");
    ASSERT(grant != NULL &&
           strcmp(grant, "/home/u/.local/share/opencode") == 0,
           "glob-binary rule keeps its exact grant target");
    ASSERT(fanotify_test_config_allow_match(
               "/tmp/.mount_Ab3xY/openchamber2",
               "/home/u/.local/share/opencode/cfg", &grant) == NULL,
           "glob binary rejects a different basename");
    ASSERT(fanotify_test_config_allow_match(
               "/var/.mount_Ab3xY/openchamber",
               "/home/u/.local/share/opencode/cfg", &grant) == NULL,
           "glob binary base prefilter rejects paths outside its base");

    /* exact binary + glob target */
    grant = NULL;
    m = fanotify_test_config_allow_match("/usr/bin/glob-target-tool",
                                         "/home/u/.local/share/x", &grant);
    ASSERT(m != NULL && strcmp(m, "/usr/bin/glob-target-tool") == 0,
           "exact binary + glob target matches the subtree");
    ASSERT(grant != NULL && strcmp(grant, "/home/u/.local/**") == 0,
           "glob target is returned verbatim as the grant target");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/glob-target-tool",
                                            "/home/u/.local", &grant) != NULL,
           "globstar target matches zero segments");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/glob-target-tool",
                                            "/home/u/.localX/y",
                                            &grant) == NULL,
           "glob target base boundary is respected");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/glob-target-tool",
                                            "/home/u/other/x",
                                            &grant) == NULL,
           "glob target rejects an unrelated path");

    /* glob binary + glob target */
    m = fanotify_test_config_allow_match("/tmp/.mount_q1/widget",
                                         "/srv/data/a/b.json", &grant);
    ASSERT(m != NULL && strcmp(m, "/tmp/.mount_*/widget") == 0,
           "glob+glob rule matches on both sides");
    ASSERT(fanotify_test_config_allow_match("/tmp/.mount_q1/sub/widget",
                                            "/srv/data/a/b.json",
                                            &grant) == NULL,
           "single-star binary glob does not cross segments");
    ASSERT(fanotify_test_config_allow_match("/tmp/.mount_q1/widget",
                                            "/srv/dataX/a", &grant) == NULL,
           "glob+glob target boundary is respected");

    /* global rules report a NULL grant target (wildcard cache entry) */
    grant = "sentinel";
    m = fanotify_test_config_allow_match("/usr/bin/global-tool", "/etc/x",
                                         &grant);
    ASSERT(m != NULL && strcmp(m, "/usr/bin/global-tool") == 0,
           "global exact rule matches any target");
    ASSERT(grant == NULL, "global rule reports a NULL grant target");
    grant = "sentinel";
    m = fanotify_test_config_allow_match("/opt/global_42/tool", "/home/u/x",
                                         &grant);
    ASSERT(m != NULL && strcmp(m, "/opt/global_*/tool") == 0,
           "global glob rule matches and returns its pattern");
    ASSERT(grant == NULL, "global glob rule reports a NULL grant target");

    /* [unsafe_allowlist] is a separate section from [allowlist] */
    m = fanotify_test_unsafe_allow_match("/opt/unsafe-tool", "/etc/unsafe/x");
    ASSERT(m != NULL && strcmp(m, "/opt/unsafe-tool") == 0,
           "unsafe seam matches its own section");
    ASSERT(fanotify_test_config_allow_match("/opt/unsafe-tool",
                                            "/etc/unsafe/x",
                                            &grant) == NULL,
           "unsafe rule is invisible to the allow seam");
    ASSERT(fanotify_test_unsafe_allow_match(
               "/usr/bin/opencode", "/home/u/.local/share/x") == NULL,
           "allowlist rule is invisible to the unsafe seam");
    m = fanotify_test_unsafe_allow_match("/opt/cache_42/plugin", "/etc/x");
    ASSERT(m != NULL && strcmp(m, "/opt/cache_*/plugin") == 0,
           "unsafe seam is glob-capable and global");
    ASSERT(fanotify_test_unsafe_allow_match("/opt/cache_42/plugin2",
                                            "/etc/x") == NULL,
           "unsafe glob binary is segment-bounded");

    /* [denylist] through the deny seam; no hashing needed */
    ASSERT(fanotify_test_config_deny_match("/usr/bin/curl",
                                           "/etc/passwd") == 1,
           "deny seam matches an exact global binary");
    ASSERT(fanotify_test_config_deny_match("/usr/bin/curl2",
                                           "/etc/passwd") == 0,
           "deny seam keeps strcmp-strict exact binaries");
    ASSERT(fanotify_test_config_deny_match("/tmp/.mount_ZZ/evil",
                                           "/etc/passwd") == 1,
           "deny seam matches glob binary + glob target");
    ASSERT(fanotify_test_config_deny_match("/tmp/.mount_ZZ/good",
                                           "/etc/passwd") == 0,
           "deny glob binary rejects a different basename");
    ASSERT(fanotify_test_config_deny_match("/tmp/.mount_ZZ/evil",
                                           "/home/u/x") == 0,
           "deny glob target rejects outside its subtree");
    ASSERT(fanotify_test_config_allow_match("/usr/bin/curl", "/etc/passwd",
                                            &grant) == NULL,
           "deny rule is invisible to the allow seam");
    ASSERT(fanotify_test_config_deny_match("/opt/unsafe-tool",
                                           "/etc/unsafe/x") == 0,
           "allow sections never appear in the deny seam");

    g_config = saved;
}

/*
 * Part 0i: [allowlist] hash pinning.  The pin module is controlled with
 * a per-run temp state file; the seams below run the pipeline's verdict
 * and first-seen store without a kernel permission event.
 */

#define PIN_SHA_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define PIN_SHA_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

static char g_pin_dir[256];
static char g_pin_file[PATH_MAX + 64];
static int g_pin_fixture_ready = 0;

static int pin_fixture_init(void)
{
    if (g_pin_fixture_ready)
        return 0;

    snprintf(g_pin_dir, sizeof(g_pin_dir),
             "/tmp/fileshield_fanotify_pin_XXXXXX");
    if (!mkdtemp(g_pin_dir))
        return -1;
    snprintf(g_pin_file, sizeof(g_pin_file), "%s/allowlist-hashes.json",
             g_pin_dir);
    g_pin_fixture_ready = 1;
    return 0;
}

/* Start from a missing state file (clean first use). */
static int pin_fixture_reset(void)
{
    if (pin_fixture_init() < 0)
        return -1;
    unlink(g_pin_file);
    pin_set_state_file(g_pin_file);
    return pin_load(g_pin_file);
}

/* Install raw file content (used for the damaged-file case). */
static int pin_fixture_write_raw(const char *text)
{
    FILE *fp;

    if (pin_fixture_init() < 0)
        return -1;
    fp = fopen(g_pin_file, "w");
    if (!fp)
        return -1;
    fputs(text, fp);
    fclose(fp);
    pin_set_state_file(g_pin_file);
    return pin_load(g_pin_file);
}

static long read_pin_file(char *out, size_t sz)
{
    FILE *fp = fopen(g_pin_file, "r");
    size_t n;

    if (!fp)
        return -1;
    n = fread(out, 1, sz - 1, fp);
    fclose(fp);
    out[n] = '\0';
    return (long)n;
}

static void pin_fixture_cleanup(void)
{
    if (!g_pin_fixture_ready)
        return;
    unlink(g_pin_file);
    rmdir(g_pin_dir);
    pin_set_state_file(NULL);
    g_pin_fixture_ready = 0;
}

/* First event for a rule: store immediately, then the digest matches. */
static void test_pin_first_seen_tofu(void)
{
    static Config cfg;
    Config *saved = g_config;
    char old[129];
    struct stat st;

    memset(&cfg, 0, sizeof(cfg));
    set_rule(&cfg.allowlist[0], "/usr/bin/pinned-tool", "/home/u/secret");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    ASSERT(pin_fixture_reset() == 0, "missing pin file is a clean first use");
    ASSERT(pin_damaged() == 0, "missing pin file is not damaged");

    ASSERT(fanotify_test_pin_first_seen("/usr/bin/pinned-tool", PIN_SHA_A,
                                        "/home/u/secret") == 0,
           "first-seen store succeeds");

    ASSERT(stat(g_pin_file, &st) == 0 && st.st_size > 0,
           "pin file exists on disk immediately");
    ASSERT(pin_load(g_pin_file) == 0, "freshly written pin file reloads");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_A, old) ==
               PIN_CHECK_MATCH,
           "pin_check matches the stored digest");
    ASSERT(old[0] == '\0', "pin match leaves old_out empty");

    /* With a pin present the pipeline takes the changed path instead. */
    ASSERT(fanotify_test_pin_first_seen("/usr/bin/pinned-tool", PIN_SHA_B,
                                        "/home/u/secret") == -1,
           "first-seen seam refuses once a pin exists");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_A, old) ==
               PIN_CHECK_MATCH,
           "refused store left the existing pin untouched");

    ASSERT(fanotify_test_pin_first_seen("/usr/bin/other", PIN_SHA_A,
                                        "/home/u/secret") == -1,
           "first-seen seam requires a matching allowlist rule");

    g_config = saved;
}

/* Rule verdicts: no match, first use, match, changed, unavailable. */
static void test_allowlist_pin_verdict_codes(void)
{
    static Config cfg;
    Config *saved = g_config;
    char old[129];

    memset(&cfg, 0, sizeof(cfg));
    set_rule(&cfg.allowlist[0], "/usr/bin/pinned-tool", "/home/u/secret");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    old[0] = 'x';
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/other", PIN_SHA_A,
                                           "/home/u/secret", old) == 3,
           "unmatched binary reports NO_MATCH");
    ASSERT(old[0] == '\0', "NO_MATCH clears old_out");

    /*
     * First use: the pipeline stores the digest and grants, so the seam
     * reports ALLOW; the verdict call itself must not write a pin.
     */
    ASSERT(pin_fixture_reset() == 0, "clean first-use state");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_A,
                                           "/home/u/secret", old) == 0,
           "first-use rule reports ALLOW");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_A, old) ==
               PIN_CHECK_FIRST_USE,
           "verdict is side-effect free (pin still absent)");

    ASSERT(fanotify_test_pin_first_seen("/usr/bin/pinned-tool", PIN_SHA_A,
                                        "/home/u/secret") == 0,
           "store the pin for the match/change cases");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_A,
                                           "/home/u/secret", old) == 0,
           "matching pin reports ALLOW");
    ASSERT(old[0] == '\0', "pin match leaves old_out empty");

    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_B,
                                           "/home/u/secret", old) == 1,
           "changed digest reports CHANGED");
    ASSERT(strcmp(old, PIN_SHA_A) == 0,
           "CHANGED returns the previously pinned digest");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_A, old) ==
               PIN_CHECK_MATCH,
           "the CHANGED verdict did not touch the pin");

    /* An accepted update (what the dialog path does on Yes) replaces the
     * pin, and the next verdict is ALLOW again. */
    ASSERT(pin_store("/usr/bin/pinned-tool", PIN_SHA_B) == 0,
           "accepted update stores the new digest");
    ASSERT(pin_check("/usr/bin/pinned-tool", PIN_SHA_B, old) ==
               PIN_CHECK_MATCH,
           "pin_check matches the new digest after the update");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_B,
                                           "/home/u/secret", old) == 0,
           "new digest reports ALLOW after the update");

    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", "",
                                           "/home/u/secret", old) == 2,
           "empty digest reports NO_SILENT_GRANT");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", NULL,
                                           "/home/u/secret", old) == 2,
           "missing digest reports NO_SILENT_GRANT");

    g_config = saved;
}

/* A damaged pin file fails closed and is never rewritten. */
static void test_pin_damaged_falls_through(void)
{
    static Config cfg;
    Config *saved = g_config;
    char old[129];
    char before[64];
    char after[64];

    memset(&cfg, 0, sizeof(cfg));
    set_rule(&cfg.allowlist[0], "/usr/bin/pinned-tool", "/home/u/secret");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    ASSERT(pin_fixture_write_raw("this is not json\n") == -1,
           "garbage pin file loads as damaged (fail closed)");
    ASSERT(pin_damaged() == 1, "damaged flag is set");

    ASSERT(read_pin_file(before, sizeof(before)) > 0,
           "read the damaged file before the verdict calls");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", PIN_SHA_A,
                                           "/home/u/secret", old) == 2,
           "damaged table reports NO_SILENT_GRANT");
    ASSERT(fanotify_test_allowlist_verdict("/usr/bin/pinned-tool", "",
                                           "/home/u/secret", old) == 2,
           "empty digest reports NO_SILENT_GRANT while damaged");
    ASSERT(read_pin_file(after, sizeof(after)) > 0, "re-read the file");
    ASSERT(strcmp(before, after) == 0,
           "no pin write happened while the table was damaged");

    ASSERT(pin_fixture_reset() == 0 && pin_damaged() == 0,
           "a missing file reloads clean (admin recovery)");

    g_config = saved;
}

/* The unsafe section wins over the pinned one and skips pin machinery. */
static void test_unsafe_allowlist_skips_pins(void)
{
    static Config cfg;
    Config *saved = g_config;
    const char *pattern = "/tmp/.mount_*/opencode";
    const char *grant = NULL;
    const char *binary = "/tmp/.mount_abc/opencode";
    const char *target = "/home/u/.local/share/x";
    char old[129];

    memset(&cfg, 0, sizeof(cfg));
    /*
     * The same binary pattern is deliberately present in both sections.
     * This pins the matcher invariant that the unsafe path is independent
     * of the safe section and never reads or writes a pin; the pipeline's
     * unsafe-first order is enforced in event_runtime_allowed() and
     * covered by the verdict seam tests.
     */
    set_rule(&cfg.unsafe_allowlist[0], pattern, "/home/u/.local");
    cfg.unsafe_allowlist_count = 1;
    set_rule(&cfg.allowlist[0], pattern, "/home/u/.local");
    cfg.allowlist_count = 1;
    g_config = &cfg;

    ASSERT(pin_fixture_reset() == 0, "clean pin state for the order test");

    ASSERT(fanotify_test_unsafe_allow_match(binary, target) != NULL,
           "unsafe seam matches the rule shared by both sections");
    ASSERT(fanotify_test_config_allow_match(binary, target, &grant) != NULL,
           "the pinned seam would also match (unsafe wins by order)");

    /* Nothing in the unsafe path reads or writes a pin, so the matching
     * key is still unpinned while the safe seam only compares. */
    ASSERT(pin_check(pattern, PIN_SHA_A, old) == PIN_CHECK_FIRST_USE,
           "no pin was written for the unsafe hit");

    g_config = saved;
}

/* The hash-change prompt must fail closed on a NULL request. */
static void test_hash_change_null_request_denies(void)
{
    ASSERT(notify_ask_hash_change(NULL) == NOTIFY_DENY,
           "NULL hash-change request denies (fail closed)");
}

/*
 * Notification flood control: identical (kind, binary, target) hits are
 * suppressed for the dedup window, distinct keys pass, a zero window
 * notifies every hit, and the global cap bounds a burst of distinct keys.
 */
static void test_notify_rate_windows(void)
{
    notify_test_reset_rate();

    ASSERT(notify_test_hit_rate(NOTIFY_HIT_DENY, "/b", "/t", 60, 20) == 1,
           "first notification passes");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_DENY, "/b", "/t", 60, 20) == 0,
           "identical hit inside the window is suppressed");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_DENY, "/b", "/t2", 60, 20) == 1,
           "a different target passes");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_ALLOW, "/b", "/t", 60, 20) == 1,
           "a different kind passes");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_DENY, "/b", "/t", 0, 20) == 1,
           "dedup window 0 notifies every hit");

    /* Unsafe hits are gated once per process by the caller, so the
     * per-key window must not suppress a second process using the rule. */
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_UNSAFE, "/b", "/t", 60, 20) == 1,
           "unsafe bypasses the per-key window (first hit)");
    ASSERT(notify_test_hit_rate(NOTIFY_HIT_UNSAFE, "/b", "/t", 60, 20) == 1,
           "unsafe bypasses the per-key window (repeat)");

    /* Configurable global cap: 10 distinct keys, cap 5 -> 5 delivered. */
    notify_test_reset_rate();
    int allowed = 0;
    for (int i = 0; i < 10; i++)
    {
        char bin[32];
        snprintf(bin, sizeof(bin), "/bin/notify-%d", i);
        allowed += notify_test_hit_rate(NOTIFY_HIT_DENY, bin, "/t", 0, 5);
    }
    ASSERT(allowed == 5, "notify_max caps the window at 5");
    notify_test_reset_rate();
}

/*
 * Unsafe hits surface once per process: the first hit qualifies for the
 * warning + notification, repeats are suppressed, and another process is
 * a new instance.
 */
static void test_unsafe_hit_once_per_process(void)
{
    pid_t self = getpid();

    ASSERT(fanotify_test_unsafe_first_hit(self) == 1,
           "first unsafe hit for a process is surfaced");
    ASSERT(fanotify_test_unsafe_first_hit(self) == 0,
           "repeat unsafe hit for the same process is suppressed");
    ASSERT(fanotify_test_unsafe_first_hit(getppid()) == 1,
           "another process is surfaced independently");
}

/* A glob deny rule beats a glob allow rule (deny is evaluated first). */
static void test_glob_deny_beats_glob_allow(void)
{
    static Config cfg;
    Config *saved = g_config;
    const char *grant = NULL;
    const char *binary = "/tmp/.mount_abc/opencode";
    const char *target = "/home/u/.local/share/opencode/x";

    memset(&cfg, 0, sizeof(cfg));
    set_rule(&cfg.allowlist[0], "/tmp/.mount_*/opencode", "/home/u/.local");
    cfg.allowlist_count = 1;
    set_rule(&cfg.denylist[0], "/tmp/.mount_*/open*", "/home/u/.local/**");
    cfg.denylist_count = 1;
    g_config = &cfg;

    ASSERT(fanotify_test_config_deny_match(binary, target) == 1,
           "glob deny rule matches the access");
    ASSERT(fanotify_test_config_allow_match(binary, target, &grant) != NULL,
           "glob allow rule also matches the same access");
    /* event_load_binary() runs the deny match before every grant stage
     * and before hashing, so the deny wins and no pin work is done. */

    g_config = saved;
}

/*
 * Part 1b: persisted allow/deny entries are file- and command-scoped.
 * An entry without a target_path, without the raw command line, or
 * without its digest (legacy or hand-edited state file) must never act
 * as a wildcard grant or a blanket denial.  Asserted observably: only a
 * fully-scoped entry can match, and only with its exact keys.
 */
static void test_incomplete_entries_grant_nothing(void) {
    const char *sha =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char cmd_fingerprint[129];

    ASSERT(sha512_string("kubectl config view --minify", cmd_fingerprint) == 0,
           "digest of the stored command line");

    PersistEntry entries[4];
    memset(entries, 0, sizeof(entries));

    /* Valid file- and command-scoped allow entry. */
    snprintf(entries[0].binary, sizeof(entries[0].binary), "/usr/bin/kubectl");
    snprintf(entries[0].binary_sha512, sizeof(entries[0].binary_sha512), "%s", sha);
    snprintf(entries[0].target_path, sizeof(entries[0].target_path),
             "/home/u/.kube/config");
    snprintf(entries[0].cmdline, sizeof(entries[0].cmdline),
             "kubectl config view --minify");
    snprintf(entries[0].cmdline_sha512, sizeof(entries[0].cmdline_sha512),
             "%s", cmd_fingerprint);

    /* Legacy wildcard entry: no target recorded. */
    snprintf(entries[1].binary, sizeof(entries[1].binary), "/usr/bin/ssh");
    snprintf(entries[1].binary_sha512, sizeof(entries[1].binary_sha512), "%s", sha);
    snprintf(entries[1].cmdline, sizeof(entries[1].cmdline), "ssh-add -l");
    snprintf(entries[1].cmdline_sha512, sizeof(entries[1].cmdline_sha512),
             "%s", sha);

    /* Digest only: the command line cannot be shown. */
    snprintf(entries[2].binary, sizeof(entries[2].binary), "/usr/bin/aws");
    snprintf(entries[2].binary_sha512, sizeof(entries[2].binary_sha512), "%s", sha);
    snprintf(entries[2].target_path, sizeof(entries[2].target_path),
             "/home/u/.aws/credentials");
    snprintf(entries[2].cmdline_sha512, sizeof(entries[2].cmdline_sha512),
             "%s", sha);

    /* Raw command only: cannot be matched. */
    snprintf(entries[3].binary, sizeof(entries[3].binary), "/usr/bin/gh");
    snprintf(entries[3].binary_sha512, sizeof(entries[3].binary_sha512), "%s", sha);
    snprintf(entries[3].target_path, sizeof(entries[3].target_path),
             "/home/u/.config/gh/hosts.yml");
    snprintf(entries[3].cmdline, sizeof(entries[3].cmdline), "gh auth status");

    fanotify_load_dyn_allowlist(entries, 4);

    /* The complete entry loads with every matching key preserved. */
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl config view --minify") == 1,
           "the complete allow entry matches its exact tuple");

    /* The incomplete records can never act as wildcard grants. */
    ASSERT(test_match_allow("/usr/bin/ssh", sha,
           "/home/u/.ssh/id_rsa", "ssh-add -l") == 0,
           "target-less allow entry grants nothing");
    ASSERT(test_match_allow("/usr/bin/aws", sha,
           "/home/u/.aws/credentials", "aws sts get-caller-identity") == 0,
           "digest-only allow entry grants nothing");
    ASSERT(test_match_allow("/usr/bin/gh", sha,
           "/home/u/.config/gh/hosts.yml", "gh auth status") == 0,
           "cmdline-only allow entry grants nothing");

    /* The surviving entry stays pinned to each of its keys. */
    ASSERT(test_match_allow("/usr/bin/kubectl", "deadbeef",
           "/home/u/.kube/config", "kubectl config view --minify") == 0,
           "unverifiable binary hash does not match");
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/other", "kubectl config view --minify") == 0,
           "different target does not match");
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get secrets") == 0,
           "different command does not match");

    /* Denies do not require a binary SHA-512, but incomplete records
     * deny nothing at all. */
    PersistEntry dentries[2];
    memset(dentries, 0, sizeof(dentries));
    snprintf(dentries[0].binary, sizeof(dentries[0].binary), "/usr/bin/curl");

    snprintf(dentries[1].binary, sizeof(dentries[1].binary), "/usr/bin/wget");
    snprintf(dentries[1].target_path, sizeof(dentries[1].target_path),
             "/home/u/.netrc");

    fanotify_load_dyn_denylist(dentries, 2);
    ASSERT(test_match_deny("/usr/bin/curl", "", "/etc/passwd",
           "curl") == 0,
           "bare deny record denies nothing");
    ASSERT(test_match_deny("/usr/bin/wget", "", "/home/u/.netrc",
           "wget") == 0,
           "deny record without a command fingerprint denies nothing");

    /* Reload an empty list so later tests see the daemon's clean state. */
    fanotify_load_dyn_allowlist(NULL, 0);
    fanotify_load_dyn_denylist(NULL, 0);
}

/*
 * Part 1c: permanent entries are scoped to the exact command line.  A
 * grant recorded for "kubectl get pods" must not cover "kubectl get
 * secrets" for the same binary, hash, file and call chain.
 */
static void test_cmdline_scoping(void) {
    const char *sha =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char cmd_pods[129];
    char cmd_secrets[129];

    ASSERT(sha512_string("kubectl get pods", cmd_pods) == 0,
           "digest of approved command");
    ASSERT(sha512_string("kubectl get secrets", cmd_secrets) == 0,
           "digest of other command");
    ASSERT(strcmp(cmd_pods, cmd_secrets) != 0, "command digests differ");

    PersistEntry e[1];
    memset(e, 0, sizeof(e));
    snprintf(e[0].binary, sizeof(e[0].binary), "/usr/bin/kubectl");
    snprintf(e[0].binary_sha512, sizeof(e[0].binary_sha512), "%s", sha);
    snprintf(e[0].target_path, sizeof(e[0].target_path),
             "/home/u/.kube/config");
    snprintf(e[0].cmdline, sizeof(e[0].cmdline), "kubectl get pods");
    snprintf(e[0].cmdline_sha512, sizeof(e[0].cmdline_sha512), "%s",
             cmd_pods);

    fanotify_load_dyn_allowlist(e, 1);
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get pods") == 1,
           "exact command matches the allow entry");
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get secrets") == 0,
           "different command does not match the allow entry");
    ASSERT(test_match_allow("/usr/bin/kubectl", sha,
           "/home/u/.ssh/id_rsa", "kubectl get pods") == 0,
           "different target does not match the allow entry");
    ASSERT(test_match_allow("/usr/bin/kubectl", "deadbeef",
           "/home/u/.kube/config", "kubectl get pods") == 0,
           "unverifiable binary hash does not match");
    fanotify_load_dyn_allowlist(NULL, 0);

    /* The deny side mirrors the same scoping. */
    fanotify_load_dyn_denylist(e, 1);
    ASSERT(test_match_deny("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get pods") == 1,
           "exact command matches the deny entry");
    ASSERT(test_match_deny("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get secrets") == 0,
           "different command does not match the deny entry");
    fanotify_load_dyn_denylist(NULL, 0);
}

/*
 * Part 1d: the command-line fingerprint covers the FULL raw command line,
 * not just the 512-byte display form.  Two invocations that share a long
 * prefix but differ at the end must fingerprint differently (the old
 * truncated hash let one approved command cover the other), and the
 * digest must equal SHA-512 over the raw /proc bytes.
 */

/* Spawn a long-running child whose argv carries one unique marker. */
static pid_t spawn_marked_child(const char *marker)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0)
    {
        /* Own process group so the whole child tree can be killed. */
        setpgid(0, 0);
        /* sh keeps the marker in its argv (as $0) while sleep holds it
         * alive.  The trailing ";" stops sh from exec-replacing itself
         * with sleep (which would drop the marker from argv). */
        execl("/bin/sh", "sh", "-c", "sleep 30; :", marker, (char *)NULL);
        _exit(127);
    }
    return pid;
}

static int read_raw_cmdline(pid_t pid, char *buf, size_t sz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sz - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}

/*
 * Wait until the child's cmdline really contains the marker: right after
 * fork() the child still shows the parent's cmdline, which would make two
 * children look identical.
 */
static int wait_for_marker(pid_t pid, const char *marker)
{
    char raw[8192];
    for (int i = 0; i < 200; i++)
    {
        int n = read_raw_cmdline(pid, raw, sizeof(raw));
        if (n > 0 &&
            memmem(raw, (size_t)n, marker, strlen(marker)) != NULL)
            return 0;
        usleep(5000);
    }
    return -1;
}

static void test_cmdline_fingerprint_full(void) {
    char prefix[600];
    memset(prefix, 'p', sizeof(prefix) - 1);
    prefix[sizeof(prefix) - 1] = '\0';

    char arg_a[1024], arg_b[1024];
    snprintf(arg_a, sizeof(arg_a), "%sAAAA", prefix);
    snprintf(arg_b, sizeof(arg_b), "%sBBBB", prefix);

    pid_t pid_a = spawn_marked_child(arg_a);
    pid_t pid_b = spawn_marked_child(arg_b);
    ASSERT(pid_a > 0 && pid_b > 0, "spawn marked children");
    if (pid_a <= 0 || pid_b <= 0)
        return;

    int ready_a = wait_for_marker(pid_a, arg_a);
    int ready_b = wait_for_marker(pid_b, arg_b);
    ASSERT(ready_a == 0 && ready_b == 0, "children exec with their markers");

    if (ready_a == 0 && ready_b == 0)
    {
        char fp_a[129] = "", fp_b[129] = "";
        ASSERT(fanotify_test_cmdline_fingerprint(pid_a, fp_a) == 0,
               "fingerprint child A");
        ASSERT(fanotify_test_cmdline_fingerprint(pid_b, fp_b) == 0,
               "fingerprint child B");
        ASSERT(strcmp(fp_a, fp_b) != 0,
               "commands sharing a 600-byte prefix fingerprint differently");

        char raw[8192];
        int n = read_raw_cmdline(pid_a, raw, sizeof(raw));
        char expected[129];
        ASSERT(n > 0 && sha512_buf(raw, (size_t)n, expected) == 0,
               "independent digest of the raw cmdline");
        ASSERT(n > 0 && strcmp(fp_a, expected) == 0,
               "fingerprint equals SHA-512 of the raw /proc bytes");
    }

    kill(-pid_a, SIGKILL); /* negative: kill the child's process group */
    kill(-pid_b, SIGKILL);
    waitpid(pid_a, NULL, 0);
    waitpid(pid_b, NULL, 0);
}

/*
 * Part 1: fill the deferred queue to capacity, verify a full queue
 * refuses further events, then verify the fail-closed flush denies and
 * closes every deferred event.
 */
static void test_defer_flush_contract(void) {
    /*
     * Pre-warm glibc's lazily-opened /dev/log socket: flush_pending()
     * calls log_msg() after closing the deferred fds, and on first use
     * syslog would otherwise claim the lowest freed fd number — which
     * would make the EBADF close-check below misread that fd as open.
     */
    log_msg(LOG_DEBUG, "warm up syslog socket");

    int resp_pipe[2];
    ASSERT(pipe(resp_pipe) == 0, "create response pipe");

    enum { MAX_PROBE = 4096 }; /* well above the internal PENDING_MAX */
    static int event_fds[MAX_PROBE];
    int filled = 0;

    for (int i = 0; i < MAX_PROBE; i++) {
        int efd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(efd >= 0, "open event fd");
        if (efd < 0)
            break;

        struct fanotify_event_metadata ev;
        memset(&ev, 0, sizeof(ev));
        ev.event_len = sizeof(ev);
        ev.vers = FANOTIFY_METADATA_VERSION;
        ev.mask = FAN_OPEN_PERM;
        ev.fd = efd;
        ev.pid = (int)getpid();

        if (fanotify_defer_event(&ev) == 0) {
            event_fds[filled++] = efd;
        } else {
            /* Queue full: caller contract is to fail closed. */
            close(efd);
            break;
        }
    }

    ASSERT(filled > 0, "deferred queue accepted events");

    struct fanotify_event_metadata probe;
    memset(&probe, 0, sizeof(probe));
    probe.event_len = sizeof(probe);
    probe.vers = FANOTIFY_METADATA_VERSION;
    probe.mask = FAN_OPEN_PERM;
    probe.fd = -1; /* FAN_NOFD */
    probe.pid = (int)getpid();
    ASSERT(fanotify_defer_event(&probe) == -1,
            "defer into a full queue fails closed");

    /* Fail-closed flush: deny + close every deferred event. */
    fanotify_flush_pending(resp_pipe[1]);

    /* Observable empty-queue check without a count helper: after the
     * flush, a fresh event must be accepted again, and the follow-up
     * fail-closed flush denies it exactly like the first batch. */
    int re_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    ASSERT(re_fd >= 0, "open re-defer event fd");
    struct fanotify_event_metadata re_ev;
    memset(&re_ev, 0, sizeof(re_ev));
    re_ev.event_len = sizeof(re_ev);
    re_ev.vers = FANOTIFY_METADATA_VERSION;
    re_ev.mask = FAN_OPEN_PERM;
    re_ev.fd = re_fd;
    re_ev.pid = (int)getpid();
    ASSERT(fanotify_defer_event(&re_ev) == 0,
            "queue accepts events again after flush");
    fanotify_flush_pending(resp_pipe[1]);
    /* Close the write end so the read below returns EOF instead of
     * blocking forever when a response is missing: a hanging make test is
     * worse than a failing one. */
    close(resp_pipe[1]);
    resp_pipe[1] = -1;

    /* Exactly one fanotify_response per deferred event must arrive. */
    size_t want = (size_t)(filled + 1) * sizeof(struct fanotify_response);
    char *buf = malloc(want);
    ASSERT(buf != NULL, "alloc response buffer");
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(resp_pipe[0], buf + got, want - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    ASSERT(got == want, "one deny response per deferred event");

    for (int i = 0; i < filled; i++) {
        const struct fanotify_response *r =
            (const struct fanotify_response *)(buf +
                (size_t)i * sizeof(*r));
        ASSERT(r->response == FAN_DENY, "flush response is FAN_DENY");
        ASSERT(r->fd == event_fds[i],
               "flush response targets the deferred fd");
        ASSERT(fcntl(event_fds[i], F_GETFD) == -1 && errno == EBADF,
               "deferred fd was closed by flush");
    }

    /* The re-deferred event is the last response and is also closed. */
    const struct fanotify_response *last =
        (const struct fanotify_response *)(buf + (size_t)filled * sizeof(*last));
    ASSERT(last->response == FAN_DENY, "flush response is FAN_DENY");
    ASSERT(last->fd == re_fd, "flush response targets the re-deferred fd");
    ASSERT(fcntl(re_fd, F_GETFD) == -1 && errno == EBADF,
           "re-deferred fd was closed by flush");

    free(buf);
    close(resp_pipe[0]);
    if (resp_pipe[1] >= 0)
        close(resp_pipe[1]);
}

/*
 * Part 2: real kernel fanotify group, no FAN_UNLIMITED_QUEUE.  Open 20000
 * distinct files under one marked directory without draining; the kernel
 * default queue holds 16384 events, so saturation is guaranteed and the
 * next read must report FAN_Q_OVERFLOW.
 */
static void test_kernel_bounded_queue_overflow(void) {
    int fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, O_RDONLY);
    if (fd < 0) {
        if (errno == EPERM || errno == ENOSYS || errno == EAGAIN) {
            printf("SKIP: fanotify group unavailable (%s); "
                   "run as root to exercise the kernel saturation test\n",
                   strerror(errno));
            return;
        }
        fprintf(stderr, "FAIL: fanotify_init: %s\n", strerror(errno));
        failures++;
        return;
    }

    char dir[] = "/tmp/fileshield_queue_sat_XXXXXX";
    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        failures++;
        close(fd);
        return;
    }

    enum { SAT_FILES = 20000 }; /* > 16384 kernel default queue limit */

    /* Create files BEFORE marking so only the opens below queue events. */
    char path[PATH_MAX];
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        int f = open(path, O_CREAT | O_WRONLY, 0600);
        if (f >= 0)
            close(f);
    }

    if (fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN | FAN_EVENT_ON_CHILD,
                      AT_FDCWD, dir) < 0) {
        fprintf(stderr, "FAIL: fanotify_mark: %s\n", strerror(errno));
        failures++;
        goto cleanup;
    }

    /* One open per distinct inode: 20000 unique events, no merging. */
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        int o = open(path, O_RDONLY);
        if (o >= 0)
            close(o);
    }

    /* Drain everything and look for the overflow report. */
    int overflow_seen = 0;
    long events_drained = 0;
    char buf[65536]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                break;
            if (errno == EOVERFLOW) { /* overflow as a read error */
                overflow_seen = 1;
                break;
            }
            fprintf(stderr, "FAIL: fanotify read: %s\n", strerror(errno));
            failures++;
            break;
        }
        if (n == 0)
            break;

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)buf;
        ssize_t remaining = n;
        while (FAN_EVENT_OK(ev, (size_t)remaining)) {
            if (ev->mask & FAN_Q_OVERFLOW)
                overflow_seen = 1;
            if (ev->event_len == 0)
                break;
            remaining -= ev->event_len;
            ev = FAN_EVENT_NEXT(ev, remaining);
            events_drained++;
        }
    }

    ASSERT(overflow_seen, "FAN_Q_OVERFLOW reported after saturation");
    ASSERT(events_drained < SAT_FILES,
           "bounded queue dropped events instead of growing unbounded");

cleanup:
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        unlink(path);
    }
    rmdir(dir);
    close(fd);
}

/*
 * Part 0d: mount marks must be placed through pid 1's mount namespace
 * ("/proc/1/root" + path) so they attach to the mount instances user
 * processes open through, and must be keyed by mount instance.  Inodes are
 * shared across namespaces, so only mount marks need the prefix
 * (MARK-SCOPE-REDESIGN.md; Phase 0 exp1/exp2/exp2p).
 */
static void test_mark_paths(void) {
    char buf[PATH_MAX];
    unsigned long long id_root, id_proc;

    ASSERT(fanotify_test_mark_path("/home/u/.ssh", buf, sizeof(buf)) == 0,
           "mark path builds");
    ASSERT(strcmp(buf, "/proc/1/root/home/u/.ssh") == 0,
           "mark path is prefixed with /proc/1/root");

    ASSERT(fanotify_test_mark_path("/", buf, sizeof(buf)) == 0,
           "root mark path builds");
    ASSERT(strcmp(buf, "/proc/1/root/") == 0, "root mark path is prefixed");

    ASSERT(fanotify_test_mark_path("/home/u/.ssh", buf, 8) == -1,
           "too-small buffer is rejected");

    id_root = fanotify_test_mount_id("/");
    id_proc = fanotify_test_mount_id("/proc");
    if (id_root == 0 || id_proc == 0) {
        printf("SKIP: statx(STATX_MNT_ID) unavailable; mount-ID checks skipped\n");
    } else {
        ASSERT(fanotify_test_mount_id("/") == id_root,
               "mount ID is stable across calls");
        ASSERT(id_root != id_proc, "different mounts have different IDs");
    }
}

/*
 * Part 0e: the scope guard refuses configurations whose own state or config
 * files the installed marks would intercept (self-deadlock class).
 */
static void test_scope_guard(void) {
    static Config cfg;
    Config *saved = g_config;

    /* Containment: the state directory is protected. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path), "%s",
             PERSIST_STATE_DIR);
    cfg.protected_count = 1;
    g_config = &cfg;
    ASSERT(fanotify_scope_guard("/tmp/scope-guard-nonexistent.conf") == -1,
           "scope guard refuses a protected state directory");

    /* Containment: the config file is inside a protected path. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path),
             "/tmp/scope-guard-test");
    cfg.protected_count = 1;
    g_config = &cfg;
    ASSERT(fanotify_scope_guard("/tmp/scope-guard-test/fileshield.conf") == -1,
           "scope guard refuses a config under a protected path");

    /* Benign: the protected path is on a different mount than the state
     * directory and the config. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.protected[0].path, sizeof(cfg.protected[0].path), "/dev");
    cfg.protected_count = 1;
    g_config = &cfg;
    ASSERT(fanotify_scope_guard("/tmp/scope-guard-test.conf") == 0,
           "scope guard accepts a benign config");

    g_config = saved;
}

/*
 * Part 1b: the shutdown drain denies and closes every permission event the
 * kernel still holds.  A socketpair stands in for the group fd: drain()
 * reads event metadata from it and writes fanotify responses back, exactly
 * like the real fd (which is both readable and writable).
 */
static void test_drain_and_deny(void) {
    log_msg(LOG_DEBUG, "warm up syslog socket");

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0,
           "create drain socketpair");

    enum { PERM_EVENTS = 3 };
    int event_fds[PERM_EVENTS + 1] = { -1 };
    struct fanotify_event_metadata evs[PERM_EVENTS + 1];
    size_t total = 0;

    memset(evs, 0, sizeof(evs));
    for (int i = 0; i < PERM_EVENTS + 1; i++) {
        int efd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(efd >= 0, "open drain event fd");
        if (efd < 0)
            break;
        event_fds[i] = efd;

        /* The last event is a notification: closed, never answered. */
        evs[i].event_len = sizeof(evs[i]);
        evs[i].vers = FANOTIFY_METADATA_VERSION;
        evs[i].mask = (i == PERM_EVENTS) ? FAN_CLOSE_WRITE : FAN_OPEN_PERM;
        evs[i].fd = efd;
        evs[i].pid = (int)getpid();
        total += sizeof(evs[i]);
    }

    ASSERT(write(sv[1], evs, total) == (ssize_t)total, "queue drain events");

    fanotify_drain_and_deny(sv[0]);

    /* One FAN_DENY per permission event; none for the notification event. */
    struct fanotify_response resp[PERM_EVENTS] = {0};
    size_t want = sizeof(resp[0]) * PERM_EVENTS;
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(sv[1], (char *)resp + got, want - got);
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    ASSERT(got == want, "one response per drained permission event");
    for (int i = 0; i < PERM_EVENTS; i++) {
        ASSERT(resp[i].response == FAN_DENY, "drain response is FAN_DENY");
        ASSERT(resp[i].fd == event_fds[i],
               "drain response targets the event fd");
    }
    for (int i = 0; i < PERM_EVENTS + 1; i++) {
        if (event_fds[i] >= 0)
            ASSERT(fcntl(event_fds[i], F_GETFD) == -1 && errno == EBADF,
                   "drained event fd was closed");
    }

    /* Empty queue: a second drain must return immediately. */
    fanotify_drain_and_deny(sv[0]);

    close(sv[0]);
    close(sv[1]);
}

/*
 * Part 0f: the recent-decision dedup cache.  The resolved path is part of
 * the key (a hard link reaches the same inode through a different path),
 * a newer decision shadow an older one for the same key, and a reload
 * clears the cache.
 */
static void test_recent_decision_cache(void) {
    fanotify_test_recent_clear();

    fanotify_test_recent_insert(100, (dev_t)1, (ino_t)2, "/home/u/secret",
                                FAN_ALLOW);
    ASSERT(fanotify_test_recent_lookup(100, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == FAN_ALLOW,
           "dedup cache returns the stored decision");
    ASSERT(fanotify_test_recent_lookup(100, (dev_t)1, (ino_t)2,
                                       "/home/u/link") == -1,
           "a different path to the same inode does not reuse the decision");
    ASSERT(fanotify_test_recent_lookup(101, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == -1,
           "a different pid does not reuse the decision");

    /* Newest decision wins for the same key. */
    fanotify_test_recent_insert(100, (dev_t)1, (ino_t)2, "/home/u/secret",
                                FAN_DENY);
    ASSERT(fanotify_test_recent_lookup(100, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == FAN_DENY,
           "a newer decision shadows the older one");

    fanotify_test_recent_clear();
    ASSERT(fanotify_test_recent_lookup(100, (dev_t)1, (ino_t)2,
                                       "/home/u/secret") == -1,
           "clear drops every cached decision");
}

/*
 * Part 0g: the dialog environment whitelist accepts only cosmetic keys and
 * rejects everything that could load code or redirect the platform.
 */
static void test_dialog_env_whitelist(void) {
    ASSERT(notify_test_env_key_allowed("XDG_CURRENT_DESKTOP") == 1,
           "desktop identity key is forwarded");
    ASSERT(notify_test_env_key_allowed("LANG") == 1, "locale key is forwarded");
    ASSERT(notify_test_env_key_allowed("XCURSOR_THEME") == 1,
           "cursor key is forwarded");

    ASSERT(notify_test_env_key_allowed("LD_PRELOAD") == 0,
           "LD_PRELOAD is never forwarded");
    ASSERT(notify_test_env_key_allowed("LD_LIBRARY_PATH") == 0,
           "LD_LIBRARY_PATH is never forwarded");
    ASSERT(notify_test_env_key_allowed("PATH") == 0,
           "PATH is never forwarded");
    ASSERT(notify_test_env_key_allowed("QT_PLUGIN_PATH") == 0,
           "QT_PLUGIN_PATH is never forwarded");
    ASSERT(notify_test_env_key_allowed("QT_QPA_PLATFORM") == 0,
           "QT_QPA_PLATFORM is never forwarded");
    ASSERT(notify_test_env_key_allowed("DISPLAY") == 0,
           "DISPLAY is never forwarded");
    ASSERT(notify_test_env_key_allowed("WAYLAND_DISPLAY") == 0,
           "WAYLAND_DISPLAY is never forwarded");
    ASSERT(notify_test_env_key_allowed("DBUS_SESSION_BUS_ADDRESS") == 0,
           "session bus is never forwarded");

    /* Exact match only: no prefix or suffix tricks. */
    ASSERT(notify_test_env_key_allowed("XLD_PRELOAD") == 0,
           "prefixed key does not match");
    ASSERT(notify_test_env_key_allowed("LANGX") == 0,
           "suffixed key does not match");

    /* The one documented exception. */
    ASSERT(notify_test_env_key_allowed("QT_QPA_PLATFORMTHEME") == 1,
           "QT_QPA_PLATFORMTHEME is the documented exception");
}

/*
 * Run the verdict-stage seam in a child: an unsafe grant records the
 * per-process "first hit" gate for whatever pid asks, and the test binary
 * must not spend its own gate (test_unsafe_hit_once_per_process relies on
 * it).  The child inherits the in-memory session table and config.
 */
static int child_verdict(const char *binary, const char *sha,
                         const char *target, pid_t sid, int hardlink) {
    int status = 0;
    pid_t pid = fork();

    if (pid < 0)
        return -1;
    if (pid == 0)
        _exit(fanotify_test_verdict_stage(binary, sha, target, NULL, sid,
                                          hardlink));
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*
 * Part 0h: the verdict stages run denials before grants (a recorded
 * session deny must beat an unsafe grant), and hard-link events skip
 * every grant stage.
 */
static void test_verdict_stage_order(void) {
    static Config cfg;
    Config *saved = g_config;
    pid_t sid = 0;
    unsigned long long start = 0;

    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.unsafe_allowlist[0].binary,
             sizeof(cfg.unsafe_allowlist[0].binary), "/bin/tool");
    snprintf(cfg.unsafe_allowlist[0].target_path,
             sizeof(cfg.unsafe_allowlist[0].target_path), "/home/u/secret");
    cfg.unsafe_allowlist_count = 1;
    g_config = &cfg;
    session_clear();

    /* The unsafe rule grants when nothing denies. */
    ASSERT(child_verdict("/bin/tool", "", "/home/u/secret", 0, 0) == 2,
           "unsafe rule grants when nothing denies");

    /* Hard-link events must not inherit any grant. */
    ASSERT(child_verdict("/bin/tool", "", "/home/u/secret", 0, 1) == 0,
           "hard-link event skips every grant stage");

    /* A recorded session deny beats the unsafe grant. */
    ASSERT(session_id_of(getpid(), &sid, &start) == 0,
           "resolve own session");
    session_deny_add(sid, start, "/bin/tool", "", "/home/u/secret", 60);
    ASSERT(child_verdict("/bin/tool", "", "/home/u/secret", sid, 0) == 1,
           "session deny wins over an unsafe grant");

    session_clear();
    g_config = saved;
}

int main(void) {
    printf("=== test_fanotify ===\n");
    test_mark_mask_rejects_fid_events();
    test_mark_paths();
    test_scope_guard();
    test_recent_decision_cache();
    test_dialog_env_whitelist();
    test_verdict_stage_order();
    test_missing_path_is_skipped();
    test_glob_protected_verdict();
    test_glob_missing_base_is_skipped();
    test_exclusions_deny_wins();
    test_exclusion_is_not_marked();
    test_config_rule_matching();
    test_pin_first_seen_tofu();
    test_allowlist_pin_verdict_codes();
    test_pin_damaged_falls_through();
    test_unsafe_allowlist_skips_pins();
    test_hash_change_null_request_denies();
    test_notify_rate_windows();
    test_unsafe_hit_once_per_process();
    test_glob_deny_beats_glob_allow();
    test_deleted_suffix_stripped();
    test_incomplete_entries_grant_nothing();
    test_cmdline_scoping();
    test_cmdline_fingerprint_full();
    test_defer_flush_contract();
    test_drain_and_deny();
    test_kernel_bounded_queue_overflow();
    pin_fixture_cleanup();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
