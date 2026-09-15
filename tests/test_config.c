#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

#include "../src/config.h"
#include "../src/utils.h"

static int failures = 0;

#define ASSERT(cond, msg)                       \
    do                                          \
    {                                           \
        if (!(cond))                            \
        {                                       \
            fprintf(stderr, "FAIL: %s\n", msg); \
            failures++;                         \
        }                                       \
    } while (0)

static char *write_temp(const char *content)
{
    char tmpl[] = "/tmp/fileshield_test_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return NULL;
    if (write(fd, content, strlen(content)) < 0)
    {
        close(fd);
        unlink(tmpl);
        return NULL;
    }
    close(fd);
    return strdup(tmpl);
}

static void test_basic_parse(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/etc/ssh/ssh_config\n" /* absolute paths — no per-user expansion */
        "/etc/ssl/certs\n"
        "# comment line\n"
        "\n"
        "[allowlist]\n"
        "/usr/bin/ssh = /etc/ssl/certs\n"
        "/usr/bin/git\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load success");

    ASSERT(cfg.protected_count == 2, "2 protected paths");
    ASSERT(strstr(cfg.protected[0].path, "ssh_config") != NULL, "first path ssh_config");
    ASSERT(strstr(cfg.protected[1].path, "certs") != NULL, "second path certs");

    ASSERT(cfg.allowlist_count == 2, "2 allowlist entries");
    ASSERT(strcmp(cfg.allowlist[0].binary, "/usr/bin/ssh") == 0, "allowlist ssh binary");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/etc/ssl/certs") == 0,
           "allowlist ssh target");
    ASSERT(strcmp(cfg.allowlist[1].binary, "/usr/bin/git") == 0, "allowlist git binary");
    ASSERT(cfg.allowlist[1].target_path[0] == '\0', "bare entry is a global rule");

    config_reset(&cfg);
    ASSERT(cfg.protected_count == 0, "config_reset zeros count");
    ASSERT(cfg.allowlist_count == 0, "config_reset zeros allowlist count");

    unlink(path);
    free(path);
}

static void test_missing_file(void)
{
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load("/nonexistent/fileshield_test.conf", &cfg) == -1, "missing file fails");
}

static void test_unknown_section(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/ok\n"
        "[bogus]\n"
        "/tmp/ignored\n"
        "[allowlist]\n"
        "/usr/bin/x = /tmp/ok\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    config_load(path, &cfg);
    ASSERT(cfg.protected_count == 1, "ignores unknown section paths");
    ASSERT(cfg.allowlist_count == 1, "allowlist under unknown section still parsed");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_settings_user_ttl(void)
{
    const char *conf =
        "[settings]\n"
        "user_ttl = 120\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for settings");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load settings success");
    ASSERT(cfg.user_ttl_seconds == 120, "user_ttl parsed correctly");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_settings_session_ttl(void)
{
    const char *conf =
        "[settings]\n"
        "user_ttl = 120\n"
        "session_ttl = 0\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for session settings");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load session settings success");
    ASSERT(cfg.user_ttl_seconds == 120, "user_ttl parsed alongside session_ttl");
    ASSERT(cfg.session_ttl_seconds == 0, "session_ttl 0 (leader lifetime) parsed");

    config_reset(&cfg);
    ASSERT(cfg.session_ttl_seconds == 0, "config_reset clears session_ttl");

    unlink(path);
    free(path);
}

static void test_settings_session_ttl_value(void)
{
    const char *conf =
        "[settings]\n"
        "session_ttl = 900\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for session_ttl value");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    config_load(path, &cfg);
    ASSERT(cfg.session_ttl_seconds == 900, "session_ttl value parsed");
    /* Absent session_ttl must default to 0, not inherit user_ttl. */
    ASSERT(cfg.user_ttl_seconds == 0, "user_ttl absent defaults to 0");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_settings_invalid_session_ttl(void)
{
    const char *conf =
        "[settings]\n"
        "session_ttl = -5\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for invalid session_ttl");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    config_load(path, &cfg);
    ASSERT(cfg.session_ttl_seconds == 0, "invalid session_ttl not applied");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_settings_invalid_user_ttl(void)
{
    const char *conf =
        "[settings]\n"
        "user_ttl = -5\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for invalid settings");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.user_ttl_seconds = 0; /* default — should stay 0 on invalid value */

    config_load(path, &cfg);
    ASSERT(cfg.user_ttl_seconds == 0, "invalid user_ttl not applied");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Absurd TTL values must be clamped (to one year) so cache expiry
 * arithmetic cannot overflow on any time_t width.
 */
static void test_ttl_clamping(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/ttl_clamp_test\n"
        "[settings]\n"
        "user_ttl = 2000000000\n"
        "session_ttl = 2000000000\n"
        "[allowlist]\n"
        "/usr/bin/huge = /tmp/ttl_clamp_test\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for ttl clamp");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load ttl clamp success");
    ASSERT(cfg.allowlist_count == 1, "allowlist parsed for ttl clamp");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/tmp/ttl_clamp_test") == 0,
           "allowlist target parsed");
    ASSERT(cfg.user_ttl_seconds == 31536000, "user_ttl clamped to one year");
    ASSERT(cfg.session_ttl_seconds == 31536000, "session_ttl clamped to one year");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

static void test_whitespace_lines(void)
{
    const char *conf =
        "   \n"
        "\t\n"
        "[protected_paths]\n"
        "/etc/ssh/ssh_config\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config with whitespace lines");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load with whitespace lines succeeds");
    ASSERT(cfg.protected_count == 1, "whitespace lines ignored");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Paths must be canonicalized at load time so symlinked protected
 * directories cannot bypass path matching in the daemon.
 */
static void test_path_canonicalization(void)
{
    char real_dir[128];
    char link_dir[128];
    char conf[2048];
    char target[512];

    snprintf(real_dir, sizeof(real_dir), "/tmp/fileshield_canon_real_%d", (int)getpid());
    snprintf(link_dir, sizeof(link_dir), "/tmp/fileshield_canon_link_%d", (int)getpid());

    ASSERT(mkdir(real_dir, 0700) == 0, "create real dir");
    unlink(link_dir);
    ASSERT(symlink(real_dir, link_dir) == 0, "create symlink");

    snprintf(target, sizeof(target), "%s/secret", link_dir);
    snprintf(conf, sizeof(conf),
             "[protected_paths]\n"
             "%s\n"
             "[allowlist]\n"
             "%s/bin = %s\n",
             target, link_dir, target);

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write symlink config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load with symlink succeeds");
    ASSERT(cfg.protected_count == 1, "symlink config protected count");
    ASSERT(strncmp(cfg.protected[0].path, real_dir, strlen(real_dir)) == 0,
           "protected path canonicalized through symlink");
    ASSERT(strstr(cfg.protected[0].path, "secret") != NULL,
           "canonicalized protected basename preserved");
    ASSERT(cfg.allowlist_count == 1, "symlink config allowlist count");
    ASSERT(strncmp(cfg.allowlist[0].binary, real_dir, strlen(real_dir)) == 0,
           "allowlist path canonicalized through symlink");
    ASSERT(strncmp(cfg.allowlist[0].target_path, real_dir, strlen(real_dir)) == 0,
           "allowlist target canonicalized through symlink");

    config_reset(&cfg);
    unlink(path);
    free(path);
    unlink(link_dir);
    rmdir(real_dir);
}

/*
 * Legacy-format safety: "binary = ttl_seconds" entries must be rejected
 * with a warning, and an '=' with an empty right side is a parse error.
 * Neither may produce a rule.
 */
static void test_rule_rejection(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/rej\n"
        "[allowlist]\n"
        "/usr/bin/old = 3600\n"
        "/usr/bin/empty =\n"
        "/usr/bin/ok = /tmp/rej\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for rule rejection");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load succeeds with skipped lines");
    ASSERT(cfg.allowlist_count == 1, "only the valid rule survives");
    ASSERT(strcmp(cfg.allowlist[0].binary, "/usr/bin/ok") == 0,
           "surviving rule is the scoped one");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * [denylist] parses the same format as [allowlist]: scoped rules and
 * bare global rules, with multiple targets for the same binary.
 */
static void test_denylist_parse(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/deny\n"
        "[denylist]\n"
        "/usr/bin/curl = /tmp/deny\n"
        "/usr/bin/curl = /tmp/other\n"
        "/usr/bin/nc\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for denylist");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load denylist success");
    ASSERT(cfg.denylist_count == 3, "3 denylist entries");
    ASSERT(strcmp(cfg.denylist[0].binary, "/usr/bin/curl") == 0,
           "denylist curl binary");
    ASSERT(strcmp(cfg.denylist[0].target_path, "/tmp/deny") == 0,
           "denylist first target");
    ASSERT(strcmp(cfg.denylist[1].target_path, "/tmp/other") == 0,
           "denylist second target for the same binary");
    ASSERT(strcmp(cfg.denylist[2].binary, "/usr/bin/nc") == 0,
           "denylist global binary");
    ASSERT(cfg.denylist[2].target_path[0] == '\0', "bare deny entry is global");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * Trailing slashes on a target are stripped at parse time so matching
 * is uniformly "equal or under".
 */
static void test_target_trailing_slash(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/slash_test/\n"
        "[allowlist]\n"
        "/usr/bin/tool = /tmp/slash_test/\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for trailing slash");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load trailing slash success");
    ASSERT(cfg.allowlist_count == 1, "trailing slash entry parsed");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/tmp/slash_test") == 0,
           "trailing slash stripped from target");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * 'Binary = target' where the target does not exist yet keeps its
 * basename (canonicalize_path resolves the parent).
 */
static void test_scoped_missing_target(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/rule_missing/secret\n"
        "[allowlist]\n"
        "/usr/bin/app = /tmp/rule_missing/secret\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for missing target");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load missing target success");
    ASSERT(cfg.allowlist_count == 1, "missing-target rule parsed");
    ASSERT(strcmp(cfg.allowlist[0].target_path, "/tmp/rule_missing/secret") == 0,
           "missing target keeps parent resolution");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

/*
 * config_load() must not publish the parsed Config through g_config: the
 * caller decides whether the config is accepted.  main.c frees a config
 * whose reload was rejected, so publishing inside config_load() would
 * leave g_config dangling (use-after-free on the next event).
 */
static void test_config_load_does_not_publish_global(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/config_publish_test\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for publish test");

    /* static: Config is several MB (fixed PATH_MAX arrays); a second
     * stack copy alongside `cfg` overflows the default 8 MB stack. */
    static Config sentinel;
    Config *saved = g_config;
    g_config = &sentinel;

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load publish test success");
    ASSERT(g_config == &sentinel,
           "config_load must not publish the parsed config through g_config");

    g_config = saved;
    config_reset(&cfg);
    unlink(path);
    free(path);
}

int main(void)
{
    printf("=== test_config ===\n");
    test_basic_parse();
    test_missing_file();
    test_unknown_section();
    test_settings_user_ttl();
    test_settings_session_ttl();
    test_settings_session_ttl_value();
    test_settings_invalid_session_ttl();
    test_settings_invalid_user_ttl();
    test_ttl_clamping();
    test_whitespace_lines();
    test_path_canonicalization();
    test_rule_rejection();
    test_denylist_parse();
    test_target_trailing_slash();
    test_scoped_missing_target();
    test_config_load_does_not_publish_global();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
