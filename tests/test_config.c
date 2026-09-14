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
        "/usr/bin/ssh = 3600\n"
        "/usr/bin/git = 300\n";

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
    ASSERT(cfg.allowlist[0].ttl_seconds == 3600, "allowlist ssh ttl");
    ASSERT(strcmp(cfg.allowlist[1].binary, "/usr/bin/git") == 0, "allowlist git binary");
    ASSERT(cfg.allowlist[1].ttl_seconds == 300, "allowlist git ttl");

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
        "/usr/bin/x = 60\n";

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
        "[allowlist]\n"
        "/usr/bin/huge = 999999999\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config for ttl clamp");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load ttl clamp success");
    ASSERT(cfg.allowlist_count == 1, "allowlist parsed for ttl clamp");
    ASSERT(cfg.allowlist[0].ttl_seconds == 31536000, "allowlist TTL clamped to one year");
    ASSERT(cfg.user_ttl_seconds == 31536000, "user_ttl clamped to one year");

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
    char conf[1024];
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
             "%s/bin = 60\n",
             target, link_dir);

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

    config_reset(&cfg);
    unlink(path);
    free(path);
    unlink(link_dir);
    rmdir(real_dir);
}

int main(void)
{
    printf("=== test_config ===\n");
    test_basic_parse();
    test_missing_file();
    test_unknown_section();
    test_settings_user_ttl();
    test_settings_invalid_user_ttl();
    test_ttl_clamping();
    test_whitespace_lines();
    test_path_canonicalization();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
