/*
 * test_reload: the SIGHUP reload decision path — parse failure, reject
 * with rollback, and rollback failure.
 *
 * Runs unprivileged with fan_fd = -1: every kernel mark fails, which is
 * exactly what drives the reject/rollback branches.  The success path
 * needs a real fanotify group and is covered by the root canary in
 * MARK-SCOPE-REDESIGN.md (history) / the rollout protocol.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/config.h"
#include "../src/reload.h"
#include "../src/utils.h"

/* Globals referenced by fanotify.c and reload.c (normally in main.c). */
volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;
volatile sig_atomic_t g_fatal = 0;

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

/* Write content to a temp file; the caller frees the returned path. */
static char *write_temp(const char *content)
{
    char tmpl[] = "/tmp/fileshield_reload_XXXXXX";
    size_t len = strlen(content);
    size_t written = 0;
    int fd = mkstemp(tmpl);

    if (fd < 0)
        return NULL;
    while (written < len)
    {
        ssize_t n = write(fd, content + written, len - written);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(tmpl);
            return NULL;
        }
        written += (size_t)n;
    }
    close(fd);
    return strdup(tmpl);
}

/*
 * Parse failure: the old config stays published and the caller continues.
 */
static void test_parse_failure_keeps_config(void)
{
    char *old_p = write_temp("[protected_paths]\n"
                             "/nonexistent/fileshield/reload-old\n");
    ASSERT(old_p != NULL, "write old config");

    Config old;
    memset(&old, 0, sizeof(old));
    ASSERT(config_load(old_p, &old) == 0, "load old config");

    Config *cfg = &old;
    g_config = &old;
    g_fatal = 0;

    ASSERT(reload_protection(-1, "/nonexistent/fileshield/reload.conf",
                             &cfg) == 0,
           "parse failure continues");
    ASSERT(cfg == &old, "parse failure keeps the old config");
    ASSERT(g_config == &old, "parse failure keeps g_config published");
    ASSERT(g_fatal == 0, "parse failure is not fatal");
    ASSERT(g_need_reload == 0, "reload request is consumed");

    config_reset(&old);
    unlink(old_p);
    free(old_p);
}

/*
 * Reject with successful rollback: the new config has an existing path
 * whose mark fails with fd = -1, so it is rejected; the old config has
 * only a missing path (skipped, not a failure), so the rollback succeeds
 * and the daemon keeps running on the old config.
 */
static void test_reject_rolls_back(void)
{
    char *old_p = write_temp("[protected_paths]\n"
                             "/nonexistent/fileshield/reload-old\n");
    char *new_p = write_temp("[protected_paths]\n"
                             "/dev\n");
    ASSERT(old_p != NULL && new_p != NULL, "write configs");

    Config old;
    memset(&old, 0, sizeof(old));
    ASSERT(config_load(old_p, &old) == 0, "load old config");

    Config *cfg = &old;
    g_config = &old;
    g_fatal = 0;

    ASSERT(reload_protection(-1, new_p, &cfg) == 0,
           "reject with rollback continues");
    ASSERT(cfg == &old, "rejected reload keeps the old config");
    ASSERT(g_config == &old, "rejected reload keeps g_config published");
    ASSERT(g_fatal == 0, "successful rollback is not fatal");

    config_reset(&old);
    unlink(old_p);
    unlink(new_p);
    free(old_p);
    free(new_p);
}

/*
 * Rollback failure: both configs protect an existing path, so the new
 * install fails and the rollback install fails too; the daemon must shut
 * down (systemd restarts from a clean state) with the old config still
 * published.
 */
static void test_failed_rollback_shuts_down(void)
{
    char *old_p = write_temp("[protected_paths]\n"
                             "/dev\n");
    char *new_p = write_temp("[protected_paths]\n"
                             "/dev\n");
    ASSERT(old_p != NULL && new_p != NULL, "write configs");

    Config old;
    memset(&old, 0, sizeof(old));
    ASSERT(config_load(old_p, &old) == 0, "load old config");

    Config *cfg = &old;
    g_config = &old;
    g_fatal = 0;

    ASSERT(reload_protection(-1, new_p, &cfg) == -1,
           "failed rollback requests shutdown");
    ASSERT(g_fatal == 1, "failed rollback sets g_fatal");
    ASSERT(cfg == &old, "failed rollback keeps the old config");
    ASSERT(g_config == &old, "failed rollback keeps g_config published");
    g_fatal = 0;

    config_reset(&old);
    unlink(old_p);
    unlink(new_p);
    free(old_p);
    free(new_p);
}

int main(void)
{
    printf("=== test_reload ===\n");
    test_parse_failure_keeps_config();
    test_reject_rolls_back();
    test_failed_rollback_shuts_down();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
