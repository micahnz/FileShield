#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>

#include "../src/utils.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } \
} while(0)

static void test_path_under(void) {
    ASSERT(path_under("/home/user/.ssh/id_rsa", "/home/user/.ssh") == 1, "file inside dir");
    ASSERT(path_under("/home/user/.ssh", "/home/user/.ssh") == 1, "exact match");
    ASSERT(path_under("/home/user/.ssh/", "/home/user/.ssh") == 1, "trailing slash same");
    ASSERT(path_under("/home/user/.sshd", "/home/user/.ssh") == 0, "prefix but not under");
    ASSERT(path_under("/home/user/.ssh", "/home/user/.aws") == 0, "different dir");
    ASSERT(path_under("/etc/passwd", "/") == 1, "everything under root");
    ASSERT(path_under("/", "/") == 1, "root equals root");
    ASSERT(path_under("", "/") == 0, "empty path not under root");
}

static void test_path_under_len(void) {
    ASSERT(path_under_len("/a/b/c", "/a/b", 4) == 1, "under with explicit length");
    ASSERT(path_under_len("/a/bc", "/a/b", 4) == 0, "boundary with explicit length");
    ASSERT(path_under_len("/a/b", "/a/b", 4) == 1, "equal with explicit length");
    ASSERT(path_under_len("/x/y", "/a/b", 4) == 0, "different prefix");
}

static void assert_glob_base(const char *pattern, const char *want, const char *msg) {
    int got = glob_base_len(pattern);
    size_t want_len = strlen(want);
    if (got != (int)want_len ||
        (want_len > 0 && memcmp(pattern, want, want_len) != 0)) {
        fprintf(stderr, "FAIL: %s: glob_base_len(%s) = %d, want %s\n",
                msg, pattern, got, want);
        failures++;
    }
}

static void test_glob_base_len(void) {
    assert_glob_base("/home/user/.cloudflared/*.json",
                     "/home/user/.cloudflared", "file glob base");
    assert_glob_base("/home/user/.cloudflared/**/*.json",
                     "/home/user/.cloudflared", "globstar base");
    assert_glob_base("/home/user/.config/*/config.json",
                     "/home/user/.config", "mid glob base");
    assert_glob_base("/foo/bar*", "/foo", "partial-segment base");
    assert_glob_base("/*.json", "/", "root-child base");
    assert_glob_base("/", "/", "root base");
    assert_glob_base("/home/user/.ssh/config", "/home/user/.ssh/config",
                     "no-wildcard base is the whole path");
    assert_glob_base("*.json", "", "first-segment wildcard has no base");
}

static void assert_glob(const char *pattern, const char *path, int want,
                        const char *msg) {
    int got = glob_match_path(pattern, path);
    if (got != want) {
        fprintf(stderr, "FAIL: %s: glob_match_path(%s, %s) = %d, want %d\n",
                msg, pattern, path, got, want);
        failures++;
    }
}

static void test_glob_match(void) {
    /* '*' stays inside one segment, matches dotfiles, honors the tail. */
    assert_glob("/a/*.json", "/a/x.json", 1, "star file match");
    assert_glob("/a/*.json", "/a/.x.json", 1, "star matches dotfiles");
    assert_glob("/a/*.json", "/a/x/y.json", 0, "star does not cross slash");
    assert_glob("/a/*.json", "/a/x.json.bak", 0, "star respects literal tail");
    assert_glob("/a/*.json", "/a/", 0, "empty segment does not match file glob");

    /* '**' matches zero or more whole segments. */
    assert_glob("/a/**/*.json", "/a/x.json", 1, "globstar zero segments");
    assert_glob("/a/**/*.json", "/a/b/x.json", 1, "globstar one segment");
    assert_glob("/a/**/*.json", "/a/b/c/x.json", 1, "globstar many segments");
    assert_glob("/a/**/*.json", "/a/b/x.txt", 0, "globstar needs matching tail");
    assert_glob("/a/**", "/a", 1, "trailing globstar matches base itself");
    assert_glob("/a/**", "/a/b/c", 1, "trailing globstar matches subtree");
    assert_glob("/a/**/b", "/a/b", 1, "mid globstar zero segments");
    assert_glob("/a/**/b", "/a/x/y/b", 1, "mid globstar many segments");
    assert_glob("/a/**/b", "/a/x/y/c", 0, "mid globstar literal tail");
    assert_glob("/**/b", "/a/b", 1, "leading globstar");
    assert_glob("/**/b", "/b", 1, "leading globstar zero segments");
    assert_glob("/a/**/**/b", "/a/x/y/b", 1, "repeated globstar");

    /* Star runs collapse; '?' and '[' ']' are literal. */
    assert_glob("/a/ab**cd", "/a/abXYZcd", 1, "star run collapses");
    assert_glob("/a/ab**cd", "/a/ab/cd", 0, "star run stays in segment");
    assert_glob("/a/x?y", "/a/x?y", 1, "'?' is literal");
    assert_glob("/a/x?y", "/a/xay", 0, "'?' does not wildcard");
    assert_glob("/a/[ab]", "/a/[ab]", 1, "'[]' are literal");
    assert_glob("/a/[ab]", "/a/a", 0, "'[]' do not wildcard");

    /* Full-path, case-sensitive semantics. */
    assert_glob("/a/b", "/a/b/c", 0, "no prefix/subtree semantics");
    assert_glob("/a/b", "/a/bc", 0, "segment boundary respected");
    assert_glob("/A/B", "/a/b", 0, "case-sensitive");
    assert_glob("/a/x*", "/a/x", 1, "trailing star matches empty");
    assert_glob("/a/x*", "/a/", 0, "star cannot fill an empty segment alone");
}

static void test_proc_exe(void) {
    char *exe = proc_exe_path(getpid());
    ASSERT(exe != NULL, "proc_exe_path returns non-NULL for own pid");
    if (exe) {
        ASSERT(strstr(exe, "test_utils") != NULL, "exe path contains test name");
        free(exe);
    }

    exe = proc_exe_path(999999);
    ASSERT(exe == NULL, "proc_exe_path returns NULL for invalid pid");
}

static void test_proc_helpers(void) {
    char comm[64];
    char cmdline[512];
    pid_t self = getpid();

    ASSERT(get_ppid(self) > 0, "own ppid readable");
    ASSERT(read_comm(self, comm, sizeof(comm)) == 0, "own comm readable");
    ASSERT(strlen(comm) > 0, "own comm non-empty");
    ASSERT(read_cmdline(self, cmdline, sizeof(cmdline)) > 0,
           "own cmdline readable");
    ASSERT(strstr(cmdline, "test_utils") != NULL,
           "cmdline contains the test binary name");

    ASSERT(get_ppid(999999) == 0, "invalid pid yields ppid 0");
    ASSERT(read_comm(999999, comm, sizeof(comm)) == -1,
           "invalid pid comm fails");
    ASSERT(read_cmdline(999999, cmdline, sizeof(cmdline)) == -1,
           "invalid pid cmdline fails");
}

int main(void) {
    printf("=== test_utils ===\n");
    test_path_under();
    test_path_under_len();
    test_glob_base_len();
    test_glob_match();
    test_proc_exe();
    test_proc_helpers();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
