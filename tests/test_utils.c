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
    test_proc_exe();
    test_proc_helpers();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
