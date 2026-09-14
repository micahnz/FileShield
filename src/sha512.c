#include "sha512.h"
#include "utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Upper bound on hashing a single executable before the helper is killed. */
#define SHA512_TIMEOUT_S 15

int sha512_file(const char *path, char hex_out[129])
{
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0)
    {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(pipefd[1]);
        /* Silence error output — callers treat a non-zero exit as failure. */
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0)
        {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        /* Do not leak the daemon's fanotify/event/pipe fds into the helper. */
        close_fds_from(3);
        /*
         * Pass the path as a separate argument — no shell involved, so
         * no command-injection risk regardless of the path content.
         */
        execl("/usr/bin/sha512sum", "sha512sum", "--", path, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);

    /*
     * Read sha512sum's stdout until EOF (or the buffer is full).  Output
     * format: "<128-hex-digits>  <filename>\n"; only the first 128 bytes
     * are used.  The deadline stops a helper that is stuck on a hung or
     * very large file from blocking the daemon's event loop forever.
     */
    char buf[200];
    ssize_t total = 0;
    time_t deadline = time(NULL) + SHA512_TIMEOUT_S;

    while (total < (ssize_t)sizeof(buf) - 1)
    {
        int remaining_ms = (int)(difftime(deadline, time(NULL)) * 1000.0);
        if (remaining_ms <= 0)
            break;

        struct pollfd pfd;
        pfd.fd = pipefd[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, remaining_ms) <= 0)
            break;

        ssize_t n = read(pipefd[0], buf + total,
                         sizeof(buf) - 1 - (size_t)total);
        if (n <= 0)
            break;
        total += n;
    }
    close(pipefd[0]);

    if (total < 128)
    {
        log_msg(LOG_ERR, "sha512_file: timed out or short read on %s", path);
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
        return -1;
    }

    int status = 0;
    int w;
    while ((w = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
        ;
    if (w < 0)
        return -1;

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;

    /* Validate: first 128 chars must all be hex digits. */
    for (int i = 0; i < 128; i++)
    {
        if (!isxdigit((unsigned char)buf[i]))
            return -1;
    }

    memcpy(hex_out, buf, 128);
    hex_out[128] = '\0';
    return 0;
}

/*
 * Hash the executable of process 'pid' via /proc/<pid>/exe.
 * This path is always accessible from the host as root, even when the process
 * lives inside a container (Podman/Docker) whose root filesystem is an overlay
 * mount not visible under the path returned by proc_exe_path().
 */
int sha512_proc_exe(pid_t pid, char hex_out[129])
{
    char proc_path[64];
    int n = snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", (int)pid);
    if (n < 0 || (size_t)n >= sizeof(proc_path))
        return -1;
    return sha512_file(proc_path, hex_out);
}
