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

/* Child-side: silence helper error output (callers treat non-zero as failure). */
static void silence_stderr(void)
{
    int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (devnull >= 0)
    {
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
}

/*
 * Reap the helper with a deadline.  Returns 0 and fills *status_out when
 * the child exited in time, -1 when it had to be killed after stalling.
 * A helper that wrote a digest but never exits is unconfirmable: the
 * caller treats the reap failure as a hashing failure (fail closed), so
 * a stuck child can never hold the event loop hostage while the
 * requesting process stays suspended.
 */
#define REAP_DEADLINE_S 2

static int reap_helper(pid_t pid, int *status_out)
{
    time_t deadline = time(NULL) + REAP_DEADLINE_S;

    for (;;)
    {
        int status = 0;
        pid_t w = waitpid(pid, status_out ? status_out : &status, WNOHANG);
        if (w == pid)
            return 0;
        if (w < 0 && errno != EINTR)
            return -1;
        if (time(NULL) >= deadline)
            break;
        usleep(10000); /* 10 ms tick */
    }

    log_msg(LOG_WARNING, "sha512: helper did not exit in %ds; killing",
            REAP_DEADLINE_S);
    kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
    return -1;
}

/*
 * Read sha512sum's stdout until EOF (or the buffer is full), enforce the
 * deadline, reap the child and validate the digest.  Output format:
 * "<128-hex-digits>  <filename>\n"; only the first 128 bytes are used.
 */
static int collect_digest(int fd, pid_t pid, char hex_out[129])
{
    char buf[200];
    ssize_t total = 0;
    time_t deadline = time(NULL) + SHA512_TIMEOUT_S;

    while (total < (ssize_t)sizeof(buf) - 1)
    {
        int remaining_ms = (int)(difftime(deadline, time(NULL)) * 1000.0);
        if (remaining_ms <= 0)
            break;

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, remaining_ms) <= 0)
            break;

        ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - (size_t)total);
        if (n <= 0)
            break;
        total += n;
    }
    close(fd);

    if (total < 128)
    {
        log_msg(LOG_ERR, "sha512: timed out or short read");
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
        return -1;
    }

    int status = 0;
    if (reap_helper(pid, &status) < 0)
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
        silence_stderr();
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
    return collect_digest(pipefd[0], pid, hex_out);
}

/* Write the whole buffer, retrying short writes.  SIGPIPE is blocked by
 * the caller so a dead helper surfaces as EPIPE instead of killing us. */
static int write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len)
    {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int sha512_string(const char *str, char hex_out[129])
{
    int inpipe[2], outpipe[2];

    if (!str)
        return -1;
    if (pipe2(inpipe, O_CLOEXEC) < 0)
        return -1;
    if (pipe2(outpipe, O_CLOEXEC) < 0)
    {
        close(inpipe[0]);
        close(inpipe[1]);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);
        return -1;
    }

    if (pid == 0)
    {
        close(inpipe[1]);
        close(outpipe[0]);
        /* sha512sum with no file argument hashes stdin. */
        if (dup2(inpipe[0], STDIN_FILENO) < 0)
            _exit(127);
        if (dup2(outpipe[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(inpipe[0]);
        close(outpipe[1]);
        silence_stderr();
        close_fds_from(3);
        execl("/usr/bin/sha512sum", "sha512sum", (char *)NULL);
        _exit(127);
    }

    close(inpipe[0]);
    close(outpipe[1]);

    /*
     * Block SIGPIPE while feeding the helper: if sha512sum is missing or
     * exits early, the write must surface as EPIPE.  A SIGPIPE generated
     * while blocked stays pending and would kill the caller when the mask
     * is restored, so consume it before unblocking.
     */
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGPIPE);
    sigprocmask(SIG_BLOCK, &block, &old);

    int w = write_all(inpipe[1], str, strlen(str));
    close(inpipe[1]); /* EOF for sha512sum */
    if (w == 0)
    {
        sigset_t pending;
        if (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE))
        {
            struct timespec zero = {0, 0};
            sigtimedwait(&block, NULL, &zero);
        }
    }
    sigprocmask(SIG_SETMASK, &old, NULL);

    if (w < 0)
    {
        close(outpipe[0]);
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
            ;
        return -1;
    }

    return collect_digest(outpipe[0], pid, hex_out);
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
