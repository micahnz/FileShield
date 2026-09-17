#include "control_client.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "persist.h"

/*
 * Client half of the control protocol (see control_client.h).  This
 * translation unit is linked into fileshield-cli and therefore must not
 * reference any daemon module or global: it depends on libc and
 * persist.c (persist_json_escape) only.
 */

/* ------------------------------------------------------------------ */
/* Field codec                                                        */
/* ------------------------------------------------------------------ */

int control_encode_field(const char *src, char *dst, size_t dst_size)
{
    /* One escaping convention for every state file, dialog and socket
     * field; a second implementation would be a place to disagree. */
    return persist_json_escape(src, dst, dst_size);
}

/* Hex digit value, or -1. */
static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Encode one code point as UTF-8; returns the byte count (1..4).
 * 0 < cp <= 0x10FFFF is guaranteed by the caller. */
static int utf8_encode(unsigned int cp, char out[4])
{
    if (cp < 0x80)
    {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800)
    {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000)
    {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

int control_decode_field(const char *src, char *dst, size_t dst_size)
{
    const char *p;
    size_t j = 0;

    if (!src || !dst || dst_size == 0)
        return -1;

    for (p = src; *p != '\0'; p++)
    {
        char add[4];
        int add_len;
        int k;

        if (*p != '\\')
        {
            unsigned char c = (unsigned char)*p;
            if (c < 0x20)
                return -1; /* raw control byte inside a JSON string */
            add[0] = (char)c;
            add_len = 1;
        }
        else
        {
            unsigned int code = 0;
            int d;

            p++;
            switch (*p)
            {
            case '"':
            case '\\':
            case '/':
                add[0] = *p;
                add_len = 1;
                break;
            case 'b':
                add[0] = '\b';
                add_len = 1;
                break;
            case 'f':
                add[0] = '\f';
                add_len = 1;
                break;
            case 'n':
                add[0] = '\n';
                add_len = 1;
                break;
            case 'r':
                add[0] = '\r';
                add_len = 1;
                break;
            case 't':
                add[0] = '\t';
                add_len = 1;
                break;
            case 'u':
                /* Exactly four hex digits: the encoder always emits four,
                 * so a short escape is a malformed field, not a value. */
                for (k = 0; k < 4; k++)
                {
                    d = hex_digit(p[1 + k]);
                    if (d < 0)
                        return -1;
                    code = (code << 4) | (unsigned int)d;
                }
                p += 4; /* p now points at the last hex digit */
                if (code == 0)
                    return -1; /* \u0000 cannot live in a C string */
                if (code >= 0xD800 && code <= 0xDBFF)
                {
                    /* A high surrogate must be followed by the low half
                     * of its pair; a lone surrogate is invalid UTF-8. */
                    unsigned int low = 0;
                    if (p[1] != '\\' || p[2] != 'u')
                        return -1;
                    for (k = 0; k < 4; k++)
                    {
                        d = hex_digit(p[3 + k]);
                        if (d < 0)
                            return -1;
                        low = (low << 4) | (unsigned int)d;
                    }
                    if (low < 0xDC00 || low > 0xDFFF)
                        return -1;
                    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                    p += 6; /* past the low half's "\uXXXX" */
                }
                else if (code >= 0xDC00 && code <= 0xDFFF)
                {
                    return -1; /* lone low surrogate */
                }
                add_len = utf8_encode(code, add);
                break;
            default:
                return -1; /* unknown escape sequence */
            }
        }

        if (j + (size_t)add_len > dst_size - 1)
            return -1; /* value does not fit */
        memcpy(dst + j, add, (size_t)add_len);
        j += (size_t)add_len;
    }

    dst[j] = '\0';
    return (int)j;
}

/* ------------------------------------------------------------------ */
/* Response parsing                                                   */
/* ------------------------------------------------------------------ */

/* Offset of the next '\n' at or after 'from'; 0 on success. */
static int line_end(const char *text, size_t len, size_t from, size_t *nl_out)
{
    for (size_t i = from; i < len; i++)
    {
        if (text[i] == '\n')
        {
            *nl_out = i;
            return 0;
        }
    }
    return -1;
}

int control_response_parse(char *text, size_t len, ControlResponse *out)
{
    size_t pos;
    size_t end;

    if (!text || !out || len == 0)
        return -1;
    memset(out, 0, sizeof(*out));

    if (len >= 3 && memcmp(text, "OK\n", 3) == 0)
    {
        long count = 0;

        pos = 3;
        if (line_end(text, len, pos, &end) < 0 || end == pos)
            return -1; /* no count line, or an empty one */
        for (size_t i = pos; i < end; i++)
        {
            if (text[i] < '0' || text[i] > '9')
                return -1;
            if (count > (LONG_MAX - 9) / 10)
                return -1;
            count = count * 10 + (text[i] - '0');
        }
        if (count > CONTROL_PAYLOAD_MAX)
            return -1;
        text[end] = '\0';
        out->ok = 1;
        out->count = (int)count;

        pos = end + 1;
        for (int i = 0; i < out->count; i++)
        {
            if (line_end(text, len, pos, &end) < 0)
                return -1; /* fewer payload lines than promised */
            text[end] = '\0';
            out->lines[i] = text + pos;
            pos = end + 1;
        }
        if (pos != len)
            return -1; /* trailing bytes: not exactly <count> lines */
        return 0;
    }

    if (len >= 4 && memcmp(text, "ERR\n", 4) == 0)
    {
        pos = 4;
        if (line_end(text, len, pos, &end) < 0)
            return -1;
        text[end] = '\0';
        out->ok = 0;
        out->count = 0;
        out->message = text + pos;
        if (end + 1 != len)
            return -1; /* trailing bytes after the message line */
        return 0;
    }

    return -1;
}

long control_response_scalar(const ControlResponse *resp)
{
    const char *p;
    long value = 0;
    int digits = 0;

    if (!resp || !resp->ok || resp->count != 1 || !resp->lines[0])
        return -1;

    p = resp->lines[0];
    for (; *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
            return -1; /* counts are non-negative plain decimals */
        if (value > (LONG_MAX - (*p - '0')) / 10)
            return -1;
        value = value * 10 + (*p - '0');
        digits++;
    }
    if (digits == 0)
        return -1;
    return value;
}

/* ------------------------------------------------------------------ */
/* Client                                                             */
/* ------------------------------------------------------------------ */

/* Blocking send of the request plus its newline.  The CLI socket is
 * blocking: a stuck daemon must surface as a slow command, not as a
 * silently dropped request. */
static int client_send_line(int fd, const char *request)
{
    size_t len = strlen(request);
    size_t off = 0;

    while (off < len)
    {
        ssize_t n = send(fd, request + off, len - off, MSG_NOSIGNAL);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }
    if (send(fd, "\n", 1, MSG_NOSIGNAL) != 1)
        return -1;
    return 0;
}

int control_client_call(const char *sock_path, const char *request,
                        char *resp_buf, size_t resp_size,
                        ControlResponse *out)
{
    struct sockaddr_un addr;
    size_t path_len;
    int fd;
    int saved_errno = 0;
    size_t used = 0;
    int rc = -1;

    if (!sock_path || sock_path[0] == '\0' || !request || !resp_buf ||
        resp_size < 2 || !out)
        return -1;

    path_len = strlen(sock_path);
    if (path_len >= sizeof(addr.sun_path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sock_path, path_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (client_send_line(fd, request) < 0)
    {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    /* Half-close: the request is complete, so the daemon must not see a
     * slow writer behind it.  Failures are harmless (the daemon reads
     * the newline either way). */
    (void)shutdown(fd, SHUT_WR);

    for (;;)
    {
        ssize_t got;

        if (used == resp_size - 1)
        {
            /* The buffer is full: one more byte decides between an exact
             * fit (EOF) and a response too large for the caller. */
            char extra;

            got = recv(fd, &extra, 1, 0);
            if (got < 0 && errno == EINTR)
                continue;
            if (got > 0)
            {
                saved_errno = ENOBUFS;
                goto fail;
            }
            if (got < 0)
            {
                saved_errno = errno;
                goto fail;
            }
            break;
        }

        got = recv(fd, resp_buf + used, resp_size - 1 - used, 0);
        if (got < 0)
        {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            goto fail;
        }
        if (got == 0)
            break;
        used += (size_t)got;
    }

    resp_buf[used] = '\0';
    if (control_response_parse(resp_buf, used, out) < 0)
    {
        saved_errno = EPROTO;
        goto fail;
    }

    rc = 0;
    saved_errno = 0;

fail:
    close(fd);
    if (rc < 0 && saved_errno != 0)
        errno = saved_errno;
    return rc;
}
