# Debugging

## Logs

Fileshield writes all events to the system journal via `syslog(3)` under the `LOG_DAEMON` facility and the identifier `fileshield`.

### Log verbosity

By default Fileshield logs **one line per access**: a rule hit logs which list allowed/denied it (first access per TTL window — repeats are silent), and a dialog access logs the prompt plus a human-readable choice:

```text
dynamic allowlist hit: /usr/bin/md5sum (pid 108385) -> ~/.kube/config
[dialog] asking user: pid=108783 binary=/usr/bin/cat target=~/.kube/config comm=cat
[dialog] user chose Allow Once for /usr/bin/cat (pid 108783) -> ~/.kube/config
```

The per-event plumbing (`[event]`, `[dedup]`, `[pump]`, display-env forwarding) is `LOG_DEBUG`, suppressed by default. Enable with `debug = yes` in `[settings]` or `--debug`.

### Log levels

| Level     | Events                                                                                                                                              |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `INFO`    | Start/stop, config load, marks added/removed, reload, one line per access, config allowlist first-use pins                                          |
| `DEBUG`   | Per-event plumbing: raw events, dedup reuse, pump decisions, dialog lifecycle. Suppressed unless `debug = yes` or `--debug`                         |
| `WARNING` | `[unsafe_allowlist]` grants (first per process), failed marks, dialog timeout, session detection unavailable, digest unavailable, hash-change prompts |
| `ERR`     | `fanotify_init` failure, config parse error or limit overflow, untrackable mark, fork/exec failure, sha512 helper timeout, damaged pin file          |

### Following and querying logs

```bash
# Live events
journalctl -u fileshield -f

# Since last boot
journalctl -u fileshield -b

# Last 100 lines
journalctl -u fileshield -n 100

# Errors only
journalctl -u fileshield -p err

# Time range
journalctl -u fileshield --since "2026-05-26 09:00" --until "2026-05-26 10:00"
```

## Foreground Mode

To see all log output directly without systemd, stop the service and run in the foreground:

```bash
sudo systemctl stop fileshield
sudo ./build/fileshield --foreground --config fileshield.conf
```

When stderr is attached to a terminal, `syslog` messages are also printed there. Combine with `strace`:

```bash
sudo strace -e trace=fanotify_init,fanotify_mark,read,write \
    ./build/fileshield --foreground --config fileshield.conf
```

## AddressSanitizer / UBSan Build

```bash
make debug
sudo ./build/fileshield --foreground --config fileshield.conf
```

Builds with `-O0 -g -fsanitize=address,undefined` and prints memory errors or undefined behaviour to stderr immediately.

## Preflight with `--dry-run`

`--dry-run` parses the config, prints every mark the daemon would install (including the init-namespace path for mount marks), runs the startup scope guard, and exits without touching the kernel:

```bash
sudo ./build/fileshield --dry-run --config fileshield.conf
```

## Running Tests

```bash
# All tests
make test

# Static analysis
make lint

# Hot-path microbenchmarks
make bench
```

Tests require no root and no kernel fanotify support (the kernel saturation test self-skips without `CAP_SYS_ADMIN`).
