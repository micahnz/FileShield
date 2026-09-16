# Mark-scope redesign — safe plan after the 2026-09-16 freeze

Status: **proposal — nothing in this document is implemented.**
Read together with the "Mark scope safety" section in `AGENTS.md`, which records
the incident this plan exists to prevent repeating.

---

## 1. Incident summary

A build that preferred `FAN_MARK_FILESYSTEM` over `FAN_MARK_MOUNT` was installed
on a machine where `/` and `/home` share one btrfs filesystem (subvolumes `@`
and `@home`). A filesystem mark is superblock-scoped, so the daemon became the
permission gate for **every open on the system**. Immediately after the marks
were installed it opened its own state files in `/var/lib/fileshield/`; that
open generated a permission event only the daemon could answer, and the daemon
was single-threaded and blocked inside the open. The machine froze.

Two independent mistakes, both now design constraints:

1. Mark scope was widened without an empirical root test.
2. The daemon's load order allowed its own opens to be intercepted.

## 2. Constraints

- **C1 — Coverage.** User processes live in the init mount namespace; their opens
  must generate events for protected paths.
- **C2 — Bounded scope.** Never intercept more than the mounts/filesystems that
  actually contain protected paths. Superblock scope is fatal when the
  filesystem contains `/` (btrfs subvolumes, single-partition systems).
- **C3 — No self-blocking.** The daemon must never have an `open()` in flight on
  a marked object, and every wait loop must answer self/child/dialog events.
- **C4 — Fail closed, not fatal.** A bad mark configuration must abort startup
  with a clear error, never deadlock the machine.
- **C5 — Reversible.** Keep the previous known-good binary hash and a stop path
  that does not depend on the GUI.
- **C6 — Testable.** Every scope-affecting change lands behind a root test on
  disposable hardware first.

## 3. Verified technical facts

- **F1.** Mount marks attach to the `struct mount`:
  `fs/notify/mark.c` — `FSNOTIFY_OBJ_TYPE_VFSMOUNT` →
  `real_mount(obj)->mnt_fsnotify_marks`.
- **F2.** Mount-namespace copies do **not** inherit marks: `clone_mnt()`
  (`fs/namespace.c`) copies no fsnotify state, and no file under `fs/notify`
  contains clone/propagation logic. Therefore a mark placed in the daemon's
  private mount namespace is invisible to opens made through init-namespace
  mounts. (This is why the shipped unit's `ProtectSystem=`/`ProtectProc=`/
  `PrivateDevices=` sandbox silently neuters mount marks.)
- **F3.** `FAN_MARK_FILESYSTEM` maps to the superblock
  (`FSNOTIFY_OBJ_TYPE_SB`) and delivers events from every mount and namespace,
  at the price of whole-filesystem scope — all subvolumes included.
- **F4.** systemd creates a private mount namespace whenever any mount-based
  sandbox option is used (`setup_namespace()` calls `unshare(CLONE_NEWNS)`).
  `PrivateMounts=no` does not undo `ProtectSystem=`.
- **F5.** `fanotify(7)`: closing the group fd **allows** outstanding permission
  events; a single-threaded listener blocked in `open()` on a marked object can
  never answer its own event.
- **F6.** `FAN_MARK_MNTNS` (kernel 6.14+) marks a whole mount namespace. It
  broadens coverage (e.g. into nested namespaces) but not scope — the init
  namespace contains every mount, so it is a coverage primitive, not a scope
  fix.
- **F7.** `st_dev` does not identify a mount: on btrfs, `/` and `/home` are
  different mounts (subvolumes) that share one device. Mount identity must come
  from the mount ID (`statx(STATX_MNT_ID)`, Linux 5.8+; fallback: parse
  `/proc/self/mountinfo`).

## 4. Options considered

| Option | Coverage | Sandbox | Risk | Verdict |
| --- | --- | --- | --- | --- |
| **A. Mount marks, no mount-namespace sandbox** | init-ns user processes | reduced (seccomp/caps kept) | low | fallback (exp1 confirms it is needed) |
| **B. Mount marks placed via `/proc/1/root/...`** | init-ns user processes | preserved | validated by exp2 + exp2p | **recommended primary** |
| **C. Filesystem marks, opt-in, guarded** | init + nested namespaces on a dedicated fs | preserved | medium | future opt-in, never on root fs |
| **D. Helper outside the sandbox performs marking** | init-ns | preserved | high complexity | future |
| **E. Keep sandbox, document the blind spot** | none (silently) | preserved | silent non-protection | rejected |

Option E is rejected outright: a daemon that looks active but cannot see user
opens is worse than no daemon, because the protection is assumed.

## 5. Recommended design

Target: **Option B** — the systemd sandbox is preserved and mount marks are
attached to init-namespace mounts through `/proc/1/root` (proven by exp2 and,
under the real sandbox options, exp2p).  Fall back to **Option A** only if
proc-root access is ever blocked.

### D1 — Unit: keep the sandbox

Option B keeps the mount-namespace sandbox: it no longer blinds the marks
because they are attached to init-namespace mount objects (D2).  Keep
`ProtectSystem=strict`, `ProtectProc=invisible` and `PrivateDevices=yes` as
they are, plus the non-namespace hardening:

```
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID CAP_KILL
AmbientCapabilities=...   (unchanged)
SystemCallFilter=@system-service rseq fanotify_init fanotify_mark setuid setgid setresuid setresgid
SystemCallFilter=~@mount  # the daemon never mounts
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
RestrictSUIDSGID=yes
RestrictNamespaces=yes    # the daemon never creates namespaces
LockPersonality=yes
MemoryDenyWriteExecute=yes
UMask=0077
StateDirectory=fileshield
```

Do **not** enable `PrivateTmp=yes`: it hides `/tmp/.X11-unix` from the dialog
child on X11 desktops, and the daemon never uses `/tmp` itself.  `ProtectHome=`
stays off (not validated with Option B).

### D2 — Daemon: mount marks on init-namespace mounts

- Keep `FAN_MARK_MOUNT`; never prefer `FAN_MARK_FILESYSTEM` outside the
  guarded opt-in (F3).
- Place every mount mark through pid 1's namespace: prefix the canonical path
  with `/proc/1/root` (exp2 proves this attaches to the init-namespace mount
  and delivers events).  This applies to protected paths, glob bases, and the
  nearest-existing-ancestor walk for missing paths; check the prefix fits in
  `PATH_MAX`.  The code path is unconditional: when the daemon runs in the
  init namespace by hand, the prefix resolves to the same mounts.
- Inode marks stay as they are: inodes are shared across namespaces, so exact
  files and directory+`FAN_EVENT_ON_CHILD` marks already work everywhere.
- If `/proc/1/root` cannot be resolved or marking through it fails, abort
  startup with a clear message.  The fallback is Option A (run without the
  namespace sandbox), never silently degraded protection.
- **Scope guard (new):** state/config mounts must not be among the marked
  mounts.  This is essential for the unsandboxed fallback (there the daemon
  shares mount instances with its own opens) and cheap insurance under
  Option B.  Identify mounts by mount ID, not `st_dev` (F7); run the guard on
  startup and reload, and reject a reload that fails it.
- Fix the mark bookkeeping while touching it: `g_mounts` currently dedupes by
  `st_dev`, so on btrfs a second protected path on a different subvolume mount
  of the same device would get no mark at all.  Key the table and the guard by
  mount ID for mount scope.
- Reload order stays: `config_load()` → validate → clear marks → install →
  load state.  Startup order becomes: `config_load()` → load state → validate →
  install marks → loop (state loads move **before** marks; still worth doing).
- Optional future: `[settings] mark_scope = mount | filesystem` (default
  `mount`). `filesystem` is refused unless the protected device differs from
  the root device and the operator acknowledges the scope in the config
  (`i_understand_filesystem_scope = yes`). This keeps Option C available to
  people who dedicate a filesystem, without ever enabling it here.

### D3 — Self-open discipline

- The daemon must never `open()` a marked object. The D2 guard covers state and
  config; the remaining opens are `/proc` reads (procfs, never marked) and
  helper execs (answered by the child allowance below).
- Every wait loop answers, in order: dialog child group, direct daemon children,
  mount-mark noise; anything protected is deferred or denied:
  - main loop (existing),
  - dialog pump (existing),
  - **hash wait** — re-land the 100 ms-slice wait hook that runs
    `fanotify_pump(fd, 0)` while `collect_digest()` polls the helper.
- `--dry-run` (new): parse the config, print every mark that would be installed
  (path, scope, device), exit. First-boot bring-up never needs a live mark.
- Optional `[settings] enforce = no` (canary): start and log without installing
  marks.

### D4 — Shutdown and error paths

- Re-land the shutdown drain (`fanotify_drain_and_deny()` before
  `close(fan_fd)`) and the `fanotify_respond()` escalation, both from the
  reverted work; F5 makes them necessary for fail-closed semantics.
- Note: `SIGKILL` cannot rescue a process blocked in D-state on its own event;
  prevention (D2/D3) is the only reliable control. A systemd watchdog heartbeat
  is still worth adding for non-D-state hangs.

### D5 — Observability

- Log one line per installed mark: scope, device, path.
- Keep counters/logging for fast-path allows, deferred events and prompts so a
  scope regression is visible in the journal on day one.

## 6. Phase 0 — required experiments before any scope change

Run on a disposable VM first; exp1/exp3 are small enough to re-run on the real
machine against a scratch tmpfs without risk.

Harness: `experiments/phase0_mark_scope.c` — root-only, builds with the
repository flags, and only ever marks its own private tmpfs. Build/run
instructions are in the file header.

1. **exp1 — mount marks vs namespaces (expected: invisible).**
   Parent forks child A (stays in the init namespace, waits on a pipe); parent
   calls `unshare(CLONE_NEWNS)`; parent mounts a private tmpfs at
   `/tmp/fs-ns-test`, marks it with `FAN_MARK_MOUNT` + `FAN_OPEN_PERM`; parent
   signals A; A opens `/tmp/fs-ns-test/secret`; parent polls the fanotify fd.
   - **No event** → F2 confirmed; Option A (or B) is mandatory.
   - **Event** → F2 is wrong on this kernel; stop and re-evaluate.
2. **exp2 — Option B proof.** Same as exp1, but the parent marks
   `/proc/<A>/root/tmp/fs-ns-test` instead of its own path. Event delivery
   proves mount marks can be placed on init-namespace mounts from inside a
   private namespace (CAP_SYS_PTRACE is already held). If exp2 fails, Option B
   is dead and D1 is the only path.
3. **exp3 — filesystem scope blast radius (optional).** Mark a scratch tmpfs
   with `FAN_MARK_FILESYSTEM` and confirm both cross-namespace delivery and that
   the scope is the whole superblock. Never run this against `/` or `/home`.

### Phase 0 results (2026-09-16)

- **exp1 — CONFIRMED.** The private-namespace control child fired; the
  init-namespace child did not.  Mount marks do not cross mount namespaces.
- **exp2 — PROVEN.** A mark placed through `/proc/<init-ns-pid>/root/...` from
  inside a private namespace attached to the init-namespace mount (`fdinfo`
  shows a different `mnt_id` than the local mount) and the init-namespace
  child's open fired.  Option B works on bare metal.
- **exp3 — CONFIRMED.** A filesystem mark on a scratch tmpfs fired for both
  namespaces (superblock scope, as expected).
- **exp2p — PASSED (2026-09-16).**  Run under `systemd-run` with
  `ProtectSystem=strict`, `ProtectProc=invisible`, `PrivateDevices=yes`,
  `PrivateTmp=yes`, it exited 0: `/proc/1/root` was reachable and the mount
  mark via proc root was accepted.  `ProtectProc=invisible` does not hide
  pid 1 from the root daemon.  Command for reference:

  ```
  cd /home/micah/Projects/FileShield
  gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 \
      -o /tmp/phase0 experiments/phase0_mark_scope.c
  sudo install -m 0755 /tmp/phase0 /usr/local/bin/phase0
  sudo systemd-run --wait --collect -p ProtectSystem=strict \
    -p ProtectProc=invisible -p PrivateDevices=yes -p PrivateTmp=yes \
    -p RuntimeDirectory=fileshield-phase0 /usr/local/bin/phase0 exp2p
  ```

  (`PrivateTmp=yes` hides `/tmp` inside the unit, so the probe binary must be
  installed outside it.)

## 7. Implementation plan (ordered, each independently reviewable)

| Phase | Work | Scope-affecting | Tests |
| --- | --- | --- | --- |
| P0 | exp1–exp3 + exp2p sandbox probe (all passed) | no | manual, root, VM |
| P1 | Re-land inert fixes from the reverted commits: shipped-config defaults + contract test (`65c2a53`), state-file parser fixes (`82b296f`), hash-cache ctime key (first half of `4647310`), `ferror()` + reload ordering (`068ef39`) | no | existing suites |
| P2 | Unit: keep the sandbox, add `~@mount` / `RestrictNamespaces`, keep `PrivateTmp` off, document Option B | no | VM smoke test + exp2p |
| P3 | `/proc/1/root` mark paths (protected/glob/missing), mount-ID keying, scope guard, load order, `--dry-run` | yes | unit tests for path builder + guard; VM |
| P4 | Re-land shutdown drain + respond escalation (second half of `4647310`) | no | root test: stop while open pending → EPERM |
| P5 | Re-land hash wait hook (`7046ab4`) | no | root test: hash a home-dir binary under a marked mount, no 15 s stall |
| P6 | Optional guarded `mark_scope = filesystem` + `i_understand…` | yes | VM with a dedicated scratch fs only |

The original commits remain in history; the reverts are `e92dc06`…`7abda2b`.
Re-apply by cherry-picking the originals listed above, not by reverting the
reverts wholesale.

### Implementation status (2026-09-16)

- **P1** — `cdc4ab7` (state-file parsers), `c7296f6` (reload ordering +
  `ferror`), `299812b` (hash-cache `ctime`).
- **P2** — `673cb0a`: the unit keeps the sandbox, gains `~@mount` and
  `RestrictNamespaces=yes`, `PrivateTmp` stays out; AGENTS.md and README
  describe the marking model, the statx dependency, the scope guard and
  `--dry-run`.
- **P3 — complete** — `447d293` attaches mount marks through `/proc/1/root`,
  keys them by mount ID, and loads state before marks; `e9d3fa2` adds the
  scope guard and `--dry-run`.
- **P4** — `099a2af`: shutdown drain denies queued kernel events before
  `close()`; response failures escalate.
- **P5** — `ce14d75`: hash wait hook services the queue while a helper is
  blocked.
- All on `fix/inert-relands` + `feature/option-b-marks`; `make test` passes at
  each commit.  Nothing merged, nothing installed.
- **Known test boundary**: mount-ID lookups traverse `/proc/1/root`, which
  needs ptrace access, so unprivileged runs cannot verify mount scope (the
  tests skip; `--dry-run` flags it).  The root daemon has the access — exp2p
  proved it under the unit sandbox.
- **Canary (2026-09-16)**: the new build ran under the installed sandbox
  (`ProtectSystem=strict`, `ProtectProc=invisible`, `PrivateDevices=yes`).
  Mount marks attached via `/proc/1/root` (`mount 59`, the home subvolume),
  persisted state and pins loaded before marks, and a protected open
  (`cat ~/.kube/config`) raised the dialog and was allowed.  No freeze.
- **Canary checks (2026-09-16)**: nested-file prompt through the mount mark
  (a file created under `~/.kube/fileshield-nested-test/` raised the dialog),
  SIGHUP reload (marks rebuilt, state reloaded), and restart (shutdown drain
  plus clean start) all passed.
- **Resolved (2026-09-16)**: the repeated `~/.local/share/opencode/` prompts
  were newly-visible traffic from subdirectories that were not excluded
  (`snapshot/`, `repos/`, `worktree`); adding `!` exclusions fixed it — no
  code change was needed.

## 8. Test matrix (root, satisfies C6)

1. Protected file under a home-dir path → prompt; allow/deny honored.
2. Nested file inside a protected directory (mount coverage, not just the
   directory inode) → prompt.
3. Missing protected path created after startup → prompt.
4. Hard link opened through an unprotected path → prompt.
5. State dir on the same mount as a protected path → startup aborts with the
   scope-guard message; machine fully responsive. The same test must **not**
   abort when the state dir and the protected path are different mounts of the
   same btrfs device (the setup on this machine).
6. Reload that would introduce such a path → reload rejected, old config kept.
7. Stress: several thousand opens on the marked mount while measuring daemon
   CPU and open latency; no multi-second stalls.
8. `systemctl stop` from a TTY while an open is pending → open fails with
   EPERM (drain), daemon exits cleanly.
9. Opens from a `unshare -m` process → documented miss; journal notes nothing
   surprising.
10. `--dry-run` prints the expected marks; installs none.

## 9. Rollout protocol

1. Build and run unit tests; build `make debug` (ASan/UBSan) and re-run.
2. VM with this config; run the matrix including the TTY stop path.
3. Real machine: record `sha256sum /usr/local/sbin/fileshield` and copy it to
   `/usr/local/sbin/fileshield.known-good`.
4. Canary: `sudo systemctl stop fileshield`; run
   `sudo ./build/fileshield --foreground --config /etc/fileshield.conf` in a
   TTY, with a second TTY ready to `pkill fileshield`. Exercise protected opens
   for several minutes.
5. Only then `sudo make install`. Keep the known-good binary until the next
   release.

Rollback: `sudo install -m 0755 /usr/local/sbin/fileshield.known-good
/usr/local/sbin/fileshield` and `sudo systemctl restart fileshield` (or
`systemctl mask fileshield` to stop entirely). If a freeze ever recurs:
`systemd.mask=fileshield.service` on the kernel command line.

## 10. Open questions

- Resolved: exp2p passed — `/proc/1` stays visible under
  `ProtectProc=invisible` and proc-root marking works from the sandbox.
- Do we care about nested-namespace coverage (Flatpak/bwrap/containers)? That is
  a separate, opt-in feature either way (`FAN_MARK_MNTNS`, kernel 6.14+), with
  its own load profile.
- Should `--dry-run` be the default for the first boot after an upgrade
  (`ExecStart=` with a flag file), or is the TTY canary enough?
