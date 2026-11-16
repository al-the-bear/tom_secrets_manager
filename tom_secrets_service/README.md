# tom_secrets_service

> Part of the **Tom Secrets Manager** by al-the-bear.
> © 2026 Peter Nicolai Alexis Kyaw — BSD-3-Clause, see [LICENSE](LICENSE).

The secrets service of the Tom Secrets Manager: a background process that
holds one user's unlocked vaults and answers local clients, the manager app
and `tsm`.

## Overview

One service runs per OS user. It opens the user's vaults (KDBX files, local
or in a GitHub repository) when the master password unlocks it, and answers
the user's programs over a local socket: a program asks for a secret by its
reference (`[env:prod]db.main`), the service resolves the reference, checks
who is asking and whether that program may have the value, and answers. It
has no UI: the manager app and `tsm` start, unlock and administer it over a
second, authenticated endpoint.

Who is asking is measured, never taken from what the client says: the peer
process's executable (or, for an interpreter, the script it runs) is read
from the operating system. Whether it may have the value is decided by
signed grants in the primary vault, and for a request no grant answers, by
an approver — the attached manager app, or a paired device reached over the
approval link. Every resolved item is written to an encrypted audit log.

The wire format of both endpoints is the
[protocol document](https://github.com/al-the-bear/tom_secrets_clients/blob/main/protocol/protocol.md);
the section numbers below refer to it. The service reaches KDBX only through
[`tom_secrets_core`](../tom_secrets_core/README.md).

## Installation

### The executable

The service ships inside the manager app's distribution, beside `tsm`
(`tsm/bin/` of the app folder; on macOS in the app bundle's
`Contents/Resources/tsm/bin/`). To build it from source:

```sh
dart build cli --target bin/tom_secrets_service.dart -o build/service
```

The bundle (`build/service/bundle/`) holds the executable in `bin/` and the
native library of `tom_pqc` (ML-DSA-65, ML-KEM-768) in `lib/`; the two ship
together. `dart compile exe` does not run `tom_pqc`'s build hook and gives an
executable without its library.

### The library

The package is also a library: the starter, the admin client, the runtime
and data directories and the keychain names (re-exported from
`package:tom_secrets_client/admin.dart`), and the service's own types for
tests and embedding.

```yaml
dependencies:
  tom_secrets_service: ^0.11.2
```

```sh
dart pub add tom_secrets_service
```

Dart SDK 3.10 or later. A program that only starts or administers the
service depends on `tom_secrets_client` and imports its `admin.dart`, which
does not link the service, the core or KDBX.

## Starting it

The service is started by the manager app or by `tsm start`, not by hand. The
starter (`tomSecretsStartService`) makes a fresh admin key, starts the
executable detached, writes one handover line to its standard input
(`TomSecretsHandover`: the admin key, the path of `bootstrap.yaml`, the
starter's PID) and closes it; the key never touches a file. The service
answers one JSON line on its standard output — `{"status":"ready"}`,
`{"status":"already_running"}` or `{"status":"error","code":…}` — and runs
until `shutdown`, SIGTERM or SIGHUP (the user logs out).

```text
tsm start --unlock
tsm status
```

| Exit code | Meaning |
| --- | --- |
| 0 | stopped |
| 2 | the handover or the bootstrap file cannot be read |
| 3 | already running |
| 4 | the runtime directory is refused (wrong owner or mode) |
| 5 | the keychain holding the device key is not available |

### The pairing mode

`tsm pair` starts the executable with a pairing handover instead
(`TomSecretsPairingHandover`, run by `tomSecretsRunPairingMode`). It receives
a pairing from the giving machine's Pairing screen (storing nothing yet),
reports what it got, takes the master password `tsm` sends (three tries),
sets the machine up from what it received — the keys and tokens in the
keychain, the device settings container with this machine's approval keys
and the giving device recorded as its approver and as a host it approves
for, and `bootstrap.yaml` — and ends. `tsm` then starts it as usual and
unlocks it.

| Exit code | Meaning |
| --- | --- |
| 0 | set up |
| 2 | the handover cannot be used |
| 6 | the pairing failed |
| 7 | the setup failed |

## Configuration

### `bootstrap.yaml`

Plain text, no secret; the only configuration readable before the unlock.
Its folder is the data directory, where the defaults go
(`TomSecretsBootstrap`).

| Key | Value | Default |
| --- | --- | --- |
| `primary` | the primary vault's locator: `file:<path>` or `github:<owner>/<repository>/<path>` | required |
| `cache_dir` | the offline cache's folder | `<data>/cache` |
| `runtime_dir` | the runtime directory | as protocol.md 3.1 names it |
| `device_key` | where the device settings container's key is kept: `auto`, `keychain`, `vault`, `keyfile` | `auto` |
| `device_container` | the device settings container's file | `<data>/device-settings.kdbx` |
| `host` | this machine's host name | the OS host name |
| `log_level` | `info` or `debug` | `info` |
| `admin_executables` | further executables that may administer the service | none |

```yaml
primary: github:example-org/vaults/primary.kdbx.tsmx
device_key: auto
host: workstation1
log_level: info
admin_executables:
  - /opt/tom-secrets-manager-dev/tom_secrets_app
```

The device key modes: `keychain` is the OS keychain (`TomDesktopSecretStore`
of `tom_core_storage`, service name `tom-secrets-manager`: the macOS login
keychain, libsecret on Linux, the Windows Credential Manager), and the start
is refused without one; `vault` is the primary vault's overlay entry
`@host:<host>/.tom-secrets/device`, which no reference reaches; `keyfile` is a
key file beside the container (mode 0600; on Windows an ACL of the user);
`auto` takes the keychain where one answers and the vault otherwise (an SSH
login without D-Bus or credential store).

### Device settings

Kept per machine, not synced, in the device settings container
(`TomSecretsDeviceSettings` of `tom_secrets_core`, opened after the primary
vault). The manager app writes them (`settings.set`); a value is applied at
once where it can be, the rest at the next unlock.

| Setting | Meaning | Default |
| --- | --- | --- |
| `serviceLock` | the service's lock policy: `mode` (`never`, `idle`), `idleSeconds`, `maxUnlockedSeconds`, `lockOnSleep` | never relock |
| `appLock` | the app's lock policy, kept here for the app | idle, 10 minutes |
| `defaultEnvironment` | the machine's default `env` dimension | none |
| `servedStores` | the stores this machine serves | every one |
| `refreshMinutes` | the refresh interval; 0 switches the timer off | 5 |
| `offlineCache` | whether the offline cache is kept | true |
| `keyExpiryWarningDays` | days before a GitHub token's expiry the reminders start | 14 |
| `approvalTimeoutSeconds` | how long a request waits for an unlock or an approval | 60 |
| `codeTimeoutSeconds` | how long an approval code is valid | 300 |
| `approvalLink` | where this host's approval link listens (`address:port`, a VPN or LAN address, never all interfaces) | no link |
| `startAtLogin` | whether the app starts at login | false |
| `otherKeyWarningDays` | days before its due date the reminders of every other key start | 30 |
| `keyPairAgeMonths` | rotation age of the approver and approval-link key pairs | 24 |
| `primaryKeyAgeMonths` | rotation age a new key file or repository key of the primary vault gets | 24 |
| `vaultKeyAgeMonths` | rotation age a new key file or repository key of every other vault gets | 12 |

### Environment variables

| Variable | Read by | Meaning |
| --- | --- | --- |
| `TSM_RUNTIME_DIR` | service, clients | the runtime directory, overriding the default |
| `XDG_RUNTIME_DIR` | service, clients (Linux) | the runtime directory is `$XDG_RUNTIME_DIR/tsm`, else `/tmp/tsm-<uid>` |
| `TMPDIR` | service, clients (macOS) | the runtime directory is `$TMPDIR/tsm` |
| `LOCALAPPDATA`, `USERPROFILE` | service, clients (Windows) | the runtime directory is `%LOCALAPPDATA%\TomSecretsManager\run` |
| `TSM_DATA_DIR` | the starters (app, `tsm`) | the data directory holding `bootstrap.yaml`; else `~/Library/Application Support/TomSecretsManager` (macOS), `%LOCALAPPDATA%\TomSecretsManager` (Windows), `$XDG_DATA_HOME/tom-secrets-manager` or `~/.local/share/tom-secrets-manager` |
| `TSM_SERVICE` | `tsm` | the service executable `tsm start` and `tsm pair` run; else the one beside `tsm` |
| `XDG_SESSION_ID`, `DISPLAY`, `WAYLAND_DISPLAY` | service (Linux) | whether a desktop session exists to measure the input idle time in |

## What it does

### The runtime directory and the endpoints

The runtime directory (`TomSecretsRuntime`) is made the user's alone (mode
0700; on Windows the inheritance cut and only the user and SYSTEM granted)
and checked for owner and mode at every start. `service.lock` is the
single-instance lock, released by the OS when the process dies;
`service.json` names the PID, the start, the protocol and the endpoints.

| Endpoint | Linux, macOS | Windows |
| --- | --- | --- |
| client | `client.sock` | a localhost TCP port in `client.port`, the per-start token in `client.token` |
| admin | `admin.sock` | a localhost TCP port in `admin.port` |

The client endpoint answers `hello` with `welcome`, then `get` and `getMany`
(1 to 256 references), each resolved through `tom_secrets_core`. While the
service is locked, a waiting request tells the subscribed admins
(`unlock_needed`), sends the client `progress`, and is answered once the
service is unlocked, or `locked` when the approval timeout passes.

### Peer identity

Each accepted connection's process is measured once
(`TomSecretsSystemPeerMeasurer`, protocol.md 7.1). The peer PID comes from
`SO_PEERCRED` (Linux), `LOCAL_PEERPID` and `LOCAL_PEERCRED` (macOS) or, for
Windows' localhost TCP, the owner of the connection in `GetExtendedTcpTable`.
The executable, arguments, working directory, start time and parent are read
through `/proc`, libproc and `sysctl(KERN_PROCARGS2)`, or `kernel32`, `ntdll`
and the process snapshot. The start time is read before and after, so a
reused PID is not identified. A peer of another OS user is refused
(`other_user`), one that cannot be measured too (`unidentifiable`).

Interpreted clients (`python`, `node`, `bun`, `deno`, `dart` and the `dartvm`
it starts, `java`, `ruby`, `perl`, the shells, PowerShell;
`TomSecretsInterpreters`, extendable) are `script` identities carrying the
script's real path and SHA-256, and the package root of `dart run` and
`python -m`. File hashes are cached by path, size and modification time
(`TomSecretsFileHashes`). The identity goes to the access policy
(`TomSecretsAccessRequest.identity`) and into `unlock_needed`.

### Approvals and grants

Every resolved value is checked by a `TomSecretsAccessPolicy`. The service's
own, `TomSecretsApprovals` (protocol.md 7, 9), is the default;
`TomSecretsDenyAllPolicy` refuses every value.

- **Grants.** The allow list of this host is read from the primary vault
  (`tsm.grants/<host>`). A grant counts only when an approver key the device
  recorded at pairing (or its own) signed it with Ed25519 and ML-DSA-65. The
  most specific grant decides: executable, script or `tsm-command`, then
  folder, then interpreter; for one subject a reference beats a store and a
  store beats `all`; `never` beats `allow` at equal rank. A pinned grant
  (`TomSecretsPin`: `hash`, `off`, or relaxed until a date, recording the new
  hash meanwhile) holds only while its file's hash is the one recorded.
- **Prompts.** A request no grant answers goes to the approvers:
  `approval_needed` to the attached app and over the approval link,
  `progress {pending: approval}` to the client. `once`, `always` and `folder`
  allow, `never` refuses; a lasting decision is written as a grant signed with
  this device's approver key.
- **Approval codes.** With no approver attached the request gets an approval
  code. A single-use token from a trusted device (`approval.issue` there,
  `approval.redeem` here) or a signed approval record in the vault answers it;
  the code timeout ends it `no_approver`, the approval timeout `timeout`.
- **Prompt flooding** is held back: one prompt per identity and reference, at
  most three per identity; three refusals in ten minutes hold the identity
  back ten minutes (`rate_limited`).
- **`tsm`** answers no prompt; it pre-approves (`tsm allow`) or issues tokens
  (`tsm approve-code`) only where the app switched command-line approvals on
  (`approvers.cliSwitch`).
- **Client tokens** (protocol.md 7.4). For a request with `wantClientToken`
  the approving device makes the token (the attached app in `approve`, a
  remote approver with its signed grant over the link). The grant's subject is
  `exe-token <path> <tokenId>`; the host keeps only the token's hash and the
  identities it came with; the client gets the token in its `value` and brings
  it in later `hello`s. Revoking the grant invalidates it; an approval code
  issues none.

### The approval link and the approver's links

- **The approval link** (`TomSecretsLinkServer`, protocol.md 9.7): while
  unlocked, on the device setting `approvalLink`, a Noise KK handshake with
  ML-KEM-768 against the recorded approvers' link keys. A connected approver
  gets the prompts and sends answers, signed grants (applied at once as
  pending copies), revocations, key changes and new link keys.
- **The approver's links** (`TomSecretsApproverLinks`, protocol.md 7.2, 9.7):
  while unlocked, a session to every paired host this device approves for
  (its recorded address, this device's link key for that host), opened again
  when it ends. The host's prompts go to the attached app as
  `<host>/<approvalId>`; the app's `approve` goes back over the link — `once`
  as `approve`, a lasting decision as grants this device signs (written to the
  host's group, sent as `grant`), an `always` with a client token as its
  `exe-token` grant with the token. A host that rotated its link key sends the
  new one first; it is recorded.

### Pairing records

The apps run the pairing between two machines (`TomSecretsPairingWindow` and
`tomSecretsReceivePairingAt` of `tom_secrets_core`; protocol.md 6.3, 9.8).
The service gives this device's public keys (`pair.identity`) and keeps what
the pairing gave (`pair.record`): the peer as an approver of this host and/or
a host this device approves for, with the approval-token key both derived,
and on the giving side the device record in the primary. `pair.revoke` ends a
pairing, `pair.list` lists the device records.

### The audit log

`TomSecretsAuditLog` writes one record per resolved item — time, host,
identity, reference, outcome, grant or approver, entry UUID, never a value —
each encrypted with XChaCha20-Poly1305 under the audit-log key, in a file per
day under `<data>/audit/`, flushed in batches and deleted after 90 days.
`audit.query` reads it.

### The admin endpoint

The admin's executable must be `tsm` or the manager app beside the service
(or the app of the distribution around it), or one named in
`admin_executables:`; any other is refused before its key is checked
(`wrong_executable`). Nothing is answered before the mutual challenge
(`challenge`, `auth`, `authed`: HMAC-SHA256 under the admin key, protocol.md
6.1) or a `claim` with the master password, which issues a new admin key and
revokes the old one. Failed authentications delay the next one (1 s, 2 s,
4 s … 60 s).

| Requests | What they do |
| --- | --- |
| `unlock`, `unlockStore`, `lock`, `reload`, `status`, `shutdown` | the service's lifecycle; `status` lists the stores with their state and source, the keys due (`expiring`), the lock mode and the hardening |
| `subscribe` | the events `unlocked`, `locked`, `unlock_needed`, `store_changed`, `store_state`, `key_expiry`, `approval_needed`, `approval_closed`, `rate_limited` |
| `approve`, `approvals.list`, `approval.issue`, `approval.redeem`, `approvers.cliSwitch` | answering approvals, and command-line approvals on or off |
| `grants.list`, `grants.add`, `grants.revoke` | the allow list |
| `pair.identity`, `pair.record`, `pair.revoke`, `pair.list` | pairing records |
| `audit.query` | the audit log |
| `settings.get`, `settings.set` | the device settings (a write only from the manager app) |
| `keys` | every key with its due date |
| `vaultKeys`, `vaultFile`, `save`, `history.resolve` | the editing path (below) |
| `compact` | the history of a `github:` vault repository cut now, with the repository's own `.tsm/compaction.yaml` retention or `retentionDays` instead (0 after a key change), pushed over git by this device |
| `token.set` | a vault repository's GitHub token renewed (manager app only): checked first (it sees the repository, a short-lived `tsm-token-check-…` branch is created and deleted to prove it may write, the expiry GitHub reports), then kept where the old one was, and every store fetched again |
| `keys.rotate` | this device's approver and link key pairs rotated (manager app only): what the old approver key signed is signed again, the key-change statement written into the vault for every host it approves for, both sent over the approval link at once; the previous link key is kept for 14 days for the peers not reached |
| `vault.move` | a store's outer encryption added or removed: the vault moved to its locator with `.kdbx.tsmx` or `.kdbx`, the new file written before the old one is removed, a `github:` vault in one commit |

### The editing path

The manager app edits vaults through the service (protocol.md 6.4).
`vaultKeys` hands it the keys of the open vaults (`password`, `keyFile`,
`outerKey`) and their locations; `save` takes the edited file, which must
open with the store's keys.

- A file still at `baseRevision` is written as it is. A file that moved
  meanwhile is merged three-way when the app edited the service's copy, and
  refused (`stale_base`) otherwise.
- `file:` vaults are written on the local disk; `github:` vaults as one
  commit on the branch, merged three-way when another device pushed
  meanwhile, then kept in the offline cache. A branch rewritten without a
  compaction is refused (`history_rewritten`): the store reports `rewritten`,
  keeps the refused edit and is not refreshed until the app answers with
  `history.resolve` (`take: remote` follows the rewritten branch,
  `take: merge` merges the held copy over it). A branch that moved on every
  attempt is refused `branch_moving`.
- A vault this machine does not serve is listed by the primary with its keys
  (`vaultKeySet.unserved`); `vaultFile` reads it for editing and `save` writes
  it. It is never resolved, served to clients, refreshed or listed in
  `status`.
- A re-keyed file (the app writes the new keys into the primary first) is
  written as it is, never merged; the primary's own new keys come in the
  save's `keys` and replace its key file and repository key in the keychain.
- A store on its offline copy, or whose remote fails during the save, refuses
  with `offline` or `token_expired`. `store_changed` names the new revision.
  The service's own writes of the primary (grants, their last use, the device
  key) go the same way; one that cannot be delivered stays in the held copy
  and the next refresh writes it first.

### `github:` vaults, the offline cache and the refresh

- **`github:` vaults** (`TomSecretsGitHubOpener`) are opened through
  `tom_secrets_core`'s `TomSecretsVaultUnit` over `TomGitHubStorage` (the REST
  API, no clone). Each repository's token is asked for on every request: the
  keychain's (`tsm.github-token.<owner>:<repository>`), else one the primary's
  vault list keeps for a vault in that repository (never for the primary's own
  repository). The expiry GitHub reports for a token is recorded for the
  reminders.
- **The offline cache** keeps every fetched file as stored. When GitHub
  cannot be reached or refuses the token, a vault opens from it (`offline` or
  `token_expired`, `source: cache`); without a copy it is `unavailable`. The
  primary is opened before the device settings are read, so it is always
  cached.
- **The refresh** runs at unlock, on `reload` and every `refreshMinutes`. A
  file that did not move costs one conditional request; a moved file is
  reopened with the keys held (`store_changed`); a file whose key changed goes
  to `needs_unlock`; a further vault the primary lists anew, or with new keys,
  is opened with them, and one it no longer lists is dropped. A failed fetch
  keeps the copy held and never locks the service: network failures back off
  1, 2, 4 … 30 minutes; a refused token is not fetched again until `reload` or
  the next unlock. Every change of a store's state or source is sent as
  `store_state`.

### Key-expiry reminders

`TomSecretsExpiringKey` covers the GitHub tokens (from `keyExpiryWarningDays`
before their expiry), the vaults' key files and repository keys (from
`otherKeyWarningDays` before their due date: a further vault's entry
Expires, the primary's `tsm.keys-due`), and the approver and approval-link key
pairs of this device and of the peers it recorded (from `otherKeyWarningDays`
before `keyPairAgeMonths` is over). Then again 7 days and 1 day before, and
once a day once expired. Each step is sent once as `key_expiry` to the
subscribed admins; an admin that subscribes gets those due at that moment.

### Unlock, lock and the lock modes

Unlocking opens the primary file first, then the device settings container,
then the further vaults the primary names; a vault whose key does not open is
`needs_unlock` and the others are still served. Locking drops the vaults, the
index and the device settings; the admin key survives.

The lock modes (`TomSecretsLockPolicy`; `status.lockMode` names them by the
protocol's letter): (a) never relock, (b) relock after the user's input has
been idle for a while; in either mode an optional hard maximum unlocked time.
The idle time comes from CoreGraphics on macOS, `GetLastInputInfo` on Windows
and logind's idle hint on Linux; where it cannot be measured (no desktop
session) the service never locks itself, the maximum unlocked time included.

### Hardening and memory hygiene

- **Process hardening** (`tomSecretsHardenProcess`, at start, before the
  handover is read; best effort, reported in `status.hardening`): no core
  files (`setrlimit(RLIMIT_CORE, 0)` on Linux and macOS, the error mode on
  Windows), not dumpable on Linux (`prctl(PR_SET_DUMPABLE, 0)`), and on
  Windows a process DACL that refuses `PROCESS_VM_READ` and
  `PROCESS_VM_WRITE` to all but SYSTEM. The macOS hardened runtime is a
  signing flag of the build.
- **Memory hygiene:** the keys held while unlocked are `TomProtectedValue`s of
  `tom_crypto` (masked, zeroed on lock), and a resolved value stays masked in
  the core's field value. An answer carrying a secret (`value`, `values`,
  `vaultKeySet`) is written into the frame straight from bytes that are zeroed
  after use (`tomSecretsSecretFrame`), never through a `String`, and the frame
  is zeroed once the socket has flushed it.
- **The operational log** (`TomSecretsLog`): `service.log` in the data
  directory, rotated at 1 MiB with three older files kept. It never holds a
  value, password, key or token; an exception is logged by its type and code,
  never its message; references and client identities only at `log_level:
  debug`.

## Limits

- One service per OS user and machine; clients reach it only locally (a Unix
  socket, or localhost TCP with a per-start token on Windows). The only
  network listener is the approval link, and only on the configured address.
- Frames: a request's payload at most 64 KiB, an answer's at most 1 MiB; a
  reference at most 1 KiB of UTF-8; `getMany` takes 1 to 256 references.
- The service offers no phase-B features (`welcome.features` is empty): no
  `getFile`, no binary chunks, no `match` or `propose`.
- Automatic locking needs a desktop session; on a headless machine only an
  explicit `lock` (or `shutdown`) locks the service.
- Values are served only while unlocked; a locked service makes clients wait
  up to the approval timeout.
- **Rate limits** (protocol.md 11), per measured identity, set by
  `TomSecretsServiceConfig.rateLimits` (`TomSecretsRateLimitSettings`, the
  protocol's values by default):
  - `get` and `getMany`: a token bucket of 20 a second, bursts of 50; over
    it a request is answered `rate_limited` (`reason` `requests`,
    `retryAfterMs` until the next one may go);
  - ten refusals (`denied`, `not_found`, `ambiguous`) within a minute make
    each request of the identity wait 10 s for the next ten minutes;
  - at most 16 open connections per identity and 256 in all; a connection
    over either is answered `rate_limited` (`reason` `connections`) at its
    `hello` and closed;
  - the prompts' own limits (prompt flooding, above) and the admin
    channel's growing delay after failed authentications.

## Key types

| Type | Responsibility |
| --- | --- |
| `TomSecretsService` | the running service: both endpoints, unlock and lock, the vaults, approvals, events |
| `TomSecretsServiceConfig` | what a service is launched with: the runtime directory, the bootstrap, the admin key, the access policy, the keychain, the vault opener |
| `TomSecretsBootstrap` | `bootstrap.yaml` |
| `TomSecretsVaultSet` | the open stores, their state and source, the refresh, the editing path's writes |
| `TomSecretsVaultOpener` | opening and committing one vault: `TomSecretsFileOpener`, `TomSecretsLocatorOpener`, `TomSecretsGitHubOpener` |
| `TomSecretsRateLimits`, `TomSecretsRateLimitSettings` | the client endpoint's rate limits per identity (protocol.md 11) |
| `TomSecretsAccessPolicy` | decides each resolved value: `TomSecretsApprovals`, `TomSecretsDenyAllPolicy` |
| `TomSecretsAccessRequest`, `TomSecretsAccessBatch` | what the policy is asked |
| `TomSecretsIdentity`, `TomSecretsPeerMeasurer` | the measured client: `TomSecretsSystemPeerMeasurer`, `TomSecretsInterpreters`, `TomSecretsFileHashes`, `TomSecretsPin` |
| `TomSecretsGrant` | a signed grant of the allow list |
| `TomSecretsLinkServer` | the approval link of this host |
| `TomSecretsApproverLinks` | this device's sessions to the hosts it approves for |
| `TomSecretsAuditLog`, `TomSecretsAuditRecord` | the encrypted audit log |
| `TomSecretsExpiringKey`, `TomSecretsKeyDate` | key-expiry reminders |
| `TomSecretsLockTimer`, `TomSecretsIdleSource` | the lock policy's timer and the input idle time |
| `TomSecretsConnection` | one framed connection; secret answers through `tomSecretsSecretFrame` |
| `TomSecretsLog` | the operational log |
| `tomSecretsHardenProcess` | the process hardening |
| `tomSecretsRunPairingMode` | the pairing mode |
| `tomSecretsCheckGitHubToken` | the check of a renewed GitHub token |
| `tomSecretsStartService`, `TomSecretsHandover`, `TomSecretsAdminClient`, `TomSecretsRuntime` | starting and administering the service (re-exported from `tom_secrets_client`) |

## Ecosystem

```text
                  manager app            tsm            client programs
                      |                   |            (Dart, TypeScript, ...)
                      |  admin endpoint   |                    |
                      +---------+---------+                    | client endpoint
                                |                              |
                       +--------v------------------------------v---+
   approval link <---->|            tom_secrets_service            |
   (paired devices)    +---------------------+---------------------+
                                             |
                  +--------------------------+--------------------------+
                  |                          |                          |
         tom_secrets_core           tom_secrets_client          tom_crypto, tom_pqc,
   (vaults, resolution, KDBX     (frames, discovery, the       tom_github_api,
    via tom_kdbx_store, pairing)  reference grammar, admin)    tom_core_storage
```

## Further documentation

| Topic | Document |
| --- | --- |
| The wire format of both endpoints, the approval link and pairing | [protocol document](https://github.com/al-the-bear/tom_secrets_clients/blob/main/protocol/protocol.md) |
| Vaults, stores, resolution, the GitHub cycle, pairing crypto | [`tom_secrets_core`](../tom_secrets_core/README.md) |
| The Dart client and the admin library | [`tom_secrets_client`](https://github.com/al-the-bear/tom_secrets_clients/blob/main/clients/dart/tom_secrets_client/README.md) |
| The command line: reading secrets, starting and administering the service | [`tsm`](https://github.com/al-the-bear/tom_secrets_clients/blob/main/clients/dart/tsm/README.md) |
| The repository: core and service | [repository README](../README.md) |

## Status

Version 0.11.4. The suite runs with `testkit :test` from the package folder.
It covers the service in-process and as a compiled process (the handover, a
second start, SIGTERM), the editing path and the log, the secret frames, the
hardening seen from outside a hardened process, the peer identity of a real
client process, approvals, grants, client tokens, the approval link and the
approver's links, pairing and the pairing mode, key rotation, and the
`github:` vaults with the offline cache, the refresh and the key-expiry
reminders against `tom_github_api`'s in-memory GitHub. Some suites run only
on their platform: the Unix-socket service tests on macOS and Linux, the
Windows tests on Windows.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE). The service reaches KDBX only through
`tom_secrets_core`; no package in its dependency closure is GPL-licensed.
