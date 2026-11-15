# tom_secrets_service

The Tom Secrets Manager's secrets service: a background process that holds the
unlocked vaults of one OS user and answers that user's programs. It has no UI;
the manager app and `tsm` administer it. License: BSD-3-Clause.

## What it does

- **Runtime directory** (`TomSecretsRuntime`): per OS user, as protocol.md 3.1
  names it (`$TSM_RUNTIME_DIR`, `$XDG_RUNTIME_DIR/tsm`, `$TMPDIR/tsm`,
  `%LOCALAPPDATA%\TomSecretsManager\run`). It is made the user's alone (mode
  0700; on Windows the inheritance cut and only the user and SYSTEM granted)
  and checked for owner and mode at every start. `service.lock` is the
  single-instance lock (the OS releases it when the process dies; a second
  start answers `already_running`), `service.json` names the PID, the start,
  the protocol and the endpoints.
- **Client endpoint**: `client.sock` (Linux, macOS), or a localhost TCP port
  in `client.port` with the per-start token in `client.token` (Windows).
  `hello` and `welcome`, `get` and `getMany` resolved through
  `tom_secrets_core`. While locked, a waiting request tells the subscribed
  admins (`unlock_needed`), sends `progress`, and is answered once the service
  is unlocked or the approval timeout passes (`locked`). Every resolved value
  is checked by a `TomSecretsAccessPolicy`; the default, `TomSecretsDenyAllPolicy`,
  refuses every value; without one the service's own approvals decide.
- **Peer identity** (part-protocol, protocol.md 7.1; `TomSecretsSystemPeerMeasurer`):
  each accepted connection's process is measured once, never taken from
  what it says. The peer PID comes from `SO_PEERCRED` (Linux),
  `LOCAL_PEERPID` and `LOCAL_PEERCRED` (macOS) or, for Windows' localhost
  TCP, the owner of the connection in `GetExtendedTcpTable`. Then the
  executable, arguments, working directory, start time and parent are read
  through `/proc`, libproc and `sysctl(KERN_PROCARGS2)`, or `kernel32`,
  `ntdll` and the process snapshot. The start time is read before and after,
  so a reused PID is not identified. A peer of another OS user is refused
  (`other_user`), one that cannot be measured too (`unidentifiable`).
  Interpreted clients (`python`, `node`, `bun`, `deno`, `dart` and the
  `dartvm` it starts, `java`, `ruby`, `perl`, the shells, PowerShell;
  `TomSecretsInterpreters`, extendable) are `script` identities with the
  script's real path and SHA-256, the package root of `dart run` and
  `python -m`. File hashes are cached by path, size and modification time
  (`TomSecretsFileHashes`); `TomSecretsPin` checks a grant's pin (`hash`,
  `off`, relaxed until a date, recording the new hash meanwhile). The
  identity goes to the access policy (`TomSecretsAccessRequest.identity`)
  and into `unlock_needed`.
- **Approvals and grants** (`TomSecretsApprovals`, protocol.md 7, 9; the
  default policy). The allow list of this host is read from the primary
  vault (`tsm.grants/<host>`); a grant counts only when an approver key the
  device recorded at pairing (or its own) signed it with Ed25519 and
  ML-DSA-65. The most specific grant decides (exe, script, `tsm-command`;
  then folder; then interpreter; for one subject a reference beats a store
  and a store beats `all`; `never` beats `allow` at equal rank), and a
  pinned grant holds only while its file's hash is the one recorded
  (relaxed pins record the new hash until their date). A request no grant
  answers goes to the approvers: `approval_needed` to the attached app and
  over the approval link, `progress {pending: approval}` to the client;
  `once`, `always` and `folder` allow, `never` refuses, and a lasting
  decision is written as a grant signed with this device's approver key.
  With no approver attached the request gets an approval code; a
  single-use token from a trusted device (`approval.issue` there,
  `approval.redeem` here) or a signed approval record in the vault answers
  it; the code timeout ends it `no_approver`, the approval timeout
  `timeout`. Prompt flooding is held back (one prompt per identity and
  reference, three per identity, three refusals in ten minutes hold the
  identity back). `tsm` answers no prompt and pre-approves or issues tokens
  only where the app switched command-line approvals on
  (`approvers.cliSwitch`).
- **Client tokens** (protocol.md 7.4, DP-20): for a request with
  `wantClientToken` the approving device makes the token (the attached app
  in `approve`, a remote approver with its signed grant over the link); the
  grant's subject is `exe-token <path> <tokenId>`, the host keeps only the
  token's hash and the identities it came with, the client gets the token
  in its `value` and brings it in later `hello`s; revoking the grant
  invalidates it; an approval code issues none.
- **The approval link** (`TomSecretsLinkServer`, protocol.md 9.7): while
  unlocked, on the device setting `approvalLink` (a VPN or LAN address),
  the Noise KK handshake with ML-KEM-768 against the recorded approvers'
  link keys; a connected approver gets the prompts and sends answers,
  signed grants (applied at once as pending copies), revocations, key
  changes and new link keys.
- **The audit log** (`TomSecretsAuditLog`): one record per resolved item
  (time, host, identity, reference, outcome, grant or approver, entry UUID,
  never a value), each encrypted with XChaCha20-Poly1305 under the audit-log
  key, in a file per day under `<data>/audit/`, flushed in batches, deleted
  after 90 days; `audit.query` reads it.
- **Admin endpoint**: `admin.sock`, or `admin.port`. The admin's executable
  must be `tsm` or the manager app beside the service, or one named in
  `admin_executables:` of `bootstrap.yaml`; any other is refused before its
  key is checked (`wrong_executable`). Nothing is answered before
  the mutual challenge (`challenge`, `auth`, `authed`: HMAC-SHA256 under the
  admin key, protocol.md 6.1) or a `claim` with the master password, which
  issues a new admin key and revokes the old one. Failed authentications delay
  the next one (1 s, 2 s, 4 s … 60 s). Then `unlock`, `unlockStore`, `lock`,
  `status`, `reload`, `subscribe` (the events `unlocked`, `locked`,
  `unlock_needed`, `store_changed`, `store_state`, `key_expiry`,
  `approval_needed`, `approval_closed`, `rate_limited`), `vaultKeys`, `save`, `approve`, `approval.redeem`, `approval.issue`,
  `grants.list`, `grants.add`, `grants.revoke`, `approvers.cliSwitch`,
  `audit.query`, `settings.get` / `settings.set` (the device settings; a
  write only from the manager app, applied at once where it can be and the
  rest named for the next unlock), `approvals.list` (the requests waiting on this host, as
  `approval_needed` reads them), `keys` (every key with its due date),
  `compact` (the history of a `github:` vault repository cut now, with its
  own `.tsm/compaction.yaml` retention, pushed over git by this device) and
  `shutdown`.
- **The editing path** (DP-13, protocol.md 6.4): `vaultKeys` hands the app the
  keys of the open vaults (`password`, `keyFile`, `outerKey`) and their
  locations; `save` takes the app's edited file, which must open with the
  store's keys. A file still at `baseRevision` is written as it is; a file
  that moved meanwhile is merged three-way when the app edited the service's
  copy, and refused (`stale_base`) otherwise. Every write goes through the
  opener's `commit` over the copy the service holds: `file:` vaults on the
  local disk (merged when the file moved there); `github:` vaults as one
  commit on the branch by this device through the vault unit kept per store,
  merged three-way when another device pushed meanwhile, then kept in the
  offline cache (`denied` with `history_rewritten` for a branch rewritten
  without a compaction, `branch_moving` when it moved on every attempt).
  After a refusal for a rewritten branch the store reports
  `rewritten: {head}` (status and `store_state`), keeps the refused edit and
  is not refreshed until the manager app answers with `history.resolve`:
  `take: remote` follows the rewritten branch, `take: merge` merges the held
  copy over it and commits on top.
  **A vault this machine does not serve** (BP-15) goes the same way: the
  primary lists it with its keys, `vaultKeySet.unserved` names it,
  `vaultKeys` naming it answers its keys (`served` false), and `vaultFile`
  naming it reads it from its location with those keys and the repository's
  token and holds the copy for editing until the lock; `save` writes it as
  above. It is never resolved, served to clients, refreshed or listed in
  `status`.
  `store_changed` names the new revision. A store on its offline copy, or
  whose remote fails during the save, refuses with `offline` /
  `token_expired`. The service's own writes of the primary (grants, their
  last use, the device key) go the same way; one that cannot be delivered
  stays in the held copy and the next refresh writes it before fetching
  (nothing of it survives a lock).
- **`github:` vaults** (`TomSecretsGitHubOpener`): opened through
  `tom_secrets_core`'s `TomSecretsVaultUnit` over `TomGitHubStorage` (the REST
  API, no clone), with the commit reader for compactions. Each repository's
  token is asked for on every request: the device keychain's
  (`tsm.github-token.<owner>:<repository>`), else one the primary's vault list
  keeps for a vault in that repository (never for the primary's own
  repository). The expiry GitHub reports for a token
  (`GitHub-Authentication-Token-Expiration`) is recorded for the reminders.
- **The offline cache** (`bootstrap.yaml`'s `cache_dir`, default
  `<data>/cache`; the device setting `offlineCache`): every file fetched is
  kept there as stored. When GitHub cannot be reached or refuses the token, a
  vault opens from it (`offline` or `token_expired`, `source: cache`); without
  a copy it is `unavailable`. The primary is opened before the device
  settings are read, so it is always cached.
- **The refresh**: at unlock, on `reload`, and on a timer every
  `refreshMinutes` (the device setting; 0 switches the timer off). A file
  that did not move costs one conditional request and is not reopened; a
  moved file is reopened with the keys held and the index rebuilt
  (`store_changed`); a file whose key changed goes to `needs_unlock`; a
  further vault the primary lists anew, or with new keys, is opened with
  them, and one it no longer lists is dropped. A failed fetch keeps the copy
  held and never locks the service: network failures back off 1, 2, 4 … 30
  minutes, a refused token is not fetched again until `reload` or the next
  unlock. Every change of a store's state or source is sent as
  `store_state`; `reload` answers `offline` or `token_expired` with the
  stores still on their copy.
- **Key-expiry reminders** (`TomSecretsExpiringKey`): the GitHub tokens from
  `keyExpiryWarningDays` (default 14) before their expiry (the one GitHub
  reports, else the one recorded with the token: the keychain's, or the
  primary's vault list's); the vaults' key files and repository keys from
  `otherKeyWarningDays` (default 30) days before their due date (a further
  vault's entry Expires, the primary's `tsm.keys-due`); this device's
  approver and approval-link key pairs and those of the peers it recorded
  from `otherKeyWarningDays` before their rotation age (`keyPairAgeMonths`,
  default 24, DP-85) is over (dated at creation, at pairing, at a key change or a new
  link key; trust material without dates is dated at the next unlock); then
  7 days and 1 day before, and once a day once expired. Each step is sent once as `key_expiry` to the subscribed
  admins (an admin that subscribes gets those due at that moment), and
  `status` lists the keys due as `expiring`.
- **Memory hygiene**: the keys the service holds while unlocked are
  `TomProtectedValue`s of `tom_crypto` (masked, zeroed on lock), and a
  resolved value stays masked in `tom_secrets_core`'s field value. An answer
  carrying a secret (`value`, `values`, `vaultKeySet`) is written into the
  frame straight from bytes that are zeroed after use
  (`tomSecretsSecretFrame`), never through a `String`, and the frame itself is
  zeroed once the socket has flushed it.
- **Process hardening** (`tomSecretsHardenProcess`, at start, before the
  handover is read; best effort, reported in `status.hardening`): no core
  files (`setrlimit(RLIMIT_CORE, 0)` on Linux and macOS, the error mode on
  Windows), not dumpable on Linux (`prctl(PR_SET_DUMPABLE, 0)`), and on
  Windows a process DACL that refuses `PROCESS_VM_READ` and
  `PROCESS_VM_WRITE` to all but SYSTEM. The macOS hardened runtime is a
  signing flag of the build.
- **The operational log** (`TomSecretsLog`): `service.log` in the data
  directory, rotated at 1 MiB with three older files kept. It never holds a
  value, password, key or token; an exception is logged by its type and code,
  never its message; references and client identities only at `debug` level
  (`log_level: debug` in `bootstrap.yaml`).
- **Unlock and lock**: the primary file first, then the device settings
  container, then the further vaults the primary names (a vault whose key does
  not open is `needs_unlock`, the others are still served). Locking drops the
  vaults, the index and the device settings; the admin key survives.
  `status.lockMode` names the lock mode by the protocol's letter (`a` never,
  `b` on idle).
- **Lock modes** (DP-14, `TomSecretsLockPolicy` from `tom_secrets_core`): (a)
  never relock, (b) relock after the user's input has been idle for a while,
  and a hard maximum unlocked time. The idle time comes from CoreGraphics on
  macOS, `GetLastInputInfo` on Windows and logind's idle hint on Linux; where
  it cannot be measured (no desktop session) the service never locks itself.
- **Device settings** (DP-15, `TomSecretsDeviceContainer` in
  `tom_secrets_core`): `bootstrap.yaml` names where the container's key is
  kept: `keychain` (the start is refused without one), `vault` (the overlay
  entry `@host:<host>/.tom-secrets/device` of the primary, which no reference
  reaches), `keyfile` (mode 0600 beside the container), or `auto`. The
  keychain is `TomDesktopSecretStore` of `tom_core_storage` (service
  `tom-secrets-manager`): the macOS login keychain, libsecret on Linux, the
  Windows Credential Manager. Where it does not answer (an SSH login without
  D-Bus or credential store) `auto` takes the vault.
- **Starting it** (`tomSecretsStartService`): the starter makes the admin key,
  starts the service detached, hands the key over on its standard input and
  reads one status line (`ready`, `already_running`, `error`). The starter,
  `TomSecretsAdminClient`, the runtime directory, the data directory and the
  keychain names are `tom_secrets_client`'s admin library
  (`package:tom_secrets_client/admin.dart`), which this package re-exports:
  the app and `tsm` use them without linking the service.

The service reaches KDBX only through `tom_secrets_core` (DP-29).

## Running it

```sh
dart build cli --target bin/tom_secrets_service.dart -o build/service
```

The bundle (`build/service/bundle/`) holds the executable in `bin/` and
`tom_pqc`'s native library in `lib/`; they ship together (`dart compile exe`
does not run `tom_pqc`'s build hook).

It is started by the app or `tsm start`, not by hand: it expects the handover
line on its standard input (`TomSecretsHandover`).

## Testing

```sh
testkit :test
```

`test/process_test.dart` runs on macOS and Linux, `test/windows_test.dart` on
Windows, the others (the service, the editing path and the log, the secret
frames, the hardening seen from outside a hardened process, the peer identity
of a real client process, the `github:` vaults with the offline cache, the
refresh and the key-expiry reminders against `tom_github_api`'s in-memory
GitHub) everywhere.
