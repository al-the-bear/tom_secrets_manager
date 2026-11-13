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
  refuses every value until the allow list and approvals are configured.
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
- **Admin endpoint**: `admin.sock`, or `admin.port`. The admin's executable
  must be `tsm` or the manager app beside the service, or one named in
  `admin_executables:` of `bootstrap.yaml`; any other is refused before its
  key is checked (`wrong_executable`). Nothing is answered before
  the mutual challenge (`challenge`, `auth`, `authed`: HMAC-SHA256 under the
  admin key, protocol.md 6.1) or a `claim` with the master password, which
  issues a new admin key and revokes the old one. Failed authentications delay
  the next one (1 s, 2 s, 4 s … 60 s). Then `unlock`, `unlockStore`, `lock`,
  `status`, `subscribe` (the events `unlocked`, `locked`, `unlock_needed`,
  `store_changed`), `vaultKeys`, `save` and `shutdown`.
- **The editing path** (DP-13, protocol.md 6.4): `vaultKeys` hands the app the
  keys of the open vaults (`password`, `keyFile`, `outerKey`) and their
  locations; `save` takes the app's edited file, which must open with the
  store's keys. A file still at `baseRevision` is written as it is; a file
  that moved meanwhile is merged three-way when the app edited the service's
  copy, and refused (`stale_base`) otherwise. The store is reopened and
  `store_changed` names the new revision. `file:` vaults are written on the
  local disk; `github:` vaults are not opened yet (the GitHub opener comes
  with the refresh) and answer `unavailable`.
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
  reads one status line (`ready`, `already_running`, `error`).
  `TomSecretsAdminClient` is the admin side for the app and `tsm`.

The service reaches KDBX only through `tom_secrets_core` (DP-29).

## Running it

```sh
dart compile exe bin/tom_secrets_service.dart -o tom_secrets_service
```

It is started by the app or `tsm start`, not by hand: it expects the handover
line on its standard input (`TomSecretsHandover`).

## Testing

```sh
testkit :test
```

`test/process_test.dart` runs on macOS and Linux, `test/windows_test.dart` on
Windows, the others (the service, the editing path and the log, the secret
frames, the hardening seen from outside a hardened process, the peer identity
of a real client process) everywhere.
