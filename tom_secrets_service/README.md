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
- **Admin endpoint**: `admin.sock`, or `admin.port`. Nothing is answered before
  the mutual challenge (`challenge`, `auth`, `authed`: HMAC-SHA256 under the
  admin key, protocol.md 6.1) or a `claim` with the master password, which
  issues a new admin key and revokes the old one. Failed authentications delay
  the next one (1 s, 2 s, 4 s … 60 s). Then `unlock`, `unlockStore`, `lock`,
  `status`, `subscribe` (the events `unlocked`, `locked`, `unlock_needed`) and
  `shutdown`.
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

`test/service_test.dart` and `test/process_test.dart` run on macOS and Linux,
`test/windows_test.dart` on Windows.
