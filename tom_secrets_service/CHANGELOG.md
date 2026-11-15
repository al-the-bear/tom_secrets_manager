# Changelog

## 0.5.0

- A `github:` store whose branch was rewritten without a compaction:
  after the refused save it reports the state (`rewritten: {head}` in
  `statusReport.stores[]` and `store_state`), holds the refused edit and is
  not refreshed until the manager app answers with `history.resolve`
  (`take: remote` follows the rewritten branch, `take: merge` merges the
  held copy over it and commits on top; protocol.md 6.3, 6.4).

## 0.4.0

- The key reminders take the rotation age of the key pairs and the reminder
  start of the other keys from the device settings (`keyPairAgeMonths`,
  `otherKeyWarningDays`, DP-85) instead of constants; `settings.set` checks
  the new settings' ranges.

## 0.3.0

- `settings.get` and `settings.set` (protocol.md 6.3): the device settings,
  the command-line approval switch and the stores the primary names; a
  write is accepted only from the manager app, checked
  (`tomSecretsSettingsProblem`), applied at once for the lock policy, the
  refresh, the timeouts, the cache and the reminder period, and answers
  which settings apply at the next unlock.

## 0.2.0

- A vault the primary lists that this machine does not serve can be edited
  through the editing path (BP-15, protocol.md 6.4): `vaultKeySet.unserved`
  lists such vaults, `vaultKeys` naming one answers its keys with `served`
  false, `vaultFile` naming one reads it from its location and holds it for
  editing until the lock, and `save` writes it there (a `github:` vault as
  a commit by this device). It is never served to clients.

## 0.1.0

- The service: the runtime directory with its owner and mode check, the
  single-instance lock and `service.json`; the client endpoint (Unix socket, or
  localhost TCP with the client token) with `hello`, `get`, `getMany` and the
  access policy; the admin endpoint with the mutual HMAC challenge, `claim`,
  the growing delay after failures, `unlock`, `unlockStore`, `lock`, `status`,
  `subscribe` and `shutdown`; lock modes (a) and (b) with the maximum unlocked
  time and the idle time per OS; the device settings container with its key
  modes; the starter, the handover and the admin client.
- The unlock takes the primary's key file (when the request carries none)
  and a `.tsmx` primary's repository key from the device keychain; the
  primary is opened, refreshed and written with its outer key.
- The service admits the manager app of the distribution it is part of
  (`tomSecretsDistributionApp`: the app carries `tsm` and the service in its
  `tsm/bin` folder) besides `tsm` and the app beside it.
