# Changelog

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
