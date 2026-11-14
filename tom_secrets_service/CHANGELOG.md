# Changelog

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
