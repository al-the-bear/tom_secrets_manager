# Changelog

## 0.11.6

- The pairing mode takes the handover's `approvalLink`: it goes into the
  device settings the machine is set up with and, as this machine's link
  address, to the giving machine, whose service then opens the approval
  link at once (`tsm pair --link`). A link that is no approval link ends
  the pairing mode with `handover` before anything is sent.
- `settings.set` and the link server check an approval link with
  `tomSecretsApprovalLinkProblem` (`tom_secrets_client` 0.2.4): `settings.set`
  now refuses every interface (`0.0.0.0`, `::`) as the link server did.

## 0.11.5

- `vault.create` (protocol.md 6.4, manager app only): a further vault
  created beside the primary. The app's new file is written where it lives
  (`TomSecretsVaultOpener.create`: a `file:` vault at its path, its folder
  made; a `github:` vault in one commit through `TomSecretsVaultUnit.create`),
  refused when a file is there (`target_exists`); only then is it listed in
  the primary with its keys, the token of a repository outside the primary's
  and its due date (`keysDue`), the primary written, and the vault served
  (`TomSecretsVaultSet.create`, `TomSecretsService.createVault`).

## 0.11.4

- The client endpoint's rate limits (protocol.md 11), per measured identity
  (`TomSecretsRateLimits`, `TomSecretsServiceConfig.rateLimits`): a token
  bucket of 20 `get`/`getMany` a second with bursts of 50 (`rate_limited`,
  `reason` `requests`, `retryAfterMs`); a 10 s wait per request for ten
  minutes after ten refusals in a minute; 16 open connections per identity
  and 256 in all (a connection over them is answered `rate_limited`,
  `reason` `connections`, at its `hello`).

## 0.11.3

- The README rewritten: installing and starting, configuration (`bootstrap.yaml`, device settings, environment), what the service does, limits, key types.

## 0.11.2

- The approver's links (`TomSecretsApproverLinks`): the service keeps a
  session to every paired host it approves for, passes the host's prompts to
  the attached app (ids qualified `<host>/<approvalId>`) and carries the
  app's answers over the link (grants signed by this device; the client
  token with its `exe-token` grant); a host's new link key is recorded.
- `TomSecretsIdentity.fromJson`, `tomSecretsGrantSubject`,
  `tomSecretsTakeHostLinkKey` public.

## 0.11.1

- The pairing mode (`tsm pair`, part-sharing): started with a
  `TomSecretsPairingHandover`, the executable receives a pairing, reports
  it, sets the machine up with the master password tsm sends
  (`TomSecretsFirstRun.runPaired`) and ends (`tomSecretsRunPairingMode`).
- `pair.record` records through `TomSecretsTrust.recordPeer`.

## 0.11.0

- Pairing (manager app only, protocol.md 6.3, 9.8):
  - `pair.identity`: this device's public keys and link address.
  - `pair.record`: a paired device recorded as an approver of this host
    and/or a host this device approves for, with the approval-token key,
    every key dated now, a device paired again replaced, and with `record`
    its device record in the primary.
  - `pair.revoke`: what was recorded of the device goes and its record is
    marked revoked.
  - `pair.list`: the device records.

## 0.10.0

- A host that rotated its own link key passes the new one to an approver
  that connects under its previous key, first in that session (`linkKey`,
  protocol.md 9.7); the host takes the approver's answer. The approver's
  side (`tomSecretsDeliverOverLink(onHostLinkKey:)`) records it for that
  host and answers `ok`, and the service writes it into its trust material,
  so the approver connects under the new key from then on.

## 0.9.0

- `vault.move` (manager app only, protocol.md 6.4): a store's outer
  encryption added or removed, which moves it to its locator with
  `.kdbx.tsmx` or `.kdbx`. The opener's new `move` writes the new file and
  then removes the old one (a `file:` store), or does both in one commit
  put on the branch without force (a `github:` store); a stale copy, a file
  at the new place or a branch that moved refuses it and the old file
  stays. A further vault's entry in the primary takes the new locator and
  keys; for the primary, the bootstrap file's `primary:` and the keychain's
  key file and repository key under the new locator's handles follow.
- `tomSecretsBootstrapWithPrimary`: a bootstrap file with another primary,
  every other line kept.

## 0.8.0

- `keys.rotate {approver?, link?}` (manager app only, protocol.md 6.3): this
  device rotates its own key pairs. A new approver pair: every grant and
  revocation it signed is signed again, and its key-change statement is
  written into the group of every host it approves for. A new link pair:
  the previous one stays in use for 14 days, for the hosts the new key has
  not reached and the approvers that connect here (the link server answers
  under it). Both go to every recorded host over the approval link at once
  (`tomSecretsDeliverOverLink`, the approver's side of the link); hosts not
  reached get the new link key at a later refresh.
- A host takes key-change statements from its group of the vault at every
  allow-list read (a host the link did not reach), and answers a statement
  it took already `ok` over the link.
- `keyList.keys[].own` marks this device's own key pairs.

## 0.7.0

- `token.set {repository, token}` (manager app only, protocol.md 6.3):
  renews a vault repository's GitHub token. The token is checked first
  (`tomSecretsCheckGitHubToken`: it sees the repository, a short-lived
  `tsm-token-check-…` branch is created and deleted to prove it may write,
  the expiry GitHub reports is taken), then it replaces the old one where
  that lives (the device keychain with its expiry, else the primary's
  vault entries for that repository) and every store is fetched again.

## 0.6.0

- Re-keyed saves (part-key-rotation, protocol.md 6.4): a further vault's
  file that opens only with the keys the primary lists for it now is taken
  as re-keyed; the primary's carries its new keys in `save`'s `keys`, which
  then replace its key file and repository key in the device keychain. A
  re-keyed file is written as it is through the opener's new `rekey` (never
  merged; `stale_base` when the file moved), and the store's keys are the
  new ones from then on. A vault whose listed keys do not open it yet stays
  served with the keys held, and a vault not served keeps its copy while
  its file has not moved.
- `compact` takes `retentionDays`, replacing the repository's retention
  (0 after a key change).

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
