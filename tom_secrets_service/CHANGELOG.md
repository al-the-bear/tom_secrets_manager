# Changelog

## 0.25.5

- The client endpoint in the macOS app's App Group container (protocol.md
  3.1, part-browser): when the service runs from the manager app's tools
  folder and the app names its App Group (`TSMAppGroup`), it also listens
  on `~/Library/Group Containers/<group>/tsm/client.sock`, which the
  sandboxed Safari Web Extension's host reaches. `tomSecretsAppGroupOf`,
  `tomSecretsAppGroupClientSocketFor`, the configuration's
  `groupClientSocket`.

## 0.25.4

- The Windows passkey plugin `tsm-passkey-plugin.exe` beside the service is
  a passkey client (protocol.md 5.8, DP-120): told by its measured
  executable, it may send `passkeys`, `passkeyGet` and `passkeyCreate`, as
  the browser host does, and nothing else (`get`, `getMany`, `getFile`,
  `match` and `propose` are `denied`, reason `not_allowed_op`).
  `tomSecretsLookupExecutables` finds it (`passkeyPlugins`), and the
  configuration takes it as `passkeyPluginExecutables`.

## 0.25.3

- Passkeys for the browser host (protocol.md 5.8, feature `passkey`,
  DP-120): `passkeys` (a page's passkeys by name and credential id, never a
  system vault's, the browser prompt with `passkey` when no grant covers
  them), `passkeyGet` (the service signs; the key never leaves it) and
  `passkeyCreate` (the app confirms it, `approval_needed` with
  `passkeyCreate`; the passkey kept in the site's login and the vault
  written before the answer); `TomSecretsService.editStore` and the vault
  set's `edit` for the service's own edit of a further vault.

## 0.25.2

- The pairing mode receives through a magic-wormhole mailbox server too
  (`relay: wormhole:ws(s)://…`, `tom_secrets_core` 0.2.25's
  `TomSecretsWormholeRelay`), as through a relay server: no token, and a
  server that fails ends the pairing with code 6 naming it. The handover no
  longer refuses it (`tom_secrets_client` 0.2.15 reads it).

## 0.25.1

- On `tom_secrets_core` 0.2.24: the relay server client paces its requests
  under the relay's per-address limits, so the service's approval links
  and `relay.put`s to many members never get its address blocked.
- `linkRelay` keeps one relay server client per relay and instance token
  while the service runs (it built a new one, with an HTTP client never
  closed, at every link channel and every put); a new token closes the old
  client; `stop` closes them all.

## 0.25.0

- `relay.put {relay, members, bytes}`: a share put into the mailbox of each
  member on a relay server, under one new package name kept 30 days, with
  the instance token the keychain keeps for the relay (a shared vault whose
  mailbox relay is a relay server, part-relay); a refusal (no token, the
  relay's limits) is `unavailable` with reason `relay` and the relay's
  message. The app reads, fetches and deletes the items itself with the
  member key's proof.

## 0.24.0

- The approval link through a relay server (part-relay): a host keeps the
  relay channel of each approver whose pairing agreed on a relay link open
  while unlocked (`TomSecretsRelayLinkHost`), an approver falls back to the
  relay when the host's address does not answer (`TomSecretsApproverLinks`),
  the handshake unchanged over the channel; the relay's instance token from
  the keychain (`relay.token.set`, `relay.token.list`); `status` reports
  every link (`links`: state, way, reason); `pair.identity` takes a relay
  server, `pair.record` a `link`; the pairing mode offers its relay server
  for the link and keeps the handover's instance token. Needs
  `tom_secrets_core` 0.2.23.

## 0.23.2

- `tomSecretsServiceVersion` (in the welcome and `status`) is the package's
  version again; 0.23.0 and 0.23.1 named 0.23.0. A test holds the two
  together.

## 0.23.1

- The pairing mode receives through a relay server too (`tsm pair --relay
  tsm:<url>`), with no token; the relay is built by `tom_secrets_core`'s
  `tomSecretsRelayFor`. Needs `tom_secrets_client` 0.2.13.

## 0.23.0

- The pairing mode receives through a GitHub relay (part-relay, `tsm pair
  --relay … --token-env …`): the handover's `relay` and `relayToken` (and
  `relayApi`), after the address when one is given, else alone; the
  machine's own token for the repository kept for the primary and reported;
  a relay failure ends with code 6 naming the relay. Needs
  `tom_secrets_client` 0.2.12.

## 0.22.0

- The relay requests (part-relay, protocol.md 6.4): `relay.revision`,
  `relay.list`, `relay.read`, `relay.create`, `relay.deleteFolder`,
  `relay.deleteFile` on the `relay/` folder of a `github:` store's
  repository, for the app's pairing through GitHub (manager app only,
  unlocked); through the repository's `TomGitHubStorage`, whose branch
  snapshot answers an unchanged branch with a conditional request. Needs
  `tom_secrets_core` 0.2.21.

## 0.21.0

- Typed certificates and PGP keys (part-sharing, part-protocol, BP-33):
  `getFile` of such an entry without a field (neither the request's nor the
  reference's) answers its private key: a certificate's `private-key.pem`
  (or PKCS#12 bundle), a PGP key's secret key (else its public key). Their
  expiry is a key reminder (`keys`, `status.expiring`, kinds `certificate`
  and `pgp_key`, `certificate:<store>/<title>`), from 30 days before.
- `TomSecretsVaultSet.openFiles`: the files of the stores served.

## 0.20.1

- The guided rotation (part-key-rotation): the primary's keys taken up with
  its next keys (`TomSecretsVaultSet.primaryKeysWith`, the keychain
  fallback) kept a key file and an OS unlock's composite key as zeros (a
  copy made after `withRevealed` wiped the bytes), so a primary with a key
  file did not open once its repository key was taken up; copied inside
  the callback now.

## 0.20.0

- The guided rotation of the own vaults (part-key-rotation, protocol.md
  6.4, decision 43): every device's service takes the next keys from the
  primary at each unlock, refresh and save of it (`tomSecretsTakeNextKeys`:
  its device record, the rotation's pending); the primary's own next keys
  go into the keychain (`<handle>.next`), and after another device switched
  the refresh and the unlock open the primary with them and keep them as
  its keys; a repository key rotated alone is taken up once the file has a
  slot for it and dropped after the finish.
- Two-slot `.tsmx` files: the held keys of a vault in a migration period
  name the new and the old repository key, every write keeps both slots;
  `vaultKeys` answers `previousOuterKey`, `save`'s `keys` takes it; a
  device whose file is under a newer key than it holds reads it with
  `keyChanged` and its saves are refused (`needs_unlock`, `key_changed`).
- `token.set` keeps a vault entry's next and previous keys.

## 0.19.0

- The inbox folders of shared vaults (part-sharing, protocol.md 6.4,
  decision 42): the admin requests `inbox.list`, `inbox.read`, `inbox.put`
  and `inbox.delete` (manager app only) over `inbox/<member>/` beside a
  shared vault; the packages are opaque `age` files the app writes and
  reads.
- `TomSecretsVaultOpener` gains `listBeside` and `deleteBeside`, and
  `readBeside` / `writeBeside` take a path below the vault's folder
  (`tomSecretsBesidePath` checks it): an implementer adds the two methods.

## 0.18.0

- The migration period of a rotation (part-key-rotation, protocol.md 6.4,
  decision 41): a vault whose current file no longer opens with the keys
  held, because another device re-keyed it, stays served from the copy
  held, or after a new unlock from the offline copy the held keys still
  open (`TomSecretsKeyChangedException`), read-only: `needs_unlock`,
  `source` `cache`, `keyChanged` in the store state; clients read it, a
  save is refused (`needs_unlock`, reason `key_changed`); once the primary
  lists the new keys it is current and writable again.
- The member key's rotation age (DP-85): `keys` / `status.expiring` list
  `member_key` (`member-key:<fingerprint>`, from the `member-key` entry's
  creation plus `memberKeyAgeMonths`, default 24); the device setting is
  checked (1..120). Takes `tom_secrets_core` 0.2.15.

## 0.17.0

- Shared vaults (part-sharing, protocol.md 6.4): `vault.recipients` reads
  a shared vault's recipients file `<vault>.keys.age` beside it, by store
  or, for a vault not listed yet, by location with the GitHub token the
  request brings (used for that read only); `vault.recipients.set` writes
  it alone over the revision read (`stale_base` otherwise); `vault.create`
  takes `recipients` for a shared vault (keys with a key file alone),
  written after the vault is listed; a re-keyed `save` takes `recipients`
  and writes the re-keyed vault and the file in one commit, without force
  (`stale_base` when the branch moved), and refuses it with a save that is
  not re-keyed. `TomSecretsVaultOpener` gains `readBeside`, `writeBeside`
  and `rekey`'s `beside`; the GitHub opener commits trees through one
  helper (`vault.move` too). Takes `tom_secrets_core` 0.2.14.

## 0.16.1

- Takes `tom_secrets_core` 0.2.13: the primary vault's `tsm.sharing`
  group (the member key and the directory of members, part-sharing) is
  never resolved into, so no client reads a member key.

## 0.16.0

- The browser prompt (protocol.md 5.5, decision 39, DP-44): the browser
  host's `match` that no grant covers asks the approvers once for the
  page's logins in the personal and shared vaults (`approval_needed` with
  `browser` and `url`; `askBrowser`); `always` / `never` write grants for
  the host as started by its browser (`exe-from`, also from a remote
  approver), `once` holds for that browser's host for 10 minutes across
  connections, `folder` is refused. No approver connected: no prompt.
- The browser host never gets a system vault's value: `get`, `getMany` and
  `getFile` of one are `denied` (reason `system_vault`), audited.
- `tomSecretsGrantSubject` takes `browser`; `tomSecretsLauncherOf` measures
  the browser above `cmd.exe` on Windows.

## 0.15.1

- After an OS unlock the app edits with the primary's composite key: the
  primary's `keys` of `save` and `vault.move` take `compositeKey` (base64, 32
  bytes) in place of `password` and `keyFile` (`keyFile` may come beside it
  for the keychain); a further vault's keys still need the password. The
  service keeps the keychain's key file beside the composite key, so
  `vaultKeys` still names it (pairing, the emergency sheet, a new vault
  sharing it), while the composite key opens the vault.

## 0.15.0

- The OS unlock (part-os-unlock, protocol.md 6.4, decision 38):
  `unlock {vault, bundle}` opens the sealed key bundle with the admin
  connection's bundle key (HKDF of the admin key and both nonces): while
  locked it unlocks the service with the primary's composite key (a primary
  of another name locks again, `not_found`), unlocked it opens the store it
  names; a bundle that does not open is `denied` `bad_bundle` and counts as
  a failed authentication, a composite key that no longer opens the vault
  (re-keyed) `bad_password`; a connection that claimed the service sends
  none (`unsupported`). The service then holds the composite key in place
  of the password (`TomSecretsHeldKeys.compositeKey`, `ofBundle`) and the
  editing path's `vaultKeySet` carries it as `keys.compositeKey`; the
  keychain adds no key file to it.
- Lock mode (c) (`osUnlock`): accepted by `settings.set`, `status` says
  `c`; it relocks on idle like (b), and the app sends `lock` at the screen
  lock.
- Needs `tom_secrets_client` 0.2.9, `tom_secrets_core` 0.2.8,
  `tom_kdbx_store` 0.2.5.

## 0.14.0

- "Sign in with GitHub" (part-key-rotation §3, DP-6, DP-83, DP-155,
  protocol.md 6.3): `github.app` (where the sign-in stands, never a
  token), `github.app.configure` (the App's client id into the primary's
  metadata, the manager app only), `github.signIn` (the device flow: the
  code to enter, then the event `github_sign_in`), `github.signOut`. The
  service is the single owner of the device's user tokens
  (`TomSecretsGitHubApp`, keychain item `tsm.github-app.session`): a
  signed-in device uses them for every `github:` vault, renewed before the
  8 hours run out and once at GitHub's first 401; a refused refresh token
  leaves `sign_in_again`. No client secret or App private key anywhere.
- `statusReport.github`; the key `github-app:<device>` (the refresh
  token's expiry) in `keys` and the reminders; the device's record names
  how it reaches GitHub (`githubAuth`, `githubTokenExpires`), also after
  `token.set`.
- A keychain that says it is not available is not read at start.
- `TomSecretsServiceConfig.githubWebUrl`. On `tom_secrets_core` 0.2.7.

## 0.13.0

- The git credential helper's side (part-os-integration, DP-52, DP-53):
  `match` takes `userName` and, for the helpers, `pick`: one login of the
  host by the host rule — the one the client's grants cover, of several the
  one an allow grant names by its reference, else the user picks one of the
  host's logins at the app's prompt (`approval_needed.pick` and `url`,
  answered by `approve` with `pick`): `always` writes a grant for that
  login's reference (the helper's subject names the tool that started it,
  `exe-from git => tsm`), `once` lets the connection read it once; refused,
  unanswered or with no approver connected, none. Over the approval link
  too.
- `propose` is open to the helpers holding an allow grant; a credential the
  vaults hold already is ignored (`accepted` with `known`).
- `TomSecretsCoverage.named`; `tomSecretsIsHelperCall`.

## 0.12.0

- The ssh-agent (part-os-integration, DP-48, DP-49, protocol.md 7.6): a
  third endpoint, `agent.sock` on Linux and macOS and the named pipe
  `\\.\pipe\tsm-ssh-agent` on Windows (FFI, overlapped I/O, the
  client's process from `GetNamedPipeClientProcessId`), named in
  `service.json` and `status` as `agent`. It lists and signs with the
  vaults' `ssh-key` entries; its peers are measured as clients are.
- Agent grants: the secret `ssh-key [host <fingerprints>] [forward]
  <target>`, matched per destination host (`session-bind`) and forwarding;
  a forwarded request without a forwarding grant is refused without a
  prompt; a forwarded one with it, and a key or vault marked to confirm, is
  confirmed each time (`approval_needed.confirmOnly`, answered `once` or
  `never`). `approval_needed.ssh` names the key, the destination (with its
  `known_hosts` names) and the purpose.
- `approve` takes `sshHost` (a lasting agent grant only for the
  destination) and `withParent` (the subject `exe-from <parent> =>
  <exe>`, e.g. ssh started by git); `grants.add` takes both forms.
- Locked, the agent lists the keys kept with their grants
  (`agent_keys.json`) and a signature waits for an unlock.
- The audit record has `ssh`.
- `TomSecretsSystemPeerMeasurer.measureProcess` measures a process by its
  id.
- On `tom_secrets_client` ^0.2.6.

## 0.11.8

- The phase-B client messages as features under protocol 1 (protocol.md
  5.5, section 8): `welcome.features` offers `binary`, `getFile`, `match`
  and `propose`, and the service keeps the ones the client's `hello` names.
- `getFile`: an attachment or a field as bytes, `file`, binary chunks of
  256 KiB (`TomSecretsConnection.sendChunk`), `end` with its SHA-256; only
  for a client that named `binary` and `getFile`.
- `match`: the login entries of a page (`tomSecretsMatchLogins`) that an
  `allow` grant of the client covers (`TomSecretsLookupPolicy.coverage`,
  `TomSecretsCoverage`), never a value; only for the browser host and the
  helpers (`TomSecretsServiceConfig.browserHostExecutables`,
  `helperExecutables`, `tomSecretsLookupExecutables`), no system vault for
  the browser host, audited.
- `propose`: a login of the browser host holding an `allow` grant, passed
  to the attached manager app as the event `proposal`; `unavailable`
  (`no_app`) with no app attached.
- The rate limits count `getFile`, `match` and `propose` with `get`.

## 0.11.7

- The approval link's listener survives a connection that drops before or
  during the handshake (a port scan, a peer that went away): the peer's
  address is read when the connection is accepted, and a failed write ends
  that session only. Before, reading the address of a closed socket for the
  log stopped the service.

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
