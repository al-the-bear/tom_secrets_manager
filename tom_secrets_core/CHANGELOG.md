# Changelog

## 0.2.14

- The `age` v1 file format (part-sharing, DP-63, DP-177):
  `tomSecretsAgeEncrypt` to hybrid (`mlkem768x25519`: HPKE base mode with
  X-Wing, HKDF-SHA256, ChaCha20-Poly1305) or classical (`X25519`)
  recipients, never both; `tomSecretsAgeDecrypt` with member keys
  (`TomSecretsAgeHybridIdentity`) or classical identities
  (`TomSecretsAgeX25519Identity`); the armour (`tomSecretsAgeArmor`,
  `tomSecretsAgeDearmor`). The reader passes every hybrid vector of the age
  testkit (`test/fixtures/age/`); files go both ways with
  `filippo.io/age` v1.3.2 (hybrid with two recipients, empty, one and
  several 64 KiB chunks, armoured, X25519).
- Shared vaults (part-sharing, part-stores): `TomSecretsSharedVaultKeys`
  (a KeePass key file and, when outer encrypted, a repository key, and the
  members), the recipients file `<vault>.keys.age` written to every
  member's hybrid key and read with a member key
  (`tomSecretsWriteRecipientsFile`, `tomSecretsReadRecipientsFile`,
  plaintext `tsm-shared-vault-keys/1`), adding a member (keys kept) and
  removing one (new keys), `tomSecretsNewSharedVault` (kind `shared`, a key
  file alone), `tomSecretsRecipientsFileName`; `tomSecretsBech32Data`.

## 0.2.13

- Member keys (part-sharing, DP-63, DP-177): `TomSecretsMemberKey`, a
  hybrid `age` v1.3 identity (`AGE-SECRET-KEY-PQ-1…`) generated or parsed,
  its recipient `age1pq1…` (X25519 + ML-KEM-768, `tom_pqc`'s X-Wing);
  `TomSecretsAgeRecipient` reads hybrid and classical `age1…` recipients
  (Bech32 without a length limit; plugin keys, classical identities, bad
  checksums and invalid ML-KEM keys refused), with the fingerprint (base32
  SHA-256 of the recipient) and its short form. The published key file in
  `age`'s recipients-file format (`tomSecretsMemberKeyFile`,
  `tomSecretsReadMemberKeys`). The entry types `member-key` and `member`
  in the primary vault's `tsm.sharing` group, which resolution skips
  (`tomSecretsAddMemberKey`, `tomSecretsAddMember`, `tomSecretsMembers`,
  `tomSecretsMarkMemberChecked`). Checked against `filippo.io/age` v1.3.2.

## 0.2.12

- Auto-type's OS-independent half (part-password-manager, DP-41):
  KeePass's sequence syntax parsed into actions (`tomSecretsParseAutoType`:
  placeholders, special keys with repeat counts, `+ ^ % @` modifiers on a
  key or a group, `~`, `{DELAY n}`, `{DELAY=n}`, escaped characters;
  `tomSecretsAutoTypeValues`), window title patterns
  (`tomSecretsAutoTypeWindowMatches`: wildcards or `//regex//`), the
  sequence an entry types into a window (`tomSecretsAutoTypeSequenceFor`:
  an association's, the entry's, the group's, the default), the entries
  fitting a window (`tomSecretsAutoTypeCandidates`). The merge and
  `tomSecretsCopyEntry` carry an entry's auto-type settings; the library
  re-exports `KdbxAutoTypeSettings` and `KdbxAutoTypeAssociation`. Needs
  `tom_kdbx_store` 0.2.6.

## 0.2.11

- `TomSecretsBrowser` (0.2.10) is `TomSecretsCsvBrowser`: the name clashed
  with `tom_secrets_client`'s browser hosts, which the apps import beside
  this library.

## 0.2.10

- The other imports and the exports (part-password-manager, DP-40):
  Bitwarden's JSON export, plain or password-protected (PBKDF2 or
  Argon2id, HKDF, AES-256-CBC with HMAC; a wrong password and the
  account-restricted export refused), folders as groups, cards and
  identities as 1Password's, SSH keys typed (`tomSecretsReadBitwardenJson`);
  the browsers' CSV exports with the CSV hash identity
  (`tomSecretsReadBrowserCsv`, `TomSecretsBrowser`); another KDBX file as a
  group or merged (`tomSecretsImportKdbxAsGroup`,
  `tomSecretsImportKdbxMerged`, `tomSecretsCopyEntry`); exports to KDBX
  under new credentials, CSV and Bitwarden JSON (`tomSecretsExportKdbx`,
  `tomSecretsExportCsv`, `tomSecretsExportBitwardenJson`,
  `TomSecretsExport`).

## 0.2.9

- The health report (part-password-manager, DP-39, DP-179):
  `tomSecretsHealthReport` lists weak passwords (`tomSecretsPasswordStrength`,
  zxcvbn with the entry's own words), reused ones across the vaults given,
  old ones (`tomSecretsPasswordChanged`, from the history; one year by
  default, `TomSecretsHealthPolicy`), entries expiring within 30 days or
  expired, short SSH keys (`TomSecretsKeyStrength`: RSA below 3072 bits,
  curves below 256, DSA) and breached passwords. `TomSecretsBreachCheck`
  asks the Have I Been Pwned range API with the SHA-1 prefix only and
  `Add-Padding: true`, caching counts per hash in memory; `tsm.breachCheck`
  `off` keeps an entry out (`tomSecretsSetBreachCheckExcluded`). New
  dependency: `zxcvbn` (MIT).

## 0.2.8

- The OS unlock (part-os-unlock, DP-72): lock mode (c)
  `TomSecretsLockMode.osUnlock` (relock on idle or at the screen lock,
  unlock with Touch ID or Windows Hello through the app; on idle it locks
  like (b)); `tomSecretsCompositeKey` (the 32 bytes the OS unlock keeps
  instead of the password text) and `tomSecretsVaultCredentials(compositeKey:)`
  opening a vault with it. Needs `tom_kdbx_store` 0.2.5.

## 0.2.7

- The GitHub App sign-in's records (part-key-rotation §3, DP-83, DP-155):
  the primary's metadata keeps the App's client id
  (`TomSecretsMetadata.githubAppClientId`, `tsm.github-app-client-id`;
  `copyWith(githubAppClientId:, clearGithubAppClientId:)`); a device record
  names how the device reaches GitHub (`TomSecretsGitHubAuth` `app` or
  `token`) and when its token expires (`githubAuth`,
  `githubTokenExpires`, `withGitHub`, `TomSecretsDeviceRecords.setGitHub`).

## 0.2.6

- The agent's side of SSH (part-os-integration, DP-48, DP-49):
  `TomSecretsSshPrivateKey.decode` reads a private key file with its
  passphrase (OpenSSH `openssh-key-v1` unencrypted or under `bcrypt_pbkdf`
  with AES-CTR, -CBC or -GCM; PEM PKCS#1 and SEC1, also `DEK-Info`-encrypted
  with AES-CBC or DES-EDE3-CBC; PKCS#8, also PBES2-encrypted) and signs as
  SSH does (Ed25519; ECDSA P-256/P-384/P-521 with RFC 6979 nonces;
  `rsa-sha2-256` / `rsa-sha2-512`, never SHA-1); `tomSecretsSshVerify`
  checks a signature; `tomSecretsBcryptPbkdf` is OpenBSD's KDF.
- The agent protocol (draft-miller-ssh-agent): `TomSecretsSshAgentFramer`,
  `TomSecretsSshAgentConnection` over a `TomSecretsSshAgentBackend`
  (identities, signatures, `session-bind@openssh.com` checked and recorded,
  a user authentication on a bound connection checked against its session,
  everything else refused), `TomSecretsSshSignRequest` with its destination,
  forwarding and purpose (`userauth`, `sshsig` with its namespace).
- `TomSecretsSshGrantSecret`: an agent grant's secret, `ssh-key [host
  <fingerprints>] [forward] <target>`; `tomSecretsSshAgentStateOf`: whether
  the agent serves an entry's key and why not, and whether each use is
  confirmed; `tomSecretsKnownHostNames`; `tomSecretsSshFingerprint`.
- `TomSecretsKeeAgentSettings.copyWith`, `tomSecretsKeeAgentSettingsOf`,
  `tomSecretsWriteKeeAgentSettings`.
- The vault setting `tsm.ssh-confirm` (`TomSecretsMetadata.sshConfirm`,
  `copyWith`): every agent signature with a key of the vault is confirmed.
- PKCS#8 EC keys with explicit curve parameters (LibreSSL's `ssh-keygen -m
  PKCS8`) are read.

## 0.2.5

- The typed SSH key (part-structure, DP-5): `tomSecretsWriteSshKey` makes an
  entry `ssh-key` with the private key as a protected attachment and
  `KeeAgent.settings` naming it (`TomSecretsKeeAgentSettings`, written as
  KeePassXC writes it, UTF-16); `tomSecretsSshKeyOf` finds an entry's key.
- `TomSecretsSshKeyInfo.parse` reads a private key file without its
  passphrase: OpenSSH (encrypted or not), PKCS#1, SEC1 (named or explicit
  curves), PKCS#8; the type, the public key as `authorized_keys` writes it,
  the fingerprint, the size.
- `tomSecretsGenerateSshKey` (DP-179): Ed25519, or RSA 4096 for a tool that
  needs RSA, written in OpenSSH's format.
- `tomSecretsMigrateSshKeys`: phase A's notes holding a key (and KeePassXC's
  entries) become typed SSH keys, their old state in the history.
- The 1Password import types an SSH key whose key the export carries.

## 0.2.4

- URL matching of login entries (part-browser, protocol.md 5.7):
  `tomSecretsMatchLogins` (the entries of a page, exact host before domain,
  then the last used, then by title; a frame only when it is the same site),
  `TomSecretsSiteUrl` (normalised: https without a scheme, punycode hosts,
  default ports dropped), `tomSecretsMatchSiteUrl` with the
  `tsm.urlMatch` rules `domain`, `host`, `exact`, `never`
  (`TomSecretsEntryFields.urlMatch`), `tomSecretsRegistrableDomain` after
  the Public Suffix List, which the package carries as data
  (`tool/update_public_suffix_list.py`; MPL-2.0, see THIRD_PARTY.md).

## 0.2.3

- `tomSecretsReceivePairingForSetup` takes `linkAddress`: where the new
  machine's approval link will listen, sent to the giving machine with its
  keys so the giver records it and opens the link; checked with
  `tom_secrets_client`'s `tomSecretsApprovalLinkProblem`. Needs
  `tom_secrets_client` 0.2.4.

## 0.2.2

- The README rewritten as the package's manual; API summaries of every area in `doc/api/`.

## 0.2.1

- Setting a machine up by pairing (part-sharing):
  `tomSecretsReceivePairingForSetup` receives with fresh trust material and
  refuses a bundle a new machine cannot be set up from
  (`tomSecretsPairingSetupProblem`: the primary missing, a `github:`
  primary without its token); `TomSecretsFirstRun.runPaired` sets the
  machine up from the receipt; `tomSecretsParsePairingAddress` reads the
  `host:port` the giving side shows.
- The pairing: a receiving side may refuse the bundle
  (`TomSecretsPairingRefusal`, `{"op":"refused","reason"}`), which ends it
  with `TomSecretsPairingFailure.refused` on both sides.
- `TomSecretsTrust.recordPeer`: what a pairing gave, recorded in the trust
  material.

## 0.2.0

- Pairing (part-sharing, DP-60–DP-64, DP-177):
  - `TomSecretsSpake2`: SPAKE2 as RFC 9382 specifies it (P256-SHA256-HKDF-HMAC,
    the RFC's M and N, key confirmation), checked with the RFC's test vectors,
    refusing a point off the curve.
  - `tomSecretsGivePairing` / `tomSecretsReceivePairing`: the pairing over a
    channel. The code (`TomSecretsPairingCode`, `<number>-<word>-<word>`)
    proved by SPAKE2, an ML-KEM-768 exchange inside, the session key mixing
    both secrets with the transcript; then the giving side's bundle
    (`TomSecretsPairingBundle`: vaults with their key files and repository
    keys, the shared configuration, tokens pasted for the device, its public
    keys), the receiving side's public keys, and the approval-token key both
    derive.
  - `TomSecretsPairingWindow`: the giving side's window on the LAN and VPN
    addresses only, the first connection only, five minutes.
  - `tomSecretsReceivePairingAt`: the receiving side over TCP.
- `TomSecretsDeviceRecords`: the device records of the primary
  (`.tom-secrets/devices`, DP-62).
- `TomSecretsLinkFrameReader`: the approval link's framing, for pairing.

## 0.1.6

- `TomSecretsLinkSession.underPreviousKey`: on the host, whether the
  approver connected under the host's previous link key, so the host passes
  it the new one.

## 0.1.5

- A device rotates its own key pairs (part-key-rotation):
  `TomSecretsTrust.rotateApproverKey` makes a new hybrid approver pair and
  answers the key-change statement signed by the old and the new pair;
  `rotateLinkKey` makes a new approval-link pair and keeps the previous one
  for the hosts the new key has not reached (`linkKeyFor`,
  `markLinkKeyDelivered`, `linkKeyPending`) during the migration period
  (`tomSecretsLinkKeyMigration`, 14 days; `expirePreviousLinkKey`;
  `previousLinkKey`, kept to the end of the period while approvers are
  recorded).
- `TomSecretsLinkSession.respond(previousMe:)` also answers an approver that
  still holds the host's previous link key.

## 0.1.4

- `TomSecretsVaultUnit.rekey`: commits a re-keyed file as it is in one commit
  on top of the base's head (never merged; a moved branch is refused with
  `TomCasConflictException`), after which the unit reads and writes with the
  new credentials and outer layer.

## 0.1.3

- `TomSecretsVaultUnit.mergeOverRemote` merges a working copy handed in
  with `replaceWorking(stored:)` over the rewritten remote instead of
  pushing the bytes it was given, and `takeRemote` drops those bytes.

## 0.1.2

- The device settings carry the rotation ages and the reminder start of
  DP-85: `otherKeyWarningDays` (30), `keyPairAgeMonths` (24),
  `primaryKeyAgeMonths` (24), `vaultKeyAgeMonths` (12).

## 0.1.1

- `TomSecretsResolver.explain`: a request explained step by step (the
  request's values, every candidate kept with its rank vector or dropped by
  the binding that drops it, the outcome with its winner or tied candidates),
  ranked through the same code as `resolve`.

## 0.1.0

- Stores over KDBX files with their index (logical paths, bindings, keys),
  overlays in both placements, the metadata entry and `tsm.config`, dimensions
  with priority, configured defaults and `fallback_to_default`, resolution
  with its rank vectors, ambiguity and fields (string fields, attachments,
  `totp`, refused passkey fields), the KDBX mapping and TOTP (RFC 6238, the
  three conventions).
- Vault locators, the GitHub cycle as a `tom_core_sync` sync unit over
  `tom_core_storage` (`TomGitHubStorage`, no clone), the three-way vault merge
  with conflict records, and the primary vault's `.tom-secrets/vaults`.
- `tomSecretsDeviceCommitter`: the device as author and committer of the
  cycle's commits (`<device>@tsm.invalid`), for `TomGitHubStorage.committer`
  (tom_core_storage 0.1.1).
- Signed objects, approval codes and tokens, the approval link (both roles),
  the grants group `tsm.grants/<host>` and the device's trust material
  (protocol.md 9; `tom_pqc` for ML-DSA-65 and ML-KEM-768).
- `TomSecretsFieldValue` held as a `TomProtectedValue` (tom_crypto 1.5.0):
  `withBytes` hands out bytes zeroed after use, `dispose` zeroes it without
  touching the vault's attachment.
- Key files (`TomSecretsKeyFile`, KeePass 2.0 XML) in the composite key, the
  key derived once from the file's bytes as KeePass derives it, and
  the `.tsmx` outer format with key slots under XChaCha20-Poly1305 (default)
  or AES-256-GCM (`tomSecretsOuterEncrypt` / `Decrypt`,
  `TomSecretsOuterCodec`, `TomSecretsRepositoryKey`).
- New vaults (`tomSecretsNewVault`): KDBX 4.1 keyed through Argon2id,
  `tomSecretsDefaultArgon2` (64 MiB, 3 iterations); `TomSecretsVaultUnit.create`
  refuses a file keyed otherwise.
- The offline cache (`TomSecretsOfflineCache`) in the vault cycle: kept on
  every read and write, opened from when the remote is unreachable or refuses
  the token; telling a compaction from a force push (`tomSecretsClassifyMove`,
  `TomSecretsCommitReader`, `TomSecretsHistoryRewritten`, `mergeOverRemote`);
  the app's compaction with `tom_git` (`tomSecretsCompact`) and the
  compaction workflow, script and configuration for the vault repositories
  (`tomSecretsCompactionFiles`).
- Imports (`tomSecretsImport`, `TomSecretsImportSource`, the report) and the
  1Password importer for 1PUX and CSV (`tomSecretsRead1Pux`,
  `tomSecretsRead1PasswordCsv`).
- The Enpass importer for JSON and CSV (`tomSecretsReadEnpassJson`,
  `tomSecretsReadEnpassCsv`) with passkeys into `KPEX_PASSKEY_*`
  (`TomSecretsPasskey`, `tomSecretsPasskeyPem`), and the Enpass JSON export
  (`tomSecretsExportEnpassJson`). Imports know folders, trashed items and
  kept passkeys.
- The device settings and their container with the key modes
  (`TomSecretsDeviceSettings`, `TomSecretsDeviceContainer`,
  `TomSecretsDeviceKeys`, `TomSecretsLockPolicy`); the KDBX types the other
  packages handle are re-exported (DP-29). A `.tom-secrets` group is never
  indexed, at any depth.
- The first run (`TomSecretsFirstRun`): a primary created or opened, local
  or on GitHub, its key file and repository key kept in the device keychain
  (`tsm.key-file.<id>`, `tsm.repository-key.<id>`), `tsm.keys-due` 24 months on,
  the device settings and `bootstrap.yaml`; a `.tsmx` rewrite keeps its
  cipher; a `.kdbx.tsmx` file's store name drops both suffixes.
