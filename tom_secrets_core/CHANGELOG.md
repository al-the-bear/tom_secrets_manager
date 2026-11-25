# Changelog

## 0.2.34

- The First run makes the data directory the user's alone on a desktop
  (`tom_secrets_client` 0.2.20's `tomSecretsPrepareDataDirectory`): before
  anything is written (a looser folder tightened) and again once the
  bootstrap is written, so every file it wrote is 0600 (Windows: the
  user-only ACL). A data directory that is no folder or another user's is
  refused with the new problem `TomSecretsFirstRunProblem.dataDirectory`,
  before anything is written.

## 0.2.33

- Pairing: the receiving side names its platform in its `done` answer
  (`tomSecretsReceivePairing`'s `platform`, default the one it runs on),
  and the giving side has it as `TomSecretsPairingGiven.receiverPlatform`
  (null for an older device, or a value that is no lower-case name), so
  the device record of a paired device says what it is.

## 0.2.32

- `TomSecretsTotp.fromEntry` reads KeePass 2.47's other secret fields:
  `TimeOtp-Secret` (UTF-8), `TimeOtp-Secret-Hex` and
  `TimeOtp-Secret-Base64`, in KeePass's order (UTF-8 first). `writeTo`
  removes them, so a stale one never wins in KeePass.
- `TomSecretsTotp.parse`: what a user types or a QR code holds, in one
  place: an `otpauth://` URI, Google Authenticator's
  `otpauth-migration://` export of one TOTP account
  (`TomSecretsTotpMigration`; several accounts or a HOTP one are named,
  not read), a base32 secret, or a hex secret (`hex:` optional; a text
  both base32 and hex is base32). `tomSecretsHexDecode`.
- `TomSecretsTotpFields.all`: every TOTP field.

## 0.2.31

- New vaults are keyed by Argon2id over 64 MiB with 4 iterations (was 3),
  the same on every device: about a third of a second to unlock on the
  fleet's desktops, about a second on a phone. Existing vaults keep the
  parameters they were made with. The doc comment of
  `tomSecretsDefaultArgon2` no longer says the app tunes it per device.

## 0.2.30

- `TomSecretsDeviceSettings.startAtLogin` is gone: nothing read it (the
  app's "Start the app at login" switch is the OS's own login item, Run key
  or autostart entry). Settings written with the key still read; it is
  ignored and not written again.

## 0.2.29

- An Enpass JSON import no longer fails on one passkey it cannot read (a
  private key that is not base64, a JWK without `d`, a PEM or DER that is
  not a key, a credential id that is not base64, a passkey value that is
  not JSON): the item is imported without it, and `notImported` names it
  as a "passkey that could not be read" with the reason, never quoting the
  key. 1PUX and Bitwarden exports were never affected: they convert no
  passkey keys, and the tests now say so.

## 0.2.28

- The Enpass and 1Password imports keep each field's own label: a section
  no longer prefixes it (`Weitere Details · PIN` is now `PIN`); a label
  used twice in one item gets a number (`PIN (2)`). A field named like a
  reserved or passkey field (`tsm.*`, `KPEX_PASSKEY_*`) is written as
  `(imported) <name>`, so it never keeps the reserved prefix.

## 0.2.27

- `tomSecretsRpIdValidFor`: whether a page may use a relying party's
  passkeys, by WebAuthn's rule (https or `http://localhost`, the page's host
  or a domain above it, never a public suffix or an IP address), for the
  service's passkey requests (protocol.md 5.8).

## 0.2.26

- Passkeys for the OS providers (part-password-manager,
  part-os-integration, DP-120): the package as a WebAuthn authenticator.
  - `tomSecretsCreatePasskey` makes ES256 or Ed25519, by the site's order,
    with the `none` attestation.
  - `tomSecretsPasskeyAssertion` signs a sign-in.
  - Both set the flags present, verified, backup eligible and backed up,
    and the counter 0.
  - `tomSecretsPasskeyRegistrationJson` and `tomSecretsPasskeyAssertionJson`
    write the `PublicKeyCredential` JSON; `tomSecretsPasskeyClientDataJson`
    makes an app's client data.
  - `tomSecretsPasskeyKeyOf` reads a passkey's key, `tomSecretsPasskeysIn`
    lists a vault's passkeys.
  - `tomSecretsKeepPasskey` keeps a new passkey in the site's login entry,
    else in a new entry; `tomSecretsPasskeyHome` picks the vault.
  - Checked against py_webauthn 3.0.1 as a relying party.

## 0.2.25

- A magic-wormhole mailbox server as a relay (part-relay, DP-66, DP-180):
  `TomSecretsWormholeRelay` (`wormhole:ws(s)://…`, pairing only) on the
  existing servers unchanged, speaking the mailbox protocol a client needs
  (`bind`, `allocate`, `claim`, `open`, `add`, `release`, `close`, `ping`)
  with the app's own application id (`tomSecretsWormholeAppId`). The
  server allocates the nameplate (the code's number); each frame is one
  mailbox message, so the pairing's SPAKE2 with ML-KEM-768 inside runs
  unchanged; the hosting side's first message (phase `host`) tells the
  joining side that a pairing waits (a claim opens any nameplate, a server
  may refuse its list); the nameplate is released once both sides have the
  mailbox; the hosting side closes after the app's own 10 minutes
  (`tomSecretsWormholeLifetime`); a welcome's `error` is said and a Hashcash
  proof of work answered (`submit-permissions`, `tomSecretsHashcashStamp`).
  `tomSecretsRelayFor` builds it; `tomSecretsWormholePublicServer` names the
  public server. Tested against a fake in the test's process and, by hand,
  against the real `magic-wormhole-mailbox-server` 0.8.0.

## 0.2.24

- The relay client paces its requests (part-relay, DP-65):
  `TomSecretsServerRelay` waits for each HTTP request's and WebSocket
  opening's turn on the relay's `TomSecretsRelayPacer` (one per relay
  address in the process, shared by every client of that relay), within
  `tomSecretsRelayClientBudgets` (5 a second, 60 a minute, 1,000 a day,
  about half of the relay's per-address limits), so a mailbox read of many
  items or a share to many members never gets the address blocked. A turn
  further away than `tomSecretsRelayLongestWait` is refused, naming when
  the next request goes (`TomSecretsRelayBudgetSpent`). A `429` with
  `Retry-After` is waited out and asked again once
  (`tomSecretsRetryAfter`, `TomSecretsRelayUpgradeRefused.retryAfter`).

## 0.2.23

- The approval link through a relay server (part-relay): the pairing's
  public keys may name a relay server and a random link id
  (`TomSecretsPairingPeerKeys.linkRelay` / `linkId`, `tomSecretsNewLinkId`);
  `tomSecretsPairingLink` takes the giving side's, else the receiving
  side's; `TomSecretsTrust.recordPeer(link:, peerIsGiver:)` keeps the relay
  and one channel per direction (`tomSecretsLinkChannelId`) with the host
  and the approver (`relay`, `linkId`). `tomSecretsReceivePairingForSetup`
  takes a `linkRelay`; the receipt keeps the keys it answered with
  (`ownKeys`, `link`), and `TomSecretsFirstRun.runPaired` records the link.

## 0.2.22

- The relay server as a relay (`tsm:<url>`): `TomSecretsServerRelay`, the
  client of `tom_secrets_relay`'s `/v1` API (pairing over its WebSocket
  rendezvous, the approval link with the instance token, the mailbox with
  the recipient's proof); `tomSecretsRelayWebSocket` keeps a refused
  upgrade's status and message (`TomSecretsRelayUpgradeRefused`).
- `tomSecretsRelayFor` builds the relay an id names (GitHub with this
  machine's token, the relay server with its instance token), and
  `tomSecretsRelayNeedsToken` tells whether pairing through it needs a token.
- The `age` format, the member keys and HKDF moved to the new package
  `tom_secrets_age` (no vault format in it, so the relay server can use
  them); this library re-exports it, so nothing changes for its users.

## 0.2.21

- The relay interface (part-relay, phase C): `TomSecretsRelay` (pairing
  `host` / `join`, the approval link `link`, the mailbox `put` / `list` /
  `fetch` / `delete`), `TomSecretsRelayId` (`tsm:`, `wormhole:`, `github:`)
  with each kind's services, `TomSecretsPairingChannel` (an approval-link
  channel with its nameplate), `TomSecretsRelayException` naming the relay.
- GitHub as the relay: `TomSecretsGitHubRelay` over a `TomSecretsRelayFolder`
  (`TomSecretsStorageRelayFolder` on `TomGitHubStorage`, or the app's through
  the service): pairing frames as files under `relay/pair/<nameplate>/`,
  polled every 2 seconds, end markers, the folder deleted by the side that
  ends second and by the next host after an hour; the mailbox on the inbox
  folders; no link.
- `TomSecretsPairingWindow.open` takes a `relayChannel` beside the LAN (or
  alone): the first device that comes takes the code, the other way is
  closed; `relayError` when the relay failed before anyone came.
  `tomSecretsReceivePairingVia` receives through a relay; a relay that
  fails while pairing is thrown as its `TomSecretsRelayException`.
- `tomSecretsReceivePairingForSetup` takes a `relay` and the machine's own
  GitHub tokens (`ownTokens`), which also open a primary whose token the
  bundle does not carry.
- `TomSecretsMetadata.mailboxRelay` (`tsm.mailbox-relay`): the relay whose
  mailbox a shared vault's members use.

## 0.2.20

- A PGP key `dart_pg` refuses (an RSA key below 2048 bits, a v3 key) is read
  by a minimal reader of the package's own (packet framing with partial
  lengths, v3 and v4 key packets, user ids, self-signature subpackets), by
  the same rules: it shows its fingerprint, user ids and expiry, gets
  Expires, and the health report flags it short. Its public key is derived
  from the secret key as GnuPG exports it.

## 0.2.19

- PGP keys checked against GnuPG 2.5: a generated RSA key's primes are
  written p < q, which GnuPG requires (it refused `dart_pg`'s keys as "Bad
  secret key"); the expiry counts from the key's creation (RFC 9580
  5.2.3.13), as GnuPG shows it; key information is read from the packets
  (the primary user id, else the latest self-signature), so a GnuPG Ed25519
  key whose signature has a short `r` reads instead of being refused.
  `tomSecretsPgpPublicOf` derives the public key block without the
  passphrase. Ed25519 is no longer flagged short; DSA and ElGamal keys are
  measured against 3072 bits. `dart_pg` is held below 2.2.0. A live test
  runs the round trip where `gpg` is on the PATH.

## 0.2.18

- Typed certificates and PGP keys (part-structure, part-sharing, BP-33,
  DP-179): `tomSecretsGenerateCertificate` (ECDSA P-384, RSA 4096 where a
  tool needs RSA; self-signed with a CSR), `TomSecretsCertificateInfo`
  (validity, key length, fingerprint, SANs), `tomSecretsWriteCertificate` /
  `tomSecretsCertificateOf` (`certificate.pem`, `private-key.pem` or a
  PKCS#12 bundle; Expires from `notAfter`); `tomSecretsGeneratePgpKey`
  (ECDSA P-384 with an ECDH subkey, RSA 4096; locked with a generated
  passphrase), `TomSecretsPgpKeyInfo`, `tomSecretsWritePgpKey` /
  `tomSecretsPgpKeyOf` (Expires the key's expiry); `tomSecretsTypedFileField`
  (what `getFile` serves without a field). Through `basic_utils` (MIT) and
  `dart_pg` (BSD-3).
- The health report flags short certificate and PGP keys (RSA below 3072
  bits, curves below 256), never refusing them.

## 0.2.17

- The guided rotation of the own vaults (part-key-rotation, DP-84): a
  vault entry's next keys (`TomSecretsVaultKeys.nextPassword`,
  `nextKeyFile`, `nextOuterKey`, `hasNext`) and the old repository key a
  two-slot file keeps (`previousOuterKey`, `writtenOuterKeys`), `copyWith`;
  the primary's own next keys (`TomSecretsPrimaryNextKeys` in
  `.tom-secrets/next-keys`); `tomSecretsTakeNextKeys` (a device's record
  gets the new key ids, it leaves the rotations' pending);
  `TomSecretsDeviceRecords.takeKeyIds`, `missingKey`.
- An outer key text may name several repository keys, the newest first
  (`tomSecretsOuterKeyList`, `tomSecretsJoinOuterKeys`):
  `tomSecretsOuterCodecFor` writes a slot for each. `tomSecretsVaultKeyIds`
  (the key ids as pairing records them).

## 0.2.16

- The `age` passphrase recipient (part-sharing): `scrypt` stanzas,
  `tomSecretsAgeEncryptPassphrase` (work factor 18 by default, scrypt in
  another isolate), `TomSecretsAgePassphraseIdentity` (work factors above
  22 refused), `tomSecretsAgeIsPassphrase`; an `scrypt` stanza beside
  another is refused, as `age` does. Checked against the age testkit's
  scrypt vectors and `filippo.io/age` v1.3.2 both ways.
- Single-entry exports (part-sharing, BP-34): `TomSecretsShare` (the JSON
  document `tsm.share` v1: entries with fields, tags, attachments, expiry,
  type and `tsm.key`; the sender), `tomSecretsShareOf`,
  `tomSecretsWriteShare` (to members' keys, under a passphrase or to
  classical keys), `tomSecretsReadShare`, `tomSecretsImportShare` (new
  entries), `tomSecretsShareFitsQr`, `tomSecretsLooksLikeShare`.
- The inbox folders: `tomSecretsInboxPath`, `tomSecretsNewInboxName`,
  `tomSecretsInboxDate`, `tomSecretsInboxExpired` (30 days),
  `tomSecretsIsInboxMember`, `tomSecretsIsInboxName`.

## 0.2.15

- The rotation record (part-key-rotation, DP-85): `TomSecretsRotations`
  over `.tom-secrets/rotations` (start refused while a rotation of the same
  target runs: the record is the lock; update; end), `TomSecretsRotation`
  (kind, target, old and new key ids, started, switched, migration end,
  pending), `TomSecretsRotationKind`, `tomSecretsRotationPeriod` (14 days),
  `tomSecretsKeyId`.
- `TomSecretsSharedVaultKeys.withoutRecipient` (a member's old key dropped
  at the finish of its rotation, the vault's keys kept), `rotated()` (new
  keys, the same members), `keyId`.
- `TomSecretsDeviceSettings.memberKeyAgeMonths` (DP-85: 24).

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
