# Tom Secrets Core

The core of the Tom Secrets Manager: the pure-Dart library the service and the
apps share. It reads KDBX files only through `tom_kdbx_store`, and takes the
reference grammar from `tom_secrets_client`, so the clients, the core and the
service parse references with one implementation.

## What it holds

- **Stores** (`TomSecretsStore`): one KDBX file under its store name (the
  machine's configuration, else the metadata's `tsm.store`, else the file
  name), indexed for resolution. Each entry gets its logical path (the groups
  below the root without the overlay groups, then the title), its bindings
  (the file binding and its overlay groups) and its flat key (`tsm.key`). The
  recycle bin, the metadata entry and the `tsm.grants` group are never
  reached; an overlay that binds a dimension twice, an overlay group between
  ordinary groups and a `tsm.key` that is not a key are skipped and named in
  `warnings`.
- **Overlays**: a group `@<dimension>:<value>` binds every entry below it,
  at the file's root (`@host:bomber/Telegram/Bot`) or inside the entry's own
  group (`Telegram/@host:bomber/Bot`), nestable.
- **The metadata entry** `.tom-secrets` (`TomSecretsMetadata`): `tsm.format`,
  `tsm.store`, `tsm.kind`, `tsm.purpose`, `tsm.dimensions` (the file binding)
  and, in the primary vault, `tsm.config`.
- **The shared configuration** `tsm.config` (`TomSecretsConfig`): the
  dimensions in priority order with an optional configured `default` and
  `fallback_to_default` (off unless set), and the stores per environment
  (a local path or a GitHub repository and path). Built-in dimensions the
  list leaves out (`host`, `platform`, `env`) come first, in that order.
- **Resolution** (`TomSecretsResolver`): the request's value per dimension (a
  binding in the brackets, else beside the reference, else the machine's
  value, else the configured default, else `default`); candidates (a path, a
  `~uuid` with the overlays of its path, or a key with the overlays at each
  keyed entry's path); the strict match with the per-dimension fallback; the
  rank vectors (2 bound to the value, 1 kept by the fallback, 0 unbound);
  ambiguity; the field (a string field, `attachment:<name>`, the virtual
  `totp`; passkey fields are `denied`). Failures are
  `TomSecretsResolveException`s with the protocol's kinds and details.
- **The KDBX mapping** (`TomSecretsEntryFields`, `TomSecretsEntryType`) and
  **TOTP** (`TomSecretsTotp`, RFC 6238): the three conventions `otp`,
  `OTPAuth` and `TimeOtp-*`, read in that order and written together.

- **Vault locators** (`TomSecretsVaultLocator`): `file:<absolute path>`,
  `github:<owner>/<repo>[@<branch>]/<path>`, and `git:` (recognised, not
  advertised in phase A).
- **The GitHub cycle** (`TomSecretsVaultUnit`, DP-81): a vault as one
  `tom_core_sync` sync unit over a `tom_core_storage` backend —
  `TomGitHubStorage` for `github:`, the REST API, no clone. Open reads the
  head and the file at it (re-reading until the head is the same before and
  after); save commits one file on top of the base and moves the branch
  without force; a refused move reads the new head, merges three-way and
  commits again, up to `maxPushAttempts`, then throws
  `TomCasExhaustedException` (the work stays local); a transport failure
  throws `TomCommitFailedException` for the engine's journal. Commit messages
  name the vault and the device (`tsm: fleet.kdbx from bigbeast`), and the
  device is their author and committer when the storage is built with
  `TomGitHubStorage(committer: tomSecretsDeviceCommitter(device))`
  (`<device>@tsm.invalid`). The outer
  encryption plugs in as a `TomSecretsVaultCodec`. `TomSyncEngine` drives it
  (pull, merge, push, retries, journal, status).
- **The merge** (`tomSecretsMergeVaults`, DP-7): entries and groups are
  records keyed by UUID (`tomMergeKeyed`); a field only one side changed takes
  that side; a real conflict keeps the newer value, puts the loser into the
  entry's history (addressed by its modification time, never pruned while
  open) and records a `TomSecretsEntryConflict` in the entry's custom data
  `tsm.conflict` until `tomSecretsSettleConflicts`; a deletion against no
  change deletes, an edit against a deletion stands and is reported; moves
  (overlay groups included) are an attribute; history is the union of both
  sides, pruned to the vault's limit; deletions and the recycle bin carry
  over; meta custom data merges per key; another product format major
  (`tsm.format`) or another vault is refused (`TomMergeRefusedException`).
  A null base merges a force-pushed branch.
- **New vaults** (`tomSecretsNewVault`, BP-36): KDBX 4.1, the key derived
  through Argon2id; `tomSecretsDefaultArgon2` is 64 MiB, 3 iterations,
  1 lane, which the app tunes at creation. The primary and every further
  vault are created this way, and `TomSecretsVaultUnit.create` refuses a file
  keyed otherwise.
- **Key files** (`TomSecretsKeyFile`, BP-18): a KeePass 2.0 XML key file
  (32 random bytes with their hash, written as KeePass 2.5x writes it), read
  back with its hash checked; `credentials(password)` is the composite key
  (`Credentials.composite`). It never goes to GitHub; the primary vault keeps
  it as an attachment.
- **The outer encryption** (`tomSecretsOuterEncrypt` / `Decrypt`,
  `TomSecretsOuterCodec`, DP-80, DP-84): a vault stored as
  `<vault>.kdbx.tsmx`, encrypted once under a fresh random file key that is
  wrapped under each repository key in a key slot (phase A writes one). The
  layout (magic `TSMX`, version, cipher id, slots of key id, nonce and wrapped
  key, content nonce, ciphertext) and the authenticated data (the header and
  the file's path) are documented in `lib/src/outer.dart`. Cipher id 2,
  XChaCha20-Poly1305 with a 192-bit nonce, is the default; cipher id 1,
  AES-256-GCM with a 96-bit nonce, is selectable per repository; both from
  `cryptography`. A file no held key has a slot for is a
  `TomKeyRequiredException`, so the sync engine asks for a key; an altered or
  moved file is a `TomSecretsOuterException`. The codec plugs into
  `TomSecretsVaultUnit`. `TomSecretsRepositoryKey` (256 bits, key id = the
  first 8 bytes of its SHA-256) moves as base64 (`tsm.outer-key` in the
  primary vault). `test/fixtures/outer/` holds phase-A files every later
  version must open.
- **The primary vault** (`TomSecretsPrimaryVaults`, BP-8): the group
  `.tom-secrets/vaults` holds one entry per further vault (locator, master
  password, key file, outer key, GitHub token); the primary cannot list
  itself, and the group never resolves.

```dart
final resolver = TomSecretsResolver(
  stores: [TomSecretsStore.fromFile(file, name: 'fleet')],
  config: TomSecretsConfig.builtIn(),
  machine: TomSecretsMachine.current(values: {'env': 'prod'}),
);
final resolution = resolver.resolve('[env:prod]db.main#UserName');
print(resolution.entry.pathText);
resolution.value.dispose();
```

The design is part-structure of the idea document
(`_ai/quests/tom_core/ideas/tom_secrets_manager/tom_secrets_manager.md`); its
worked examples are `test/worked_examples_test.dart`, row by row.

## Licence

BSD-3-Clause (`LICENSE`).
