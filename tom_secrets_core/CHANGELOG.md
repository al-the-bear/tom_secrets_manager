# Changelog

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
