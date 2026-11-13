# Changelog

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
- Key files (`TomSecretsKeyFile`, KeePass 2.0 XML) in the composite key, and
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
