// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The core of the Tom Secrets Manager: stores over KDBX files, the metadata
/// entry and the shared configuration, dimensions, overlays and resolution
/// (part-structure). The reference grammar is `tom_secrets_client`'s.
library;

export 'src/compaction.dart';
export 'src/config.dart';
export 'src/history.dart';
export 'src/import.dart';
export 'src/import_1password.dart';
export 'src/key_file.dart';
export 'src/locator.dart';
export 'src/mapping.dart';
export 'src/metadata.dart';
export 'src/new_vault.dart';
export 'src/offline_cache.dart';
export 'src/outer.dart';
export 'src/primary.dart';
export 'src/resolution.dart';
export 'src/store.dart';
export 'src/totp.dart';
export 'src/vault_merge.dart';
export 'src/vault_sync.dart';
