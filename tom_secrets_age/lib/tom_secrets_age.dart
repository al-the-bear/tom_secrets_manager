// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The `age` v1 file format and the member keys of Tom Secrets Manager
/// (part-sharing, DP-63, DP-177), without any vault format: hybrid
/// (`mlkem768x25519`, X25519 + ML-KEM-768) and classical (`X25519`)
/// recipients, passphrases (`scrypt`), the armour; member keys
/// (`AGE-SECRET-KEY-PQ-1…`), recipients (`age1pq1…`, `age1…`) and their
/// fingerprints. Used by `tom_secrets_core` (which re-exports it) and by the
/// relay server, which must not reach the vault format.
library;

export 'src/age.dart';
export 'src/hkdf.dart';
export 'src/recipient.dart';
