// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A new vault (KeePass compatibility, BP-36): KDBX 4.1, its key derived
/// through Argon2id. Every vault the product creates, the primary and every
/// further one, starts here.
library;

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'vault_merge.dart';

/// The key derivation of a new vault (part-stores): Argon2id over 64 MiB,
/// 3 iterations, 1 lane. The app tunes it at creation so unlocking takes
/// about one second on the slowest of the user's devices, and passes the
/// result as `argon2` to [tomSecretsNewVault].
const KdbxArgon2 tomSecretsDefaultArgon2 = KdbxArgon2(
  type: KdbxArgon2Type.argon2id,
  memory: 64 << 20,
  iterations: 3,
);

/// A new, empty vault named [name], opened with [credentials] (a password,
/// a key file or both): KDBX 4.1, its key derived through [argon2], which
/// must be Argon2id, and the product's format version in its custom data.
/// A primary vault is such a vault holding `.tom-secrets/vaults`
/// (`TomSecretsPrimaryVaults`).
///
/// Throws [ArgumentError] for an [argon2] that is not Argon2id or is outside
/// Argon2's ranges.
KdbxFile tomSecretsNewVault(
  Credentials credentials,
  String name, {
  KdbxArgon2 argon2 = tomSecretsDefaultArgon2,
}) {
  if (argon2.type != KdbxArgon2Type.argon2id) {
    throw ArgumentError.value(argon2, 'argon2', 'a vault is keyed by Argon2id');
  }
  final file = KdbxFormat().create(credentials, name, argon2: argon2);
  file.body.meta.customData[tomSecretsFormatKey] = tomSecretsFormatVersion;
  return file;
}
