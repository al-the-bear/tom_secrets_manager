// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A vault file as its store keeps it: a plain `.kdbx`, or a `.tsmx` under
/// the repository's outer key (BP-18). The service opens and writes stores
/// with these, and the manager app opens the copy the service hands it for
/// editing and encodes the file it saves (protocol.md 6.4).
library;

import 'dart:typed_data';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'key_file.dart';
import 'locator.dart';
import 'outer.dart';

/// The outer layer of a vault file named [fileName]: a `.tsmx` file opened
/// with [outerKey] (base64), written under [cipher] until it decodes a file
/// (then under that file's), or null for a plain `.kdbx`.
///
/// **[C]** [outerKey] may name several repository keys, separated by `,`
/// ([tomSecretsJoinOuterKeys]): during a guided rotation's migration period
/// the new and the old key (part-key-rotation, DP-84). The file opens with
/// whichever has a slot, and every write gets a slot for each, so a device
/// holding only the old key still reads it.
TomSecretsOuterCodec? tomSecretsOuterCodecFor(
  String fileName,
  String? outerKey, {
  TomSecretsOuterCipher cipher = TomSecretsOuterCipher.xchacha20Poly1305,
}) => fileName.endsWith(tomSecretsOuterSuffix)
    ? TomSecretsOuterCodec(
        path: fileName,
        keys: [
          for (final k in tomSecretsOuterKeyList(outerKey))
            TomSecretsRepositoryKey.fromBase64(k),
        ],
        cipher: cipher,
      )
    : null;

/// **[C]** The repository keys (base64) an outer key text names: one, or
/// several separated by `,`, the newest first; none for null or empty.
List<String> tomSecretsOuterKeyList(String? outerKey) => [
  for (final k in (outerKey ?? '').split(','))
    if (k.trim().isNotEmpty) k.trim(),
];

/// **[C]** [keys] (base64, the newest first; nulls and repeats left out) as
/// one outer key text for [tomSecretsOuterCodecFor], or null for none.
String? tomSecretsJoinOuterKeys(Iterable<String?> keys) {
  final out = <String>[];
  for (final k in keys) {
    for (final one in tomSecretsOuterKeyList(k)) {
      if (!out.contains(one)) out.add(one);
    }
  }
  return out.isEmpty ? null : out.join(',');
}

/// **[C]** The ids of a vault's keys as device records and rotation records
/// name them (part-sharing, part-key-rotation): the key file's hash
/// (`TomSecretsKeyFile.hash`) and each repository key's id
/// (`TomSecretsRepositoryKey.keyIdHex`).
List<String> tomSecretsVaultKeyIds({List<int>? keyFile, String? outerKey}) => [
  if (keyFile != null)
    TomSecretsKeyFile.parse(Uint8List.fromList(keyFile)).hash,
  for (final k in tomSecretsOuterKeyList(outerKey))
    TomSecretsRepositoryKey.fromBase64(k).keyIdHex,
];

/// The credentials of a vault with [password] and the bytes of a [keyFile],
/// either of them optional; or of its [compositeKey] alone (what the OS
/// unlock keeps, part-os-unlock), which then takes the place of both.
Credentials tomSecretsVaultCredentials({
  String? password,
  Uint8List? keyFile,
  Uint8List? compositeKey,
}) => compositeKey != null
    ? Credentials.fromCompositeKey(compositeKey)
    : Credentials.composite(
        password == null ? null : ProtectedValue.fromString(password),
        keyFile,
      );

/// The composite key of [password] and the bytes of a [keyFile] (32 bytes):
/// what the OS unlock keeps for a vault instead of the password text
/// (part-os-unlock, DP-72). It opens the vault with or without the key file
/// and stays valid across saves; it changes when the vault is re-keyed.
Uint8List tomSecretsCompositeKey({String? password, Uint8List? keyFile}) =>
    tomSecretsVaultCredentials(password: password, keyFile: keyFile).getHash();

/// [stored], the file at [locator] as its store keeps it, opened with
/// [credentials] (and [outerKey] for a `.tsmx` file). Throws
/// [KdbxInvalidKeyException] for wrong credentials, `TomKeyRequiredException`
/// (`tom_core_storage`) when no outer key given opens it, and
/// [TomSecretsOuterException] for a damaged outer layer.
Future<KdbxFile> tomSecretsDecodeStored(
  String locator,
  Uint8List stored,
  Credentials credentials, {
  String? outerKey,
}) async {
  final codec = tomSecretsOuterCodecFor(
    TomSecretsVaultLocator.parse(locator).fileName,
    outerKey,
  );
  return KdbxFormat().read(
    codec == null ? stored : await codec.decode(stored),
    credentials,
  );
}

/// [file] saved as the store at [locator] keeps it: its KDBX bytes, under the
/// outer layer with [outerKey] for a `.tsmx` file. The outer layer keeps the
/// cipher of [like] (the file as stored before, so a rewrite never switches
/// the repository's cipher), else uses [cipher].
Future<Uint8List> tomSecretsEncodeStored(
  String locator,
  KdbxFile file, {
  String? outerKey,
  Uint8List? like,
  TomSecretsOuterCipher cipher = TomSecretsOuterCipher.xchacha20Poly1305,
}) async {
  final fileName = TomSecretsVaultLocator.parse(locator).fileName;
  final codec = tomSecretsOuterCodecFor(
    fileName,
    outerKey,
    cipher: like != null && fileName.endsWith(tomSecretsOuterSuffix)
        ? tomSecretsOuterCipherOf(like)
        : cipher,
  );
  final bytes = await file.save();
  return codec == null ? bytes : codec.encode(bytes);
}
