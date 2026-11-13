// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Key files (part-stores, BP-18): a KeePass 2.0 XML key file — 32 random
/// bytes with their hash — the form KeePass, KeePassXC, Strongbox and
/// KeePassDX all read; a vault's credential is password plus key file.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

/// A key file that is not a KeePass 2.0 key file or whose hash is wrong.
final class TomSecretsKeyFileException implements Exception {
  /// A key-file problem described by [message].
  TomSecretsKeyFileException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsKeyFileException: $message';
}

/// A KeePass 2.0 XML key file.
final class TomSecretsKeyFile {
  TomSecretsKeyFile._(this.key);

  /// A new key file of 32 random bytes from [random] (default: the OS's
  /// secure generator).
  factory TomSecretsKeyFile.generate({Random? random}) {
    final r = random ?? Random.secure();
    return TomSecretsKeyFile._(
      Uint8List.fromList(List.generate(32, (_) => r.nextInt(256))),
    );
  }

  /// The key file of the 32 bytes [key].
  factory TomSecretsKeyFile.fromKey(Uint8List key) {
    if (key.length != 32) {
      throw TomSecretsKeyFileException('a key file key is 32 bytes');
    }
    return TomSecretsKeyFile._(Uint8List.fromList(key));
  }

  /// Reads a KeePass 2.0 key file's [bytes] and checks its hash.
  factory TomSecretsKeyFile.parse(Uint8List bytes) {
    final text = utf8.decode(bytes, allowMalformed: true);
    final version = RegExp(
      r'<Version>\s*([^<]+?)\s*</Version>',
    ).firstMatch(text);
    final data = RegExp(
      r'<Data(?:\s+Hash="([0-9A-Fa-f]{8})")?\s*>([^<]*)</Data>',
    ).firstMatch(text);
    if (version?.group(1) != '2.0' || data == null) {
      throw TomSecretsKeyFileException('not a KeePass 2.0 key file');
    }
    final hex = data.group(2)!.replaceAll(RegExp(r'\s'), '');
    if (!RegExp(r'^[0-9A-Fa-f]{64}$').hasMatch(hex)) {
      throw TomSecretsKeyFileException('the key is not 64 hex digits');
    }
    final file = TomSecretsKeyFile._(
      Uint8List.fromList([
        for (var i = 0; i < 64; i += 2)
          int.parse(hex.substring(i, i + 2), radix: 16),
      ]),
    );
    final hash = data.group(1);
    if (hash != null && hash.toUpperCase() != file.hash) {
      throw TomSecretsKeyFileException('the key file\'s hash does not match');
    }
    return file;
  }

  /// The 32 bytes the key file contributes to the composite key.
  final Uint8List key;

  /// The first 4 bytes of the key's SHA-256, upper-case hex, as KeePass
  /// writes it in `Hash`.
  String get hash => _hex(crypto.sha256.convert(key).bytes.sublist(0, 4));

  /// The file, as KeePass 2.5x writes it: the key in upper-case hex, in
  /// groups of 8 digits, two lines.
  Uint8List toBytes() {
    final hex = _hex(key);
    final groups = [for (var i = 0; i < 64; i += 8) hex.substring(i, i + 8)];
    final text =
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<KeyFile>\n'
        '\t<Meta>\n'
        '\t\t<Version>2.0</Version>\n'
        '\t</Meta>\n'
        '\t<Key>\n'
        '\t\t<Data Hash="$hash">\n'
        '\t\t\t${groups.sublist(0, 4).join(' ')}\n'
        '\t\t\t${groups.sublist(4).join(' ')}\n'
        '\t\t</Data>\n'
        '\t</Key>\n'
        '</KeyFile>\n';
    return Uint8List.fromList(utf8.encode(text));
  }

  /// The credential of [password] plus this key file
  /// (`Credentials.composite`); a null [password] is the key file alone.
  Credentials credentials(String? password) => Credentials.composite(
    password == null ? null : ProtectedValue.fromString(password),
    Credentials.keyFileKey(toBytes()),
  );

  /// Overwrites the key with zeros.
  void dispose() => key.fillRange(0, key.length, 0);

  @override
  String toString() => 'TomSecretsKeyFile($hash, ***)';

  static String _hex(List<int> bytes) => bytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join()
      .toUpperCase();
}
