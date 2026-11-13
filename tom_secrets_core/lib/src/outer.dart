// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The outer encryption (part-stores, BP-18, DP-80, DP-84): a vault file
/// stored as `<vault>.kdbx.tsmx`, its content encrypted once under a fresh
/// random file key, the file key wrapped under each valid repository key in
/// one key slot each.
///
/// Layout, integers big-endian:
///
/// | Bytes | Content |
/// | --- | --- |
/// | 4 | magic `TSMX` |
/// | 1 | format version, 1 |
/// | 1 | cipher id: 1 AES-256-GCM, 2 XChaCha20-Poly1305 (slots and content) |
/// | 1 | slot count, 1 to 255 |
/// | per slot | key id (8: the first 8 bytes of SHA-256 over the repository key), nonce (12 or 24), wrapped file key (32) and its tag (16) |
/// | nonce | the content's nonce (12 or 24) |
/// | rest | ciphertext and its 16-byte tag |
///
/// Additional authenticated data, so neither a slot nor the content can be
/// moved to another file or position: a slot's is the first 7 bytes, its key
/// id and the path; the content's is the whole header (everything before the
/// ciphertext) and the path. The path (the file's path in the repository) is
/// written as its UTF-8 length (4 bytes) and the UTF-8.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:tom_core_storage/tom_core_storage.dart'
    show TomKeyRequiredException;

import 'vault_sync.dart';

/// The suffix of an outer-encrypted vault file.
const String tomSecretsOuterSuffix = '.tsmx';

/// The `.tsmx` format version this library writes and reads.
const int tomSecretsOuterVersion = 1;

const List<int> _magic = [0x54, 0x53, 0x4D, 0x58]; // TSMX
const int _tagLength = 16;
const int _fileKeyLength = 32;
const int _keyIdLength = 8;

/// The content and slot cipher of a repository (DP-8).
enum TomSecretsOuterCipher {
  /// AES-256-GCM, 96-bit random nonce per write; selectable per repository.
  aes256Gcm(1, 12),

  /// XChaCha20-Poly1305, 192-bit random nonce; the default (DP-80).
  xchacha20Poly1305(2, 24);

  const TomSecretsOuterCipher(this.id, this.nonceLength);

  /// The cipher id in the header.
  final int id;

  /// The nonce length in bytes.
  final int nonceLength;

  Cipher get _algorithm => switch (this) {
    aes256Gcm => AesGcm.with256bits(),
    xchacha20Poly1305 => Xchacha20.poly1305Aead(),
  };

  /// The cipher of header id [id], or null.
  static TomSecretsOuterCipher? ofId(int id) =>
      values.where((c) => c.id == id).firstOrNull;
}

/// A file that is not a `.tsmx` file, of a format or cipher this library
/// does not read, or that fails its authentication (altered, truncated, or
/// moved to another path).
final class TomSecretsOuterException implements Exception {
  /// A problem described by [message].
  TomSecretsOuterException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsOuterException: $message';
}

/// A 256-bit repository key.
final class TomSecretsRepositoryKey {
  TomSecretsRepositoryKey._(this.bytes);

  /// A new key from [random] (default: the OS's secure generator).
  factory TomSecretsRepositoryKey.generate({Random? random}) =>
      TomSecretsRepositoryKey._(_randomBytes(32, random ?? Random.secure()));

  /// The key of 32 [bytes].
  factory TomSecretsRepositoryKey.fromBytes(List<int> bytes) {
    if (bytes.length != 32) {
      throw ArgumentError.value(bytes.length, 'bytes', 'a key is 32 bytes');
    }
    return TomSecretsRepositoryKey._(Uint8List.fromList(bytes));
  }

  /// The key of its base64 (as the primary vault keeps it,
  /// `tsm.outer-key`).
  factory TomSecretsRepositoryKey.fromBase64(String text) =>
      TomSecretsRepositoryKey.fromBytes(base64.decode(text));

  /// The key's bytes.
  final Uint8List bytes;

  /// The first 8 bytes of SHA-256 over the key: the slot's key id.
  Uint8List get keyId => Uint8List.fromList(
    crypto.sha256.convert(bytes).bytes.sublist(0, _keyIdLength),
  );

  /// The key id as hex.
  String get keyIdHex =>
      keyId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// The key as base64.
  String toBase64() => base64.encode(bytes);

  /// Overwrites the key with zeros.
  void dispose() => bytes.fillRange(0, bytes.length, 0);

  @override
  String toString() => 'TomSecretsRepositoryKey($keyIdHex, ***)';
}

Uint8List _randomBytes(int n, Random random) =>
    Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));

Uint8List _lengthPrefixed(String text) {
  final bytes = utf8.encode(text);
  return Uint8List.fromList([
    (bytes.length >> 24) & 0xff,
    (bytes.length >> 16) & 0xff,
    (bytes.length >> 8) & 0xff,
    bytes.length & 0xff,
    ...bytes,
  ]);
}

/// The key ids of the slots of a `.tsmx` file, without decrypting anything.
List<String> tomSecretsOuterKeyIds(Uint8List file) => [
  for (final s in _parse(file).slots) s.keyIdHex,
];

/// Encrypts [content] (the KDBX bytes) as a `.tsmx` file for [path], with a
/// fresh random file key wrapped under each of [keys] (phase A and B write
/// one; the guided rotation writes two).
Future<Uint8List> tomSecretsOuterEncrypt(
  Uint8List content, {
  required String path,
  required List<TomSecretsRepositoryKey> keys,
  TomSecretsOuterCipher cipher = TomSecretsOuterCipher.xchacha20Poly1305,
  Random? random,
}) async {
  if (keys.isEmpty || keys.length > 255) {
    throw ArgumentError.value(keys.length, 'keys', '1 to 255 keys');
  }
  final r = random ?? Random.secure();
  final algorithm = cipher._algorithm;
  final pathBytes = _lengthPrefixed(path);
  final fileKey = _randomBytes(_fileKeyLength, r);
  final start = Uint8List.fromList([
    ..._magic,
    tomSecretsOuterVersion,
    cipher.id,
    keys.length,
  ]);
  final header = BytesBuilder()..add(start);
  try {
    for (final key in keys) {
      final nonce = _randomBytes(cipher.nonceLength, r);
      final box = await algorithm.encrypt(
        fileKey,
        secretKey: SecretKey(key.bytes),
        nonce: nonce,
        aad: [...start, ...key.keyId, ...pathBytes],
      );
      header
        ..add(key.keyId)
        ..add(nonce)
        ..add(box.cipherText)
        ..add(box.mac.bytes);
    }
    final contentNonce = _randomBytes(cipher.nonceLength, r);
    header.add(contentNonce);
    final head = header.toBytes();
    final box = await algorithm.encrypt(
      content,
      secretKey: SecretKey(fileKey),
      nonce: contentNonce,
      aad: [...head, ...pathBytes],
    );
    return Uint8List.fromList([...head, ...box.cipherText, ...box.mac.bytes]);
  } finally {
    fileKey.fillRange(0, fileKey.length, 0);
  }
}

/// Decrypts the `.tsmx` [file] for [path] with whichever of [keys] has a
/// slot. Throws `TomKeyRequiredException` (the storage port's "no configured
/// key opens it", so the sync engine asks for a key) when none of [keys]
/// has a slot, and [TomSecretsOuterException] for a file that is not
/// `.tsmx`, of another version or cipher, or that fails authentication.
Future<Uint8List> tomSecretsOuterDecrypt(
  Uint8List file, {
  required String path,
  required List<TomSecretsRepositoryKey> keys,
}) async {
  final parsed = _parse(file);
  final algorithm = parsed.cipher._algorithm;
  final pathBytes = _lengthPrefixed(path);
  final start = file.sublist(0, 7);
  for (final slot in parsed.slots) {
    final key = keys.where((k) => k.keyIdHex == slot.keyIdHex).firstOrNull;
    if (key == null) continue;
    final List<int> fileKey;
    try {
      fileKey = await algorithm.decrypt(
        SecretBox(slot.wrapped, nonce: slot.nonce, mac: Mac(slot.tag)),
        secretKey: SecretKey(key.bytes),
        aad: [...start, ...slot.keyId, ...pathBytes],
      );
    } on SecretBoxAuthenticationError {
      throw TomSecretsOuterException(
        'the key slot ${slot.keyIdHex} does not open for $path',
      );
    }
    try {
      return Uint8List.fromList(
        await algorithm.decrypt(
          SecretBox(
            parsed.ciphertext,
            nonce: parsed.contentNonce,
            mac: Mac(parsed.tag),
          ),
          secretKey: SecretKey(fileKey),
          aad: [...file.sublist(0, parsed.headerLength), ...pathBytes],
        ),
      );
    } on SecretBoxAuthenticationError {
      throw TomSecretsOuterException('the content does not open for $path');
    } finally {
      if (fileKey is Uint8List) fileKey.fillRange(0, fileKey.length, 0);
    }
  }
  throw TomKeyRequiredException(
    path,
    'no repository key held opens it (slots ${parsed.slots.map((s) => s.keyIdHex).join(', ')})',
  );
}

final class _Slot {
  _Slot(this.keyId, this.nonce, this.wrapped, this.tag);
  final Uint8List keyId;
  final Uint8List nonce;
  final Uint8List wrapped;
  final Uint8List tag;
  String get keyIdHex =>
      keyId.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

final class _Parsed {
  _Parsed(
    this.cipher,
    this.slots,
    this.contentNonce,
    this.headerLength,
    this.ciphertext,
    this.tag,
  );
  final TomSecretsOuterCipher cipher;
  final List<_Slot> slots;
  final Uint8List contentNonce;
  final int headerLength;
  final Uint8List ciphertext;
  final Uint8List tag;
}

_Parsed _parse(Uint8List file) {
  if (file.length < 7 ||
      file[0] != _magic[0] ||
      file[1] != _magic[1] ||
      file[2] != _magic[2] ||
      file[3] != _magic[3]) {
    throw TomSecretsOuterException('not a .tsmx file');
  }
  if (file[4] != tomSecretsOuterVersion) {
    throw TomSecretsOuterException(
      '.tsmx format version ${file[4]}; this library reads $tomSecretsOuterVersion',
    );
  }
  final cipher = TomSecretsOuterCipher.ofId(file[5]);
  if (cipher == null) {
    throw TomSecretsOuterException('unknown cipher id ${file[5]}');
  }
  final count = file[6];
  if (count == 0) throw TomSecretsOuterException('a .tsmx file without a slot');
  final slotLength =
      _keyIdLength + cipher.nonceLength + _fileKeyLength + _tagLength;
  final headerLength = 7 + count * slotLength + cipher.nonceLength;
  if (file.length < headerLength + _tagLength) {
    throw TomSecretsOuterException('the .tsmx file is truncated');
  }
  final slots = <_Slot>[];
  var at = 7;
  Uint8List take(int n) {
    final out = file.sublist(at, at + n);
    at += n;
    return out;
  }

  for (var i = 0; i < count; i++) {
    slots.add(
      _Slot(
        take(_keyIdLength),
        take(cipher.nonceLength),
        take(_fileKeyLength),
        take(_tagLength),
      ),
    );
  }
  final contentNonce = take(cipher.nonceLength);
  return _Parsed(
    cipher,
    slots,
    contentNonce,
    headerLength,
    file.sublist(headerLength, file.length - _tagLength),
    file.sublist(file.length - _tagLength),
  );
}

/// The outer layer as the GitHub cycle's codec: decrypts with whichever of
/// [keys] has a slot, encrypts with a slot for each of [keys] under
/// [cipher], for the file at [path] in its repository.
final class TomSecretsOuterCodec implements TomSecretsVaultCodec {
  /// A codec for [path] (the file's path in the repository, e.g.
  /// `vaults/fleet.kdbx.tsmx`).
  TomSecretsOuterCodec({
    required this.path,
    required List<TomSecretsRepositoryKey> keys,
    this.cipher = TomSecretsOuterCipher.xchacha20Poly1305,
    Random? random,
  }) : keys = List.unmodifiable(keys),
       _random = random;

  /// The file's path in its repository (part of the authenticated data).
  final String path;

  /// The repository keys held; every write gets a slot for each.
  final List<TomSecretsRepositoryKey> keys;

  /// The repository's cipher.
  final TomSecretsOuterCipher cipher;
  final Random? _random;

  @override
  Future<Uint8List> decode(Uint8List bytes) =>
      tomSecretsOuterDecrypt(bytes, path: path, keys: keys);

  @override
  Future<Uint8List> encode(Uint8List bytes) => tomSecretsOuterEncrypt(
    bytes,
    path: path,
    keys: keys,
    cipher: cipher,
    random: _random,
  );
}
