// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The typed `pgp-key` entry (part-structure, part-sharing, BP-33,
/// DP-179): an OpenPGP key.
///
/// - **The entry:** the armoured secret key as the attachment
///   `private-key.asc`, the armoured public key as `public-key.asc` (what is
///   handed to others), the passphrase of the secret key in `Password`.
///   Expires is the key's own expiry, when it has one.
/// - **Generated** (DP-179): ECDSA on P-384 with an ECDH subkey for
///   encryption, or RSA 4096 where a tool needs RSA, through `dart_pg`
///   (BSD-3); the secret key is locked with a generated passphrase, kept in
///   `Password`, since OpenPGP tools expect one.
/// - **Read:** fingerprint, key id, user ids, algorithm and length, creation
///   and expiry; an imported short key (RSA below 3072 bits, a curve below
///   256) is kept and flagged by the health report, never refused. A key the
///   library does not read (RSA below 2048 bits, an old version) is kept as
///   it is, without its information.
/// - **Served:** `getFile` of the entry without a field answers the secret
///   key (else the public key).
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart' as pg;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';

/// The attachment holding a PGP key entry's armoured secret key.
const String tomSecretsPgpPrivateAttachment = 'private-key.asc';

/// The attachment holding a PGP key entry's armoured public key.
const String tomSecretsPgpPublicAttachment = 'public-key.asc';

/// A PGP key refused as unreadable.
final class TomSecretsPgpKeyException implements Exception {
  /// A refusal told by [message].
  const TomSecretsPgpKeyException(this.message);

  /// For people.
  final String message;

  @override
  String toString() => 'TomSecretsPgpKeyException: $message';
}

/// What an OpenPGP key says.
final class TomSecretsPgpKeyInfo {
  const TomSecretsPgpKeyInfo._({
    required this.fingerprint,
    required this.keyId,
    required this.userIds,
    required this.algorithm,
    required this.bits,
    required this.created,
    required this.expires,
    required this.isPrivate,
    required this.version,
  });

  /// The primary key's fingerprint, upper-case hex.
  final String fingerprint;

  /// The primary key's id, upper-case hex.
  final String keyId;

  /// Its user ids, `Name <mail>`.
  final List<String> userIds;

  /// The primary key's algorithm, e.g. `ecdsa`, `rsaEncryptSign`, `eddsaLegacy`.
  final String algorithm;

  /// The primary key's length in bits (the curve's for ECC).
  final int bits;

  /// When it was made.
  final DateTime created;

  /// When it expires, or null.
  final DateTime? expires;

  /// Whether it was read from a secret key block.
  final bool isPrivate;

  /// The key version (4 or 6).
  final int version;

  /// Whether [algorithm] is RSA.
  bool get isRsa => algorithm.startsWith('rsa');

  /// The key in words, e.g. `ECDSA P-384` or `RSA 4096`.
  String get keyDescription => isRsa
      ? 'RSA $bits'
      : switch (algorithm) {
          'ecdsa' => 'ECDSA $bits',
          'eddsaLegacy' || 'ed25519' => 'Ed25519',
          'ed448' => 'Ed448',
          _ => '$algorithm $bits',
        };

  /// Why its primary key is shorter than today's guidance (DP-179: RSA
  /// below 3072 bits, a curve below 256), or null.
  String? get shortness {
    if (isRsa && bits < 3072) return 'RSA $bits bits: below 3072';
    if (!isRsa && bits > 0 && bits < 256) {
      return '$algorithm $bits bits: below 256';
    }
    return null;
  }

  /// The information of the armoured key [armored] (a secret or a public key
  /// block). Throws [TomSecretsPgpKeyException] for one the library does not
  /// read.
  factory TomSecretsPgpKeyInfo.parse(String armored) {
    final isPrivate = armored.contains('PRIVATE KEY BLOCK');
    String hex(Uint8List bytes) => [
      for (final b in bytes) b.toRadixString(16).padLeft(2, '0'),
    ].join().toUpperCase();
    try {
      final key = isPrivate
          ? pg.OpenPGP.readPrivateKey(armored)
          : pg.OpenPGP.readPublicKey(armored);
      return TomSecretsPgpKeyInfo._(
        fingerprint: hex(key.fingerprint),
        keyId: hex(key.keyID),
        userIds: [for (final u in key.users) u.userID],
        algorithm: key.keyAlgorithm.name,
        bits: key.keyStrength,
        created: key.creationTime.toUtc(),
        expires: key.expirationTime?.toUtc(),
        isPrivate: isPrivate,
        version: key.version,
      );
    } on Object catch (e) {
      throw TomSecretsPgpKeyException('an unreadable OpenPGP key ($e)');
    }
  }
}

/// The key a PGP key is generated with (DP-179).
enum TomSecretsPgpKeyAlgorithm {
  /// ECDSA on P-384, with an ECDH subkey (the default).
  ecdsaP384,

  /// RSA 4096, for a tool that needs RSA.
  rsa,
}

/// A generated PGP key: the armoured secret and public key, the passphrase
/// the secret key is locked with, and what it says.
final class TomSecretsGeneratedPgpKey {
  const TomSecretsGeneratedPgpKey._({
    required this.privateArmored,
    required this.publicArmored,
    required this.passphrase,
    required this.info,
  });

  /// The secret key block, locked with [passphrase].
  final String privateArmored;

  /// The public key block, to hand to others.
  final String publicArmored;

  /// The generated passphrase of the secret key.
  final String passphrase;

  /// What the key says.
  final TomSecretsPgpKeyInfo info;
}

/// A new OpenPGP key for [userId] (`Name <mail>`) (DP-179): ECDSA P-384 with
/// an ECDH subkey, or RSA 4096 with [algorithm] `rsa`; expiring after
/// [expiresAfter] (null: never); its secret key locked with [passphrase]
/// (default a generated one of 32 random characters).
TomSecretsGeneratedPgpKey tomSecretsGeneratePgpKey({
  required String userId,
  TomSecretsPgpKeyAlgorithm algorithm = TomSecretsPgpKeyAlgorithm.ecdsaP384,
  Duration? expiresAfter,
  String? passphrase,
  DateTime? now,
}) {
  final secret = passphrase ?? _passphrase();
  final key = pg.OpenPGP.generateKey(
    [userId],
    secret,
    type: algorithm == TomSecretsPgpKeyAlgorithm.rsa
        ? pg.KeyType.rsa
        : pg.KeyType.ecc,
    rsaKeySize: pg.RSAKeySize.ultraHigh,
    curve: pg.Ecc.secp384r1,
    keyExpiry: expiresAfter?.inSeconds ?? 0,
    time: now,
  );
  final privateArmored = key.armor();
  final publicArmored = key.publicKey.armor();
  return TomSecretsGeneratedPgpKey._(
    privateArmored: privateArmored,
    publicArmored: publicArmored,
    passphrase: secret,
    info: TomSecretsPgpKeyInfo.parse(privateArmored),
  );
}

String _passphrase() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  final random = Random.secure();
  return String.fromCharCodes([
    for (var i = 0; i < 32; i++)
      alphabet.codeUnitAt(random.nextInt(alphabet.length)),
  ]);
}

/// Makes [entry] a `pgp-key` entry holding [privateArmored] (a secret key
/// block, or null for someone's public key alone) and [publicArmored] (its
/// public key; read from the secret key when not given and readable), with
/// [passphrase] in `Password`; Expires is the key's expiry when it has one
/// (else none). The entry as it was goes to its history. Answers what the
/// key says, or null for a key the library does not read.
TomSecretsPgpKeyInfo? tomSecretsWritePgpKey(
  KdbxEntry entry, {
  String? privateArmored,
  String? publicArmored,
  String? passphrase,
}) {
  if (privateArmored == null && publicArmored == null) {
    throw ArgumentError('a secret or a public key');
  }
  TomSecretsPgpKeyInfo? info;
  try {
    info = TomSecretsPgpKeyInfo.parse(privateArmored ?? publicArmored!);
  } on TomSecretsPgpKeyException {
    info = null;
  }
  var public = publicArmored;
  if (public == null && privateArmored != null) {
    try {
      public = pg.OpenPGP.readPrivateKey(privateArmored).publicKey.armor();
    } on Object {
      public = null;
    }
  }
  entry.modify(() {
    entry.setString(
      TomSecretsEntryFields.type,
      PlainValue(TomSecretsEntryType.pgpKey.wireName),
    );
    entry.removeBinary(const KdbxKey(tomSecretsPgpPrivateAttachment));
    entry.removeBinary(const KdbxKey(tomSecretsPgpPublicAttachment));
    if (privateArmored != null) {
      entry.createBinary(
        isProtected: true,
        name: tomSecretsPgpPrivateAttachment,
        bytes: Uint8List.fromList(utf8.encode(privateArmored)),
      );
    }
    if (public != null) {
      entry.createBinary(
        isProtected: false,
        name: tomSecretsPgpPublicAttachment,
        bytes: Uint8List.fromList(utf8.encode(public)),
      );
    }
    if (passphrase != null) {
      entry.setString(
        KdbxKeyCommon.PASSWORD,
        ProtectedValue.fromString(passphrase),
      );
    }
    final expires = info?.expires;
    entry.times.expires.set(expires != null);
    if (expires != null) entry.times.expiryTime.set(expires);
  });
  return info;
}

/// What the key of the `pgp-key` entry [entry] says (read from its public
/// key, so the secret key is not decoded), or null when it holds none that
/// reads.
TomSecretsPgpKeyInfo? tomSecretsPgpKeyOf(KdbxEntry entry) {
  final public = entry.getBinary(const KdbxKey(tomSecretsPgpPublicAttachment));
  final private = entry.getBinary(
    const KdbxKey(tomSecretsPgpPrivateAttachment),
  );
  try {
    if (public != null) {
      final info = TomSecretsPgpKeyInfo.parse(utf8.decode(public.value));
      return private == null
          ? info
          : TomSecretsPgpKeyInfo._(
              fingerprint: info.fingerprint,
              keyId: info.keyId,
              userIds: info.userIds,
              algorithm: info.algorithm,
              bits: info.bits,
              created: info.created,
              expires: info.expires,
              isPrivate: true,
              version: info.version,
            );
    }
    if (private != null) {
      return TomSecretsPgpKeyInfo.parse(utf8.decode(private.value));
    }
  } on Object {
    return null;
  }
  return null;
}

/// The field `getFile` serves for a typed key entry asked without a field
/// (part-protocol): a certificate's private key (or its PKCS#12 bundle), a
/// PGP key's secret key (else its public key); null for other entries.
String? tomSecretsTypedFileField(KdbxEntry entry) {
  final type = TomSecretsEntryType.of(
    entry.getString(TomSecretsEntryFields.type)?.getText(),
  );
  bool has(String name) => entry.getBinary(KdbxKey(name)) != null;
  const prefix = TomSecretsEntryFields.attachmentPrefix;
  return switch (type) {
    TomSecretsEntryType.certificate when has('private-key.pem') =>
      '${prefix}private-key.pem',
    TomSecretsEntryType.certificate when has('certificate.p12') =>
      '${prefix}certificate.p12',
    TomSecretsEntryType.certificate when has('certificate.pem') =>
      '${prefix}certificate.pem',
    TomSecretsEntryType.pgpKey when has(tomSecretsPgpPrivateAttachment) =>
      '$prefix$tomSecretsPgpPrivateAttachment',
    TomSecretsEntryType.pgpKey when has(tomSecretsPgpPublicAttachment) =>
      '$prefix$tomSecretsPgpPublicAttachment',
    _ => null,
  };
}
