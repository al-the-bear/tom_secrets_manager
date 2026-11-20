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
/// - **GnuPG:** a generated key imports into GnuPG and signs, verifies,
///   encrypts and decrypts there; a GnuPG-made key reads with the same
///   fingerprint, user ids and expiry `gpg --with-colons` shows. Three
///   `dart_pg` 2.1 behaviours are corrected here: an RSA key's primes are
///   written with p < q (libgcrypt refuses the other order as a bad secret
///   key), the expiry counts from the key's creation (RFC 9580 5.2.3.13;
///   `dart_pg` counts from the signature's), and the information is read
///   from the packets, so a GnuPG Ed25519 key whose signature has a short
///   `r` or `s` (one in 128) is not refused.
library;

// Why: the packet classes are not exported by dart_pg, and the fixes above
// need them; the dependency is held below 2.2.0 for that reason.
// ignore_for_file: implementation_imports

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart' as pg;
import 'package:dart_pg/src/common/armor.dart' as pga;
import 'package:dart_pg/src/enum/armor_type.dart' as pga;
import 'package:dart_pg/src/packet/key/rsa_secret_material.dart' as pgp;
import 'package:dart_pg/src/packet/packet_list.dart' as pgp;
import 'package:dart_pg/src/packet/public_key.dart' as pgp;
import 'package:dart_pg/src/packet/public_subkey.dart' as pgp;
import 'package:dart_pg/src/packet/secret_key.dart' as pgp;
import 'package:dart_pg/src/packet/secret_subkey.dart' as pgp;
import 'package:dart_pg/src/packet/signature.dart' as pgp;
import 'package:dart_pg/src/packet/user_attribute.dart' as pgp;
import 'package:dart_pg/src/packet/user_id.dart' as pgp;
import 'package:dart_pg/src/type/packet.dart' as pgp;
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

  /// Whether [algorithm] works over a finite field (RSA, DSA, ElGamal),
  /// whose keys are measured against 3072 bits rather than a curve's 256.
  bool get isFiniteField =>
      isRsa || algorithm == 'dsa' || algorithm == 'elgamal';

  /// The key in words, e.g. `ECDSA 384`, `RSA 4096` or `Ed25519`.
  String get keyDescription => isRsa
      ? 'RSA $bits'
      : switch (algorithm) {
          'ecdsa' => 'ECDSA $bits',
          'eddsaLegacy' || 'ed25519' => 'Ed25519',
          'ed448' => 'Ed448',
          'dsa' => 'DSA $bits',
          'elgamal' => 'ElGamal $bits',
          _ => '$algorithm $bits',
        };

  /// Why its primary key is shorter than today's guidance (DP-179: RSA,
  /// DSA and ElGamal below 3072 bits, a curve below 256; Curve25519's 255
  /// bits count as 256, as for SSH keys), or null.
  String? get shortness {
    if (isFiniteField && bits < 3072) {
      return '${keyDescription.split(' ').first} $bits bits: below 3072';
    }
    if (!isFiniteField && bits > 0 && bits < 255) {
      return '$algorithm $bits bits: below 256';
    }
    return null;
  }

  /// The information of the armoured key [armored] (a secret or a public key
  /// block), read from its packets as GnuPG reads it: the primary key's
  /// fingerprint, id, algorithm, length and creation; the user ids, the
  /// primary one first; the expiry from the latest self-signature (a direct
  /// key signature's, else the primary user id's, else the latest user id
  /// self-signature's), counted from the key's creation. Signatures are not
  /// verified: the information describes the key, it vouches for nothing.
  /// Throws [TomSecretsPgpKeyException] for text that is no key block.
  factory TomSecretsPgpKeyInfo.parse(String armored) {
    try {
      final armor = pga.Armor.decode(armored);
      return _fromPackets(
        pgp.PacketList.decode(armor.data),
        isPrivate: armor.type == pga.ArmorType.privateKey,
      );
    } on TomSecretsPgpKeyException {
      rethrow;
    } on Object catch (e) {
      throw TomSecretsPgpKeyException('an unreadable OpenPGP key ($e)');
    }
  }

  static TomSecretsPgpKeyInfo _fromPackets(
    List<pgp.PacketInterface> packets, {
    required bool isPrivate,
  }) {
    final first = packets.firstOrNull;
    final key = switch (first) {
      pgp.SecretKeyPacket(:final publicKey) => publicKey,
      pgp.PublicKeyPacket() => first,
      _ => throw const TomSecretsPgpKeyException('no primary key packet'),
    };
    bool own(pgp.SignaturePacket s) =>
        _sameBytes(s.issuerKeyID, key.keyID) ||
        _sameBytes(s.issuerFingerprint, key.fingerprint);
    final direct = <pgp.SignaturePacket>[];
    final users = <String, List<pgp.SignaturePacket>>{};
    String? user;
    var inUser = false;
    for (final packet in packets.skip(1)) {
      if (packet is pgp.PublicSubkeyPacket ||
          packet is pgp.SecretSubkeyPacket) {
        break;
      }
      switch (packet) {
        case pgp.UserIDPacket(:final userID):
          user = userID;
          inUser = true;
          users.putIfAbsent(userID, () => []);
        case pgp.UserAttributePacket():
          user = null;
          inUser = true;
        case final pgp.SignaturePacket s when own(s):
          if (!inUser && s.isDirectKey) direct.add(s);
          if (user != null && s.isCertification) users[user]!.add(s);
      }
    }
    pgp.SignaturePacket? latest(Iterable<pgp.SignaturePacket> sigs) =>
        sigs.fold<pgp.SignaturePacket?>(
          null,
          (a, b) => a == null || b.creationTime.isAfter(a.creationTime) ? b : a,
        );
    final lastOf = {
      for (final MapEntry(:key, :value) in users.entries) key: ?latest(value),
    };
    final primaries = {
      for (final MapEntry(:key, :value) in lastOf.entries)
        if (value.isPrimaryUserID) key: value,
    };
    final pick = latest(primaries.isEmpty ? lastOf.values : primaries.values);
    final primaryUser = [
      for (final MapEntry(:key, :value) in lastOf.entries)
        if (identical(value, pick)) key,
    ].firstOrNull;
    final directSig = latest(direct);
    final seconds = (directSig?.keyExpirationTime ?? 0) > 0
        ? directSig!.keyExpirationTime
        : pick?.keyExpirationTime ?? 0;
    final created = key.creationTime.toUtc();
    return TomSecretsPgpKeyInfo._(
      fingerprint: _hex(key.fingerprint),
      keyId: _hex(key.keyID),
      userIds: [
        ?primaryUser,
        for (final u in users.keys)
          if (u != primaryUser) u,
      ],
      algorithm: key.keyAlgorithm.name,
      bits: key.keyStrength,
      created: created,
      expires: seconds > 0 ? created.add(Duration(seconds: seconds)) : null,
      isPrivate: isPrivate,
      version: key.keyVersion,
    );
  }
}

String _hex(Uint8List bytes) => [
  for (final b in bytes) b.toRadixString(16).padLeft(2, '0'),
].join().toUpperCase();

bool _sameBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// The public key block of the secret key block [privateArmored]: every
/// secret key packet replaced by its public key packet, user ids and
/// signatures kept (as `gpg --export` writes it). Read from the packets, so
/// it needs neither the passphrase nor a key `dart_pg` verifies.
String tomSecretsPgpPublicOf(String privateArmored) {
  final packets = pgp.PacketList.decode(pga.Armor.decode(privateArmored).data);
  return pga.Armor.encode(
    pga.ArmorType.publicKey,
    pgp.PacketList([
      for (final p in packets)
        if (p is pgp.SecretKeyPacket) p.publicKey else p,
    ]).encode(),
  );
}

/// [privateArmored] (locked with [passphrase]) with every RSA secret key
/// packet holding its primes as p < q and u = p⁻¹ mod q, locked again with
/// [passphrase]. `dart_pg` 2.1 generates them as p > q (pointycastle's
/// order), which libgcrypt refuses ("Bad secret key"); the public key and
/// every signature stay as they are, since the primes are only swapped.
String _rsaPrimesForGnuPG(String privateArmored, String passphrase) {
  final decrypted = pg.OpenPGP.decryptPrivateKey(privateArmored, passphrase);
  var swapped = false;
  pgp.PacketInterface ordered(pgp.PacketInterface packet) {
    if (packet is! pgp.SecretKeyPacket) return packet;
    final m = packet.secretKeyMaterial;
    if (m is! pgp.RSASecretMaterial || m.primeP < m.primeQ) return packet;
    swapped = true;
    final o = pgp.RSASecretMaterial(
      m.exponent,
      m.primeQ,
      m.primeP,
      m.publicMaterial,
    );
    return packet is pgp.SecretSubkeyPacket
        ? pgp.SecretSubkeyPacket(
            packet.publicKey as pgp.PublicSubkeyPacket,
            o.toBytes,
            secretKeyMaterial: o,
          )
        : pgp.SecretKeyPacket(
            packet.publicKey,
            o.toBytes,
            secretKeyMaterial: o,
          );
  }

  final packets = [for (final p in decrypted.packetList) ordered(p)];
  if (!swapped) return privateArmored;
  final unlocked = pga.Armor.encode(
    pga.ArmorType.privateKey,
    pgp.PacketList(packets).encode(),
  );
  return pg.OpenPGP.readPrivateKey(unlocked).encrypt(passphrase).armor();
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
  final privateArmored = algorithm == TomSecretsPgpKeyAlgorithm.rsa
      ? _rsaPrimesForGnuPG(key.armor(), secret)
      : key.armor();
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
      public = tomSecretsPgpPublicOf(privateArmored);
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
