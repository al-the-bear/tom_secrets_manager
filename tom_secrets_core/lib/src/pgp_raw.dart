// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** A minimal reader of OpenPGP key blocks (RFC 4880, RFC 9580): the
/// fallback `pgp_key.dart` uses for a key `dart_pg` refuses — an RSA key
/// below 2048 bits, a v3 key — so such a key still shows its fingerprint,
/// user ids and expiry, gets Expires, and the health report flags it short
/// (DP-179). It reads the packet framing (old and new headers, partial
/// lengths), v3 and v4 key packets, user id packets and signatures' subpackets;
/// it verifies nothing and decrypts nothing. Not exported.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// One OpenPGP packet: its tag and body.
final class PgpPacket {
  /// A packet of [tag] holding [body].
  const PgpPacket(this.tag, this.body);

  /// The packet tag (5 secret key, 6 public key, 7 secret subkey, 13 user
  /// id, 14 public subkey, 2 signature, 17 user attribute, ...).
  final int tag;

  /// The packet body.
  final Uint8List body;
}

/// The packets of [data], a binary key block. Throws [FormatException] for
/// framing that does not read.
List<PgpPacket> pgpReadPackets(Uint8List data) {
  final packets = <PgpPacket>[];
  var pos = 0;
  int byte() {
    if (pos >= data.length) {
      throw const FormatException('the key block ends inside a packet');
    }
    return data[pos++];
  }

  int be(int n) {
    var v = 0;
    for (var i = 0; i < n; i++) {
      v = (v << 8) | byte();
    }
    return v;
  }

  Uint8List take(int n) {
    if (n < 0 || pos + n > data.length) {
      throw const FormatException('a packet is longer than the key block');
    }
    final out = Uint8List.sublistView(data, pos, pos + n);
    pos += n;
    return out;
  }

  while (pos < data.length) {
    final head = byte();
    if (head & 0x80 == 0) {
      throw const FormatException('not an OpenPGP packet header');
    }
    if (head & 0x40 != 0) {
      // New format: lengths of one, two or five octets, or partial lengths.
      final tag = head & 0x3f;
      final body = BytesBuilder(copy: false);
      while (true) {
        final o = byte();
        if (o < 192) {
          body.add(take(o));
        } else if (o < 224) {
          body.add(take(((o - 192) << 8) + byte() + 192));
        } else if (o == 255) {
          body.add(take(be(4)));
        } else {
          body.add(take(1 << (o & 0x1f)));
          continue;
        }
        break;
      }
      packets.add(PgpPacket(tag, body.toBytes()));
    } else {
      // Old format: the length type in the low two bits.
      final tag = (head >> 2) & 0x0f;
      final length = switch (head & 3) {
        0 => be(1),
        1 => be(2),
        2 => be(4),
        _ => data.length - pos,
      };
      packets.add(PgpPacket(tag, take(length)));
    }
  }
  return packets;
}

/// [packets] as a binary key block with new-format headers.
Uint8List pgpWritePackets(List<PgpPacket> packets) {
  final out = BytesBuilder(copy: false);
  for (final p in packets) {
    final n = p.body.length;
    out.addByte(0xc0 | p.tag);
    if (n < 192) {
      out.addByte(n);
    } else if (n < 8384) {
      out
        ..addByte(((n - 192) >> 8) + 192)
        ..addByte((n - 192) & 0xff);
    } else {
      out
        ..addByte(255)
        ..add([n >> 24 & 0xff, n >> 16 & 0xff, n >> 8 & 0xff, n & 0xff]);
    }
    out.add(p.body);
  }
  return out.toBytes();
}

/// The algorithm names `dart_pg` uses for the algorithm ids this reader
/// knows.
const Map<int, String> _algorithmNames = {
  1: 'rsaEncryptSign',
  2: 'rsaEncrypt',
  3: 'rsaSign',
  16: 'elgamal',
  17: 'dsa',
  18: 'ecdh',
  19: 'ecdsa',
  22: 'eddsaLegacy',
  25: 'x25519',
  26: 'x448',
  27: 'ed25519',
  28: 'ed448',
};

/// A key packet's public part.
final class _KeyPacket {
  _KeyPacket(this.body) {
    if (body.isEmpty) throw const FormatException('an empty key packet');
    version = body[0];
    if (version != 2 && version != 3 && version != 4) {
      throw FormatException('key version $version is not read');
    }
    created = DateTime.fromMillisecondsSinceEpoch(
      _be32(body, 1) * 1000,
      isUtc: true,
    );
    var pos = 5;
    if (version < 4) {
      validDays = (body[pos] << 8) | body[pos + 1];
      pos += 2;
    }
    algorithm = body[pos++];
    final mpis = <Uint8List>[];
    int mpi() {
      final bitCount = (body[pos] << 8) | body[pos + 1];
      final n = (bitCount + 7) >> 3;
      mpis.add(Uint8List.sublistView(body, pos + 2, pos + 2 + n));
      pos += 2 + n;
      return bitCount;
    }

    void oid() => pos += 1 + body[pos];
    switch (algorithm) {
      case 1 || 2 || 3:
        bits = mpi();
        mpi();
      case 16:
        bits = mpi();
        mpi();
        mpi();
      case 17:
        bits = mpi();
        mpi();
        mpi();
        mpi();
      case 19 || 22:
        oid();
        mpi();
      case 18:
        oid();
        mpi();
        pos += 1 + body[pos];
      case 25 || 27:
        pos += 32;
      case 26:
        pos += 56;
      case 28:
        pos += 57;
      default:
        throw FormatException('key algorithm $algorithm is not read');
    }
    if (pos > body.length) {
      throw const FormatException('a key packet ends inside its key');
    }
    publicLength = pos;
    final public = Uint8List.sublistView(body, 0, pos);
    if (version == 4) {
      fingerprint = Uint8List.fromList(
        crypto.sha1.convert([0x99, pos >> 8, pos & 0xff, ...public]).bytes,
      );
      keyId = Uint8List.sublistView(fingerprint, 12);
    } else {
      // RFC 4880 12.2: v3 keys are RSA; MD5 over n and e, the key id the
      // low 64 bits of n.
      if (mpis.length < 2) {
        throw const FormatException('a v3 key that is not RSA');
      }
      fingerprint = Uint8List.fromList(
        crypto.md5.convert([...mpis[0], ...mpis[1]]).bytes,
      );
      keyId = Uint8List.sublistView(mpis[0], mpis[0].length - 8);
    }
  }

  final Uint8List body;
  late final int version;
  late final DateTime created;
  int validDays = 0;
  late final int algorithm;
  int bits = 0;
  late final int publicLength;
  late final Uint8List fingerprint;
  late final Uint8List keyId;
}

int _be32(Uint8List b, int at) =>
    (b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3];

/// What a signature says about the key: the parts the information needs.
final class _Signature {
  _Signature(Uint8List body) {
    if (body.isEmpty) throw const FormatException('an empty signature');
    final version = body[0];
    if (version == 3 || version == 2) {
      type = body[2];
      created = _be32(body, 3);
      issuer = Uint8List.sublistView(body, 7, 15);
      return;
    }
    if (version != 4) return;
    type = body[1];
    var pos = 4;
    final hashedLength = (body[pos] << 8) | body[pos + 1];
    pos += 2;
    _subpackets(body, pos, pos + hashedLength, hashed: true);
    pos += hashedLength;
    final unhashedLength = (body[pos] << 8) | body[pos + 1];
    pos += 2;
    _subpackets(body, pos, pos + unhashedLength, hashed: false);
  }

  void _subpackets(Uint8List b, int start, int end, {required bool hashed}) {
    var pos = start;
    while (pos < end) {
      final o = b[pos];
      int length;
      if (o < 192) {
        length = o;
        pos += 1;
      } else if (o < 255) {
        length = ((o - 192) << 8) + b[pos + 1] + 192;
        pos += 2;
      } else {
        length = _be32(b, pos + 1);
        pos += 5;
      }
      if (length == 0 || pos + length > end) {
        throw const FormatException('a signature subpacket does not fit');
      }
      final kind = b[pos] & 0x7f;
      final data = Uint8List.sublistView(b, pos + 1, pos + length);
      pos += length;
      switch (kind) {
        case 2 when hashed && data.length == 4:
          created = _be32(data, 0);
        case 9 when hashed && data.length == 4:
          keyExpiration = _be32(data, 0);
        case 25 when hashed && data.isNotEmpty:
          primary = data[0] != 0;
        case 16 when data.length == 8:
          issuer = data;
        case 33 when data.length > 1:
          issuerFingerprint = Uint8List.sublistView(data, 1);
      }
    }
  }

  int type = -1;
  int created = 0;
  int keyExpiration = 0;
  bool primary = false;
  Uint8List? issuer;
  Uint8List? issuerFingerprint;

  bool get isCertification => type >= 0x10 && type <= 0x13;
  bool get isDirectKey => type == 0x1f;
}

/// What a key block says, read by this reader.
final class PgpRawKey {
  const PgpRawKey._({
    required this.fingerprint,
    required this.keyId,
    required this.algorithm,
    required this.bits,
    required this.created,
    required this.expires,
    required this.userIds,
    required this.version,
  });

  /// The primary key's fingerprint (SHA-1 for v4, MD5 for v3).
  final Uint8List fingerprint;

  /// The primary key's id.
  final Uint8List keyId;

  /// Its algorithm, named as `dart_pg` names it.
  final String algorithm;

  /// The length of its first MPI (the modulus or prime), 0 for a curve.
  final int bits;

  /// When it was made.
  final DateTime created;

  /// When it expires, or null.
  final DateTime? expires;

  /// Its user ids, the primary one first.
  final List<String> userIds;

  /// The key version (3 or 4).
  final int version;
}

bool _same(Uint8List? a, Uint8List b) {
  if (a == null || a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// What the key block [packets] says, by the rules `TomSecretsPgpKeyInfo`
/// reads with: the expiry from the latest self-signature (a direct key
/// signature's, else the primary user id's, else the latest user id
/// self-signature's) counted from the key's creation (a v3 key's from its
/// validity period); the primary user id first. Throws [FormatException].
PgpRawKey pgpReadRawKey(List<PgpPacket> packets) {
  final first = packets.firstOrNull;
  if (first == null || (first.tag != 5 && first.tag != 6)) {
    throw const FormatException('no primary key packet');
  }
  final key = _KeyPacket(first.body);
  bool own(_Signature s) =>
      _same(s.issuer, key.keyId) || _same(s.issuerFingerprint, key.fingerprint);
  final direct = <_Signature>[];
  final users = <String, List<_Signature>>{};
  String? user;
  var inUser = false;
  for (final packet in packets.skip(1)) {
    if (packet.tag == 7 || packet.tag == 14) break;
    switch (packet.tag) {
      case 13:
        final id = utf8.decode(packet.body, allowMalformed: true);
        user = id;
        inUser = true;
        users.putIfAbsent(id, () => []);
      case 17:
        user = null;
        inUser = true;
      case 2:
        final s = _Signature(packet.body);
        if (!own(s)) continue;
        if (!inUser && s.isDirectKey) direct.add(s);
        if (user != null && s.isCertification) users[user]!.add(s);
    }
  }
  _Signature? latest(Iterable<_Signature> sigs) => sigs.fold<_Signature?>(
    null,
    (a, b) => a == null || b.created > a.created ? b : a,
  );
  final lastOf = {
    for (final MapEntry(:key, :value) in users.entries) key: ?latest(value),
  };
  final primaries = [
    for (final s in lastOf.values)
      if (s.primary) s,
  ];
  final pick = latest(primaries.isEmpty ? lastOf.values : primaries);
  final primaryUser = [
    for (final MapEntry(:key, :value) in lastOf.entries)
      if (identical(value, pick)) key,
  ].firstOrNull;
  final directSig = latest(direct);
  final seconds = key.version < 4
      ? key.validDays * 86400
      : (directSig?.keyExpiration ?? 0) > 0
      ? directSig!.keyExpiration
      : pick?.keyExpiration ?? 0;
  return PgpRawKey._(
    fingerprint: key.fingerprint,
    keyId: key.keyId,
    algorithm: _algorithmNames[key.algorithm] ?? 'algorithm${key.algorithm}',
    bits: key.bits,
    created: key.created,
    expires: seconds > 0 ? key.created.add(Duration(seconds: seconds)) : null,
    userIds: [
      ?primaryUser,
      for (final u in users.keys)
        if (u != primaryUser) u,
    ],
    version: key.version,
  );
}

/// The public key block of the secret key block [packets]: every secret
/// key packet (5, 7) replaced by its public part as a public key packet (6,
/// 14), everything else kept.
List<PgpPacket> pgpPublicPackets(List<PgpPacket> packets) => [
  for (final p in packets)
    if (p.tag == 5 || p.tag == 7)
      PgpPacket(
        p.tag == 5 ? 6 : 14,
        Uint8List.sublistView(p.body, 0, _KeyPacket(p.body).publicLength),
      )
    else
      p,
];
