// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Passkeys as KeePassXC stores them (DP-120): string fields of the site's
/// login entry, `KPEX_PASSKEY_*` (the names checked against KeePassXC 2.8.0's
/// binary). Written by the Enpass import in phase A, used from phase C; the
/// client endpoint never serves them (`tomSecretsIsPasskeyField`).
///
/// [tomSecretsPasskeyPem] turns a private key in the shapes an export may hold
/// it — PEM, base64 or base64url DER (PKCS#8 or SEC1), a raw P-256 scalar, a
/// JWK (EC P-256 or OKP Ed25519) — into the PKCS#8 PEM KeePassXC reads.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

/// KeePassXC's passkey attributes.
abstract final class TomSecretsPasskeyFields {
  /// The relying party (the site's domain).
  static const relyingParty = KdbxKey('KPEX_PASSKEY_RELYING_PARTY');

  /// The credential id, base64url without padding.
  static const credentialId = KdbxKey('KPEX_PASSKEY_CREDENTIAL_ID');

  /// The private key, PKCS#8 PEM (protected).
  static const privateKeyPem = KdbxKey('KPEX_PASSKEY_PRIVATE_KEY_PEM');

  /// The user handle, base64url without padding.
  static const userHandle = KdbxKey('KPEX_PASSKEY_USER_HANDLE');

  /// The account name at the relying party.
  static const userName = KdbxKey('KPEX_PASSKEY_USERNAME');
}

/// A passkey's private key that cannot be read.
final class TomSecretsPasskeyException implements Exception {
  /// Unreadable for [message].
  TomSecretsPasskeyException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsPasskeyException: $message';
}

/// A passkey with its private key.
final class TomSecretsPasskey {
  /// A passkey of [relyingParty] for [userName]; [credentialId] and
  /// [userHandle] base64url, [privateKeyPem] PKCS#8 PEM.
  const TomSecretsPasskey({
    required this.relyingParty,
    required this.credentialId,
    required this.privateKeyPem,
    this.userHandle,
    this.userName,
  });

  /// The relying party.
  final String relyingParty;

  /// The credential id (base64url, no padding).
  final String credentialId;

  /// The private key (PKCS#8 PEM).
  final String privateKeyPem;

  /// The user handle (base64url, no padding), when known.
  final String? userHandle;

  /// The account name, when known.
  final String? userName;

  /// The fields KeePassXC reads, by name.
  Map<KdbxKey, StringValue> get fields => {
    TomSecretsPasskeyFields.relyingParty: PlainValue(relyingParty),
    TomSecretsPasskeyFields.credentialId: PlainValue(credentialId),
    TomSecretsPasskeyFields.privateKeyPem: ProtectedValue.fromString(
      privateKeyPem,
    ),
    if (userHandle != null)
      TomSecretsPasskeyFields.userHandle: PlainValue(userHandle!),
    if (userName != null)
      TomSecretsPasskeyFields.userName: PlainValue(userName!),
  };

  /// The passkey stored in [entry], or null.
  static TomSecretsPasskey? fromEntry(KdbxEntry entry) {
    String? read(KdbxKey key) => entry.getString(key)?.getText();
    final rp = read(TomSecretsPasskeyFields.relyingParty);
    final id = read(TomSecretsPasskeyFields.credentialId);
    final pem = read(TomSecretsPasskeyFields.privateKeyPem);
    if (rp == null || id == null || pem == null) return null;
    return TomSecretsPasskey(
      relyingParty: rp,
      credentialId: id,
      privateKeyPem: pem,
      userHandle: read(TomSecretsPasskeyFields.userHandle),
      userName: read(TomSecretsPasskeyFields.userName),
    );
  }

  @override
  String toString() => 'TomSecretsPasskey($relyingParty, ***)';
}

/// [text] (base64, base64url, padded or not) as base64url without padding.
String tomSecretsBase64Url(String text) =>
    base64Url.encode(tomSecretsDecodeBase64(text)).replaceAll('=', '');

/// The bytes of base64 or base64url [text], padded or not.
Uint8List tomSecretsDecodeBase64(String text) {
  var t = text.trim().replaceAll('-', '+').replaceAll('_', '/');
  t = t.replaceAll(RegExp(r'\s'), '');
  while (t.length % 4 != 0) {
    t += '=';
  }
  return base64.decode(t);
}

const _ecPublicKeyOid = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const _p256Oid = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const _ed25519Oid = [0x2B, 0x65, 0x70];

/// [key] as PKCS#8 PEM: a PEM (PKCS#8 as it is; SEC1 `EC PRIVATE KEY`
/// converted), base64 or base64url DER (PKCS#8 or SEC1), 32 raw bytes or
/// their base64 (a P-256 scalar), or a JWK (a map or its JSON text; `EC`
/// on `P-256`, or `OKP` on `Ed25519`).
String tomSecretsPasskeyPem(Object key) {
  final der = switch (key) {
    final Map<String, Object?> jwk => _fromJwk(jwk),
    final Map jwk => _fromJwk(jwk.cast<String, Object?>()),
    final List<int> bytes => _fromBytes(Uint8List.fromList(bytes)),
    final String text => _fromText(text.trim()),
    _ => throw TomSecretsPasskeyException('an unknown key shape'),
  };
  final body = base64.encode(der);
  final lines = [
    for (var i = 0; i < body.length; i += 64)
      body.substring(i, i + 64 > body.length ? body.length : i + 64),
  ];
  return '-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n'
      '-----END PRIVATE KEY-----\n';
}

Uint8List _fromText(String text) {
  if (text.startsWith('{')) {
    final json = jsonDecode(text);
    if (json is Map) return _fromJwk(json.cast<String, Object?>());
  }
  final pem = RegExp(
    r'-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----',
  ).firstMatch(text);
  if (pem != null) return _fromBytes(tomSecretsDecodeBase64(pem.group(2)!));
  final Uint8List bytes;
  try {
    bytes = tomSecretsDecodeBase64(text);
  } on FormatException {
    throw TomSecretsPasskeyException('neither PEM, base64 nor a JWK');
  }
  return _fromBytes(bytes);
}

Uint8List _fromBytes(Uint8List bytes) {
  if (bytes.length == 32) return _p256Pkcs8(bytes);
  final top = _Der(bytes).read();
  if (top.tag != 0x30) throw TomSecretsPasskeyException('not DER');
  final parts = _Der(top.content).readAll();
  // PKCS#8: version 0, an algorithm identifier, the key as an octet string.
  if (parts.length >= 3 &&
      parts[0].tag == 0x02 &&
      parts[1].tag == 0x30 &&
      parts[2].tag == 0x04) {
    return bytes;
  }
  // SEC1 ECPrivateKey: version 1, the scalar as an octet string.
  if (parts.length >= 2 &&
      parts[0].tag == 0x02 &&
      parts[0].content.length == 1 &&
      parts[0].content[0] == 1 &&
      parts[1].tag == 0x04) {
    final curve = parts.where((p) => p.tag == 0xA0).firstOrNull;
    if (curve != null) {
      final oid = _Der(curve.content).read();
      if (!_same(oid.content, _p256Oid)) {
        throw TomSecretsPasskeyException(
          'an EC key on a curve other than P-256',
        );
      }
    }
    return _p256Pkcs8(parts[1].content);
  }
  throw TomSecretsPasskeyException('neither PKCS#8 nor SEC1 DER');
}

Uint8List _fromJwk(Map<String, Object?> jwk) {
  final d = jwk['d'];
  if (d is! String) throw TomSecretsPasskeyException('a JWK without d');
  final scalar = tomSecretsDecodeBase64(d);
  switch ((jwk['kty'], jwk['crv'])) {
    case ('EC', 'P-256'):
      return _p256Pkcs8(scalar);
    case ('OKP', 'Ed25519'):
      if (scalar.length != 32) {
        throw TomSecretsPasskeyException('an Ed25519 key is 32 bytes');
      }
      return _seq([
        _int0,
        _seq([_oid(_ed25519Oid)]),
        _tlv(0x04, _tlv(0x04, scalar)),
      ]);
    case (final kty, final crv):
      throw TomSecretsPasskeyException('a JWK of $kty $crv');
  }
}

/// The PKCS#8 DER of the P-256 scalar [d], with the public key.
Uint8List _p256Pkcs8(List<int> d) {
  final scalar = d.length > 32 && d.first == 0 ? d.sublist(d.length - 32) : d;
  if (scalar.length != 32) {
    throw TomSecretsPasskeyException('a P-256 key is 32 bytes');
  }
  final params = pc.ECDomainParameters('prime256v1');
  final value = BigInt.parse(
    scalar.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
    radix: 16,
  );
  if (value == BigInt.zero || value >= params.n) {
    throw TomSecretsPasskeyException('not a P-256 private key');
  }
  final public = (params.G * value)!.getEncoded(false);
  final ecPrivateKey = _seq([
    _tlv(0x02, [1]),
    _tlv(0x04, scalar),
    _tlv(0xA1, _tlv(0x03, [0, ...public])),
  ]);
  return _seq([
    _int0,
    _seq([_oid(_ecPublicKeyOid), _oid(_p256Oid)]),
    _tlv(0x04, ecPrivateKey),
  ]);
}

final _int0 = _tlv(0x02, [0]);

Uint8List _oid(List<int> body) => _tlv(0x06, body);

Uint8List _seq(List<List<int>> parts) =>
    _tlv(0x30, [for (final p in parts) ...p]);

Uint8List _tlv(int tag, List<int> content) {
  final n = content.length;
  final length = n < 0x80
      ? [n]
      : n < 0x100
      ? [0x81, n]
      : [0x82, n >> 8, n & 0xFF];
  return Uint8List.fromList([tag, ...length, ...content]);
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// One DER element.
final class _Element {
  _Element(this.tag, this.content);
  final int tag;
  final Uint8List content;
}

/// A minimal DER reader (definite lengths, single-byte tags).
final class _Der {
  _Der(this.bytes);
  final Uint8List bytes;
  var _at = 0;

  _Element read() {
    if (_at + 2 > bytes.length) throw TomSecretsPasskeyException('short DER');
    final tag = bytes[_at++];
    var length = bytes[_at++];
    if (length & 0x80 != 0) {
      final count = length & 0x7F;
      if (count == 0 || count > 3 || _at + count > bytes.length) {
        throw TomSecretsPasskeyException('a DER length it cannot read');
      }
      length = 0;
      for (var i = 0; i < count; i++) {
        length = (length << 8) | bytes[_at++];
      }
    }
    if (_at + length > bytes.length) {
      throw TomSecretsPasskeyException('truncated DER');
    }
    final content = Uint8List.sublistView(bytes, _at, _at + length);
    _at += length;
    return _Element(tag, content);
  }

  List<_Element> readAll() => [for (; _at < bytes.length;) read()];
}

/// **[C]** The kind of a passkey's key pair (its COSE algorithm).
enum TomSecretsPasskeyAlgorithm {
  /// ECDSA on P-256 with SHA-256 (COSE -7), what most sites ask for.
  es256(-7),

  /// Ed25519 (COSE -8).
  edDsa(-8);

  const TomSecretsPasskeyAlgorithm(this.cose);

  /// The COSE algorithm number.
  final int cose;
}

/// **[C]** A passkey's private key as the authenticator signs with it: the
/// P-256 scalar or the Ed25519 seed (32 bytes each).
typedef TomSecretsPasskeyKey = ({
  TomSecretsPasskeyAlgorithm algorithm,
  Uint8List secret,
});

/// **[C]** The key of the PKCS#8 PEM [pem] (as [tomSecretsPasskeyPem]
/// writes it). Throws [TomSecretsPasskeyException] for another key.
TomSecretsPasskeyKey tomSecretsPasskeyKeyOf(String pem) {
  final der = tomSecretsDecodeBase64(
    pem
        .replaceAll(RegExp(r'-----[A-Z ]+-----'), '')
        .replaceAll(RegExp(r'\s'), ''),
  );
  final top = _Der(der).read();
  if (top.tag != 0x30) throw TomSecretsPasskeyException('not DER');
  final parts = _Der(top.content).readAll();
  if (parts.length < 3 || parts[1].tag != 0x30 || parts[2].tag != 0x04) {
    throw TomSecretsPasskeyException('not PKCS#8');
  }
  final algorithm = _Der(parts[1].content).readAll();
  final oid = algorithm.first.content;
  if (_same(oid, _ed25519Oid)) {
    final seed = _Der(parts[2].content).read();
    if (seed.content.length != 32) {
      throw TomSecretsPasskeyException('an Ed25519 key is 32 bytes');
    }
    return (
      algorithm: TomSecretsPasskeyAlgorithm.edDsa,
      secret: Uint8List.fromList(seed.content),
    );
  }
  if (_same(oid, _ecPublicKeyOid) &&
      algorithm.length > 1 &&
      _same(algorithm[1].content, _p256Oid)) {
    final sec1 = _Der(_Der(parts[2].content).read().content).readAll();
    if (sec1.length < 2 || sec1[1].tag != 0x04) {
      throw TomSecretsPasskeyException('not an EC private key');
    }
    return (
      algorithm: TomSecretsPasskeyAlgorithm.es256,
      secret: Uint8List.fromList(sec1[1].content),
    );
  }
  throw TomSecretsPasskeyException('a key that is neither P-256 nor Ed25519');
}

/// **[C]** The passkeys of [file]'s entries (its recycle bin left out),
/// with the entry each is kept in.
List<({KdbxEntry entry, TomSecretsPasskey passkey})> tomSecretsPasskeysIn(
  KdbxFile file,
) {
  final bin = file.recycleBin;
  final out = <({KdbxEntry entry, TomSecretsPasskey passkey})>[];
  void walk(KdbxGroup group) {
    if (bin != null && identical(group, bin)) return;
    for (final e in group.entries) {
      final p = TomSecretsPasskey.fromEntry(e);
      if (p != null) out.add((entry: e, passkey: p));
    }
    group.groups.forEach(walk);
  }

  walk(file.body.rootGroup);
  return out;
}

/// Whether [e]'s URL names [relyingParty] (its host the relying party or
/// below it).
bool _ofSite(KdbxEntry e, String relyingParty) {
  final rp = relyingParty.toLowerCase();
  final url = e.getString(KdbxKeyCommon.URL)?.getText() ?? '';
  final host = Uri.tryParse(url.contains('://') ? url : 'https://$url')?.host;
  if (host == null || host.isEmpty) return false;
  final h = host.toLowerCase();
  return h == rp || h.endsWith('.$rp');
}

/// **[C]** The vault of [candidates] (store name → its file, the vaults a
/// new passkey may go into) that takes [passkey]: the one holding a passkey
/// of the same relying party and user handle, else one with a login of the
/// site (outside its recycle bin), else the first. Null without
/// candidates.
String? tomSecretsPasskeyHome(
  Map<String, KdbxFile> candidates,
  TomSecretsPasskey passkey,
) {
  for (final MapEntry(:key, :value) in candidates.entries) {
    if (tomSecretsPasskeysIn(value).any(
      (p) =>
          p.passkey.relyingParty == passkey.relyingParty &&
          p.passkey.userHandle == passkey.userHandle,
    )) {
      return key;
    }
  }
  for (final MapEntry(:key, :value) in candidates.entries) {
    final bin = value.recycleBin;
    bool holds(KdbxGroup g) =>
        !(bin != null && identical(g, bin)) &&
        (g.entries.any((e) => _ofSite(e, passkey.relyingParty)) ||
            g.groups.any(holds));
    if (holds(value.body.rootGroup)) return key;
  }
  return candidates.keys.firstOrNull;
}

/// **[C]** Keeps [passkey] in [file]: in the login entry of its relying
/// party and user name that has no passkey yet (its URL's host the relying
/// party or below it), else in a new login entry in [group] (default the
/// root group) titled after the site, with the URL `https://<rp>` and the
/// user name. A passkey of the same relying party and user handle is
/// replaced (the site registered again). Answers the entry.
KdbxEntry tomSecretsKeepPasskey(
  KdbxFile file,
  TomSecretsPasskey passkey, {
  KdbxGroup? group,
}) {
  bool ofSite(KdbxEntry e) => _ofSite(e, passkey.relyingParty);

  final existing = tomSecretsPasskeysIn(file);
  final same = existing
      .where(
        (p) =>
            p.passkey.relyingParty == passkey.relyingParty &&
            p.passkey.userHandle != null &&
            p.passkey.userHandle == passkey.userHandle,
      )
      .firstOrNull;
  KdbxEntry? target = same?.entry;
  if (target == null) {
    final bin = file.recycleBin;
    KdbxEntry? found;
    void walk(KdbxGroup g) {
      if (found != null || (bin != null && identical(g, bin))) return;
      for (final e in g.entries) {
        final user = e.getString(KdbxKeyCommon.USER_NAME)?.getText() ?? '';
        if (ofSite(e) &&
            TomSecretsPasskey.fromEntry(e) == null &&
            (passkey.userName == null ||
                user.isEmpty ||
                user == passkey.userName)) {
          found = e;
          return;
        }
      }
      g.groups.forEach(walk);
    }

    walk(file.body.rootGroup);
    target = found;
  }
  if (target == null) {
    final parent = group ?? file.body.rootGroup;
    target = KdbxEntry.create(file, parent)
      ..setString(KdbxKeyCommon.TITLE, PlainValue(passkey.relyingParty))
      ..setString(
        KdbxKeyCommon.URL,
        PlainValue('https://${passkey.relyingParty}'),
      );
    if (passkey.userName != null) {
      target.setString(KdbxKeyCommon.USER_NAME, PlainValue(passkey.userName!));
    }
    parent.addEntry(target);
  } else if ((target.getString(KdbxKeyCommon.USER_NAME)?.getText() ?? '')
          .isEmpty &&
      passkey.userName != null) {
    target.setString(KdbxKeyCommon.USER_NAME, PlainValue(passkey.userName!));
  }
  for (final MapEntry(:key, :value) in passkey.fields.entries) {
    target.setString(key, value);
  }
  return target;
}
