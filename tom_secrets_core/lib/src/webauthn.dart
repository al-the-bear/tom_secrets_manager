// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The product as a WebAuthn authenticator for its passkeys
/// (part-password-manager, part-os-integration): what the OS providers (the
/// macOS AutoFill provider, Android's Credential Manager) hand to a site.
///
/// - **Creating** ([tomSecretsCreatePasskey]): a new key pair of the
///   algorithm the site asks for (ES256, else Ed25519), a random credential
///   id, kept as KeePassXC keeps passkeys (`KPEX_PASSKEY_*`,
///   [TomSecretsPasskey]); the registration answers the `none` attestation
///   ([TomSecretsPasskeyRegistration.attestationObject]).
/// - **Using** ([tomSecretsPasskeyAssertion]): the authenticator data and the
///   signature over it and the client data's hash.
/// - **Flags:** user present and verified (the provider verifies the user
///   before it answers), backup eligible and backed up (the vault is
///   synced); the signature counter stays 0, as synced passkeys keep it; the
///   AAGUID is all zeros (no attestation).
/// - **JSON** ([tomSecretsPasskeyRegistrationJson],
///   [tomSecretsPasskeyAssertionJson]): WebAuthn's `PublicKeyCredential` as
///   Android's Credential Manager returns it, with the client data the
///   provider builds for an app ([tomSecretsPasskeyClientDataJson]) or the
///   hash a browser gives.
///
/// A passkey's algorithm is the site's choice, so it stays classical; the
/// client endpoint never serves the fields.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;
import 'package:pointycastle/export.dart' as pc;

import 'passkey.dart';

/// User present.
const int tomSecretsWebAuthnFlagUp = 0x01;

/// User verified.
const int tomSecretsWebAuthnFlagUv = 0x04;

/// Backup eligible.
const int tomSecretsWebAuthnFlagBe = 0x08;

/// Backed up.
const int tomSecretsWebAuthnFlagBs = 0x10;

/// Attested credential data included.
const int tomSecretsWebAuthnFlagAt = 0x40;

/// The flags of every answer: present, verified, backup eligible, backed up.
const int tomSecretsPasskeyFlags =
    tomSecretsWebAuthnFlagUp |
    tomSecretsWebAuthnFlagUv |
    tomSecretsWebAuthnFlagBe |
    tomSecretsWebAuthnFlagBs;

/// A WebAuthn request this authenticator cannot answer.
final class TomSecretsWebAuthnException implements Exception {
  /// Refused for [message].
  const TomSecretsWebAuthnException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsWebAuthnException: $message';
}

/// A passkey just made, with what its registration answers.
final class TomSecretsPasskeyRegistration {
  /// The registration of [passkey].
  const TomSecretsPasskeyRegistration({
    required this.passkey,
    required this.credentialId,
    required this.authenticatorData,
    required this.attestationObject,
    required this.publicKeySpki,
    required this.algorithm,
  });

  /// The passkey to keep.
  final TomSecretsPasskey passkey;

  /// The credential id.
  final Uint8List credentialId;

  /// The authenticator data with the attested credential data.
  final Uint8List authenticatorData;

  /// The attestation object (`fmt` `none`).
  final Uint8List attestationObject;

  /// The public key as DER SubjectPublicKeyInfo (`getPublicKey()`).
  final Uint8List publicKeySpki;

  /// The key pair's algorithm.
  final TomSecretsPasskeyAlgorithm algorithm;
}

/// An assertion: what a sign-in answers.
final class TomSecretsPasskeyAssertion {
  /// An assertion of [credentialId].
  const TomSecretsPasskeyAssertion({
    required this.credentialId,
    required this.authenticatorData,
    required this.signature,
    this.userHandle,
  });

  /// The credential id.
  final Uint8List credentialId;

  /// The authenticator data.
  final Uint8List authenticatorData;

  /// The signature over the authenticator data and the client data's hash
  /// (DER for ES256, 64 bytes for Ed25519).
  final Uint8List signature;

  /// The user handle, when the passkey has one.
  final Uint8List? userHandle;
}

/// Makes a passkey for [rpId] and the user [userHandle] / [userName] with
/// the first of [algorithms] (COSE numbers, the site's order) this
/// authenticator can make: ES256 or Ed25519. Throws
/// [TomSecretsWebAuthnException] when the site offers neither.
Future<TomSecretsPasskeyRegistration> tomSecretsCreatePasskey({
  required String rpId,
  required Uint8List userHandle,
  String? userName,
  List<int> algorithms = const [-7],
  Random? random,
}) async {
  final r = random ?? Random.secure();
  final algorithm = [
    for (final a in algorithms)
      ...TomSecretsPasskeyAlgorithm.values.where((v) => v.cose == a),
  ].firstOrNull;
  if (algorithm == null) {
    throw TomSecretsWebAuthnException(
      'the site asks for algorithms $algorithms; this authenticator makes '
      'ES256 (-7) and Ed25519 (-8) keys',
    );
  }
  final credentialId = Uint8List.fromList([
    for (var i = 0; i < 32; i++) r.nextInt(256),
  ]);
  final Uint8List secret;
  final Uint8List cose;
  final Uint8List spki;
  switch (algorithm) {
    case TomSecretsPasskeyAlgorithm.es256:
      final params = pc.ECDomainParameters('prime256v1');
      BigInt d;
      do {
        d = _bigInt([for (var i = 0; i < 32; i++) r.nextInt(256)]);
      } while (d == BigInt.zero || d >= params.n);
      secret = _bytes32(d);
      final q = (params.G * d)!;
      final x = _bytes32(q.x!.toBigInteger()!);
      final y = _bytes32(q.y!.toBigInteger()!);
      cose = _cbor({1: 2, 3: -7, -1: 1, -2: x, -3: y});
      spki = _spki(
        const [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01],
        const [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        [0x04, ...x, ...y],
      );
    case TomSecretsPasskeyAlgorithm.edDsa:
      secret = Uint8List.fromList([
        for (var i = 0; i < 32; i++) r.nextInt(256),
      ]);
      final pair = await cg.Ed25519().newKeyPairFromSeed(secret);
      final public = Uint8List.fromList((await pair.extractPublicKey()).bytes);
      cose = _cbor({1: 1, 3: -8, -1: 6, -2: public});
      spki = _spki(const [0x2B, 0x65, 0x70], null, public);
  }
  final pem = tomSecretsPasskeyPem(
    algorithm == TomSecretsPasskeyAlgorithm.es256
        ? secret
        : {'kty': 'OKP', 'crv': 'Ed25519', 'd': base64Url.encode(secret)},
  );
  final authenticatorData = Uint8List.fromList([
    ...tomSecretsRpIdHash(rpId),
    tomSecretsPasskeyFlags | tomSecretsWebAuthnFlagAt,
    0, 0, 0, 0, // the signature counter
    ...List<int>.filled(16, 0), // the AAGUID
    credentialId.length >> 8,
    credentialId.length & 0xFF,
    ...credentialId,
    ...cose,
  ]);
  return TomSecretsPasskeyRegistration(
    passkey: TomSecretsPasskey(
      relyingParty: rpId,
      credentialId: _b64url(credentialId),
      privateKeyPem: pem,
      userHandle: _b64url(userHandle),
      userName: userName,
    ),
    credentialId: credentialId,
    authenticatorData: authenticatorData,
    attestationObject: _cbor({
      'fmt': 'none',
      'attStmt': <Object, Object>{},
      'authData': authenticatorData,
    }),
    publicKeySpki: spki,
    algorithm: algorithm,
  );
}

/// Signs in with [passkey]: the authenticator data for its relying party
/// and the signature over it and [clientDataHash] (SHA-256 of the client
/// data). Throws [TomSecretsPasskeyException] for a key it cannot read.
Future<TomSecretsPasskeyAssertion> tomSecretsPasskeyAssertion(
  TomSecretsPasskey passkey,
  List<int> clientDataHash,
) async {
  if (clientDataHash.length != 32) {
    throw const TomSecretsWebAuthnException('the client data hash is 32 bytes');
  }
  final key = tomSecretsPasskeyKeyOf(passkey.privateKeyPem);
  final authenticatorData = Uint8List.fromList([
    ...tomSecretsRpIdHash(passkey.relyingParty),
    tomSecretsPasskeyFlags,
    0,
    0,
    0,
    0,
  ]);
  final signed = Uint8List.fromList([...authenticatorData, ...clientDataHash]);
  final Uint8List signature;
  switch (key.algorithm) {
    case TomSecretsPasskeyAlgorithm.es256:
      final params = pc.ECDomainParameters('prime256v1');
      final signer =
          pc.ECDSASigner(pc.SHA256Digest(), pc.HMac(pc.SHA256Digest(), 64))
            ..init(
              true,
              pc.PrivateKeyParameter<pc.ECPrivateKey>(
                pc.ECPrivateKey(_bigInt(key.secret), params),
              ),
            );
      var sig = signer.generateSignature(signed) as pc.ECSignature;
      // Low S, as most verifiers prefer.
      if (sig.s > params.n >> 1) sig = pc.ECSignature(sig.r, params.n - sig.s);
      signature = _derSignature(sig.r, sig.s);
    case TomSecretsPasskeyAlgorithm.edDsa:
      final pair = await cg.Ed25519().newKeyPairFromSeed(key.secret);
      signature = Uint8List.fromList(
        (await cg.Ed25519().sign(signed, keyPair: pair)).bytes,
      );
  }
  return TomSecretsPasskeyAssertion(
    credentialId: tomSecretsDecodeBase64(passkey.credentialId),
    authenticatorData: authenticatorData,
    signature: signature,
    userHandle: passkey.userHandle == null
        ? null
        : tomSecretsDecodeBase64(passkey.userHandle!),
  );
}

/// SHA-256 of [rpId], the first 32 bytes of the authenticator data.
Uint8List tomSecretsRpIdHash(String rpId) =>
    Uint8List.fromList(crypto.sha256.convert(utf8.encode(rpId)).bytes);

/// The client data a provider builds for an app (no browser gave its
/// hash): [type] `webauthn.create` or `webauthn.get`, the request's
/// [challenge] (base64url), the caller's [origin] (an app's
/// `android:apk-key-hash:<base64url SHA-256 of its signing certificate>`),
/// and the app's [packageName] when it is one.
Uint8List tomSecretsPasskeyClientDataJson({
  required String type,
  required String challenge,
  required String origin,
  String? packageName,
}) => Uint8List.fromList(
  utf8.encode(
    jsonEncode({
      'type': type,
      'challenge': challenge,
      'origin': origin,
      'crossOrigin': false,
      'androidPackageName': ?packageName,
    }),
  ),
);

/// The registration's `PublicKeyCredential` JSON (WebAuthn's
/// `RegistrationResponseJSON`, as Credential Manager returns it), with the
/// [clientDataJson] the provider built, or a placeholder when the browser
/// gave the hash (it puts its own in).
String tomSecretsPasskeyRegistrationJson(
  TomSecretsPasskeyRegistration registration, {
  Uint8List? clientDataJson,
}) {
  final id = _b64url(registration.credentialId);
  return jsonEncode({
    'id': id,
    'rawId': id,
    'type': 'public-key',
    'authenticatorAttachment': 'platform',
    'response': {
      'clientDataJSON': _b64url(clientDataJson ?? _placeholder),
      'attestationObject': _b64url(registration.attestationObject),
      'authenticatorData': _b64url(registration.authenticatorData),
      'publicKey': _b64url(registration.publicKeySpki),
      'publicKeyAlgorithm': registration.algorithm.cose,
      'transports': ['internal', 'hybrid'],
    },
    'clientExtensionResults': <String, Object?>{},
  });
}

/// The assertion's `PublicKeyCredential` JSON (WebAuthn's
/// `AuthenticationResponseJSON`), with the [clientDataJson] as for
/// [tomSecretsPasskeyRegistrationJson].
String tomSecretsPasskeyAssertionJson(
  TomSecretsPasskeyAssertion assertion, {
  Uint8List? clientDataJson,
}) {
  final id = _b64url(assertion.credentialId);
  return jsonEncode({
    'id': id,
    'rawId': id,
    'type': 'public-key',
    'authenticatorAttachment': 'platform',
    'response': {
      'clientDataJSON': _b64url(clientDataJson ?? _placeholder),
      'authenticatorData': _b64url(assertion.authenticatorData),
      'signature': _b64url(assertion.signature),
      if (assertion.userHandle != null)
        'userHandle': _b64url(assertion.userHandle!),
    },
    'clientExtensionResults': <String, Object?>{},
  });
}

/// What a browser's client data stands in for: it replaces it.
final Uint8List _placeholder = Uint8List.fromList(utf8.encode('{}'));

String _b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

BigInt _bigInt(List<int> bytes) {
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  return v;
}

Uint8List _bytes32(BigInt v) {
  final out = Uint8List(32);
  var x = v;
  for (var i = 31; i >= 0; i--) {
    out[i] = (x & BigInt.from(0xFF)).toInt();
    x >>= 8;
  }
  return out;
}

/// An ECDSA signature as DER (`SEQUENCE { INTEGER r, INTEGER s }`).
Uint8List _derSignature(BigInt r, BigInt s) {
  List<int> integer(BigInt v) {
    var bytes = _bytes32(v).toList();
    while (bytes.length > 1 && bytes.first == 0 && bytes[1] < 0x80) {
      bytes = bytes.sublist(1);
    }
    if (bytes.first >= 0x80) bytes = [0, ...bytes];
    return [0x02, bytes.length, ...bytes];
  }

  final body = [...integer(r), ...integer(s)];
  return Uint8List.fromList([0x30, body.length, ...body]);
}

/// A SubjectPublicKeyInfo of the algorithm [oid] ([curve] for EC) and the
/// public key [key].
Uint8List _spki(List<int> oid, List<int>? curve, List<int> key) {
  List<int> tlv(int tag, List<int> content) => [
    tag,
    if (content.length < 0x80) content.length else ...[0x81, content.length],
    ...content,
  ];
  final algorithm = tlv(0x30, [
    ...tlv(0x06, oid),
    if (curve != null) ...tlv(0x06, curve),
  ]);
  return Uint8List.fromList(
    tlv(0x30, [
      ...algorithm,
      ...tlv(0x03, [0, ...key]),
    ]),
  );
}

/// [value] as CBOR (RFC 8949): integers, byte and text strings, lists and
/// maps (the keys in the order given, which callers make CTAP2's
/// canonical order).
Uint8List _cbor(Object value) {
  final out = BytesBuilder();
  void head(int major, int n) {
    if (n < 24) {
      out.addByte(major << 5 | n);
    } else if (n < 0x100) {
      out
        ..addByte(major << 5 | 24)
        ..addByte(n);
    } else if (n < 0x10000) {
      out
        ..addByte(major << 5 | 25)
        ..addByte(n >> 8)
        ..addByte(n & 0xFF);
    } else {
      out
        ..addByte(major << 5 | 26)
        ..add([n >> 24 & 0xFF, n >> 16 & 0xFF, n >> 8 & 0xFF, n & 0xFF]);
    }
  }

  void write(Object v) {
    switch (v) {
      case int i when i >= 0:
        head(0, i);
      case int i:
        head(1, -1 - i);
      case Uint8List b:
        head(2, b.length);
        out.add(b);
      case String s:
        final b = utf8.encode(s);
        head(3, b.length);
        out.add(b);
      case List<Object> l:
        head(4, l.length);
        l.forEach(write);
      case Map<Object, Object> m:
        head(5, m.length);
        for (final MapEntry(:key, :value) in m.entries) {
          write(key);
          write(value);
        }
      default:
        throw ArgumentError.value(v, 'value', 'not encodable as CBOR here');
    }
  }

  write(value);
  return out.takeBytes();
}
