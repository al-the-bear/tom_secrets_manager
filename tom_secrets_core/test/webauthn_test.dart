// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The product as a WebAuthn authenticator (part-password-manager,
// part-os-integration): a passkey made with the site's algorithm, the
// authenticator data and the `none` attestation as a relying party reads
// them, assertions whose signatures verify with the registered public key
// (ES256 and Ed25519, an imported Enpass passkey too), the JSON Credential
// Manager returns, and the passkey kept in the site's login entry. Demo
// keys only.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

/// A minimal CBOR reader for the test: what the authenticator writes.
(Object, int) _cbor(Uint8List b, int at) {
  final major = b[at] >> 5;
  var info = b[at] & 0x1F;
  var i = at + 1;
  var n = info;
  if (info == 24) {
    n = b[i++];
  } else if (info == 25) {
    n = b[i] << 8 | b[i + 1];
    i += 2;
  } else if (info == 26) {
    n = b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3];
    i += 4;
  }
  switch (major) {
    case 0:
      return (n, i);
    case 1:
      return (-1 - n, i);
    case 2:
      return (Uint8List.sublistView(b, i, i + n), i + n);
    case 3:
      return (utf8.decode(b.sublist(i, i + n)), i + n);
    case 4:
      final list = <Object>[];
      for (var k = 0; k < n; k++) {
        final (v, next) = _cbor(b, i);
        list.add(v);
        i = next;
      }
      return (list, i);
    case 5:
      final map = <Object, Object>{};
      for (var k = 0; k < n; k++) {
        final (key, a) = _cbor(b, i);
        final (value, c) = _cbor(b, a);
        map[key] = value;
        i = c;
      }
      return (map, i);
  }
  throw StateError('major $major');
}

Object cbor(Uint8List b) {
  final (v, end) = _cbor(b, 0);
  expect(end, b.length, reason: 'nothing after the CBOR item');
  return v;
}

BigInt _big(List<int> bytes) =>
    bytes.fold(BigInt.zero, (v, b) => (v << 8) | BigInt.from(b));

/// Verifies an ES256 DER signature with the COSE key [cose].
bool verifyEs256(Map<Object, Object> cose, List<int> message, Uint8List der) {
  final params = pc.ECDomainParameters('prime256v1');
  final q = params.curve.createPoint(
    _big(cose[-2]! as Uint8List),
    _big(cose[-3]! as Uint8List),
  );
  // DER: SEQUENCE { INTEGER r, INTEGER s }.
  var i = 2;
  BigInt integer() {
    expect(der[i], 0x02);
    final n = der[i + 1];
    final v = _big(der.sublist(i + 2, i + 2 + n));
    i += 2 + n;
    return v;
  }

  final r = integer();
  final s = integer();
  final verifier = pc.ECDSASigner(pc.SHA256Digest())
    ..init(
      false,
      pc.PublicKeyParameter<pc.ECPublicKey>(pc.ECPublicKey(q, params)),
    );
  return verifier.verifySignature(
    Uint8List.fromList(message),
    pc.ECSignature(r, s),
  );
}

void main() {
  final userHandle = Uint8List.fromList(utf8.encode('demo-user-handle'));
  final clientDataHash = Uint8List.fromList(
    crypto.sha256.convert(utf8.encode('{"type":"webauthn.get"}')).bytes,
  );

  test('a new ES256 passkey: the authenticator data with its attested '
      'credential and COSE key, the none attestation, kept as KeePassXC '
      'keeps it', () async {
    final reg = await tomSecretsCreatePasskey(
      rpId: 'demo.example',
      userHandle: userHandle,
      userName: 'alice',
      algorithms: [-8, -7],
      random: Random(1),
    );
    // The site's order: Ed25519 offered first is taken.
    expect(reg.algorithm, TomSecretsPasskeyAlgorithm.edDsa);
    final es = await tomSecretsCreatePasskey(
      rpId: 'demo.example',
      userHandle: userHandle,
      userName: 'alice',
      algorithms: [-257, -7],
    );
    expect(es.algorithm, TomSecretsPasskeyAlgorithm.es256);
    final a = es.authenticatorData;
    expect(a.sublist(0, 32), tomSecretsRpIdHash('demo.example'));
    expect(a[32], 0x5D); // UP, UV, BE, BS, AT
    expect(a.sublist(33, 37), [0, 0, 0, 0]);
    expect(a.sublist(37, 53), List.filled(16, 0));
    final idLength = a[53] << 8 | a[54];
    expect(idLength, 32);
    expect(a.sublist(55, 55 + idLength), es.credentialId);
    final cose = cbor(Uint8List.sublistView(a, 55 + idLength)) as Map;
    expect(cose[1], 2);
    expect(cose[3], -7);
    expect(cose[-1], 1);
    expect((cose[-2] as Uint8List).length, 32);
    final att = cbor(es.attestationObject) as Map;
    expect(att.keys.toList(), ['fmt', 'attStmt', 'authData']);
    expect(att['fmt'], 'none');
    expect(att['attStmt'], isEmpty);
    expect(att['authData'], a);
    // As KeePassXC keeps it: base64url without padding, PKCS#8 PEM.
    expect(es.passkey.credentialId, isNot(contains('=')));
    expect(tomSecretsDecodeBase64(es.passkey.credentialId), es.credentialId);
    expect(tomSecretsDecodeBase64(es.passkey.userHandle!), userHandle);
    expect(es.passkey.privateKeyPem, startsWith('-----BEGIN PRIVATE KEY-----'));
    expect(
      tomSecretsPasskeyKeyOf(es.passkey.privateKeyPem).algorithm,
      TomSecretsPasskeyAlgorithm.es256,
    );
    // The SPKI holds the same point as the COSE key.
    expect(es.publicKeySpki.sublist(es.publicKeySpki.length - 64), [
      ...cose[-2] as Uint8List,
      ...cose[-3] as Uint8List,
    ]);
  });

  test('an ES256 assertion verifies with the registered key; low S; a '
      'wrong hash does not', () async {
    final reg = await tomSecretsCreatePasskey(
      rpId: 'demo.example',
      userHandle: userHandle,
    );
    final cose =
        cbor(
              Uint8List.sublistView(
                reg.authenticatorData,
                55 + reg.credentialId.length,
              ),
            )
            as Map<Object, Object>;
    final assertion = await tomSecretsPasskeyAssertion(
      reg.passkey,
      clientDataHash,
    );
    expect(assertion.credentialId, reg.credentialId);
    expect(assertion.userHandle, userHandle);
    expect(assertion.authenticatorData.length, 37);
    expect(assertion.authenticatorData[32], 0x1D); // UP, UV, BE, BS
    expect(
      verifyEs256(cose, [
        ...assertion.authenticatorData,
        ...clientDataHash,
      ], assertion.signature),
      isTrue,
    );
    expect(
      verifyEs256(cose, [
        ...assertion.authenticatorData,
        ...List.filled(32, 0),
      ], assertion.signature),
      isFalse,
    );
    await expectLater(
      tomSecretsPasskeyAssertion(reg.passkey, [1, 2, 3]),
      throwsA(isA<TomSecretsWebAuthnException>()),
    );
  });

  test(
    'an Ed25519 passkey: COSE OKP key, an assertion that verifies',
    () async {
      final reg = await tomSecretsCreatePasskey(
        rpId: 'demo.example',
        userHandle: userHandle,
        algorithms: [-8],
      );
      final cose =
          cbor(
                Uint8List.sublistView(
                  reg.authenticatorData,
                  55 + reg.credentialId.length,
                ),
              )
              as Map;
      expect(cose[1], 1);
      expect(cose[3], -8);
      expect(cose[-1], 6);
      final assertion = await tomSecretsPasskeyAssertion(
        reg.passkey,
        clientDataHash,
      );
      expect(assertion.signature.length, 64);
      final ok = await cg.Ed25519().verify(
        [...assertion.authenticatorData, ...clientDataHash],
        signature: cg.Signature(
          assertion.signature,
          publicKey: cg.SimplePublicKey(
            cose[-2] as Uint8List,
            type: cg.KeyPairType.ed25519,
          ),
        ),
      );
      expect(ok, isTrue);
    },
  );

  test('a site that offers neither ES256 nor Ed25519 is refused', () async {
    await expectLater(
      tomSecretsCreatePasskey(
        rpId: 'demo.example',
        userHandle: userHandle,
        algorithms: [-257],
      ),
      throwsA(
        isA<TomSecretsWebAuthnException>().having(
          (e) => e.message,
          'message',
          contains('-257'),
        ),
      ),
    );
  });

  test('an imported passkey (a JWK as Enpass may hold it) signs too', () async {
    final params = pc.ECDomainParameters('prime256v1');
    final d = Uint8List.fromList(List.generate(32, (i) => i + 1));
    final q = params.G * _big(d);
    final passkey = TomSecretsPasskey(
      relyingParty: 'demo.example',
      credentialId: 'ZGVtby1jcmVk',
      privateKeyPem: tomSecretsPasskeyPem({
        'kty': 'EC',
        'crv': 'P-256',
        'd': base64Url.encode(d),
      }),
    );
    final assertion = await tomSecretsPasskeyAssertion(passkey, clientDataHash);
    List<int> b32(BigInt v) => List.generate(
      32,
      (i) => ((v >> (8 * (31 - i))) & BigInt.from(0xFF)).toInt(),
    );
    expect(
      verifyEs256(
        {
          -2: Uint8List.fromList(b32(q!.x!.toBigInteger()!)),
          -3: Uint8List.fromList(b32(q.y!.toBigInteger()!)),
        },
        [...assertion.authenticatorData, ...clientDataHash],
        assertion.signature,
      ),
      isTrue,
    );
    expect(assertion.userHandle, isNull);
  });

  test('the JSON Credential Manager returns, with the client data the '
      'provider built', () async {
    final reg = await tomSecretsCreatePasskey(
      rpId: 'demo.example',
      userHandle: userHandle,
    );
    final clientData = tomSecretsPasskeyClientDataJson(
      type: 'webauthn.create',
      challenge: 'Y2hhbGxlbmdl',
      origin: 'android:apk-key-hash:AAAA',
      packageName: 'com.example.app',
    );
    expect(jsonDecode(utf8.decode(clientData)), {
      'type': 'webauthn.create',
      'challenge': 'Y2hhbGxlbmdl',
      'origin': 'android:apk-key-hash:AAAA',
      'crossOrigin': false,
      'androidPackageName': 'com.example.app',
    });
    final json =
        jsonDecode(
              tomSecretsPasskeyRegistrationJson(
                reg,
                clientDataJson: clientData,
              ),
            )
            as Map;
    expect(json['id'], reg.passkey.credentialId);
    expect(json['rawId'], json['id']);
    expect(json['type'], 'public-key');
    final response = json['response'] as Map;
    expect(
      tomSecretsDecodeBase64(response['clientDataJSON'] as String),
      clientData,
    );
    expect(
      tomSecretsDecodeBase64(response['attestationObject'] as String),
      reg.attestationObject,
    );
    expect(response['publicKeyAlgorithm'], -7);
    final assertion = await tomSecretsPasskeyAssertion(
      reg.passkey,
      clientDataHash,
    );
    final get = jsonDecode(tomSecretsPasskeyAssertionJson(assertion)) as Map;
    expect((get['response'] as Map)['userHandle'], reg.passkey.userHandle);
    expect(
      tomSecretsDecodeBase64((get['response'] as Map)['signature'] as String),
      assertion.signature,
    );
  });

  test(
    'kept in the login entry of the site and user, else in a new one; '
    'the same user registering again replaces it; the passkeys listed',
    () async {
      final file = tomSecretsNewVault(
        Credentials(ProtectedValue.fromString('demo-pw')),
        'demo',
      );
      final login = KdbxEntry.create(file, file.body.rootGroup)
        ..setString(KdbxKeyCommon.TITLE, PlainValue('Demo site'))
        ..setString(
          KdbxKeyCommon.URL,
          PlainValue('https://www.demo.example/login'),
        )
        ..setString(KdbxKeyCommon.USER_NAME, PlainValue('alice'));
      file.body.rootGroup.addEntry(login);
      final reg = await tomSecretsCreatePasskey(
        rpId: 'demo.example',
        userHandle: userHandle,
        userName: 'alice',
      );
      expect(
        identical(tomSecretsKeepPasskey(file, reg.passkey), login),
        isTrue,
      );
      expect(
        TomSecretsPasskey.fromEntry(login)!.credentialId,
        reg.passkey.credentialId,
      );
      expect(
        login.getString(TomSecretsPasskeyFields.privateKeyPem),
        isA<ProtectedValue>(),
      );
      // Another user of the site: a new entry.
      final bob = await tomSecretsCreatePasskey(
        rpId: 'demo.example',
        userHandle: Uint8List.fromList([9, 9]),
        userName: 'bob',
      );
      final made = tomSecretsKeepPasskey(file, bob.passkey);
      expect(identical(made, login), isFalse);
      expect(made.getString(KdbxKeyCommon.TITLE)!.getText(), 'demo.example');
      expect(
        made.getString(KdbxKeyCommon.URL)!.getText(),
        'https://demo.example',
      );
      expect(made.getString(KdbxKeyCommon.USER_NAME)!.getText(), 'bob');
      // Alice registers again: her passkey replaced in place.
      final again = await tomSecretsCreatePasskey(
        rpId: 'demo.example',
        userHandle: userHandle,
        userName: 'alice',
      );
      expect(
        identical(tomSecretsKeepPasskey(file, again.passkey), login),
        isTrue,
      );
      final listed = tomSecretsPasskeysIn(file);
      expect(listed, hasLength(2));
      expect(listed.map((p) => p.passkey.credentialId).toSet(), {
        again.passkey.credentialId,
        bob.passkey.credentialId,
      });
    },
  );

  test('the vault a new passkey goes into', () async {
    KdbxFile vault(String name) => tomSecretsNewVault(
      Credentials(ProtectedValue.fromString('demo')),
      name,
    );

    final a = vault('a');
    final b = vault('b');
    final c = vault('c');
    final passkey = TomSecretsPasskey(
      relyingParty: 'site.example',
      credentialId: 'Y3JlZA',
      privateKeyPem: 'demo',
      userHandle: 'dXNlcg',
      userName: 'alice',
    );
    expect(tomSecretsPasskeyHome({}, passkey), isNull);
    expect(tomSecretsPasskeyHome({'a': a, 'b': b}, passkey), 'a');
    b.body.rootGroup.addEntry(
      KdbxEntry.create(b, b.body.rootGroup)..setString(
        KdbxKeyCommon.URL,
        PlainValue('https://login.site.example/'),
      ),
    );
    expect(tomSecretsPasskeyHome({'a': a, 'b': b}, passkey), 'b');
    tomSecretsKeepPasskey(c, passkey);
    expect(tomSecretsPasskeyHome({'a': a, 'b': b, 'c': c}, passkey), 'c');
  });

  test('which relying parties a page may use', () {
    expect(
      tomSecretsRpIdValidFor('https://login.example.com/x', 'example.com'),
      isTrue,
    );
    expect(
      tomSecretsRpIdValidFor('https://example.com', 'example.com'),
      isTrue,
    );
    expect(
      tomSecretsRpIdValidFor('https://example.com', 'login.example.com'),
      isFalse,
    );
    expect(
      tomSecretsRpIdValidFor('https://evil.example', 'example.com'),
      isFalse,
    );
    expect(
      tomSecretsRpIdValidFor('https://notexample.com', 'example.com'),
      isFalse,
    );
    expect(
      tomSecretsRpIdValidFor('http://example.com', 'example.com'),
      isFalse,
    );
    // A public suffix is no relying party.
    expect(tomSecretsRpIdValidFor('https://a.github.io', 'github.io'), isFalse);
    expect(
      tomSecretsRpIdValidFor('https://a.github.io', 'a.github.io'),
      isTrue,
    );
    expect(tomSecretsRpIdValidFor('https://example.co.uk', 'co.uk'), isFalse);
    expect(
      tomSecretsRpIdValidFor('http://localhost:8080', 'localhost'),
      isTrue,
    );
    expect(
      tomSecretsRpIdValidFor('https://192.168.1.2', '192.168.1.2'),
      isFalse,
    );
    expect(tomSecretsRpIdValidFor('not a url', 'example.com'), isFalse);
    expect(
      tomSecretsRpIdValidFor('https://Example.COM', 'example.com'),
      isTrue,
    );
  });
}
