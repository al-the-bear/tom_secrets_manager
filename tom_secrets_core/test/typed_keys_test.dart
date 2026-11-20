// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The typed certificate and PGP key entries (part-structure, BP-33,
// DP-179): generated (ECDSA P-384, RSA 4096 where a tool needs RSA), read
// (validity, key length, fingerprint, expiry), written into an entry
// (attachments, Expires from notAfter / the key's expiry), the field
// `getFile` serves for them, and the health report flagging short keys
// without refusing them. Demo keys only; the generated certificates were
// checked once with OpenSSL 4.1 (x509, verify, req -verify, ec -check).

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart' as pg;
import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

KdbxEntry _entry(KdbxFile file, String title) {
  final e = KdbxEntry.create(file, file.body.rootGroup)
    ..setString(KdbxKeyCommon.TITLE, PlainValue(title));
  file.body.rootGroup.addEntry(e);
  return e;
}

void main() {
  group('certificates', () {
    test('generated on ECDSA P-384: self-signed, a CSR, read back', () {
      final now = DateTime.utc(2026, 11, 20, 9);
      final c = tomSecretsGenerateCertificate(
        commonName: 'demo.example',
        subjectAlternativeNames: ['demo.example', 'www.demo.example'],
        days: 90,
        now: now,
      );
      expect(c.certificatePem, startsWith('-----BEGIN CERTIFICATE-----'));
      expect(c.privateKeyPem, contains('PRIVATE KEY-----'));
      expect(c.csrPem, contains('CERTIFICATE REQUEST'));
      final info = c.info;
      expect(info.subject, 'demo.example');
      expect(info.selfSigned, isTrue);
      expect(info.keyType, TomSecretsCertificateKeyType.ec);
      expect(info.keyBits, 384);
      expect(info.keyDescription, 'ECDSA P-384');
      expect(info.shortness, isNull);
      expect(info.notAfter, now.add(const Duration(days: 90)));
      expect(info.subjectAlternativeNames, contains('www.demo.example'));
      expect(info.hasPrivateKey, isTrue);
      expect(
        info.sha256Fingerprint,
        matches(r'^([0-9A-F]{2}:){31}[0-9A-F]{2}$'),
      );
    });

    test('RSA where a tool needs it; a short key flagged, kept', () {
      final c = tomSecretsGenerateCertificate(
        commonName: 'old.example',
        algorithm: TomSecretsCertificateAlgorithm.rsa,
        rsaBits: 2048,
      );
      expect(c.info.keyType, TomSecretsCertificateKeyType.rsa);
      expect(c.info.keyBits, 2048);
      expect(c.info.shortness, 'RSA 2048 bits: below 3072');
    });

    test('written into an entry: attachments, Expires from notAfter, the '
        'field getFile serves, the health report', () async {
      final file = newTestVault(demoCredentials, 'vault');
      final good = _entry(file, 'Web');
      final c = tomSecretsGenerateCertificate(commonName: 'web.example');
      final info = tomSecretsWriteCertificate(
        good,
        certificatePem: c.certificatePem,
        privateKeyPem: c.privateKeyPem,
      )!;
      expect(
        good.getString(TomSecretsEntryFields.type)?.getText(),
        'certificate',
      );
      expect(good.times.expires.get(), isTrue);
      expect(good.times.expiryTime.get(), info.notAfter);
      expect(
        good
            .getBinary(const KdbxKey(tomSecretsCertificateKeyAttachment))!
            .isProtected,
        isTrue,
      );
      expect(tomSecretsTypedFileField(good), 'attachment:private-key.pem');
      expect(tomSecretsCertificateOf(good)!.subject, 'web.example');

      final old = _entry(file, 'Old');
      final short = tomSecretsGenerateCertificate(
        commonName: 'old.example',
        algorithm: TomSecretsCertificateAlgorithm.rsa,
        rsaBits: 2048,
        days: 10,
      );
      tomSecretsWriteCertificate(
        old,
        certificatePem: short.certificatePem,
        privateKeyPem: short.privateKeyPem,
      );
      final report = tomSecretsHealthReport([
        for (final e in file.body.rootGroup.entries)
          TomSecretsHealthEntry('vault', e),
      ], now: DateTime.now().toUtc());
      final shortKeys = report.of(TomSecretsHealthIssue.shortKey);
      expect(shortKeys.map((f) => f.entry.label), ['Old']);
      expect(shortKeys.single.detail, 'RSA 2048 bits: below 3072');
      expect(
        report.of(TomSecretsHealthIssue.expiring).map((f) => f.entry.label),
        contains('Old'),
      );

      // A PKCS#12 bundle: stored and served, Expires set by hand.
      final bundle = _entry(file, 'Bundle');
      final p12 = Uint8List.fromList([0x30, 0x82, 0x01, 0x00, 1, 2, 3, 4]);
      expect(tomSecretsIsPkcs12(p12), isTrue);
      expect(tomSecretsIsPkcs12(utf8.encode(c.certificatePem)), isFalse);
      expect(
        tomSecretsWriteCertificate(bundle, pkcs12: p12, passphrase: 'demo'),
        isNull,
      );
      expect(tomSecretsTypedFileField(bundle), 'attachment:certificate.p12');
      expect(
        () => TomSecretsCertificateInfo.parse('no certificate'),
        throwsA(isA<TomSecretsCertificateException>()),
      );
    });
  });

  group('PGP keys', () {
    late TomSecretsGeneratedPgpKey key;
    setUpAll(() {
      key = tomSecretsGeneratePgpKey(
        userId: 'Demo <demo@example.com>',
        expiresAfter: const Duration(days: 365),
        now: DateTime.utc(2026, 11, 20, 9),
      );
    });

    test('generated on ECDSA P-384, locked, read back', () {
      final info = key.info;
      expect(info.isPrivate, isTrue);
      expect(info.algorithm, 'ecdsa');
      expect(info.bits, 384);
      expect(info.shortness, isNull);
      expect(info.userIds, ['Demo <demo@example.com>']);
      expect(info.fingerprint, matches(r'^[0-9A-F]{40}$'));
      expect(info.expires, DateTime.utc(2027, 11, 20, 9));
      expect(key.passphrase, hasLength(32));
      expect(key.publicArmored, contains('PUBLIC KEY BLOCK'));
      // The secret key opens with the passphrase only.
      expect(
        () => pg.OpenPGP.decryptPrivateKey(key.privateArmored, 'wrong'),
        throwsA(anything),
      );
      pg.OpenPGP.decryptPrivateKey(key.privateArmored, key.passphrase);
      final public = TomSecretsPgpKeyInfo.parse(key.publicArmored);
      expect(public.isPrivate, isFalse);
      expect(public.fingerprint, info.fingerprint);
    });

    test('written into an entry: attachments, the passphrase, Expires; a '
        'public key alone; the field getFile serves', () {
      final file = newTestVault(demoCredentials, 'vault');
      final mine = _entry(file, 'Mine');
      tomSecretsWritePgpKey(
        mine,
        privateArmored: key.privateArmored,
        passphrase: key.passphrase,
      );
      expect(mine.getString(TomSecretsEntryFields.type)?.getText(), 'pgp-key');
      expect(mine.getString(KdbxKeyCommon.PASSWORD)?.getText(), key.passphrase);
      expect(mine.times.expiryTime.get(), key.info.expires);
      // The public key was read from the secret key.
      expect(
        utf8.decode(
          mine.getBinary(const KdbxKey(tomSecretsPgpPublicAttachment))!.value,
        ),
        contains('PUBLIC KEY BLOCK'),
      );
      expect(tomSecretsPgpKeyOf(mine)!.isPrivate, isTrue);
      expect(tomSecretsTypedFileField(mine), 'attachment:private-key.asc');

      final theirs = _entry(file, 'Theirs');
      tomSecretsWritePgpKey(theirs, publicArmored: key.publicArmored);
      expect(tomSecretsPgpKeyOf(theirs)!.isPrivate, isFalse);
      expect(tomSecretsTypedFileField(theirs), 'attachment:public-key.asc');
      expect(
        () => TomSecretsPgpKeyInfo.parse('not a key'),
        throwsA(isA<TomSecretsPgpKeyException>()),
      );
    });

    test('a short RSA key is flagged by the health report, never refused', () {
      final short = pg.OpenPGP.generateKey(
        ['Old <old@example.com>'],
        'demo-pass',
        type: pg.KeyType.rsa,
      );
      final file = newTestVault(demoCredentials, 'vault');
      final e = _entry(file, 'Old');
      final info = tomSecretsWritePgpKey(
        e,
        publicArmored: short.publicKey.armor(),
      )!;
      expect(info.bits, 2048);
      expect(info.shortness, 'RSA 2048 bits: below 3072');
      final report = tomSecretsHealthReport([
        for (final e in file.body.rootGroup.entries)
          TomSecretsHealthEntry('vault', e),
      ], now: DateTime.now().toUtc());
      expect(
        report.of(TomSecretsHealthIssue.shortKey).map((f) => f.entry.label),
        ['Old'],
      );
    });
  });
}
