// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The typed certificate and PGP key entries (part-structure, BP-33,
// DP-179): generated (ECDSA P-384, RSA 4096 where a tool needs RSA), read
// (validity, key length, fingerprint, expiry), written into an entry
// (attachments, Expires from notAfter / the key's expiry), the field
// `getFile` serves for them, and the health report flagging short keys
// without refusing them. Demo keys only; the generated certificates were
// checked once with OpenSSL 4.1 (x509, verify, req -verify, ec -check).
//
// GnuPG (checked with GnuPG 2.5.24): a generated ECDSA P-384 and RSA 4096
// key import into GnuPG with their passphrase and sign, verify, encrypt to
// the subkey and decrypt there, and `dart_pg` verifies and decrypts what
// GnuPG made; fingerprints, key ids and expiry match `gpg --with-colons`.
// GnuPG-made Ed25519/Curve25519 and RSA 3072 keys read with GnuPG's
// fingerprint, user ids and expiry. That check found, and pgp_key.dart
// corrects, three dart_pg 2.1 behaviours: RSA primes written p > q (GnuPG:
// "Bad secret key"), the expiry counted from the signature instead of the
// key's creation, and a GnuPG Ed25519 key with a short signature `r`
// refused as unreadable. A key dart_pg's decoder refuses (a GnuPG RSA 1024
// key, a v3 key) is read by the package's own minimal reader (pgp_raw.dart)
// with GnuPG's values and flagged short. The live round trip below runs
// where `gpg` is on the PATH and is skipped elsewhere.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:dart_pg/dart_pg.dart' as pg;
// ignore: implementation_imports
import 'package:dart_pg/src/packet/key/rsa_secret_material.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_core/src/pgp_raw.dart';
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

  group('GnuPG', () {
    String fixture(String name) =>
        File('test/fixtures/gnupg/$name').readAsStringSync();

    test('a GnuPG Ed25519 key whose signature has a short r reads as gpg '
        'shows it; its public key derived from the secret key', () {
      final info = TomSecretsPgpKeyInfo.parse(fixture('gpg_ed25519.pub.asc'));
      // gpg --with-colons: pub:...:255:22:6A9FD15517BFB0DB:1795180265:1826716265
      expect(info.fingerprint, '678D6914C2EB75E748B8CFDB6A9FD15517BFB0DB');
      expect(info.keyId, '6A9FD15517BFB0DB');
      expect(info.userIds, ['Gpg Ed <gpg-ed@example.com>']);
      expect(info.keyDescription, 'Ed25519');
      expect(info.shortness, isNull, reason: "Curve25519's 255 bits");
      expect(info.created, DateTime.utc(2026, 11, 20, 13, 11, 5));
      expect(info.expires, DateTime.utc(2027, 11, 20, 13, 11, 5));

      final file = newTestVault(demoCredentials, 'vault');
      final e = _entry(file, 'Gpg Ed');
      final written = tomSecretsWritePgpKey(
        e,
        privateArmored: fixture('gpg_ed25519.priv.asc'),
        passphrase: 'demo-gpg-pass',
      )!;
      expect(written.isPrivate, isTrue);
      expect(written.fingerprint, info.fingerprint);
      expect(e.times.expiryTime.get(), info.expires);
      final public = utf8.decode(
        e.getBinary(const KdbxKey(tomSecretsPgpPublicAttachment))!.value,
      );
      expect(public, contains('PUBLIC KEY BLOCK'));
      expect(TomSecretsPgpKeyInfo.parse(public).fingerprint, info.fingerprint);
    });

    test('a GnuPG RSA 3072 key with two user ids and none primary: the '
        'expiry from the latest self-signature, counted from creation', () {
      final info = TomSecretsPgpKeyInfo.parse(fixture('gpg_rsa3072.pub.asc'));
      // gpg --with-colons: pub:...:3072:1:1BA7C1EDDABA2F3E:1795180266:1858252266
      expect(info.fingerprint, '2783F0B103F4CBE01DA9EA281BA7C1EDDABA2F3E');
      expect(info.userIds, [
        'Gpg Rsa Second <gpg-rsa2@example.com>',
        'Gpg Rsa <gpg-rsa@example.com>',
      ]);
      expect(info.bits, 3072);
      expect(info.shortness, isNull);
      expect(info.expires, DateTime.utc(2028, 11, 19, 13, 11, 6));
    });

    test('a generated RSA key holds its primes as p < q, as libgcrypt '
        'requires, and still opens with its passphrase only', () {
      final k = tomSecretsGeneratePgpKey(
        userId: 'Demo <demo@example.com>',
        algorithm: TomSecretsPgpKeyAlgorithm.rsa,
      );
      expect(k.info.bits, 4096);
      final key = pg.OpenPGP.decryptPrivateKey(k.privateArmored, k.passphrase);
      final materials = [
        key.secretKeyPacket.secretKeyMaterial,
        for (final s in key.subkeys) (s.keyPacket as dynamic).secretKeyMaterial,
      ].cast<RSASecretMaterial>();
      expect(materials, hasLength(2));
      for (final m in materials) {
        expect(m.primeP < m.primeQ, isTrue);
        expect((m.primeP * m.coefficient) % m.primeQ, BigInt.one);
        expect(m.isValid, isTrue);
      }
      expect(
        () => pg.OpenPGP.decryptPrivateKey(k.privateArmored, 'wrong'),
        throwsA(anything),
      );
      expect(
        TomSecretsPgpKeyInfo.parse(k.publicArmored).fingerprint,
        k.info.fingerprint,
      );
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('a GnuPG RSA 1024 key dart_pg refuses reads with GnuPG\'s values '
        'and is flagged short by the health report', () {
      expect(
        () => pg.OpenPGP.readPublicKey(fixture('gpg_rsa1024.pub.asc')),
        throwsA(anything),
        reason: 'the fallback is what reads it',
      );
      final info = TomSecretsPgpKeyInfo.parse(fixture('gpg_rsa1024.pub.asc'));
      // gpg --with-colons: pub:u:1024:1:4513D8293B331721:1795182590:1826718590
      expect(info.fingerprint, '40EA17C83EEE73742F07F5F44513D8293B331721');
      expect(info.keyId, '4513D8293B331721');
      expect(info.userIds, [
        'Old Rsa <old-rsa@example.com>',
        'Old Rsa Second <old-rsa2@example.com>',
      ], reason: 'the older user id was set primary');
      expect(info.algorithm, 'rsaEncryptSign');
      expect(info.bits, 1024);
      expect(info.version, 4);
      expect(info.isPrivate, isFalse);
      expect(info.keyDescription, 'RSA 1024');
      expect(info.shortness, 'RSA 1024 bits: below 3072');
      expect(info.created, DateTime.utc(2026, 11, 20, 13, 49, 50));
      expect(info.expires, DateTime.utc(2027, 11, 20, 13, 49, 50));

      final file = newTestVault(demoCredentials, 'vault');
      final e = _entry(file, 'Old');
      final written = tomSecretsWritePgpKey(
        e,
        privateArmored: fixture('gpg_rsa1024.priv.asc'),
        passphrase: 'demo-gpg-pass',
      )!;
      expect(written.isPrivate, isTrue);
      expect(written.fingerprint, info.fingerprint);
      expect(e.times.expires.get(), isTrue);
      expect(e.times.expiryTime.get(), info.expires);
      // The public key derived from the secret key is GnuPG's export.
      final public = utf8.decode(
        e.getBinary(const KdbxKey(tomSecretsPgpPublicAttachment))!.value,
      );
      List<(int, String)> packets(String armored) => [
        for (final p in pgpReadPackets(_dearmor(armored)))
          (p.tag, base64.encode(p.body)),
      ];
      expect(packets(public), packets(fixture('gpg_rsa1024.pub.asc')));
      expect(tomSecretsPgpKeyOf(e)!.isPrivate, isTrue);

      final report = tomSecretsHealthReport([
        TomSecretsHealthEntry('vault', e),
      ], now: DateTime.utc(2026, 11, 21));
      final short = report.of(TomSecretsHealthIssue.shortKey).single;
      expect(short.entry.label, 'Old');
      expect(short.detail, 'RSA 1024 bits: below 3072');
    });

    test('a v3 RSA key (old-format framing) reads: its MD5 fingerprint, the '
        'key id from the modulus, the expiry from its validity days', () {
      final n = Uint8List.fromList([
        0xC1,
        for (var i = 1; i < 128; i++) (i * 37 + 11) & 0xff,
      ]);
      final e = Uint8List.fromList([0x01, 0x00, 0x01]);
      final created = DateTime.utc(1999, 1, 2, 3, 4, 5);
      final t = created.millisecondsSinceEpoch ~/ 1000;
      final key = [
        3,
        t >> 24 & 0xff, t >> 16 & 0xff, t >> 8 & 0xff, t & 0xff,
        0, 10, // valid for 10 days
        1, // RSA
        (1024 >> 8), 1024 & 0xff, ...n,
        0, 17, ...e,
      ];
      final uid = utf8.encode('Pgp Two <two@example.com>');
      final block = Uint8List.fromList([
        0x99, key.length >> 8, key.length & 0xff, ...key, // old format, tag 6
        0xB4, uid.length, ...uid, // old format, tag 13
      ]);
      final armored =
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n'
          '${base64.encode(block)}\n'
          '=${base64.encode(_crc24(block))}\n'
          '-----END PGP PUBLIC KEY BLOCK-----\n';
      final info = TomSecretsPgpKeyInfo.parse(armored);
      expect(info.version, 3);
      expect(info.keyId, _hexOf(n.sublist(n.length - 8)));
      expect(
        info.fingerprint,
        crypto.md5.convert([...n, ...e]).toString().toUpperCase(),
      );
      expect(info.bits, 1024);
      expect(info.userIds, ['Pgp Two <two@example.com>']);
      expect(info.created, created);
      expect(info.expires, created.add(const Duration(days: 10)));
      expect(info.shortness, 'RSA 1024 bits: below 3072');
    });

    test('the packet reader takes partial lengths and five-octet lengths', () {
      final body = utf8.encode('Partial <partial@example.com>!!!');
      expect(body, hasLength(32));
      final framed = Uint8List.fromList([
        0xC0 | 13,
        0xE0 | 3, ...body.sublist(0, 8), // a partial chunk of 8 octets
        0xE0 | 4, ...body.sublist(8, 24), // one of 16
        8, ...body.sublist(24), // the last 8
        0xC0 | 13,
        255, 0, 0, 0, 4, ...utf8.encode('five'),
      ]);
      final packets = pgpReadPackets(framed);
      expect(packets.map((p) => p.tag), [13, 13]);
      expect(utf8.decode(packets[0].body), utf8.decode(body));
      expect(utf8.decode(packets[1].body), 'five');
      expect(pgpReadPackets(pgpWritePackets(packets)).map((p) => p.body), [
        body,
        utf8.encode('five'),
      ]);
      expect(
        () => pgpReadPackets(Uint8List.fromList([0xC0 | 13, 20, 1, 2])),
        throwsFormatException,
      );
    });

    final gpg = _gpg();
    test(
      'live: generated keys sign, verify, encrypt and decrypt in GnuPG',
      () async {
        final home = Directory.systemTemp.createTempSync('tsmgpg');
        addTearDown(() {
          Process.runSync('${File(gpg!).parent.path}/gpgconf', [
            '--homedir',
            home.path,
            '--kill',
            'all',
          ]);
          home.deleteSync(recursive: true);
        });
        ProcessResult run(List<String> args) => Process.runSync(gpg!, [
          '--homedir',
          home.path,
          '--batch',
          '--pinentry-mode',
          'loopback',
          '--trust-model',
          'always',
          ...args,
        ]);
        File('${home.path}/msg.txt').writeAsStringSync('demo message');
        for (final algorithm in TomSecretsPgpKeyAlgorithm.values) {
          final k = tomSecretsGeneratePgpKey(
            userId: 'Demo ${algorithm.name} <${algorithm.name}@example.com>',
            algorithm: algorithm,
            expiresAfter: const Duration(days: 30),
          );
          final p = '${home.path}/${algorithm.name}';
          File('$p.asc').writeAsStringSync(k.privateArmored);
          File('$p.pass').writeAsStringSync(k.passphrase);
          var r = run(['--passphrase-file', '$p.pass', '--import', '$p.asc']);
          expect(r.stderr, contains('secret key imported'));
          r = run(['--with-colons', '--list-keys', k.info.fingerprint]);
          final pub = (r.stdout as String)
              .split('\n')
              .firstWhere((l) => l.startsWith('pub:'))
              .split(':');
          expect(pub[4], k.info.keyId);
          expect(
            int.parse(pub[6]),
            k.info.expires!.millisecondsSinceEpoch ~/ 1000,
          );
          r = run([
            '--passphrase-file',
            '$p.pass',
            '-u',
            k.info.fingerprint,
            '--detach-sign',
            '-o',
            '$p.sig',
            '${home.path}/msg.txt',
          ]);
          expect(r.exitCode, 0, reason: '${r.stderr}');
          r = run(['--verify', '$p.sig', '${home.path}/msg.txt']);
          expect(r.stderr, contains('Good signature'));
          r = run([
            '-r',
            k.info.fingerprint,
            '-o',
            '$p.enc',
            '--encrypt',
            '${home.path}/msg.txt',
          ]);
          expect(r.exitCode, 0, reason: '${r.stderr}');
          r = run(['--passphrase-file', '$p.pass', '-d', '$p.enc']);
          expect(r.stdout, 'demo message', reason: '${r.stderr}');
        }
      },
      skip: gpg == null ? 'gpg is not on the PATH' : false,
      timeout: const Timeout(Duration(minutes: 3)),
    );
  });
}

/// The `gpg` executable on the PATH, or null.
String? _gpg() {
  try {
    final r = Process.runSync('gpg', ['--version']);
    if (r.exitCode != 0) return null;
    final which = Process.runSync(Platform.isWindows ? 'where' : 'which', [
      'gpg',
    ]);
    return (which.stdout as String).split('\n').first.trim();
  } on ProcessException {
    return null;
  }
}

Uint8List _dearmor(String armored) {
  final lines = armored.split('\n').map((l) => l.trim()).toList();
  final start = lines.indexOf('') + 1;
  final body = lines
      .sublist(start)
      .takeWhile((l) => !l.startsWith('=') && !l.startsWith('-----'))
      .join();
  return base64.decode(body);
}

String _hexOf(List<int> bytes) => [
  for (final b in bytes) b.toRadixString(16).padLeft(2, '0'),
].join().toUpperCase();

/// The armour checksum (RFC 4880 6.1).
List<int> _crc24(List<int> data) {
  var crc = 0xB704CE;
  for (final b in data) {
    crc ^= b << 16;
    for (var i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000 != 0) crc ^= 0x1864CFB;
    }
  }
  return [crc >> 16 & 0xff, crc >> 8 & 0xff, crc & 0xff];
}
