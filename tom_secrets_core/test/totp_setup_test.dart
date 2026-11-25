// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Setting a TOTP up: KeePass's secret fields (UTF-8, hex, base32, base64)
/// read as KeePass 2.47 reads them, the setup text a user types or a QR code
/// holds (an otpauth:// URI, a base32 or hex secret, Google Authenticator's
/// otpauth-migration:// export), checked against RFC 6238's test vectors.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

/// RFC 6238 appendix B: the seeds and the codes at T = 59 s (8 digits).
const _seed1 = '12345678901234567890';
const _seed256 = '12345678901234567890123456789012';
const _seed512 =
    '1234567890123456789012345678901234567890123456789012345678901234';
final _t59 = DateTime.fromMillisecondsSinceEpoch(59 * 1000, isUtc: true);
final _t1111111109 = DateTime.fromMillisecondsSinceEpoch(
  1111111109 * 1000,
  isUtc: true,
);

String _hex(String ascii) => [
  for (final b in utf8.encode(ascii)) b.toRadixString(16).padLeft(2, '0'),
].join();

KdbxEntry _entry(Map<KdbxKey, String> strings) {
  final file = KdbxFormat().create(
    Credentials(ProtectedValue.fromString('demo-pw')),
    'demo',
    argon2: const KdbxArgon2(
      type: KdbxArgon2Type.argon2id,
      memory: 1 << 20,
      iterations: 1,
    ),
  );
  final entry = KdbxEntry.create(file, file.body.rootGroup);
  file.body.rootGroup.addEntry(entry);
  strings.forEach((k, v) => entry.setString(k, PlainValue(v)));
  return entry;
}

/// One protobuf field: varint (wire 0) or bytes (wire 2).
List<int> _pb(int field, Object value) {
  List<int> varint(int v) {
    final out = <int>[];
    while (v >= 0x80) {
      out.add((v & 0x7f) | 0x80);
      v >>= 7;
    }
    return [...out, v];
  }

  return switch (value) {
    final int v => [...varint(field << 3), ...varint(v)],
    final List<int> b => [...varint(field << 3 | 2), ...varint(b.length), ...b],
    _ => throw ArgumentError(value),
  };
}

String _migration(List<List<int>> accounts) {
  final payload = [for (final a in accounts) ..._pb(1, a)];
  final data = base64.encode(payload);
  return 'otpauth-migration://offline?data=${Uri.encodeQueryComponent(data)}';
}

List<int> _account({
  required List<int> secret,
  String name = 'demo@example.com',
  String issuer = 'Demo',
  int algorithm = 1,
  int digits = 1,
  int type = 2,
}) => [
  ..._pb(1, secret),
  ..._pb(2, utf8.encode(name)),
  ..._pb(3, utf8.encode(issuer)),
  ..._pb(4, algorithm),
  ..._pb(5, digits),
  ..._pb(6, type),
];

void main() {
  group('KeePass 2.47 secret fields give the RFC 6238 codes', () {
    for (final (algorithm, seed, at59) in [
      ('HMAC-SHA-1', _seed1, '94287082'),
      ('HMAC-SHA-256', _seed256, '46119246'),
      ('HMAC-SHA-512', _seed512, '90693936'),
    ]) {
      test('$algorithm: TimeOtp-Secret-Hex, TimeOtp-Secret (UTF-8), '
          '-Base32 and -Base64', () {
        final params = {
          TomSecretsTotpFields.length: '8',
          TomSecretsTotpFields.algorithm: algorithm,
        };
        for (final secret in [
          {TomSecretsTotpFields.secretHex: _hex(seed)},
          {TomSecretsTotpFields.secretText: seed},
          {
            TomSecretsTotpFields.secretBase32: tomSecretsBase32Encode(
              utf8.encode(seed),
            ),
          },
          {TomSecretsTotpFields.secretBase64: base64.encode(utf8.encode(seed))},
        ]) {
          final totp = TomSecretsTotp.fromEntry(_entry({...params, ...secret}));
          expect(totp, isNotNull, reason: secret.keys.single.key);
          expect(totp!.code(_t59), at59, reason: secret.keys.single.key);
        }
      });
    }

    test('the UTF-8 field is read first, as KeePass does', () {
      final totp = TomSecretsTotp.fromEntry(
        _entry({
          TomSecretsTotpFields.secretText: _seed1,
          TomSecretsTotpFields.secretHex: _hex('another secret'),
          TomSecretsTotpFields.length: '8',
        }),
      );
      expect(totp!.code(_t59), '94287082');
    });

    test('writeTo replaces KeePass\'s other secret fields', () {
      final entry = _entry({
        TomSecretsTotpFields.secretText: 'an old secret',
        TomSecretsTotpFields.secretHex: _hex('an old secret'),
        TomSecretsTotpFields.secretBase64: base64.encode(utf8.encode('old')),
      });
      TomSecretsTotp(
        Uint8List.fromList(utf8.encode(_seed1)),
        digits: 8,
      ).writeTo(entry);
      for (final key in [
        TomSecretsTotpFields.secretText,
        TomSecretsTotpFields.secretHex,
        TomSecretsTotpFields.secretBase64,
      ]) {
        expect(entry.getString(key), isNull, reason: key.key);
      }
      expect(TomSecretsTotp.fromEntry(entry)!.code(_t59), '94287082');
    });
  });

  group('the setup text', () {
    String code(String text) => TomSecretsTotp.parse(text)!.code(_t1111111109);

    // RFC 6238 at T = 1111111109 with the SHA-1 seed: 07081804, 6 digits
    // 081804.
    test('a hex secret, with or without hex:, any case and spaced', () {
      final hex = _hex(_seed1);
      expect(code(hex), '081804');
      expect(code('hex:$hex'), '081804');
      expect(code('HEX:${hex.toUpperCase()}'), '081804');
      expect(
        code(hex.replaceAllMapped(RegExp('.{4}'), (m) => '${m[0]} ')),
        '081804',
      );
    });

    test('base32 and the otpauth:// URI', () {
      final base32 = tomSecretsBase32Encode(utf8.encode(_seed1));
      expect(code(base32), '081804');
      expect(code(base32.toLowerCase()), '081804');
      expect(
        code('otpauth://totp/Demo:demo?secret=$base32&issuer=Demo'),
        '081804',
      );
    });

    test('a text both base32 and hex is base32; hex: makes it hex', () {
      const both = 'abcd2345';
      expect(TomSecretsTotp.parse(both)!.secret, tomSecretsBase32Decode(both));
      expect(TomSecretsTotp.parse('hex:$both')!.secret, [
        0xab,
        0xcd,
        0x23,
        0x45,
      ]);
    });

    test('what it refuses, and why', () {
      expect(TomSecretsTotp.parse('  '), isNull);
      for (final (text, says) in [
        ('not a secret!', 'neither an otpauth:// URI nor a base32 or hex'),
        ('hex:abc', 'not hex'),
        ('hex:zz', 'not hex'),
        ('otpauth://hotp/Demo?secret=GEZDGNBV&counter=1', 'HOTP'),
        ('otpauth-migration://offline?data=%%%', 'cannot read'),
      ]) {
        expect(
          () => TomSecretsTotp.parse(text),
          throwsA(
            isA<FormatException>().having(
              (e) => e.message,
              'message',
              contains(says),
            ),
          ),
          reason: text,
        );
      }
    });
  });

  group('Google Authenticator\'s otpauth-migration:// export', () {
    test('one TOTP account is read, with its issuer, name and digits', () {
      final text = _migration([
        _account(
          secret: utf8.encode(_seed1),
          name: 'Demo:demo@example.com',
          digits: 2,
        ),
      ]);
      final totp = TomSecretsTotp.parse(text)!;
      expect(totp.issuer, 'Demo');
      expect(totp.account, 'demo@example.com');
      expect(totp.digits, 8);
      expect(totp.code(_t59), '94287082');
    });

    test('SHA-256 and SHA-512 accounts', () {
      for (final (algorithm, seed, at59) in [
        (2, _seed256, '46119246'),
        (3, _seed512, '90693936'),
      ]) {
        final totp = TomSecretsTotp.parse(
          _migration([
            _account(
              secret: utf8.encode(seed),
              algorithm: algorithm,
              digits: 2,
            ),
          ]),
        )!;
        expect(totp.code(_t59), at59);
      }
    });

    test('several accounts or a HOTP one are named, not read', () {
      final two = _migration([
        _account(secret: utf8.encode(_seed1)),
        _account(secret: utf8.encode(_seed256), name: 'other'),
      ]);
      expect(TomSecretsTotpMigration.tryParse(two)!.totps, hasLength(2));
      expect(
        () => TomSecretsTotp.parse(two),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('2 accounts: export them one at a time'),
          ),
        ),
      );
      expect(
        () => TomSecretsTotp.parse(
          _migration([_account(secret: utf8.encode(_seed1), type: 1)]),
        ),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('counter-based (HOTP)'),
          ),
        ),
      );
    });

    test('not an export, or a payload it cannot read: null', () {
      expect(TomSecretsTotpMigration.tryParse('otpauth://totp/x'), isNull);
      expect(
        TomSecretsTotpMigration.tryParse(
          'otpauth-migration://offline?data=${base64.encode([0x0a, 0x7f])}',
        ),
        isNull,
        reason: 'a field longer than the payload',
      );
    });
  });
}
