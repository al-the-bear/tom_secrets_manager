// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The shared configuration, the metadata entry, the KDBX mapping and TOTP.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

void main() {
  group('tsm.config', () {
    const full = '''
dimensions:
  - name: host
  - name: env
    default: dev
    fallback_to_default: true
  - name: region
stores:
  prod:
    - name: prod
      github: {repository: al-the-bear/vault, path: prod.kdbx}
  dev:
    - name: dev
      path: /srv/tsm/dev.kdbx
''';

    test('reads dimensions, defaults, the fallback and the stores', () {
      final c = TomSecretsConfig.parse(full);
      expect(c.dimensions.map((d) => d.name), [
        'platform',
        'host',
        'env',
        'region',
      ]);
      expect(c.dimension('env')!.defaultValue, 'dev');
      expect(c.dimension('env')!.fallbackToDefault, isTrue);
      expect(c.dimension('host')!.fallbackToDefault, isFalse);
      expect(c.dimension('region')!.isBuiltIn, isFalse);
      expect(c.dimension('nope'), isNull);
      final prod = c.stores['prod']!.single;
      expect(prod.name, 'prod');
      expect(
        prod.location,
        isA<TomSecretsGitHubLocation>()
            .having((l) => l.repository, 'repository', 'al-the-bear/vault')
            .having((l) => l.path, 'path', 'prod.kdbx'),
      );
      expect(
        c.stores['dev']!.single.location,
        isA<TomSecretsLocalLocation>().having(
          (l) => l.path,
          'path',
          '/srv/tsm/dev.kdbx',
        ),
      );
    });

    test('an absent fallback means off; no config is the built-ins', () {
      final c = TomSecretsConfig.builtIn();
      expect(c.dimensions.map((d) => d.name), ['host', 'platform', 'env']);
      expect(c.dimensions.every((d) => !d.fallbackToDefault), isTrue);
      expect(c.dimensions.every((d) => d.defaultValue == null), isTrue);
      expect(TomSecretsConfig.parse('').dimensions, hasLength(3));
    });

    test('toYaml reads back the same', () {
      final c = TomSecretsConfig.parse(full);
      final again = TomSecretsConfig.parse(c.toYaml());
      expect(again.toYaml(), c.toYaml());
      expect(
        again.dimensions.map((d) => d.name),
        c.dimensions.map((d) => d.name),
      );
      expect(again.dimension('env')!.fallbackToDefault, isTrue);
      expect(again.stores.keys, ['prod', 'dev']);
    });

    for (final (yaml, why) in [
      ('[1, 2]', 'not a mapping'),
      ('dimensions: 3', 'dimensions is not a list'),
      ('dimensions:\n  - default: x', 'a dimension without a name'),
      ('dimensions:\n  - name: Env', 'not a dimension name'),
      ('dimensions:\n  - name: env\n  - name: env', 'declared twice'),
      (
        'dimensions:\n  - name: env\n    fallback_to_default: yes please',
        'not true or false',
      ),
      ('dimensions:\n  - name: platform\n    default: amiga', 'not a platform'),
      ('stores:\n  prod:\n    - name: p', 'exactly one of path and github'),
      (
        'stores:\n  prod:\n    - name: p\n      path: a\n    - name: p\n      path: b',
        'twice',
      ),
      ('stores:\n  prod:\n    - name: P\n      path: a', 'not a store name'),
      ('a: [', 'not YAML'),
    ]) {
      test('refuses: $why', () {
        expect(
          () => TomSecretsConfig.parse(yaml),
          throwsA(
            isA<TomSecretsConfigException>().having(
              (e) => e.message,
              'message',
              contains(why),
            ),
          ),
        );
      });
    }
  });

  group('the metadata entry', () {
    test('a file without one: no binding, personal, no store name', () {
      final m = TomSecretsMetadata.read(DemoVault().file);
      expect(m.binding, isEmpty);
      expect(m.kind, TomSecretsVaultKind.personal);
      expect(m.store, isNull);
      expect(m.config, isNull);
    });

    test('written and read back, every field; it stays one entry', () async {
      final v = DemoVault();
      final m = TomSecretsMetadata(
        store: 'fleet',
        kind: TomSecretsVaultKind.system,
        purpose: 'The fleet\'s system secrets',
        binding: {'env': 'prod', 'region': 'eu'},
        configYaml: 'dimensions:\n  - name: region\n',
        keysDue: DateTime.utc(2028, 11, 13),
      )..writeTo(v.file);
      m.writeTo(v.file);
      final back = TomSecretsMetadata.read(
        await KdbxFormat().read(await v.file.save(), demoCredentials),
      );
      expect(back.store, 'fleet');
      expect(back.kind, TomSecretsVaultKind.system);
      expect(back.purpose, 'The fleet\'s system secrets');
      expect(back.binding, {'env': 'prod', 'region': 'eu'});
      expect(back.config!.dimension('region'), isNotNull);
      expect(back.format, 1);
      expect(back.keysDue, DateTime.utc(2028, 11, 13), reason: 'tsm.keys-due');
      expect(
        v.file.body.rootGroup.entries.where(
          (e) => e.label == tomSecretsMetadataTitle,
        ),
        hasLength(1),
      );
      final entry = tomSecretsMetadataEntry(v.file)!;
      expect(
        entry.getString(TomSecretsMetadataFields.dimensions)!.getText(),
        'env=prod;region=eu',
      );
    });

    test('file bindings: parsed, and refused when broken', () {
      expect(tomSecretsParseFileBinding(' env=prod ; region=eu ;'), {
        'env': 'prod',
        'region': 'eu',
      });
      expect(tomSecretsParseFileBinding(''), isEmpty);
      for (final bad in ['env', 'env=', '=prod', 'Env=prod', 'env=a;env=b']) {
        expect(
          () => tomSecretsParseFileBinding(bad),
          throwsA(isA<TomSecretsMetadataException>()),
          reason: bad,
        );
      }
    });

    test('a newer format, an unknown kind or a bad store name is refused', () {
      for (final (field, value) in [
        (TomSecretsMetadataFields.format, '2'),
        (TomSecretsMetadataFields.format, 'one'),
        (TomSecretsMetadataFields.kind, 'secret'),
        (TomSecretsMetadataFields.store, 'Bad Name'),
        (TomSecretsMetadataFields.keysDue, 'next year'),
      ]) {
        final v = DemoVault(store: 'fleet');
        tomSecretsMetadataEntry(v.file)!.setString(field, PlainValue(value));
        expect(
          () => TomSecretsMetadata.read(v.file),
          throwsA(isA<TomSecretsMetadataException>()),
          reason: '${field.key}=$value',
        );
      }
    });
  });

  group('the mapping', () {
    test('entry types: absent or unknown is login', () {
      expect(TomSecretsEntryType.of(null), TomSecretsEntryType.login);
      expect(TomSecretsEntryType.of('api-token'), TomSecretsEntryType.apiToken);
      expect(TomSecretsEntryType.of('ssh-key'), TomSecretsEntryType.sshKey);
      expect(TomSecretsEntryType.of('mystery'), TomSecretsEntryType.login);
    });

    test('reserved names, passkey fields, import ids', () {
      expect(tomSecretsIsReservedName('tsm.key'), isTrue);
      expect(tomSecretsIsReservedName('@host:x'), isTrue);
      expect(tomSecretsIsReservedName('Mail'), isFalse);
      expect(tomSecretsIsPasskeyField('KPEX_PASSKEY_USERNAME'), isTrue);
      expect(tomSecretsIsPasskeyField('Password'), isFalse);
      expect(
        TomSecretsEntryFields.importId('1password').key,
        'tsm.import.1password.id',
      );
    });

    test('uuid hex both ways, as the ~uuid reference writes it', () {
      final uuid = KdbxUuid.random();
      final hex = tomSecretsUuidHex(uuid);
      expect(hex, matches(RegExp(r'^[0-9a-f]{32}$')));
      expect(tomSecretsUuidFromHex(hex), uuid);
    });

    test('overlay group names', () {
      expect(tomSecretsOverlayBinding('@host:bomber'), ('host', 'bomber'));
      expect(tomSecretsOverlayBinding('@env:a:b'), ('env', 'a:b'));
      expect(tomSecretsOverlayBinding('@env:'), isNull);
      expect(tomSecretsOverlayBinding('@:x'), isNull);
      expect(tomSecretsOverlayBinding('@Env:x'), isNull);
      expect(tomSecretsOverlayBinding('env:x'), isNull);
    });
  });

  group('TOTP (RFC 6238, DP-38)', () {
    final sha1Secret = Uint8List.fromList(ascii.encode('12345678901234567890'));
    final sha256Secret = Uint8List.fromList(
      ascii.encode('12345678901234567890123456789012'),
    );
    final sha512Secret = Uint8List.fromList(
      ascii.encode(
        '1234567890123456789012345678901234567890123456789012345678901234',
      ),
    );
    // RFC 6238 Appendix B.
    for (final (seconds, codes) in [
      (59, ['94287082', '46119246', '90693936']),
      (1111111109, ['07081804', '68084774', '25091201']),
      (1234567890, ['89005924', '91819424', '93441116']),
      (20000000000, ['65353130', '77737706', '47863826']),
    ]) {
      test('RFC 6238 at T=$seconds', () {
        final at = DateTime.fromMillisecondsSinceEpoch(
          seconds * 1000,
          isUtc: true,
        );
        expect(TomSecretsTotp(sha1Secret, digits: 8).code(at), codes[0]);
        expect(
          TomSecretsTotp(
            sha256Secret,
            digits: 8,
            algorithm: TomSecretsTotpAlgorithm.sha256,
          ).code(at),
          codes[1],
        );
        expect(
          TomSecretsTotp(
            sha512Secret,
            digits: 8,
            algorithm: TomSecretsTotpAlgorithm.sha512,
          ).code(at),
          codes[2],
        );
      });
    }

    test('the three conventions are written together and each reads alone', () {
      final totp = TomSecretsTotp(
        sha256Secret,
        digits: 7,
        period: 60,
        algorithm: TomSecretsTotpAlgorithm.sha256,
        issuer: 'Demo',
        account: 'alice@example.org',
      );
      final at = DateTime.utc(2026, 11, 13, 9);
      for (final keep in [
        TomSecretsTotpFields.otp,
        TomSecretsTotpFields.otpAuth,
        TomSecretsTotpFields.secretBase32,
      ]) {
        final entry = DemoVault().add('X', password: 'x');
        totp.writeTo(entry);
        expect(
          entry.getString(TomSecretsTotpFields.otp),
          isA<ProtectedValue>(),
        );
        for (final drop in [
          TomSecretsTotpFields.otp,
          TomSecretsTotpFields.otpAuth,
          TomSecretsTotpFields.secretBase32,
        ]) {
          if (drop != keep) entry.removeString(drop);
        }
        final read = TomSecretsTotp.fromEntry(entry)!;
        expect(read.code(at), totp.code(at), reason: keep.key);
        expect(read.digits, 7);
        expect(read.period, 60);
      }
    });

    test('the read order is otp, OTPAuth, TimeOtp-*', () {
      final entry = DemoVault().add('X', password: 'x');
      final a = TomSecretsTotp(sha1Secret);
      final b = TomSecretsTotp(sha256Secret);
      a.writeTo(entry);
      entry.setString(TomSecretsTotpFields.otpAuth, PlainValue(b.toUri()));
      final at = DateTime.utc(2026);
      expect(TomSecretsTotp.fromEntry(entry)!.code(at), a.code(at));
      entry.removeString(TomSecretsTotpFields.otp);
      expect(TomSecretsTotp.fromEntry(entry)!.code(at), b.code(at));
    });

    test('URIs: issuer and account, bad ones are none', () {
      final t = TomSecretsTotp.tryParseUri(
        'otpauth://totp/ACME%20Co:john@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&digits=6',
      )!;
      expect(t.issuer, 'ACME Co');
      expect(t.account, 'john@example.com');
      expect(t.secret, sha1Secret);
      expect(
        TomSecretsTotp.tryParseUri('otpauth://hotp/x?secret=GEZD'),
        isNull,
      );
      expect(TomSecretsTotp.tryParseUri('https://example.org'), isNull);
      expect(TomSecretsTotp.tryParseUri('otpauth://totp/x?secret=1!'), isNull);
      expect(
        TomSecretsTotp.tryParseUri(
          'otpauth://totp/x?secret=GEZD&algorithm=MD5',
        ),
        isNull,
      );
    });

    test('base32 both ways', () {
      expect(tomSecretsBase32Encode(ascii.encode('foobar')), 'MZXW6YTBOI');
      expect(
        tomSecretsBase32Decode('mzxw 6ytb-oi======'),
        ascii.encode('foobar'),
      );
      expect(tomSecretsBase32Decode('MZ1W'), isNull);
    });

    test('a TOTP never prints its secret', () {
      expect(TomSecretsTotp(sha1Secret).toString(), contains('***'));
      expect(TomSecretsTotp(sha1Secret).toString(), isNot(contains('1234')));
    });
  });
}
