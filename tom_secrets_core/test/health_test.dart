// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The health report (part-password-manager, DP-39, DP-179): weak, reused,
/// old, expiring, short keys and breached passwords, and the breach check's
/// range requests (only the hash prefix sent, padding asked for and left
/// out). Demo data only; the range API is a fake.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

final _now = DateTime.utc(2026, 11, 19, 12);

List<TomSecretsHealthEntry> _entries(DemoVault vault, String store) => [
  for (final e in vault.file.body.rootGroup.getAllEntries())
    TomSecretsHealthEntry(store, e),
];

void _setModified(KdbxEntry entry, DateTime at) =>
    entry.times.lastModificationTime.set(at);

void main() {
  group('password strength (zxcvbn)', () {
    test('common, patterned and keyboard-walk passwords are weak', () {
      for (final p in ['password', 'P@ssw0rd', 'qwertzuiop', '1qaz2wsx']) {
        expect(tomSecretsPasswordStrength(p).weak, isTrue, reason: p);
      }
      expect(tomSecretsPasswordStrength('password').warning, isNotNull);
    });

    test('a generated password is strong', () {
      expect(
        tomSecretsPasswordStrength('xK9#mQ2!vL7@pR4zW8nB3^jF6tY1').weak,
        isFalse,
      );
    });

    test('the entry\'s own words make a password weak', () {
      const p = 'demouser-example.org';
      expect(
        tomSecretsPasswordStrength(
          p,
          userInputs: ['demouser', 'example.org'],
        ).score,
        lessThan(tomSecretsPasswordStrength(p).score),
      );
    });

    test('a very long password is read by its first characters', () {
      expect(tomSecretsPasswordStrength('a' * 500).weak, isTrue);
      expect(tomSecretsPasswordStrength('').weak, isTrue);
    });
  });

  group('the report', () {
    test('weak and reused passwords across vaults', () {
      final a = DemoVault()..add('Mail', password: 'password');
      final b = DemoVault()
        ..add('Shop', password: 'xK9#mQ2!vL7@pR4zW8nB3^jF6tY1')
        ..add('Forum', password: 'xK9#mQ2!vL7@pR4zW8nB3^jF6tY1');
      final report = tomSecretsHealthReport([
        ..._entries(a, 'personal'),
        ..._entries(b, 'shared'),
      ], now: _now);
      expect(report.checkedPasswords, 3);
      expect(report.of(TomSecretsHealthIssue.weak).map((f) => f.store), [
        'personal',
      ]);
      final reused = report.of(TomSecretsHealthIssue.reused);
      expect(reused.map((f) => f.entry.label), ['Forum', 'Shop']);
      expect(reused.first.detail, 'Shared with 1 other entry');
    });

    test('only login passwords: an API token is not weak or reused', () {
      final v = DemoVault()
        ..add('Token', password: 'abc', fields: {'tsm.type': 'api-token'})
        ..add('Note', password: 'abc', fields: {'tsm.type': 'note'});
      final report = tomSecretsHealthReport(_entries(v, 'v'), now: _now);
      expect(report.checkedPasswords, 0);
      expect(report.healthy, isTrue);
    });

    test('old: the password\'s own age, from the history', () async {
      final v = DemoVault();
      final entry = v.add('Old', password: 'xK9#mQ2!vL7@pR4zW8nB3^jF6tY1');
      _setModified(entry, DateTime.utc(2024, 3, 1));
      final changed = v.add('Changed', password: 'first-Pw-Zq81!xx');
      _setModified(changed, DateTime.utc(2024, 3, 1));
      // Saved: the next change of each keeps its previous version.
      await v.file.save();
      // A later change of the title keeps the password's age.
      entry.modify(() => entry.label = 'Old login');
      _setModified(entry, DateTime.utc(2026, 11, 1));
      changed.modify(
        () => changed.setString(
          KdbxKeyCommon.PASSWORD,
          ProtectedValue.fromString('second-Pw-Zq82!yy'),
        ),
      );
      _setModified(changed, DateTime.utc(2026, 10, 1));
      expect(tomSecretsPasswordChanged(entry), DateTime.utc(2024, 3, 1));
      expect(tomSecretsPasswordChanged(changed), DateTime.utc(2026, 10, 1));
      final report = tomSecretsHealthReport(_entries(v, 'v'), now: _now);
      final old = report.of(TomSecretsHealthIssue.old);
      expect(old.map((f) => f.entry.label), ['Old login']);
      expect(old.single.detail, 'Unchanged since 2024-03-01');
      final shorter = tomSecretsHealthReport(
        _entries(v, 'v'),
        now: _now,
        policy: const TomSecretsHealthPolicy(oldAfter: Duration(days: 30)),
      );
      expect(shorter.of(TomSecretsHealthIssue.old), hasLength(2));
    });

    test('expiring within 30 days, and expired, of any type', () {
      final v = DemoVault();
      KdbxEntry expiring(String title, DateTime at, String type) {
        final e = v.add(title, password: 'x', fields: {'tsm.type': type});
        e.times.expires.set(true);
        e.times.expiryTime.set(at);
        return e;
      }

      expiring('Soon', DateTime.utc(2026, 12, 1), 'api-token');
      expiring('Gone', DateTime.utc(2026, 11, 1), 'login');
      expiring('Later', DateTime.utc(2027, 6, 1), 'api-token');
      final report = tomSecretsHealthReport(_entries(v, 'v'), now: _now);
      final flagged = report.of(TomSecretsHealthIssue.expiring);
      expect(flagged.map((f) => f.detail), [
        'Expired on 2026-11-01',
        'Expires on 2026-12-01',
      ]);
    });

    test(
      'short keys (DP-179): RSA below 3072 flagged, Ed25519 passes',
      () async {
        final v = DemoVault();
        final rsa = await tomSecretsGenerateSshKey(
          algorithm: TomSecretsSshKeyAlgorithm.rsa,
          rsaBits: 1024,
        );
        final ed = await tomSecretsGenerateSshKey();
        tomSecretsWriteSshKey(
          v.add('Old server'),
          attachmentName: 'id_rsa',
          privateKey: rsa.privateKey,
        );
        tomSecretsWriteSshKey(
          v.add('New server'),
          attachmentName: 'id_ed25519',
          privateKey: ed.privateKey,
        );
        final report = tomSecretsHealthReport(_entries(v, 'v'), now: _now);
        final short = report.of(TomSecretsHealthIssue.shortKey);
        expect(short.map((f) => f.entry.label), ['Old server']);
        expect(short.single.detail, 'RSA 1024 bits: below 3072');
      },
    );

    test('key lengths by DP-179', () {
      expect(TomSecretsKeyStrength.shortness('ssh-rsa', 2048), isNotNull);
      expect(TomSecretsKeyStrength.shortness('ssh-rsa', 3072), isNull);
      expect(TomSecretsKeyStrength.shortness('ssh-rsa', 4096), isNull);
      expect(
        TomSecretsKeyStrength.shortness('ecdsa-sha2-nistp256', 256),
        isNull,
      );
      expect(
        TomSecretsKeyStrength.shortness('ecdsa-sha2-nistp384', 384),
        isNull,
      );
      expect(TomSecretsKeyStrength.shortness('ssh-ed25519', 256), isNull);
      expect(TomSecretsKeyStrength.shortness('ssh-dss', null), isNotNull);
      expect(TomSecretsKeyStrength.shortness('ssh-rsa', null), isNull);
    });

    test('breached: the count the check found, unless excluded', () {
      final v = DemoVault();
      v.add('Leaked', password: 'Leaked-Demo-Pw-1!');
      final kept = v.add('Kept', password: 'Leaked-Demo-Pw-1!x');
      tomSecretsSetBreachCheckExcluded(kept, true);
      expect(tomSecretsBreachCheckExcluded(kept), isTrue);
      final report = tomSecretsHealthReport(
        _entries(v, 'v'),
        now: _now,
        breachCount: (e, password) => 7,
      );
      final breached = report.of(TomSecretsHealthIssue.breached);
      expect(breached.map((f) => f.entry.label), ['Leaked']);
      expect(breached.single.detail, 'Seen 7 times in known breaches');
      tomSecretsSetBreachCheckExcluded(kept, false);
      expect(tomSecretsBreachCheckExcluded(kept), isFalse);
    });
  });

  group('the breach check', () {
    const password = 'Leaked-Demo-Pw-1!';
    final hash = tomSecretsPasswordHash(password);

    test('sends the five-character prefix only, asks for padding, and '
        'reads the suffixes without the padding lines', () async {
      final asked = <http.Request>[];
      final client = MockClient((request) async {
        asked.add(request);
        final prefix = request.url.pathSegments.last;
        final body = prefix == hash.substring(0, 5)
            ? '${hash.substring(5)}:12\r\n'
                  '0123456789012345678901234567890ABCD:0\r\n'
                  '1111111111111111111111111111111111A:3'
            : '0123456789012345678901234567890ABCD:0';
        return http.Response(body, 200);
      });
      final check = TomSecretsBreachCheck(
        client: client,
        endpoint: Uri.parse('https://range.example/range/'),
      );
      final counts = await check.countAll([password, 'Unseen-Demo-Pw-2!']);
      expect(counts, {password: 12, 'Unseen-Demo-Pw-2!': 0});
      expect(asked, hasLength(2));
      for (final r in asked) {
        expect(r.url.pathSegments.last, hasLength(5));
        expect(r.headers['Add-Padding'], 'true');
        expect(utf8.decode(r.bodyBytes), isEmpty);
        expect(r.url.toString(), isNot(contains(hash.substring(5))));
      }
      expect(
        asked.first.url.toString(),
        startsWith('https://range.example/range/'),
      );
      // Cached per hash: asked once per run.
      expect(check.cached(password), 12);
      expect(await check.count(password), 12);
      expect(asked, hasLength(2));
    });

    test('a failed request throws and caches nothing', () async {
      final check = TomSecretsBreachCheck(
        client: MockClient((_) async => http.Response('busy', 503)),
      );
      await expectLater(
        check.countAll([password]),
        throwsA(isA<TomSecretsBreachCheckException>()),
      );
      expect(check.cached(password), isNull);
    });

    test('the default endpoint is the Have I Been Pwned range API', () {
      expect(
        TomSecretsBreachCheck.defaultEndpoint.toString(),
        'https://api.pwnedpasswords.com/range/',
      );
      expect(TomSecretsBreachCheck.parseRange('ABC:2\nDEF:0'), {'ABC': 2});
    });
  });
}
