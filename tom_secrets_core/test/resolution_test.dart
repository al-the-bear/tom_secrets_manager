// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Resolution beyond the worked examples: the edge cases of part-structure,
/// the request's values, overlays in both placements, the index's skips, and
/// the field (attachments, totp, passkeys).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart'
    show TomSecretsErrorKind;
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

Matcher fails(TomSecretsErrorKind kind, {String? reason}) => throwsA(
  isA<TomSecretsResolveException>()
      .having((e) => e.kind, 'kind', kind)
      .having((e) => e.reason, 'reason', reason ?? anything),
);

TomSecretsConfig envConfig({String? defaultValue, bool fallback = false}) =>
    TomSecretsConfig(
      dimensions: [
        TomSecretsDimension(
          'env',
          defaultValue: defaultValue,
          fallbackToDefault: fallback,
        ),
      ],
    );

void main() {
  group('candidates and placements', () {
    test('an overlay inside the entry\'s own group overlays it like the root '
        'form', () {
      final fleet =
          (DemoVault()
                ..add(
                  'Telegram/Bot',
                  password: 'shared',
                  key: 'telegram.bot_token',
                )
                ..add('Telegram/@host:bomber/Bot', password: 'inner'))
              .store('fleet');
      expect(
        resolver([
          fleet,
        ], host: 'bomber').resolve('telegram.bot_token').value.text,
        'inner',
      );
      expect(
        resolver([
          fleet,
        ], host: 'bomber').resolve('fleet/Telegram/Bot').value.text,
        'inner',
      );
      expect(
        resolver([fleet], host: 'mbp').resolve('fleet/Telegram/Bot').value.text,
        'shared',
      );
    });

    test('the same overlay in both placements is ambiguous', () {
      final fleet =
          (DemoVault()
                ..add('@host:bomber/Telegram/Bot', password: 'root')
                ..add('Telegram/@host:bomber/Bot', password: 'inner'))
              .store('fleet');
      expect(
        () => resolver([fleet], host: 'bomber').resolve('fleet/Telegram/Bot'),
        fails(TomSecretsErrorKind.ambiguous),
      );
    });

    test('two entries of one title in one group are ambiguous by path; the '
        'uuid reference names one', () {
      final v = DemoVault();
      final first = v.add('Mail/Box', password: 'one');
      v.add('Mail/Box', password: 'two');
      final fleet = v.store('fleet');
      final r = resolver([fleet], host: 'mbp');
      expect(
        () => r.resolve('fleet/Mail/Box'),
        fails(TomSecretsErrorKind.ambiguous),
      );
      expect(
        r.resolve('fleet/~${tomSecretsUuidHex(first.uuid)}').value.text,
        'one',
      );
    });

    test('a uuid reference takes the overlays of its path', () {
      final v = DemoVault();
      final shared = v.add('Db/Main', password: 'shared');
      v.add('@host:bomber/Db/Main', password: 'bomber');
      final r = resolver([v.store('fleet')], host: 'bomber');
      expect(
        r
            .resolve('fleet/~${tomSecretsUuidHex(shared.uuid).toUpperCase()}')
            .value
            .text,
        'bomber',
      );
    });

    test('an overlay with no shared entry serves only its host', () {
      final fleet = (DemoVault()..add('@host:bomber/Only/Here', password: 'x'))
          .store('fleet');
      expect(
        resolver([fleet], host: 'bomber').resolve('fleet/Only/Here').value.text,
        'x',
      );
      expect(
        () => resolver([fleet], host: 'mbp').resolve('fleet/Only/Here'),
        fails(TomSecretsErrorKind.notFound),
      );
    });

    test(
      'an overlay entry carrying another key is no candidate of the key',
      () {
        final fleet =
            (DemoVault()
                  ..add('Db/Main', password: 'shared', key: 'db.main')
                  ..add(
                    '@host:bomber/Db/Main',
                    password: 'other',
                    key: 'db.other',
                  ))
                .store('fleet');
        final r = resolver([fleet], host: 'bomber');
        expect(r.resolve('db.main').value.text, 'shared');
        expect(r.resolve('db.other').value.text, 'other');
      },
    );

    test('nested overlays at the root bind both dimensions', () {
      final fleet =
          (DemoVault()..add('@host:bomber/@env:dev/Db', password: 'bomber-dev'))
              .store('fleet');
      final entry = fleet.entries.single;
      expect(entry.path, ['Db']);
      expect(entry.bindings, {'host': 'bomber', 'env': 'dev'});
      expect(
        resolver(
          [fleet],
          host: 'bomber',
          values: {'env': 'dev'},
        ).resolve('fleet/Db').value.text,
        'bomber-dev',
      );
    });

    test('a path in an unknown store, or an unknown uuid, is not_found', () {
      final r = resolver([DemoVault().store('fleet')], host: 'mbp');
      expect(() => r.resolve('nostore/X'), fails(TomSecretsErrorKind.notFound));
      expect(
        () => r.resolve('fleet/~${'0' * 32}'),
        fails(TomSecretsErrorKind.notFound),
      );
    });
  });

  group('the index', () {
    test('a file bound env=prod holding @env:dev is skipped with a warning; '
        '@env:prod is fine', () {
      final prod =
          (DemoVault(binding: {'env': 'prod'})
                ..add('@env:dev/Db/Main', password: 'wrong')
                ..add('@env:prod/Db/Main', password: 'right'))
              .store('prod');
      expect(prod.entries.map((e) => e.entry.label), ['Main']);
      expect(prod.entries.single.bindings, {'env': 'prod'});
      expect(prod.warnings.single, contains('env bound twice'));
    });

    test('an overlay group between ordinary groups, and a group named @ '
        'without a binding, are skipped with a warning', () {
      final fleet =
          (DemoVault()
                ..add('A/@host:x/B/C', password: '1')
                ..add('@nonsense/D', password: '2')
                ..add('Fine/E', password: '3'))
              .store('fleet');
      expect(fleet.entries.map((e) => e.pathText), ['Fine/E']);
      expect(fleet.warnings, hasLength(2));
    });

    test('the metadata entry, the grants group and the recycle bin are never '
        'reached', () {
      final v = DemoVault(store: 'fleet');
      v.add('tsm.grants/bigbeast/g-0001', fields: {'tsm.key': 'grant.one'});
      final gone = v.add('Old/Entry', password: 'deleted', key: 'old.entry');
      v.file.deleteEntry(gone);
      v.add('Kept', password: 'k');
      final fleet = TomSecretsStore.fromFile(v.file);
      expect(fleet.name, 'fleet');
      expect(fleet.entries.map((e) => e.pathText), ['Kept']);
      final r = resolver([fleet], host: 'mbp');
      expect(() => r.resolve('grant.one'), fails(TomSecretsErrorKind.notFound));
      expect(() => r.resolve('old.entry'), fails(TomSecretsErrorKind.notFound));
      expect(
        () => r.resolve('fleet/.tom-secrets'),
        fails(TomSecretsErrorKind.notFound),
      );
    });

    test('the product group inside an overlay (a device\'s settings key, '
        'DP-15) is never reached', () {
      final fleet =
          (DemoVault(store: 'fleet')
                ..add('@host:mbp/.tom-secrets/device', password: 'device-key')
                ..add('.tom-secrets/vaults/other', password: 'vault-key')
                ..add('Kept', password: 'k'))
              .store('fleet');
      expect(fleet.entries.map((e) => e.pathText), ['Kept']);
      final r = resolver([fleet], host: 'mbp');
      expect(
        () => r.resolve('fleet/.tom-secrets/device'),
        fails(TomSecretsErrorKind.notFound),
      );
    });

    test('a tsm.key that is not a key is ignored with a warning', () {
      final fleet = (DemoVault()..add('X', password: 'x', key: 'Not.A.Key'))
          .store('fleet');
      expect(fleet.entries.single.key, isNull);
      expect(fleet.warnings.single, contains('is not a key'));
    });

    test('the store name: the machine\'s name, else tsm.store, else the file '
        'name', () {
      final named = DemoVault(store: 'from-meta');
      expect(TomSecretsStore.fromFile(named.file, name: 'given').name, 'given');
      expect(TomSecretsStore.fromFile(named.file).name, 'from-meta');
      expect(
        TomSecretsStore.fromFile(
          DemoVault().file,
          fileName: '/srv/x/fleet.kdbx',
        ).name,
        'fleet',
      );
      expect(
        () => TomSecretsStore.fromFile(
          DemoVault().file,
          fileName: 'Bad Name.kdbx',
        ),
        throwsArgumentError,
      );
    });
  });

  group('the request\'s values', () {
    late TomSecretsStore dev;
    late TomSecretsStore fleet;
    setUp(() {
      dev = (DemoVault(
        binding: {'env': 'dev'},
      )..add('Db/Main', password: 'D', key: 'db.main')).store('dev');
      fleet =
          (DemoVault()
                ..add('@env:default/Db/Main', password: 'E', key: 'db.main')
                ..add('Shared/Only', password: 'U', key: 'shared.only'))
              .store('fleet');
    });

    test('a binding passed beside the reference applies', () {
      final r = resolver([dev, fleet], host: 'mbp');
      expect(r.resolve('db.main', dimensions: {'env': 'dev'}).value.text, 'D');
    });

    test('the same value in the brackets and beside them is fine; different '
        'values are malformed, conflicting_dimension', () {
      final r = resolver([dev, fleet], host: 'mbp');
      expect(
        r.resolve('[env:dev]db.main', dimensions: {'env': 'dev'}).value.text,
        'D',
      );
      expect(
        () => r.resolve('[env:dev]db.main', dimensions: {'env': 'prod'}),
        fails(TomSecretsErrorKind.malformed, reason: 'conflicting_dimension'),
      );
    });

    test('an undeclared dimension is malformed, in the brackets or beside', () {
      final r = resolver([dev, fleet], host: 'mbp');
      expect(
        () => r.resolve('[evn:prod]db.main'),
        fails(TomSecretsErrorKind.malformed, reason: 'undeclared_dimension'),
      );
      expect(
        () => r.resolve('db.main', dimensions: {'region': 'eu'}),
        fails(TomSecretsErrorKind.malformed, reason: 'undeclared_dimension'),
      );
    });

    test('default given explicitly ends the fallback: [env:default] ignores a '
        'configured default', () {
      final r = resolver(
        [dev, fleet],
        host: 'mbp',
        config: envConfig(defaultValue: 'dev'),
      );
      expect(r.resolve('db.main').value.text, 'D');
      expect(r.resolve('[env:default]db.main').value.text, 'E');
    });

    test('a mistyped value: not_found with the fallback off, the default '
        'entry with it on', () {
      expect(
        () => resolver([dev, fleet], host: 'mbp').resolve('[env:prdo]db.main'),
        fails(TomSecretsErrorKind.notFound),
      );
      expect(
        resolver(
          [dev, fleet],
          host: 'mbp',
          config: envConfig(fallback: true),
        ).resolve('[env:prdo]db.main').value.text,
        'E',
      );
    });

    test('an unbound entry serves every value', () {
      final r = resolver([fleet], host: 'mbp', values: {'env': 'anything'});
      expect(r.resolve('shared.only').value.text, 'U');
    });

    test('a declared dimension ranks below the built-ins', () {
      final config = TomSecretsConfig.parse('dimensions:\n  - name: region\n');
      expect(config.dimensions.map((d) => d.name), [
        'host',
        'platform',
        'env',
        'region',
      ]);
      final eu =
          (DemoVault()
                ..add('@region:eu/X', password: 'eu')
                ..add('@env:dev/X', password: 'dev'))
              .store('fleet');
      final r = resolver(
        [eu],
        host: 'mbp',
        values: {'env': 'dev', 'region': 'eu'},
        config: config,
      );
      expect(r.resolve('fleet/X').value.text, 'dev');
    });

    test('a file bound on an undeclared dimension is never matched', () {
      final odd = (DemoVault(
        binding: {'zone': 'a'},
      )..add('X', password: 'x', key: 'odd.x')).store('odd');
      expect(
        () => resolver([odd], host: 'mbp').resolve('odd.x'),
        fails(TomSecretsErrorKind.notFound),
      );
    });

    test('malformed references are malformed, with the grammar\'s reason', () {
      final r = resolver([fleet], host: 'mbp');
      expect(
        () => r.resolve('fleet//X'),
        fails(TomSecretsErrorKind.malformed, reason: 'empty_segment'),
      );
      expect(
        () => r.resolve('[env:]x'),
        fails(TomSecretsErrorKind.malformed, reason: 'empty_segment'),
      );
      expect(
        () => r.resolve('x' * 1025),
        fails(TomSecretsErrorKind.malformed, reason: 'too_long'),
      );
    });
  });

  group('the field', () {
    late TomSecretsResolver r;
    late KdbxEntry entry;
    setUp(() {
      final v = DemoVault();
      entry = v.add(
        'Mail/Box',
        password: 'pw',
        key: 'mail.box',
        fields: {'UserName': 'alice', 'KPEX_PASSKEY_PRIVATE_KEY_PEM': 'demo'},
      );
      entry.createBinary(
        isProtected: true,
        name: 'id_demo',
        bytes: Uint8List.fromList([0, 1, 2, 255]),
      );
      TomSecretsTotp(
        Uint8List.fromList('12345678901234567890'.codeUnits),
        digits: 8,
      ).writeTo(entry);
      entry
        ..times.expires.set(true)
        ..times.expiryTime.set(DateTime.utc(2027));
      r = resolver([v.store('fleet')], host: 'mbp');
    });

    test('Password by default, a named string field, protection kept', () {
      final p = r.resolve('mail.box');
      expect(p.value.text, 'pw');
      expect(p.value.isProtected, isTrue);
      expect(p.field, 'Password');
      final u = r.resolve('mail.box#UserName');
      expect(u.value.text, 'alice');
      expect(u.value.isProtected, isFalse);
      expect(r.resolve('mail.box', field: 'UserName').value.text, 'alice');
    });

    test(
      'a field in the reference and beside it is malformed, field_twice',
      () {
        expect(
          () => r.resolve('mail.box#UserName', field: 'UserName'),
          fails(TomSecretsErrorKind.malformed, reason: 'field_twice'),
        );
      },
    );

    test('an attachment is bytes', () {
      final a = r.resolve('mail.box#attachment%3Aid_demo');
      expect(a.value.isText, isFalse);
      expect(a.value.bytes, [0, 1, 2, 255]);
      expect(() => a.value.text, throwsStateError);
    });

    test('disposing a value zeroes it, never the vault\'s own bytes', () {
      final a = r.resolve('mail.box#attachment%3Aid_demo');
      a.value.dispose();
      expect(() => a.value.bytes, throwsStateError);
      final again = r.resolve('mail.box#attachment%3Aid_demo');
      expect(again.value.bytes, [0, 1, 2, 255], reason: 'the vault keeps it');
      final p = r.resolve('mail.box');
      expect(p.value.isProtected, isTrue);
      expect(p.value.withBytes(utf8.decode), 'pw');
      p.value.dispose();
      expect(r.resolve('mail.box').value.text, 'pw');
    });

    test('totp is the current code (RFC 6238)', () {
      final t = r.resolve(
        'mail.box#totp',
        now: DateTime.utc(1970, 1, 1, 0, 0, 59),
      );
      expect(t.value.text, '94287082');
    });

    test('a missing field is not_found naming the entry and the field', () {
      expect(
        () => r.resolve('mail.box#URL'),
        throwsA(
          isA<TomSecretsResolveException>()
              .having((e) => e.kind, 'kind', TomSecretsErrorKind.notFound)
              .having((e) => e.details['field'], 'field', 'URL')
              .having(
                (e) => (e.details['entry']! as Map)['path'],
                'path',
                'Mail/Box',
              ),
        ),
      );
      expect(
        () => r.resolve('mail.box#attachment%3Anone'),
        fails(TomSecretsErrorKind.notFound),
      );
    });

    test('totp on an entry without one is not_found', () {
      final plain = (DemoVault()..add('X', password: 'x', key: 'x.y')).store(
        'fleet',
      );
      expect(
        () => resolver([plain], host: 'mbp').resolve('x.y#totp'),
        fails(TomSecretsErrorKind.notFound),
      );
    });

    test('a passkey field is denied, reserved_field, whatever else', () {
      expect(
        () => r.resolve('mail.box#KPEX_PASSKEY_PRIVATE_KEY_PEM'),
        fails(TomSecretsErrorKind.denied, reason: 'reserved_field'),
      );
      expect(
        () => r.resolve('nothing.here#KPEX_PASSKEY_X'),
        fails(TomSecretsErrorKind.denied, reason: 'reserved_field'),
      );
    });

    test(
      'the resolution carries the binding, expiry, modification and type',
      () {
        final p = r.resolve('mail.box');
        expect(p.bound, isEmpty);
        expect(p.expires, DateTime.utc(2027));
        expect(p.modified, isNotNull);
        expect(p.type, TomSecretsEntryType.login);
        expect(p.entry.uuid, matches(RegExp(r'^[0-9a-f]{32}$')));
        expect(p.value.toString(), isNot(contains('pw')));
        p.value.dispose();
        expect(() => p.value.bytes, throwsStateError, reason: 'zeroed');
      },
    );
  });
}
