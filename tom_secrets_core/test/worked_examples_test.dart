// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The worked examples of part-structure's resolution, row by row.
/// Priority `host`, `platform`, `env`. Store `fleet` is not bound; store
/// `dev` has `tsm.dimensions: env=dev`; store `prod` has `env=prod`.
library;

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart'
    show TomSecretsErrorKind;
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

String winner(TomSecretsResolver r, String reference) =>
    r.resolve(reference).value.text;

Matcher fails(TomSecretsErrorKind kind, [Map<String, Object?>? details]) =>
    throwsA(
      isA<TomSecretsResolveException>()
          .having((e) => e.kind, 'kind', kind)
          .having(
            (e) => e.details,
            'details',
            details == null
                ? anything
                : containsPair(details.keys.single, details.values.single),
          ),
    );

void main() {
  group('Telegram/Bot with host and platform overlays', () {
    late TomSecretsStore fleet;
    setUp(() {
      final v = DemoVault()
        ..add('Telegram/Bot', password: 'T0', key: 'telegram.bot_token')
        ..add('@host:bomber/Telegram/Bot', password: 'T1')
        ..add('@platform:windows/Telegram/Bot', password: 'T2');
      fleet = v.store('fleet');
    });

    test('row 1: mbp (macos) gets T0, both overlays dropped by step 2', () {
      final r = resolver([fleet], host: 'mbp', platform: 'macos');
      expect(winner(r, 'telegram.bot_token'), 'T0');
    });

    test('row 2: bomber gets T1, host-bound beats the shared entry', () {
      final r = resolver([fleet], host: 'bomber', platform: 'linux');
      expect(winner(r, 'telegram.bot_token'), 'T1');
    });

    test('row 3: legiondary01 (windows) gets T2', () {
      final r = resolver([fleet], host: 'legiondary01', platform: 'windows');
      expect(winner(r, 'telegram.bot_token'), 'T2');
    });

    test('row 4: with a legiondary01 overlay, host ranks above platform', () {
      final v = DemoVault()
        ..add('Telegram/Bot', password: 'T0', key: 'telegram.bot_token')
        ..add('@host:bomber/Telegram/Bot', password: 'T1')
        ..add('@platform:windows/Telegram/Bot', password: 'T2')
        ..add('@host:legiondary01/Telegram/Bot', password: 'T3');
      final r = resolver(
        [v.store('fleet')],
        host: 'legiondary01',
        platform: 'windows',
      );
      expect(winner(r, 'telegram.bot_token'), 'T3');
    });
  });

  group('db.main in the dev and prod stores', () {
    late TomSecretsStore dev;
    late TomSecretsStore prod;
    setUp(() {
      dev = (DemoVault(
        binding: {'env': 'dev'},
      )..add('Db/Main', password: 'D', key: 'db.main')).store('dev');
      prod = (DemoVault(
        binding: {'env': 'prod'},
      )..add('Db/Main', password: 'P', key: 'db.main')).store('prod');
    });

    TomSecretsStore fleetWithE() =>
        (DemoVault()
              ..add('@env:default/Db/Main', password: 'E', key: 'db.main'))
            .store('fleet');

    test('row 5: mbp with env dev gets D', () {
      final r = resolver([dev, prod], host: 'mbp', values: {'env': 'dev'});
      expect(winner(r, 'db.main'), 'D');
    });

    test('row 6: mbp asking [env:prod]db.main gets P', () {
      final r = resolver([dev, prod], host: 'mbp', values: {'env': 'dev'});
      expect(winner(r, '[env:prod]db.main'), 'P');
    });

    test('row 7: env unset, no configured default: not_found (DP-12)', () {
      final r = resolver([dev, prod], host: 'mbp');
      expect(
        () => r.resolve('db.main'),
        fails(TomSecretsErrorKind.notFound, {
          'dimensions': {'host': 'mbp', 'platform': 'linux', 'env': 'default'},
        }),
      );
    });

    test('row 8: env unset, configured default dev: D', () {
      final r = resolver(
        [dev, prod],
        host: 'mbp',
        config: TomSecretsConfig.parse(
          'dimensions:\n  - name: env\n    default: dev\n',
        ),
      );
      expect(winner(r, 'db.main'), 'D');
    });

    test(
      'row 9: plus @env:default E, env unset: E, unset counts as default',
      () {
        final r = resolver([dev, prod, fleetWithE()], host: 'mbp');
        expect(winner(r, 'db.main'), 'E');
      },
    );

    test(
      'row 10: same, mbp with env dev: D, env:default does not match dev',
      () {
        final r = resolver(
          [dev, prod, fleetWithE()],
          host: 'mbp',
          values: {'env': 'dev'},
        );
        expect(winner(r, 'db.main'), 'D');
      },
    );

    group('fallback_to_default (DP-90)', () {
      TomSecretsConfig env({required bool fallback}) => TomSecretsConfig.parse(
        'dimensions:\n  - name: env\n    fallback_to_default: $fallback\n',
      );

      test('row 11: E and P, fallback off, env staging: not_found naming '
          'env=staging', () {
        final r = resolver(
          [prod, fleetWithE()],
          host: 'mbp',
          values: {'env': 'staging'},
          config: env(fallback: false),
        );
        expect(
          () => r.resolve('db.main'),
          throwsA(
            isA<TomSecretsResolveException>()
                .having((e) => e.kind, 'kind', TomSecretsErrorKind.notFound)
                .having(
                  (e) => (e.details['dimensions']! as Map)['env'],
                  'env',
                  'staging',
                ),
          ),
        );
      });

      test('row 12: same with the fallback on: E, kept with rank 1', () {
        final r = resolver(
          [prod, fleetWithE()],
          host: 'mbp',
          values: {'env': 'staging'},
          config: env(fallback: true),
        );
        final resolution = r.resolve('db.main');
        expect(resolution.value.text, 'E');
        // Ranks in priority order host, platform, env.
        expect(resolution.ranked.single.vector, [0, 0, 1]);
      });

      test('row 13: plus @env:staging S (no key), fallback on: S, rank 2 '
          'beats rank 1', () {
        final fleet =
            (DemoVault()
                  ..add('@env:default/Db/Main', password: 'E', key: 'db.main')
                  ..add('@env:staging/Db/Main', password: 'S'))
                .store('fleet');
        final r = resolver(
          [prod, fleet],
          host: 'mbp',
          values: {'env': 'staging'},
          config: env(fallback: true),
        );
        final resolution = r.resolve('db.main');
        expect(resolution.value.text, 'S');
        expect(resolution.ranked.map((c) => c.vector), [
          [0, 0, 2],
          [0, 0, 1],
        ]);
      });
    });

    test('row 14: unbound fleet/Db/Main F plus D, P and E, env dev: D, '
        'env-bound beats unbound', () {
      final fleet =
          (DemoVault()
                ..add('Db/Main', password: 'F', key: 'db.main')
                ..add('@env:default/Db/Main', password: 'E', key: 'db.main'))
              .store('fleet');
      final r = resolver(
        [dev, prod, fleet],
        host: 'mbp',
        values: {'env': 'dev'},
      );
      expect(winner(r, 'db.main'), 'D');
    });
  });

  test('row 15: dev/Db/Main and dev/Legacy/Db with the same key: ambiguous, '
      'naming both', () {
    final dev =
        (DemoVault(binding: {'env': 'dev'})
              ..add('Db/Main', password: 'D1', key: 'db.main')
              ..add('Legacy/Db', password: 'D2', key: 'db.main'))
            .store('dev');
    final r = resolver([dev], host: 'mbp', values: {'env': 'dev'});
    expect(
      () => r.resolve('db.main'),
      throwsA(
        isA<TomSecretsResolveException>()
            .having((e) => e.kind, 'kind', TomSecretsErrorKind.ambiguous)
            .having(
              (e) => [
                for (final c in e.details['candidates']! as List)
                  '${(c as Map)['store']}/${c['path']}',
              ],
              'candidates',
              unorderedEquals(['dev/Db/Main', 'dev/Legacy/Db']),
            ),
      ),
    );
  });

  test('row 16: host+env against host+platform on bomber, linux, env dev: '
      'the platform one, (2,2,0) beats (2,0,2)', () {
    final fleet =
        (DemoVault()
              ..add('@host:bomber/@env:dev/X', password: 'host-env')
              ..add(
                '@host:bomber/@platform:linux/X',
                password: 'host-platform',
              ))
            .store('fleet');
    final r = resolver(
      [fleet],
      host: 'bomber',
      platform: 'linux',
      values: {'env': 'dev'},
    );
    final resolution = r.resolve('fleet/X');
    expect(resolution.value.text, 'host-platform');
    expect(resolution.ranked.map((c) => c.vector), [
      [2, 2, 0],
      [2, 0, 2],
    ]);
  });
}
