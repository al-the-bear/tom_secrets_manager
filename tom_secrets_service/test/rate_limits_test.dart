// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The client endpoint's rate limits (protocol.md 11): the token bucket of
/// `get` and `getMany`, the slowdown after repeated refusals and the caps
/// on open connections, on a clock the test moves; then the service with
/// small limits answering `rate_limited` with `retryAfterMs` and refusing a
/// connection over the cap. Demo data only.
@TestOn('vm')
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

void main() {
  group('the limits', () {
    late DateTime now;
    TomSecretsRateLimits limits([
      TomSecretsRateLimitSettings settings =
          const TomSecretsRateLimitSettings(),
    ]) => TomSecretsRateLimits(settings: settings, now: () => now);

    setUp(() => now = DateTime.utc(2026, 11, 16, 12));

    test('a bucket of 50, refilled at 20 a second, per identity', () {
      final l = limits();
      for (var i = 0; i < 50; i++) {
        expect(l.take('a'), isNull, reason: 'request $i of the burst');
      }
      final wait = l.take('a')!;
      expect(wait, const Duration(milliseconds: 50));
      expect(l.take('b'), isNull, reason: 'another identity has its own');
      now = now.add(const Duration(milliseconds: 500));
      for (var i = 0; i < 10; i++) {
        expect(l.take('a'), isNull, reason: 'refilled request $i');
      }
      expect(l.take('a'), isNotNull);
      now = now.add(const Duration(minutes: 1));
      for (var i = 0; i < 50; i++) {
        expect(l.take('a'), isNull, reason: 'full again, not over 50');
      }
      expect(l.take('a'), isNotNull);
    });

    test('ten refusals in a minute: each request waits 10 s for ten '
        'minutes', () {
      final l = limits();
      l.refused('a', 9);
      expect(l.delayFor('a'), Duration.zero);
      now = now.add(const Duration(seconds: 61));
      l.refused('a', 1);
      expect(
        l.delayFor('a'),
        Duration.zero,
        reason: 'the nine are out of the window',
      );
      l.refused('a', 9);
      expect(l.delayFor('a'), const Duration(seconds: 10));
      expect(l.delayFor('b'), Duration.zero);
      now = now.add(const Duration(minutes: 9, seconds: 59));
      expect(l.delayFor('a'), const Duration(seconds: 10));
      now = now.add(const Duration(seconds: 1));
      expect(l.delayFor('a'), Duration.zero);
    });

    test('16 connections per identity, 256 in all', () {
      final l = limits();
      for (var i = 0; i < 16; i++) {
        expect(l.admit('a'), isTrue);
      }
      expect(l.admit('a'), isFalse);
      l.release('a');
      expect(l.admit('a'), isTrue);
      final small = limits(
        const TomSecretsRateLimitSettings(
          connectionsPerIdentity: 5,
          connections: 3,
        ),
      );
      expect(small.admit('a'), isTrue);
      expect(small.admit('b'), isTrue);
      expect(small.admit('c'), isTrue);
      expect(small.admit('d'), isFalse, reason: 'the total cap');
      small.release('b');
      expect(small.admit('d'), isTrue);
    });
  });

  group('the service', () {
    final transport = Platform.isWindows
        ? TomSecretsTransport.tcp
        : TomSecretsTransport.unix;
    late Demo demo;

    Future<void> start(TomSecretsRateLimitSettings limits) async {
      demo = await Demo.create();
      await demo.start(transport: transport, rateLimits: limits);
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(transport),
        demo.adminKey,
      );
      addTearDown(admin.close);
      await admin.unlock(primaryPassword);
    }

    Future<TomSecretsClient> client() async {
      final c = await TomSecretsClient.connect(
        clientName: 'demo-client',
        environment: demo.clientEnvironment(),
      );
      addTearDown(c.close);
      return c;
    }

    Matcher rateLimited(String reason) => throwsA(
      isA<TomSecretsClientException>()
          .having((e) => e.kind, 'kind', TomSecretsErrorKind.rateLimited)
          .having((e) => e.reason, 'reason', reason)
          .having((e) => e.details['retryAfterMs'], 'retryAfterMs', isA<int>()),
    );

    test('over the bucket: rate_limited with retryAfterMs; waited out on '
        'request', () async {
      await start(
        const TomSecretsRateLimitSettings(
          requestsPerSecond: 2,
          requestBurst: 2,
        ),
      );
      final c = await client();
      expect((await c.get('primary/Db/Main')).text, 'demo-db-pw');
      expect((await c.get('primary/Db/Main')).text, 'demo-db-pw');
      await expectLater(c.get('primary/Db/Main'), rateLimited('requests'));
      // The client waits it out when asked to.
      expect(
        (await c.get('primary/Db/Main', waitOnRateLimit: true)).text,
        'demo-db-pw',
      );
    });

    test('repeated refusals slow the identity down', () async {
      await start(
        const TomSecretsRateLimitSettings(
          refusals: 2,
          refusalDelay: Duration(milliseconds: 400),
        ),
      );
      final c = await client();
      for (var i = 0; i < 2; i++) {
        await expectLater(
          c.get('primary/Db/Nothing'),
          throwsA(
            isA<TomSecretsClientException>().having(
              (e) => e.kind,
              'kind',
              TomSecretsErrorKind.notFound,
            ),
          ),
        );
      }
      final watch = Stopwatch()..start();
      expect((await c.get('primary/Db/Main')).text, 'demo-db-pw');
      expect(watch.elapsedMilliseconds, greaterThanOrEqualTo(400));
    });

    test('a connection over the identity\'s cap is refused', () async {
      await start(const TomSecretsRateLimitSettings(connectionsPerIdentity: 1));
      final first = await client();
      expect((await first.get('primary/Db/Main')).text, 'demo-db-pw');
      // Refused at its hello: the connection is over the cap.
      await expectLater(client(), rateLimited('connections'));
      // Closed, the first one frees its place.
      await first.close();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      final third = await client();
      expect((await third.get('primary/Db/Main')).text, 'demo-db-pw');
    });
  });
}
