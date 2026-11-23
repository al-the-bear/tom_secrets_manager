// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The relay client's pacing (part-relay, DP-65): the budgets per second,
// minute and day, the order of the turns, a spent budget refused, a
// relay's Retry-After waited out once. The time is a fake: sleeping moves
// it on.

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

void main() {
  late DateTime now;
  late List<Duration> slept;

  TomSecretsRelayPacer pacer({
    List<TomSecretsRelayBudget> budgets = tomSecretsRelayClientBudgets,
  }) => TomSecretsRelayPacer(
    budgets: budgets,
    clock: () => now,
    sleep: (d) async {
      slept.add(d);
      now = now.add(d);
    },
  );

  setUp(() {
    now = DateTime.utc(2026, 11, 23, 12);
    slept = [];
  });

  test('the client spends about half of the relay\'s defaults', () {
    expect(tomSecretsRelayClientBudgets, [
      (limit: 5, window: const Duration(seconds: 1)),
      (limit: 60, window: const Duration(minutes: 1)),
      (limit: 1000, window: const Duration(days: 1)),
    ]);
  });

  test('five requests in a second go at once, the sixth waits for the '
      'first to leave the second', () async {
    final p = pacer();
    for (var i = 0; i < 5; i++) {
      await p.turn();
    }
    expect(slept, isEmpty);
    await p.turn();
    expect(slept, [const Duration(seconds: 1)]);
  });

  test('never more than the budget in any window', () async {
    final p = pacer();
    final times = <DateTime>[];
    for (var i = 0; i < 130; i++) {
      await p.turn();
      times.add(now);
    }
    for (var i = 0; i < times.length; i++) {
      bool within(DateTime t, Duration w) =>
          !t.isBefore(times[i]) && t.isBefore(times[i].add(w));
      expect(
        times.where((t) => within(t, const Duration(seconds: 1))).length,
        lessThanOrEqualTo(5),
      );
      expect(
        times.where((t) => within(t, const Duration(minutes: 1))).length,
        lessThanOrEqualTo(60),
      );
    }
    // 130 requests at 60 a minute take two full minutes and a bit.
    expect(
      times.last.difference(times.first),
      greaterThanOrEqualTo(const Duration(minutes: 2)),
    );
  });

  test('concurrent requests take their turns one after the other', () async {
    final p = pacer(budgets: const [(limit: 1, window: Duration(seconds: 1))]);
    final order = <int>[];
    await Future.wait([
      for (var i = 0; i < 3; i++) p.turn().then((_) => order.add(i)),
    ]);
    expect(order, [0, 1, 2]);
    expect(slept, [const Duration(seconds: 1), const Duration(seconds: 1)]);
  });

  test('a turn further away than the longest wait is refused, naming when, '
      'and counts nothing', () async {
    final p = pacer(budgets: const [(limit: 2, window: Duration(days: 1))]);
    await p.turn();
    await p.turn();
    await expectLater(
      p.turn(),
      throwsA(
        isA<TomSecretsRelayBudgetSpent>().having(
          (e) => e.until,
          'until',
          now.add(const Duration(days: 1)),
        ),
      ),
    );
    expect(slept, isEmpty);
    // The next turn is not stuck behind the refused one.
    now = now.add(const Duration(days: 1, seconds: 1));
    await p.turn();
  });

  test(
    'a Retry-After is waited out when it is short, refused when not',
    () async {
      final p = pacer();
      expect(await p.waitOut(null), isFalse);
      expect(await p.waitOut(const Duration(minutes: 5)), isFalse);
      expect(await p.waitOut(const Duration(seconds: 3)), isTrue);
      expect(slept, [const Duration(seconds: 3)]);
      expect(tomSecretsRetryAfter(' 30 '), const Duration(seconds: 30));
      expect(tomSecretsRetryAfter('Wed, 21 Oct 2026 07:28:00 GMT'), isNull);
      expect(tomSecretsRetryAfter(null), isNull);
    },
  );

  test('one pacer per relay address in the process', () {
    expect(
      identical(
        TomSecretsRelayPacer.of('https://relay.example'),
        TomSecretsRelayPacer.of('https://relay.example'),
      ),
      isTrue,
    );
    expect(
      identical(
        TomSecretsRelayPacer.of('https://relay.example'),
        TomSecretsRelayPacer.of('https://other.example'),
      ),
      isFalse,
    );
    final a = TomSecretsServerRelay(
      TomSecretsRelayId.parse('tsm:https://relay.example'),
    );
    final b = TomSecretsServerRelay(
      TomSecretsRelayId.parse('tsm:https://relay.example'),
      token: 'instance-token-1',
    );
    expect(identical(a.pacer, b.pacer), isTrue);
    a.close();
    b.close();
  });
}
