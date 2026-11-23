// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** Pacing the requests to a relay server (part-relay, DP-65): the
/// relay blocks an address for a day when it makes more than 10 requests
/// in a second, 120 in a minute or 2,000 in a day, so this device's client
/// stays well under each, leaving room for the other processes and
/// devices behind the same address.
///
/// Every HTTP request and every WebSocket opened to one relay waits for
/// its turn here: one pacer per relay address in the process, shared by
/// every `TomSecretsServerRelay` of that relay (the app's mailbox reads,
/// the service's puts and links). The frames inside an open channel are
/// not requests.
library;

import 'dart:async';
import 'dart:collection';

/// One budget: at most [limit] requests within [window].
typedef TomSecretsRelayBudget = ({int limit, Duration window});

/// What this device's client spends on one relay: about half of the
/// relay's per-address defaults (10 / second, 120 / minute, 2,000 / day).
const List<TomSecretsRelayBudget> tomSecretsRelayClientBudgets = [
  (limit: 5, window: Duration(seconds: 1)),
  (limit: 60, window: Duration(minutes: 1)),
  (limit: 1000, window: Duration(days: 1)),
];

/// The longest a request waits for its turn; a longer wait (the day's
/// budget spent) is refused instead of holding the caller for hours.
const Duration tomSecretsRelayLongestWait = Duration(seconds: 70);

/// The budget of [budgets] is spent until [until]: a request now would
/// wait longer than [tomSecretsRelayLongestWait].
final class TomSecretsRelayBudgetSpent implements Exception {
  /// Spent until [until].
  const TomSecretsRelayBudgetSpent(this.until);

  /// When the next request may go.
  final DateTime until;

  @override
  String toString() => 'TomSecretsRelayBudgetSpent(until $until)';
}

/// The turns of the requests to one relay.
final class TomSecretsRelayPacer {
  /// A pacer spending [budgets], the time read from [clock], waiting with
  /// [sleep] (tests replace both).
  TomSecretsRelayPacer({
    this.budgets = tomSecretsRelayClientBudgets,
    this.longestWait = tomSecretsRelayLongestWait,
    DateTime Function()? clock,
    Future<void> Function(Duration)? sleep,
  }) : _clock = clock ?? DateTime.now,
       _sleep = sleep ?? ((d) => Future<void>.delayed(d)),
       _keep = budgets.map((b) => b.window).reduce((a, b) => a > b ? a : b);

  /// The pacer of the relay at [address] in this process.
  static TomSecretsRelayPacer of(String address) =>
      _byAddress.putIfAbsent(address, TomSecretsRelayPacer.new);

  static final Map<String, TomSecretsRelayPacer> _byAddress = {};

  /// The budgets.
  final List<TomSecretsRelayBudget> budgets;

  /// The longest wait before [turn] refuses.
  final Duration longestWait;

  final DateTime Function() _clock;
  final Future<void> Function(Duration) _sleep;
  final Duration _keep;

  /// When the requests of the longest window went, oldest first.
  final Queue<DateTime> _sent = Queue();

  /// The turns in order: each waits for the one before.
  Future<void> _last = Future<void>.value();

  /// How many requests went within [window] before [now].
  int _within(Duration window, DateTime now) {
    final since = now.subtract(window);
    var n = 0;
    for (final t in _sent) {
      if (t.isAfter(since)) n++;
    }
    return n;
  }

  /// When the next request may go, from [now].
  DateTime _next(DateTime now) {
    var at = now;
    final sent = _sent.toList();
    for (final b in budgets) {
      if (_within(b.window, now) < b.limit) continue;
      // The request that must leave the window first: the limit-th newest.
      final freeing = sent[sent.length - b.limit].add(b.window);
      if (freeing.isAfter(at)) at = freeing;
    }
    return at;
  }

  /// Waits for this request's turn and counts it. Throws
  /// [TomSecretsRelayBudgetSpent] when the turn is further away than
  /// [longestWait] (nothing counted).
  Future<void> turn() {
    final mine = _last.then((_) => _take());
    _last = mine.then((_) {}, onError: (_) {});
    return mine;
  }

  Future<void> _take() async {
    while (true) {
      final now = _clock();
      while (_sent.isNotEmpty && !_sent.first.isAfter(now.subtract(_keep))) {
        _sent.removeFirst();
      }
      final at = _next(now);
      if (!at.isAfter(now)) {
        _sent.add(now);
        return;
      }
      final wait = at.difference(now);
      if (wait > longestWait) throw TomSecretsRelayBudgetSpent(at);
      await _sleep(wait);
    }
  }

  /// A request the relay refused for its limits ([retryAfter]) is asked
  /// again once after waiting that long, when it is no longer than
  /// [longestWait]; true when it may be asked again.
  Future<bool> waitOut(Duration? retryAfter) async {
    if (retryAfter == null || retryAfter > longestWait) return false;
    await _sleep(retryAfter);
    return true;
  }
}

/// The `Retry-After` header's delay in seconds, or null.
Duration? tomSecretsRetryAfter(String? header) {
  final seconds = int.tryParse(header?.trim() ?? '');
  return seconds == null || seconds < 0 ? null : Duration(seconds: seconds);
}
