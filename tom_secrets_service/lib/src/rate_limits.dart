// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The client endpoint's rate limits (protocol.md 11), per measured
/// identity: a token bucket for `get` and `getMany`, a slowdown after
/// repeated refusals, and caps on open connections. The limits on prompts
/// are the approvals' own; failed admin authentications are the admin
/// channel's.
library;

/// The limits, protocol.md 11's by default.
final class TomSecretsRateLimitSettings {
  /// The limits.
  const TomSecretsRateLimitSettings({
    this.requestsPerSecond = 20,
    this.requestBurst = 50,
    this.refusals = 10,
    this.refusalWindow = const Duration(minutes: 1),
    this.refusalDelay = const Duration(seconds: 10),
    this.refusalHold = const Duration(minutes: 10),
    this.connectionsPerIdentity = 16,
    this.connections = 256,
  });

  /// `get` and `getMany` refilled per second.
  final int requestsPerSecond;

  /// How many may come at once (the bucket's size).
  final int requestBurst;

  /// Refusals (`denied`, `not_found`, `ambiguous`) within [refusalWindow]
  /// that slow the identity down.
  final int refusals;

  /// The window [refusals] are counted in.
  final Duration refusalWindow;

  /// How long each request of a slowed-down identity waits.
  final Duration refusalDelay;

  /// How long the slowdown lasts.
  final Duration refusalHold;

  /// Open connections per identity.
  final int connectionsPerIdentity;

  /// Open connections in all.
  final int connections;
}

/// The refusal kinds the slowdown counts.
const Set<String> tomSecretsRefusalKinds = {'denied', 'not_found', 'ambiguous'};

/// The state of the limits, kept per identity key.
final class TomSecretsRateLimits {
  /// Limits of [settings] on the clock [now].
  TomSecretsRateLimits({
    this.settings = const TomSecretsRateLimitSettings(),
    DateTime Function()? now,
  }) : _now = now ?? DateTime.now;

  /// The limits.
  final TomSecretsRateLimitSettings settings;

  final DateTime Function() _now;
  final Map<String, _Bucket> _buckets = {};
  final Map<String, List<DateTime>> _refusals = {};
  final Map<String, DateTime> _slowedUntil = {};
  final Map<String, int> _open = {};
  int _openTotal = 0;

  /// Admits a connection of the identity [key]: false when the identity or
  /// the service has as many open as allowed. An admitted connection is
  /// [release]d when it closes.
  bool admit(String key) {
    final open = _open[key] ?? 0;
    if (open >= settings.connectionsPerIdentity ||
        _openTotal >= settings.connections) {
      return false;
    }
    _open[key] = open + 1;
    _openTotal++;
    return true;
  }

  /// Releases an admitted connection of [key].
  void release(String key) {
    final open = _open[key] ?? 0;
    if (open <= 1) {
      _open.remove(key);
    } else {
      _open[key] = open - 1;
    }
    if (_openTotal > 0) _openTotal--;
  }

  /// Takes a request (`get` or `getMany`) of [key] from its bucket: null
  /// when it may go on, else how long until one is there again.
  Duration? take(String key) {
    final now = _now();
    final bucket = _buckets.putIfAbsent(
      key,
      () => _Bucket(settings.requestBurst.toDouble(), now),
    );
    final rate = settings.requestsPerSecond;
    final elapsed = now.difference(bucket.at).inMicroseconds / 1e6;
    bucket
      ..tokens = (bucket.tokens + elapsed * rate).clamp(
        0,
        settings.requestBurst.toDouble(),
      )
      ..at = now;
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return null;
    }
    final missing = 1 - bucket.tokens;
    return Duration(microseconds: (missing / rate * 1e6).ceil());
  }

  /// Records [count] refusals of [key]; [refusals] within the window slow
  /// it down for [TomSecretsRateLimitSettings.refusalHold].
  void refused(String key, int count) {
    if (count <= 0) return;
    final now = _now();
    final recent = (_refusals[key] ??= [])
      ..removeWhere((t) => now.difference(t) >= settings.refusalWindow);
    for (var i = 0; i < count; i++) {
      recent.add(now);
    }
    if (recent.length >= settings.refusals) {
      _slowedUntil[key] = now.add(settings.refusalHold);
      recent.clear();
    }
  }

  /// How long a request of [key] waits before it is answered: the refusal
  /// delay while the identity is slowed down, else nothing.
  Duration delayFor(String key) {
    final until = _slowedUntil[key];
    if (until == null) return Duration.zero;
    if (!_now().isBefore(until)) {
      _slowedUntil.remove(key);
      return Duration.zero;
    }
    return settings.refusalDelay;
  }
}

final class _Bucket {
  _Bucket(this.tokens, this.at);

  double tokens;
  DateTime at;
}
