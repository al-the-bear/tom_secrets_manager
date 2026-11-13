// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The key-expiry reminders (part-key-rotation, Reminders): a key is
/// reminded of from a number of days before its expiry (the GitHub token
/// from `keyExpiryWarningDays`, default 14; every other key from 30), then 7
/// days and 1 day before, and daily once expired. The service computes them
/// whenever it reads the vaults; nothing is scheduled for them.
library;

/// A key due for a reminder.
final class TomSecretsExpiringKey {
  /// [key] of [kind] (in [vault]) expiring at [expiresAt], [daysLeft] whole
  /// days from now, at reminder [step].
  const TomSecretsExpiringKey({
    required this.kind,
    required this.key,
    required this.expiresAt,
    required this.daysLeft,
    required this.step,
    this.vault,
  });

  /// The days before the expiry the reminders of every key but the GitHub
  /// token start.
  static const int otherKeyDays = 30;

  /// [key] when a reminder is due for it at [now], else null: from
  /// [firstDays] before [expiresAt], then 7 and 1 day before, and once a
  /// day once expired.
  static TomSecretsExpiringKey? due({
    required String kind,
    required String key,
    required DateTime expiresAt,
    required DateTime now,
    required int firstDays,
    String? vault,
  }) {
    final at = expiresAt.toUtc();
    final utcNow = now.toUtc();
    final daysLeft = (at.difference(utcNow).inMinutes / (24 * 60)).floor();
    final String step;
    if (!utcNow.isBefore(at)) {
      step = 'expired ${utcNow.toIso8601String().substring(0, 10)}';
    } else if (daysLeft <= 1) {
      step = '1';
    } else if (daysLeft <= 7) {
      step = '7';
    } else if (daysLeft <= firstDays) {
      step = 'first';
    } else {
      return null;
    }
    return TomSecretsExpiringKey(
      kind: kind,
      key: key,
      vault: vault,
      expiresAt: at,
      daysLeft: daysLeft,
      step: step,
    );
  }

  /// `github_token` or `vault_keys`.
  final String kind;

  /// The key's id: `github-token:<owner>/<repository>`,
  /// `vault-keys:<vault>`.
  final String key;

  /// The vault the key belongs to, when one.
  final String? vault;

  /// When it expires (UTC).
  final DateTime expiresAt;

  /// Whole days left (negative once expired).
  final int daysLeft;

  /// The reminder step: `first`, `7`, `1`, or `expired <date>` (one a day).
  final String step;

  /// As `statusReport.expiring[]` writes it.
  Map<String, Object?> toJson() => {
    'kind': kind,
    'key': key,
    'vault': ?vault,
    'expiresAt': expiresAt.toIso8601String(),
    'daysLeft': daysLeft,
  };

  /// The `key_expiry` event.
  Map<String, Object?> toEvent() => {
    'op': 'key_expiry',
    'key': key,
    'expiresAt': expiresAt.toIso8601String(),
    'daysLeft': daysLeft,
  };
}
