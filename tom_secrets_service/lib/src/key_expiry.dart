// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The key-expiry reminders (part-key-rotation, Reminders): a key is
/// reminded of from a number of days before its expiry (the GitHub token
/// from `keyExpiryWarningDays`, default 14; every other key from 30), then 7
/// days and 1 day before, and daily once expired. A key with a rotation age
/// instead of an expiry (the approver and approval-link key pairs, 24
/// months) expires when its age is over. The service computes them
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

  /// The default days before the expiry the reminders of every key but the
  /// GitHub token start (DP-85; the device setting `otherKeyWarningDays`).
  static const int otherKeyDays = 30;

  /// The default rotation age of the approver and approval-link key pairs
  /// (DP-85; the device setting `keyPairAgeMonths`).
  static const int keyPairAgeMonths = 24;

  /// When a key pair taken into use [since] is due for rotation: [since]
  /// plus [months] (default [keyPairAgeMonths]); null when [since] is.
  static DateTime? keyPairDue(
    DateTime? since, {
    int months = keyPairAgeMonths,
  }) {
    if (since == null) return null;
    final s = since.toUtc();
    return DateTime.utc(
      s.year,
      s.month + months,
      s.day,
      s.hour,
      s.minute,
      s.second,
    );
  }

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

  /// `github_token`, `github_app`, `vault_keys`, `approver_key`, `link_key`
  /// or **[C]** `member_key`.
  final String kind;

  /// The key's id: `github-token:<owner>/<repository>`,
  /// `vault-keys:<vault>`, `approver-key:<device>`, `link-key:<device>`,
  /// `member-key:<the first 16 characters of its fingerprint>`.
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

/// A key the service knows the due date of (`tsm keys`, the `keys` admin
/// request): [kind] and [key] as in [TomSecretsExpiringKey], the [vault] it
/// belongs to, when it [expiresAt], and how many days before that its
/// reminders start ([firstDays]).
final class TomSecretsKeyDate {
  /// A key of [kind] due at [expiresAt], reminded of from [firstDays] before.
  const TomSecretsKeyDate({
    required this.kind,
    required this.key,
    required this.expiresAt,
    required this.firstDays,
    this.vault,
    this.own = false,
  });

  /// Whether it is one of this device's own key pairs (rotated here,
  /// `keys.rotate`).
  final bool own;

  /// As [TomSecretsExpiringKey.kind].
  final String kind;

  /// As [TomSecretsExpiringKey.key].
  final String key;

  /// The vault it belongs to, when one.
  final String? vault;

  /// When it expires or is due for rotation.
  final DateTime expiresAt;

  /// The days before [expiresAt] its reminders start.
  final int firstDays;

  /// Its reminder at [now], or null when none is due.
  TomSecretsExpiringKey? dueAt(DateTime now) => TomSecretsExpiringKey.due(
    kind: kind,
    key: key,
    vault: vault,
    expiresAt: expiresAt,
    now: now,
    firstDays: firstDays,
  );

  /// As `keyList.keys[]` writes it at [now]: [expiresAt], the whole
  /// `daysLeft` and whether a reminder is due (`reminding`).
  Map<String, Object?> toJson(DateTime now) {
    final at = expiresAt.toUtc();
    return {
      'kind': kind,
      'key': key,
      'vault': ?vault,
      'expiresAt': at.toIso8601String(),
      'daysLeft': (at.difference(now.toUtc()).inMinutes / (24 * 60)).floor(),
      'reminding': dueAt(now) != null,
      if (own) 'own': true,
    };
  }
}
