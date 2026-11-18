// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The device settings' JSON: the defaults (DP-85's rotation ages and
/// reminder starts among them), a round trip, and settings written before a
/// field existed reading with its default.
library;

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

void main() {
  test('the defaults: DP-85 ages and reminder starts', () {
    const d = TomSecretsDeviceSettings();
    expect(d.otherKeyWarningDays, 30);
    expect(d.keyPairAgeMonths, 24);
    expect(d.primaryKeyAgeMonths, 24);
    expect(d.vaultKeyAgeMonths, 12);
    expect(d.keyExpiryWarningDays, 14);
  });

  test('a round trip keeps every value; a missing field takes its default', () {
    final s = TomSecretsDeviceSettings.fromJson({
      ...const TomSecretsDeviceSettings().toJson(),
      'otherKeyWarningDays': 45,
      'keyPairAgeMonths': 18,
      'primaryKeyAgeMonths': 36,
      'vaultKeyAgeMonths': 6,
      'servedStores': ['team'],
    });
    final back = TomSecretsDeviceSettings.fromJson(s.toJson());
    expect(back.otherKeyWarningDays, 45);
    expect(back.keyPairAgeMonths, 18);
    expect(back.primaryKeyAgeMonths, 36);
    expect(back.vaultKeyAgeMonths, 6);
    expect(back.servedStores, ['team']);

    final old = TomSecretsDeviceSettings.fromJson({'refreshMinutes': 10});
    expect(old.refreshMinutes, 10);
    expect(old.keyPairAgeMonths, 24);
    expect(old.vaultKeyAgeMonths, 12);
  });

  test('lock mode (c) relocks on idle like (b), keeps its name across a '
      'round trip, and headless never locks', () {
    const c = TomSecretsLockPolicy(
      mode: TomSecretsLockMode.osUnlock,
      idle: Duration(minutes: 5),
    );
    final back = TomSecretsLockPolicy.fromJson(c.toJson());
    expect(back.mode, TomSecretsLockMode.osUnlock);
    expect(c.toJson()['mode'], 'osUnlock');
    const unlocked = Duration(minutes: 1);
    expect(
      c.shouldLock(idle: const Duration(minutes: 6), unlockedFor: unlocked),
      isTrue,
    );
    expect(
      c.shouldLock(idle: const Duration(minutes: 4), unlockedFor: unlocked),
      isFalse,
    );
    expect(c.shouldLock(idle: null, unlockedFor: unlocked), isFalse);
    const never = TomSecretsLockPolicy(mode: TomSecretsLockMode.never);
    expect(
      never.shouldLock(idle: const Duration(days: 1), unlockedFor: unlocked),
      isFalse,
    );
  });
}
