// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The quick unlock (protocol.md 6.4, part-app Unlocking): the primary's
/// keys sealed in the service's memory under a PIN or the biometric's
/// token. The PIN after an idle lock; 5 wrong PINs; a restart (the PIN
/// refused until the master password was typed once); the age limit;
/// nothing about the PIN on the disk but the switch; `tsm` refused;
/// "Lock completely". Demo data only.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

const _small = TomSecretsPinKdf(memoryKiB: 256, iterations: 1);
const _pin = 'tiger7';

/// Measures every peer as [identity].
final class _FixedMeasurer implements TomSecretsPeerMeasurer {
  const _FixedMeasurer(this.identity);

  final TomSecretsIdentity identity;

  @override
  Future<TomSecretsPeerMeasurement> measure(Socket socket) async =>
      TomSecretsPeerMeasured(identity);
}

Matcher _denied(String reason) => throwsA(
  isA<TomSecretsAdminException>()
      .having((e) => e.kind, 'kind', 'denied')
      .having((e) => e.details['reason'], 'reason', reason),
);

void main() {
  group('the sealed keys in memory', () {
    late DateTime clock;
    late TomSecretsQuickUnlock quick;
    final keys = utf8.encode('{"password":"demo"}');

    setUp(() {
      clock = DateTime.utc(2026, 11, 26, 9);
      quick = TomSecretsQuickUnlock(kdf: _small, now: () => clock);
    });

    test(
      'a PIN is set only after an unlock with the master password and '
      'has at least 6 characters; it opens the keys, the token too',
      () async {
        await expectLater(quick.setPin(_pin, keys), throwsStateError);
        quick.passwordUnlocked(keys);
        await expectLater(quick.setPin('12345', keys), throwsArgumentError);
        await quick.setPin(_pin, keys);
        expect(quick.pinArmed, isTrue);
        expect(await quick.openWithPin(_pin), keys);
        final token = await quick.newToken(keys);
        expect(await quick.openWithToken(token), keys);
        await expectLater(
          quick.openWithToken(Uint8List(32)),
          throwsA(
            isA<TomSecretsQuickUnlockException>().having(
              (e) => e.refusal,
              'refusal',
              TomSecretsQuickRefusal.badToken,
            ),
          ),
        );
      },
    );

    test('5 wrong PINs wipe the sealed keys; a right one in between resets '
        'the count', () async {
      quick.passwordUnlocked(keys);
      await quick.setPin(_pin, keys);
      await quick.newToken(keys);
      for (var left = 4; left >= 1; left--) {
        await expectLater(
          quick.openWithPin('wrong1'),
          throwsA(
            isA<TomSecretsQuickUnlockException>().having(
              (e) => e.attemptsLeft,
              'attemptsLeft',
              left,
            ),
          ),
        );
      }
      await quick.openWithPin(_pin);
      expect(quick.attemptsLeft, tomSecretsPinAttempts);
      for (var i = 0; i < 4; i++) {
        await expectLater(quick.openWithPin('wrong1'), throwsA(anything));
      }
      await expectLater(
        quick.openWithPin('wrong1'),
        throwsA(
          isA<TomSecretsQuickUnlockException>().having(
            (e) => e.refusal,
            'refusal',
            TomSecretsQuickRefusal.wiped,
          ),
        ),
      );
      expect(quick.pinArmed, isFalse);
      expect(quick.tokenArmed, isFalse, reason: 'everything sealed goes');
      await expectLater(
        quick.openWithPin(_pin),
        throwsA(
          isA<TomSecretsQuickUnlockException>().having(
            (e) => e.refusal,
            'refusal',
            TomSecretsQuickRefusal.none,
          ),
        ),
      );
    });

    test('the age limit: 7 days after the last master-password unlock the '
        'keys are wiped; a new password unlock counts from then', () async {
      quick.passwordUnlocked(keys);
      await quick.setPin(_pin, keys);
      clock = clock.add(const Duration(days: 6, hours: 23));
      expect(await quick.openWithPin(_pin), keys);
      expect(quick.until, DateTime.utc(2026, 12, 3, 9));
      clock = clock.add(const Duration(hours: 1));
      expect(quick.pinArmed, isFalse);
      await expectLater(
        quick.openWithPin(_pin),
        throwsA(
          isA<TomSecretsQuickUnlockException>().having(
            (e) => e.refusal,
            'refusal',
            TomSecretsQuickRefusal.expired,
          ),
        ),
      );
      quick.passwordUnlocked(keys);
      await quick.setPin(_pin, keys);
      expect(quick.pinArmed, isTrue);
    });

    test('other keys (a re-keyed vault) end what was sealed', () async {
      quick.passwordUnlocked(keys);
      await quick.setPin(_pin, keys);
      expect(quick.matches(keys), isTrue);
      final other = utf8.encode('{"password":"new"}');
      expect(quick.matches(other), isFalse);
      quick.passwordUnlocked(other);
      expect(quick.pinArmed, isFalse);
    });
  });

  group('the service', () {
    late Demo demo;
    late TomSecretsService service;
    late TomSecretsAdminClient admin;
    var clock = DateTime.utc(2026, 11, 26, 9);

    Future<void> start({TomSecretsPeerMeasurer? measurer}) async {
      service = await demo.start(
        clock: () => clock,
        peerMeasurer: measurer,
        quickUnlockKdf: _small,
      );
      admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      addTearDown(admin.close);
    }

    Future<void> setPin(String pin) => admin.requestSealed(
      'quickUnlock.set',
      sealed: {'pin': utf8.encode(pin)},
    );

    Future<void> unlockWithPin(String pin) =>
        admin.requestSealed('unlock', sealed: {'pin': utf8.encode(pin)});

    Future<Map<String, Object?>> quickStatus() async =>
        ((await admin.request('status'))['quickUnlock']! as Map)
            .cast<String, Object?>();

    Future<void> idleLock() async {
      demo.idle.idle = const Duration(hours: 2);
      final deadline = DateTime.now().add(const Duration(seconds: 5));
      while (!service.isLocked && DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
      expect(service.isLocked, isTrue, reason: 'locked on idle');
      demo.idle.idle = Duration.zero;
    }

    setUp(() async {
      clock = DateTime.utc(2026, 11, 26, 9);
      demo = await Demo.create();
      await start();
    });

    test('the PIN undoes an idle lock; status says what is possible and '
        'never more', () async {
      await expectLater(setPin(_pin), throwsA(anything), reason: 'locked');
      await admin.unlock(primaryPassword);
      expect(await quickStatus(), {
        'pin': false,
        'pinArmed': false,
        'token': false,
        'attemptsLeft': 5,
      });
      await setPin(_pin);
      expect(service.settings.quickUnlockPin, isTrue);
      final status = await quickStatus();
      expect(status['pin'], isTrue);
      expect(status['pinArmed'], isTrue);
      expect(status['until'], '2026-12-03T09:00:00.000Z');
      await idleLock();
      expect((await quickStatus())['pinArmed'], isTrue);
      await unlockWithPin(_pin);
      expect(service.isLocked, isFalse);
      // The PIN works again after the next idle lock.
      await idleLock();
      await unlockWithPin(_pin);
      expect(service.isLocked, isFalse);
    });

    test('a PIN shorter than 6 characters is refused', () async {
      await admin.unlock(primaryPassword);
      await expectLater(
        setPin('12345'),
        throwsA(
          isA<TomSecretsAdminException>().having(
            (e) => e.details['reason'],
            'reason',
            'pin',
          ),
        ),
      );
    });

    test('5 wrong PINs wipe the sealed keys: then only the master password '
        'unlocks', () async {
      await admin.unlock(primaryPassword);
      await setPin(_pin);
      await admin.request('lock');
      for (var left = 4; left >= 1; left--) {
        await expectLater(
          unlockWithPin('wrong1'),
          throwsA(
            isA<TomSecretsAdminException>()
                .having((e) => e.details['reason'], 'reason', 'bad_pin')
                .having((e) => e.details['attemptsLeft'], 'attemptsLeft', left),
          ),
        );
      }
      await expectLater(unlockWithPin('wrong1'), _denied('pin_wiped'));
      await expectLater(unlockWithPin(_pin), _denied('no_quick_unlock'));
      expect(service.isLocked, isTrue);
      await admin.unlock(primaryPassword);
      expect(await quickStatus(), containsPair('pinArmed', false));
      expect(
        (await quickStatus())['pin'],
        isTrue,
        reason: 'the switch stays on: the app asks for the PIN again',
      );
    });

    test('after a restart the PIN is refused until the master password was '
        'typed once, then set again it is accepted', () async {
      await admin.unlock(primaryPassword);
      await setPin(_pin);
      await admin.close();
      await service.stop();
      await start();
      await expectLater(unlockWithPin(_pin), _denied('no_quick_unlock'));
      expect(await quickStatus(), containsPair('pinArmed', false));
      await admin.unlock(primaryPassword);
      expect(await quickStatus(), containsPair('pin', true));
      expect(await quickStatus(), containsPair('pinArmed', false));
      await setPin(_pin);
      await admin.request('lock');
      await unlockWithPin(_pin);
      expect(service.isLocked, isFalse);
    });

    test('the age limit: a week after the last master-password unlock the '
        'PIN no longer unlocks', () async {
      await admin.unlock(primaryPassword);
      await setPin(_pin);
      await admin.request('lock');
      clock = clock.add(const Duration(days: 7));
      await expectLater(unlockWithPin(_pin), _denied('quick_expired'));
      await admin.unlock(primaryPassword);
      expect(await quickStatus(), containsPair('pinArmed', false));
    });

    test(
      '"Lock completely" ends the quick unlock; a plain lock keeps it',
      () async {
        await admin.unlock(primaryPassword);
        await setPin(_pin);
        await admin.request('lock');
        await unlockWithPin(_pin);
        await admin.request('lock', {'completely': true});
        await expectLater(unlockWithPin(_pin), _denied('no_quick_unlock'));
      },
    );

    test('the biometric\'s token undoes an idle lock; turned off, it does '
        'not', () async {
      await admin.unlock(primaryPassword);
      final answer = await admin.requestSealed(
        'quickUnlock.token',
        open: ['token'],
      );
      final token = answer['token']! as Uint8List;
      expect(token, hasLength(32));
      expect((await quickStatus())['token'], isTrue);
      await idleLock();
      await admin.requestSealed(
        'unlock',
        sealed: {
          'quick': [...token],
        },
      );
      expect(service.isLocked, isFalse);
      await admin.request('quickUnlock.remove', {'token': true});
      await admin.request('lock');
      await expectLater(
        admin.requestSealed(
          'unlock',
          sealed: {
            'quick': [...token],
          },
        ),
        _denied('no_quick_unlock'),
      );
    });

    test('nothing about the PIN is on the disk but the switch: the data '
        'folder before and after', () async {
      await admin.unlock(primaryPassword);
      final before = _snapshot(demo.bootstrap.dataDirectory);
      final settingsBefore = service.settings.toJson();
      await setPin(_pin);
      await admin.request('lock');
      await unlockWithPin(_pin);
      final after = _snapshot(demo.bootstrap.dataDirectory);
      final changed = {
        for (final f in {...before.keys, ...after.keys})
          if (before[f] != after[f]) f,
      };
      // Only the device settings container (the switch) and the
      // operational log (what happened, never the PIN) were written.
      expect(
        changed.every(
          (f) =>
              f.endsWith('device-settings.kdbx') || f.endsWith('service.log'),
        ),
        isTrue,
        reason: 'changed: $changed',
      );
      expect(service.settings.toJson(), {
        ...settingsBefore,
        'quickUnlockPin': true,
      });
      for (final f in Directory(
        demo.bootstrap.dataDirectory,
      ).listSync(recursive: true).whereType<File>()) {
        final text = latin1.decode(f.readAsBytesSync());
        expect(text.contains(_pin), isFalse, reason: f.path);
      }
      // Removed, the switch is off again.
      await admin.request('quickUnlock.remove', {'pin': true});
      expect(service.settings.quickUnlockPin, isFalse);
      expect(service.settings.toJson(), settingsBefore);
    });

    test('settings.set does not move the switch', () async {
      await admin.unlock(primaryPassword);
      await setPin(_pin);
      await admin.request('settings.set', {
        'device': {...service.settings.toJson(), 'quickUnlockPin': false},
      });
      expect(service.settings.quickUnlockPin, isTrue);
    });

    test('tsm cannot send unlock {pin} or set a PIN', () async {
      await admin.close();
      await service.stop();
      await start(
        measurer: _FixedMeasurer(
          TomSecretsIdentity(
            kind: 'exe',
            exe: '/usr/local/bin/tsm',
            args: const ['unlock'],
            cwd: '/',
            uid: tomSecretsOwnUid()!,
          ),
        ),
      );
      await admin.unlock(primaryPassword);
      await expectLater(setPin(_pin), _denied('wrong_executable'));
      await admin.request('lock');
      await expectLater(unlockWithPin(_pin), _denied('wrong_executable'));
      await expectLater(
        admin.requestSealed('quickUnlock.token', open: ['token']),
        _denied('wrong_executable'),
      );
    });
  });
}

/// The SHA-256 of every file under [dir], by path.
Map<String, String> _snapshot(String dir) => {
  for (final f in Directory(dir).listSync(recursive: true).whereType<File>())
    f.path: crypto.sha256.convert(f.readAsBytesSync()).toString(),
};
