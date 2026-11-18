// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The OS unlock on the service's side (part-os-unlock, protocol.md 6.4):
/// `unlock {vault, bundle}` with the composite key sealed under the admin
/// connection's bundle key; a bundle that does not open, one whose key no
/// longer opens the vault, one naming another vault, one from a claimed
/// connection; the editing path's `compositeKey`; a store of an unlocked
/// service; lock mode (c). Demo data only.
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

void main() {
  TomSecretsUnlockBundle bundleOf(String password) => TomSecretsUnlockBundle(
    compositeKey: tomSecretsCompositeKey(password: password),
  );

  Future<(Demo, TomSecretsService, TomSecretsAdminClient)> started() async {
    final demo = await Demo.create();
    final service = await demo.start();
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(),
      demo.adminKey,
    );
    addTearDown(admin.close);
    return (demo, service, admin);
  }

  Matcher deniedFor(String reason) => isA<TomSecretsAdminException>()
      .having((e) => e.kind, 'kind', 'denied')
      .having((e) => e.details['reason'], 'reason', reason);

  test('the primary\'s bundle unlocks the service; the editing path then '
      'carries the composite key, never a password', () async {
    final (_, service, admin) = await started();
    await admin.unlockWithBundle('primary', bundleOf(primaryPassword));
    expect(service.isLocked, isFalse);
    final status = await admin.request('status');
    expect((status['stores'] as List).map((s) => (s as Map)['state']), [
      'current',
      'current',
    ]);
    final keys = await admin.request('vaultKeys', {
      'stores': ['primary'],
    });
    final primary = ((keys['stores']! as List).single as Map)['keys']! as Map;
    expect(primary.containsKey('password'), isFalse);
    expect(
      base64.decode(primary['compositeKey']! as String),
      tomSecretsCompositeKey(password: primaryPassword),
    );
  });

  test('a bundle that does not open is bad_bundle and counts as a failed '
      'authentication; a stale composite key is bad_password; another '
      'vault\'s name locks again', () async {
    final (demo, service, admin) = await started();
    await expectLater(
      admin.request('unlock', {
        'vault': 'primary',
        'bundle': {
          'nonce': base64.encode(List.filled(12, 1)),
          'ciphertext': base64.encode(List.filled(48, 2)),
        },
      }),
      throwsA(deniedFor('bad_bundle')),
    );
    // Sealed for another connection's key: bad_bundle too.
    final other = await TomSecretsAdminClient.connect(
      demo.runtime(),
      demo.adminKey,
    );
    addTearDown(other.close);
    final sealed = await tomSecretsSealBundle(
      bundleKey: List.filled(32, 9),
      vault: 'primary',
      serviceStart: other.serviceStart,
      plaintext: bundleOf(primaryPassword).encode(),
    );
    await expectLater(
      other.request('unlock', {'vault': 'primary', 'bundle': sealed}),
      throwsA(deniedFor('bad_bundle')),
    );
    expect(service.isLocked, isTrue);
    await expectLater(
      other.unlockWithBundle('primary', bundleOf('the old password')),
      throwsA(deniedFor('bad_password')),
    );
    await expectLater(
      other.unlockWithBundle('team', bundleOf(primaryPassword)),
      throwsA(
        isA<TomSecretsAdminException>().having(
          (e) => e.kind,
          'kind',
          'not_found',
        ),
      ),
    );
    expect(service.isLocked, isTrue);
  });

  test('unlocked, a further store opens with its own bundle', () async {
    final demo = await Demo.create();
    final team = await KdbxFormat().read(
      File(demo.teamPath).readAsBytesSync(),
      Credentials(ProtectedValue.fromString(teamPassword)),
    );
    team.credentials = Credentials(ProtectedValue.fromString('changed-pw'));
    File(demo.teamPath).writeAsBytesSync(await team.save());
    await demo.start();
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(),
      demo.adminKey,
    );
    addTearDown(admin.close);
    // Locked, the service knows no store names: every bundle is taken as
    // the primary's, and this one does not open it.
    await expectLater(
      admin.unlockWithBundle('team', bundleOf('changed-pw')),
      throwsA(deniedFor('bad_password')),
    );
    await admin.unlockWithBundle('primary', bundleOf(primaryPassword));
    await admin.unlockWithBundle('team', bundleOf('changed-pw'));
    final status = await admin.request('status');
    expect((status['stores'] as List).map((s) => (s as Map)['state']), [
      'current',
      'current',
    ]);
  });

  test('a connection that claimed the service sends no bundle', () async {
    final (demo, _, admin) = await started();
    await admin.unlock(primaryPassword);
    final (claimed, _) = await TomSecretsAdminClient.claim(
      demo.runtime(),
      password: primaryPassword,
    );
    addTearDown(claimed.close);
    await expectLater(
      claimed.unlockWithBundle('primary', bundleOf(primaryPassword)),
      throwsA(
        isA<TomSecretsAdminException>().having(
          (e) => e.kind,
          'kind',
          'unsupported',
        ),
      ),
    );
  });

  test('lock mode (c): settings.set takes osUnlock, status says c, and it '
      'relocks on idle like (b)', () async {
    final (demo, service, admin) = await started();
    await admin.unlock(primaryPassword);
    await admin.request('settings.set', {
      'device': {
        'serviceLock': {'mode': 'osUnlock', 'idleSeconds': 60},
      },
    });
    expect(service.settings.serviceLock.mode, TomSecretsLockMode.osUnlock);
    expect((await admin.request('status'))['lockMode'], 'c');
    demo.idle.idle = const Duration(minutes: 2);
    final deadline = DateTime.now().add(const Duration(seconds: 5));
    while (!service.isLocked && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    expect(service.isLocked, isTrue);
    demo.idle.idle = Duration.zero;
    await admin.unlockWithBundle('primary', bundleOf(primaryPassword));
    expect(service.isLocked, isFalse);
  });

  test('after an OS unlock the app opens and saves the primary with its '
      'composite key; keys with one are refused for a further vault', () async {
    final (_, _, admin) = await started();
    await admin.unlockWithBundle('primary', bundleOf(primaryPassword));
    final set = await admin.request('vaultKeys', {
      'stores': ['primary'],
    });
    final keys = (((set['stores'] as List).single as Map)['keys'] as Map)
        .cast<String, Object?>();
    final file = await admin.request('vaultFile', {'store': 'primary'});
    final opened = await tomSecretsDecodeStored(
      file['location'] as String,
      base64.decode(file['bytes'] as String),
      tomSecretsVaultCredentials(
        compositeKey: base64.decode(keys['compositeKey']! as String),
      ),
    );
    opened.body.rootGroup.addEntry(
      KdbxEntry.create(opened, opened.body.rootGroup)..label = 'Added',
    );
    final bytes = await tomSecretsEncodeStored(
      file['location'] as String,
      opened,
    );
    await admin.request('save', {
      'store': 'primary',
      'bytes': base64.encode(bytes),
      'baseRevision': file['revision'],
      'keys': {'compositeKey': keys['compositeKey']},
    });
    // Still opens with the password: the composite key is the same key.
    final saved = await admin.request('vaultFile', {'store': 'primary'});
    final back = await tomSecretsDecodeStored(
      saved['location'] as String,
      base64.decode(saved['bytes'] as String),
      tomSecretsVaultCredentials(password: primaryPassword),
    );
    expect(back.body.rootGroup.entries.map((e) => e.label), contains('Added'));
    await expectLater(
      admin.request('save', {
        'store': 'team',
        'bytes': saved['bytes'],
        'keys': {'compositeKey': keys['compositeKey']},
      }),
      throwsA(
        isA<TomSecretsAdminException>()
            .having((e) => e.kind, 'kind', 'malformed')
            .having((e) => e.details['reason'], 'reason', 'keys'),
      ),
    );
  });

  test('a primary with a key file in the keychain: the bundle carries the '
      'composite key alone, the service keeps the key file beside it for '
      'the editing path', () async {
    final demo = await Demo.create();
    final keychain = TomInMemorySecretStore();
    final keyFile = TomSecretsKeyFile.generate();
    final primary = await KdbxFormat().read(
      File(demo.primaryPath).readAsBytesSync(),
      Credentials(ProtectedValue.fromString(primaryPassword)),
    );
    primary.credentials = keyFile.credentials(primaryPassword);
    File(demo.primaryPath).writeAsBytesSync(await primary.save());
    await keychain.write(
      TomSecretsVaultLocator.parse('file:${demo.primaryPath}').keyFileHandle,
      base64.encode(keyFile.toBytes()),
    );
    await demo.start(keychain: keychain);
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlockWithBundle(
      'primary',
      TomSecretsUnlockBundle(
        compositeKey: tomSecretsCompositeKey(
          password: primaryPassword,
          keyFile: keyFile.toBytes(),
        ),
      ),
    );
    final set = await admin.request('vaultKeys', {
      'stores': ['primary'],
    });
    final keys = ((set['stores'] as List).single as Map)['keys'] as Map;
    expect(base64.decode(keys['keyFile']! as String), keyFile.toBytes());
    expect(keys['compositeKey'], isNotNull);
    expect(keys.containsKey('password'), isFalse);
  });
}
