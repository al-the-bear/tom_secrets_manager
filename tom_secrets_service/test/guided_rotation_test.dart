// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The guided rotation of the own vaults with a migration period
/// (part-key-rotation, protocol.md 6.4, decision 43) through the service,
/// with `file:` vaults and two machines on the same files:
///
/// - a further vault's next key file prepared in the primary: each device's
///   service takes it at its unlock or the primary's next load (its device
///   record gets the key id, it leaves the record's pending); a device that
///   never syncs stays missing; the switch re-keys the vault and the other
///   device serves it with the new keys;
/// - a repository key rotated alone: the `.tsmx` file written with two
///   slots, a device holding only the old key reads it but writes nothing;
///   with both keys every write keeps both slots; after the finish one;
/// - the primary's own next key file: taken into the device keychain beside
///   its keys, and after the switch the device opens the re-keyed primary
///   with it (at the refresh and at a new unlock).
///
/// Demo keys only.
@TestOn('vm')
@Timeout(Duration(minutes: 3))
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// One machine: its demo files, service, admin connection and keychain.
final class _Device {
  _Device(this.demo, this.keychain);

  final Demo demo;
  final TomInMemorySecretStore keychain;
  late TomSecretsService service;
  late TomSecretsAdminClient admin;
}

final _transport = Platform.isWindows
    ? TomSecretsTransport.tcp
    : TomSecretsTransport.unix;

Future<_Device> _start(
  Demo demo,
  String host, {
  TomInMemorySecretStore? keychain,
  bool unlock = true,
}) async {
  final d = _Device(demo, keychain ?? TomInMemorySecretStore());
  d.service = await demo.start(
    transport: _transport,
    keychain: d.keychain,
    host: host,
  );
  d.admin = await TomSecretsAdminClient.connect(
    demo.runtime(_transport),
    demo.adminKey,
  );
  addTearDown(d.admin.close);
  if (unlock) await d.admin.unlock(primaryPassword);
  return d;
}

Future<String?> _get(Demo demo, String ref) async {
  final client = await TomSecretsClient.connect(
    clientName: 'demo-client',
    environment: demo.clientEnvironment(),
  );
  try {
    return (await client.get(ref)).text;
  } finally {
    await client.close();
  }
}

/// [store] as the app reads it through [admin]: its keys, its copy and that
/// copy opened.
Future<
  ({Map<String, Object?> keys, Map<String, Object?> file, KdbxFile opened})
>
_read(TomSecretsAdminClient admin, String store) async {
  final set = await admin.request('vaultKeys', {
    'stores': [store],
  });
  final keys = (((set['stores'] as List).single as Map)['keys'] as Map)
      .cast<String, Object?>();
  final file = await admin.request('vaultFile', {'store': store});
  final keyFile = keys['keyFile'] as String?;
  final opened = await tomSecretsDecodeStored(
    file['location'] as String,
    base64.decode(file['bytes'] as String),
    tomSecretsVaultCredentials(
      password: keys['password'] as String?,
      keyFile: keyFile == null ? null : base64.decode(keyFile),
    ),
    outerKey: tomSecretsJoinOuterKeys([
      keys['outerKey'] as String?,
      keys['previousOuterKey'] as String?,
    ]),
  );
  return (keys: keys, file: file, opened: opened);
}

/// Changes the primary with [change] and saves it through [admin], as the
/// app does.
Future<void> _editPrimary(
  TomSecretsAdminClient admin,
  void Function(KdbxFile primary) change,
) async {
  final primary = await _read(admin, 'primary');
  change(primary.opened);
  await admin.request('save', {
    'store': 'primary',
    'bytes': base64.encode(
      await tomSecretsEncodeStored(
        primary.file['location'] as String,
        primary.opened,
        outerKey: tomSecretsJoinOuterKeys([
          primary.keys['outerKey'] as String?,
          primary.keys['previousOuterKey'] as String?,
        ]),
      ),
    ),
    'baseRevision': primary.file['revision'],
  });
}

Future<TomSecretsAdminException> _refused(Future<Object?> request) async {
  try {
    await request;
  } on TomSecretsAdminException catch (e) {
    return e;
  }
  fail('the request was not refused');
}

Future<KdbxFile> _openPrimary(Demo demo, {Uint8List? keyFile}) =>
    KdbxFormat().read(
      File(demo.primaryPath).readAsBytesSync(),
      tomSecretsVaultCredentials(password: primaryPassword, keyFile: keyFile),
    );

void main() {
  late Demo demo;

  setUp(() async => demo = await Demo.create());

  test('a further vault\'s next key file: taken by each device that syncs, '
      'one that never does stays missing; the switch re-keys the vault and '
      'the other device serves it with the new keys', () async {
    final mbp = await _start(demo, 'mbp');
    final now = DateTime.now().toUtc();
    final nextKeyFile = TomSecretsKeyFile.generate().toBytes();
    final newId = TomSecretsKeyFile.parse(nextKeyFile).hash;

    // 1. Prepare: the next key beside the old one, the record started,
    // bigbeast's record from an earlier pairing.
    await _editPrimary(mbp.admin, (p) {
      final list = TomSecretsPrimaryVaults(p);
      list.put(list.byName('team')!.copyWith(nextKeyFile: nextKeyFile));
      TomSecretsDeviceRecords(
        p,
      ).put(TomSecretsDeviceRecord(device: 'bigbeast', paired: now));
      TomSecretsRotations(p).start(
        TomSecretsRotation(
          kind: TomSecretsRotationKind.vaultKeys,
          target: 'team',
          oldKeyId: 'none',
          newKeyId: newId,
          started: now,
          endsAt: now.add(tomSecretsRotationPeriod),
          by: 'mbp',
          pending: const ['bomber', 'bigbeast'],
        ),
      );
    });
    var primary = await _openPrimary(demo);
    expect(
      TomSecretsDeviceRecords(primary).byDevice('mbp')!.keyIds,
      contains(newId),
    );
    // Nothing re-encrypted yet: the vault opens with its password alone.
    expect(await _get(demo, 'team/Api/Token'), 'demo-api-token');

    // The second machine takes it at its unlock.
    final bomber = await _start(Demo.sameFilesAs(demo), 'bomber');
    primary = await _openPrimary(demo);
    final records = TomSecretsDeviceRecords(primary);
    expect(records.byDevice('bomber')!.keyIds, contains(newId));
    expect(records.missingKey(newId).map((r) => r.device), ['bigbeast']);
    expect(
      TomSecretsRotations(
        primary,
      ).of(TomSecretsRotationKind.vaultKeys, 'team')!.pending,
      ['bigbeast'],
    );

    // 2. Switch: the next key becomes the key, then the vault re-keyed.
    await _editPrimary(mbp.admin, (p) {
      final list = TomSecretsPrimaryVaults(p);
      final team = list.byName('team')!;
      list.put(team.copyWith(keyFile: team.nextKeyFile, clearNext: true));
      final rotations = TomSecretsRotations(p);
      rotations.update(
        rotations
            .of(TomSecretsRotationKind.vaultKeys, 'team')!
            .copyWith(switched: now),
      );
    });
    final team = await _read(mbp.admin, 'team');
    team.opened.credentials = tomSecretsVaultCredentials(
      password: teamPassword,
      keyFile: nextKeyFile,
    );
    await mbp.admin.request('save', {
      'store': 'team',
      'bytes': base64.encode(
        await tomSecretsEncodeStored(
          team.file['location'] as String,
          team.opened,
        ),
      ),
      'baseRevision': team.file['revision'],
    });
    await expectLater(
      KdbxFormat().read(
        File(demo.teamPath).readAsBytesSync(),
        Credentials(ProtectedValue.fromString(teamPassword)),
      ),
      throwsA(isA<KdbxInvalidKeyException>()),
    );

    // bomber reads the new primary and serves the vault with the new key.
    await bomber.admin.request('reload');
    expect(
      bomber.service.vaults.statusOf('team')!.state,
      TomSecretsStoreState.current,
    );
    expect(await _get(bomber.demo, 'team/Api/Token'), 'demo-api-token');

    // 3. Finish: the record ends; bigbeast is listed as never having taken
    // the key.
    await _editPrimary(mbp.admin, (p) {
      TomSecretsRotations(p).end(TomSecretsRotationKind.vaultKeys, 'team');
    });
    primary = await _openPrimary(demo);
    expect(TomSecretsRotations(primary).list(), isEmpty);
    expect(
      TomSecretsDeviceRecords(primary).missingKey(newId).map((r) => r.device),
      ['bigbeast'],
    );
  });

  test('a repository key rotated alone: two slots; a device with only the '
      'old key reads but writes nothing; with both every write keeps both; '
      'after the finish one slot', () async {
    // The team vault as a .tsmx file under the old repository key.
    final oldKey = TomSecretsRepositoryKey.generate().toBase64();
    final newKey = TomSecretsRepositoryKey.generate().toBase64();
    final oldId = TomSecretsRepositoryKey.fromBase64(oldKey).keyIdHex;
    final newId = TomSecretsRepositoryKey.fromBase64(newKey).keyIdHex;
    final tsmx = '${demo.teamPath}$tomSecretsOuterSuffix';
    final locator = 'file:$tsmx';
    final team = await KdbxFormat().read(
      File(demo.teamPath).readAsBytesSync(),
      Credentials(ProtectedValue.fromString(teamPassword)),
    );
    File(tsmx).writeAsBytesSync(
      await tomSecretsEncodeStored(locator, team, outerKey: oldKey),
    );
    final primary = await _openPrimary(demo);
    TomSecretsPrimaryVaults(primary).put(
      TomSecretsVaultKeys(
        name: 'team',
        locator: locator,
        password: teamPassword,
        outerKey: oldKey,
      ),
    );
    File(demo.primaryPath).writeAsBytesSync(await primary.save());

    final d = await _start(demo, 'mbp');
    expect(await _get(demo, 'team/Api/Token'), 'demo-api-token');

    // Another device switched: the file with both slots, while this one
    // still lists only the old key.
    File(tsmx).writeAsBytesSync(
      await tomSecretsEncodeStored(
        locator,
        team,
        outerKey: tomSecretsJoinOuterKeys([newKey, oldKey]),
      ),
    );
    expect(tomSecretsOuterKeyIds(File(tsmx).readAsBytesSync()), [newId, oldId]);
    await d.admin.request('reload');
    final status = d.service.vaults.statusOf('team')!;
    expect(status.keyChanged, isTrue);
    expect(await _get(demo, 'team/Api/Token'), 'demo-api-token');
    var copy = await _read(d.admin, 'team');
    final refused = await _refused(
      d.admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(
          await tomSecretsEncodeStored(locator, copy.opened, outerKey: oldKey),
        ),
        'baseRevision': copy.file['revision'],
      }),
    );
    expect(refused.kind, 'needs_unlock');
    expect(refused.details['reason'], 'key_changed');

    // The primary lists the new key and the old one's slot: both held, the
    // writes keep both slots.
    await _editPrimary(d.admin, (p) {
      final list = TomSecretsPrimaryVaults(p);
      list.put(
        list
            .byName('team')!
            .copyWith(outerKey: newKey, previousOuterKey: oldKey),
      );
    });
    await d.admin.request('reload');
    expect(d.service.vaults.statusOf('team')!.keyChanged, isFalse);
    copy = await _read(d.admin, 'team');
    expect(copy.keys['outerKey'], newKey);
    expect(copy.keys['previousOuterKey'], oldKey);
    await d.admin.request('save', {
      'store': 'team',
      'bytes': base64.encode(
        await tomSecretsEncodeStored(
          locator,
          copy.opened,
          outerKey: tomSecretsJoinOuterKeys([newKey, oldKey]),
        ),
      ),
      'baseRevision': copy.file['revision'],
    });
    expect(tomSecretsOuterKeyIds(File(tsmx).readAsBytesSync()), [newId, oldId]);

    // The finish: the previous key leaves the primary; the file is written
    // again with the new key's slot only.
    await _editPrimary(d.admin, (p) {
      final list = TomSecretsPrimaryVaults(p);
      list.put(list.byName('team')!.copyWith(clearPrevious: true));
    });
    await d.admin.request('reload');
    copy = await _read(d.admin, 'team');
    expect(copy.keys['previousOuterKey'], isNull);
    await d.admin.request('save', {
      'store': 'team',
      'bytes': base64.encode(
        await tomSecretsEncodeStored(locator, copy.opened, outerKey: newKey),
      ),
      'baseRevision': copy.file['revision'],
    });
    expect(tomSecretsOuterKeyIds(File(tsmx).readAsBytesSync()), [newId]);
  });

  test('the primary\'s own next key file: taken into the keychain; after '
      'the switch the other device opens the re-keyed primary with it, at '
      'the refresh and at a new unlock', () async {
    final mbp = await _start(demo, 'mbp');
    final second = Demo.sameFilesAs(demo);
    final keychain = TomInMemorySecretStore();
    var bomber = await _start(second, 'bomber', keychain: keychain);
    final nextKeyFile = TomSecretsKeyFile.generate().toBytes();
    final handle = TomSecretsVaultLocator.parse(
      demo.bootstrap.primary,
    ).keyFileHandle;
    final now = DateTime.now().toUtc();

    // Prepare: the primary's next key file in .tom-secrets/next-keys.
    await _editPrimary(mbp.admin, (p) {
      TomSecretsPrimaryNextKeys(keyFile: nextKeyFile).writeTo(p);
      TomSecretsRotations(p).start(
        TomSecretsRotation(
          kind: TomSecretsRotationKind.vaultKeys,
          target: 'primary',
          oldKeyId: 'none',
          newKeyId: TomSecretsKeyFile.parse(nextKeyFile).hash,
          started: now,
          endsAt: now.add(tomSecretsRotationPeriod),
          by: 'mbp',
          pending: const ['bomber'],
        ),
      );
    });
    await bomber.admin.request('reload');
    expect(await keychain.read('$handle.next'), base64.encode(nextKeyFile));
    expect(await keychain.read(handle), isNull);
    var primary = await _openPrimary(demo);
    expect(
      TomSecretsRotations(
        primary,
      ).of(TomSecretsRotationKind.vaultKeys, 'primary')!.pending,
      isEmpty,
    );

    // Switch: mbp saves the primary re-keyed with the new key file, over
    // the primary as it is now (bomber wrote its device record).
    await mbp.admin.request('reload');
    final copy = await _read(mbp.admin, 'primary');
    copy.opened.credentials = tomSecretsVaultCredentials(
      password: primaryPassword,
      keyFile: nextKeyFile,
    );
    await mbp.admin.request('save', {
      'store': 'primary',
      'bytes': base64.encode(
        await tomSecretsEncodeStored(
          copy.file['location'] as String,
          copy.opened,
        ),
      ),
      'baseRevision': copy.file['revision'],
      'keys': {
        'password': primaryPassword,
        'keyFile': base64.encode(nextKeyFile),
      },
    });
    primary = await _openPrimary(demo, keyFile: nextKeyFile);

    // bomber's refresh: the password alone no longer opens it; the next key
    // file from the keychain does, and is its key file from now on.
    await bomber.admin.request('reload');
    expect(
      bomber.service.vaults.statusOf('primary')!.state,
      TomSecretsStoreState.current,
    );
    expect(await keychain.read(handle), base64.encode(nextKeyFile));
    expect(await _get(second, 'primary/Db/Main'), 'demo-db-pw');

    // A new unlock with the password finds the key file in the keychain.
    await bomber.admin.request('lock');
    await bomber.admin.unlock(primaryPassword);
    expect(await _get(second, 'primary/Db/Main'), 'demo-db-pw');

    // A device that took the next key but was stopped before the switch:
    // its next unlock opens the re-keyed primary with it.
    await bomber.service.stop();
    final third = TomInMemorySecretStore();
    await third.write('$handle.next', base64.encode(nextKeyFile));
    bomber = await _start(Demo.sameFilesAs(demo), 'bigbeast', keychain: third);
    expect(await third.read(handle), base64.encode(nextKeyFile));
  });

  test('the primary\'s own repository key rotated alone: two slots, the '
      'other device takes the new key up while the old one still reads, its '
      'writes keep both slots; after the finish one', () async {
    // The primary as a .tsmx file under the old repository key, which each
    // device's keychain holds.
    final oldKey = TomSecretsRepositoryKey.generate().toBase64();
    final newKey = TomSecretsRepositoryKey.generate().toBase64();
    final oldId = TomSecretsRepositoryKey.fromBase64(oldKey).keyIdHex;
    final newId = TomSecretsRepositoryKey.fromBase64(newKey).keyIdHex;
    final tsmx = '${demo.primaryPath}$tomSecretsOuterSuffix';
    final locator = 'file:$tsmx';
    // With a key file too: the keys taken up keep it (a copy made inside
    // withRevealed, never of the bytes it wipes after).
    final keyFile = TomSecretsKeyFile.generate().toBytes();
    final plain = await _openPrimary(demo)
      ..credentials = tomSecretsVaultCredentials(
        password: primaryPassword,
        keyFile: keyFile,
      );
    File(tsmx).writeAsBytesSync(
      await tomSecretsEncodeStored(locator, plain, outerKey: oldKey),
    );
    demo.bootstrap = TomSecretsBootstrap(
      primary: locator,
      dataDirectory: demo.bootstrap.dataDirectory,
      deviceKey: demo.bootstrap.deviceKey,
    );
    final handle = TomSecretsVaultLocator.parse(locator).repositoryKeyHandle;
    final keyFileHandle = TomSecretsVaultLocator.parse(locator).keyFileHandle;
    final mbpKeys = TomInMemorySecretStore();
    await mbpKeys.write(handle, oldKey);
    await mbpKeys.write(keyFileHandle, base64.encode(keyFile));
    final bomberKeys = TomInMemorySecretStore();
    await bomberKeys.write(handle, oldKey);
    await bomberKeys.write(keyFileHandle, base64.encode(keyFile));
    final mbp = await _start(demo, 'mbp', keychain: mbpKeys);
    final second = Demo.sameFilesAs(demo);
    final bomber = await _start(second, 'bomber', keychain: bomberKeys);
    Future<List<String>> slots() async =>
        tomSecretsOuterKeyIds(File(tsmx).readAsBytesSync());

    // Prepare: the next repository key in .tom-secrets/next-keys.
    await _editPrimary(mbp.admin, (p) {
      TomSecretsPrimaryNextKeys(outerKey: newKey).writeTo(p);
    });
    await bomber.admin.request('reload');
    expect(await bomberKeys.read('$handle.next'), newKey);

    // Switch: mbp writes the primary with both slots, the old key named as
    // the one kept, and holds both keys.
    await mbp.admin.request('reload');
    final copy = await _read(mbp.admin, 'primary');
    TomSecretsPrimaryNextKeys(
      outerKey: newKey,
      previousOuterKey: oldKey,
    ).writeTo(copy.opened);
    final both = tomSecretsJoinOuterKeys([newKey, oldKey]);
    await mbp.admin.request('save', {
      'store': 'primary',
      'bytes': base64.encode(
        await tomSecretsEncodeStored(locator, copy.opened, outerKey: both),
      ),
      'baseRevision': copy.file['revision'],
      'keys': {
        'password': primaryPassword,
        'keyFile': base64.encode(keyFile),
        'outerKey': newKey,
        'previousOuterKey': oldKey,
      },
    });
    expect(await slots(), [newId, oldId]);
    expect(await mbpKeys.read(handle), newKey);

    // bomber still opens it with the old key and takes the new one up.
    await bomber.admin.request('reload');
    expect(bomber.service.vaults.statusOf('primary')!.keyChanged, isFalse);
    expect(await bomberKeys.read(handle), newKey);
    // Its own writes (a device record) keep both slots.
    await bomber.service.savePrimary();
    expect(await slots(), [newId, oldId]);

    // Finish: the next keys leave the primary, which is written with the
    // new key's slot only; the devices drop the old key.
    await mbp.admin.request('reload');
    await _editPrimary(mbp.admin, TomSecretsPrimaryNextKeys.clear);
    final finished = await _read(mbp.admin, 'primary');
    await mbp.admin.request('save', {
      'store': 'primary',
      'bytes': base64.encode(
        await tomSecretsEncodeStored(
          locator,
          finished.opened,
          outerKey: newKey,
        ),
      ),
      'baseRevision': finished.file['revision'],
    });
    expect(await slots(), [newId]);
    await bomber.admin.request('reload');
    expect(
      bomber.service.vaults.statusOf('primary')!.state,
      TomSecretsStoreState.current,
    );
    await bomber.service.savePrimary();
    expect(await slots(), [newId]);
    expect(await bomberKeys.read('$handle.next'), isNull);
    expect(await _get(second, 'primary/Db/Main'), 'demo-db-pw');
  });
}
