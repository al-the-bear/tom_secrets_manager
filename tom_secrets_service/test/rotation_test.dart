// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Re-keyed saves (part-key-rotation, protocol.md 6.4): the app writes a
/// vault's new keys into the primary first, then saves the vault re-keyed;
/// the service takes the new keys from the primary, writes the file as it
/// is (never merged), and serves the vault with them. Until the re-keyed
/// file arrives the vault stays served with the keys held. The primary's own
/// re-keyed save carries its new keys, which replace the old ones in the
/// device keychain. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
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

const _newTeamPassword = 'team-demo-pw-2';

Future<TomSecretsAdminException> _refused(Future<Object?> request) async {
  try {
    await request;
  } on TomSecretsAdminException catch (e) {
    return e;
  }
  fail('the request was not refused');
}

void main() {
  late Demo demo;
  late TomSecretsAdminClient admin;
  late TomInMemorySecretStore keychain;

  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  Future<TomSecretsService> start({bool unlock = true}) async {
    final service = await demo.start(transport: transport, keychain: keychain);
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    if (unlock) await admin.unlock(primaryPassword);
    return service;
  }

  Future<String?> get(String ref) async {
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

  /// [store] as the app reads it: its keys, its copy and that copy opened.
  Future<
    ({Map<String, Object?> keys, Map<String, Object?> file, KdbxFile opened})
  >
  read(String store) async {
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
      outerKey: keys['outerKey'] as String?,
    );
    return (keys: keys, file: file, opened: opened);
  }

  /// Writes [change] of [store]'s entry into the primary through `save`.
  Future<void> list(
    String store,
    TomSecretsVaultKeys Function(TomSecretsVaultKeys old) change,
  ) async {
    final primary = await read('primary');
    final vaults = TomSecretsPrimaryVaults(primary.opened);
    vaults.put(change(vaults.byName(store)!));
    await admin.request('save', {
      'store': 'primary',
      'bytes': base64.encode(
        await tomSecretsEncodeStored(
          primary.file['location'] as String,
          primary.opened,
        ),
      ),
      'baseRevision': primary.file['revision'],
    });
  }

  TomSecretsVaultKeys withKeys(
    TomSecretsVaultKeys old, {
    String? password,
    Uint8List? keyFile,
    String? outerKey,
  }) => TomSecretsVaultKeys(
    name: old.name,
    locator: old.locator,
    password: password ?? old.password,
    keyFile: keyFile,
    outerKey: outerKey,
    githubToken: old.githubToken,
    githubTokenExpires: old.githubTokenExpires,
    expires: DateTime.utc(2027, 11, 15),
  );

  /// [read] of [store] re-encoded with [password] / [keyFile] / [outerKey].
  Future<Uint8List> rekeyed(
    ({Map<String, Object?> keys, Map<String, Object?> file, KdbxFile opened})
    vault, {
    required String password,
    Uint8List? keyFile,
    String? outerKey,
    TomSecretsOuterCipher cipher = TomSecretsOuterCipher.xchacha20Poly1305,
  }) {
    vault.opened.credentials = tomSecretsVaultCredentials(
      password: password,
      keyFile: keyFile,
    );
    return tomSecretsEncodeStored(
      vault.file['location'] as String,
      vault.opened,
      outerKey: outerKey,
      cipher: cipher,
    );
  }

  setUp(() async {
    demo = await Demo.create();
    keychain = TomInMemorySecretStore();
  });

  test(
    'a further vault: the new keys listed first, then the re-keyed file; '
    'taken with the listed keys, served with them, kept after the lock',
    () async {
      final service = await start();
      final team = await read('team');
      await list('team', (old) => withKeys(old, password: _newTeamPassword));
      // Listed but not saved yet: the vault stays served with the keys held,
      // also over a refresh (a rotation in progress).
      await admin.request('reload');
      expect(
        service.vaults.statusOf('team')!.state,
        TomSecretsStoreState.current,
      );
      expect(await get('team/Api/Token'), 'demo-api-token');

      final bytes = await rekeyed(team, password: _newTeamPassword);
      await admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(bytes),
        'baseRevision': team.file['revision'],
      });
      expect(File(demo.teamPath).readAsBytesSync(), bytes, reason: 'as it is');
      await KdbxFormat().read(
        File(demo.teamPath).readAsBytesSync(),
        Credentials(ProtectedValue.fromString(_newTeamPassword)),
      );
      expect(await get('team/Api/Token'), 'demo-api-token');
      final keys = await read('team');
      expect(keys.keys['password'], _newTeamPassword);

      // An ordinary edit afterwards goes out under the new keys.
      keys.opened.body.rootGroup
          .getAllEntries()
          .firstWhere((e) => e.label == 'Token')
          .setString(
            KdbxKeyCommon.PASSWORD,
            ProtectedValue.fromString('token-after-rotation'),
          );
      await admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(
          await tomSecretsEncodeStored(
            keys.file['location'] as String,
            keys.opened,
          ),
        ),
        'baseRevision': keys.file['revision'],
      });
      await admin.request('lock');
      await admin.unlock(primaryPassword);
      expect(
        service.vaults.statusOf('team')!.state,
        TomSecretsStoreState.current,
      );
      expect(await get('team/Api/Token'), 'token-after-rotation');
    },
  );

  test('a key file added, then a .tsmx vault\'s repository key and cipher '
      'changed', () async {
    // A second further vault, outer-encrypted, in the primary's list.
    final repoKey = TomSecretsRepositoryKey.generate();
    final secretsPath = '${demo.dir}/secrets.kdbx.tsmx';
    final secrets = tomSecretsNewVault(
      Credentials(ProtectedValue.fromString('secrets-demo-pw')),
      'secrets',
      argon2: testArgon2,
    );
    File(secretsPath).writeAsBytesSync(
      await tomSecretsEncodeStored(
        'file:$secretsPath',
        secrets,
        outerKey: repoKey.toBase64(),
      ),
    );
    final primary = await KdbxFormat().read(
      File(demo.primaryPath).readAsBytesSync(),
      Credentials(ProtectedValue.fromString(primaryPassword)),
    );
    TomSecretsPrimaryVaults(primary).put(
      TomSecretsVaultKeys(
        name: 'secrets',
        locator: 'file:$secretsPath',
        password: 'secrets-demo-pw',
        outerKey: repoKey.toBase64(),
      ),
    );
    File(demo.primaryPath).writeAsBytesSync(await primary.save());
    final service = await start();

    final keyFile = TomSecretsKeyFile.generate().toBytes();
    final team = await read('team');
    await list(
      'team',
      (old) => withKeys(old, password: teamPassword, keyFile: keyFile),
    );
    await admin.request('save', {
      'store': 'team',
      'bytes': base64.encode(
        await rekeyed(team, password: teamPassword, keyFile: keyFile),
      ),
      'baseRevision': team.file['revision'],
    });
    expect(
      base64.decode((await read('team')).keys['keyFile']! as String),
      keyFile,
    );

    final newKey = TomSecretsRepositoryKey.generate().toBase64();
    final vault = await read('secrets');
    expect(
      tomSecretsOuterCipherOf(base64.decode(vault.file['bytes'] as String)),
      TomSecretsOuterCipher.xchacha20Poly1305,
    );
    await list(
      'secrets',
      (old) => withKeys(old, password: 'secrets-demo-pw', outerKey: newKey),
    );
    await admin.request('save', {
      'store': 'secrets',
      'bytes': base64.encode(
        await rekeyed(
          vault,
          password: 'secrets-demo-pw',
          outerKey: newKey,
          cipher: TomSecretsOuterCipher.aes256Gcm,
        ),
      ),
      'baseRevision': vault.file['revision'],
    });
    final stored = File(secretsPath).readAsBytesSync();
    expect(tomSecretsOuterCipherOf(stored), TomSecretsOuterCipher.aes256Gcm);
    await expectLater(
      tomSecretsDecodeStored(
        'file:$secretsPath',
        stored,
        tomSecretsVaultCredentials(password: 'secrets-demo-pw'),
        outerKey: repoKey.toBase64(),
      ),
      throwsA(anything),
      reason: 'the old repository key opens it no more',
    );
    await admin.request('lock');
    await admin.unlock(primaryPassword);
    expect(
      service.vaults.statusOf('secrets')!.state,
      TomSecretsStoreState.current,
    );
    expect(
      service.vaults.statusOf('team')!.state,
      TomSecretsStoreState.current,
    );
  });

  test('refused: a re-keyed file over a moved file (stale_base), keys the '
      'primary does not list, new keys on a further vault', () async {
    final service = await start();
    final team = await read('team');
    final bytes = await rekeyed(team, password: _newTeamPassword);
    // Not listed yet: the file opens with no keys the service knows.
    final unlisted = await _refused(
      admin.request('save', {'store': 'team', 'bytes': base64.encode(bytes)}),
    );
    expect(unlisted.kind, 'malformed');
    expect(unlisted.details['reason'], 'bytes');

    await list('team', (old) => withKeys(old, password: _newTeamPassword));
    final withKeysField = await _refused(
      admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(bytes),
        'keys': {'password': _newTeamPassword},
      }),
    );
    expect(withKeysField.details['reason'], 'keys');

    // Another writer changed the file under the old keys meanwhile.
    final moved = await KdbxFormat().read(
      File(demo.teamPath).readAsBytesSync(),
      Credentials(ProtectedValue.fromString(teamPassword)),
    );
    moved.body.rootGroup.addEntry(
      KdbxEntry.create(moved, moved.body.rootGroup)
        ..setString(KdbxKeyCommon.TITLE, PlainValue('moved')),
    );
    File(demo.teamPath).writeAsBytesSync(await moved.save());
    final stale = await _refused(
      admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(bytes),
        'baseRevision': team.file['revision'],
      }),
    );
    expect(stale.kind, 'denied');
    expect(stale.details['reason'], 'stale_base');
    // Nothing changed: the moved file stays and is served as before.
    await KdbxFormat().read(
      File(demo.teamPath).readAsBytesSync(),
      Credentials(ProtectedValue.fromString(teamPassword)),
    );
    expect(
      service.vaults.statusOf('team')!.state,
      TomSecretsStoreState.current,
    );
  });

  test(
    'the primary\'s own keys: the re-keyed save carries them; the key '
    'file goes into the keychain; the next unlock takes the new ones',
    () async {
      await start();
      final primary = await read('primary');
      final keyFile = TomSecretsKeyFile.generate().toBytes();
      TomSecretsMetadata(
        store: 'primary',
        keysDue: DateTime.utc(2028, 11, 15),
      ).writeTo(primary.opened);
      final bytes = await rekeyed(
        primary,
        password: 'primary-demo-pw-2',
        keyFile: keyFile,
      );
      final malformed = await _refused(
        admin.request('save', {
          'store': 'primary',
          'bytes': base64.encode(bytes),
          'keys': {'password': 'primary-demo-pw-2', 'outerKey': 'not a key'},
        }),
      );
      expect(malformed.details['reason'], 'keys');
      await admin.request('save', {
        'store': 'primary',
        'bytes': base64.encode(bytes),
        'baseRevision': primary.file['revision'],
        'keys': {
          'password': 'primary-demo-pw-2',
          'keyFile': base64.encode(keyFile),
        },
      });
      expect(File(demo.primaryPath).readAsBytesSync(), bytes);
      final locator = TomSecretsVaultLocator.parse('file:${demo.primaryPath}');
      expect(
        base64.decode((await keychain.read(locator.keyFileHandle))!),
        keyFile,
      );
      expect((await read('primary')).keys['password'], 'primary-demo-pw-2');

      await admin.request('lock');
      final old = await _refused(admin.unlock(primaryPassword));
      expect(old.details['reason'], 'bad_password');
      await admin.unlock('primary-demo-pw-2');
      expect(await get('team/Api/Token'), 'demo-api-token');
      final keys = await admin.request('keys');
      expect(
        (keys['keys'] as List).cast<Map>().firstWhere(
          (k) => k['key'] == 'vault-keys:primary',
        )['expiresAt'],
        '2028-11-15T00:00:00.000Z',
      );
    },
  );

  test('a vault this machine does not serve: read before the primary lists '
      'its new keys, saved re-keyed after', () async {
    final service = await start();
    await service.deviceContainer!.write(
      const TomSecretsDeviceSettings(servedStores: []),
    );
    await admin.request('lock');
    await admin.unlock(primaryPassword);
    final team = await read('team');
    await list('team', (old) => withKeys(old, password: _newTeamPassword));
    // The file has not moved: the copy and the keys held stay.
    await admin.request('reload');
    expect((await read('team')).keys['password'], teamPassword);
    await admin.request('save', {
      'store': 'team',
      'bytes': base64.encode(await rekeyed(team, password: _newTeamPassword)),
      'baseRevision': team.file['revision'],
    });
    await KdbxFormat().read(
      File(demo.teamPath).readAsBytesSync(),
      Credentials(ProtectedValue.fromString(_newTeamPassword)),
    );
    expect((await read('team')).keys['password'], _newTeamPassword);
  });
}
