// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The editing path (DP-13, protocol.md 6.4): `vaultKeys` hands the app the
/// keys of the open vaults over the authenticated admin connection, and
/// `save` takes the app's edited file, writes it, reopens the store and
/// announces it; a file that moved meanwhile is merged three-way when the
/// app edited the service's copy. And the operational log, which never
/// holds a value, a password, a key or a token. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show
        TomSecretsDeviceSettings,
        TomSecretsKeyFile,
        tomSecretsBlobId,
        tomSecretsDecodeStored,
        tomSecretsEncodeStored,
        tomSecretsNewVault,
        tomSecretsVaultCredentials;
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

Credentials _team() => Credentials(ProtectedValue.fromString(teamPassword));

KdbxEntry _entry(KdbxFile file, String title) => file.body.rootGroup
    .getAllEntries()
    .firstWhere((e) => e.getString(KdbxKeyCommon.TITLE)?.getText() == title);

/// The team file at [path], read, changed by [edit] and saved: its bytes.
Future<Uint8List> _edited(
  Uint8List stored,
  void Function(KdbxFile file) edit,
) async {
  final file = await KdbxFormat().read(stored, _team());
  edit(file);
  return file.save();
}

void _setToken(KdbxFile file, String value) => _entry(
  file,
  'Token',
).setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(value));

void _addNote(KdbxFile file, String title) {
  final entry = KdbxEntry.create(file, file.body.rootGroup)
    ..setString(KdbxKeyCommon.TITLE, PlainValue(title));
  file.body.rootGroup.addEntry(entry);
}

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

  // Unix sockets on Linux and macOS, localhost TCP on Windows.
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  Future<void> start({bool unlock = true}) async {
    await demo.start(transport: transport);
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    if (unlock) await admin.unlock(primaryPassword);
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

  setUp(() async {
    demo = await Demo.create();
  });

  group('vaultKeys', () {
    test('the keys of the open vaults, the primary first; they open the '
        'files', () async {
      await start();
      final answer = await admin.request('vaultKeys');
      expect(answer['op'], 'vaultKeySet');
      final stores = (answer['stores'] as List).cast<Map>();
      expect(stores.map((s) => s['store']), ['primary', 'team']);
      expect(stores[0]['location'], 'file:${demo.primaryPath}');
      expect(stores[0]['keys'], {'password': primaryPassword});
      expect(stores[1]['location'], 'file:${demo.teamPath}');
      final keys = (stores[1]['keys'] as Map).cast<String, Object?>();
      final opened = await KdbxFormat().read(
        File(demo.teamPath).readAsBytesSync(),
        Credentials(ProtectedValue.fromString(keys['password']! as String)),
      );
      expect(
        _entry(opened, 'Token').getString(KdbxKeyCommon.PASSWORD)?.getText(),
        'demo-api-token',
      );

      final only = await admin.request('vaultKeys', {
        'stores': ['team'],
      });
      expect((only['stores'] as List).map((s) => (s as Map)['store']), [
        'team',
      ]);
      final missing = await _refused(
        admin.request('vaultKeys', {
          'stores': ['nope'],
        }),
      );
      expect(missing.kind, 'not_found');
    });

    test('a key file travels as base64', () async {
      final keyFile = TomSecretsKeyFile.generate();
      final primary = tomSecretsNewVault(
        keyFile.credentials(primaryPassword),
        'primary',
        argon2: testArgon2,
      );
      File(demo.primaryPath).writeAsBytesSync(await primary.save());
      await start(unlock: false);
      await admin.unlock(primaryPassword, keyFile: keyFile.toBytes());
      final answer = await admin.request('vaultKeys', {
        'stores': ['primary'],
      });
      final keys = ((answer['stores'] as List).single as Map)['keys'] as Map;
      expect(keys['password'], primaryPassword);
      expect(base64.decode(keys['keyFile'] as String), keyFile.toBytes());
    });

    test('locked: refused', () async {
      await start(unlock: false);
      expect((await _refused(admin.request('vaultKeys'))).kind, 'locked');
    });
  });

  group('vaultFile', () {
    test('the copy the service holds, its revision and location; edited and '
        'saved against that revision, it is written', () async {
      await start();
      final answer = await admin.request('vaultFile', {'store': 'team'});
      expect(answer['op'], 'vaultFileData');
      expect(answer['store'], 'team');
      expect(answer['location'], 'file:${demo.teamPath}');
      final stored = base64.decode(answer['bytes'] as String);
      expect(stored, File(demo.teamPath).readAsBytesSync());
      expect(answer['revision'], tomSecretsBlobId(stored));
      final file = await tomSecretsDecodeStored(
        answer['location'] as String,
        stored,
        tomSecretsVaultCredentials(password: teamPassword),
      );
      _setToken(file, 'token-from-the-app');
      await admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(
          await tomSecretsEncodeStored(answer['location'] as String, file),
        ),
        'baseRevision': answer['revision'],
      });
      expect(await get('team/Api/Token'), 'token-from-the-app');
    });

    test('a store that is not open, a missing name, a locked service: '
        'refused', () async {
      await start();
      expect(
        (await _refused(admin.request('vaultFile', {'store': 'nope'}))).kind,
        'not_found',
      );
      final malformed = await _refused(admin.request('vaultFile'));
      expect(malformed.kind, 'malformed');
      await admin.request('lock');
      expect(
        (await _refused(admin.request('vaultFile', {'store': 'team'}))).kind,
        'locked',
      );
    });
  });

  group('a vault this machine does not serve (BP-15)', () {
    /// Unlocked with the device settings serving only the primary.
    Future<TomSecretsService> primaryOnly() async {
      final service = await demo.start(transport: transport);
      admin = await TomSecretsAdminClient.connect(
        demo.runtime(transport),
        demo.adminKey,
      );
      addTearDown(admin.close);
      await admin.unlock(primaryPassword);
      await service.deviceContainer!.write(
        const TomSecretsDeviceSettings(servedStores: []),
      );
      await admin.request('lock');
      await admin.unlock(primaryPassword);
      return service;
    }

    test('listed in unserved, its keys only when named, never served to '
        'clients', () async {
      await primaryOnly();
      final all = await admin.request('vaultKeys');
      expect((all['stores'] as List).map((s) => (s as Map)['store']), [
        'primary',
      ]);
      expect(all['unserved'], [
        {'store': 'team', 'location': 'file:${demo.teamPath}'},
      ]);
      final named = await admin.request('vaultKeys', {
        'stores': ['team'],
      });
      final team = (named['stores'] as List).single as Map;
      expect(team['served'], isFalse);
      expect(team['location'], 'file:${demo.teamPath}');
      expect(team['keys'], {'password': teamPassword});
      await expectLater(get('team/Api/Token'), throwsA(anything));
      final status = await admin.request('status');
      expect((status['stores'] as List).map((s) => (s as Map)['name']), [
        'primary',
      ]);
    });

    test(
      'read from its location, edited and saved there; still not served',
      () async {
        await primaryOnly();
        final answer = await admin.request('vaultFile', {'store': 'team'});
        expect(answer['served'], isFalse);
        expect(answer['location'], 'file:${demo.teamPath}');
        final stored = base64.decode(answer['bytes'] as String);
        expect(stored, File(demo.teamPath).readAsBytesSync());
        final edited = await _edited(stored, (f) => _setToken(f, 'from-app'));
        await admin.request('save', {
          'store': 'team',
          'bytes': base64.encode(edited),
          'baseRevision': answer['revision'],
        });
        final written = await KdbxFormat().read(
          File(demo.teamPath).readAsBytesSync(),
          _team(),
        );
        expect(
          _entry(written, 'Token').getString(KdbxKeyCommon.PASSWORD)?.getText(),
          'from-app',
        );
        // The held copy is the written one: its revision is the next base.
        final again = await admin.request('vaultFile', {'store': 'team'});
        expect(
          again['revision'],
          tomSecretsBlobId(File(demo.teamPath).readAsBytesSync()),
        );
        await expectLater(get('team/Api/Token'), throwsA(anything));
        // A stale base is refused as for a served store.
        final stale = await _refused(
          admin.request('save', {
            'store': 'team',
            'bytes': base64.encode(edited),
            'baseRevision': 'not-a-revision',
          }),
        );
        expect(stale.details['reason'], 'stale_base');
      },
    );

    test('listed keys that do not open it: needs_unlock; a vault the primary '
        'does not list: not_found; the lock drops the copy', () async {
      final service = await primaryOnly();
      // The team file now has another password than the primary lists.
      final other = tomSecretsNewVault(
        Credentials(ProtectedValue.fromString('another-demo-password')),
        'team',
        argon2: testArgon2,
      );
      final original = File(demo.teamPath).readAsBytesSync();
      File(demo.teamPath).writeAsBytesSync(await other.save());
      final refused = await _refused(
        admin.request('vaultFile', {'store': 'team'}),
      );
      expect(refused.kind, 'needs_unlock');
      expect(
        (await _refused(admin.request('vaultFile', {'store': 'nope'}))).kind,
        'not_found',
      );
      File(demo.teamPath).writeAsBytesSync(original);
      await admin.request('vaultFile', {'store': 'team'});
      await admin.request('lock');
      expect(service.vaults.unserved, isEmpty);
      final save = await _refused(
        admin.request('save', {
          'store': 'team',
          'bytes': base64.encode(original),
        }),
      );
      expect(save.kind, 'locked');
    });
  });

  group('save', () {
    test('an edited file is written as it is, served, and announced', () async {
      await start();
      await admin.request('subscribe');
      final changed = admin.events.firstWhere(
        (e) => e['op'] == 'store_changed',
      );
      final before = File(demo.teamPath).readAsBytesSync();
      final edited = await _edited(before, (f) => _setToken(f, 'token-2'));
      final answer = await admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(edited),
        'baseRevision': tomSecretsBlobId(before),
      });
      // Written as it was sent: the answer names the file's revision and
      // no merge, so the app keeps its copy and reads nothing back.
      expect(answer['revision'], tomSecretsBlobId(edited));
      expect(answer.containsKey('merged'), isFalse);
      expect(answer.containsKey('pending'), isFalse);
      expect(File(demo.teamPath).readAsBytesSync(), edited);
      final event = await changed;
      expect(event['store'], 'team');
      expect(event['revision'], tomSecretsBlobId(edited));
      expect(await get('team/Api/Token'), 'token-2');
    });

    test('without a base the file is taken as it is', () async {
      await start();
      final edited = await _edited(
        File(demo.teamPath).readAsBytesSync(),
        (f) => _setToken(f, 'token-3'),
      );
      await admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(edited),
      });
      expect(await get('team/Api/Token'), 'token-3');
    });

    test('a file that moved is merged when the app edited the service\'s '
        'copy; any other base is refused', () async {
      await start();
      final held = File(demo.teamPath).readAsBytesSync();
      // Another writer changes the file after the service read it.
      File(demo.teamPath).writeAsBytesSync(
        await _edited(held, (f) => _addNote(f, 'Written meanwhile')),
      );
      final edited = await _edited(held, (f) => _setToken(f, 'token-4'));
      final answer = await admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(edited),
        'baseRevision': tomSecretsBlobId(held),
      });
      // Merged: the answer says so, and names what is there now (the app
      // reads it again).
      expect(answer['merged'], isTrue);
      expect(
        answer['revision'],
        tomSecretsBlobId(File(demo.teamPath).readAsBytesSync()),
      );
      expect(answer['revision'], isNot(tomSecretsBlobId(edited)));
      final merged = await KdbxFormat().read(
        File(demo.teamPath).readAsBytesSync(),
        _team(),
      );
      expect(_entry(merged, 'Written meanwhile'), isNotNull);
      expect(
        _entry(merged, 'Token').getString(KdbxKeyCommon.PASSWORD)?.getText(),
        'token-4',
      );
      expect(await get('team/Api/Token'), 'token-4');

      final stale = await _refused(
        admin.request('save', {
          'store': 'team',
          'bytes': base64.encode(edited),
          'baseRevision': 'b1946ac92492d2347c6235b4d2611184f1d4b1e6',
        }),
      );
      expect(stale.kind, 'denied');
      expect(stale.details['reason'], 'stale_base');
    });

    test('a file that does not open with the store\'s keys, bytes that are '
        'no base64, an unknown store, a locked service: refused', () async {
      await start();
      final wrong = await _refused(
        admin.request('save', {
          'store': 'team',
          'bytes': base64.encode(File(demo.primaryPath).readAsBytesSync()),
        }),
      );
      expect(wrong.kind, 'malformed');
      expect(wrong.details['reason'], 'bytes');
      final notBase64 = await _refused(
        admin.request('save', {'store': 'team', 'bytes': '%%%'}),
      );
      expect(notBase64.details['reason'], 'bytes');
      final unknown = await _refused(
        admin.request('save', {'store': 'nope', 'bytes': 'AAAA'}),
      );
      expect(unknown.kind, 'not_found');
      expect(await get('team/Api/Token'), 'demo-api-token', reason: 'kept');
      await admin.request('lock');
      final locked = await _refused(
        admin.request('save', {'store': 'team', 'bytes': 'AAAA'}),
      );
      expect(locked.kind, 'locked');
    });
  });

  group('the operational log', () {
    test('never a value, password, key or token; references only at debug '
        'level', () async {
      demo.bootstrap = TomSecretsBootstrap(
        primary: demo.bootstrap.primary,
        dataDirectory: demo.bootstrap.dataDirectory,
        deviceKey: demo.bootstrap.deviceKey,
        logLevel: TomSecretsLogLevel.debug,
      );
      await start();
      expect(await get('primary/Db/Main'), 'demo-db-pw');
      await admin.request('vaultKeys');
      await admin.request('lock');
      await _refused(admin.unlock('a-wrong-demo-password'));
      await admin.unlock(primaryPassword);
      final edited = await _edited(
        File(demo.teamPath).readAsBytesSync(),
        (f) => _setToken(f, 'token-in-a-save'),
      );
      await admin.request('save', {
        'store': 'team',
        'bytes': base64.encode(edited),
      });
      final log = File(demo.bootstrap.logFile).readAsStringSync();
      for (final line in [
        ' INFO start ',
        ' INFO unlock ',
        ' INFO get outcome=value',
        ' DEBUG get refs=primary/Db/Main',
        ' DEBUG client name=demo-client',
        ' INFO vault_keys stores=2',
        ' INFO unlock_refused reason=bad_password',
        ' INFO save store=team merged=false conflicts=0',
      ]) {
        expect(log, contains(line));
      }
      for (final secret in [
        primaryPassword,
        teamPassword,
        'a-wrong-demo-password',
        'demo-db-pw',
        'demo-api-token',
        'token-in-a-save',
        base64.encode(demo.adminKey),
      ]) {
        expect(log, isNot(contains(secret)), reason: 'no secret in the log');
      }
    });

    test('at info level no reference or identity', () async {
      await start();
      expect(await get('primary/Db/Main'), 'demo-db-pw');
      final log = File(demo.bootstrap.logFile).readAsStringSync();
      expect(log, contains(' INFO get outcome=value'));
      expect(log, isNot(contains('primary/Db/Main')));
      expect(log, isNot(contains('demo-client')));
    });

    test('rotated by size, keeping the newest files', () {
      final dir = Directory.systemTemp.createTempSync('tsmlog');
      addTearDown(() => dir.deleteSync(recursive: true));
      final log = TomSecretsLog(
        '${dir.path}/service.log',
        maxBytes: 300,
        keep: 2,
      );
      for (var i = 0; i < 40; i++) {
        log.info('event', {'n': i, 'text': 'line\nbreak'});
      }
      final names = dir.listSync().map((f) => f.uri.pathSegments.last).toSet();
      expect(names, {'service.log', 'service.log.1', 'service.log.2'});
      for (final f in dir.listSync().cast<File>()) {
        expect(f.lengthSync(), lessThanOrEqualTo(300));
      }
      final last = File('${dir.path}/service.log').readAsLinesSync().last;
      expect(last, endsWith('INFO event n=39 text=line?break'));
    });

    test('an exception by its type and code, never its message', () {
      final dir = Directory.systemTemp.createTempSync('tsmlog');
      addTearDown(() => dir.deleteSync(recursive: true));
      final log = TomSecretsLog('${dir.path}/service.log');
      log.error(
        'save_failed',
        const FileSystemException(
          'cannot write secret-in-message',
          '/x',
          OSError('denied', 13),
        ),
      );
      final line = File('${dir.path}/service.log').readAsStringSync();
      expect(
        line,
        contains('ERROR save_failed error=FileSystemException code=13'),
      );
      expect(line, isNot(contains('secret-in-message')));
    });
  });
}
