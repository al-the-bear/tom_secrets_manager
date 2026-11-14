// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The secrets service (part-service, part-protocol, DP-14, DP-15): the
/// runtime directory and its lock, the client endpoint over a Unix socket
/// and over localhost TCP with the client token, the admin channel's mutual
/// challenge and `claim`, unlock and lock, the lock modes, and the device
/// settings container with its key modes. Demo data only.
@TestOn('mac-os || linux')
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_core_storage/io.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// A raw protocol connection: frames in, frames out.
final class Raw {
  Raw._(this.socket) {
    socket.listen(
      (bytes) {
        for (final f in reader.add(bytes)) {
          final m = tomSecretsDecodePayload(f.payload);
          if (waiting.isNotEmpty) {
            waiting.removeFirst().complete(m);
          } else {
            queue.add(m);
          }
        }
      },
      onDone: () {
        closed.complete();
        while (waiting.isNotEmpty) {
          waiting.removeFirst().completeError(StateError('closed'));
        }
      },
    );
  }

  static Future<Raw> connect(
    TomSecretsRuntime runtime, {
    bool admin = false,
  }) async {
    final socket = runtime.transport == TomSecretsTransport.unix
        ? await Socket.connect(
            InternetAddress(
              admin ? runtime.adminSocket : runtime.clientSocket,
              type: InternetAddressType.unix,
            ),
            0,
          )
        : await Socket.connect(
            InternetAddress.loopbackIPv4,
            readTomSecretsPortFile(
              File(
                admin ? runtime.adminPortFile : runtime.clientPortFile,
              ).readAsStringSync(),
            )!,
          );
    addTearDown(socket.destroy);
    return Raw._(socket);
  }

  final Socket socket;
  final TomSecretsFrameReader reader = TomSecretsFrameReader(
    maxPayload: tomSecretsMaxAnswerPayload,
  );
  final Queue<Map<String, Object?>> queue = Queue();
  final Queue<Completer<Map<String, Object?>>> waiting = Queue();
  final Completer<void> closed = Completer();

  void send(Map<String, Object?> m) => socket.add(tomSecretsJsonFrame(m));

  Future<Map<String, Object?>> next() {
    if (queue.isNotEmpty) return Future.value(queue.removeFirst());
    final c = Completer<Map<String, Object?>>();
    waiting.add(c);
    return c.future.timeout(const Duration(seconds: 10));
  }
}

Map<String, Object?> hello([Map<String, Object?> extra = const {}]) => {
  'op': 'hello',
  'protocol': 1,
  'client': {'name': 'demo', 'version': '1', 'language': 'dart'},
  ...extra,
};

void main() {
  group('the runtime directory', () {
    test('made 0700 at the start; one instance only; endpoints, service.json '
        'and the lock gone at the stop', () async {
      final demo = await Demo.create();
      final service = await demo.start();
      final runtime = demo.runtime();
      final stat = FileStat.statSync(runtime.directory);
      expect(stat.mode & 0x1FF, 0x1C0, reason: 'mode 0700');
      expect(
        FileSystemEntity.typeSync(runtime.clientSocket),
        FileSystemEntityType.unixDomainSock,
      );
      final info = jsonDecode(File(runtime.infoFile).readAsStringSync()) as Map;
      expect(info['pid'], pid);
      expect(info['start'], service.startedAt);
      expect(info['protocol'], 1);
      expect(info['client'], {'socket': runtime.clientSocket});

      await expectLater(demo.start(), throwsA(isA<TomSecretsAlreadyRunning>()));
      await service.stop();
      expect(File(runtime.infoFile).existsSync(), isFalse);
      expect(
        FileSystemEntity.typeSync(runtime.clientSocket),
        FileSystemEntityType.notFound,
      );
      final again = await demo.start();
      expect(again.isLocked, isTrue, reason: 'the lock was released');
    });

    test('a directory open to others is refused; a dead instance\'s socket '
        'is removed after the lock is taken', () async {
      final demo = await Demo.create();
      final runtime = demo.runtime();
      Directory(runtime.directory).createSync(recursive: true);
      Process.runSync('chmod', ['755', runtime.directory]);
      await expectLater(
        demo.start(),
        throwsA(isA<TomSecretsRuntimeException>()),
      );
      Process.runSync('chmod', ['700', runtime.directory]);
      File(runtime.clientSocket).writeAsStringSync('stale');
      final service = await demo.start();
      expect(
        FileSystemEntity.typeSync(runtime.clientSocket),
        FileSystemEntityType.unixDomainSock,
      );
      expect(service.isLocked, isTrue);
    });
  });

  test('the admins: tsm and the app beside the service, the app of the '
      'distribution around it, the bootstrap\'s admin_executables', () {
    final root = Directory.systemTemp.createTempSync('tsmdist');
    addTearDown(() => root.deleteSync(recursive: true));
    final macos = Platform.isMacOS;
    final ext = Platform.isWindows ? '.exe' : '';
    final appDir = macos
        ? '${root.path}/Tom Secrets Manager.app/Contents/MacOS'
        : '${root.path}/app';
    final toolsDir = macos
        ? '${root.path}/Tom Secrets Manager.app/Contents/Resources/tsm/bin'
        : '$appDir/tsm/bin';
    final app = File('$appDir/tom_secrets_app$ext')
      ..createSync(recursive: true);
    final service = File('$toolsDir/tom_secrets_service$ext')
      ..createSync(recursive: true);
    final tsm = File('$toolsDir/tsm$ext')..createSync();
    final admins = tomSecretsAdminExecutables(
      service.path,
      TomSecretsBootstrap(
        primary: 'file:/demo/primary.kdbx',
        dataDirectory: '${root.path}/data',
        adminExecutables: ['${root.path}/dev/tom_secrets_app$ext'],
      ),
    );
    expect(admins, contains(app.resolveSymbolicLinksSync()));
    expect(admins, contains(tsm.resolveSymbolicLinksSync()));
    expect(admins, contains('${root.path}/dev/tom_secrets_app$ext'));
  });

  group('the admin channel', () {
    test('the mutual challenge matches protocol/vectors/hmac.json', () {
      final vectors =
          jsonDecode(
                File(
                  '../../secrets_clients/protocol/vectors/hmac.json',
                ).readAsStringSync(),
              )
              as Map;
      for (final c in (vectors['cases'] as List).cast<Map>()) {
        final key = base64.decode(c['adminKey'] as String);
        final sn = base64.decode(c['serviceNonce'] as String);
        final an = base64.decode(c['adminNonce'] as String);
        final start = c['serviceStart'] as int;
        expect(
          base64.encode(
            tomSecretsChallengeMac(key, tomSecretsAdminLabel, sn, an, start),
          ),
          c['mac'],
          reason: '${c['name']}',
        );
        expect(
          base64.encode(
            tomSecretsChallengeMac(key, tomSecretsServiceLabel, sn, an, start),
          ),
          c['mac2'],
        );
      }
      expect(tomSecretsAuthDelay(0), Duration.zero);
      expect(tomSecretsAuthDelay(1), const Duration(seconds: 1));
      expect(tomSecretsAuthDelay(3), const Duration(seconds: 4));
      expect(tomSecretsAuthDelay(20), const Duration(seconds: 60));
    });

    test('the right key: authed, mac2 checked; a wrong key: denied bad_mac, '
        'the connection closed, the next attempt delayed', () async {
      final demo = await Demo.create();
      final delays = <int>[];
      await demo.start(
        authDelay: (n) {
          delays.add(n);
          return Duration(milliseconds: 5 * n);
        },
      );
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      final status = await admin.request('status');
      expect(status['locked'], isTrue);
      expect(status['protocol'], 1);
      await admin.close();

      await expectLater(
        TomSecretsAdminClient.connect(demo.runtime(), tomSecretsRandomBytes()),
        throwsA(
          isA<TomSecretsAdminException>()
              .having((e) => e.kind, 'kind', 'denied')
              .having((e) => e.details['reason'], 'reason', 'bad_mac'),
        ),
      );
      await expectLater(
        TomSecretsAdminClient.connect(demo.runtime(), tomSecretsRandomBytes()),
        throwsA(isA<TomSecretsAdminException>()),
      );
      expect(delays, [0, 0, 1], reason: 'failures counted into the delay');

      final raw = await Raw.connect(demo.runtime(), admin: true);
      expect((await raw.next())['op'], 'challenge');
      raw.send({'op': 'status', 'id': 1});
      final refused = await raw.next();
      expect(refused['kind'], 'malformed');
      await raw.closed.future;
    });

    test('a service that does not hold the key is caught by mac2', () async {
      // A fake "service" answering authed with a made-up mac2.
      final demo = await Demo.create();
      final runtime = demo.runtime();
      await runtime.prepare();
      final server = await ServerSocket.bind(
        InternetAddress(runtime.adminSocket, type: InternetAddressType.unix),
        0,
      );
      addTearDown(server.close);
      server.listen((s) {
        s.add(
          tomSecretsJsonFrame({
            'op': 'challenge',
            'serviceNonce': base64.encode(tomSecretsRandomBytes()),
            'serviceStart': 1,
            'protocol': 1,
            'service': {'version': 'impostor'},
          }),
        );
        s.listen(
          (_) => s.add(
            tomSecretsJsonFrame({
              'op': 'authed',
              'mac2': base64.encode(tomSecretsRandomBytes()),
            }),
          ),
        );
      });
      await expectLater(
        TomSecretsAdminClient.connect(runtime, demo.adminKey),
        throwsA(
          isA<TomSecretsAdminException>().having(
            (e) => e.kind,
            'kind',
            'service_impostor',
          ),
        ),
      );
    });

    test('claim: a wrong password is denied; the right one, locked or '
        'unlocked, issues a new key and revokes the old', () async {
      final demo = await Demo.create();
      final service = await demo.start();
      final runtime = demo.runtime();
      await expectLater(
        TomSecretsAdminClient.claim(runtime, password: 'wrong'),
        throwsA(
          isA<TomSecretsAdminException>().having(
            (e) => e.details['reason'],
            'reason',
            'bad_password',
          ),
        ),
      );
      final first = await TomSecretsAdminClient.connect(runtime, demo.adminKey);
      final (claimer, newKey) = await TomSecretsAdminClient.claim(
        runtime,
        password: primaryPassword,
      );
      expect(newKey, hasLength(32));
      expect(newKey, isNot(demo.adminKey));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(first.isClosed, isTrue, reason: 'the old key\'s admin dropped');
      await expectLater(
        TomSecretsAdminClient.connect(runtime, demo.adminKey),
        throwsA(isA<TomSecretsAdminException>()),
        reason: 'the old key is revoked',
      );
      await claimer.unlock(primaryPassword);
      expect(service.isLocked, isFalse);
      final again = await TomSecretsAdminClient.connect(runtime, newKey);
      final (_, newer) = await TomSecretsAdminClient.claim(
        runtime,
        password: primaryPassword,
      );
      expect(newer, isNot(newKey), reason: 'claimed while unlocked too');
      await again.close();
    });

    test('unlock: a wrong password denied; the right one opens the primary '
        'and the vault it names; status, lock and shutdown', () async {
      final demo = await Demo.create();
      final service = await demo.start();
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      await admin.request('subscribe');
      final events = <String>[];
      admin.events.listen((e) => events.add(e['op']! as String));
      await expectLater(
        admin.unlock('wrong'),
        throwsA(
          isA<TomSecretsAdminException>().having(
            (e) => e.details['reason'],
            'reason',
            'bad_password',
          ),
        ),
      );
      await admin.unlock(primaryPassword);
      final status = await admin.request('status');
      expect(status['locked'], isFalse);
      expect((status['stores'] as List).map((s) => (s as Map)['name']), [
        'primary',
        'team',
      ]);
      expect((status['stores'] as List).map((s) => (s as Map)['state']), [
        'current',
        'current',
      ]);
      expect((status['stores'] as List).map((s) => (s as Map)['source']), [
        'file',
        'file',
      ]);
      expect(status['lockMode'], 'b', reason: 'lock mode (b), on idle');
      expect(await admin.request('reload'), {'op': 'ok', 'id': isA<int>()});
      expect(status['expiring'], isEmpty);
      await admin.request('lock');
      await expectLater(
        admin.request('reload'),
        throwsA(
          isA<TomSecretsAdminException>().having(
            (e) => e.kind,
            'kind',
            'locked',
          ),
        ),
      );
      expect(service.isLocked, isTrue);
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(events, containsAllInOrder(['unlocked', 'locked']));
      await admin.request('shutdown');
      await service.done;
      expect(File(demo.runtime().infoFile).existsSync(), isFalse);
    });

    test('a .tsmx primary with a key file: its key file and repository key '
        'from the keychain, the master password alone unlocks; the '
        'service\'s own write keeps it .tsmx and AES-256-GCM', () async {
      final demo = await Demo.create(deviceKey: TomSecretsDeviceKeyMode.vault);
      final keyFile = TomSecretsKeyFile.generate().toBytes();
      final repositoryKey = TomSecretsRepositoryKey.generate();
      final path = '${demo.dir}/primary.kdbx.tsmx';
      final locator = TomSecretsVaultLocator.parse('file:$path');
      final primary = tomSecretsNewVault(
        tomSecretsVaultCredentials(password: primaryPassword, keyFile: keyFile),
        'primary',
        argon2: testArgon2,
      );
      File(path).writeAsBytesSync(
        await tomSecretsEncodeStored(
          locator.text,
          primary,
          outerKey: repositoryKey.toBase64(),
          cipher: TomSecretsOuterCipher.aes256Gcm,
        ),
      );
      demo.bootstrap = TomSecretsBootstrap(
        primary: locator.text,
        dataDirectory: '${demo.dir}/data',
        deviceKey: TomSecretsDeviceKeyMode.vault,
      );
      final keychain = TomInMemorySecretStore();
      await keychain.write(locator.keyFileHandle, base64.encode(keyFile));
      await keychain.write(
        locator.repositoryKeyHandle,
        repositoryKey.toBase64(),
      );
      final service = await demo.start(keychain: keychain);
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      await admin.unlock(primaryPassword);
      expect(service.isLocked, isFalse);
      // The vault mode wrote the device settings key into the primary.
      final written = File(path).readAsBytesSync();
      expect(tomSecretsOuterCipherOf(written), TomSecretsOuterCipher.aes256Gcm);
      final reread = await tomSecretsDecodeStored(
        locator.text,
        written,
        tomSecretsVaultCredentials(password: primaryPassword, keyFile: keyFile),
        outerKey: repositoryKey.toBase64(),
      );
      expect(
        reread.body.rootGroup.getAllEntries().map((e) => e.label),
        contains('device'),
      );
      await admin.request('lock');

      // Without the key file in the keychain, the password alone is wrong.
      await keychain.delete(locator.keyFileHandle);
      await expectLater(
        admin.unlock(primaryPassword),
        throwsA(
          isA<TomSecretsAdminException>().having(
            (e) => e.details['reason'],
            'reason',
            'bad_password',
          ),
        ),
      );
      await admin.unlock(primaryPassword, keyFile: keyFile);
      expect(service.isLocked, isFalse);
    });

    test('a vault whose key does not open is needs_unlock; unlockStore opens '
        'it with its own password', () async {
      final demo = await Demo.create();
      // The team vault gets another password; the primary still names the
      // old one.
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
      await admin.unlock(primaryPassword);
      final status = await admin.request('status');
      expect((status['stores'] as List).map((s) => (s as Map)['state']), [
        'current',
        'needs_unlock',
      ]);
      final client = await TomSecretsClient.connect(
        environment: demo.clientEnvironment(),
      );
      addTearDown(client.close);
      await expectLater(
        client.get('team/Api/Token'),
        throwsA(
          isA<TomSecretsClientException>().having(
            (e) => e.kind,
            'kind',
            TomSecretsErrorKind.needsUnlock,
          ),
        ),
      );
      await admin.request('unlockStore', {
        'store': 'team',
        'password': 'changed-pw',
      });
      expect((await client.get('team/Api/Token')).text, 'demo-api-token');
    });
  });

  group('the client endpoint', () {
    test('hello, then get and getMany through the client library', () async {
      final demo = await Demo.create();
      await demo.start();
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      await admin.unlock(primaryPassword);
      final client = await TomSecretsClient.connect(
        clientName: 'demo-client',
        environment: demo.clientEnvironment(),
      );
      addTearDown(client.close);
      final value = await client.get('primary/Db/Main');
      expect(value.text, 'demo-db-pw');
      expect(value.entry.store, 'primary');
      expect(value.entry.source, TomSecretSource.file, reason: 'a file: vault');
      expect(value.version.revision, hasLength(40));
      final many = await client.getMany([
        const TomSecretRequest('primary/Db/Main'),
        const TomSecretRequest('team/Api/Token'),
        const TomSecretRequest('primary/Nope'),
      ]);
      expect(many[0].value!.text, 'demo-db-pw');
      expect(many[1].value!.text, 'demo-api-token');
      expect(many[2].error!.kind, TomSecretsErrorKind.notFound);
      await expectLater(
        client.get('primary/Db/Main#KPEX_PASSKEY_PRIVATE_KEY_PEM'),
        throwsA(
          isA<TomSecretsClientException>().having(
            (e) => e.reason,
            'reason',
            'reserved_field',
          ),
        ),
      );
    });

    test('the default policy refuses every value', () async {
      final demo = await Demo.create();
      await demo.start(policy: const TomSecretsDenyAllPolicy());
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      await admin.unlock(primaryPassword);
      final client = await TomSecretsClient.connect(
        environment: demo.clientEnvironment(),
      );
      addTearDown(client.close);
      await expectLater(
        client.get('primary/Db/Main'),
        throwsA(
          isA<TomSecretsClientException>()
              .having((e) => e.kind, 'kind', TomSecretsErrorKind.denied)
              .having((e) => e.reason, 'reason', 'no_approver'),
        ),
      );
    });

    test('locked: no admin, locked at once; an admin subscribed, '
        'unlock_needed and progress, the answer after the unlock', () async {
      final demo = await Demo.create();
      await demo.start();
      final client = await TomSecretsClient.connect(
        environment: demo.clientEnvironment(),
      );
      addTearDown(client.close);
      await expectLater(
        client.get('primary/Db/Main'),
        throwsA(
          isA<TomSecretsClientException>().having(
            (e) => e.kind,
            'kind',
            TomSecretsErrorKind.locked,
          ),
        ),
      );
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      await admin.request('subscribe');
      final needed = admin.events.firstWhere((e) => e['op'] == 'unlock_needed');
      final pending = <String>[];
      final answer = client.get(
        'primary/Db/Main',
        onProgress: (p) => pending.add(p.pending.name),
      );
      final event = await needed;
      final identity = event['identity']! as Map;
      expect(identity['kind'], 'script', reason: 'the measured test process');
      expect(identity['uid'], tomSecretsOwnUid());
      await admin.unlock(primaryPassword);
      expect((await answer).text, 'demo-db-pw');
      expect(pending, ['unlock']);
    });

    test('protocol rules on raw frames: the first frame is hello, another '
        'protocol is unsupported, an unknown op keeps the connection, a '
        'duplicate id is refused, an oversized frame closes', () async {
      final demo = await Demo.create();
      await demo.start();
      final runtime = demo.runtime();

      var raw = await Raw.connect(runtime);
      raw.send({'op': 'get', 'id': 1, 'ref': 'x/y'});
      expect((await raw.next())['kind'], 'malformed');
      await raw.closed.future;

      raw = await Raw.connect(runtime);
      raw.send(hello({'protocol': 2}));
      final unsupported = await raw.next();
      expect(unsupported['kind'], 'unsupported');
      expect((unsupported['details']! as Map)['protocols'], [1]);
      await raw.closed.future;

      raw = await Raw.connect(runtime);
      raw.send(hello());
      final welcome = await raw.next();
      expect(welcome['op'], 'welcome');
      expect(welcome['host'], 'demo-host');
      expect(welcome['features'], isEmpty);
      raw.send({'op': 'getFile', 'id': 7, 'ref': 'x/y'});
      expect(await raw.next(), containsPair('kind', 'unsupported'));
      raw.send({'op': 'get', 'id': 8, 'ref': 'primary/Db/Main', 'wait': false});
      expect(await raw.next(), containsPair('kind', 'locked'));
      raw.send({'op': 'get', 'id': 1 << 54, 'ref': 'x/y'});
      expect(await raw.next(), containsPair('kind', 'malformed'));
      await raw.closed.future;

      raw = await Raw.connect(runtime);
      raw.send(hello());
      await raw.next();
      final header = ByteData(5)
        ..setUint32(0, tomSecretsMaxRequestPayload + 1)
        ..setUint8(4, 0);
      raw.socket.add(header.buffer.asUint8List());
      await raw.closed.future.timeout(const Duration(seconds: 5));
    });

    test('over TCP (Windows): ports and the client token in the runtime '
        'directory; a wrong token is denied bad_token', () async {
      final demo = await Demo.create();
      final service = await demo.start(transport: TomSecretsTransport.tcp);
      final runtime = demo.runtime(TomSecretsTransport.tcp);
      final token = File(runtime.clientTokenFile).readAsStringSync().trim();
      expect(token, service.clientToken);
      expect(base64.decode(token), hasLength(32));

      var raw = await Raw.connect(runtime);
      raw.send(hello({'token': 'not-the-token'}));
      final denied = await raw.next();
      expect(denied['kind'], 'denied');
      expect((denied['details']! as Map)['reason'], 'bad_token');
      await raw.closed.future;

      final admin = await TomSecretsAdminClient.connect(runtime, demo.adminKey);
      await admin.unlock(primaryPassword);
      raw = await Raw.connect(runtime);
      raw.send(hello({'token': token}));
      expect((await raw.next())['op'], 'welcome');
      raw.send({'op': 'get', 'id': 1, 'ref': 'team/Api/Token'});
      final value = await raw.next();
      expect(value['op'], 'value');
      expect(value['value'], 'demo-api-token');
      expect(value['encoding'], 'utf8');
    });
  });

  group('lock modes (DP-14)', () {
    test('the policy: (a) never relocks, (b) after the idle period, the '
        'maximum unlocked time, headless never', () {
      const never = TomSecretsLockPolicy(mode: TomSecretsLockMode.never);
      const idle = TomSecretsLockPolicy(idle: Duration(minutes: 5));
      const capped = TomSecretsLockPolicy(
        mode: TomSecretsLockMode.never,
        maxUnlocked: Duration(hours: 8),
      );
      const h = Duration(hours: 1);
      expect(
        never.shouldLock(idle: const Duration(days: 1), unlockedFor: h),
        isFalse,
      );
      expect(
        idle.shouldLock(idle: const Duration(minutes: 4), unlockedFor: h),
        isFalse,
      );
      expect(
        idle.shouldLock(idle: const Duration(minutes: 5), unlockedFor: h),
        isTrue,
      );
      expect(
        capped.shouldLock(
          idle: Duration.zero,
          unlockedFor: const Duration(hours: 8),
        ),
        isTrue,
      );
      expect(
        capped.shouldLock(idle: null, unlockedFor: const Duration(days: 9)),
        isFalse,
        reason: 'headless never locks automatically',
      );
      expect(
        TomSecretsLockPolicy.fromJson(capped.toJson()).maxUnlocked,
        const Duration(hours: 8),
      );
    });

    test('the service relocks on idle, and not while headless', () async {
      final demo = await Demo.create();
      final service = await demo.start();
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      Future<void> configure() async {
        await admin.unlock(primaryPassword);
        await service.deviceContainer!.write(
          const TomSecretsDeviceSettings(
            serviceLock: TomSecretsLockPolicy(
              idle: Duration(milliseconds: 100),
            ),
          ),
        );
        await admin.request('lock');
      }

      await configure();
      demo.idle.idle = null; // headless
      await admin.unlock(primaryPassword);
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(service.isLocked, isFalse, reason: 'headless');
      demo.idle.idle = const Duration(seconds: 1);
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(service.isLocked, isTrue, reason: 'idle past the period');
    });

    test(
      'the system idle source answers on this machine (or headless)',
      () async {
        final idle = await tomSecretsSystemIdleSource().idleTime();
        if (Platform.isMacOS) {
          expect(idle, isNotNull);
          expect(idle!, greaterThanOrEqualTo(Duration.zero));
        }
      },
    );
  });

  group('the device settings container (DP-15)', () {
    Future<(TomSecretsService, TomSecretsAdminClient)> unlocked(
      Demo demo, {
      TomSecretStore? keychain,
    }) async {
      final service = await demo.start(keychain: keychain);
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(),
        demo.adminKey,
      );
      await admin.unlock(primaryPassword);
      return (service, admin);
    }

    test(
      'settings are kept encrypted and read back after the next unlock',
      () async {
        final demo = await Demo.create();
        final (service, admin) = await unlocked(demo);
        expect(service.settings.refreshMinutes, 5, reason: 'the defaults');
        await service.deviceContainer!.write(
          const TomSecretsDeviceSettings(
            defaultEnvironment: 'prod',
            refreshMinutes: 0,
            serviceLock: TomSecretsLockPolicy(mode: TomSecretsLockMode.never),
          ),
        );
        await admin.request('lock');
        expect(service.deviceContainer, isNull);
        await admin.unlock(primaryPassword);
        expect(service.settings.defaultEnvironment, 'prod');
        expect(service.settings.refreshMinutes, 0);
        expect(service.settings.serviceLock.mode, TomSecretsLockMode.never);
        final bytes = File(demo.bootstrap.deviceContainer).readAsBytesSync();
        expect(
          utf8.decode(bytes, allowMalformed: true),
          isNot(contains('prod')),
        );
      },
    );

    test('keyfile: a 0600 key file beside the container', () async {
      final demo = await Demo.create();
      await unlocked(demo);
      final keyFile = File('${demo.bootstrap.deviceContainer}.key');
      expect(keyFile.existsSync(), isTrue);
      expect(FileStat.statSync(keyFile.path).mode & 0x1FF, 0x180);
    });

    test('vault: the key in @host:<host>/.tom-secrets/device of the primary, '
        'which no reference reaches', () async {
      final demo = await Demo.create(deviceKey: TomSecretsDeviceKeyMode.vault);
      final (service, admin) = await unlocked(demo);
      await admin.request('lock');
      final primary = await KdbxFormat().read(
        File(demo.primaryPath).readAsBytesSync(),
        Credentials(ProtectedValue.fromString(primaryPassword)),
      );
      final overlay = primary.body.rootGroup.groups.firstWhere(
        (g) => g.name.get() == '@host:demo-host',
      );
      final device = overlay.groups.single.entries.single;
      expect(device.label, 'device');
      expect(device.getString(KdbxKeyCommon.PASSWORD), isA<ProtectedValue>());
      await admin.unlock(primaryPassword);
      expect(service.deviceContainer, isNotNull, reason: 'the same key opens');
      final client = await TomSecretsClient.connect(
        environment: demo.clientEnvironment(),
      );
      addTearDown(client.close);
      await expectLater(
        client.get('primary/.tom-secrets/device'),
        throwsA(
          isA<TomSecretsClientException>().having(
            (e) => e.kind,
            'kind',
            TomSecretsErrorKind.notFound,
          ),
        ),
      );
    });

    test(
      'keychain: the key in the keychain; auto takes the keychain where '
      'one answers, else the vault; keychain without one refuses the start',
      () async {
        final keychain = TomInMemorySecretStore();
        final demo = await Demo.create(
          deviceKey: TomSecretsDeviceKeyMode.keychain,
        );
        await unlocked(demo, keychain: keychain);
        expect(await keychain.read('tsm.device-settings.demo-host'), isNotNull);

        final auto = await Demo.create();
        auto.bootstrap = TomSecretsBootstrap(
          primary: auto.bootstrap.primary,
          dataDirectory: auto.bootstrap.dataDirectory,
        );
        final keys = TomSecretsDeviceKeys(
          mode: TomSecretsDeviceKeyMode.auto,
          host: 'demo-host',
          containerPath: auto.bootstrap.deviceContainer,
          keychain: keychain,
        );
        expect(await keys.effectiveMode(), TomSecretsDeviceKeyMode.keychain);
        expect(
          await TomSecretsDeviceKeys(
            mode: TomSecretsDeviceKeyMode.auto,
            host: 'demo-host',
            containerPath: auto.bootstrap.deviceContainer,
          ).effectiveMode(),
          TomSecretsDeviceKeyMode.vault,
        );

        final refused = await Demo.create(
          deviceKey: TomSecretsDeviceKeyMode.keychain,
        );
        await expectLater(
          refused.start(),
          throwsA(isA<TomSecretsDeviceKeyException>()),
        );
        expect(File(refused.runtime().infoFile).existsSync(), isFalse);
      },
    );

    test('a store that says it is not available: auto takes the vault, '
        'keychain refuses the start', () async {
      final unavailable = _UnavailableStore();
      final auto = await Demo.create(deviceKey: TomSecretsDeviceKeyMode.auto);
      final (service, _) = await unlocked(auto, keychain: unavailable);
      expect(service.deviceContainer, isNotNull);
      expect(unavailable.reads, 0, reason: 'asked isAvailable, not read');
      final primary = await KdbxFormat().read(
        File(auto.primaryPath).readAsBytesSync(),
        Credentials(ProtectedValue.fromString(primaryPassword)),
      );
      expect(
        primary.body.rootGroup.groups.map((g) => g.name.get()),
        contains('@host:demo-host'),
        reason: 'the key went into the vault',
      );
      final keychain = await Demo.create(
        deviceKey: TomSecretsDeviceKeyMode.keychain,
      );
      await expectLater(
        keychain.start(keychain: unavailable),
        throwsA(isA<TomSecretsDeviceKeyException>()),
      );
    });

    test('the OS keychain of this machine keeps the device key', () async {
      final store = TomDesktopSecretStore(service: 'tom-secrets-manager-test');
      if (!await store.isAvailable()) {
        markTestSkipped('no keychain answers in this session');
        return;
      }
      final demo = await Demo.create(
        deviceKey: TomSecretsDeviceKeyMode.keychain,
      );
      addTearDown(() => store.delete('tsm.device-settings.demo-host'));
      final (service, admin) = await unlocked(demo, keychain: store);
      expect(await store.read('tsm.device-settings.demo-host'), isNotNull);
      await admin.request('lock');
      await admin.unlock(primaryPassword);
      expect(service.deviceContainer, isNotNull, reason: 'the same key opens');
    });

    test('bootstrap.yaml', () {
      final b = TomSecretsBootstrap.parse(
        'primary: github:al-the-bear/demo-vaults/primary.kdbx\n'
        'device_key: vault\n'
        'host: bigbeast\n',
        dataDirectory: '/data',
      );
      expect(b.primary, 'github:al-the-bear/demo-vaults/primary.kdbx');
      expect(b.deviceKey, TomSecretsDeviceKeyMode.vault);
      expect(b.deviceContainer, '/data/device-settings.kdbx');
      expect(b.cacheDirectory, '/data/cache');
      expect(b.host, 'bigbeast');
      expect(
        () => TomSecretsBootstrap.parse(
          'device_key: auto\n',
          dataDirectory: '/d',
        ),
        throwsFormatException,
      );
      expect(
        () => TomSecretsBootstrap.parse(
          'primary: x\ndevice_key: tpm\n',
          dataDirectory: '/d',
        ),
        throwsFormatException,
      );
    });
  });
}

/// A keychain that says it is not available, and counts reads.
final class _UnavailableStore
    implements TomSecretStore, TomSecretStoreAvailability {
  int reads = 0;

  @override
  Future<bool> isAvailable() async => false;

  @override
  Future<String?> read(String handle) async {
    reads++;
    return null;
  }

  @override
  Future<void> write(String handle, String secret) async {}

  @override
  Future<void> delete(String handle) async {}
}
