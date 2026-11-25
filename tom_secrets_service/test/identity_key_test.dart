// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service's identity key (protocol.md 6.1, 6.2): the same across
/// restarts, proved in the identity exchange with the real primitives,
/// checked against the admin's pins before an `auth` or a `claim`; the
/// claim's master password sealed to the connection's one-time key; the
/// key's rotation followed by its statement; the key in the device records.
/// Demo data only.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// An identity check over [pins] with the real primitives, pinning nothing
/// by itself.
TomSecretsServiceTrust strict(
  TomSecretsServicePins pins, {
  TomSecretsEndpointInspector? inspector,
}) => TomSecretsServiceTrust(
  inspector: inspector ?? const TomSecretsSystemEndpointInspector(),
  identity: TomSecretsIdentityTrust(
    pins: pins,
    crypto: const TomSecretsPqcIdentityCrypto(),
    host: 'demo-host',
  ),
);

Matcher refused(String kind, [String? reason]) => throwsA(
  isA<TomSecretsAdminException>()
      .having((e) => e.kind, 'kind', kind)
      .having((e) => e.details['reason'], 'reason', reason ?? anything),
);

/// The transport of this OS: Unix sockets, on Windows localhost ports.
final transport = Platform.isWindows
    ? TomSecretsTransport.tcp
    : TomSecretsTransport.unix;

/// A connection to the admin endpoint of [runtime].
Future<Socket> connectAdmin(TomSecretsRuntime runtime) =>
    runtime.transport == TomSecretsTransport.unix
    ? Socket.connect(
        InternetAddress(runtime.adminSocket, type: InternetAddressType.unix),
        0,
      )
    : Socket.connect(
        InternetAddress.loopbackIPv4,
        readTomSecretsPortFile(File(runtime.adminPortFile).readAsStringSync())!,
      );

/// Frames spoken by hand on the admin endpoint.
final class RawAdmin {
  RawAdmin._(this.socket) {
    socket.listen((bytes) {
      for (final f in reader.add(bytes)) {
        final m = tomSecretsDecodePayload(f.payload);
        if (waiting.isNotEmpty) {
          waiting.removeAt(0).complete(m);
        } else {
          queue.add(m);
        }
      }
    }, onError: (Object _) {});
  }

  static Future<RawAdmin> open(TomSecretsRuntime runtime) async {
    final socket = await connectAdmin(runtime);
    addTearDown(socket.destroy);
    return RawAdmin._(socket);
  }

  final Socket socket;
  final reader = TomSecretsFrameReader(maxPayload: tomSecretsMaxAnswerPayload);
  final queue = <Map<String, Object?>>[];
  final waiting = <Completer<Map<String, Object?>>>[];

  void send(Map<String, Object?> m) => socket.add(tomSecretsJsonFrame(m));

  Future<Map<String, Object?>> next() {
    if (queue.isNotEmpty) return Future.value(queue.removeAt(0));
    final c = Completer<Map<String, Object?>>();
    waiting.add(c);
    return c.future.timeout(const Duration(seconds: 10));
  }
}

void main() {
  test(
    'the key is made at the first start, kept in the data directory for '
    'the user alone, and the same after a restart; status names it',
    () async {
      final demo = await Demo.create();
      final first = await demo.start(transport: transport);
      final key = Uint8List.fromList(first.identityKey);
      expect(key, hasLength(tomSecretsIdentityKeyLength));
      final file = File(
        '${demo.bootstrap.dataDirectory}/$tomSecretsServiceIdentityFile',
      );
      expect(file.existsSync(), isTrue);
      if (!Platform.isWindows) {
        expect(file.statSync().mode & 0x1ff, 0x180, reason: '0600');
      }
      final identity = first.statusReport()['identity']! as Map;
      expect(identity['words'], tomSecretsIdentityWords(key));
      expect(identity['fingerprint'], tomSecretsIdentityFingerprint(key));
      await first.stop();
      final second = await demo.start(transport: transport);
      expect(second.identityKey, key);
    },
  );

  test('a key file that cannot be read stops the start: the key is never '
      'replaced silently', () async {
    final demo = await Demo.create();
    File('${demo.bootstrap.dataDirectory}/$tomSecretsServiceIdentityFile')
      ..createSync(recursive: true)
      ..writeAsStringSync('{"secretKey": "no key"}');
    await expectLater(
      demo.start(transport: transport),
      throwsA(isA<FileSystemException>()),
    );
  });

  group('the pins', () {
    test('a service that is not pinned gets neither an auth nor a claim: '
        '`unpinned`, with its words to compare', () async {
      final demo = await Demo.create();
      final service = await demo.start(transport: transport);
      final runtime = demo.runtime(transport);
      final trust = strict(TomSecretsMemoryPins());
      for (final attempt in [
        () =>
            TomSecretsAdminClient.connect(runtime, demo.adminKey, trust: trust),
        () => TomSecretsAdminClient.claim(
          runtime,
          password: primaryPassword,
          trust: trust,
        ),
      ]) {
        await expectLater(
          attempt(),
          throwsA(
            isA<TomSecretsAdminException>()
                .having((e) => e.kind, 'kind', tomSecretsServiceUntrusted)
                .having((e) => e.details['reason'], 'reason', 'unpinned')
                .having(
                  (e) => e.details['words'],
                  'words',
                  tomSecretsIdentityWords(service.identityKey),
                ),
          ),
        );
      }
      // The claim never reached it: the admin key is the one it started
      // with.
      final admin = await TomSecretsAdminClient.connect(runtime, demo.adminKey);
      await admin.close();
    });

    test('pinned (as the starter pins what the started process said), it is '
        'authenticated and claimed', () async {
      final demo = await Demo.create();
      final service = await demo.start(transport: transport);
      final runtime = demo.runtime(transport);
      final pins = TomSecretsMemoryPins();
      await pins.pin(
        'demo-host',
        runtime.directory,
        service.identityKey,
        TomSecretsPinSource.start,
      );
      final admin = await TomSecretsAdminClient.connect(
        runtime,
        demo.adminKey,
        trust: strict(pins),
      );
      expect(admin.identity!.publicKey, service.identityKey);
      await admin.close();
      final (claimer, key) = await TomSecretsAdminClient.claim(
        runtime,
        password: primaryPassword,
        trust: strict(pins),
      );
      expect(key, isNot(demo.adminKey));
      await claimer.close();
    });

    test('a host-level pin (a device record of the primary, a pairing) '
        'holds for the service wherever it answers', () async {
      final demo = await Demo.create();
      final service = await demo.start(transport: transport);
      final pins = TomSecretsMemoryPins();
      await pins.pin(
        'demo-host',
        null,
        service.identityKey,
        TomSecretsPinSource.pairing,
      );
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(transport),
        demo.adminKey,
        trust: strict(pins),
      );
      await admin.close();
    });

    test('a service with another key than the pinned one is refused before '
        'anything is sent: `service_key_changed`, no way around it', () async {
      final demo = await Demo.create();
      await demo.start(transport: transport);
      final runtime = demo.runtime(transport);
      final other = await TomSecretsServiceIdentityKey.generate();
      addTearDown(other.dispose);
      final pins = TomSecretsMemoryPins();
      await pins.pin(
        'demo-host',
        runtime.directory,
        other.publicKey,
        TomSecretsPinSource.start,
      );
      await expectLater(
        TomSecretsAdminClient.claim(
          runtime,
          password: primaryPassword,
          trust: strict(pins),
        ),
        throwsA(
          isA<TomSecretsAdminException>()
              .having((e) => e.kind, 'kind', tomSecretsServiceKeyChanged)
              .having(
                (e) => e.details['pinned'],
                'pinned',
                tomSecretsIdentityWords(other.publicKey),
              ),
        ),
      );
      await expectLater(
        TomSecretsAdminClient.connect(
          runtime,
          demo.adminKey,
          trust: strict(pins),
        ),
        refused(tomSecretsServiceKeyChanged),
      );
      await expectLater(
        TomSecretsAdminClient.checkService(runtime, trust: strict(pins)),
        refused(tomSecretsServiceKeyChanged),
      );
      // Nothing was claimed, and the pin stays what it was.
      final admin = await TomSecretsAdminClient.connect(runtime, demo.adminKey);
      await admin.close();
      expect((await pins.all()).single.key, other.publicKey);
    });
  });

  group('the claim', () {
    test('a claim in the clear is refused', () async {
      final demo = await Demo.create();
      await demo.start(transport: transport);
      for (final identify in [false, true]) {
        final raw = await RawAdmin.open(demo.runtime(transport));
        expect((await raw.next())['features'], contains('identity'));
        if (identify) {
          raw.send({
            'op': 'identify',
            'clientNonce': base64.encode(tomSecretsRandomBytes()),
          });
          expect((await raw.next())['op'], 'identity');
        }
        raw.send({'op': 'claim', 'password': primaryPassword});
        final answer = await raw.next();
        expect(answer['op'], 'error');
        expect(answer['kind'], 'malformed');
        expect((answer['details']! as Map)['reason'], 'unsealed');
      }
      // Nothing was claimed.
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(transport),
        demo.adminKey,
      );
      await admin.close();
    });

    test('a claim sealed to another key than this connection\'s one-time '
        'key does not open', () async {
      final demo = await Demo.create();
      await demo.start(transport: transport);
      final raw = await RawAdmin.open(demo.runtime(transport));
      await raw.next();
      final nonce = tomSecretsRandomBytes();
      raw.send({'op': 'identify', 'clientNonce': base64.encode(nonce)});
      final identity = await raw.next();
      final other = await TomSecretsOneTimeKey.generate();
      addTearDown(other.dispose);
      final sealed = await const TomSecretsPqcIdentityCrypto().encapsulate(
        other.publicKey,
      );
      raw.send({
        'op': 'claim',
        'sealed': await tomSecretsSealClaim(
          sharedSecret: sealed.sharedSecret,
          kemCiphertext: sealed.ciphertext,
          transcript: base64.decode(identity['signature']! as String),
          password: primaryPassword,
        ),
      });
      final answer = await raw.next();
      expect(answer['kind'], 'denied');
      expect((answer['details']! as Map)['reason'], 'bad_seal');
    });

    test('the master password reaches only the holder of the one-time key: '
        'what stands between the admin and the service passes the claim on '
        'and reads nothing of it', () async {
      final demo = await Demo.create();
      final service = await demo.start(transport: transport);
      final real = demo.runtime(transport);
      // A relay on a socket of its own: every byte both ways is kept.
      final relayDir = Directory('${demo.dir}/relay')..createSync();
      final relayRuntime = TomSecretsRuntime(
        relayDir.path,
        transport: transport,
      );
      final seen = BytesBuilder();
      final ServerSocket relay;
      if (transport == TomSecretsTransport.unix) {
        relay = await ServerSocket.bind(
          InternetAddress(
            relayRuntime.adminSocket,
            type: InternetAddressType.unix,
          ),
          0,
        );
      } else {
        relay = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        await relayRuntime.writePort(relayRuntime.adminPortFile, relay.port);
      }
      addTearDown(relay.close);
      relay.listen((client) async {
        final upstream = await connectAdmin(real);
        unawaited(client.done.catchError((Object _) => client));
        unawaited(upstream.done.catchError((Object _) => upstream));
        client.listen(
          (b) {
            seen.add(b);
            upstream.add(b);
          },
          onDone: upstream.destroy,
          onError: (Object _) {},
        );
        upstream.listen(
          (b) {
            seen.add(b);
            client.add(b);
          },
          onDone: client.destroy,
          onError: (Object _) {},
        );
      });
      final pins = TomSecretsMemoryPins();
      await pins.pin(
        'demo-host',
        relayRuntime.directory,
        service.identityKey,
        TomSecretsPinSource.trust,
      );
      const keyFile = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
      // The relay's files are not the service's: the check of them is
      // tested elsewhere; here it is what a relay sees that counts.
      final (claimer, key) = await TomSecretsAdminClient.claim(
        relayRuntime,
        password: primaryPassword,
        trust: strict(pins, inspector: const _Passing()),
      );
      expect(key, hasLength(32));
      await claimer.close();
      await expectLater(
        TomSecretsAdminClient.claim(
          relayRuntime,
          password: 'another-demo-pw',
          keyFile: keyFile,
          trust: strict(pins, inspector: const _Passing()),
        ),
        refused('denied', 'bad_password'),
      );
      final bytes = seen.takeBytes();
      final text = latin1.decode(bytes);
      expect(text, contains('"op":"claim"'));
      expect(text, contains('"sealed"'));
      for (final secret in [
        primaryPassword,
        base64.encode(utf8.encode(primaryPassword)),
        'another-demo-pw',
        base64.encode(keyFile),
      ]) {
        expect(text, isNot(contains(secret)));
      }
    });
  });

  group('rotation and the device records', () {
    test(
      'this device\'s record names the service\'s key from the first '
      'unlock; pair.identity carries it, pair.record keeps a peer\'s',
      () async {
        final demo = await Demo.create();
        final service = await demo.start(transport: transport);
        final admin = await TomSecretsAdminClient.connect(
          demo.runtime(transport),
          demo.adminKey,
        );
        addTearDown(admin.close);
        await admin.unlock(primaryPassword);
        final own = base64.encode(service.identityKey);
        Future<List<Map>> devices() async => [
          ...((await admin.request('pair.list'))['devices']! as List).cast(),
        ];
        expect((await devices()).single['serviceKey'], own);
        final identity = await admin.request('pair.identity');
        expect(identity['serviceKey'], own);
        expect(TomSecretsPairingPeerKeys.fromJson(identity).serviceKey, own);

        final peer = await TomSecretsServiceIdentityKey.generate();
        addTearDown(peer.dispose);
        await admin.request('pair.record', {
          'device': 'demo-peer',
          'tokenKey': base64.encode(tomSecretsRandomBytes()),
          'host': {'linkKey': identity['linkKey']},
          'record': {
            'platform': 'linux',
            'keyIds': const <String>[],
            'serviceKey': base64.encode(peer.publicKey),
          },
        });
        final recorded = (await devices()).firstWhere(
          (d) => d['device'] == 'demo-peer',
        );
        expect(recorded['serviceKey'], base64.encode(peer.publicKey));
      },
    );

    test('keys.rotate {identity}: the old key signs the new one; an admin '
        'that pinned the old key follows the statement and pins the new '
        'one; one that pinned another key is still refused', () async {
      final demo = await Demo.create();
      final service = await demo.start(transport: transport);
      final runtime = demo.runtime(transport);
      final old = Uint8List.fromList(service.identityKey);
      final pins = TomSecretsMemoryPins();
      await pins.pin(
        'demo-host',
        runtime.directory,
        old,
        TomSecretsPinSource.start,
      );
      final admin = await TomSecretsAdminClient.connect(
        runtime,
        demo.adminKey,
        trust: strict(pins),
      );
      await admin.unlock(primaryPassword);
      final answer = await admin.request('keys.rotate', {
        'approver': false,
        'link': false,
        'identity': true,
      });
      final rotated = base64.decode(
        (answer['identity']! as Map)['key'] as String,
      );
      expect(rotated, isNot(old));
      expect(service.identityKey, rotated);
      expect(
        (answer['identity']! as Map)['words'],
        tomSecretsIdentityWords(rotated),
      );
      final devices = (await admin.request('pair.list'))['devices']! as List;
      expect((devices.single as Map)['serviceKey'], base64.encode(rotated));
      await admin.close();

      final again = await TomSecretsAdminClient.connect(
        runtime,
        demo.adminKey,
        trust: strict(pins),
      );
      await again.close();
      final pin = (await pins.all()).single;
      expect(pin.key, rotated);
      expect(pin.source, TomSecretsPinSource.rotation);

      // The statement leads from the old key only.
      final stranger = await TomSecretsServiceIdentityKey.generate();
      addTearDown(stranger.dispose);
      final others = TomSecretsMemoryPins();
      await others.pin(
        'demo-host',
        runtime.directory,
        stranger.publicKey,
        TomSecretsPinSource.start,
      );
      await expectLater(
        TomSecretsAdminClient.connect(
          runtime,
          demo.adminKey,
          trust: strict(others),
        ),
        refused(tomSecretsServiceKeyChanged),
      );

      // The rotated key is the one a restart finds.
      await service.stop();
      expect((await demo.start(transport: transport)).identityKey, rotated);
    });
  });
}

final class _Passing implements TomSecretsEndpointInspector {
  const _Passing();

  @override
  TomSecretsEndpointFacts files(TomSecretsRuntime runtime) =>
      TomSecretsEndpointFacts(
        operatingSystem: 'linux',
        ownUser: 1000,
        ownPid: pid,
        directory: (owner: 1000, mode: 448, type: 'directory'),
        socket: (owner: 1000, mode: 384, type: 'socket'),
        peer: TomSecretsServicePeer(pid: pid, user: 1000, executable: null),
      );

  @override
  TomSecretsEndpointFacts withPeer(TomSecretsEndpointFacts f, Socket s) => f;
}
