// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The live check of the magic-wormhole relay against the real mailbox
/// server (part-relay, DP-66): what the fake in wormhole_relay_test.dart
/// cannot prove — that `magic-wormhole-mailbox-server`, run unchanged,
/// carries a pairing (SPAKE2 with ML-KEM-768 inside) for the app's own
/// application id, finds no pairing under a code nobody hosts (also with
/// `--disallow-list`), and refuses a third device.
///
/// Run by hand with the server installed (MIT, `pip install
/// magic-wormhole-mailbox-server` into a virtual environment); the test
/// starts and stops it on a free loopback port:
///
/// ```sh
/// TSM_WORMHOLE_TWIST=<venv>/bin/twist \
///   dart test test/live_wormhole_server_test.dart
/// ```
///
/// `TSM_WORMHOLE_SERVER=ws://host:port/v1` runs the pairing against a
/// server that is running already (the public one:
/// `ws://relay.magic-wormhole.io:4000/v1`). Without either variable it
/// skips. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 3))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

final _twist = Platform.environment['TSM_WORMHOLE_TWIST'];
final _running = Platform.environment['TSM_WORMHOLE_SERVER'];

late TomSecretsPairingPeerKeys _peer;

/// A started mailbox server: its relay id and how to stop it.
typedef _Server = ({String relayId, Future<void> Function() stop});

Future<_Server> _start({bool disallowList = false}) async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  final dir = await Directory.systemTemp.createTemp('wormhole_mailbox');
  final process = await Process.start(_twist!, [
    'wormhole-mailbox',
    '--port=tcp:$port:interface=127.0.0.1',
    '--channel-db=${dir.path}/relay.sqlite',
    if (disallowList) '--disallow-list',
  ], workingDirectory: dir.path);
  final output = StringBuffer();
  process.stdout.transform(utf8.decoder).listen(output.write);
  process.stderr.transform(utf8.decoder).listen(output.write);
  Future<void> stop() async {
    process.kill();
    await process.exitCode;
    await dir.delete(recursive: true);
  }

  for (var i = 0; i < 100; i++) {
    try {
      final s = await Socket.connect(InternetAddress.loopbackIPv4, port);
      s.destroy();
      return (relayId: 'wormhole:ws://127.0.0.1:$port/v1', stop: stop);
    } on SocketException {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }
  await stop();
  throw StateError('the mailbox server did not start: $output');
}

Future<void> _pair(String relayId) async {
  TomSecretsWormholeRelay relay() =>
      TomSecretsWormholeRelay(TomSecretsRelayId.parse(relayId));
  final channel = await relay().host();
  final number = int.parse(channel.nameplate);
  final window = await TomSecretsPairingWindow.open(
    addresses: const [],
    relayChannel: channel,
    code: TomSecretsPairingCode(number, ['guitar', 'orbit']),
    device: 'mbp',
    bundleFor: (receiver) async => TomSecretsPairingBundle(
      vaults: [
        TomSecretsPairingVault(
          name: 'primary',
          locator: 'github:demo-owner/demo-vaults/primary.kdbx',
          primary: true,
        ),
      ],
      giverKeys: _peer,
    ),
  );
  final received = await tomSecretsReceivePairingVia(
    relay(),
    code: TomSecretsPairingCode.parse('$number guitar orbit'),
    device: 'bigbeast',
    keysFor: (_, _) async => _peer,
  );
  final given = await window.result;
  expect(given.receiver, 'bigbeast');
  expect(received.giver, 'mbp');
  expect(received.bundle.vaults.single.name, 'primary');
  expect(received.tokenKey, given.tokenKey);
}

void main() {
  setUpAll(() async {
    _peer = TomSecretsPairingPeerKeys(
      linkKey: (await TomSecretsTrust.create('demo').linkKey()).publicKey,
    );
  });

  group(
    'the real mailbox server',
    () {
      test('a pairing through it', () async {
        final server = await _start();
        addTearDown(server.stop);
        await _pair(server.relayId);
      });

      for (final disallowList in [false, true]) {
        test('a code nobody hosts is said'
            '${disallowList ? ' (--disallow-list)' : ''}; a hosted one is '
            'found', () async {
          final server = await _start(disallowList: disallowList);
          addTearDown(server.stop);
          final id = TomSecretsRelayId.parse(server.relayId);
          await expectLater(
            TomSecretsWormholeRelay(id).join('77'),
            throwsA(
              isA<TomSecretsRelayException>().having(
                (e) => e.message,
                'message',
                contains('no pairing is open under 77'),
              ),
            ),
          );
          final host = await TomSecretsWormholeRelay(id).host();
          final joiner = await TomSecretsWormholeRelay(id).join(host.nameplate);
          final atHost = StreamIterator(host.incoming);
          joiner.send([9]);
          expect(await atHost.moveNext(), isTrue);
          expect(atHost.current, [9]);
          await joiner.close();
          await host.close();
        });
      }

      test('a third device is refused while the pairing runs', () async {
        final server = await _start();
        addTearDown(server.stop);
        final id = TomSecretsRelayId.parse(server.relayId);
        final host = await TomSecretsWormholeRelay(id).host();
        // The joining side holds the nameplate until it has the mailbox; a
        // third side claiming meanwhile is crowded out. A side that came
        // after both released finds nobody hosting any more.
        final joiner = await TomSecretsWormholeRelay(id).join(host.nameplate);
        await expectLater(
          TomSecretsWormholeRelay(id).join(host.nameplate),
          throwsA(
            isA<TomSecretsRelayException>().having(
              (e) => e.message,
              'message',
              contains('two devices are in this pairing'),
            ),
          ),
        );
        await joiner.close();
        await host.close();
      });
    },
    skip: _twist == null
        ? 'set TSM_WORMHOLE_TWIST to the server\'s twist'
        : null,
  );

  test(
    'a pairing through a running server',
    () async {
      await _pair('wormhole:${_running!}');
    },
    skip: _running == null
        ? 'set TSM_WORMHOLE_SERVER to a server\'s URL'
        : null,
  );
}
