// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service executable's pairing mode (`tsm pair`, part-sharing), in
/// this process against a giving `TomSecretsPairingWindow` on loopback: the
/// report (nothing stored yet), a wrong master password answered and
/// another taken, the machine set up (keychain, container, bootstrap); then
/// the service started from that bootstrap unlocks and has the giving
/// device recorded as its approver and as a host it approves for. A wrong
/// code ends it with the pairing's failure. Through a GitHub repository as
/// the relay (part-relay), against the fake GitHub server: alone, after an
/// address that does not answer, the machine's own token kept for the
/// primary's repository; a relay without the pairing named in the error.
/// Demo data under demo keys.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart' show TomInMemorySecretStore;
import 'package:tom_github_api/testing.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

void main() {
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;
  late Demo demo;
  late TomSecretsPairingPeerKeys giverKeys;

  setUp(() async {
    demo = await Demo.create();
    final giver = TomSecretsTrust.create('mbp');
    giverKeys = TomSecretsPairingPeerKeys(
      linkKey: (await giver.linkKey()).publicKey,
      approverKey: (await giver.approverKey()).publicKey,
      linkAddress: '10.8.0.7:47731',
    );
  });

  Future<(TomSecretsPairingWindow, TomSecretsPairingCode)> window() async {
    final code = TomSecretsPairingCode.generate();
    final w = await TomSecretsPairingWindow.open(
      addresses: [InternetAddress.loopbackIPv4],
      allowLoopback: true,
      code: code,
      device: 'mbp',
      bundleFor: (_) async => TomSecretsPairingBundle(
        vaults: [
          TomSecretsPairingVault(
            name: 'primary',
            locator: 'file:${demo.primaryPath}',
            primary: true,
          ),
        ],
        giverKeys: giverKeys,
        configYaml: 'dimensions: []\n',
      ),
    );
    return (w, code);
  }

  TomSecretsPairingHandover handover(
    int port,
    String code, {
    String? approvalLink,
  }) => TomSecretsPairingHandover(
    dataDirectory: '${demo.dir}/paired',
    address: '127.0.0.1',
    port: port,
    code: code,
    device: 'bigbeast',
    deviceKey: 'keyfile',
    approvalLink: approvalLink,
  );

  test('reported, a wrong password answered, set up; the service then '
      'unlocks with the giver recorded', () async {
    final (w, code) = await window();
    final input = StreamController<String>();
    final lines = StreamIterator(input.stream);
    final answers = StreamController<Map<String, Object?>>();
    final answered = StreamIterator(answers.stream);
    final keychain = TomInMemorySecretStore();
    final exit = tomSecretsRunPairingMode(
      handover(w.port, code.text),
      lines: lines,
      answer: answers.add,
      keychain: keychain,
    );

    expect(await answered.moveNext(), isTrue);
    final report = TomSecretsPairingReport.fromJson(answered.current);
    expect(report.giver, 'mbp');
    expect(report.vaults.single.name, 'primary');
    expect(report.vaults.single.primary, isTrue);
    expect(report.config, isTrue);
    final given = await w.result;
    expect(given.receiver, 'bigbeast');
    expect(Directory('${demo.dir}/paired').existsSync(), isFalse);

    input.add(jsonEncode({'password': 'wrong'}));
    expect(await answered.moveNext(), isTrue);
    expect(answered.current['code'], tomSecretsPairingWrongPassword);
    input.add(jsonEncode({'password': primaryPassword}));
    expect(await answered.moveNext(), isTrue);
    expect(answered.current['status'], 'setUp');
    final bootstrapPath = answered.current['bootstrap']! as String;
    expect(await exit, 0);
    await lines.cancel();
    unawaited(input.close());

    demo.bootstrap = await TomSecretsBootstrap.read(bootstrapPath);
    final service = await demo.start(
      transport: transport,
      keychain: keychain,
      host: 'bigbeast',
    );
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    final trust = service.trust;
    expect(trust.device, 'bigbeast');
    expect(
      (await trust.approverKey()).publicKey.keyId,
      given.receiverKeys.approverKey!.keyId,
    );
    final approver = trust.approvers.single;
    expect(approver.device, 'mbp');
    expect(approver.approverKey.keyId, giverKeys.approverKey!.keyId);
    expect(approver.tokenKey, given.tokenKey);
    expect(trust.hosts.single.host, 'mbp');
    expect(trust.hosts.single.address, '10.8.0.7:47731');
  });

  test('with an approval link: the giver is told the address, the device '
      'settings hold it, the service listens there once unlocked, and the '
      'giver\'s service, recording the pairing, opens the link', () async {
    // The giving machine's service: its keys go into the bundle.
    final mbpDemo = await Demo.create();
    final mbp = await mbpDemo.start(transport: transport, host: 'mbp');
    final mbpAdmin = await TomSecretsAdminClient.connect(
      mbpDemo.runtime(transport),
      mbpDemo.adminKey,
    );
    addTearDown(mbpAdmin.close);
    await mbpAdmin.unlock(primaryPassword);
    giverKeys = TomSecretsPairingPeerKeys(
      linkKey: (await mbp.trust.linkKey()).publicKey,
      approverKey: (await mbp.trust.approverKey()).publicKey,
    );

    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final link = '127.0.0.1:${probe.port}';
    await probe.close();
    final (w, code) = await window();
    final input = StreamController<String>();
    final lines = StreamIterator(input.stream);
    final answers = StreamController<Map<String, Object?>>();
    final answered = StreamIterator(answers.stream);
    final keychain = TomInMemorySecretStore();
    final exit = tomSecretsRunPairingMode(
      handover(w.port, code.text, approvalLink: link),
      lines: lines,
      answer: answers.add,
      keychain: keychain,
    );
    expect(await answered.moveNext(), isTrue);
    final given = await w.result;
    expect(given.receiverKeys.linkAddress, link);
    input.add(jsonEncode({'password': primaryPassword}));
    expect(await answered.moveNext(), isTrue);
    expect(answered.current['status'], 'setUp');
    final bootstrapPath = answered.current['bootstrap']! as String;
    expect(await exit, 0);
    await lines.cancel();
    unawaited(input.close());

    demo.bootstrap = await TomSecretsBootstrap.read(bootstrapPath);
    final service = await demo.start(
      transport: transport,
      keychain: keychain,
      host: 'bigbeast',
    );
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    expect(service.settings.approvalLink, link);
    expect(service.linkServer!.address, link);

    // What the giving app's pair.record keeps: the host and its address.
    await mbp.recordPairing(
      device: given.receiver,
      tokenKey: given.tokenKey,
      hostLinkKey: given.receiverKeys.linkKey,
      hostAddress: given.receiverKeys.linkAddress,
    );
    expect(mbp.trust.host('bigbeast')!.address, link);
    for (var i = 0; i < 100; i++) {
      if (mbp.approverLinks!.connected.contains('bigbeast')) break;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(mbp.approverLinks!.connected, contains('bigbeast'));
  });

  test('an approval link on every interface is refused before the pairing '
      'starts', () async {
    final answers = <Map<String, Object?>>[];
    final exit = await tomSecretsRunPairingMode(
      handover(1, '7-guitar-orbit', approvalLink: '0.0.0.0:47731'),
      lines: StreamIterator(const Stream.empty()),
      answer: answers.add,
      keychain: TomInMemorySecretStore(),
    );
    expect(exit, 2);
    expect(answers.single['code'], 'handover');
    expect(answers.single['message'], contains('every interface'));
  });

  test('a wrong code: the pairing\'s failure, nothing stored', () async {
    final (w, code) = await window();
    final failed = expectLater(
      w.result,
      throwsA(isA<TomSecretsPairingException>()),
    );
    final [first, second] = code.words;
    final wrong = first == second
        ? '${code.number == 999 ? 1 : code.number + 1}-$first-$second'
        : '${code.number}-$second-$first';
    final answers = <Map<String, Object?>>[];
    final exit = await tomSecretsRunPairingMode(
      handover(w.port, wrong),
      lines: StreamIterator(const Stream.empty()),
      answer: answers.add,
      keychain: TomInMemorySecretStore(),
    );
    await failed;
    expect(exit, 6);
    expect(answers.single['code'], 'pairing');
    expect(answers.single['failure'], 'wrongCode');
    expect(Directory('${demo.dir}/paired').existsSync(), isFalse);
  });

  group('through a GitHub relay (part-relay)', () {
    const slug = 'demo-owner/demo-vaults';
    final id = TomSecretsRelayId.parse('github:$slug');
    late FakeGitHubServer server;

    setUp(() {
      server = FakeGitHubServer()..commitFiles(slug, {'README.md': 'demo'});
    });

    TomSecretsRelay relay(String token, String device) =>
        TomSecretsGitHubRelay.withToken(
          id,
          token,
          device: device,
          httpClient: server.client,
          baseUrl: FakeGitHubServer.baseUrl,
          pollInterval: const Duration(milliseconds: 20),
        );

    /// The giving machine's pairing, on the relay alone.
    Future<(TomSecretsPairingWindow, TomSecretsPairingCode)> giving() async {
      final channel = await relay('demo-giver-token', 'mbp').host();
      final code = TomSecretsPairingCode(int.parse(channel.nameplate), [
        'guitar',
        'orbit',
      ]);
      final w = await TomSecretsPairingWindow.open(
        addresses: const [],
        relayChannel: channel,
        code: code,
        device: 'mbp',
        bundleFor: (_) async => TomSecretsPairingBundle(
          vaults: [
            TomSecretsPairingVault(
              name: 'primary',
              locator: 'file:${demo.primaryPath}',
              primary: true,
            ),
            const TomSecretsPairingVault(
              name: 'team',
              locator: 'github:$slug/team.kdbx',
              primary: false,
            ),
          ],
          giverKeys: giverKeys,
        ),
      );
      return (w, code);
    }

    Future<(int, List<Map<String, Object?>>, TomInMemorySecretStore)> run(
      TomSecretsPairingHandover h, {
      String? password,
    }) async {
      final input = StreamController<String>();
      if (password != null) input.add(jsonEncode({'password': password}));
      final lines = StreamIterator(input.stream);
      final answers = <Map<String, Object?>>[];
      final keychain = TomInMemorySecretStore();
      final exit = await tomSecretsRunPairingMode(
        h,
        lines: lines,
        answer: answers.add,
        keychain: keychain,
        relayFor: (relayId, token, api, device) {
          if (relayId.kind == TomSecretsRelayKind.wormhole) {
            // A magic-wormhole server: built as the service builds it.
            expect(token, isNull);
            return tomSecretsRelayFor(relayId, device: device);
          }
          if (relayId.kind == TomSecretsRelayKind.server) {
            // A relay server: no token. The rendezvous itself is the
            // GitHub fake's, which carries the same channel.
            expect(token, isNull);
            return relay('demo-receiver-token', device);
          }
          expect(relayId, id);
          expect(api, 'http://fake.api.test');
          return relay(token!, device);
        },
      );
      await lines.cancel();
      unawaited(input.close());
      return (exit, answers, keychain);
    }

    TomSecretsPairingHandover handover(
      TomSecretsPairingCode code, {
      String? address,
      int? port,
    }) => TomSecretsPairingHandover(
      dataDirectory: '${demo.dir}/paired',
      address: address,
      port: port,
      code: code.text,
      device: 'bigbeast',
      deviceKey: 'keyfile',
      relay: id.text,
      relayToken: 'github_pat_demo_own',
      relayApi: 'http://fake.api.test',
    );

    test('alone: received through the repository, the machine set up, its '
        'own token kept for the repository; the folder gone', () async {
      final (w, code) = await giving();
      final (exit, answers, keychain) = await run(
        handover(code),
        password: primaryPassword,
      );
      expect(exit, 0, reason: '$answers');
      final report = TomSecretsPairingReport.fromJson(answers.first);
      expect(report.giver, 'mbp');
      expect(report.tokens, [slug]);
      expect(answers.last['status'], 'setUp');
      expect((await w.result).receiver, 'bigbeast');
      final team =
          TomSecretsVaultLocator.parse('github:$slug/team.kdbx')
              as TomSecretsGitHubLocator;
      expect(await keychain.read(team.tokenHandle), 'github_pat_demo_own');
      List<String> paths() {
        final head = server.repos[slug]!.refs['heads/main']!;
        return server.trees[server.commits[head]!.treeSha]!.keys.toList();
      }

      for (var i = 0; i < 100; i++) {
        if (!paths().any((p) => p.startsWith('relay/'))) break;
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
      expect(paths(), [
        'README.md',
      ], reason: 'the pairing\'s files deleted by the side that ended second');
    });

    test(
      'the address first: one that does not answer, then the relay',
      () async {
        final unused = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        final port = unused.port;
        await unused.close();
        final (w, code) = await giving();
        final (exit, answers, _) = await run(
          handover(code, address: '127.0.0.1', port: port),
          password: primaryPassword,
        );
        expect(exit, 0, reason: '$answers');
        expect((await w.result).receiver, 'bigbeast');
      },
    );

    test('through a relay server: no token, none kept', () async {
      final (w, code) = await giving();
      final (exit, answers, keychain) = await run(
        TomSecretsPairingHandover(
          dataDirectory: '${demo.dir}/paired',
          code: code.text,
          device: 'bigbeast',
          deviceKey: 'keyfile',
          relay: 'tsm:https://relay.example',
        ),
        password: primaryPassword,
      );
      expect(exit, 0, reason: '$answers');
      expect(TomSecretsPairingReport.fromJson(answers.first).tokens, isEmpty);
      expect((await w.result).receiver, 'bigbeast');
      final team =
          TomSecretsVaultLocator.parse('github:$slug/team.kdbx')
              as TomSecretsGitHubLocator;
      expect(await keychain.read(team.tokenHandle), isNull);
    });

    test('no pairing on the relay: the pairing fails naming the relay; a '
        'magic-wormhole server is tried as well', () async {
      final (exit, answers, _) = await run(
        handover(TomSecretsPairingCode(77, ['guitar', 'orbit'])),
      );
      expect(exit, 6);
      expect(answers.single['code'], 'pairing');
      expect(answers.single['failure'], 'relay');
      expect(answers.single['message'], contains('github:$slug'));
      expect(Directory('${demo.dir}/paired').existsSync(), isFalse);

      // A wormhole server that does not answer: tried, and said by name.
      final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final closed = probe.port;
      await probe.close();
      final wormhole = 'wormhole:ws://127.0.0.1:$closed/v1';
      final (failed, said, _) = await run(
        TomSecretsPairingHandover(
          dataDirectory: '${demo.dir}/paired',
          code: '77-guitar-orbit',
          device: 'bigbeast',
          relay: wormhole,
        ),
      );
      expect(failed, 6);
      expect(said.single['failure'], 'relay');
      expect(said.single['message'], contains(wormhole));
      expect(Directory('${demo.dir}/paired').existsSync(), isFalse);
    });
  });
}
