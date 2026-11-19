// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The approver's long-lived links (part-sharing, protocol.md 9.7) with two
/// services on one primary vault: `bigbeast` the host, `mbp` the approver,
/// whose app answers bigbeast's prompts. The prompt reaches mbp's app with
/// its id qualified by the host; once, always (a grant signed by mbp,
/// applied on bigbeast at once) and always with a client token (its
/// `exe-token` grant answers the request); the link opened again after the
/// host relocked, and under the host's rotated link key the new key taken;
/// a browser prompt (protocol.md 5.5) answered always over the link names
/// the browser in its grant. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// Measures the next client connection as [next] when it is set (then
/// forgets it), every other peer as the tests always are measured.
final class SwitchMeasurer implements TomSecretsPeerMeasurer {
  SwitchMeasurer(TomSecretsTransport transport)
    : _usual = transport == TomSecretsTransport.tcp && !Platform.isWindows
          ? const SelfPeerMeasurer()
          : TomSecretsSystemPeerMeasurer();

  final TomSecretsPeerMeasurer _usual;

  /// The identity the next connection is measured as.
  TomSecretsIdentity? next;

  @override
  Future<TomSecretsPeerMeasurement> measure(Socket socket) async {
    final identity = next;
    next = null;
    return identity == null
        ? _usual.measure(socket)
        : TomSecretsPeerMeasured(identity);
  }
}

void main() {
  late Demo demoA;
  late Demo demoB;
  late TomSecretsService mbp;
  late TomSecretsService bigbeast;
  late TomSecretsAdminClient adminA;
  late TomSecretsAdminClient adminB;
  late int linkPort;
  late SwitchMeasurer measurerB;
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  Future<TomSecretsAdminClient> admin(Demo demo) async {
    final client = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(client.close);
    await client.unlock(primaryPassword);
    return client;
  }

  Future<void> until(bool Function() done, String what) async {
    for (var i = 0; i < 100 && !done(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(done(), isTrue, reason: what);
  }

  setUp(() async {
    demoA = await Demo.create();
    demoB = await Demo.create();
    // One primary vault for both machines, as the fleet shares it.
    demoB.bootstrap = TomSecretsBootstrap(
      primary: 'file:${demoA.primaryPath}',
      dataDirectory: '${demoB.dir}/data',
      deviceKey: TomSecretsDeviceKeyMode.keyfile,
    );
    // A login of a web site in the team vault both machines serve.
    final team = await KdbxFormat().read(
      File(demoA.teamPath).readAsBytesSync(),
      tomSecretsVaultCredentials(password: teamPassword),
    );
    final root = team.body.rootGroup;
    root.addEntry(
      KdbxEntry.create(team, root)
        ..setString(KdbxKeyCommon.TITLE, PlainValue('Mail'))
        ..setString(KdbxKeyCommon.USER_NAME, PlainValue('demo-user'))
        ..setString(KdbxKeyCommon.URL, PlainValue('https://mail.example.com'))
        ..setString(
          KdbxKeyCommon.PASSWORD,
          ProtectedValue.fromString('demo-mail-pw'),
        ),
    );
    File(demoA.teamPath).writeAsBytesSync(await team.save());
    mbp = await demoA.start(transport: transport, host: 'mbp');
    // bigbeast asks its approvers: no grants of the test's own.
    measurerB = SwitchMeasurer(transport);
    bigbeast = await demoB.start(
      transport: transport,
      host: 'bigbeast',
      policy: null,
      peerMeasurer: measurerB,
    );
    adminA = await admin(demoA);
    adminB = await admin(demoB);
    // A fixed port, so the link listens on the same address after a relock.
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    linkPort = probe.port;
    await probe.close();
    await bigbeast.deviceContainer!.write(
      TomSecretsDeviceSettings(approvalLink: '127.0.0.1:$linkPort'),
    );
    await adminB.request('lock');
    await adminB.unlock(primaryPassword);

    // Paired as tsm_a27's pairing records it: mbp approves for bigbeast.
    final tokenKey = Uint8List(32)..[0] = 5;
    bigbeast.trust.approvers.add(
      TomSecretsRecordedApprover(
        device: 'mbp',
        approverKey: (await mbp.trust.approverKey()).publicKey,
        linkKey: (await mbp.trust.linkKey()).publicKey,
        tokenKey: tokenKey,
      ),
    );
    await bigbeast.writeTrust();
    await bigbeast.approvals!.reload();
    mbp.trust.hosts.add(
      TomSecretsRecordedHost(
        host: 'bigbeast',
        linkKey: (await bigbeast.trust.linkKey()).publicKey,
        tokenKey: tokenKey,
        address: '127.0.0.1:$linkPort',
      ),
    );
    await mbp.writeTrust();
    mbp.approverLinks!.refresh();
    await until(
      () => mbp.approverLinks!.connected.contains('bigbeast'),
      'mbp opened the link to bigbeast',
    );
    await adminA.request('subscribe');
  });

  Future<TomSecretsClient> clientOnB() async {
    final c = await TomSecretsClient.connect(
      clientName: 'demo-client',
      environment: demoB.clientEnvironment(),
    );
    addTearDown(c.close);
    return c;
  }

  Future<Map<String, Object?>> nextEvent(String op) =>
      adminA.events.firstWhere((e) => e['op'] == op);

  test('a prompt on bigbeast reaches mbp\'s app and is answered once over '
      'the link', () async {
    final needed = nextEvent('approval_needed');
    final closed = nextEvent('approval_closed');
    final c = await clientOnB();
    final answer = c.get('primary/Db/Main');
    final event = await needed;
    expect(event['host'], 'bigbeast');
    expect(event['approvalId'], startsWith('bigbeast/'));
    expect(event['refs'], ['primary/Db/Main']);
    expect(event['approvalCode'], isNull, reason: 'an approver is linked');
    // Not in tsm's list of this host's prompts; in the app's subscription.
    expect((await adminA.request('approvals.list'))['approvals'], isEmpty);
    await adminA.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    expect((await answer).text, 'demo-db-pw');
    final done = await closed;
    expect(done['approvalId'], event['approvalId']);
    expect(done['host'], 'bigbeast');
    expect(done['outcome'], 'approved');
    // An id that waits nowhere.
    await expectLater(
      adminA.request('approve', {
        'approvalId': 'bigbeast/a-99',
        'decision': 'once',
        'secret': 'ref',
      }),
      throwsA(
        isA<TomSecretsAdminException>().having(
          (e) => e.kind,
          'kind',
          'not_found',
        ),
      ),
    );
  });

  test('always: mbp signs the grant for bigbeast, which applies it at once '
      'and answers the next request without a prompt', () async {
    final needed = nextEvent('approval_needed');
    final c = await clientOnB();
    final answer = c.get('primary/Db/Main');
    final event = await needed;
    await adminA.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'always',
      'secret': 'ref',
    });
    expect((await answer).text, 'demo-db-pw');
    // Written by mbp into bigbeast's group of the primary vault.
    final grants = await adminA.request('grants.list', {'host': 'bigbeast'});
    final grant = (grants['grants']! as List).cast<Map>().single;
    expect(grant['approver'], 'mbp');
    expect(grant['secret'], 'primary/Db/Main');
    expect(grant['decision'], 'allow');
    // Granted: no prompt the second time.
    var prompted = false;
    final sub = adminA.events.listen((e) {
      if (e['op'] == 'approval_needed') prompted = true;
    });
    addTearDown(sub.cancel);
    expect((await c.get('primary/Db/Main')).text, 'demo-db-pw');
    expect(prompted, isFalse);
  });

  test('a browser prompt on bigbeast answered always on mbp: the grant names '
      'the browser that started the browser host', () async {
    const chrome =
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
    const hostExe =
        '/Applications/Tom Secrets Manager.app/tsm/bin/'
        'tsm-browser-host';
    measurerB.next = TomSecretsIdentity.fromJson({
      'kind': 'exe',
      'exe': hostExe,
      'args': ['chrome-extension://lcejninmlbnhfnpedlgjjfeelhbgmach/'],
      'cwd': '/',
      'parent': {'exe': chrome},
    });
    final needed = nextEvent('approval_needed');
    final c = await clientOnB();
    final listed = c.match('https://mail.example.com/login');
    final event = await needed;
    expect(event['host'], 'bigbeast');
    expect(event['browser'], isTrue);
    expect(event['url'], 'https://mail.example.com/login');
    await adminA.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'always',
      'secret': 'all',
      'pin': 'off',
    });
    expect([for (final l in await listed) l.title], ['Mail']);
    final grants = await adminA.request('grants.list', {'host': 'bigbeast'});
    final grant = (grants['grants']! as List).cast<Map>().single;
    expect(grant['approver'], 'mbp');
    expect(grant['subject'], 'exe-from $chrome => $hostExe');
    expect(grant['secret'], 'all');
  });

  test('always with a client token: its exe-token grant answers the request '
      'and the client gets the token', () async {
    final needed = nextEvent('approval_needed');
    final c = await clientOnB();
    final answer = c.get('primary/Db/Main', wantClientToken: true);
    final event = await needed;
    expect(event['wantClientToken'], isTrue);
    final r = Random.secure();
    final token = base64.encode(List.generate(32, (_) => r.nextInt(256)));
    await adminA.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'always',
      'secret': 'ref',
      'clientToken': token,
    });
    final value = await answer;
    expect(value.text, 'demo-db-pw');
    expect(value.clientToken, token);
    final tokenId = tomSecretsClientTokenId(
      tomSecretsClientTokenHash(base64.decode(token)),
    );
    expect(bigbeast.trust.clientTokens.keys, contains(tokenId));
    final grants = await adminA.request('grants.list', {'host': 'bigbeast'});
    expect(
      ((grants['grants']! as List).cast<Map>().single)['subject'],
      endsWith(' $tokenId'),
    );
  });

  test('a connection that drops before or during the handshake leaves the '
      'host serving: its link and its admin endpoint answer', () async {
    for (final send in [false, true]) {
      final socket = await Socket.connect(
        InternetAddress.loopbackIPv4,
        linkPort,
      );
      if (send) socket.add(List.filled(64, 7));
      socket.destroy();
    }
    await Future<void>.delayed(const Duration(milliseconds: 500));
    expect((await adminB.request('status'))['locked'], isFalse);
    // And the approver's link still carries prompts.
    final needed = nextEvent('approval_needed');
    final c = await clientOnB();
    final answer = c.get('primary/Db/Main');
    final event = await needed;
    await adminA.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    expect((await answer).text, 'demo-db-pw');
  });

  test('the link is opened again after bigbeast relocked; under its rotated '
      'link key mbp takes the new key', () async {
    final before = mbp.trust.host('bigbeast')!.linkKey;
    await adminB.request('keys.rotate', {'approver': false, 'link': true});
    // The relock closes the links; mbp connects again under the old key.
    await adminB.request('lock');
    await until(
      () => !mbp.approverLinks!.connected.contains('bigbeast'),
      'the link closed',
    );
    await adminB.unlock(primaryPassword);
    await until(
      () =>
          base64.encode(mbp.trust.host('bigbeast')!.linkKey.x25519) !=
          base64.encode(before.x25519),
      'mbp took bigbeast\'s new link key',
    );
    expect(
      base64.encode(mbp.trust.host('bigbeast')!.linkKey.x25519),
      base64.encode((await bigbeast.trust.linkKey()).publicKey.x25519),
    );
    await until(
      () => mbp.approverLinks!.connected.contains('bigbeast'),
      'the link open again',
    );
    // And it carries prompts again.
    final needed = nextEvent('approval_needed');
    final c = await clientOnB();
    final answer = c.get('primary/Db/Main');
    final event = await needed;
    await adminA.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    expect((await answer).text, 'demo-db-pw');
  });
}
