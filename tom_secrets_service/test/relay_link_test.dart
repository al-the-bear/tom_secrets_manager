// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The approval link through a relay server (part-relay) with two services
/// on one primary vault: `bigbeast` the host, `mbp` the approver, and an
/// in-memory relay standing in for `tom_secrets_relay` (the relay package
/// runs the same flow against the real server). The address first, the
/// relay when it does not answer; a prompt answered through the relay; the
/// link opened again after the host relocked; a relay that refuses the
/// link (no instance token) shown like an unreachable link; the token kept
/// in the keychain and used; the pairing's identity and record carrying the
/// relay link. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

const _relay = 'tsm:https://relay.example';
const _linkId = 'L0123456789abcdef';

/// A relay server in memory: channels joined by link id, the instance token
/// checked when [requireToken].
final class MemoryRelay {
  MemoryRelay({this.requireToken});

  /// The token a link needs, or null: none.
  final String? requireToken;

  final Map<String, List<_End>> _open = {};

  /// The tokens links were asked with.
  final List<String?> tokens = [];

  /// The link ids asked for.
  final List<String> asked = [];

  TomSecretsRelay forToken(String relay, String? token) =>
      _MemoryRelayClient(this, relay, token);

  Future<TomSecretsPairingChannel> link(String id, String? token) async {
    tokens.add(token);
    asked.add(id);
    if (requireToken != null && token != requireToken) {
      throw const TomSecretsRelayException(
        _relay,
        'it opens approval links only for holders of an instance token',
      );
    }
    final ends = _open.putIfAbsent(id, () => []);
    if (ends.length >= 2) {
      throw const TomSecretsRelayException(_relay, 'two sides already');
    }
    final end = _End(this, id);
    ends.add(end);
    if (ends.length == 2) {
      ends[0].other = ends[1];
      ends[1].other = ends[0];
      for (final b in ends[0].pending) {
        ends[1]._in.add(b);
      }
      ends[0].pending.clear();
    }
    return end;
  }

  /// How many sides wait on [id].
  int sides(String id) => _open[id]?.length ?? 0;

  void _left(_End end) {
    final ends = _open[end.id];
    if (ends == null) return;
    ends.remove(end);
    final other = end.other;
    if (ends.isEmpty) _open.remove(end.id);
    if (other != null) {
      other.other = null;
      unawaited(other.close());
    }
  }
}

final class _MemoryRelayClient implements TomSecretsRelay {
  _MemoryRelayClient(this.memory, String relay, this.token)
    : id = TomSecretsRelayId.parse(relay);

  final MemoryRelay memory;
  final String? token;

  @override
  final TomSecretsRelayId id;

  @override
  Set<TomSecretsRelayService> get services => id.services;

  @override
  Future<TomSecretsPairingChannel> link(String linkId) =>
      memory.link(linkId, token);

  @override
  Future<TomSecretsPairingChannel> host() => throw UnimplementedError();
  @override
  Future<TomSecretsPairingChannel> join(String nameplate) =>
      throw UnimplementedError();
  @override
  Future<void> put(TomSecretsMailboxItem item) => throw UnimplementedError();
  @override
  Future<List<TomSecretsMailboxEntry>> list(TomSecretsMemberKey me) =>
      throw UnimplementedError();
  @override
  Future<Uint8List> fetch(TomSecretsMemberKey me, String itemId) =>
      throw UnimplementedError();
  @override
  Future<void> delete(TomSecretsMemberKey me, String itemId) =>
      throw UnimplementedError();
}

final class _End implements TomSecretsPairingChannel {
  _End(this.relay, this.id);

  final MemoryRelay relay;
  final String id;
  _End? other;
  final List<List<int>> pending = [];
  final StreamController<List<int>> _in = StreamController();
  final Completer<void> _joined = Completer();
  bool _closed = false;

  @override
  String get nameplate => id;

  @override
  Future<void> get joined => _joined.future;

  @override
  Stream<List<int>> get incoming => _in.stream;

  @override
  void send(List<int> bytes) {
    if (_closed) return;
    final o = other;
    final copy = List<int>.of(bytes);
    if (o == null) {
      pending.add(copy);
    } else {
      if (!o._joined.isCompleted) o._joined.complete();
      o._in.add(copy);
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    relay._left(this);
    unawaited(_in.close());
  }
}

void main() {
  late Demo demoA;
  late Demo demoB;
  late TomSecretsService mbp;
  late TomSecretsService bigbeast;
  late TomSecretsAdminClient adminA;
  late TomSecretsAdminClient adminB;
  late MemoryRelay relay;
  late TomInMemorySecretStore keychainA;
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

  Map<String, Object?>? linkState(
    TomSecretsService s,
    String device,
    String role,
  ) => s.linkStates
      .where((l) => l['device'] == device && l['role'] == role)
      .firstOrNull;

  /// Pairs them as a pairing through the relay records it: mbp approves for
  /// bigbeast, whose address is [address] (null: none).
  Future<void> pair({String? address}) async {
    final tokenKey = Uint8List(32)..[0] = 7;
    final link = (relay: _relay, linkId: _linkId);
    bigbeast.trust.recordPeer(
      device: 'mbp',
      tokenKey: tokenKey,
      at: DateTime.now(),
      approverKey: (await mbp.trust.approverKey()).publicKey,
      approverLinkKey: (await mbp.trust.linkKey()).publicKey,
      link: link,
      peerIsGiver: true,
    );
    await bigbeast.writeTrust();
    await bigbeast.approvals!.reload();
    bigbeast.relayLinkHost!.refresh();
    mbp.trust.recordPeer(
      device: 'bigbeast',
      tokenKey: tokenKey,
      at: DateTime.now(),
      hostLinkKey: (await bigbeast.trust.linkKey()).publicKey,
      hostAddress: address,
      link: link,
    );
    await mbp.writeTrust();
    mbp.approverLinks!.refresh();
  }

  Future<void> startBoth({String? requireToken}) async {
    relay = MemoryRelay(requireToken: requireToken);
    demoA = await Demo.create();
    demoB = await Demo.create();
    demoB.bootstrap = TomSecretsBootstrap(
      primary: 'file:${demoA.primaryPath}',
      dataDirectory: '${demoB.dir}/data',
      deviceKey: TomSecretsDeviceKeyMode.keyfile,
    );
    keychainA = TomInMemorySecretStore();
    mbp = await demoA.start(
      transport: transport,
      host: 'mbp',
      keychain: keychainA,
      linkRelayFor: relay.forToken,
    );
    bigbeast = await demoB.start(
      transport: transport,
      host: 'bigbeast',
      policy: null,
      keychain: TomInMemorySecretStore(),
      linkRelayFor: relay.forToken,
    );
    adminA = await admin(demoA);
    adminB = await admin(demoB);
    await adminA.request('subscribe');
  }

  Future<TomSecretsClient> clientOnB() async {
    final c = await TomSecretsClient.connect(
      clientName: 'demo-client',
      environment: demoB.clientEnvironment(),
    );
    addTearDown(c.close);
    return c;
  }

  Future<int> closedPort() async {
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    return port;
  }

  test('the host\'s address does not answer: the link goes through the '
      'relay, and a prompt is answered over it', () async {
    await startBoth();
    await pair(address: '127.0.0.1:${await closedPort()}');
    await until(
      () => mbp.approverLinks!.connected.contains('bigbeast'),
      'mbp reached bigbeast through the relay',
    );
    // Each direction has its own channel; the giver (mbp) is no host here.
    expect(relay.asked, everyElement('$_linkId-r'));
    expect(linkState(mbp, 'bigbeast', 'host'), {
      'device': 'bigbeast',
      'role': 'host',
      'state': 'connected',
      'via': 'relay',
    });
    await until(
      () => linkState(bigbeast, 'mbp', 'approver')?['state'] == 'connected',
      'bigbeast took mbp\'s session from the relay',
    );
    final status = await adminA.request('status');
    expect((status['links']! as List).cast<Map>().single['via'], 'relay');

    final needed = adminA.events.firstWhere(
      (e) => e['op'] == 'approval_needed',
    );
    final c = await clientOnB();
    final answer = c.get('primary/Db/Main');
    final event = await needed;
    expect(event['approvalId'], startsWith('bigbeast/'));
    await adminA.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    expect((await answer).text, 'demo-db-pw');
  });

  test('the address first: a host that answers there is not reached through '
      'the relay', () async {
    await startBoth();
    final port = await closedPort();
    await bigbeast.deviceContainer!.write(
      TomSecretsDeviceSettings(approvalLink: '127.0.0.1:$port'),
    );
    await adminB.request('lock');
    await adminB.unlock(primaryPassword);
    await pair(address: '127.0.0.1:$port');
    await until(
      () => mbp.approverLinks!.connected.contains('bigbeast'),
      'mbp reached bigbeast',
    );
    expect(linkState(mbp, 'bigbeast', 'host')!['via'], 'address');
    // bigbeast's channel waits on the relay all the same.
    await until(
      () => linkState(bigbeast, 'mbp', 'approver')?['state'] == 'waiting',
      'bigbeast waits on the relay too',
    );
    expect(relay.sides('$_linkId-r'), 1);
  });

  test(
    'after the host relocked, the link through the relay opens again',
    () async {
      await startBoth();
      await pair();
      await until(
        () => mbp.approverLinks!.connected.contains('bigbeast'),
        'the first link',
      );
      await adminB.request('lock');
      await until(
        () => !mbp.approverLinks!.connected.contains('bigbeast'),
        'the link ended with the lock',
      );
      expect(linkState(mbp, 'bigbeast', 'host')!['state'], 'unreachable');
      await adminB.unlock(primaryPassword);
      await until(
        () => mbp.approverLinks!.connected.contains('bigbeast'),
        'the link opened again',
      );
      expect(linkState(mbp, 'bigbeast', 'host')!['via'], 'relay');
    },
  );

  test('a relay that refuses the link is shown like an unreachable link; '
      'the instance token kept through the app opens it', () async {
    await startBoth(requireToken: 'instance-token-0123456789');
    await pair();
    await until(
      () =>
          linkState(mbp, 'bigbeast', 'host')?['state'] == 'unreachable' &&
          linkState(mbp, 'bigbeast', 'host')?['reason'] != null,
      'the refused link is said',
    );
    expect(
      linkState(mbp, 'bigbeast', 'host')!['reason'],
      contains('instance token'),
    );
    expect(linkState(bigbeast, 'mbp', 'approver')!['state'], 'unreachable');
    // The app keeps the token through the service, in the keychain.
    final listed = await adminA.request('relay.token.list', {
      'relays': [_relay, 'github:a/b'],
    });
    expect(listed['relays'], {_relay: false, 'github:a/b': false});
    await adminA.request('relay.token.set', {
      'relay': _relay,
      'token': 'instance-token-0123456789',
    });
    expect(
      await keychainA.read(tomSecretsRelayTokenHandle(_relay)),
      'instance-token-0123456789',
    );
    expect(
      (await adminA.request('relay.token.list', {
        'relays': [_relay],
      }))['relays'],
      {_relay: true},
    );
    await adminB.request('relay.token.set', {
      'relay': _relay,
      'token': 'instance-token-0123456789',
    });
    await until(
      () => mbp.approverLinks!.connected.contains('bigbeast'),
      'the link opened with the token',
    );
    expect(relay.tokens.last, 'instance-token-0123456789');
    // Removed again; a relay that is no relay server is refused.
    await adminA.request('relay.token.set', {'relay': _relay});
    expect(await keychainA.read(tomSecretsRelayTokenHandle(_relay)), isNull);
    await expectLater(
      adminA.request('relay.token.set', {'relay': 'github:a/b', 'token': 'x'}),
      throwsA(
        isA<TomSecretsAdminException>().having(
          (e) => e.kind,
          'kind',
          'malformed',
        ),
      ),
    );
  });

  test('the pairing\'s identity names the relay link, and its record keeps '
      'the channels', () async {
    await startBoth();
    final identity = await adminA.request('pair.identity', {'relay': _relay});
    expect(identity['linkRelay'], _relay);
    expect(identity['linkId'], matches(tomSecretsLinkIdPattern));
    expect((await adminA.request('pair.identity'))['linkRelay'], isNull);
    final peer = (await bigbeast.trust.linkKey()).publicKey;
    await adminA.request('pair.record', {
      'device': 'bigbeast',
      'tokenKey': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      'host': {'linkKey': peer.toJson()},
      'approver': {
        'approverKey': (await bigbeast.trust.approverKey()).publicKey.toJson(),
        'linkKey': peer.toJson(),
      },
      'link': {'relay': _relay, 'linkId': _linkId},
    });
    // The giving side: the receiver as the host waits on `-r`, the giver
    // as the host on `-g`.
    expect(mbp.trust.host('bigbeast')!.linkId, '$_linkId-r');
    expect(mbp.trust.approver('bigbeast')!.linkId, '$_linkId-g');
    expect(mbp.trust.host('bigbeast')!.relay, _relay);
    await expectLater(
      adminA.request('pair.record', {
        'device': 'bigbeast',
        'tokenKey': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'host': {'linkKey': peer.toJson()},
        'link': {'relay': 'github:a/b', 'linkId': _linkId},
      }),
      throwsA(isA<TomSecretsAdminException>()),
    );
  });
}
