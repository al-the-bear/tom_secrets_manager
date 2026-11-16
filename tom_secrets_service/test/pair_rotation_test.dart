// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A device rotating its own key pairs (`keys.rotate`, part-key-rotation §4)
/// with two services on one primary vault: the approver `mbp` and the host
/// `bigbeast` it approves for. The new approver key and its key-change
/// statement, the grants and revocations signed again, the new link key
/// sent over the link under the old one; a host not reached takes the key
/// change from the vault at its refresh, and the new link key later. Demo
/// data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

void main() {
  late Demo demoA;
  late Demo demoB;
  late TomSecretsService mbp;
  late TomSecretsService bigbeast;
  late TomSecretsAdminClient adminA;
  late TomSecretsAdminClient adminB;
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

  Future<void> relockB() async {
    await adminB.request('lock');
    await adminB.unlock(primaryPassword);
  }

  /// bigbeast's allow list for itself, by grant id: whether accepted.
  Future<Map<String, Object?>> grantsOnB() async {
    final list = await adminB.request('grants.list', {'host': 'bigbeast'});
    return {
      for (final g in (list['grants']! as List).cast<Map>())
        g['id'] as String: g['accepted'],
    };
  }

  /// Pairs the two by hand (as tsm_a27's pairing records them); bigbeast's
  /// link listens when [listening].
  Future<void> pair({required bool listening}) async {
    if (listening) {
      await bigbeast.deviceContainer!.write(
        const TomSecretsDeviceSettings(approvalLink: '127.0.0.1:0'),
      );
      await relockB();
    }
    final tokenKey = Uint8List(32)..[0] = 3;
    bigbeast.trust.approvers.add(
      TomSecretsRecordedApprover(
        device: 'mbp',
        approverKey: (await mbp.trust.approverKey()).publicKey,
        linkKey: (await mbp.trust.linkKey()).publicKey,
        tokenKey: tokenKey,
      ),
    );
    await bigbeast.writeTrust();
    mbp.trust.hosts.add(
      TomSecretsRecordedHost(
        host: 'bigbeast',
        linkKey: (await bigbeast.trust.linkKey()).publicKey,
        tokenKey: tokenKey,
        // A port nothing listens on when bigbeast's link is off.
        address: '127.0.0.1:${bigbeast.linkServer?.port ?? 9}',
      ),
    );
    await mbp.writeTrust();
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
    mbp = await demoA.start(transport: transport, host: 'mbp');
    bigbeast = await demoB.start(transport: transport, host: 'bigbeast');
    adminA = await admin(demoA);
    adminB = await admin(demoB);
  });

  Future<(String, String)> twoGrants() async {
    for (final subject in [
      'exe /usr/bin/demo-kept',
      'exe /usr/bin/demo-revoked',
    ]) {
      await adminA.request('grants.add', {
        'grant': {
          'host': 'bigbeast',
          'subject': subject,
          'secret': 'team/Api/Token',
          'decision': 'allow',
        },
      });
    }
    final list = await adminA.request('grants.list', {'host': 'bigbeast'});
    final ids = {
      for (final g in (list['grants']! as List).cast<Map>())
        g['subject'] as String: g['id'] as String,
    };
    final kept = ids['exe /usr/bin/demo-kept']!;
    final revoked = ids['exe /usr/bin/demo-revoked']!;
    await adminA.request('grants.revoke', {
      'host': 'bigbeast',
      'grantId': revoked,
    });
    await adminB.request('reload');
    return (kept, revoked);
  }

  test(
    'keys.rotate: the host accepts the new approver key and link key over '
    'the link; the re-signed grants stay accepted, the revocation stays',
    () async {
      await pair(listening: true);
      final (kept, revoked) = await twoGrants();
      expect(await grantsOnB(), {kept: true});

      final oldApprover = (await mbp.trust.approverKey()).keyId;
      final oldLink = (await mbp.trust.linkKey()).publicKey;
      final answer = await adminA.request('keys.rotate');
      expect(answer['op'], 'keysRotated');
      expect(
        answer['resigned'],
        2,
        reason:
            'the kept grant and the revocation (revoking removed its grant)',
      );
      expect(answer['delivered'], ['bigbeast']);
      expect(answer['pending'], isEmpty);
      final newApprover = (await mbp.trust.approverKey()).keyId;
      expect(newApprover, isNot(oldApprover));
      expect(answer['approverKeyId'], newApprover);

      // bigbeast took both over the link at once.
      final recorded = bigbeast.trust.approver('mbp')!;
      expect(recorded.approverKey.keyId, newApprover);
      expect(
        recorded.linkKey!.x25519,
        (await mbp.trust.linkKey()).publicKey.x25519,
      );
      expect(recorded.previousLinkKey!.x25519, oldLink.x25519);
      expect(mbp.trust.linkKeyPending, isEmpty);

      // The vault's grants, signed again with the new key, still hold.
      await adminB.request('reload');
      expect(await grantsOnB(), {kept: true}, reason: '$revoked stays revoked');
      // mbp now connects with its new link key.
      await tomSecretsDeliverOverLink(
        address: '127.0.0.1:${bigbeast.linkServer!.port}',
        me: await mbp.trust.linkKey(),
        hostKey: (await bigbeast.trust.linkKey()).publicKey,
        device: 'mbp',
        messages: const [],
      );
      // The Keys screen marks this device's own pairs.
      final keys = await adminA.request('keys');
      final own = [
        for (final k in (keys['keys']! as List).cast<Map>())
          if (k['own'] == true) k['key'],
      ];
      expect(own, ['approver-key:mbp', 'link-key:mbp']);
    },
  );

  test('a host the link does not reach: it takes the key change from the '
      'vault at its refresh; the new link key goes later, the old one '
      'meanwhile', () async {
    await pair(listening: false);
    final (kept, _) = await twoGrants();
    final oldLink = (await mbp.trust.linkKey()).publicKey;
    final answer = await adminA.request('keys.rotate');
    expect(answer['delivered'], isEmpty);
    expect(answer['pending'], ['bigbeast']);
    expect(
      bigbeast.trust.approver('mbp')!.approverKey.keyId,
      isNot(answer['approverKeyId']),
      reason: 'not reached yet',
    );

    await adminB.request('reload');
    expect(
      bigbeast.trust.approver('mbp')!.approverKey.keyId,
      answer['approverKeyId'],
      reason: 'the statement in the vault',
    );
    expect(await grantsOnB(), {kept: true});
    expect(mbp.trust.linkKeyPending.map((h) => h.host), ['bigbeast']);
    expect(
      (await mbp.trust.linkKeyFor('bigbeast')).publicKey.x25519,
      oldLink.x25519,
      reason: 'the key bigbeast knows, meanwhile',
    );

    // bigbeast's link comes up: the new link key goes at the next delivery.
    await bigbeast.deviceContainer!.write(
      const TomSecretsDeviceSettings(approvalLink: '127.0.0.1:0'),
    );
    await relockB();
    final record = mbp.trust.host('bigbeast')!;
    mbp.trust.hosts
      ..remove(record)
      ..add(
        TomSecretsRecordedHost(
          host: 'bigbeast',
          linkKey: record.linkKey,
          tokenKey: record.tokenKey,
          address: '127.0.0.1:${bigbeast.linkServer!.port}',
          linkKeyDelivered: false,
        ),
      );
    final delivery = await mbp.deliverToHosts(force: true);
    expect(delivery.delivered, ['bigbeast']);
    expect(
      bigbeast.trust.approver('mbp')!.linkKey!.x25519,
      (await mbp.trust.linkKey()).publicKey.x25519,
    );
    expect(mbp.trust.linkKeyPending, isEmpty);
  });

  test('the host rotated its link key: an approver that connects within the '
      'migration period under the old key takes the new one', () async {
    await pair(listening: true);
    final oldHostKey = (await bigbeast.trust.linkKey()).publicKey;
    // bigbeast rotates its own link key (it approves for nobody).
    final rotated = await adminB.request('keys.rotate', {
      'approver': false,
      'link': true,
    });
    expect(rotated['delivered'], isEmpty);
    final newHostKey = (await bigbeast.trust.linkKey()).publicKey;
    expect(newHostKey.x25519, isNot(oldHostKey.x25519));
    expect(
      mbp.trust.host('bigbeast')!.linkKey.x25519,
      oldHostKey.x25519,
      reason: 'mbp knows only the old key',
    );

    // mbp connects (its own key change to deliver) under bigbeast's old key;
    // bigbeast answers under it and passes its new key first.
    final answer = await adminA.request('keys.rotate', {
      'approver': true,
      'link': false,
    });
    expect(answer['delivered'], ['bigbeast']);
    final recorded = mbp.trust.host('bigbeast')!;
    expect(recorded.linkKey.x25519, newHostKey.x25519);
    expect(recorded.linkKey.mlKem768, newHostKey.mlKem768);
    expect(recorded.linkKeySince, isNotNull);
    expect(
      bigbeast.trust.approver('mbp')!.approverKey.keyId,
      answer['approverKeyId'],
      reason: 'the key change went through in the same session',
    );

    // From now on mbp connects under bigbeast's new key, and the new key is
    // kept across mbp's restart (written to its trust material).
    await tomSecretsDeliverOverLink(
      address: '127.0.0.1:${bigbeast.linkServer!.port}',
      me: await mbp.trust.linkKey(),
      hostKey: newHostKey,
      device: 'mbp',
      messages: const [],
    );
    await adminA.request('lock');
    await adminA.unlock(primaryPassword);
    expect(mbp.trust.host('bigbeast')!.linkKey.x25519, newHostKey.x25519);
  });

  test('a host link key that names another device is refused and not '
      'recorded; the session still delivers', () async {
    final hostKey = await TomSecretsLinkKey.fromSeeds(
      Uint8List(32)..[0] = 11,
      Uint8List(64)..[0] = 11,
    );
    final approverKey = await mbp.trust.linkKey();
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    final answered = Completer<Map<String, Object?>>();
    server.listen((socket) async {
      final session = await TomSecretsLinkSession.respond(
        TomSecretsSocketChannel(socket),
        me: hostKey,
        approvers: [(device: 'mbp', key: approverKey.publicKey)],
        host: 'bigbeast',
      );
      // Listened to before anything is sent: a broadcast stream keeps
      // nothing for a late listener.
      session.messages.listen((m) async {
        if (m['id'] == 'host-link-key') {
          if (!answered.isCompleted) answered.complete(m);
        } else if (m['id'] is int) {
          await session.send({'op': 'ok', 'id': m['id']});
        }
      });
      final other = await TomSecretsLinkKey.fromSeeds(
        Uint8List(32)..[0] = 12,
        Uint8List(64)..[0] = 12,
      );
      await session.send({
        'op': 'linkKey',
        'id': 'host-link-key',
        'device': 'impostor',
        'x25519': base64.encode(other.publicKey.x25519),
        'mlKem768': base64.encode(other.publicKey.mlKem768),
      });
    });
    TomSecretsLinkPublicKey? taken;
    await tomSecretsDeliverOverLink(
      address: '127.0.0.1:${server.port}',
      me: approverKey,
      hostKey: hostKey.publicKey,
      device: 'mbp',
      messages: const [
        {'op': 'ping'},
      ],
      onHostLinkKey: (key) async => taken = key,
    );
    expect(taken, isNull);
    // The answer to the key may arrive after the delivery has ended.
    final answer = await answered.future.timeout(const Duration(seconds: 5));
    expect(answer['op'], 'error');
  });

  test('keys.rotate refuses nothing to rotate and a locked service', () async {
    final none = await _refused(
      adminA.request('keys.rotate', {'approver': false, 'link': false}),
    );
    expect(none.details['reason'], 'keys');
    await adminA.request('lock');
    expect((await _refused(adminA.request('keys.rotate'))).kind, 'locked');
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
