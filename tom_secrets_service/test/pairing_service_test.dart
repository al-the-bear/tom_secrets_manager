// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Pairing two machines through the service (part-sharing, DP-60–DP-64):
/// mbp gives, bigbeast receives, over a pairing window on TCP; each side's
/// public keys come from `pair.identity`, and `pair.record` keeps what the
/// pairing gave. Then mbp's signed pre-approval is accepted on bigbeast,
/// mbp's link reaches bigbeast under the pinned keys, mbp's primary holds
/// bigbeast's device record, and `pair.revoke` ends it. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

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

  setUp(() async {
    demoA = await Demo.create();
    demoB = await Demo.create();
    demoB.bootstrap = TomSecretsBootstrap(
      primary: 'file:${demoA.primaryPath}',
      dataDirectory: '${demoB.dir}/data',
      deviceKey: TomSecretsDeviceKeyMode.keyfile,
    );
    mbp = await demoA.start(transport: transport, host: 'mbp');
    bigbeast = await demoB.start(transport: transport, host: 'bigbeast');
    adminA = await admin(demoA);
    adminB = await admin(demoB);
    // bigbeast's approval link listens (applied at the next unlock).
    await bigbeast.deviceContainer!.write(
      const TomSecretsDeviceSettings(approvalLink: '127.0.0.1:0'),
    );
    await adminB.request('lock');
    await adminB.unlock(primaryPassword);
  });

  TomSecretsPairingPeerKeys keysOf(Map<String, Object?> identity) =>
      TomSecretsPairingPeerKeys.fromJson(identity);

  /// One pairing, as the apps run it: the window on mbp, bigbeast connects.
  Future<(TomSecretsPairingGiven, TomSecretsPairingReceived)> pair() async {
    final identityA = await adminA.request('pair.identity');
    final identityB = await adminB.request('pair.identity');
    expect(identityA['device'], 'mbp');
    expect(identityB['linkAddress'], bigbeast.linkServer!.address);
    final code = TomSecretsPairingCode.generate();
    final window = await TomSecretsPairingWindow.open(
      addresses: [InternetAddress.loopbackIPv4],
      allowLoopback: true,
      code: code,
      device: 'mbp',
      bundleFor: (receiver) async => TomSecretsPairingBundle(
        vaults: const [],
        giverKeys: keysOf(identityA),
      ),
    );
    final received = await tomSecretsReceivePairingAt(
      '127.0.0.1',
      window.port,
      code: TomSecretsPairingCode.parse(code.text),
      device: 'bigbeast',
      keysFor: (giver, bundle) async => keysOf(identityB),
    );
    return (await window.result, received);
  }

  test('paired both ways: keys recorded with the shared token key, mbp\'s '
      'pre-approval accepted on bigbeast, the link under the pinned keys, '
      'the device record in the primary', () async {
    final (given, received) = await pair();
    // bigbeast records mbp as its approver (and mbp's link as a host it
    // could approve for); mbp records bigbeast as a host it approves for,
    // and its device record.
    final giver = received.bundle.giverKeys;
    await adminB.request('pair.record', {
      'device': 'mbp',
      'tokenKey': base64.encode(received.tokenKey),
      'approver': {
        'approverKey': giver.approverKey!.toJson(),
        'linkKey': giver.linkKey.toJson(),
      },
    });
    final receiverKeys = given.receiverKeys;
    await adminA.request('pair.record', {
      'device': 'bigbeast',
      'tokenKey': base64.encode(given.tokenKey),
      'host': {
        'linkKey': receiverKeys.linkKey.toJson(),
        'address': receiverKeys.linkAddress,
      },
      'approver': {
        'approverKey': receiverKeys.approverKey!.toJson(),
        'linkKey': receiverKeys.linkKey.toJson(),
      },
      'record': {
        'platform': 'linux',
        'keyIds': ['0123456789abcdef'],
      },
    });
    final onB = bigbeast.trust.approver('mbp')!;
    final onA = mbp.trust.host('bigbeast')!;
    expect(onB.tokenKey, onA.tokenKey, reason: 'the same approval-token key');
    expect(onB.approverKeySince, isNotNull);
    expect(onA.address, bigbeast.linkServer!.address);
    expect(
      mbp.trust.approver('bigbeast')!.approverKey.keyId,
      receiverKeys.approverKey!.keyId,
    );

    // mbp pre-approves for bigbeast: bigbeast accepts it.
    await adminA.request('grants.add', {
      'grant': {
        'host': 'bigbeast',
        'subject': 'exe /usr/bin/demo',
        'secret': 'team/Api/Token',
        'decision': 'allow',
      },
    });
    await adminB.request('reload');
    final list = await adminB.request('grants.list', {'host': 'bigbeast'});
    expect(
      [for (final g in (list['grants']! as List).cast<Map>()) g['accepted']],
      [true],
    );

    // mbp's link reaches bigbeast under the keys the pairing pinned.
    await tomSecretsDeliverOverLink(
      address: onA.address!,
      me: await mbp.trust.linkKey(),
      hostKey: onA.linkKey,
      device: 'mbp',
      messages: const [
        {'op': 'ping'},
      ],
    ).then(
      (_) {},
      onError: (Object e) {
        // `ping` is no link message: the host closes the link after the
        // handshake, which proves the handshake itself.
        expect(e, isA<TomSecretsLinkDeliveryException>());
      },
    );

    final devices = await adminA.request('pair.list');
    final record = (devices['devices']! as List).cast<Map>().single;
    expect(record['device'], 'bigbeast');
    expect(record['platform'], 'linux');
    expect(record['pairedBy'], 'mbp');
    expect(record['keyIds'], ['0123456789abcdef']);
    expect(record['approverKeyId'], receiverKeys.approverKey!.keyId);
    expect(record.containsKey('revoked'), isFalse);
    // The keys page dates the paired device's pairs.
    final keys = await adminA.request('keys');
    expect([
      for (final k in (keys['keys']! as List).cast<Map>()) k['key'],
    ], containsAll(['approver-key:bigbeast', 'link-key:bigbeast']));
  });

  test('pair.revoke: the device approves no longer and its record says so; '
      'paired again, it is recorded anew', () async {
    final (given, received) = await pair();
    final giver = received.bundle.giverKeys;
    await adminB.request('pair.record', {
      'device': 'mbp',
      'tokenKey': base64.encode(received.tokenKey),
      'approver': {
        'approverKey': giver.approverKey!.toJson(),
        'linkKey': giver.linkKey.toJson(),
      },
    });
    await adminA.request('pair.record', {
      'device': 'bigbeast',
      'tokenKey': base64.encode(given.tokenKey),
      'host': {'linkKey': given.receiverKeys.linkKey.toJson()},
      'record': {'platform': 'linux', 'keyIds': <String>[]},
    });
    await adminA.request('grants.add', {
      'grant': {
        'host': 'bigbeast',
        'subject': 'exe /usr/bin/demo',
        'secret': 'team/Api/Token',
        'decision': 'allow',
      },
    });
    await adminB.request('reload');

    // On bigbeast: mbp revoked as approver; its grant is no longer accepted.
    await adminB.request('pair.revoke', {'device': 'mbp'});
    expect(bigbeast.trust.approver('mbp'), isNull);
    final list = await adminB.request('grants.list', {'host': 'bigbeast'});
    expect(
      [for (final g in (list['grants']! as List).cast<Map>()) g['accepted']],
      [false],
    );
    // On mbp: bigbeast's host record goes, its device record is revoked.
    await adminA.request('pair.revoke', {'device': 'bigbeast'});
    expect(mbp.trust.host('bigbeast'), isNull);
    final devices = await adminA.request('pair.list');
    expect(
      ((devices['devices']! as List).single as Map).containsKey('revoked'),
      isTrue,
    );
    final unknown = await adminA
        .request('pair.revoke', {'device': 'nobody'})
        .then<Object?>((v) => v, onError: (Object e) => e);
    expect((unknown! as TomSecretsAdminException).kind, 'not_found');

    // Paired again: recorded anew, not revoked any more.
    final (again, _) = await pair();
    await adminA.request('pair.record', {
      'device': 'bigbeast',
      'tokenKey': base64.encode(again.tokenKey),
      'host': {'linkKey': again.receiverKeys.linkKey.toJson()},
      'record': {'platform': 'linux', 'keyIds': <String>[]},
    });
    final relisted = await adminA.request('pair.list');
    final record = (relisted['devices']! as List).cast<Map>();
    expect(record, hasLength(1));
    expect(record.single.containsKey('revoked'), isFalse);
    expect(mbp.trust.host('bigbeast')!.tokenKey, again.tokenKey);
  });

  test(
    'refused: nothing to record, a bad token key, this device itself',
    () async {
      Future<String?> reason(Map<String, Object?> args) => adminA
          .request('pair.record', args)
          .then<String?>(
            (_) => null,
            onError: (Object e) =>
                (e as TomSecretsAdminException).details['reason'] as String?,
          );
      final tokenKey = base64.encode(List.filled(32, 1));
      expect(await reason({'device': 'x', 'tokenKey': tokenKey}), 'pair');
      expect(
        await reason({
          'device': 'x',
          'tokenKey': base64.encode([1, 2]),
          'host': <String, Object?>{},
        }),
        'pair',
      );
      final identity = await adminA.request('pair.identity');
      expect(
        await reason({
          'device': 'mbp',
          'tokenKey': tokenKey,
          'host': {'linkKey': identity['linkKey']},
        }),
        'pair',
      );
    },
  );
}
