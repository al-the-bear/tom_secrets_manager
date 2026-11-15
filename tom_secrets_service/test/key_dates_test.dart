// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The rotation age of the approver and approval-link key pairs
/// (part-key-rotation, DP-85): the trust material dates each key pair (the
/// device's own at creation, a peer's when recorded, at a key change and at
/// a new link key), and the service reminds of it from 30 days before its
/// 24 months are over (`key_expiry`, `status.expiring`). Demo data only.
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

/// The signature vectors: the approver key and its key-change statement.
final Map<String, Object?> _vectors =
    (jsonDecode(
              File(
                '../../secrets_clients/protocol/vectors/signatures.json',
              ).readAsStringSync(),
            )
            as Map)
        .cast();

Future<TomSecretsApproverKey> _vectorKey(String name) {
  final k = ((_vectors['keys']! as Map)[name]! as Map).cast<String, Object?>();
  return TomSecretsApproverKey.fromSeeds(
    base64.decode(k['ed25519Seed']! as String),
    base64.decode(k['mlDsa65Seed']! as String),
  );
}

Map<String, Object?> _keyChange() =>
    ((_vectors['accepted']! as List).cast<Map>().firstWhere(
              (a) => a['label'] == TomSecretsSignedLabels.keyChange,
            )['object']!
            as Map)
        .cast();

void main() {
  late Demo demo;
  late TomSecretsService service;
  late TomSecretsAdminClient admin;
  late List<Map<String, Object?>> events;
  late DateTime now;
  final now0 = DateTime.utc(2026, 11, 13, 9);
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  setUp(() async {
    now = now0;
    demo = await Demo.create();
    service = await demo.start(transport: transport, clock: () => now);
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    events = [];
    admin.events.listen(events.add);
    await admin.request('subscribe');
    await admin.unlock(primaryPassword);
  });

  /// [service]'s reminders as (key, daysLeft).
  List<(String, int)> expiring() => [
    for (final k in (service.statusReport()['expiring']! as List).cast<Map>())
      (k['key']! as String, k['daysLeft']! as int),
  ];

  Future<void> relock() async {
    await admin.request('lock');
    await admin.unlock(primaryPassword);
  }

  test('the device\'s key pairs are dated at creation and reminded of from '
      '30 days before their 24 months are over', () async {
    final trust = service.trust;
    expect(trust.approverKeySince, now0);
    expect(trust.linkKeySince, now0);
    expect(
      TomSecretsTrust.fromJson(
        (jsonDecode(jsonEncode(trust.toJson())) as Map).cast(),
      ).linkKeySince,
      now0,
      reason: 'kept in the device settings container',
    );
    expect(expiring(), isEmpty);

    now = DateTime.utc(2028, 10, 14, 9); // 24 months less 30 days
    events.clear();
    await service.refresh();
    await admin.request('status');
    await pumpEventQueue();
    expect(expiring(), [
      ('approver-key:demo-host', 30),
      ('link-key:demo-host', 30),
    ]);
    expect(
      [for (final e in events.where((e) => e['op'] == 'key_expiry')) e['key']],
      ['approver-key:demo-host', 'link-key:demo-host'],
    );
    final kinds = {
      for (final k in (service.statusReport()['expiring']! as List).cast<Map>())
        k['key']: k['kind'],
    };
    expect(kinds, {
      'approver-key:demo-host': 'approver_key',
      'link-key:demo-host': 'link_key',
    });
  });

  test('the rotation age and the reminder start come from the device '
      'settings (DP-85)', () async {
    await admin.request('settings.set', {
      'device': {
        ...service.settings.toJson(),
        'keyPairAgeMonths': 12,
        'otherKeyWarningDays': 60,
      },
    });
    // 12 months less 60 days.
    now = DateTime.utc(2027, 9, 14, 9);
    expect(expiring(), [
      ('approver-key:demo-host', 60),
      ('link-key:demo-host', 60),
    ]);
    final keys = (await admin.request('keys'))['keys']! as List;
    expect(
      (keys.cast<Map>().firstWhere(
        (k) => k['key'] == 'approver-key:demo-host',
      ))['expiresAt'],
      DateTime.utc(2027, 11, 13, 9).toIso8601String(),
    );
  });

  test('trust material without dates is dated at the next unlock', () async {
    service.trust
      ..approverKeySince = null
      ..linkKeySince = null;
    await service.writeTrust();
    now = now0.add(const Duration(days: 3));
    await relock();
    expect(service.trust.approverKeySince, now);
    expect(service.trust.linkKeySince, now);
    final stamped = now;
    now = now.add(const Duration(days: 3));
    await relock();
    expect(
      service.trust.approverKeySince,
      stamped,
      reason: 'written back to the device settings container',
    );
  });

  test('a peer\'s keys are dated when recorded; a key change and a new link '
      'key over the link start their age again', () async {
    final approverKey = await _vectorKey('approver');
    final approverLink = await TomSecretsLinkKey.fromSeeds(
      Uint8List(32)..[0] = 5,
      Uint8List(64)..[0] = 5,
    );
    final hostLink = await TomSecretsLinkKey.fromSeeds(
      Uint8List(32)..[0] = 7,
      Uint8List(64)..[0] = 7,
    );
    service.trust
      ..approvers.add(
        TomSecretsRecordedApprover(
          device: 'mbp',
          approverKey: approverKey.publicKey,
          linkKey: approverLink.publicKey,
          tokenKey: Uint8List(32),
        ),
      )
      ..hosts.add(
        TomSecretsRecordedHost(
          host: 'bigbeast',
          linkKey: hostLink.publicKey,
          tokenKey: Uint8List(32),
        ),
      );
    await service.writeTrust();
    await service.deviceContainer!.write(
      const TomSecretsDeviceSettings(approvalLink: '127.0.0.1:0'),
    );
    now = now0.add(const Duration(days: 1));
    await relock(); // the dates, and the link listens
    final mbp = service.trust.approver('mbp')!;
    expect(mbp.approverKeySince, now);
    expect(mbp.linkKeySince, now);
    expect(service.trust.host('bigbeast')!.linkKeySince, now);

    final session = await TomSecretsLinkSession.initiate(
      TomSecretsSocketChannel(
        await Socket.connect(
          InternetAddress.loopbackIPv4,
          service.linkServer!.port,
        ),
      ),
      me: approverLink,
      hostKey: (await service.trust.linkKey()).publicKey,
      device: 'mbp',
    );
    addTearDown(session.close);
    final messages = StreamIterator(session.messages);
    Future<Map<String, Object?>> reply(int id) async {
      while (await messages.moveNext()) {
        if (messages.current['id'] == id) return messages.current;
      }
      fail('the link closed');
    }

    now = now0.add(const Duration(days: 365));
    await session.send({'op': 'keychange', 'id': 1, 'statement': _keyChange()});
    expect((await reply(1))['op'], 'ok');
    final changed = service.trust.approver('mbp')!;
    expect(
      changed.approverKey.keyId,
      (await _vectorKey('approverRotated')).keyId,
    );
    expect(changed.approverKeySince, now);
    expect(changed.linkKeySince, now0.add(const Duration(days: 1)));

    final newLink = await TomSecretsLinkKey.fromSeeds(
      Uint8List(32)..[0] = 9,
      Uint8List(64)..[0] = 9,
    );
    now = now0.add(const Duration(days: 400));
    await session.send({
      'op': 'linkKey',
      'id': 2,
      'device': 'mbp',
      'x25519': base64.encode(newLink.publicKey.x25519),
      'mlKem768': base64.encode(newLink.publicKey.mlKem768),
    });
    expect((await reply(2))['op'], 'ok');
    expect(service.trust.approver('mbp')!.linkKeySince, now);
    await messages.cancel();

    // 24 months after the first recording, less 10 days: this device's own
    // pairs and bigbeast's link key are due, mbp's keys were renewed since.
    now = DateTime.utc(2028, 11, 4, 9);
    expect(expiring(), [
      ('approver-key:demo-host', 9),
      ('link-key:demo-host', 9),
      ('link-key:bigbeast', 10),
    ]);
  });
}
