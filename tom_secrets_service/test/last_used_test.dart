// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A grant's last use (protocol.md 7.3): kept in memory and written into the
/// grant's unsigned `lastUsed` in the primary vault in one save per interval
/// and at lock, never when nothing was used; an app that edited the primary
/// before such a write is merged, not refused. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show
        Credentials,
        KdbxEntry,
        KdbxFile,
        KdbxFormat,
        KdbxKeyCommon,
        PlainValue,
        ProtectedValue,
        TomSecretsGrantsGroup,
        TomSecretsSignedKind,
        tomSecretsBlobId;
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

void main() {
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;
  late Demo demo;
  late TomSecretsService service;
  late TomSecretsAdminClient admin;

  setUp(() async {
    demo = await Demo.create();
  });

  Future<String> start(Duration interval) async {
    service = await demo.start(
      transport: transport,
      policy: null,
      lastUsedInterval: interval,
    );
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    final self = tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!);
    await admin.request('grants.add', {
      'grant': {
        'host': 'demo-host',
        'subject': self.kind == 'script'
            ? 'script ${self.interpreter} ${self.script}'
            : 'exe ${self.exe}',
        'secret': 'all',
        'decision': 'allow',
        'pin': 'off',
      },
    });
    return service.approvals!.grants.single.id;
  }

  Future<KdbxFile> onDisk() => KdbxFormat().read(
    File(demo.primaryPath).readAsBytesSync(),
    Credentials(ProtectedValue.fromString(primaryPassword)),
  );

  Future<String?> lastUsedOnDisk(String grantId) async {
    final grant = TomSecretsGrantsGroup(
      await onDisk(),
    ).read('demo-host', TomSecretsSignedKind.grant).single;
    expect(grant['id'], grantId);
    return grant['lastUsed'] as String?;
  }

  Future<void> use() async {
    final c = await TomSecretsClient.connect(
      clientName: 'demo-client',
      environment: demo.clientEnvironment(),
    );
    addTearDown(c.close);
    expect((await c.get('primary/Db/Main')).text, 'demo-db-pw');
  }

  test('kept in memory, written after the interval in one save, announced; '
      'grants.list shows it before', () async {
    final grantId = await start(const Duration(milliseconds: 600));
    await admin.request('subscribe');
    await use();
    expect(service.approvals!.unwrittenLastUse.keys, [grantId]);
    final listed =
        ((await admin.request('grants.list'))['grants']! as List).single as Map;
    expect(listed['lastUsed'], isA<String>());
    final changed = admin.events.firstWhere((e) => e['op'] == 'store_changed');
    expect((await changed)['store'], 'primary');
    expect(await lastUsedOnDisk(grantId), isNotNull);
    expect(service.approvals!.unwrittenLastUse, isEmpty);
    final written = DateTime.parse((await lastUsedOnDisk(grantId))!);
    expect(
      DateTime.now().toUtc().difference(written),
      lessThan(const Duration(minutes: 1)),
    );
  });

  test('written at lock', () async {
    final grantId = await start(const Duration(hours: 1));
    await use();
    expect(await lastUsedOnDisk(grantId), isNull, reason: 'not before');
    await admin.request('lock');
    expect(await lastUsedOnDisk(grantId), isNotNull);
  });

  test('nothing used: no write', () async {
    await start(const Duration(milliseconds: 200));
    final before = File(demo.primaryPath).readAsBytesSync();
    await Future<void>.delayed(const Duration(seconds: 1));
    await admin.request('lock');
    expect(File(demo.primaryPath).readAsBytesSync(), before);
    expect(
      File(demo.bootstrap.logFile).readAsStringSync(),
      isNot(contains('last_used_written')),
    );
  });

  test('an app that edited the primary before the service wrote it is '
      'merged, not refused', () async {
    service = await demo.start(transport: transport, policy: null);
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    final read = File(demo.primaryPath).readAsBytesSync();
    // The service writes the primary itself (a grant).
    await admin.request('grants.add', {
      'grant': {
        'host': 'bomber',
        'subject': 'exe /usr/bin/backup',
        'secret': 'all',
        'decision': 'allow',
      },
    });
    final edited = await KdbxFormat().read(
      read,
      Credentials(ProtectedValue.fromString(primaryPassword)),
    );
    final entry = KdbxEntry.create(edited, edited.body.rootGroup)
      ..setString(KdbxKeyCommon.TITLE, PlainValue('Added by the app'));
    edited.body.rootGroup.addEntry(entry);
    await admin.request('save', {
      'store': 'primary',
      'bytes': base64.encode(await edited.save()),
      'baseRevision': tomSecretsBlobId(read),
    });
    final merged = await onDisk();
    expect(
      merged.body.rootGroup.getAllEntries().map((e) => e.label),
      contains('Added by the app'),
    );
    expect(
      TomSecretsGrantsGroup(merged).read('bomber', TomSecretsSignedKind.grant),
      hasLength(1),
      reason: 'the service\'s own write kept',
    );
  });
}
