// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Approvals, grants, the audit log and the approval link in the service
/// (part-protocol, protocol.md 7, 9; DP-17, DP-19, DP-100, DP-160, TD-3):
/// a prompt to the attached app answered once, always (a signed grant in
/// `tsm.grants/<host>`) or never; the approval timeout; the approval code
/// and its single-use token when no approver is attached; grants that do not
/// verify ignored; revocation; `tsm`'s limits; the audit records; and a
/// remote approver over the approval link. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 3))
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show
        Credentials,
        KdbxFormat,
        ProtectedValue,
        TomSecretsApproverKey,
        TomSecretsDeviceSettings,
        TomSecretsGrantsGroup,
        TomSecretsLinkKey,
        TomSecretsLinkSession,
        TomSecretsRecordedApprover,
        TomSecretsRecordedHost,
        TomSecretsSignedKind,
        TomSecretsSignedLabels,
        TomSecretsSocketChannel;
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// Measures every peer as [identity] (a `tsm`, for its limits).
final class FixedMeasurer implements TomSecretsPeerMeasurer {
  const FixedMeasurer(this.identity);

  final TomSecretsIdentity identity;

  @override
  Future<TomSecretsPeerMeasurement> measure(Socket socket) async =>
      TomSecretsPeerMeasured(identity);
}

void main() {
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;
  late Demo demo;
  late TomSecretsService service;

  setUp(() async {
    demo = await Demo.create();
  });

  Future<TomSecretsAdminClient> admin({bool subscribe = false}) async {
    final a = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(a.close);
    if (subscribe) await a.request('subscribe');
    return a;
  }

  Future<TomSecretsAdminClient> start({
    TomSecretsPeerMeasurer? measurer,
    bool subscribe = true,
  }) async {
    service = await demo.start(
      transport: transport,
      policy: null,
      peerMeasurer: measurer,
    );
    final a = await admin();
    await a.unlock(primaryPassword);
    if (subscribe) await a.request('subscribe');
    return a;
  }

  Future<TomSecretsClient> client() async {
    final c = await TomSecretsClient.connect(
      clientName: 'demo-client',
      environment: demo.clientEnvironment(),
    );
    addTearDown(c.close);
    return c;
  }

  Future<void> settings(Map<String, Object?> changes) async {
    final container = service.deviceContainer!;
    await container.write(
      TomSecretsDeviceSettings.fromJson({
        ...container.settings.toJson(),
        ...changes,
      }),
    );
  }

  Matcher fails(TomSecretsErrorKind kind, [String? reason]) => throwsA(
    isA<TomSecretsClientException>()
        .having((e) => e.kind, 'kind', kind)
        .having((e) => e.reason, 'reason', reason ?? anything),
  );

  test('a prompt answered once: the value, approval_closed, the audit '
      'record; asked again, a new prompt', () async {
    final a = await start();
    final needed = a.events.firstWhere((e) => e['op'] == 'approval_needed');
    final closed = a.events.firstWhere((e) => e['op'] == 'approval_closed');
    final pending = <String>[];
    final c = await client();
    final answer = c.get(
      'primary/Db/Main',
      onProgress: (p) => pending.add(p.pending.name),
    );
    final event = await needed;
    expect(event['host'], 'demo-host');
    expect(event['refs'], ['primary/Db/Main']);
    expect((event['identity']! as Map)['uid'], tomSecretsOwnUid());
    expect(event['resolved'], [
      {'store': 'primary', 'path': 'Db/Main', 'kind': 'login'},
    ]);
    expect(event['approvalCode'], isNull, reason: 'an approver is attached');
    await a.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    expect((await answer).text, 'demo-db-pw');
    expect(pending, ['approval']);
    expect(await closed, containsPair('outcome', 'approved'));

    final again = a.events.firstWhere((e) => e['op'] == 'approval_needed');
    // The expectation is attached at once: the refusal may arrive before
    // the admin's ok.
    final second = expectLater(
      c.get('primary/Db/Main'),
      fails(TomSecretsErrorKind.denied, 'refused'),
    );
    final event2 = await again;
    await a.request('approve', {
      'approvalId': event2['approvalId'],
      'decision': 'never',
      'secret': 'ref',
    });
    await second;

    final records = await a.request('audit.query', {
      'from': DateTime.now()
          .subtract(const Duration(hours: 1))
          .toIso8601String(),
      'to': DateTime.now().add(const Duration(hours: 1)).toIso8601String(),
      'ref': 'primary/Db/Main',
    });
    final outcomes = [
      for (final r in records['records']! as List) (r as Map)['outcome'],
    ];
    expect(outcomes, containsAll(['allowed', 'denied:refused']));
    expect(records.toString(), isNot(contains('demo-db-pw')));
  });

  test('always: a signed grant in tsm.grants/<host>, which answers the next '
      'request without a prompt; revoked, it asks again', () async {
    final a = await start();
    final needed = a.events.firstWhere((e) => e['op'] == 'approval_needed');
    final c = await client();
    final first = c.get('primary/Db/Main');
    final event = await needed;
    await a.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'always',
      'secret': 'ref',
    });
    expect((await first).text, 'demo-db-pw');
    final listed = await a.request('grants.list', {'host': 'demo-host'});
    final grant = (listed['grants']! as List).single as Map;
    expect(grant['accepted'], isTrue);
    expect(grant['secret'], 'primary/Db/Main');
    expect(grant['decision'], 'allow');
    expect((grant['signatures']! as List), hasLength(2));
    // On disk, in the primary vault.
    final file = await KdbxFormat().read(
      File(demo.primaryPath).readAsBytesSync(),
      Credentials(ProtectedValue.fromString(primaryPassword)),
    );
    expect(
      TomSecretsGrantsGroup(
        file,
      ).read('demo-host', TomSecretsSignedKind.grant).single['id'],
      grant['id'],
    );

    var prompted = false;
    final sub = a.events.listen((e) {
      if (e['op'] == 'approval_needed') prompted = true;
    });
    expect((await c.get('primary/Db/Main')).text, 'demo-db-pw');
    expect(prompted, isFalse, reason: 'the grant answered');

    await a.request('grants.revoke', {
      'host': 'demo-host',
      'grantId': grant['id'],
    });
    final again = c.get('primary/Db/Main', timeout: const Duration(seconds: 1));
    await expectLater(again, fails(TomSecretsErrorKind.timeout));
    expect(prompted, isTrue, reason: 'revoked: asked again');
    await sub.cancel();
  });

  test('a grant that does not verify is ignored; grants.add signs one; a '
      'never grant refuses at once', () async {
    final a = await start();
    final primary = service.primary!;
    TomSecretsGrantsGroup(
      primary,
    ).write('demo-host', TomSecretsSignedKind.grant, {
      'id': 'g-forged',
      'host': 'demo-host',
      'subject': 'exe ${tomSecretsProcessInfo(pid)!.exe}',
      'secret': 'all',
      'decision': 'allow',
      'created': '2026-11-13T10:00:00Z',
      'pin': 'off',
      'approver': 'mallory',
      'signatures': const [],
    });
    await service.approvals!.reload();
    expect(service.approvals!.grants, isEmpty);

    final self = tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!);
    final subject = self.kind == 'script'
        ? 'script ${self.interpreter} ${self.script}'
        : 'exe ${self.exe}';
    await a.request('grants.add', {
      'grant': {
        'host': 'demo-host',
        'subject': subject,
        'secret': 'store primary',
        'decision': 'never',
        'pin': 'off',
      },
    });
    final c = await client();
    await expectLater(
      c.get('primary/Db/Main'),
      fails(TomSecretsErrorKind.denied, 'never'),
    );
  });

  test('a prompt waiting when the service locks: abandoned, the client '
      'gets locked', () async {
    final a = await start();
    final needed = a.events.firstWhere((e) => e['op'] == 'approval_needed');
    final closed = a.events.firstWhere((e) => e['op'] == 'approval_closed');
    final c = await client();
    final answer = expectLater(
      c.get('primary/Db/Main'),
      fails(TomSecretsErrorKind.locked),
    );
    await needed;
    await a.request('lock');
    await answer;
    expect(await closed, containsPair('outcome', 'abandoned'));
  });

  test('the approval timeout ends an unanswered prompt', () async {
    await start();
    await settings({'approvalTimeoutSeconds': 1});
    final c = await client();
    await expectLater(
      c.get('primary/Db/Main'),
      fails(TomSecretsErrorKind.timeout),
    );
  });

  test('no approver attached: an approval code, a single-use token from '
      'approval.issue redeemed with approval.redeem; bad tokens end the '
      'request', () async {
    final a = await start(subscribe: false);
    // This device approves for itself here: the token key it shares with
    // the host is the one it recorded as an approver.
    final tokenKey = Uint8List.fromList(List.generate(32, (i) => i + 1));
    final trust = service.trust;
    trust.approvers.add(
      TomSecretsRecordedApprover(
        device: 'mbp',
        approverKey: (await trust.approverKey()).publicKey,
        tokenKey: tokenKey,
      ),
    );
    trust.hosts.add(
      TomSecretsRecordedHost(
        host: 'demo-host',
        linkKey: (await trust.linkKey()).publicKey,
        tokenKey: tokenKey,
      ),
    );
    await service.writeTrust();

    final c = await client();
    final code = Completer<String>();
    final answer = c.get(
      'primary/Db/Main',
      onProgress: (p) {
        if (p.approvalCode != null && !code.isCompleted) {
          code.complete(p.approvalCode);
        }
      },
    );
    final shown = await code.future;
    expect(shown, matches(RegExp(r'^[A-Z2-7]{10}$')));
    final issued = await a.request('approval.issue', {
      'host': 'demo-host',
      'code': shown.toLowerCase(),
      'decision': 'once',
      'secret': 'ref',
    });
    final token = issued['token']! as String;
    await a.request('approval.redeem', {'token': token});
    expect((await answer).text, 'demo-db-pw');
    await expectLater(
      a.request('approval.redeem', {'token': token}),
      throwsA(
        isA<TomSecretsAdminException>().having(
          (e) => e.details['reason'],
          'reason',
          'bad_token',
        ),
      ),
      reason: 'single use: its request has ended',
    );

    final code2 = Completer<String>();
    final second = expectLater(
      c.get(
        'primary/Db/Main',
        onProgress: (p) {
          if (p.approvalCode != null && !code2.isCompleted) {
            code2.complete(p.approvalCode);
          }
        },
      ),
      fails(TomSecretsErrorKind.denied, 'bad_token'),
    );
    await code2.future;
    for (var i = 0; i < 3; i++) {
      await expectLater(
        a.request('approval.redeem', {'token': 'A' * 26}),
        throwsA(isA<TomSecretsAdminException>()),
      );
    }
    await second;
  });

  test('no approver and no token: the code timeout ends the request '
      'no_approver', () async {
    await start(subscribe: false);
    await settings({'codeTimeoutSeconds': 1});
    final c = await client();
    await expectLater(
      c.get('primary/Db/Main'),
      fails(TomSecretsErrorKind.denied, 'no_approver'),
    );
  });

  test('three refusals in ten minutes hold the identity back '
      '(rate_limited), and the app hears of it', () async {
    final a = await start();
    final c = await client();
    final heldBack = a.events.firstWhere((e) => e['op'] == 'rate_limited');
    // Three different references: a never at a prompt is also a never
    // grant, which refuses the same reference again without a prompt.
    for (final ref in [
      'primary/Db/Main',
      'primary/Db/Main#Title',
      'team/Api/Token',
    ]) {
      final needed = a.events.firstWhere((e) => e['op'] == 'approval_needed');
      final answer = expectLater(
        c.get(ref),
        fails(TomSecretsErrorKind.denied, 'refused'),
      );
      final event = await needed;
      await a.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'never',
        'secret': 'ref',
      });
      await answer;
    }
    expect((await heldBack)['until'], isA<String>());
    await expectLater(
      c.get('team/Api/Token#Title'),
      throwsA(
        isA<TomSecretsClientException>().having(
          (e) => e.kind,
          'kind',
          TomSecretsErrorKind.rateLimited,
        ),
      ),
    );
  });

  test('an approval record in the vault answers the waiting code (tsm '
      'approve without a token)', () async {
    await start(subscribe: false);
    final c = await client();
    final code = Completer<String>();
    final answer = c.get(
      'primary/Db/Main',
      onProgress: (p) {
        if (p.approvalCode != null && !code.isCompleted) {
          code.complete(p.approvalCode);
        }
      },
    );
    final shown = await code.future;
    final key = await service.trust.approverKey();
    final record = await key.signObject(TomSecretsSignedLabels.approval, {
      'host': 'demo-host',
      'code': shown,
      'decision': 'once',
      'approver': 'phone',
      'created': DateTime.now().toUtc().toIso8601String(),
    });
    TomSecretsGrantsGroup(
      service.primary!,
    ).write('demo-host', TomSecretsSignedKind.approval, record);
    await service.approvals!.reload();
    expect((await answer).text, 'demo-db-pw');
  });

  test('the audit log: records encrypted, queried by time, subject and '
      'reference, old days deleted', () async {
    final dir = Directory.systemTemp.createTempSync('tsmaudit');
    addTearDown(() => dir.deleteSync(recursive: true));
    final key = List.generate(32, (i) => i);
    final log = TomSecretsAuditLog(
      dir.path,
      key,
      retention: const Duration(days: 2),
    );
    final now = DateTime.now().toUtc();
    TomSecretsAuditRecord record(DateTime time, String exe, String ref) =>
        TomSecretsAuditRecord(
          time: time,
          host: 'demo-host',
          identity: {'kind': 'exe', 'exe': exe},
          refs: [ref],
          outcome: 'allowed',
          grantId: 'g-1',
        );
    log
      ..add(record(now, '/usr/bin/a', 'db.main'))
      ..add(record(now, '/usr/bin/b', 'db.other'))
      ..add(
        record(now.subtract(const Duration(days: 10)), '/usr/bin/a', 'x.y'),
      );
    await log.flush();
    final files = dir.listSync().map((f) => f.uri.pathSegments.last).toList();
    expect(files, hasLength(1), reason: 'the ten-day-old day is deleted');
    final text = File(dir.listSync().single.path).readAsStringSync();
    expect(text, isNot(contains('db.main')), reason: 'encrypted');
    final range = (
      from: now.subtract(const Duration(hours: 1)),
      to: now.add(const Duration(hours: 1)),
    );
    expect(await log.query(from: range.from, to: range.to), hasLength(2));
    final byA = await log.query(
      from: range.from,
      to: range.to,
      subject: '/usr/bin/a',
    );
    expect(byA.single.refs, ['db.main']);
    expect(
      (await log.query(
        from: range.from,
        to: range.to,
        ref: 'db.other',
      )).single.identity['exe'],
      '/usr/bin/b',
    );
    final other = TomSecretsAuditLog(dir.path, List.filled(32, 9));
    expect(
      await other.query(from: range.from, to: range.to),
      isEmpty,
      reason: 'another key reads nothing',
    );
  });

  test('tsm cannot answer a prompt, pre-approve or issue tokens unless '
      'command-line approvals are on, which only the app switches', () async {
    final tsm = TomSecretsIdentity(
      kind: 'exe',
      exe: '/usr/local/bin/tsm',
      args: const ['get', 'x'],
      cwd: '/',
      uid: tomSecretsOwnUid()!,
    );
    final a = await start(measurer: FixedMeasurer(tsm), subscribe: false);
    Matcher refused(String reason) => throwsA(
      isA<TomSecretsAdminException>().having(
        (e) => e.details['reason'],
        'reason',
        reason,
      ),
    );
    await expectLater(
      a.request('approve', {
        'approvalId': 'a-1',
        'decision': 'once',
        'secret': 'ref',
      }),
      refused('not_allowed_op'),
    );
    await expectLater(
      a.request('grants.add', {
        'grant': {
          'host': 'demo-host',
          'subject': 'exe /usr/bin/x',
          'secret': 'all',
          'decision': 'allow',
        },
      }),
      refused('not_allowed_op'),
    );
    await expectLater(
      a.request('approvers.cliSwitch', {'on': true}),
      refused('wrong_executable'),
    );
  });

  test('a remote approver over the approval link: the prompt, its answer, '
      'its signed grant applied at once, a revocation', () async {
    final a = await start();
    final approverLink = await TomSecretsLinkKey.fromSeeds(
      Uint8List(32)..[0] = 5,
      Uint8List(64)..[0] = 5,
    );
    final approverKey = await TomSecretsApproverKey.fromSeeds(
      Uint8List(32)..[0] = 6,
      Uint8List(32)..[0] = 6,
    );
    service.trust.approvers.add(
      TomSecretsRecordedApprover(
        device: 'mbp',
        approverKey: approverKey.publicKey,
        linkKey: approverLink.publicKey,
        tokenKey: Uint8List(32),
      ),
    );
    await service.writeTrust();
    await settings({'approvalLink': '127.0.0.1:0'});
    // The link listens from the next unlock.
    await a.request('lock');
    await a.unlock(primaryPassword);
    final port = service.linkServer!.port;
    final hostKey = (await service.trust.linkKey()).publicKey;
    // A remote approver only: the local admin unsubscribes.
    await a.close();

    final session = await TomSecretsLinkSession.initiate(
      TomSecretsSocketChannel(
        await Socket.connect(InternetAddress.loopbackIPv4, port),
      ),
      me: approverLink,
      hostKey: hostKey,
      device: 'mbp',
    );
    addTearDown(session.close);
    expect(session.peerDevice, 'demo-host');
    final messages = StreamIterator(session.messages);

    final c = await client();
    final answer = c.get('primary/Db/Main');
    expect(await messages.moveNext(), isTrue);
    final needed = messages.current;
    expect(needed['op'], 'approval_needed');
    await session.send({
      'op': 'approve',
      'id': 1,
      'approvalId': needed['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    final replies = <Map<String, Object?>>[];
    while (replies.where((m) => m['op'] == 'ok').isEmpty) {
      expect(await messages.moveNext(), isTrue);
      replies.add(messages.current);
    }
    expect((await answer).text, 'demo-db-pw');

    final self = tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!);
    final grant = await approverKey.signObject(TomSecretsSignedLabels.grant, {
      'id': 'g-remote',
      'host': 'demo-host',
      'subject': self.kind == 'script'
          ? 'script ${self.interpreter} ${self.script}'
          : 'exe ${self.exe}',
      'secret': 'all',
      'decision': 'allow',
      'created': DateTime.now().toUtc().toIso8601String(),
      'pin': 'off',
      'approver': 'mbp',
    });
    await session.send({'op': 'grant', 'id': 2, 'grant': grant});
    Future<Map<String, Object?>> reply(int id) async {
      while (await messages.moveNext()) {
        if (messages.current['id'] == id) return messages.current;
      }
      fail('the link closed');
    }

    expect((await reply(2))['op'], 'ok');
    expect((await c.get('primary/Db/Main')).text, 'demo-db-pw');

    final forged = {...grant, 'id': 'g-forged', 'secret': 'primary/X'};
    await session.send({'op': 'grant', 'id': 3, 'grant': forged});
    expect((await reply(3))['kind'], 'denied');

    final revocation = await approverKey
        .signObject(TomSecretsSignedLabels.revoke, {
          'host': 'demo-host',
          'grantId': 'g-remote',
          'revoked': DateTime.now().toUtc().toIso8601String(),
          'approver': 'mbp',
        });
    await session.send({'op': 'revoke', 'id': 4, ...revocation});
    expect((await reply(4))['op'], 'ok');
    expect(service.approvals!.grants, isEmpty);
    await messages.cancel();
  });
}
