// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Client tokens (protocol.md 7.4, DP-20, decision (c) of tsm_a_ct1): the
/// approving device makes the token; the host keeps its hash and hands the
/// token to the client, whose later `hello.clientToken` makes it the
/// `exe-token` subject; without the token it is the bare executable;
/// revoking the grant invalidates the token; a remote approver sends the
/// token with its grant over the approval link; an approval code issues no
/// token. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 3))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show
        TomSecretsApproverKey,
        TomSecretsLinkKey,
        TomSecretsLinkSession,
        TomSecretsRecordedApprover,
        TomSecretsRecordedHost,
        TomSecretsSignedLabels,
        TomSecretsSocketChannel,
        TomSecretsDeviceSettings,
        tomSecretsClientTokenHash,
        tomSecretsClientTokenId;
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

String _newToken() {
  final r = Random.secure();
  return base64.encode(List.generate(32, (_) => r.nextInt(256)));
}

String _idOf(String token) =>
    tomSecretsClientTokenId(tomSecretsClientTokenHash(base64.decode(token)));

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

  Future<void> start({bool subscribe = true}) async {
    service = await demo.start(transport: transport, policy: null);
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    if (subscribe) await admin.request('subscribe');
  }

  Future<TomSecretsClient> client([String? token]) async {
    final c = await TomSecretsClient.connect(
      clientName: 'demo-extension-host',
      clientToken: token,
      environment: demo.clientEnvironment(),
    );
    addTearDown(c.close);
    return c;
  }

  /// Whether [ref] is answered without a prompt (a grant decides) within a
  /// second; a prompt that nobody answers ends `timeout`.
  Future<bool> answeredByGrant(TomSecretsClient c, String ref) async {
    try {
      await c.get(ref, timeout: const Duration(seconds: 1));
      return true;
    } on TomSecretsClientException catch (e) {
      expect(e.kind, TomSecretsErrorKind.timeout);
      return false;
    }
  }

  test(
    'the app approves always with a token: the client gets it, the host '
    'keeps its hash, a later connection with it is the exe-token subject, '
    'without it the bare executable; revoked, the token is invalid',
    () async {
      await start();
      final token = _newToken();
      final needed = admin.events.firstWhere(
        (e) => e['op'] == 'approval_needed',
      );
      final c = await client();
      final answer = c.get('primary/Db/Main', wantClientToken: true);
      final event = await needed;
      expect(event['wantClientToken'], isTrue);
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'always',
        'secret': 'ref',
        'clientToken': token,
      });
      final value = await answer;
      expect(value.text, 'demo-db-pw');
      expect(value.clientToken, token);

      final grant =
          ((await admin.request('grants.list', {
                        'host': 'demo-host',
                      }))['grants']!
                      as List)
                  .single
              as Map;
      final exe = tomSecretsProcessInfo(pid)!.exe;
      expect(grant['subject'], 'exe-token $exe ${_idOf(token)}');
      expect(grant['accepted'], isTrue);
      final stored = jsonEncode(service.trust.toJson());
      expect(stored, isNot(contains(token)), reason: 'only the hash is kept');
      expect(stored, contains(tomSecretsClientTokenHash(base64.decode(token))));

      final withToken = await client(token);
      expect(await answeredByGrant(withToken, 'primary/Db/Main'), isTrue);
      final record = service.trust.clientTokens[_idOf(token)]!;
      expect(record.firstIdentity?['exe'], exe);
      expect(record.lastSeen, isNotNull);

      final without = await client();
      expect(
        await answeredByGrant(without, 'primary/Db/Main'),
        isFalse,
        reason: 'the bare executable: no grant',
      );
      final wrong = await client(_newToken());
      expect(await answeredByGrant(wrong, 'primary/Db/Main'), isFalse);

      await admin.request('grants.revoke', {
        'host': 'demo-host',
        'grantId': grant['id'],
      });
      expect(service.trust.clientTokens, isEmpty);
      final revoked = await client(token);
      expect(await answeredByGrant(revoked, 'primary/Db/Main'), isFalse);
    },
  );

  test('a token is refused unless 32 bytes for an always of a request that '
      'asked for one', () async {
    await start();
    final needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final c = await client();
    final answer = c.get('primary/Db/Main');
    final event = await needed;
    for (final bad in [
      {'decision': 'always', 'clientToken': _newToken()},
      {'decision': 'once', 'clientToken': _newToken()},
    ]) {
      await expectLater(
        admin.request('approve', {
          'approvalId': event['approvalId'],
          'secret': 'ref',
          ...bad,
        }),
        throwsA(
          isA<TomSecretsAdminException>().having(
            (e) => e.kind,
            'kind',
            'malformed',
          ),
        ),
      );
    }
    await admin.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    expect((await answer).clientToken, isNull);
  });

  test('a remote approver sends the token with its exe-token grant; a grant '
      'that does not name the token is refused', () async {
    await start();
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
    await service.deviceContainer!.write(
      TomSecretsDeviceSettings.fromJson({
        ...service.deviceContainer!.settings.toJson(),
        'approvalLink': '127.0.0.1:0',
      }),
    );
    await admin.request('lock');
    await admin.unlock(primaryPassword);
    final hostKey = (await service.trust.linkKey()).publicKey;
    final port = service.linkServer!.port;
    await admin.close();
    final session = await TomSecretsLinkSession.initiate(
      TomSecretsSocketChannel(
        await Socket.connect(InternetAddress.loopbackIPv4, port),
      ),
      me: approverLink,
      hostKey: hostKey,
      device: 'mbp',
    );
    addTearDown(session.close);
    final messages = StreamIterator(session.messages);
    Future<Map<String, Object?>> next(
      bool Function(Map<String, Object?>) f,
    ) async {
      while (await messages.moveNext()) {
        if (f(messages.current)) return messages.current;
      }
      fail('the link closed');
    }

    final c = await client();
    final answer = c.get('primary/Db/Main', wantClientToken: true);
    final needed = await next((m) => m['op'] == 'approval_needed');
    expect(needed['wantClientToken'], isTrue);
    final exe = (needed['identity']! as Map)['exe']! as String;

    Future<Map<String, Object?>> grantOf(String tokenId, String id) =>
        approverKey.signObject(TomSecretsSignedLabels.grant, {
          'id': id,
          'host': 'demo-host',
          'subject': 'exe-token $exe $tokenId',
          'secret': 'all',
          'decision': 'allow',
          'created': DateTime.now().toUtc().toIso8601String(),
          'pin': 'off',
          'approver': 'mbp',
        });

    final token = _newToken();
    await session.send({
      'op': 'grant',
      'id': 1,
      'grant': await grantOf(_idOf(_newToken()), 'g-other'),
      'clientToken': token,
      'approvalId': needed['approvalId'],
    });
    expect((await next((m) => m['id'] == 1))['kind'], 'denied');

    await session.send({
      'op': 'grant',
      'id': 2,
      'grant': await grantOf(_idOf(token), 'g-token'),
      'clientToken': token,
      'approvalId': needed['approvalId'],
    });
    expect((await next((m) => m['id'] == 2))['op'], 'ok');
    final value = await answer;
    expect(value.clientToken, token);
    final withToken = await client(token);
    expect(await answeredByGrant(withToken, 'primary/Db/Main'), isTrue);
    await messages.cancel();
  });

  test(
    'an approval code issues no token: answered, the value has none',
    () async {
      await start(subscribe: false);
      final tokenKey = Uint8List.fromList(List.generate(32, (i) => i + 7));
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
        wantClientToken: true,
        onProgress: (p) {
          if (p.approvalCode != null && !code.isCompleted) {
            code.complete(p.approvalCode);
          }
        },
      );
      final issued = await admin.request('approval.issue', {
        'host': 'demo-host',
        'code': await code.future,
        'decision': 'always',
        'secret': 'ref',
      });
      await admin.request('approval.redeem', {'token': issued['token']});
      final value = await answer;
      expect(value.text, 'demo-db-pw');
      expect(value.clientToken, isNull);
    },
  );
}
