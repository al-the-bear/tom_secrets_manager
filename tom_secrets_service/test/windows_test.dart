// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service on Windows (part-service): the runtime directory restricted
/// to the user and SYSTEM (and another ACL refused), the endpoints as
/// localhost TCP ports with the client token, the admin challenge over TCP,
/// and the input idle time from `GetLastInputInfo`. Demo data only.
@TestOn('windows')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

void main() {
  test('the runtime directory: the user and SYSTEM only; another grant is '
      'refused', () async {
    final dir = Directory.systemTemp.createTempSync('tsmwin');
    addTearDown(() => dir.deleteSync(recursive: true));
    final runtime = TomSecretsRuntime(
      '${dir.path}\\run',
      transport: TomSecretsTransport.tcp,
    );
    await runtime.prepare();
    final acl =
        (await Process.run('icacls', [runtime.directory])).stdout as String;
    expect(acl, contains(Platform.environment['USERNAME']));
    expect(acl, isNot(contains('BUILTIN\\Users')));
    // Everyone by its well-known SID: the account's name is localised
    // ("Jeder" on a German Windows).
    final grant = await Process.run('icacls', [
      runtime.directory,
      '/grant',
      '*S-1-1-0:(R)',
    ]);
    expect(grant.exitCode, 0, reason: '${grant.stdout}');
    await expectLater(
      runtime.check(),
      throwsA(isA<TomSecretsRuntimeException>()),
    );
  });

  test(
    'TCP endpoints, the client token, the admin challenge, a value',
    () async {
      final demo = await Demo.create();
      final runtime = TomSecretsRuntime(
        '${demo.dir}\\run',
        transport: TomSecretsTransport.tcp,
      );
      final service = await TomSecretsService.launch(
        TomSecretsServiceConfig(
          runtime: runtime,
          bootstrap: demo.bootstrap,
          adminKey: demo.adminKey,
          policy: const AllowAllPolicy(),
          host: 'demo-host',
        ),
      );
      addTearDown(service.stop);
      final port = readTomSecretsPortFile(
        File(runtime.clientPortFile).readAsStringSync(),
      )!;
      final token = File(runtime.clientTokenFile).readAsStringSync().trim();
      expect(token, service.clientToken);

      final admin = await TomSecretsAdminClient.connect(runtime, demo.adminKey);
      await admin.unlock(primaryPassword);

      final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
      addTearDown(socket.destroy);
      final reader = TomSecretsFrameReader(
        maxPayload: tomSecretsMaxAnswerPayload,
      );
      final messages = socket
          .expand((b) => reader.add(b))
          .map((f) => tomSecretsDecodePayload(f.payload))
          .asBroadcastStream();
      socket.add(
        tomSecretsJsonFrame({
          'op': 'hello',
          'protocol': 1,
          'client': {'name': 'demo'},
          'token': token,
        }),
      );
      expect((await messages.first)['op'], 'welcome');
      socket.add(
        tomSecretsJsonFrame({'op': 'get', 'id': 1, 'ref': 'primary/Db/Main'}),
      );
      final value = await messages.first;
      expect(value['value'], 'demo-db-pw');
      expect(jsonEncode(value), contains('"encoding":"utf8"'));
    },
  );

  test('the input idle time from GetLastInputInfo', () async {
    final idle = await tomSecretsSystemIdleSource().idleTime();
    expect(idle, isNotNull);
    expect(idle!, greaterThanOrEqualTo(Duration.zero));
  });
}
