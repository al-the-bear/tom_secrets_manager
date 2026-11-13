// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The peer identity in the service (part-protocol, protocol.md 6.1, 7.1):
/// an admin from another program is refused even with the right key, a
/// client the service cannot measure or of another user is refused, and the
/// access policy decides on the measured identity, never on `hello.client`.
/// Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// Allows every value and records what it was asked.
final class RecordingPolicy implements TomSecretsAccessPolicy {
  final List<TomSecretsAccessRequest> requests = [];

  @override
  Future<TomSecretsAccess> check(TomSecretsAccessRequest request) async {
    requests.add(request);
    return const TomSecretsAccessAllowed();
  }
}

/// Refuses every peer for [reason].
final class RefusingMeasurer implements TomSecretsPeerMeasurer {
  const RefusingMeasurer(this.reason);

  final String reason;

  @override
  Future<TomSecretsPeerMeasurement> measure(Socket socket) async =>
      TomSecretsPeerRefused(reason);
}

void main() {
  // Unix sockets on Linux and macOS, localhost TCP on Windows: the
  // transports the service uses there, measured by the system measurer.
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;
  late Demo demo;

  setUp(() async {
    demo = await Demo.create();
  });

  Future<TomSecretsAdminClient> admin() async {
    final client = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(client.close);
    return client;
  }

  test('an admin from another program is refused even with the right key; '
      'its own executable is let in', () async {
    final service = await demo.start(
      transport: transport,
      adminExecutables: {'/nowhere/bin/tsm'},
    );
    await expectLater(
      admin(),
      throwsA(
        isA<TomSecretsAdminException>()
            .having((e) => e.kind, 'kind', 'denied')
            .having((e) => e.details['reason'], 'reason', 'wrong_executable'),
      ),
    );
    await service.stop();

    final self = tomSecretsProcessInfo(pid)!.exe;
    await demo.start(transport: transport, adminExecutables: {self});
    final ok = await admin();
    await ok.unlock(primaryPassword);
    expect((await ok.request('status'))['locked'], isFalse);
  });

  test('an admin the service cannot measure is refused', () async {
    await demo.start(
      transport: transport,
      peerMeasurer: const RefusingMeasurer('unidentifiable'),
    );
    await expectLater(
      admin(),
      throwsA(
        isA<TomSecretsAdminException>().having(
          (e) => e.details['reason'],
          'reason',
          'unidentifiable',
        ),
      ),
    );
  });

  test('a client of another user is refused outright', () async {
    await demo.start(
      transport: transport,
      peerMeasurer: const RefusingMeasurer('other_user'),
    );
    await expectLater(
      TomSecretsClient.connect(
        clientName: 'demo-client',
        environment: demo.clientEnvironment(),
      ).then((c) => c.get('primary/Db/Main')),
      throwsA(
        isA<TomSecretsClientException>()
            .having((e) => e.kind, 'kind', TomSecretsErrorKind.denied)
            .having((e) => e.reason, 'reason', 'other_user'),
      ),
    );
  });

  test('the policy decides on the measured identity', () async {
    final policy = RecordingPolicy();
    await demo.start(transport: transport, policy: policy);
    await (await admin()).unlock(primaryPassword);
    final client = await TomSecretsClient.connect(
      clientName: 'claims-to-be-something-else',
      environment: demo.clientEnvironment(),
    );
    addTearDown(client.close);
    expect((await client.get('primary/Db/Main')).text, 'demo-db-pw');
    final request = policy.requests.single;
    expect(request.client['name'], 'claims-to-be-something-else');
    final identity = request.identity;
    expect(identity.pid, pid, reason: 'the test process itself');
    expect(identity.uid, tomSecretsOwnUid());
    expect(identity.exe, tomSecretsProcessInfo(pid)!.exe);
    expect(
      identity.toJson().keys,
      containsAll(['kind', 'exe', 'args', 'cwd', 'uid']),
    );
  });
}
