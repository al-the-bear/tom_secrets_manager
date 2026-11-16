// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A demo installation for the service's tests: a primary vault naming a
/// second vault, both `file:` vaults under demo keys, a bootstrap, a
/// runtime directory. Demo data only.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_github_api/testing.dart' show FakeGitHubServer;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

/// The primary's demo master password.
const primaryPassword = 'primary-demo-pw';

/// The team vault's demo password.
const teamPassword = 'team-demo-pw';

/// A light Argon2id, so a test opens a vault in milliseconds.
const testArgon2 = KdbxArgon2(
  type: KdbxArgon2Type.argon2id,
  memory: 1 << 20,
  iterations: 1,
);

/// Allows every value (the tests of the endpoint, not of the allow list).
final class AllowAllPolicy implements TomSecretsAccessPolicy {
  /// The policy.
  const AllowAllPolicy();

  @override
  Future<List<TomSecretsAccess>> check(TomSecretsAccessBatch batch) async => [
    for (final _ in batch.items) const TomSecretsAccessAllowed(),
  ];
}

/// The identity of this process, for the tests' TCP runs on Linux and
/// macOS: TCP is the Windows transport, and a TCP connection there carries
/// no peer credentials, so the system measurer refuses it; the tests' client
/// is this process.
final class SelfPeerMeasurer implements TomSecretsPeerMeasurer {
  /// The measurer.
  const SelfPeerMeasurer();

  @override
  Future<TomSecretsPeerMeasurement> measure(Socket socket) async =>
      TomSecretsPeerMeasured(tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!));
}

/// An idle source the test sets.
final class FakeIdle implements TomSecretsIdleSource {
  /// The idle time answered (null: headless).
  Duration? idle = Duration.zero;

  @override
  Future<Duration?> idleTime() async => idle;
}

KdbxEntry _add(KdbxFile file, List<String> path, String title, String pw) {
  var group = file.body.rootGroup;
  for (final name in path) {
    group =
        group.groups.where((g) => g.name.get() == name).firstOrNull ??
        file.createGroup(parent: group, name: name);
  }
  final entry = KdbxEntry.create(file, group)
    ..setString(KdbxKeyCommon.TITLE, PlainValue(title))
    ..setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(pw));
  group.addEntry(entry);
  return entry;
}

/// A demo installation in a temporary directory (the system's temp: a Unix
/// socket path is limited to 104 bytes on macOS, which the workspace path
/// exceeds).
final class Demo {
  Demo._(this.dir);

  /// Makes the vaults and the bootstrap.
  static Future<Demo> create({
    TomSecretsDeviceKeyMode deviceKey = TomSecretsDeviceKeyMode.keyfile,
  }) async {
    final dir = Directory.systemTemp.createTempSync('tsm');
    addTearDown(() {
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    });
    final demo = Demo._(dir.path);
    final team = tomSecretsNewVault(
      Credentials(ProtectedValue.fromString(teamPassword)),
      'team',
      argon2: testArgon2,
    );
    _add(team, ['Api'], 'Token', 'demo-api-token');
    await File(demo.teamPath).writeAsBytes(await team.save());

    final primary = tomSecretsNewVault(
      Credentials(ProtectedValue.fromString(primaryPassword)),
      'primary',
      argon2: testArgon2,
    );
    _add(primary, ['Db'], 'Main', 'demo-db-pw');
    TomSecretsPrimaryVaults(primary).put(
      TomSecretsVaultKeys(
        name: 'team',
        locator: 'file:${demo.teamPath}',
        password: teamPassword,
      ),
    );
    await File(demo.primaryPath).writeAsBytes(await primary.save());
    demo.bootstrap = TomSecretsBootstrap(
      primary: 'file:${demo.primaryPath}',
      dataDirectory: '${dir.path}/data',
      deviceKey: deviceKey,
    );
    return demo;
  }

  /// The directory.
  final String dir;

  /// The primary vault's file.
  String get primaryPath => '$dir/primary.kdbx';

  /// The team vault's file.
  String get teamPath => '$dir/team.kdbx';

  /// The bootstrap.
  late TomSecretsBootstrap bootstrap;

  /// The admin key the tests start the service with.
  final Uint8List adminKey = tomSecretsRandomBytes();

  /// The idle source.
  final FakeIdle idle = FakeIdle();

  /// A runtime directory of [transport].
  TomSecretsRuntime runtime([
    TomSecretsTransport transport = TomSecretsTransport.unix,
  ]) => TomSecretsRuntime('$dir/run', transport: transport);

  /// Starts a service.
  Future<TomSecretsService> start({
    TomSecretsTransport transport = TomSecretsTransport.unix,
    // Null: the service's own approvals and grants.
    TomSecretsAccessPolicy? policy = const AllowAllPolicy(),
    TomSecretStore? keychain,
    Duration Function(int)? authDelay,
    TomSecretsPeerMeasurer? peerMeasurer,
    Set<String>? adminExecutables,
    Duration? lastUsedInterval,
    http.Client? githubClient,
    DateTime Function()? clock,
    Duration refreshTick = const Duration(minutes: 1),
    TomSecretsGitRemoteFor? githubRemoteFor,
    TomSecretsCommitReaderFor? githubReaderFor,
    String host = 'demo-host',
    Duration approverLinkRetry = const Duration(milliseconds: 100),
  }) async {
    final service = await TomSecretsService.launch(
      TomSecretsServiceConfig(
        runtime: runtime(transport),
        bootstrap: bootstrap,
        adminKey: adminKey,
        idleSource: idle,
        keychain: keychain,
        policy: policy,
        host: host,
        lockCheckInterval: const Duration(milliseconds: 20),
        authDelay: authDelay ?? (n) => Duration(milliseconds: 10 * n),
        peerMeasurer:
            peerMeasurer ??
            (transport == TomSecretsTransport.tcp && !Platform.isWindows
                ? const SelfPeerMeasurer()
                : null),
        adminExecutables: adminExecutables,
        lastUsedInterval: lastUsedInterval,
        githubBaseUrl: FakeGitHubServer.baseUrl,
        githubClient: githubClient,
        clock: clock,
        refreshTick: refreshTick,
        githubRemoteFor: githubRemoteFor,
        githubReaderFor: githubReaderFor,
        approverLinkRetry: approverLinkRetry,
      ),
    );
    addTearDown(service.stop);
    return service;
  }

  /// The environment a client library finds this runtime directory with.
  Map<String, String> clientEnvironment() => {'TSM_RUNTIME_DIR': '$dir/run'};
}
