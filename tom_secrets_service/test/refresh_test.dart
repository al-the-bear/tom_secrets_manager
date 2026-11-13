// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `github:` vaults, the offline cache, the refresh and the key-expiry
/// reminders (part-service, part-key-rotation): the service opens its vaults
/// over GitHub's REST API (an in-memory GitHub here) with each repository's
/// token from the keychain or the primary's vault list, reopens a moved file
/// at the refresh, serves its held copy while GitHub cannot be reached or
/// refuses the token (`offline`, `token_expired`, backing off 1, 2, 4 …
/// minutes, a refused token not retried until `reload`), tells the attached
/// admins (`store_state`, `store_changed`), and reminds of expiring keys
/// (`key_expiry`, `status.expiring`). Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_github_api/testing.dart';
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

const _repo = 'al-the-bear/demo-vaults';
const _otherRepo = 'al-the-bear/other-vaults';
const _primary = 'github:$_repo/primary.kdbx';
const _team = 'github:$_repo/team.kdbx';
const _other = 'github:$_otherRepo/other.kdbx';
const _otherPassword = 'other-demo-pw';

enum _Net { online, unreachable, rejected }

/// The network between the service and GitHub: up, down, or refusing the
/// token; it records each request's path and token and can add GitHub's
/// token-expiry header to every answer.
final class _Network extends http.BaseClient {
  _Network(this.inner);

  final http.Client inner;
  _Net net = _Net.online;
  String? expiration;
  final List<(String, String?)> requests = [];

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    requests.add((request.url.path, request.headers['Authorization']));
    switch (net) {
      case _Net.unreachable:
        throw const SocketException('demo: the network is down');
      case _Net.rejected:
        return http.StreamedResponse(
          Stream.value(utf8.encode('{"message": "Bad credentials"}')),
          401,
          headers: {'content-type': 'application/json'},
        );
      case _Net.online:
        final answer = await inner.send(request);
        final header = expiration;
        // GitHub reports the expiry of the token a request carried: here
        // the keychain's, for the demo repository.
        if (header == null || !request.url.path.contains('/repos/$_repo/')) {
          return answer;
        }
        return http.StreamedResponse(
          answer.stream,
          answer.statusCode,
          headers: {...answer.headers, tomSecretsTokenExpirationHeader: header},
          request: answer.request,
          reasonPhrase: answer.reasonPhrase,
        );
    }
  }
}

Credentials _pw(String password) =>
    Credentials(ProtectedValue.fromString(password));

KdbxFile _vault(String name, String password, Map<String, String> entries) {
  final file = tomSecretsNewVault(_pw(password), name, argon2: testArgon2);
  for (final MapEntry(:key, :value) in entries.entries) {
    final [group, title] = key.split('/');
    final parent =
        file.body.rootGroup.groups
            .where((g) => g.name.get() == group)
            .firstOrNull ??
        file.createGroup(parent: file.body.rootGroup, name: group);
    final entry = KdbxEntry.create(file, parent)
      ..setString(KdbxKeyCommon.TITLE, PlainValue(title))
      ..setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(value));
    parent.addEntry(entry);
  }
  return file;
}

void main() {
  late FakeGitHubServer server;
  late _Network network;
  late Demo demo;
  late TomInMemorySecretStore keychain;
  late DateTime now;
  late TomSecretsAdminClient admin;
  late List<Map<String, Object?>> events;
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  /// Another device writing [file] to [locator] on GitHub.
  Future<void> put(String locator, KdbxFile file) async {
    final storage = TomGitHubStorage.withClient(
      GitHubApiClient(
        token: 'demo-seed',
        httpClient: server.client,
        baseUrl: FakeGitHubServer.baseUrl,
        minMutativeInterval: Duration.zero,
      ),
      committer: tomSecretsDeviceCommitter('seed'),
    );
    try {
      String? head;
      try {
        head = await storage.headOf(locator);
      } on TomStorageException {
        head = null;
      }
      await storage.commit(
        locator,
        TomChangeset.singleFile(await file.save()),
        expectedHead: head,
        message: 'seed',
      );
    } finally {
      storage.close();
    }
  }

  KdbxFile primaryVault({bool withOther = true, DateTime? otherExpires}) {
    final primary = _vault('primary', primaryPassword, {
      'Db/Main': 'demo-db-pw',
    });
    final list = TomSecretsPrimaryVaults(primary, primaryLocator: _primary)
      ..put(
        TomSecretsVaultKeys(
          name: 'team',
          locator: _team,
          password: teamPassword,
        ),
      );
    if (withOther) {
      list.put(
        TomSecretsVaultKeys(
          name: 'other',
          locator: _other,
          password: _otherPassword,
          githubToken: 'demo-other-token',
          expires: otherExpires,
        ),
      );
    }
    return primary;
  }

  setUp(() async {
    server = FakeGitHubServer()
      ..repo(_repo)
      ..repo(_otherRepo);
    network = _Network(server.client);
    now = DateTime.utc(2026, 11, 13, 9);
    keychain = TomInMemorySecretStore();
    await keychain.write(
      tomSecretsGitHubTokenHandle('al-the-bear', 'demo-vaults'),
      'demo-keychain-token',
    );
    demo = await Demo.create();
    demo.bootstrap = TomSecretsBootstrap(
      primary: _primary,
      dataDirectory: '${demo.dir}/data',
      deviceKey: TomSecretsDeviceKeyMode.keyfile,
    );
    await put(_primary, primaryVault());
    await put(_team, _vault('team', teamPassword, {'Api/Token': 'token-1'}));
    await put(_other, _vault('other', _otherPassword, {'Web/Key': 'key-1'}));
  });

  Future<TomSecretsService> start({
    bool unlock = true,
    Duration refreshTick = const Duration(minutes: 1),
  }) async {
    final service = await demo.start(
      transport: transport,
      keychain: keychain,
      githubClient: network,
      clock: () => now,
      refreshTick: refreshTick,
    );
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    events = [];
    admin.events.listen(events.add);
    await admin.request('subscribe');
    if (unlock) await admin.unlock(primaryPassword);
    return service;
  }

  Future<String?> get(String ref) async {
    final client = await TomSecretsClient.connect(
      clientName: 'demo-client',
      environment: demo.clientEnvironment(),
    );
    try {
      return (await client.get(ref)).text;
    } finally {
      await client.close();
    }
  }

  Map<String, Map<String, Object?>> stores(TomSecretsService service) => {
    for (final s in service.statusReport()['stores']! as List)
      (s as Map)['name'] as String: s.cast<String, Object?>(),
  };

  /// Every event sent before now has arrived: they precede the answer on
  /// the same connection, and the client's event stream delivers them
  /// asynchronously.
  Future<void> settle() async {
    await admin.request('status');
    await pumpEventQueue();
  }

  List<Map<String, Object?>> ofOp(String op) =>
      events.where((e) => e['op'] == op).toList();

  Future<TomSecretsAdminException> refused(Future<Object?> request) async {
    try {
      await request;
    } on TomSecretsAdminException catch (e) {
      return e;
    }
    fail('the request was not refused');
  }

  test('github: vaults open with the keychain\'s token and the token the '
      'primary keeps for another repository; status says github, '
      'current', () async {
    final service = await start();
    final status = stores(service);
    expect(status.keys, ['primary', 'team', 'other']);
    for (final s in status.values) {
      expect(s['state'], 'current', reason: '${s['name']}');
      expect(s['source'], 'github');
      expect(s['fetchedAt'], now.toIso8601String());
    }
    expect(await get('team/Api/Token'), 'token-1');
    expect(await get('other/Web/Key'), 'key-1');
    String? tokenOf(String repo) =>
        network.requests.firstWhere((r) => r.$1.contains('/repos/$repo/')).$2;
    expect(tokenOf(_repo), 'Bearer demo-keychain-token');
    expect(tokenOf(_otherRepo), 'Bearer demo-other-token');
  });

  test('the refresh: a file that did not move costs one request each and is '
      'not reopened; a moved file is reopened and announced', () async {
    final service = await start();
    events.clear();
    final before = network.requests.length;
    var report = await service.refresh(force: true);
    expect(report.reopened, isEmpty);
    expect(report.states, isEmpty);
    expect(
      network.requests.length - before,
      lessThanOrEqualTo(3),
      reason: 'one conditional ref read per store',
    );

    await put(_team, _vault('team', teamPassword, {'Api/Token': 'token-2'}));
    report = await service.refresh(force: true);
    expect(report.reopened, ['team']);
    expect(await get('team/Api/Token'), 'token-2');
    await settle();
    expect(ofOp('store_changed').single['store'], 'team');
    expect(ofOp('store_state'), isEmpty, reason: 'still current');
  });

  test('stores are fetched every refreshMinutes, on the timer', () async {
    final service = await start(refreshTick: const Duration(milliseconds: 50));
    await put(_team, _vault('team', teamPassword, {'Api/Token': 'token-2'}));
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(await get('team/Api/Token'), 'token-1', reason: 'not due yet');
    now = now.add(Duration(minutes: service.settings.refreshMinutes));
    final changed = admin.events.firstWhere((e) => e['op'] == 'store_changed');
    await changed.timeout(const Duration(seconds: 10));
    expect(await get('team/Api/Token'), 'token-2');
  });

  test('GitHub unreachable: the stores are served from the copy held '
      '(offline, source cache), the admins are told, reload answers '
      'offline, the fetch backs off 1, 2, 4 minutes; back online all is '
      'current again', () async {
    final service = await start();
    events.clear();
    network.net = _Net.unreachable;
    await service.refresh(force: true);
    final status = stores(service);
    for (final s in status.values) {
      expect(s['state'], 'offline');
      expect(s['source'], 'cache');
      expect(s['fetchedAt'], now.toIso8601String());
    }
    expect(await get('team/Api/Token'), 'token-1', reason: 'never locked');
    await settle();
    expect(
      {for (final e in ofOp('store_state')) e['store']: e['state']},
      {'primary': 'offline', 'team': 'offline', 'other': 'offline'},
    );
    expect(ofOp('store_state').first['source'], 'cache');

    // The backoff: 1, 2, 4 minutes after the failures.
    Future<bool> fetched(Duration after) async {
      now = now.add(after);
      final before = network.requests.length;
      await service.refresh();
      return network.requests.length > before;
    }

    expect(await fetched(const Duration(seconds: 50)), isFalse);
    expect(await fetched(const Duration(seconds: 15)), isTrue, reason: '1 m');
    expect(await fetched(const Duration(seconds: 90)), isFalse);
    expect(await fetched(const Duration(seconds: 35)), isTrue, reason: '2 m');
    expect(await fetched(const Duration(minutes: 3)), isFalse);
    expect(await fetched(const Duration(minutes: 1)), isTrue, reason: '4 m');

    final e = await refused(admin.request('reload'));
    expect(e.kind, 'offline');
    expect(e.details['stores'], ['primary', 'team', 'other']);
    final save = await refused(
      admin.request('save', {
        'store': 'team',
        'bytes': base64.encode([1, 2, 3]),
      }),
    );
    expect(save.kind, 'offline', reason: 'no save while on the copy');
    expect(save.details['stores'], ['team']);

    network.net = _Net.online;
    events.clear();
    await admin.request('reload');
    for (final s in stores(service).values) {
      expect(s['state'], 'current');
      expect(s['source'], 'github');
    }
    await settle();
    expect(ofOp('store_state').map((e) => e['state']).toSet(), {'current'});
  });

  test('the token refused: token_expired, not fetched again on the timer '
      'until reload', () async {
    final service = await start();
    network.net = _Net.rejected;
    await service.refresh(force: true);
    expect(stores(service).values.map((s) => s['state']).toSet(), {
      'token_expired',
    });
    expect(await get('team/Api/Token'), 'token-1');
    now = now.add(const Duration(hours: 5));
    final before = network.requests.length;
    await service.refresh();
    expect(network.requests.length, before, reason: 'no retry on a refusal');
    final e = await refused(admin.request('reload'));
    expect(e.kind, 'token_expired');
    expect(e.details['stores'], ['primary', 'team', 'other']);
    expect(network.requests.length, greaterThan(before));
    network.net = _Net.online;
    await admin.request('reload');
    expect(stores(service).values.map((s) => s['state']).toSet(), {'current'});
  });

  test(
    'unlock with GitHub unreachable: the vaults open from the offline '
    'cache; with the cache switched off a further vault is unavailable',
    () async {
      final service = await start();
      await admin.request('lock');
      network.net = _Net.unreachable;
      await admin.unlock(primaryPassword);
      var status = stores(service);
      expect(status['primary']!['state'], 'offline');
      expect(status['team']!['state'], 'offline');
      expect(status['team']!['source'], 'cache');
      expect(await get('team/Api/Token'), 'token-1');

      network.net = _Net.online;
      await admin.request('reload');
      await service.deviceContainer!.write(
        const TomSecretsDeviceSettings(offlineCache: false),
      );
      await admin.request('lock');
      await Directory(demo.bootstrap.cacheDirectory).delete(recursive: true);
      network.net = _Net.unreachable;
      await expectLater(
        admin.unlock(primaryPassword),
        throwsA(isA<TomSecretsAdminException>()),
        reason: 'no copy of the primary',
      );
      network.net = _Net.online;
      await admin.unlock(primaryPassword);
      expect(
        Directory(
          demo.bootstrap.cacheDirectory,
        ).listSync(recursive: true).where((f) => f.path.endsWith('team.kdbx')),
        isEmpty,
        reason: 'no further vault cached with the cache off',
      );
      await admin.request('lock');
      network.net = _Net.unreachable;
      await admin.unlock(primaryPassword);
      status = stores(service);
      expect(status['primary']!['state'], 'offline', reason: 'its cached copy');
      expect(status['team']!['state'], 'unavailable');
    },
  );

  test(
    'a file whose key changed goes to needs_unlock and leaves the index; '
    'a vault the primary lists anew is opened, one it drops is dropped',
    () async {
      final service = await start();
      events.clear();
      await put(_team, _vault('team', 'rotated-pw', {'Api/Token': 'token-9'}));
      await service.refresh(force: true);
      expect(stores(service)['team']!['state'], 'needs_unlock');
      await settle();
      expect(ofOp('store_state').single, {
        'op': 'store_state',
        'store': 'team',
        'state': 'needs_unlock',
        'source': 'github',
        'notPushed': 0,
      });
      final client = await TomSecretsClient.connect(
        clientName: 'demo-client',
        environment: demo.clientEnvironment(),
      );
      addTearDown(client.close);
      await expectLater(
        client.get('team/Api/Token'),
        throwsA(isA<TomSecretsClientException>()),
      );

      // The primary now lists the rotated password and drops `other`.
      final primary = primaryVault(withOther: false);
      TomSecretsPrimaryVaults(primary, primaryLocator: _primary).put(
        TomSecretsVaultKeys(
          name: 'team',
          locator: _team,
          password: 'rotated-pw',
        ),
      );
      await put(_primary, primary);
      final report = await service.refresh(force: true);
      expect(report.reopened, containsAll(['primary', 'team']));
      expect(stores(service).keys, ['primary', 'team']);
      expect(stores(service)['team']!['state'], 'current');
      expect(await get('team/Api/Token'), 'token-9');
    },
  );

  test('file: vaults are refreshed too: a file changed on the disk is '
      'reopened', () async {
    final local = await Demo.create();
    final service = await local.start(transport: transport);
    final localAdmin = await TomSecretsAdminClient.connect(
      local.runtime(transport),
      local.adminKey,
    );
    addTearDown(localAdmin.close);
    await localAdmin.unlock(primaryPassword);
    final team = _vault('team', teamPassword, {'Api/Token': 'disk-2'});
    await File(local.teamPath).writeAsBytes(await team.save());
    final report = await service.refresh(force: true);
    expect(report.reopened, ['team']);
    expect(
      service.statusReport()['stores'],
      everyElement(containsPair('source', 'file')),
    );
  });

  group('key-expiry reminders', () {
    test('the GitHub token from keyExpiryWarningDays before, then 7 and 1 '
        'day before, and daily once expired; a vault\'s keys from 30 days '
        'before their Expires; status lists them', () async {
      await put(
        _primary,
        primaryVault(otherExpires: now.add(const Duration(days: 25))),
      );
      final expiry = now.add(const Duration(days: 20));
      network.expiration =
          '${expiry.toIso8601String().replaceFirst('T', ' ').substring(0, 19)}'
          ' UTC';
      final service = await start();
      await settle();
      expect(ofOp('key_expiry'), [
        {
          'op': 'key_expiry',
          'key': 'vault-keys:other',
          'expiresAt': now.add(const Duration(days: 25)).toIso8601String(),
          'daysLeft': 25,
        },
      ], reason: 'the token has 20 days left, its reminders start at 14');

      Future<List<Object?>> after(Duration step) async {
        now = now.add(step);
        events.clear();
        await service.refresh();
        await settle();
        return [for (final e in ofOp('key_expiry')) (e['key'], e['daysLeft'])];
      }

      expect(await after(const Duration(days: 6)), [
        ('github-token:$_repo', 14),
      ]);
      expect(await after(const Duration(hours: 1)), isEmpty);
      expect(await after(const Duration(days: 7)), [
        ('github-token:$_repo', 6),
      ]);
      expect(await after(const Duration(days: 6)), [
        ('github-token:$_repo', 0),
        ('vault-keys:other', 5),
      ]);
      expect(await after(const Duration(days: 2)), [
        ('github-token:$_repo', -2),
      ]);
      expect(await after(const Duration(hours: 2)), isEmpty);
      expect(await after(const Duration(days: 1)), [
        ('github-token:$_repo', -3),
      ], reason: 'daily once expired');

      final expiring = (service.statusReport()['expiring']! as List)
          .cast<Map>();
      expect(expiring, [
        {
          'kind': 'github_token',
          'key': 'github-token:$_repo',
          'expiresAt': expiry.toIso8601String(),
          'daysLeft': -3,
        },
        {
          'kind': 'vault_keys',
          'key': 'vault-keys:other',
          'vault': 'other',
          'expiresAt': DateTime.utc(2026, 12, 8, 9).toIso8601String(),
          'daysLeft': 2,
        },
      ]);
    });

    test('an admin that subscribes gets the reminders due now', () async {
      network.expiration = '2026-11-20 09:00:00 UTC';
      await start();
      final second = await TomSecretsAdminClient.connect(
        demo.runtime(transport),
        demo.adminKey,
      );
      addTearDown(second.close);
      final got = <Map<String, Object?>>[];
      second.events.listen(got.add);
      await second.request('subscribe');
      await second.request('status');
      await pumpEventQueue();
      expect(got.single['key'], 'github-token:$_repo');
      expect(got.single['daysLeft'], 7);
    });

    test('the expiry header and the reminder steps', () {
      expect(
        tomSecretsParseTokenExpiration('2026-12-01 10:00:00 UTC'),
        DateTime.utc(2026, 12, 1, 10),
      );
      expect(
        tomSecretsParseTokenExpiration('2026-12-01 10:00:00 +0100'),
        DateTime.utc(2026, 12, 1, 9),
      );
      expect(tomSecretsParseTokenExpiration('soon'), isNull);
      TomSecretsExpiringKey? at(int days, {int hours = 0}) =>
          TomSecretsExpiringKey.due(
            kind: 'github_token',
            key: 'k',
            expiresAt: DateTime.utc(2026, 12, 1),
            now: DateTime.utc(
              2026,
              12,
              1,
            ).subtract(Duration(days: days, hours: hours)),
            firstDays: 14,
          );
      expect(at(15), isNull);
      expect(at(14)!.step, 'first');
      expect(at(8)!.step, 'first');
      expect(at(7)!.step, '7');
      expect(at(2)!.step, '7');
      expect(at(1)!.step, '1');
      expect(at(0, hours: 3)!.step, '1');
      expect(at(0)!.step, 'expired 2026-12-01');
      expect(at(-1)!.daysLeft, -1);
    });
  });
}
