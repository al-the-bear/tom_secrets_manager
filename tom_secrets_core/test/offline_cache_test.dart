// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The offline cache (part-key-rotation, DP-75): the last file retrieved of
/// each vault, as stored, with its record; a vault opens from it when GitHub
/// cannot be reached or refuses the token, an offline edit is merged against
/// it on reconnecting, and it is shown with its age. Demo data under demo
/// keys, the GitHub REST API faked.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:test/test.dart';
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/testing.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_core_sync/tom_core_sync.dart';
import 'package:tom_git/tom_git.dart';
import 'package:tom_github_api/testing.dart';
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const notes = KdbxKey('Notes');
const locator = 'github:al-the-bear/demo-vaults/vaults/fleet.kdbx';

enum Net { online, unreachable, rejected }

/// The fake GitHub server behind a switch: online, unreachable (no answer),
/// or refusing the token (401).
final class SwitchedClient extends http.BaseClient {
  SwitchedClient(this.inner);

  final http.Client inner;
  Net net = Net.online;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    switch (net) {
      case Net.online:
        return inner.send(request);
      case Net.unreachable:
        throw const SocketException('demo: the network is down');
      case Net.rejected:
        return http.StreamedResponse(
          Stream.value(utf8.encode('{"message": "Bad credentials"}')),
          401,
          headers: {'content-type': 'application/json'},
        );
    }
  }
}

KdbxEntry byTitle(KdbxFile file, String title) =>
    file.body.rootGroup.getAllEntries().firstWhere((e) => e.label == title);

KdbxFile demoVault() {
  final v = DemoVault(store: 'fleet');
  v.add('Mail/Box', password: 'pw0', key: 'mail.box', fields: {'Notes': 'n0'});
  v.add('Db/Main', password: 'db0', key: 'db.main');
  return v.file;
}

Directory scratch(String name) {
  final dir = Directory('${Directory.current.path}/testlog/scratch_$name');
  if (dir.existsSync()) dir.deleteSync(recursive: true);
  dir.createSync(recursive: true);
  addTearDown(() => dir.deleteSync(recursive: true));
  return dir;
}

void main() {
  group('the cache directory', () {
    test('a file is kept as stored, under <owner>/<repository>/<path>, with '
        'its record', () async {
      final root = scratch('layout');
      final cache = TomSecretsOfflineCache(root);
      final bytes = Uint8List.fromList(utf8.encode('TSMX demo bytes'));
      final at = DateTime.utc(2026, 11, 13, 10);
      await cache.put(
        TomSecretsCachedVault(
          locator: '$locator.tsmx',
          bytes: bytes,
          head: 'a' * 40,
          fetchedAt: at,
        ),
      );
      final file = File(
        '${root.path}/al-the-bear/demo-vaults/vaults/fleet.kdbx.tsmx',
      );
      expect(file.readAsBytesSync(), bytes);
      final record =
          jsonDecode(File('${file.path}.tsm-cache.json').readAsStringSync())
              as Map<String, dynamic>;
      expect(record, {
        'locator': '$locator.tsmx',
        'head': 'a' * 40,
        'blobId': GitObjectId.hash('blob', bytes).hex,
        'fetchedAt': '2026-11-13T10:00:00.000Z',
      });

      final back = (await cache.get('$locator.tsmx'))!;
      expect(back.bytes, bytes);
      expect(back.head, 'a' * 40);
      expect(back.fetchedAt, at);
      expect(back.blobId, GitObjectId.hash('blob', bytes).hex);
    });

    test('another locator, or a file its record does not name, is no cached '
        'copy; remove deletes both files', () async {
      final root = scratch('mismatch');
      final cache = TomSecretsOfflineCache(root);
      await cache.put(
        TomSecretsCachedVault(
          locator: locator,
          bytes: Uint8List.fromList([1, 2, 3]),
          head: 'b' * 40,
          fetchedAt: DateTime.utc(2026),
        ),
      );
      expect(await cache.get(locator), isNotNull);
      cache.fileFor(locator).writeAsBytesSync([9, 9]);
      expect(await cache.get(locator), isNull, reason: 'a torn write');
      expect(await cache.remove(locator), isTrue);
      expect(cache.fileFor(locator).existsSync(), isFalse);
      expect(
        File('${cache.fileFor(locator).path}.tsm-cache.json').existsSync(),
        isFalse,
      );
      expect(await cache.remove(locator), isFalse);
      expect(await cache.get('github:o/r/x.kdbx'), isNull);
    });

    test('the age is shown, and turns into a warning after 7 days; it never '
        'stops the copy being served', () {
      final copy = TomSecretsCachedVault(
        locator: locator,
        bytes: Uint8List(0),
        head: 'c' * 40,
        fetchedAt: DateTime.utc(2026, 11, 1),
      );
      final now = DateTime.utc(2026, 11, 4);
      expect(copy.ageAt(now), const Duration(days: 3));
      expect(copy.isStaleAt(now), isFalse);
      expect(copy.isStaleAt(DateTime.utc(2026, 11, 8, 1)), isTrue);
      expect(copy.isStaleAt(now, staleAfter: const Duration(days: 2)), isTrue);
      expect(TomSecretsOfflineCache.defaultStaleAfter, const Duration(days: 7));
    });
  });

  group('a vault and its offline copy', () {
    late FakeGitHubServer server;
    late SwitchedClient net;
    var clock = DateTime.utc(2026, 11, 13, 9);

    setUp(() {
      server = FakeGitHubServer()..repo('al-the-bear/demo-vaults');
      net = SwitchedClient(server.client);
      clock = DateTime.utc(2026, 11, 13, 9);
    });

    TomGitHubStorage device(String name) {
      final storage = TomGitHubStorage.withClient(
        GitHubApiClient(
          token: 'demo-token',
          httpClient: net,
          baseUrl: FakeGitHubServer.baseUrl,
          minMutativeInterval: Duration.zero,
        ),
        committer: tomSecretsDeviceCommitter(name),
      );
      addTearDown(storage.close);
      return storage;
    }

    Future<TomSecretsVaultUnit> open(String name, TomSecretsOfflineCache? c) =>
        TomSecretsVaultUnit.open(
          locator: locator,
          storage: device(name),
          credentials: demoCredentials,
          device: name,
          cache: c,
          clock: () => clock,
        );

    test(
      'every file read or written is cached with its head and time',
      () async {
        final cache = TomSecretsOfflineCache(scratch('kept'));
        final a = await TomSecretsVaultUnit.create(
          locator: locator,
          storage: device('mbp'),
          file: demoVault(),
          device: 'mbp',
          cache: cache,
          clock: () => clock,
        );
        var copy = (await cache.get(locator))!;
        expect(copy.head, a.head);
        expect(copy.bytes, a.baseBytes);
        expect(copy.fetchedAt, clock);
        expect(a.source, TomSecretsVaultSource.remote);
        expect(a.fetchedAt, clock);

        clock = clock.add(const Duration(hours: 1));
        byTitle(a.working, 'Box').setString(notes, PlainValue('n1'));
        a.markEdited();
        await a.push();
        copy = (await cache.get(locator))!;
        expect(copy.head, a.head);
        expect(copy.bytes, a.baseBytes);
        expect(copy.fetchedAt, clock);
      },
    );

    test('unreachable, or the token refused: the vault opens from the copy, '
        'marked with its source, time and reason', () async {
      final cache = TomSecretsOfflineCache(scratch('fallback'));
      await TomSecretsVaultUnit.create(
        locator: locator,
        storage: device('mbp'),
        file: demoVault(),
        device: 'mbp',
      );
      final online = await open('bigbeast', cache);
      final fetched = clock;
      clock = clock.add(const Duration(days: 3));

      for (final (mode, reason) in [
        (Net.unreachable, isA<TomUnreachableException>()),
        (Net.rejected, isA<TomTokenRejectedException>()),
      ]) {
        net.net = mode;
        final offline = await open('bigbeast', cache);
        expect(offline.source, TomSecretsVaultSource.cache, reason: '$mode');
        expect(offline.fetchedAt, fetched);
        expect(offline.offlineReason, reason);
        expect(offline.head, online.head);
        expect(offline.baseBytes, online.baseBytes);
        expect(
          byTitle(offline.working, 'Box').getString(notes)?.getText(),
          'n0',
        );
      }
    });

    test('without a cached copy the failure stands; a refusal that is not a '
        'network or token failure is never covered', () async {
      net.net = Net.unreachable;
      await expectLater(
        open('bigbeast', TomSecretsOfflineCache(scratch('empty'))),
        throwsA(isA<TomUnreachableException>()),
      );
      await expectLater(
        open('bigbeast', null),
        throwsA(isA<TomUnreachableException>()),
      );
      net.net = Net.online;
      final cache = TomSecretsOfflineCache(scratch('notfound'));
      await expectLater(
        open('bigbeast', cache),
        throwsA(isA<TomContainerNotFoundException>()),
        reason: 'a vault that is not there is not served from a cache',
      );
    });

    test('an edit made offline waits, then merges against the cached base '
        'with what another device saved meanwhile', () async {
      final cache = TomSecretsOfflineCache(scratch('offline-edit'));
      final a = await TomSecretsVaultUnit.create(
        locator: locator,
        storage: device('mbp'),
        file: demoVault(),
        device: 'mbp',
      );
      await open('bigbeast', cache);

      net.net = Net.unreachable;
      final b = await open('bigbeast', cache);
      expect(b.source, TomSecretsVaultSource.cache);
      byTitle(b.working, 'Main').setString(notes, PlainValue('offline edit'));
      b.markEdited();
      await expectLater(b.push(), throwsA(isA<TomCommitFailedException>()));
      expect(b.hasLocalChanges, isTrue, reason: 'waits for the network');

      net.net = Net.online;
      byTitle(a.working, 'Box').setString(notes, PlainValue('from mbp'));
      a.markEdited();
      await a.push();

      expect(await b.push(), isEmpty);
      expect(b.source, TomSecretsVaultSource.remote);
      expect(b.merges, hasLength(1));
      final check = await open('bomber', null);
      expect(
        byTitle(check.working, 'Box').getString(notes)?.getText(),
        'from mbp',
      );
      expect(
        byTitle(check.working, 'Main').getString(notes)?.getText(),
        'offline edit',
      );
      expect((await cache.get(locator))!.head, b.head);
    });

    test(
      'an outer-encrypted vault is cached as stored, still encrypted',
      () async {
        final cache = TomSecretsOfflineCache(scratch('outer'));
        final key = TomSecretsRepositoryKey.generate();
        final codec = TomSecretsOuterCodec(
          path: 'vaults/fleet.kdbx.tsmx',
          keys: [key],
        );
        final unit = await TomSecretsVaultUnit.create(
          locator: 'mem:vaults/fleet.kdbx.tsmx',
          storage: TomMemoryStorage(TomMemoryRemote()),
          file: demoVault(),
          device: 'mbp',
          codec: codec,
          cache: cache,
        );
        final copy = (await cache.get('mem:vaults/fleet.kdbx.tsmx'))!;
        expect(ascii.decode(copy.bytes.sublist(0, 4)), 'TSMX');
        expect(copy.bytes, unit.baseBytes);
        final opened = await KdbxFormat().read(
          await codec.decode(copy.bytes),
          demoCredentials,
        );
        expect(byTitle(opened, 'Box').getString(notes)?.getText(), 'n0');
      },
    );

    test('an open vault keeps its state through a failed refresh; which '
        'failures the cache stands in for', () async {
      final cache = TomSecretsOfflineCache(scratch('engine'));
      await TomSecretsVaultUnit.create(
        locator: locator,
        storage: device('mbp'),
        file: demoVault(),
        device: 'mbp',
      );
      final b = await open('bigbeast', cache);
      net.net = Net.unreachable;
      await expectLater(
        b.pull(b.head!),
        throwsA(isA<TomUnreachableException>()),
      );
      expect(
        b.source,
        TomSecretsVaultSource.remote,
        reason: 'an open vault keeps what it has',
      );
      expect(
        TomSecretsVaultUnit.isOfflineFailure(
          const TomTokenRequiredException('github.com'),
        ),
        isTrue,
      );
      expect(
        TomSecretsVaultUnit.isOfflineFailure(
          TomRateLimitException('x', kind: TomRateLimitKind.quota),
        ),
        isFalse,
      );
    });
  });
}
