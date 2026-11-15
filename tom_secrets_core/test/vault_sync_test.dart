// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The GitHub cycle (part-stores, DP-81): a vault as a sync unit, two
/// devices on one remote; then the same over `TomGitHubStorage`'s real code
/// against a fake GitHub REST API (no clone anywhere).
library;

import 'package:test/test.dart';
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/testing.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_core_sync/tom_core_sync.dart';
import 'package:tom_github_api/testing.dart';
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const notes = KdbxKey('Notes');
const user = KdbxKey('UserName');

KdbxEntry byTitle(KdbxFile file, String title) =>
    file.body.rootGroup.getAllEntries().firstWhere((e) => e.label == title);

String? text(KdbxEntry e, KdbxKey key) => e.getString(key)?.getText();

KdbxFile demoVault() {
  final v = DemoVault(store: 'fleet');
  v.add('Mail/Box', password: 'pw0', key: 'mail.box', fields: {'Notes': 'n0'});
  v.add('Db/Main', password: 'db0', key: 'db.main');
  return v.file;
}

void main() {
  group('two devices on one remote', () {
    late TomMemoryRemote remote;
    late TomMemoryStorage storageA;
    late TomMemoryStorage storageB;
    const locator = 'mem:vaults/fleet.kdbx';

    setUp(() {
      remote = TomMemoryRemote();
      storageA = TomMemoryStorage(remote);
      storageB = TomMemoryStorage(remote);
    });

    Future<(TomSecretsVaultUnit, TomSecretsVaultUnit)> twoDevices() async {
      final a = await TomSecretsVaultUnit.create(
        locator: locator,
        storage: storageA,
        file: demoVault(),
        device: 'mbp',
      );
      final b = await TomSecretsVaultUnit.open(
        locator: locator,
        storage: storageB,
        credentials: demoCredentials,
        device: 'bigbeast',
      );
      return (a, b);
    }

    test('rekey writes the re-keyed file as it is; the unit and other '
        'devices then use the new keys; a moved branch is refused', () async {
      final (a, b) = await twoDevices();
      final newCredentials = Credentials(
        ProtectedValue.fromString('demo-key-2'),
      );
      final key = TomSecretsRepositoryKey.generate();
      final codec = TomSecretsOuterCodec(path: 'fleet.kdbx.tsmx', keys: [key]);
      final file = a.working..credentials = newCredentials;
      final stored = await codec.encode(await file.save());
      await a.rekey(file, stored: stored, codec: codec);
      expect(a.credentials, same(newCredentials));
      expect(a.codec, same(codec));
      expect(a.baseBytes, stored);
      expect(await storageB.readBytes(locator), stored);

      // b's copy is the old one: a re-key of it over the moved branch is
      // refused and nothing changes.
      final oldHead = b.head;
      final bFile = b.working
        ..credentials = Credentials(ProtectedValue.fromString('demo-key-3'));
      await expectLater(
        b.rekey(
          bFile,
          stored: await const TomSecretsPlainCodec().encode(await bFile.save()),
          codec: const TomSecretsPlainCodec(),
        ),
        throwsA(isA<TomCasConflictException>()),
      );
      expect(b.head, oldHead);
      expect(b.credentials, demoCredentials);

      // A later edit through a goes out under the new keys.
      byTitle(a.working, 'Box').setString(notes, PlainValue('after rekey'));
      a.markEdited();
      await a.push();
      final c = await TomSecretsVaultUnit.open(
        locator: locator,
        storage: TomMemoryStorage(remote),
        credentials: newCredentials,
        codec: TomSecretsOuterCodec(path: 'fleet.kdbx.tsmx', keys: [key]),
        device: 'bomber',
      );
      expect(text(byTitle(c.working, 'Box'), notes), 'after rekey');
      await expectLater(
        TomSecretsVaultUnit.open(
          locator: locator,
          storage: TomMemoryStorage(remote),
          credentials: newCredentials,
          device: 'bomber',
        ),
        throwsA(anything),
        reason: 'the file is outer-encrypted now',
      );
    });

    test('create, open on another device, push, pull: one commit per save, '
        'messages naming the vault and the device', () async {
      final (a, b) = await twoDevices();
      expect(b.head, a.head);
      byTitle(a.working, 'Box').setString(notes, PlainValue('from mbp'));
      a.markEdited();
      expect(a.hasLocalChanges, isTrue);
      await a.push();
      expect(a.hasLocalChanges, isFalse);
      expect(remote.commits, [
        'tsm: fleet.kdbx from mbp',
        'tsm: fleet.kdbx from mbp',
      ]);
      final remoteHead = await storageB.headOf(locator);
      expect(await b.pull(remoteHead!), isEmpty);
      expect(text(byTitle(b.working, 'Box'), notes), 'from mbp');
      expect(b.head, remoteHead);
    });

    test('a refused branch move: read the new head, merge three-way, commit '
        'on top (different fields: both kept, no conflict)', () async {
      final (a, b) = await twoDevices();
      byTitle(a.working, 'Box').setString(notes, PlainValue('from mbp'));
      a.markEdited();
      await a.push();
      byTitle(b.working, 'Main').setString(user, PlainValue('dbuser'));
      b.markEdited();
      final conflicts = await b.push();
      expect(conflicts, isEmpty);
      expect(remote.commits.last, 'tsm: fleet.kdbx from bigbeast');
      final final_ = await KdbxFormat().read(
        remote.snapshot(locator)[TomChangeset.containerPath]!,
        demoCredentials,
      );
      expect(text(byTitle(final_, 'Box'), notes), 'from mbp');
      expect(text(byTitle(final_, 'Main'), user), 'dbuser');
      expect(b.merges, hasLength(1));
    });

    test('replaceWorking: a whole edited file (read from its saved bytes) is '
        'committed over the base, merged with a remote that moved', () async {
      final (a, b) = await twoDevices();
      byTitle(a.working, 'Box').setString(notes, PlainValue('from mbp'));
      a.markEdited();
      await a.push();
      // bigbeast's app edited the copy bigbeast holds and saved it whole.
      final edited = await KdbxFormat().read(
        await b.working.save(),
        demoCredentials,
      );
      byTitle(edited, 'Main').setString(user, PlainValue('dbuser'));
      b.replaceWorking(edited);
      expect(b.hasLocalChanges, isTrue);
      expect(await b.push(), isEmpty);
      final now = await KdbxFormat().read(
        remote.snapshot(locator)[TomChangeset.containerPath]!,
        demoCredentials,
      );
      expect(text(byTitle(now, 'Box'), notes), 'from mbp');
      expect(text(byTitle(now, 'Main'), user), 'dbuser');
      expect(identical(b.working, edited), isTrue);

      // Given the saved bytes and with nothing to merge, those are committed
      // as they are.
      final again = await KdbxFormat().read(
        await b.working.save(),
        demoCredentials,
      );
      byTitle(again, 'Main').setString(user, PlainValue('dbuser2'));
      final bytes = await again.save();
      b.replaceWorking(again, stored: bytes);
      await b.push();
      expect(remote.snapshot(locator)[TomChangeset.containerPath], bytes);
      expect(b.baseBytes, bytes);
    });

    test('the same field on both: a conflict reaches the sync queue and the '
        'vault', () async {
      final (a, b) = await twoDevices();
      byTitle(a.working, 'Box').setString(notes, PlainValue('a'));
      a.markEdited();
      await a.push();
      final box = byTitle(b.working, 'Box')..setString(notes, PlainValue('b'));
      box.times.lastModificationTime.set(DateTime.utc(2099));
      b.markEdited();
      final conflicts = await b.push();
      expect(conflicts.single, isA<TomSecretsVaultConflict>());
      expect(conflicts.single.anchor, startsWith('$locator#'));
      expect(text(byTitle(b.working, 'Box'), notes), 'b');
      expect(tomSecretsConflictsOf(byTitle(b.working, 'Box')), hasLength(1));
    });

    test('a remote that moves on every attempt: TomCasExhaustedException, the '
        'work kept', () async {
      await twoDevices();
      final racing = _RacingStorage(remote, locator);
      final c = await TomSecretsVaultUnit.open(
        locator: locator,
        storage: racing,
        credentials: demoCredentials,
        device: 'bomber',
        maxPushAttempts: 2,
      );
      byTitle(c.working, 'Main').setString(user, PlainValue('c'));
      c.markEdited();
      await expectLater(c.push(), throwsA(isA<TomCasExhaustedException>()));
      expect(c.hasLocalChanges, isTrue);
      expect(racing.commitsAttempted, 2);
    });

    test(
      'a transport failure: TomCommitFailedException carrying the commit',
      () async {
        final (_, b) = await twoDevices();
        storageB.goOffline();
        byTitle(b.working, 'Main').setString(user, PlainValue('offline'));
        b.markEdited();
        await expectLater(
          b.push(),
          throwsA(
            isA<TomCommitFailedException>()
                .having(
                  (e) => e.commitMessage,
                  'message',
                  'tsm: fleet.kdbx from bigbeast',
                )
                .having((e) => e.baseHead, 'baseHead', b.head),
          ),
        );
        expect(b.hasLocalChanges, isTrue);
      },
    );

    test('through the sync engine: an edit converges, offline work waits in '
        'the journal and lands when the network returns', () async {
      final (a, b) = await twoDevices();
      final journal = TomMemoryCommitJournal();
      final engine = TomSyncEngine(unit: b, journal: journal);
      addTearDown(engine.dispose);
      byTitle(b.working, 'Main').setString(user, PlainValue('via engine'));
      b.markEdited();
      var status = await engine.syncNow();
      expect(status.state, TomSyncState.clean);
      expect(await a.pull((await storageA.headOf(locator))!), isEmpty);
      expect(text(byTitle(a.working, 'Main'), user), 'via engine');

      storageB.goOffline();
      byTitle(b.working, 'Main').setString(user, PlainValue('offline'));
      b.markEdited();
      status = await engine.syncNow();
      expect(status.pendingCount, 1);
      storageB.goOnline();
      status = await engine.syncNow();
      expect(status.pendingCount, 0);
      final landed = await KdbxFormat().read(
        remote.snapshot(locator)[TomChangeset.containerPath]!,
        demoCredentials,
      );
      expect(text(byTitle(landed, 'Main'), user), 'offline');
    });

    test('takeRemote drops local work for the remote as it is', () async {
      final (a, b) = await twoDevices();
      byTitle(a.working, 'Box').setString(notes, PlainValue('remote'));
      a.markEdited();
      await a.push();
      byTitle(b.working, 'Box').setString(notes, PlainValue('local'));
      b.markEdited();
      await b.takeRemote();
      expect(b.hasLocalChanges, isFalse);
      expect(text(byTitle(b.working, 'Box'), notes), 'remote');
      expect(b.head, await storageB.headOf(locator));
    });
  });

  group('over TomGitHubStorage (the REST API, no clone)', () {
    late FakeGitHubServer server;
    TomGitHubStorage device([String? name]) => TomGitHubStorage.withClient(
      GitHubApiClient(
        token: 'demo-token',
        httpClient: server.client,
        baseUrl: FakeGitHubServer.baseUrl,
        minMutativeInterval: Duration.zero,
      ),
      committer: name == null ? null : tomSecretsDeviceCommitter(name),
    );
    const locator = 'github:al-the-bear/demo-vaults/vaults/fleet.kdbx';

    setUp(() {
      server = FakeGitHubServer()..repo('al-the-bear/demo-vaults');
    });

    test(
      'two devices save concurrently; the second merges and lands on top',
      () async {
        final mbp = device('mbp');
        final bigbeast = device('bigbeast');
        addTearDown(mbp.close);
        addTearDown(bigbeast.close);
        final a = await TomSecretsVaultUnit.create(
          locator: locator,
          storage: mbp,
          file: demoVault(),
          device: 'mbp',
        );
        final b = await TomSecretsVaultUnit.open(
          locator: locator,
          storage: bigbeast,
          credentials: demoCredentials,
          device: 'bigbeast',
        );
        expect(b.head, a.head);
        byTitle(a.working, 'Box').setString(notes, PlainValue('from mbp'));
        a.markEdited();
        await a.push();
        byTitle(b.working, 'Main').setString(user, PlainValue('from bigbeast'));
        b.markEdited();
        expect(await b.push(), isEmpty);
        expect(
          b.merges,
          hasLength(1),
          reason: 'the refused move made it merge',
        );

        final reader = device();
        addTearDown(reader.close);
        final check = await TomSecretsVaultUnit.open(
          locator: locator,
          storage: reader,
          credentials: demoCredentials,
          device: 'bomber',
        );
        expect(text(byTitle(check.working, 'Box'), notes), 'from mbp');
        expect(text(byTitle(check.working, 'Main'), user), 'from bigbeast');
        expect(check.head, b.head);
        expect(mbp.maxObjectBytes, 41820160, reason: 'the blob ceiling');
        // Every commit of the cycle names its device as author and
        // committer, with the placeholder address, never the token's owner.
        final saves = server.commits.values
            .where((c) => c.message.startsWith('tsm: '))
            .toList();
        expect(saves.map((c) => c.message), [
          'tsm: fleet.kdbx from mbp',
          'tsm: fleet.kdbx from mbp',
          'tsm: fleet.kdbx from bigbeast',
        ]);
        for (final c in saves) {
          final name = c.message.split(' ').last;
          expect(c.author, {'name': name, 'email': '$name@tsm.invalid'});
          expect(c.committer, c.author);
        }
      },
    );
  });

  group('the primary vault\'s .tom-secrets/vaults', () {
    test('put, list, update, remove; the keys open the vault; the primary '
        'cannot list itself; the group never resolves', () async {
      final primary = DemoVault(store: 'primary').file;
      final vaults = TomSecretsPrimaryVaults(
        primary,
        primaryLocator: 'github:al-the-bear/demo-vaults/vaults/primary.kdbx',
      );
      final fleet = demoVault();
      fleet.credentials = Credentials(ProtectedValue.fromString('fleet-pw'));
      final fleetBytes = await fleet.save();
      vaults.put(
        TomSecretsVaultKeys(
          name: 'fleet',
          locator: 'github:al-the-bear/demo-vaults/vaults/fleet.kdbx',
          password: 'fleet-pw',
          githubToken: 'demo-other-token',
          githubTokenExpires: DateTime.utc(2027, 2, 1),
          expires: DateTime.utc(2027, 11, 13),
        ),
      );
      final back = TomSecretsPrimaryVaults(
        await KdbxFormat().read(await primary.save(), demoCredentials),
      );
      final keys = back.byName('fleet')!;
      expect(keys.locator, 'github:al-the-bear/demo-vaults/vaults/fleet.kdbx');
      expect(keys.githubToken, 'demo-other-token');
      expect(keys.expires, DateTime.utc(2027, 11, 13), reason: 'KDBX Expires');
      expect(keys.githubTokenExpires, DateTime.utc(2027, 2, 1));
      expect(keys.toString(), isNot(contains('fleet-pw')));
      final opened = await KdbxFormat().read(fleetBytes, keys.credentials);
      expect(byTitle(opened, 'Main').label, 'Main');

      vaults.put(
        TomSecretsVaultKeys(
          name: 'fleet',
          locator: 'github:al-the-bear/demo-vaults/vaults/fleet.kdbx',
          password: 'changed',
        ),
      );
      expect(vaults.list().single.password, 'changed');
      expect(vaults.list().single.githubToken, isNull);
      expect(vaults.list().single.expires, isNull, reason: 'Expires cleared');
      expect(
        () => vaults.put(
          TomSecretsVaultKeys(
            name: 'self',
            locator: 'github:al-the-bear/demo-vaults/vaults/primary.kdbx',
          ),
        ),
        throwsArgumentError,
      );
      final store = TomSecretsStore.fromFile(primary, name: 'primary');
      expect(store.entries, isEmpty, reason: 'the vault keys never resolve');
      expect(vaults.remove('fleet'), isTrue);
      expect(vaults.list(), isEmpty);
      expect(vaults.remove('fleet'), isFalse);
    });
  });

  group('locators', () {
    test('file:, github: with and without a branch, git:', () {
      final f = TomSecretsVaultLocator.parse('file:/srv/tsm/fleet.kdbx');
      expect(f, isA<TomSecretsFileLocator>());
      expect(f.fileName, 'fleet.kdbx');
      final g =
          TomSecretsVaultLocator.parse(
                'github:al-the-bear/vault@main/vaults/prod.kdbx',
              )
              as TomSecretsGitHubLocator;
      expect(
        (g.owner, g.repository, g.branch, g.path),
        ('al-the-bear', 'vault', 'main', 'vaults/prod.kdbx'),
      );
      expect(g.text, 'github:al-the-bear/vault@main/vaults/prod.kdbx');
      expect(g.repositorySlug, 'al-the-bear/vault');
      expect(
        g.tokenHandle,
        'tsm.github-token.al-the-bear:vault',
        reason: 'one keychain token per repository, any branch',
      );
      expect(g.tokenExpiryHandle, 'tsm.github-token-expiry.al-the-bear:vault');
      // The OS keychain (TomDesktopSecretStore) takes item names of letters,
      // digits and . _ : @ - only: a handle with a `/` would be refused.
      final keychainName = RegExp(r'^[A-Za-z0-9._:@-]{1,200}$');
      expect(g.tokenHandle, matches(keychainName));
      expect(g.tokenExpiryHandle, matches(keychainName));
      final d =
          TomSecretsVaultLocator.parse('github:o/r/v.kdbx')
              as TomSecretsGitHubLocator;
      expect(d.branch, isNull);
      expect(
        TomSecretsVaultLocator.parse('git:https://git.example.org/r@b/v.kdbx'),
        isA<TomSecretsGitLocator>(),
      );
      for (final bad in [
        'file:relative/x.kdbx',
        'github:o/r',
        'github:o/r/../x.kdbx',
        'https://example.org/x.kdbx',
      ]) {
        expect(
          () => TomSecretsVaultLocator.parse(bad),
          throwsA(isA<TomSecretsLocatorException>()),
          reason: bad,
        );
      }
    });
  });
}

/// A storage whose remote moves (another device commits) just before every
/// commit this device attempts.
final class _RacingStorage extends TomMemoryStorage {
  _RacingStorage(super.remote, this._locator);

  final String _locator;
  int commitsAttempted = 0;

  @override
  Future<String> commit(
    String locator,
    TomChangeset changeset, {
    String? expectedHead,
    String? message,
    TomCommitProgressSink? onProgress,
  }) async {
    commitsAttempted++;
    // Another device lands first: same bytes, a new head.
    final current = await readBytes(_locator);
    await super.commit(
      _locator,
      TomChangeset.singleFile(current),
      expectedHead: await headOf(_locator),
      message: 'tsm: fleet.kdbx from elsewhere',
    );
    return super.commit(
      locator,
      changeset,
      expectedHead: expectedHead,
      message: message,
      onProgress: onProgress,
    );
  }
}
