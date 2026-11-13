// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// History compaction (part-stores, part-key-rotation, DP-82): how the cycle
/// tells a compaction from a force push (followed silently / the user
/// chooses), the app's compaction pushed with `tom_git` against a git server
/// in memory, and the workflow's script run by real git over a bare
/// repository. Demo data under demo keys; no network.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/testing.dart';
import 'package:tom_git/io.dart';
import 'package:tom_git/testing.dart';
import 'package:tom_git/tom_git.dart';
import 'package:tom_github_api/testing.dart';
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:yaml/yaml.dart';

import 'support/vaults.dart';

const notes = KdbxKey('Notes');
const user = KdbxKey('UserName');
const owner = 'al-the-bear';
const repo = 'demo-vaults';
const locator = 'github:$owner/$repo/vaults/fleet.kdbx';
final now = DateTime.utc(2026, 11, 13, 12);
const day = 86400;

KdbxEntry byTitle(KdbxFile file, String title) =>
    file.body.rootGroup.getAllEntries().firstWhere((e) => e.label == title);

String? noteOf(KdbxFile file, String title) =>
    byTitle(file, title).getString(notes)?.getText();

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

/// A commit on [branch] of [repository] writing [files], made [daysAgo]
/// days before [now] by [who].
Future<GitObjectId> commitAt(
  GitRepository repository,
  Map<String, String> files,
  int daysAgo, {
  String branch = 'main',
  String who = 'mbp',
  String? message,
}) async {
  final ref = 'refs/heads/$branch';
  final parent = await repository.refs.read(ref);
  final base = parent == null
      ? null
      : (await repository.readCommit(parent)).tree;
  final tree = await repository.editTree(
    base,
    writes: {for (final e in files.entries) e.key: utf8.encode(e.value)},
  );
  final person = GitPerson(
    name: who,
    email: '$who@tsm.invalid',
    seconds: now.millisecondsSinceEpoch ~/ 1000 - daysAgo * day,
  );
  final id = await repository.commit(
    tree: tree,
    parents: [?parent],
    message: message ?? 'tsm: fleet.kdbx from $who ($daysAgo days ago)',
    author: person,
  );
  await repository.refs.write(ref, id);
  return id;
}

void main() {
  group('trailers', () {
    test('a compaction root carries Tsm-Compacted-From and Tsm-Retention', () {
      final message = tomSecretsCompactionMessage(
        compactedBy: 'mbp',
        oldHead: 'f' * 40,
        retentionDays: 0,
      );
      expect(
        message,
        'tsm: history compacted by mbp\n\n'
        'Tsm-Compacted-From: ${'f' * 40}\nTsm-Retention: 0\n',
      );
      final root = TomSecretsCommit(
        id: '1' * 40,
        tree: '2' * 40,
        parents: const [],
        message: message,
      );
      expect(root.compactedFrom, 'f' * 40);
      expect(root.trailer(tomSecretsRetentionTrailer), '0');
      final child = TomSecretsCommit(
        id: '3' * 40,
        tree: '2' * 40,
        parents: ['1' * 40],
        message: message,
      );
      expect(child.compactedFrom, isNull, reason: 'only a root compacts');
      expect(
        TomSecretsCommit(
          id: '4' * 40,
          tree: '2' * 40,
          parents: const [],
          message: 'Tsm-Compacted-From: x\n\nlater paragraph',
        ).compactedFrom,
        isNull,
        reason: 'a trailer is in the last paragraph',
      );
    });
  });

  group('the cycle over GitHub: compaction or force push', () {
    late FakeGitHubServer server;

    setUp(() => server = FakeGitHubServer()..repo('$owner/$repo'));

    GitHubApiClient client() => GitHubApiClient(
      token: 'demo-token',
      httpClient: server.client,
      baseUrl: FakeGitHubServer.baseUrl,
      minMutativeInterval: Duration.zero,
    );

    TomGitHubStorage device(String name) {
      final storage = TomGitHubStorage.withClient(
        client(),
        committer: tomSecretsDeviceCommitter(name),
      );
      addTearDown(storage.close);
      return storage;
    }

    TomSecretsCommitReader reader() =>
        TomSecretsGitHubCommitReader(client(), owner, repo);

    Future<String> branchHead() async => (await client().git.getRef(
      owner: owner,
      repo: repo,
      ref: 'heads/main',
    )).sha;

    /// Rewrites the branch to a root commit of [tree] (default: the head's),
    /// with [message]: a compaction when it carries the trailer, a force
    /// push otherwise.
    Future<String> rewrite(String message, {String? tree}) async {
      final api = client();
      final head = await branchHead();
      final treeSha =
          tree ??
          (await api.git.getCommit(
            owner: owner,
            repo: repo,
            sha: head,
          )).treeSha;
      final root = await api.git.createCommit(
        owner: owner,
        repo: repo,
        message: message,
        treeSha: treeSha,
        parentShas: const [],
      );
      await api.git.updateRef(
        owner: owner,
        repo: repo,
        ref: 'heads/main',
        sha: root.sha,
        force: true,
      );
      return root.sha;
    }

    Future<TomSecretsVaultUnit> open(String name) => TomSecretsVaultUnit.open(
      locator: locator,
      storage: device(name),
      credentials: demoCredentials,
      device: name,
      history: reader(),
    );

    test('tomSecretsClassifyMove: ahead, compacted, rewritten', () async {
      const path = 'vaults/fleet.kdbx';
      final a = await TomSecretsVaultUnit.create(
        locator: locator,
        storage: device('mbp'),
        file: demoVault(),
        device: 'mbp',
      );
      final baseBlob = tomSecretsBlobId(a.baseBytes);
      expect(a.head, baseBlob, reason: "TomGitHubStorage's head is the blob");
      for (final n in ['n1', 'n2']) {
        byTitle(a.working, 'Box').setString(notes, PlainValue(n));
        a.markEdited();
        await a.push();
      }
      final head = await branchHead();
      Future<TomSecretsBranchMove> classify(String blob, String at) =>
          tomSecretsClassifyMove(
            reader(),
            path: path,
            baseBlob: blob,
            head: at,
          );
      expect(
        await classify(baseBlob, head),
        isA<TomSecretsBranchAhead>().having((m) => m.commits, 'commits', 2),
      );
      expect(
        await classify(tomSecretsBlobId(a.baseBytes), head),
        isA<TomSecretsBranchAhead>().having((m) => m.commits, 'commits', 0),
      );

      final root = await rewrite(
        tomSecretsCompactionMessage(
          compactedBy: 'the compaction workflow',
          oldHead: head,
          retentionDays: 0,
        ),
      );
      expect(
        await classify(baseBlob, root),
        isA<TomSecretsBranchCompacted>()
            .having((m) => m.root, 'root', root)
            .having((m) => m.from, 'from', head),
      );

      final forced = await rewrite('somebody force-pushed');
      expect(
        await classify(baseBlob, forced),
        isA<TomSecretsBranchRewritten>(),
      );
      expect(
        await tomSecretsClassifyMove(
          reader(),
          path: path,
          baseBlob: 'e' * 40,
          head: head,
          maxCommits: 1,
        ),
        isA<TomSecretsBranchRewritten>(),
        reason: 'a walk that hits its limit asks rather than guesses',
      );
    });

    test('a compacted history is followed without asking, a save on top '
        'of it merged as usual', () async {
      final a = await TomSecretsVaultUnit.create(
        locator: locator,
        storage: device('mbp'),
        file: demoVault(),
        device: 'mbp',
        history: reader(),
      );
      final b = await open('bigbeast');
      byTitle(a.working, 'Box').setString(notes, PlainValue('n1'));
      a.markEdited();
      await a.push();
      await rewrite(
        tomSecretsCompactionMessage(
          compactedBy: 'the compaction workflow',
          oldHead: await branchHead(),
          retentionDays: 90,
        ),
      );

      byTitle(
        a.working,
        'Box',
      ).setString(notes, PlainValue('after compaction'));
      a.markEdited();
      expect(await a.push(), isEmpty);

      byTitle(b.working, 'Main').setString(notes, PlainValue('from bigbeast'));
      b.markEdited();
      expect(await b.pull(await branchHead()), isEmpty);
      expect(b.lastMove, isA<TomSecretsBranchCompacted>());
      expect(b.rewrittenHead, isNull);
      expect(noteOf(b.working, 'Box'), 'after compaction');
      expect(await b.push(), isEmpty);

      final check = await open('bomber');
      expect(noteOf(check.working, 'Box'), 'after compaction');
      expect(noteOf(check.working, 'Main'), 'from bigbeast');
    });

    test(
      'a force push is not merged: the user takes the remote as it is',
      () async {
        final a = await TomSecretsVaultUnit.create(
          locator: locator,
          storage: device('mbp'),
          file: demoVault(),
          device: 'mbp',
        );
        final b = await open('bigbeast');
        byTitle(a.working, 'Box').setString(notes, PlainValue('n1'));
        a.markEdited();
        await a.push();
        final forced = await rewrite('force push of the current state');

        byTitle(b.working, 'Main').setString(notes, PlainValue('local'));
        b.markEdited();
        final conflicts = await b.pull(forced);
        expect(conflicts.single, isA<TomSecretsHistoryRewritten>());
        expect(b.merges, isEmpty, reason: 'nothing merged silently');
        expect(b.rewrittenHead, forced);
        final pushed = await b.push();
        expect(pushed.single, isA<TomSecretsHistoryRewritten>());
        expect(await branchHead(), forced, reason: 'the push did not land');

        await b.takeRemote();
        expect(b.rewrittenHead, isNull);
        expect(b.hasLocalChanges, isFalse);
        expect(noteOf(b.working, 'Main'), isNull);
        expect(noteOf(b.working, 'Box'), 'n1');
      },
    );

    test('a force push is not merged: the user pushes the local copy over it, '
        'merged against an empty base', () async {
      final a = await TomSecretsVaultUnit.create(
        locator: locator,
        storage: device('mbp'),
        file: demoVault(),
        device: 'mbp',
      );
      final b = await open('bigbeast');
      byTitle(a.working, 'Main').setString(user, PlainValue('remote user'));
      a.markEdited();
      await a.push();
      final forced = await rewrite('force push');
      byTitle(b.working, 'Main').setString(notes, PlainValue('local'));
      b.markEdited();
      expect((await b.pull(forced)).single, isA<TomSecretsHistoryRewritten>());

      final conflicts = await b.mergeOverRemote();
      expect(conflicts, everyElement(isA<TomSecretsVaultConflict>()));
      expect(b.rewrittenHead, isNull);
      expect(b.merges, hasLength(1));
      final check = await open('bomber');
      expect(noteOf(check.working, 'Main'), 'local');
      expect(
        byTitle(check.working, 'Main').getString(user)?.getText(),
        'remote user',
      );
      expect(noteOf(check.working, 'Box'), 'n0');
      final head = (await client().git.getCommit(
        owner: owner,
        repo: repo,
        sha: await branchHead(),
      ));
      expect(head.parentShas, [forced], reason: 'committed on top');
    });
  });

  group('the app compacts with tom_git', () {
    late GitMemoryServer server;
    late GitHttpRemote remote;

    setUp(() {
      server = GitMemoryServer();
      remote = GitHttpRemote(server.url, client: server.client);
    });

    TomSecretsCommitReader reader() =>
        TomSecretsGitCommitReader(server.repository);

    Future<GitObjectId> head() async =>
        (await server.repository.refs.read('refs/heads/main'))!;

    test('on a key change: one root commit holding the files as they are, '
        'by the device, with the trailers; only the commit is sent', () async {
      await commitAt(server.repository, {
        'vaults/fleet.kdbx': 'old key 1',
        '.tsm/compaction.yaml': 'retention_days: 90\n',
      }, 40);
      await commitAt(server.repository, {'vaults/fleet.kdbx': 'old key 2'}, 20);
      final reencrypted = await commitAt(server.repository, {
        'vaults/fleet.kdbx': 'new key',
      }, 0);
      final before = await server.repository.readCommit(reencrypted);

      final result = await tomSecretsCompact(
        remote: remote,
        reader: reader(),
        branch: 'main',
        device: 'mbp',
        now: now,
      );
      expect(result.compacted, isTrue);
      expect(result.oldHead, reencrypted.hex);
      expect(result.kept, 0);
      expect(result.newHead, result.root);
      expect((await head()).hex, result.newHead);

      final root = await server.repository.readCommit(await head());
      expect(root.parents, isEmpty);
      expect(root.tree, before.tree, reason: 'the files as they are now');
      expect(
        root.author.encode(),
        'mbp <mbp@tsm.invalid> '
        '${now.millisecondsSinceEpoch ~/ 1000} +0000',
      );
      expect(root.committer.encode(), root.author.encode());
      expect(
        root.message,
        tomSecretsCompactionMessage(
          compactedBy: 'mbp',
          oldHead: reencrypted.hex,
          retentionDays: 0,
        ),
      );
      expect(
        await tomSecretsClassifyMove(
          reader(),
          path: 'vaults/fleet.kdbx',
          baseBlob: tomSecretsBlobId(utf8.encode('old key 2')),
          head: result.newHead,
        ),
        isA<TomSecretsBranchCompacted>(),
        reason: 'a device whose base was under the old key follows it',
      );
      expect(server.requests['push'], 1);
    });

    test('with a retention: the root holds the files at the window\'s start, '
        'later commits are re-created with their trees, messages and '
        'people', () async {
      final r = server.repository;
      await commitAt(r, {'vaults/fleet.kdbx': 'v200'}, 200);
      await commitAt(r, {'vaults/fleet.kdbx': 'v120'}, 120);
      final atStart = await commitAt(r, {'vaults/fleet.kdbx': 'v100'}, 100);
      final keep1 = await commitAt(
        r,
        {'vaults/fleet.kdbx': 'v60'},
        60,
        who: 'bigbeast',
      );
      final keep2 = await commitAt(r, {'vaults/fleet.kdbx': 'v10'}, 10);

      final result = await tomSecretsCompact(
        remote: remote,
        reader: reader(),
        branch: 'main',
        device: 'mbp',
        retentionDays: 90,
        now: now,
      );
      expect(result.compacted, isTrue);
      expect(result.kept, 2);

      final tip = await r.readCommit(await head());
      final middle = await r.readCommit(tip.parents.single);
      final root = await r.readCommit(middle.parents.single);
      expect(root.parents, isEmpty);
      expect(root.tree, (await r.readCommit(atStart)).tree);
      expect(root.message, contains('Tsm-Retention: 90'));
      for (final (rewritten, original) in [(middle, keep1), (tip, keep2)]) {
        final o = await r.readCommit(original);
        expect(rewritten.tree, o.tree);
        expect(rewritten.message, o.message);
        expect(rewritten.author.encode(), o.author.encode());
        expect(rewritten.committer.encode(), o.committer.encode());
      }
      expect(await head(), isNot(keep2), reason: 'new commit ids');
    });

    test('nothing older than the window, or a head that is a root already: '
        'nothing is pushed', () async {
      await commitAt(server.repository, {'vaults/fleet.kdbx': 'v30'}, 30);
      await commitAt(server.repository, {'vaults/fleet.kdbx': 'v10'}, 10);
      final h = await head();
      final result = await tomSecretsCompact(
        remote: remote,
        reader: reader(),
        branch: 'main',
        device: 'mbp',
        retentionDays: 90,
        now: now,
      );
      expect(result.compacted, isFalse);
      expect(await head(), h);

      final once = await tomSecretsCompact(
        remote: remote,
        reader: reader(),
        branch: 'main',
        device: 'mbp',
        now: now,
      );
      final again = await tomSecretsCompact(
        remote: remote,
        reader: reader(),
        branch: 'main',
        device: 'mbp',
        now: now,
      );
      expect(once.compacted, isTrue);
      expect(again.compacted, isFalse);
      expect(again.newHead, once.newHead);
      expect(server.requests['push'], 1);
    });

    test('a save that lands during the compaction refuses its push; it reads '
        'the head again and keeps the save', () async {
      await commitAt(server.repository, {'vaults/fleet.kdbx': 'v0'}, 9);
      await commitAt(server.repository, {'vaults/fleet.kdbx': 'v1'}, 5);
      var raced = false;
      server.beforePush = () async {
        if (raced) return;
        raced = true;
        await commitAt(server.repository, {'vaults/fleet.kdbx': 'saved'}, 0);
      };
      final saved = server.repository;
      final result = await tomSecretsCompact(
        remote: remote,
        reader: reader(),
        branch: 'main',
        device: 'mbp',
        now: now,
      );
      expect(result.compacted, isTrue);
      final root = await saved.readCommit(await head());
      expect(
        utf8.decode(
          await saved.readBlob(
            (await saved.entryAt(root.tree, 'vaults/fleet.kdbx'))!.id,
          ),
        ),
        'saved',
      );
      expect(server.requests['push'], 2);
    });

    test('a github: vault\'s remote: the repository over smart HTTP, the '
        'token as x-access-token', () async {
      final remote = tomSecretsGitHubRemote(
        TomSecretsVaultLocator.parse(locator) as TomSecretsGitHubLocator,
        token: () async => 'demo-token',
      );
      expect(remote.url.toString(), 'https://github.com/$owner/$repo.git');
      final credentials = (await remote.credentials!(remote.url))!;
      expect(credentials.username, 'x-access-token');
      expect(credentials.password, 'demo-token');
      remote.close();
    });

    test('a device following its own compaction moves its base without a '
        'read; the cache record follows', () async {
      final cache = TomSecretsOfflineCache(scratch('follow'));
      final unit = await TomSecretsVaultUnit.create(
        locator: 'mem:vaults/fleet.kdbx',
        storage: TomMemoryStorage(TomMemoryRemote()),
        file: demoVault(),
        device: 'mbp',
        cache: cache,
      );
      final old = unit.head!;
      await unit.followCompaction(
        TomSecretsCompactionResult(
          oldHead: old,
          newHead: 'a' * 40,
          root: 'a' * 40,
          kept: 0,
          compacted: true,
        ),
      );
      expect(unit.head, 'a' * 40);
      expect((await cache.get('mem:vaults/fleet.kdbx'))!.head, 'a' * 40);
      await unit.followCompaction(
        const TomSecretsCompactionResult(
          oldHead: 'x',
          newHead: 'y',
          root: 'y',
          kept: 0,
          compacted: true,
        ),
      );
      expect(unit.head, 'a' * 40, reason: 'another head is not followed');
    });
  });

  group('the workflow in each vault repository', () {
    test('the workflow, its script and its configuration', () {
      final files = tomSecretsCompactionFiles(
        const TomSecretsCompactionSettings(retentionDays: 30, intervalDays: 7),
      );
      expect(files.keys, [
        '.github/workflows/compact.yml',
        '.tsm/compact.sh',
        '.tsm/compaction.yaml',
      ]);
      final workflow = loadYaml(files['.github/workflows/compact.yml']!) as Map;
      expect(workflow['permissions'], {'contents': 'write'});
      final on = workflow['on'] as Map;
      expect((on['schedule'] as List).single, contains('cron'));
      expect(on.containsKey('workflow_dispatch'), isTrue);
      final steps =
          ((workflow['jobs'] as Map)['compact'] as Map)['steps'] as List;
      expect(
        steps.where((s) => (s as Map).containsKey('uses')),
        isEmpty,
        reason: 'no actions at all, only the repository\'s own script',
      );
      expect((steps.last as Map)['run'], 'bash .tsm/compact.sh');
      expect(
        files['.github/workflows/compact.yml'],
        isNot(contains('secrets.TSM')),
        reason: 'no vault key reaches the workflow',
      );

      final settings = TomSecretsCompactionSettings.parse(
        files['.tsm/compaction.yaml']!,
      );
      expect(settings.retentionDays, 30);
      expect(settings.intervalDays, 7);
      expect(tomSecretsCompactionSettingsOf(null).retentionDays, 90);
      expect(tomSecretsCompactionSettingsOf(null).intervalDays, 30);
      expect(
        () => TomSecretsCompactionSettings.parse('interval_days: 0\n'),
        throwsFormatException,
      );
      expect(
        () => TomSecretsCompactionSettings.parse('retention_days: soon\n'),
        throwsFormatException,
      );
    });

    group('the script, run by git', () {
      final git = Process.runSync('git', ['--version']).exitCode == 0;

      late Directory dir;
      late String origin;
      late Map<String, String> env;

      Future<String> run(List<String> args, {String? cwd, int? at}) async {
        final result = await Process.run(
          args.first,
          args.sublist(1),
          workingDirectory: cwd ?? dir.path,
          environment: {
            ...env,
            if (at != null) ...{
              'GIT_AUTHOR_DATE': '$at +0000',
              'GIT_COMMITTER_DATE': '$at +0000',
            },
          },
        );
        expect(result.exitCode, 0, reason: '${result.stderr}');
        return (result.stdout as String).trim();
      }

      int ago(int days) => now.millisecondsSinceEpoch ~/ 1000 - days * day;

      /// A vault repository on a bare origin: the compaction files with
      /// [settings], then saves [daysAgo] days ago.
      Future<String> history(
        TomSecretsCompactionSettings settings,
        List<int> daysAgo,
      ) async {
        dir = scratch('script');
        origin = '${dir.path}/origin.git';
        env = {
          'GIT_AUTHOR_NAME': 'mbp',
          'GIT_AUTHOR_EMAIL': 'mbp@tsm.invalid',
          'GIT_COMMITTER_NAME': 'mbp',
          'GIT_COMMITTER_EMAIL': 'mbp@tsm.invalid',
          'GIT_CONFIG_NOSYSTEM': '1',
          // No detached auto gc or maintenance: it would still write into
          // the scratch repository while the teardown deletes it.
          'GIT_CONFIG_COUNT': '3',
          'GIT_CONFIG_KEY_0': 'gc.autoDetach',
          'GIT_CONFIG_VALUE_0': 'false',
          'GIT_CONFIG_KEY_1': 'maintenance.autoDetach',
          'GIT_CONFIG_VALUE_1': 'false',
          'GIT_CONFIG_KEY_2': 'maintenance.auto',
          'GIT_CONFIG_VALUE_2': 'false',
          'HOME': dir.path,
          'TSM_NOW': '${now.millisecondsSinceEpoch ~/ 1000}',
        };
        await run(['git', 'init', '--quiet', '--bare', '-b', 'main', origin]);
        await run(['git', 'clone', '--quiet', origin, 'work']);
        final work = '${dir.path}/work';
        await run([
          'git',
          'symbolic-ref',
          'HEAD',
          'refs/heads/main',
        ], cwd: work);
        for (final e in tomSecretsCompactionFiles(settings).entries) {
          File('$work/${e.key}')
            ..parent.createSync(recursive: true)
            ..writeAsStringSync(e.value);
        }
        Directory('$work/vaults').createSync();
        var first = true;
        for (final d in daysAgo) {
          File('$work/vaults/fleet.kdbx').writeAsStringSync('v$d');
          await run(['git', 'add', '-A'], cwd: work);
          await run(
            [
              'git',
              'commit',
              '--quiet',
              '-m',
              first ? 'tsm: vault created' : 'tsm: fleet.kdbx from mbp ($d)',
            ],
            cwd: work,
            at: ago(d),
          );
          first = false;
        }
        await run(['git', 'push', '--quiet', 'origin', 'main'], cwd: work);
        return run(['git', 'rev-parse', 'HEAD'], cwd: work);
      }

      /// The workflow's steps: a fresh clone, then the script.
      Future<String> workflowRun() async {
        final vault = '${dir.path}/vault';
        if (Directory(vault).existsSync()) {
          Directory(vault).deleteSync(recursive: true);
        }
        await run([
          'git',
          'clone',
          '--quiet',
          '--branch',
          'main',
          origin,
          'vault',
        ]);
        return run(['bash', '.tsm/compact.sh'], cwd: vault);
      }

      Future<List<String>> originLog(String format) async => (await run(
        ['git', '--git-dir', origin, 'log', '--format=$format%x1e', 'main'],
      )).split('\x1e').map((r) => r.trim()).where((r) => r.isNotEmpty).toList();

      test('retention 90: the root holds the files at the window\'s start, '
          'later saves keep their files, messages and people; the cycle '
          'reads it as a compaction', () async {
        final old = await history(const TomSecretsCompactionSettings(), [
          200,
          120,
          100,
          60,
          10,
        ]);
        final before = await originLog('%T|%B|%an|%ae|%at|%cn|%ce|%ct');
        final out = await workflowRun();
        expect(out, contains('2 commits kept'));

        final after = await originLog('%T|%B|%an|%ae|%at|%cn|%ce|%ct');
        expect(after, hasLength(3));
        expect(
          after.sublist(0, 2),
          before.sublist(0, 2),
          reason: 'the kept saves are the same but for their ids',
        );
        final rootTree = after.last.split('|').first;
        expect(
          rootTree,
          before[2].split('|').first,
          reason: 'the files as at day 100, the window\'s start',
        );

        final repository = gitOpenDirectory(origin);
        final head = (await repository.refs.read('refs/heads/main'))!.hex;
        final move = await tomSecretsClassifyMove(
          TomSecretsGitCommitReader(repository),
          path: 'vaults/fleet.kdbx',
          baseBlob: tomSecretsBlobId(utf8.encode('v120')),
          head: head,
        );
        expect(
          move,
          isA<TomSecretsBranchCompacted>().having((m) => m.from, 'from', old),
        );
        var id = head;
        while (true) {
          final c = await TomSecretsGitCommitReader(repository).readCommit(id);
          if (c.parents.isEmpty) {
            expect(c.trailer(tomSecretsRetentionTrailer), '90');
            expect(c.committer!.name, 'tsm compaction');
            break;
          }
          id = c.parents.single;
        }

        expect(
          await workflowRun(),
          contains('not due'),
          reason: 'the interval runs from the newest compaction',
        );
        expect((await originLog('%H')).first, head);
      }, skip: git ? null : 'git is not on this machine');

      test('retention 0: only the current state is kept', () async {
        await history(const TomSecretsCompactionSettings(retentionDays: 0), [
          50,
          40,
          31,
        ]);
        final tree = (await originLog('%T')).first;
        expect(await workflowRun(), contains('0 commits kept'));
        final after = await originLog('%T|%P');
        expect(after, ['$tree|']);
      }, skip: git ? null : 'git is not on this machine');

      test(
        'nothing older than the window: nothing to cut, nothing pushed',
        () async {
          await history(const TomSecretsCompactionSettings(), [50, 10]);
          final heads = await originLog('%H');
          expect(await workflowRun(), contains('nothing to cut'));
          expect(await originLog('%H'), heads);
        },
        skip: git ? null : 'git is not on this machine',
      );
    });
  });
}
