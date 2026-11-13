// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The live check of the compaction against github.com (tsm_a_cmp1): what no
/// offline test proves — that GitHub's receive-pack takes the non-fast-forward
/// update to a parentless root commit sent as a pack of that commit alone,
/// refuses it when the old value is stale, and that the REST reader finds the
/// base's blob and the `Tsm-Compacted-From` root.
///
/// Run by hand against a throwaway PRIVATE repository holding nothing else
/// (the test rewrites its default branch), demo data only:
///
/// ```sh
/// TSM_LIVE_GITHUB_TOKEN=$(gh auth token) \
/// TSM_LIVE_GITHUB_REPO=<owner>/<repo> \
///   dart test test/live_github_compaction_test.dart
/// ```
///
/// Without both variables it skips. The token needs contents write on the
/// repository; it is never printed.
@TestOn('vm')
@Timeout(Duration(minutes: 5))
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_core_storage/github.dart';
import 'package:tom_git/tom_git.dart';
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const notes = KdbxKey('Notes');

/// A remote whose first push is preceded by [beforeFirstPush]: a save that
/// lands between the compaction's read and its push.
final class RacingRemote extends GitHttpRemote {
  RacingRemote(super.url, {super.credentials, required this.beforeFirstPush});

  final Future<void> Function() beforeFirstPush;
  var pushes = 0;

  @override
  Future<GitPushResult> push(
    List<GitRefUpdate> updates,
    Uint8List? pack, {
    void Function(String message)? progress,
  }) async {
    if (pushes++ == 0) await beforeFirstPush();
    return super.push(updates, pack, progress: progress);
  }
}

void main() {
  final token = Platform.environment['TSM_LIVE_GITHUB_TOKEN'];
  final slug = Platform.environment['TSM_LIVE_GITHUB_REPO'];
  final skip = token == null || slug == null
      ? 'set TSM_LIVE_GITHUB_TOKEN and TSM_LIVE_GITHUB_REPO to run it'
      : null;

  test(
    'the app\'s compaction and the force-push detection on github.com',
    () async {
      final [owner, repo] = slug!.split('/');
      // A path of its own per run, so the check repeats on one repository.
      final path =
          'vaults/live-check-${DateTime.now().millisecondsSinceEpoch}.kdbx';
      final locator = 'github:$owner/$repo/$path';
      GitHubApiClient client() => GitHubApiClient(token: token!);
      final api = client();
      final branch = await api.getDefaultBranch(owner: owner, repo: repo);
      final parsed =
          TomSecretsVaultLocator.parse(locator) as TomSecretsGitHubLocator;
      Future<String> head() async => (await api.git.getRef(
        owner: owner,
        repo: repo,
        ref: 'heads/$branch',
      )).sha;
      TomSecretsCommitReader reader() =>
          TomSecretsGitHubCommitReader(client(), owner, repo);
      TomGitHubStorage storage(String device) {
        final s = TomGitHubStorage.withClient(
          client(),
          committer: tomSecretsDeviceCommitter(device),
        );
        addTearDown(s.close);
        return s;
      }

      void edit(TomSecretsVaultUnit unit, String title, String value) {
        unit.working.body.rootGroup
            .getAllEntries()
            .firstWhere((e) => e.label == title)
            .setString(notes, PlainValue(value));
        unit.markEdited();
      }

      String? note(KdbxFile file, String title) => file.body.rootGroup
          .getAllEntries()
          .firstWhere((e) => e.label == title)
          .getString(notes)
          ?.getText();

      // 2. A demo vault, saved three times from two units.
      final vault = DemoVault(store: 'live')
        ..add('Mail/Box', password: 'demo-pw-1', key: 'mail.box')
        ..add('Db/Main', password: 'demo-pw-2', key: 'db.main');
      final a = await TomSecretsVaultUnit.create(
        locator: locator,
        storage: storage('mbp'),
        file: vault.file,
        device: 'mbp',
        history: reader(),
      );
      final firstTree = (await api.git.getCommit(
        owner: owner,
        repo: repo,
        sha: await head(),
      )).treeSha;
      final b = await TomSecretsVaultUnit.open(
        locator: locator,
        storage: storage('bigbeast'),
        credentials: demoCredentials,
        device: 'bigbeast',
        history: reader(),
      );
      edit(b, 'Main', 'from bigbeast');
      expect(await b.push(), isEmpty);
      edit(a, 'Box', 'from mbp');
      expect(await a.push(), isEmpty, reason: 'merged with bigbeast\'s save');
      expect(a.merges, hasLength(1));
      final saved = await head();
      final savedTree = (await api.git.getCommit(
        owner: owner,
        repo: repo,
        sha: saved,
      )).treeSha;
      expect(
        await tomSecretsClassifyMove(
          reader(),
          path: path,
          baseBlob: tomSecretsBlobId(b.baseBytes),
          head: saved,
        ),
        isA<TomSecretsBranchAhead>().having((m) => m.commits, 'commits', 1),
        reason: 'the REST reader finds the base by its blob',
      );

      // 3. The key-change compaction (retention 0), pushed with tom_git.
      final result = await tomSecretsCompact(
        remote: tomSecretsGitHubRemote(parsed, token: () async => token),
        reader: reader(),
        branch: branch,
        device: 'mbp',
      );
      expect(result.compacted, isTrue);
      expect(result.oldHead, saved);
      expect(await head(), result.newHead);
      final root = await api.git.getCommit(
        owner: owner,
        repo: repo,
        sha: result.newHead,
      );
      expect(root.parentShas, isEmpty, reason: 'one commit');
      expect(root.treeSha, savedTree, reason: 'the files as they are');
      expect(root.message, contains('Tsm-Compacted-From: $saved'));
      expect(root.message, contains('Tsm-Retention: 0'));
      expect(root.author?.name, 'mbp');
      expect(root.author?.email, 'mbp@tsm.invalid');
      expect(root.committer?.name, 'mbp');
      expect(root.committer?.email, 'mbp@tsm.invalid');
      await a.followCompaction(result);

      expect(await b.pull(result.newHead), isEmpty);
      expect(b.lastMove, isA<TomSecretsBranchCompacted>());
      expect(note(b.working, 'Box'), 'from mbp');

      // 4a. A save lands between the compaction's read and its push: GitHub
      // refuses the stale old value, the compaction reads again and keeps it.
      // A save first, so the head is no root and there is something to cut.
      edit(a, 'Main', 'saved before the compaction');
      expect(await a.push(), isEmpty);
      final racing = RacingRemote(
        Uri.parse('https://github.com/$owner/$repo.git'),
        credentials: (_) async => GitCredentials.token(token!),
        beforeFirstPush: () async {
          edit(a, 'Box', 'saved during the compaction');
          expect(await a.push(), isEmpty);
        },
      );
      final raced = await tomSecretsCompact(
        remote: racing,
        reader: reader(),
        branch: branch,
        device: 'mbp',
      );
      expect(racing.pushes, 2, reason: 'the first push was refused');
      expect(raced.compacted, isTrue);
      final racedRoot = await api.git.getCommit(
        owner: owner,
        repo: repo,
        sha: raced.newHead,
      );
      expect(racedRoot.parentShas, isEmpty);
      final check = await TomSecretsVaultUnit.open(
        locator: locator,
        storage: storage('bomber'),
        credentials: demoCredentials,
        device: 'bomber',
        history: reader(),
      );
      expect(
        note(check.working, 'Box'),
        'saved during the compaction',
        reason: 'the save that raced the compaction survived it',
      );

      // 4b. A force push through REST without the trailer: not merged.
      final forced = await api.git.createCommit(
        owner: owner,
        repo: repo,
        message: 'demo: a force push of an older state',
        treeSha: firstTree,
        parentShas: const [],
      );
      await api.git.updateRef(
        owner: owner,
        repo: repo,
        ref: 'heads/$branch',
        sha: forced.sha,
        force: true,
      );
      final conflicts = await check.pull(forced.sha);
      expect(conflicts.single, isA<TomSecretsHistoryRewritten>());
      expect(check.rewrittenHead, forced.sha);
      expect(check.merges, isEmpty);
      await check.takeRemote();
      expect(note(check.working, 'Box'), isNull, reason: 'the older state');
    },
    skip: skip,
  );
}
