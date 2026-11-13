// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// How a vault's branch moved (part-stores): ahead of the base, rewritten by
/// a history compaction, or rewritten otherwise (a force push). The cycle
/// follows the first two silently and asks the user about the third.
/// `TomStorage` exposes a file's head (for `TomGitHubStorage` its blob id)
/// and its bytes, not the history, so the history is read through a
/// [TomSecretsCommitReader]: the GitHub REST API for `github:` vaults, a
/// `tom_git` repository for `git:` vaults. The base is found by its file:
/// the commit whose file at the vault's path is the base's blob.
library;

import 'package:tom_git/tom_git.dart';
import 'package:tom_github_api/tom_github_api.dart';

/// The trailer naming the head a compaction replaced.
const String tomSecretsCompactedFromTrailer = 'Tsm-Compacted-From';

/// The trailer naming the retention, in days, a compaction kept.
const String tomSecretsRetentionTrailer = 'Tsm-Retention';

/// One commit as the cycle and the compaction read it.
final class TomSecretsCommit {
  /// Commit [id] of [tree] on [parents] with [message], written by [author]
  /// and made by [committer] (when known).
  const TomSecretsCommit({
    required this.id,
    required this.tree,
    required this.parents,
    required this.message,
    this.author,
    this.committer,
  });

  /// The commit id.
  final String id;

  /// Its root tree.
  final String tree;

  /// Its parents (none for a root commit).
  final List<String> parents;

  /// Its message.
  final String message;

  /// Who wrote it, when known.
  final GitPerson? author;

  /// Who made it, and when, when known.
  final GitPerson? committer;

  /// When it was committed, when known.
  DateTime? get committedAt => committer == null
      ? null
      : DateTime.fromMillisecondsSinceEpoch(
          committer!.seconds * 1000,
          isUtc: true,
        );

  /// The value of the trailer [key] in the message's last paragraph, or
  /// null.
  String? trailer(String key) {
    final paragraphs = message.trim().split(RegExp(r'\n\s*\n'));
    for (final line in paragraphs.last.split('\n')) {
      final colon = line.indexOf(':');
      if (colon > 0 && line.substring(0, colon).trim() == key) {
        return line.substring(colon + 1).trim();
      }
    }
    return null;
  }

  /// The head a compaction made this root commit from, or null when it is
  /// not a compaction's root.
  String? get compactedFrom =>
      parents.isEmpty ? trailer(tomSecretsCompactedFromTrailer) : null;

  @override
  String toString() => 'TomSecretsCommit($id, ${parents.length} parents)';
}

/// Reads the commits of one branch of a repository.
abstract interface class TomSecretsCommitReader {
  /// The branch's head commit, or null when the branch does not exist.
  Future<String?> branchHead();

  /// The commit [id].
  Future<TomSecretsCommit> readCommit(String id);

  /// The blob id of the file at [path] in [commit]'s tree, or null when the
  /// tree holds no file there.
  Future<String?> blobAt(TomSecretsCommit commit, String path);
}

/// Commits read through the GitHub REST API (`GET git/commits/{sha}`), one
/// request each.
final class TomSecretsGitHubCommitReader implements TomSecretsCommitReader {
  /// Commits of [branch] (default: the repository's default branch) of
  /// [owner]/[repository] through [client].
  TomSecretsGitHubCommitReader(
    this.client,
    this.owner,
    this.repository, {
    String? branch,
  }) : _branch = branch;

  /// The API client.
  final GitHubApiClient client;

  /// The repository's owner.
  final String owner;

  /// The repository.
  final String repository;

  String? _branch;

  @override
  Future<String?> branchHead() async {
    final branch = _branch ??= await client.getDefaultBranch(
      owner: owner,
      repo: repository,
    );
    try {
      return (await client.git.getRef(
        owner: owner,
        repo: repository,
        ref: 'heads/$branch',
      )).sha;
    } on GitHubNotFoundException {
      return null;
    }
  }

  /// One request: the commit's tree read recursively (a vault repository
  /// is small; a truncated listing is answered as no file).
  @override
  Future<String?> blobAt(TomSecretsCommit commit, String path) async {
    final tree = await client.git.getTreeOrNull(
      owner: owner,
      repo: repository,
      sha: commit.tree,
      recursive: true,
    );
    if (tree == null) return null;
    for (final e in tree.entries) {
      if (e.path == path && e.type == 'blob') return e.sha;
    }
    return null;
  }

  @override
  Future<TomSecretsCommit> readCommit(String id) async {
    final c = await client.git.getCommit(
      owner: owner,
      repo: repository,
      sha: id,
    );
    return TomSecretsCommit(
      id: c.sha,
      tree: c.treeSha,
      parents: c.parentShas,
      message: c.message,
      author: _person(c.author),
      committer: _person(c.committer),
    );
  }

  static GitPerson? _person(GitHubGitIdentity? identity) {
    final date = identity?.date;
    if (identity == null || date == null) return null;
    return GitPerson(
      name: identity.name,
      email: identity.email,
      seconds: date.millisecondsSinceEpoch ~/ 1000,
    );
  }
}

/// Commits read from a `tom_git` repository (a `git:` vault's clone, or a
/// repository a compaction fetched into).
final class TomSecretsGitCommitReader implements TomSecretsCommitReader {
  /// Commits of [branch] of [repository]; [ref] names the branch's ref
  /// (default `refs/heads/<branch>`, e.g. a remote-tracking ref instead).
  TomSecretsGitCommitReader(
    this.repository, {
    this.branch = 'main',
    String? ref,
  }) : ref = ref ?? 'refs/heads/$branch';

  /// The repository.
  final GitRepository repository;

  /// The branch.
  final String branch;

  /// The ref its head is read from.
  final String ref;

  @override
  Future<String?> branchHead() async => (await repository.refs.read(ref))?.hex;

  @override
  Future<String?> blobAt(TomSecretsCommit commit, String path) async {
    final entry = await repository.entryAt(
      GitObjectId.fromHex(commit.tree),
      path,
    );
    return entry == null || entry.isTree ? null : entry.id.hex;
  }

  @override
  Future<TomSecretsCommit> readCommit(String id) async {
    final c = await repository.readCommit(GitObjectId.fromHex(id));
    return TomSecretsCommit(
      id: id,
      tree: c.tree.hex,
      parents: [for (final p in c.parents) p.hex],
      message: c.message,
      author: c.author,
      committer: c.committer,
    );
  }
}

/// How a branch moved from a base to a new head.
sealed class TomSecretsBranchMove {
  const TomSecretsBranchMove();
}

/// The new head descends from the base: merge as usual.
final class TomSecretsBranchAhead extends TomSecretsBranchMove {
  /// Ahead by [commits] commits.
  const TomSecretsBranchAhead(this.commits);

  /// How many commits the new head is ahead.
  final int commits;
}

/// The history was compacted: the base left it, and the new history starts
/// at a root commit carrying `Tsm-Compacted-From`. Its files continue the
/// base's line, so the cycle merges against its base as usual.
final class TomSecretsBranchCompacted extends TomSecretsBranchMove {
  /// Compacted by the root [root] from the old head [from].
  const TomSecretsBranchCompacted({required this.root, required this.from});

  /// The new root commit.
  final String root;

  /// The head the compaction replaced.
  final String from;
}

/// The history was rewritten without a compaction's trailer (a force push),
/// or could not be followed within the walk's limit: the user decides.
final class TomSecretsBranchRewritten extends TomSecretsBranchMove {
  /// Rewritten, for [reason].
  const TomSecretsBranchRewritten(this.reason);

  /// Why the move counts as rewritten.
  final String reason;
}

/// How the branch moved from the base to [head]: the history behind [head]
/// is walked (newest first, every parent) until a commit whose file at
/// [path] is [baseBlob] is found, or every path ends at a root commit, or
/// [maxCommits] commits were read. Each commit read costs a request or a few
/// on GitHub (the commit and the trees down to [path]), so the limit is
/// small; a walk that hits it is answered as rewritten, so the user is asked
/// rather than a merge guessed.
Future<TomSecretsBranchMove> tomSecretsClassifyMove(
  TomSecretsCommitReader reader, {
  required String path,
  required String baseBlob,
  required String head,
  int maxCommits = 100,
}) async {
  final seen = <String>{head};
  final queue = <String>[head];
  TomSecretsBranchCompacted? compaction;
  var read = 0;
  while (queue.isNotEmpty) {
    if (read == maxCommits) {
      return TomSecretsBranchRewritten(
        'the base was not found in the newest $maxCommits commits',
      );
    }
    final commit = await reader.readCommit(queue.removeAt(0));
    if (await reader.blobAt(commit, path) == baseBlob) {
      return TomSecretsBranchAhead(read);
    }
    read++;
    final from = commit.compactedFrom;
    if (from != null) {
      compaction ??= TomSecretsBranchCompacted(root: commit.id, from: from);
    }
    for (final parent in commit.parents) {
      if (seen.add(parent)) queue.add(parent);
    }
  }
  return compaction ??
      const TomSecretsBranchRewritten(
        'the history no longer holds the base, and no compaction replaced it',
      );
}
