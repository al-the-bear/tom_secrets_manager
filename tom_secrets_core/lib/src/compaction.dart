// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// History compaction (part-stores, part-key-rotation, DP-9, DP-82).
///
/// - **The app's compaction** ([tomSecretsCompact]): on every key change,
///   after the files were re-encrypted, the branch is rewritten to a single
///   root commit holding the files as they are now (retention 0); "Compact
///   now" and `tsm compact` run the same cut with the repository's retention.
///   It is pushed over the git protocol with `tom_git`, the old head as the
///   expected value: GitHub's REST ref update has none for a forced update.
/// - **The workflow** ([tomSecretsCompactionFiles]): each vault repository
///   carries `.github/workflows/compact.yml`, its script `.tsm/compact.sh` and
///   its configuration `.tsm/compaction.yaml`. The workflow holds no vault key
///   and only cuts the history: a new root commit holding the files as they
///   were at the retention window's start, every later commit re-created on
///   top of it with the same files and messages.
///
/// Both write the same root commit trailers, `Tsm-Compacted-From: <old head>`
/// and `Tsm-Retention: <days>`, by which every device follows a compaction
/// silently (`tomSecretsClassifyMove`).
library;

import 'package:http/http.dart' as http;
import 'package:tom_git/tom_git.dart';
import 'package:yaml/yaml.dart';

import 'history.dart';
import 'locator.dart';
import 'vault_sync.dart' show tomSecretsDeviceCommitter;

/// A compaction that could not be pushed.
final class TomSecretsCompactionException implements Exception {
  /// A failure described by [message]; [race] when saves kept landing
  /// between the read and the push.
  TomSecretsCompactionException(this.message, {this.race = false});

  /// What went wrong.
  final String message;

  /// Whether every attempt lost a race against a save.
  final bool race;

  @override
  String toString() => 'TomSecretsCompactionException: $message';
}

/// A repository's compaction configuration (`.tsm/compaction.yaml`).
final class TomSecretsCompactionSettings {
  /// Revisions kept for [retentionDays] (0: only the current state); a
  /// compaction due every [intervalDays].
  const TomSecretsCompactionSettings({
    this.retentionDays = 90,
    this.intervalDays = 30,
  }) : assert(retentionDays >= 0 && intervalDays >= 1);

  /// The configuration in [yaml]; a missing key keeps its default.
  factory TomSecretsCompactionSettings.parse(String yaml) {
    final doc = loadYaml(yaml);
    final map = doc is YamlMap ? doc : YamlMap();
    int read(String key, int fallback, int min) {
      final value = map[key];
      if (value == null) return fallback;
      if (value is! int || value < min) {
        throw FormatException('$key must be a whole number of at least $min');
      }
      return value;
    }

    return TomSecretsCompactionSettings(
      retentionDays: read('retention_days', 90, 0),
      intervalDays: read('interval_days', 30, 1),
    );
  }

  /// How far back revisions are kept, in days.
  final int retentionDays;

  /// How often a compaction is due, in days.
  final int intervalDays;

  /// The configuration file's text.
  String toYaml() =>
      '# Tom Secrets Manager: history compaction (.github/workflows/compact.yml).\n'
      '# retention_days: how far back revisions are kept; 0 keeps only the\n'
      '# current state. interval_days: how often a compaction is due.\n'
      'retention_days: $retentionDays\n'
      'interval_days: $intervalDays\n';
}

/// What a compaction did.
final class TomSecretsCompactionResult {
  /// Rewrote [oldHead] to [newHead], starting at [root], keeping [kept]
  /// commits above the root; [compacted] false when there was nothing to cut.
  const TomSecretsCompactionResult({
    required this.oldHead,
    required this.newHead,
    required this.root,
    required this.kept,
    required this.compacted,
  });

  /// The head before.
  final String oldHead;

  /// The head after (the old head when nothing was cut).
  final String newHead;

  /// The new root commit (the old root when nothing was cut).
  final String root;

  /// The commits re-created above the root.
  final int kept;

  /// Whether the branch was rewritten.
  final bool compacted;
}

/// The root commit's message: a subject naming who compacted, then the
/// trailers.
String tomSecretsCompactionMessage({
  required String compactedBy,
  required String oldHead,
  required int retentionDays,
}) =>
    'tsm: history compacted by $compactedBy\n'
    '\n'
    '$tomSecretsCompactedFromTrailer: $oldHead\n'
    '$tomSecretsRetentionTrailer: $retentionDays\n';

/// Compacts [branch] of [remote] for [device]: a new root commit holding the
/// files as they were [retentionDays] days before [now] (0: as they are
/// now), every later commit of the first-parent line re-created on it with
/// the same tree, message, author and committer, the older ones dropped.
/// The root names [device] as author and committer
/// (`tomSecretsDeviceCommitter`).
///
/// [reader] reads the remote's commits (the GitHub REST API for a `github:`
/// vault, the fetched clone for a `git:` vault). Only the new commits are
/// sent: their trees and files are the remote's already. The push expects
/// the head it read; a save that landed in between refuses it, and the
/// compaction reads the head again and starts over, up to [maxAttempts]
/// times. Nothing to cut (the window reaches back to the root, or the head
/// is a root already) pushes nothing.
Future<TomSecretsCompactionResult> tomSecretsCompact({
  required GitHttpRemote remote,
  required TomSecretsCommitReader reader,
  required String branch,
  required String device,
  int retentionDays = 0,
  DateTime? now,
  int maxAttempts = 3,
}) async {
  if (retentionDays < 0) {
    throw ArgumentError.value(retentionDays, 'retentionDays', 'at least 0');
  }
  final at = (now ?? DateTime.now()).toUtc();
  final windowStart = at.subtract(Duration(days: retentionDays));
  final identity = tomSecretsDeviceCommitter(device);
  final person = GitPerson.now(identity.name, identity.email, at: at);
  final ref = 'refs/heads/$branch';

  for (var attempt = 1; attempt <= maxAttempts; attempt++) {
    final headId = (await remote.listPushRefs()).refs[ref];
    if (headId == null) {
      throw TomSecretsCompactionException('the remote has no branch $branch');
    }
    final head = headId.hex;

    // The first-parent line, newest first, down to the commit that holds
    // the files as they were at the window's start.
    final line = <TomSecretsCommit>[];
    TomSecretsCommit? base;
    var id = head;
    while (true) {
      final commit = await reader.readCommit(id);
      final committed = commit.committedAt;
      if (retentionDays == 0 ||
          (committed != null && committed.isBefore(windowStart))) {
        base = commit;
        break;
      }
      line.add(commit);
      if (commit.parents.isEmpty) break;
      id = commit.parents.first;
    }
    if (base == null || base.parents.isEmpty) {
      return TomSecretsCompactionResult(
        oldHead: head,
        newHead: head,
        root: base?.id ?? line.last.id,
        kept: line.length,
        compacted: false,
      );
    }

    final objects = <GitObject>[];
    GitObjectId write(GitCommit commit) {
      final object = commit.toObject();
      objects.add(object);
      return GitObjectId.hash('commit', object.content);
    }

    final root = write(
      GitCommit(
        tree: GitObjectId.fromHex(base.tree),
        parents: const [],
        author: person,
        committer: person,
        message: tomSecretsCompactionMessage(
          compactedBy: device,
          oldHead: head,
          retentionDays: retentionDays,
        ),
      ),
    );
    var tip = root;
    for (final commit in line.reversed) {
      final committer = commit.committer ?? person;
      tip = write(
        GitCommit(
          tree: GitObjectId.fromHex(commit.tree),
          parents: [tip],
          author: commit.author ?? committer,
          committer: committer,
          message: commit.message.endsWith('\n')
              ? commit.message
              : '${commit.message}\n',
        ),
      );
    }

    final result = await remote.push([
      GitRefUpdate(ref, oldId: headId, newId: tip),
    ], gitWritePack(objects));
    if (result.ok) {
      return TomSecretsCompactionResult(
        oldHead: head,
        newHead: tip.hex,
        root: root.hex,
        kept: line.length,
        compacted: true,
      );
    }
    final current = (await remote.listPushRefs()).refs[ref];
    if (result.unpackError != null || current == headId) {
      throw TomSecretsCompactionException('the remote refused it: $result');
    }
  }
  throw TomSecretsCompactionException(
    'saves landed during each of $maxAttempts attempts',
    race: true,
  );
}

/// The git remote of a `github:` vault's repository for [tomSecretsCompact]:
/// `https://github.com/<owner>/<repository>.git` over smart HTTP, the vault
/// token sent as `x-access-token` (the GitHub token the cycle uses; a
/// compaction needs contents write, no more).
GitHttpRemote tomSecretsGitHubRemote(
  TomSecretsGitHubLocator locator, {
  required Future<String?> Function() token,
  http.Client? client,
}) => GitHttpRemote(
  Uri.parse('https://github.com/${locator.owner}/${locator.repository}.git'),
  client: client,
  credentials: (_) async {
    final secret = await token();
    return secret == null ? null : GitCredentials.token(secret);
  },
);

/// The workflow file's path in a vault repository.
const String tomSecretsCompactionWorkflowPath = '.github/workflows/compact.yml';

/// The script's path in a vault repository.
const String tomSecretsCompactionScriptPath = '.tsm/compact.sh';

/// The configuration's path in a vault repository.
const String tomSecretsCompactionConfigPath = '.tsm/compaction.yaml';

/// The files the app places in a vault repository: the workflow, its script
/// and the configuration [settings], by path. The workflow file needs the
/// `workflows` permission the vault tokens do not have, so the app shows it
/// and the user commits it; the script and the configuration the app
/// commits itself.
Map<String, String> tomSecretsCompactionFiles([
  TomSecretsCompactionSettings settings = const TomSecretsCompactionSettings(),
]) => {
  tomSecretsCompactionWorkflowPath: _workflow,
  tomSecretsCompactionScriptPath: _script,
  tomSecretsCompactionConfigPath: settings.toYaml(),
};

// Why no actions/checkout: the repository allows its own workflows only
// (allowed_actions=local_only), so the workflow clones with git itself.
const String _workflow = r'''
# Tom Secrets Manager: history compaction (DP-82).
# It holds no vault key and decrypts nothing: it only cuts the history
# (.tsm/compact.sh, configured in .tsm/compaction.yaml), and never runs
# anything but this repository's own script.
name: tsm-compact

on:
  schedule:
    - cron: '23 3 * * *'
  workflow_dispatch: {}

permissions:
  contents: write

concurrency:
  group: tsm-compact
  cancel-in-progress: false

jobs:
  compact:
    runs-on: ubuntu-latest
    steps:
      - name: Clone the repository with its whole history
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          git clone --quiet --branch "${GITHUB_REF_NAME}" \
            "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" vault
      - name: Compact when due
        working-directory: vault
        run: bash .tsm/compact.sh
''';

const String _script = r'''
#!/usr/bin/env bash
# Tom Secrets Manager: history compaction (DP-82), run by
# .github/workflows/compact.yml in a full clone of the vault repository.
# It holds and needs no vault key: it moves the stored files as they are.
#
# When the interval (.tsm/compaction.yaml, interval_days) has passed since the
# newest compaction, it makes a new root commit holding the files as they were
# retention_days ago, re-creates every later commit on it with the same files,
# message, author and committer, and drops the older ones. retention_days 0
# keeps only the current state. The push expects the head it read
# (--force-with-lease): a save that lands in between makes it fail, and the
# next run tries again. TSM_NOW (seconds since the epoch) stands in for the
# clock in tests. Under pipefail every reader in a pipeline reads its input
# to the end: one that stops early (head, grep -q, awk's exit) can leave the
# writer dying of SIGPIPE, which fails the run on a long history.
set -euo pipefail

config=.tsm/compaction.yaml
setting() {
  local value
  value=$(sed -n "s/^$1:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*\(#.*\)\{0,1\}$/\1/p" \
    "$config" 2>/dev/null | sed -n 1p)
  echo "${value:-$2}"
}
retention_days=$(setting retention_days 90)
interval_days=$(setting interval_days 30)
now=${TSM_NOW:-$(date +%s)}
branch=$(git symbolic-ref --short HEAD)
head=$(git rev-parse HEAD)

# The newest compaction is the root commit, when it carries the trailer.
root=$(git rev-list --max-parents=0 HEAD | sed -n 1p)
last=0
if git log -1 --format=%B "$root" | grep '^Tsm-Compacted-From:' >/dev/null; then
  last=$(git log -1 --format=%ct "$root")
fi
if [ $((now - last)) -lt $((interval_days * 86400)) ]; then
  echo "tsm-compact: not due (interval ${interval_days} days)"
  exit 0
fi

# The commit holding the files as they were at the window's start.
if [ "$retention_days" -eq 0 ]; then
  base=$head
else
  window_start=$((now - retention_days * 86400))
  base=$(git log --first-parent --format='%H %ct' HEAD |
    awk -v start="$window_start" '!found && $2 < start { print $1; found = 1 }')
fi
if [ -z "$base" ] || [ -z "$(git log -1 --format=%P "$base")" ]; then
  echo "tsm-compact: nothing to cut"
  exit 0
fi

export GIT_AUTHOR_NAME='tsm compaction' GIT_AUTHOR_EMAIL='compaction@tsm.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE="$now +0000" GIT_COMMITTER_DATE="$now +0000"
new=$(printf 'tsm: history compacted by the compaction workflow\n\nTsm-Compacted-From: %s\nTsm-Retention: %s\n' \
  "$head" "$retention_days" | git commit-tree "$base^{tree}" -F -)
kept=0
for commit in $(git rev-list --reverse --first-parent "$base..$head"); do
  IFS=$'\037' read -r an ae ad cn ce cd < <(git log -1 --date=raw \
    --format='%an%x1f%ae%x1f%ad%x1f%cn%x1f%ce%x1f%cd' "$commit")
  new=$(git cat-file commit "$commit" | sed '1,/^$/d' |
    GIT_AUTHOR_NAME="$an" GIT_AUTHOR_EMAIL="$ae" GIT_AUTHOR_DATE="$ad" \
    GIT_COMMITTER_NAME="$cn" GIT_COMMITTER_EMAIL="$ce" GIT_COMMITTER_DATE="$cd" \
    git commit-tree "$commit^{tree}" -p "$new" -F -)
  kept=$((kept + 1))
done

git push --quiet --force-with-lease="refs/heads/$branch:$head" origin \
  "$new:refs/heads/$branch"
echo "tsm-compact: compacted $head to $new, ${kept} commits kept (${retention_days} days)"
''';

/// [settings] read from the configuration file's [text], or the defaults
/// when there is none.
TomSecretsCompactionSettings tomSecretsCompactionSettingsOf(String? text) =>
    text == null || text.trim().isEmpty
    ? const TomSecretsCompactionSettings()
    : TomSecretsCompactionSettings.parse(text);
