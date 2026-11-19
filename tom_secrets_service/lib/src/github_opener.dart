// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `github:` vaults for the service (part-service, part-stores): opened
/// through tom_secrets_core's `TomSecretsVaultUnit` over `TomGitHubStorage`,
/// kept in the offline cache and opened from it when GitHub cannot be reached
/// or refuses the token. The token of each repository is asked for on every
/// request, so a token the user replaces takes effect at the next fetch; the
/// expiry GitHub reports for it (`GitHub-Authentication-Token-Expiration`)
/// is recorded for the key-expiry reminders.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:tom_basics/diagnostics.dart';
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_core_sync/tom_core_sync.dart'
    show TomCasExhaustedException, TomCommitFailedException, TomSyncConflict;
import 'package:tom_git/tom_git.dart' show GitHttpRemote;
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'vault_set.dart';

/// The git remote a compaction pushes [vault]'s repository to, with
/// [token] its credential.
typedef TomSecretsGitRemoteFor =
    GitHttpRemote Function(
      TomSecretsGitHubLocator vault,
      Future<String?> Function() token,
    );

/// The commit reader a compaction reads [vault]'s repository's history with.
typedef TomSecretsCommitReaderFor =
    TomSecretsCommitReader Function(TomSecretsGitHubLocator vault);

/// The GitHub token for [vault]'s repository, or null when there is none.
typedef TomSecretsGitHubTokens =
    Future<String?> Function(TomSecretsGitHubLocator vault);

/// Opens, reads and writes `github:` vaults.
final class TomSecretsGitHubOpener implements TomSecretsVaultOpener {
  /// An opener committing as [device], asking [tokens] for each repository's
  /// token, keeping the offline cache under [cacheDirectory] while
  /// [useCache] answers true (null: no cache), reaching GitHub at [baseUrl]
  /// through [httpClient] (null: its own).
  TomSecretsGitHubOpener({
    required this.device,
    required this.tokens,
    this.cacheDirectory,
    bool Function()? useCache,
    this.baseUrl = 'https://api.github.com',
    http.Client? httpClient,
    DateTime Function()? clock,
    TomSecretsGitRemoteFor? remoteFor,
    TomSecretsCommitReaderFor? readerFor,
  }) : _useCache = useCache ?? _always,
       _httpClient = httpClient,
       _clock = clock ?? DateTime.now,
       _remoteFor = remoteFor,
       _readerFor = readerFor;

  final TomSecretsGitRemoteFor? _remoteFor;
  final TomSecretsCommitReaderFor? _readerFor;

  static bool _always() => true;

  /// This device's name, in commit messages.
  final String device;

  /// The token source.
  final TomSecretsGitHubTokens tokens;

  /// The offline cache's directory, or null.
  final String? cacheDirectory;

  /// GitHub's API.
  final String baseUrl;

  final bool Function() _useCache;
  final http.Client? _httpClient;
  final DateTime Function() _clock;
  final Map<String, _Repository> _repositories = {};

  /// The unit of each vault opened, kept for its saves: its base is the
  /// copy the service serves.
  final Map<String, TomSecretsVaultUnit> _units = {};
  final Map<String, DateTime> _tokenExpiries = {};

  /// The expiry GitHub reported for each repository's token
  /// (`owner/repository` → UTC), as last seen; a token without an expiry
  /// carries no header and has no entry.
  Map<String, DateTime> get tokenExpiries => Map.unmodifiable(_tokenExpiries);

  static TomSecretsGitHubLocator _parse(String locator) {
    final parsed = TomSecretsVaultLocator.parse(locator);
    if (parsed is! TomSecretsGitHubLocator) {
      throw UnsupportedError('$locator is not a github: vault');
    }
    return parsed;
  }

  _Repository _repository(TomSecretsGitHubLocator vault) => _repositories
      .putIfAbsent(vault.repositorySlug, () => _Repository(this, vault));

  TomSecretsVaultCodec _codec(
    TomSecretsGitHubLocator vault,
    String? outerKey,
  ) =>
      tomSecretsOuterCodecFor(vault.fileName, outerKey) ??
      const TomSecretsPlainCodec();

  @override
  Future<TomSecretsOpenedVault> open(
    String locator,
    Credentials credentials, {
    String? outerKey,
  }) async {
    final vault = _parse(locator);
    final repository = _repository(vault);
    repository.watch.servedOffline = false;
    final cache = cacheDirectory != null && _useCache()
        ? TomSecretsOfflineCache(Directory(cacheDirectory!))
        : null;
    final TomSecretsVaultUnit unit;
    try {
      unit = await TomSecretsVaultUnit.open(
        locator: locator,
        storage: repository.storage,
        credentials: credentials,
        device: device,
        codec: _codec(vault, outerKey),
        cache: cache,
        history: await repository.history(vault.branch),
        clock: () => _clock().toUtc(),
      );
    } on Object catch (e) {
      if (e is! KdbxInvalidKeyException && e is! TomKeyRequiredException) {
        rethrow;
      }
      // Another device re-keyed the vault (part-key-rotation, the
      // migration period): the offline copy under the key held is served,
      // read-only, until the new key is listed.
      final copy = await _cachedUnderOldKey(
        cache,
        vault,
        locator,
        credentials,
        outerKey,
      );
      if (copy == null) rethrow;
      await _units.remove(locator)?.dispose();
      return copy;
    }
    // Kept for the saves: its base is what the service serves from now on.
    await _units.remove(locator)?.dispose();
    _units[locator] = unit;
    final head = unit.head!;
    // The storage answered from the tree it holds because GitHub did not
    // answer: what was read is the copy held, not a fetch.
    final unanswered = repository.watch.servedOffline
        ? TomUnreachableException(locator, 'GitHub could not be reached')
        : null;
    final cached =
        unit.source == TomSecretsVaultSource.cache || unanswered != null;
    return TomSecretsOpenedVault(
      locator: locator,
      file: unit.working,
      stored: unit.baseBytes,
      revision: head,
      source: cached ? 'cache' : 'github',
      fetchedAt: unit.fetchedAt,
      offlineReason: unit.offlineReason ?? unanswered,
    );
  }

  /// The offline copy of [locator] that [credentials] still open, as a
  /// store served read-only ([TomSecretsKeyChangedException]); null when
  /// there is none or it does not open either.
  Future<TomSecretsOpenedVault?> _cachedUnderOldKey(
    TomSecretsOfflineCache? cache,
    TomSecretsGitHubLocator vault,
    String locator,
    Credentials credentials,
    String? outerKey,
  ) async {
    final cached = await cache?.get(locator);
    if (cached == null) return null;
    try {
      final file = await KdbxFormat().read(
        await _codec(vault, outerKey).decode(cached.bytes),
        credentials,
      );
      return TomSecretsOpenedVault(
        locator: locator,
        file: file,
        stored: cached.bytes,
        revision: cached.head,
        source: 'cache',
        fetchedAt: cached.fetchedAt,
        offlineReason: TomSecretsKeyChangedException(locator),
      );
    } on Object {
      return null;
    }
  }

  @override
  Future<String> revision(String locator) async {
    final repository = _repository(_parse(locator));
    repository.watch.servedOffline = false;
    final head = await repository.storage.headOf(locator);
    if (repository.watch.servedOffline) {
      throw TomUnreachableException(locator, 'GitHub could not be reached');
    }
    if (head == null) throw TomContainerNotFoundException(locator);
    return head;
  }

  @override
  Future<Uint8List> read(String locator) async {
    final vault = _parse(locator);
    final (bytes, _) = await TomSecretsVaultUnit.readAtHead(
      _repository(vault).storage,
      locator,
    );
    return bytes;
  }

  @override
  Future<KdbxFile> decode(
    String locator,
    Uint8List stored,
    Credentials credentials, {
    String? outerKey,
  }) async => KdbxFormat().read(
    await _codec(_parse(locator), outerKey).decode(stored),
    credentials,
  );

  @override
  Future<Uint8List> encode(
    String locator,
    KdbxFile file, {
    String? outerKey,
  }) async => _codec(_parse(locator), outerKey).encode(await file.save());

  /// Commits [file] as the vault's new state through the unit [open] kept
  /// (part-stores, DP-81): one commit on the branch through the REST API,
  /// committed by this device; when the branch moved, the unit reads the
  /// new head, merges [file] three-way with it (its base the copy served,
  /// which is [base]) and tries again; the result goes into the offline
  /// cache. A branch rewritten without a compaction refuses the save
  /// (`denied`, `history_rewritten`: the app decides), and so does a branch
  /// that kept moving over every attempt (`denied`, `branch_moving`). A
  /// remote that cannot be reached or refuses the token throws that
  /// storage failure.
  @override
  Future<TomSecretsCommitted> commit(
    String locator,
    KdbxFile file, {
    required Uint8List base,
    required Credentials credentials,
    String? outerKey,
    Uint8List? stored,
  }) async {
    final unit = _units[locator];
    if (unit == null) throw StateError('$locator is not open');
    final mergesBefore = unit.merges.length;
    unit.replaceWorking(file, stored: stored);
    final List<TomSyncConflict> conflicts;
    try {
      conflicts = await unit.push();
    } on TomCasExhaustedException {
      throw TomSecretsSaveException(
        'denied',
        'the branch moved during every attempt; save again',
        reason: 'branch_moving',
      );
    } on TomCommitFailedException catch (e) {
      // The storage's own failure (unreachable, the token refused) is what
      // the caller tells apart.
      throw e.cause ?? e;
    }
    if (conflicts.any((c) => c is TomSecretsHistoryRewritten)) {
      throw TomSecretsSaveException(
        'denied',
        'the branch was rewritten without a compaction',
        reason: 'history_rewritten',
      );
    }
    return TomSecretsCommitted(
      opened: TomSecretsOpenedVault(
        locator: locator,
        file: unit.working,
        stored: unit.baseBytes,
        revision: unit.head,
        source: 'github',
        fetchedAt: unit.fetchedAt,
      ),
      merged: unit.merges.length > mergesBefore,
      conflicts: conflicts.whereType<TomSecretsVaultConflict>().length,
    );
  }

  /// Commits [stored], [file] re-keyed, through the unit [open] kept
  /// (`TomSecretsVaultUnit.rekey`): one commit on top of the head the
  /// service holds, never merged; a branch that moved since is refused
  /// (`denied`, `stale_base`). The unit reads and writes with the new keys
  /// from then on.
  @override
  Future<TomSecretsCommitted> rekey(
    String locator,
    KdbxFile file, {
    required Uint8List base,
    required Uint8List stored,
    String? outerKey,
    Map<String, Uint8List> beside = const {},
  }) async {
    final unit = _units[locator];
    if (unit == null) throw StateError('$locator is not open');
    if (beside.isNotEmpty) {
      // The re-keyed file and the files beside it in one commit: a shared
      // vault's removal (part-sharing). The unit is opened again on the new
      // head with the new keys.
      final vault = _parse(locator);
      await _commitTree(
        vault,
        writes: {
          vault.path: stored,
          for (final MapEntry(:key, :value) in beside.entries)
            _besidePath(vault, key): value,
        },
        expected: {vault.path: tomSecretsBlobId(base)},
        refusals: {
          vault.path: (
            'the branch moved since the copy that was re-keyed',
            'stale_base',
          ),
        },
        message: 'tsm: ${vault.fileName} re-keyed from $device',
        moving: 'the branch moved since the copy that was re-keyed',
        movingReason: 'stale_base',
      );
      await _units.remove(locator)?.dispose();
      return TomSecretsCommitted(
        opened: await open(locator, file.credentials, outerKey: outerKey),
      );
    }
    try {
      await unit.rekey(
        file,
        stored: stored,
        codec: _codec(_parse(locator), outerKey),
      );
    } on TomCasConflictException {
      throw TomSecretsSaveException(
        'denied',
        'the branch moved since the copy that was re-keyed',
        reason: 'stale_base',
      );
    } on TomCommitFailedException catch (e) {
      throw e.cause ?? e;
    }
    return TomSecretsCommitted(
      opened: TomSecretsOpenedVault(
        locator: locator,
        file: unit.working,
        stored: unit.baseBytes,
        revision: unit.head,
        source: 'github',
        fetchedAt: unit.fetchedAt,
      ),
    );
  }

  /// Moves the vault at [from] to [to] in one commit on the branch (part-
  /// stores, the outer encryption added or removed): the tree of the
  /// branch's head with [stored] at [to]'s path and [from]'s path removed,
  /// committed by this device and moved onto the branch without force, so a
  /// branch that moved meanwhile refuses it (`denied`, `branch_moving`).
  /// [from]'s file at the head must be [base] (`stale_base` otherwise) and
  /// [to]'s path free (`target_exists`). Then [to] is opened (its unit
  /// kept) and [from]'s unit dropped.
  @override
  Future<TomSecretsOpenedVault> move(
    String from,
    String to,
    KdbxFile file, {
    required Uint8List base,
    required Uint8List stored,
    required Credentials credentials,
    String? outerKey,
  }) async {
    final old = _parse(from);
    final target = _parse(to);
    if (old.repositorySlug != target.repositorySlug ||
        old.branch != target.branch) {
      throw ArgumentError.value(to, 'to', 'not in the repository of $from');
    }
    await _commitTree(
      old,
      writes: {target.path: stored},
      deletes: {old.path},
      expected: {old.path: tomSecretsBlobId(base), target.path: null},
      refusals: {
        old.path: (
          'the file has moved since the copy that is moved',
          'stale_base',
        ),
        target.path: ('a file is at ${target.path} already', 'target_exists'),
      },
      message: 'tsm: ${old.fileName} to ${target.fileName} from $device',
      moving: 'the branch moved meanwhile; move again',
    );
    await _units.remove(from)?.dispose();
    return open(to, credentials, outerKey: outerKey);
  }

  /// Creates the vault [file] at [locator] in one commit on the branch
  /// through `TomSecretsVaultUnit.create` (part-stores), committed by this
  /// device; a `.tsmx` file keeps the outer cipher of [stored]. A file at
  /// [locator] refuses it (`denied`, `target_exists`). The unit is kept for
  /// the saves, as [open] keeps it.
  @override
  Future<TomSecretsOpenedVault> create(
    String locator,
    KdbxFile file, {
    required Uint8List stored,
    required Credentials credentials,
    String? outerKey,
  }) async {
    final vault = _parse(locator);
    final repository = _repository(vault);
    final codec = outerKey == null
        ? _codec(vault, null)
        : tomSecretsOuterCodecFor(
                vault.fileName,
                outerKey,
                cipher: tomSecretsOuterCipherOf(stored),
              ) ??
              const TomSecretsPlainCodec();
    final TomSecretsVaultUnit unit;
    try {
      unit = await TomSecretsVaultUnit.create(
        locator: locator,
        storage: repository.storage,
        file: file,
        device: device,
        codec: codec,
        cache: cacheDirectory != null && _useCache()
            ? TomSecretsOfflineCache(Directory(cacheDirectory!))
            : null,
        history: await repository.history(vault.branch),
        clock: () => _clock().toUtc(),
      );
    } on TomCasConflictException {
      throw TomSecretsSaveException(
        'denied',
        'a file is at ${vault.path} already',
        reason: 'target_exists',
      );
    } on TomCommitFailedException catch (e) {
      throw e.cause ?? e;
    } on GitHubAuthException {
      throw const TomTokenRejectedException(
        'github',
        TomGitHubStorage.host,
        'GitHub refused the token',
      );
    }
    await _units.remove(locator)?.dispose();
    _units[locator] = unit;
    return TomSecretsOpenedVault(
      locator: locator,
      file: unit.working,
      stored: unit.baseBytes,
      revision: unit.head,
      source: 'github',
      fetchedAt: unit.fetchedAt,
    );
  }

  /// The path of the file [name] in the folder of [vault]'s file; a name
  /// with a path in it is refused.
  static String _besidePath(TomSecretsGitHubLocator vault, String name) {
    tomSecretsBesidePath(name);
    final slash = vault.path.lastIndexOf('/');
    return slash < 0 ? name : '${vault.path.substring(0, slash + 1)}$name';
  }

  /// Reads the file [name] beside [locator]'s file at the branch's head
  /// through the REST API.
  @override
  Future<({Uint8List bytes, String revision})?> readBeside(
    String locator,
    String name,
  ) async {
    final vault = _parse(locator);
    final path = _besidePath(vault, name);
    final (git, branch) = await _git(vault);
    try {
      final head = await git.getRef(
        owner: vault.owner,
        repo: vault.repository,
        ref: 'heads/$branch',
      );
      final commit = await git.getCommit(
        owner: vault.owner,
        repo: vault.repository,
        sha: head.sha,
      );
      final tree = await git.getTree(
        owner: vault.owner,
        repo: vault.repository,
        sha: commit.treeSha,
        recursive: true,
      );
      final sha = tree.entries.where((e) => e.path == path).firstOrNull?.sha;
      if (sha == null) return null;
      final bytes = await git.getBlob(
        owner: vault.owner,
        repo: vault.repository,
        sha: sha,
      );
      return (bytes: bytes, revision: sha);
    } on GitHubAuthException {
      throw const TomTokenRejectedException(
        'github',
        TomGitHubStorage.host,
        'GitHub refused the token',
      );
    }
  }

  /// Writes the file [name] beside [locator]'s file in one commit on the
  /// branch, through the REST API.
  @override
  Future<String> writeBeside(
    String locator,
    String name,
    Uint8List bytes, {
    required String? baseRevision,
  }) async {
    final vault = _parse(locator);
    final path = _besidePath(vault, name);
    await _commitTree(
      vault,
      writes: {path: bytes},
      expected: {path: baseRevision},
      refusals: {
        path: ('the file $name has moved since it was read', 'stale_base'),
      },
      message: 'tsm: $name from $device',
      moving: 'the branch moved meanwhile; write again',
    );
    return tomSecretsBlobId(bytes);
  }

  /// Lists the files below [folder] beside [locator]'s file at the branch's
  /// head (one recursive tree read through the REST API).
  @override
  Future<Map<String, String>> listBeside(String locator, String folder) async {
    final vault = _parse(locator);
    final prefix = '${_besidePath(vault, folder)}/';
    final base = _besidePath(vault, 'x');
    final dir = base.substring(0, base.length - 1);
    final tree = await _headTree(vault);
    return {
      for (final e in tree.entries)
        if (e.path.startsWith(prefix) && e.type == 'blob')
          e.path.substring(dir.length): e.sha,
    };
  }

  /// Deletes [paths] beside [locator]'s file in one commit, those still
  /// there at the head.
  @override
  Future<void> deleteBeside(String locator, List<String> paths) async {
    final vault = _parse(locator);
    final tree = await _headTree(vault);
    final present = <String, String>{
      for (final p in paths)
        if (tree.entries
                .where((e) => e.path == _besidePath(vault, p))
                .firstOrNull
            case final e?)
          e.path: e.sha,
    };
    if (present.isEmpty) return;
    await _commitTree(
      vault,
      writes: const {},
      deletes: present.keys.toSet(),
      expected: present,
      refusals: {
        for (final p in present.keys)
          p: ('the file $p has moved since it was read', 'stale_base'),
      },
      message: 'tsm: ${present.length} inbox file(s) removed from $device',
      moving: 'the branch moved meanwhile; delete again',
    );
  }

  /// The recursive tree of [vault]'s branch head.
  Future<GitHubTree> _headTree(TomSecretsGitHubLocator vault) async {
    final (git, branch) = await _git(vault);
    try {
      final head = await git.getRef(
        owner: vault.owner,
        repo: vault.repository,
        ref: 'heads/$branch',
      );
      final commit = await git.getCommit(
        owner: vault.owner,
        repo: vault.repository,
        sha: head.sha,
      );
      return await git.getTree(
        owner: vault.owner,
        repo: vault.repository,
        sha: commit.treeSha,
        recursive: true,
      );
    } on GitHubAuthException {
      throw const TomTokenRejectedException(
        'github',
        TomGitHubStorage.host,
        'GitHub refused the token',
      );
    }
  }

  /// The git API of [vault]'s repository with its token, and its branch.
  Future<(GitHubGitApi, String)> _git(TomSecretsGitHubLocator vault) async {
    final repository = _repository(vault);
    final token = await tokens(vault);
    if (token == null) {
      throw const TomTokenRequiredException(TomGitHubStorage.host);
    }
    final git = repository._client(token).git;
    return (git, vault.branch ?? await repository.defaultBranch());
  }

  /// One commit on [vault]'s branch, on top of its head, moved onto the
  /// branch without force: the head's tree with [writes] (path → bytes)
  /// and without [deletes]. Each path of [expected] must hold that blob at
  /// the head (null: no file), else the commit is refused as its
  /// [refusals] entry says (`denied`); a branch that moved meanwhile is
  /// refused with [moving] (`denied`, [movingReason]).
  Future<void> _commitTree(
    TomSecretsGitHubLocator vault, {
    required Map<String, Uint8List> writes,
    Set<String> deletes = const {},
    required Map<String, String?> expected,
    required Map<String, (String, String)> refusals,
    required String message,
    required String moving,
    String movingReason = 'branch_moving',
  }) async {
    final (git, branch) = await _git(vault);
    final owner = vault.owner;
    final repo = vault.repository;
    try {
      final head = await git.getRef(
        owner: owner,
        repo: repo,
        ref: 'heads/$branch',
      );
      final commit = await git.getCommit(
        owner: owner,
        repo: repo,
        sha: head.sha,
      );
      final tree = await git.getTree(
        owner: owner,
        repo: repo,
        sha: commit.treeSha,
        recursive: true,
      );
      String? blobAt(String path) =>
          tree.entries.where((e) => e.path == path).firstOrNull?.sha;
      for (final MapEntry(key: path, value: blob) in expected.entries) {
        if (blobAt(path) != blob) {
          final (text, reason) = refusals[path]!;
          throw TomSecretsSaveException('denied', text, reason: reason);
        }
      }
      final entries = <GitHubTreeEntry>[
        for (final MapEntry(key: path, value: bytes) in writes.entries)
          GitHubTreeEntry(
            path: path,
            sha: await git.createBlob(owner: owner, repo: repo, bytes: bytes),
          ),
        for (final path in deletes) GitHubTreeEntry.deletion(path),
      ];
      final next = await git.createTree(
        owner: owner,
        repo: repo,
        baseTreeSha: commit.treeSha,
        entries: entries,
      );
      final identity = tomSecretsDeviceCommitter(device);
      final made = await git.createCommit(
        owner: owner,
        repo: repo,
        message: message,
        treeSha: next.sha,
        parentShas: [head.sha],
        author: identity,
        committer: identity,
      );
      try {
        await git.updateRef(
          owner: owner,
          repo: repo,
          ref: 'heads/$branch',
          sha: made.sha,
        );
      } on GitHubException catch (e) {
        if (e.statusCode == 422 || e.statusCode == 409) {
          throw TomSecretsSaveException('denied', moving, reason: movingReason);
        }
        rethrow;
      }
    } on GitHubAuthException {
      throw const TomTokenRejectedException(
        'github',
        TomGitHubStorage.host,
        'GitHub refused the token',
      );
    }
  }

  @override
  String? rewrittenHeadOf(String locator) => _units[locator]?.rewrittenHead;

  /// Answers the rewritten branch of [locator] through its unit:
  /// [TomSecretsVaultUnit.takeRemote] or
  /// [TomSecretsVaultUnit.mergeOverRemote] (which commits the merge on top of
  /// the remote's head).
  @override
  Future<TomSecretsCommitted> resolveRewritten(
    String locator, {
    required bool takeRemote,
  }) async {
    final unit = _units[locator];
    if (unit == null || unit.rewrittenHead == null) {
      throw StateError('no rewritten branch of $locator waits for an answer');
    }
    var conflicts = 0;
    if (takeRemote) {
      await unit.takeRemote();
    } else {
      final List<TomSyncConflict> found;
      try {
        found = await unit.mergeOverRemote();
      } on TomCasExhaustedException {
        throw TomSecretsSaveException(
          'denied',
          'the branch moved during every attempt; answer again',
          reason: 'branch_moving',
        );
      } on TomCommitFailedException catch (e) {
        throw e.cause ?? e;
      }
      if (found.any((c) => c is TomSecretsHistoryRewritten)) {
        throw TomSecretsSaveException(
          'denied',
          'the branch was rewritten again',
          reason: 'history_rewritten',
        );
      }
      conflicts = found.whereType<TomSecretsVaultConflict>().length;
    }
    return TomSecretsCommitted(
      opened: TomSecretsOpenedVault(
        locator: locator,
        file: unit.working,
        stored: unit.baseBytes,
        revision: unit.head,
        source: 'github',
        fetchedAt: unit.fetchedAt,
      ),
      merged: !takeRemote,
      conflicts: conflicts,
    );
  }

  /// The repositories (`owner/repository`) of the vaults open.
  Set<String> get repositories => {
    for (final locator in _units.keys) _parse(locator).repositorySlug,
  };

  /// Compacts the history of [repositorySlug] (`owner/repository`) on
  /// request (part-stores, `tsm compact`): the cut `tomSecretsCompact` makes,
  /// keeping the repository's own retention (its `.tsm/compaction.yaml`,
  /// else the defaults), pushed over git by this device; then the open
  /// units of that repository follow the new head. [retentionDays] replaces
  /// the repository's retention (0 after a key change, part-key-rotation:
  /// no commit keeps a file under the old keys). Throws [StateError] when
  /// no open vault is in [repositorySlug], the storage's failure when GitHub
  /// cannot be reached or refuses the token, and
  /// [TomSecretsCompactionException] when the cut is refused.
  Future<TomSecretsCompactionResult> compact(
    String repositorySlug, {
    int? retentionDays,
  }) async {
    final locators = [
      for (final locator in _units.keys)
        if (_parse(locator).repositorySlug == repositorySlug) locator,
    ];
    if (locators.isEmpty) {
      throw StateError('no open vault in $repositorySlug');
    }
    final vault = _parse(locators.first);
    final repository = _repository(vault);
    final branch = vault.branch ?? await repository.defaultBranch();
    final settings = tomSecretsCompactionSettingsOf(
      await repository.readText(branch, tomSecretsCompactionConfigPath),
    );
    final reader =
        _readerFor?.call(vault) ??
        (await repository.history(branch)) ??
        (throw const TomTokenRequiredException(TomGitHubStorage.host));
    final remote =
        (_remoteFor ??
        (v, token) => tomSecretsGitHubRemote(
          v,
          token: token,
          client: _httpClient,
        ))(vault, () => tokens(vault));
    final result = await tomSecretsCompact(
      remote: remote,
      reader: reader,
      branch: branch,
      device: device,
      retentionDays: retentionDays ?? settings.retentionDays,
      now: _clock(),
    );
    for (final locator in locators) {
      await _units[locator]?.followCompaction(result);
    }
    return result;
  }

  /// Drops the units it keeps (their open files) and their working copies.
  @override
  void drop() {
    for (final unit in _units.values) {
      unawaited(unit.dispose());
    }
    _units.clear();
  }

  /// Closes the connections.
  void close() {
    drop();
    for (final r in _repositories.values) {
      r.storage.close();
    }
    _repositories.clear();
  }
}

/// One repository: its storage (one per repository, so each asks for its own
/// token) and its commit reader.
final class _Repository {
  _Repository(this.opener, this.vault) {
    storage = TomGitHubStorage(
      tokens: _RepositoryTokens(this),
      clientFactory: _client,
      committer: tomSecretsDeviceCommitter(opener.device),
      diagnostics: watch,
    );
  }

  final TomSecretsGitHubOpener opener;
  final TomSecretsGitHubLocator vault;
  late final TomGitHubStorage storage;
  final _OfflineWatch watch = _OfflineWatch();

  GitHubApiClient _client(String token) => GitHubApiClient(
    token: token,
    httpClient: _ExpiryRecorder(
      opener._httpClient,
      (expiry) => expiry == null
          ? opener._tokenExpiries.remove(vault.repositorySlug)
          : opener._tokenExpiries[vault.repositorySlug] = expiry,
    ),
    baseUrl: opener.baseUrl,
  );

  /// The commit reader of [branch], when a token is there; without one the
  /// unit merges a moved head as usual (the service never pushes).
  /// The repository's default branch.
  Future<String> defaultBranch() async {
    final token = await opener.tokens(vault);
    if (token == null) {
      throw const TomTokenRequiredException(TomGitHubStorage.host);
    }
    return _client(
      token,
    ).getDefaultBranch(owner: vault.owner, repo: vault.repository);
  }

  /// The text of [path] on [branch], or null when there is none.
  Future<String?> readText(String branch, String path) async {
    try {
      return utf8.decode(
        await storage.readBytes(
          'github:${vault.owner}/${vault.repository}@$branch/$path',
        ),
      );
    } on TomContainerNotFoundException {
      return null;
    }
  }

  Future<TomSecretsCommitReader?> history(String? branch) async {
    final token = await opener.tokens(vault);
    if (token == null) return null;
    return TomSecretsGitHubCommitReader(
      _client(token),
      vault.owner,
      vault.repository,
      branch: branch,
    );
  }
}

/// Notices the storage serving the tree it holds because GitHub did not
/// answer (`TomGitHubStorage` does that silently, for its editors).
final class _OfflineWatch implements TomDiagnostics {
  bool servedOffline = false;

  @override
  void log(TomDiagnosticEvent event) {
    if (event.operation == 'github.snapshot.served-offline') {
      servedOffline = true;
    }
  }
}

final class _RepositoryTokens extends TomTokenSource {
  _RepositoryTokens(this.repository);

  final _Repository repository;

  @override
  Future<TomToken?> tokenFor(String host) async {
    final secret = await repository.opener.tokens(repository.vault);
    return secret == null ? null : TomToken(host: host, secret: secret);
  }
}

/// Passes requests to [inner] and records the token expiry GitHub reports:
/// an answer that took the token without the header means a token without
/// an expiry.
final class _ExpiryRecorder extends http.BaseClient {
  _ExpiryRecorder(http.Client? inner, this.onExpiry)
    : _inner = inner ?? http.Client(),
      _owned = inner == null;

  final http.Client _inner;
  final bool _owned;
  final void Function(DateTime? expiry) onExpiry;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await _inner.send(request);
    final header = response.headers[tomSecretsTokenExpirationHeader];
    final expiry = header == null
        ? null
        : tomSecretsParseTokenExpiration(header);
    if (expiry != null || response.statusCode ~/ 100 == 2) onExpiry(expiry);
    return response;
  }

  @override
  void close() {
    if (_owned) _inner.close();
  }
}
