// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The GitHub cycle (part-stores, DP-81): a vault as one `tom_core_sync` sync
/// unit over a `tom_core_storage` backend (`TomGitHubStorage` for `github:`,
/// no clone). Open reads the head and the file; save commits on top of the
/// base and moves the branch without force; a refused move reads the new
/// head, merges three-way and commits again, up to [maxPushAttempts].
///
/// With an offline cache (desktop and service, part-key-rotation) every file
/// read or written is kept, and a vault whose remote cannot be reached, or
/// refuses the token, opens from it. With a commit reader the cycle tells a
/// compacted history (followed silently) from a rewritten one (the user
/// chooses: [TomSecretsVaultUnit.takeRemote] or
/// [TomSecretsVaultUnit.mergeOverRemote]).
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:tom_core_storage/github.dart' show GitHubGitIdentity;
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_core_sync/tom_core_sync.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'compaction.dart' show TomSecretsCompactionResult;
import 'history.dart';
import 'locator.dart';
import 'offline_cache.dart';
import 'vault_merge.dart';

/// Turns a vault file's stored bytes into KDBX bytes and back: the outer
/// encryption layer (part-stores, BP-18) plugs in here; the identity when a
/// repository has none.
abstract interface class TomSecretsVaultCodec {
  /// The KDBX bytes of the stored [bytes].
  Future<Uint8List> decode(Uint8List bytes);

  /// The stored bytes of the KDBX [bytes].
  Future<Uint8List> encode(Uint8List bytes);
}

/// The committer and author of the cycle's commits for [device]: the device
/// name with a placeholder address (part-stores), `<device>@tsm.invalid`
/// (`.invalid` never resolves, RFC 2606). The composition root passes it as
/// `TomGitHubStorage(committer: ...)`.
GitHubGitIdentity tomSecretsDeviceCommitter(String device) =>
    GitHubGitIdentity(name: device, email: '$device@tsm.invalid');

/// No outer layer.
final class TomSecretsPlainCodec implements TomSecretsVaultCodec {
  /// The identity.
  const TomSecretsPlainCodec();
  @override
  Future<Uint8List> decode(Uint8List bytes) async => bytes;
  @override
  Future<Uint8List> encode(Uint8List bytes) async => bytes;
}

/// The merge conflicts of one entry, as the sync engine queues them.
final class TomSecretsVaultConflict implements TomSyncConflict {
  /// A conflict of [conflict]'s entry in the vault at [locator].
  const TomSecretsVaultConflict(this.locator, this.conflict);

  /// The vault.
  final String locator;

  /// The entry's conflict record.
  final TomSecretsEntryConflict conflict;

  @override
  String get anchor => '$locator#${conflict.entryUuid}';

  @override
  String toString() => 'TomSecretsVaultConflict($anchor ${conflict.fields})';
}

/// Where an open vault's file came from.
enum TomSecretsVaultSource {
  /// Read from (or written to) the remote.
  remote,

  /// The offline cache: the remote could not be reached or refused the
  /// token.
  cache,
}

/// The remote's history was rewritten without a compaction (a force push):
/// nothing was merged; the user chooses [TomSecretsVaultUnit.takeRemote] or
/// [TomSecretsVaultUnit.mergeOverRemote].
final class TomSecretsHistoryRewritten implements TomSyncConflict {
  /// The vault at [locator], its branch rewritten to the commit
  /// [remoteHead], for [reason].
  const TomSecretsHistoryRewritten(this.locator, this.remoteHead, this.reason);

  /// The vault.
  final String locator;

  /// The rewritten branch's head commit.
  final String remoteHead;

  /// Why the move counts as rewritten.
  final String reason;

  @override
  String get anchor => '$locator@$remoteHead';

  @override
  String toString() => 'TomSecretsHistoryRewritten($anchor: $reason)';
}

/// One vault kept converged with its remote.
final class TomSecretsVaultUnit implements TomSyncUnit {
  TomSecretsVaultUnit._({
    required this.locator,
    required this.storage,
    required this.credentials,
    required this.device,
    required this.codec,
    required this.maxPushAttempts,
    required this.head,
    required this.cache,
    required this.history,
    required DateTime Function() clock,
    required KdbxFile working,
    required Uint8List baseBytes,
  }) : _clock = clock,
       _working = working,
       _baseBytes = baseBytes;

  /// Whether [error] is a failure the offline cache may stand in for: no
  /// answer, or the token refused or missing (GitHub's 401 and 403 for the
  /// token).
  static bool isOfflineFailure(Object error) =>
      error is TomUnreachableException ||
      error is TomTokenRejectedException ||
      error is TomTokenRequiredException;

  /// Opens the vault at [locator] on [storage] with [credentials]: reads the
  /// head and the file at it; the head and the file as read are the base.
  /// [device] names this device in commit messages.
  ///
  /// With [cache] the file is kept there, and when the remote cannot be
  /// reached or refuses the token ([isOfflineFailure]) the vault opens from
  /// the cached file and head instead ([source] `cache`, [offlineReason]);
  /// without a cached file the failure stands. [history] reads the remote's
  /// commits for telling a compaction from a force push.
  static Future<TomSecretsVaultUnit> open({
    required String locator,
    required TomStorage storage,
    required Credentials credentials,
    required String device,
    TomSecretsVaultCodec codec = const TomSecretsPlainCodec(),
    int maxPushAttempts = 3,
    TomSecretsOfflineCache? cache,
    TomSecretsCommitReader? history,
    DateTime Function() clock = _now,
  }) async {
    Uint8List stored;
    String head;
    Object? offline;
    TomSecretsCachedVault? cached;
    try {
      (stored, head) = await readAtHead(storage, locator);
    } on Object catch (error) {
      cached = cache != null && isOfflineFailure(error)
          ? await cache.get(locator)
          : null;
      if (cached == null) rethrow;
      offline = error;
      (stored, head) = (cached.bytes, cached.head);
    }
    final file = await KdbxFormat().read(
      await codec.decode(stored),
      credentials,
    );
    final unit = TomSecretsVaultUnit._(
      locator: locator,
      storage: storage,
      credentials: credentials,
      device: device,
      codec: codec,
      maxPushAttempts: maxPushAttempts,
      head: head,
      cache: cache,
      history: history,
      clock: clock,
      working: file,
      baseBytes: stored,
    );
    if (cached != null) {
      unit
        .._source = TomSecretsVaultSource.cache
        .._fetchedAt = cached.fetchedAt
        .._offlineReason = offline;
    } else {
      await unit._retrieved(stored, head);
    }
    return unit;
  }

  static DateTime _now() => DateTime.now();

  /// Creates the vault [file] at [locator] (which must not exist yet) and
  /// opens it. [file] is a new vault from `tomSecretsNewVault`; a file whose
  /// key is not derived through Argon2id is refused with [ArgumentError].
  static Future<TomSecretsVaultUnit> create({
    required String locator,
    required TomStorage storage,
    required KdbxFile file,
    required String device,
    TomSecretsVaultCodec codec = const TomSecretsPlainCodec(),
    int maxPushAttempts = 3,
    TomSecretsOfflineCache? cache,
    TomSecretsCommitReader? history,
    DateTime Function() clock = _now,
  }) async {
    if (file.argon2?.type != KdbxArgon2Type.argon2id) {
      throw ArgumentError.value(
        file.argon2,
        'file',
        'a new vault is keyed by Argon2id (tomSecretsNewVault)',
      );
    }
    file.body.meta.customData[tomSecretsFormatKey] = tomSecretsFormatVersion;
    final stored = await codec.encode(await file.save());
    final head = await storage.commit(
      locator,
      TomChangeset.singleFile(stored),
      message: commitMessageFor(_fileName(locator), device),
    );
    final unit = TomSecretsVaultUnit._(
      locator: locator,
      storage: storage,
      credentials: file.credentials,
      device: device,
      codec: codec,
      maxPushAttempts: maxPushAttempts,
      head: head,
      cache: cache,
      history: history,
      clock: clock,
      working: await KdbxFormat().read(
        await codec.decode(stored),
        file.credentials,
      ),
      baseBytes: stored,
    );
    await unit._retrieved(stored, head);
    return unit;
  }

  /// The commit message of a save: the vault and the device, never an entry
  /// title or a value.
  static String commitMessageFor(String fileName, String device) =>
      'tsm: $fileName from $device';

  @override
  final String locator;

  @override
  final TomStorage storage;

  /// The vault's credentials.
  final Credentials credentials;

  /// This device's name.
  final String device;

  /// The outer layer.
  final TomSecretsVaultCodec codec;

  /// How many commits a save attempts before its work waits in the journal.
  final int maxPushAttempts;

  @override
  String? head;

  /// The offline cache, or null (mobile, or a vault never stored on this
  /// device): the base then lives in memory only while the vault is open.
  final TomSecretsOfflineCache? cache;

  /// Reads the remote branch's commits, or null: without it a moved head is
  /// merged as usual, compaction or not. Used for `github:` vaults, whose
  /// path in the repository the locator names.
  final TomSecretsCommitReader? history;

  final DateTime Function() _clock;
  TomSecretsVaultSource _source = TomSecretsVaultSource.remote;
  DateTime? _fetchedAt;
  Object? _offlineReason;
  String? _rewrittenHead;
  TomSecretsBranchMove? _lastMove;

  /// Where the open file came from: the remote, or the offline cache.
  TomSecretsVaultSource get source => _source;

  /// When the base was last retrieved from (or written to) the remote.
  DateTime? get fetchedAt => _fetchedAt;

  /// Why the vault opened from the cache (the remote's failure), or null.
  Object? get offlineReason => _offlineReason;

  /// The head commit of a rewritten remote history awaiting the user's
  /// choice ([takeRemote] or [mergeOverRemote]), or null.
  String? get rewrittenHead => _rewrittenHead;

  /// How the remote moved the last time a new head was merged in, or null
  /// (no commit reader, or no move yet).
  TomSecretsBranchMove? get lastMove => _lastMove;

  KdbxFile _working;
  Uint8List _baseBytes;
  bool _dirty = false;
  final StreamController<void> _edits = StreamController<void>.broadcast(
    sync: true,
  );
  final List<TomSecretsMergeResult> _merges = [];

  /// The open copy the app edits; after an edit call [markEdited].
  KdbxFile get working => _working;

  /// The file as last read or written (the merge's base), as stored.
  Uint8List get baseBytes => _baseBytes;

  /// What every merge of this unit reported, oldest first.
  List<TomSecretsMergeResult> get merges => List.unmodifiable(_merges);

  /// The commit message of this vault's saves.
  String get commitMessage => commitMessageFor(_fileName(locator), device);

  /// The file name of [locator]: the vault locator's, else the last segment
  /// (a storage scheme the vault locators do not name, as in tests).
  static String _fileName(String locator) {
    try {
      return TomSecretsVaultLocator.parse(locator).fileName;
    } on TomSecretsLocatorException {
      return locator.split(RegExp(r'[/:]')).last;
    }
  }

  @override
  Stream<void> get edits => _edits.stream;

  @override
  bool get hasLocalChanges => _dirty;

  /// Records that the working copy changed, so the engine pushes it.
  void markEdited() {
    _replacedStored = null;
    _dirty = true;
    _edits.add(null);
  }

  /// Makes [file] the working copy (a whole edited file, e.g. the one the
  /// app saved through the service) and marks it edited: the next [push]
  /// commits it over the base, merging with the remote when it moved. With
  /// [stored] (the file as the store keeps it, as it was saved) a push that
  /// needs no merge commits those bytes as they are.
  void replaceWorking(KdbxFile file, {Uint8List? stored}) {
    _working = file;
    markEdited();
    _replacedStored = stored;
  }

  /// The bytes [replaceWorking] was given, until a merge or an edit changes
  /// the working copy.
  Uint8List? _replacedStored;

  Future<KdbxFile> _read(Uint8List stored) async =>
      KdbxFormat().read(await codec.decode(stored), credentials);

  @override
  Future<List<TomSyncConflict>> pull(String remoteHead) async {
    final (stored, head) = await readAtHead(storage, locator);
    if (head != this.head) {
      final rewritten = await _checkMove();
      if (rewritten != null) return [rewritten];
    }
    return _mergeIn(stored, head);
  }

  /// Records the retrieved [stored] file at [head] as the base's source:
  /// in the cache, and as the vault's state.
  Future<void> _retrieved(Uint8List stored, String head) async {
    final at = _clock().toUtc();
    _source = TomSecretsVaultSource.remote;
    _fetchedAt = at;
    _offlineReason = null;
    await cache?.put(
      TomSecretsCachedVault(
        locator: locator,
        bytes: stored,
        head: head,
        fetchedAt: at,
      ),
    );
  }

  /// The vault's path in its repository, which the commit reader looks the
  /// base's file up at: a `github:` locator's path, or null.
  String? get _historyPath {
    try {
      final parsed = TomSecretsVaultLocator.parse(locator);
      return parsed is TomSecretsGitHubLocator ? parsed.path : null;
    } on TomSecretsLocatorException {
      return null;
    }
  }

  /// How the remote branch moved from the base; a rewritten history is
  /// remembered and answered as a conflict.
  Future<TomSecretsHistoryRewritten?> _checkMove() async {
    final reader = history;
    final path = _historyPath;
    if (reader == null || path == null) return null;
    final remoteHead = await reader.branchHead();
    if (remoteHead == null) return null;
    final move = await tomSecretsClassifyMove(
      reader,
      path: path,
      baseBlob: tomSecretsBlobId(_baseBytes),
      head: remoteHead,
    );
    _lastMove = move;
    if (move is! TomSecretsBranchRewritten) {
      _rewrittenHead = null;
      return null;
    }
    _rewrittenHead = remoteHead;
    return TomSecretsHistoryRewritten(locator, remoteHead, move.reason);
  }

  /// The file at [locator] with the head it was read at: the head is read
  /// before and after the file, and again until both agree, so a branch that
  /// moved in between never pairs one head with another head's file.
  static Future<(Uint8List, String)> readAtHead(
    TomStorage storage,
    String locator, {
    int attempts = 5,
  }) async {
    for (var i = 0; i < attempts; i++) {
      final before = await storage.headOf(locator);
      if (before == null) throw TomContainerNotFoundException(locator);
      final bytes = await storage.readBytes(locator);
      final after = await storage.headOf(locator);
      if (after == before) return (bytes, before);
    }
    throw TomUnreachableException(
      locator,
      'the branch moved during every one of $attempts reads',
    );
  }

  Future<List<TomSyncConflict>> _mergeIn(Uint8List stored, String head) async {
    final theirs = await _read(stored);
    final base = await _read(_baseBytes);
    final result = tomSecretsMergeVaults(
      base: base,
      ours: _working,
      theirs: theirs,
      location: locator,
    );
    // The working copy is the merge now, not the bytes it was given.
    _replacedStored = null;
    _merges.add(result);
    _baseBytes = stored;
    this.head = head;
    await _retrieved(stored, head);
    return [
      for (final c in result.conflicts) TomSecretsVaultConflict(locator, c),
    ];
  }

  @override
  Future<List<TomSyncConflict>> push() async {
    final conflicts = <TomSyncConflict>[];
    _dirty = false;
    for (var attempt = 1; attempt <= maxPushAttempts; attempt++) {
      _working.body.meta.customData[tomSecretsFormatKey] ??=
          tomSecretsFormatVersion;
      final stored =
          _replacedStored ?? await codec.encode(await _working.save());
      try {
        head = await storage.commit(
          locator,
          TomChangeset.singleFile(stored),
          expectedHead: head,
          message: commitMessage,
        );
        _baseBytes = stored;
        _replacedStored = null;
        await _retrieved(stored, head!);
        return conflicts;
      } on TomCasConflictException catch (e) {
        if (attempt == maxPushAttempts) {
          _dirty = true;
          throw TomCasExhaustedException(
            locator,
            conflicts: conflicts,
            attempts: attempt,
          );
        }
        final (remote, remoteHead) = await readAtHead(storage, locator);
        if (remoteHead == e.expectedHead) continue;
        final rewritten = await _checkMove();
        if (rewritten != null) {
          _dirty = true;
          return [...conflicts, rewritten];
        }
        conflicts.addAll(await _mergeIn(remote, remoteHead));
      } on TomStorageException catch (cause) {
        _dirty = true;
        throw TomCommitFailedException(
          locator,
          changeset: TomChangeset.singleFile(stored),
          baseHead: head,
          version: 0,
          commitMessage: commitMessage,
          cause: cause,
        );
      }
    }
    return conflicts;
  }

  /// Takes the remote as it is, dropping local work: the answer to a
  /// force-pushed branch the user chose to follow.
  Future<void> takeRemote() async {
    final (stored, remoteHead) = await readAtHead(storage, locator);
    head = remoteHead;
    _working = await _read(stored);
    _baseBytes = stored;
    _replacedStored = null;
    _dirty = false;
    _rewrittenHead = null;
    await _retrieved(stored, remoteHead);
  }

  /// Pushes the local copy over a rewritten remote: merges it three-way
  /// against an empty base with the remote's file (nothing is taken as
  /// deleted), then commits on top of the remote's head. The other answer to
  /// a force-pushed branch.
  Future<List<TomSyncConflict>> mergeOverRemote() async {
    final (stored, remoteHead) = await readAtHead(storage, locator);
    final result = tomSecretsMergeVaults(
      base: null,
      ours: _working,
      theirs: await _read(stored),
      location: locator,
    );
    // The working copy is the merge now, not the bytes it was given.
    _replacedStored = null;
    _merges.add(result);
    _baseBytes = stored;
    head = remoteHead;
    _rewrittenHead = null;
    await _retrieved(stored, remoteHead);
    _dirty = true;
    return [
      for (final c in result.conflicts) TomSecretsVaultConflict(locator, c),
      ...await push(),
    ];
  }

  /// Follows a compaction this device made ([result] of `tomSecretsCompact`)
  /// without a read: the base's head moves to the rewritten head, whose file
  /// is the same.
  Future<void> followCompaction(TomSecretsCompactionResult result) async {
    if (!result.compacted || head != result.oldHead) return;
    head = result.newHead;
    await _retrieved(_baseBytes, result.newHead);
  }

  @override
  Future<void> dispose() async => _edits.close();
}
