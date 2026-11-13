// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The GitHub cycle (part-stores, DP-81): a vault as one `tom_core_sync` sync
/// unit over a `tom_core_storage` backend (`TomGitHubStorage` for `github:`,
/// no clone). Open reads the head and the file; save commits on top of the
/// base and moves the branch without force; a refused move reads the new
/// head, merges three-way and commits again, up to [maxPushAttempts].
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_core_sync/tom_core_sync.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'locator.dart';
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
    required KdbxFile working,
    required Uint8List baseBytes,
  }) : _working = working,
       _baseBytes = baseBytes;

  /// Opens the vault at [locator] on [storage] with [credentials]: reads the
  /// head and the file at it; the head and the file as read are the base.
  /// [device] names this device in commit messages.
  static Future<TomSecretsVaultUnit> open({
    required String locator,
    required TomStorage storage,
    required Credentials credentials,
    required String device,
    TomSecretsVaultCodec codec = const TomSecretsPlainCodec(),
    int maxPushAttempts = 3,
  }) async {
    final (stored, head) = await readAtHead(storage, locator);
    final file = await KdbxFormat().read(
      await codec.decode(stored),
      credentials,
    );
    return TomSecretsVaultUnit._(
      locator: locator,
      storage: storage,
      credentials: credentials,
      device: device,
      codec: codec,
      maxPushAttempts: maxPushAttempts,
      head: head,
      working: file,
      baseBytes: stored,
    );
  }

  /// Creates the vault [file] at [locator] (which must not exist yet) and
  /// opens it.
  static Future<TomSecretsVaultUnit> create({
    required String locator,
    required TomStorage storage,
    required KdbxFile file,
    required String device,
    TomSecretsVaultCodec codec = const TomSecretsPlainCodec(),
    int maxPushAttempts = 3,
  }) async {
    file.body.meta.customData[tomSecretsFormatKey] = tomSecretsFormatVersion;
    final stored = await codec.encode(await file.save());
    final head = await storage.commit(
      locator,
      TomChangeset.singleFile(stored),
      message: commitMessageFor(_fileName(locator), device),
    );
    return TomSecretsVaultUnit._(
      locator: locator,
      storage: storage,
      credentials: file.credentials,
      device: device,
      codec: codec,
      maxPushAttempts: maxPushAttempts,
      head: head,
      working: await KdbxFormat().read(
        await codec.decode(stored),
        file.credentials,
      ),
      baseBytes: stored,
    );
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
    _dirty = true;
    _edits.add(null);
  }

  Future<KdbxFile> _read(Uint8List stored) async =>
      KdbxFormat().read(await codec.decode(stored), credentials);

  @override
  Future<List<TomSyncConflict>> pull(String remoteHead) async {
    final (stored, head) = await readAtHead(storage, locator);
    return _mergeIn(stored, head);
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
    _merges.add(result);
    _baseBytes = stored;
    this.head = head;
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
      final stored = await codec.encode(await _working.save());
      try {
        head = await storage.commit(
          locator,
          TomChangeset.singleFile(stored),
          expectedHead: head,
          message: commitMessage,
        );
        _baseBytes = stored;
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
    _dirty = false;
  }

  @override
  Future<void> dispose() async => _edits.close();
}
