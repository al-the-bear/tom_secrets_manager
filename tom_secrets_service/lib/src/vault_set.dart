// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The vaults the service serves while unlocked (part-service, Unlock and
/// lock): the primary file, the further vaults whose keys it holds (BP-8),
/// the index the resolver reads, and each store's state. Locking drops all
/// of it.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:tom_core_storage/tom_core_storage.dart'
    show
        TomKeyRequiredException,
        TomRateLimitException,
        TomStorageException,
        TomTokenRejectedException,
        TomTokenRequiredException;
import 'package:tom_crypto/protected_value.dart';
import 'package:tom_secrets_client/admin.dart' show TomSecretsUnlockBundle;
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'secret_frame.dart';

/// A store's state (protocol.md 6.3).
enum TomSecretsStoreState {
  /// Opened and current.
  current('current'),

  /// Served from the offline cache: the remote could not be reached.
  offline('offline'),

  /// Served from the offline cache: the token was refused or has expired.
  tokenExpired('token_expired'),

  /// Its key changed or is not held: `unlockStore` opens it.
  needsUnlock('needs_unlock'),

  /// Could not be opened and has no copy to serve.
  unavailable('unavailable');

  const TomSecretsStoreState(this.wireName);

  /// The protocol's name.
  final String wireName;

  /// The state of a store served from its offline copy because of [reason]:
  /// `token_expired` when GitHub refused the token or none is there, else
  /// `offline`.
  static TomSecretsStoreState offlineFor(Object reason) =>
      reason is TomSecretsKeyChangedException
      ? needsUnlock
      : reason is TomTokenRejectedException ||
            reason is TomTokenRequiredException
      ? tokenExpired
      : offline;
}

/// **[C]** Why a store is served from a copy under its old key (part-key-
/// rotation, the migration period): the current file no longer opens with
/// the keys this device holds — another device re-keyed it. The copy is
/// served read-only (`needs_unlock`, `source` `cache`, `keyChanged`) until
/// the new key is listed in the primary; a save is refused meanwhile.
final class TomSecretsKeyChangedException implements Exception {
  /// The key of [locator] changed.
  const TomSecretsKeyChangedException(this.locator);

  /// The store's locator.
  final String locator;

  @override
  String toString() =>
      'TomSecretsKeyChangedException: the key of $locator changed';
}

/// Whether [error] is a failure to reach the remote, or a refusal of the
/// token, that a held or cached copy stands in for (and the refresh backs
/// off from).
bool tomSecretsIsFetchFailure(Object error) =>
    TomSecretsVaultUnit.isOfflineFailure(error) ||
    error is TomRateLimitException;

/// The failure behind [error] a held or cached copy stands in for, or null:
/// [error] itself, or the cause a storage failure wraps.
Object? tomSecretsFetchFailureOf(Object error) {
  if (tomSecretsIsFetchFailure(error)) return error;
  final cause = error is TomStorageException ? error.cause : null;
  return cause != null && tomSecretsIsFetchFailure(cause) ? cause : null;
}

/// A vault file as opened.
final class TomSecretsOpenedVault {
  /// [file] read from [locator] at [revision], from [source] (`file`,
  /// `github`, `cache`) fetched at [fetchedAt]; [offlineReason] is why it
  /// came from the offline cache.
  TomSecretsOpenedVault({
    required this.locator,
    required this.file,
    required this.stored,
    this.revision,
    this.source = 'file',
    this.fetchedAt,
    this.offlineReason,
  });

  /// Where it is.
  final String locator;

  /// The open file.
  final KdbxFile file;

  /// The file as stored (to check a password against without the remote).
  final Uint8List stored;

  /// The revision it was read at, when known.
  final String? revision;

  /// Where it came from.
  final String source;

  /// When it was fetched.
  final DateTime? fetchedAt;

  /// Why it was opened from the offline cache (the remote's failure), or
  /// null when it came from the remote or the disk.
  final Object? offlineReason;

  /// The state of a store holding this file.
  TomSecretsStoreState get state => offlineReason == null
      ? TomSecretsStoreState.current
      : TomSecretsStoreState.offlineFor(offlineReason!);
}

/// Reads, decodes, encodes and writes vault files by locator.
abstract interface class TomSecretsVaultOpener {
  /// Opens [locator] with [credentials]; [outerKey] (base64) opens a `.tsmx`
  /// file. Throws [KdbxInvalidKeyException] for wrong credentials.
  Future<TomSecretsOpenedVault> open(
    String locator,
    Credentials credentials, {
    String? outerKey,
  });

  /// The file at [locator] as stored now.
  Future<Uint8List> read(String locator);

  /// The revision of the file at [locator] now, without opening it: the
  /// remote's head, or the git blob id of a file on the disk. The refresh
  /// reopens a file only when it moved.
  Future<String> revision(String locator);

  /// [stored] (as [locator] keeps it: a `.tsmx` file outer-encrypted under
  /// [outerKey]) opened with [credentials].
  Future<KdbxFile> decode(
    String locator,
    Uint8List stored,
    Credentials credentials, {
    String? outerKey,
  });

  /// [file] as [locator] keeps it.
  Future<Uint8List> encode(String locator, KdbxFile file, {String? outerKey});

  /// Writes [file] to [locator] over [base] (the file as the service holds
  /// it, as stored): when the file there has moved since, [file] is merged
  /// three-way with it first, [base] the merge base (part-stores). Answers
  /// the store as written; [file] is its open file from then on. Throws the
  /// storage's failure when the remote cannot be reached or refuses the
  /// token, and [TomSecretsSaveException] when the write is refused. With
  /// [stored] ([file] as the store keeps it, as it was saved) a write that
  /// needs no merge writes those bytes as they are.
  Future<TomSecretsCommitted> commit(
    String locator,
    KdbxFile file, {
    required Uint8List base,
    required Credentials credentials,
    String? outerKey,
    Uint8List? stored,
  });

  /// Writes [stored], [file] re-keyed (part-key-rotation: as the store
  /// keeps it under new keys, [outerKey] the new repository key of a `.tsmx`
  /// file), to [locator] as it is, over [base] (the file as the service
  /// holds it). A re-keyed file is never merged: when the file there has
  /// moved since [base], the write is refused (`denied`, `stale_base`) and
  /// nothing changes. From then on the opener reads and writes [locator]
  /// with the new keys. Throws the storage's failure when the remote cannot
  /// be reached or refuses the token.
  ///
  /// **[C]** [beside] (file name → bytes) are written beside the vault in
  /// the same commit: a shared vault's recipients file, re-written with the
  /// new keys when a member is removed (part-sharing).
  Future<TomSecretsCommitted> rekey(
    String locator,
    KdbxFile file, {
    required Uint8List base,
    required Uint8List stored,
    String? outerKey,
    Map<String, Uint8List> beside = const {},
  });

  /// **[C]** The file [name] beside the vault at [locator] (in its folder,
  /// a shared vault's recipients file, part-sharing; or a path below that
  /// folder, `inbox/<member-id>/<package>`) and its revision (its git blob
  /// id), or null when there is none. Throws the storage's failure when the
  /// remote cannot be reached or refuses the token.
  Future<({Uint8List bytes, String revision})?> readBeside(
    String locator,
    String name,
  );

  /// **[C]** The files below the folder [folder] beside the vault at
  /// [locator] (e.g. `inbox`, part-sharing's inbox folders), at any depth:
  /// each one's path relative to the vault's folder (`/` between segments)
  /// with its revision. Empty when there is no such folder.
  Future<Map<String, String>> listBeside(String locator, String folder);

  /// **[C]** Deletes the files [paths] (relative to the vault's folder, as
  /// [listBeside] answers them); a `github:` vault in one commit. A path
  /// that is not there is skipped. Refused (`denied`, `branch_moving`) when
  /// the branch moved during the write.
  Future<void> deleteBeside(String locator, List<String> paths);

  /// **[C]** Writes [bytes] as the file [name] beside the vault at
  /// [locator]; a `github:` vault in one commit on the branch. Refused
  /// (`denied`, `stale_base`) when the file there is not [baseRevision]
  /// (null: no file may be there yet), and (`denied`, `branch_moving`) when
  /// the branch moved during the write. Answers the file's new revision.
  Future<String> writeBeside(
    String locator,
    String name,
    Uint8List bytes, {
    required String? baseRevision,
  });

  /// Moves the store at [from] to [to] (part-stores: adding or removing the
  /// outer encryption renames `.kdbx` <-> `.kdbx.tsmx`): [stored], [file] as
  /// [to] keeps it (opened with [credentials] and [outerKey]), is written at
  /// [to] and [from] is removed; a `github:` store in one commit. Refused
  /// (`denied`, `stale_base`) when [from] has moved since [base] (the file
  /// as the service holds it), and (`denied`, `target_exists`) when [to]
  /// exists; nothing is changed then. Answers the store opened at [to].
  /// Throws the storage's failure when the remote cannot be reached.
  Future<TomSecretsOpenedVault> move(
    String from,
    String to,
    KdbxFile file, {
    required Uint8List base,
    required Uint8List stored,
    required Credentials credentials,
    String? outerKey,
  });

  /// Creates the store [file] at [locator], where nothing may be yet
  /// (`denied`, `target_exists` otherwise): [stored], [file] as [locator]
  /// keeps it (opened with [credentials] and [outerKey]), is written there;
  /// a `github:` store in one commit on the branch. Answers the store opened
  /// at [locator]. Throws the storage's failure when the remote cannot be
  /// reached or refuses the token.
  Future<TomSecretsOpenedVault> create(
    String locator,
    KdbxFile file, {
    required Uint8List stored,
    required Credentials credentials,
    String? outerKey,
  });

  /// The head of a rewritten branch (a force push without a compaction) a
  /// refused [commit] of [locator] met, awaiting the user's answer; null when
  /// there is none (and always for a `file:` vault).
  String? rewrittenHeadOf(String locator);

  /// Answers a rewritten branch of [locator] ([rewrittenHeadOf]): with
  /// [takeRemote] the remote file is taken as it is and the refused edit is
  /// dropped; otherwise the held copy is merged over the remote (nothing
  /// taken as deleted) and committed on top of it. Answers the store as it
  /// is then; throws [StateError] when no answer is awaited, the storage's
  /// failure when the remote cannot be reached, and
  /// [TomSecretsSaveException] when the branch moved again.
  Future<TomSecretsCommitted> resolveRewritten(
    String locator, {
    required bool takeRemote,
  });

  /// Drops whatever the opener keeps of the vaults it opened (on lock).
  void drop();
}

/// What [TomSecretsVaultOpener.commit] wrote.
final class TomSecretsCommitted {
  /// [opened] as written; [merged] when the file had moved and was merged,
  /// with [conflicts] recorded in the vault.
  const TomSecretsCommitted({
    required this.opened,
    this.merged = false,
    this.conflicts = 0,
  });

  /// The store as written.
  final TomSecretsOpenedVault opened;

  /// Whether a three-way merge ran.
  final bool merged;

  /// The conflicts the merge recorded.
  final int conflicts;
}

/// Each locator to the opener of its kind: `file:` vaults to [file],
/// `github:` vaults to [github].
final class TomSecretsLocatorOpener implements TomSecretsVaultOpener {
  /// An opener of `file:` vaults through [file] and `github:` vaults through
  /// [github] (null: `github:` vaults are not opened).
  const TomSecretsLocatorOpener({
    this.file = const TomSecretsFileOpener(),
    this.github,
  });

  /// The `file:` opener.
  final TomSecretsVaultOpener file;

  /// The `github:` opener, or null.
  final TomSecretsVaultOpener? github;

  TomSecretsVaultOpener _for(String locator) =>
      switch (TomSecretsVaultLocator.parse(locator)) {
        TomSecretsFileLocator() => file,
        TomSecretsGitHubLocator() when github != null => github!,
        _ => throw UnsupportedError('no opener for $locator'),
      };

  @override
  Future<TomSecretsOpenedVault> open(
    String locator,
    Credentials credentials, {
    String? outerKey,
  }) => _for(locator).open(locator, credentials, outerKey: outerKey);

  @override
  Future<Uint8List> read(String locator) => _for(locator).read(locator);

  @override
  Future<String> revision(String locator) => _for(locator).revision(locator);

  @override
  Future<KdbxFile> decode(
    String locator,
    Uint8List stored,
    Credentials credentials, {
    String? outerKey,
  }) => _for(locator).decode(locator, stored, credentials, outerKey: outerKey);

  @override
  Future<Uint8List> encode(String locator, KdbxFile file, {String? outerKey}) =>
      _for(locator).encode(locator, file, outerKey: outerKey);

  @override
  Future<TomSecretsCommitted> commit(
    String locator,
    KdbxFile file, {
    required Uint8List base,
    required Credentials credentials,
    String? outerKey,
    Uint8List? stored,
  }) => _for(locator).commit(
    locator,
    file,
    base: base,
    credentials: credentials,
    outerKey: outerKey,
    stored: stored,
  );

  @override
  Future<TomSecretsCommitted> rekey(
    String locator,
    KdbxFile file, {
    required Uint8List base,
    required Uint8List stored,
    String? outerKey,
    Map<String, Uint8List> beside = const {},
  }) => _for(locator).rekey(
    locator,
    file,
    base: base,
    stored: stored,
    outerKey: outerKey,
    beside: beside,
  );

  @override
  Future<({Uint8List bytes, String revision})?> readBeside(
    String locator,
    String name,
  ) => _for(locator).readBeside(locator, name);

  @override
  Future<String> writeBeside(
    String locator,
    String name,
    Uint8List bytes, {
    required String? baseRevision,
  }) => _for(
    locator,
  ).writeBeside(locator, name, bytes, baseRevision: baseRevision);

  @override
  Future<Map<String, String>> listBeside(String locator, String folder) =>
      _for(locator).listBeside(locator, folder);

  @override
  Future<void> deleteBeside(String locator, List<String> paths) =>
      _for(locator).deleteBeside(locator, paths);

  @override
  Future<TomSecretsOpenedVault> move(
    String from,
    String to,
    KdbxFile file, {
    required Uint8List base,
    required Uint8List stored,
    required Credentials credentials,
    String? outerKey,
  }) => _for(from).move(
    from,
    to,
    file,
    base: base,
    stored: stored,
    credentials: credentials,
    outerKey: outerKey,
  );

  @override
  Future<TomSecretsOpenedVault> create(
    String locator,
    KdbxFile file, {
    required Uint8List stored,
    required Credentials credentials,
    String? outerKey,
  }) => _for(locator).create(
    locator,
    file,
    stored: stored,
    credentials: credentials,
    outerKey: outerKey,
  );

  @override
  String? rewrittenHeadOf(String locator) =>
      _for(locator).rewrittenHeadOf(locator);

  @override
  Future<TomSecretsCommitted> resolveRewritten(
    String locator, {
    required bool takeRemote,
  }) => _for(locator).resolveRewritten(locator, takeRemote: takeRemote);

  @override
  void drop() {
    file.drop();
    github?.drop();
  }
}

/// `file:` vaults: read and written on the local disk (a `.tsmx` file
/// through the outer layer).
final class TomSecretsFileOpener implements TomSecretsVaultOpener {
  /// The opener.
  const TomSecretsFileOpener();

  static String _path(String locator) {
    final parsed = TomSecretsVaultLocator.parse(locator);
    if (parsed is! TomSecretsFileLocator) {
      throw UnsupportedError('$locator is not a file: vault');
    }
    return parsed.path;
  }

  @override
  Future<TomSecretsOpenedVault> open(
    String locator,
    Credentials credentials, {
    String? outerKey,
  }) async {
    final stored = await read(locator);
    return TomSecretsOpenedVault(
      locator: locator,
      file: await decode(locator, stored, credentials, outerKey: outerKey),
      stored: stored,
      fetchedAt: (await File(_path(locator)).lastModified()).toUtc(),
    );
  }

  @override
  Future<Uint8List> read(String locator) => File(_path(locator)).readAsBytes();

  @override
  Future<String> revision(String locator) async =>
      tomSecretsBlobId(await read(locator));

  @override
  Future<KdbxFile> decode(
    String locator,
    Uint8List stored,
    Credentials credentials, {
    String? outerKey,
  }) {
    _path(locator);
    return tomSecretsDecodeStored(
      locator,
      stored,
      credentials,
      outerKey: outerKey,
    );
  }

  @override
  Future<Uint8List> encode(String locator, KdbxFile file, {String? outerKey}) {
    _path(locator);
    return tomSecretsEncodeStored(locator, file, outerKey: outerKey);
  }

  /// Replaces the file at [locator] with [stored] at once.
  Future<void> _write(String locator, Uint8List stored) =>
      _writeFile(_path(locator), stored);

  /// Replaces the file at [path] with [bytes] at once.
  static Future<void> _writeFile(String path, Uint8List bytes) async {
    final temp = File('$path.tmp');
    await temp.writeAsBytes(bytes, flush: true);
    await temp.rename(path);
  }

  /// The path of [name] (a file name, or a relative path below the vault's
  /// folder) in the folder of the vault at [locator].
  static String _besidePath(String locator, String name) =>
      '${File(_path(locator)).parent.path}${Platform.pathSeparator}'
      '${tomSecretsBesidePath(name).replaceAll('/', Platform.pathSeparator)}';

  @override
  Future<Map<String, String>> listBeside(String locator, String folder) async {
    final dir = Directory(_besidePath(locator, folder));
    if (!dir.existsSync()) return const {};
    final base = File(_path(locator)).parent.path;
    final out = <String, String>{};
    await for (final f in dir.list(recursive: true, followLinks: false)) {
      if (f is! File || f.path.endsWith('.tmp')) continue;
      final relative = f.path
          .substring(base.length + 1)
          .replaceAll(Platform.pathSeparator, '/');
      out[relative] = tomSecretsBlobId(await f.readAsBytes());
    }
    return out;
  }

  @override
  Future<void> deleteBeside(String locator, List<String> paths) async {
    for (final p in paths) {
      final f = File(_besidePath(locator, p));
      if (f.existsSync()) await f.delete();
    }
  }

  @override
  Future<({Uint8List bytes, String revision})?> readBeside(
    String locator,
    String name,
  ) async {
    final file = File(_besidePath(locator, name));
    if (!file.existsSync()) return null;
    final bytes = await file.readAsBytes();
    return (bytes: bytes, revision: tomSecretsBlobId(bytes));
  }

  @override
  Future<String> writeBeside(
    String locator,
    String name,
    Uint8List bytes, {
    required String? baseRevision,
  }) async {
    final path = _besidePath(locator, name);
    final file = File(path);
    final now = file.existsSync()
        ? tomSecretsBlobId(await file.readAsBytes())
        : null;
    if (now != baseRevision) {
      throw TomSecretsSaveException(
        'denied',
        'the file $name has moved since it was read',
        reason: 'stale_base',
      );
    }
    await file.parent.create(recursive: true);
    await _writeFile(path, bytes);
    return tomSecretsBlobId(bytes);
  }

  @override
  Future<TomSecretsCommitted> commit(
    String locator,
    KdbxFile file, {
    required Uint8List base,
    required Credentials credentials,
    String? outerKey,
    Uint8List? stored,
  }) async {
    final current = await read(locator);
    var merged = false;
    var conflicts = 0;
    if (tomSecretsBlobId(current) != tomSecretsBlobId(base)) {
      final result = tomSecretsMergeVaults(
        base: await decode(locator, base, credentials, outerKey: outerKey),
        ours: file,
        theirs: await decode(locator, current, credentials, outerKey: outerKey),
        location: locator,
      );
      merged = true;
      conflicts = result.conflicts.length;
    }
    final written = merged || stored == null
        ? await tomSecretsEncodeStored(
            locator,
            file,
            outerKey: outerKey,
            like: current,
          )
        : stored;
    await _write(locator, written);
    return TomSecretsCommitted(
      opened: TomSecretsOpenedVault(
        locator: locator,
        file: file,
        stored: written,
        fetchedAt: (await File(_path(locator)).lastModified()).toUtc(),
      ),
      merged: merged,
      conflicts: conflicts,
    );
  }

  @override
  Future<TomSecretsCommitted> rekey(
    String locator,
    KdbxFile file, {
    required Uint8List base,
    required Uint8List stored,
    String? outerKey,
    Map<String, Uint8List> beside = const {},
  }) async {
    final current = await read(locator);
    if (tomSecretsBlobId(current) != tomSecretsBlobId(base)) {
      throw TomSecretsSaveException(
        'denied',
        'the file has moved since the copy that was re-keyed',
        reason: 'stale_base',
      );
    }
    await _write(locator, stored);
    for (final MapEntry(:key, :value) in beside.entries) {
      await _writeFile(_besidePath(locator, key), value);
    }
    return TomSecretsCommitted(
      opened: TomSecretsOpenedVault(
        locator: locator,
        file: file,
        stored: stored,
        fetchedAt: (await File(_path(locator)).lastModified()).toUtc(),
      ),
    );
  }

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
    final current = await read(from);
    if (tomSecretsBlobId(current) != tomSecretsBlobId(base)) {
      throw TomSecretsSaveException(
        'denied',
        'the file has moved since the copy that is moved',
        reason: 'stale_base',
      );
    }
    final target = File(_path(to));
    if (target.existsSync()) {
      throw TomSecretsSaveException(
        'denied',
        'a file is at ${target.path} already',
        reason: 'target_exists',
      );
    }
    await _write(to, stored);
    // The new file is in place: only now is the old one removed.
    await File(_path(from)).delete();
    return TomSecretsOpenedVault(
      locator: to,
      file: file,
      stored: stored,
      fetchedAt: (await target.lastModified()).toUtc(),
    );
  }

  @override
  Future<TomSecretsOpenedVault> create(
    String locator,
    KdbxFile file, {
    required Uint8List stored,
    required Credentials credentials,
    String? outerKey,
  }) async {
    final target = File(_path(locator));
    if (target.existsSync()) {
      throw TomSecretsSaveException(
        'denied',
        'a file is at ${target.path} already',
        reason: 'target_exists',
      );
    }
    await target.parent.create(recursive: true);
    await _write(locator, stored);
    return TomSecretsOpenedVault(
      locator: locator,
      file: file,
      stored: stored,
      fetchedAt: (await target.lastModified()).toUtc(),
    );
  }

  @override
  String? rewrittenHeadOf(String locator) => null;

  @override
  Future<TomSecretsCommitted> resolveRewritten(
    String locator, {
    required bool takeRemote,
  }) => throw StateError('a file: vault has no branch to answer for');

  @override
  void drop() {}
}

/// The key material the service holds for one store while unlocked, masked
/// (part-service, Memory hygiene): what opens it, and what `vaultKeySet`
/// hands the app (protocol.md 6.4). [dispose] zeroes it.
final class TomSecretsHeldKeys {
  /// Keys of a [password], a [keyFile] (its bytes) and an [outerKey] (the
  /// repository key, base64).
  TomSecretsHeldKeys({
    this.password,
    this.keyFile,
    this.outerKey,
    this.compositeKey,
  });

  /// The keys of an OS unlock's bundle (protocol.md 6.4): the composite key
  /// in place of the password and the key file, and the repository key.
  factory TomSecretsHeldKeys.ofBundle(TomSecretsUnlockBundle bundle) =>
      TomSecretsHeldKeys(
        compositeKey: TomProtectedValue.fromBytes(
          Uint8List.fromList(bundle.compositeKey),
        ),
        outerKey: bundle.outerKey == null
            ? null
            : TomProtectedValue.of(bundle.outerKey!),
      );

  /// The keys a request carries: `password` and `keyFile` (base64).
  factory TomSecretsHeldKeys.of({String? password, Uint8List? keyFile}) =>
      TomSecretsHeldKeys(
        password: password == null ? null : TomProtectedValue.of(password),
        keyFile: keyFile == null ? null : TomProtectedValue.fromBytes(keyFile),
      );

  /// The keys the primary's vault list names for a further vault.
  factory TomSecretsHeldKeys.fromVaultKeys(TomSecretsVaultKeys keys) =>
      TomSecretsHeldKeys(
        password: keys.password == null
            ? null
            : TomProtectedValue.of(keys.password!),
        keyFile: keys.keyFile == null
            ? null
            : TomProtectedValue.fromBytes(Uint8List.fromList(keys.keyFile!)),
        outerKey: keys.writtenOuterKeys == null
            ? null
            : TomProtectedValue.of(keys.writtenOuterKeys!),
      );

  /// The master password, or null.
  final TomProtectedValue? password;

  /// The key file's bytes, or null.
  final TomProtectedValue? keyFile;

  /// The repository's outer key (base64), or null.
  final TomProtectedValue? outerKey;

  /// The composite key an OS unlock opened the vault with, in place of
  /// [password] and [keyFile] (32 bytes), or null.
  final TomProtectedValue? compositeKey;

  /// The same keys with [outerKey].
  TomSecretsHeldKeys withOuterKey(TomProtectedValue? outerKey) =>
      TomSecretsHeldKeys(
        password: password,
        keyFile: keyFile,
        outerKey: outerKey,
        compositeKey: compositeKey,
      );

  /// The credentials that open the vault (`Credentials.composite` takes the
  /// key file's bytes and derives the key itself; a composite key is taken
  /// as it is).
  Credentials get credentials {
    final composite = compositeKey;
    if (composite != null) {
      return composite.withRevealed(
        (b) => Credentials.fromCompositeKey(Uint8List.fromList(b)),
      );
    }
    return Credentials.composite(
      password?.withRevealed(
        (b) => ProtectedValue.fromBinary(Uint8List.fromList(b)),
      ),
      keyFile?.withRevealed(Uint8List.fromList),
    );
  }

  /// The outer key as the codec takes it: the repository key, and during a
  /// guided rotation's migration period also the old one, `,`-separated,
  /// the newest first (`tomSecretsOuterCodecFor`).
  String? get outerKeyText => outerKey?.reveal();

  /// **[C]** The newest repository key alone (base64), or null: what the
  /// keychain keeps and the app is given as `outerKey`.
  String? get newestOuterKey =>
      tomSecretsOuterKeyList(outerKeyText).firstOrNull;

  /// **[C]** The older repository keys the file keeps slots for during a
  /// migration period, `,`-separated, or null.
  String? get previousOuterKeys {
    final rest = tomSecretsOuterKeyList(outerKeyText).skip(1).toList();
    return rest.isEmpty ? null : rest.join(',');
  }

  /// **[C]** The ids of the repository keys held (`keyIdHex`).
  List<String> get outerKeyIds => [
    for (final k in tomSecretsOuterKeyList(outerKeyText))
      TomSecretsRepositoryKey.fromBase64(k).keyIdHex,
  ];

  /// The `keys` object of `vaultKeySet`: `password`, `keyFile` (base64),
  /// `outerKey` (base64) and an OS unlock's `compositeKey` (base64), written
  /// into the frame from their bytes.
  Map<String, Object?> toWire() => {
    'password': ?(password == null
        ? null
        : TomSecretsSecretSlot.ofText(password!)),
    'keyFile': ?(keyFile == null
        ? null
        : TomSecretsSecretSlot.ofBytes(keyFile!)),
    'outerKey': ?(outerKey == null
        ? null
        : TomSecretsSecretSlot.ofText(
            previousOuterKeys == null
                ? outerKey!
                : TomProtectedValue.of(newestOuterKey!),
          )),
    'previousOuterKey': ?(previousOuterKeys == null
        ? null
        : TomSecretsSecretSlot.ofText(
            TomProtectedValue.of(previousOuterKeys!),
          )),
    'compositeKey': ?(compositeKey == null
        ? null
        : TomSecretsSecretSlot.ofBytes(compositeKey!)),
  };

  /// Zeroes every key.
  void dispose() {
    password?.dispose();
    keyFile?.dispose();
    outerKey?.dispose();
    compositeKey?.dispose();
  }

  @override
  String toString() => 'TomSecretsHeldKeys(***)';
}

/// A `save` the service does not take (protocol.md 6.4, 10).
final class TomSecretsSaveException implements Exception {
  /// A refusal of [kind] (a protocol error kind) for [reason].
  TomSecretsSaveException(this.kind, this.message, {this.reason});

  /// The protocol's error kind.
  final String kind;

  /// `details.reason`, when the kind has one.
  final String? reason;

  /// What went wrong, never a value.
  final String message;

  @override
  String toString() => 'TomSecretsSaveException($kind, $reason)';
}

/// What a `save` did.
final class TomSecretsSaveResult {
  /// A save that wrote [revision]; [merged] when the file had moved and the
  /// app's copy was merged into it, with [conflicts] recorded in the vault.
  const TomSecretsSaveResult({
    required this.revision,
    this.merged = false,
    this.conflicts = 0,
    this.rekeyed = false,
  });

  /// Whether the file was written re-keyed (part-key-rotation): the store's
  /// keys are the new ones from then on.
  final bool rekeyed;

  /// The revision of the file written.
  final String revision;

  /// Whether a three-way merge ran.
  final bool merged;

  /// The conflicts the merge recorded.
  final int conflicts;
}

/// A store's status, as `status` reports it.
final class TomSecretsStoreStatus {
  /// [name] in [state], from [source], fetched at [fetchedAt].
  const TomSecretsStoreStatus({
    required this.name,
    required this.state,
    this.locator,
    this.source,
    this.fetchedAt,
    this.revision,
    this.notPushed = 0,
    this.rewrittenHead,
    this.keyChanged = false,
  });

  /// The store's name.
  final String name;

  /// **[C]** Whether it is served from a copy under its old key, read-only,
  /// because another device re-keyed it ([TomSecretsKeyChangedException]).
  final bool keyChanged;

  /// The head of its rewritten branch awaiting the user's answer
  /// (`history.resolve`), or null.
  final String? rewrittenHead;

  /// Its state.
  final TomSecretsStoreState state;

  /// Its locator.
  final String? locator;

  /// `file`, `github` or `cache`.
  final String? source;

  /// When it was last fetched.
  final DateTime? fetchedAt;

  /// The revision of the file as read (the remote's, else the git blob id of
  /// the stored bytes).
  final String? revision;

  /// Its changes not yet pushed.
  final int notPushed;

  /// The protocol's `source` (5.2): `file`, `github` or `cache` as read; a
  /// store not read yet answers by its locator's kind (`file:` or GitHub).
  String get wireSource => switch (source) {
    'file' || 'github' || 'cache' => source!,
    _ => (locator ?? '').startsWith('file:') ? 'file' : 'github',
  };

  /// As `statusReport.stores[]` writes it.
  Map<String, Object?> toJson() => {
    'name': name,
    'state': state.wireName,
    'source': wireSource,
    'fetchedAt': ?fetchedAt?.toUtc().toIso8601String(),
    'notPushed': notPushed,
    if (rewrittenHead != null) 'rewritten': {'head': rewrittenHead},
    if (keyChanged) 'keyChanged': true,
  };
}

/// What a refresh changed.
final class TomSecretsRefreshReport {
  /// A report of the stores whose state or source changed ([states], their
  /// new status) and of those reopened with new content ([reopened]).
  const TomSecretsRefreshReport({
    this.states = const [],
    this.reopened = const [],
  });

  /// The new status of every store whose state or source changed (a store
  /// new in the primary's list included).
  final List<TomSecretsStoreStatus> states;

  /// The stores reopened with new content.
  final List<String> reopened;
}

enum _Outcome { unchanged, reopened, dropped }

/// A save's file opened ([TomSecretsVaultSet._opening]): with the keys held
/// ([newKeys] null), or re-keyed with [newKeys] ([listed]: the primary's
/// entry they come from, for a further vault).
typedef _Opening = ({
  KdbxFile file,
  TomSecretsHeldKeys? newKeys,
  TomSecretsVaultKeys? listed,
});

/// When a store is fetched next, and how often a fetch failed in a row.
final class _Next {
  const _Next(this.at, {this.failures = 0, this.auth = false});

  /// Not before then.
  final DateTime at;

  /// Fetches failed in a row for a network reason.
  final int failures;

  /// The token was refused: only an unlock or a `reload` fetches again.
  final bool auth;
}

/// A store name (protocol.md 3).
final RegExp _storeNamePattern = RegExp(r'^[a-z0-9][a-z0-9_-]*$');

/// The unlocked vaults.
final class TomSecretsVaultSet {
  /// A set opening vaults through [opener]; [clock] is the refresh's time.
  TomSecretsVaultSet({required this.opener, DateTime Function()? clock})
    : _clock = clock ?? DateTime.now;

  /// The opener.
  final TomSecretsVaultOpener opener;

  /// How long after a fetch a store is fetched again (the device settings'
  /// `refreshMinutes`).
  Duration refreshInterval = const Duration(minutes: 5);

  /// The longest wait after network failures (1, 2, 4 … minutes).
  static const maxBackoff = Duration(minutes: 30);

  final DateTime Function() _clock;
  final Map<String, _Next> _next = {};
  List<String>? _served;
  int _epoch = 0;

  TomSecretsOpenedVault? _primary;
  String? _primaryName;
  TomSecretsHeldKeys? _primaryKeys;
  final Map<String, TomSecretsOpenedVault> _opened = {};
  final Map<String, TomSecretsStoreStatus> _status = {};
  final Map<String, TomSecretsVaultKeys> _keys = {};
  final Map<String, TomSecretsHeldKeys> _held = {};
  TomSecretsMachine? _machine;
  TomSecretsResolver? _resolver;

  // The vaults the primary lists that this machine does not serve, opened
  // for the app's editing only (protocol.md 6.4): never resolved, served or
  // refreshed; dropped on the lock.
  final Map<String, TomSecretsOpenedVault> _editOnly = {};
  final Map<String, TomSecretsVaultKeys> _editListed = {};

  // The stores whose branch was rewritten without a compaction, by the
  // rewritten head, until the user answers (`history.resolve`); not
  // refreshed meanwhile, so the question stays.
  final Map<String, String> _rewritten = {};
  final Map<String, TomSecretsHeldKeys> _editHeld = {};

  /// Whether the primary is open.
  bool get isUnlocked => _primary != null;

  /// **[C]** The primary's own next keys of a guided rotation
  /// (part-key-rotation), as the service took them from the primary: the
  /// refresh tries them when the primary no longer opens with the keys held
  /// (another device switched it), and [adoptPrimaryNext] takes them up.
  TomSecretsPrimaryNextKeys? primaryNextKeys;

  /// **[C]** Called with the primary's keys when the set took up its next
  /// keys (the service keeps them in the keychain).
  Future<void> Function(TomSecretsHeldKeys keys)? onPrimaryKeysChanged;

  /// **[C]** The primary's keys held now with [next] taken up: its key file
  /// (else the one held) and its repository keys (the next one, and the
  /// previous one while the file keeps its slot); the password or the OS
  /// unlock's composite key as held.
  TomSecretsHeldKeys? primaryKeysWith(TomSecretsPrimaryNextKeys next) {
    final held = _primaryKeys;
    if (held == null) return null;
    final keyFile = next.keyFile;
    // A composite key binds the old key file: with a new one it does not
    // open the vault, which then needs the master password.
    if (keyFile != null && held.compositeKey != null) return null;
    return TomSecretsHeldKeys(
      password: held.password == null
          ? null
          : TomProtectedValue.of(held.password!.reveal()),
      keyFile: keyFile != null
          ? TomProtectedValue.fromBytes(Uint8List.fromList(keyFile))
          : (held.keyFile == null
                ? null
                : TomProtectedValue.fromBytes(
                    held.keyFile!.withRevealed(Uint8List.fromList),
                  )),
      outerKey: switch (tomSecretsJoinOuterKeys([
        next.outerKey ?? held.newestOuterKey,
        next.previousOuterKey,
      ])) {
        null => null,
        final k => TomProtectedValue.of(k),
      },
      compositeKey: held.compositeKey == null
          ? null
          : TomProtectedValue.fromBytes(
              held.compositeKey!.withRevealed(Uint8List.fromList),
            ),
    );
  }

  /// **[C]** Takes up the primary's next repository key once its file keeps
  /// a slot for it (another device switched a rotation of the repository
  /// key alone: the file still opens with the old key, part-key-rotation),
  /// and drops a previous repository key once no rotation of the primary
  /// runs any more (the finish). Answers whether the keys held changed.
  Future<bool> adoptPrimaryNext() async {
    final primary = _primary;
    final held = _primaryKeys;
    if (primary == null || held == null) return false;
    final next = primaryNextKeys;
    TomSecretsHeldKeys? keys;
    if (next == null) {
      if (held.previousOuterKeys != null) {
        keys = held.withOuterKey(TomProtectedValue.of(held.newestOuterKey!));
      }
    } else if (next.outerKey != null &&
        next.keyFile == null &&
        primary.locator.endsWith(tomSecretsOuterSuffix) &&
        !tomSecretsOuterKeyList(held.outerKeyText).contains(next.outerKey)) {
      final nextId = TomSecretsRepositoryKey.fromBase64(
        next.outerKey!,
      ).keyIdHex;
      List<String> slots;
      try {
        slots = tomSecretsOuterKeyIds(primary.stored);
      } on Object {
        slots = const [];
      }
      if (slots.contains(nextId)) keys = primaryKeysWith(next);
    }
    if (keys == null) return false;
    _primaryKeys = keys;
    if (_primaryName != null) _restatusSlots(_primaryName!);
    await onPrimaryKeysChanged?.call(keys);
    return true;
  }

  /// The open primary vault, or null.
  TomSecretsOpenedVault? get primary => _primary;

  /// The primary's store name, while unlocked.
  String? get primaryName => _primaryName;

  /// The resolver over the opened stores, or null while locked.
  TomSecretsResolver? get resolver => _resolver;

  /// Every store's status, the primary first.
  List<TomSecretsStoreStatus> get status => _status.values.toList();

  /// The status of store [name], or null.
  TomSecretsStoreStatus? statusOf(String name) => _status[name];

  /// Opens the primary at [locator] with [keys] (phase one of the unlock:
  /// the device settings container's key may live in it). The set holds
  /// [keys] from then on (and disposes them on [lock]).
  Future<TomSecretsOpenedVault> openPrimary(
    String locator,
    TomSecretsHeldKeys keys,
  ) async {
    final opened = await opener.open(
      locator,
      keys.credentials,
      outerKey: keys.outerKeyText,
    );
    _primary = opened;
    _primaryKeys = keys;
    return opened;
  }

  /// The further vaults the primary lists, as last read.
  List<TomSecretsVaultKeys> get listed => _keys.values.toList();

  /// The further vaults the primary lists that this machine does not serve
  /// (its device settings name others): editable through [vaultKeys],
  /// [vaultFile] and [save], never served (protocol.md 6.4).
  List<TomSecretsVaultKeys> get unserved {
    final primary = _primary;
    if (primary == null || _primaryName == null) return const [];
    return [
      for (final keys in TomSecretsPrimaryVaults(primary.file).list())
        if (keys.name != _primaryName && !_keys.containsKey(keys.name)) keys,
    ];
  }

  /// The keys of the vault not served [name], held until the lock; throws
  /// [StateError] naming a vault the primary does not list as not served.
  TomSecretsHeldKeys _editKeys(String name) {
    final listed = unserved.where((k) => k.name == name).firstOrNull;
    if (listed == null) throw StateError(name);
    // A copy held keeps its keys while the location stays: a rotation in
    // progress (the primary lists the new keys first), or another device's,
    // whose file the app then cannot save over (refresh drops the copy only
    // when the location changes).
    final old = _editListed[name];
    if (old != null && old.locator != listed.locator) _dropEditOnly(name);
    if (!_editHeld.containsKey(name)) _editListed[name] = listed;
    return _editHeld[name] ??= TomSecretsHeldKeys.fromVaultKeys(listed);
  }

  void _dropEditOnly(String name) {
    _editOnly.remove(name);
    _editListed.remove(name);
    _editHeld.remove(name)?.dispose();
  }

  /// Records a fetch of [name] that failed with [failure] (null: it
  /// succeeded): the next one is due a refresh interval later, after a
  /// network failure after the backoff (1, 2, 4 … up to 30 minutes), and
  /// after a refused token only on an unlock or a `reload`.
  void _fetched(String name, Object? failure) {
    final now = _clock();
    if (failure == null) {
      _next[name] = _Next(now.add(refreshInterval));
      return;
    }
    if (TomSecretsStoreState.offlineFor(failure) ==
        TomSecretsStoreState.tokenExpired) {
      _next[name] = _Next(now, auth: true);
      return;
    }
    final failures = (_next[name]?.failures ?? 0) + 1;
    final minutes = 1 << (failures - 1).clamp(0, 5);
    final wait = Duration(minutes: minutes) > maxBackoff
        ? maxBackoff
        : Duration(minutes: minutes);
    _next[name] = _Next(now.add(wait), failures: failures);
  }

  bool _due(String name, bool force) {
    if (force) return true;
    final next = _next[name];
    if (next == null) return true;
    if (next.auth) return false;
    return !_clock().isBefore(next.at);
  }

  /// Writes the open primary through the opener's [TomSecretsVaultOpener.
  /// commit] (the service's own edits: grants, their last use, the device
  /// key): a `github:` primary as a commit on the branch, merged with a
  /// remote that moved. The held copy then is what was written; the copy it
  /// replaces stays a merge base for an app that edited it. Returns the
  /// revision written.
  ///
  /// When the remote cannot be reached or refuses the token, the edits stay
  /// in the held copy ([primaryWritePending]), the primary goes to
  /// `offline` / `token_expired`, and the next refresh writes them before it
  /// fetches; the failure is rethrown. Nothing is kept across a lock.
  Future<String> writePrimary() async {
    final primary = _primary!;
    final name = _primaryName;
    final TomSecretsCommitted committed;
    try {
      committed = await opener.commit(
        primary.locator,
        primary.file,
        base: primary.stored,
        credentials: _primaryKeys!.credentials,
        outerKey: _primaryKeys!.outerKeyText,
      );
    } on Object catch (e) {
      _primaryPending = true;
      final failure = tomSecretsFetchFailureOf(e);
      if (failure != null && name != null) {
        _fetched(name, failure);
        _setStatus(
          name,
          primary.locator,
          TomSecretsStoreState.offlineFor(failure),
          from: primary,
          source: primary.source == 'file' ? null : 'cache',
        );
      }
      rethrow;
    }
    _primaryPending = false;
    // The copy this write replaces stays a merge base: an app that edited
    // it is merged, not refused (stale_base).
    _ownWrites[_revisionOf(primary)] = primary.stored;
    while (_ownWrites.length > 8) {
      _ownWrites.remove(_ownWrites.keys.first);
    }
    final written = _primary = committed.opened;
    if (name != null) {
      _opened[name] = written;
      _fetched(name, null);
      _setStatus(
        name,
        written.locator,
        TomSecretsStoreState.current,
        from: written,
      );
      // A merge brought the remote's changes in.
      final machine = _machine;
      if (committed.merged && machine != null) _rebuildOpened(machine);
    }
    return _revisionOf(written);
  }

  bool _primaryPending = false;

  /// Whether the service's own edits of the primary wait to be written (the
  /// last [writePrimary] could not reach the remote).
  bool get primaryWritePending => _primaryPending;

  /// The primary as stored before the service's own writes (revision →
  /// bytes), the merge bases of an app's save of an older revision.
  final Map<String, Uint8List> _ownWrites = {};

  /// Opens the further vaults the primary names (phase two), only those in
  /// [served] when given, and builds the index for [machine]. A vault that
  /// does not open is marked `needs_unlock` (its key) or `unavailable` (any
  /// other failure); the others are still served.
  Future<void> openStores({
    required TomSecretsMachine machine,
    List<String>? served,
  }) async {
    final primary = _primary!;
    _served = served;
    final primaryStore = TomSecretsStore.fromFile(
      primary.file,
      fileName: TomSecretsVaultLocator.parse(primary.locator).fileName,
    );
    final stores = <TomSecretsStore>[primaryStore];
    _primaryName = primaryStore.name;
    _next.clear();
    _fetched(primaryStore.name, primary.offlineReason);
    _status
      ..clear()
      ..[primaryStore.name] = TomSecretsStoreStatus(
        name: primaryStore.name,
        state: primary.state,
        locator: primary.locator,
        source: primary.source,
        fetchedAt: primary.fetchedAt,
        revision: _revisionOf(primary),
      );
    _opened
      ..clear()
      ..[primaryStore.name] = primary;
    _keys.clear();
    _disposeHeld();
    for (final keys in TomSecretsPrimaryVaults(primary.file).list()) {
      if (served != null && !served.contains(keys.name)) continue;
      _keys[keys.name] = keys;
      final held = TomSecretsHeldKeys.fromVaultKeys(keys);
      final store = await _open(
        keys.name,
        keys.locator,
        held.credentials,
        outerKey: keys.writtenOuterKeys,
      );
      if (store != null) {
        _held[keys.name] = held;
        stores.add(store);
      } else {
        held.dispose();
      }
    }
    _rebuild(stores, machine);
  }

  Future<TomSecretsStore?> _open(
    String name,
    String locator,
    Credentials credentials, {
    String? outerKey,
  }) async {
    try {
      final opened = await opener.open(
        locator,
        credentials,
        outerKey: outerKey,
      );
      final store = TomSecretsStore.fromFile(opened.file, name: name);
      final keyChanged = opened.offlineReason is TomSecretsKeyChangedException;
      _fetched(name, keyChanged ? null : opened.offlineReason);
      _opened[name] = opened;
      _status[name] = TomSecretsStoreStatus(
        name: name,
        state: opened.state,
        locator: locator,
        source: opened.source,
        fetchedAt: opened.fetchedAt,
        revision: _revisionOf(opened),
        keyChanged:
            keyChanged ||
            _slotsMissing(
              opened,
              TomSecretsHeldKeys(
                outerKey: outerKey == null
                    ? null
                    : TomProtectedValue.of(outerKey),
              ),
            ),
      );
      return store;
    } on KdbxInvalidKeyException {
      _status[name] = TomSecretsStoreStatus(
        name: name,
        state: TomSecretsStoreState.needsUnlock,
        locator: locator,
      );
    } on TomKeyRequiredException {
      _status[name] = TomSecretsStoreStatus(
        name: name,
        state: TomSecretsStoreState.needsUnlock,
        locator: locator,
      );
    } on Object catch (e) {
      // A file the service cannot fetch and has no copy of.
      _fetched(name, tomSecretsIsFetchFailure(e) ? e : null);
      _status[name] = TomSecretsStoreStatus(
        name: name,
        state: TomSecretsStoreState.unavailable,
        locator: locator,
      );
    }
    return null;
  }

  /// Opens store [name] (in `needs_unlock`) with [keys] of its own (the
  /// outer key stays the primary list's); the set holds them from then on.
  /// Throws [KdbxInvalidKeyException] for wrong credentials and
  /// [StateError] for a store the primary does not name.
  Future<void> unlockStore(
    String name,
    TomSecretsHeldKeys keys, {
    required TomSecretsMachine machine,
  }) async {
    final listed = _keys[name];
    if (listed == null) throw StateError('no store $name');
    final opened = await opener.open(
      listed.locator,
      keys.credentials,
      outerKey: listed.writtenOuterKeys,
    );
    _held.remove(name)?.dispose();
    _held[name] = keys.withOuterKey(
      listed.writtenOuterKeys == null
          ? null
          : TomProtectedValue.of(listed.writtenOuterKeys!),
    );
    _opened[name] = opened;
    _fetched(name, opened.offlineReason);
    _status[name] = TomSecretsStoreStatus(
      name: name,
      state: opened.state,
      locator: listed.locator,
      source: opened.source,
      fetchedAt: opened.fetchedAt,
      revision: _revisionOf(opened),
    );
    _rebuildOpened(machine);
  }

  void _rebuildOpened(TomSecretsMachine machine) => _rebuild([
    for (final e in _opened.entries)
      TomSecretsStore.fromFile(
        e.value.file,
        name: e.value == _primary ? null : e.key,
        fileName: TomSecretsVaultLocator.parse(e.value.locator).fileName,
      ),
  ], machine);

  /// The copy of the open store [name] the service holds
  /// (`vaultFileData`, protocol.md 6.4): its locator, its revision (the
  /// `baseRevision` a `save` of an edit of it names) and the file as the
  /// store keeps it. Throws [StateError] naming a store that is not open.
  ///
  /// A vault the primary lists that this machine does not serve is read
  /// from its location with its listed keys (and the repository's token)
  /// on the first call and held for editing until the lock (`served`
  /// false). Throws what opening it throws: [KdbxInvalidKeyException] or
  /// `TomKeyRequiredException` when its keys do not open it, a fetch
  /// failure when its location cannot be read.
  Future<({String location, String revision, Uint8List stored, bool served})>
  vaultFile(String name) async {
    final served = _opened[name];
    if (served != null) {
      return (
        location: served.locator,
        revision: _revisionOf(served),
        stored: served.stored,
        served: true,
      );
    }
    final keys = _editKeys(name);
    var opened = _editOnly[name];
    if (opened == null) {
      final listed = _editListed[name]!;
      final epoch = _epoch;
      opened = await opener.open(
        listed.locator,
        keys.credentials,
        outerKey: keys.outerKeyText,
      );
      // Locked meanwhile: the keys are gone, nothing is held.
      if (epoch != _epoch) throw StateError(name);
      _editOnly[name] = opened;
    }
    return (
      location: opened.locator,
      revision: _revisionOf(opened),
      stored: opened.stored,
      served: false,
    );
  }

  /// The keys of the open stores (`vaultKeySet.stores`, protocol.md 6.4),
  /// the primary first; only [stores] when given. Each `keys` object carries
  /// its secrets as [TomSecretsSecretSlot]s. Throws [StateError] naming a
  /// store that is not open.
  List<Map<String, Object?>> vaultKeys({List<String>? stores}) {
    final open = [
      ?_primaryName,
      for (final name in _opened.keys)
        if (name != _primaryName) name,
    ];
    final notServed = {for (final k in unserved) k.name};
    for (final name in stores ?? const <String>[]) {
      if (!open.contains(name) && !notServed.contains(name)) {
        throw StateError(name);
      }
    }
    return [
      for (final name in open)
        if (stores == null || stores.contains(name))
          {
            'store': name,
            'location': _opened[name]!.locator,
            'keys':
                (name == _primaryName ? _primaryKeys : _held[name])?.toWire() ??
                const <String, Object?>{},
          },
      // A vault not served only when named: the app opens it for editing.
      for (final name in stores ?? const <String>[])
        if (notServed.contains(name))
          {
            'store': name,
            'location': _editListedOrNew(name).locator,
            'served': false,
            'keys': _editKeys(name).toWire(),
          },
    ];
  }

  TomSecretsVaultKeys _editListedOrNew(String name) {
    _editKeys(name);
    return _editListed[name]!;
  }

  /// Takes the app's edited file of store [name] (protocol.md 6.4): [stored]
  /// is the whole file as the store keeps it, [baseRevision] the revision
  /// the app edited. It must open with the store's keys. The edit is
  /// written through the opener's [TomSecretsVaultOpener.commit] over the
  /// copy the service holds: when the file has moved since (on the disk, or
  /// a `github:` branch another device pushed to), the app's copy is merged
  /// three-way into it, the held copy as the base. [baseRevision] must be
  /// the held copy, a copy the service wrote over itself (the primary's
  /// grants; merged onto the held copy first), or the file as it is now;
  /// any other is refused (`denied`, `stale_base`). A store on its offline
  /// copy, or whose remote fails during the save, refuses with `offline` /
  /// `token_expired`. The written file is the store's from then on.
  ///
  /// **A re-keyed file** (part-key-rotation): a further vault's [stored]
  /// that does not open with the keys held but opens with the keys the
  /// primary lists for it now (the app wrote the new keys into the primary
  /// first) is taken as re-keyed; the primary's own re-keyed file carries its
  /// new keys in [newKeys] (the set holds them from then on; a further
  /// vault's save naming [newKeys] is refused `malformed`, reason `keys`).
  /// A re-keyed file is written as it is, never merged: [baseRevision] must
  /// be the held copy (or none) and the file must not have moved since,
  /// otherwise `denied`, `stale_base`. The store's keys are the new ones
  /// from then on.
  Future<TomSecretsSaveResult> save(
    String name,
    Uint8List stored, {
    String? baseRevision,
    TomSecretsHeldKeys? newKeys,
    Uint8List? recipients,
  }) async {
    if (newKeys != null && name != _primaryName) {
      newKeys.dispose();
      throw TomSecretsSaveException(
        'malformed',
        'only the primary\'s save carries its new keys',
        reason: 'keys',
      );
    }
    // A vault not served, opened for editing by vaultFile.
    final editOnly =
        !_opened.containsKey(name) &&
        _editOnly.containsKey(name) &&
        unserved.any((k) => k.name == name);
    final opened = _opened[name] ?? (editOnly ? _editOnly[name] : null);
    final keys = name == _primaryName
        ? _primaryKeys
        : (_held[name] ?? (editOnly ? _editHeld[name] : null));
    final machine = _machine;
    if (opened == null || keys == null || machine == null) {
      newKeys?.dispose();
      final state = _status[name]?.state;
      if (state == TomSecretsStoreState.needsUnlock) {
        throw TomSecretsSaveException(
          'needs_unlock',
          'the store needs its own unlock',
        );
      }
      if (state == TomSecretsStoreState.unavailable) {
        throw TomSecretsSaveException(
          'unavailable',
          'the store could not be opened',
          reason: 'no_cache',
        );
      }
      throw TomSecretsSaveException('not_found', 'no open store $name');
    }
    final state = _status[name]?.state;
    if (state == TomSecretsStoreState.needsUnlock &&
        (_status[name]?.keyChanged ?? false)) {
      newKeys?.dispose();
      throw TomSecretsSaveException(
        'needs_unlock',
        'the key of $name changed on another device; its copy is read-only '
            'until the new key is here',
        reason: 'key_changed',
      );
    }
    if (newKeys == null && _slotsMissing(opened, keys)) {
      // A guided rotation's migration period (part-key-rotation, DP-84): the
      // file keeps a slot for a repository key this device does not hold.
      // It reads the file with the old key, but a write would drop the new
      // key's slot, so it writes nothing until the new key is here.
      throw TomSecretsSaveException(
        'needs_unlock',
        'the repository key of $name changed on another device; it is '
            'read-only here until the new key is here',
        reason: 'key_changed',
      );
    }
    if (state == TomSecretsStoreState.offline ||
        state == TomSecretsStoreState.tokenExpired) {
      newKeys?.dispose();
      throw TomSecretsSaveException(
        state!.wireName,
        state == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    final locator = opened.locator;
    final outerKey = keys.outerKeyText;
    final held = _revisionOf(opened);
    final opens = await _opening(
      name,
      opened,
      stored,
      keys,
      newKeys: newKeys,
      editOnly: editOnly,
    );
    if (opens.newKeys != null) {
      return _saveRekeyed(
        name,
        opened,
        stored,
        opens,
        baseRevision: baseRevision,
        editOnly: editOnly,
        machine: machine,
        recipients: recipients,
      );
    }
    if (recipients != null) {
      throw TomSecretsSaveException(
        'malformed',
        'a recipients file goes with a re-keyed save only (a member '
            'removed); write it alone with vault.recipients.set',
        reason: 'recipients',
      );
    }
    final edited = opens.file;
    var base = opened.stored;
    var merged = false;
    var conflicts = 0;
    final TomSecretsCommitted committed;
    try {
      if (baseRevision != null && baseRevision != held) {
        final own = name == _primaryName ? _ownWrites[baseRevision] : null;
        if (own != null) {
          // The app edited a copy the service has since written over itself
          // (grants, their last use): merged onto the held copy, that copy
          // the base.
          final result = tomSecretsMergeVaults(
            base: await opener.decode(
              locator,
              own,
              keys.credentials,
              outerKey: outerKey,
            ),
            ours: edited,
            theirs: opened.file,
            location: '$name (save)',
          );
          merged = true;
          conflicts = result.conflicts.length;
        } else {
          // The app edited the file as it is now, newer than the held copy:
          // that is the base it is written over.
          final current = await opener.read(locator);
          if (tomSecretsBlobId(current) != baseRevision) {
            throw TomSecretsSaveException(
              'denied',
              'the file has moved past the revision the app edited',
              reason: 'stale_base',
            );
          }
          base = current;
        }
      }
      committed = await opener.commit(
        locator,
        edited,
        base: base,
        credentials: keys.credentials,
        outerKey: outerKey,
        // Unmerged, the app's file is written as it saved it.
        stored: merged ? null : stored,
      );
    } on TomSecretsSaveException catch (e) {
      final head = e.reason == 'history_rewritten' && !editOnly
          ? opener.rewrittenHeadOf(locator)
          : null;
      if (head != null) {
        _rewritten[name] = head;
        _setStatus(
          name,
          locator,
          _status[name]?.state ?? TomSecretsStoreState.current,
          from: opened,
        );
      }
      rethrow;
    } on Object catch (e) {
      final failure = tomSecretsFetchFailureOf(e);
      if (failure == null) rethrow;
      final now = TomSecretsStoreState.offlineFor(failure);
      if (!editOnly) {
        _fetched(name, failure);
        _setStatus(
          name,
          locator,
          now,
          from: opened,
          source: opened.source == 'file' ? null : 'cache',
        );
      }
      throw TomSecretsSaveException(
        now.wireName,
        now == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    final written = committed.opened;
    if (editOnly) {
      _editOnly[name] = written;
      return TomSecretsSaveResult(
        revision: _revisionOf(written),
        merged: merged || committed.merged,
        conflicts: conflicts + committed.conflicts,
      );
    }
    _opened[name] = written;
    if (name == _primaryName) _primary = written;
    _fetched(name, null);
    _setStatus(name, locator, TomSecretsStoreState.current, from: written);
    _rebuildOpened(machine);
    return TomSecretsSaveResult(
      revision: _revisionOf(written),
      merged: merged || committed.merged,
      conflicts: conflicts + committed.conflicts,
    );
  }

  /// [stored] of a save of [name] opened, with the keys it opens with: the
  /// keys [held] (`newKeys` null), else for a re-keyed file (part-key-
  /// rotation) the primary's [newKeys] when given, or for a further vault the
  /// keys the primary lists for it now ([listed]). Throws `malformed`
  /// (`bytes`) when [stored] opens with none of them.
  Future<_Opening> _opening(
    String name,
    TomSecretsOpenedVault opened,
    Uint8List stored,
    TomSecretsHeldKeys held, {
    TomSecretsHeldKeys? newKeys,
    required bool editOnly,
  }) async {
    Future<KdbxFile?> open(TomSecretsHeldKeys keys) async {
      try {
        return await opener.decode(
          opened.locator,
          stored,
          keys.credentials,
          outerKey: keys.outerKeyText,
        );
      } on Object {
        return null;
      }
    }

    Never unreadable() => throw TomSecretsSaveException(
      'malformed',
      'the file does not open with the store\'s keys',
      reason: 'bytes',
    );

    if (newKeys != null) {
      final file = await open(newKeys);
      if (file == null) {
        newKeys.dispose();
        unreadable();
      }
      return (file: file, newKeys: newKeys, listed: null);
    }
    final file = await open(held);
    if (file != null) return (file: file, newKeys: null, listed: null);
    if (name == _primaryName) unreadable();
    final listed = editOnly
        ? unserved.where((k) => k.name == name).firstOrNull
        : TomSecretsPrimaryVaults(_primary!.file).byName(name);
    if (listed == null || listed.locator != opened.locator) unreadable();
    final keys = TomSecretsHeldKeys.fromVaultKeys(listed);
    final rekeyed = await open(keys);
    if (rekeyed == null) {
      keys.dispose();
      unreadable();
    }
    return (file: rekeyed, newKeys: keys, listed: listed);
  }

  /// Writes the re-keyed file of [name] ([_rekeyed]) as it is and makes its
  /// new keys the store's.
  Future<TomSecretsSaveResult> _saveRekeyed(
    String name,
    TomSecretsOpenedVault opened,
    Uint8List stored,
    _Opening rekey, {
    required String? baseRevision,
    required bool editOnly,
    required TomSecretsMachine machine,
    Uint8List? recipients,
  }) async {
    final locator = opened.locator;
    final TomSecretsCommitted committed;
    try {
      if (baseRevision != null && baseRevision != _revisionOf(opened)) {
        throw TomSecretsSaveException(
          'denied',
          'a re-keyed file is written over the copy the service holds only',
          reason: 'stale_base',
        );
      }
      committed = await opener.rekey(
        locator,
        rekey.file,
        base: opened.stored,
        stored: stored,
        outerKey: rekey.newKeys!.outerKeyText,
        beside: {_recipientsName(locator): ?recipients},
      );
    } on TomSecretsSaveException {
      rekey.newKeys!.dispose();
      rethrow;
    } on Object catch (e) {
      rekey.newKeys!.dispose();
      final failure = tomSecretsFetchFailureOf(e);
      if (failure == null) rethrow;
      final now = TomSecretsStoreState.offlineFor(failure);
      throw TomSecretsSaveException(
        now.wireName,
        now == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    final written = committed.opened;
    final revision = _revisionOf(written);
    if (editOnly) {
      _editOnly[name] = written;
      _editHeld.remove(name)?.dispose();
      _editHeld[name] = rekey.newKeys!;
      _editListed[name] = rekey.listed!;
      return TomSecretsSaveResult(revision: revision, rekeyed: true);
    }
    if (name == _primaryName) {
      _primaryKeys?.dispose();
      _primaryKeys = rekey.newKeys!;
      _primary = written;
      // Copies under the old keys are no merge base any more.
      _ownWrites.clear();
    } else {
      _held.remove(name)?.dispose();
      _held[name] = rekey.newKeys!;
      _keys[name] = rekey.listed!;
    }
    _opened[name] = written;
    _fetched(name, null);
    _setStatus(name, locator, TomSecretsStoreState.current, from: written);
    _rebuildOpened(machine);
    return TomSecretsSaveResult(revision: revision, rekeyed: true);
  }

  /// The name of a shared vault's recipients file beside the vault at
  /// [locator] (part-sharing): `<vault>.keys.age`.
  static String _recipientsName(String locator) => tomSecretsRecipientsFileName(
    TomSecretsVaultLocator.parse(locator).fileName,
  );

  /// The locator of the store [name]: the primary's, an open or edit-only
  /// store's, else the primary's vault list's; null when none names it.
  String? locatorOf(String name) {
    if (name == _primaryName) return _primary?.locator;
    final opened = _opened[name] ?? _editOnly[name];
    if (opened != null) return opened.locator;
    final primary = _primary;
    if (primary == null) return null;
    return TomSecretsPrimaryVaults(primary.file).byName(name)?.locator;
  }

  /// **[C]** The recipients file of the shared vault at [location]
  /// (`vault.recipients`, part-sharing) and its revision, or null when the
  /// vault has none. Throws the storage's failure when the remote cannot be
  /// reached or refuses the token.
  Future<({Uint8List bytes, String revision})?> recipientsAt(String location) {
    final parsed = TomSecretsVaultLocator.parse(location);
    if (parsed is! TomSecretsFileLocator &&
        parsed is! TomSecretsGitHubLocator) {
      throw TomSecretsSaveException(
        'malformed',
        'a shared vault is a file: or a github: vault',
        reason: 'location',
      );
    }
    return opener.readBeside(location, _recipientsName(location));
  }

  /// **[C]** Writes the recipients file of the store [name]
  /// (`vault.recipients.set`, part-sharing: a member added), over
  /// [baseRevision] (the file as read; null when there is none yet).
  /// Answers its new revision. Refused (`not_found`) for a store nobody
  /// names, (`denied`, `stale_base`) when the file moved since it was read.
  Future<String> setRecipients(
    String name,
    Uint8List bytes, {
    required String? baseRevision,
  }) async {
    final location = _besideLocation(name);
    return _beside(
      () => opener.writeBeside(
        location,
        _recipientsName(location),
        bytes,
        baseRevision: baseRevision,
      ),
    );
  }

  /// The locator of the store [name] for a file beside it: refused while
  /// locked (`locked`) and for a store nobody names (`not_found`).
  String _besideLocation(String name) {
    if (_primary == null) {
      throw TomSecretsSaveException('locked', 'unlock the service first');
    }
    final location = locatorOf(name);
    if (location == null) {
      throw TomSecretsSaveException('not_found', 'no store $name');
    }
    return location;
  }

  /// Runs [io] on files beside a store; a remote that cannot be reached or
  /// refuses the token becomes the store state's refusal (`offline`,
  /// `token_expired`).
  Future<T> _beside<T>(Future<T> Function() io) async {
    try {
      return await io();
    } on TomSecretsSaveException {
      rethrow;
    } on Object catch (e) {
      final failure = tomSecretsFetchFailureOf(e);
      if (failure == null) rethrow;
      final now = TomSecretsStoreState.offlineFor(failure);
      throw TomSecretsSaveException(
        now.wireName,
        now == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
  }

  /// **[C]** The packages in the inbox folders beside the store [name]
  /// (`inbox.list`, part-sharing): every file `inbox/<member-id>/<file>`,
  /// by member id and file name, with its revision; other files below
  /// `inbox/` are left out.
  Future<List<({String member, String name, String revision})>> inbox(
    String name,
  ) async {
    final location = _besideLocation(name);
    final files = await _beside(
      () => opener.listBeside(location, tomSecretsInboxFolder),
    );
    return [
      for (final MapEntry(:key, :value) in files.entries)
        if (key.split('/') case [
          _,
          final member,
          final file,
        ] when tomSecretsIsInboxMember(member))
          (member: member, name: file, revision: value),
    ]..sort(
      (a, b) => '${a.member}/${a.name}'.compareTo('${b.member}/${b.name}'),
    );
  }

  /// **[C]** The package [file] in the inbox of [member] beside the store
  /// [name] (`inbox.read`), or null when it is not there.
  Future<({Uint8List bytes, String revision})?> inboxFile(
    String name,
    String member,
    String file,
  ) {
    final location = _besideLocation(name);
    final path = _inboxPath(member, file);
    return _beside(() => opener.readBeside(location, path));
  }

  /// **[C]** Puts [bytes] (an `age` package) into the inbox of each of
  /// [members] beside the store [name] (`inbox.put`) under one new name
  /// `<date>-<random>.age` (UTC at [now]); a `github:` vault one commit per
  /// member. Answers the name.
  Future<String> inboxPut(
    String name,
    List<String> members,
    Uint8List bytes, {
    DateTime? now,
  }) async {
    final location = _besideLocation(name);
    final file = tomSecretsNewInboxName(now: now);
    for (final member in members) {
      final path = _inboxPath(member, file);
      await _beside(
        () => opener.writeBeside(location, path, bytes, baseRevision: null),
      );
    }
    return file;
  }

  /// **[C]** Deletes [files] (member id and file name) from the inbox
  /// folders beside the store [name] (`inbox.delete`: a package imported or
  /// declined, or past its 30 days); a `github:` vault in one commit. A file
  /// that is gone already is skipped.
  Future<void> inboxDelete(
    String name,
    List<({String member, String name})> files,
  ) async {
    final location = _besideLocation(name);
    final paths = [for (final f in files) _inboxPath(f.member, f.name)];
    if (paths.isEmpty) return;
    await _beside(() => opener.deleteBeside(location, paths));
  }

  static String _inboxPath(String member, String file) {
    try {
      return tomSecretsInboxPath(member, file);
    } on ArgumentError catch (e) {
      throw TomSecretsSaveException(
        'malformed',
        '${e.message}: ${e.invalidValue}',
        reason: 'inbox',
      );
    }
  }

  /// Moves the open store [name] to [location] (`vault.move`, protocol.md
  /// 6.4): its outer encryption added (`.kdbx` -> `.kdbx.tsmx`) or removed,
  /// so [location] is its locator with the suffix added or taken off and
  /// nothing else changed (`malformed`, `location` otherwise). [stored] is
  /// the file as [location] keeps it and must open with [newKeys] (its
  /// `outerKey` for a `.tsmx` location); [baseRevision], when given, must be
  /// the held copy (`denied`, `stale_base`). The file is written there and
  /// the old one removed through the opener's [TomSecretsVaultOpener.move];
  /// a refused or failed move leaves the old file in place. Then a further
  /// vault's entry in the primary gets the new locator and keys (the primary
  /// written), or the primary's own keys are [newKeys]; the store is served
  /// from the new place. Answers the new revision. The set holds [newKeys]
  /// from then on (disposed on a refusal).
  Future<String> move(
    String name,
    String location,
    Uint8List stored, {
    String? baseRevision,
    required TomSecretsHeldKeys newKeys,
  }) async {
    final opened = _opened[name];
    final machine = _machine;
    Never refuse(String kind, String message, [String? reason]) {
      newKeys.dispose();
      throw TomSecretsSaveException(kind, message, reason: reason);
    }

    if (opened == null || machine == null) {
      refuse('not_found', 'no open store $name');
    }
    final state = _status[name]?.state;
    if (state == TomSecretsStoreState.offline ||
        state == TomSecretsStoreState.tokenExpired) {
      refuse(
        state!.wireName,
        state == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    final from = opened.locator;
    final expected = from.endsWith(tomSecretsOuterSuffix)
        ? from.substring(0, from.length - tomSecretsOuterSuffix.length)
        : '$from$tomSecretsOuterSuffix';
    if (location != expected) {
      refuse(
        'malformed',
        'a store moves only to its locator with $tomSecretsOuterSuffix added '
            'or removed: $expected',
        'location',
      );
    }
    final outer = location.endsWith(tomSecretsOuterSuffix);
    if (outer != (newKeys.outerKeyText != null)) {
      refuse(
        'malformed',
        outer
            ? 'an outer-encrypted file needs its repository key'
            : 'a file without outer encryption takes no repository key',
        'keys',
      );
    }
    if (baseRevision != null && baseRevision != _revisionOf(opened)) {
      refuse(
        'denied',
        'the store has moved past the revision the app read',
        'stale_base',
      );
    }
    final KdbxFile file;
    try {
      file = await opener.decode(
        location,
        stored,
        newKeys.credentials,
        outerKey: newKeys.outerKeyText,
      );
    } on Object {
      refuse(
        'malformed',
        'the file does not open with the keys at the new location',
        'bytes',
      );
    }
    final TomSecretsOpenedVault moved;
    try {
      moved = await opener.move(
        from,
        location,
        file,
        base: opened.stored,
        stored: stored,
        credentials: newKeys.credentials,
        outerKey: newKeys.outerKeyText,
      );
    } on TomSecretsSaveException {
      newKeys.dispose();
      rethrow;
    } on Object catch (e) {
      newKeys.dispose();
      final failure = tomSecretsFetchFailureOf(e);
      if (failure == null) rethrow;
      final now = TomSecretsStoreState.offlineFor(failure);
      throw TomSecretsSaveException(
        now.wireName,
        now == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    _opened[name] = moved;
    if (name == _primaryName) {
      _primaryKeys?.dispose();
      _primaryKeys = newKeys;
      _primary = moved;
      _ownWrites.clear();
    } else {
      final list = TomSecretsPrimaryVaults(_primary!.file);
      final old = list.byName(name);
      list.put(
        TomSecretsVaultKeys(
          name: name,
          locator: location,
          password: newKeys.password?.reveal(),
          keyFile: newKeys.keyFile?.withRevealed(Uint8List.fromList),
          outerKey: newKeys.outerKeyText,
          githubToken: old?.githubToken,
          githubTokenExpires: old?.githubTokenExpires,
          expires: old?.expires,
        ),
      );
      _held.remove(name)?.dispose();
      _held[name] = newKeys;
      _keys[name] = list.byName(name)!;
      try {
        await writePrimary();
      } on Object catch (e) {
        // Not delivered: the entry waits in the held copy and the next
        // refresh writes it (primaryWritePending).
        if (tomSecretsFetchFailureOf(e) == null) rethrow;
      }
    }
    _fetched(name, null);
    _setStatus(name, location, TomSecretsStoreState.current, from: moved);
    _rebuildOpened(machine);
    return _revisionOf(moved);
  }

  /// Creates the further vault [name] at [location] (`vault.create`,
  /// protocol.md 6.4): [stored] is the new file as [location] keeps it and
  /// must open with [keys] (its `outerKey` exactly for a `.tsmx` location)
  /// and carry readable metadata. [name] must be a store name the primary
  /// does not use yet (`malformed`, `store`), [location] a vault locator
  /// that is neither the primary's nor a listed vault's (`malformed`,
  /// `location`), and [githubToken] is only for a `github:` vault outside
  /// the primary's repository (`malformed`, `githubToken`). The file is
  /// written first, through the opener's [TomSecretsVaultOpener.create]
  /// (`denied`, `target_exists` when a file is there); only then is the
  /// vault listed in the primary with [keys], [githubToken] and [keysDue]
  /// (its Expires) and the primary written. The vault is served from then
  /// on, unless this machine's device settings name the stores it serves
  /// and not this one. Answers the new vault's revision. The set holds
  /// [keys] from then on (disposed on a refusal or when it is not served).
  Future<String> create(
    String name,
    String location,
    Uint8List stored, {
    required TomSecretsHeldKeys keys,
    String? githubToken,
    DateTime? keysDue,
    Uint8List? recipients,
  }) async {
    final primary = _primary;
    final machine = _machine;
    Never refuse(String kind, String message, [String? reason]) {
      keys.dispose();
      throw TomSecretsSaveException(kind, message, reason: reason);
    }

    if (primary == null || machine == null || _primaryName == null) {
      refuse('locked', 'unlock the service first');
    }
    final list = TomSecretsPrimaryVaults(primary.file);
    if (!_storeNamePattern.hasMatch(name) || name.length > 64) {
      refuse('malformed', '$name is not a store name', 'store');
    }
    if (name == _primaryName || list.byName(name) != null) {
      refuse('malformed', 'the primary names a store $name already', 'store');
    }
    final TomSecretsVaultLocator parsed;
    try {
      parsed = TomSecretsVaultLocator.parse(location);
    } on Object {
      refuse('malformed', '$location is not a vault locator', 'location');
    }
    if (parsed is! TomSecretsFileLocator &&
        parsed is! TomSecretsGitHubLocator) {
      refuse(
        'malformed',
        'a new vault is a file: or a github: vault',
        'location',
      );
    }
    if (location == primary.locator ||
        list.list().any((k) => k.locator == location)) {
      refuse('malformed', 'another vault is at $location already', 'location');
    }
    final outer = location.endsWith(tomSecretsOuterSuffix);
    if (outer != (keys.outerKeyText != null)) {
      refuse(
        'malformed',
        outer
            ? 'an outer-encrypted file needs its repository key'
            : 'a file without outer encryption takes no repository key',
        'keys',
      );
    }
    if (githubToken != null) {
      final own = TomSecretsVaultLocator.parse(primary.locator);
      final inPrimaryRepository =
          parsed is TomSecretsGitHubLocator &&
          own is TomSecretsGitHubLocator &&
          own.repositorySlug == parsed.repositorySlug;
      if (parsed is! TomSecretsGitHubLocator || inPrimaryRepository) {
        refuse(
          'malformed',
          'a GitHub token is kept only for a github: vault outside the '
              'primary\'s repository',
          'githubToken',
        );
      }
    }
    final KdbxFile file;
    try {
      file = await opener.decode(
        location,
        stored,
        keys.credentials,
        outerKey: keys.outerKeyText,
      );
      TomSecretsMetadata.read(file);
    } on Object {
      refuse('malformed', 'the file does not open with the keys', 'bytes');
    }
    final entry = TomSecretsVaultKeys(
      name: name,
      locator: location,
      password: keys.password?.reveal(),
      keyFile: keys.keyFile?.withRevealed(Uint8List.fromList),
      outerKey: keys.outerKeyText,
      githubToken: githubToken,
      expires: keysDue?.toUtc(),
    );
    // Listed before the file is written, so the token source finds a token
    // the request brings for another repository; taken out again when the
    // write fails.
    list.put(entry);
    final TomSecretsOpenedVault created;
    try {
      created = await opener.create(
        location,
        file,
        stored: stored,
        credentials: keys.credentials,
        outerKey: keys.outerKeyText,
      );
    } on TomSecretsSaveException {
      list.remove(name);
      keys.dispose();
      rethrow;
    } on Object catch (e) {
      list.remove(name);
      keys.dispose();
      final failure = tomSecretsFetchFailureOf(e);
      if (failure == null) rethrow;
      final now = TomSecretsStoreState.offlineFor(failure);
      throw TomSecretsSaveException(
        now.wireName,
        now == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    try {
      await writePrimary();
    } on Object catch (e) {
      // Not delivered: the entry waits in the held copy and the next
      // refresh writes it (primaryWritePending).
      if (tomSecretsFetchFailureOf(e) == null) rethrow;
    }
    if (recipients != null) {
      // A shared vault's recipients file beside it (part-sharing): a second
      // commit, after the vault is listed; a failure leaves the vault
      // listed and served, and the app writes the file again with
      // vault.recipients.set (the failure is thrown once it is served).
      try {
        await opener.writeBeside(
          location,
          _recipientsName(location),
          recipients,
          baseRevision: null,
        );
      } on Object catch (e, trace) {
        _serveCreated(name, location, created, keys, machine);
        final failure = tomSecretsFetchFailureOf(e);
        if (failure == null) Error.throwWithStackTrace(e, trace);
        throw TomSecretsSaveException(
          TomSecretsStoreState.offlineFor(failure).wireName,
          'the vault is created; its recipients file could not be written',
          reason: 'recipients',
        );
      }
    }
    _serveCreated(name, location, created, keys, machine);
    return _revisionOf(created);
  }

  /// Serves the vault [name] just created at [location] with [keys], unless
  /// this machine does not serve it (then [keys] are dropped: it stays
  /// editable through vaultKeys / vaultFile as a vault not served).
  void _serveCreated(
    String name,
    String location,
    TomSecretsOpenedVault created,
    TomSecretsHeldKeys keys,
    TomSecretsMachine machine,
  ) {
    final served = _served;
    if (served != null && !served.contains(name)) {
      keys.dispose();
      return;
    }
    _keys[name] = TomSecretsPrimaryVaults(_primary!.file).byName(name)!;
    _held.remove(name)?.dispose();
    _held[name] = keys;
    _opened[name] = created;
    _fetched(name, null);
    _setStatus(name, location, TomSecretsStoreState.current, from: created);
    _rebuildOpened(machine);
  }

  /// The stores whose branch was rewritten and that wait for the user's
  /// answer, by the rewritten head.
  Map<String, String> get rewritten => Map.unmodifiable(_rewritten);

  /// Answers the rewritten branch of store [name] (`history.resolve`,
  /// protocol.md 6.3): [takeRemote] takes the remote file as it is (the
  /// refused edit is dropped), otherwise the held copy is merged over the
  /// remote and committed on top of it. The store is served from what the
  /// answer leaves. Throws [TomSecretsSaveException] (`not_found` when no
  /// answer is awaited, `offline` / `token_expired` when the remote cannot
  /// be reached, `denied` when the branch was rewritten again).
  Future<TomSecretsSaveResult> resolveRewritten(
    String name, {
    required bool takeRemote,
  }) async {
    final opened = _opened[name];
    final machine = _machine;
    if (!_rewritten.containsKey(name) || opened == null || machine == null) {
      throw TomSecretsSaveException(
        'not_found',
        'no rewritten branch waits for an answer on $name',
      );
    }
    final locator = opened.locator;
    final TomSecretsCommitted committed;
    try {
      committed = await opener.resolveRewritten(
        locator,
        takeRemote: takeRemote,
      );
    } on TomSecretsSaveException {
      _rewritten[name] = opener.rewrittenHeadOf(locator) ?? _rewritten[name]!;
      rethrow;
    } on Object catch (e) {
      final failure = tomSecretsFetchFailureOf(e);
      if (failure == null) rethrow;
      final now = TomSecretsStoreState.offlineFor(failure);
      throw TomSecretsSaveException(
        now.wireName,
        now == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    _rewritten.remove(name);
    final written = committed.opened;
    _opened[name] = written;
    if (name == _primaryName) _primary = written;
    _fetched(name, null);
    _setStatus(name, locator, TomSecretsStoreState.current, from: written);
    _rebuildOpened(machine);
    return TomSecretsSaveResult(
      revision: _revisionOf(written),
      merged: committed.merged,
      conflicts: committed.conflicts,
    );
  }

  static String _revisionOf(TomSecretsOpenedVault v) =>
      v.revision ?? tomSecretsBlobId(v.stored);

  /// Fetches the stores that are due ([force]: every store, the `reload`)
  /// and reopens those whose file moved, with the keys held (part-service,
  /// Refresh): a file that did not move costs one request and is not
  /// reopened; a fetch that fails for a network reason or a refused token
  /// keeps the copy held (`offline`, `token_expired`, served from the
  /// cache); a file whose key changed goes to `needs_unlock`; a further
  /// vault the primary lists anew, or with new keys, is opened with them,
  /// and one it no longer lists is dropped. The index is rebuilt when
  /// anything was reopened or dropped. Edits of the primary the service
  /// could not write before ([primaryWritePending]) are written first, and
  /// the primary is not fetched while they wait. Nothing is done while
  /// locked, and a lock during the refresh ends it.
  Future<TomSecretsRefreshReport> refresh({bool force = false}) async {
    final primaryName = _primaryName;
    final primaryKeys = _primaryKeys;
    final machine = _machine;
    if (primaryName == null || primaryKeys == null || machine == null) {
      return const TomSecretsRefreshReport();
    }
    final epoch = _epoch;
    final before = Map.of(_status);
    final reopened = <String>[];
    var rebuild = false;
    if (_primaryPending) {
      // The service's own edits the last write could not deliver go first:
      // a fetch now would drop them.
      try {
        await writePrimary();
        reopened.add(primaryName);
      } on Object {
        // Still not delivered: the held copy stays served.
      }
      if (epoch != _epoch) return const TomSecretsRefreshReport();
    }
    if (!_primaryPending && _due(primaryName, force)) {
      final outcome = await _refreshStore(
        primaryName,
        _primary!.locator,
        primaryKeys.credentials,
        primaryKeys.outerKeyText,
        isPrimary: true,
      );
      if (epoch != _epoch) return const TomSecretsRefreshReport();
      if (outcome == _Outcome.reopened) {
        reopened.add(primaryName);
        rebuild = true;
      }
    }
    final served = _served;
    final listed = {
      for (final keys in TomSecretsPrimaryVaults(_primary!.file).list())
        if (served == null || served.contains(keys.name)) keys.name: keys,
    };
    // A vault opened for editing whose listing went or changed is dropped;
    // the app reads it again.
    // Keys that changed while the file did not move keep the copy and the
    // keys held: a rotation in progress, whose re-keyed save takes the new
    // keys. A file that moved is read again by the app.
    for (final name in [..._editOnly.keys]) {
      final now = unserved.where((k) => k.name == name).firstOrNull;
      final old = _editListed[name];
      final copy = _editOnly[name]!;
      var drop = now == null || old == null || old.locator != now.locator;
      if (!drop && !_sameKeys(old, now)) {
        try {
          drop = await opener.revision(now.locator) != _revisionOf(copy);
        } on Object {
          drop = true;
        }
        if (epoch != _epoch) return const TomSecretsRefreshReport();
      }
      if (drop) _dropEditOnly(name);
    }
    for (final name in [..._status.keys]) {
      if (name == primaryName || listed.containsKey(name)) continue;
      _status.remove(name);
      _next.remove(name);
      _keys.remove(name);
      _held.remove(name)?.dispose();
      if (_opened.remove(name) != null) rebuild = true;
    }
    for (final keys in listed.values) {
      final name = keys.name;
      final old = _keys[name];
      final changed = old == null || !_sameKeys(old, keys);
      if (!changed &&
          (_status[name]?.state == TomSecretsStoreState.needsUnlock ||
              !_due(name, force))) {
        continue;
      }
      _keys[name] = keys;
      final heldBefore = _held[name];
      final wasOpen = _opened.containsKey(name);
      var use = changed ? null : heldBefore;
      TomSecretsHeldKeys? fresh;
      use ??= fresh = TomSecretsHeldKeys.fromVaultKeys(keys);
      var outcome = await _refreshStore(
        name,
        keys.locator,
        use.credentials,
        use.outerKeyText,
        reopen: changed,
      );
      if (epoch != _epoch) {
        fresh?.dispose();
        return const TomSecretsRefreshReport();
      }
      if (fresh != null &&
          wasOpen &&
          heldBefore != null &&
          old?.locator == keys.locator &&
          _status[name]?.state == TomSecretsStoreState.needsUnlock) {
        // A rotation in progress (part-key-rotation): the primary lists the
        // new keys, the re-keyed file is still to be saved. While the keys
        // held still open the file it stays served with them; the re-keyed
        // save makes the listed keys the store's.
        final kept = await _refreshStore(
          name,
          keys.locator,
          heldBefore.credentials,
          heldBefore.outerKeyText,
          reopen: true,
        );
        if (epoch != _epoch) {
          fresh.dispose();
          return const TomSecretsRefreshReport();
        }
        if (_opened.containsKey(name)) {
          fresh.dispose();
          fresh = null;
          outcome = kept;
        }
      }
      if (fresh != null) {
        if (_opened.containsKey(name)) {
          // The listed keys are the vault's now, also for a copy held
          // while offline.
          _held.remove(name)?.dispose();
          _held[name] = fresh;
          _restatusSlots(name);
        } else {
          fresh.dispose();
        }
      }
      if (outcome != _Outcome.unchanged) rebuild = true;
      if (outcome == _Outcome.reopened) reopened.add(name);
    }
    if (rebuild) _rebuildOpened(machine);
    return TomSecretsRefreshReport(
      states: [
        for (final status in _status.values)
          if (before[status.name]?.state != status.state ||
              before[status.name]?.wireSource != status.wireSource)
            status,
      ],
      reopened: reopened,
    );
  }

  /// **[C]** Whether the `.tsmx` file of [opened] is written under a newer
  /// repository key than [keys] hold: its first slot (writers put the
  /// newest key first) is for a key this device does not hold, because
  /// another device switched a guided rotation of its repository key and
  /// this one has only the old key. The old key's slot left after the
  /// finish is no such case: the device holding the new key writes the file
  /// again without it.
  static bool _slotsMissing(
    TomSecretsOpenedVault opened,
    TomSecretsHeldKeys keys,
  ) {
    if (!opened.locator.endsWith(tomSecretsOuterSuffix)) return false;
    final List<String> slots;
    try {
      slots = tomSecretsOuterKeyIds(opened.stored);
    } on Object {
      return false;
    }
    return slots.isNotEmpty && !keys.outerKeyIds.contains(slots.first);
  }

  /// The status of [name] again, its `keyChanged` from the keys held now
  /// (the refresh took up new keys after it reopened the file).
  void _restatusSlots(String name) {
    final status = _status[name];
    final opened = _opened[name];
    if (status == null || opened == null) return;
    final keyChanged =
        opened.offlineReason is TomSecretsKeyChangedException ||
        _slotsMissingFor(name, opened);
    if (keyChanged == status.keyChanged) return;
    _status[name] = TomSecretsStoreStatus(
      name: status.name,
      state: status.state,
      locator: status.locator,
      source: status.source,
      fetchedAt: status.fetchedAt,
      revision: status.revision,
      notPushed: status.notPushed,
      rewrittenHead: status.rewrittenHead,
      keyChanged: keyChanged,
    );
  }

  bool _slotsMissingFor(String name, TomSecretsOpenedVault opened) {
    final keys = name == _primaryName ? _primaryKeys : _held[name];
    return keys != null && _slotsMissing(opened, keys);
  }

  static bool _sameKeys(TomSecretsVaultKeys a, TomSecretsVaultKeys b) =>
      a.locator == b.locator &&
      a.password == b.password &&
      a.outerKey == b.outerKey &&
      a.previousOuterKey == b.previousOuterKey &&
      _sameBytes(a.keyFile, b.keyFile);

  static bool _sameBytes(Uint8List? a, Uint8List? b) {
    if (a == null || b == null) return a == b;
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  void _setStatus(
    String name,
    String locator,
    TomSecretsStoreState state, {
    TomSecretsOpenedVault? from,
    String? source,
    bool keyChanged = false,
  }) => _status[name] = TomSecretsStoreStatus(
    name: name,
    state: state,
    locator: locator,
    source: source ?? from?.source,
    fetchedAt: from?.fetchedAt,
    revision: from == null ? null : _revisionOf(from),
    rewrittenHead: _rewritten[name],
    keyChanged:
        keyChanged || from?.offlineReason is TomSecretsKeyChangedException,
  );

  /// Fetches store [name] at [locator] and reopens it when its file moved
  /// ([reopen]: always, its keys changed).
  Future<_Outcome> _refreshStore(
    String name,
    String locator,
    Credentials credentials,
    String? outerKey, {
    bool reopen = false,
    bool isPrimary = false,
  }) async {
    final held = _opened[name];
    // A rewritten branch waits for the user's answer: a reopen would take
    // the remote without asking.
    if (_rewritten.containsKey(name)) return _Outcome.unchanged;
    try {
      if (!reopen &&
          held != null &&
          _status[name]?.state == TomSecretsStoreState.current &&
          await opener.revision(locator) == _revisionOf(held)) {
        _fetched(name, null);
        return _Outcome.unchanged;
      }
      final opened = await opener.open(
        locator,
        credentials,
        outerKey: outerKey,
      );
      final keyChanged = opened.offlineReason is TomSecretsKeyChangedException;
      if (keyChanged && isPrimary) {
        final taken = await _openPrimaryWithNext(name, locator);
        if (taken != null) return taken;
      }
      _fetched(name, keyChanged ? null : opened.offlineReason);
      if (opened.offlineReason != null && held != null) {
        // The copy held is at least as new as the cached one.
        _setStatus(
          name,
          locator,
          opened.state,
          from: held,
          source: 'cache',
          keyChanged: keyChanged,
        );
        return _Outcome.unchanged;
      }
      if (!reopen && held != null && _revisionOf(held) == _revisionOf(opened)) {
        _setStatus(
          name,
          locator,
          opened.state,
          from: opened,
          keyChanged: _slotsMissingFor(name, opened),
        );
        return _Outcome.unchanged;
      }
      _opened[name] = opened;
      if (isPrimary) _primary = opened;
      _setStatus(
        name,
        locator,
        opened.state,
        from: opened,
        keyChanged: _slotsMissingFor(name, opened),
      );
      return _Outcome.reopened;
    } on Object catch (e) {
      final keyChanged =
          e is KdbxInvalidKeyException || e is TomKeyRequiredException;
      if (keyChanged && isPrimary) {
        final taken = await _openPrimaryWithNext(name, locator);
        if (taken != null) return taken;
      }
      if (keyChanged) {
        _fetched(name, null);
      } else {
        _fetched(name, e);
      }
      final fetchFailed = !keyChanged && tomSecretsIsFetchFailure(e);
      if (held != null && keyChanged && !isPrimary) {
        // Another device re-keyed it (part-key-rotation): the copy held,
        // under the old key, is served read-only until the new key is
        // listed in the primary.
        _setStatus(
          name,
          locator,
          TomSecretsStoreState.needsUnlock,
          from: held,
          source: 'cache',
          keyChanged: true,
        );
        return _Outcome.unchanged;
      }
      if (held != null && (fetchFailed || isPrimary)) {
        // The primary is never dropped while unlocked: its held copy is
        // served until the next unlock.
        _setStatus(
          name,
          locator,
          keyChanged
              ? TomSecretsStoreState.needsUnlock
              : fetchFailed
              ? TomSecretsStoreState.offlineFor(e)
              : TomSecretsStoreState.unavailable,
          from: held,
          source: fetchFailed && held.source != 'file' ? 'cache' : null,
        );
        return _Outcome.unchanged;
      }
      _setStatus(
        name,
        locator,
        keyChanged
            ? TomSecretsStoreState.needsUnlock
            : TomSecretsStoreState.unavailable,
      );
      return _opened.remove(name) == null
          ? _Outcome.unchanged
          : _Outcome.dropped;
    }
  }

  /// **[C]** Opens the primary [name] at [locator] with its next keys
  /// ([primaryNextKeys]) after it no longer opened with the keys held:
  /// another device switched a guided rotation of them. On success the set
  /// holds the next keys ([onPrimaryKeysChanged]) and answers `reopened`;
  /// null when there are none, or they do not open it either.
  Future<_Outcome?> _openPrimaryWithNext(String name, String locator) async {
    final next = primaryNextKeys;
    if (next == null) return null;
    final keys = primaryKeysWith(next);
    if (keys == null) return null;
    try {
      final opened = await opener.open(
        locator,
        keys.credentials,
        outerKey: keys.outerKeyText,
      );
      if (opened.offlineReason != null) {
        keys.dispose();
        return null;
      }
      _primaryKeys?.dispose();
      _primaryKeys = keys;
      _opened[name] = opened;
      _primary = opened;
      _fetched(name, null);
      _setStatus(name, locator, opened.state, from: opened);
      await onPrimaryKeysChanged?.call(keys);
      return _Outcome.reopened;
    } on Object {
      keys.dispose();
      return null;
    }
  }

  void _rebuild(List<TomSecretsStore> stores, TomSecretsMachine machine) {
    _machine = machine;
    final config =
        TomSecretsMetadata.read(_primary!.file).config ??
        TomSecretsConfig.builtIn();
    _resolver = TomSecretsResolver(
      stores: stores,
      config: config,
      machine: machine,
    );
  }

  /// Whether [credentials] open the primary: the copy held while unlocked,
  /// else the primary at [locator] read again.
  Future<bool> checkPrimary(String locator, Credentials credentials) async {
    try {
      final primary = _primary;
      if (primary != null) {
        final codec = primary.locator.endsWith(tomSecretsOuterSuffix);
        if (!codec) {
          await KdbxFormat().read(primary.stored, credentials);
          return true;
        }
      }
      await opener.open(locator, credentials);
      return true;
    } on KdbxInvalidKeyException {
      return false;
    }
  }

  void _disposeHeld() {
    _ownWrites.clear();
    for (final name in [..._editOnly.keys, ..._editHeld.keys]) {
      _dropEditOnly(name);
    }
    for (final keys in _held.values) {
      keys.dispose();
    }
    _held.clear();
  }

  /// Drops every opened file, the index and the keys (zeroing the held
  /// ones).
  void lock() {
    _epoch++;
    opener.drop();
    _primaryPending = false;
    _next.clear();
    _served = null;
    _primary = null;
    _primaryName = null;
    _primaryKeys?.dispose();
    _primaryKeys = null;
    _opened.clear();
    _status.clear();
    _keys.clear();
    _rewritten.clear();
    _disposeHeld();
    _machine = null;
    _resolver = null;
  }
}

/// **[C]** [name] checked as a path beside a vault: a file name, or
/// segments below the vault's folder joined by `/` (`inbox/<id>/<file>`);
/// an empty segment, `.`, `..` or a backslash is refused.
String tomSecretsBesidePath(String name) {
  final segments = name.split('/');
  if (name.contains(r'\') ||
      segments.any((s) => s.isEmpty || s == '.' || s == '..')) {
    throw ArgumentError.value(name, 'name', 'not a path beside the vault');
  }
  return name;
}
