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
      reason is TomTokenRejectedException || reason is TomTokenRequiredException
      ? tokenExpired
      : offline;
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
  Future<void> _write(String locator, Uint8List stored) async {
    final path = _path(locator);
    final temp = File('$path.tmp');
    await temp.writeAsBytes(stored, flush: true);
    await temp.rename(path);
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
        ? await encode(locator, file, outerKey: outerKey)
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
  void drop() {}
}

/// The key material the service holds for one store while unlocked, masked
/// (part-service, Memory hygiene): what opens it, and what `vaultKeySet`
/// hands the app (protocol.md 6.4). [dispose] zeroes it.
final class TomSecretsHeldKeys {
  /// Keys of a [password], a [keyFile] (its bytes) and an [outerKey] (the
  /// repository key, base64).
  TomSecretsHeldKeys({this.password, this.keyFile, this.outerKey});

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
        outerKey: keys.outerKey == null
            ? null
            : TomProtectedValue.of(keys.outerKey!),
      );

  /// The master password, or null.
  final TomProtectedValue? password;

  /// The key file's bytes, or null.
  final TomProtectedValue? keyFile;

  /// The repository's outer key (base64), or null.
  final TomProtectedValue? outerKey;

  /// The same keys with [outerKey].
  TomSecretsHeldKeys withOuterKey(TomProtectedValue? outerKey) =>
      TomSecretsHeldKeys(
        password: password,
        keyFile: keyFile,
        outerKey: outerKey,
      );

  /// The credentials that open the vault (`Credentials.composite` takes the
  /// key file's bytes and derives the key itself).
  Credentials get credentials => Credentials.composite(
    password?.withRevealed(
      (b) => ProtectedValue.fromBinary(Uint8List.fromList(b)),
    ),
    keyFile?.withRevealed(Uint8List.fromList),
  );

  /// The outer key as the codec takes it.
  String? get outerKeyText => outerKey?.reveal();

  /// The `keys` object of `vaultKeySet`: `password`, `keyFile` (base64) and
  /// `outerKey` (base64), written into the frame from their bytes.
  Map<String, Object?> toWire() => {
    'password': ?(password == null
        ? null
        : TomSecretsSecretSlot.ofText(password!)),
    'keyFile': ?(keyFile == null
        ? null
        : TomSecretsSecretSlot.ofBytes(keyFile!)),
    'outerKey': ?(outerKey == null
        ? null
        : TomSecretsSecretSlot.ofText(outerKey!)),
  };

  /// Zeroes every key.
  void dispose() {
    password?.dispose();
    keyFile?.dispose();
    outerKey?.dispose();
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
  });

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
  });

  /// The store's name.
  final String name;

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

  /// Whether the primary is open.
  bool get isUnlocked => _primary != null;

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
    final opened = await opener.open(locator, keys.credentials);
    _primary = opened;
    _primaryKeys = keys;
    return opened;
  }

  /// The further vaults the primary lists, as last read.
  List<TomSecretsVaultKeys> get listed => _keys.values.toList();

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
        outerKey: keys.outerKey,
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
      _fetched(name, opened.offlineReason);
      _opened[name] = opened;
      _status[name] = TomSecretsStoreStatus(
        name: name,
        state: opened.state,
        locator: locator,
        source: opened.source,
        fetchedAt: opened.fetchedAt,
        revision: _revisionOf(opened),
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
      outerKey: listed.outerKey,
    );
    _held.remove(name)?.dispose();
    _held[name] = keys.withOuterKey(
      listed.outerKey == null ? null : TomProtectedValue.of(listed.outerKey!),
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
  ({String location, String revision, Uint8List stored}) vaultFile(
    String name,
  ) {
    final opened = _opened[name];
    if (opened == null) throw StateError(name);
    return (
      location: opened.locator,
      revision: _revisionOf(opened),
      stored: opened.stored,
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
    for (final name in stores ?? const <String>[]) {
      if (!open.contains(name)) throw StateError(name);
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
    ];
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
  Future<TomSecretsSaveResult> save(
    String name,
    Uint8List stored, {
    String? baseRevision,
  }) async {
    final opened = _opened[name];
    final keys = name == _primaryName ? _primaryKeys : _held[name];
    final machine = _machine;
    if (opened == null || keys == null || machine == null) {
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
    if (state == TomSecretsStoreState.offline ||
        state == TomSecretsStoreState.tokenExpired) {
      throw TomSecretsSaveException(
        state!.wireName,
        state == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    final locator = opened.locator;
    final outerKey = keys.outerKeyText;
    final KdbxFile edited;
    try {
      edited = await opener.decode(
        locator,
        stored,
        keys.credentials,
        outerKey: outerKey,
      );
    } on Object {
      throw TomSecretsSaveException(
        'malformed',
        'the file does not open with the store\'s keys',
        reason: 'bytes',
      );
    }
    final held = _revisionOf(opened);
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
    } on TomSecretsSaveException {
      rethrow;
    } on Object catch (e) {
      final failure = tomSecretsFetchFailureOf(e);
      if (failure == null) rethrow;
      final now = TomSecretsStoreState.offlineFor(failure);
      _fetched(name, failure);
      _setStatus(
        name,
        locator,
        now,
        from: opened,
        source: opened.source == 'file' ? null : 'cache',
      );
      throw TomSecretsSaveException(
        now.wireName,
        now == TomSecretsStoreState.offline
            ? 'the store cannot be reached'
            : 'the store\'s token was refused',
      );
    }
    final written = committed.opened;
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
        null,
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
      var use = changed ? null : _held[name];
      TomSecretsHeldKeys? fresh;
      use ??= fresh = TomSecretsHeldKeys.fromVaultKeys(keys);
      final outcome = await _refreshStore(
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
      if (fresh != null) {
        if (_opened.containsKey(name)) {
          // The listed keys are the vault's now, also for a copy held
          // while offline.
          _held.remove(name)?.dispose();
          _held[name] = fresh;
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

  static bool _sameKeys(TomSecretsVaultKeys a, TomSecretsVaultKeys b) =>
      a.locator == b.locator &&
      a.password == b.password &&
      a.outerKey == b.outerKey &&
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
  }) => _status[name] = TomSecretsStoreStatus(
    name: name,
    state: state,
    locator: locator,
    source: source ?? from?.source,
    fetchedAt: from?.fetchedAt,
    revision: from == null ? null : _revisionOf(from),
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
      _fetched(name, opened.offlineReason);
      if (opened.offlineReason != null && held != null) {
        // The copy held is at least as new as the cached one.
        _setStatus(name, locator, opened.state, from: held, source: 'cache');
        return _Outcome.unchanged;
      }
      if (!reopen && held != null && _revisionOf(held) == _revisionOf(opened)) {
        _setStatus(name, locator, opened.state, from: opened);
        return _Outcome.unchanged;
      }
      _opened[name] = opened;
      if (isPrimary) _primary = opened;
      _setStatus(name, locator, opened.state, from: opened);
      return _Outcome.reopened;
    } on Object catch (e) {
      final keyChanged =
          e is KdbxInvalidKeyException || e is TomKeyRequiredException;
      if (keyChanged) {
        _fetched(name, null);
      } else {
        _fetched(name, e);
      }
      final fetchFailed = !keyChanged && tomSecretsIsFetchFailure(e);
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
    _disposeHeld();
    _machine = null;
    _resolver = null;
  }
}
