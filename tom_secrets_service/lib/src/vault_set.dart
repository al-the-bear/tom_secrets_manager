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
    show TomKeyRequiredException;
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
}

/// A vault file as opened.
final class TomSecretsOpenedVault {
  /// [file] read from [locator] at [revision], from [source] (`file`,
  /// `github`, `cache`) fetched at [fetchedAt].
  TomSecretsOpenedVault({
    required this.locator,
    required this.file,
    required this.stored,
    this.revision,
    this.source = 'file',
    this.fetchedAt,
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

  /// Writes [stored] to [locator], replacing the file at once.
  Future<void> write(String locator, Uint8List stored);
}

/// `file:` vaults: read and written on the local disk (a `.tsmx` file
/// through the outer layer). `github:` vaults are opened by the service's
/// GitHub opener (the refresh, part-service).
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

  static TomSecretsOuterCodec? _codec(String path, String? outerKey) =>
      path.endsWith(tomSecretsOuterSuffix)
      ? TomSecretsOuterCodec(
          path: path.split(RegExp(r'[/\\]')).last,
          keys: [
            if (outerKey != null) TomSecretsRepositoryKey.fromBase64(outerKey),
          ],
        )
      : null;

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
  Future<KdbxFile> decode(
    String locator,
    Uint8List stored,
    Credentials credentials, {
    String? outerKey,
  }) async {
    final codec = _codec(_path(locator), outerKey);
    final kdbx = codec == null ? stored : await codec.decode(stored);
    return KdbxFormat().read(kdbx, credentials);
  }

  @override
  Future<Uint8List> encode(
    String locator,
    KdbxFile file, {
    String? outerKey,
  }) async {
    final codec = _codec(_path(locator), outerKey);
    final bytes = await file.save();
    return codec == null ? bytes : codec.encode(bytes);
  }

  @override
  Future<void> write(String locator, Uint8List stored) async {
    final path = _path(locator);
    final temp = File('$path.tmp');
    await temp.writeAsBytes(stored, flush: true);
    await temp.rename(path);
  }
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

/// The unlocked vaults.
final class TomSecretsVaultSet {
  /// A set opening vaults through [opener].
  TomSecretsVaultSet({required this.opener});

  /// The opener.
  final TomSecretsVaultOpener opener;

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

  /// Writes the open primary back to its file (the service's own edit, e.g.
  /// a new device key kept in it); the held copy then is what was written.
  Future<void> writePrimary() async {
    final primary = _primary!;
    final stored = await opener.encode(primary.locator, primary.file);
    await opener.write(primary.locator, stored);
    _primary = TomSecretsOpenedVault(
      locator: primary.locator,
      file: primary.file,
      stored: stored,
      source: primary.source,
      fetchedAt: primary.fetchedAt,
    );
  }

  /// Opens the further vaults the primary names (phase two), only those in
  /// [served] when given, and builds the index for [machine]. A vault that
  /// does not open is marked `needs_unlock` (its key) or `unavailable` (any
  /// other failure); the others are still served.
  Future<void> openStores({
    required TomSecretsMachine machine,
    List<String>? served,
  }) async {
    final primary = _primary!;
    final primaryStore = TomSecretsStore.fromFile(
      primary.file,
      fileName: TomSecretsVaultLocator.parse(primary.locator).fileName,
    );
    final stores = <TomSecretsStore>[primaryStore];
    _primaryName = primaryStore.name;
    _status
      ..clear()
      ..[primaryStore.name] = TomSecretsStoreStatus(
        name: primaryStore.name,
        state: TomSecretsStoreState.current,
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
      _opened[name] = opened;
      _status[name] = TomSecretsStoreStatus(
        name: name,
        state: TomSecretsStoreState.current,
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
    } on Object {
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
    _status[name] = TomSecretsStoreStatus(
      name: name,
      state: TomSecretsStoreState.current,
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
  /// the app edited. It must open with the store's keys. When the file is
  /// still at [baseRevision] (or no base is given) it is written as it is;
  /// when the file has moved but [baseRevision] is the copy the service
  /// holds, the app's copy is merged three-way into the file as it is now,
  /// with the held copy as the base; any other base is refused
  /// (`denied`, `stale_base`). The store is reopened from what was written.
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
    final current = await opener.read(locator);
    final currentRevision = tomSecretsBlobId(current);
    final held = _revisionOf(opened);
    var toWrite = stored;
    var merged = false;
    var conflicts = 0;
    if (baseRevision != null && baseRevision != currentRevision) {
      if (baseRevision != held) {
        throw TomSecretsSaveException(
          'denied',
          'the file has moved past the revision the app edited',
          reason: 'stale_base',
        );
      }
      final theirs = await opener.decode(
        locator,
        current,
        keys.credentials,
        outerKey: outerKey,
      );
      final result = tomSecretsMergeVaults(
        base: opened.file,
        ours: edited,
        theirs: theirs,
        location: '$name (save)',
      );
      merged = true;
      conflicts = result.conflicts.length;
      toWrite = await opener.encode(locator, edited, outerKey: outerKey);
    }
    await opener.write(locator, toWrite);
    final reopened = await opener.open(
      locator,
      keys.credentials,
      outerKey: outerKey,
    );
    _opened[name] = reopened;
    if (name == _primaryName) _primary = reopened;
    final revision = _revisionOf(reopened);
    _status[name] = TomSecretsStoreStatus(
      name: name,
      state: TomSecretsStoreState.current,
      locator: locator,
      source: reopened.source,
      fetchedAt: reopened.fetchedAt,
      revision: revision,
    );
    _rebuildOpened(machine);
    return TomSecretsSaveResult(
      revision: revision,
      merged: merged,
      conflicts: conflicts,
    );
  }

  static String _revisionOf(TomSecretsOpenedVault v) =>
      v.revision ?? tomSecretsBlobId(v.stored);

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
    for (final keys in _held.values) {
      keys.dispose();
    }
    _held.clear();
  }

  /// Drops every opened file, the index and the keys (zeroing the held
  /// ones).
  void lock() {
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
