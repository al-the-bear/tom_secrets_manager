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
import 'package:tom_secrets_core/tom_secrets_core.dart';

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

/// Opens and saves vault files by locator.
abstract interface class TomSecretsVaultOpener {
  /// Opens [locator] with [credentials]; [outerKey] (base64) opens a `.tsmx`
  /// file. Throws [KdbxInvalidKeyException] for wrong credentials.
  Future<TomSecretsOpenedVault> open(
    String locator,
    Credentials credentials, {
    String? outerKey,
  });

  /// Writes [file] back to [locator] (the service's own edits, e.g. a new
  /// device key in the primary).
  Future<void> save(String locator, KdbxFile file, {String? outerKey});
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
    final path = _path(locator);
    final stored = await File(path).readAsBytes();
    final codec = _codec(path, outerKey);
    final kdbx = codec == null ? stored : await codec.decode(stored);
    return TomSecretsOpenedVault(
      locator: locator,
      file: await KdbxFormat().read(kdbx, credentials),
      stored: stored,
      fetchedAt: (await File(path).lastModified()).toUtc(),
    );
  }

  @override
  Future<void> save(String locator, KdbxFile file, {String? outerKey}) async {
    final path = _path(locator);
    final codec = _codec(path, outerKey);
    final bytes = await file.save();
    final stored = codec == null ? bytes : await codec.encode(bytes);
    final temp = File('$path.tmp');
    await temp.writeAsBytes(stored, flush: true);
    await temp.rename(path);
  }
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
  final Map<String, TomSecretsOpenedVault> _opened = {};
  final Map<String, TomSecretsStoreStatus> _status = {};
  final Map<String, TomSecretsVaultKeys> _keys = {};
  TomSecretsResolver? _resolver;

  /// Whether the primary is open.
  bool get isUnlocked => _primary != null;

  /// The open primary vault, or null.
  TomSecretsOpenedVault? get primary => _primary;

  /// The resolver over the opened stores, or null while locked.
  TomSecretsResolver? get resolver => _resolver;

  /// Every store's status, the primary first.
  List<TomSecretsStoreStatus> get status => _status.values.toList();

  /// The status of store [name], or null.
  TomSecretsStoreStatus? statusOf(String name) => _status[name];

  /// Opens the primary at [locator] with [credentials] (phase one of the
  /// unlock: the device settings container's key may live in it).
  Future<TomSecretsOpenedVault> openPrimary(
    String locator,
    Credentials credentials,
  ) async {
    final opened = await opener.open(locator, credentials);
    _primary = opened;
    return opened;
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
    for (final keys in TomSecretsPrimaryVaults(primary.file).list()) {
      if (served != null && !served.contains(keys.name)) continue;
      _keys[keys.name] = keys;
      final store = await _open(
        keys.name,
        keys.locator,
        keys.credentials,
        outerKey: keys.outerKey,
      );
      if (store != null) stores.add(store);
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

  /// Opens store [name] (in `needs_unlock`) with a password of its own.
  /// Throws [KdbxInvalidKeyException] for wrong credentials and
  /// [StateError] for a store the primary does not name.
  Future<void> unlockStore(
    String name,
    Credentials credentials, {
    required TomSecretsMachine machine,
  }) async {
    final keys = _keys[name];
    if (keys == null) throw StateError('no store $name');
    final opened = await opener.open(
      keys.locator,
      credentials,
      outerKey: keys.outerKey,
    );
    _opened[name] = opened;
    _status[name] = TomSecretsStoreStatus(
      name: name,
      state: TomSecretsStoreState.current,
      locator: keys.locator,
      source: opened.source,
      fetchedAt: opened.fetchedAt,
      revision: _revisionOf(opened),
    );
    _rebuild([
      for (final e in _opened.entries)
        TomSecretsStore.fromFile(
          e.value.file,
          name: e.value == _primary ? null : e.key,
          fileName: TomSecretsVaultLocator.parse(e.value.locator).fileName,
        ),
    ], machine);
  }

  static String _revisionOf(TomSecretsOpenedVault v) =>
      v.revision ?? tomSecretsBlobId(v.stored);

  void _rebuild(List<TomSecretsStore> stores, TomSecretsMachine machine) {
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

  /// Drops every opened file, the index and the keys.
  void lock() {
    _primary = null;
    _opened.clear();
    _status.clear();
    _keys.clear();
    _resolver = null;
  }
}
