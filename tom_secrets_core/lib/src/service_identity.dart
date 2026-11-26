// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service's identity key (protocol.md 6.1): a signing key pair of its
/// own, ML-DSA-65 with Ed25519 as one composite signature (RFC 10073,
/// `tom_pqc`), made at the service's first start and kept in its data
/// directory; the one-time key (ML-KEM-768 with X25519) a claim's secrets
/// are sealed to; and the two primitives an admin checks them with, run in
/// this process ([TomSecretsPqcIdentityCrypto]) or, for `tsm`, by the
/// service executable's helper mode ([tomSecretsIdentityHelperAnswer]).
/// The formats, the pins and the decision are `tom_secrets_client`'s
/// (`admin.dart`), which links no post-quantum code.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:tom_pqc/tom_pqc.dart';
import 'package:tom_secrets_client/admin.dart';

/// The file of the service's identity key in its data directory.
const String tomSecretsServiceIdentityFile = 'service-identity.json';

/// How many key-change statements a service keeps and presents: a pin of a
/// key that many rotations back still follows to the current one.
const int tomSecretsIdentityChangesKept = 8;

/// The identity primitives run in this process.
final class TomSecretsPqcIdentityCrypto implements TomSecretsIdentityCrypto {
  /// The primitives.
  const TomSecretsPqcIdentityCrypto();

  @override
  Future<bool> verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List context,
  }) => MlDsa65Ed25519.verify(message, signature, publicKey, context: context);

  @override
  Future<({Uint8List ciphertext, Uint8List sharedSecret})> encapsulate(
    Uint8List publicKey,
  ) async {
    final sealed = await MlKem768X25519.encapsulate(publicKey);
    try {
      return (
        ciphertext: sealed.ciphertext,
        sharedSecret: sealed.sharedSecret.extractBytes(),
      );
    } finally {
      sealed.sharedSecret.dispose();
    }
  }
}

/// One request of the identity helper mode answered: `verify`
/// (`{publicKey, message, signature, context}` → `{valid}`) or
/// `encapsulate` (`{publicKey}` → `{ciphertext, sharedSecret}`), everything
/// in base64; anything else is `{error}`.
Future<Map<String, Object?>> tomSecretsIdentityHelperAnswer(
  Object? request,
) async {
  const crypto = TomSecretsPqcIdentityCrypto();
  try {
    if (request is! Map) return {'error': 'malformed'};
    Uint8List bytes(String name) => base64.decode(request[name] as String);
    switch (request['op']) {
      case 'verify':
        return {
          'valid': await crypto.verify(
            publicKey: bytes('publicKey'),
            message: bytes('message'),
            signature: bytes('signature'),
            context: bytes('context'),
          ),
        };
      case 'encapsulate':
        final sealed = await crypto.encapsulate(bytes('publicKey'));
        return {
          'ciphertext': base64.encode(sealed.ciphertext),
          'sharedSecret': base64.encode(sealed.sharedSecret),
        };
      default:
        return {'error': 'unsupported'};
    }
  } on Object catch (e) {
    return {'error': e.runtimeType.toString()};
  }
}

/// Where the secret half of a service identity key is kept, beside the
/// public half in its file (protocol.md 6.1): a store of the platform that
/// only the service process opens (the macOS keychain item trusting the
/// service's code signature, Windows' DPAPI). Without one the secret is in
/// the file itself, which the file's mode protects.
abstract interface class TomSecretsIdentitySecretStore {
  /// Its name, in the key file and in `status` (`keychain`, `dpapi`).
  String get name;

  /// Keeps [secret], the secret key of the key whose file is [file], and
  /// answers what the file records of it (`store` is added). Throws
  /// [TomSecretsIdentityKeyUnavailable] when the store cannot take it now
  /// (a locked keychain in an SSH session): the key stays in the file.
  Future<Map<String, Object?>> seal(Uint8List secret, File file);

  /// The secret [sealed] names. Throws [TomSecretsIdentityKeyUnavailable]
  /// when the store does not give it (refused, locked, gone).
  Future<Uint8List> open(Map<String, Object?> sealed, File file);

  /// Removes what [sealed] names (a replaced key's secret).
  Future<void> forget(Map<String, Object?> sealed, File file);
}

/// The secret of the service's identity key cannot be read where it is
/// kept: the start stops (it is never replaced silently).
final class TomSecretsIdentityKeyUnavailable implements Exception {
  /// Why, for the operator.
  const TomSecretsIdentityKeyUnavailable(this.message);

  /// Why.
  final String message;

  @override
  String toString() => 'TomSecretsIdentityKeyUnavailable: $message';
}

/// The service's identity key pair, with the statements of the keys it
/// replaced.
final class TomSecretsServiceIdentityKey {
  TomSecretsServiceIdentityKey._(
    this._pair,
    this.created,
    this.changes,
    this._file, {
    TomSecretsIdentitySecretStore? store,
    Map<String, Object?>? sealed,
    String? kept,
  }) : _store = store,
       _sealed = sealed,
       _kept = kept;

  final MlDsa65Ed25519KeyPair _pair;
  final File? _file;
  final TomSecretsIdentitySecretStore? _store;
  // What the file records of the secret when a store keeps it.
  Map<String, Object?>? _sealed;
  final String? _kept;

  /// When this key was made.
  final DateTime created;

  /// The statements of earlier keys, oldest first: each key signed the one
  /// that replaced it.
  final List<TomSecretsIdentityChange> changes;

  /// The public key.
  Uint8List get publicKey => _pair.publicKey;

  /// The public key's words.
  String get words => tomSecretsIdentityWords(publicKey);

  /// Where the secret key is kept: the store's name (`keychain`, `dpapi`)
  /// while one keeps it, else the place the caller named for the file
  /// (`system` for a system install), else `file`.
  String get keptIn => _sealed != null ? _store!.name : (_kept ?? 'file');

  /// The file of the key.
  File? get file => _file;

  /// A new key pair, kept nowhere (a test, or a service without a data
  /// directory).
  static Future<TomSecretsServiceIdentityKey> generate({DateTime? now}) async =>
      TomSecretsServiceIdentityKey._(
        await MlDsa65Ed25519.generateKeyPair(),
        (now ?? DateTime.now()).toUtc(),
        const [],
        null,
      );

  /// The key of the service whose data directory is [dataDirectory]: read
  /// from [tomSecretsServiceIdentityFile] there, made and written (the
  /// user's alone) when there is none. It stays the same across restarts
  /// and updates. Throws [FileSystemException] for a file that cannot be
  /// read as a key: it is never replaced silently, since every admin has
  /// pinned the key it held.
  ///
  /// With [write] false a new key is not written yet ([store] does): a
  /// machine being set up names its key in the pairing and keeps it only
  /// once the set-up succeeded.
  ///
  /// With [secretStore] the secret key is kept there (a key whose secret is
  /// in the file moves there, when the store takes it). A secret kept in a
  /// store this call is not given, or that the store does not give, throws
  /// [TomSecretsIdentityKeyUnavailable].
  static Future<TomSecretsServiceIdentityKey> loadOrCreate(
    String dataDirectory, {
    DateTime? now,
    bool write = true,
    TomSecretsIdentitySecretStore? secretStore,
  }) => loadOrCreateFile(
    File(
      '$dataDirectory${Platform.pathSeparator}$tomSecretsServiceIdentityFile',
    ),
    now: now,
    write: write,
    secretStore: secretStore,
  );

  /// As [loadOrCreate], for the key file [file] itself. [kept] names the
  /// place for `status` when the secret is in the file (`system`: a
  /// directory only the system-installed service reaches). With
  /// [previous], the key file the service used before (its data
  /// directory's, before a system install): when [file] is not there yet,
  /// that key signs a new one kept in [file], so every admin that pinned it
  /// follows, and the previous file is removed.
  static Future<TomSecretsServiceIdentityKey> loadOrCreateFile(
    File file, {
    DateTime? now,
    bool write = true,
    TomSecretsIdentitySecretStore? secretStore,
    String? kept,
    File? previous,
  }) async {
    if (file.existsSync()) {
      return _read(file, secretStore, kept);
    }
    if (previous != null && previous.existsSync()) {
      final old = await _read(previous, null, null);
      final moved = await old._rotateInto(
        file,
        secretStore: secretStore,
        kept: kept,
        now: now,
      );
      previous.deleteSync();
      return moved;
    }
    final key = TomSecretsServiceIdentityKey._(
      await MlDsa65Ed25519.generateKeyPair(),
      (now ?? DateTime.now()).toUtc(),
      const [],
      file,
      store: secretStore,
      kept: kept,
    );
    if (write) await key._save();
    return key;
  }

  static Future<TomSecretsServiceIdentityKey> _read(
    File file,
    TomSecretsIdentitySecretStore? store,
    String? kept,
  ) async {
    final Map json;
    try {
      json = jsonDecode(file.readAsStringSync()) as Map;
    } on FileSystemException {
      rethrow;
    } on Object {
      throw FileSystemException(
        'the service\'s identity key cannot be read',
        file.path,
      );
    }
    final sealed = json['secret'];
    final Uint8List secret;
    try {
      if (sealed is Map) {
        final name = sealed['store'];
        if (store == null || store.name != name) {
          throw TomSecretsIdentityKeyUnavailable(
            'the identity key is kept in the $name store, which this '
            'program does not open',
          );
        }
        secret = await store.open(sealed.cast(), file);
      } else {
        secret = base64.decode(json['secretKey'] as String);
      }
    } on TomSecretsIdentityKeyUnavailable {
      rethrow;
    } on Object {
      throw FileSystemException(
        'the service\'s identity key cannot be read',
        file.path,
      );
    }
    final MlDsa65Ed25519KeyPair pair;
    try {
      pair = await MlDsa65Ed25519.keyPairFromSecretKey(
        SecretBytes.fromBytes(secret),
      );
    } on Object {
      throw FileSystemException(
        'the service\'s identity key cannot be read',
        file.path,
      );
    } finally {
      secret.fillRange(0, secret.length, 0);
    }
    final key = TomSecretsServiceIdentityKey._(
      pair,
      DateTime.tryParse('${json['created']}')?.toUtc() ??
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      [
        for (final c in json['changes'] as List? ?? const [])
          ?TomSecretsIdentityChange.fromJson(c),
      ],
      file,
      store: store,
      sealed: sealed is Map ? sealed.cast() : null,
      kept: kept,
    );
    // A secret still in the file moves into the store, when it takes it.
    if (sealed is! Map && store != null) await key._save();
    return key;
  }

  /// Writes the file; with a store, the secret goes there (when the store
  /// cannot take it now, it stays in the file).
  Future<void> _save() async {
    final file = _file;
    if (file == null) return;
    final store = _store;
    if (store != null) {
      final secret = _pair.secretKey.extractBytes();
      try {
        final sealed = await store.seal(secret, file);
        _writeFile(file, {...sealed, 'store': store.name});
        _sealed = {...sealed, 'store': store.name};
        return;
      } on TomSecretsIdentityKeyUnavailable {
        // The store cannot take it now: the file keeps it, as without one.
      } finally {
        secret.fillRange(0, secret.length, 0);
      }
    }
    _writeFile(file, null);
    _sealed = null;
  }

  /// Writes the key into its file with the secret in it (a key of
  /// [loadOrCreate] without `write`). The service moves the secret into
  /// its store at its next start.
  void store() {
    final file = _file;
    if (file != null) _writeFile(file, null);
  }

  void _writeFile(File file, Map<String, Object?>? sealed) {
    file.parent.createSync(recursive: true);
    final secret = sealed == null ? _pair.secretKey.extractBytes() : null;
    final temp = File('${file.path}.tmp');
    try {
      temp.writeAsStringSync(
        '${jsonEncode({
          'version': 1,
          if (secret != null) 'secretKey': base64.encode(secret) else 'secret': sealed,
          'publicKey': base64.encode(publicKey),
          'created': created.toIso8601String(),
          'changes': [for (final c in changes) c.toJson()],
        })}\n',
        flush: true,
      );
    } finally {
      secret?.fillRange(0, secret.length, 0);
    }
    // The user's alone before it carries its name (a system install's
    // directory is the group's; the file keeps the group's read bit).
    if (!Platform.isWindows) {
      Process.runSync('chmod', [_kept == 'system' ? '640' : '600', temp.path]);
    }
    temp.renameSync(file.path);
  }

  /// The composite signature of [message] with [context].
  Future<Uint8List> sign(Uint8List message, Uint8List context) =>
      MlDsa65Ed25519.sign(message, _pair.secretKey, context: context);

  /// What the service answers an `identify` with: its key, a new
  /// [oneTimeKey]'s public key, the signature over the exchange and the
  /// statements of its earlier keys.
  Future<Map<String, Object?>> present({
    required List<int> clientNonce,
    required List<int> serviceNonce,
    required int serviceStart,
    required TomSecretsOneTimeKey oneTimeKey,
  }) async => {
    'publicKey': base64.encode(publicKey),
    'oneTimeKey': base64.encode(oneTimeKey.publicKey),
    'signature': base64.encode(
      await sign(
        tomSecretsIdentityMessage(
          clientNonce: clientNonce,
          serviceNonce: serviceNonce,
          serviceStart: serviceStart,
          oneTimeKey: oneTimeKey.publicKey,
        ),
        tomSecretsIdentityContext,
      ),
    ),
    if (changes.isNotEmpty) 'changes': [for (final c in changes) c.toJson()],
  };

  /// A new key in this one's place: this key signs it (the statement an
  /// admin that pinned this key follows to the new one), the file is
  /// rewritten, and this key's secret is gone. Answers the new key.
  Future<TomSecretsServiceIdentityKey> rotate({DateTime? now}) =>
      _rotateInto(_file, secretStore: _store, kept: _kept, now: now);

  Future<TomSecretsServiceIdentityKey> _rotateInto(
    File? file, {
    TomSecretsIdentitySecretStore? secretStore,
    String? kept,
    DateTime? now,
  }) async {
    final next = await MlDsa65Ed25519.generateKeyPair();
    final statement = TomSecretsIdentityChange(
      from: publicKey,
      to: next.publicKey,
      signature: await sign(next.publicKey, tomSecretsIdentityChangeContext),
    );
    final all = [...changes, statement];
    final rotated = TomSecretsServiceIdentityKey._(
      next,
      (now ?? DateTime.now()).toUtc(),
      all.length > tomSecretsIdentityChangesKept
          ? all.sublist(all.length - tomSecretsIdentityChangesKept)
          : all,
      file,
      store: secretStore,
      kept: kept,
    );
    await rotated._save();
    // The replaced key's secret leaves its store once the new one is kept
    // (the new one may be in the same item: then it was replaced already).
    final oldSealed = _sealed;
    final oldStore = _store;
    final sameItem =
        rotated._sealed != null &&
        oldStore?.name == secretStore?.name &&
        _file?.path == file?.path;
    if (oldSealed != null && oldStore != null && !sameItem) {
      try {
        await oldStore.forget(oldSealed, _file!);
      } on Object {
        // A leftover item names a key no longer presented.
      }
    }
    dispose();
    return rotated;
  }

  /// Wipes the secret key.
  void dispose() => _pair.dispose();
}

/// The one-time key of one admin connection: a claim's secrets are sealed
/// to it, and only the process that made it opens them.
final class TomSecretsOneTimeKey {
  TomSecretsOneTimeKey._(this._pair);

  final MlKem768X25519KeyPair _pair;

  /// A new key pair.
  static Future<TomSecretsOneTimeKey> generate() async =>
      TomSecretsOneTimeKey._(await MlKem768X25519.generateKeyPair());

  /// The public key.
  Uint8List get publicKey => _pair.publicKey;

  /// The shared secret of [ciphertext] (32 bytes), for
  /// `tomSecretsOpenClaim`.
  Future<Uint8List> decapsulate(Uint8List ciphertext) async {
    final secret = await MlKem768X25519.decapsulate(
      ciphertext,
      _pair.secretKey,
    );
    try {
      return secret.extractBytes();
    } finally {
      secret.dispose();
    }
  }

  /// Wipes the secret key.
  void dispose() => _pair.secretKey.dispose();
}
