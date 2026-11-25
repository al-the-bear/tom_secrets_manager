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

/// The service's identity key pair, with the statements of the keys it
/// replaced.
final class TomSecretsServiceIdentityKey {
  TomSecretsServiceIdentityKey._(
    this._pair,
    this.created,
    this.changes,
    this._file,
  );

  final MlDsa65Ed25519KeyPair _pair;
  final File? _file;

  /// When this key was made.
  final DateTime created;

  /// The statements of earlier keys, oldest first: each key signed the one
  /// that replaced it.
  final List<TomSecretsIdentityChange> changes;

  /// The public key.
  Uint8List get publicKey => _pair.publicKey;

  /// The public key's words.
  String get words => tomSecretsIdentityWords(publicKey);

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
  static Future<TomSecretsServiceIdentityKey> loadOrCreate(
    String dataDirectory, {
    DateTime? now,
    bool write = true,
  }) async {
    final file = File(
      '$dataDirectory${Platform.pathSeparator}$tomSecretsServiceIdentityFile',
    );
    if (file.existsSync()) {
      try {
        final json = jsonDecode(file.readAsStringSync()) as Map;
        final secret = base64.decode(json['secretKey'] as String);
        final pair = await MlDsa65Ed25519.keyPairFromSecretKey(
          SecretBytes.fromBytes(secret),
        );
        secret.fillRange(0, secret.length, 0);
        return TomSecretsServiceIdentityKey._(
          pair,
          DateTime.tryParse('${json['created']}')?.toUtc() ??
              DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
          [
            for (final c in json['changes'] as List? ?? const [])
              ?TomSecretsIdentityChange.fromJson(c),
          ],
          file,
        );
      } on FileSystemException {
        rethrow;
      } on Object {
        throw FileSystemException(
          'the service\'s identity key cannot be read',
          file.path,
        );
      }
    }
    final key = TomSecretsServiceIdentityKey._(
      await MlDsa65Ed25519.generateKeyPair(),
      (now ?? DateTime.now()).toUtc(),
      const [],
      file,
    );
    if (write) key._write();
    return key;
  }

  /// Writes the key into its data directory (a key of [loadOrCreate]
  /// without `write`).
  void store() => _write();

  void _write() {
    final file = _file;
    if (file == null) return;
    file.parent.createSync(recursive: true);
    final secret = _pair.secretKey.extractBytes();
    final temp = File('${file.path}.tmp');
    try {
      temp.writeAsStringSync(
        '${jsonEncode({
          'version': 1,
          'secretKey': base64.encode(secret),
          'publicKey': base64.encode(publicKey),
          'created': created.toIso8601String(),
          'changes': [for (final c in changes) c.toJson()],
        })}\n',
        flush: true,
      );
    } finally {
      secret.fillRange(0, secret.length, 0);
    }
    // The user's alone before it carries its name.
    if (!Platform.isWindows) Process.runSync('chmod', ['600', temp.path]);
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
  Future<TomSecretsServiceIdentityKey> rotate({DateTime? now}) async {
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
      _file,
    ).._write();
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
