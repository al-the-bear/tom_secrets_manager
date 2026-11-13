// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Signed objects (protocol.md 9.1 to 9.4, DP-160): the length-prefixed
/// encoding, approver keys and their ids, the signed bytes of grants,
/// revocations, approval records and key-change statements, and their
/// signature list. A receiver accepts an object only when one recorded
/// approver key signed it with Ed25519 and with ML-DSA-65.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:tom_pqc/tom_pqc.dart';

/// `lp(x)`: the length of [bytes] as 4 bytes big-endian, then the bytes.
Uint8List tomSecretsLp(List<int> bytes) {
  final out = Uint8List(4 + bytes.length);
  ByteData.sublistView(out).setUint32(0, bytes.length);
  out.setRange(4, out.length, bytes);
  return out;
}

/// `lp` of a text's UTF-8.
Uint8List tomSecretsLps(String text) => tomSecretsLp(utf8.encode(text));

/// A list: its item count as 4 bytes big-endian, then `lps` of each item.
Uint8List tomSecretsLpList(List<String> items) {
  final out = BytesBuilder()
    ..add((ByteData(4)..setUint32(0, items.length)).buffer.asUint8List());
  for (final item in items) {
    out.add(tomSecretsLps(item));
  }
  return out.toBytes();
}

/// The domain labels of the signed objects.
abstract final class TomSecretsSignedLabels {
  /// A grant.
  static const grant = 'tsm-grant-v1';

  /// A revocation.
  static const revoke = 'tsm-revoke-v1';

  /// An approval record.
  static const approval = 'tsm-approval-v1';

  /// A key-change statement.
  static const keyChange = 'tsm-keychange-v1';

  /// An approver key's id.
  static const approverKey = 'tsm-approver-key-v1';
}

/// The members of each signed object, in the order they are signed (9.4).
const Map<String, List<String>> tomSecretsSignedFields = {
  TomSecretsSignedLabels.grant: [
    'id',
    'host',
    'subject',
    'secret',
    'decision',
    'created',
    'pin',
    'approver',
  ],
  TomSecretsSignedLabels.revoke: ['host', 'grantId', 'revoked', 'approver'],
  TomSecretsSignedLabels.approval: [
    'host',
    'code',
    'decision',
    'approver',
    'created',
  ],
  TomSecretsSignedLabels.keyChange: [
    'device',
    'oldKeyId',
    'newKeyId',
    'newEd25519',
    'newMlDsa65',
    'time',
  ],
};

/// The text a `pin` member is signed as: `hash`, `off`,
/// `relaxed:<relaxedUntil>`, or empty when absent.
String tomSecretsPinText(Object? pin) => switch (pin) {
  null => '',
  final String s => s,
  final Map m => 'relaxed:${m['relaxedUntil']}',
  _ => throw ArgumentError.value(pin, 'pin'),
};

/// The signed bytes of [object] under [label]: `lps(label)`, then `lps` of
/// each member of [tomSecretsSignedFields] (an absent one as empty).
Uint8List tomSecretsSignedBytes(String label, Map<String, Object?> object) {
  final out = BytesBuilder()..add(tomSecretsLps(label));
  for (final name in tomSecretsSignedFields[label]!) {
    final value = object[name];
    out.add(
      tomSecretsLps(
        name == 'pin' ? tomSecretsPinText(value) : (value as String?) ?? '',
      ),
    );
  }
  return out.toBytes();
}

/// An approver key's id (9.2): the first 16 bytes, in lower-case hex, of
/// SHA-256(lps("tsm-approver-key-v1") || lp(Ed25519 public) || lp(ML-DSA-65
/// public)).
String tomSecretsApproverKeyId(List<int> ed25519, List<int> mlDsa65) {
  final digest = crypto.sha256.convert([
    ...tomSecretsLps(TomSecretsSignedLabels.approverKey),
    ...tomSecretsLp(ed25519),
    ...tomSecretsLp(mlDsa65),
  ]);
  return digest.bytes
      .sublist(0, 16)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
}

/// The public half of an approver key, as a host records it at pairing.
final class TomSecretsApproverPublicKey {
  /// The key of [ed25519] (32 bytes) and [mlDsa65] (1,952 bytes).
  TomSecretsApproverPublicKey(this.ed25519, this.mlDsa65)
    : keyId = tomSecretsApproverKeyId(ed25519, mlDsa65);

  /// The Ed25519 public key.
  final Uint8List ed25519;

  /// The ML-DSA-65 public key.
  final Uint8List mlDsa65;

  /// Its key id.
  final String keyId;

  /// `{ed25519, mlDsa65}` in base64.
  Map<String, Object?> toJson() => {
    'ed25519': base64.encode(ed25519),
    'mlDsa65': base64.encode(mlDsa65),
  };

  /// From [toJson].
  factory TomSecretsApproverPublicKey.fromJson(Map<String, Object?> json) =>
      TomSecretsApproverPublicKey(
        base64.decode(json['ed25519']! as String),
        base64.decode(json['mlDsa65']! as String),
      );
}

/// An approver key pair: an Ed25519 and an ML-DSA-65 key used together,
/// made from two 32-byte seeds (which the device settings keep).
final class TomSecretsApproverKey {
  TomSecretsApproverKey._(this._ed25519, this._mlDsa, this.publicKey);

  final SimpleKeyPair _ed25519;
  final MlDsa65KeyPair _mlDsa;

  /// The public half.
  final TomSecretsApproverPublicKey publicKey;

  /// Its key id.
  String get keyId => publicKey.keyId;

  /// The pair from its seeds.
  static Future<TomSecretsApproverKey> fromSeeds(
    List<int> ed25519Seed,
    List<int> mlDsaSeed,
  ) async {
    final ed = await Ed25519().newKeyPairFromSeed(ed25519Seed);
    final edPublic = Uint8List.fromList((await ed.extractPublicKey()).bytes);
    final ml = MlDsa65.keyPairFromSeed(
      SecretBytes.fromBytes(Uint8List.fromList(mlDsaSeed)),
    );
    return TomSecretsApproverKey._(
      ed,
      ml,
      TomSecretsApproverPublicKey(edPublic, ml.publicKey),
    );
  }

  /// The two signature items of [bytes] under [label] (9.3): Ed25519, and
  /// ML-DSA-65 hedged with [label] as its context.
  Future<List<Map<String, Object?>>> sign(String label, Uint8List bytes) async {
    final ed = await Ed25519().sign(bytes, keyPair: _ed25519);
    final ml = MlDsa65.sign(
      bytes,
      _mlDsa.secretKey,
      context: Uint8List.fromList(utf8.encode(label)),
    );
    return [
      {'alg': 'ed25519', 'keyId': keyId, 'sig': base64.encode(ed.bytes)},
      {'alg': 'ml-dsa-65', 'keyId': keyId, 'sig': base64.encode(ml)},
    ];
  }

  /// [object] (of [label]) with its `signatures` made by this key.
  Future<Map<String, Object?>> signObject(
    String label,
    Map<String, Object?> object,
  ) async => {
    ...object,
    'signatures': await sign(label, tomSecretsSignedBytes(label, object)),
  };
}

List<Map<String, Object?>> _signaturesOf(Map<String, Object?> object) {
  final list = object['signatures'];
  if (list is! List) return const [];
  return [
    for (final item in list)
      if (item is Map) item.cast<String, Object?>(),
  ];
}

/// Whether [signatures] carry, for [key], an Ed25519 item and an ML-DSA-65
/// item that both verify over [bytes] under [label] (9.3).
Future<bool> tomSecretsVerifiedBy(
  TomSecretsApproverPublicKey key,
  String label,
  Uint8List bytes,
  List<Map<String, Object?>> signatures,
) async {
  var ed = false;
  var ml = false;
  for (final item in signatures) {
    if (item['keyId'] != key.keyId) continue;
    final Uint8List sig;
    try {
      sig = base64.decode(item['sig']! as String);
    } on Object {
      continue;
    }
    if (item['alg'] == 'ed25519' && !ed) {
      ed = await Ed25519().verify(
        bytes,
        signature: Signature(
          sig,
          publicKey: SimplePublicKey(key.ed25519, type: KeyPairType.ed25519),
        ),
      );
    } else if (item['alg'] == 'ml-dsa-65' && !ml) {
      ml = MlDsa65.verify(
        bytes,
        sig,
        key.mlDsa65,
        context: Uint8List.fromList(utf8.encode(label)),
      );
    }
  }
  return ed && ml;
}

/// The recorded key that signed [object] (a grant, revocation or approval
/// record of [label]) with both algorithms, or null: the object is accepted
/// only then.
Future<TomSecretsApproverPublicKey?> tomSecretsAcceptedBy(
  String label,
  Map<String, Object?> object,
  Iterable<TomSecretsApproverPublicKey> recorded,
) async {
  final Uint8List bytes;
  try {
    bytes = tomSecretsSignedBytes(label, object);
  } on Object {
    return null;
  }
  final signatures = _signaturesOf(object);
  for (final key in recorded) {
    if (await tomSecretsVerifiedBy(key, label, bytes, signatures)) return key;
  }
  return null;
}

/// The new key of a key-change [statement] when it is accepted (9.4): its
/// old key is [oldKey], `newKeyId` is the id of the keys it carries, and the
/// old and the new key both signed it with both algorithms. Null otherwise.
Future<TomSecretsApproverPublicKey?> tomSecretsAcceptKeyChange(
  Map<String, Object?> statement,
  TomSecretsApproverPublicKey oldKey,
) async {
  final TomSecretsApproverPublicKey newKey;
  final Uint8List bytes;
  try {
    newKey = TomSecretsApproverPublicKey(
      base64.decode(statement['newEd25519']! as String),
      base64.decode(statement['newMlDsa65']! as String),
    );
    bytes = tomSecretsSignedBytes(TomSecretsSignedLabels.keyChange, statement);
  } on Object {
    return null;
  }
  if (newKey.keyId != statement['newKeyId'] ||
      oldKey.keyId != statement['oldKeyId']) {
    return null;
  }
  final signatures = _signaturesOf(statement);
  final ok =
      await tomSecretsVerifiedBy(
        oldKey,
        TomSecretsSignedLabels.keyChange,
        bytes,
        signatures,
      ) &&
      await tomSecretsVerifiedBy(
        newKey,
        TomSecretsSignedLabels.keyChange,
        bytes,
        signatures,
      );
  return ok ? newKey : null;
}
