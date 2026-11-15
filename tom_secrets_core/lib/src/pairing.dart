// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Pairing between the user's own machines (part-sharing, DP-60–DP-64,
/// DP-177): a short one-time code turned into a strong key by SPAKE2 (RFC
/// 9382, P256-SHA256-HKDF-HMAC, the RFC's M and N points and key
/// confirmation), an ML-KEM-768 exchange inside the authenticated channel,
/// and the session key mixing both secrets with the whole transcript; then
/// the giving side's bundle in one AEAD message and the receiving side's
/// public keys back. Framed over a channel (DP-64): the approval link's
/// length-prefixed frames, TCP in phase A, a relay in phase C.
///
/// The receiving side connects and is SPAKE2's A (it uses M); the giving
/// side, which shows the code (DP-61), is B (it uses N). Both identities are
/// the device names each side sends first.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as aead;
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:tom_pqc/tom_pqc.dart';

import 'approval_link.dart';
import 'pairing_words.dart';
import 'signed_objects.dart';

/// The pairing protocol's version (each side's first message carries it).
const int tomSecretsPairingVersion = 1;

/// SPAKE2's associated data: the protocol and its version, so both sides
/// agree on them (RFC 9382 §3.2, against a downgrade).
const String tomSecretsPairingAad = 'tsm-pair-v1';

/// How long the giving side's pairing window stays open (part-sharing).
const Duration tomSecretsPairingWindow = Duration(minutes: 5);

// ── The code ────────────────────────────────────────────────────────────

/// A pairing code: `<number>-<word>-<word>` (e.g. `7-guitar-orbit`), the
/// number 1..999 (it finds the giving side, e.g. in its mDNS record), the
/// words from [tomSecretsPairingWords].
final class TomSecretsPairingCode {
  /// The code of [number] and [words].
  TomSecretsPairingCode(this.number, this.words)
    : assert(number >= 1 && number <= 999),
      assert(words.length == 2);

  /// A fresh random code.
  factory TomSecretsPairingCode.generate({Random? random}) {
    final r = random ?? Random.secure();
    return TomSecretsPairingCode(1 + r.nextInt(999), [
      tomSecretsPairingWords[r.nextInt(256)],
      tomSecretsPairingWords[r.nextInt(256)],
    ]);
  }

  /// The code typed as [text]: spaces and case do not matter; throws
  /// [FormatException] for anything else.
  factory TomSecretsPairingCode.parse(String text) {
    final parts = text
        .trim()
        .toLowerCase()
        .split(RegExp(r'[\s-]+'))
        .where((p) => p.isNotEmpty)
        .toList();
    final number = parts.isEmpty ? null : int.tryParse(parts.first);
    if (parts.length != 3 ||
        number == null ||
        number < 1 ||
        number > 999 ||
        !tomSecretsPairingWords.contains(parts[1]) ||
        !tomSecretsPairingWords.contains(parts[2])) {
      throw FormatException('not a pairing code: $text');
    }
    return TomSecretsPairingCode(number, [parts[1], parts[2]]);
  }

  /// The number.
  final int number;

  /// The two words.
  final List<String> words;

  /// `<number>-<word>-<word>`.
  String get text => '$number-${words[0]}-${words[1]}';

  /// SPAKE2's w: HKDF-SHA-256 over [text] (salt `tsm-pair-code-v1`), 40
  /// bytes (64 bits more than the group order's), reduced mod the order
  /// (RFC 9382 §3.2). The code is one-time and an attacker gets one guess
  /// at it, so no memory-hard function is needed.
  BigInt get w =>
      _bigInt(
        tomSecretsHkdf(
          utf8.encode(text),
          salt: utf8.encode('tsm-pair-code-v1'),
          info: const [],
          length: 40,
        ),
      ) %
      _p256.n;

  @override
  String toString() => text;
}

// ── SPAKE2 (RFC 9382) ───────────────────────────────────────────────────

final ECDomainParameters _p256 = ECCurve_secp256r1();

final ECPoint _m = _p256.curve.decodePoint(
  _hex('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f'),
)!;
final ECPoint _n = _p256.curve.decodePoint(
  _hex('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49'),
)!;

/// What SPAKE2 derives (RFC 9382 §4): the shared secret [ke], the
/// transcript [tt], and both confirmation MACs.
final class TomSecretsSpake2Keys {
  TomSecretsSpake2Keys._(this.ke, this.tt, this.confirmA, this.confirmB);

  /// Ke, the shared secret (16 bytes).
  final Uint8List ke;

  /// TT, the transcript.
  final Uint8List tt;

  /// cA = MAC(KcA, TT).
  final Uint8List confirmA;

  /// cB = MAC(KcB, TT).
  final Uint8List confirmB;
}

/// One side of SPAKE2-P256-SHA256-HKDF-HMAC: A (the receiving side, uses M)
/// or B (the giving side, uses N).
final class TomSecretsSpake2 {
  TomSecretsSpake2._(this._isA, this._w, this._scalar, this._a, this._b);

  /// Side A with password scalar [w], identities [a] and [b]; [x] is its
  /// secret scalar (random when not given; given only by tests).
  factory TomSecretsSpake2.a(
    BigInt w, {
    required List<int> a,
    required List<int> b,
    BigInt? x,
  }) => TomSecretsSpake2._(true, w, x ?? _randomScalar(), a, b);

  /// Side B; see [TomSecretsSpake2.a].
  factory TomSecretsSpake2.b(
    BigInt w, {
    required List<int> a,
    required List<int> b,
    BigInt? y,
  }) => TomSecretsSpake2._(false, w, y ?? _randomScalar(), a, b);

  final bool _isA;
  final BigInt _w;
  final BigInt _scalar;
  final List<int> _a;
  final List<int> _b;

  /// This side's message: pA = w*M + x*P, or pB = w*N + y*P (uncompressed).
  Uint8List get message =>
      (((_isA ? _m : _n) * _w)! + (_p256.G * _scalar))!.getEncoded(false);

  /// The keys from the peer's message [peer] (pB on A, pA on B). Throws
  /// [FormatException] for a message that is no point of the curve or is
  /// the identity.
  TomSecretsSpake2Keys finish(List<int> peer) {
    // Only an uncompressed point on the curve is taken: a point off it
    // would let a peer confine the result to a weak group (an
    // invalid-curve attack); the decoder does not check that.
    if (!_onCurve(peer)) {
      throw const FormatException('the SPAKE2 message is no point of P-256');
    }
    final point = _p256.curve.decodePoint(peer)!;
    if (point.isInfinity) {
      throw const FormatException('the SPAKE2 message is the identity');
    }
    // K = h*x*(pB - w*N) on A, h*y*(pA - w*M) on B; h is 1 on P-256.
    final k = (point - ((_isA ? _n : _m) * _w)!)! * _scalar;
    if (k == null || k.isInfinity) {
      throw const FormatException('SPAKE2 gave the identity');
    }
    final mine = message;
    final pA = _isA ? mine : Uint8List.fromList(peer);
    final pB = _isA ? Uint8List.fromList(peer) : mine;
    final tt = BytesBuilder()
      ..add(_len(_a))
      ..add(_a)
      ..add(_len(_b))
      ..add(_b)
      ..add(_len(pA))
      ..add(pA)
      ..add(_len(pB))
      ..add(pB);
    final kBytes = k.getEncoded(false);
    final wBytes = _fixed(_w, 32);
    tt
      ..add(_len(kBytes))
      ..add(kBytes)
      ..add(_len(wBytes))
      ..add(wBytes);
    final transcript = tt.toBytes();
    final hash = crypto.sha256.convert(transcript).bytes;
    final ke = Uint8List.fromList(hash.sublist(0, 16));
    final ka = hash.sublist(16, 32);
    final kc = tomSecretsHkdf(
      ka,
      salt: const [],
      info: [...utf8.encode('ConfirmationKeys'), ...utf8.encode(_aad)],
      length: 32,
    );
    return TomSecretsSpake2Keys._(
      ke,
      transcript,
      _hmac(kc.sublist(0, 16), transcript),
      _hmac(kc.sublist(16, 32), transcript),
    );
  }

  /// The associated data; [aad] in tests (the RFC's vectors use none).
  static String _aad = tomSecretsPairingAad;

  /// Runs [body] with SPAKE2's AAD set to [aad] (the RFC's test vectors use
  /// none); for tests only.
  static T withAad<T>(String aad, T Function() body) {
    final before = _aad;
    _aad = aad;
    try {
      return body();
    } finally {
      _aad = before;
    }
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────
// The field prime and the coefficient b of P-256 (SEC 2; a = p - 3).
final BigInt _fieldP = BigInt.parse(
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
  radix: 16,
);
final BigInt _curveB = BigInt.parse(
  '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
  radix: 16,
);

/// Whether [encoded] is an uncompressed point of P-256: `04 || x || y` with
/// x, y below the field prime and y^2 = x^3 - 3x + b.
bool _onCurve(List<int> encoded) {
  if (encoded.length != 65 || encoded[0] != 4) return false;
  final x = _bigInt(encoded.sublist(1, 33));
  final y = _bigInt(encoded.sublist(33));
  if (x >= _fieldP || y >= _fieldP) return false;
  final left = (y * y) % _fieldP;
  final right = (x * x * x - BigInt.from(3) * x + _curveB) % _fieldP;
  return left == right;
}

/// HKDF-SHA-256 (RFC 5869) of [ikm] with [salt] and [info], [length] bytes.
Uint8List tomSecretsHkdf(
  List<int> ikm, {
  required List<int> salt,
  required List<int> info,
  required int length,
}) {
  final prk = _hmac(salt.isEmpty ? List.filled(32, 0) : salt, ikm);
  final out = BytesBuilder();
  var previous = <int>[];
  for (var i = 1; out.length < length; i++) {
    previous = _hmac(prk, [...previous, ...info, i]);
    out.add(previous);
  }
  return Uint8List.fromList(out.toBytes().sublist(0, length));
}

Uint8List _hmac(List<int> key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);

Uint8List _len(List<int> bytes) {
  final out = ByteData(8)..setUint64(0, bytes.length, Endian.little);
  return out.buffer.asUint8List();
}

Uint8List _fixed(BigInt value, int length) {
  final out = Uint8List(length);
  var v = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return out;
}

BigInt _bigInt(List<int> bytes) {
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  return v;
}

BigInt _randomScalar() {
  final r = Random.secure();
  // 64 bits more than the order, reduced: no visible bias.
  return _bigInt(List.generate(40, (_) => r.nextInt(256))) % _p256.n;
}

Uint8List _hex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

// ── The bundle ──────────────────────────────────────────────────────────

/// One vault the bundle hands over: its locator and the keys a device needs
/// beyond the master password (part-sharing).
final class TomSecretsPairingVault {
  /// The vault [name] at [locator].
  const TomSecretsPairingVault({
    required this.name,
    required this.locator,
    this.primary = false,
    this.keyFile,
    this.repositoryKey,
  });

  /// From [toJson].
  factory TomSecretsPairingVault.fromJson(Map<String, Object?> json) =>
      TomSecretsPairingVault(
        name: json['name']! as String,
        locator: json['locator']! as String,
        primary: json['primary'] == true,
        keyFile: json['keyFile'] == null
            ? null
            : base64.decode(json['keyFile']! as String),
        repositoryKey: json['repositoryKey'] as String?,
      );

  /// Its store name.
  final String name;

  /// Its locator.
  final String locator;

  /// Whether it is the primary.
  final bool primary;

  /// Its key file's bytes, or null.
  final Uint8List? keyFile;

  /// Its repository key (base64), or null.
  final String? repositoryKey;

  /// The JSON the bundle carries.
  Map<String, Object?> toJson() => {
    'name': name,
    'locator': locator,
    if (primary) 'primary': true,
    if (keyFile != null) 'keyFile': base64.encode(keyFile!),
    'repositoryKey': ?repositoryKey,
  };
}

/// A GitHub token the user pasted on the giving side for the receiving
/// device (DP-59, DP-83): never the giving side's own.
final class TomSecretsPairingToken {
  /// The [token] for [repository] (`owner/name`), expiring at [expires].
  const TomSecretsPairingToken({
    required this.repository,
    required this.token,
    this.expires,
  });

  /// From [toJson].
  factory TomSecretsPairingToken.fromJson(Map<String, Object?> json) =>
      TomSecretsPairingToken(
        repository: json['repository']! as String,
        token: json['token']! as String,
        expires: json['expires'] == null
            ? null
            : DateTime.parse(json['expires']! as String).toUtc(),
      );

  /// The repository.
  final String repository;

  /// The token.
  final String token;

  /// Its expiry, or null.
  final DateTime? expires;

  /// The JSON the bundle carries.
  Map<String, Object?> toJson() => {
    'repository': repository,
    'token': token,
    if (expires != null) 'expires': expires!.toUtc().toIso8601String(),
  };
}

/// A device's public keys for the approvals (DP-19): its approver key pair
/// (null when it is no approver) and its approval-link key, with the
/// address its link listens on (null when it does not listen).
final class TomSecretsPairingPeerKeys {
  /// The keys.
  const TomSecretsPairingPeerKeys({
    required this.linkKey,
    this.approverKey,
    this.linkAddress,
  });

  /// From [toJson].
  factory TomSecretsPairingPeerKeys.fromJson(Map<String, Object?> json) =>
      TomSecretsPairingPeerKeys(
        linkKey: TomSecretsLinkPublicKey.fromJson(
          (json['linkKey']! as Map).cast(),
        ),
        approverKey: json['approverKey'] == null
            ? null
            : TomSecretsApproverPublicKey.fromJson(
                (json['approverKey']! as Map).cast(),
              ),
        linkAddress: json['linkAddress'] as String?,
      );

  /// The approval-link public key.
  final TomSecretsLinkPublicKey linkKey;

  /// The approver public key, or null for a device that approves nothing.
  final TomSecretsApproverPublicKey? approverKey;

  /// Where its approval link listens (`address:port`), or null.
  final String? linkAddress;

  /// The JSON.
  Map<String, Object?> toJson() => {
    'linkKey': linkKey.toJson(),
    if (approverKey != null) 'approverKey': approverKey!.toJson(),
    'linkAddress': ?linkAddress,
  };
}

/// What the giving side hands over (part-sharing, the pairing bundle): the
/// vaults chosen with their keys, the shared configuration, a token pasted
/// for this device, and the giving device's public keys. Never a private
/// approver or link key, a master password, the allow list or the audit log.
final class TomSecretsPairingBundle {
  /// A bundle.
  const TomSecretsPairingBundle({
    required this.vaults,
    required this.giverKeys,
    this.configYaml,
    this.tokens = const [],
  });

  /// From [toJson].
  factory TomSecretsPairingBundle.fromJson(Map<String, Object?> json) =>
      TomSecretsPairingBundle(
        vaults: [
          for (final v in (json['vaults']! as List).cast<Map>())
            TomSecretsPairingVault.fromJson(v.cast()),
        ],
        giverKeys: TomSecretsPairingPeerKeys.fromJson(
          (json['giverKeys']! as Map).cast(),
        ),
        configYaml: json['configYaml'] as String?,
        tokens: [
          for (final t in (json['tokens'] as List? ?? const []).cast<Map>())
            TomSecretsPairingToken.fromJson(t.cast()),
        ],
      );

  /// The vaults, the primary among them when it was chosen.
  final List<TomSecretsPairingVault> vaults;

  /// The giving device's public keys.
  final TomSecretsPairingPeerKeys giverKeys;

  /// The dimension configuration (`tsm.config`, BP-43), or null.
  final String? configYaml;

  /// Tokens pasted for the receiving device.
  final List<TomSecretsPairingToken> tokens;

  /// The JSON sent.
  Map<String, Object?> toJson() => {
    'vaults': [for (final v in vaults) v.toJson()],
    'giverKeys': giverKeys.toJson(),
    'configYaml': ?configYaml,
    if (tokens.isNotEmpty) 'tokens': [for (final t in tokens) t.toJson()],
  };
}

// ── The protocol ────────────────────────────────────────────────────────

/// Why a pairing ended without a result.
enum TomSecretsPairingFailure {
  /// The code did not match (the key confirmation failed); the code is
  /// burnt.
  wrongCode,

  /// The giving side's user declined the device.
  declined,

  /// The peer speaks another protocol version.
  version,

  /// The peer sent something the protocol does not expect, or a frame did
  /// not open.
  protocol,

  /// The channel ended or a step timed out.
  closed,
}

/// A pairing that ended without a result.
final class TomSecretsPairingException implements Exception {
  /// A failure of [failure] with [message].
  const TomSecretsPairingException(this.failure, this.message);

  /// Why.
  final TomSecretsPairingFailure failure;

  /// For the user and the log.
  final String message;

  @override
  String toString() => 'TomSecretsPairingException(${failure.name}): $message';
}

/// What a pairing gave the receiving side.
final class TomSecretsPairingReceived {
  TomSecretsPairingReceived._(this.giver, this.bundle, this.tokenKey);

  /// The giving device's name.
  final String giver;

  /// The bundle.
  final TomSecretsPairingBundle bundle;

  /// The approval-token key both sides derived (32 bytes, TD-3).
  final Uint8List tokenKey;
}

/// What a pairing gave the giving side.
final class TomSecretsPairingGiven {
  TomSecretsPairingGiven._(this.receiver, this.receiverKeys, this.tokenKey);

  /// The receiving device's name.
  final String receiver;

  /// The receiving device's public keys.
  final TomSecretsPairingPeerKeys receiverKeys;

  /// The approval-token key both sides derived (32 bytes, TD-3).
  final Uint8List tokenKey;
}

/// The giving side of a pairing over [channel] (part-sharing): it showed
/// [code]; [device] is its name. After the receiver proved the code and the
/// session key stands, [bundleFor] is asked with the receiver's name (the
/// user confirms the device and chooses what it gets); null declines. The
/// bundle goes over, the receiver answers with its public keys. Throws
/// [TomSecretsPairingException]; a wrong code fails at the key confirmation.
Future<TomSecretsPairingGiven> tomSecretsGivePairing(
  TomSecretsApprovalChannel channel, {
  required TomSecretsPairingCode code,
  required String device,
  required Future<TomSecretsPairingBundle?> Function(String receiver) bundleFor,
  Duration timeout = const Duration(seconds: 30),
  BigInt? y,
}) async {
  final frames = TomSecretsLinkFrameReader(channel);
  final io = _Io(channel, frames, timeout);
  try {
    final hello = await io.plain('hello');
    if (hello['version'] != tomSecretsPairingVersion) {
      io.sendPlain({'op': 'error', 'reason': 'version'});
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.version,
        'the other device speaks another pairing version',
      );
    }
    final receiver = hello['device'];
    if (receiver is! String || receiver.isEmpty) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'no device name',
      );
    }
    final spake = TomSecretsSpake2.b(
      code.w,
      a: utf8.encode(receiver),
      b: utf8.encode(device),
      y: y,
    );
    io.sendPlain({
      'op': 'hello',
      'version': tomSecretsPairingVersion,
      'device': device,
      'message': base64.encode(spake.message),
    });
    final keys = _finish(spake, await io.plain('message'));
    final confirm = await io.plain('confirm');
    if (!_equal(_bytes(confirm['mac']), keys.confirmA)) {
      io.sendPlain({'op': 'error', 'reason': 'wrong_code'});
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.wrongCode,
        'wrong code: a new one is needed',
      );
    }
    io.sendPlain({'op': 'confirm', 'mac': base64.encode(keys.confirmB)});

    // Under the SPAKE2 key: the ML-KEM-768 exchange.
    final channelKey = _derive(keys.ke, 'tsm-pair-channel-v1');
    final kem = await io.sealed(channelKey, 'kem', 'A');
    final ek = _bytes(kem['encapsulationKey']);
    if (ek.length != MlKem768.publicKeyLength ||
        !MlKem768.isValidPublicKey(ek)) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'not an ML-KEM-768 encapsulation key',
      );
    }
    final encapsulation = MlKem768.encapsulate(ek);
    await io.seal(channelKey, 'B', {
      'op': 'kem',
      'ciphertext': base64.encode(encapsulation.ciphertext),
    });
    final secret = encapsulation.sharedSecret.extractBytes();
    encapsulation.sharedSecret.dispose();
    final session = _sessionKey(keys, ek, encapsulation.ciphertext, secret);
    await _confirmSession(
      io,
      session,
      keys,
      ek,
      encapsulation.ciphertext,
      giver: true,
    );

    final bundle = await bundleFor(receiver);
    if (bundle == null) {
      await io.seal(session, 'B', {'op': 'declined'});
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.declined,
        'the device was declined',
      );
    }
    await io.seal(session, 'B', {'op': 'bundle', 'bundle': bundle.toJson()});
    final done = await io.sealed(session, 'done', 'A');
    final receiverKeys = TomSecretsPairingPeerKeys.fromJson(
      (done['keys']! as Map).cast(),
    );
    return TomSecretsPairingGiven._(
      receiver,
      receiverKeys,
      _derive(session, 'tsm-pair-token-key-v1'),
    );
  } on TomSecretsPairingException {
    rethrow;
  } on FormatException catch (e) {
    throw TomSecretsPairingException(
      TomSecretsPairingFailure.protocol,
      e.message,
    );
  } finally {
    await frames.cancel();
    await channel.close();
  }
}

/// The receiving side of a pairing over [channel]: the user typed [code];
/// [device] is its name. After the giving side proved the code and the
/// session key stands, the giving side's bundle arrives; [keysFor] answers
/// with this device's public keys (made by then, e.g. a fresh trust
/// material's). Nothing of the bundle is to be stored before this returns.
/// Throws [TomSecretsPairingException].
Future<TomSecretsPairingReceived> tomSecretsReceivePairing(
  TomSecretsApprovalChannel channel, {
  required TomSecretsPairingCode code,
  required String device,
  required Future<TomSecretsPairingPeerKeys> Function(
    String giver,
    TomSecretsPairingBundle bundle,
  )
  keysFor,
  Duration timeout = const Duration(minutes: 5),
  BigInt? x,
}) async {
  final frames = TomSecretsLinkFrameReader(channel);
  final io = _Io(channel, frames, timeout);
  try {
    // The giving side's name is known only from its answer: A's message
    // depends on both identities, so A sends its name first and its SPAKE2
    // message once it knows B's.
    io.sendPlain({
      'op': 'hello',
      'version': tomSecretsPairingVersion,
      'device': device,
    });
    final hello = await io.plain('hello');
    if (hello['version'] != tomSecretsPairingVersion) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.version,
        'the other device speaks another pairing version',
      );
    }
    final giver = hello['device'];
    if (giver is! String || giver.isEmpty) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'no device name',
      );
    }
    final spake = TomSecretsSpake2.a(
      code.w,
      a: utf8.encode(device),
      b: utf8.encode(giver),
      x: x,
    );
    io.sendPlain({'op': 'message', 'message': base64.encode(spake.message)});
    final keys = _finish(spake, hello);
    io.sendPlain({'op': 'confirm', 'mac': base64.encode(keys.confirmA)});
    final confirm = await io.plain('confirm');
    if (!_equal(_bytes(confirm['mac']), keys.confirmB)) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.wrongCode,
        'the other device did not prove the code',
      );
    }

    final channelKey = _derive(keys.ke, 'tsm-pair-channel-v1');
    final pair = MlKem768.generateKeyPair();
    try {
      await io.seal(channelKey, 'A', {
        'op': 'kem',
        'encapsulationKey': base64.encode(pair.publicKey),
      });
      final kem = await io.sealed(channelKey, 'kem', 'B');
      final ciphertext = _bytes(kem['ciphertext']);
      final shared = MlKem768.decapsulate(ciphertext, pair.secretKey);
      final secret = shared.extractBytes();
      shared.dispose();
      final session = _sessionKey(keys, pair.publicKey, ciphertext, secret);
      await _confirmSession(
        io,
        session,
        keys,
        pair.publicKey,
        ciphertext,
        giver: false,
      );

      final m = await io.sealedAny(session, 'B');
      if (m['op'] == 'declined') {
        throw const TomSecretsPairingException(
          TomSecretsPairingFailure.declined,
          'the other device declined the pairing',
        );
      }
      if (m['op'] != 'bundle') {
        throw TomSecretsPairingException(
          TomSecretsPairingFailure.protocol,
          'expected the bundle, got ${m['op']}',
        );
      }
      final bundle = TomSecretsPairingBundle.fromJson(
        (m['bundle']! as Map).cast(),
      );
      final mine = await keysFor(giver, bundle);
      await io.seal(session, 'A', {'op': 'done', 'keys': mine.toJson()});
      return TomSecretsPairingReceived._(
        giver,
        bundle,
        _derive(session, 'tsm-pair-token-key-v1'),
      );
    } finally {
      pair.secretKey.dispose();
    }
  } on TomSecretsPairingException {
    rethrow;
  } on FormatException catch (e) {
    throw TomSecretsPairingException(
      TomSecretsPairingFailure.protocol,
      e.message,
    );
  } finally {
    await frames.cancel();
    await channel.close();
  }
}

TomSecretsSpake2Keys _finish(TomSecretsSpake2 spake, Map<String, Object?> m) =>
    spake.finish(_bytes(m['message']));

Uint8List _derive(List<int> key, String label) =>
    tomSecretsHkdf(key, salt: const [], info: utf8.encode(label), length: 32);

/// The session key (DP-177): HKDF-SHA-256 over Ke || the ML-KEM shared
/// secret, the salt the hash of the whole transcript (TT, the encapsulation
/// key, the ciphertext); it holds if either SPAKE2 or ML-KEM holds.
Uint8List _sessionKey(
  TomSecretsSpake2Keys keys,
  List<int> ek,
  List<int> ciphertext,
  Uint8List secret,
) {
  final key = tomSecretsHkdf(
    [...keys.ke, ...secret],
    salt: _transcriptHash(keys, ek, ciphertext),
    info: utf8.encode('tsm-pair-session-v1'),
    length: 32,
  );
  secret.fillRange(0, secret.length, 0);
  return key;
}

Uint8List _transcriptHash(
  TomSecretsSpake2Keys keys,
  List<int> ek,
  List<int> ciphertext,
) => Uint8List.fromList(
  crypto.sha256.convert([...keys.tt, ...ek, ...ciphertext]).bytes,
);

/// Both confirm the session key with a MAC before anything else is sent:
/// the receiver (A) first.
Future<void> _confirmSession(
  _Io io,
  Uint8List session,
  TomSecretsSpake2Keys keys,
  List<int> ek,
  List<int> ciphertext, {
  required bool giver,
}) async {
  final th = _transcriptHash(keys, ek, ciphertext);
  final macA = _hmac(session, [...utf8.encode('tsm-pair-confirm-A'), ...th]);
  final macB = _hmac(session, [...utf8.encode('tsm-pair-confirm-B'), ...th]);
  if (giver) {
    final got = await io.sealed(session, 'confirm', 'A');
    if (!_equal(_bytes(got['mac']), macA)) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'the session key does not match',
      );
    }
    await io.seal(session, 'B', {'op': 'confirm', 'mac': base64.encode(macB)});
  } else {
    await io.seal(session, 'A', {'op': 'confirm', 'mac': base64.encode(macA)});
    final got = await io.sealed(session, 'confirm', 'B');
    if (!_equal(_bytes(got['mac']), macB)) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'the session key does not match',
      );
    }
  }
}

Uint8List _bytes(Object? value) {
  if (value is! String) throw const FormatException('a byte field is missing');
  return base64.decode(value);
}

/// The frames of one pairing: plain JSON before the keys stand, then
/// XChaCha20-Poly1305 (the outer encryption's AEAD, DP-8) with a random
/// nonce, the sender's role (`A` / `B`) and a counter as associated data.
final class _Io {
  _Io(this._channel, this._frames, this._timeout);

  final TomSecretsApprovalChannel _channel;
  final TomSecretsLinkFrameReader _frames;
  final Duration _timeout;
  final aead.Cipher _cipher = aead.Xchacha20.poly1305Aead();
  final Map<String, int> _counter = {'A': 0, 'B': 0};

  void sendPlain(Map<String, Object?> m) =>
      _channel.send(tomSecretsLinkFrame(utf8.encode(jsonEncode(m))));

  Future<Uint8List> _next() async {
    final frame = await _frames.next(_timeout);
    if (frame == null) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.closed,
        'the other device closed the pairing or did not answer in time',
      );
    }
    return frame;
  }

  Future<Map<String, Object?>> plain(String op) async {
    final Object? m;
    try {
      m = jsonDecode(utf8.decode(await _next()));
    } on FormatException {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'a frame is no JSON',
      );
    }
    if (m is! Map) {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'a frame is no object',
      );
    }
    final map = m.cast<String, Object?>();
    if (map['op'] == 'error') {
      throw TomSecretsPairingException(
        switch (map['reason']) {
          'wrong_code' => TomSecretsPairingFailure.wrongCode,
          'version' => TomSecretsPairingFailure.version,
          _ => TomSecretsPairingFailure.protocol,
        },
        map['reason'] == 'wrong_code'
            ? 'wrong code: a new one is needed'
            : 'the other device refused: ${map['reason']}',
      );
    }
    if (map['op'] != op) {
      throw TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'expected $op, got ${map['op']}',
      );
    }
    return map;
  }

  Future<void> seal(List<int> key, String role, Map<String, Object?> m) async {
    final counter = _counter[role]!;
    _counter[role] = counter + 1;
    final box = await _cipher.encrypt(
      utf8.encode(jsonEncode(m)),
      secretKey: aead.SecretKey(key),
      aad: utf8.encode('$role$counter'),
    );
    _channel.send(tomSecretsLinkFrame(box.concatenation()));
  }

  Future<Map<String, Object?>> sealedAny(List<int> key, String role) async {
    final frame = await _next();
    final counter = _counter[role]!;
    _counter[role] = counter + 1;
    try {
      final box = aead.SecretBox.fromConcatenation(
        frame,
        nonceLength: 24,
        macLength: 16,
      );
      final clear = await _cipher.decrypt(
        box,
        secretKey: aead.SecretKey(key),
        aad: utf8.encode('$role$counter'),
      );
      return (jsonDecode(utf8.decode(clear)) as Map).cast<String, Object?>();
    } on Object {
      throw const TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'a frame did not open under the pairing key',
      );
    }
  }

  Future<Map<String, Object?>> sealed(
    List<int> key,
    String op,
    String role,
  ) async {
    final m = await sealedAny(key, role);
    if (m['op'] != op) {
      throw TomSecretsPairingException(
        TomSecretsPairingFailure.protocol,
        'expected $op, got ${m['op']}',
      );
    }
    return m;
  }
}

// ── The pairing window ──────────────────────────────────────────────────

/// Whether [address] is a LAN or VPN address a pairing window may listen
/// on: a private IPv4 address (10/8, which the fleet's VPN uses, 172.16/12,
/// 192.168/16) or an IPv6 unique local address (fc00::/7); never a public,
/// loopback or wildcard address (part-sharing).
bool tomSecretsIsPairingAddress(InternetAddress address) {
  final b = address.rawAddress;
  if (address.type == InternetAddressType.IPv4) {
    return b[0] == 10 ||
        (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
        (b[0] == 192 && b[1] == 168);
  }
  if (address.type == InternetAddressType.IPv6) return (b[0] & 0xfe) == 0xfc;
  return false;
}

/// This machine's LAN and VPN addresses ([tomSecretsIsPairingAddress]).
Future<List<InternetAddress>> tomSecretsPairingAddresses() async => [
  for (final i in await NetworkInterface.list(includeLinkLocal: false))
    for (final a in i.addresses)
      if (tomSecretsIsPairingAddress(a)) a,
];

/// The giving side's pairing window (part-sharing): it listens on the
/// addresses given (the LAN and VPN ones, [tomSecretsPairingAddresses]),
/// takes the first connection and runs [tomSecretsGivePairing] over it.
/// Any further connection is refused, and the window closes after that one
/// attempt (the code is burnt, right or wrong) or when [window] ends.
final class TomSecretsPairingWindow {
  TomSecretsPairingWindow._(this._servers, this.port, this.addresses);

  final List<ServerSocket> _servers;
  final Completer<TomSecretsPairingGiven> _result = Completer();
  Timer? _timer;
  bool _taken = false;

  /// The port it listens on (the same on every address).
  final int port;

  /// The addresses it listens on.
  final List<InternetAddress> addresses;

  /// Opens a window on [addresses] (at [port], 0: one the system picks) for
  /// [code], this machine being [device]; [bundleFor] as for
  /// [tomSecretsGivePairing]. Throws [ArgumentError] for an address that is
  /// no LAN or VPN address, [SocketException] when none can be bound.
  static Future<TomSecretsPairingWindow> open({
    required List<InternetAddress> addresses,
    required TomSecretsPairingCode code,
    required String device,
    required Future<TomSecretsPairingBundle?> Function(String receiver)
    bundleFor,
    int port = 0,
    Duration window = tomSecretsPairingWindow,
    Duration stepTimeout = const Duration(seconds: 30),
    bool allowLoopback = false,
  }) async {
    if (addresses.isEmpty) {
      throw ArgumentError.value(addresses, 'addresses', 'none to listen on');
    }
    for (final a in addresses) {
      if (!tomSecretsIsPairingAddress(a) && !(allowLoopback && a.isLoopback)) {
        throw ArgumentError.value(a, 'addresses', 'no LAN or VPN address');
      }
    }
    final servers = <ServerSocket>[];
    var chosen = port;
    for (final a in addresses) {
      try {
        final server = await ServerSocket.bind(a, chosen);
        chosen = server.port;
        servers.add(server);
      } on SocketException {
        if (servers.isEmpty && a == addresses.last) rethrow;
      }
    }
    final w = TomSecretsPairingWindow._(servers, chosen, [
      for (final s in servers) s.address,
    ]);
    w._timer = Timer(window, () {
      if (!w._result.isCompleted) {
        w._result.completeError(
          const TomSecretsPairingException(
            TomSecretsPairingFailure.closed,
            'the pairing window closed',
          ),
        );
      }
      unawaited(w.close());
    });
    for (final server in servers) {
      server.listen((socket) {
        if (w._taken) {
          // A second connection while one runs, or after: refused.
          socket.destroy();
          return;
        }
        w._taken = true;
        // The code is burnt: nothing else connects.
        unawaited(w._closeServers());
        unawaited(
          tomSecretsGivePairing(
                TomSecretsSocketChannel(socket),
                code: code,
                device: device,
                bundleFor: bundleFor,
                timeout: stepTimeout,
              )
              .then(
                (given) {
                  if (!w._result.isCompleted) w._result.complete(given);
                },
                onError: (Object e, StackTrace s) {
                  if (!w._result.isCompleted) w._result.completeError(e, s);
                },
              )
              .whenComplete(() => w._timer?.cancel()),
        );
      });
    }
    return w;
  }

  /// What the pairing gave, or the [TomSecretsPairingException] it ended
  /// with (`closed` when the window ended without a connection).
  Future<TomSecretsPairingGiven> get result => _result.future;

  Future<void> _closeServers() async {
    for (final s in _servers) {
      await s.close();
    }
  }

  /// Closes the window (a pairing already running goes on).
  Future<void> close() async {
    _timer?.cancel();
    await _closeServers();
    if (!_result.isCompleted && !_taken) {
      _result.completeError(
        const TomSecretsPairingException(
          TomSecretsPairingFailure.closed,
          'the pairing window closed',
        ),
      );
    }
  }
}

/// The receiving side connecting to a pairing window at [address]:[port]
/// ([tomSecretsReceivePairing] over TCP). Throws
/// [TomSecretsPairingException] (`closed` when nothing answers there).
Future<TomSecretsPairingReceived> tomSecretsReceivePairingAt(
  String address,
  int port, {
  required TomSecretsPairingCode code,
  required String device,
  required Future<TomSecretsPairingPeerKeys> Function(
    String giver,
    TomSecretsPairingBundle bundle,
  )
  keysFor,
  Duration connectTimeout = const Duration(seconds: 10),
}) async {
  final Socket socket;
  try {
    socket = await Socket.connect(address, port, timeout: connectTimeout);
  } on SocketException catch (e) {
    throw TomSecretsPairingException(
      TomSecretsPairingFailure.closed,
      'cannot reach $address:$port: ${e.message} (same network or the VPN?)',
    );
  }
  return tomSecretsReceivePairing(
    TomSecretsSocketChannel(socket),
    code: code,
    device: device,
    keysFor: keysFor,
  );
}
