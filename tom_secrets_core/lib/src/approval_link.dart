// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The approval link (protocol.md 9.7, DP-100, DP-160): a host's service and
/// the manager app of a paired approver device, over an
/// [TomSecretsApprovalChannel] (a TCP connection in phase A, the relay in
/// phase C). The handshake is Noise KK with every Diffie-Hellman paired with
/// an ML-KEM-768 encapsulation; the transport is ChaCha20-Poly1305 with a
/// counter nonce and REKEY on `rekey`. Both roles: the approver initiates,
/// the host responds.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:tom_pqc/tom_pqc.dart';

/// The protocol name hashed into the handshake.
const String tomSecretsLinkProtocolName =
    'tsm-link-v1_KK-hybrid_25519+MLKEM768_ChaChaPoly_SHA256';

/// The largest frame on the channel.
const int tomSecretsLinkMaxFrame = 1024 * 1024;

/// The handshake or the transport failed: the link closes.
final class TomSecretsLinkException implements Exception {
  /// A failure: [message].
  TomSecretsLinkException(this.message);

  /// What failed.
  final String message;

  @override
  String toString() => 'TomSecretsLinkException: $message';
}

Uint8List _hmac(List<int> key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);

Uint8List _sha256(List<int> data) =>
    Uint8List.fromList(crypto.sha256.convert(data).bytes);

/// Noise's HKDF with HMAC-SHA256: two 32-byte outputs.
(Uint8List, Uint8List) tomSecretsNoiseHkdf(
  List<int> chainingKey,
  List<int> ikm,
) {
  final temp = _hmac(chainingKey, ikm);
  final out1 = _hmac(temp, [1]);
  final out2 = _hmac(temp, [...out1, 2]);
  return (out1, out2);
}

Uint8List _nonce(int n) {
  final nonce = Uint8List(12);
  var v = n;
  for (var i = 4; i < 12; i++) {
    nonce[i] = v & 0xff;
    v >>= 8;
  }
  return nonce;
}

final Cipher _aead = Chacha20.poly1305Aead();

Future<Uint8List> _encrypt(
  List<int> key,
  int n,
  List<int> ad,
  List<int> plaintext,
) async {
  final box = await _aead.encrypt(
    plaintext,
    secretKey: SecretKey(key),
    nonce: _nonce(n),
    aad: ad,
  );
  return Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
}

Future<Uint8List> _decrypt(
  List<int> key,
  int n,
  List<int> ad,
  List<int> ciphertext,
) async {
  if (ciphertext.length < 16) {
    throw TomSecretsLinkException('a frame is too short');
  }
  try {
    return Uint8List.fromList(
      await _aead.decrypt(
        SecretBox(
          ciphertext.sublist(0, ciphertext.length - 16),
          nonce: _nonce(n),
          mac: Mac(ciphertext.sublist(ciphertext.length - 16)),
        ),
        secretKey: SecretKey(key),
        aad: ad,
      ),
    );
  } on SecretBoxAuthenticationError {
    throw TomSecretsLinkException('a frame does not decrypt');
  }
}

/// Noise's REKEY: the first 32 bytes of ENCRYPT(k, 2^64 - 1, empty, zeros).
Future<Uint8List> tomSecretsLinkRekey(List<int> key) async {
  final box = await _aead.encrypt(
    Uint8List(32),
    secretKey: SecretKey(key),
    nonce: Uint8List.fromList([0, 0, 0, 0, ...List.filled(8, 255)]),
  );
  return Uint8List.fromList(box.cipherText.sublist(0, 32));
}

/// Noise's symmetric state with SHA-256.
final class _SymmetricState {
  _SymmetricState() {
    h = _sha256(utf8.encode(tomSecretsLinkProtocolName));
    ck = Uint8List.fromList(h);
  }

  late Uint8List h;
  late Uint8List ck;
  Uint8List? k;
  int n = 0;

  void mixHash(List<int> data) => h = _sha256([...h, ...data]);

  void mixKey(List<int> ikm) {
    final (newCk, tempK) = tomSecretsNoiseHkdf(ck, ikm);
    ck = newCk;
    k = tempK;
    n = 0;
  }

  Future<Uint8List> encryptAndHash(List<int> plaintext) async {
    final c = await _encrypt(k!, n++, h, plaintext);
    mixHash(c);
    return c;
  }

  Future<Uint8List> decryptAndHash(List<int> ciphertext) async {
    final p = await _decrypt(k!, n++, h, ciphertext);
    mixHash(ciphertext);
    return p;
  }

  (Uint8List, Uint8List) split() => tomSecretsNoiseHkdf(ck, const []);
}

/// The public half of a link key: X25519 and ML-KEM-768, as pairing records
/// it.
final class TomSecretsLinkPublicKey {
  /// The key of [x25519] (32 bytes) and [mlKem768] (1,184 bytes).
  const TomSecretsLinkPublicKey(this.x25519, this.mlKem768);

  /// The X25519 public key.
  final Uint8List x25519;

  /// The ML-KEM-768 encapsulation key.
  final Uint8List mlKem768;

  /// `{x25519, mlKem768}` in base64.
  Map<String, Object?> toJson() => {
    'x25519': base64.encode(x25519),
    'mlKem768': base64.encode(mlKem768),
  };

  /// From [toJson].
  factory TomSecretsLinkPublicKey.fromJson(Map<String, Object?> json) =>
      TomSecretsLinkPublicKey(
        base64.decode(json['x25519']! as String),
        base64.decode(json['mlKem768']! as String),
      );

  /// Whether both halves are [other]'s.
  bool sameAs(TomSecretsLinkPublicKey other) =>
      _same(x25519, other.x25519) && _same(mlKem768, other.mlKem768);
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// One side's static link key: X25519 and ML-KEM-768, from two 32-byte
/// seeds (which the device settings keep; the ML-KEM seed is FIPS 203's 64
/// bytes, d || z).
final class TomSecretsLinkKey {
  TomSecretsLinkKey._(this._x25519, this._mlKem, this.publicKey);

  final SimpleKeyPair _x25519;
  final MlKem768KeyPair _mlKem;

  /// The public half.
  final TomSecretsLinkPublicKey publicKey;

  /// The key of [x25519Seed] (32 bytes) and [mlKemSeed] (64 bytes).
  static Future<TomSecretsLinkKey> fromSeeds(
    List<int> x25519Seed,
    List<int> mlKemSeed,
  ) async {
    final x = await X25519().newKeyPairFromSeed(x25519Seed);
    final xp = Uint8List.fromList((await x.extractPublicKey()).bytes);
    final kem = MlKem768.keyPairFromSeed(
      SecretBytes.fromBytes(Uint8List.fromList(mlKemSeed)),
    );
    return TomSecretsLinkKey._(
      x,
      kem,
      TomSecretsLinkPublicKey(xp, kem.publicKey),
    );
  }
}

/// The randomness of a handshake: system randomness by default; the tests
/// give the vectors' seeds and coins.
abstract interface class TomSecretsLinkRandom {
  /// A fresh ephemeral X25519 key.
  Future<SimpleKeyPair> ephemeralX25519();

  /// A fresh ephemeral ML-KEM-768 key.
  MlKem768KeyPair ephemeralMlKem();

  /// An encapsulation to [publicKey].
  MlKem768Encapsulation encapsulate(Uint8List publicKey);
}

/// System randomness.
final class TomSecretsSystemLinkRandom implements TomSecretsLinkRandom {
  /// The randomness.
  const TomSecretsSystemLinkRandom();

  @override
  Future<SimpleKeyPair> ephemeralX25519() => X25519().newKeyPair();

  @override
  MlKem768KeyPair ephemeralMlKem() => MlKem768.generateKeyPair();

  @override
  MlKem768Encapsulation encapsulate(Uint8List publicKey) =>
      MlKem768.encapsulate(publicKey);
}

Future<Uint8List> _dh(SimpleKeyPair mine, List<int> theirs) async {
  if (theirs.length != 32) {
    throw TomSecretsLinkException('an X25519 key is not 32 bytes');
  }
  final secret = await X25519().sharedSecretKey(
    keyPair: mine,
    remotePublicKey: SimplePublicKey(theirs, type: KeyPairType.x25519),
  );
  final bytes = Uint8List.fromList(await secret.extractBytes());
  if (bytes.every((b) => b == 0)) {
    throw TomSecretsLinkException('a low-order X25519 point');
  }
  return bytes;
}

Uint8List _decapsulate(Uint8List ciphertext, MlKem768KeyPair key) {
  try {
    final secret = MlKem768.decapsulate(ciphertext, key.secretKey);
    final bytes = secret.extractBytes();
    secret.dispose();
    return bytes;
  } on Object {
    throw TomSecretsLinkException('an ML-KEM ciphertext does not decapsulate');
  }
}

/// What a finished handshake yields.
final class TomSecretsLinkKeys {
  TomSecretsLinkKeys._(
    this.initiatorToResponder,
    this.responderToInitiator,
    this.handshakeHash,
  );

  /// The approver-to-host key.
  final Uint8List initiatorToResponder;

  /// The host-to-approver key.
  final Uint8List responderToInitiator;

  /// The final handshake hash.
  final Uint8List handshakeHash;
}

void _mixStatics(
  _SymmetricState s,
  TomSecretsLinkPublicKey initiator,
  TomSecretsLinkPublicKey responder,
) {
  s
    ..mixHash(initiator.x25519)
    ..mixHash(initiator.mlKem768)
    ..mixHash(responder.x25519)
    ..mixHash(responder.mlKem768);
}

/// The approver's side of the handshake (the initiator, who connects).
final class TomSecretsLinkInitiator {
  /// The approver [me] connecting to the host whose recorded key is
  /// [responder].
  TomSecretsLinkInitiator(
    this.me,
    this.responder, {
    this.random = const TomSecretsSystemLinkRandom(),
  });

  /// This approver's static key.
  final TomSecretsLinkKey me;

  /// The host's recorded public key.
  final TomSecretsLinkPublicKey responder;

  /// The randomness.
  final TomSecretsLinkRandom random;

  final _SymmetricState _state = _SymmetricState();
  late SimpleKeyPair _e;
  late MlKem768KeyPair _eKem;

  /// The handshake hash so far.
  Uint8List get handshakeHash => _state.h;

  /// Message 1: e (32) || ephemeral ML-KEM key (1,184) || ciphertext to the
  /// host's static ML-KEM key (1,088) || the encrypted [payload].
  Future<Uint8List> writeMessage1(List<int> payload) async {
    _mixStatics(_state, me.publicKey, responder);
    _e = await random.ephemeralX25519();
    final ePub = (await _e.extractPublicKey()).bytes;
    _state.mixHash(ePub);
    _eKem = random.ephemeralMlKem();
    _state
      ..mixHash(_eKem.publicKey)
      ..mixKey(await _dh(_e, responder.x25519))
      ..mixKey(await _dh(me._x25519, responder.x25519));
    final sent = random.encapsulate(responder.mlKem768);
    _state
      ..mixHash(sent.ciphertext)
      ..mixKey(sent.sharedSecret.extractBytes());
    sent.sharedSecret.dispose();
    final c = await _state.encryptAndHash(payload);
    return Uint8List.fromList([
      ...ePub,
      ..._eKem.publicKey,
      ...sent.ciphertext,
      ...c,
    ]);
  }

  /// Reads message 2: its payload and the session keys.
  Future<(Uint8List, TomSecretsLinkKeys)> readMessage2(
    Uint8List message,
  ) async {
    const fixed = 32 + 1088 + 1088;
    if (message.length < fixed + 16) {
      throw TomSecretsLinkException('message 2 has a wrong length');
    }
    final re = message.sublist(0, 32);
    _state
      ..mixHash(re)
      ..mixKey(await _dh(_e, re))
      ..mixKey(await _dh(me._x25519, re));
    final c1 = message.sublist(32, 32 + 1088);
    _state
      ..mixHash(c1)
      ..mixKey(_decapsulate(c1, _eKem));
    final c2 = message.sublist(32 + 1088, fixed);
    _state
      ..mixHash(c2)
      ..mixKey(_decapsulate(c2, me._mlKem));
    final payload = await _state.decryptAndHash(message.sublist(fixed));
    final (i2r, r2i) = _state.split();
    _eKem.dispose();
    return (payload, TomSecretsLinkKeys._(i2r, r2i, _state.h));
  }
}

/// The host's side of the handshake (the responder).
final class TomSecretsLinkResponder {
  /// The host [me] answering an approver whose recorded key is [initiator].
  TomSecretsLinkResponder(
    this.me,
    this.initiator, {
    this.random = const TomSecretsSystemLinkRandom(),
  });

  /// This host's static key.
  final TomSecretsLinkKey me;

  /// The approver's recorded public key.
  final TomSecretsLinkPublicKey initiator;

  /// The randomness.
  final TomSecretsLinkRandom random;

  final _SymmetricState _state = _SymmetricState();
  late Uint8List _re;
  late Uint8List _reKem;

  /// The handshake hash so far.
  Uint8List get handshakeHash => _state.h;

  /// Reads message 1: its payload. Throws [TomSecretsLinkException] when it
  /// does not come from [initiator].
  Future<Uint8List> readMessage1(Uint8List message) async {
    const fixed = 32 + 1184 + 1088;
    if (message.length < fixed + 16) {
      throw TomSecretsLinkException('message 1 has a wrong length');
    }
    _mixStatics(_state, initiator, me.publicKey);
    _re = message.sublist(0, 32);
    _reKem = message.sublist(32, 32 + 1184);
    final c = message.sublist(32 + 1184, fixed);
    _state
      ..mixHash(_re)
      ..mixHash(_reKem)
      ..mixKey(await _dh(me._x25519, _re))
      ..mixKey(await _dh(me._x25519, initiator.x25519))
      ..mixHash(c)
      ..mixKey(_decapsulate(c, me._mlKem));
    return _state.decryptAndHash(message.sublist(fixed));
  }

  /// Message 2: e (32) || ciphertext to the approver's ephemeral ML-KEM key
  /// (1,088) || ciphertext to its static ML-KEM key (1,088) || the encrypted
  /// [payload]; and the session keys.
  Future<(Uint8List, TomSecretsLinkKeys)> writeMessage2(
    List<int> payload,
  ) async {
    final e = await random.ephemeralX25519();
    final ePub = (await e.extractPublicKey()).bytes;
    _state
      ..mixHash(ePub)
      ..mixKey(await _dh(e, _re))
      ..mixKey(await _dh(e, initiator.x25519));
    final s1 = random.encapsulate(_reKem);
    _state
      ..mixHash(s1.ciphertext)
      ..mixKey(s1.sharedSecret.extractBytes());
    s1.sharedSecret.dispose();
    final s2 = random.encapsulate(initiator.mlKem768);
    _state
      ..mixHash(s2.ciphertext)
      ..mixKey(s2.sharedSecret.extractBytes());
    s2.sharedSecret.dispose();
    final c = await _state.encryptAndHash(payload);
    final (i2r, r2i) = _state.split();
    return (
      Uint8List.fromList([...ePub, ...s1.ciphertext, ...s2.ciphertext, ...c]),
      TomSecretsLinkKeys._(i2r, r2i, _state.h),
    );
  }
}

/// One direction of the transport: ChaCha20-Poly1305 with a counter nonce,
/// empty associated data, REKEY on demand.
final class TomSecretsLinkCipher {
  /// A cipher under [key].
  TomSecretsLinkCipher(this.key);

  /// The current key.
  Uint8List key;

  /// The counter.
  int n = 0;

  /// The ciphertext of [plaintext].
  Future<Uint8List> encrypt(List<int> plaintext) =>
      _encrypt(key, n++, const [], plaintext);

  /// The plaintext of [ciphertext]; throws [TomSecretsLinkException].
  Future<Uint8List> decrypt(List<int> ciphertext) =>
      _decrypt(key, n++, const [], ciphertext);

  /// Replaces the key by Noise's REKEY; the counter goes on.
  Future<void> rekey() async => key = await tomSecretsLinkRekey(key);
}

// ── The channel ──────────────────────────────────────────────────────────

/// The approval link's byte stream (DP-100): a TCP connection in phase A,
/// the relay in phase C.
abstract interface class TomSecretsApprovalChannel {
  /// The bytes that arrive.
  Stream<List<int>> get incoming;

  /// Sends [bytes].
  void send(List<int> bytes);

  /// Ends the channel.
  Future<void> close();
}

/// A channel over a TCP [Socket].
final class TomSecretsSocketChannel implements TomSecretsApprovalChannel {
  /// The channel of [socket].
  TomSecretsSocketChannel(this.socket);

  /// The socket.
  final Socket socket;

  @override
  Stream<List<int>> get incoming => socket;

  @override
  void send(List<int> bytes) => socket.add(bytes);

  @override
  Future<void> close() async => socket.destroy();
}

/// A frame on the channel: the length as 4 bytes big-endian, then [bytes].
Uint8List tomSecretsLinkFrame(List<int> bytes) {
  final out = Uint8List(4 + bytes.length);
  ByteData.sublistView(out).setUint32(0, bytes.length);
  out.setRange(4, out.length, bytes);
  return out;
}

/// The frames of a channel read one by one ([next]), for the protocols that
/// share the approval link's framing (pairing, DP-64): a frame over 1 MiB,
/// or the channel's end, ends it.
final class TomSecretsLinkFrameReader {
  /// The reader of [channel]'s frames.
  TomSecretsLinkFrameReader(TomSecretsApprovalChannel channel)
    : _queue = _FrameQueue(channel);

  final _FrameQueue _queue;

  /// The next frame, or null when the channel ended or [timeout] passed.
  Future<Uint8List?> next(Duration timeout) => _queue.next(timeout);

  /// Stops reading.
  Future<void> cancel() => _queue.cancel();

  /// The error the channel ended with (e.g. a relay that failed), or null.
  Object? get error => _queue.error;
}

/// The frames of a channel: during the handshake read one by one with
/// [next], afterwards handed to a callback ([deliver]); a frame over 1 MiB,
/// or the channel's end, ends it.
final class _FrameQueue {
  _FrameQueue(TomSecretsApprovalChannel channel) {
    _subscription = channel.incoming.listen(
      _add,
      onError: (Object e) => _end(e),
      onDone: () => _end(null),
    );
  }

  late final StreamSubscription<List<int>> _subscription;
  final BytesBuilder _buffer = BytesBuilder(copy: false);
  final List<Uint8List> _pending = [];
  Completer<Uint8List?>? _waiting;
  void Function(Uint8List frame)? _deliver;
  void Function()? _onEnd;
  bool _ended = false;

  /// The error the channel ended with, or null.
  Object? error;

  void _add(List<int> bytes) {
    _buffer.add(bytes);
    var data = _buffer.takeBytes();
    while (data.length >= 4) {
      final length = ByteData.sublistView(data).getUint32(0);
      if (length > tomSecretsLinkMaxFrame) {
        _end(TomSecretsLinkException('a frame is over 1 MiB'));
        return;
      }
      if (data.length < 4 + length) break;
      _push(Uint8List.fromList(data.sublist(4, 4 + length)));
      data = data.sublist(4 + length);
    }
    _buffer.add(data);
  }

  void _push(Uint8List frame) {
    final deliver = _deliver;
    if (deliver != null) {
      deliver(frame);
      return;
    }
    final waiting = _waiting;
    if (waiting != null) {
      _waiting = null;
      waiting.complete(frame);
    } else {
      _pending.add(frame);
    }
  }

  void _end(Object? error) {
    if (_ended) return;
    _ended = true;
    this.error = error;
    final waiting = _waiting;
    _waiting = null;
    waiting?.complete(null);
    _onEnd?.call();
  }

  /// The next frame, or null when the channel ended.
  Future<Uint8List?> next(Duration timeout) {
    if (_pending.isNotEmpty) return Future.value(_pending.removeAt(0));
    if (_ended) return Future.value(null);
    final c = _waiting = Completer<Uint8List?>();
    return c.future.timeout(
      timeout,
      onTimeout: () {
        _waiting = null;
        return null;
      },
    );
  }

  /// From now on every frame goes to [deliver] (the pending ones first);
  /// [onEnd] when the channel ends.
  void deliver(void Function(Uint8List) deliver, void Function() onEnd) {
    _deliver = deliver;
    _onEnd = onEnd;
    final pending = [..._pending];
    _pending.clear();
    pending.forEach(deliver);
    if (_ended) onEnd();
  }

  Future<void> cancel() => _subscription.cancel();
}

/// An established approval link: JSON messages (protocol.md 2.2) both ways,
/// encrypted per direction, `rekey` handled, closed on any failure.
final class TomSecretsLinkSession {
  TomSecretsLinkSession._(
    this._channel,
    this._send,
    this._receive,
    this.peerDevice,
    this.handshakeHash, {
    this.underPreviousKey = false,
  });

  final TomSecretsApprovalChannel _channel;
  final TomSecretsLinkCipher _send;
  final TomSecretsLinkCipher _receive;

  /// The peer: the approver's device id (on the host) or the host's name
  /// (on the approver).
  final String peerDevice;

  /// On the host: whether the approver connected under the host's previous
  /// link key (`respond(previousMe:)`) — it does not know the new one yet,
  /// and the host passes it (`linkKey`). Always false on the approver.
  final bool underPreviousKey;

  /// The handshake hash.
  final Uint8List handshakeHash;

  final StreamController<Map<String, Object?>> _messages =
      StreamController.broadcast();
  _FrameQueue? _frames;
  Future<void> _decrypting = Future<void>.value();
  Future<void> _sending = Future<void>.value();
  int _sentFrames = 0;
  DateTime _rekeyedAt = DateTime.now();
  bool _closed = false;

  /// After how many frames, or how long, a side sends `rekey` (9.7).
  static int rekeyFrames = 1 << 20;

  /// See [rekeyFrames].
  static Duration rekeyAge = const Duration(hours: 1);

  /// The messages the peer sends (`rekey` is handled here, not passed on).
  Stream<Map<String, Object?>> get messages => _messages.stream;

  /// Whether the link has ended.
  bool get isClosed => _closed;

  void _listen(_FrameQueue frames) {
    _frames = frames;
    frames.deliver(
      (frame) => _decrypting = _decrypting.then((_) => _onFrame(frame)),
      () => unawaited(close()),
    );
  }

  Future<void> _onFrame(List<int> frame) async {
    if (_closed) return;
    try {
      final plain = await _receive.decrypt(frame);
      final message = jsonDecode(utf8.decode(plain));
      if (message is! Map || message['op'] is! String) {
        throw TomSecretsLinkException('a message without op');
      }
      if (message['op'] == 'rekey') {
        await _receive.rekey();
        return;
      }
      _messages.add(message.cast<String, Object?>());
    } on Object {
      await close();
    }
  }

  /// Sends [message] (JSON with `op`); after [rekeyFrames] frames or
  /// [rekeyAge] it sends `rekey` first and replaces its key.
  Future<void> send(Map<String, Object?> message) =>
      _sending = _sending.then((_) async {
        if (_closed) return;
        if (_sentFrames >= rekeyFrames ||
            DateTime.now().difference(_rekeyedAt) >= rekeyAge) {
          await _write({'op': 'rekey'});
          await _send.rekey();
          _sentFrames = 0;
          _rekeyedAt = DateTime.now();
        }
        await _write(message);
      });

  Future<void> _write(Map<String, Object?> message) async {
    final c = await _send.encrypt(utf8.encode(jsonEncode(message)));
    _sentFrames++;
    _channel.send(tomSecretsLinkFrame(c));
  }

  /// Ends the link.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _frames?.cancel();
    await _channel.close();
    // Not awaited: a listener that paused (a StreamIterator between reads)
    // would hold the close until it reads again.
    unawaited(_messages.close());
  }

  /// The approver's side: the handshake with the host recorded as
  /// [hostKey], sending [device] (this approver's device id); then `ready`.
  /// Throws [TomSecretsLinkException] when the host is not the recorded one.
  static Future<TomSecretsLinkSession> initiate(
    TomSecretsApprovalChannel channel, {
    required TomSecretsLinkKey me,
    required TomSecretsLinkPublicKey hostKey,
    required String device,
    TomSecretsLinkRandom random = const TomSecretsSystemLinkRandom(),
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final frames = _FrameQueue(channel);
    try {
      final initiator = TomSecretsLinkInitiator(me, hostKey, random: random);
      channel.send(
        tomSecretsLinkFrame(
          await initiator.writeMessage1(
            utf8.encode(jsonEncode({'protocol': 1, 'device': device})),
          ),
        ),
      );
      final message2 = await frames.next(timeout);
      if (message2 == null) {
        throw TomSecretsLinkException('the host closed the link');
      }
      final (payload, keys) = await initiator.readMessage2(message2);
      final hello = jsonDecode(utf8.decode(payload));
      if (hello is! Map || hello['protocol'] != 1 || hello['host'] is! String) {
        throw TomSecretsLinkException('message 2 carries no host');
      }
      final session = TomSecretsLinkSession._(
        channel,
        TomSecretsLinkCipher(keys.initiatorToResponder),
        TomSecretsLinkCipher(keys.responderToInitiator),
        hello['host']! as String,
        keys.handshakeHash,
      );
      session._listen(frames);
      await session.send({'op': 'ready'});
      return session;
    } on Object {
      await frames.cancel();
      await channel.close();
      rethrow;
    }
  }

  /// The host's side: reads message 1 from one of the [approvers] (a device
  /// id with a recorded link key; a device may appear twice, its previous key
  /// during the migration period), answers as [host], and waits for `ready`. Throws
  /// [TomSecretsLinkException] for an unknown peer, a device id that is not
  /// the one paired with the key, or anything that does not decrypt.
  static Future<TomSecretsLinkSession> respond(
    TomSecretsApprovalChannel channel, {
    required TomSecretsLinkKey me,
    required List<({String device, TomSecretsLinkPublicKey key})> approvers,
    required String host,
    TomSecretsLinkKey? previousMe,
    TomSecretsLinkRandom random = const TomSecretsSystemLinkRandom(),
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final frames = _FrameQueue(channel);
    try {
      final message1 = await frames.next(timeout);
      if (message1 == null) {
        throw TomSecretsLinkException('the approver closed the link');
      }
      // KK: the responder knows the initiator's key; with several paired
      // approvers, only the one whose key it is decrypts message 1. After a
      // rotation of this host's own link key, an approver that still holds
      // its previous key ([previousMe]) is answered under that one.
      for (final (:device, :key, :mine) in [
        for (final a in approvers) (device: a.device, key: a.key, mine: me),
        if (previousMe != null)
          for (final a in approvers)
            (device: a.device, key: a.key, mine: previousMe),
      ]) {
        final responder = TomSecretsLinkResponder(mine, key, random: random);
        final Uint8List payload;
        try {
          payload = await responder.readMessage1(message1);
        } on TomSecretsLinkException {
          continue;
        }
        final hello = jsonDecode(utf8.decode(payload));
        if (hello is! Map ||
            hello['protocol'] != 1 ||
            hello['device'] != device) {
          throw TomSecretsLinkException(
            'the device id is not the one paired with the key',
          );
        }
        final (message2, keys) = await responder.writeMessage2(
          utf8.encode(jsonEncode({'protocol': 1, 'host': host})),
        );
        channel.send(tomSecretsLinkFrame(message2));
        final session = TomSecretsLinkSession._(
          channel,
          TomSecretsLinkCipher(keys.responderToInitiator),
          TomSecretsLinkCipher(keys.initiatorToResponder),
          device,
          keys.handshakeHash,
          underPreviousKey: previousMe != null && identical(mine, previousMe),
        );
        // Nothing is sent before `ready` has decrypted: it proves the
        // approver holds its static ML-KEM key.
        final readyFrame = await frames.next(timeout);
        if (readyFrame == null) throw TomSecretsLinkException('no ready');
        final ready = jsonDecode(
          utf8.decode(await session._receive.decrypt(readyFrame)),
        );
        if (ready is! Map || ready['op'] != 'ready') {
          throw TomSecretsLinkException('the first message is not ready');
        }
        session._listen(frames);
        return session;
      }
      throw TomSecretsLinkException('no paired approver sent message 1');
    } on Object {
      await frames.cancel();
      await channel.close();
      rethrow;
    }
  }
}
