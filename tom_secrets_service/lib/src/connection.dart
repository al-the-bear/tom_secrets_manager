// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// One connection of an endpoint (protocol.md 2): frames read with the
/// request limit checked before a payload is read, JSON payloads decoded
/// strictly, answers sent within the answer limit.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:tom_secrets_client/tom_secrets_client.dart';

import 'secret_frame.dart';

/// A connection to a client or an admin.
final class TomSecretsConnection {
  /// Reads [socket]; [onMessage] gets each JSON message, [onClosed] is told
  /// once when the connection ends.
  TomSecretsConnection(
    this.socket, {
    required this.onMessage,
    required this.onClosed,
  }) {
    _subscription = socket.listen(
      _data,
      onError: (Object _) => close(),
      onDone: close,
      cancelOnError: true,
    );
  }

  /// The socket.
  final Socket socket;

  /// Called for every message.
  final void Function(Map<String, Object?> message) onMessage;

  /// Called once when the connection ends.
  final void Function() onClosed;

  final TomSecretsFrameReader _reader = TomSecretsFrameReader(
    maxPayload: tomSecretsMaxRequestPayload,
  );
  late final StreamSubscription<List<int>> _subscription;
  bool _closed = false;

  /// Whether the connection has ended.
  bool get isClosed => _closed;

  void _data(List<int> bytes) {
    if (_closed) return;
    final List<TomSecretsFrame> frames;
    try {
      frames = _reader.add(bytes);
    } on TomSecretsFrameException {
      // An oversized length or an unknown type: closed without reading on.
      unawaited(close());
      return;
    }
    for (final frame in frames) {
      if (_closed) return;
      final Map<String, Object?> message;
      try {
        message = tomSecretsDecodePayload(frame.payload);
      } on TomSecretsFrameException catch (e) {
        sendError(null, 'malformed', e.message, {'reason': 'frame'});
        unawaited(close());
        return;
      }
      onMessage(message);
    }
  }

  /// Sends [message], its [TomSecretsSecretSlot]s written from their bytes
  /// (`tomSecretsSecretFrame`); an answer over the answer limit is replaced
  /// by an `internal` error. Frames are written in order, one at a time, and
  /// each is zeroed once the socket has flushed it: `Socket.add` keeps the
  /// buffer until it is written, so it cannot be wiped earlier.
  void send(Map<String, Object?> message) {
    if (_closed) return;
    final frame =
        tomSecretsSecretFrame(message) ??
        tomSecretsJsonFrame({
          'op': 'error',
          'id': ?message['id'],
          'kind': 'internal',
          'message': 'the answer is larger than a frame',
          'details': {'code': 'answer_too_large'},
        });
    _tail = _tail.then((_) => _write(frame));
  }

  Future<void> _tail = Future<void>.value();

  Future<void> _write(Uint8List frame) async {
    try {
      socket.add(frame);
      await socket.flush();
    } on Object {
      // The peer went first; the connection closes on its own.
    } finally {
      frame.fillRange(0, frame.length, 0);
      onFrameWritten?.call(frame);
    }
  }

  /// Called with each frame after it was written and zeroed (tests).
  void Function(Uint8List frame)? onFrameWritten;

  /// Sends an `error` of [kind]; without [id] it concerns the connection.
  void sendError(
    Object? id,
    String kind,
    String message, [
    Map<String, Object?>? details,
  ]) => send({
    'op': 'error',
    'id': ?id,
    'kind': kind,
    'message': message,
    'details': ?details,
  });

  /// Ends the connection.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription.cancel();
    // The queued frames are written (and wiped) first; a peer that stops
    // reading does not hold the close up for long.
    await _tail.timeout(const Duration(seconds: 5), onTimeout: () {});
    socket.destroy();
    onClosed();
  }
}
