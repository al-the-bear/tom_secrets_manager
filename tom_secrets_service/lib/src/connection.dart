// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// One connection of an endpoint (protocol.md 2): frames read with the
/// request limit checked before a payload is read, JSON payloads decoded
/// strictly, answers sent within the answer limit.
library;

import 'dart:async';
import 'dart:io';

import 'package:tom_secrets_client/tom_secrets_client.dart';

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

  /// Sends [message]; an answer over the answer limit is replaced by an
  /// `internal` error.
  void send(Map<String, Object?> message) {
    if (_closed) return;
    var frame = tomSecretsJsonFrame(message);
    if (frame.length - 5 > tomSecretsMaxAnswerPayload) {
      frame = tomSecretsJsonFrame({
        'op': 'error',
        'id': ?message['id'],
        'kind': 'internal',
        'message': 'the answer is larger than a frame',
        'details': {'code': 'answer_too_large'},
      });
    }
    // Not wiped here: the socket keeps the buffer until it is written.
    socket.add(frame);
  }

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
    try {
      await socket.flush();
    } on Object {
      // The peer went first.
    }
    socket.destroy();
    onClosed();
  }
}
