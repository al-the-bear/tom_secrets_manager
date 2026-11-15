// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The approver's side of the approval link (protocol.md 9.7) for what this
/// device sends a paired host on its own: its key-change statement and its
/// new link key after a rotation (part-key-rotation). A session is opened to
/// the host's link address as the initiator, each message is answered `ok`
/// or `error`, and the session is closed.
library;

import 'dart:async';
import 'dart:io';

import 'package:tom_secrets_core/tom_secrets_core.dart';

/// A message the host refused (`error`), or a link that could not be
/// opened or closed before every answer.
final class TomSecretsLinkDeliveryException implements Exception {
  /// A failure: [message], and the error's [kind] when the host answered
  /// one.
  const TomSecretsLinkDeliveryException(this.message, {this.kind});

  /// What went wrong.
  final String message;

  /// The host's error kind, or null when the link itself failed.
  final String? kind;

  @override
  String toString() => 'TomSecretsLinkDeliveryException: $message';
}

/// Sends [messages] (each without `id`, which is added) to the host at
/// [address] (`host:port`) over a link session initiated with this device's
/// link key [me], the host's recorded key [hostKey] and this [device]'s
/// name; each must be answered `ok`. Throws
/// [TomSecretsLinkDeliveryException]; [timeout] bounds the connection and
/// each answer.
Future<void> tomSecretsDeliverOverLink({
  required String address,
  required TomSecretsLinkKey me,
  required TomSecretsLinkPublicKey hostKey,
  required String device,
  required List<Map<String, Object?>> messages,
  Duration timeout = const Duration(seconds: 5),
}) async {
  final at = address.lastIndexOf(':');
  final port = at < 0 ? null : int.tryParse(address.substring(at + 1));
  if (at <= 0 || port == null) {
    throw TomSecretsLinkDeliveryException('no link address: $address');
  }
  final Socket socket;
  try {
    socket = await Socket.connect(
      address.substring(0, at),
      port,
      timeout: timeout,
    );
  } on SocketException catch (e) {
    throw TomSecretsLinkDeliveryException(
      '$address could not be reached: ${e.message}',
    );
  }
  TomSecretsLinkSession? session;
  StreamIterator<Map<String, Object?>>? answers;
  try {
    session = await TomSecretsLinkSession.initiate(
      TomSecretsSocketChannel(socket),
      me: me,
      hostKey: hostKey,
      device: device,
    ).timeout(timeout);
    answers = StreamIterator(session.messages);
    var id = 0;
    for (final message in messages) {
      id++;
      await session.send({...message, 'id': id});
      Map<String, Object?>? answer;
      while (await answers.moveNext().timeout(timeout)) {
        if (answers.current['id'] == id) {
          answer = answers.current;
          break;
        }
      }
      if (answer == null) {
        throw const TomSecretsLinkDeliveryException(
          'the host closed the link before it answered',
        );
      }
      if (answer['op'] != 'ok') {
        throw TomSecretsLinkDeliveryException(
          'the host refused ${message['op']}: ${answer['message']}',
          kind: answer['kind'] as String?,
        );
      }
    }
  } on TimeoutException {
    throw TomSecretsLinkDeliveryException('$address did not answer in time');
  } on TomSecretsLinkDeliveryException {
    rethrow;
  } on Object catch (e) {
    throw TomSecretsLinkDeliveryException(
      'the link to $address failed: ${e.runtimeType}',
    );
  } finally {
    await answers?.cancel();
    if (session != null) {
      await session.close();
    } else {
      socket.destroy();
    }
  }
}
