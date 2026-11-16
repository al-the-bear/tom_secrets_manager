// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The approver's side of the approval link (protocol.md 9.7) for what this
/// device sends a paired host on its own: its key-change statement and its
/// new link key after a rotation (part-key-rotation). A session is opened to
/// the host's link address as the initiator, each message is answered `ok`
/// or `error`, and the session is closed.
library;

import 'dart:async';
import 'dart:convert';
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
///
/// A host that rotated its own link key and was reached under its previous
/// one sends its new key first (`linkKey {id, device, x25519, mlKem768}`,
/// protocol.md 9.7): [onHostLinkKey] records it (in the session authenticated
/// under the old keys), and the host is answered `ok`.
Future<void> tomSecretsDeliverOverLink({
  required String address,
  required TomSecretsLinkKey me,
  required TomSecretsLinkPublicKey hostKey,
  required String device,
  required List<Map<String, Object?>> messages,
  Future<void> Function(TomSecretsLinkPublicKey key)? onHostLinkKey,
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
  // A write that fails (the host went away) is reported through `done`;
  // the session's stream ends and the delivery fails as told below.
  unawaited(socket.done.then<void>((_) {}, onError: (Object _) {}));
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
        final current = answers.current;
        if (current['op'] == 'linkKey' && current['id'] is String) {
          await tomSecretsTakeHostLinkKey(session, current, onHostLinkKey);
          continue;
        }
        if (current['id'] == id) {
          answer = current;
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

/// Records the host's new link key of [message] through [onHostLinkKey] and
/// answers it: `ok`, or `error` for a key of another device or that cannot
/// be read.
Future<void> tomSecretsTakeHostLinkKey(
  TomSecretsLinkSession session,
  Map<String, Object?> message,
  Future<void> Function(TomSecretsLinkPublicKey key)? onHostLinkKey,
) async {
  final id = message['id'];
  Future<void> fail(String why) => session.send({
    'op': 'error',
    'id': id,
    'kind': 'denied',
    'message': why,
    'details': {'reason': 'refused'},
  });
  if (message['device'] != session.peerDevice) {
    await fail('the key names another device');
    return;
  }
  final TomSecretsLinkPublicKey key;
  try {
    key = TomSecretsLinkPublicKey(
      base64.decode(message['x25519']! as String),
      base64.decode(message['mlKem768']! as String),
    );
  } on Object {
    await fail('the key cannot be read');
    return;
  }
  await onHostLinkKey?.call(key);
  await session.send({'op': 'ok', 'id': id});
}
