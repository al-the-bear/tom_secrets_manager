// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A client connection that speaks frames by hand, for the messages the
/// client library leaves to the browser host and the helpers.
library;

import 'dart:async';
import 'dart:collection';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'setup.dart';

/// A client connection that speaks frames by hand: `hello` without
/// features, `match`, `propose` and the passkey messages.
final class RawClient {
  RawClient._(this.socket) {
    socket.listen((bytes) {
      for (final f in reader.add(bytes)) {
        final m = tomSecretsDecodePayload(f.payload);
        if (waiting.isNotEmpty) {
          waiting.removeFirst().complete(m);
        } else {
          queue.add(m);
        }
      }
    });
  }

  static Future<RawClient> open(
    Demo demo,
    TomSecretsTransport transport,
  ) async {
    final runtime = demo.runtime(transport);
    final socket = transport == TomSecretsTransport.unix
        ? await Socket.connect(
            InternetAddress(
              runtime.clientSocket,
              type: InternetAddressType.unix,
            ),
            0,
          )
        : await Socket.connect(
            InternetAddress.loopbackIPv4,
            readTomSecretsPortFile(
              File(runtime.clientPortFile).readAsStringSync(),
            )!,
          );
    addTearDown(socket.destroy);
    return RawClient._(socket);
  }

  final Socket socket;
  final TomSecretsFrameReader reader = TomSecretsFrameReader(
    maxPayload: tomSecretsMaxAnswerPayload,
  );
  final Queue<Map<String, Object?>> queue = Queue();
  final Queue<Completer<Map<String, Object?>>> waiting = Queue();

  void send(Map<String, Object?> m) => socket.add(tomSecretsJsonFrame(m));

  Future<Map<String, Object?>> next() {
    if (queue.isNotEmpty) return Future.value(queue.removeFirst());
    final c = Completer<Map<String, Object?>>();
    waiting.add(c);
    return c.future.timeout(const Duration(seconds: 10));
  }

  /// Says hello (with [features]) and returns the welcome.
  Future<Map<String, Object?>> hello(
    TomSecretsService service, {
    List<String>? features,
  }) {
    send({
      'op': 'hello',
      'protocol': 1,
      'client': {'name': 'demo-host-extension', 'version': '1'},
      if (Platform.isWindows) 'token': service.clientToken,
      'features': ?features,
    });
    return next();
  }

  /// Sends [request] and returns its answer.
  Future<Map<String, Object?>> ask(Map<String, Object?> request) {
    send(request);
    return next();
  }
}
