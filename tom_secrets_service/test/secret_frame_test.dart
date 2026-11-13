// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Frames that carry secrets (part-service, Memory hygiene): written from
/// bytes that are zeroed afterwards, byte for byte the frame `jsonEncode`
/// would give, and wiped by the connection once the socket has sent them.
/// Demo data only.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_crypto/protected_value.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

/// A slot over [bytes] that records the buffers it handed out.
TomSecretsSecretSlot recording(
  Uint8List bytes,
  List<Uint8List> seen, {
  bool base64 = false,
}) {
  final value = TomProtectedValue.fromBytes(Uint8List.fromList(bytes));
  T read<T>(T Function(Uint8List bytes) use) => value.withRevealed((b) {
    seen.add(b);
    return use(b);
  });
  return base64
      ? TomSecretsSecretSlot.base64(read)
      : TomSecretsSecretSlot.text(read);
}

void main() {
  group('tomSecretsSecretFrame', () {
    test('text with every kind of character: the frame jsonEncode writes', () {
      final texts = [
        '',
        'demo-db-pw',
        'quote " backslash \\ slash /',
        'tab\t newline\n cr\r bs\b ff\f nul\u0000 esc\u001b del\u007f',
        'pässwörd 🔑 日本',
      ];
      for (final text in texts) {
        final seen = <Uint8List>[];
        final message = {
          'op': 'value',
          'id': 7,
          'value': recording(utf8.encode(text), seen),
          'encoding': 'utf8',
        };
        final frame = tomSecretsSecretFrame(message)!;
        expect(
          frame,
          tomSecretsJsonFrame({...message, 'value': text}),
          reason: jsonEncode(text),
        );
        expect(seen, isNotEmpty);
        for (final buffer in seen) {
          expect(buffer, everyElement(0), reason: 'zeroed after use');
        }
      }
    });

    test('bytes of every length as base64: the frame jsonEncode writes', () {
      for (var n = 0; n <= 7; n++) {
        final bytes = Uint8List.fromList([for (var i = 0; i < n; i++) 250 - i]);
        final seen = <Uint8List>[];
        final message = {
          'op': 'value',
          'value': recording(bytes, seen, base64: true),
        };
        expect(
          tomSecretsSecretFrame(message),
          tomSecretsJsonFrame({...message, 'value': base64Encode(bytes)}),
          reason: '$n bytes',
        );
      }
    });

    test('several slots in nested results, in any order', () {
      final seen = <Uint8List>[];
      final message = {
        'op': 'values',
        'id': 3,
        'results': [
          {'op': 'value', 'value': recording(utf8.encode('first'), seen)},
          {'op': 'error', 'kind': 'not_found'},
          {
            'op': 'value',
            'value': recording(Uint8List.fromList([1, 2]), seen, base64: true),
          },
        ],
        'keys': {'password': recording(utf8.encode('pw'), seen)},
      };
      expect(
        tomSecretsSecretFrame(message),
        tomSecretsJsonFrame({
          'op': 'values',
          'id': 3,
          'results': [
            {'op': 'value', 'value': 'first'},
            {'op': 'error', 'kind': 'not_found'},
            {'op': 'value', 'value': 'AQI='},
          ],
          'keys': {'password': 'pw'},
        }),
      );
      expect(
        tomSecretsDecodePayload(
          tomSecretsSecretFrame(message)!.sublist(5),
        )['keys'],
        {'password': 'pw'},
      );
    });

    test('over the answer limit: null, the secret not written', () {
      final seen = <Uint8List>[];
      expect(
        tomSecretsSecretFrame({
          'op': 'value',
          'value': recording(Uint8List(100), seen),
        }, maxPayload: 50),
        isNull,
      );
      for (final buffer in seen) {
        expect(buffer, everyElement(0));
      }
    });

    test('a slot never shows its secret', () {
      final slot = TomSecretsSecretSlot.ofText(TomProtectedValue.of('hunter2'));
      expect('$slot', isNot(contains('hunter2')));
    });
  });

  test('the connection wipes each frame once the socket has sent it, and '
      'the peer reads the secret', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    final accepted = server.first;
    final peer = await Socket.connect(
      InternetAddress.loopbackIPv4,
      server.port,
    );
    addTearDown(peer.destroy);
    final connection = TomSecretsConnection(
      await accepted,
      onMessage: (_) {},
      onClosed: () {},
    );
    final written = <Uint8List>[];
    connection.onFrameWritten = written.add;
    final reader = TomSecretsFrameReader(
      maxPayload: tomSecretsMaxAnswerPayload,
    );
    final messages = StreamController<Map<String, Object?>>();
    peer.listen((bytes) {
      for (final f in reader.add(bytes)) {
        messages.add(tomSecretsDecodePayload(f.payload));
      }
    });
    final received = StreamIterator(messages.stream);
    final big = 'x' * 300000;
    connection
      ..send({
        'op': 'value',
        'id': 1,
        'value': TomSecretsSecretSlot.ofText(TomProtectedValue.of('demo-pw')),
      })
      ..send({
        'op': 'value',
        'id': 2,
        'value': TomSecretsSecretSlot.ofText(TomProtectedValue.of(big)),
      });
    expect(await received.moveNext(), isTrue);
    expect(received.current['value'], 'demo-pw');
    expect(await received.moveNext(), isTrue);
    expect(received.current['id'], 2, reason: 'in order');
    expect((received.current['value'] as String).length, big.length);
    await connection.close();
    expect(written, hasLength(2));
    for (final frame in written) {
      expect(frame, everyElement(0), reason: 'wiped after the flush');
    }
  });
}
