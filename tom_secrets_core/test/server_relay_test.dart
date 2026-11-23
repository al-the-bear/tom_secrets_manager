// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The relay server's client (`tsm:`) against a small fake of the relay's
// `/v1` API in this process: the URLs, the headers, the proof, the
// channels. The real server (`tom_secrets_relay`) runs this client in its
// own end-to-end tests.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

/// A fake relay: one nameplate, WebSockets joined by path, a mailbox in a
/// map, proofs checked.
final class _FakeRelay {
  _FakeRelay._(this.server);

  static Future<_FakeRelay> start() async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final relay = _FakeRelay._(server);
    server.listen(relay._handle);
    return relay;
  }

  final HttpServer server;
  final List<HttpRequest> requests = [];
  final Map<String, List<WebSocket>> sockets = {};
  final Map<String, Uint8List> items = {};
  final Set<String> proofs = {};
  String? nameplate;
  int challenges = 0;

  /// How many of the next requests answer 429 with `Retry-After: 2`.
  int busy = 0;

  String get base => 'http://127.0.0.1:${server.port}/relay';

  Future<void> _handle(HttpRequest request) async {
    requests.add(request);
    final path = request.uri.path;
    final res = request.response;
    if (busy > 0) {
      busy--;
      res
        ..statusCode = 429
        ..headers.set('retry-after', '2')
        ..headers.contentType = ContentType.json
        ..write(jsonEncode({'error': 'too many puts per instance token'}));
      await res.close();
      return;
    }
    Future<void> answer(int status, [Object? json]) async {
      res.statusCode = status;
      if (json != null) {
        res.headers.contentType = ContentType.json;
        res.write(jsonEncode(json));
      }
      await res.close();
    }

    if (path == '/relay/v1/pair' && request.method == 'POST') {
      nameplate = '42';
      return answer(200, {'nameplate': '42', 'expires': '2026-11-23T12:10Z'});
    }
    final ws = RegExp(r'^/relay/v1/(pair|link)/(.+)$').firstMatch(path);
    if (ws != null && WebSocketTransformer.isUpgradeRequest(request)) {
      if (ws[1] == 'pair' && ws[2] != nameplate) {
        return answer(404, {'error': 'no pairing'});
      }
      if (ws[1] == 'link' &&
          request.headers.value('authorization') != 'Bearer instance-token-1') {
        return answer(401, {'error': 'token'});
      }
      final socket = await WebSocketTransformer.upgrade(request);
      final peers = sockets.putIfAbsent(path, () => []);
      peers.add(socket);
      socket.listen(
        (m) {
          for (final p in peers) {
            if (!identical(p, socket)) p.add(m);
          }
        },
        onDone: () {
          for (final p in [...peers]) {
            if (!identical(p, socket)) unawaited(p.close(4000, 'left'));
          }
        },
      );
      return;
    }
    final mailbox = RegExp(
      r'^/relay/v1/mailbox/([a-z2-7]{52})(?:/(.+))?$',
    ).firstMatch(path);
    if (mailbox != null) {
      final recipient = mailbox[1]!;
      final item = mailbox[2];
      final body = await request.fold<List<int>>([], (a, b) => a..addAll(b));
      if (item == 'challenge' && request.method == 'POST') {
        challenges++;
        final r = TomSecretsAgeRecipient.parse(utf8.decode(body));
        if (r.fingerprint != recipient) return answer(400, {'error': 'hash'});
        final proof = 'proof-$challenges';
        proofs.add(proof);
        final file = await tomSecretsAgeEncrypt(utf8.encode(proof), [r]);
        res.headers.contentType = ContentType.binary;
        res.add(file);
        return res.close();
      }
      if (request.method == 'PUT') {
        if (request.headers.value('authorization') !=
            'Bearer instance-token-1') {
          return answer(401, {'error': 'add the instance token'});
        }
        items['$recipient/$item'] = Uint8List.fromList(body);
        return answer(201, {'id': item});
      }
      final auth = request.headers.value('authorization') ?? '';
      if (!proofs.contains(auth.replaceFirst('Bearer ', ''))) {
        return answer(401, {'error': 'proof'});
      }
      if (item == null) {
        return answer(200, {
          'items': [
            for (final e in items.entries)
              if (e.key.startsWith('$recipient/'))
                {
                  'id': e.key.split('/').last,
                  'size': e.value.length,
                  'received': '2026-11-23T12:00:00.000Z',
                  'expires': '2026-12-23T12:00:00.000Z',
                },
          ],
        });
      }
      if (request.method == 'DELETE') {
        return answer(items.remove('$recipient/$item') == null ? 404 : 204);
      }
      final bytes = items['$recipient/$item'];
      if (bytes == null) return answer(404, {'error': 'none'});
      res.headers.contentType = ContentType.binary;
      res.add(bytes);
      return res.close();
    }
    return answer(404, {'error': 'not found'});
  }

  Future<void> close() => server.close(force: true);
}

void main() {
  late _FakeRelay fake;
  late TomSecretsServerRelay relay;
  setUp(() async {
    fake = await _FakeRelay.start();
    relay = TomSecretsServerRelay(
      TomSecretsRelayId.parse('tsm:${fake.base}'),
      token: 'instance-token-1',
    );
  });
  tearDown(() async {
    relay.close();
    await fake.close();
  });

  test('offers all three services and refuses another kind', () {
    expect(relay.services, TomSecretsRelayService.values.toSet());
    expect(
      () => TomSecretsServerRelay(TomSecretsRelayId.parse('github:a/b')),
      throwsArgumentError,
    );
  });

  test(
    'a pairing: the host allocates, the joiner joins, frames flow',
    () async {
      final host = await relay.host();
      expect(host.nameplate, '42');
      final joiner = await TomSecretsServerRelay(
        TomSecretsRelayId.parse('tsm:${fake.base}'),
      ).join('42');
      final atHost = StreamIterator(host.incoming);
      final atJoiner = StreamIterator(joiner.incoming);
      joiner.send([1, 2, 3]);
      await host.joined;
      expect(await atHost.moveNext(), isTrue);
      expect(atHost.current, [1, 2, 3]);
      host.send(utf8.encode('hi'));
      expect(await atJoiner.moveNext(), isTrue);
      expect(utf8.decode(atJoiner.current), 'hi');
      // The host leaving ends the joiner's channel, without an error.
      await host.close();
      expect(await atJoiner.moveNext(), isFalse);
    },
  );

  test('joining a nameplate that is not open names the relay', () async {
    await expectLater(
      relay.join('7'),
      throwsA(
        isA<TomSecretsRelayException>()
            .having((e) => e.relay, 'relay', 'tsm:${fake.base}')
            .having((e) => e.message, 'message', contains('no pairing')),
      ),
    );
    expect(() => relay.join('1000'), throwsA(isA<TomSecretsRelayException>()));
  });

  test('a link carries the instance token', () async {
    final a = await relay.link('link-abcdef12');
    final b = await relay.link('link-abcdef12');
    final got = b.incoming.first;
    a.send([9]);
    expect(await got, [9]);
    await a.close();
    await b.close();
    final withoutToken = TomSecretsServerRelay(
      TomSecretsRelayId.parse('tsm:${fake.base}'),
    );
    await expectLater(
      withoutToken.link('link-abcdef12'),
      throwsA(
        isA<TomSecretsRelayException>().having(
          (e) => e.message,
          'message',
          contains('instance token'),
        ),
      ),
    );
  });

  group('the mailbox', () {
    late TomSecretsMemberKey me;
    setUpAll(() async => me = await TomSecretsMemberKey.generate());
    tearDownAll(() => me.dispose());

    test('put with the token, list, fetch, delete with the proof', () async {
      final expires = DateTime.utc(2026, 12, 1);
      await relay.put(
        TomSecretsMailboxItem(
          recipient: me.recipient.fingerprint,
          itemId: '2026-11-23-0123456789abcdef.age',
          bytes: Uint8List.fromList([5, 6]),
          expires: expires,
        ),
      );
      final put = fake.requests.firstWhere((r) => r.method == 'PUT');
      expect(put.headers.value('tsm-expires'), expires.toIso8601String());
      final list = await relay.list(me);
      expect(list.single.itemId, '2026-11-23-0123456789abcdef.age');
      expect(list.single.size, 2);
      expect(list.single.expires, DateTime.utc(2026, 12, 23, 12));
      expect(await relay.fetch(me, '2026-11-23-0123456789abcdef.age'), [5, 6]);
      await relay.delete(me, '2026-11-23-0123456789abcdef.age');
      expect(await relay.list(me), isEmpty);
      // One challenge served the four calls.
      expect(fake.challenges, 1);
    });

    test('a proof the relay no longer takes is asked for again', () async {
      await relay.list(me);
      fake.proofs.clear();
      expect(await relay.list(me), isEmpty);
      expect(fake.challenges, 2);
    });

    test('a put without a token says what is missing', () async {
      final bare = TomSecretsServerRelay(
        TomSecretsRelayId.parse('tsm:${fake.base}'),
      );
      await expectLater(
        bare.put(
          TomSecretsMailboxItem(
            recipient: me.recipient.fingerprint,
            itemId: 'x',
            bytes: Uint8List(1),
            expires: DateTime.utc(2026, 12, 1),
          ),
        ),
        throwsA(
          isA<TomSecretsRelayException>().having(
            (e) => e.message,
            'message',
            contains('add the instance token'),
          ),
        ),
      );
    });
  });

  test('tomSecretsRelayFor builds each kind', () {
    expect(
      tomSecretsRelayFor(TomSecretsRelayId.parse('tsm:https://r.example')),
      isA<TomSecretsServerRelay>(),
    );
    expect(
      tomSecretsRelayFor(
        TomSecretsRelayId.parse('github:owner/repo'),
        token: 'github-token',
      ),
      isA<TomSecretsGitHubRelay>(),
    );
    expect(
      () => tomSecretsRelayFor(TomSecretsRelayId.parse('github:owner/repo')),
      throwsA(isA<TomSecretsRelayException>()),
    );
    expect(
      tomSecretsRelayFor(TomSecretsRelayId.parse('wormhole:wss://w.example')),
      isA<TomSecretsWormholeRelay>(),
    );
    expect(
      tomSecretsRelayNeedsToken(
        TomSecretsRelayId.parse('wormhole:wss://w.example'),
      ),
      isFalse,
    );
    expect(
      tomSecretsRelayNeedsToken(TomSecretsRelayId.parse('github:owner/repo')),
      isTrue,
    );
    expect(
      tomSecretsRelayNeedsToken(TomSecretsRelayId.parse('tsm:https://r.x')),
      isFalse,
    );
  });

  group('a relay\'s limits', () {
    late List<Duration> slept;
    late TomSecretsServerRelay paced;
    setUp(() {
      slept = [];
      paced = TomSecretsServerRelay(
        TomSecretsRelayId.parse('tsm:${fake.base}'),
        token: 'instance-token-1',
        pacer: TomSecretsRelayPacer(sleep: (d) async => slept.add(d)),
      );
    });
    tearDown(() => paced.close());

    TomSecretsMailboxItem item() => TomSecretsMailboxItem(
      recipient: 'a' * 52,
      itemId: 'x',
      bytes: Uint8List.fromList([1]),
      expires: DateTime.utc(2026, 12, 1),
    );

    test('a 429 with Retry-After is waited out and asked again once', () async {
      fake.busy = 1;
      await paced.put(item());
      expect(slept, [const Duration(seconds: 2)]);
      expect(fake.items, contains('${'a' * 52}/x'));
      expect(fake.requests.where((r) => r.method == 'PUT'), hasLength(2));
    });

    test('a second 429 is said with the relay\'s message', () async {
      fake.busy = 2;
      await expectLater(
        paced.put(item()),
        throwsA(
          isA<TomSecretsRelayException>().having(
            (e) => e.message,
            'message',
            contains('too many puts per instance token'),
          ),
        ),
      );
      expect(slept, [const Duration(seconds: 2)]);
    });

    test(
      'a refused WebSocket upgrade with Retry-After is waited out once',
      () async {
        fake.busy = 1;
        final a = await paced.link('link-abcdef12');
        expect(slept, [const Duration(seconds: 2)]);
        await a.close();
      },
    );
  });
}
