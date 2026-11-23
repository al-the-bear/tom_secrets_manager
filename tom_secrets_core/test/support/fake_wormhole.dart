// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// A magic-wormhole mailbox server in the test's process, following
// `magic-wormhole-mailbox-server` 0.8.0's `server_websocket.py`: the
// welcome, an `ack` for every message, `bind`, `list` (empty with the list
// disallowed), `allocate`, `claim` (crowded past two sides), `release`,
// `open` (the earlier messages sent, then every new one), `add`, `close`,
// `ping`, and `error` with `orig`. It can ask for a Hashcash proof of work
// before `bind` (the protocol's `permission-required`) and checks it.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_core/tom_secrets_core.dart';

/// One mailbox message.
typedef FakeWormholeMessage = ({String side, String phase, String body});

/// A fake mailbox server.
final class FakeWormhole {
  FakeWormhole._(this.server);

  /// Starts one; [welcome] is what its welcome carries, [disallowList]
  /// answers every `list` with none.
  static Future<FakeWormhole> start({
    Map<String, Object?> welcome = const {},
    bool disallowList = false,
  }) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final f = FakeWormhole._(server)
      ..welcome = welcome
      ..disallowList = disallowList;
    server.listen(f._handle);
    return f;
  }

  final HttpServer server;
  Map<String, Object?> welcome = const {};
  bool disallowList = false;

  /// The relay id of this server.
  String get relayId => 'wormhole:ws://127.0.0.1:${server.port}/v1';

  /// Nameplates by app id: name → (mailbox, the sides that claim it).
  final Map<String, Map<String, ({String mailbox, Set<String> sides})>>
  nameplates = {};

  /// Mailboxes: id → messages.
  final Map<String, List<FakeWormholeMessage>> mailboxes = {};

  /// Each mailbox's sides and how they closed it (`side` → mood).
  final Map<String, Map<String, String>> moods = {};

  /// Every message a client sent, in order.
  final List<Map<String, Object?>> received = [];

  /// The stamps submitted.
  final List<String> stamps = [];

  final Map<String, List<void Function(FakeWormholeMessage)>> _listeners = {};
  int _mailboxes = 0;

  Future<void> close() => server.close(force: true);

  Future<void> _handle(HttpRequest request) async {
    final socket = await WebSocketTransformer.upgrade(request);
    String? app;
    String? side;
    String? nameplate;
    String? mailbox;
    void Function(FakeWormholeMessage)? listener;
    void send(String type, [Map<String, Object?> fields = const {}]) =>
        socket.add(jsonEncode({'type': type, ...fields, 'server_tx': 0}));
    send('welcome', {
      'welcome': {
        ...welcome,
        'your-address': {'ipv4': '127.0.0.1'},
      },
    });
    await for (final data in socket) {
      final m = (jsonDecode(data as String) as Map).cast<String, Object?>();
      received.add(m);
      send('ack', {'id': m['id']});
      void error(String e) => send('error', {'error': e, 'orig': m});
      switch (m['type']) {
        case 'submit-permissions':
          final stamp = '${m['stamp']}';
          stamps.add(stamp);
          final hashcash =
              (welcome['permission-required'] as Map?)?['hashcash'];
          final parts = stamp.split(':');
          if (hashcash is! Map ||
              m['method'] != 'hashcash' ||
              parts.length != 7 ||
              parts[1] != '${hashcash['bits']}' ||
              parts[3] != hashcash['resource'] ||
              tomSecretsHashcashBits(stamp) < (hashcash['bits'] as int)) {
            error('permission denied');
            await socket.close();
          }
        case 'ping':
          send('pong', {'pong': m['ping']});
        case 'bind':
          if (app != null) {
            error('already bound');
          } else {
            app = '${m['appid']}';
            side = '${m['side']}';
          }
        case _ when app == null:
          error('must bind first');
        case 'list':
          final names = disallowList
              ? const <String>[]
              : (nameplates[app]?.keys.toList() ?? const <String>[]);
          send('nameplates', {
            'nameplates': [
              for (final n in names) {'id': n},
            ],
          });
        case 'allocate':
          final used = nameplates.putIfAbsent(app, () => {});
          var n = 1;
          while (used.containsKey('$n')) {
            n++;
          }
          nameplate = '$n';
          _claim(app, '$n', side!);
          send('allocated', {'nameplate': '$n'});
        case 'claim':
          final n = '${m['nameplate']}';
          final claimed = _claim(app, n, side!);
          if (claimed == null) {
            error('crowded');
          } else {
            nameplate = n;
            send('claimed', {'mailbox': claimed});
          }
        case 'release':
          final n = m['nameplate'] as String? ?? nameplate;
          final entry = nameplates[app]?[n];
          entry?.sides.remove(side);
          if (entry != null && entry.sides.isEmpty) nameplates[app]!.remove(n);
          send('released');
        case 'open':
          mailbox = '${m['mailbox']}';
          final box = mailboxes.putIfAbsent(mailbox, () => []);
          void deliver(FakeWormholeMessage sm) => send('message', {
            'side': sm.side,
            'phase': sm.phase,
            'body': sm.body,
          });
          for (final sm in [...box]) {
            deliver(sm);
          }
          listener = deliver;
          _listeners.putIfAbsent(mailbox, () => []).add(deliver);
        case 'add':
          if (mailbox == null) {
            error('must open mailbox before adding');
          } else {
            final sm = (
              side: side!,
              phase: '${m['phase']}',
              body: '${m['body']}',
            );
            mailboxes[mailbox]!.add(sm);
            for (final l in [...?_listeners[mailbox]]) {
              l(sm);
            }
          }
        case 'close':
          final box = (m['mailbox'] as String?) ?? mailbox;
          _listeners[box]?.remove(listener);
          moods.putIfAbsent(box!, () => {})[side!] = '${m['mood']}';
          send('closed');
        default:
          error('unknown type');
      }
    }
    if (mailbox != null) _listeners[mailbox]?.remove(listener);
  }

  /// Claims [n] for [side]; the mailbox, or null when two others have it.
  String? _claim(String app, String n, String side) {
    final used = nameplates.putIfAbsent(app, () => {});
    final entry = used.putIfAbsent(
      n,
      () => (mailbox: 'mb${++_mailboxes}', sides: <String>{}),
    );
    if (!entry.sides.contains(side) && entry.sides.length >= 2) return null;
    entry.sides.add(side);
    return entry.mailbox;
  }
}
