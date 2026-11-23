// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** A magic-wormhole mailbox server as a relay (part-relay, DP-66,
/// DP-180, `wormhole:<ws(s) url>`): pairing only.
///
/// The app runs on the existing servers unchanged (the public
/// `ws://relay.magic-wormhole.io:4000/v1` or a self-hosted
/// `magic-wormhole-mailbox-server`) and speaks only the mailbox protocol a
/// client needs: the WebSocket JSON messages `bind`, `list`, `allocate`,
/// `claim`, `open`, `add`, `release`, `close` and `ping`, with the
/// `welcome`'s `motd` and `error` read and a Hashcash proof of work
/// answered (`submit-permissions`) when the welcome asks for one.
///
/// - **Its own application id** ([tomSecretsWormholeAppId]): its nameplates
///   and mailboxes never meet the `wormhole` tools' traffic, and the
///   `wormhole` command cannot exchange anything with the app.
/// - **Pairing:** the hosting side allocates the nameplate (the pairing
///   code's number), claims it, opens its mailbox and adds a first message
///   (phase `host`); the joining side claims the nameplate and opens the
///   mailbox, and finds no pairing there when that message is missing (a
///   claim opens any nameplate, and a server may refuse its list). Each
///   [TomSecretsPairingChannel.send] is one mailbox message (`add`, the
///   bytes as hex, a phase counting up per side), so the pairing's own
///   SPAKE2 with the ML-KEM-768 exchange inside runs in the mailbox
///   unchanged: the server sees ciphertext only, and magic-wormhole's own
///   classical SPAKE2 is not used (DP-177). A side that closes adds a last
///   message (phase `close`), which ends the other side's channel.
/// - **The code's lifetime** is the app's own 10 minutes
///   ([tomSecretsWormholeLifetime], DP-180): the hosting side closes its
///   mailbox (`lonely`) when no one came by then, whatever the server's own
///   pruning; the nameplate is released as soon as the other side came.
/// - **No mailbox service and no link:** the server keeps a mailbox only
///   while its sides use it. Transit (bulk TCP) is not used.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:tom_secrets_age/tom_secrets_age.dart';

import 'relay.dart';

/// The application id the app binds with: its own, so its traffic never
/// meets the `wormhole` tools'.
const String tomSecretsWormholeAppId = 'tomsecrets.app/pair/v1';

/// The public mailbox server of the magic-wormhole project (plain `ws://`;
/// the pairing's own encryption protects the content).
const String tomSecretsWormholePublicServer =
    'wormhole:ws://relay.magic-wormhole.io:4000/v1';

/// How long a hosted pairing waits for the other side (DP-180).
const Duration tomSecretsWormholeLifetime = Duration(minutes: 10);

/// The phase of the hosting side's first message, which tells the joining
/// side that a pairing waits under the nameplate.
const String tomSecretsWormholeHostPhase = 'host';

/// The phase of the last message a side adds when it closes.
const String tomSecretsWormholeClosePhase = 'close';

/// Opens the WebSocket [url].
typedef TomSecretsWormholeConnect = Future<WebSocket> Function(Uri url);

/// A magic-wormhole mailbox server as a relay: pairing only.
final class TomSecretsWormholeRelay implements TomSecretsRelay {
  /// The server [id] (`wormhole:ws(s)://…`), bound as [appId]; WebSockets
  /// through [connect] (default `WebSocket.connect`); a server's answer
  /// waited for up to [timeout]; a hosted pairing kept open for
  /// [lifetime] without the other side.
  TomSecretsWormholeRelay(
    this.id, {
    this.appId = tomSecretsWormholeAppId,
    TomSecretsWormholeConnect? connect,
    this.timeout = const Duration(seconds: 30),
    this.lifetime = tomSecretsWormholeLifetime,
    Random? random,
    DateTime Function()? clock,
  }) : _connect = connect ?? ((url) => WebSocket.connect(url.toString())),
       _random = random ?? Random.secure(),
       _clock = clock ?? DateTime.now {
    if (id.kind != TomSecretsRelayKind.wormhole) {
      throw ArgumentError.value(id, 'id', 'not a magic-wormhole server');
    }
  }

  @override
  final TomSecretsRelayId id;

  /// The application id it binds with.
  final String appId;

  /// How long a server's answer may take.
  final Duration timeout;

  /// How long a hosted pairing waits for the other side.
  final Duration lifetime;

  final TomSecretsWormholeConnect _connect;
  final Random _random;
  final DateTime Function() _clock;

  @override
  Set<TomSecretsRelayService> get services => id.services;

  TomSecretsRelayException _failure(String message) =>
      TomSecretsRelayException(id.text, message);

  TomSecretsRelayException _unsupported(String what) =>
      TomSecretsRelayException(
        id.text,
        'a magic-wormhole server offers pairing only, not $what',
        unsupported: true,
      );

  String _hex(int bytes) => [
    for (var i = 0; i < bytes; i++)
      _random.nextInt(256).toRadixString(16).padLeft(2, '0'),
  ].join();

  /// A connection bound to [appId]: the welcome read, its proof of work
  /// answered, `bind` confirmed by a `ping`.
  Future<_WormholeConnection> _bound() async {
    final WebSocket socket;
    try {
      socket = await _connect(Uri.parse(id.address)).timeout(timeout);
    } on TimeoutException {
      throw _failure('no answer within ${timeout.inSeconds} seconds');
    } on SocketException catch (e) {
      throw _failure('not reachable: ${e.message}');
    } on WebSocketException catch (e) {
      throw _failure('it refused the connection: ${e.message}');
    } on HttpException catch (e) {
      throw _failure('not reachable: ${e.message}');
    }
    final c = _WormholeConnection(this, socket, _hex(5));
    try {
      final welcome = await c.welcome.future.timeout(timeout);
      final error = welcome['error'];
      if (error != null) throw _failure('it refuses clients: $error');
      final permission = welcome['permission-required'];
      if (permission is Map && !permission.containsKey('none')) {
        final hashcash = permission['hashcash'];
        if (hashcash is! Map) {
          throw _failure(
            'it asks for a permission this app cannot give '
            '(${permission.keys.join(', ')})',
          );
        }
        final bits = hashcash['bits'];
        final resource = hashcash['resource'];
        if (bits is! int || bits < 0 || bits > 32 || resource is! String) {
          throw _failure('it asks for a proof of work this app cannot read');
        }
        c.post('submit-permissions', {
          'method': 'hashcash',
          'stamp': tomSecretsHashcashStamp(
            bits,
            resource,
            now: _clock(),
            random: _random,
          ),
        });
      }
      c.post('bind', {
        'appid': appId,
        'side': c.side,
        'client_version': ['tom_secrets', '1'],
      });
      await c.ask('ping', {'ping': 1}, 'pong');
      return c;
    } on Object {
      await c.dispose();
      rethrow;
    }
  }

  @override
  Future<TomSecretsPairingChannel> host() async {
    final c = await _bound();
    try {
      final allocated = await c.ask('allocate', const {}, 'allocated');
      final nameplate = '${allocated['nameplate']}';
      final n = int.tryParse(nameplate);
      final claimed = await c.ask('claim', {'nameplate': nameplate}, 'claimed');
      if (n == null || n < 1 || n > 999) {
        await c.ask('release', {'nameplate': nameplate}, 'released');
        throw _failure(
          'it allocated the nameplate $nameplate, outside a pairing code\'s '
          '1–999; try again later',
        );
      }
      final mailbox = '${claimed['mailbox']}';
      final channel = _WormholeChannel(c, nameplate, mailbox, host: true);
      c.post('open', {'mailbox': mailbox});
      // The joining side learns from it that a pairing waits here.
      c.post('add', {'phase': tomSecretsWormholeHostPhase, 'body': ''});
      return channel;
    } on Object {
      await c.dispose();
      rethrow;
    }
  }

  @override
  Future<TomSecretsPairingChannel> join(String nameplate) async {
    final n = int.tryParse(nameplate);
    if (n == null || n < 1 || n > 999) {
      throw _failure('not a nameplate: $nameplate');
    }
    final c = await _bound();
    try {
      // A claim opens any nameplate, and a server may refuse its list: the
      // hosting side's first message says a pairing waits here. The server
      // sends a mailbox's earlier messages at the open, before the answer
      // to the ping that follows it.
      final claimed = await c.ask('claim', {'nameplate': '$n'}, 'claimed');
      final mailbox = '${claimed['mailbox']}';
      final channel = _WormholeChannel(c, '$n', mailbox, host: false);
      c.post('open', {'mailbox': mailbox});
      await c.ask('ping', {'ping': 2}, 'pong');
      final refused = c.refused;
      if (refused != null) throw refused;
      if (!channel._hostSeen) {
        await channel._release();
        await channel.close();
        throw _failure(
          'no pairing is open under $n: is the code from a pairing opened '
          'on this relay, and still open?',
        );
      }
      // Both sides have the mailbox now: the nameplate can go.
      await channel._release();
      return channel;
    } on Object {
      await c.dispose();
      rethrow;
    }
  }

  @override
  Future<TomSecretsPairingChannel> link(String linkId) async =>
      throw _unsupported('the approval link');

  @override
  Future<void> put(TomSecretsMailboxItem item) async =>
      throw _unsupported('the mailbox');

  @override
  Future<List<TomSecretsMailboxEntry>> list(TomSecretsMemberKey me) async =>
      throw _unsupported('the mailbox');

  @override
  Future<Uint8List> fetch(TomSecretsMemberKey me, String itemId) async =>
      throw _unsupported('the mailbox');

  @override
  Future<void> delete(TomSecretsMemberKey me, String itemId) async =>
      throw _unsupported('the mailbox');
}

/// A Hashcash v1 stamp of [bits] for [resource] (the mailbox protocol's
/// `submit-permissions`): `1:<bits>:<YYMMDD>:<resource>::<rand>:<counter>`,
/// whose SHA-1 starts with [bits] zero bits.
String tomSecretsHashcashStamp(
  int bits,
  String resource, {
  DateTime? now,
  Random? random,
}) {
  if (resource.contains(':')) {
    throw ArgumentError.value(resource, 'resource', 'contains a colon');
  }
  final r = random ?? Random.secure();
  final t = (now ?? DateTime.now()).toUtc();
  String two(int v) => v.toString().padLeft(2, '0');
  final date = '${two(t.year % 100)}${two(t.month)}${two(t.day)}';
  const alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  final rand = [for (var i = 0; i < 16; i++) alphabet[r.nextInt(64)]].join();
  final prefix = '1:$bits:$date:$resource::$rand:';
  for (var counter = 0; ; counter++) {
    final stamp = '$prefix${counter.toRadixString(16)}';
    if (tomSecretsHashcashBits(stamp) >= bits) return stamp;
  }
}

/// How many leading zero bits the SHA-1 of [stamp] has.
int tomSecretsHashcashBits(String stamp) {
  final digest = sha1.convert(ascii.encode(stamp)).bytes;
  var n = 0;
  for (final b in digest) {
    if (b == 0) {
      n += 8;
      continue;
    }
    for (var m = 0x80; m > 0 && b & m == 0; m >>= 1) {
      n++;
    }
    break;
  }
  return n;
}

/// One WebSocket to the mailbox server: its messages sorted into the
/// answers asked for and the mailbox's messages.
final class _WormholeConnection {
  _WormholeConnection(this.relay, this.socket, this.side) {
    socket.pingInterval = const Duration(seconds: 30);
    _subscription = socket.listen(
      _receive,
      onDone: _ended,
      onError: (Object e) => _ended(error: e),
      cancelOnError: false,
    );
  }

  final TomSecretsWormholeRelay relay;
  final WebSocket socket;

  /// This side's name in the mailbox.
  final String side;

  /// The welcome's content.
  final Completer<Map<String, Object?>> welcome = Completer();

  /// The mailbox's messages, the own side's included.
  final StreamController<Map<String, Object?>> messages = StreamController();

  /// The answers waited for, by the type they come as.
  final Map<String, Completer<Map<String, Object?>>> _waiting = {};

  /// The types asked, by the answer they wait for (an `error` names the
  /// asked type in `orig`).
  final Map<String, String> _asked = {};

  /// The first refusal of a message that has no answer of its own.
  TomSecretsRelayException? refused;

  late final StreamSubscription<dynamic> _subscription;
  bool _disposed = false;
  int _ids = 0;

  void _receive(dynamic data) {
    if (data is! String) return;
    final Object? json;
    try {
      json = jsonDecode(data);
    } on FormatException {
      return;
    }
    if (json is! Map) return;
    final m = json.cast<String, Object?>();
    switch (m['type']) {
      case 'welcome':
        final w = m['welcome'];
        if (!welcome.isCompleted) {
          welcome.complete(w is Map ? w.cast<String, Object?>() : {});
        }
      case 'message':
        if (!messages.isClosed) messages.add(m);
      case 'error':
        final orig = m['orig'];
        final asked = orig is Map ? '${orig['type']}' : '';
        final error = relay._failure(_said('${m['error']}', asked));
        final answer = _asked[asked];
        final waiting = answer == null ? null : _waiting.remove(answer);
        if (waiting != null) {
          waiting.completeError(error);
        } else {
          // A refused `open` or `add` has no answer of its own.
          refused ??= error;
          if (!messages.isClosed) messages.addError(error);
        }
      case final String type:
        _waiting.remove(type)?.complete(m);
    }
  }

  /// What the server's [error] to [asked] means, for people.
  static String _said(String error, String asked) => switch (error) {
    'crowded' => 'two devices are in this pairing already',
    'reclaimed' => 'this pairing was taken and given up already',
    'must bind first' ||
    'already bound' => 'it did not take this app\'s binding ($error)',
    _ => 'it refused $asked: $error',
  };

  void _ended({Object? error}) {
    final failure = relay._failure(
      error == null
          ? 'it closed the connection'
          : 'the connection broke: $error',
    );
    if (!welcome.isCompleted) welcome.completeError(failure);
    for (final w in _waiting.values) {
      w.completeError(failure);
    }
    _waiting.clear();
    if (!messages.isClosed) {
      if (!_disposed) messages.addError(failure);
      unawaited(messages.close());
    }
  }

  /// Sends [type] with [fields].
  void post(String type, Map<String, Object?> fields) {
    if (_disposed) throw relay._failure('the connection is closed');
    socket.add(
      jsonEncode({'type': type, 'id': '${side}_${_ids++}', ...fields}),
    );
  }

  /// Sends [type] and waits for its answer [answer].
  Future<Map<String, Object?>> ask(
    String type,
    Map<String, Object?> fields,
    String answer,
  ) async {
    final c = Completer<Map<String, Object?>>();
    _waiting[answer] = c;
    _asked[type] = answer;
    post(type, fields);
    try {
      return await c.future.timeout(relay.timeout);
    } on TimeoutException {
      _waiting.remove(answer);
      throw relay._failure(
        'no answer to $type within ${relay.timeout.inSeconds} seconds',
      );
    }
  }

  /// Closes the WebSocket.
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    try {
      await socket.close(WebSocketStatus.normalClosure);
    } on Object {
      // Gone already.
    }
    await _subscription.cancel();
    if (!messages.isClosed) unawaited(messages.close());
  }
}

/// A pairing channel in a mailbox: one message per [send].
final class _WormholeChannel implements TomSecretsPairingChannel {
  _WormholeChannel(this._c, this.nameplate, this._mailbox, {required bool host})
    : _host = host {
    _c.messages.stream.listen(
      _message,
      onError: (Object e) {
        if (!_in.isClosed && !_closed) _in.addError(e);
      },
      onDone: () {
        if (!_in.isClosed) unawaited(_in.close());
      },
    );
    if (host) {
      _lonely = Timer(_c.relay.lifetime, () {
        if (_joined.isCompleted || _closed) return;
        if (!_in.isClosed) {
          _in.addError(
            _c.relay._failure(
              'no one joined pairing $nameplate within '
              '${_c.relay.lifetime.inMinutes} minutes',
            ),
          );
        }
        unawaited(close());
      });
    }
  }

  final _WormholeConnection _c;
  final String _mailbox;
  final bool _host;

  @override
  final String nameplate;

  final StreamController<List<int>> _in = StreamController();
  final Completer<void> _joined = Completer();
  final Set<String> _seen = {};
  Timer? _lonely;
  bool _closed = false;
  bool _released = false;

  /// Whether the hosting side's first message was seen.
  bool _hostSeen = false;
  int _phase = 0;

  @override
  Stream<List<int>> get incoming => _in.stream;

  @override
  Future<void> get joined => _joined.future;

  void _message(Map<String, Object?> m) {
    if (m['side'] == _c.side) return;
    final phase = '${m['phase']}';
    // The server sends the mailbox's earlier messages again at an open.
    if (!_seen.add(phase)) return;
    if (phase == tomSecretsWormholeHostPhase) {
      _hostSeen = true;
      return;
    }
    if (phase == tomSecretsWormholeClosePhase) {
      if (!_in.isClosed) unawaited(_in.close());
      return;
    }
    final Uint8List bytes;
    try {
      bytes = _fromHex('${m['body']}');
    } on FormatException {
      return;
    }
    if (!_joined.isCompleted) {
      _joined.complete();
      _lonely?.cancel();
      if (_host) unawaited(_release().catchError((Object _) {}));
    }
    if (!_in.isClosed) _in.add(bytes);
  }

  /// Gives the nameplate back once both sides have the mailbox.
  Future<void> _release() async {
    if (_released) return;
    _released = true;
    await _c.ask('release', {'nameplate': nameplate}, 'released');
  }

  @override
  void send(List<int> bytes) {
    if (_closed) return;
    _c.post('add', {'phase': '${_phase++}', 'body': _toHex(bytes)});
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _lonely?.cancel();
    try {
      _c.post('add', {'phase': tomSecretsWormholeClosePhase, 'body': ''});
      await _c.ask('close', {
        'mailbox': _mailbox,
        'mood': _joined.isCompleted ? 'happy' : 'lonely',
      }, 'closed');
    } on Object {
      // The server went first; the socket is closed below either way.
    }
    await _c.dispose();
    if (!_in.isClosed) unawaited(_in.close());
  }

  static String _toHex(List<int> bytes) =>
      [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

  static Uint8List _fromHex(String hex) {
    if (hex.length.isOdd) throw const FormatException('odd hex');
    final out = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      final v = int.tryParse(hex.substring(2 * i, 2 * i + 2), radix: 16);
      if (v == null) throw const FormatException('not hex');
      out[i] = v;
    }
    return out;
  }
}
