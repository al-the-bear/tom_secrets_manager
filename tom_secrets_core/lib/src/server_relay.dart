// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The own relay server as a relay (part-relay, `tsm:<url>`): the
/// client side of `tom_secrets_relay`'s `/v1` API, offering all three
/// services.
///
/// - **Pairing:** `POST /v1/pair` allocates the nameplate (the pairing
///   code's number); both sides open the WebSocket `/v1/pair/<nameplate>`,
///   whose binary frames the relay forwards.
/// - **Link:** the WebSocket `/v1/link/<link-id>`, with the instance token
///   when the relay runs in token mode.
/// - **Mailbox:** `PUT /v1/mailbox/<recipient>/<item-id>` with the instance
///   token and `Tsm-Expires`; listing, fetching and deleting with the
///   recipient's proof (a token the relay encrypts to the member key with
///   `age`, decrypted here, valid 5 minutes).
///
/// Every credential travels as `Authorization: Bearer`. The relay sees
/// ciphertext only: the pairing's and the link's own handshakes run inside
/// the channel, a mailbox item is an `age` package.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'package:http/http.dart' as http;
import 'package:tom_secrets_age/tom_secrets_age.dart';

import 'github_relay.dart';
import 'relay.dart';
import 'share.dart';

/// The relay server [id] names (`tsm:https://relay.example`), reached with
/// the instance token [token] (null: none; pairing needs none, a mailbox
/// put and a link do in token mode).
final class TomSecretsServerRelay implements TomSecretsRelay {
  /// The relay [id] (`tsm:<url>`) with the instance [token]; requests go
  /// through [httpClient] (default a fresh client), WebSockets through
  /// [connect] (default `WebSocket.connect`).
  TomSecretsServerRelay(
    this.id, {
    this.token,
    http.Client? httpClient,
    Future<WebSocket> Function(Uri url, Map<String, String> headers)? connect,
    DateTime Function()? clock,
    this.timeout = const Duration(seconds: 30),
  }) : _http = httpClient ?? http.Client(),
       _connect = connect ?? tomSecretsRelayWebSocket,
       _clock = clock ?? DateTime.now {
    if (id.kind != TomSecretsRelayKind.server) {
      throw ArgumentError.value(id, 'id', 'not a relay server');
    }
  }

  @override
  final TomSecretsRelayId id;

  /// The instance token, or null.
  final String? token;

  /// How long a request may take.
  final Duration timeout;

  final http.Client _http;
  final Future<WebSocket> Function(Uri url, Map<String, String> headers)
  _connect;
  final DateTime Function() _clock;

  /// Proofs by recipient: (token, valid until).
  final Map<String, (String, DateTime)> _proofs = {};

  @override
  Set<TomSecretsRelayService> get services => id.services;

  Uri get _base {
    final u = Uri.parse(id.address);
    final path = u.path.endsWith('/')
        ? u.path.substring(0, u.path.length - 1)
        : u.path;
    return u.replace(path: path);
  }

  Uri _url(String path) => _base.replace(path: '${_base.path}$path');

  Uri _ws(String path) =>
      _url(path).replace(scheme: _base.scheme == 'https' ? 'wss' : 'ws');

  TomSecretsRelayException _failure(String message) =>
      TomSecretsRelayException(id.text, message);

  Map<String, String> get _tokenHeader => {
    if (token != null && token!.isNotEmpty) 'authorization': 'Bearer $token',
  };

  /// The relay's message in an error answer, or the status.
  static String _reason(http.Response r) {
    try {
      final json = jsonDecode(utf8.decode(r.bodyBytes));
      final error = json is Map ? json['error'] : null;
      if (error is String) return error;
    } on FormatException {
      // Not the relay's JSON (a proxy's page).
    }
    return 'HTTP ${r.statusCode}';
  }

  Future<http.Response> _send(
    String method,
    String path, {
    Map<String, String> headers = const {},
    List<int>? body,
  }) async {
    final request = http.Request(method, _url(path));
    request.headers.addAll(headers);
    if (body != null) {
      request.headers['content-type'] = 'application/octet-stream';
      request.bodyBytes = body;
    } else if (method != 'GET' && method != 'DELETE') {
      request.headers['content-type'] = 'application/octet-stream';
    }
    try {
      final streamed = await _http.send(request).timeout(timeout);
      return await http.Response.fromStream(streamed).timeout(timeout);
    } on TimeoutException {
      throw _failure('no answer within ${timeout.inSeconds} seconds');
    } on SocketException catch (e) {
      throw _failure('not reachable: ${e.message}');
    } on http.ClientException catch (e) {
      throw _failure('not reachable: ${e.message}');
    }
  }

  Future<TomSecretsPairingChannel> _open(
    String path,
    String nameplate,
    Map<String, String> headers,
  ) async {
    final WebSocket socket;
    try {
      socket = await _connect(_ws(path), headers).timeout(timeout);
    } on TomSecretsRelayUpgradeRefused catch (e) {
      throw _failure(_upgradeRefusal(e, nameplate));
    } on WebSocketException catch (e) {
      throw _failure('it refused the connection: ${e.message}');
    } on TimeoutException {
      throw _failure('no answer within ${timeout.inSeconds} seconds');
    } on SocketException catch (e) {
      throw _failure('not reachable: ${e.message}');
    } on HttpException catch (e) {
      throw _failure('not reachable: ${e.message}');
    }
    return _ServerChannel(this, socket, nameplate);
  }

  /// What a refused upgrade means: the relay's own message, else the
  /// status said for people.
  static String _upgradeRefusal(
    TomSecretsRelayUpgradeRefused e,
    String nameplate,
  ) {
    final said = e.message;
    return switch (e.status) {
      401 =>
        'it opens approval links only for holders of an instance token: add '
            'the token to the relay in the relay settings',
      403 => said ?? 'it does not serve this address',
      404 =>
        'no pairing is open under $nameplate: is the code from a pairing '
            'opened on this relay, and still open?',
      409 => said ?? 'two devices are connected to $nameplate already',
      429 => said ?? 'its limits are reached; try again later',
      _ => said ?? 'it refused the connection (HTTP ${e.status})',
    };
  }

  @override
  Future<TomSecretsPairingChannel> host() async {
    final r = await _send('POST', '/v1/pair');
    if (r.statusCode != 200) {
      throw _failure('it allocates no nameplate: ${_reason(r)}');
    }
    final String nameplate;
    try {
      nameplate = (jsonDecode(r.body) as Map)['nameplate'] as String;
    } on Object {
      throw _failure('it answered no nameplate');
    }
    return _open('/v1/pair/$nameplate', nameplate, const {});
  }

  @override
  Future<TomSecretsPairingChannel> join(String nameplate) {
    final n = int.tryParse(nameplate);
    if (n == null || n < 1 || n > 999) {
      throw _failure('not a nameplate: $nameplate');
    }
    return _open('/v1/pair/$n', '$n', const {});
  }

  @override
  Future<TomSecretsPairingChannel> link(String linkId) {
    if (!RegExp(r'^[A-Za-z0-9_-]{8,128}$').hasMatch(linkId)) {
      throw _failure('not a link id: $linkId');
    }
    return _open('/v1/link/$linkId', linkId, _tokenHeader);
  }

  static void _checkRecipient(String recipient) {
    if (!tomSecretsIsInboxMember(recipient)) {
      throw ArgumentError.value(recipient, 'recipient', 'not a member id');
    }
  }

  @override
  Future<void> put(TomSecretsMailboxItem item) async {
    _checkRecipient(item.recipient);
    final r = await _send(
      'PUT',
      '/v1/mailbox/${item.recipient}/${Uri.encodeComponent(item.itemId)}',
      headers: {
        ..._tokenHeader,
        'tsm-expires': item.expires.toUtc().toIso8601String(),
      },
      body: item.bytes,
    );
    if (r.statusCode != 201 && r.statusCode != 200) {
      throw _failure('it did not take the package: ${_reason(r)}');
    }
  }

  /// The proof of [me] (cached while it holds): the challenge answered.
  Future<String> _proof(TomSecretsMemberKey me) async {
    final recipient = me.recipient.fingerprint;
    final cached = _proofs[recipient];
    if (cached != null && cached.$2.isAfter(_clock())) return cached.$1;
    final r = await _send(
      'POST',
      '/v1/mailbox/$recipient/challenge',
      body: utf8.encode(me.recipient.encoded),
    );
    if (r.statusCode != 200) {
      throw _failure('it gave no proof challenge: ${_reason(r)}');
    }
    final String proof;
    try {
      proof = utf8.decode(
        await tomSecretsAgeDecrypt(r.bodyBytes, [
          TomSecretsAgeHybridIdentity(me),
        ]),
      );
    } on TomSecretsAgeException catch (e) {
      throw _failure('its proof challenge does not open: ${e.message}');
    }
    // A little under the relay's 5 minutes, so a proof is never used as it
    // runs out.
    _proofs[recipient] = (proof, _clock().add(const Duration(minutes: 4)));
    return proof;
  }

  /// A mailbox request of [me] with the proof, asked again once with a
  /// fresh proof when the relay no longer takes the cached one.
  Future<http.Response> _proven(
    TomSecretsMemberKey me,
    String method,
    String path,
  ) async {
    for (var attempt = 0; ; attempt++) {
      final proof = await _proof(me);
      final r = await _send(
        method,
        path,
        headers: {'authorization': 'Bearer $proof'},
      );
      if (r.statusCode != 401 || attempt > 0) return r;
      _proofs.remove(me.recipient.fingerprint);
    }
  }

  @override
  Future<List<TomSecretsMailboxEntry>> list(TomSecretsMemberKey me) async {
    final recipient = me.recipient.fingerprint;
    final r = await _proven(me, 'GET', '/v1/mailbox/$recipient');
    if (r.statusCode != 200) {
      throw _failure('it lists no mailbox: ${_reason(r)}');
    }
    final items = (jsonDecode(r.body) as Map)['items'] as List;
    return [
      for (final i in items.cast<Map>())
        TomSecretsMailboxEntry(
          itemId: i['id'] as String,
          size: (i['size'] as num?)?.toInt() ?? 0,
          received: DateTime.tryParse('${i['received']}'),
          expires: DateTime.tryParse('${i['expires']}'),
        ),
    ];
  }

  @override
  Future<Uint8List> fetch(TomSecretsMemberKey me, String itemId) async {
    final recipient = me.recipient.fingerprint;
    final r = await _proven(
      me,
      'GET',
      '/v1/mailbox/$recipient/${Uri.encodeComponent(itemId)}',
    );
    if (r.statusCode != 200) {
      throw _failure('it has no package $itemId: ${_reason(r)}');
    }
    return r.bodyBytes;
  }

  @override
  Future<void> delete(TomSecretsMemberKey me, String itemId) async {
    final recipient = me.recipient.fingerprint;
    final r = await _proven(
      me,
      'DELETE',
      '/v1/mailbox/$recipient/${Uri.encodeComponent(itemId)}',
    );
    if (r.statusCode != 204 && r.statusCode != 200 && r.statusCode != 404) {
      throw _failure('it did not delete $itemId: ${_reason(r)}');
    }
  }

  /// Closes the HTTP client.
  void close() => _http.close();
}

/// A WebSocket to the relay as a pairing or link channel.
final class _ServerChannel implements TomSecretsPairingChannel {
  _ServerChannel(this.relay, this.socket, this.nameplate) {
    socket.listen(
      (message) {
        if (message is List<int>) {
          if (!_joined.isCompleted) _joined.complete();
          _in.add(message);
        }
      },
      onDone: () {
        final code = socket.closeCode;
        // 1000 and 4000 (the other side left) end the channel; anything
        // else is the relay's refusal, said as such.
        if (!_closed &&
            code != null &&
            code != 1000 &&
            code != 4000 &&
            code != 1005) {
          _in.addError(
            TomSecretsRelayException(
              relay.id.text,
              socket.closeReason?.isNotEmpty == true
                  ? socket.closeReason!
                  : 'it closed the channel ($code)',
            ),
          );
        }
        unawaited(_in.close());
      },
      onError: (Object e) {
        _in.addError(
          TomSecretsRelayException(relay.id.text, 'the channel broke: $e'),
        );
      },
      cancelOnError: false,
    );
  }

  final TomSecretsServerRelay relay;
  final WebSocket socket;

  @override
  final String nameplate;

  final StreamController<List<int>> _in = StreamController();
  final Completer<void> _joined = Completer();
  bool _closed = false;

  @override
  Stream<List<int>> get incoming => _in.stream;

  @override
  Future<void> get joined => _joined.future;

  @override
  void send(List<int> bytes) {
    if (_closed) return;
    socket.add(bytes is Uint8List ? bytes : Uint8List.fromList(bytes));
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await socket.close(1000);
  }
}

/// A WebSocket upgrade the relay answered with [status] instead of 101,
/// and the relay's [message] (its JSON `error`), if any.
final class TomSecretsRelayUpgradeRefused implements Exception {
  /// A refusal.
  const TomSecretsRelayUpgradeRefused(this.status, this.message);

  /// The HTTP status.
  final int status;

  /// What the relay said.
  final String? message;

  @override
  String toString() => 'TomSecretsRelayUpgradeRefused($status): $message';
}

/// Opens the WebSocket [url] (`ws:` or `wss:`) with [headers], doing the
/// handshake itself so a refusal keeps its status and the relay's message
/// ([TomSecretsRelayUpgradeRefused]); dart:io's `WebSocket.connect` keeps
/// neither.
Future<WebSocket> tomSecretsRelayWebSocket(
  Uri url,
  Map<String, String> headers,
) async {
  final client = HttpClient();
  try {
    final key = base64.encode(
      List<int>.generate(16, (_) => _keyRandom.nextInt(256)),
    );
    final request = await client.getUrl(
      url.replace(scheme: url.scheme == 'wss' ? 'https' : 'http'),
    );
    request.followRedirects = false;
    request.headers
      ..set(HttpHeaders.connectionHeader, 'Upgrade')
      ..set(HttpHeaders.upgradeHeader, 'websocket')
      ..set('sec-websocket-version', '13')
      ..set('sec-websocket-key', key);
    headers.forEach(request.headers.set);
    final response = await request.close();
    if (response.statusCode != HttpStatus.switchingProtocols) {
      String? message;
      try {
        final json = jsonDecode(await utf8.decodeStream(response));
        final error = json is Map ? json['error'] : null;
        if (error is String) message = error;
      } on FormatException {
        // Not the relay's JSON.
      }
      throw TomSecretsRelayUpgradeRefused(response.statusCode, message);
    }
    final accept = base64.encode(
      sha1
          .convert(utf8.encode('${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11'))
          .bytes,
    );
    if (response.headers.value('sec-websocket-accept') != accept) {
      throw const WebSocketException('the handshake answer does not match');
    }
    final socket = await response.detachSocket();
    return WebSocket.fromUpgradedSocket(socket, serverSide: false);
  } finally {
    client.close();
  }
}

final _keyRandom = Random.secure();

/// The relay [id] names, built for this device: GitHub reached with the
/// GitHub [token] (required; [githubApi] for GitHub Enterprise), the relay
/// server with its instance [token] (optional). A magic-wormhole server is
/// not carried yet: [TomSecretsRelayException] with `unsupported`.
TomSecretsRelay tomSecretsRelayFor(
  TomSecretsRelayId id, {
  String? token,
  String device = 'tsm',
  String? githubApi,
}) {
  switch (id.kind) {
    case TomSecretsRelayKind.github:
      if (token == null || token.isEmpty) {
        throw TomSecretsRelayException(
          id.text,
          'a GitHub repository is reached with this machine\'s own token for '
          'it',
        );
      }
      return TomSecretsGitHubRelay.withToken(
        id,
        token,
        device: device,
        baseUrl: githubApi ?? 'https://api.github.com',
      );
    case TomSecretsRelayKind.server:
      return TomSecretsServerRelay(id, token: token);
    case TomSecretsRelayKind.wormhole:
      throw TomSecretsRelayException(
        id.text,
        'a magic-wormhole server is not available as a relay in this '
        'version; pair through a relay server or a GitHub repository, on the '
        'same network or over the VPN',
        unsupported: true,
      );
  }
}

/// Whether a relay of [id]'s kind is reached with a token of this machine's
/// own that the pairing must know (GitHub: the repository token; a relay
/// server's instance token is not needed to pair).
bool tomSecretsRelayNeedsToken(TomSecretsRelayId id) =>
    id.kind == TomSecretsRelayKind.github;
