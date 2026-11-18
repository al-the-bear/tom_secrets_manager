// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The approver's end of the approval link, kept open (protocol.md 9.7,
/// part-sharing): while unlocked, the service holds a session to every
/// paired host it approves for (a recorded host with a link address), as
/// the initiator with this device's link key for that host. The service and
/// not the app holds these sessions: it has the private link and approver
/// keys, the app has neither.
///
/// A host's `approval_needed` and `approval_closed` go to the attached apps
/// beside this host's own prompts (they name their `host`), the prompt's id
/// qualified as `<host>/<approvalId>` (each service counts its own ids, and
/// this host's contain no `/`); the app answers
/// with `approve` as for a local prompt, and the service carries the answer
/// over the link: a lasting decision as grants signed with this device's
/// approver key (written to the host's group in the primary and sent as
/// `grant` to apply at once), an `always` with a client token as its
/// `exe-token` grant with `clientToken` and `approvalId` (protocol.md 7.4),
/// otherwise `approve`. A host that rotated its link key sends the new one
/// first; it is recorded as the one-shot delivery records it. A session
/// that ends is opened again after a pause that grows to five minutes.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'approvals.dart';
import 'identity.dart';
import 'link_client.dart';

/// The longest pause before a session to a host is opened again.
const Duration tomSecretsLinkRetryMax = Duration(minutes: 5);

/// The sessions to the paired hosts this device approves for.
final class TomSecretsApproverLinks {
  /// Links for [service], granting through [approvals]; [retry] is the first
  /// pause before a session is opened again (doubling up to
  /// [tomSecretsLinkRetryMax]).
  TomSecretsApproverLinks(
    this.service,
    this.approvals, {
    this.retry = const Duration(seconds: 5),
    this.timeout = const Duration(seconds: 10),
  });

  /// The service.
  final TomSecretsApprovalHost service;

  /// The approvals, which sign grants.
  final TomSecretsApprovals approvals;

  /// The first pause before a session is opened again.
  final Duration retry;

  /// How long an answer over a link may take.
  final Duration timeout;

  final Map<String, _HostLink> _links = {};
  bool _stopped = false;

  /// The prompts of the paired hosts that wait, as the apps get them (the
  /// ids qualified).
  List<Map<String, Object?>> get waitingEvents => [
    for (final l in _links.values)
      for (final e in l.waiting.entries) l.forApps(e.key, e.value),
  ];

  /// The hosts a session is open to.
  List<String> get connected => [
    for (final l in _links.values)
      if (l.session != null) l.host,
  ];

  /// Opens a session to every recorded host with a link address, and to
  /// those recorded later ([refresh]).
  void start() {
    _stopped = false;
    refresh();
  }

  /// Opens sessions to recorded hosts without one, and closes those of
  /// hosts no longer recorded or whose address or key changed.
  void refresh() {
    if (_stopped) return;
    final trust = service.trust;
    final wanted = {
      for (final h in trust.hosts)
        if (h.address != null) h.host: h,
    };
    for (final name in [..._links.keys]) {
      final h = wanted[name];
      final link = _links[name]!;
      if (h == null ||
          h.address != link.address ||
          !_sameKey(h.linkKey, link.hostKey)) {
        unawaited(link.stop());
        _links.remove(name);
      }
    }
    for (final h in wanted.values) {
      _links.putIfAbsent(h.host, () => _HostLink(this, h)..open());
    }
  }

  /// Closes every session (the service locked).
  Future<void> stop() async {
    _stopped = true;
    for (final l in [..._links.values]) {
      await l.stop();
    }
    _links.clear();
  }

  /// The qualified id the apps know a paired [host]'s prompt
  /// [approvalId] by.
  static String qualified(String host, String approvalId) =>
      '$host/$approvalId';

  /// The host of the qualified prompt id [approvalId] while it waits, or
  /// null (this host's own prompt, or none).
  String? hostOf(String approvalId) {
    final (host, id) = _split(approvalId) ?? ('', '');
    final link = _links[host];
    return link != null && link.waiting.containsKey(id) ? host : null;
  }

  static (String, String)? _split(String qualified) {
    final at = qualified.indexOf('/');
    if (at <= 0) return null;
    return (qualified.substring(0, at), qualified.substring(at + 1));
  }

  /// Answers the paired host's prompt [approvalId] with [answer] (an
  /// `approve` from the app). Throws [StateError] for a prompt no host
  /// waits on, [ArgumentError] for a malformed answer and
  /// [TomSecretsLinkDeliveryException] when the host does not take it.
  Future<void> approve(
    String qualified,
    TomSecretsApprovalAnswer answer,
  ) async {
    final (host, approvalId) = _split(qualified) ?? ('', '');
    final link = _links[host];
    final event = link?.waiting[approvalId];
    if (link == null || event == null) {
      throw StateError('no prompt $qualified');
    }
    if (event['confirmOnly'] == true) {
      // An ssh-agent confirmation: this signature only (part-os-integration).
      if (answer.decision != 'once' && answer.decision != 'never') {
        throw ArgumentError('a confirmation is answered once or never');
      }
      await link.request({
        'op': 'approve',
        'approvalId': approvalId,
        'decision': answer.decision,
        'secret': answer.secret,
      });
      return;
    }
    if (!tomSecretsDecisions.contains(answer.decision) ||
        !const ['ref', 'store', 'all'].contains(answer.secret) ||
        (answer.decision == 'folder' && answer.folder == null)) {
      throw ArgumentError('decision, secret and folder');
    }
    final token = answer.clientToken;
    if (token != null &&
        (answer.decision != 'always' || event['wantClientToken'] != true)) {
      throw ArgumentError(
        'a client token answers an always of a request that asked for one',
      );
    }
    if (answer.decision == 'once') {
      await link.request({
        'op': 'approve',
        'approvalId': approvalId,
        'decision': answer.decision,
        'secret': answer.secret,
      });
      return;
    }
    final identity = TomSecretsIdentity.fromJson(
      (event['identity']! as Map).cast<String, Object?>(),
    );
    String? tokenId;
    if (token != null) {
      final bytes = base64.decode(token);
      if (bytes.length != 32) throw ArgumentError('a client token is 32 bytes');
      tokenId = tomSecretsClientTokenId(tomSecretsClientTokenHash(bytes));
    }
    final subject = tokenId == null
        ? tomSecretsGrantSubject(identity, answer)
        : 'exe-token ${identity.exe} $tokenId';
    final secrets = tomSecretsGrantSecrets(
      answer,
      refs: [for (final r in (event['refs'] as List? ?? const [])) '$r'],
      stores: [
        for (final r in (event['resolved'] as List? ?? const []).cast<Map>())
          '${r['store']}',
      ],
      ssh: (event['ssh'] as Map?)?.cast<String, Object?>(),
    );
    final pin = answer.pin ?? (identity.kind == 'script' ? 'hash' : 'off');
    final grants = [
      for (final secret in secrets)
        await approvals.addGrant({
          'host': link.host,
          'subject': subject,
          'secret': secret,
          'decision': answer.decision == 'never' ? 'never' : 'allow',
          'pin': pin,
        }, save: false),
    ];
    await service.savePrimary();
    for (final (i, grant) in grants.indexed) {
      await link.request({
        'op': 'grant',
        'grant': grant,
        // The token comes with its grant, which answers the request.
        if (token != null && i == 0) ...{
          'clientToken': token,
          'approvalId': approvalId,
        },
      });
    }
    if (token == null) {
      await link.request({
        'op': 'approve',
        'approvalId': approvalId,
        'decision': answer.decision,
        'secret': answer.secret,
        'folder': ?answer.folder,
        'pin': ?answer.pin,
      });
    }
  }

  static bool _sameKey(TomSecretsLinkPublicKey a, TomSecretsLinkPublicKey b) =>
      base64.encode(a.x25519) == base64.encode(b.x25519) &&
      base64.encode(a.mlKem768) == base64.encode(b.mlKem768);
}

/// The session to one host.
final class _HostLink {
  _HostLink(this.links, TomSecretsRecordedHost recorded)
    : host = recorded.host,
      address = recorded.address!,
      hostKey = recorded.linkKey;

  final TomSecretsApproverLinks links;
  final String host;
  final String address;
  TomSecretsLinkPublicKey hostKey;

  TomSecretsLinkSession? session;
  final Map<String, Map<String, Object?>> waiting = {};
  final Map<int, Completer<Map<String, Object?>>> _answers = {};
  int _nextId = 0;
  bool _stopped = false;
  Timer? _again;
  Duration _pause = Duration.zero;

  TomSecretsApprovalHost get _service => links.service;

  void open() => unawaited(_connect());

  /// [event] of the prompt [id] as the apps get it: the id qualified.
  Map<String, Object?> forApps(String id, Map<String, Object?> event) => {
    ...event,
    'approvalId': TomSecretsApproverLinks.qualified(host, id),
  };

  Future<void> _connect() async {
    if (_stopped) return;
    final at = address.lastIndexOf(':');
    final port = at < 0 ? null : int.tryParse(address.substring(at + 1));
    if (at <= 0 || port == null) return;
    try {
      final socket = await Socket.connect(
        address.substring(0, at),
        port,
        timeout: links.timeout,
      );
      // A write that fails (the host went away) is reported through `done`;
      // the session then ends, and the link is opened again.
      unawaited(socket.done.then<void>((_) {}, onError: (Object _) {}));
      final trust = _service.trust;
      final s = await TomSecretsLinkSession.initiate(
        TomSecretsSocketChannel(socket),
        me: await trust.linkKeyFor(host, now: _service.now),
        hostKey: hostKey,
        device: trust.device,
      ).timeout(links.timeout);
      if (_stopped) {
        await s.close();
        return;
      }
      session = s;
      _pause = Duration.zero;
      _service.log.info('approver_link_open', {'host': host});
      s.messages.listen(
        (m) => unawaited(_onMessage(s, m)),
        onDone: () => _ended(s),
      );
    } on Object catch (e) {
      _service.log.info('approver_link_failed', {
        'host': host,
        'error': e.runtimeType.toString(),
      });
      _scheduleAgain();
    }
  }

  Future<void> _onMessage(
    TomSecretsLinkSession s,
    Map<String, Object?> m,
  ) async {
    switch (m['op']) {
      case 'approval_needed':
        final id = m['approvalId'];
        if (id is! String || m['host'] != host) return;
        waiting[id] = m;
        _service.emitToApprovers(forApps(id, m));
      case 'approval_closed':
        final id = m['approvalId'];
        if (id is! String || waiting.remove(id) == null) return;
        _service.emitToApprovers({...forApps(id, m), 'host': host});
      case 'linkKey' when m['id'] is String:
        // The host rotated its link key and was reached under the old one.
        await tomSecretsTakeHostLinkKey(s, m, (key) async {
          final recorded = _service.trust.host(host);
          if (recorded == null) return;
          recorded
            ..linkKey = key
            ..linkKeySince = _service.now;
          hostKey = key;
          await _service.writeTrust();
          _service.log.info('host_link_key_taken', {'host': host});
        });
      case 'ok' || 'error':
        final id = m['id'];
        if (id is int) _answers.remove(id)?.complete(m);
      default:
        break;
    }
  }

  /// Sends [message] and waits for its answer: `ok`, else
  /// [TomSecretsLinkDeliveryException].
  Future<void> request(Map<String, Object?> message) async {
    final s = session;
    if (s == null) {
      throw TomSecretsLinkDeliveryException('$host is not connected');
    }
    final id = ++_nextId;
    final answer = Completer<Map<String, Object?>>();
    _answers[id] = answer;
    await s.send({...message, 'id': id});
    final Map<String, Object?> got;
    try {
      got = await answer.future.timeout(links.timeout);
    } on TimeoutException {
      _answers.remove(id);
      throw TomSecretsLinkDeliveryException('$host did not answer in time');
    }
    if (got['op'] != 'ok') {
      throw TomSecretsLinkDeliveryException(
        '$host refused ${message['op']}: ${got['message']}',
        kind: got['kind'] as String?,
      );
    }
  }

  void _ended(TomSecretsLinkSession s) {
    if (session != s) return;
    session = null;
    for (final a in _answers.values) {
      a.complete({'op': 'error', 'kind': 'unavailable', 'message': 'closed'});
    }
    _answers.clear();
    // The host sends what still waits when the session is open again.
    for (final id in [...waiting.keys]) {
      waiting.remove(id);
      _service.emitToApprovers({
        'op': 'approval_closed',
        'approvalId': TomSecretsApproverLinks.qualified(host, id),
        'host': host,
        'outcome': 'unreachable',
      });
    }
    _service.log.info('approver_link_closed', {'host': host});
    _scheduleAgain();
  }

  void _scheduleAgain() {
    if (_stopped) return;
    _pause = _pause == Duration.zero
        ? links.retry
        : _pause * 2 > tomSecretsLinkRetryMax
        ? tomSecretsLinkRetryMax
        : _pause * 2;
    _again?.cancel();
    _again = Timer(_pause, open);
  }

  Future<void> stop() async {
    _stopped = true;
    _again?.cancel();
    final s = session;
    session = null;
    for (final id in [...waiting.keys]) {
      waiting.remove(id);
      _service.emitToApprovers({
        'op': 'approval_closed',
        'approvalId': TomSecretsApproverLinks.qualified(host, id),
        'host': host,
        'outcome': 'abandoned',
      });
    }
    await s?.close();
  }
}
