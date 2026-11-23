// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The approval link through a relay server (part-relay, DP-64),
/// and the state of every approval link as `status` reports it.
///
/// - **The host's side:** while unlocked, the service keeps a channel open
///   on the relay for every recorded approver whose pairing agreed on a
///   relay link (`TomSecretsRecordedApprover.relay` / `linkId`); when the
///   approver comes, the handshake runs as the responder exactly as over
///   TCP and the session goes to the approvals. When it ends, or the relay
///   closes the channel (24 hours alone), the channel is opened again.
/// - **The approver's side:** `TomSecretsApproverLinks` opens the relay
///   channel of a host when its address does not answer (or it has none).
/// - **The relay's instance token** is the one the app keeps for the relay
///   in the keychain (`relay.token.set`); without one a relay in token mode
///   refuses the link, which is shown like an unreachable link.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'approvals.dart';
import 'log.dart';

/// The keychain handle of the instance token kept for the relay server
/// [relay] (`tsm:<url>`, as `TomSecretsRelayId.text` writes it).
String tomSecretsRelayTokenHandle(String relay) =>
    'tsm.relay-token.${base64Url.encode(utf8.encode(relay)).replaceAll('=', '')}';

/// Builds the relay [relay] names (`tsm:<url>`), with its instance token.
typedef TomSecretsLinkRelayFor = Future<TomSecretsRelay> Function(String relay);

/// The longest pause before a relay channel is opened again.
const Duration tomSecretsRelayLinkRetryMax = Duration(minutes: 5);

/// The state of the approval links, by peer and role.
final class TomSecretsLinkStates {
  final Map<String, Map<String, Object?>> _states = {};

  /// Sets the state of the link to [peer] in [role] (`host`: a host this
  /// device approves for; `approver`: an approver of this host): [state]
  /// `connected`, `waiting` (a relay channel open, the other side not
  /// there), `connecting` or `unreachable`; [via] `address` or `relay`;
  /// [reason] what failed, for people.
  void set(
    String peer,
    String role, {
    required String state,
    String? via,
    String? reason,
  }) {
    _states['$role|$peer'] = {
      'device': peer,
      'role': role,
      'state': state,
      'via': ?via,
      'reason': ?reason,
    };
  }

  /// Forgets the link to [peer] in [role].
  void remove(String peer, String role) => _states.remove('$role|$peer');

  /// Forgets every link of [role].
  void removeRole(String role) =>
      _states.removeWhere((_, s) => s['role'] == role);

  /// The states, as `statusReport.links`.
  List<Map<String, Object?>> get report => [
    for (final key in _states.keys.toList()..sort()) _states[key]!,
  ];
}

/// What a relay failure is, said like an unreachable link.
String tomSecretsRelayLinkReason(Object e) => switch (e) {
  TomSecretsRelayException(:final relay, :final message) =>
    'the relay $relay: $message',
  TomSecretsLinkException(:final message) => message,
  TimeoutException() => 'no answer in time',
  SocketException(:final message) => message,
  _ => e.runtimeType.toString(),
};

/// The host's channels on relay servers, one per approver that has one.
final class TomSecretsRelayLinkHost {
  /// The channels of [trust]'s approvers, sessions handed to [approvals];
  /// [relayFor] builds a relay with its token; [retry] is the first pause
  /// before a channel is opened again (doubling up to
  /// [tomSecretsRelayLinkRetryMax]).
  TomSecretsRelayLinkHost({
    required this.trust,
    required this.host,
    required this.approvals,
    required this.relayFor,
    required this.states,
    required this.log,
    this.retry = const Duration(seconds: 5),
  });

  /// This device's trust material.
  final TomSecretsTrust trust;

  /// This host's name.
  final String host;

  /// Where the sessions go.
  final TomSecretsApprovals approvals;

  /// Builds a relay.
  final TomSecretsLinkRelayFor relayFor;

  /// Where the links' states are kept.
  final TomSecretsLinkStates states;

  /// The service's log.
  final TomSecretsLog log;

  /// The first pause before a channel is opened again.
  final Duration retry;

  final Map<String, _Waiting> _waiting = {};
  bool _stopped = false;

  /// The approvers a channel waits for.
  List<String> get waitingFor => _waiting.keys.toList()..sort();

  /// Opens a channel for every approver with a relay link.
  void start() {
    _stopped = false;
    refresh();
  }

  /// Opens channels for approvers recorded since, closes those of
  /// approvers gone or whose relay link changed.
  void refresh() {
    if (_stopped) return;
    final wanted = {
      for (final a in trust.approvers)
        if (a.relay != null && a.linkId != null && a.linkKey != null)
          a.device: a,
    };
    for (final name in [..._waiting.keys]) {
      final a = wanted[name];
      final w = _waiting[name]!;
      if (a == null || a.relay != w.relay || a.linkId != w.linkId) {
        unawaited(w.stop());
        _waiting.remove(name);
        states.remove(name, 'approver');
      }
    }
    for (final a in wanted.values) {
      _waiting.putIfAbsent(a.device, () => _Waiting(this, a)..open());
    }
  }

  /// Closes every channel (the service locked).
  Future<void> stop() async {
    _stopped = true;
    for (final w in [..._waiting.values]) {
      await w.stop();
    }
    _waiting.clear();
    states.removeRole('approver');
  }
}

/// The channel one approver comes through.
final class _Waiting {
  _Waiting(this.owner, TomSecretsRecordedApprover approver)
    : device = approver.device,
      relay = approver.relay!,
      linkId = approver.linkId!;

  final TomSecretsRelayLinkHost owner;
  final String device;
  final String relay;
  final String linkId;

  TomSecretsPairingChannel? _channel;
  bool _stopped = false;
  Timer? _again;
  Duration _pause = Duration.zero;

  void open() => unawaited(_run());

  void _state(String state, {String? reason}) => owner.states.set(
    device,
    'approver',
    state: state,
    via: 'relay',
    reason: reason,
  );

  Future<void> _run() async {
    if (_stopped) return;
    TomSecretsPairingChannel? channel;
    try {
      _state('connecting');
      final r = await owner.relayFor(relay);
      channel = _channel = await r.link(linkId);
      if (_stopped) {
        await channel.close();
        return;
      }
      _state('waiting');
      final ended = Completer<void>();
      final watched = _WatchedChannel(channel, ended);
      // The approver came when its first bytes arrive; the channel ending
      // before that (the relay's 24 hours alone, a stop) opens it again.
      await Future.any([watched.joined.future, ended.future]);
      if (_stopped || ended.isCompleted) {
        throw const _ChannelEnded();
      }
      final me = await owner.trust.linkKey();
      final previousMe = await owner.trust.previousLinkKey();
      final recorded = owner.trust.approver(device);
      if (recorded == null) throw const _ChannelEnded();
      final session = await TomSecretsLinkSession.respond(
        watched,
        me: me,
        previousMe: previousMe,
        approvers: [
          if (recorded.linkKey != null)
            (device: device, key: recorded.linkKey!),
          if (recorded.previousLinkKey != null)
            (device: device, key: recorded.previousLinkKey!),
        ],
        host: owner.host,
      );
      owner.approvals.addLinkSession(session, linkKey: me.publicKey);
      _pause = Duration.zero;
      _state('connected');
      owner.log.info('relay_link_open', {'approver': device});
      await ended.future;
      owner.log.info('relay_link_closed', {'approver': device});
      _again?.cancel();
      _again = Timer(Duration.zero, open);
      if (!_stopped) _state('connecting');
    } on _ChannelEnded {
      // Closed before anyone came: opened again after the first pause, so a
      // relay that ends channels at once is not asked in a loop.
      await channel?.close();
      if (_stopped) return;
      _again?.cancel();
      _again = Timer(owner.retry, open);
    } on Object catch (e) {
      await channel?.close();
      if (_stopped) return;
      _state('unreachable', reason: tomSecretsRelayLinkReason(e));
      owner.log.info('relay_link_failed', {
        'approver': device,
        'error': tomSecretsRelayLinkReason(e),
      });
      _pause = _pause == Duration.zero
          ? owner.retry
          : _pause * 2 > tomSecretsRelayLinkRetryMax
          ? tomSecretsRelayLinkRetryMax
          : _pause * 2;
      _again?.cancel();
      _again = Timer(_pause, open);
    }
  }

  Future<void> stop() async {
    _stopped = true;
    _again?.cancel();
    await _channel?.close();
  }
}

final class _ChannelEnded implements Exception {
  const _ChannelEnded();
}

/// [inner], read from at once: its bytes are kept for the session until it
/// listens, [joined] completes at the first ones, [ended] when they end
/// (the session, the other side or the relay closed it).
final class _WatchedChannel implements TomSecretsApprovalChannel {
  _WatchedChannel(this.inner, this.ended) {
    _subscription = inner.incoming.listen(
      (bytes) {
        if (!joined.isCompleted) joined.complete();
        _out.add(bytes);
      },
      onError: _out.addError,
      onDone: () {
        _end();
        unawaited(_out.close());
      },
    );
  }

  final TomSecretsApprovalChannel inner;
  final Completer<void> ended;

  /// Completes at the first bytes.
  final Completer<void> joined = Completer();
  final StreamController<List<int>> _out = StreamController();
  late final StreamSubscription<List<int>> _subscription;

  void _end() {
    if (!ended.isCompleted) ended.complete();
  }

  @override
  Stream<List<int>> get incoming => _out.stream;

  @override
  void send(List<int> bytes) => inner.send(bytes);

  @override
  Future<void> close() async {
    _end();
    await _subscription.cancel();
    unawaited(_out.close());
    await inner.close();
  }
}
