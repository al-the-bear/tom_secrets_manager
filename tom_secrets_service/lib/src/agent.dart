// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The ssh-agent inside the service (part-os-integration, DP-48, DP-49): a
/// third endpoint (`agent.sock` on Linux and macOS, the named pipe
/// `\\.\pipe\tsm-ssh-agent` on Windows) that serves the vaults' SSH keys to
/// `ssh`, `git`, `scp` and `rsync`. Private keys never leave the service.
///
/// - Each connection's peer is measured as a client's is; a peer that
///   cannot be measured, or another OS user's, gets no keys and no
///   signature.
/// - `REQUEST_IDENTITIES`: unlocked, the `ssh-key` entries the vaults serve
///   (KeeAgent's "allow" and "add at open"), less those a `never` agent
///   grant refuses the client; a forwarded connection only the keys an agent
///   grant lets it use forwarded. Locked, the public keys kept from the last
///   unlock with the grants that cover them (`agent_keys.json` in the data
///   directory; public keys are no secrets).
/// - `SIGN_REQUEST`: the grants and the approvers decide
///   ([TomSecretsAccessPolicy] with a [TomSecretsSshUse]); a locked service
///   asks for an unlock and waits up to the approval timeout; every decision
///   is audited by the policy.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'access.dart';
import 'agent_pipe.dart';
import 'approvals.dart';
import 'audit.dart';
import 'identity.dart';
import 'log.dart';
import 'peer_identity.dart';

/// What the agent needs from the service.
abstract interface class TomSecretsAgentHost {
  /// This host's name.
  String get host;

  /// Whether the service is locked.
  bool get isLocked;

  /// Waits up to [timeout] for an unlock; whether the service is unlocked.
  Future<bool> waitUnlocked(Duration timeout);

  /// Asks the attached app for an unlock for [identity]; whether one is
  /// attached.
  bool askUnlock(TomSecretsIdentity identity);

  /// How long a request waits for an unlock or an approver.
  Duration get approvalTimeout;

  /// The served vaults, while unlocked.
  TomSecretsResolver? get resolver;

  /// Who decides a signature.
  TomSecretsAccessPolicy? get agentPolicy;

  /// The audit log, while unlocked.
  TomSecretsAuditLog? get audit;

  /// The operational log.
  TomSecretsLog get log;

  /// Measures the peers.
  TomSecretsPeerMeasurer get peerMeasurer;

  /// `agent_keys.json` (the public keys a locked agent lists).
  String get agentKeysFile;

  /// The user's `known_hosts`, read for the names of a destination.
  String? get knownHostsFile;
}

/// One accepted agent connection, whatever carries it.
abstract interface class TomSecretsAgentChannel {
  /// The bytes the client sends.
  Stream<List<int>> get input;

  /// Sends [bytes] (one framed answer).
  void send(List<int> bytes);

  /// Ends the connection.
  Future<void> close();

  /// Measures the peer.
  Future<TomSecretsPeerMeasurement> measure();
}

/// A key the agent serves.
final class _AgentKey {
  _AgentKey(this.entry, this.blob, this.keyType, this.confirm);

  final TomSecretsIndexedEntry entry;
  final Uint8List blob;
  final String keyType;
  final bool confirm;

  String get reference => '${entry.store}/~${entry.uuid}';

  String get title => entry.entry.label ?? '';
}

/// The agent of one service.
final class TomSecretsSshAgent {
  /// The agent of [host].
  TomSecretsSshAgent(this.host);

  /// The service.
  final TomSecretsAgentHost host;

  final Set<_AgentSession> _sessions = {};
  final Map<String, Uint8List> _publicKeys = {};
  String? _written;
  ServerSocket? _socket;
  TomSecretsAgentPipeServer? _pipe;

  /// The endpoint as `service.json` names it, while it runs.
  Map<String, Object?>? endpoint;

  /// Opens the Unix socket at [path]; a file left there by a dead service
  /// is replaced.
  Future<void> listenSocket(String path) async {
    if (await FileSystemEntity.type(path, followLinks: false) !=
        FileSystemEntityType.notFound) {
      await File(path).delete();
    }
    final server = await ServerSocket.bind(
      InternetAddress(path, type: InternetAddressType.unix),
      0,
    );
    _socket = server;
    endpoint = {'socket': path};
    server.listen(
      (socket) => _accept(_SocketChannel(socket, host.peerMeasurer)),
    );
  }

  /// Opens the named pipe [name] (Windows).
  Future<void> listenPipe(String name) async {
    final measurer = host.peerMeasurer;
    _pipe = await TomSecretsAgentPipeServer.start(
      name,
      onChannel: (channel) => _accept(channel),
      measure: (pid) async => measurer is TomSecretsSystemPeerMeasurer
          ? measurer.measureProcess(pid)
          : const TomSecretsPeerRefused('unidentifiable', 'no measurer'),
    );
    endpoint = {'pipe': name};
  }

  /// Closes the endpoint and every connection.
  Future<void> close() async {
    await _socket?.close();
    await _pipe?.close();
    for (final s in [..._sessions]) {
      await s.channel.close();
    }
    final path = endpoint?['socket'];
    if (path is String &&
        await FileSystemEntity.type(path, followLinks: false) !=
            FileSystemEntityType.notFound) {
      await File(path).delete();
    }
    endpoint = null;
  }

  void _accept(TomSecretsAgentChannel channel) {
    final session = _AgentSession(this, channel);
    _sessions.add(session);
    unawaited(session.start().whenComplete(() => _sessions.remove(session)));
  }

  // ── The keys ────────────────────────────────────────────────────────────

  /// The keys the unlocked vaults serve.
  Future<List<_AgentKey>> _keys() async {
    final resolver = host.resolver;
    if (resolver == null) return const [];
    final out = <_AgentKey>[];
    for (final store in resolver.stores) {
      final vaultConfirm = store.metadata.sshConfirm;
      for (final e in store.entries) {
        if (e.isOverlay) continue;
        final state = tomSecretsSshAgentStateOf(e.entry);
        if (state.state != TomSecretsSshAgentServing.served) continue;
        final key = state.key!;
        final blob = await _publicKeyOf(e, key.bytes, key.info);
        final keyType = key.info.keyType;
        if (blob == null || keyType == null) continue;
        out.add(_AgentKey(e, blob, keyType, state.confirm || vaultConfirm));
      }
    }
    return out;
  }

  /// The public key of a key file: from the file, or (an encrypted PEM key)
  /// decoded once with the entry's passphrase and remembered.
  Future<Uint8List?> _publicKeyOf(
    TomSecretsIndexedEntry e,
    Uint8List bytes,
    TomSecretsSshKeyInfo info,
  ) async {
    if (info.publicKeyBlob != null) return info.publicKeyBlob;
    final cacheKey = '${e.store}/${e.uuid}/${crypto.sha256.convert(bytes)}';
    final known = _publicKeys[cacheKey];
    if (known != null) return known;
    try {
      final key = await TomSecretsSshPrivateKey.decode(
        bytes,
        passphrase: e.entry.getString(KdbxKeyCommon.PASSWORD)?.getText(),
      );
      final blob = key.publicKeyBlob;
      key.dispose();
      return _publicKeys[cacheKey] = blob;
    } on TomSecretsSshKeyException catch (x) {
      host.log.info('agent_key_unusable', {
        'store': e.store,
        'problem': x.problem.name,
      });
      return null;
    }
  }

  /// Keeps the public keys an agent grant covers, with the grants' subjects,
  /// for listing while locked.
  Future<void> _keepForLocked(List<_AgentKey> keys) async {
    final policy = host.agentPolicy;
    if (policy is! TomSecretsApprovals) return;
    final kept = <Map<String, Object?>>[];
    for (final k in keys) {
      final subjects = <String>{
        for (final g in policy.grants)
          if (g.decision == 'allow')
            if (TomSecretsSshGrantSecret.parse(g.secret) case final s?)
              if (s.valid && _covers(s.target, k)) g.subject,
      };
      if (subjects.isEmpty) continue;
      kept.add({
        'key': base64.encode(k.blob),
        'comment': k.title,
        'subjects': subjects.toList()..sort(),
      });
    }
    final text = jsonEncode(kept);
    if (text == _written) return;
    _written = text;
    final file = File(host.agentKeysFile);
    await file.parent.create(recursive: true);
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsString(text, flush: true);
    await tmp.rename(file.path);
  }

  static bool _covers(String target, _AgentKey k) {
    if (target == 'all') return true;
    if (target.startsWith('store ')) {
      return target.substring(6) == k.entry.store;
    }
    return target == k.reference;
  }

  /// The kept public keys whose grants name [identity].
  List<TomSecretsSshAgentIdentity> _keptFor(TomSecretsIdentity identity) {
    try {
      final file = File(host.agentKeysFile);
      if (!file.existsSync()) return const [];
      final list = jsonDecode(file.readAsStringSync()) as List;
      return [
        for (final item in list.cast<Map>())
          if ((item['subjects'] as List).cast<String>().any(
            (s) => TomSecretsApprovals.subjectMatches(s, identity),
          ))
            TomSecretsSshAgentIdentity(
              base64.decode(item['key']! as String),
              item['comment'] as String? ?? '',
            ),
      ];
    } on Object catch (e) {
      host.log.error('agent_keys_unreadable', e);
      return const [];
    }
  }

  List<String> _hostNames(Uint8List hostKey) {
    final path = host.knownHostsFile;
    if (path == null) return const [];
    try {
      final file = File(path);
      if (!file.existsSync()) return const [];
      return tomSecretsKnownHostNames(file.readAsStringSync(), hostKey);
    } on Object {
      return const [];
    }
  }
}

/// One connection's state and its backend.
final class _AgentSession implements TomSecretsSshAgentBackend {
  _AgentSession(this.agent, this.channel);

  final TomSecretsSshAgent agent;
  final TomSecretsAgentChannel channel;
  TomSecretsIdentity? _identity;
  String? _refused;

  TomSecretsAgentHost get host => agent.host;

  Future<void> start() async {
    final measurement = await channel.measure();
    switch (measurement) {
      case TomSecretsPeerMeasured(:final identity):
        _identity = identity;
      case TomSecretsPeerRefused(:final reason, :final detail):
        _refused = reason;
        host.log.info('agent_refused', {'reason': reason, 'detail': ?detail});
    }
    final connection = TomSecretsSshAgentConnection(this);
    final framer = TomSecretsSshAgentFramer();
    final done = Completer<void>();
    var queue = Future<void>.value();
    channel.input.listen(
      (bytes) {
        final List<Uint8List> messages;
        try {
          messages = framer.add(bytes);
        } on FormatException {
          unawaited(channel.close());
          return;
        }
        for (final m in messages) {
          queue = queue.then((_) async {
            final Uint8List answer;
            try {
              answer = await connection.handle(m);
            } on Object catch (e) {
              host.log.error('agent_request_failed', e);
              channel.send(
                TomSecretsSshAgentFramer.frame([
                  TomSecretsSshAgentMessage.failure,
                ]),
              );
              return;
            }
            channel.send(TomSecretsSshAgentFramer.frame(answer));
          });
        }
      },
      onError: (_) {},
      onDone: () {
        if (!done.isCompleted) done.complete();
      },
      cancelOnError: true,
    );
    await done.future;
    await queue;
  }

  TomSecretsSshUse _use(
    _AgentKey key, {
    required List<TomSecretsSshBinding> bindings,
    String purpose = 'other',
    String? namespace,
    bool listing = false,
  }) {
    final destination = bindings.isEmpty ? null : bindings.last;
    return TomSecretsSshUse(
      keyFingerprint: tomSecretsSshFingerprint(key.blob),
      keyType: key.keyType,
      title: key.title,
      hostKeyFingerprint: destination?.hostKeyFingerprint,
      hostNames: destination == null || listing
          ? const []
          : agent._hostNames(destination.hostKey),
      forwarded: bindings.any((b) => b.forwarded),
      purpose: purpose,
      namespace: namespace,
      confirm: key.confirm,
      listing: listing,
    );
  }

  TomSecretsAccessRequest? _requestOf(_AgentKey key) {
    final resolver = host.resolver;
    if (resolver == null) return null;
    try {
      // The entry by its UUID; the title is read (a key entry may have no
      // Password), the key itself is taken from the entry when signing.
      final resolution = resolver.resolve(key.reference, field: 'Title');
      resolution.value.dispose();
      return TomSecretsAccessRequest(
        reference: key.reference,
        resolution: resolution,
        client: const {'name': 'ssh-agent'},
        identity: _identity!,
      );
    } on Object {
      return null;
    }
  }

  @override
  Future<List<TomSecretsSshAgentIdentity>> identities(
    List<TomSecretsSshBinding> bindings,
  ) async {
    final identity = _identity;
    if (identity == null) return const [];
    if (host.isLocked) return agent._keptFor(identity);
    final keys = await agent._keys();
    await agent._keepForLocked(keys);
    final policy = host.agentPolicy;
    final forwarded = bindings.any((b) => b.forwarded);
    final out = <TomSecretsSshAgentIdentity>[];
    for (final k in keys) {
      if (policy != null) {
        final request = _requestOf(k);
        if (request == null) continue;
        final decision = (await policy.check(
          TomSecretsAccessBatch(
            identity: identity,
            client: const {'name': 'ssh-agent'},
            items: [request],
            ssh: _use(k, bindings: bindings, listing: true),
          ),
        )).single;
        if (decision is TomSecretsAccessDenied) continue;
        // A forwarded connection sees only the keys a grant lets it use.
        if (forwarded &&
            decision is TomSecretsAccessAllowed &&
            decision.grantId == null) {
          continue;
        }
      } else if (forwarded) {
        continue;
      }
      out.add(TomSecretsSshAgentIdentity(k.blob, k.title));
    }
    return out;
  }

  @override
  Future<Uint8List?> sign(TomSecretsSshSignRequest request) async {
    final identity = _identity;
    if (identity == null) {
      _auditRefusal(request, 'denied:${_refused ?? 'unidentifiable'}');
      return null;
    }
    if (host.isLocked) {
      host.askUnlock(identity);
      if (!await host.waitUnlocked(host.approvalTimeout)) {
        host.log.info('agent_sign', {'outcome': 'locked'});
        return null;
      }
    }
    final keys = await agent._keys();
    final key = keys
        .where((k) => _same(k.blob, request.publicKeyBlob))
        .firstOrNull;
    if (key == null) {
      host.log.info('agent_sign', {'outcome': 'unknown_key'});
      return null;
    }
    // SHA-1 RSA signatures are not made (RFC 8332): refused before anyone
    // is asked.
    if (key.keyType == 'ssh-rsa' &&
        request.flags &
                (TomSecretsSshSignFlags.rsaSha256 |
                    TomSecretsSshSignFlags.rsaSha512) ==
            0) {
      host.log.info('agent_sign', {'outcome': 'sha1_refused'});
      return null;
    }
    final policy = host.agentPolicy;
    final item = _requestOf(key);
    if (policy == null || item == null) return null;
    final decision = (await policy.check(
      TomSecretsAccessBatch(
        identity: identity,
        client: const {'name': 'ssh-agent'},
        items: [item],
        ssh: _use(
          key,
          bindings: request.bindings,
          purpose: switch (request.purpose) {
            TomSecretsSshSignPurpose.userAuth => 'userauth',
            TomSecretsSshSignPurpose.sshSig => 'sshsig',
            TomSecretsSshSignPurpose.other => 'other',
          },
          namespace: request.namespace,
        ),
        timeout: host.approvalTimeout,
      ),
    )).single;
    if (decision is! TomSecretsAccessAllowed) {
      host.log.info('agent_sign', {
        'outcome': (decision as TomSecretsAccessDenied).reason,
      });
      return null;
    }
    final state = tomSecretsSshAgentStateOf(key.entry.entry);
    final file = state.key;
    if (file == null) return null;
    TomSecretsSshPrivateKey? private;
    try {
      private = await TomSecretsSshPrivateKey.decode(
        file.bytes,
        passphrase: key.entry.entry
            .getString(KdbxKeyCommon.PASSWORD)
            ?.getText(),
      );
      final signature = await private.sign(request.data, flags: request.flags);
      host.log.info('agent_sign', {'outcome': 'signed'});
      return signature;
    } on TomSecretsSshKeyException catch (e) {
      host.log.info('agent_sign', {'outcome': e.problem.name});
      return null;
    } on StateError {
      return null;
    } finally {
      private?.dispose();
    }
  }

  void _auditRefusal(TomSecretsSshSignRequest request, String outcome) {
    final audit = host.audit;
    if (audit == null) return;
    final destination = request.destination;
    audit.add(
      TomSecretsAuditRecord(
        time: DateTime.now().toUtc(),
        host: host.host,
        identity: const {'kind': 'unidentified'},
        refs: const [],
        outcome: outcome,
        ssh: {
          'key': request.keyFingerprint,
          'host': ?destination?.hostKeyFingerprint,
          'forwarded': request.forwarded,
        },
      ),
    );
  }

  static bool _same(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// A connection on the Unix socket.
final class _SocketChannel implements TomSecretsAgentChannel {
  _SocketChannel(this.socket, this.measurer);

  final Socket socket;
  final TomSecretsPeerMeasurer measurer;

  @override
  Stream<List<int>> get input => socket;

  @override
  void send(List<int> bytes) => socket.add(bytes);

  @override
  Future<void> close() async {
    try {
      await socket.close();
    } on Object {
      socket.destroy();
    }
  }

  @override
  Future<TomSecretsPeerMeasurement> measure() => measurer.measure(socket);
}
