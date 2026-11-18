// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The SSH agent protocol (draft-miller-ssh-agent) as OpenSSH speaks it,
/// for the agent inside the service (part-os-integration, DP-48): framing,
/// one connection's state, and the checks OpenSSH's own agent makes.
///
/// | Message | Handled |
/// | --- | --- |
/// | `REQUEST_IDENTITIES` | the backend's identities for the connection |
/// | `SIGN_REQUEST` | the backend's signature, or `FAILURE` |
/// | `EXTENSION session-bind@openssh.com` | the host key's signature of the session id checked, the binding recorded |
/// | everything else (`ADD_IDENTITY`, `REMOVE_*`, `LOCK`, `UNLOCK`, other extensions) | `FAILURE` |
///
/// A connection bound by `session-bind` records each binding (destination
/// host key, session id, whether it was forwarded). A sign request that is an
/// SSH user authentication on a bound connection must name the last
/// binding's session id; the destination is the last binding's host key,
/// and the request is forwarded when an earlier binding was.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'ssh_private_key.dart';
import 'ssh_wire.dart';

/// The agent protocol's message numbers.
abstract final class TomSecretsSshAgentMessage {
  /// `SSH_AGENT_FAILURE`.
  static const int failure = 5;

  /// `SSH_AGENT_SUCCESS`.
  static const int success = 6;

  /// `SSH_AGENTC_REQUEST_IDENTITIES`.
  static const int requestIdentities = 11;

  /// `SSH_AGENT_IDENTITIES_ANSWER`.
  static const int identitiesAnswer = 12;

  /// `SSH_AGENTC_SIGN_REQUEST`.
  static const int signRequest = 13;

  /// `SSH_AGENT_SIGN_RESPONSE`.
  static const int signResponse = 14;

  /// `SSH_AGENTC_EXTENSION`.
  static const int extension = 27;
}

/// The largest message the agent reads (OpenSSH's `AGENT_MAX_LEN`).
const int tomSecretsSshAgentMaxMessage = 256 * 1024;

/// At most this many bindings per connection (OpenSSH's
/// `AGENT_MAX_SESSION_IDS`).
const int tomSecretsSshAgentMaxBindings = 16;

/// The fingerprint of an SSH public key [blob] as `ssh-keygen -l` prints it:
/// `SHA256:` and the unpadded base64 of its SHA-256.
String tomSecretsSshFingerprint(List<int> blob) =>
    'SHA256:${base64.encode(crypto.sha256.convert(blob).bytes).replaceAll('=', '')}';

/// One `session-bind@openssh.com` of a connection: the host [hostKey] ssh
/// connected to, the SSH [sessionId], and whether the connection is
/// [forwarded] (the agent reached from a remote host).
final class TomSecretsSshBinding {
  /// A binding.
  const TomSecretsSshBinding(this.hostKey, this.sessionId, this.forwarded);

  /// The destination's host key (SSH's wire form).
  final Uint8List hostKey;

  /// The session identifier the host key signed.
  final Uint8List sessionId;

  /// Whether the binding is of a forwarded connection.
  final bool forwarded;

  /// The host key's fingerprint.
  String get hostKeyFingerprint => tomSecretsSshFingerprint(hostKey);
}

/// What a signature is for, read from the data to be signed.
enum TomSecretsSshSignPurpose {
  /// An SSH user authentication (`SSH_MSG_USERAUTH_REQUEST`, publickey).
  userAuth,

  /// An `SSHSIG` signature (`ssh-keygen -Y sign`, git's commit signing).
  sshSig,

  /// Anything else.
  other,
}

/// A key the agent offers.
final class TomSecretsSshAgentIdentity {
  /// The key [publicKeyBlob] with [comment].
  const TomSecretsSshAgentIdentity(this.publicKeyBlob, this.comment);

  /// The public key (SSH's wire form).
  final Uint8List publicKeyBlob;

  /// Its comment (shown by `ssh-add -l`).
  final String comment;
}

/// A sign request after the connection's checks.
final class TomSecretsSshSignRequest {
  /// A request to sign [data] with [publicKeyBlob].
  const TomSecretsSshSignRequest({
    required this.publicKeyBlob,
    required this.data,
    required this.flags,
    required this.bindings,
    required this.purpose,
    this.namespace,
  });

  /// The key asked for.
  final Uint8List publicKeyBlob;

  /// The data to sign.
  final Uint8List data;

  /// The flags ([TomSecretsSshSignFlags]).
  final int flags;

  /// The connection's bindings, oldest first.
  final List<TomSecretsSshBinding> bindings;

  /// What the signature is for.
  final TomSecretsSshSignPurpose purpose;

  /// The namespace of an `SSHSIG` signature (`git`, `file`, ...).
  final String? namespace;

  /// The destination: the last binding, or null on an unbound connection.
  TomSecretsSshBinding? get destination =>
      bindings.isEmpty ? null : bindings.last;

  /// Whether the request comes over a forwarded agent connection.
  bool get forwarded => bindings.any((b) => b.forwarded);

  /// The key's fingerprint.
  String get keyFingerprint => tomSecretsSshFingerprint(publicKeyBlob);
}

/// What the agent answers from: the keys and the signatures. The service
/// decides grants, prompts and the audit behind it.
abstract interface class TomSecretsSshAgentBackend {
  /// The keys to list for a connection with [bindings].
  Future<List<TomSecretsSshAgentIdentity>> identities(
    List<TomSecretsSshBinding> bindings,
  );

  /// The signature blob for [request], or null (`FAILURE`).
  Future<Uint8List?> sign(TomSecretsSshSignRequest request);
}

/// Splits a byte stream into agent messages (`uint32 length`, the message).
final class TomSecretsSshAgentFramer {
  final BytesBuilder _buffer = BytesBuilder();

  /// The complete messages after [bytes] arrived. Throws [FormatException]
  /// for an empty message or one over [tomSecretsSshAgentMaxMessage] (the
  /// connection is then closed).
  List<Uint8List> add(List<int> bytes) {
    _buffer.add(bytes);
    final out = <Uint8List>[];
    var data = _buffer.takeBytes();
    var at = 0;
    while (data.length - at >= 4) {
      final length = ByteData.sublistView(data, at, at + 4).getUint32(0);
      if (length == 0 || length > tomSecretsSshAgentMaxMessage) {
        throw const FormatException('agent message length');
      }
      if (data.length - at - 4 < length) break;
      out.add(Uint8List.fromList(data.sublist(at + 4, at + 4 + length)));
      at += 4 + length;
    }
    if (at < data.length) _buffer.add(data.sublist(at));
    data = Uint8List(0);
    return out;
  }

  /// [message] framed for sending.
  static Uint8List frame(List<int> message) =>
      (SshWireWriter()
            ..uint32(message.length)
            ..raw(message))
          .bytes;
}

/// One agent connection: answers each message in turn.
final class TomSecretsSshAgentConnection {
  /// A connection answering from [backend].
  TomSecretsSshAgentConnection(this.backend);

  /// The backend.
  final TomSecretsSshAgentBackend backend;

  final List<TomSecretsSshBinding> _bindings = [];

  /// The connection's bindings, oldest first.
  List<TomSecretsSshBinding> get bindings => List.unmodifiable(_bindings);

  static final Uint8List _failure = Uint8List.fromList([
    TomSecretsSshAgentMessage.failure,
  ]);
  static final Uint8List _success = Uint8List.fromList([
    TomSecretsSshAgentMessage.success,
  ]);

  /// The answer to [message] (without its length).
  Future<Uint8List> handle(Uint8List message) async {
    try {
      final r = SshWire(message);
      final type = r.byte();
      switch (type) {
        case TomSecretsSshAgentMessage.requestIdentities:
          final ids = await backend.identities(bindings);
          final w = SshWireWriter()
            ..byte(TomSecretsSshAgentMessage.identitiesAnswer)
            ..uint32(ids.length);
          for (final id in ids) {
            w
              ..bytes_(id.publicKeyBlob)
              ..text(id.comment);
          }
          return w.bytes;
        case TomSecretsSshAgentMessage.signRequest:
          final blob = Uint8List.fromList(r.string());
          final data = Uint8List.fromList(r.string());
          final flags = r.uint32();
          final request = _signRequest(blob, data, flags);
          if (request == null) return _failure;
          final signature = await backend.sign(request);
          if (signature == null) return _failure;
          return (SshWireWriter()
                ..byte(TomSecretsSshAgentMessage.signResponse)
                ..bytes_(signature))
              .bytes;
        case TomSecretsSshAgentMessage.extension:
          final name = r.text();
          if (name != 'session-bind@openssh.com') return _failure;
          return await _sessionBind(r) ? _success : _failure;
        default:
          return _failure;
      }
    } on FormatException {
      return _failure;
    }
  }

  /// `session-bind@openssh.com`: string host key, string session id,
  /// string signature, bool forwarding. The host key's signature of the
  /// session id must verify. A session id bound before is accepted again
  /// with the same forwarding flag; after a binding for authentication
  /// (not forwarded) no other binding is accepted.
  Future<bool> _sessionBind(SshWire r) async {
    final hostKey = Uint8List.fromList(r.string());
    final sessionId = Uint8List.fromList(r.string());
    final signature = r.string();
    final forwarded = r.boolean();
    if (!await tomSecretsSshVerify(hostKey, signature, sessionId)) {
      return false;
    }
    for (final b in _bindings) {
      if (_equal(b.sessionId, sessionId)) {
        return b.forwarded == forwarded && _equal(b.hostKey, hostKey);
      }
    }
    if (_bindings.length >= tomSecretsSshAgentMaxBindings) return false;
    if (_bindings.isNotEmpty && !_bindings.last.forwarded) return false;
    _bindings.add(TomSecretsSshBinding(hostKey, sessionId, forwarded));
    return true;
  }

  /// The request, or null when OpenSSH's agent would refuse it: a user
  /// authentication on a bound connection that names another session or
  /// another key, or (host-bound publickey) another host key.
  TomSecretsSshSignRequest? _signRequest(
    Uint8List blob,
    Uint8List data,
    int flags,
  ) {
    var purpose = TomSecretsSshSignPurpose.other;
    String? namespace;
    final auth = _userAuth(data);
    if (auth != null) {
      purpose = TomSecretsSshSignPurpose.userAuth;
      if (!_equal(auth.key, blob)) return null;
      if (_bindings.isNotEmpty) {
        final last = _bindings.last;
        if (!_equal(auth.sessionId, last.sessionId)) return null;
        if (auth.hostKey != null && !_equal(auth.hostKey!, last.hostKey)) {
          return null;
        }
      }
    } else if (_startsWith(data, _sshsigMagic)) {
      purpose = TomSecretsSshSignPurpose.sshSig;
      try {
        final r = SshWire(data, _sshsigMagic.length);
        namespace = r.text();
      } on FormatException {
        namespace = null;
      }
    }
    return TomSecretsSshSignRequest(
      publicKeyBlob: blob,
      data: data,
      flags: flags,
      bindings: bindings,
      purpose: purpose,
      namespace: namespace,
    );
  }

  static final List<int> _sshsigMagic = ascii.encode('SSHSIG');

  /// The parts of an SSH publickey user authentication request (RFC 4252
  /// section 7; `publickey-hostbound-v00@openssh.com` adds the host key),
  /// or null when [data] is not one.
  static ({Uint8List sessionId, Uint8List key, Uint8List? hostKey})? _userAuth(
    Uint8List data,
  ) {
    try {
      final r = SshWire(data);
      final sessionId = Uint8List.fromList(r.string());
      if (r.byte() != 50) return null; // SSH_MSG_USERAUTH_REQUEST
      r.string(); // user
      r.string(); // service
      final method = r.text();
      final hostBound = method == 'publickey-hostbound-v00@openssh.com';
      if (method != 'publickey' && !hostBound) return null;
      if (!r.boolean()) return null;
      r.string(); // algorithm
      final key = Uint8List.fromList(r.string());
      final hostKey = hostBound ? Uint8List.fromList(r.string()) : null;
      if (!r.done) return null;
      return (sessionId: sessionId, key: key, hostKey: hostKey);
    } on FormatException {
      return null;
    }
  }

  static bool _startsWith(List<int> data, List<int> prefix) {
    if (data.length < prefix.length) return false;
    for (var i = 0; i < prefix.length; i++) {
      if (data[i] != prefix[i]) return false;
    }
    return true;
  }

  static bool _equal(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// The host names `known_hosts` [text] lists for the host key [hostKey]
/// (SSH's wire form): the plain names of its lines (hashed names cannot be
/// read back; `@revoked` lines and wildcard patterns are left out).
List<String> tomSecretsKnownHostNames(String text, List<int> hostKey) {
  final encoded = base64.encode(hostKey);
  final names = <String>{};
  for (final raw in const LineSplitter().convert(text)) {
    final line = raw.trim();
    if (line.isEmpty || line.startsWith('#')) continue;
    var parts = line.split(RegExp(r'\s+'));
    if (parts.first.startsWith('@')) {
      if (parts.first == '@revoked') continue;
      parts = parts.sublist(1);
    }
    if (parts.length < 3 || parts[2] != encoded) continue;
    for (final name in parts[0].split(',')) {
      if (name.startsWith('|') || name.contains('*') || name.contains('?')) {
        continue;
      }
      if (name.startsWith('!')) continue;
      names.add(name);
    }
  }
  return names.toList();
}

/// The `secret` of a grant for the agent (part-os-integration): which keys
/// a client may sign with, optionally only for destination hosts by their
/// host key, and whether a forwarded agent connection may use them (DP-49).
/// Written into the grant's signed `secret` member as
/// `ssh-key [host <fingerprint>[,<fingerprint>...]] [forward] <target>`,
/// where `<target>` is a canonical reference (one key), `store <name>` (the
/// keys of a vault) or `all`. A value grant never names such a secret, and an
/// agent grant never answers a value.
final class TomSecretsSshGrantSecret {
  /// Keys of [target], for [hosts] (empty: any) and with [forward].
  const TomSecretsSshGrantSecret(
    this.target, {
    this.hosts = const [],
    this.forward = false,
  });

  /// The prefix of an agent grant's secret.
  static const String prefix = 'ssh-key ';

  /// The agent secret [secret], or null when it is none.
  static TomSecretsSshGrantSecret? parse(String secret) {
    if (!secret.startsWith(prefix)) return null;
    final tokens = secret.substring(prefix.length).split(' ');
    var i = 0;
    var hosts = const <String>[];
    var forward = false;
    if (i < tokens.length && tokens[i] == 'host') {
      if (i + 1 >= tokens.length) return null;
      hosts = tokens[i + 1].split(',').where((h) => h.isNotEmpty).toList();
      if (hosts.isEmpty) return null;
      i += 2;
    }
    if (i < tokens.length && tokens[i] == 'forward') {
      forward = true;
      i++;
    }
    final target = tokens.sublist(i).join(' ');
    if (target.isEmpty) return null;
    return TomSecretsSshGrantSecret(target, hosts: hosts, forward: forward);
  }

  /// `all`, `store <name>` or a canonical reference.
  final String target;

  /// The destination hosts' key fingerprints (`SHA256:...`); empty: any.
  final List<String> hosts;

  /// Whether a forwarded connection may use the keys (each signature still
  /// confirmed). Only with a named key and named hosts.
  final bool forward;

  /// The secret as written into the grant.
  String get text => [
    'ssh-key',
    if (hosts.isNotEmpty) ...['host', hosts.join(',')],
    if (forward) 'forward',
    target,
  ].join(' ');

  /// Whether the grant is valid: forwarding only for one key and named
  /// hosts.
  bool get valid =>
      !forward ||
      (hosts.isNotEmpty && target != 'all' && !target.startsWith('store '));

  @override
  String toString() => text;
}
