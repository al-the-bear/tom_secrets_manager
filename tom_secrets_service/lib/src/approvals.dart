// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Approvals and grants (part-protocol, protocol.md 7.2 to 7.5, 9; DP-17,
/// DP-18, DP-19, DP-100, DP-160, TD-3): the allow list of this host read
/// from the primary vault (`tsm.grants/<host>`, only grants whose Ed25519
/// and ML-DSA-65 signatures verify against a recorded approver key), the
/// matching with its pins, the prompt to the attached app and over the
/// approval link, the approval code and its single-use token when no
/// approver is connected, prompt flooding held back, and the audit record
/// of every decision.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:tom_secrets_client/tom_secrets_client.dart'
    show TomSecretReference;
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'access.dart';
import 'audit.dart';
import 'identity.dart';
import 'log.dart';

/// What the approvals need from the service.
abstract interface class TomSecretsApprovalHost {
  /// This host's name.
  String get host;

  /// The device settings (timeouts).
  TomSecretsDeviceSettings get settings;

  /// The device's trust material, while unlocked.
  TomSecretsTrust get trust;

  /// The open primary vault, while unlocked.
  KdbxFile? get primary;

  /// Writes the primary vault (after a grant or revocation was added).
  Future<void> savePrimary();

  /// Commits the trust material (recorded pins, keys).
  Future<void> writeTrust();

  /// Whether an approver app is attached (a subscribed admin that is not
  /// `tsm`).
  bool get hasLocalApprover;

  /// Sends [event] to the attached approver apps.
  void emitToApprovers(Map<String, Object?> event);

  /// The audit log, while unlocked.
  TomSecretsAuditLog? get audit;

  /// The operational log.
  TomSecretsLog get log;

  /// The current time (UTC) the key dates are recorded at.
  DateTime get now;
}

/// An answer to a prompt.
final class TomSecretsApprovalAnswer {
  /// [decision] (`once`, `always`, `folder`, `never`) for [secret] (`ref`,
  /// `store`, `all`) with [folder] and [pin], by [approver].
  const TomSecretsApprovalAnswer({
    required this.decision,
    required this.secret,
    required this.approver,
    this.folder,
    this.pin,
    this.clientToken,
  });

  /// The decision.
  final String decision;

  /// What a lasting decision covers.
  final String secret;

  /// The folder of a `folder` decision.
  final String? folder;

  /// The pin of a lasting decision (`hash`, `off`, `{relaxedUntil}`).
  final Object? pin;

  /// The approver device.
  final String approver;

  /// The client token the approving app issued for an `always` of a request
  /// with `wantClientToken` (32 bytes, base64; protocol.md 7.4).
  final String? clientToken;
}

/// A request that went to the approvers.
final class _Waiting {
  _Waiting(this.approvalId, this.batch, this.items, this.key, this.code);

  final String approvalId;
  final TomSecretsAccessBatch batch;
  final List<TomSecretsAccessRequest> items;
  final String key;
  final String? code;
  final Completer<List<TomSecretsAccess>> done = Completer();
  final Set<String> redeemedTokens = {};
  int badTokens = 0;
  Timer? timer;

  Map<String, Object?> event(String host) => {
    'op': 'approval_needed',
    'approvalId': approvalId,
    'host': host,
    'identity': batch.identity.toJson(),
    'refs': [for (final i in items) _canonical(i.reference)],
    'resolved': [
      for (final i in items)
        {
          'store': i.resolution.entry.store,
          'path': i.resolution.entry.pathText,
          'kind': i.resolution.type.wireName,
        },
    ],
    if (_remote(batch.identity)) 'hostHint': 'remote',
    'approvalCode': ?code,
    if (wantsToken) 'wantClientToken': true,
  };

  /// Whether the client asked for a client token.
  bool get wantsToken => items.any((i) => i.wantClientToken);
}

String _canonical(String ref) {
  try {
    return TomSecretReference.parse(ref).canonical;
  } on Object {
    return ref;
  }
}

String _base(String path) =>
    path.split(RegExp(r'[/\\]')).last.toLowerCase().replaceAll('.exe', '');

/// A peer forwarded over SSH: the prompt says it comes from another machine.
bool _remote(TomSecretsIdentity identity) =>
    _base(identity.exe) == 'sshd' ||
    _base((identity.parent?['exe'] as String?) ?? '') == 'sshd';

/// An accepted grant of this host.
final class TomSecretsGrant {
  TomSecretsGrant._(this.object, this.approverKeyId);

  /// The grant as stored (members, signatures).
  final Map<String, Object?> object;

  /// The recorded key that signed it.
  final String approverKeyId;

  /// Its id.
  String get id => object['id']! as String;

  /// `exe <path>`, `script <interpreter> <path>`, ...
  String get subject => object['subject']! as String;

  /// A canonical reference, `store <name>` or `all`.
  String get secret => object['secret']! as String;

  /// `allow` or `never`.
  String get decision => object['decision']! as String;

  /// Its pin.
  TomSecretsPin get pin => object['pin'] == null
      ? const TomSecretsPinOff()
      : TomSecretsPin.parse(object['pin']);
}

/// Approvals and grants of one unlocked service.
final class TomSecretsApprovals implements TomSecretsAccessPolicy {
  /// The approvals of [service].
  TomSecretsApprovals(this.service, {TomSecretsFileHashes? hashes})
    : hashes = hashes ?? TomSecretsFileHashes();

  /// The service.
  final TomSecretsApprovalHost service;

  /// The file hashes pins are checked with.
  final TomSecretsFileHashes hashes;

  final List<TomSecretsGrant> _grants = [];
  final List<TomSecretsGrant> _pending = [];
  final Set<String> _revoked = {};
  final Map<String, _Waiting> _waiting = {};
  final Map<String, List<DateTime>> _refusals = {};
  final Map<String, DateTime> _heldBack = {};
  final Map<String, DateTime> _lastUsed = {};
  final List<_LinkPeer> _links = [];
  int _nextApproval = 1;

  /// The grants this host applies (from the vault, and pending copies from
  /// the link).
  List<TomSecretsGrant> get grants => [..._grants, ..._pending];

  /// The approval codes of the requests waiting with one.
  List<String> get waitingCodes => [
    for (final w in _waiting.values)
      if (w.code != null) w.code!,
  ];

  /// The waiting requests' `approval_needed` events.
  List<Map<String, Object?>> get waitingEvents => [
    for (final w in _waiting.values) w.event(service.host),
  ];

  // ── The allow list ──────────────────────────────────────────────────────

  /// Reads this host's grants and revocations from the primary vault:
  /// only those signed by a recorded approver key (or this device's own).
  /// An unsigned or wrongly signed object is ignored and logged. Approval
  /// records for waiting codes are taken too.
  Future<void> reload() async {
    final primary = service.primary;
    if (primary == null) return;
    final group = TomSecretsGrantsGroup(primary);
    final keys = await service.trust.grantKeys();
    _revoked.clear();
    for (final r in group.read(service.host, TomSecretsSignedKind.revocation)) {
      if (r['host'] == service.host &&
          await tomSecretsAcceptedBy(TomSecretsSignedLabels.revoke, r, keys) !=
              null) {
        _revoked.add(r['grantId']! as String);
      } else {
        service.log.info('revocation_ignored', {'grantId': r['grantId']});
      }
    }
    _grants.clear();
    for (final g in group.read(service.host, TomSecretsSignedKind.grant)) {
      final key = g['host'] == service.host
          ? await tomSecretsAcceptedBy(TomSecretsSignedLabels.grant, g, keys)
          : null;
      if (key == null) {
        service.log.info('grant_ignored', {'grantId': g['id']});
        continue;
      }
      if (_revoked.contains(g['id'])) continue;
      _grants.add(TomSecretsGrant._(g, key.keyId));
    }
    _pending.removeWhere(
      (p) => _revoked.contains(p.id) || _grants.any((g) => g.id == p.id),
    );
    await _takeApprovalRecords(group, keys);
    await _pruneTokens();
  }

  Future<void> _takeApprovalRecords(
    TomSecretsGrantsGroup group,
    List<TomSecretsApproverPublicKey> keys,
  ) async {
    if (!_waiting.values.any((w) => w.code != null)) return;
    for (final record in group.read(
      service.host,
      TomSecretsSignedKind.approval,
    )) {
      final waiting = _waiting.values
          .where((w) => w.code != null && w.code == record['code'])
          .firstOrNull;
      if (waiting == null || record['host'] != service.host) continue;
      if (await tomSecretsAcceptedBy(
            TomSecretsSignedLabels.approval,
            record,
            keys,
          ) ==
          null) {
        continue;
      }
      _answer(
        waiting,
        TomSecretsApprovalAnswer(
          decision: record['decision']! as String,
          secret: 'ref',
          approver: (record['approver'] as String?) ?? '',
        ),
      );
    }
  }

  static int _subjectRank(String subject) => switch (subject.split(' ').first) {
    'exe' || 'script' || 'exe-token' || 'tsm-command' => 3,
    'folder' => 2,
    'interpreter' => 1,
    _ => 0,
  };

  static bool _under(String path, String folder) {
    final f = folder.endsWith('/') || folder.endsWith(r'\')
        ? folder
        : '$folder${path.contains(r'\') ? r'\' : '/'}';
    return path.startsWith(f);
  }

  /// Whether [subject] names [identity]; [complete] identities only for
  /// anything but a plain executable.
  static bool subjectMatches(
    String subject,
    TomSecretsIdentity identity, {
    String? clientTokenId,
  }) {
    final space = subject.indexOf(' ');
    if (space < 0) return false;
    final kind = subject.substring(0, space);
    final rest = subject.substring(space + 1);
    switch (kind) {
      case 'exe':
        return identity.kind == 'exe' && identity.exe == rest;
      case 'script':
        return identity.kind == 'script' &&
            rest == '${identity.interpreter} ${identity.script}';
      case 'interpreter':
        return identity.interpreter == rest;
      case 'folder':
        final target = identity.script ?? identity.exe;
        final interpreter = identity.interpreter;
        if (interpreter != null && rest.endsWith(' $interpreter')) {
          final folder = rest.substring(
            0,
            rest.length - interpreter.length - 1,
          );
          if (_under(target, folder)) return true;
        }
        return _under(target, rest);
      case 'tsm-command':
        return _base(identity.exe) == 'tsm' && identity.args.join(' ') == rest;
      case 'exe-token':
        // The grant's executable and the token the connection's hello
        // carried; without the token it is the bare executable.
        final cut = rest.lastIndexOf(' ');
        return cut > 0 &&
            clientTokenId != null &&
            identity.exe == rest.substring(0, cut) &&
            rest.substring(cut + 1) == clientTokenId;
      default:
        return false;
    }
  }

  static int _secretRank(String secret, TomSecretsAccessRequest item) {
    if (secret == 'all') return 1;
    if (secret.startsWith('store ')) {
      return item.resolution.entry.store == secret.substring(6) ? 2 : 0;
    }
    return _canonical(item.reference) == secret ? 3 : 0;
  }

  /// The file a pin of [subject] names for [identity].
  static String _pinnedFile(String subject, TomSecretsIdentity identity) =>
      switch (subject.split(' ').first) {
        'script' || 'folder' => identity.script ?? identity.exe,
        _ => identity.exe,
      };

  /// The grant that decides [item], or null: the most specific subject, then
  /// the most specific secret; `never` beats `allow` at equal rank. A pinned
  /// grant whose file changed does not decide.
  Future<TomSecretsGrant?> match(
    TomSecretsIdentity identity,
    TomSecretsAccessRequest item, {
    String? clientTokenId,
  }) async {
    TomSecretsGrant? best;
    var bestRank = -1;
    for (final g in grants) {
      if (!identity.complete &&
          !(g.subject.startsWith('exe ') &&
              const TomSecretsInterpreters().ruleFor(identity.exe) == null)) {
        // Arguments or working directory unread: only a plain executable's
        // grant is no guess.
        continue;
      }
      if (!subjectMatches(g.subject, identity, clientTokenId: clientTokenId)) {
        continue;
      }
      final secretRank = _secretRank(g.secret, item);
      if (secretRank == 0) continue;
      final rank = _subjectRank(g.subject) * 10 + secretRank;
      if (rank > bestRank ||
          (rank == bestRank &&
              g.decision == 'never' &&
              best?.decision != 'never')) {
        if (g.decision == 'allow' && !await _pinHolds(g, identity)) continue;
        best = g;
        bestRank = rank;
      }
    }
    return best;
  }

  Future<bool> _pinHolds(TomSecretsGrant g, TomSecretsIdentity identity) async {
    final pin = g.pin;
    if (pin is TomSecretsPinOff) return true;
    final current = hashes.hashOf(_pinnedFile(g.subject, identity));
    final recorded = service.trust.pins[g.id];
    if (recorded == null) {
      // First use on this host: the hash it was granted for (DP-18).
      if (current == null) return false;
      service.trust.pins[g.id] = current;
      await service.writeTrust();
      return true;
    }
    final check = pin.check(recorded: recorded, current: current);
    if (check.record != null) {
      service.trust.pins[g.id] = check.record!;
      await service.writeTrust();
    }
    return check.accepted;
  }

  // ── Deciding a request ──────────────────────────────────────────────────

  String _keyOf(TomSecretsIdentity i) => '${i.kind}|${i.exe}|${i.script}';

  @override
  Future<List<TomSecretsAccess>> check(TomSecretsAccessBatch batch) async {
    final identity = batch.identity;
    final clientTokenId = await _clientTokenOf(batch);
    final decisions = List<TomSecretsAccess?>.filled(batch.items.length, null);
    final open = <int>[];
    for (var i = 0; i < batch.items.length; i++) {
      final grant = await match(
        identity,
        batch.items[i],
        clientTokenId: clientTokenId,
      );
      if (grant == null) {
        open.add(i);
      } else {
        _lastUsed[grant.id] = DateTime.now().toUtc();
        decisions[i] = grant.decision == 'allow'
            ? TomSecretsAccessAllowed(grantId: grant.id)
            : TomSecretsAccessDenied('never', grantId: grant.id);
      }
    }
    if (open.isNotEmpty) {
      final answers = await _ask(batch, [for (final i in open) batch.items[i]]);
      for (var k = 0; k < open.length; k++) {
        decisions[open[k]] = answers[k];
      }
    }
    final result = decisions.cast<TomSecretsAccess>();
    _auditBatch(batch, result);
    return result;
  }

  void _auditBatch(TomSecretsAccessBatch batch, List<TomSecretsAccess> out) {
    final audit = service.audit;
    if (audit == null) return;
    for (var i = 0; i < out.length; i++) {
      final d = out[i];
      audit.add(
        TomSecretsAuditRecord(
          time: DateTime.now().toUtc(),
          host: service.host,
          identity: batch.identity.toJson(),
          refs: [_canonical(batch.items[i].reference)],
          outcome: switch (d) {
            TomSecretsAccessAllowed() => 'allowed',
            TomSecretsAccessDenied(:final kind, :final reason) =>
              kind == 'denied' ? 'denied:$reason' : kind,
          },
          grantId: switch (d) {
            TomSecretsAccessAllowed(:final grantId) => grantId,
            TomSecretsAccessDenied(:final grantId) => grantId,
          },
          approver: switch (d) {
            TomSecretsAccessAllowed(:final approver) => approver,
            _ => null,
          },
          entries: [
            tomSecretsUuidHex(batch.items[i].resolution.entry.entry.uuid),
          ],
        ),
      );
    }
  }

  Future<List<TomSecretsAccess>> _ask(
    TomSecretsAccessBatch batch,
    List<TomSecretsAccessRequest> items,
  ) {
    final identity = batch.identity;
    List<TomSecretsAccess> all(TomSecretsAccess a) => [
      for (final _ in items) a,
    ];
    if (!identity.complete) {
      return Future.value(all(const TomSecretsAccessDenied('unidentifiable')));
    }
    final key = _keyOf(identity);
    final now = DateTime.now();
    final held = _heldBack[key];
    if (held != null && held.isAfter(now)) {
      return Future.value(
        all(
          TomSecretsAccessDenied(
            'held_back',
            kind: 'rate_limited',
            details: {'retryAfterMs': held.difference(now).inMilliseconds},
          ),
        ),
      );
    }
    final refs = [for (final i in items) _canonical(i.reference)]..sort();
    // One pending prompt per identity and reference: a repeat joins it.
    for (final w in _waiting.values) {
      final wRefs = [for (final i in w.items) _canonical(i.reference)]..sort();
      if (w.key == key && _sameList(wRefs, refs)) {
        _progress(batch, w);
        return w.done.future;
      }
    }
    if (_waiting.values.where((w) => w.key == key).length >= 3) {
      return Future.value(
        all(
          const TomSecretsAccessDenied(
            'too_many_prompts',
            kind: 'rate_limited',
            details: {'retryAfterMs': 10000},
          ),
        ),
      );
    }
    final approvalId = 'a-${_nextApproval++}';
    final connected = service.hasLocalApprover || _links.isNotEmpty;
    final code = connected
        ? null
        : tomSecretsApprovalCode(service.host, approvalId, identity.toJson(), [
            for (final i in items) i.reference,
          ]);
    final waiting = _Waiting(approvalId, batch, items, key, code);
    _waiting[approvalId] = waiting;
    var limit = connected
        ? service.settings.approvalTimeout
        : service.settings.codeTimeout;
    if (connected && batch.timeout != null && batch.timeout! < limit) {
      limit = batch.timeout!;
    }
    waiting.timer = Timer(limit, () {
      _close(
        waiting,
        connected ? 'timeout' : 'no_approver',
        all(
          connected
              ? const TomSecretsAccessDenied('timeout', kind: 'timeout')
              : const TomSecretsAccessDenied('no_approver'),
        ),
      );
    });
    final event = waiting.event(service.host);
    service.emitToApprovers(event);
    for (final link in _links) {
      unawaited(link.session.send(event));
    }
    _progress(batch, waiting);
    service.log.info('approval_needed', {
      'approvalId': approvalId,
      'refs': refs.length,
      'code': code != null,
    });
    return waiting.done.future;
  }

  void _progress(TomSecretsAccessBatch batch, _Waiting w) =>
      batch.onProgress?.call({'pending': 'approval', 'approvalCode': ?w.code});

  void _close(_Waiting w, String outcome, List<TomSecretsAccess> answer) {
    if (w.done.isCompleted) return;
    w.timer?.cancel();
    _waiting.remove(w.approvalId);
    w.done.complete(answer);
    final event = {
      'op': 'approval_closed',
      'approvalId': w.approvalId,
      'outcome': outcome,
    };
    service.emitToApprovers(event);
    for (final link in _links) {
      unawaited(link.session.send(event));
    }
    if (outcome == 'denied') {
      final key = w.key;
      final now = DateTime.now();
      final recent = (_refusals[key] ??= [])
        ..add(now)
        ..removeWhere((t) => now.difference(t) > const Duration(minutes: 10));
      if (recent.length >= 3) {
        final until = now.add(const Duration(minutes: 10));
        _heldBack[key] = until;
        recent.clear();
        service.emitToApprovers({
          'op': 'rate_limited',
          'identity': w.batch.identity.toJson(),
          'until': until.toUtc().toIso8601String(),
        });
      }
    }
    service.log.info('approval_closed', {
      'approvalId': w.approvalId,
      'outcome': outcome,
    });
  }

  /// Ends every waiting request (`abandoned`, the client gets `locked`):
  /// the service locked.
  void abandonAll() {
    for (final w in [..._waiting.values]) {
      _close(w, 'abandoned', [
        for (final _ in w.items)
          const TomSecretsAccessDenied('abandoned', kind: 'locked'),
      ]);
    }
  }

  // ── Answers ─────────────────────────────────────────────────────────────

  /// Answers the prompt [approvalId] (`approve`). A lasting decision from
  /// this device ([lasting]) is written as a grant signed with its approver
  /// key; one from a remote approver comes as its own signed grant over the
  /// link. Throws [StateError] for an unknown or ended prompt and
  /// [ArgumentError] for a malformed answer.
  Future<void> approve(
    String approvalId,
    TomSecretsApprovalAnswer answer, {
    bool lasting = true,
  }) async {
    final w = _waiting[approvalId];
    if (w == null) throw StateError('no prompt $approvalId');
    if (!tomSecretsDecisions.contains(answer.decision) ||
        !const ['ref', 'store', 'all'].contains(answer.secret) ||
        (answer.decision == 'folder' && answer.folder == null)) {
      throw ArgumentError('decision, secret and folder');
    }
    final token = answer.clientToken;
    if (token != null &&
        (answer.decision != 'always' || !w.wantsToken || !lasting)) {
      throw ArgumentError(
        'a client token answers an always of a request '
        'that asked for one',
      );
    }
    String? tokenId;
    if (token != null) tokenId = await _recordToken(token);
    if (lasting && answer.decision != 'once') {
      await _writeGrants(w, answer, clientTokenId: tokenId);
    }
    _answer(w, answer);
  }

  void _answer(_Waiting w, TomSecretsApprovalAnswer answer) {
    final allowed = answer.decision != 'never';
    _close(w, allowed ? 'approved' : 'denied', [
      for (final _ in w.items)
        allowed
            ? TomSecretsAccessAllowed(
                approver: answer.approver,
                clientToken: answer.clientToken,
              )
            : const TomSecretsAccessDenied('refused'),
    ]);
  }

  // ── Client tokens (protocol.md 7.4, DP-20) ──────────────────────────────

  /// Records the client token [token] (base64 of 32 bytes) an approver
  /// issued: only its hash. Returns its id. Throws [ArgumentError] for a
  /// token that is not 32 bytes.
  Future<String> _recordToken(String token) async {
    final List<int> bytes;
    try {
      bytes = base64.decode(token);
    } on FormatException {
      throw ArgumentError('the client token is not base64');
    }
    if (bytes.length != 32) {
      throw ArgumentError('a client token is 32 bytes');
    }
    final hash = tomSecretsClientTokenHash(bytes);
    final id = tomSecretsClientTokenId(hash);
    service.trust.clientTokens[id] ??= TomSecretsClientTokenRecord(
      hash: hash,
      created: DateTime.now().toUtc(),
    );
    await service.writeTrust();
    return id;
  }

  /// The token id the batch's connection brought, recording the identity
  /// it came with (the first one, and the last when it changes).
  Future<String?> _clientTokenOf(TomSecretsAccessBatch batch) async {
    final hash = batch.clientTokenHash;
    if (hash == null) return null;
    final id = service.trust.clientTokenIdOf(hash);
    if (id == null) return null;
    final record = service.trust.clientTokens[id]!;
    final identity = batch.identity.toJson();
    record.lastSeen = DateTime.now().toUtc();
    final changed = jsonEncode(record.lastIdentity) != jsonEncode(identity);
    record.firstIdentity ??= identity;
    record.lastIdentity = identity;
    if (changed) await service.writeTrust();
    return id;
  }

  /// The token id of an `exe-token` [subject], or null.
  static String? _tokenIdOf(String subject) => subject.startsWith('exe-token ')
      ? subject.substring(subject.lastIndexOf(' ') + 1)
      : null;

  /// Drops the token records no `exe-token` grant of this host names any
  /// more (a revoked or removed grant invalidates its token).
  Future<void> _pruneTokens() async {
    final named = {for (final g in grants) ?_tokenIdOf(g.subject)};
    final before = service.trust.clientTokens.length;
    service.trust.clientTokens.removeWhere((id, _) => !named.contains(id));
    if (service.trust.clientTokens.length != before) {
      await service.writeTrust();
    }
  }

  String _subjectFor(TomSecretsIdentity i, TomSecretsApprovalAnswer a) {
    if (a.decision == 'folder') {
      return i.interpreter == null
          ? 'folder ${a.folder}'
          : 'folder ${a.folder} ${i.interpreter}';
    }
    if (_base(i.exe) == 'tsm' && i.args.isNotEmpty && i.args.first == 'run') {
      return 'tsm-command ${i.args.join(' ')}';
    }
    return switch (i.kind) {
      'script' => 'script ${i.interpreter} ${i.script}',
      'interpreter' => 'interpreter ${i.exe}',
      _ => 'exe ${i.exe}',
    };
  }

  Future<void> _writeGrants(
    _Waiting w,
    TomSecretsApprovalAnswer a, {
    String? clientTokenId,
  }) async {
    final identity = w.batch.identity;
    final subject = clientTokenId == null
        ? _subjectFor(identity, a)
        : 'exe-token ${identity.exe} $clientTokenId';
    final secrets = switch (a.secret) {
      'all' => {'all'},
      'store' => {for (final i in w.items) 'store ${i.resolution.entry.store}'},
      _ => {for (final i in w.items) _canonical(i.reference)},
    };
    // Scripts are pinned by default, executables by path only (DP-18).
    final pin = a.pin ?? (identity.kind == 'script' ? 'hash' : 'off');
    for (final secret in secrets) {
      final grant = await addGrant({
        'host': service.host,
        'subject': subject,
        'secret': secret,
        'decision': a.decision == 'never' ? 'never' : 'allow',
        'pin': pin,
      }, save: false);
      if (pin != 'off') {
        final hash = hashes.hashOf(_pinnedFile(subject, identity));
        if (hash != null) service.trust.pins[grant['id']! as String] = hash;
      }
    }
    await service.savePrimary();
    await service.writeTrust();
  }

  static String _newId(String prefix) {
    final r = Random.secure();
    return '$prefix-${List.generate(8, (_) => r.nextInt(256).toRadixString(16).padLeft(2, '0')).join()}';
  }

  /// Adds a grant ([spec]: `host`, `subject`, `secret`, `decision`, `pin?`)
  /// signed by this device (`grants.add`); for this host it applies at once.
  /// Returns the signed grant.
  Future<Map<String, Object?>> addGrant(
    Map<String, Object?> spec, {
    bool save = true,
  }) async {
    final primary = service.primary;
    if (primary == null) throw StateError('locked');
    final key = await service.trust.approverKey();
    final grant = await key.signObject(TomSecretsSignedLabels.grant, {
      'id': _newId('g'),
      'host': spec['host'],
      'subject': spec['subject'],
      'secret': spec['secret'],
      'decision': spec['decision'],
      'created': DateTime.now().toUtc().toIso8601String(),
      'pin': ?spec['pin'],
      'approver': service.trust.device,
    });
    TomSecretsGrantsGroup(
      primary,
    ).write(spec['host']! as String, TomSecretsSignedKind.grant, grant);
    if (spec['host'] == service.host) {
      _grants.add(TomSecretsGrant._(grant, key.keyId));
    }
    if (save) await service.savePrimary();
    service.log.info('grant_added', {
      'host': spec['host'],
      'grantId': grant['id'],
      'decision': spec['decision'],
    });
    return grant;
  }

  /// The grants used since the last write, by id (written by
  /// [flushLastUsed]).
  Map<String, DateTime> get unwrittenLastUse => Map.unmodifiable(_lastUsed);

  /// Writes the last use of every grant used since the last write into its
  /// entry in the primary vault (the unsigned `lastUsed`, protocol.md 7.3),
  /// in one save; whether it wrote. A grant not in the vault yet (a pending
  /// copy from the link) waits for its vault copy.
  Future<bool> flushLastUsed() async {
    final primary = service.primary;
    if (_lastUsed.isEmpty || primary == null) return false;
    final group = TomSecretsGrantsGroup(primary);
    final written = [
      for (final MapEntry(key: id, value: time) in _lastUsed.entries)
        if (group.setLastUsed(service.host, id, time)) id,
    ];
    if (written.isEmpty) return false;
    written.forEach(_lastUsed.remove);
    await service.savePrimary();
    service.log.info('last_used_written', {'grants': written.length});
    return true;
  }

  /// Revokes the grant [grantId] of [host] (`grants.revoke`): a signed
  /// revocation is written and the grant's entry removed.
  Future<void> revokeGrant(String host, String grantId) async {
    final primary = service.primary;
    if (primary == null) throw StateError('locked');
    final key = await service.trust.approverKey();
    final revocation = await key.signObject(TomSecretsSignedLabels.revoke, {
      'host': host,
      'grantId': grantId,
      'revoked': DateTime.now().toUtc().toIso8601String(),
      'approver': service.trust.device,
    });
    TomSecretsGrantsGroup(primary)
      ..write(host, TomSecretsSignedKind.revocation, revocation)
      ..remove(host, TomSecretsSignedKind.grant, {'id': grantId});
    if (host == service.host) _applyRevocation(grantId);
    await service.savePrimary();
    await service.writeTrust();
    service.log.info('grant_revoked', {'host': host, 'grantId': grantId});
  }

  void _applyRevocation(String grantId) {
    _revoked.add(grantId);
    for (final g in grants.where((g) => g.id == grantId)) {
      // Revoking the grant invalidates its client token (protocol.md 7.4).
      final token = _tokenIdOf(g.subject);
      if (token != null) service.trust.clientTokens.remove(token);
    }
    _grants.removeWhere((g) => g.id == grantId);
    _pending.removeWhere((g) => g.id == grantId);
    service.trust.pins.remove(grantId);
  }

  /// The grants of [host], or of every host (`grants.list`), as stored,
  /// each with `accepted` (its signatures verify) and, for this host's, the
  /// last use not written yet.
  Future<List<Map<String, Object?>>> listGrants([String? host]) async {
    final primary = service.primary;
    if (primary == null) return const [];
    final group = TomSecretsGrantsGroup(primary);
    final keys = await service.trust.grantKeys();
    return [
      for (final h in host == null ? group.hosts : [host])
        for (final g in group.read(h, TomSecretsSignedKind.grant))
          {
            ...g,
            // A use not written yet shows already.
            if (h == service.host && _lastUsed[g['id']] != null)
              'lastUsed': _lastUsed[g['id']]!.toIso8601String(),
            'accepted':
                await tomSecretsAcceptedBy(
                  TomSecretsSignedLabels.grant,
                  g,
                  keys,
                ) !=
                null,
          },
    ];
  }

  // ── Approval codes and tokens ───────────────────────────────────────────

  /// Redeems [token] (`approval.redeem`, protocol.md 9.6): the outcome is
  /// `answered`, `used` (redeemed before) or `bad` (it matches nothing; it
  /// counts against every request waiting with a code, the third ends it
  /// `denied`).
  String redeem(String token) {
    final keys = [for (final a in service.trust.approvers) a.tokenKey];
    final normal = tomSecretsNormalizeCode(token);
    final match = tomSecretsRedeemToken(
      normal,
      waitingCodes,
      keys,
      service.host,
    );
    if (match == null) {
      for (final w in [..._waiting.values]) {
        if (w.code == null) continue;
        if (++w.badTokens >= 3) {
          _close(w, 'denied', [
            for (final _ in w.items) const TomSecretsAccessDenied('bad_token'),
          ]);
        }
      }
      return 'bad';
    }
    final w = _waiting.values.firstWhere((w) => w.code == match.code);
    if (!w.redeemedTokens.add(normal)) return 'used';
    _answer(
      w,
      TomSecretsApprovalAnswer(
        decision: match.decision,
        secret: 'ref',
        approver: 'token',
      ),
    );
    return 'answered';
  }

  /// The token this device issues for [code] shown on [host] (protocol.md
  /// 9.6, `approval.issue`). Throws [StateError] for a host it does not
  /// approve for.
  String issue(String host, String code, String decision) {
    final recorded = service.trust.host(host);
    if (recorded == null) throw StateError('no host $host');
    return tomSecretsCodeToken(
      recorded.tokenKey,
      host,
      tomSecretsNormalizeCode(code),
      decision,
    );
  }

  // ── The approval link ───────────────────────────────────────────────────

  /// Serves [session] (an approver connected over the approval link): sends
  /// it every waiting prompt, takes its answers, grants, revocations, key
  /// changes and new link keys (protocol.md 9.7).
  void addLinkSession(TomSecretsLinkSession session) {
    final peer = _LinkPeer(session);
    _links.add(peer);
    for (final event in waitingEvents) {
      unawaited(session.send(event));
    }
    session.messages.listen(
      (m) => unawaited(_onLinkMessage(peer, m)),
      onDone: () => _links.remove(peer),
    );
    service.log.info('link_connected', {'device': session.peerDevice});
  }

  /// Closes every approval link.
  Future<void> closeLinks() async {
    for (final l in [..._links]) {
      await l.session.close();
    }
    _links.clear();
  }

  Future<void> _onLinkMessage(_LinkPeer peer, Map<String, Object?> m) async {
    final session = peer.session;
    final id = m['id'];
    Future<void> ok() => session.send({'op': 'ok', 'id': id});
    Future<void> fail(String kind, String message, [String? reason]) =>
        session.send({
          'op': 'error',
          'id': id,
          'kind': kind,
          'message': message,
          if (reason != null) 'details': {'reason': reason},
        });
    try {
      switch (m['op']) {
        case 'approve':
          await approve(
            m['approvalId']! as String,
            TomSecretsApprovalAnswer(
              decision: m['decision']! as String,
              secret: m['secret']! as String,
              folder: m['folder'] as String?,
              pin: m['pin'],
              approver: session.peerDevice,
            ),
            // A remote approver's lasting decision comes as its own grant.
            lasting: false,
          );
          await ok();
        case 'grant':
          final grant = (m['grant']! as Map).cast<String, Object?>();
          final key = grant['host'] == service.host
              ? await tomSecretsAcceptedBy(
                  TomSecretsSignedLabels.grant,
                  grant,
                  await service.trust.grantKeys(),
                )
              : null;
          if (key == null) {
            await fail('denied', 'not accepted', 'refused');
            return;
          }
          // A client token comes with its exe-token grant (protocol.md 7.4,
          // DP-20): the approving device made it, the host keeps its hash.
          final token = m['clientToken'];
          final tokenId = _tokenIdOf((grant['subject'] as String?) ?? '');
          if (token != null) {
            if (token is! String || tokenId == null) {
              await fail(
                'malformed',
                'a token needs an exe-token grant',
                'grant',
              );
              return;
            }
            final List<int> bytes;
            try {
              bytes = base64.decode(token);
            } on FormatException {
              await fail('malformed', 'the token is not base64', 'grant');
              return;
            }
            if (bytes.length != 32 ||
                tomSecretsClientTokenId(tomSecretsClientTokenHash(bytes)) !=
                    tokenId) {
              await fail(
                'denied',
                'the grant does not name this token',
                'refused',
              );
              return;
            }
            await _recordToken(token);
          }
          if (!_revoked.contains(grant['id'])) {
            // A pending local copy until the vault copy arrives.
            _pending
              ..removeWhere((p) => p.id == grant['id'])
              ..add(TomSecretsGrant._(grant, key.keyId));
          }
          // With approvalId, the grant answers that waiting request; its
          // client gets the token.
          final waiting = _waiting[m['approvalId']];
          if (waiting != null) {
            _answer(
              waiting,
              TomSecretsApprovalAnswer(
                decision: grant['decision'] == 'never' ? 'never' : 'always',
                secret: 'ref',
                approver: session.peerDevice,
                clientToken: waiting.wantsToken && token is String
                    ? token
                    : null,
              ),
            );
          }
          await ok();
        case 'revoke':
          final revocation = Map<String, Object?>.from(m)
            ..remove('op')
            ..remove('id');
          final key = revocation['host'] == service.host
              ? await tomSecretsAcceptedBy(
                  TomSecretsSignedLabels.revoke,
                  revocation,
                  await service.trust.grantKeys(),
                )
              : null;
          if (key == null) {
            await fail('denied', 'not accepted', 'refused');
            return;
          }
          _applyRevocation(revocation['grantId']! as String);
          await service.writeTrust();
          await ok();
        case 'keychange':
          final statement = (m['statement']! as Map).cast<String, Object?>();
          final recorded = service.trust.approver(
            (statement['device'] as String?) ?? '',
          );
          final newKey = recorded == null
              ? null
              : await tomSecretsAcceptKeyChange(
                  statement,
                  recorded.approverKey,
                );
          if (recorded == null || newKey == null) {
            await fail('denied', 'not accepted', 'refused');
            return;
          }
          recorded
            ..approverKey = newKey
            ..approverKeySince = service.now;
          await service.writeTrust();
          await reload();
          await ok();
        case 'linkKey':
          final recorded = service.trust.approver(session.peerDevice);
          if (recorded == null || m['device'] != session.peerDevice) {
            await fail('denied', 'not this device', 'refused');
            return;
          }
          recorded
            ..previousLinkKey = recorded.linkKey
            ..linkKey = TomSecretsLinkPublicKey(
              base64.decode(m['x25519']! as String),
              base64.decode(m['mlKem768']! as String),
            )
            ..linkKeySince = service.now;
          await service.writeTrust();
          await ok();
        default:
          // Any other message closes the link (protocol.md 9.7).
          await session.close();
      }
    } on StateError catch (e) {
      await fail('not_found', e.message);
    } on Object {
      await fail('malformed', 'the message cannot be read', 'frame');
    }
  }
}

final class _LinkPeer {
  _LinkPeer(this.session);

  final TomSecretsLinkSession session;
}

bool _sameList(List<Object?> a, List<Object?> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
