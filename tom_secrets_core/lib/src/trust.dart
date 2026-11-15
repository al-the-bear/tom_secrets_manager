// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A device's trust material (part-protocol, part-service, DP-160, TD-3),
/// kept in its device settings container, never synced: its own approver
/// and approval-link key pairs, its audit-log key, the approvers it recorded
/// at pairing (their approver and link public keys, the approval-token key
/// shared with each), the hosts it approves for, and whether command-line
/// approvals are switched on.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'approval_link.dart';
import 'signed_objects.dart';

Uint8List _random(int n) {
  final r = Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => r.nextInt(256)));
}

Uint8List _b64(Object? text) => base64.decode(text! as String);

DateTime? _time(Object? text) =>
    text is String ? DateTime.tryParse(text)?.toUtc() : null;

String? _iso(DateTime? time) => time?.toUtc().toIso8601String();

/// An approver device a host recorded at pairing.
final class TomSecretsRecordedApprover {
  /// The approver [device] with its [approverKey], its [linkKey] (null when
  /// it never connects over the link), the [tokenKey] the two share, a link
  /// key it replaced and is still accepted during the migration period
  /// ([previousLinkKey]), and since when each key is recorded
  /// ([approverKeySince], [linkKeySince]).
  TomSecretsRecordedApprover({
    required this.device,
    required this.approverKey,
    required this.tokenKey,
    this.linkKey,
    this.previousLinkKey,
    this.approverKeySince,
    this.linkKeySince,
  });

  /// The approver's device id.
  final String device;

  /// Its approver public key.
  TomSecretsApproverPublicKey approverKey;

  /// Its approval-link public key.
  TomSecretsLinkPublicKey? linkKey;

  /// The link key it replaced, accepted for the migration period.
  TomSecretsLinkPublicKey? previousLinkKey;

  /// The approval-token key (32 bytes).
  final Uint8List tokenKey;

  /// When [approverKey] was recorded (at pairing, or its key change): the
  /// start of its rotation age.
  DateTime? approverKeySince;

  /// When [linkKey] was recorded (at pairing, or a new link key).
  DateTime? linkKeySince;

  /// The stored JSON.
  Map<String, Object?> toJson() => {
    'device': device,
    'approverKey': approverKey.toJson(),
    'linkKey': ?linkKey?.toJson(),
    'previousLinkKey': ?previousLinkKey?.toJson(),
    'tokenKey': base64.encode(tokenKey),
    'approverKeySince': ?_iso(approverKeySince),
    'linkKeySince': ?_iso(linkKeySince),
  };

  /// From [toJson].
  factory TomSecretsRecordedApprover.fromJson(Map<String, Object?> json) =>
      TomSecretsRecordedApprover(
        device: json['device']! as String,
        approverKey: TomSecretsApproverPublicKey.fromJson(
          (json['approverKey']! as Map).cast(),
        ),
        linkKey: json['linkKey'] is Map
            ? TomSecretsLinkPublicKey.fromJson((json['linkKey']! as Map).cast())
            : null,
        previousLinkKey: json['previousLinkKey'] is Map
            ? TomSecretsLinkPublicKey.fromJson(
                (json['previousLinkKey']! as Map).cast(),
              )
            : null,
        tokenKey: _b64(json['tokenKey']),
        approverKeySince: _time(json['approverKeySince']),
        linkKeySince: _time(json['linkKeySince']),
      );
}

/// A host this device approves for (recorded at pairing on the approver).
final class TomSecretsRecordedHost {
  /// The [host] with its [linkKey], the [tokenKey] the two share, the
  /// [address] (`host:port`) its link listens on, and since when the link
  /// key is recorded ([linkKeySince]).
  TomSecretsRecordedHost({
    required this.host,
    required this.linkKey,
    required this.tokenKey,
    this.address,
    this.linkKeySince,
    this.linkKeyDelivered = true,
  });

  /// The host's name.
  final String host;

  /// Its approval-link public key.
  TomSecretsLinkPublicKey linkKey;

  /// The approval-token key (32 bytes).
  final Uint8List tokenKey;

  /// Where its link listens (`address:port`), when known.
  final String? address;

  /// When [linkKey] was recorded (at pairing, or a new link key).
  DateTime? linkKeySince;

  /// Whether this device's current approval-link key reached the host
  /// (`linkKey` over the link, part-key-rotation): until then this device
  /// connects to it with its previous link key, during the migration period.
  bool linkKeyDelivered;

  /// The stored JSON.
  Map<String, Object?> toJson() => {
    'host': host,
    'linkKey': linkKey.toJson(),
    'tokenKey': base64.encode(tokenKey),
    'address': ?address,
    'linkKeySince': ?_iso(linkKeySince),
    if (!linkKeyDelivered) 'linkKeyDelivered': false,
  };

  /// From [toJson].
  factory TomSecretsRecordedHost.fromJson(Map<String, Object?> json) =>
      TomSecretsRecordedHost(
        host: json['host']! as String,
        linkKey: TomSecretsLinkPublicKey.fromJson(
          (json['linkKey']! as Map).cast(),
        ),
        tokenKey: _b64(json['tokenKey']),
        address: json['address'] as String?,
        linkKeySince: _time(json['linkKeySince']),
        linkKeyDelivered: json['linkKeyDelivered'] != false,
      );
}

/// How long a device's previous approval-link key stays in use for the
/// hosts its new key has not reached yet (part-key-rotation).
const Duration tomSecretsLinkKeyMigration = Duration(days: 14);

/// A device's trust material.
final class TomSecretsTrust {
  TomSecretsTrust._({
    required this.device,
    required Uint8List approverSeeds,
    required Uint8List linkSeeds,
    required this.auditKey,
    required this.approvers,
    required this.hosts,
    required this.cliApprovals,
    this.approverKeySince,
    this.linkKeySince,
    Uint8List? previousLinkSeeds,
    this.previousLinkUntil,
    Map<String, String>? pins,
    Map<String, TomSecretsClientTokenRecord>? clientTokens,
  }) : pins = pins ?? {},
       clientTokens = clientTokens ?? {},
       _approverSeeds = approverSeeds,
       _linkSeeds = linkSeeds,
       _previousLinkSeeds = previousLinkSeeds;

  /// New trust material for [device]: fresh key pairs (created [now],
  /// default the current time) and audit-log key, no approver or host
  /// recorded, command-line approvals off.
  factory TomSecretsTrust.create(String device, {DateTime? now}) {
    final created = (now ?? DateTime.now()).toUtc();
    return TomSecretsTrust._(
      device: device,
      approverSeeds: _random(64),
      linkSeeds: _random(96),
      auditKey: _random(32),
      approvers: [],
      hosts: [],
      cliApprovals: false,
      approverKeySince: created,
      linkKeySince: created,
    );
  }

  /// From the stored JSON.
  factory TomSecretsTrust.fromJson(Map<String, Object?> json) =>
      TomSecretsTrust._(
        device: json['device']! as String,
        approverSeeds: _b64(json['approverSeeds']),
        linkSeeds: _b64(json['linkSeeds']),
        auditKey: _b64(json['auditKey']),
        approvers: [
          for (final a in (json['approvers'] as List?) ?? const [])
            TomSecretsRecordedApprover.fromJson((a as Map).cast()),
        ],
        hosts: [
          for (final h in (json['hosts'] as List?) ?? const [])
            TomSecretsRecordedHost.fromJson((h as Map).cast()),
        ],
        cliApprovals: json['cliApprovals'] == true,
        approverKeySince: _time(json['approverKeySince']),
        linkKeySince: _time(json['linkKeySince']),
        previousLinkSeeds: json['previousLinkSeeds'] == null
            ? null
            : _b64(json['previousLinkSeeds']),
        previousLinkUntil: _time(json['previousLinkUntil']),
        pins: ((json['pins'] as Map?) ?? const {}).cast<String, String>(),
        clientTokens: {
          for (final MapEntry(:key, :value)
              in ((json['clientTokens'] as Map?) ?? const {}).entries)
            key as String: TomSecretsClientTokenRecord.fromJson(
              (value as Map).cast(),
            ),
        },
      );

  /// This device's id (its approver identity at pairing).
  final String device;

  /// Ed25519 seed (32) || ML-DSA-65 seed (32).
  Uint8List _approverSeeds;

  /// X25519 seed (32) || ML-KEM-768 seed (64).
  Uint8List _linkSeeds;

  /// The previous link key's seeds after a rotation, while a recorded host
  /// has not received the new key and the migration period lasts.
  Uint8List? _previousLinkSeeds;

  /// Until when the previous link key is used ([rotateLinkKey]).
  DateTime? previousLinkUntil;

  /// The audit-log key (32 bytes, XChaCha20-Poly1305).
  final Uint8List auditKey;

  /// The approvers this host recorded at pairing.
  final List<TomSecretsRecordedApprover> approvers;

  /// The hosts this device approves for.
  final List<TomSecretsRecordedHost> hosts;

  /// Records what a pairing with the peer [device] gave (part-sharing): it
  /// approves for this host with [approverKey] (reached over the approval
  /// link with [approverLinkKey]), and this device approves for it as a
  /// host with [hostLinkKey] at [hostAddress]; [tokenKey] is the
  /// approval-token key both sides derived. Every key is dated [at]; what
  /// was recorded of [device] before is replaced. Throws [ArgumentError]
  /// for this device itself.
  void recordPeer({
    required String device,
    required Uint8List tokenKey,
    required DateTime at,
    TomSecretsApproverPublicKey? approverKey,
    TomSecretsLinkPublicKey? approverLinkKey,
    TomSecretsLinkPublicKey? hostLinkKey,
    String? hostAddress,
  }) {
    if (device == this.device) {
      throw ArgumentError.value(device, 'device', 'this device itself');
    }
    final when = at.toUtc();
    approvers.removeWhere((a) => a.device == device);
    hosts.removeWhere((h) => h.host == device);
    if (approverKey != null) {
      approvers.add(
        TomSecretsRecordedApprover(
          device: device,
          approverKey: approverKey,
          linkKey: approverLinkKey,
          tokenKey: tokenKey,
          approverKeySince: when,
          linkKeySince: approverLinkKey == null ? null : when,
        ),
      );
    }
    if (hostLinkKey != null) {
      hosts.add(
        TomSecretsRecordedHost(
          host: device,
          linkKey: hostLinkKey,
          tokenKey: tokenKey,
          address: hostAddress,
          linkKeySince: when,
        ),
      );
    }
  }

  /// Whether `tsm` on this device may pre-approve and issue tokens (DP-19);
  /// switched only from the manager app.
  bool cliApprovals;

  /// When this device's approver key pair was created: the start of its
  /// rotation age (part-key-rotation); null in trust material written
  /// before the date was kept ([stampKeyDates]).
  DateTime? approverKeySince;

  /// When this device's approval-link key pair was created.
  DateTime? linkKeySince;

  /// Gives every key without a recorded date the date [now]: trust material
  /// written before the dates were kept counts its keys' age from then.
  /// Whether anything changed (the caller writes the trust back).
  bool stampKeyDates(DateTime now) {
    final at = now.toUtc();
    var changed = false;
    DateTime stamp(DateTime? since) {
      if (since != null) return since;
      changed = true;
      return at;
    }

    approverKeySince = stamp(approverKeySince);
    linkKeySince = stamp(linkKeySince);
    for (final a in approvers) {
      a.approverKeySince = stamp(a.approverKeySince);
      if (a.linkKey != null) a.linkKeySince = stamp(a.linkKeySince);
    }
    for (final h in hosts) {
      h.linkKeySince = stamp(h.linkKeySince);
    }
    return changed;
  }

  /// The SHA-256 recorded for each pinned grant of this host (grant id →
  /// hex): a grant's signed members carry no hash, and the host keeps it
  /// here, out of the synced vault, so no one who can write the vault can
  /// move a pin (DP-18).
  final Map<String, String> pins;

  /// The client tokens of this host's `exe-token` grants (token id →
  /// record): only the token's hash, never the token (DP-20).
  final Map<String, TomSecretsClientTokenRecord> clientTokens;

  /// The token id whose hash is [hash] (hex), or null.
  String? clientTokenIdOf(String hash) {
    for (final MapEntry(:key, :value) in clientTokens.entries) {
      if (value.hash == hash) return key;
    }
    return null;
  }

  /// This device's approver key pair.
  Future<TomSecretsApproverKey> approverKey() =>
      TomSecretsApproverKey.fromSeeds(
        _approverSeeds.sublist(0, 32),
        _approverSeeds.sublist(32),
      );

  /// This device's approval-link key pair.
  Future<TomSecretsLinkKey> linkKey() => TomSecretsLinkKey.fromSeeds(
    _linkSeeds.sublist(0, 32),
    _linkSeeds.sublist(32),
  );

  /// Rotates this device's approver key pair (part-key-rotation): a new
  /// hybrid pair (Ed25519 + ML-DSA-65) replaces it from [now] on, and the
  /// key-change statement (9.4, `tsm-keychange-v1`) is answered, signed by
  /// the old and the new pair with both algorithms (four signatures). A host
  /// that recorded the old key accepts the new one from it
  /// (`tomSecretsAcceptKeyChange`). The caller writes the trust back, and
  /// re-signs what the old key signed.
  Future<Map<String, Object?>> rotateApproverKey({DateTime? now}) async {
    final at = (now ?? DateTime.now()).toUtc();
    final old = await approverKey();
    final seeds = _random(64);
    final fresh = await TomSecretsApproverKey.fromSeeds(
      seeds.sublist(0, 32),
      seeds.sublist(32),
    );
    final statement = {
      'device': device,
      'oldKeyId': old.keyId,
      'newKeyId': fresh.keyId,
      'newEd25519': base64.encode(fresh.publicKey.ed25519),
      'newMlDsa65': base64.encode(fresh.publicKey.mlDsa65),
      'time': at.toIso8601String(),
    };
    final bytes = tomSecretsSignedBytes(
      TomSecretsSignedLabels.keyChange,
      statement,
    );
    final signatures = [
      ...await old.sign(TomSecretsSignedLabels.keyChange, bytes),
      ...await fresh.sign(TomSecretsSignedLabels.keyChange, bytes),
    ];
    _approverSeeds.fillRange(0, _approverSeeds.length, 0);
    _approverSeeds = seeds;
    approverKeySince = at;
    return {...statement, 'signatures': signatures};
  }

  /// Rotates this device's approval-link key pair (part-key-rotation): a
  /// new pair from [now] on; the previous one stays in use for every
  /// recorded host until the new key reached it ([markLinkKeyDelivered]) or
  /// [migration] is over. A pending earlier rotation's previous key is
  /// dropped (the hosts that did not get that one keep the oldest key and
  /// are paired again). The caller writes the trust back.
  void rotateLinkKey({
    DateTime? now,
    Duration migration = tomSecretsLinkKeyMigration,
  }) {
    final at = (now ?? DateTime.now()).toUtc();
    _previousLinkSeeds?.fillRange(0, _previousLinkSeeds!.length, 0);
    _previousLinkSeeds = _linkSeeds;
    _linkSeeds = _random(96);
    linkKeySince = at;
    previousLinkUntil = at.add(migration);
    for (final h in hosts) {
      h.linkKeyDelivered = false;
    }
  }

  /// The hosts the current link key has not reached yet while the previous
  /// one is in use.
  List<TomSecretsRecordedHost> get linkKeyPending => [
    if (_previousLinkSeeds != null)
      for (final h in hosts)
        if (!h.linkKeyDelivered) h,
  ];

  /// The link key pair this device connects to [host] with at [now]: the
  /// current one, or the previous one while the new one has not reached
  /// that host and the migration period lasts.
  Future<TomSecretsLinkKey> linkKeyFor(String host, {DateTime? now}) {
    final recorded = this.host(host);
    final previous = _previousLinkSeeds;
    final until = previousLinkUntil;
    final at = (now ?? DateTime.now()).toUtc();
    if (recorded != null &&
        !recorded.linkKeyDelivered &&
        previous != null &&
        until != null &&
        at.isBefore(until)) {
      return TomSecretsLinkKey.fromSeeds(
        previous.sublist(0, 32),
        previous.sublist(32),
      );
    }
    return linkKey();
  }

  /// The previous link key pair while the migration period lasts at [now]
  /// (an approver that still holds it is answered under it), else null.
  Future<TomSecretsLinkKey?> previousLinkKey({DateTime? now}) async {
    final previous = _previousLinkSeeds;
    final until = previousLinkUntil;
    if (previous == null ||
        until == null ||
        !(now ?? DateTime.now()).toUtc().isBefore(until)) {
      return null;
    }
    return TomSecretsLinkKey.fromSeeds(
      previous.sublist(0, 32),
      previous.sublist(32),
    );
  }

  /// Records that the current link key reached [host]; once every host has
  /// it, and no approver connects to this device, the previous key is
  /// dropped.
  void markLinkKeyDelivered(String host) {
    this.host(host)?.linkKeyDelivered = true;
    _dropPreviousWhenDone();
  }

  /// Drops the previous link key when every host has the new one or the
  /// migration period is over at [now]; whether it dropped it.
  bool expirePreviousLinkKey(DateTime now) {
    final until = previousLinkUntil;
    if (_previousLinkSeeds == null) return false;
    if (until != null && !now.toUtc().isBefore(until)) {
      _clearPrevious();
      return true;
    }
    return _dropPreviousWhenDone();
  }

  bool _dropPreviousWhenDone() {
    // The approvers that connect to this device hold its link key too: with
    // any recorded, the previous key stays to the end of the period.
    if (_previousLinkSeeds == null ||
        approvers.isNotEmpty ||
        hosts.any((h) => !h.linkKeyDelivered)) {
      return false;
    }
    _clearPrevious();
    return true;
  }

  void _clearPrevious() {
    _previousLinkSeeds?.fillRange(0, _previousLinkSeeds!.length, 0);
    _previousLinkSeeds = null;
    previousLinkUntil = null;
    for (final h in hosts) {
      h.linkKeyDelivered = true;
    }
  }

  /// The approver keys a grant on this host may be signed by: every
  /// recorded approver's, and this device's own (the attached app approves
  /// through this service, which signs).
  Future<List<TomSecretsApproverPublicKey>> grantKeys() async => [
    (await approverKey()).publicKey,
    for (final a in approvers) a.approverKey,
  ];

  /// The recorded approver of [device], or null.
  TomSecretsRecordedApprover? approver(String device) =>
      approvers.where((a) => a.device == device).firstOrNull;

  /// The recorded host [host], or null.
  TomSecretsRecordedHost? host(String host) =>
      hosts.where((h) => h.host == host).firstOrNull;

  /// The stored JSON.
  Map<String, Object?> toJson() => {
    'device': device,
    'approverSeeds': base64.encode(_approverSeeds),
    'linkSeeds': base64.encode(_linkSeeds),
    'auditKey': base64.encode(auditKey),
    'approvers': [for (final a in approvers) a.toJson()],
    'hosts': [for (final h in hosts) h.toJson()],
    'cliApprovals': cliApprovals,
    'approverKeySince': ?_iso(approverKeySince),
    'linkKeySince': ?_iso(linkKeySince),
    'previousLinkSeeds': ?(_previousLinkSeeds == null
        ? null
        : base64.encode(_previousLinkSeeds!)),
    'previousLinkUntil': ?_iso(previousLinkUntil),
    'pins': pins,
    'clientTokens': {
      for (final e in clientTokens.entries) e.key: e.value.toJson(),
    },
  };

  @override
  String toString() => 'TomSecretsTrust($device, ***)';
}

/// A client token's id (protocol.md 7.4): the first 16 bytes, in lower-case
/// hex, of its [hash]; the approving device derives it from the token, and
/// the host checks the grant's `exe-token <path> <tokenId>` against the token
/// it is sent.
String tomSecretsClientTokenId(String hash) => hash.substring(0, 32);

/// A client token's hash: SHA-256(lps("tsm-client-token-v1") || token), hex.
String tomSecretsClientTokenHash(List<int> token) {
  const label = 'tsm-client-token-v1';
  final out = BytesBuilder()
    ..add((ByteData(4)..setUint32(0, label.length)).buffer.asUint8List())
    ..add(utf8.encode(label))
    ..add(token);
  return crypto.sha256.convert(out.toBytes()).toString();
}

/// What a host keeps of a client token: its [hash], when it was [created],
/// and the identity of the client that first and last brought it in
/// `hello.clientToken` (so access can later be narrowed to it).
final class TomSecretsClientTokenRecord {
  /// A record of [hash].
  TomSecretsClientTokenRecord({
    required this.hash,
    required this.created,
    this.firstIdentity,
    this.lastIdentity,
    this.lastSeen,
  });

  /// From the stored JSON.
  factory TomSecretsClientTokenRecord.fromJson(Map<String, Object?> json) =>
      TomSecretsClientTokenRecord(
        hash: json['hash']! as String,
        created: DateTime.parse(json['created']! as String),
        firstIdentity: (json['firstIdentity'] as Map?)?.cast(),
        lastIdentity: (json['lastIdentity'] as Map?)?.cast(),
        lastSeen: json['lastSeen'] == null
            ? null
            : DateTime.parse(json['lastSeen']! as String),
      );

  /// The token's hash (hex).
  final String hash;

  /// When the host received it.
  final DateTime created;

  /// The measured identity of the first client that brought it.
  Map<String, Object?>? firstIdentity;

  /// The measured identity of the last client that brought it.
  Map<String, Object?>? lastIdentity;

  /// When a client last brought it.
  DateTime? lastSeen;

  /// The stored JSON.
  Map<String, Object?> toJson() => {
    'hash': hash,
    'created': created.toUtc().toIso8601String(),
    'firstIdentity': ?firstIdentity,
    'lastIdentity': ?lastIdentity,
    'lastSeen': ?lastSeen?.toUtc().toIso8601String(),
  };
}
