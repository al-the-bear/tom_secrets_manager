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

import 'approval_link.dart';
import 'signed_objects.dart';

Uint8List _random(int n) {
  final r = Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => r.nextInt(256)));
}

Uint8List _b64(Object? text) => base64.decode(text! as String);

/// An approver device a host recorded at pairing.
final class TomSecretsRecordedApprover {
  /// The approver [device] with its [approverKey], its [linkKey] (null when
  /// it never connects over the link), the [tokenKey] the two share, and a
  /// link key it replaced and is still accepted during the migration period
  /// ([previousLinkKey]).
  TomSecretsRecordedApprover({
    required this.device,
    required this.approverKey,
    required this.tokenKey,
    this.linkKey,
    this.previousLinkKey,
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

  /// The stored JSON.
  Map<String, Object?> toJson() => {
    'device': device,
    'approverKey': approverKey.toJson(),
    'linkKey': ?linkKey?.toJson(),
    'previousLinkKey': ?previousLinkKey?.toJson(),
    'tokenKey': base64.encode(tokenKey),
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
      );
}

/// A host this device approves for (recorded at pairing on the approver).
final class TomSecretsRecordedHost {
  /// The [host] with its [linkKey], the [tokenKey] the two share and the
  /// [address] (`host:port`) its link listens on.
  TomSecretsRecordedHost({
    required this.host,
    required this.linkKey,
    required this.tokenKey,
    this.address,
  });

  /// The host's name.
  final String host;

  /// Its approval-link public key.
  TomSecretsLinkPublicKey linkKey;

  /// The approval-token key (32 bytes).
  final Uint8List tokenKey;

  /// Where its link listens (`address:port`), when known.
  final String? address;

  /// The stored JSON.
  Map<String, Object?> toJson() => {
    'host': host,
    'linkKey': linkKey.toJson(),
    'tokenKey': base64.encode(tokenKey),
    'address': ?address,
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
      );
}

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
  }) : _approverSeeds = approverSeeds,
       _linkSeeds = linkSeeds;

  /// New trust material for [device]: fresh key pairs and audit-log key, no
  /// approver or host recorded, command-line approvals off.
  factory TomSecretsTrust.create(String device) => TomSecretsTrust._(
    device: device,
    approverSeeds: _random(64),
    linkSeeds: _random(96),
    auditKey: _random(32),
    approvers: [],
    hosts: [],
    cliApprovals: false,
  );

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
      );

  /// This device's id (its approver identity at pairing).
  final String device;

  /// Ed25519 seed (32) || ML-DSA-65 seed (32).
  final Uint8List _approverSeeds;

  /// X25519 seed (32) || ML-KEM-768 seed (64).
  final Uint8List _linkSeeds;

  /// The audit-log key (32 bytes, XChaCha20-Poly1305).
  final Uint8List auditKey;

  /// The approvers this host recorded at pairing.
  final List<TomSecretsRecordedApprover> approvers;

  /// The hosts this device approves for.
  final List<TomSecretsRecordedHost> hosts;

  /// Whether `tsm` on this device may pre-approve and issue tokens (DP-19);
  /// switched only from the manager app.
  bool cliApprovals;

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
  };

  @override
  String toString() => 'TomSecretsTrust($device, ***)';
}
