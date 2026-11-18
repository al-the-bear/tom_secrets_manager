// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Who may read a resolved secret (protocol.md 5.6 step 5): the allow list
/// and the approval flow decide (part-protocol). Until a policy that knows
/// grants is configured, the service refuses every value.
library;

import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'identity.dart';

/// One resolved secret of a client's request.
final class TomSecretsAccessRequest {
  /// [reference] resolved to [resolution] for the client measured as
  /// [identity] (its `hello.client` [client] is shown, never trusted).
  const TomSecretsAccessRequest({
    required this.reference,
    required this.resolution,
    required this.client,
    required this.identity,
    this.wantClientToken = false,
  });

  /// The reference as sent.
  final String reference;

  /// What it resolved to.
  final TomSecretsResolution resolution;

  /// Whether the client asked for a client token (`wantClientToken`).
  final bool wantClientToken;

  /// The client's `hello.client` (`name`, `version`, `language`).
  final Map<String, Object?> client;

  /// The client as the service measured it (part-protocol, protocol.md
  /// 7.1): what grants match and audits record.
  final TomSecretsIdentity identity;
}

/// What an ssh-agent request is about (part-os-integration): shown in the
/// prompt, matched against an agent grant's hosts and forwarding, and
/// audited.
final class TomSecretsSshUse {
  /// A use of the key [keyFingerprint].
  const TomSecretsSshUse({
    required this.keyFingerprint,
    required this.keyType,
    required this.forwarded,
    required this.purpose,
    this.title,
    this.hostKeyFingerprint,
    this.hostNames = const [],
    this.namespace,
    this.confirm = false,
    this.listing = false,
  });

  /// The key's fingerprint (`SHA256:...`).
  final String keyFingerprint;

  /// The key's type (`ssh-ed25519`, ...).
  final String keyType;

  /// The entry's title.
  final String? title;

  /// The destination's host key fingerprint (the connection's last
  /// `session-bind`), or null on an unbound connection.
  final String? hostKeyFingerprint;

  /// The destination's names from `known_hosts`, when it lists them.
  final List<String> hostNames;

  /// Whether the request came over a forwarded agent connection.
  final bool forwarded;

  /// `userauth`, `sshsig` or `other`.
  final String purpose;

  /// The `SSHSIG` namespace (`git`, `file`, ...).
  final String? namespace;

  /// Whether every signature with the key is confirmed (KeeAgent's flag, or
  /// the vault's `tsm.ssh-confirm`).
  final bool confirm;

  /// Whether this only decides whether the key is listed
  /// (`REQUEST_IDENTITIES`): matched against the grants, never prompted or
  /// audited.
  final bool listing;

  /// As `approval_needed` and the audit record carry it.
  Map<String, Object?> toJson() => {
    'key': keyFingerprint,
    'keyType': keyType,
    'title': ?title,
    'host': ?hostKeyFingerprint,
    if (hostNames.isNotEmpty) 'hostNames': hostNames,
    'forwarded': forwarded,
    'purpose': purpose,
    'namespace': ?namespace,
  };
}

/// A client request's resolved items, decided together: one prompt for a
/// whole `getMany` (protocol.md 7.2, `once` answers the whole batch).
final class TomSecretsAccessBatch {
  /// The [items] of one request of the client measured as [identity].
  TomSecretsAccessBatch({
    required this.identity,
    required this.client,
    required this.items,
    this.onProgress,
    this.timeout,
    this.clientTokenHash,
    this.ssh,
  });

  /// The client as measured.
  final TomSecretsIdentity identity;

  /// Its `hello.client`.
  final Map<String, Object?> client;

  /// The resolved items, in request order.
  final List<TomSecretsAccessRequest> items;

  /// Sends the client a `progress` notice (`pending`, `approvalCode?`).
  final void Function(Map<String, Object?> progress)? onProgress;

  /// The request's own `timeoutMs`, which caps the approval timeout.
  final Duration? timeout;

  /// The hash of the client token the connection's `hello` carried
  /// (protocol.md 7.4), or null.
  final String? clientTokenHash;

  /// An ssh-agent request's use of its key (one item), or null for a value
  /// request. Only agent grants (`ssh-key ...`) decide it.
  final TomSecretsSshUse? ssh;
}

/// A policy's answer.
sealed class TomSecretsAccess {
  const TomSecretsAccess();
}

/// The value may be sent; [grantId] or [approver] say why.
final class TomSecretsAccessAllowed extends TomSecretsAccess {
  /// Allowed.
  const TomSecretsAccessAllowed({
    this.grantId,
    this.approver,
    this.clientToken,
  });

  /// The grant that allowed it.
  final String? grantId;

  /// The approver that allowed it at a prompt.
  final String? approver;

  /// The client token the approver issued for this client (base64), sent in
  /// the `value` (protocol.md 7.4).
  final String? clientToken;
}

/// The value may not be sent: an `error` of [kind] (protocol.md 10, default
/// `denied`) with `details.reason` [reason] and further [details].
final class TomSecretsAccessDenied extends TomSecretsAccess {
  /// Denied for [reason].
  const TomSecretsAccessDenied(
    this.reason, {
    this.kind = 'denied',
    this.details = const {},
    this.grantId,
  });

  /// `never`, `refused`, `no_approver`, `unidentifiable`, ...
  final String reason;

  /// The error kind: `denied`, `timeout`, `rate_limited`.
  final String kind;

  /// Further details (`retryAfterMs` for `rate_limited`).
  final Map<String, Object?> details;

  /// The `never` grant that refused it.
  final String? grantId;
}

/// Decides whether a client may read its resolved secrets.
abstract interface class TomSecretsAccessPolicy {
  /// The decision for each item of [batch], in its order.
  Future<List<TomSecretsAccess>> check(TomSecretsAccessBatch batch);
}

/// What a client's grants cover without a prompt (protocol.md 5.5): `match`
/// lists only the entries an `allow` grant covers, and `propose` needs the
/// client to hold an `allow` grant at all.
final class TomSecretsCoverage {
  /// Coverage deciding each entry with [covers]; [hasAllowGrant] when some
  /// `allow` grant names the client.
  const TomSecretsCoverage({
    required this.covers,
    required this.hasAllowGrant,
    bool Function(String store, String uuid)? named,
  }) : _named = named;

  /// Nothing covered, no grant.
  static final TomSecretsCoverage none = TomSecretsCoverage(
    covers: (_, _) => false,
    hasAllowGrant: false,
  );

  /// Whether an `allow` grant decides the entry [uuid] (hex) of [store].
  final bool Function(String store, String uuid) covers;

  final bool Function(String store, String uuid)? _named;

  /// Whether the `allow` grant that decides the entry names it by its
  /// reference (a remembered pick, protocol.md 5.5), not by its store or
  /// `all`.
  bool named(String store, String uuid) => _named?.call(store, uuid) ?? false;

  /// Whether some `allow` grant names the client.
  final bool hasAllowGrant;
}

/// A policy that can say what a client's grants cover without asking
/// (protocol.md 5.5 `match`, `propose`). A policy that is not one covers
/// nothing.
abstract interface class TomSecretsLookupPolicy {
  /// The coverage of the client measured as [identity] whose `hello` brought
  /// the client token of [clientTokenHash]; [entryOf] resolves a grant's
  /// reference to the entry it names (store and UUID hex), or null.
  Future<TomSecretsCoverage> coverage(
    TomSecretsIdentity identity, {
    String? clientTokenHash,
    required ({String store, String uuid})? Function(String reference) entryOf,
  });
}

/// Refuses every value (`denied`, reason `no_approver`): the policy of a
/// service with no allow list and no approver.
final class TomSecretsDenyAllPolicy implements TomSecretsAccessPolicy {
  /// The policy.
  const TomSecretsDenyAllPolicy();

  @override
  Future<List<TomSecretsAccess>> check(TomSecretsAccessBatch batch) async => [
    for (final _ in batch.items) const TomSecretsAccessDenied('no_approver'),
  ];
}
