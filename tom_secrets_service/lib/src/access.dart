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
  });

  /// The reference as sent.
  final String reference;

  /// What it resolved to.
  final TomSecretsResolution resolution;

  /// The client's `hello.client` (`name`, `version`, `language`).
  final Map<String, Object?> client;

  /// The client as the service measured it (part-protocol, protocol.md
  /// 7.1): what grants match and audits record.
  final TomSecretsIdentity identity;
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
}

/// A policy's answer.
sealed class TomSecretsAccess {
  const TomSecretsAccess();
}

/// The value may be sent; [grantId] or [approver] say why.
final class TomSecretsAccessAllowed extends TomSecretsAccess {
  /// Allowed.
  const TomSecretsAccessAllowed({this.grantId, this.approver});

  /// The grant that allowed it.
  final String? grantId;

  /// The approver that allowed it at a prompt.
  final String? approver;
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
