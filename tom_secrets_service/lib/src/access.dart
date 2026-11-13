// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Who may read a resolved secret (protocol.md 5.6 step 5): the allow list
/// and the approval flow decide (part-protocol). Until a policy that knows
/// grants is configured, the service refuses every value.
library;

import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'identity.dart';

/// A client's request for one resolved secret.
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

/// A policy's answer.
sealed class TomSecretsAccess {
  const TomSecretsAccess();
}

/// The value may be sent.
final class TomSecretsAccessAllowed extends TomSecretsAccess {
  /// Allowed.
  const TomSecretsAccessAllowed();
}

/// The value may not be sent, for [reason] (protocol.md 10, `denied`).
final class TomSecretsAccessDenied extends TomSecretsAccess {
  /// Denied for [reason].
  const TomSecretsAccessDenied(this.reason);

  /// `never`, `refused`, `no_approver`, `unidentifiable`, ...
  final String reason;
}

/// Decides whether a client may read a resolved secret.
abstract interface class TomSecretsAccessPolicy {
  /// The decision for [request].
  Future<TomSecretsAccess> check(TomSecretsAccessRequest request);
}

/// Refuses every value (`denied`, reason `no_approver`): the policy of a
/// service with no allow list and no approver.
final class TomSecretsDenyAllPolicy implements TomSecretsAccessPolicy {
  /// The policy.
  const TomSecretsDenyAllPolicy();

  @override
  Future<TomSecretsAccess> check(TomSecretsAccessRequest request) async =>
      const TomSecretsAccessDenied('no_approver');
}
