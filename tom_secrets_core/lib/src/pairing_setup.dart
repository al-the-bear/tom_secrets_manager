// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The receiving side of a pairing on a machine being set up (part-sharing,
/// 1. Pairing): a new desktop's First run and `tsm pair` on a headless
/// machine (through the service's pairing mode). The machine makes fresh
/// trust material for the pairing, checks that it can be set up from the
/// bundle (the primary is in it, a `github:` primary with its token) and
/// refuses it otherwise, and keeps everything in memory: nothing is stored
/// until `TomSecretsFirstRun.runPaired` sets the machine up with the master
/// password.
library;

import 'dart:io';

import 'package:tom_secrets_client/admin.dart'
    show tomSecretsApprovalLinkProblem;

import 'locator.dart';
import 'pairing.dart';
import 'relay.dart';
import 'relay_link.dart';
import 'trust.dart';

/// A pairing received by a machine being set up, held in memory until the
/// setup: the bundle, the approval-token key, and this machine's fresh
/// trust material (whose public keys the giving side recorded).
final class TomSecretsPairingReceipt {
  TomSecretsPairingReceipt._(
    this.received,
    this.trust, [
    this.ownTokens = const {},
    this.ownKeys,
  ]);

  /// **[C]** The public keys this machine answered with (its relay link
  /// among them), or null.
  final TomSecretsPairingPeerKeys? ownKeys;

  /// **[C]** The relay link the two sides agreed on
  /// (`tomSecretsPairingLink`), or null.
  ({String relay, String linkId})? get link => ownKeys == null
      ? null
      : tomSecretsPairingLink(bundle.giverKeys, ownKeys!);

  /// The GitHub tokens this machine brought itself, by `owner/name` (a
  /// pairing through GitHub needs one before it starts, part-relay).
  final Map<String, String> ownTokens;

  /// What the pairing gave.
  final TomSecretsPairingReceived received;

  /// This machine's trust material, made for the pairing.
  final TomSecretsTrust trust;

  /// The giving device's name.
  String get giver => received.giver;

  /// The bundle.
  TomSecretsPairingBundle get bundle => received.bundle;

  /// The primary vault of the bundle.
  TomSecretsPairingVault get primary =>
      bundle.vaults.firstWhere((v) => v.primary);

  /// The token pasted for [repository] (`owner/name`), else the one this
  /// machine brought itself ([ownTokens]), or null.
  TomSecretsPairingToken? tokenFor(String repository) =>
      bundle.tokens.where((t) => t.repository == repository).firstOrNull ??
      switch (ownTokens[repository]) {
        final token? => TomSecretsPairingToken(
          repository: repository,
          token: token,
        ),
        null => null,
      };
}

/// Why a bundle cannot set a machine up, or null when it can: the primary
/// must be in it, with its token when it is in a GitHub repository (in the
/// bundle, or one this machine holds itself for one of [ownTokens]).
String? tomSecretsPairingSetupProblem(
  TomSecretsPairingBundle bundle, {
  Set<String> ownTokens = const {},
}) {
  final primary = bundle.vaults.where((v) => v.primary).firstOrNull;
  if (primary == null) {
    return 'a new machine is set up from the primary vault, and the bundle '
        'does not carry it: pair again with the primary ticked';
  }
  final TomSecretsVaultLocator locator;
  try {
    locator = TomSecretsVaultLocator.parse(primary.locator);
  } on TomSecretsLocatorException catch (e) {
    return 'the primary\'s location cannot be read: ${e.message}';
  }
  if (locator case TomSecretsGitHubLocator(:final repositorySlug)
      when !bundle.tokens.any((t) => t.repository == repositorySlug) &&
          !ownTokens.contains(repositorySlug)) {
    return 'the primary is in $repositorySlug, and the bundle '
        'carries no GitHub token for this machine: paste one when pairing '
        'again';
  }
  return null;
}

/// Receives a pairing for a machine being set up as [device]: connects to
/// the giving machine's window at [address]:[port] with [code] — or, with
/// [relay], joins the pairing hosted there under the code's number
/// (part-relay; [ownTokens] are the GitHub tokens this machine holds itself,
/// by `owner/name`, which a pairing through GitHub needs) — answers with
/// the public keys of fresh trust material (made [now]) and [linkAddress],
/// the address this machine's approval link will listen on (the device
/// setting `approvalLink`), so the giving machine records it and opens the
/// link; **[C]** [linkRelay], a relay server (`tsm:<url>`) the approval
/// link may also go through, goes with a fresh link id (used when the
/// giving side names none, `tomSecretsPairingLink`); refuses a bundle it
/// cannot be set up from
/// ([tomSecretsPairingSetupProblem]). Stores nothing. Throws
/// [TomSecretsPairingException], and [ArgumentError] for a [linkAddress]
/// that is no approval link (`tomSecretsApprovalLinkProblem`).
Future<TomSecretsPairingReceipt> tomSecretsReceivePairingForSetup({
  String? address,
  int? port,
  TomSecretsRelay? relay,
  Map<String, String> ownTokens = const {},
  required TomSecretsPairingCode code,
  required String device,
  String? linkAddress,
  String? linkRelay,
  DateTime? now,
  Duration connectTimeout = const Duration(seconds: 10),
}) async {
  if (linkRelay != null && !tomSecretsIsLinkRelay(linkRelay)) {
    throw ArgumentError.value(linkRelay, 'linkRelay', 'not a relay server');
  }
  TomSecretsPairingPeerKeys? sent;
  if (relay == null && (address == null || port == null)) {
    throw ArgumentError('an address and port, or a relay');
  }
  if (linkAddress != null) {
    final problem = tomSecretsApprovalLinkProblem(linkAddress);
    if (problem != null) {
      throw ArgumentError.value(linkAddress, 'linkAddress', problem);
    }
  }
  final trust = TomSecretsTrust.create(device, now: now);
  Future<TomSecretsPairingPeerKeys> keysFor(
    String _,
    TomSecretsPairingBundle bundle,
  ) async {
    final problem = tomSecretsPairingSetupProblem(
      bundle,
      ownTokens: ownTokens.keys.toSet(),
    );
    if (problem != null) throw TomSecretsPairingRefusal(problem);
    return sent = TomSecretsPairingPeerKeys(
      linkKey: (await trust.linkKey()).publicKey,
      approverKey: (await trust.approverKey()).publicKey,
      linkAddress: linkAddress,
      linkRelay: linkRelay == null
          ? null
          : TomSecretsRelayId.parse(linkRelay).text,
      linkId: linkRelay == null ? null : tomSecretsNewLinkId(),
    );
  }

  final received = relay != null
      ? await tomSecretsReceivePairingVia(
          relay,
          code: code,
          device: device,
          keysFor: keysFor,
        )
      : await tomSecretsReceivePairingAt(
          address!,
          port!,
          code: code,
          device: device,
          connectTimeout: connectTimeout,
          keysFor: keysFor,
        );
  return TomSecretsPairingReceipt._(received, trust, Map.of(ownTokens), sent);
}

/// Splits `host:port` (an IPv6 address in brackets: `[fd00::1]:47900`) as
/// the giving machine's Pairing screen shows it. Throws [FormatException].
(String host, int port) tomSecretsParsePairingAddress(String text) {
  final t = text.trim();
  final at = t.lastIndexOf(':');
  final port = at < 0 ? null : int.tryParse(t.substring(at + 1));
  if (at <= 0 || port == null || port < 1 || port > 65535) {
    throw FormatException('not an address and port (host:port): $text');
  }
  var host = t.substring(0, at);
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.substring(1, host.length - 1);
  }
  if (InternetAddress.tryParse(host) == null &&
      !RegExp(r'^[A-Za-z0-9.-]+$').hasMatch(host)) {
    throw FormatException('not a host name or address: $host');
  }
  return (host, port);
}
