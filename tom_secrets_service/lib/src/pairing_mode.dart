// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service executable's pairing mode (part-sharing, 1. Pairing): `tsm
/// pair` sets a headless machine up by pairing through it, so tsm itself
/// stays a thin client of the protocol. The lines are
/// `package:tom_secrets_client/admin.dart`'s `TomSecretsServicePairing`:
/// the pairing received (nothing stored), reported; then, with the master
/// password, the machine set up by `TomSecretsFirstRun.runPaired` (the
/// keychain, the device settings container with the trust material and the
/// giver recorded, `bootstrap.yaml`). The handover's `approvalLink` goes
/// into the device settings and to the giving machine as this machine's
/// link address, so its service opens the approval link to this one. A
/// handover naming a relay (part-relay: a GitHub repository, with this
/// machine's own token for it) receives through that repository after the
/// address, or alone without one; the token also opens the primary when it
/// is there. The executable ends after it; tsm starts the service as usual
/// and unlocks it.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_core_storage/settings.dart' show TomSecretStore;
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'relay_links.dart';

/// Runs the pairing mode for [handover]: reads tsm's lines from [lines],
/// answers through [answer], keeps keys in [keychain] (null: none on this
/// machine); [relayFor] builds the relay a handover names (default
/// `tomSecretsRelayFor`: a relay server, or GitHub reached with the
/// handover's token). Answers the exit code: 0 set up, 2
/// the handover cannot be used, 6 the pairing failed (also through the
/// relay, the error naming it), 7 the setup failed or no password came.
Future<int> tomSecretsRunPairingMode(
  TomSecretsPairingHandover handover, {
  required StreamIterator<String> lines,
  required void Function(Map<String, Object?> line) answer,
  required TomSecretStore? keychain,
  TomSecretsRelay Function(
    TomSecretsRelayId id,
    String? token,
    String? apiUrl,
    String device,
  )?
  relayFor,
}) async {
  void error(String code, String message, {String? failure}) => answer({
    'status': 'error',
    'code': code,
    'message': message,
    'failure': ?failure,
  });

  final TomSecretsPairingCode code;
  final TomSecretsDeviceKeyMode deviceKey;
  final link = handover.approvalLink;
  final linkProblem = link == null ? null : tomSecretsApprovalLinkProblem(link);
  if (linkProblem != null) {
    error('handover', linkProblem);
    return 2;
  }
  TomSecretsRelayId? relayId;
  try {
    code = TomSecretsPairingCode.parse(handover.code);
    deviceKey = handover.deviceKey == null
        ? TomSecretsDeviceKeyMode.auto
        : TomSecretsDeviceKeyMode.parse(handover.deviceKey!);
    if (handover.relay case final relay?) {
      relayId = TomSecretsRelayId.parse(relay);
      if (tomSecretsRelayNeedsToken(relayId) &&
          (handover.relayToken ?? '').isEmpty) {
        throw FormatException(
          'pairing through ${relayId.text} needs this machine\'s token for it',
        );
      }
    }
  } on FormatException catch (e) {
    error('handover', e.message);
    return 2;
  }
  final firstRun = TomSecretsFirstRun(
    dataDirectory: handover.dataDirectory,
    keychain: keychain,
  );
  if (File(firstRun.bootstrapPath).existsSync()) {
    error(
      'setup',
      'This machine is set up already: ${firstRun.bootstrapPath} is there.',
    );
    return 7;
  }

  // [C] A relay server named for the pairing is offered for the approval
  // link too (part-relay); its instance token, when the handover carries
  // one, is kept in the keychain for the link.
  final linkRelay = relayId?.kind == TomSecretsRelayKind.server
      ? relayId!.text
      : null;
  // The identity key of the service this machine will run (protocol.md
  // 6.1), made before the pairing: the giving machine records it with the
  // device, and tsm pins it from the `setUp` line.
  // Written only once the machine is set up: a pairing that fails stores
  // nothing.
  final TomSecretsServiceIdentityKey identityKey;
  try {
    identityKey = await TomSecretsServiceIdentityKey.loadOrCreate(
      firstRun.dataDirectory,
      write: false,
    );
  } on FileSystemException catch (e) {
    error('setup', e.message);
    return 7;
  }
  final serviceKey = base64.encode(identityKey.publicKey);
  TomSecretsPairingReceipt? receipt;
  try {
    if (handover.address != null && handover.port != null) {
      try {
        receipt = await tomSecretsReceivePairingForSetup(
          address: handover.address,
          port: handover.port,
          code: code,
          device: handover.device,
          linkAddress: handover.approvalLink,
          linkRelay: linkRelay,
          serviceKey: serviceKey,
        );
      } on TomSecretsPairingException catch (e) {
        // Not reachable there: the relay next, when the handover names one
        // (part-relay: the LAN and the VPN first).
        if (relayId == null || e.failure != TomSecretsPairingFailure.closed) {
          rethrow;
        }
      }
    }
    if (receipt == null) {
      final token = handover.relayToken;
      final build =
          relayFor ??
          (id, token, api, device) => tomSecretsRelayFor(
            id,
            token: token,
            device: device,
            githubApi: api,
          );
      receipt = await tomSecretsReceivePairingForSetup(
        relay: build(relayId!, token, handover.relayApi, handover.device),
        ownTokens: tomSecretsRelayNeedsToken(relayId)
            ? {relayId.address: token!}
            : const {},
        code: code,
        device: handover.device,
        linkAddress: handover.approvalLink,
        linkRelay: linkRelay,
        serviceKey: serviceKey,
      );
    }
  } on TomSecretsRelayException catch (e) {
    error(
      'pairing',
      'the relay ${e.relay} failed: ${e.message}',
      failure: 'relay',
    );
    return 6;
  } on TomSecretsPairingException catch (e) {
    error('pairing', e.message, failure: e.failure.name);
    return 6;
  }
  final bundle = receipt.bundle;
  answer(
    TomSecretsPairingReport(
      giver: receipt.giver,
      vaults: [
        for (final v in bundle.vaults)
          (name: v.name, locator: v.locator, primary: v.primary),
      ],
      config: bundle.configYaml != null,
      tokens: [
        for (final t in bundle.tokens) t.repository,
        // The token this machine brought for the relay's repository.
        for (final r in receipt.ownTokens.keys)
          if (!bundle.tokens.any((t) => t.repository == r)) r,
      ],
    ).toJson(),
  );

  for (var tried = 0; tried < tomSecretsPairingPasswordTries; tried++) {
    if (!await lines.moveNext()) {
      error('ended', 'no master password came: nothing was stored');
      return 7;
    }
    final String password;
    try {
      password = _password(lines.current);
    } on FormatException catch (e) {
      error('handover', e.message);
      return 2;
    }
    try {
      final result = await firstRun.runPaired(
        receipt,
        masterPassword: password,
        settings: TomSecretsDeviceSettings(approvalLink: handover.approvalLink),
        deviceKey: deviceKey,
      );
      final instanceToken = handover.relayToken;
      if (linkRelay != null &&
          receipt.link != null &&
          keychain != null &&
          instanceToken != null &&
          instanceToken.isNotEmpty) {
        await keychain.write(
          tomSecretsRelayTokenHandle(receipt.link!.relay),
          instanceToken,
        );
      }
      identityKey.store();
      answer({
        'status': 'setUp',
        'bootstrap': result.bootstrapPath,
        'identity': serviceKey,
      });
      return 0;
    } on TomSecretsFirstRunException catch (e) {
      if (e.problem == TomSecretsFirstRunProblem.wrongPassword) {
        error(tomSecretsPairingWrongPassword, e.message);
        continue;
      }
      error('setup', e.message);
      return 7;
    }
  }
  return 7;
}

String _password(String line) {
  final Object? json;
  try {
    json = jsonDecode(line);
  } on FormatException {
    throw const FormatException('a password line is JSON');
  }
  if (json is! Map || json['password'] is! String) {
    throw const FormatException('a password line names the password');
  }
  return json['password'] as String;
}
