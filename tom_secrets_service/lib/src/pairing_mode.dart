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
/// link address, so its service opens the approval link to this one. The executable ends after it; tsm
/// starts the service as usual and unlocks it.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_core_storage/settings.dart' show TomSecretStore;
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

/// Runs the pairing mode for [handover]: reads tsm's lines from [lines],
/// answers through [answer], keeps keys in [keychain] (null: none on this
/// machine). Answers the exit code: 0 set up, 2 the handover cannot be
/// used, 6 the pairing failed, 7 the setup failed or no password came.
Future<int> tomSecretsRunPairingMode(
  TomSecretsPairingHandover handover, {
  required StreamIterator<String> lines,
  required void Function(Map<String, Object?> line) answer,
  required TomSecretStore? keychain,
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
  try {
    code = TomSecretsPairingCode.parse(handover.code);
    deviceKey = handover.deviceKey == null
        ? TomSecretsDeviceKeyMode.auto
        : TomSecretsDeviceKeyMode.parse(handover.deviceKey!);
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

  final TomSecretsPairingReceipt receipt;
  try {
    receipt = await tomSecretsReceivePairingForSetup(
      address: handover.address,
      port: handover.port,
      code: code,
      device: handover.device,
      linkAddress: handover.approvalLink,
    );
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
      tokens: [for (final t in bundle.tokens) t.repository],
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
      answer({'status': 'setUp', 'bootstrap': result.bootstrapPath});
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
