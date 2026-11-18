// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The ssh-agent tests' demo keys: three `ssh-key` entries in the demo team
/// vault (an Ed25519 key, one KeeAgent asks to confirm, an RSA key),
/// generated for the test. Demo keys only.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show
        TomSecretsKeeAgentSettings,
        TomSecretsSshKeyAlgorithm,
        tomSecretsDecodeStored,
        tomSecretsGenerateSshKey,
        tomSecretsKeeAgentSettingsName,
        tomSecretsUuidHex,
        tomSecretsVaultCredentials,
        tomSecretsWriteSshKey;

import 'setup.dart';

/// The demo keys of the team vault: each entry's UUID, public key blob and
/// `authorized_keys` line.
final class DemoKeys {
  /// `deployUuid`.
  late String deployUuid;

  /// `deployBlob`.
  late Uint8List deployBlob;

  /// `deployPublic`.
  late String deployPublic;

  /// `confirmedUuid`.
  late String confirmedUuid;

  /// `confirmedBlob`.
  late Uint8List confirmedBlob;

  /// `confirmedPublic`.
  late String confirmedPublic;
}

/// Adds the demo keys to [demo]'s team vault.
Future<DemoKeys> addDemoKeys(Demo demo) async {
  final keys = DemoKeys();
  final location = 'file:${demo.teamPath}';
  final file = await tomSecretsDecodeStored(
    location,
    File(demo.teamPath).readAsBytesSync(),
    tomSecretsVaultCredentials(password: teamPassword),
  );
  final root = file.body.rootGroup;
  final group = file.createGroup(parent: root, name: 'Ssh');
  Future<(String, Uint8List, String)> add(
    String title, {
    TomSecretsSshKeyAlgorithm algorithm = TomSecretsSshKeyAlgorithm.ed25519,
    bool confirm = false,
  }) async {
    final entry = KdbxEntry.create(file, group)..label = title;
    group.addEntry(entry);
    final key = await tomSecretsGenerateSshKey(
      algorithm: algorithm,
      comment: title,
      rsaBits: 2048,
    );
    tomSecretsWriteSshKey(
      entry,
      attachmentName: 'id',
      privateKey: key.privateKey,
    );
    if (confirm) {
      entry.removeBinary(const KdbxKey(tomSecretsKeeAgentSettingsName));
      entry.createBinary(
        isProtected: false,
        name: tomSecretsKeeAgentSettingsName,
        bytes: const TomSecretsKeeAgentSettings(
          useConfirmConstraintWhenAdding: true,
          attachmentName: 'id',
        ).toBytes(),
      );
    }
    return (
      tomSecretsUuidHex(entry.uuid),
      key.info.publicKeyBlob!,
      key.info.publicKey!,
    );
  }

  final deploy = await add('Deploy key');
  keys
    ..deployUuid = deploy.$1
    ..deployBlob = deploy.$2
    ..deployPublic = deploy.$3;
  final confirmed = await add('Confirmed key', confirm: true);
  keys
    ..confirmedUuid = confirmed.$1
    ..confirmedBlob = confirmed.$2
    ..confirmedPublic = confirmed.$3;
  await add('Rsa key', algorithm: TomSecretsSshKeyAlgorithm.rsa);
  await File(demo.teamPath).writeAsBytes(await file.save());
  return keys;
}
