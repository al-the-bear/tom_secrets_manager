// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A demo installation for a user's default data directory: a primary
/// vault (`primary-demo-pw`) with one login and the bootstrap naming it.
/// The system install's container check (tom_secrets_build `:system`) makes
/// one per demo user. Demo data only.
///
///     dart run tool/demo_installation.dart <data directory> <vault folder>
library;

import 'dart:io';

import 'package:tom_kdbx_store/tom_kdbx_store.dart'
    show KdbxArgon2, KdbxArgon2Type;
import 'package:tom_secrets_core/tom_secrets_core.dart';

Future<void> main(List<String> args) async {
  if (args.length != 2) {
    stderr.writeln(
      'usage: demo_installation.dart <data directory> <vault folder>',
    );
    exit(2);
  }
  final data = Directory(args[0])..createSync(recursive: true);
  final vaults = Directory(args[1])..createSync(recursive: true);
  final primary = tomSecretsNewVault(
    tomSecretsVaultCredentials(password: 'primary-demo-pw'),
    'primary',
    argon2: const KdbxArgon2(
      type: KdbxArgon2Type.argon2id,
      memory: 1 << 20,
      iterations: 1,
    ),
  );
  final entry = KdbxEntry.create(primary, primary.body.rootGroup)
    ..label = 'Main';
  entry.setString(
    KdbxKeyCommon.PASSWORD,
    ProtectedValue.fromString('demo-db-pw'),
  );
  primary.body.rootGroup.addEntry(entry);
  final file = File('${vaults.path}/primary.kdbx')
    ..writeAsBytesSync(await primary.save());
  File('${data.path}/bootstrap.yaml').writeAsStringSync(
    'primary: file:${file.absolute.path}\n'
    'device_key: keyfile\n'
    'host: demo-host\n',
  );
}
