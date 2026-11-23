// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Writes an `age` file to a fresh member key (a demo key, never kept) and
// opens it again; then the same under a passphrase.

import 'dart:convert';

import 'package:tom_secrets_age/tom_secrets_age.dart';

Future<void> main() async {
  final key = await TomSecretsMemberKey.generate();
  print('fingerprint: ${key.recipient.shortFingerprint}');

  final file = await tomSecretsAgeEncrypt(utf8.encode('demo secret'), [
    key.recipient,
  ]);
  print(tomSecretsAgeArmor(file));
  final opened = await tomSecretsAgeDecrypt(file, [
    TomSecretsAgeHybridIdentity(key),
  ]);
  print(utf8.decode(opened));

  final locked = await tomSecretsAgeEncryptPassphrase(
    utf8.encode('demo secret'),
    'demo passphrase',
    workFactor: 10,
  );
  print(tomSecretsAgeIsPassphrase(locked));
  key.dispose();
}
