// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `tsm_import_cleaner`: cleans a password manager's export for testing
/// the import.
library;

import 'dart:io';

import 'package:tom_secrets_import_cleaner/tom_secrets_import_cleaner.dart';

Future<void> main(List<String> arguments) async {
  final code = await tomSecretsImportCleanerMain(arguments);
  await stdout.flush();
  await stderr.flush();
  exit(code);
}
