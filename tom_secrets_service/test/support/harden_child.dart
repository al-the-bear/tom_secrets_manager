// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A child process for hardening_test.dart: hardens itself, prints its pid
/// and what it achieved as one JSON line, and waits until its standard input
/// closes. Its own pid: on Windows `dart.exe` runs the script in a child
/// process (`dartvm.exe`), so the starter's pid is another process.
library;

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_service/tom_secrets_service.dart';

Future<void> main() async {
  final achieved = tomSecretsHardenProcess();
  stdout.writeln(jsonEncode({'pid': pid, 'achieved': achieved}));
  await stdout.flush();
  await stdin.drain<void>();
}
