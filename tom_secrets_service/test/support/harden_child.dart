// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A child process for hardening_test.dart: hardens itself, writes a file
/// at its first argument (as the service writes its log and cache), prints
/// its pid, what it achieved and that file's mode as one JSON line, and
/// waits until its standard input closes. Its own pid: on Windows `dart.exe` runs the script in a child
/// process (`dartvm.exe`), so the starter's pid is another process.
library;

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_service/tom_secrets_service.dart';

Future<void> main(List<String> args) async {
  final achieved = tomSecretsHardenProcess();
  final file = File(args.first)..writeAsStringSync('demo');
  stdout.writeln(
    jsonEncode({
      'pid': pid,
      'achieved': achieved,
      'fileMode': file.statSync().mode & 0x1FF,
    }),
  );
  await stdout.flush();
  await stdin.drain<void>();
}
