// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Starting the service (part-service, Lifecycle): the app or `tsm start`
/// generates the admin key, starts the service detached so it outlives its
/// starter, and hands it one JSON line on its standard input — the admin
/// key, the bootstrap file, the starter's PID — then closes it. The key
/// never touches a file. The service answers one JSON line on its standard
/// output: `{"status":"ready"}`, `{"status":"already_running"}` (the
/// starter attaches to the running one) or `{"status":"error","code":…}`.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'admin_auth.dart';

/// The handover line the service reads from its standard input.
final class TomSecretsHandover {
  /// A handover of [adminKey] and [bootstrap] from [starterPid].
  const TomSecretsHandover({
    required this.adminKey,
    required this.bootstrap,
    required this.starterPid,
  });

  /// From the JSON line.
  factory TomSecretsHandover.parse(String line) {
    final json = jsonDecode(line);
    if (json is! Map ||
        json['adminKey'] is! String ||
        json['bootstrap'] is! String) {
      throw const FormatException('the handover names adminKey and bootstrap');
    }
    final key = base64.decode(json['adminKey'] as String);
    if (key.length != tomSecretsKeyBytes) {
      throw const FormatException('the admin key is 32 bytes');
    }
    return TomSecretsHandover(
      adminKey: key,
      bootstrap: json['bootstrap'] as String,
      starterPid: json['starterPid'] is int ? json['starterPid'] as int : 0,
    );
  }

  /// The admin key.
  final Uint8List adminKey;

  /// The bootstrap file's path.
  final String bootstrap;

  /// The starter's PID.
  final int starterPid;

  /// The JSON line.
  String toLine() => jsonEncode({
    'adminKey': base64.encode(adminKey),
    'bootstrap': bootstrap,
    'starterPid': starterPid,
  });
}

/// What a start found.
sealed class TomSecretsStartResult {
  const TomSecretsStartResult();
}

/// A new service runs with [adminKey].
final class TomSecretsStarted extends TomSecretsStartResult {
  /// Started, holding [adminKey].
  const TomSecretsStarted(this.adminKey);

  /// The admin key the starter keeps (in the keychain, for the app).
  final Uint8List adminKey;
}

/// A service was already running: attach to it (with the key held, or by
/// `claim`).
final class TomSecretsAlreadyStarted extends TomSecretsStartResult {
  /// Already running.
  const TomSecretsAlreadyStarted();
}

/// The service could not start, for [code].
final class TomSecretsStartFailed extends TomSecretsStartResult {
  /// Failed with [code] (`runtime`, `device_key`, `handover`, ...).
  const TomSecretsStartFailed(this.code, this.message);

  /// The failure's code.
  final String code;

  /// What happened (no secret).
  final String message;
}

/// Starts the service [executable] (with [arguments]) for [bootstrap],
/// detached; waits up to [timeout] for its answer line.
Future<TomSecretsStartResult> tomSecretsStartService({
  required String executable,
  List<String> arguments = const [],
  required String bootstrap,
  Map<String, String>? environment,
  Duration timeout = const Duration(seconds: 60),
}) async {
  final key = tomSecretsRandomBytes();
  final process = await Process.start(
    executable,
    arguments,
    mode: ProcessStartMode.detachedWithStdio,
    environment: environment,
  );
  process.stdin.writeln(
    TomSecretsHandover(
      adminKey: key,
      bootstrap: bootstrap,
      starterPid: pid,
    ).toLine(),
  );
  await process.stdin.flush();
  await process.stdin.close();
  final String line;
  try {
    line = await process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .first
        .timeout(timeout);
  } on Object {
    return const TomSecretsStartFailed(
      'no_answer',
      'the service did not answer',
    );
  } finally {
    unawaited(process.stderr.drain<void>());
  }
  final answer = jsonDecode(line) as Map;
  return switch (answer['status']) {
    'ready' => TomSecretsStarted(key),
    'already_running' => const TomSecretsAlreadyStarted(),
    _ => TomSecretsStartFailed(
      '${answer['code'] ?? 'error'}',
      '${answer['message'] ?? ''}',
    ),
  };
}
