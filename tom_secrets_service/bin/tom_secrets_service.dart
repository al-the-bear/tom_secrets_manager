// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The secrets service executable. Started detached by the app or
/// `tsm start` (`tomSecretsStartService`): it reads the handover line from
/// its standard input, answers one status line on its standard output, and
/// runs until `shutdown`, SIGTERM or SIGHUP (logout).
///
/// Exit codes: 0 stopped, 2 the handover or the bootstrap cannot be read,
/// 3 already running, 4 the runtime directory is refused, 5 the device key's
/// keychain is not available.
///
/// Started by `tsm pair` with a pairing handover instead, it runs the
/// pairing mode (`tomSecretsRunPairingMode`): it receives a pairing, sets
/// the machine up with the master password tsm sends, and ends (0 set up,
/// 2 the handover cannot be used, 6 the pairing failed, 7 the setup failed).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:tom_core_storage/io.dart' show TomDesktopSecretStore;
import 'package:tom_secrets_service/tom_secrets_service.dart';

Future<void> main() async {
  // First, before the admin key or anything secret is in memory: no core
  // dumps, not dumpable, the Windows process DACL (status.hardening).
  final hardening = tomSecretsHardenProcess();

  Future<Never> answer(Map<String, Object?> status, int code) async {
    stdout.writeln(jsonEncode(status));
    await stdout.flush();
    exit(code);
  }

  final lines = StreamIterator(
    stdin.transform(utf8.decoder).transform(const LineSplitter()),
  );
  final TomSecretsHandover handover;
  final TomSecretsBootstrap bootstrap;
  try {
    if (!await lines.moveNext()) throw const FormatException('no handover');
    final line = lines.current;
    // `tsm pair`: the pairing mode sets the machine up and ends.
    final pairing = TomSecretsPairingHandover.fromJson(jsonDecode(line));
    if (pairing != null) {
      final store = TomDesktopSecretStore(service: tomSecretsKeychainService);
      final code = await tomSecretsRunPairingMode(
        pairing,
        lines: lines,
        answer: (m) => stdout.writeln(jsonEncode(m)),
        keychain: await store.isAvailable() ? store : null,
      );
      await stdout.flush();
      exit(code);
    }
    handover = TomSecretsHandover.parse(line);
    bootstrap = await TomSecretsBootstrap.read(handover.bootstrap);
  } on Object catch (e) {
    await answer({
      'status': 'error',
      'code': 'handover',
      'message': e.runtimeType.toString(),
    }, 2);
  }

  final runtime = bootstrap.runtimeDirectory == null
      ? TomSecretsRuntime.current()
      : TomSecretsRuntime(
          bootstrap.runtimeDirectory!,
          transport: Platform.isWindows
              ? TomSecretsTransport.tcp
              : TomSecretsTransport.unix,
        );
  final lookup = tomSecretsLookupExecutables(Platform.resolvedExecutable);
  final TomSecretsService service;
  try {
    service = await TomSecretsService.launch(
      TomSecretsServiceConfig(
        runtime: runtime,
        bootstrap: bootstrap,
        adminKey: handover.adminKey,
        // The OS keychain, for the device key's `keychain` and `auto` modes
        // (not available in a session without one: `auto` then takes the
        // vault, `keychain` refuses the start), and the GitHub token of each
        // vault repository.
        keychain: TomDesktopSecretStore(service: tomSecretsKeychainService),
        harden: () => hardening,
        // Only tsm and the manager app administer it (protocol.md 6.1).
        adminExecutables: tomSecretsAdminExecutables(
          Platform.resolvedExecutable,
          bootstrap,
        ),
        // The browser host and the helpers beside it (protocol.md 5.5).
        browserHostExecutables: lookup.browserHosts,
        helperExecutables: lookup.helpers,
      ),
    );
  } on TomSecretsAlreadyRunning {
    await answer({'status': 'already_running'}, 3);
  } on TomSecretsRuntimeException catch (e) {
    await answer({
      'status': 'error',
      'code': 'runtime',
      'message': e.message,
    }, 4);
  } on TomSecretsDeviceKeyException catch (e) {
    await answer({
      'status': 'error',
      'code': 'device_key',
      'message': e.message,
    }, 5);
  }

  stdout.writeln(jsonEncode({'status': 'ready'}));
  await stdout.flush();

  final signals = <StreamSubscription<ProcessSignal>>[
    ProcessSignal.sigint.watch().listen((_) => unawaited(service.stop())),
    if (!Platform.isWindows) ...[
      ProcessSignal.sigterm.watch().listen((_) => unawaited(service.stop())),
      ProcessSignal.sighup.watch().listen((_) => unawaited(service.stop())),
    ],
  ];
  await service.done;
  for (final s in signals) {
    await s.cancel();
  }
  exit(0);
}
