// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The secrets service executable. Started detached by the app or
/// `tsm start` (`tomSecretsStartService`): it reads the handover line from
/// its standard input, answers one status line on its standard output, and
/// runs until `shutdown`, SIGTERM or SIGHUP (logout).
///
/// Exit codes: 0 stopped, 2 the handover or the bootstrap cannot be read,
/// 3 already running, 4 the runtime directory is refused, 5 the device key's
/// keychain is not available, 8 the data directory is refused, 9 the
/// identity key cannot be read (where it is kept, or a system install's).
///
/// Installed with `tsm install --system` (Linux: root's, set-group-ID to
/// tsm-identity), it takes the real user's identity key first and drops
/// the group (system_mode.dart).
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
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show
        TomSecretsIdentityKeyUnavailable,
        TomSecretsServiceIdentityKey,
        tomSecretsIdentityHelperAnswer;
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

  // A system install (Linux, set-group-ID to tsm-identity): the real
  // user's identity key is taken with the group's rights, then the group
  // is dropped for good, before the handover or the environment is read.
  TomSecretsSystemMode? system;
  TomSecretsServiceIdentityKey? systemKey;
  try {
    system = TomSecretsSystemMode.detect();
    systemKey = await system?.takeIdentity();
  } on TomSecretsSystemModeException catch (e) {
    await answer({
      'status': 'error',
      'code': 'identity',
      'message': e.message,
    }, 9);
  }

  final lines = StreamIterator(
    stdin.transform(utf8.decoder).transform(const LineSplitter()),
  );
  final TomSecretsHandover handover;
  final TomSecretsBootstrap bootstrap;
  try {
    if (!await lines.moveNext()) throw const FormatException('no handover');
    final line = lines.current;
    // An admin's identity helper (`tsm`, which links no post-quantum code):
    // the two primitives, one JSON line in and one out, until the input
    // ends. No secret of a vault passes it.
    final first = jsonDecode(line);
    if (first is Map && first[tomSecretsIdentityHelperHandover] != null) {
      while (await lines.moveNext()) {
        Object? request;
        try {
          request = jsonDecode(lines.current);
        } on FormatException {
          request = null;
        }
        stdout.writeln(
          jsonEncode(await tomSecretsIdentityHelperAnswer(request)),
        );
        await stdout.flush();
      }
      exit(0);
    }
    // `tsm pair`: the pairing mode sets the machine up and ends.
    final pairing = TomSecretsPairingHandover.fromJson(first);
    if (pairing != null) {
      if (system != null &&
          !_samePath(pairing.dataDirectory, system.dataDirectory)) {
        throw FormatException(
          'a system-installed service sets up only the user\'s own data '
          'directory (${system.dataDirectory})',
        );
      }
      final store = TomDesktopSecretStore(service: tomSecretsKeychainService);
      final code = await tomSecretsRunPairingMode(
        pairing,
        lines: lines,
        answer: (m) => stdout.writeln(jsonEncode(m)),
        keychain: await store.isAvailable() ? store : null,
        systemIdentityKey: systemKey,
      );
      await stdout.flush();
      exit(code);
    }
    handover = TomSecretsHandover.parse(line);
    // A system-installed service starts only with the user's own bootstrap
    // in the user's own data directory (the environment does not move it).
    if (system != null &&
        !_samePath(handover.bootstrap, system.bootstrapPath)) {
      throw FormatException(
        'a system-installed service starts only with ${system.bootstrapPath}',
      );
    }
    bootstrap = await TomSecretsBootstrap.read(handover.bootstrap);
  } on Object catch (e) {
    await answer({
      'status': 'error',
      'code': 'handover',
      'message': e.runtimeType.toString(),
    }, 2);
  }

  final runtime = system != null
      // The user's own runtime directory, from the account.
      ? system.runtime
      : bootstrap.runtimeDirectory == null
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
        // The browser host, the helpers and the Windows passkey plugin
        // beside it (protocol.md 5.5, 5.8).
        browserHostExecutables: lookup.browserHosts,
        helperExecutables: lookup.helpers,
        passkeyPluginExecutables: lookup.passkeyPlugins,
        // The Safari extension's way in (macOS, the team-signed app): the
        // client endpoint in the app's App Group container too.
        groupClientSocket: tomSecretsAppGroupClientSocketFor(
          Platform.resolvedExecutable,
        ),
        // The identity key's secret: a system install's, read before the
        // group was dropped, else this platform's store (the macOS
        // keychain, DPAPI on Windows, the file on Linux).
        identityKey: systemKey,
        identityStore: systemKey == null && !bootstrap.identityKeyInFile
            ? tomSecretsPlatformIdentityStore()
            : null,
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
  } on TomSecretsDataDirectoryException catch (e) {
    await answer({
      'status': 'error',
      'code': 'data_directory',
      'message': e.message,
    }, 8);
  } on TomSecretsIdentityKeyUnavailable catch (e) {
    // Its store does not give it (a locked keychain, a refused prompt): it
    // is never replaced silently.
    await answer({
      'status': 'error',
      'code': 'identity',
      'message': e.message,
    }, 9);
  } on FileSystemException catch (e) {
    // The identity key in the data directory cannot be read: it is never
    // replaced silently (protocol.md 6.1).
    await answer({
      'status': 'error',
      'code': 'identity',
      'message': e.message,
    }, 9);
  }

  // The starter pins the identity key this line names: it comes through
  // the pipe of the process it started, which nothing else writes to.
  stdout.writeln(
    jsonEncode({
      'status': 'ready',
      'identity': base64.encode(service.identityKey),
    }),
  );
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

/// Whether [a] and [b] name the same place.
bool _samePath(String a, String b) =>
    File(a).absolute.uri.normalizePath().path ==
    File(b).absolute.uri.normalizePath().path;
