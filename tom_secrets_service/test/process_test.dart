// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service as a process (part-service, Lifecycle): compiled ahead of
/// time, started detached by the starter with the admin key handed over on
/// its standard input, a second start answering `already_running` (the OS
/// lock between processes), SIGTERM cleaning up, a bad handover refused.
@TestOn('mac-os || linux')
@Timeout(Duration(minutes: 4))
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

void main() {
  late String exe;

  setUpAll(() async {
    final dir = Directory.systemTemp.createTempSync('tsmexe');
    exe = '${dir.path}/tom_secrets_service';
    final result = await Process.run(Platform.resolvedExecutable, [
      'compile',
      'exe',
      'bin/tom_secrets_service.dart',
      '-o',
      exe,
    ]);
    expect(result.exitCode, 0, reason: '${result.stderr}');
    addTearDown(() => dir.deleteSync(recursive: true));
  });

  test('started detached with the handover; a second start attaches; '
      'SIGTERM stops it and removes the endpoints', () async {
    final demo = await Demo.create();
    final runtime = demo.runtime();
    final bootstrap = File('${demo.dir}/data/bootstrap.yaml')
      ..createSync(recursive: true)
      ..writeAsStringSync(
        'primary: ${demo.bootstrap.primary}\n'
        'runtime_dir: ${runtime.directory}\n'
        'device_key: keyfile\n',
      );

    final started = await tomSecretsStartService(
      executable: exe,
      bootstrap: bootstrap.path,
    );
    expect(started, isA<TomSecretsStarted>());
    final key = (started as TomSecretsStarted).adminKey;
    final info = jsonDecode(File(runtime.infoFile).readAsStringSync()) as Map;
    final servicePid = info['pid'] as int;
    expect(servicePid, isNot(pid));
    addTearDown(() => Process.killPid(servicePid));

    final admin = await TomSecretsAdminClient.connect(runtime, key);
    await admin.unlock(primaryPassword);
    expect((await admin.request('status'))['locked'], isFalse);
    await admin.close();

    expect(
      await tomSecretsStartService(executable: exe, bootstrap: bootstrap.path),
      isA<TomSecretsAlreadyStarted>(),
    );

    expect(Process.killPid(servicePid, ProcessSignal.sigterm), isTrue);
    for (var i = 0; i < 100 && File(runtime.infoFile).existsSync(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(File(runtime.infoFile).existsSync(), isFalse);
    expect(
      FileSystemEntity.typeSync(runtime.adminSocket),
      FileSystemEntityType.notFound,
    );
  });

  test('a handover that cannot be read is refused with exit code 2', () async {
    final process = await Process.start(exe, const []);
    process.stdin.writeln('{"adminKey": "short", "bootstrap": "/x"}');
    await process.stdin.close();
    final line = await process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .first;
    expect(jsonDecode(line), containsPair('code', 'handover'));
    expect(await process.exitCode, 2);
  });
}
