// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Who is asking (part-protocol, BP-19, BP-21, DP-18): the peer of a real
/// connection measured on this OS (`SO_PEERCRED`, `LOCAL_PEERPID`,
/// `GetExtendedTcpTable`) with its executable, arguments, working directory
/// and parent; interpreted clients by their interpreter and script; file
/// hashes cached; pins with their development relaxation.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

TomSecretsIdentity classify(
  String exe,
  List<String> args, {
  String cwd = '/work',
}) => tomSecretsIdentityOf(
  TomSecretsProcessInfo(
    pid: 42,
    exe: exe,
    args: args,
    cwd: cwd,
    startTime: 1,
    parentPid: 1,
    uid: 501,
  ),
);

void main() {
  group('interpreted clients (BP-21)', () {
    final sep = Platform.pathSeparator;
    String at(String cwd, String path) =>
        tomSecretsRealPath(path, cwd); // not on disk: made absolute

    test('a program is an exe', () {
      final id = classify('/usr/local/bin/tsm', ['get', 'db.main']);
      expect(id.kind, 'exe');
      expect(id.interpreter, isNull);
      expect(id.args, ['get', 'db.main']);
    });

    test('python: a script, -m with its package root, -c alone', () {
      final s = classify('/usr/bin/python3.12', ['-u', '-W', 'x', 'tool.py']);
      expect(s.kind, 'script');
      expect(s.interpreter, '/usr/bin/python3.12');
      expect(s.script, at('/work', 'tool.py'));
      final dir = Directory.systemTemp.createTempSync('tsmpy');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}${sep}pyproject.toml').writeAsStringSync('');
      Directory('${dir.path}${sep}sub').createSync();
      final m = classify('/usr/bin/python3', [
        '-m',
        'pkg.tool',
      ], cwd: '${dir.path}${sep}sub');
      expect(m.kind, 'script');
      expect(m.script, 'pkg.tool');
      expect(m.packageRoot, dir.path);
      expect(
        classify('/usr/bin/python', ['-c', 'print(1)']).kind,
        'interpreter',
      );
      expect(
        classify(r'C:\Python312\Python.EXE', ['x.py'], cwd: r'C:\w').kind,
        'script',
      );
    });

    test('node, deno run, bun run', () {
      expect(
        classify('/usr/bin/node', ['--inspect', 'a.js']).script,
        at('/work', 'a.js'),
      );
      expect(
        classify('/usr/bin/deno', ['run', '-A', 'b.ts']).script,
        at('/work', 'b.ts'),
      );
      expect(
        classify('/usr/bin/bun', ['run', 'c.ts']).script,
        at('/work', 'c.ts'),
      );
      expect(classify('/usr/bin/node', []).kind, 'interpreter');
    });

    test('dart: a file, the VM the dart command starts, dart run with the '
        'package root', () {
      expect(
        classify('/sdk/bin/dart', ['tool.dart', 'x']).script,
        at('/work', 'tool.dart'),
      );
      final vm = classify('/sdk/bin/dartvm', [
        '--resolved_executable_name=/sdk/bin/dart',
        '--executable_name=/sdk/bin/dart',
        'tool.dart',
        'one',
      ]);
      expect(vm.kind, 'script');
      expect(vm.script, at('/work', 'tool.dart'));
      final dir = Directory.systemTemp.createTempSync('tsmdart');
      addTearDown(() => dir.deleteSync(recursive: true));
      File('${dir.path}${sep}pubspec.yaml').writeAsStringSync('name: x\n');
      Directory('${dir.path}${sep}lib').createSync();
      final run = classify('/sdk/bin/dart', [
        'run',
        'x:serve',
      ], cwd: '${dir.path}${sep}lib');
      expect(run.kind, 'script');
      expect(run.packageRoot, dir.path);
      expect(run.script, 'x:serve');
    });

    test('java -jar and -cp; shells; PowerShell', () {
      expect(
        classify('/usr/bin/java', ['-Xmx1g', '-jar', 'app.jar']).script,
        at('/work', 'app.jar'),
      );
      final cp = classify('/usr/bin/java', ['-cp', 'lib/*', 'com.x.Main']);
      expect(cp.script, 'com.x.Main');
      expect(cp.packageRoot, 'lib/*');
      expect(classify('/bin/bash', ['-e', 'deploy.sh']).kind, 'interpreter');
      expect(
        classify('/bin/bash', ['deploy.sh']).script,
        at('/work', 'deploy.sh'),
      );
      expect(classify('/bin/sh', ['-c', 'tsm get x']).kind, 'interpreter');
      expect(
        classify('/usr/bin/pwsh', ['-NoProfile', '-File', 'a.ps1']).script,
        at('/work', 'a.ps1'),
      );
      expect(classify('/usr/bin/pwsh', ['-Command', 'x']).kind, 'interpreter');
    });

    test('the user extends the table', () {
      const table = TomSecretsInterpreters({
        ...tomSecretsDefaultInterpreters,
        'lua': TomSecretsInterpreterRule.script,
      });
      final id = tomSecretsIdentityOf(
        const TomSecretsProcessInfo(
          pid: 1,
          exe: '/usr/bin/lua',
          args: ['x.lua'],
          cwd: '/w',
          startTime: 1,
          parentPid: null,
          uid: 0,
        ),
        interpreters: table,
      );
      expect(id.kind, 'script');
    });

    test('a script is its real path, its hash taken; a relative script '
        'without a working directory stays as written', () {
      final dir = Directory.systemTemp.createTempSync('tsmscript');
      addTearDown(() => dir.deleteSync(recursive: true));
      final real = File('${dir.path}${sep}real.py')..writeAsStringSync('x=1');
      final hashes = TomSecretsFileHashes();
      String? linkPath;
      if (!Platform.isWindows) {
        linkPath = '${dir.path}${sep}link.py';
        Link(linkPath).createSync(real.path);
      }
      final id = tomSecretsIdentityOf(
        TomSecretsProcessInfo(
          pid: 1,
          exe: '/usr/bin/python3',
          args: [linkPath == null ? 'real.py' : 'link.py'],
          cwd: dir.path,
          startTime: 1,
          parentPid: null,
          uid: 0,
        ),
        hashes: hashes,
      );
      expect(id.script, real.resolveSymbolicLinksSync());
      expect(id.scriptHash, sha256.convert(utf8.encode('x=1')).toString());
      final unresolved = tomSecretsIdentityOf(
        const TomSecretsProcessInfo(
          pid: 1,
          exe: '/usr/bin/python3',
          args: ['rel.py'],
          cwd: null,
          startTime: 1,
          parentPid: null,
          uid: 0,
        ),
      );
      expect(unresolved.script, 'rel.py');
      expect(unresolved.cwd, '');
      expect(unresolved.complete, isFalse, reason: 'no working directory');
      expect(id.complete, isTrue);
    });
  });

  group('hashes and pins (DP-18)', () {
    test('a hash is cached by path, size and modification time', () async {
      final dir = Directory.systemTemp.createTempSync('tsmhash');
      addTearDown(() => dir.deleteSync(recursive: true));
      final file = File('${dir.path}/tool')..writeAsStringSync('one');
      final hashes = TomSecretsFileHashes();
      final first = hashes.hashOf(file.path);
      expect(hashes.hashOf(file.path), first);
      expect(hashes.computed, 1);
      file.writeAsStringSync('two!');
      expect(hashes.hashOf(file.path), isNot(first));
      expect(hashes.computed, 2);
      expect(hashes.hashOf('${dir.path}/missing'), isNull);
    });

    test('hash: only the recorded hash; off: any; relaxed: a change is '
        'accepted and recorded until the date, then the pin is on', () {
      const hash = TomSecretsPinHash();
      expect(hash.check(recorded: 'a', current: 'a').accepted, isTrue);
      expect(hash.check(recorded: 'a', current: 'b').accepted, isFalse);
      expect(hash.check(recorded: 'a', current: null).accepted, isFalse);
      expect(
        const TomSecretsPinOff().check(recorded: 'a', current: 'b').accepted,
        isTrue,
      );
      final relaxed = TomSecretsPinRelaxed(DateTime.utc(2026, 12, 1));
      final during = relaxed.check(
        recorded: 'a',
        current: 'b',
        now: DateTime.utc(2026, 11, 20),
      );
      expect(during.accepted, isTrue);
      expect(during.record, 'b');
      final same = relaxed.check(
        recorded: 'b',
        current: 'b',
        now: DateTime.utc(2026, 12, 2),
      );
      expect(same.accepted, isTrue);
      expect(same.record, isNull);
      expect(
        relaxed
            .check(recorded: 'b', current: 'c', now: DateTime.utc(2026, 12, 2))
            .accepted,
        isFalse,
      );
      expect(TomSecretsPin.parse('hash'), isA<TomSecretsPinHash>());
      expect(TomSecretsPin.parse('off'), isA<TomSecretsPinOff>());
      final parsed = TomSecretsPin.parse({
        'relaxedUntil': '2026-12-01T00:00:00Z',
      });
      expect((parsed as TomSecretsPinRelaxed).until, DateTime.utc(2026, 12));
      expect(parsed.toJson(), {'relaxedUntil': '2026-12-01T00:00:00.000Z'});
    });
  });

  group('the peer of a real connection on this OS', () {
    test('this process: its executable, arguments, start time and user', () {
      final self = tomSecretsProcessInfo(pid)!;
      expect(self.pid, pid);
      // The `dart` command runs the program in the SDK's VM beside it
      // (`dartvm`): the measured executable is the VM.
      final sdkBin = File(
        Platform.resolvedExecutable,
      ).resolveSymbolicLinksSync().replaceFirst(RegExp(r'[/\\][^/\\]+$'), '');
      expect(self.exe, startsWith(sdkBin));
      expect(
        self.exe.split(RegExp(r'[/\\]')).last.toLowerCase(),
        startsWith('dart'),
      );
      expect(self.args, isNotNull);
      expect(self.cwd, isNotNull);
      expect(self.uid, tomSecretsOwnUid());
      expect(tomSecretsStartTimeOf(pid), self.startTime);
      expect(self.parentPid, isNotNull);
    });

    test('a process that does not exist cannot be measured', () {
      expect(tomSecretsProcessInfo(0x7ffffff0), isNull);
      expect(tomSecretsStartTimeOf(0x7ffffff0), isNull);
    });

    test('a client process connecting: its pid, interpreter, script with '
        'hash, working directory, parent and user', () async {
      final dir = Directory.systemTemp.createTempSync('tsmpeer');
      addTearDown(() => dir.deleteSync(recursive: true));
      final ServerSocket server;
      final String address;
      if (Platform.isWindows) {
        server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        address = 'tcp:${server.port}';
      } else {
        address = '${dir.path}/peer.sock';
        server = await ServerSocket.bind(
          InternetAddress(address, type: InternetAddressType.unix),
          0,
        );
      }
      addTearDown(server.close);
      final accepted = server.first;
      final child = await Process.start(Platform.resolvedExecutable, [
        'test/support/peer_child.dart',
        address,
      ]);
      addTearDown(() async {
        await child.stdin.close();
        child.kill();
      });
      final childPid = int.parse(
        await child.stdout
            .transform(utf8.decoder)
            .transform(const LineSplitter())
            .first,
      );
      final socket = await accepted;
      addTearDown(socket.destroy);

      expect(tomSecretsPeerOf(socket)?.pid, childPid);
      final measured = await TomSecretsSystemPeerMeasurer().measure(socket);
      final id = (measured as TomSecretsPeerMeasured).identity;
      expect(id.pid, childPid);
      expect(id.kind, 'script');
      expect(id.interpreter, id.exe);
      expect(
        id.exe.split(RegExp(r'[/\\]')).last.toLowerCase(),
        startsWith('dart'),
      );
      final script = File('test/support/peer_child.dart');
      expect(id.script, script.resolveSymbolicLinksSync());
      expect(
        id.scriptHash,
        sha256.convert(script.readAsBytesSync()).toString(),
      );
      expect(id.args, contains(address));
      expect(
        id.cwd.toLowerCase(),
        Directory.current.resolveSymbolicLinksSync().toLowerCase(),
      );
      expect(id.uid, tomSecretsOwnUid());
      expect(id.parent?['exe'], isA<String>());
      expect(jsonEncode(id.toJson()), contains('"kind":"script"'));
    });
  });
}
