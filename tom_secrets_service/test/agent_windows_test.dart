// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The ssh-agent on Windows (part-os-integration): the named pipe
/// (`\\.\pipe\tsm-ssh-agent`, here a name of the test's own) served
/// through FFI, its clients measured by `GetNamedPipeClientProcessId`,
/// driven by Win32-OpenSSH's `ssh-add` and `ssh-keygen -Y sign`; a signature
/// approved at a prompt. Run on a Windows host. Demo keys only, made for the
/// test.
@TestOn('windows')
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/agent_keys.dart';
import 'support/setup.dart';

const String _openssh = r'C:\Windows\System32\OpenSSH';

String? _tool(String name) {
  final path = '$_openssh\\$name.exe';
  return File(path).existsSync() ? path : null;
}

final String? _sshAdd = _tool('ssh-add');
final String? _keygen = _tool('ssh-keygen');

void main() {
  test('the pipe: ssh-add -L lists the keys (the client measured), '
      'service.json and status name the pipe, ssh-keygen -Y sign signs '
      'after a prompt and ssh-keygen -Y verify accepts it', () async {
    final demo = await Demo.create();
    final keys = await addDemoKeys(demo);
    // A pipe of the test's own: other test files' services take the
    // default name.
    final pipe = '\\\\.\\pipe\\tsm-ssh-agent-test-$pid';
    await demo.start(
      transport: TomSecretsTransport.tcp,
      policy: null,
      agentPipe: pipe,
    );
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(TomSecretsTransport.tcp),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    await admin.request('subscribe');
    final env = {'SSH_AUTH_SOCK': pipe};

    final info = await demo.runtime(TomSecretsTransport.tcp).readInfo();
    expect(info!['agent'], {'pipe': pipe});
    expect((await admin.request('status'))['agent'], {'pipe': pipe});

    final list = await Process.run(_sshAdd!, ['-L'], environment: env);
    expect(list.exitCode, 0, reason: '${list.stderr}');
    expect('${list.stdout}', contains('Deploy key'));
    expect('${list.stdout}'.trim().split('\n'), hasLength(3));

    final work = Directory.systemTemp.createTempSync('tsm_agent_win');
    addTearDown(() => work.deleteSync(recursive: true));
    File('${work.path}\\k.pub').writeAsStringSync('${keys.deployPublic}\n');
    final data = File('${work.path}\\data')..writeAsStringSync('demo data');
    final needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final signing = Process.run(_keygen!, [
      '-Y',
      'sign',
      '-f',
      '${work.path}\\k.pub',
      '-n',
      'file',
      data.path,
    ], environment: env);
    final event = await needed;
    expect((event['identity']! as Map)['exe'], endsWith('ssh-keygen.exe'));
    expect((event['ssh']! as Map)['purpose'], 'sshsig');
    await admin.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    final r = await signing;
    expect(r.exitCode, 0, reason: '${r.stderr}');
    File(
      '${work.path}\\allowed',
    ).writeAsStringSync('demo@example ${keys.deployPublic}\n');
    final verify = await Process.start(_keygen!, [
      '-Y',
      'verify',
      '-f',
      '${work.path}\\allowed',
      '-I',
      'demo@example',
      '-n',
      'file',
      '-s',
      '${data.path}.sig',
    ]);
    verify.stdin.add(data.readAsBytesSync());
    await verify.stdin.close();
    expect(await verify.exitCode, 0);
  }, skip: _sshAdd == null || _keygen == null ? 'no Win32-OpenSSH' : false);
}
