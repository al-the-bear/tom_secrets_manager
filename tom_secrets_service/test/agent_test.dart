// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The ssh-agent inside the service (part-os-integration, DP-48, DP-49),
/// driven by OpenSSH's own tools against the real endpoint with the
/// system's peer measurement: the keys listed (`ssh-add -L`), a signature
/// approved at a prompt and then by its grant (`ssh-keygen -Y sign`), a
/// `never` grant, KeeAgent's confirmation, the locked agent, and with a
/// user-level `sshd` on 127.0.0.1 the grants per destination host and a
/// forwarded agent. Every decision is audited. Demo keys only, made for the
/// test.
@TestOn('mac-os || linux')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show tomSecretsKnownHostNames, tomSecretsSshFingerprint;
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/agent_keys.dart';
import 'support/setup.dart';

String? _tool(String name) {
  for (final dir in ['/usr/bin', '/usr/sbin', '/usr/local/bin']) {
    if (File('$dir/$name').existsSync()) return '$dir/$name';
  }
  return null;
}

final String? _sshAdd = _tool('ssh-add');
final String? _keygen = _tool('ssh-keygen');
final String? _ssh = _tool('ssh');
final String? _sshd = _tool('sshd');

void main() {
  late Demo demo;
  late DemoKeys keys;
  late TomSecretsAdminClient admin;
  late String socket;
  late Directory work;

  Future<void> start({String? knownHosts}) async {
    await demo.start(policy: null, knownHostsFile: knownHosts);
    admin = await TomSecretsAdminClient.connect(demo.runtime(), demo.adminKey);
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    await admin.request('subscribe');
    socket = demo.runtime().agentSocket;
  }

  setUp(() async {
    demo = await Demo.create();
    keys = await addDemoKeys(demo);
    work = Directory.systemTemp.createTempSync('tsm_agent_work');
    addTearDown(() => work.deleteSync(recursive: true));
  });

  Map<String, String> env() => {'SSH_AUTH_SOCK': socket};

  /// `ssh-keygen -Y sign` with the public key [public] through the agent.
  Future<ProcessResult> sign(String public, {String name = 'k'}) {
    File('${work.path}/$name.pub').writeAsStringSync('$public\n');
    final data = File('${work.path}/data')..writeAsStringSync('demo data');
    final sig = File('${data.path}.sig');
    if (sig.existsSync()) sig.deleteSync();
    return Process.run(_keygen!, [
      '-Y',
      'sign',
      '-f',
      '${work.path}/$name.pub',
      '-n',
      'file',
      data.path,
    ], environment: env());
  }

  Future<bool> verify(String public) async {
    File('${work.path}/allowed').writeAsStringSync('demo@example $public\n');
    final p = await Process.start(_keygen!, [
      '-Y',
      'verify',
      '-f',
      '${work.path}/allowed',
      '-I',
      'demo@example',
      '-n',
      'file',
      '-s',
      '${work.path}/data.sig',
    ]);
    p.stdin.add(File('${work.path}/data').readAsBytesSync());
    await p.stdin.close();
    return await p.exitCode == 0;
  }

  Future<List<Map<String, Object?>>> audit() async {
    final records = await admin.request('audit.query', {
      'from': DateTime.now()
          .subtract(const Duration(hours: 1))
          .toIso8601String(),
      'to': DateTime.now().add(const Duration(hours: 1)).toIso8601String(),
    });
    return [
      for (final r in records['records']! as List)
        (r as Map).cast<String, Object?>(),
    ];
  }

  Future<List<Map<String, Object?>>> grants() async => [
    for (final g in (await admin.request('grants.list'))['grants']! as List)
      (g as Map).cast<String, Object?>(),
  ];

  test('ssh-add -L lists the served keys by their titles; service.json '
      'names the agent; ssh-add -D and adding a key are refused', () async {
    await start();
    final r = await Process.run(_sshAdd!, ['-L'], environment: env());
    expect(r.exitCode, 0, reason: '${r.stderr}');
    final lines = '${r.stdout}'.trim().split('\n');
    expect(lines, hasLength(3));
    expect(
      lines,
      contains(
        '${keys.deployPublic.split(' ').take(2).join(' ')} '
        'Deploy key',
      ),
    );
    final info = await demo.runtime().readInfo();
    expect(info!['agent'], {'socket': socket});
    expect((await admin.request('status'))['agent'], {'socket': socket});
    expect(
      (await Process.run(_sshAdd!, ['-D'], environment: env())).exitCode,
      isNot(0),
    );
  }, skip: _sshAdd == null ? 'no ssh-add' : false);

  test('a signature at a prompt (the key, sshsig, the namespace), always '
      'writes an agent grant, the next one goes without a prompt; both '
      'audited with the key', () async {
    await start();
    final needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final first = sign(keys.deployPublic);
    final event = await needed;
    final fingerprint = tomSecretsSshFingerprint(keys.deployBlob);
    expect(event['refs'], ['team/~${keys.deployUuid}']);
    expect(event['ssh'], {
      'key': fingerprint,
      'keyType': 'ssh-ed25519',
      'title': 'Deploy key',
      'forwarded': false,
      'purpose': 'sshsig',
      'namespace': 'file',
    });
    expect((event['identity']! as Map)['exe'], _keygen);
    await admin.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'always',
      'secret': 'ref',
    });
    final r = await first;
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(await verify(keys.deployPublic), isTrue);
    final grant = (await grants()).singleWhere(
      (g) => (g['secret'] as String).startsWith('ssh-key '),
    );
    expect(grant['secret'], 'ssh-key team/~${keys.deployUuid}');
    expect(grant['subject'], 'exe $_keygen');

    var prompted = false;
    final sub = admin.events.listen((e) {
      if (e['op'] == 'approval_needed') prompted = true;
    });
    final second = await sign(keys.deployPublic);
    await sub.cancel();
    expect(second.exitCode, 0);
    expect(prompted, isFalse);
    final signed = [
      for (final r in await audit())
        if ((r['ssh'] as Map?)?['key'] == fingerprint) r,
    ];
    expect(signed.map((r) => r['outcome']), ['allowed', 'allowed']);
    expect(signed.last['grantId'], grant['id']);
    expect(signed.last['refs'], ['team/~${keys.deployUuid}']);
  }, skip: _keygen == null ? 'no ssh-keygen' : false);

  test('a never grant: the key is not listed to that client', () async {
    await start();
    await admin.request('grants.add', {
      'grant': {
        'host': 'demo-host',
        'subject': 'exe $_sshAdd',
        'secret': 'ssh-key team/~${keys.deployUuid}',
        'decision': 'never',
      },
    });
    final r = await Process.run(_sshAdd!, ['-L'], environment: env());
    expect('${r.stdout}', isNot(contains('Deploy key')));
    expect('${r.stdout}', contains('Confirmed key'));
  }, skip: _sshAdd == null ? 'no ssh-add' : false);

  test("KeeAgent's confirmation: each signature is confirmed though a grant "
      'allows it; a lasting answer is refused', () async {
    await start();
    await admin.request('grants.add', {
      'grant': {
        'host': 'demo-host',
        'subject': 'exe $_keygen',
        'secret': 'ssh-key store team',
        'decision': 'allow',
      },
    });
    final needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final signing = sign(keys.confirmedPublic);
    final event = await needed;
    expect(event['confirmOnly'], isTrue);
    await expectLater(
      admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'always',
        'secret': 'ref',
      }),
      throwsA(isA<TomSecretsAdminException>()),
    );
    await admin.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    expect((await signing).exitCode, 0);
    expect(await verify(keys.confirmedPublic), isTrue);
    // The grant wrote nothing new.
    expect(
      (await grants()).where(
        (g) => (g['secret'] as String).startsWith('ssh-key '),
      ),
      hasLength(1),
    );
  }, skip: _keygen == null ? 'no ssh-keygen' : false);

  test('locked: the kept key is listed to its granted client; its '
      'signature waits for the unlock', () async {
    await start();
    await admin.request('grants.add', {
      'grant': {
        'host': 'demo-host',
        'subject': 'exe $_keygen',
        'secret': 'ssh-key team/~${keys.deployUuid}',
        'decision': 'allow',
      },
    });
    // Unlocked listing keeps the covered keys for the locked agent: the
    // public key with the subjects of its grants, nothing else.
    await Process.run(_sshAdd!, ['-L'], environment: env());
    final kept =
        jsonDecode(
              File(
                '${demo.bootstrap.dataDirectory}/agent_keys.json',
              ).readAsStringSync(),
            )
            as List;
    expect(kept, [
      {
        'key': base64.encode(keys.deployBlob),
        'comment': 'Deploy key',
        'subjects': ['exe $_keygen'],
      },
    ]);
    await admin.request('lock');
    final lockedList = await Process.run(_sshAdd!, ['-L'], environment: env());
    // ssh-add holds no grant: nothing while locked.
    expect('${lockedList.stdout}', isNot(contains('Deploy key')));
    final unlockNeeded = admin.events.firstWhere(
      (e) => e['op'] == 'unlock_needed',
    );
    final signing = sign(keys.deployPublic);
    await unlockNeeded;
    await admin.unlock(primaryPassword);
    final r = await signing;
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(await verify(keys.deployPublic), isTrue);
  }, skip: _keygen == null || _sshAdd == null ? 'no ssh-keygen' : false);

  test(
    'sshd: a grant limited to another host prompts; always for this host '
    'writes a host grant that answers; a forwarded agent gets no key '
    'without a forwarding grant, and with one each signature is '
    'confirmed (DP-49)',
    () async {
      final dir = work.path;
      final hostKey = '$dir/host';
      final hk = await Process.run(_keygen!, [
        '-t',
        'ed25519',
        '-q',
        '-N',
        '',
        '-C',
        'host',
        '-f',
        hostKey,
      ]);
      expect(hk.exitCode, 0);
      final hostBlob = base64.decode(
        File('$hostKey.pub').readAsStringSync().split(' ')[1],
      );
      final hostFingerprint = tomSecretsSshFingerprint(hostBlob);
      File('$dir/authorized_keys').writeAsStringSync('${keys.deployPublic}\n');
      final port = 43000 + (pid % 1000);
      File('$dir/sshd_config').writeAsStringSync('''
Port $port
ListenAddress 127.0.0.1
HostKey $hostKey
AuthorizedKeysFile $dir/authorized_keys
PidFile $dir/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowAgentForwarding yes
''');
      final known = '$dir/known_hosts';
      await start(knownHosts: known);
      final sshd = await Process.start(_sshd!, [
        '-D',
        '-e',
        '-f',
        '$dir/sshd_config',
      ]);
      addTearDown(sshd.kill);
      final log = StringBuffer();
      sshd.stderr.transform(utf8.decoder).listen(log.write);
      await Future<void>.delayed(const Duration(milliseconds: 800));
      List<String> args(String agent) => [
        '-F',
        '/dev/null',
        '-o',
        'StrictHostKeyChecking=no',
        '-o',
        'UserKnownHostsFile=$known',
        '-o',
        'IdentityAgent=$agent',
        '-o',
        'BatchMode=yes',
        '-p',
        '$port',
      ];
      await admin.request('grants.add', {
        'grant': {
          'host': 'demo-host',
          'subject': 'exe $_ssh',
          'secret': 'ssh-key host SHA256:another-host team/~${keys.deployUuid}',
          'decision': 'allow',
        },
      });
      var needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
      final first = Process.run(_ssh!, [
        ...args(socket),
        '127.0.0.1',
        'echo',
        'demo-ok',
      ]);
      final event = await needed;
      final ssh = (event['ssh']! as Map).cast<String, Object?>();
      expect(ssh['host'], hostFingerprint);
      expect(ssh['purpose'], 'userauth');
      expect(ssh['forwarded'], isFalse);
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'always',
        'secret': 'ref',
        'sshHost': true,
      });
      final r = await first;
      expect('${r.stdout}'.trim(), 'demo-ok', reason: '${r.stderr}$log');
      expect(
        (await grants()).map((g) => g['secret']),
        contains('ssh-key host $hostFingerprint team/~${keys.deployUuid}'),
      );
      // known_hosts now names the host: the next prompt shows its name.
      expect(
        tomSecretsKnownHostNames(File(known).readAsStringSync(), hostBlob),
        contains('[127.0.0.1]:$port'),
      );

      // ssh -A, and ssh again on the far side.
      String nested() => [
        'ssh',
        ...args(r'$SSH_AUTH_SOCK').map((a) => "'$a'"),
        '127.0.0.1',
        'echo',
        'demo-nested',
      ].join(' ');
      var prompted = false;
      final sub = admin.events.listen((e) {
        if (e['op'] == 'approval_needed') prompted = true;
      });
      final refused = await Process.run(_ssh!, [
        ...args(socket),
        '-A',
        '127.0.0.1',
        nested(),
      ]);
      await sub.cancel();
      expect('${refused.stdout}', isNot(contains('demo-nested')));
      expect(prompted, isFalse, reason: 'refused without a prompt');

      await admin.request('grants.add', {
        'grant': {
          'host': 'demo-host',
          'subject': 'exe $_ssh',
          'secret':
              'ssh-key host $hostFingerprint forward team/~${keys.deployUuid}',
          'decision': 'allow',
        },
      });
      needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
      final forwarded = Process.run(_ssh!, [
        ...args(socket),
        '-A',
        '127.0.0.1',
        nested(),
      ]);
      final confirm = await needed;
      expect(confirm['confirmOnly'], isTrue);
      expect((confirm['ssh']! as Map)['forwarded'], isTrue);
      expect(
        (confirm['ssh']! as Map)['hostNames'],
        contains('[127.0.0.1]:$port'),
      );
      await admin.request('approve', {
        'approvalId': confirm['approvalId'],
        'decision': 'once',
        'secret': 'ref',
      });
      final f = await forwarded;
      expect('${f.stdout}'.trim(), 'demo-nested', reason: '${f.stderr}$log');
      final records = await audit();
      expect(
        records.where((r) => (r['ssh'] as Map?)?['forwarded'] == true),
        isNotEmpty,
      );
    },
    skip: _sshd == null || _ssh == null || _keygen == null ? 'no sshd' : false,
  );
}
