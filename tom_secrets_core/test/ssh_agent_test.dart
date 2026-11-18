// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The agent's side of SSH (part-os-integration): `bcrypt_pbkdf`, private
/// key files decoded (checked against `ssh-keygen -y` and keys OpenSSL
/// encrypts, where they are installed), signatures made and checked, the
/// agent protocol against OpenSSH's own tools (`ssh-add -L`,
/// `ssh-keygen -Y sign` through the agent), and `session-bind` with a
/// forwarded agent against a user-level `sshd` on 127.0.0.1. Demo keys
/// only, made for the test.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

String? _tool(String name) {
  for (final dir in [
    '/usr/bin',
    '/usr/sbin',
    '/usr/local/bin',
    '/opt/homebrew/bin',
  ]) {
    final path = '$dir/$name';
    if (File(path).existsSync()) return path;
  }
  return null;
}

final String? _keygen = _tool('ssh-keygen');
final String? _openssl = _tool('openssl');
final String? _sshAdd = _tool('ssh-add');
final String? _ssh = _tool('ssh');
final String? _sshd = _tool('sshd');

String _run(String exe, List<String> args, {Map<String, String>? env}) {
  final r = Process.runSync(exe, args, environment: env);
  if (r.exitCode != 0) {
    fail('$exe ${args.join(' ')}: ${r.stdout}${r.stderr}');
  }
  return '${r.stdout}';
}

/// Runs [exe] without blocking the isolate (the agent under test answers
/// it from the same isolate).
Future<String> _runAsync(
  String exe,
  List<String> args, {
  Map<String, String>? env,
}) async {
  final r = await Process.run(exe, args, environment: env);
  if (r.exitCode != 0) {
    fail('$exe ${args.join(' ')}: ${r.stdout}${r.stderr}');
  }
  return '${r.stdout}';
}

/// The public key blob `ssh-keygen -y` prints for [file].
Uint8List _publicBlob(String file, [String? pass]) {
  final line = _run(_keygen!, ['-y', '-f', file, '-P', pass ?? '']);
  return base64.decode(line.trim().split(' ')[1]);
}

/// An agent backend serving [keys] (decoded), signing everything, recording
/// the requests.
final class _Backend implements TomSecretsSshAgentBackend {
  _Backend(this.keys);

  final List<TomSecretsSshPrivateKey> keys;
  final List<TomSecretsSshSignRequest> requests = [];

  @override
  Future<List<TomSecretsSshAgentIdentity>> identities(
    List<TomSecretsSshBinding> bindings,
  ) async => [
    for (final k in keys)
      TomSecretsSshAgentIdentity(k.publicKeyBlob, k.comment),
  ];

  @override
  Future<Uint8List?> sign(TomSecretsSshSignRequest request) async {
    requests.add(request);
    for (final k in keys) {
      if (_same(k.publicKeyBlob, request.publicKeyBlob)) {
        try {
          return await k.sign(request.data, flags: request.flags);
        } on StateError {
          return null;
        }
      }
    }
    return null;
  }
}

bool _same(List<int> a, List<int> b) =>
    a.length == b.length && base64.encode(a) == base64.encode(b);

/// Serves [backend] on a Unix socket at [path].
Future<ServerSocket> _serve(
  String path,
  TomSecretsSshAgentBackend backend,
) async {
  final server = await ServerSocket.bind(
    InternetAddress(path, type: InternetAddressType.unix),
    0,
  );
  server.listen((socket) {
    final framer = TomSecretsSshAgentFramer();
    final connection = TomSecretsSshAgentConnection(backend);
    var queue = Future<void>.value();
    socket.listen(
      (bytes) {
        final List<Uint8List> messages;
        try {
          messages = framer.add(bytes);
        } on FormatException {
          socket.destroy();
          return;
        }
        for (final m in messages) {
          queue = queue.then((_) async {
            socket.add(
              TomSecretsSshAgentFramer.frame(await connection.handle(m)),
            );
          });
        }
      },
      onError: (_) {},
      cancelOnError: true,
    );
  });
  return server;
}

void main() {
  _modelTests();

  test('bcrypt_pbkdf: the OpenBSD vector', () {
    final key = tomSecretsBcryptPbkdf(
      utf8.encode('password'),
      utf8.encode('salt'),
      32,
      4,
    );
    expect(
      key.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      '5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9',
    );
  });

  group('key files', () {
    late Directory dir;

    setUp(() => dir = Directory.systemTemp.createTempSync('tsm_agent_keys'));
    tearDown(() => dir.deleteSync(recursive: true));

    String keyFile(String name, List<String> args, {String pass = ''}) {
      final path = '${dir.path}/$name';
      _run(_keygen!, [...args, '-q', '-N', pass, '-C', 'demo', '-f', path]);
      return path;
    }

    final specs = <(String, List<String>, String)>[
      ('ed25519', ['-t', 'ed25519'], ''),
      ('ed25519 encrypted (aes256-ctr)', ['-t', 'ed25519'], 'demo-pass'),
      (
        'ed25519 encrypted (aes256-gcm)',
        ['-t', 'ed25519', '-Z', 'aes256-gcm@openssh.com'],
        'demo-pass',
      ),
      (
        'ed25519 encrypted (aes128-cbc)',
        ['-t', 'ed25519', '-Z', 'aes128-cbc'],
        'demo-pass',
      ),
      ('ecdsa 256', ['-t', 'ecdsa', '-b', '256'], ''),
      ('ecdsa 384 encrypted', ['-t', 'ecdsa', '-b', '384'], 'demo-pass'),
      ('ecdsa 521', ['-t', 'ecdsa', '-b', '521'], ''),
      ('rsa 2048', ['-t', 'rsa', '-b', '2048'], ''),
      ('rsa 2048 encrypted', ['-t', 'rsa', '-b', '2048'], 'demo-pass'),
      ('rsa PEM (PKCS#1)', ['-t', 'rsa', '-b', '2048', '-m', 'PEM'], ''),
      ('ecdsa PEM (SEC1)', ['-t', 'ecdsa', '-b', '256', '-m', 'PEM'], ''),
      ('rsa PKCS#8', ['-t', 'rsa', '-b', '2048', '-m', 'PKCS8'], ''),
      ('ecdsa PKCS#8', ['-t', 'ecdsa', '-b', '384', '-m', 'PKCS8'], ''),
    ];
    for (final (name, args, pass) in specs) {
      test(
        '$name: decoded as ssh-keygen reads it, signs and verifies',
        () async {
          final path = keyFile('k', args, pass: pass);
          final bytes = File(path).readAsBytesSync();
          final key = await TomSecretsSshPrivateKey.decode(
            bytes,
            passphrase: pass.isEmpty ? null : pass,
          );
          expect(key.publicKeyBlob, _publicBlob(path, pass));
          if (args.contains('-m')) {
            expect(key.comment, '');
          } else {
            expect(key.comment, 'demo');
          }
          final data = utf8.encode('demo data to sign');
          final flags = key.keyType == 'ssh-rsa'
              ? TomSecretsSshSignFlags.rsaSha512
              : 0;
          final sig = await key.sign(data, flags: flags);
          expect(
            await tomSecretsSshVerify(key.publicKeyBlob, sig, data),
            isTrue,
          );
          expect(
            await tomSecretsSshVerify(key.publicKeyBlob, sig, [...data, 1]),
            isFalse,
          );
          if (key.keyType == 'ssh-rsa') {
            final sha256 = await key.sign(
              data,
              flags: TomSecretsSshSignFlags.rsaSha256,
            );
            expect(utf8.decode(sha256.sublist(4, 16)), 'rsa-sha2-256');
            expect(
              await tomSecretsSshVerify(key.publicKeyBlob, sha256, data),
              isTrue,
            );
            // SHA-1 is refused.
            expect(() => key.sign(data), throwsStateError);
          }
          if (pass.isNotEmpty) {
            await expectLater(
              TomSecretsSshPrivateKey.decode(bytes),
              throwsA(
                isA<TomSecretsSshKeyException>().having(
                  (e) => e.problem,
                  'problem',
                  TomSecretsSshKeyProblem.passphraseNeeded,
                ),
              ),
            );
            await expectLater(
              TomSecretsSshPrivateKey.decode(bytes, passphrase: 'wrong'),
              throwsA(
                isA<TomSecretsSshKeyException>().having(
                  (e) => e.problem,
                  'problem',
                  TomSecretsSshKeyProblem.wrongPassphrase,
                ),
              ),
            );
          }
          key.dispose();
        },
        skip: _keygen == null ? 'no ssh-keygen' : false,
      );
    }

    final opensslSpecs = <(String, String, List<String>)>[
      ('PKCS#1 AES-128-CBC (DEK-Info)', 'rsa', ['-aes128']),
      ('PKCS#1 DES-EDE3-CBC (DEK-Info)', 'rsa', ['-des3']),
      ('SEC1 AES-256-CBC (DEK-Info)', 'ec', ['-aes256']),
    ];
    for (final (name, kind, cipher) in opensslSpecs) {
      test('$name: an OpenSSL-encrypted key', () async {
        final plain = keyFile(
          'plain',
          kind == 'rsa'
              ? ['-t', 'rsa', '-b', '2048', '-m', 'PEM']
              : ['-t', 'ecdsa', '-b', '256', '-m', 'PEM'],
        );
        final out = '${dir.path}/enc';
        _run(_openssl!, [
          kind,
          '-in',
          plain,
          ...cipher,
          '-passout',
          'pass:demo-pass',
          '-out',
          out,
        ]);
        expect(File(out).readAsStringSync(), contains('DEK-Info'));
        final key = await TomSecretsSshPrivateKey.decode(
          File(out).readAsBytesSync(),
          passphrase: 'demo-pass',
        );
        expect(key.publicKeyBlob, _publicBlob(plain));
        await expectLater(
          TomSecretsSshPrivateKey.decode(
            File(out).readAsBytesSync(),
            passphrase: 'wrong',
          ),
          throwsA(isA<TomSecretsSshKeyException>()),
        );
      }, skip: _keygen == null || _openssl == null ? 'no openssl' : false);
    }

    test('PKCS#8 encrypted with PBES2 (PBKDF2, AES-256-CBC)', () async {
      final plain = keyFile('plain', ['-t', 'ecdsa', '-b', '256', '-m', 'PEM']);
      final out = '${dir.path}/enc8';
      _run(_openssl!, [
        'pkcs8',
        '-topk8',
        '-in',
        plain,
        '-v2',
        'aes-256-cbc',
        '-passout',
        'pass:demo-pass',
        '-out',
        out,
      ]);
      expect(File(out).readAsStringSync(), contains('ENCRYPTED PRIVATE KEY'));
      final key = await TomSecretsSshPrivateKey.decode(
        File(out).readAsBytesSync(),
        passphrase: 'demo-pass',
      );
      expect(key.publicKeyBlob, _publicBlob(plain));
    }, skip: _keygen == null || _openssl == null ? 'no openssl' : false);

    test(
      'Ed25519 PKCS#8 (no public key in the file) and a generated key',
      () async {
        final generated = await tomSecretsGenerateSshKey(comment: 'demo');
        final key = await TomSecretsSshPrivateKey.decode(generated.privateKey);
        expect(key.publicKeyBlob, generated.info.publicKeyBlob);
        expect(key.comment, 'demo');
        // RFC 8410 test key (a published example, not a secret).
        const pkcs8 =
            '-----BEGIN PRIVATE KEY-----\n'
            'MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n'
            '-----END PRIVATE KEY-----\n';
        final ed = await TomSecretsSshPrivateKey.decode(utf8.encode(pkcs8));
        expect(ed.keyType, 'ssh-ed25519');
        expect(
          base64.encode(ed.publicKeyBlob.sublist(ed.publicKeyBlob.length - 32)),
          base64.encode([
            0x19, 0xbf, 0x44, 0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, //
            0xc1, 0x67, 0xdc, 0x3b, 0x96, 0xc8, 0x50, 0x86, 0xaa, 0x30, 0xb6,
            0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31, 0x66, 0xe1,
          ]),
        );
      },
    );

    test('not a key, DSA', () async {
      await expectLater(
        TomSecretsSshPrivateKey.decode(utf8.encode('hello')),
        throwsA(
          isA<TomSecretsSshKeyException>().having(
            (e) => e.problem,
            'problem',
            TomSecretsSshKeyProblem.malformed,
          ),
        ),
      );
      await expectLater(
        TomSecretsSshPrivateKey.decode(
          utf8.encode(
            '-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n',
          ),
        ),
        throwsA(
          isA<TomSecretsSshKeyException>().having(
            (e) => e.problem,
            'problem',
            TomSecretsSshKeyProblem.unsupported,
          ),
        ),
      );
    });
  });

  group('the agent protocol', () {
    late Directory dir;
    late List<TomSecretsSshPrivateKey> keys;
    late _Backend backend;
    late ServerSocket server;
    late String socket;

    setUp(() async {
      dir = Directory.systemTemp.createTempSync('tsm_agent');
      keys = [];
      for (final (name, args) in [
        ('ed', ['-t', 'ed25519']),
        ('ec', ['-t', 'ecdsa', '-b', '256']),
        ('rsa', ['-t', 'rsa', '-b', '2048']),
      ]) {
        final path = '${dir.path}/$name';
        _run(_keygen!, [
          ...args,
          '-q',
          '-N',
          '',
          '-C',
          'demo-$name',
          '-f',
          path,
        ]);
        keys.add(
          await TomSecretsSshPrivateKey.decode(File(path).readAsBytesSync()),
        );
      }
      backend = _Backend(keys);
      socket = '${dir.path}/agent.sock';
      server = await _serve(socket, backend);
    });

    tearDown(() async {
      await server.close();
      dir.deleteSync(recursive: true);
    });

    test(
      'ssh-add -L lists the keys; ssh-add and ssh-add -D are refused',
      () async {
        final env = {'SSH_AUTH_SOCK': socket};
        final r = await Process.run(_sshAdd!, ['-L'], environment: env);
        expect(r.exitCode, 0, reason: '${r.stderr}');
        final lines = '${r.stdout}'.trim().split('\n');
        expect(lines, hasLength(3));
        expect(lines[0], endsWith('demo-ed'));
        expect(lines[2], startsWith('ssh-rsa '));
        final d = await Process.run(_sshAdd!, ['-D'], environment: env);
        expect(d.exitCode, isNot(0));
        final add = await Process.run(_sshAdd!, [
          '${dir.path}/ed',
        ], environment: env);
        expect(add.exitCode, isNot(0));
      },
      skip: _sshAdd == null ? 'no ssh-add' : false,
    );

    test('ssh-keygen -Y sign signs through the agent with every key type; '
        'ssh-keygen -Y verify accepts the signatures', () async {
      final env = {'SSH_AUTH_SOCK': socket};
      final data = File('${dir.path}/data')..writeAsStringSync('demo');
      for (final name in ['ed', 'ec', 'rsa']) {
        File('${dir.path}/data.sig').deleteIfExists();
        // Only the public key is on disk for ssh-keygen: the private one
        // signs in the agent.
        File('${dir.path}/$name').deleteSync();
        await _runAsync(_keygen!, [
          '-Y',
          'sign',
          '-f',
          '${dir.path}/$name.pub',
          '-n',
          'file',
          data.path,
        ], env: env);
        final pub = File('${dir.path}/$name.pub').readAsStringSync().trim();
        File('${dir.path}/allowed').writeAsStringSync('demo@example $pub\n');
        final verify = await Process.start(_keygen!, [
          '-Y',
          'verify',
          '-f',
          '${dir.path}/allowed',
          '-I',
          'demo@example',
          '-n',
          'file',
          '-s',
          '${dir.path}/data.sig',
        ]);
        verify.stdin.add(data.readAsBytesSync());
        await verify.stdin.close();
        expect(await verify.exitCode, 0, reason: name);
      }
      expect(backend.requests, hasLength(3));
      expect(
        backend.requests.map((r) => r.purpose),
        everyElement(TomSecretsSshSignPurpose.sshSig),
      );
      expect(backend.requests.first.namespace, 'file');
      expect(backend.requests.last.flags, TomSecretsSshSignFlags.rsaSha512);
    }, skip: _keygen == null ? 'no ssh-keygen' : false);

    test('framing: a message over the limit is refused', () {
      final framer = TomSecretsSshAgentFramer();
      expect(() => framer.add([0, 0x10, 0, 0, 11]), throwsFormatException);
      final ok = TomSecretsSshAgentFramer();
      expect(ok.add([0, 0, 0, 1]), isEmpty);
      expect(ok.add([11, 0, 0]), hasLength(1));
    });

    test(
      'session-bind: a forged host-key signature is refused; a bound '
      'connection refuses a user authentication of another session',
      () async {
        final host = keys.first;
        final connection = TomSecretsSshAgentConnection(backend);
        final sid = Uint8List.fromList(List.generate(32, (i) => i));
        Uint8List bind(List<int> sig, bool forwarded) =>
            (_Writer()
                  ..byte(TomSecretsSshAgentMessage.extension)
                  ..text('session-bind@openssh.com')
                  ..bytes(host.publicKeyBlob)
                  ..bytes(sid)
                  ..bytes(sig)
                  ..byte(forwarded ? 1 : 0))
                .done;
        final forged = await keys[1].sign(sid);
        expect((await connection.handle(bind(forged, false)))[0], 5);
        final good = await host.sign(sid);
        expect((await connection.handle(bind(good, false)))[0], 6);
        expect(connection.bindings.single.forwarded, isFalse);
        // After a binding for authentication, no other one.
        final other = Uint8List.fromList(List.generate(32, (i) => 255 - i));
        final otherSig = await host.sign(other);
        final second =
            (_Writer()
                  ..byte(TomSecretsSshAgentMessage.extension)
                  ..text('session-bind@openssh.com')
                  ..bytes(host.publicKeyBlob)
                  ..bytes(other)
                  ..bytes(otherSig)
                  ..byte(0))
                .done;
        expect((await connection.handle(second))[0], 5);

        Uint8List userAuth(List<int> session) =>
            (_Writer()
                  ..bytes(session)
                  ..byte(50)
                  ..text('demo')
                  ..text('ssh-connection')
                  ..text('publickey')
                  ..byte(1)
                  ..text('ssh-ed25519')
                  ..bytes(host.publicKeyBlob))
                .done;
        Uint8List signRequest(List<int> data) =>
            (_Writer()
                  ..byte(TomSecretsSshAgentMessage.signRequest)
                  ..bytes(host.publicKeyBlob)
                  ..bytes(data)
                  ..uint32(0))
                .done;
        expect((await connection.handle(signRequest(userAuth(other))))[0], 5);
        final answer = await connection.handle(signRequest(userAuth(sid)));
        expect(answer[0], TomSecretsSshAgentMessage.signResponse);
        final request = backend.requests.last;
        expect(request.purpose, TomSecretsSshSignPurpose.userAuth);
        expect(
          request.destination!.hostKeyFingerprint,
          tomSecretsSshFingerprint(host.publicKeyBlob),
        );
        expect(request.forwarded, isFalse);
        // Messages the agent does not do.
        for (final type in [17, 18, 19, 22, 23, 25]) {
          expect((await connection.handle(Uint8List.fromList([type])))[0], 5);
        }
      },
    );
  });

  test(
    'sshd: ssh authenticates through the agent with a bound session; a '
    'forwarded agent is seen as forwarded',
    () async {
      final dir = Directory.systemTemp.createTempSync('tsm_sshd');
      Process? sshd;
      ServerSocket? server;
      try {
        String key(String name) {
          final path = '${dir.path}/$name';
          _run(_keygen!, [
            '-t',
            'ed25519',
            '-q',
            '-N',
            '',
            '-C',
            name,
            '-f',
            path,
          ]);
          return path;
        }

        final hostKey = key('host');
        final userKey = key('user');
        File(
          '${dir.path}/authorized_keys',
        ).writeAsStringSync(File('$userKey.pub').readAsStringSync());
        final port = 42000 + (pid % 1000);
        File('${dir.path}/sshd_config').writeAsStringSync('''
Port $port
ListenAddress 127.0.0.1
HostKey $hostKey
AuthorizedKeysFile ${dir.path}/authorized_keys
PidFile ${dir.path}/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowAgentForwarding yes
''');
        final backend = _Backend([
          await TomSecretsSshPrivateKey.decode(File(userKey).readAsBytesSync()),
        ]);
        final socket = '${dir.path}/agent.sock';
        server = await _serve(socket, backend);
        sshd = await Process.start(_sshd!, [
          '-D',
          '-e',
          '-f',
          '${dir.path}/sshd_config',
        ]);
        final log = StringBuffer();
        sshd.stderr.transform(utf8.decoder).listen(log.write);
        await Future<void>.delayed(const Duration(milliseconds: 800));
        final known = '${dir.path}/known_hosts';
        List<String> sshArgs(String agent) => [
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
        final first = await Process.run(_ssh!, [
          ...sshArgs(socket),
          '127.0.0.1',
          'echo',
          'demo-ok',
        ]);
        if (first.exitCode == 255 && '$log'.contains('Privilege separation')) {
          markTestSkipped('sshd does not run as this user');
          return;
        }
        expect(
          '${first.stdout}'.trim(),
          'demo-ok',
          reason: '${first.stderr}$log',
        );
        final direct = backend.requests.single;
        expect(direct.purpose, TomSecretsSshSignPurpose.userAuth);
        expect(direct.forwarded, isFalse);
        expect(
          direct.destination!.hostKeyFingerprint,
          tomSecretsSshFingerprint(_publicBlob(hostKey)),
        );
        expect(
          tomSecretsKnownHostNames(
            File(known).readAsStringSync(),
            _publicBlob(hostKey),
          ),
          contains('[127.0.0.1]:$port'),
        );

        // ssh -A, and on the far side ssh again: the inner authentication
        // reaches the agent over the forwarded connection.
        final inner = [
          'ssh',
          ...sshArgs(r'$SSH_AUTH_SOCK').map((a) => "'$a'"),
          '127.0.0.1',
          'echo',
          'demo-nested',
        ].join(' ');
        final nested = await Process.run(_ssh!, [
          ...sshArgs(socket),
          '-A',
          '127.0.0.1',
          inner,
        ]);
        expect(
          '${nested.stdout}'.trim(),
          'demo-nested',
          reason: '${nested.stderr}$log',
        );
        final forwarded = backend.requests.last;
        expect(forwarded.forwarded, isTrue);
        expect(forwarded.bindings, hasLength(2));
        expect(forwarded.bindings.first.forwarded, isTrue);
      } finally {
        sshd?.kill();
        await server?.close();
        dir.deleteSync(recursive: true);
      }
    },
    skip: _sshd == null || _ssh == null || _keygen == null ? 'no sshd' : false,
  );
}

void _modelTests() {
  group('grants, serving, known_hosts, the vault setting', () {
    test('the agent grant secret: written and read back; forwarding only '
        'for one key and named hosts', () {
      const one = TomSecretsSshGrantSecret(
        'personal/Ssh/Deploy key',
        hosts: ['SHA256:aaa', 'SHA256:bbb'],
        forward: true,
      );
      expect(
        one.text,
        'ssh-key host SHA256:aaa,SHA256:bbb forward personal/Ssh/Deploy key',
      );
      final back = TomSecretsSshGrantSecret.parse(one.text)!;
      expect(back.target, 'personal/Ssh/Deploy key');
      expect(back.hosts, ['SHA256:aaa', 'SHA256:bbb']);
      expect(back.forward, isTrue);
      expect(back.valid, isTrue);
      expect(
        TomSecretsSshGrantSecret.parse('ssh-key store personal')!.target,
        'store personal',
      );
      expect(TomSecretsSshGrantSecret.parse('ssh-key all')!.hosts, isEmpty);
      expect(TomSecretsSshGrantSecret.parse('store personal'), isNull);
      expect(TomSecretsSshGrantSecret.parse('ssh-key host'), isNull);
      expect(
        const TomSecretsSshGrantSecret('all', forward: true).valid,
        isFalse,
      );
      expect(
        const TomSecretsSshGrantSecret('x/y', forward: true).valid,
        isFalse,
      );
    });

    test('what the agent serves: typed keys allowed and added; the reasons '
        'for the others', () async {
      final file = newTestVault(demoCredentials, 'personal');
      final key = (await tomSecretsGenerateSshKey(comment: 'demo')).privateKey;
      KdbxEntry add({String type = 'ssh-key', bool withKey = true}) {
        final root = file.body.rootGroup;
        final e = KdbxEntry.create(file, root)
          ..setString(TomSecretsEntryFields.type, PlainValue(type));
        root.addEntry(e);
        if (withKey) {
          tomSecretsWriteSshKey(
            e,
            attachmentName: 'id_ed25519',
            privateKey: key,
          );
        }
        return e;
      }

      expect(
        tomSecretsSshAgentStateOf(add()).state,
        TomSecretsSshAgentServing.served,
      );
      final note = add(withKey: false)
        ..setString(TomSecretsEntryFields.type, PlainValue('note'));
      expect(
        tomSecretsSshAgentStateOf(note).state,
        TomSecretsSshAgentServing.notSshKey,
      );
      expect(
        tomSecretsSshAgentStateOf(add(withKey: false)).state,
        TomSecretsSshAgentServing.noKey,
      );
      KdbxEntry withSettings(TomSecretsKeeAgentSettings settings) {
        final e = add();
        e.removeBinary(const KdbxKey(tomSecretsKeeAgentSettingsName));
        e.createBinary(
          isProtected: false,
          name: tomSecretsKeeAgentSettingsName,
          bytes: settings.toBytes(),
        );
        return e;
      }

      expect(
        tomSecretsSshAgentStateOf(
          withSettings(
            const TomSecretsKeeAgentSettings(
              allowUseOfSshKey: false,
              attachmentName: 'id_ed25519',
            ),
          ),
        ).state,
        TomSecretsSshAgentServing.notAllowed,
      );
      expect(
        tomSecretsSshAgentStateOf(
          withSettings(
            const TomSecretsKeeAgentSettings(
              addAtDatabaseOpen: false,
              attachmentName: 'id_ed25519',
            ),
          ),
        ).state,
        TomSecretsSshAgentServing.notAdded,
      );
      final confirmed = tomSecretsSshAgentStateOf(
        withSettings(
          const TomSecretsKeeAgentSettings(
            useConfirmConstraintWhenAdding: true,
            attachmentName: 'id_ed25519',
          ),
        ),
      );
      expect(confirmed.state, TomSecretsSshAgentServing.served);
      expect(confirmed.confirm, isTrue);
      expect(
        tomSecretsSshAgentStateOf(
          withSettings(
            const TomSecretsKeeAgentSettings(
              selectedType: 'file',
              fileName: '/demo/id_rsa',
            ),
          ),
        ).state,
        TomSecretsSshAgentServing.keyFileOutside,
      );
      const encrypted =
          '-----BEGIN RSA PRIVATE KEY-----\n'
          'Proc-Type: 4,ENCRYPTED\n'
          'DEK-Info: AES-128-CBC,00000000000000000000000000000000\n\n'
          'AAAA\n'
          '-----END RSA PRIVATE KEY-----\n';
      final locked = add(withKey: false);
      tomSecretsWriteSshKey(
        locked,
        attachmentName: 'id_rsa',
        privateKey: Uint8List.fromList(utf8.encode(encrypted)),
      );
      expect(
        tomSecretsSshAgentStateOf(locked).state,
        TomSecretsSshAgentServing.passphraseMissing,
      );
      locked.setString(
        KdbxKeyCommon.PASSWORD,
        ProtectedValue.fromString('demo-pass'),
      );
      expect(
        tomSecretsSshAgentStateOf(locked).state,
        TomSecretsSshAgentServing.served,
      );
    });

    test('KeeAgent settings: read and written back with a flag changed, '
        'the rest kept', () async {
      final file = newTestVault(demoCredentials, 'personal');
      final root = file.body.rootGroup;
      final entry = KdbxEntry.create(file, root);
      root.addEntry(entry);
      final key = (await tomSecretsGenerateSshKey(comment: 'demo')).privateKey;
      tomSecretsWriteSshKey(entry, attachmentName: 'id_x', privateKey: key);
      final before = tomSecretsKeeAgentSettingsOf(entry)!;
      expect(before.useConfirmConstraintWhenAdding, isFalse);
      tomSecretsWriteKeeAgentSettings(
        entry,
        before.copyWith(useConfirmConstraintWhenAdding: true),
      );
      final after = tomSecretsKeeAgentSettingsOf(entry)!;
      expect(after.useConfirmConstraintWhenAdding, isTrue);
      expect(after.attachmentName, 'id_x');
      expect(tomSecretsSshAgentStateOf(entry).confirm, isTrue);
    });

    test('known_hosts: the plain names of a host key; hashed, revoked and '
        'wildcard lines left out', () {
      final key = base64.decode(
        'AAAAC3NzaC1lZDI1NTE5AAAAIDemoHostKeyDemoHostKeyDemoHostKey00',
      );
      final k = base64.encode(key);
      final text = [
        'demo.example,192.0.2.7 ssh-ed25519 $k',
        '|1|c2FsdA==|aGFzaA== ssh-ed25519 $k',
        '@revoked old.example ssh-ed25519 $k',
        '*.example ssh-ed25519 $k',
        '[demo.example]:2222 ssh-ed25519 $k',
        'other.example ssh-ed25519 AAAAother',
      ].join('\n');
      expect(tomSecretsKnownHostNames(text, key), [
        'demo.example',
        '192.0.2.7',
        '[demo.example]:2222',
      ]);
    });

    test('the vault setting tsm.ssh-confirm is read and written', () {
      final file = newTestVault(demoCredentials, 'personal');
      expect(TomSecretsMetadata.read(file).sshConfirm, isFalse);
      TomSecretsMetadata.read(file).copyWith(sshConfirm: true).writeTo(file);
      expect(TomSecretsMetadata.read(file).sshConfirm, isTrue);
      expect(
        TomSecretsMetadata.read(file).copyWith(purpose: 'x').sshConfirm,
        isTrue,
      );
    });
  });
}

/// Writes agent messages in the tests.
final class _Writer {
  final BytesBuilder _b = BytesBuilder();

  void byte(int v) => _b.addByte(v);

  void uint32(int v) =>
      _b.add((ByteData(4)..setUint32(0, v)).buffer.asUint8List());

  void bytes(List<int> v) {
    uint32(v.length);
    _b.add(v);
  }

  void text(String v) => bytes(utf8.encode(v));

  Uint8List get done => _b.toBytes();
}

extension on File {
  void deleteIfExists() {
    if (existsSync()) deleteSync();
  }
}
