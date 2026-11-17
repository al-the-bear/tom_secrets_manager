// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A further vault created beside the primary (`vault.create`, protocol.md
/// 6.4) with `file:` vaults: the app makes the new file, the service writes
/// it where it lives, lists it with its keys in the primary and serves it;
/// a request that does not fit is refused and changes nothing. The
/// `github:` cases are in github_test.dart. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

const _opsPassword = 'ops-demo-pw';

/// A new vault [name] as the app makes it: its metadata ([kind], bound in
/// [binding]) and the entries, stored as [location] keeps it.
Future<Uint8List> _newVault(
  String location,
  String name, {
  String? password = _opsPassword,
  Uint8List? keyFile,
  String? outerKey,
  TomSecretsVaultKind kind = TomSecretsVaultKind.personal,
  Map<String, String> binding = const {},
  Map<String, String> entries = const {'Svc/Key': 'demo-ops-key'},
}) async {
  final file = tomSecretsNewVault(
    tomSecretsVaultCredentials(password: password, keyFile: keyFile),
    name,
    argon2: testArgon2,
  );
  TomSecretsMetadata(store: name, kind: kind, binding: binding).writeTo(file);
  for (final MapEntry(:key, :value) in entries.entries) {
    final [group, title] = key.split('/');
    final parent = file.createGroup(parent: file.body.rootGroup, name: group);
    parent.addEntry(
      KdbxEntry.create(file, parent)
        ..setString(KdbxKeyCommon.TITLE, PlainValue(title))
        ..setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(value)),
    );
  }
  return tomSecretsEncodeStored(location, file, outerKey: outerKey);
}

void main() {
  late Demo demo;
  late TomSecretsAdminClient admin;
  late List<Map<String, Object?>> events;
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  setUp(() async => demo = await Demo.create());

  Future<TomSecretsService> start() async {
    final service = await demo.start(transport: transport);
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    events = [];
    admin.events.listen(events.add);
    await admin.request('subscribe');
    await admin.unlock(primaryPassword);
    return service;
  }

  Future<String?> get(String ref, {Map<String, String>? dimensions}) async {
    final client = await TomSecretsClient.connect(
      clientName: 'demo-client',
      environment: demo.clientEnvironment(),
    );
    try {
      return (await client.get(ref, dimensions: dimensions)).text;
    } finally {
      await client.close();
    }
  }

  Future<TomSecretsAdminException> refused(Future<Object?> request) async {
    try {
      await request;
    } on TomSecretsAdminException catch (e) {
      return e;
    }
    fail('the request was not refused');
  }

  Future<Map<String, Object?>> create(
    String store,
    String location,
    Uint8List bytes, {
    Map<String, Object?> keys = const {'password': _opsPassword},
    String? githubToken,
    String? keysDue,
  }) => admin.request('vault.create', {
    'store': store,
    'location': location,
    'bytes': base64.encode(bytes),
    'keys': keys,
    'githubToken': ?githubToken,
    'keysDue': ?keysDue,
  });

  /// The primary's vault list as written on the disk.
  Future<TomSecretsPrimaryVaults> listed() async => TomSecretsPrimaryVaults(
    await KdbxFormat().read(
      File(demo.primaryPath).readAsBytesSync(),
      tomSecretsVaultCredentials(password: primaryPassword),
    ),
  );

  test('a system vault with a key file: written where it lives, listed in '
      'the primary with its keys and due date, served at once and after the '
      'next unlock', () async {
    final service = await start();
    final location = 'file:${demo.dir}/vaults/ops.kdbx';
    final keyFile = TomSecretsKeyFile.generate().toBytes();
    final answer = await create(
      'ops',
      location,
      await _newVault(
        location,
        'ops',
        keyFile: keyFile,
        kind: TomSecretsVaultKind.system,
        binding: {'env': 'prod'},
      ),
      keys: {'password': _opsPassword, 'keyFile': base64.encode(keyFile)},
      keysDue: '2028-11-17T00:00:00Z',
    );
    expect(answer['store'], 'ops');
    expect(answer['location'], location);
    expect(answer['revision'], isA<String>());
    expect(File('${demo.dir}/vaults/ops.kdbx').existsSync(), isTrue);

    final entry = (await listed()).byName('ops')!;
    expect(entry.locator, location);
    expect(entry.password, _opsPassword);
    expect(entry.keyFile, keyFile);
    expect(entry.outerKey, isNull);
    expect(entry.expires, DateTime.utc(2028, 11, 17));

    expect(service.vaults.statusOf('ops')!.state, TomSecretsStoreState.current);
    const prod = {'env': 'prod'};
    expect(await get('ops/Svc/Key', dimensions: prod), 'demo-ops-key');
    // The file is bound in env=prod: elsewhere it holds nothing.
    await expectLater(
      get('ops/Svc/Key'),
      throwsA(
        isA<TomSecretsClientException>().having(
          (e) => e.kind,
          'kind',
          TomSecretsErrorKind.notFound,
        ),
      ),
    );
    // The metadata the app wrote: bound in env=prod, a system vault.
    final file = await admin.request('vaultFile', {'store': 'ops'});
    final opened = await tomSecretsDecodeStored(
      location,
      base64.decode(file['bytes'] as String),
      tomSecretsVaultCredentials(password: _opsPassword, keyFile: keyFile),
    );
    final metadata = TomSecretsMetadata.read(opened);
    expect(metadata.kind, TomSecretsVaultKind.system);
    expect(metadata.binding, {'env': 'prod'});

    await admin.request('status');
    await pumpEventQueue();
    expect([
      for (final e in events)
        if (e['op'] == 'store_changed') e['store'],
    ], containsAll(['primary', 'ops']));

    await admin.request('lock');
    await admin.unlock(primaryPassword);
    expect(await get('ops/Svc/Key', dimensions: prod), 'demo-ops-key');
  });

  test('a personal vault under outer encryption: listed with its repository '
      'key and served', () async {
    await start();
    final location = 'file:${demo.dir}/me.kdbx$tomSecretsOuterSuffix';
    final key = TomSecretsRepositoryKey.generate().toBase64();
    await create(
      'me',
      location,
      await _newVault(
        location,
        'me',
        outerKey: key,
        entries: {'Web/Mail': 'demo-mail-pw'},
      ),
      keys: {'password': _opsPassword, 'outerKey': key},
    );
    expect((await listed()).byName('me')!.outerKey, key);
    expect(await get('me/Web/Mail'), 'demo-mail-pw');
  });

  test('refused, nothing written and nothing listed: a name in use or not a '
      'store name, a location in use or not a locator, keys that do not '
      'fit, a file that does not open, a file already there, a token for a '
      'file: vault', () async {
    await start();
    final location = 'file:${demo.dir}/ops.kdbx';
    final bytes = await _newVault(location, 'ops');
    Future<String?> reason(Future<Object?> request) async =>
        (await refused(request)).details['reason'] as String?;

    expect(await reason(create('team', location, bytes)), 'store');
    expect(await reason(create('primary', location, bytes)), 'store');
    expect(await reason(create('Ops!', location, bytes)), 'store');
    expect(
      await reason(create('ops', 'file:${demo.teamPath}', bytes)),
      'location',
    );
    expect(
      await reason(create('ops', 'file:${demo.primaryPath}', bytes)),
      'location',
    );
    expect(await reason(create('ops', 'nowhere', bytes)), 'location');
    expect(
      await reason(
        create('ops', 'git:https://example.invalid/v.git/ops.kdbx', bytes),
      ),
      'location',
    );
    expect(
      await reason(
        create('ops', location, bytes, keys: {'password': 'wrong-pw'}),
      ),
      'bytes',
    );
    expect(
      await reason(
        create(
          'ops',
          location,
          bytes,
          keys: {
            'password': _opsPassword,
            'outerKey': TomSecretsRepositoryKey.generate().toBase64(),
          },
        ),
      ),
      'keys',
    );
    expect(
      await reason(create('ops', location, bytes, githubToken: 'demo-tok')),
      'githubToken',
    );
    expect(
      await reason(
        admin.request('vault.create', {'store': 'ops', 'location': location}),
      ),
      'create',
    );
    File('${demo.dir}/ops.kdbx').writeAsStringSync('x');
    final exists = await refused(create('ops', location, bytes));
    expect(exists.kind, 'denied');
    expect(exists.details['reason'], 'target_exists');
    expect(File('${demo.dir}/ops.kdbx').readAsStringSync(), 'x');
    expect((await listed()).byName('ops'), isNull);
    expect(
      (await admin.request('vaultKeys'))['stores'] as List,
      hasLength(2),
      reason: 'primary and team only',
    );
  });

  test('a vault this machine does not serve: listed in the primary and '
      'editable here as a vault not served', () async {
    await start();
    await admin.request('settings.set', {
      'device': {
        'servedStores': ['primary', 'team'],
      },
    });
    await admin.request('lock');
    await admin.unlock(primaryPassword);
    final location = 'file:${demo.dir}/ops.kdbx';
    await create('ops', location, await _newVault(location, 'ops'));
    expect((await listed()).byName('ops'), isNotNull);
    final keys = await admin.request('vaultKeys');
    expect(keys['unserved'], [
      {'store': 'ops', 'location': location},
    ]);
    expect(
      [for (final s in (keys['stores'] as List).cast<Map>()) s['store']],
      ['primary', 'team'],
    );
  });

  test('locked: refused', () async {
    await start();
    await admin.request('lock');
    final location = 'file:${demo.dir}/ops.kdbx';
    final e = await refused(
      create('ops', location, await _newVault(location, 'ops')),
    );
    expect(e.kind, 'locked');
  });
}
