// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Shared vaults through the service (protocol.md 6.4, part-sharing) with
/// `file:` vaults: created with the recipients file beside them and a key
/// file alone, the file read by store and by location, written alone over
/// its revision (a member added), and a member removed: the vault re-keyed
/// and the recipients file written with it. The `github:` cases are in
/// github_test.dart. Demo keys only.
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

void main() {
  late Demo demo;
  late TomSecretsAdminClient admin;
  late TomSecretsMemberKey alice;
  late TomSecretsMemberKey bob;
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  setUpAll(() async {
    alice = await TomSecretsMemberKey.generate();
    bob = await TomSecretsMemberKey.generate();
  });
  tearDownAll(() {
    alice.dispose();
    bob.dispose();
  });

  setUp(() async => demo = await Demo.create());

  Future<TomSecretsService> start() async {
    final service = await demo.start(transport: transport);
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    return service;
  }

  Future<String?> get(String ref) async {
    final client = await TomSecretsClient.connect(
      clientName: 'demo-client',
      environment: demo.clientEnvironment(),
    );
    try {
      return (await client.get(ref)).text;
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

  /// A new shared vault `crew` for [keys], with one entry.
  Future<Uint8List> newCrew(String location, TomSecretsSharedVaultKeys keys) {
    final file = tomSecretsNewSharedVault('crew', keys, argon2: testArgon2);
    final group = file.createGroup(parent: file.body.rootGroup, name: 'Api');
    group.addEntry(
      KdbxEntry.create(file, group)
        ..setString(KdbxKeyCommon.TITLE, PlainValue('Token'))
        ..setString(
          KdbxKeyCommon.PASSWORD,
          ProtectedValue.fromString('team-token-1'),
        ),
    );
    return tomSecretsEncodeStored(location, file);
  }

  Future<Map<String, Object?>> createCrew(
    String location,
    TomSecretsSharedVaultKeys keys,
  ) async => admin.request('vault.create', {
    'store': 'crew',
    'location': location,
    'bytes': base64.encode(await newCrew(location, keys)),
    'keys': {'keyFile': base64.encode(keys.keyFile)},
    'recipients': base64.encode(await tomSecretsWriteRecipientsFile(keys)),
  });

  TomSecretsSharedVaultMember member(String name, TomSecretsMemberKey k) =>
      (name: name, recipient: k.recipient);

  test(
    'created: the vault and its recipients file beside it, listed with '
    'its key file alone and served; the file read by store and by location',
    () async {
      final service = await start();
      final location = 'file:${demo.dir}/shared/crew.kdbx';
      Directory('${demo.dir}/shared').createSync();
      final keys = TomSecretsSharedVaultKeys.generate(
        'crew',
        members: [member('Alice', alice), member('Bob', bob)],
      );
      await createCrew(location, keys);
      final beside = File('${demo.dir}/shared/crew.keys.age');
      expect(beside.existsSync(), isTrue);
      expect(
        service.vaults.statusOf('crew')!.state,
        TomSecretsStoreState.current,
      );
      expect(await get('crew/Api/Token'), 'team-token-1');
      final listed = TomSecretsPrimaryVaults(
        await KdbxFormat().read(
          File(demo.primaryPath).readAsBytesSync(),
          tomSecretsVaultCredentials(password: primaryPassword),
        ),
      ).byName('crew')!;
      expect(listed.password, isNull);
      expect(listed.keyFile, keys.keyFile);

      for (final request in [
        {'store': 'crew'},
        {'location': location},
      ]) {
        final read = await admin.request('vault.recipients', request);
        expect(read['op'], 'recipientsData');
        expect(read['location'], location);
        final bytes = base64.decode(read['bytes'] as String);
        expect(read['revision'], tomSecretsBlobId(bytes));
        expect(bytes, beside.readAsBytesSync());
        final opened = await tomSecretsReadRecipientsFile(bytes, bob);
        expect(opened.keyFile, keys.keyFile);
      }

      final none = await refused(
        admin.request('vault.recipients', {
          'location': 'file:${demo.dir}/other.kdbx',
        }),
      );
      expect(none.kind, 'not_found');
      expect(none.details['reason'], 'no_recipients');
      for (final bad in [
        <String, Object?>{},
        {'store': 'crew', 'location': location},
      ]) {
        expect(
          (await refused(admin.request('vault.recipients', bad))).kind,
          'malformed',
        );
      }
      expect(
        (await refused(
          admin.request('vault.recipients', {'store': 'nope'}),
        )).kind,
        'not_found',
      );
    },
  );

  test('a key file alone only for a shared vault; a recipients file with a '
      'save that is not re-keyed is refused', () async {
    await start();
    final location = 'file:${demo.dir}/crew.kdbx';
    final keys = TomSecretsSharedVaultKeys.generate(
      'crew',
      members: [member('Alice', alice)],
    );
    final noPassword = await refused(
      admin.request('vault.create', {
        'store': 'crew',
        'location': location,
        'bytes': base64.encode(await newCrew(location, keys)),
        'keys': {'keyFile': base64.encode(keys.keyFile)},
      }),
    );
    expect(noPassword.details['reason'], 'keys');
    expect(File('${demo.dir}/crew.kdbx').existsSync(), isFalse);

    await createCrew(location, keys);
    final held = await admin.request('vaultFile', {'store': 'crew'});
    final notRekeyed = await refused(
      admin.request('save', {
        'store': 'crew',
        'bytes': held['bytes'],
        'baseRevision': held['revision'],
        'recipients': base64.encode(await tomSecretsWriteRecipientsFile(keys)),
      }),
    );
    expect(notRekeyed.kind, 'malformed');
    expect(notRekeyed.details['reason'], 'recipients');
  });

  test('a member added: the recipients file written alone over the revision '
      'read; a stale revision is refused', () async {
    await start();
    final location = 'file:${demo.dir}/crew.kdbx';
    final keys = TomSecretsSharedVaultKeys.generate(
      'crew',
      members: [member('Alice', alice)],
    );
    await createCrew(location, keys);
    final read = await admin.request('vault.recipients', {'store': 'crew'});
    final withBob = await tomSecretsWriteRecipientsFile(
      keys.withMember(member('Bob', bob)),
    );
    final stale = await refused(
      admin.request('vault.recipients.set', {
        'store': 'crew',
        'bytes': base64.encode(withBob),
        'baseRevision': 'b1946ac92492d2347c62',
      }),
    );
    expect(stale.details['reason'], 'stale_base');
    final none = await refused(
      admin.request('vault.recipients.set', {
        'store': 'crew',
        'bytes': base64.encode(withBob),
      }),
    );
    expect(none.details['reason'], 'stale_base');
    final ok = await admin.request('vault.recipients.set', {
      'store': 'crew',
      'bytes': base64.encode(withBob),
      'baseRevision': read['revision'],
    });
    expect(ok['revision'], tomSecretsBlobId(withBob));
    final bytes = File('${demo.dir}/crew.keys.age').readAsBytesSync();
    expect(
      (await tomSecretsReadRecipientsFile(bytes, bob)).keyFile,
      keys.keyFile,
    );
  });

  test('a member removed: the new keys listed in the primary, then the vault '
      're-keyed and its recipients file written with it; the removed member '
      'opens neither', () async {
    final service = await start();
    final location = 'file:${demo.dir}/crew.kdbx';
    final keys = TomSecretsSharedVaultKeys.generate(
      'crew',
      members: [member('Alice', alice), member('Bob', bob)],
    );
    await createCrew(location, keys);
    final next = keys.withoutMember(bob.recipient);

    // The app lists the new keys in the primary first.
    final primaryFile = await admin.request('vaultFile', {'store': 'primary'});
    final primary = await KdbxFormat().read(
      base64.decode(primaryFile['bytes'] as String),
      tomSecretsVaultCredentials(password: primaryPassword),
    );
    final vaults = TomSecretsPrimaryVaults(primary);
    final old = vaults.byName('crew')!;
    vaults.put(
      TomSecretsVaultKeys(
        name: old.name,
        locator: old.locator,
        keyFile: next.keyFile,
      ),
    );
    await admin.request('save', {
      'store': 'primary',
      'bytes': base64.encode(await primary.save()),
      'baseRevision': primaryFile['revision'],
    });

    // Then the vault, re-keyed, with the recipients file.
    final held = await admin.request('vaultFile', {'store': 'crew'});
    final team = await tomSecretsDecodeStored(
      location,
      base64.decode(held['bytes'] as String),
      keys.credentials,
    );
    team.credentials = next.credentials;
    final recipients = await tomSecretsWriteRecipientsFile(next);
    await admin.request('save', {
      'store': 'crew',
      'bytes': base64.encode(await tomSecretsEncodeStored(location, team)),
      'baseRevision': held['revision'],
      'recipients': base64.encode(recipients),
    });

    final stored = File('${demo.dir}/crew.kdbx').readAsBytesSync();
    await expectLater(
      tomSecretsDecodeStored(location, stored, keys.credentials),
      throwsA(isA<KdbxInvalidKeyException>()),
    );
    await tomSecretsDecodeStored(location, stored, next.credentials);
    final beside = File('${demo.dir}/crew.keys.age').readAsBytesSync();
    expect(beside, recipients);
    await expectLater(
      tomSecretsReadRecipientsFile(beside, bob),
      throwsA(
        isA<TomSecretsSharedVaultException>().having(
          (e) => e.reason,
          'reason',
          TomSecretsSharedVaultFailure.notAMember,
        ),
      ),
    );
    expect(
      (await tomSecretsReadRecipientsFile(beside, alice)).keyFile,
      next.keyFile,
    );
    expect(
      service.vaults.statusOf('crew')!.state,
      TomSecretsStoreState.current,
    );
    expect(await get('crew/Api/Token'), 'team-token-1');
  });
}
