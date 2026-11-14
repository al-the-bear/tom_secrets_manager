// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The first run (part-app, First run): a new or existing primary, local or
/// in a GitHub repository, its protection layers kept in the keychain, the
/// device settings and `bootstrap.yaml`. Demo data under demo keys; the
/// scratch directories are under `.dart_tool/`.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_github_api/testing.dart' show FakeGitHubServer;
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const _password = 'primary-demo-pw';

Directory _scratch() {
  final root = Directory('.dart_tool/first_run_test')
    ..createSync(recursive: true);
  final dir = root.createTempSync('run');
  addTearDown(() => dir.deleteSync(recursive: true));
  return Directory(dir.absolute.path);
}

TomSecretsFirstRun _firstRun(
  Directory dir, {
  TomSecretStore? keychain,
  FakeGitHubServer? server,
  DateTime? now,
}) => TomSecretsFirstRun(
  dataDirectory: '${dir.path}/data',
  keychain: keychain,
  httpClient: server?.client,
  githubBaseUrl: FakeGitHubServer.baseUrl,
  argon2: testArgon2,
  clock: now == null ? null : () => now,
);

Future<TomSecretsDeviceSettings> _settingsOf(
  TomSecretsFirstRun run,
  TomSecretStore keychain,
  String host,
) async {
  final key = await keychain.read('tsm.device-settings.$host');
  final container = await TomSecretsDeviceContainer.open(
    run.deviceContainerPath,
    key!,
  );
  return container.settings;
}

void main() {
  group('keys due and keychain handles', () {
    test('24 months on, the day kept or the month\'s last', () {
      expect(
        tomSecretsKeysDue(DateTime.utc(2026, 11, 14, 9, 30)),
        DateTime.utc(2028, 11, 14, 9, 30),
      );
      expect(
        tomSecretsKeysDue(DateTime.utc(2028, 2, 29)),
        DateTime.utc(2030, 2, 28),
      );
      expect(
        tomSecretsKeysDue(DateTime.utc(2026, 1, 31), months: 1),
        DateTime.utc(2026, 2, 28),
      );
    });

    test('a key file per vault, a repository key per repository, no "/" in '
        'a handle, the branch left out', () {
      final a = TomSecretsVaultLocator.parse(
        'github:al-the-bear/demo-vaults/vaults/primary.kdbx.tsmx',
      );
      final aOnBranch = TomSecretsVaultLocator.parse(
        'github:al-the-bear/demo-vaults@main/vaults/primary.kdbx.tsmx',
      );
      final b = TomSecretsVaultLocator.parse(
        'github:al-the-bear/demo-vaults/vaults/team.kdbx.tsmx',
      );
      final local = TomSecretsVaultLocator.parse('file:/demo/v/primary.kdbx');
      final localTeam = TomSecretsVaultLocator.parse('file:/demo/v/team.kdbx');
      expect(a.keyFileHandle, aOnBranch.keyFileHandle);
      expect(a.keyFileHandle, isNot(b.keyFileHandle));
      expect(a.repositoryKeyHandle, b.repositoryKeyHandle);
      expect(local.repositoryKeyHandle, localTeam.repositoryKeyHandle);
      expect(local.repositoryKeyHandle, isNot(a.repositoryKeyHandle));
      for (final h in [
        a.keyFileHandle,
        a.repositoryKeyHandle,
        local.keyFileHandle,
      ]) {
        expect(
          h,
          matches(RegExp(r'^tsm\.(key-file|repository-key)\.[0-9a-f]{16}$')),
        );
      }
    });
  });

  group('a local primary', () {
    test('created with a key file and an AES-256-GCM repository key: the '
        '.tsmx file, the keys in the keychain, keys due, the settings and '
        'the bootstrap', () async {
      final dir = _scratch();
      final keychain = TomInMemorySecretStore();
      final now = DateTime.utc(2026, 11, 14, 10);
      final run = _firstRun(dir, keychain: keychain, now: now);
      final keyFile = TomSecretsKeyFile.generate().toBytes();
      final repositoryKey = TomSecretsRepositoryKey.generate();
      final locator = TomSecretsVaultLocator.parse(
        'file:${dir.path}/vaults/primary.kdbx.tsmx',
      );
      final result = await run.run(
        TomSecretsFirstRunSetup(
          primary: locator,
          create: true,
          masterPassword: _password,
          keyFile: keyFile,
          repositoryKey: repositoryKey,
          cipher: TomSecretsOuterCipher.aes256Gcm,
          settings: const TomSecretsDeviceSettings(
            defaultEnvironment: 'prod',
            servedStores: ['primary'],
            serviceLock: TomSecretsLockPolicy(mode: TomSecretsLockMode.never),
          ),
          deviceKey: TomSecretsDeviceKeyMode.keychain,
          host: 'demo-host',
        ),
      );
      expect(result.created, isTrue);
      expect(result.deviceKey, TomSecretsDeviceKeyMode.keychain);
      expect(result.keysDue, DateTime.utc(2028, 11, 14, 10));

      final stored = File(
        '${dir.path}/vaults/primary.kdbx.tsmx',
      ).readAsBytesSync();
      expect(tomSecretsOuterCipherOf(stored), TomSecretsOuterCipher.aes256Gcm);
      final file = await tomSecretsDecodeStored(
        locator.text,
        stored,
        tomSecretsVaultCredentials(password: _password, keyFile: keyFile),
        outerKey: repositoryKey.toBase64(),
      );
      expect(
        TomSecretsMetadata.read(file).keysDue,
        DateTime.utc(2028, 11, 14, 10),
      );
      await expectLater(
        tomSecretsDecodeStored(
          locator.text,
          stored,
          tomSecretsVaultCredentials(password: _password),
          outerKey: repositoryKey.toBase64(),
        ),
        throwsA(isA<KdbxInvalidKeyException>()),
        reason: 'the key file is part of the key',
      );

      expect(
        await keychain.read(locator.keyFileHandle),
        base64.encode(keyFile),
      );
      expect(
        await keychain.read(locator.repositoryKeyHandle),
        repositoryKey.toBase64(),
      );
      final settings = await _settingsOf(run, keychain, 'demo-host');
      expect(settings.defaultEnvironment, 'prod');
      expect(settings.servedStores, ['primary']);
      expect(settings.serviceLock.mode, TomSecretsLockMode.never);

      final bootstrap = File(run.bootstrapPath).readAsStringSync();
      expect(bootstrap, contains('primary: "${locator.text}"'));
      expect(bootstrap, contains('device_key: keychain'));
      expect(bootstrap, contains('host: "demo-host"'));
      expect(bootstrap, isNot(contains(_password)));
      expect(bootstrap, isNot(contains(repositoryKey.toBase64())));
    });

    test('a plain primary without layers gets no keys-due; a second run is '
        'refused: the machine is set up', () async {
      final dir = _scratch();
      final keychain = TomInMemorySecretStore();
      final run = _firstRun(dir, keychain: keychain);
      final locator = TomSecretsVaultLocator.parse(
        'file:${dir.path}/primary.kdbx',
      );
      final result = await run.run(
        TomSecretsFirstRunSetup(
          primary: locator,
          create: true,
          masterPassword: _password,
          host: 'demo-host',
        ),
      );
      expect(result.keysDue, isNull);
      final file = await tomSecretsDecodeStored(
        locator.text,
        File('${dir.path}/primary.kdbx').readAsBytesSync(),
        tomSecretsVaultCredentials(password: _password),
      );
      expect(TomSecretsMetadata.read(file).keysDue, isNull);
      expect(await keychain.read(locator.keyFileHandle), isNull);
      await expectLater(
        run.run(
          TomSecretsFirstRunSetup(
            primary: locator,
            create: false,
            masterPassword: _password,
          ),
        ),
        throwsA(
          isA<TomSecretsFirstRunException>().having(
            (e) => e.problem,
            'problem',
            TomSecretsFirstRunProblem.alreadySetUp,
          ),
        ),
      );
    });

    test(
      'an existing primary opened: a wrong password refused and nothing '
      'written; the vault mode keeps the container key in the primary',
      () async {
        final dir = _scratch();
        final keychain = TomInMemorySecretStore();
        final vault = newTestVault(
          tomSecretsVaultCredentials(password: _password),
          'primary',
        );
        final path = '${dir.path}/primary.kdbx';
        File(path).writeAsBytesSync(await vault.save());
        final before = File(path).readAsBytesSync();
        final run = _firstRun(dir, keychain: keychain);
        final locator = TomSecretsVaultLocator.parse('file:$path');
        await expectLater(
          run.run(
            TomSecretsFirstRunSetup(
              primary: locator,
              create: false,
              masterPassword: 'wrong',
            ),
          ),
          throwsA(
            isA<TomSecretsFirstRunException>().having(
              (e) => e.problem,
              'problem',
              TomSecretsFirstRunProblem.wrongPassword,
            ),
          ),
        );
        expect(File(run.bootstrapPath).existsSync(), isFalse);
        expect(File(run.deviceContainerPath).existsSync(), isFalse);

        final result = await run.run(
          TomSecretsFirstRunSetup(
            primary: locator,
            create: false,
            masterPassword: _password,
            deviceKey: TomSecretsDeviceKeyMode.vault,
            host: 'demo-host',
          ),
        );
        expect(result.created, isFalse);
        expect(result.deviceKey, TomSecretsDeviceKeyMode.vault);
        final after = File(path).readAsBytesSync();
        expect(after, isNot(before), reason: 'the key was written into it');
        final reread = await tomSecretsDecodeStored(
          locator.text,
          after,
          tomSecretsVaultCredentials(password: _password),
        );
        final keys = TomSecretsDeviceKeys(
          mode: TomSecretsDeviceKeyMode.vault,
          host: 'demo-host',
          containerPath: run.deviceContainerPath,
        );
        final key = await keys.keyFor(
          primary: reread,
          savePrimary: () async => fail('the key is there already'),
        );
        final container = await TomSecretsDeviceContainer.open(
          run.deviceContainerPath,
          key,
        );
        expect(container.settings.refreshMinutes, 5);
      },
    );

    test('refusals: a file there already, a .tsmx name without a key, a key '
        'for a plain name, a missing file, a key without a keychain, an '
        'outer-encrypted primary without its key', () async {
      final dir = _scratch();
      final keychain = TomInMemorySecretStore();
      final run = _firstRun(dir, keychain: keychain);
      final existing = '${dir.path}/there.kdbx';
      File(existing).writeAsBytesSync(
        await newTestVault(
          tomSecretsVaultCredentials(password: _password),
          'there',
        ).save(),
      );
      Future<void> refused(
        TomSecretsFirstRun run,
        TomSecretsFirstRunSetup setup,
        TomSecretsFirstRunProblem problem,
      ) => expectLater(
        run.run(setup),
        throwsA(
          isA<TomSecretsFirstRunException>().having(
            (e) => e.problem,
            'problem',
            problem,
          ),
        ),
      );
      TomSecretsVaultLocator at(String name) =>
          TomSecretsVaultLocator.parse('file:${dir.path}/$name');

      await refused(
        run,
        TomSecretsFirstRunSetup(
          primary: at('there.kdbx'),
          create: true,
          masterPassword: _password,
        ),
        TomSecretsFirstRunProblem.primaryExists,
      );
      await refused(
        run,
        TomSecretsFirstRunSetup(
          primary: at('new.kdbx.tsmx'),
          create: true,
          masterPassword: _password,
        ),
        TomSecretsFirstRunProblem.inconsistent,
      );
      await refused(
        run,
        TomSecretsFirstRunSetup(
          primary: at('new.kdbx'),
          create: true,
          masterPassword: _password,
          repositoryKey: TomSecretsRepositoryKey.generate(),
        ),
        TomSecretsFirstRunProblem.inconsistent,
      );
      await refused(
        run,
        TomSecretsFirstRunSetup(
          primary: at('missing.kdbx'),
          create: false,
          masterPassword: _password,
        ),
        TomSecretsFirstRunProblem.primaryNotFound,
      );
      await refused(
        _firstRun(dir),
        TomSecretsFirstRunSetup(
          primary: at('new.kdbx'),
          create: true,
          masterPassword: _password,
          keyFile: TomSecretsKeyFile.generate().toBytes(),
        ),
        TomSecretsFirstRunProblem.keychainNeeded,
      );
      await refused(
        run,
        TomSecretsFirstRunSetup(
          primary: at('outer.kdbx.tsmx'),
          create: false,
          masterPassword: _password,
        ),
        TomSecretsFirstRunProblem.repositoryKeyNeeded,
      );
      File('${dir.path}/garbage.kdbx').writeAsStringSync('not a vault');
      await expectLater(
        run.run(
          TomSecretsFirstRunSetup(
            primary: at('garbage.kdbx'),
            create: false,
            masterPassword: _password,
          ),
        ),
        throwsA(
          isA<TomSecretsFirstRunException>().having(
            (e) => e.problem,
            'problem',
            TomSecretsFirstRunProblem.notAVault,
          ),
        ),
      );
      expect(File(run.bootstrapPath).existsSync(), isFalse);
      expect(await keychain.read(at('new.kdbx').keyFileHandle), isNull);
    });
  });

  group('a primary in a GitHub repository', () {
    late FakeGitHubServer server;
    const repo = 'al-the-bear/demo-vaults';

    setUp(() {
      server = FakeGitHubServer()..repo(repo);
    });

    test('the repository checked: its default branch; an unknown one is '
        'repositoryNotFound', () async {
      final run = _firstRun(_scratch(), server: server);
      final check = await run.checkGitHub(
        owner: 'al-the-bear',
        repository: 'demo-vaults',
        token: 'demo-token',
      );
      expect(check.defaultBranch, 'main');
      await expectLater(
        run.checkGitHub(
          owner: 'al-the-bear',
          repository: 'nothing-here',
          token: 'demo-token',
        ),
        throwsA(
          isA<TomSecretsFirstRunException>().having(
            (e) => e.problem,
            'problem',
            TomSecretsFirstRunProblem.repositoryNotFound,
          ),
        ),
      );
    });

    test('created as a commit by the device, the token and its expiry in '
        'the keychain; opened on a second machine with its keys', () async {
      final keychain = TomInMemorySecretStore();
      final dir = _scratch();
      final run = _firstRun(dir, keychain: keychain, server: server);
      final repositoryKey = TomSecretsRepositoryKey.generate();
      final keyFile = TomSecretsKeyFile.generate().toBytes();
      final locator = TomSecretsVaultLocator.parse(
        'github:$repo/vaults/primary.kdbx.tsmx',
      );
      final expires = DateTime.utc(2027, 2, 1);
      await run.run(
        TomSecretsFirstRunSetup(
          primary: locator,
          create: true,
          masterPassword: _password,
          keyFile: keyFile,
          repositoryKey: repositoryKey,
          githubToken: 'demo-token',
          githubTokenExpires: expires,
          host: 'demo-host',
        ),
      );
      final bytes = server.bytesAt(repo, 'vaults/primary.kdbx.tsmx')!;
      expect(
        tomSecretsOuterCipherOf(Uint8List.fromList(bytes)),
        TomSecretsOuterCipher.xchacha20Poly1305,
      );
      final github = locator as TomSecretsGitHubLocator;
      expect(await keychain.read(github.tokenHandle), 'demo-token');
      expect(
        await keychain.read(github.tokenExpiryHandle),
        expires.toIso8601String(),
      );

      // A second machine opens it; the vault mode commits the container key.
      final other = TomInMemorySecretStore();
      final second = _firstRun(_scratch(), keychain: other, server: server);
      await expectLater(
        second.run(
          TomSecretsFirstRunSetup(
            primary: locator,
            create: true,
            masterPassword: _password,
            keyFile: keyFile,
            repositoryKey: repositoryKey,
            githubToken: 'demo-token',
          ),
        ),
        throwsA(
          isA<TomSecretsFirstRunException>().having(
            (e) => e.problem,
            'problem',
            TomSecretsFirstRunProblem.primaryExists,
          ),
        ),
      );
      await expectLater(
        second.run(
          TomSecretsFirstRunSetup(
            primary: locator,
            create: false,
            masterPassword: _password,
            keyFile: keyFile,
            repositoryKey: TomSecretsRepositoryKey.generate(random: Random(1)),
            githubToken: 'demo-token',
          ),
        ),
        throwsA(
          isA<TomSecretsFirstRunException>().having(
            (e) => e.problem,
            'problem',
            TomSecretsFirstRunProblem.repositoryKeyWrong,
          ),
        ),
      );
      final opened = await second.run(
        TomSecretsFirstRunSetup(
          primary: locator,
          create: false,
          masterPassword: _password,
          keyFile: keyFile,
          repositoryKey: repositoryKey,
          githubToken: 'demo-token',
          deviceKey: TomSecretsDeviceKeyMode.vault,
          host: 'other-host',
        ),
      );
      expect(opened.deviceKey, TomSecretsDeviceKeyMode.vault);
      final storage = TomGitHubStorage.withClient(
        GitHubApiClient(
          token: 'demo-token',
          httpClient: server.client,
          baseUrl: FakeGitHubServer.baseUrl,
        ),
        committer: tomSecretsDeviceCommitter('reader'),
      );
      addTearDown(storage.close);
      final (stored, _) = await TomSecretsVaultUnit.readAtHead(
        storage,
        locator.text,
      );
      final file = await tomSecretsDecodeStored(
        locator.text,
        stored,
        tomSecretsVaultCredentials(password: _password, keyFile: keyFile),
        outerKey: repositoryKey.toBase64(),
      );
      final device = file.body.rootGroup.getAllEntries().where(
        (e) => e.parent?.parent?.name.get() == '@host:other-host',
      );
      expect(device, hasLength(1), reason: 'the container key committed');
      expect(await other.read(github.tokenHandle), 'demo-token');
    });
  });
}
