// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The receiving side of a pairing on a machine being set up
/// (part-sharing): received from a giving `TomSecretsPairingWindow` on
/// loopback, nothing stored until the setup; the first run from the bundle
/// (the primary opened with its key file, the further vaults' keys and the
/// tokens in the keychain, the trust material with the giver recorded); a
/// bundle without the primary refused on both sides. Demo data under demo
/// keys; the scratch directories are under `.dart_tool/`.
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const _password = 'primary-demo-pw';

Directory _scratch() {
  final root = Directory('.dart_tool/pairing_setup_test')
    ..createSync(recursive: true);
  final dir = root.createTempSync('run');
  addTearDown(() => dir.deleteSync(recursive: true));
  return Directory(dir.absolute.path);
}

void main() {
  final loopback = [InternetAddress.loopbackIPv4];
  late Directory dir;
  late TomSecretsKeyFile keyFile;
  late TomSecretsRepositoryKey teamKey;
  late TomSecretsPairingPeerKeys giverKeys;
  late String primaryPath;

  setUp(() async {
    dir = _scratch();
    keyFile = TomSecretsKeyFile.generate();
    teamKey = TomSecretsRepositoryKey.generate();
    final giver = TomSecretsTrust.create('mbp');
    giverKeys = TomSecretsPairingPeerKeys(
      linkKey: (await giver.linkKey()).publicKey,
      approverKey: (await giver.approverKey()).publicKey,
      linkAddress: '10.8.0.7:47731',
    );
    final vault = newTestVault(
      tomSecretsVaultCredentials(
        password: _password,
        keyFile: keyFile.toBytes(),
      ),
      'primary',
    );
    primaryPath = '${dir.path}/primary.kdbx';
    File(primaryPath).writeAsBytesSync(await vault.save());
  });

  TomSecretsPairingBundle bundle({bool withPrimary = true}) =>
      TomSecretsPairingBundle(
        vaults: [
          if (withPrimary)
            TomSecretsPairingVault(
              name: 'primary',
              locator: 'file:$primaryPath',
              primary: true,
              keyFile: keyFile.toBytes(),
            ),
          TomSecretsPairingVault(
            name: 'team',
            locator: 'github:al-the-bear/demo-vaults/team.kdbx.tsmx',
            primary: false,
            repositoryKey: teamKey.toBase64(),
          ),
        ],
        giverKeys: giverKeys,
        configYaml: 'dimensions: []\n',
        tokens: [
          TomSecretsPairingToken(
            repository: 'al-the-bear/demo-vaults',
            token: 'github_pat_demo_for_bigbeast',
            expires: DateTime.utc(2027, 2, 13),
          ),
        ],
      );

  Future<(TomSecretsPairingWindow, TomSecretsPairingCode)> window(
    TomSecretsPairingBundle given,
  ) async {
    final code = TomSecretsPairingCode.generate();
    final w = await TomSecretsPairingWindow.open(
      addresses: loopback,
      allowLoopback: true,
      code: code,
      device: 'mbp',
      bundleFor: (_) async => given,
    );
    return (w, code);
  }

  test(
    'received, nothing stored; set up from the bundle: the primary '
    'opened, the keys and tokens in the keychain, the giver recorded',
    () async {
      final (w, code) = await window(bundle());
      final receipt = await tomSecretsReceivePairingForSetup(
        address: '127.0.0.1',
        port: w.port,
        code: code,
        device: 'bigbeast',
      );
      final given = await w.result;
      expect(receipt.giver, 'mbp');
      expect(receipt.received.tokenKey, given.tokenKey);
      expect(
        given.receiverKeys.approverKey!.keyId,
        (await receipt.trust.approverKey()).publicKey.keyId,
      );
      expect(
        given.receiverKeys.linkKey.toJson(),
        (await receipt.trust.linkKey()).publicKey.toJson(),
      );

      final keychain = TomInMemorySecretStore();
      final run = TomSecretsFirstRun(
        dataDirectory: '${dir.path}/data',
        keychain: keychain,
        argon2: testArgon2,
      );
      expect(Directory(run.dataDirectory).existsSync(), isFalse);
      await expectLater(
        run.runPaired(receipt, masterPassword: 'wrong'),
        throwsA(
          isA<TomSecretsFirstRunException>().having(
            (e) => e.problem,
            'problem',
            TomSecretsFirstRunProblem.wrongPassword,
          ),
        ),
      );
      expect(File(run.bootstrapPath).existsSync(), isFalse);
      expect(await keychain.read('tsm.device-settings.bigbeast'), isNull);

      await run.runPaired(
        receipt,
        masterPassword: _password,
        deviceKey: TomSecretsDeviceKeyMode.keychain,
      );
      final primary = TomSecretsVaultLocator.parse('file:$primaryPath');
      final team =
          TomSecretsVaultLocator.parse(
                'github:al-the-bear/demo-vaults/team.kdbx.tsmx',
              )
              as TomSecretsGitHubLocator;
      expect(
        await keychain.read(primary.keyFileHandle),
        base64.encode(keyFile.toBytes()),
      );
      expect(await keychain.read(team.repositoryKeyHandle), teamKey.toBase64());
      expect(
        await keychain.read(team.tokenHandle),
        'github_pat_demo_for_bigbeast',
      );
      expect(
        await keychain.read(team.tokenExpiryHandle),
        '2027-02-13T00:00:00.000Z',
      );
      final bootstrap = File(run.bootstrapPath).readAsStringSync();
      expect(bootstrap, contains('primary: "file:$primaryPath"'));
      expect(bootstrap, contains('host: "bigbeast"'));

      final container = await TomSecretsDeviceContainer.open(
        run.deviceContainerPath,
        (await keychain.read('tsm.device-settings.bigbeast'))!,
      );
      final trust = await container.trust('bigbeast');
      expect(
        (await trust.approverKey()).publicKey.keyId,
        (await receipt.trust.approverKey()).publicKey.keyId,
      );
      final approver = trust.approvers.single;
      expect(approver.device, 'mbp');
      expect(approver.approverKey.keyId, giverKeys.approverKey!.keyId);
      expect(approver.tokenKey, given.tokenKey);
      final host = trust.hosts.single;
      expect(host.host, 'mbp');
      expect(host.address, '10.8.0.7:47731');
      expect(host.linkKey.toJson(), giverKeys.linkKey.toJson());
    },
  );

  test('a bundle without the primary is refused on both sides; nothing '
      'is stored', () async {
    final (w, code) = await window(bundle(withPrimary: false));
    final result = expectLater(
      w.result,
      throwsA(
        isA<TomSecretsPairingException>().having(
          (e) => e.failure,
          'failure',
          TomSecretsPairingFailure.refused,
        ),
      ),
    );
    await expectLater(
      tomSecretsReceivePairingForSetup(
        address: '127.0.0.1',
        port: w.port,
        code: code,
        device: 'bigbeast',
      ),
      throwsA(
        isA<TomSecretsPairingException>()
            .having(
              (e) => e.failure,
              'failure',
              TomSecretsPairingFailure.refused,
            )
            .having((e) => e.message, 'message', contains('primary')),
      ),
    );
    await result;
  });

  test('a github: primary without a token for this machine is refused', () {
    final b = TomSecretsPairingBundle(
      vaults: const [
        TomSecretsPairingVault(
          name: 'primary',
          locator: 'github:al-the-bear/demo-vaults/primary.kdbx',
          primary: true,
        ),
      ],
      giverKeys: giverKeys,
    );
    expect(tomSecretsPairingSetupProblem(b), contains('GitHub token'));
    expect(tomSecretsPairingSetupProblem(bundle()), isNull);
  });

  test('the address as the Pairing screen shows it', () {
    expect(tomSecretsParsePairingAddress('10.8.0.7:47900'), (
      '10.8.0.7',
      47900,
    ));
    expect(tomSecretsParsePairingAddress('[fd00::7]:47900'), (
      'fd00::7',
      47900,
    ));
    expect(tomSecretsParsePairingAddress(' mbp.local:5 '), ('mbp.local', 5));
    for (final bad in ['10.8.0.7', '10.8.0.7:0', ':47900', 'a b:1']) {
      expect(
        () => tomSecretsParsePairingAddress(bad),
        throwsFormatException,
        reason: bad,
      );
    }
  });
}
