// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// New vaults (KeePass compatibility, BP-36): KDBX 4.1 keyed through
/// Argon2id with the design's parameters (64 MiB, 3 iterations), the primary
/// and a further vault alike, read back after the GitHub cycle and, with
/// `keepassxc-cli` on the machine, by KeePassXC. Demo data under demo keys.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_core_storage/testing.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const keepassxcApp = '/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli';

String? findKeePassXc() {
  if (File(keepassxcApp).existsSync()) return keepassxcApp;
  final which = Process.runSync('which', ['keepassxc-cli']);
  final path = (which.stdout as String).trim();
  return which.exitCode == 0 && path.isNotEmpty ? path : null;
}

/// The KDBX version in [bytes]'s header: (major, minor).
(int, int) kdbxVersion(Uint8List bytes) {
  final data = ByteData.sublistView(bytes);
  return (data.getUint16(10, Endian.little), data.getUint16(8, Endian.little));
}

void main() {
  final primaryCredentials = Credentials(
    ProtectedValue.fromString('primary-demo-pw'),
  );

  test('NV-1: a new vault is keyed by Argon2id over 64 MiB, 3 iterations, '
      '1 lane', () {
    expect(
      tomSecretsDefaultArgon2,
      const KdbxArgon2(
        type: KdbxArgon2Type.argon2id,
        memory: 64 * 1024 * 1024,
        iterations: 3,
      ),
    );
    final vault = tomSecretsNewVault(primaryCredentials, 'primary');
    expect(vault.argon2, tomSecretsDefaultArgon2);
    expect(
      vault.body.meta.customData[tomSecretsFormatKey],
      tomSecretsFormatVersion,
    );
  });

  test('NV-2: the primary and a further vault, created and pushed, read back '
      'on another device as KDBX 4.1 with that Argon2id', () async {
    final remote = TomMemoryRemote();
    const primaryLocator = 'mem:vaults/primary.kdbx';
    const fleetLocator = 'mem:vaults/fleet.kdbx';
    // The primary records the vault's real locator; the memory remote here
    // stands in for its repository.
    const fleetGitHub = 'github:al-the-bear/demo-vaults/vaults/fleet.kdbx';
    final keyFile = TomSecretsKeyFile.generate();
    final fleetKeys = TomSecretsVaultKeys(
      name: 'fleet',
      locator: fleetGitHub,
      password: 'fleet-demo-pw',
      keyFile: keyFile.toBytes(),
    );

    final primary = tomSecretsNewVault(primaryCredentials, 'primary');
    TomSecretsPrimaryVaults(primary).put(fleetKeys);
    await TomSecretsVaultUnit.create(
      locator: primaryLocator,
      storage: TomMemoryStorage(remote),
      file: primary,
      device: 'mbp',
    );
    await TomSecretsVaultUnit.create(
      locator: fleetLocator,
      storage: TomMemoryStorage(remote),
      file: tomSecretsNewVault(fleetKeys.credentials, 'fleet'),
      device: 'mbp',
    );

    final openedPrimary = await TomSecretsVaultUnit.open(
      locator: primaryLocator,
      storage: TomMemoryStorage(remote),
      credentials: primaryCredentials,
      device: 'bigbeast',
    );
    final keys = TomSecretsPrimaryVaults(
      openedPrimary.working,
    ).byName('fleet')!;
    expect(keys.locator, fleetGitHub);
    final fleet = await TomSecretsVaultUnit.open(
      locator: fleetLocator,
      storage: TomMemoryStorage(remote),
      credentials: keys.credentials,
      device: 'bigbeast',
    );
    for (final unit in [openedPrimary, fleet]) {
      expect(kdbxVersion(unit.baseBytes), (4, 1), reason: unit.locator);
      expect(unit.working.argon2, tomSecretsDefaultArgon2);
    }

    fleet.working.body.rootGroup.addEntry(
      KdbxEntry.create(fleet.working, fleet.working.body.rootGroup)
        ..setString(KdbxKeyCommon.TITLE, PlainValue('Db')),
    );
    fleet.markEdited();
    await fleet.push();
    final again = await KdbxFormat().read(
      remote.snapshot(fleetLocator)[TomChangeset.containerPath]!,
      keys.credentials,
    );
    expect(again.argon2, tomSecretsDefaultArgon2, reason: 'after a save');
  });

  test(
    'NV-3: KeePassXC opens a new vault and reports Argon2id, 3 rounds, '
    '64 MiB',
    () async {
      final cli = findKeePassXc()!;
      final dir = Directory('${Directory.current.path}/testlog/new_vault_nv3')
        ..createSync(recursive: true);
      try {
        final vault = tomSecretsNewVault(primaryCredentials, 'kxc');
        final file = File('${dir.path}/kxc.kdbx')
          ..writeAsBytesSync(await vault.save());
        final process = await Process.start(cli, ['db-info', '-q', file.path]);
        process.stdin.writeln('primary-demo-pw');
        await process.stdin.close();
        final out = await process.stdout.transform(utf8.decoder).join();
        final error = await process.stderr.transform(utf8.decoder).join();
        expect(await process.exitCode, 0, reason: error);
        expect(out, contains('KDF: Argon2id (3 rounds, 65536 KB)'));
      } finally {
        dir.deleteSync(recursive: true);
      }
    },
    skip: findKeePassXc() == null
        ? 'keepassxc-cli is not on this machine'
        : null,
  );

  test('NV-4: a vault is never created with another key derivation', () async {
    expect(
      () => tomSecretsNewVault(
        primaryCredentials,
        'd',
        argon2: KdbxArgon2.defaults,
      ),
      throwsArgumentError,
    );
    await expectLater(
      TomSecretsVaultUnit.create(
        locator: 'mem:vaults/argon2d.kdbx',
        storage: TomMemoryStorage(TomMemoryRemote()),
        file: KdbxFormat().create(primaryCredentials, 'd'),
        device: 'mbp',
      ),
      throwsArgumentError,
    );
  });

  test('NV-5: the tests\' own vaults are Argon2id too', () {
    expect(DemoVault().file.argon2?.type, KdbxArgon2Type.argon2id);
  });
}
