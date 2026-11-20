// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The guided rotation's record (part-key-rotation): started (the lock: one
// per target), switched, updated, ended, read back from a saved vault; the
// key id; and the recipients file during a member key's rotation (old and
// new key side by side, the old one dropped at the finish) and a shared
// vault's rotated keys. Demo keys only.

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

void main() {
  final started = DateTime.utc(2026, 11, 19, 10);

  TomSecretsRotation rotation(String target, {String by = 'mbp'}) =>
      TomSecretsRotation(
        kind: TomSecretsRotationKind.sharedVault,
        target: target,
        oldKeyId: '0011223344556677',
        newKeyId: '8899aabbccddeeff',
        started: started,
        endsAt: started.add(tomSecretsRotationPeriod),
        by: by,
        pending: const ['bigbeast'],
      );

  test(
    'a record: started, one per target, switched, read back, ended',
    () async {
      final file = newTestVault(demoCredentials, 'primary');
      final records = TomSecretsRotations(file);
      expect(records.list(), isEmpty);
      records.start(rotation('crew'));
      records.start(rotation('team'));
      expect(
        () => records.start(rotation('crew', by: 'bomber')),
        throwsA(
          isA<TomSecretsRotationException>()
              .having((e) => e.rotation?.by, 'by', 'mbp')
              .having((e) => e.message, 'message', contains('2026-11-19')),
        ),
      );

      final crew = records.of(TomSecretsRotationKind.sharedVault, 'crew')!;
      expect(crew.endsAt, DateTime.utc(2026, 12, 3, 10));
      expect(crew.isDueAt(DateTime.utc(2026, 12, 3, 9)), isFalse);
      expect(crew.isDueAt(DateTime.utc(2026, 12, 3, 10)), isTrue);
      records.update(crew.copyWith(switched: started, pending: const []));

      final back = TomSecretsRotations(
        await KdbxFormat().read(await file.save(), demoCredentials),
      );
      final read = back.of(TomSecretsRotationKind.sharedVault, 'crew')!;
      expect(read.switched, started);
      expect(read.pending, isEmpty);
      expect(read.oldKeyId, '0011223344556677');
      expect(read.by, 'mbp');
      expect(back.list(), hasLength(2));
      expect(back.of(TomSecretsRotationKind.memberKey, 'crew'), isNull);

      expect(back.end(TomSecretsRotationKind.sharedVault, 'crew'), isTrue);
      expect(back.end(TomSecretsRotationKind.sharedVault, 'crew'), isFalse);
      expect(back.list().map((r) => r.target), ['team']);
      expect(
        () => back.update(rotation('gone')),
        throwsA(isA<TomSecretsRotationException>()),
      );
    },
  );

  test('the key id: the first 8 bytes of the SHA-256, in hex', () {
    // printf 'demo' | shasum -a 256
    expect(tomSecretsKeyId('demo'.codeUnits), '2a97516c354b6884');
  });

  group('recipients files during a rotation', () {
    late TomSecretsMemberKey old;
    late TomSecretsMemberKey next;
    late TomSecretsMemberKey bob;
    setUpAll(() async {
      old = await TomSecretsMemberKey.generate();
      next = await TomSecretsMemberKey.generate();
      bob = await TomSecretsMemberKey.generate();
    });
    tearDownAll(() {
      old.dispose();
      next.dispose();
      bob.dispose();
    });

    test('a member key rotating: old and new key side by side, the old one '
        'dropped at the finish, the vault\'s keys kept', () async {
      final keys = TomSecretsSharedVaultKeys.generate(
        'crew',
        members: [
          (name: 'Alice', recipient: old.recipient),
          (name: 'Bob', recipient: bob.recipient),
        ],
      );
      final during = keys.withMember((
        name: 'Alice',
        recipient: next.recipient,
      ));
      final file = await tomSecretsWriteRecipientsFile(during);
      for (final k in [old, next, bob]) {
        expect(
          (await tomSecretsReadRecipientsFile(file, k)).keyFile,
          keys.keyFile,
        );
      }
      final finished = during.withoutRecipient(old.recipient);
      expect(finished.keyFile, keys.keyFile);
      expect(finished.members.map((m) => m.recipient), [
        bob.recipient,
        next.recipient,
      ]);
      final after = await tomSecretsWriteRecipientsFile(finished);
      await expectLater(
        tomSecretsReadRecipientsFile(after, old),
        throwsA(isA<TomSecretsSharedVaultException>()),
      );
      expect(
        () => finished.withoutRecipient(old.recipient),
        throwsA(isA<TomSecretsSharedVaultException>()),
      );
    });

    test('a shared vault\'s keys rotated: new keys, the same members', () {
      final keys = TomSecretsSharedVaultKeys.generate(
        'crew',
        members: [
          (name: 'Alice', recipient: old.recipient),
          (name: 'Bob', recipient: bob.recipient),
        ],
        outer: true,
      );
      final rotated = keys.rotated();
      expect(rotated.keyFile, isNot(keys.keyFile));
      expect(rotated.keyId, isNot(keys.keyId));
      expect(rotated.repositoryKey, isNot(keys.repositoryKey));
      expect(rotated.repositoryKey, isNotNull);
      expect(rotated.members, keys.members);
      expect(keys.keyId, tomSecretsKeyId(keys.keyFile));
    });
  });

  group('the guided rotation of the own vaults (prepare, switch, finish)', () {
    test(
      'a vault entry keeps next and previous keys; copyWith moves them',
      () async {
        final file = newTestVault(demoCredentials, 'primary');
        final list = TomSecretsPrimaryVaults(file);
        final oldOuter = TomSecretsRepositoryKey.generate().toBase64();
        final newOuter = TomSecretsRepositoryKey.generate().toBase64();
        final nextFile = TomSecretsKeyFile.generate().toBytes();
        list.put(
          TomSecretsVaultKeys(
            name: 'fleet',
            locator: 'github:demo/vaults/fleet.kdbx.tsmx',
            password: 'demo-pw',
            outerKey: oldOuter,
            nextKeyFile: nextFile,
            nextOuterKey: newOuter,
          ),
        );
        final back = TomSecretsPrimaryVaults(
          await KdbxFormat().read(await file.save(), demoCredentials),
        ).byName('fleet')!;
        expect(back.hasNext, isTrue);
        expect(back.nextKeyFile, nextFile);
        expect(back.nextOuterKey, newOuter);
        expect(back.writtenOuterKeys, oldOuter);

        final switched = back.copyWith(
          keyFile: back.nextKeyFile,
          outerKey: back.nextOuterKey,
          previousOuterKey: back.outerKey,
          clearNext: true,
        );
        expect(switched.hasNext, isFalse);
        expect(switched.writtenOuterKeys, '$newOuter,$oldOuter');
        list.put(switched);
        final finished = list.byName('fleet')!.copyWith(clearPrevious: true);
        expect(finished.previousOuterKey, isNull);
        expect(finished.outerKey, newOuter);
        expect(finished.password, 'demo-pw');
      },
    );

    test('the primary\'s own next keys: written, read back, cleared', () async {
      final file = newTestVault(demoCredentials, 'primary');
      expect(TomSecretsPrimaryNextKeys.of(file), isNull);
      final keyFile = TomSecretsKeyFile.generate().toBytes();
      final outer = TomSecretsRepositoryKey.generate().toBase64();
      TomSecretsPrimaryNextKeys(
        keyFile: keyFile,
        outerKey: outer,
      ).writeTo(file);
      final read = TomSecretsPrimaryNextKeys.of(
        await KdbxFormat().read(await file.save(), demoCredentials),
      )!;
      expect(read.keyFile, keyFile);
      expect(read.outerKey, outer);
      expect(read.previousOuterKey, isNull);
      expect(TomSecretsPrimaryVaults(file).list(), isEmpty);
      expect(TomSecretsPrimaryNextKeys.clear(file), isTrue);
      expect(TomSecretsPrimaryNextKeys.of(file), isNull);
      expect(TomSecretsPrimaryNextKeys.clear(file), isFalse);
    });

    test('two repository keys: every write gets a slot for each, either '
        'reads it, the key ids as pairing records them', () async {
      final oldKey = TomSecretsRepositoryKey.generate();
      final newKey = TomSecretsRepositoryKey.generate();
      final joined = tomSecretsJoinOuterKeys([
        newKey.toBase64(),
        null,
        oldKey.toBase64(),
        newKey.toBase64(),
      ])!;
      expect(tomSecretsOuterKeyList(joined), [
        newKey.toBase64(),
        oldKey.toBase64(),
      ]);
      const locator = 'github:demo/vaults/fleet.kdbx.tsmx';
      final vault = newTestVault(demoCredentials, 'fleet');
      final stored = await tomSecretsEncodeStored(
        locator,
        vault,
        outerKey: joined,
      );
      expect(tomSecretsOuterKeyIds(stored), [newKey.keyIdHex, oldKey.keyIdHex]);
      for (final one in [oldKey, newKey]) {
        await tomSecretsDecodeStored(
          locator,
          stored,
          demoCredentials,
          outerKey: one.toBase64(),
        );
      }
      final keyFile = TomSecretsKeyFile.generate().toBytes();
      expect(tomSecretsVaultKeyIds(keyFile: keyFile, outerKey: joined), [
        TomSecretsKeyFile.parse(keyFile).hash,
        newKey.keyIdHex,
        oldKey.keyIdHex,
      ]);
      expect(tomSecretsJoinOuterKeys([null, '']), isNull);
    });

    test('a device takes the next keys: its record gets the new key id, it '
        'leaves the pending; a device that did not stays missing', () async {
      final file = newTestVault(demoCredentials, 'primary');
      final now = DateTime.utc(2026, 11, 20, 9);
      final nextFile = TomSecretsKeyFile.generate().toBytes();
      TomSecretsPrimaryVaults(file).put(
        TomSecretsVaultKeys(
          name: 'fleet',
          locator: 'github:demo/vaults/fleet.kdbx',
          keyFile: TomSecretsKeyFile.generate().toBytes(),
          nextKeyFile: nextFile,
        ),
      );
      final newId = TomSecretsKeyFile.parse(nextFile).hash;
      final records = TomSecretsDeviceRecords(file);
      for (final d in ['bomber', 'bigbeast']) {
        records.put(TomSecretsDeviceRecord(device: d, paired: now));
      }
      TomSecretsRotations(file).start(
        TomSecretsRotation(
          kind: TomSecretsRotationKind.vaultKeys,
          target: 'fleet',
          oldKeyId: 'old',
          newKeyId: newId,
          started: now,
          endsAt: now.add(tomSecretsRotationPeriod),
          by: 'mbp',
          pending: const ['bomber', 'bigbeast'],
        ),
      );
      expect(records.missingKey(newId).map((r) => r.device), [
        'bomber',
        'bigbeast',
      ]);
      expect(tomSecretsTakeNextKeys(file, device: 'bomber', now: now), isTrue);
      expect(tomSecretsTakeNextKeys(file, device: 'bomber', now: now), isFalse);
      // The first device, never paired, gets a record.
      expect(tomSecretsTakeNextKeys(file, device: 'mbp', now: now), isTrue);
      expect(records.byDevice('mbp')!.keyIds, [newId]);
      expect(records.missingKey(newId).map((r) => r.device), ['bigbeast']);
      final record = TomSecretsRotations(
        file,
      ).of(TomSecretsRotationKind.vaultKeys, 'fleet')!;
      expect(record.pending, ['bigbeast']);
      // Nothing running: nothing taken.
      final plain = newTestVault(demoCredentials, 'other');
      expect(tomSecretsTakeNextKeys(plain, device: 'mbp', now: now), isFalse);
    });
  });
}
