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
}
