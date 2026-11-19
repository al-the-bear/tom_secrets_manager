// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Shared vaults (part-sharing, part-stores): the recipients file written to
// the members' hybrid keys and read by each, a member added (keys kept) and
// removed (new keys the removed member cannot read), the refusals, the file
// name beside the vault, and a new shared vault opened by its key file
// alone. Demo keys only.

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

TypeMatcher<TomSecretsSharedVaultException> _refused(
  TomSecretsSharedVaultFailure reason,
) => isA<TomSecretsSharedVaultException>().having(
  (e) => e.reason,
  'reason',
  reason,
);

void main() {
  late TomSecretsMemberKey alice;
  late TomSecretsMemberKey bob;
  late TomSecretsMemberKey carol;
  setUpAll(() async {
    alice = await TomSecretsMemberKey.generate();
    bob = await TomSecretsMemberKey.generate();
    carol = await TomSecretsMemberKey.generate();
  });
  tearDownAll(() {
    alice.dispose();
    bob.dispose();
    carol.dispose();
  });

  TomSecretsSharedVaultMember member(String name, TomSecretsMemberKey k) =>
      (name: name, recipient: k.recipient);

  test('the recipients file is read by every member, not by others', () async {
    final keys = TomSecretsSharedVaultKeys.generate(
      'team',
      members: [member('Alice', alice), member('Bob', bob)],
    );
    addTearDown(keys.dispose);
    expect(keys.repositoryKey, isNull);
    expect(TomSecretsKeyFile.parse(keys.keyFile).key, hasLength(32));
    final file = await tomSecretsWriteRecipientsFile(keys);
    expect(ascii.decode(file.sublist(0, 22)), 'age-encryption.org/v1\n');
    for (final k in [alice, bob]) {
      final read = await tomSecretsReadRecipientsFile(file, k);
      expect(read.vault, 'team');
      expect(read.keyFile, keys.keyFile);
      expect(read.members.map((m) => m.name), ['Alice', 'Bob']);
      expect(read.members.map((m) => m.recipient), [
        alice.recipient,
        bob.recipient,
      ]);
    }
    await expectLater(
      tomSecretsReadRecipientsFile(file, carol),
      throwsA(_refused(TomSecretsSharedVaultFailure.notAMember)),
    );
  });

  test('adding keeps the keys; removing makes new keys the removed member '
      'cannot read', () async {
    final keys = TomSecretsSharedVaultKeys.generate(
      'team',
      members: [member('Alice', alice), member('Bob', bob)],
      outer: true,
    );
    addTearDown(keys.dispose);
    expect(
      TomSecretsRepositoryKey.fromBase64(keys.repositoryKey!).bytes,
      hasLength(32),
    );

    final added = keys.withMember(member('Carol', carol));
    expect(added.keyFile, keys.keyFile);
    expect(added.repositoryKey, keys.repositoryKey);
    expect(added.hasMember(carol.recipient), isTrue);
    final withCarol = await tomSecretsWriteRecipientsFile(added);
    expect(
      (await tomSecretsReadRecipientsFile(withCarol, carol)).keyFile,
      keys.keyFile,
    );

    final removed = added.withoutMember(bob.recipient);
    expect(removed.keyFile, isNot(keys.keyFile));
    expect(removed.repositoryKey, isNotNull);
    expect(removed.repositoryKey, isNot(keys.repositoryKey));
    expect(removed.members.map((m) => m.name), ['Alice', 'Carol']);
    final withoutBob = await tomSecretsWriteRecipientsFile(removed);
    await expectLater(
      tomSecretsReadRecipientsFile(withoutBob, bob),
      throwsA(_refused(TomSecretsSharedVaultFailure.notAMember)),
    );
    expect(
      (await tomSecretsReadRecipientsFile(withoutBob, alice)).keyFile,
      removed.keyFile,
    );
  });

  test('refused: no member, a classical key, a member twice, removing a '
      'stranger', () {
    final classical = TomSecretsAgeRecipient.parse(
      'age1vg68yht8qxg2p0tedkg4pp9f6tqu4zpm55n52zca7mzy0rw7lvwq73k9ju',
    );
    expect(
      () => TomSecretsSharedVaultKeys.generate('team', members: const []),
      throwsA(_refused(TomSecretsSharedVaultFailure.members)),
    );
    expect(
      () => TomSecretsSharedVaultKeys.generate(
        'team',
        members: [member('Alice', alice), (name: 'Dan', recipient: classical)],
      ),
      throwsA(
        _refused(
          TomSecretsSharedVaultFailure.members,
        ).having((e) => e.message, 'message', contains('Dan has a classical')),
      ),
    );
    final keys = TomSecretsSharedVaultKeys.generate(
      'team',
      members: [member('Alice', alice)],
    );
    expect(
      () => keys.withMember(member('Alice again', alice)),
      throwsA(_refused(TomSecretsSharedVaultFailure.members)),
    );
    expect(
      () => keys.withoutMember(bob.recipient),
      throwsA(_refused(TomSecretsSharedVaultFailure.members)),
    );
  });

  test('the plaintext is JSON age opens; a broken one is refused', () async {
    final keys = TomSecretsSharedVaultKeys.generate(
      'team',
      members: [member('Alice', alice)],
    );
    final json = keys.toJson();
    expect(json['format'], 'tsm-shared-vault-keys/1');
    expect(json.containsKey('repositoryKey'), isFalse);
    expect(TomSecretsSharedVaultKeys.fromJson(json).keyFile, keys.keyFile);
    for (final bad in [
      {...json, 'format': 'other/1'},
      {...json, 'keyFile': 7},
      {
        ...json,
        'members': [
          {'name': 'X', 'recipient': 'nope'},
        ],
      },
    ]) {
      expect(
        () => TomSecretsSharedVaultKeys.fromJson(bad),
        throwsA(_refused(TomSecretsSharedVaultFailure.malformed)),
      );
    }
    final notJson = await tomSecretsAgeEncrypt(utf8.encode('not json'), [
      alice.recipient,
    ]);
    await expectLater(
      tomSecretsReadRecipientsFile(notJson, alice),
      throwsA(_refused(TomSecretsSharedVaultFailure.malformed)),
    );
  });

  test(
    'the file beside the vault; a new shared vault opens by its key file',
    () async {
      expect(tomSecretsRecipientsFileName('team.kdbx'), 'team.keys.age');
      expect(tomSecretsRecipientsFileName('team.kdbx.tsmx'), 'team.keys.age');
      final keys = TomSecretsSharedVaultKeys.generate(
        'team',
        members: [member('Alice', alice)],
      );
      final file = tomSecretsNewSharedVault(
        'team',
        keys,
        purpose: 'demo',
        argon2: testArgon2,
      );
      final saved = await file.save();
      final opened = await KdbxFormat().read(saved, keys.credentials);
      final metadata = TomSecretsMetadata.read(opened);
      expect(metadata.kind, TomSecretsVaultKind.shared);
      expect(metadata.store, 'team');
      expect(metadata.purpose, 'demo');
      await expectLater(
        KdbxFormat().read(
          saved,
          tomSecretsVaultCredentials(keyFile: Uint8List(32)),
        ),
        throwsA(isA<KdbxInvalidKeyException>()),
      );
    },
  );
}
