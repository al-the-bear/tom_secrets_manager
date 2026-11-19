// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Member keys (part-sharing, DP-63, DP-177): the hybrid age identity and
// recipient against keys filippo.io/age v1.3.2 made
// (fixtures/member_keys/go_age_v1_3.txt), the fingerprints against an
// independent SHA-256/base32, the refusals, the published key file, and
// the member-key and member entries in a demo vault. Demo keys only.

import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

Map<String, String> _goKeys() => {
  for (final line in File(
    'test/fixtures/member_keys/go_age_v1_3.txt',
  ).readAsLinesSync())
    if (!line.startsWith('#'))
      line.substring(0, line.indexOf(': ')): line.substring(
        line.indexOf(': ') + 2,
      ),
};

TypeMatcher<TomSecretsMemberKeyException> _refused(
  TomSecretsMemberKeyFailure reason,
) => isA<TomSecretsMemberKeyException>().having(
  (e) => e.reason,
  'reason',
  reason,
);

void main() {
  final go = _goKeys();

  group('keys', () {
    test('an identity age made gives the recipient age computes', () async {
      final key = await TomSecretsMemberKey.parse(go['hybrid-identity']!);
      addTearDown(key.dispose);
      expect(key.recipient.encoded, go['hybrid-recipient']);
      expect(key.recipient.isHybrid, isTrue);
      expect(key.recipient.encoded, hasLength(1959));
      expect(key.revealIdentity(), go['hybrid-identity']);
      expect(
        TomSecretsAgeRecipient.parse(go['hybrid-recipient']!),
        key.recipient,
      );
    });

    test('a new key: age1pq1, its identity reads back to it', () async {
      final key = await TomSecretsMemberKey.generate();
      addTearDown(key.dispose);
      expect(key.recipient.encoded, startsWith('age1pq1'));
      expect(key.recipient.publicKey, hasLength(1216));
      final identity = key.revealIdentity();
      expect(identity, startsWith('AGE-SECRET-KEY-PQ-1'));
      expect(identity, hasLength(77));
      final back = await TomSecretsMemberKey.parse(identity);
      addTearDown(back.dispose);
      expect(back.recipient, key.recipient);
      await key.recipient.check();
      final other = await TomSecretsMemberKey.generate();
      addTearDown(other.dispose);
      expect(other.recipient, isNot(key.recipient));
    });

    test('fingerprints: base32 of the SHA-256 of the recipient', () {
      final hybrid = TomSecretsAgeRecipient.parse(go['hybrid-recipient']!);
      // Python: base64.b32encode(sha256(recipient)).lower().rstrip('=').
      expect(
        hybrid.fingerprint,
        'wgelhhnt6gbnci7utaaz5zrwgep5gra64jr7575he67lakmu6sha',
      );
      expect(hybrid.shortFingerprint, 'wgel hhnt 6gbn ci7u taaz');
      final classical = TomSecretsAgeRecipient.parse(go['x25519-recipient']!);
      expect(
        classical.fingerprint,
        '4zpfsxdellllocbwll7eeh3mhpviuzq3mru25nnntowi7wxyoswa',
      );
    });

    test(
      'a classical recipient is read, for exports; its identity is refused',
      () async {
        final classical = TomSecretsAgeRecipient.parse(go['x25519-recipient']!);
        expect(classical.kind, TomSecretsAgeRecipientKind.classical);
        expect(classical.isHybrid, isFalse);
        expect(classical.publicKey, hasLength(32));
        await classical.check();
        await expectLater(
          TomSecretsMemberKey.parse(go['x25519-identity']!),
          throwsA(_refused(TomSecretsMemberKeyFailure.classicalIdentity)),
        );
      },
    );

    test(
      'upper case reads as the same key, written in lower case; mixed case is refused',
      () {
        final r = TomSecretsAgeRecipient.parse(go['hybrid-recipient']!);
        final upper = TomSecretsAgeRecipient.parse(
          '  ${r.encoded.toUpperCase()}\n',
        );
        expect(upper, r);
        expect(upper.encoded, go['hybrid-recipient']);
        final mixed = 'A${r.encoded.substring(1)}';
        expect(
          () => TomSecretsAgeRecipient.parse(mixed),
          throwsA(_refused(TomSecretsMemberKeyFailure.malformed)),
        );
      },
    );

    test(
      'a changed character, a plugin key, the wrong length and other text are refused',
      () {
        final r = go['hybrid-recipient']!;
        final i = r.length ~/ 2;
        final changed =
            '${r.substring(0, i)}${r[i] == 'q' ? 'p' : 'q'}${r.substring(i + 1)}';
        expect(
          () => TomSecretsAgeRecipient.parse(changed),
          throwsA(_refused(TomSecretsMemberKeyFailure.malformed)),
        );
        // Bech32 strings made by an independent encoder.
        expect(
          () => TomSecretsAgeRecipient.parse(
            'age1yubikey1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqmenk29',
          ),
          throwsA(_refused(TomSecretsMemberKeyFailure.plugin)),
        );
        expect(
          () => TomSecretsAgeRecipient.parse(
            'age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnryu6xr',
          ),
          throwsA(_refused(TomSecretsMemberKeyFailure.malformed)),
        );
        for (final text in [
          '',
          'ssh-ed25519 AAAA demo',
          'age1',
          'hello world',
        ]) {
          expect(
            () => TomSecretsAgeRecipient.parse(text),
            throwsA(_refused(TomSecretsMemberKeyFailure.malformed)),
            reason: text,
          );
        }
      },
    );

    test('a hybrid key whose ML-KEM half fails FIPS 203 is invalid', () async {
      final bad = TomSecretsAgeRecipient.hybrid(
        Uint8List(1216)
          ..fillRange(0, 1184, 0xff)
          ..[1200] = 9,
      );
      await expectLater(
        bad.check(),
        throwsA(_refused(TomSecretsMemberKeyFailure.invalidKey)),
      );
    });
  });

  group('the published key file', () {
    test(
      'age recipients-file format with name, fingerprint and date as comments',
      () {
        final r = TomSecretsAgeRecipient.parse(go['hybrid-recipient']!);
        final text = tomSecretsMemberKeyFile(
          r,
          name: 'Alice\nDemo',
          created: DateTime.utc(2026, 11, 19, 15),
        );
        expect(text.split('\n'), [
          '# Tom Secrets Manager member key (age, X25519 + ML-KEM-768)',
          '# name: Alice Demo',
          '# fingerprint: wgel hhnt 6gbn ci7u taaz',
          '# created: 2026-11-19',
          r.encoded,
          '',
        ]);
        final read = tomSecretsReadMemberKeys(text);
        expect(read, hasLength(1));
        expect(read.single.recipient, r);
        expect(read.single.name, 'Alice Demo');
        expect(
          tomSecretsMemberKeyFileName(' Alice Demo! '),
          'alice_demo.age-recipient.txt',
        );
        expect(tomSecretsMemberKeyFileName('…'), 'member.age-recipient.txt');
      },
    );

    test('several keys, pasted keys and QR text; a bad line is named', () {
      final h = go['hybrid-recipient']!;
      final x = go['x25519-recipient']!;
      final read = tomSecretsReadMemberKeys(
        '# name: Bob\n$h\n\n# a comment\n${x.toUpperCase()}\n',
      );
      expect(read.map((k) => k.name), ['Bob', null]);
      expect(read.map((k) => k.recipient.encoded), [h, x]);
      expect(tomSecretsReadMemberKeys(h).single.name, isNull);
      expect(
        () => tomSecretsReadMemberKeys('$h\nnot a key\n'),
        throwsA(
          _refused(
            TomSecretsMemberKeyFailure.malformed,
          ).having((e) => e.message, 'message', startsWith('line 2: ')),
        ),
      );
      expect(
        () => tomSecretsReadMemberKeys('# only a comment\n'),
        throwsA(_refused(TomSecretsMemberKeyFailure.malformed)),
      );
    });
  });

  group('the primary vault', () {
    late KdbxFile file;
    setUp(() => file = newTestVault(demoCredentials, 'primary'));

    test(
      'the member key in tsm.sharing, read back; not resolved, not exported',
      () async {
        final key = await TomSecretsMemberKey.generate();
        addTearDown(key.dispose);
        final entry = tomSecretsAddMemberKey(file, key);
        expect(tomSecretsSharingGroupOf(file)!.entries, [entry]);
        expect(tomSecretsMemberKeyEntries(file), [entry]);
        expect(entry.label, 'Member key');
        expect(entry.getString(KdbxKeyCommon.PASSWORD), isA<ProtectedValue>());
        expect(tomSecretsMemberKeyRecipientOf(entry), key.recipient);
        expect(
          entry.getString(TomSecretsMemberFields.fingerprint)!.getText(),
          key.recipient.fingerprint,
        );
        final back = await tomSecretsMemberKeyOf(entry);
        addTearDown(back.dispose);
        expect(back.recipient, key.recipient);

        final store = TomSecretsStore.fromFile(file, name: 'primary');
        expect(store.entries, isEmpty);
        expect(tomSecretsExportEntries(file), isEmpty);
      },
    );

    test(
      'members: added by name, refused twice or as the own key, checked',
      () async {
        final own = await TomSecretsMemberKey.generate();
        addTearDown(own.dispose);
        tomSecretsAddMemberKey(file, own);
        final bob = TomSecretsAgeRecipient.parse(go['hybrid-recipient']!);
        final carol = TomSecretsAgeRecipient.parse(go['x25519-recipient']!);

        final added = await tomSecretsAddMember(
          file,
          name: ' Bob ',
          recipient: bob,
        );
        expect(added.name, 'Bob');
        expect(added.checked, isNull);
        expect(added.canJoinSharedVaults, isTrue);
        await tomSecretsAddMember(
          file,
          name: 'Carol',
          recipient: carol,
          checked: DateTime.utc(2026, 11, 18, 23),
        );

        final members = tomSecretsMembers(file);
        expect(members.map((m) => m.name), ['Bob', 'Carol']);
        expect(members.last.checked, DateTime.parse('2026-11-18'));
        expect(members.last.canJoinSharedVaults, isFalse);
        expect(
          TomSecretsEntryType.of(
            members.first.entry
                .getString(TomSecretsEntryFields.type)!
                .getText(),
          ),
          TomSecretsEntryType.member,
        );

        await expectLater(
          tomSecretsAddMember(file, name: 'Bob again', recipient: bob),
          throwsA(
            _refused(
              TomSecretsMemberKeyFailure.duplicate,
            ).having((e) => e.message, 'message', contains('Bob')),
          ),
        );
        await expectLater(
          tomSecretsAddMember(file, name: 'Me', recipient: own.recipient),
          throwsA(_refused(TomSecretsMemberKeyFailure.ownKey)),
        );

        // As the app meets it: the vault read from its file.
        file = await KdbxFormat().read(await file.save(), demoCredentials);
        final bobEntry = tomSecretsMembers(file).first.entry;
        final before = bobEntry.history.length;
        tomSecretsMarkMemberChecked(bobEntry, DateTime.utc(2026, 11, 19));
        expect(
          tomSecretsMembers(file).first.checked,
          DateTime.parse('2026-11-19'),
        );
        expect(bobEntry.history.length, before + 1);
        expect(tomSecretsMembers(file).map((m) => m.recipient), [bob, carol]);
        expect(tomSecretsMemberKeyEntries(file), hasLength(1));
      },
    );
  });
}
