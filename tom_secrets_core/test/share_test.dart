// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Single-entry exports (part-sharing, BP-34): the share's JSON document
// made from vault entries (what it carries and leaves out), encrypted to
// member keys, under a passphrase or to a classical key, read back and
// imported as new entries; its refusals; whether it fits a QR code; and
// the inbox folders' names, dates and expiry. Demo keys only.

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

void main() {
  late TomSecretsMemberKey alice;
  late TomSecretsMemberKey bob;
  setUpAll(() async {
    alice = await TomSecretsMemberKey.generate();
    bob = await TomSecretsMemberKey.generate();
  });
  tearDownAll(() {
    alice.dispose();
    bob.dispose();
  });

  /// A login with a protected password, tags, an attachment, an expiry,
  /// the product's type and key, another `tsm.*` field and an overlay.
  KdbxEntry login(KdbxFile file) {
    final e = KdbxEntry.create(file, file.body.rootGroup);
    file.body.rootGroup.addEntry(e);
    e.modify(() {
      e
        ..setString(KdbxKey('Title'), PlainValue('Demo mail'))
        ..setString(KdbxKey('UserName'), PlainValue('alice@example.com'))
        ..setString(KdbxKey('Password'), ProtectedValue.fromString('demo-pw'))
        ..setString(TomSecretsEntryFields.type, PlainValue('login'))
        ..setString(TomSecretsEntryFields.key, PlainValue('mail.demo'))
        ..setString(KdbxKey('tsm.urlMatch'), PlainValue('host'))
        ..setString(KdbxKey('@host=mbp'), PlainValue('mbp-only'))
        ..createBinary(
          isProtected: false,
          name: 'note.txt',
          bytes: Uint8List.fromList(utf8.encode('attached')),
        );
      e.tags.set('mail;work');
      e.times.expires.set(true);
      e.times.expiryTime.set(DateTime.utc(2027, 1, 31));
    });
    return e;
  }

  test('the document: what an entry carries, read back', () {
    final file = newTestVault(demoCredentials, 'mine');
    final share = tomSecretsShareOf(
      [login(file)],
      from: (name: 'Alice', fingerprint: alice.recipient.fingerprint),
      now: DateTime.utc(2026, 11, 19, 12),
    );
    final back = TomSecretsShare.decode(share.encode());
    expect(back.from?.name, 'Alice');
    expect(back.from?.fingerprint, alice.recipient.fingerprint);
    expect(back.created, DateTime.utc(2026, 11, 19, 12));
    final e = back.entries.single;
    expect(e.title, 'Demo mail');
    expect(e.type, TomSecretsEntryType.login);
    expect(e.fields['Password'], (value: 'demo-pw', protected: true));
    expect(e.fields['UserName']?.protected, isFalse);
    expect(e.fields['tsm.key']?.value, 'mail.demo');
    expect(e.fields.containsKey('tsm.urlMatch'), isFalse);
    expect(e.fields.containsKey('@host=mbp'), isFalse);
    expect(e.tags, ['mail', 'work']);
    expect(utf8.decode(e.attachments['note.txt']!.bytes), 'attached');
    expect(e.expires, DateTime.utc(2027, 1, 31));
  });

  test('to member keys: read by each, imported as new entries', () async {
    final file = newTestVault(demoCredentials, 'mine');
    final original = login(file);
    final share = tomSecretsShareOf([original]);
    final bytes = await tomSecretsWriteShare(
      share,
      recipients: [alice.recipient, bob.recipient],
    );
    expect(tomSecretsAgeIsPassphrase(bytes), isFalse);
    for (final k in [alice, bob]) {
      final read = await tomSecretsReadShare(bytes, [
        TomSecretsAgeHybridIdentity(k),
      ]);
      expect(read.entries.single.title, 'Demo mail');
    }
    // The armoured text reads the same.
    final text = tomSecretsAgeArmor(bytes);
    expect(tomSecretsLooksLikeShare(text), isTrue);
    final pasted = await tomSecretsReadShare(utf8.encode(text), [
      TomSecretsAgeHybridIdentity(bob),
    ]);

    final theirs = newTestVault(demoCredentials, 'theirs');
    final group = theirs.createGroup(
      parent: theirs.body.rootGroup,
      name: 'From Alice',
    );
    final imported = tomSecretsImportShare(theirs, group, pasted);
    expect(imported, hasLength(1));
    final e = imported.single;
    expect(e.parent, same(group));
    expect(e.uuid, isNot(original.uuid));
    expect(e.getString(KdbxKey('Password')), isA<ProtectedValue>());
    expect(e.getString(KdbxKey('Password'))?.getText(), 'demo-pw');
    expect(e.getString(TomSecretsEntryFields.type)?.getText(), 'login');
    expect(e.tags.get(), 'mail;work');
    expect(e.times.expires.get(), isTrue);
    expect(e.binaryEntries.single.key.key, 'note.txt');
    // Imported twice: two entries, no collision.
    tomSecretsImportShare(theirs, group, pasted);
    expect(group.entries, hasLength(2));
  });

  test('under a passphrase, to a classical key; the refusals', () async {
    final share = tomSecretsShareOf([
      login(newTestVault(demoCredentials, 'mine')),
    ]);
    final locked = await tomSecretsWriteShare(
      share,
      passphrase: 'demo passphrase',
      workFactor: 10,
    );
    expect(tomSecretsAgeIsPassphrase(locked), isTrue);
    expect(
      (await tomSecretsReadShare(locked, [
        const TomSecretsAgePassphraseIdentity('demo passphrase'),
      ])).entries.single.title,
      'Demo mail',
    );
    await expectLater(
      tomSecretsReadShare(locked, [TomSecretsAgeHybridIdentity(alice)]),
      throwsA(isA<TomSecretsAgeException>()),
    );

    final identity = TomSecretsAgeX25519Identity.parse(
      'AGE-SECRET-KEY-1CYJJCCQEGXMJWST3YH0Q40FSAN9253TSGS566S9LXJFAWSRMF3AST60U4U',
    );
    addTearDown(identity.dispose);
    final classical = await tomSecretsWriteShare(
      share,
      recipients: [
        TomSecretsAgeRecipient.parse(
          'age1vg68yht8qxg2p0tedkg4pp9f6tqu4zpm55n52zca7mzy0rw7lvwq73k9ju',
        ),
      ],
    );
    expect(
      (await tomSecretsReadShare(classical, [identity])).entries,
      hasLength(1),
    );

    Matcher refused(TomSecretsShareFailure reason) => throwsA(
      isA<TomSecretsShareException>().having((e) => e.reason, 'reason', reason),
    );
    await expectLater(
      tomSecretsWriteShare(share),
      refused(TomSecretsShareFailure.protection),
    );
    await expectLater(
      tomSecretsWriteShare(
        share,
        recipients: [alice.recipient],
        passphrase: 'both',
      ),
      refused(TomSecretsShareFailure.protection),
    );
    await expectLater(
      tomSecretsWriteShare(share, passphrase: ''),
      refused(TomSecretsShareFailure.protection),
    );
    // A document that is not a share (another age file).
    final other = await tomSecretsAgeEncrypt(utf8.encode('{"a": 1}'), [
      alice.recipient,
    ]);
    await expectLater(
      tomSecretsReadShare(other, [TomSecretsAgeHybridIdentity(alice)]),
      refused(TomSecretsShareFailure.format),
    );
    expect(
      () => TomSecretsShare.decode(
        utf8.encode(
          '{"format": "tsm.share", "version": 2, "entries": [], '
          '"created": "2026-11-19T00:00:00Z"}',
        ),
      ),
      refused(TomSecretsShareFailure.format),
    );
    expect(
      () => TomSecretsShare.decode(utf8.encode('not json')),
      refused(TomSecretsShareFailure.format),
    );
  });

  test(
    'a QR code: one password to one member fits, an attachment does not',
    () async {
      final one = TomSecretsShare(
        created: DateTime.utc(2026, 11, 19),
        entries: const [
          TomSecretsSharedEntry(
            fields: {
              'Title': (value: 'Wi-Fi', protected: false),
              'Password': (value: 'demo-wifi-pw', protected: true),
            },
          ),
        ],
      );
      final small = await tomSecretsWriteShare(
        one,
        recipients: [bob.recipient],
      );
      expect(tomSecretsShareFitsQr(small), isTrue);
      final two = await tomSecretsWriteShare(
        one,
        recipients: [alice.recipient, bob.recipient],
      );
      expect(tomSecretsShareFitsQr(two), isFalse);
      final big = await tomSecretsWriteShare(
        tomSecretsShareOf([login(newTestVault(demoCredentials, 'mine'))]),
        passphrase: 'p',
        workFactor: 10,
      );
      expect(tomSecretsShareFitsQr(big), isTrue);
      final huge = TomSecretsShare(
        created: DateTime.utc(2026, 11, 19),
        entries: [
          TomSecretsSharedEntry(
            fields: const {'Title': (value: 'Chain', protected: false)},
            attachments: {
              'chain.pem': (bytes: Uint8List(4000), protected: false),
            },
          ),
        ],
      );
      expect(
        tomSecretsShareFitsQr(
          await tomSecretsWriteShare(huge, passphrase: 'p', workFactor: 10),
        ),
        isFalse,
      );
    },
  );

  test('the inbox: names, paths, dates and the 30-day expiry', () {
    final name = tomSecretsNewInboxName(now: DateTime.utc(2026, 11, 19, 23));
    expect(name, matches(r'^2026-11-19-[0-9a-f]{16}\.age$'));
    expect(tomSecretsIsInboxName(name), isTrue);
    expect(
      tomSecretsNewInboxName(now: DateTime.utc(2026, 11, 19)),
      isNot(name),
    );
    final member = bob.recipient.fingerprint;
    expect(tomSecretsIsInboxMember(member), isTrue);
    expect(tomSecretsInboxPath(member, name), 'inbox/$member/$name');
    expect(() => tomSecretsInboxPath('../x', name), throwsArgumentError);
    expect(() => tomSecretsInboxPath(member, 'x.age'), throwsArgumentError);
    expect(tomSecretsInboxDate(name), DateTime.utc(2026, 11, 19));
    expect(tomSecretsInboxExpired(name, DateTime.utc(2026, 12, 19)), isFalse);
    expect(tomSecretsInboxExpired(name, DateTime.utc(2026, 12, 20, 1)), isTrue);
    expect(tomSecretsInboxExpired('README.md', DateTime.utc(2030)), isFalse);
  });
}
