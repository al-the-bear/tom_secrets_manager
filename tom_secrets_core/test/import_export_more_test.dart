// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The other imports and the exports (part-password-manager, DP-40): Bitwarden
/// JSON (plain and password-protected, against fixtures a second writer made),
/// the browsers' CSV exports, another KDBX file as a group or merged, and the
/// exports to KDBX, CSV and Bitwarden JSON, each read back. Demo data only.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;
import 'package:test/test.dart';
import 'package:tom_core_sync/tom_core_sync.dart' show TomMergeRefusedException;
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const _bitwarden = 'test/fixtures/bitwarden';
const _browser = 'test/fixtures/browser';

String _read(String path) => File(path).readAsStringSync();

KdbxEntry _find(KdbxFile file, String title) =>
    file.body.rootGroup.getAllEntries().firstWhere((e) => e.label == title);

String? _text(KdbxEntry e, String field) =>
    e.getString(KdbxKey(field))?.getText();

List<String> _pathOf(KdbxEntry e) {
  final names = <String>[];
  for (var g = e.parent; g != null && g.parent != null; g = g.parent) {
    names.insert(0, g.name.get() ?? '');
  }
  return names;
}

/// A type-2 cipher string, written here for the Argon2id case (the PBKDF2
/// fixture comes from generate.py's own implementation).
Future<String> _encrypt(List<int> plain, TomSecretsBitwardenKeys keys) async {
  final iv = List<int>.generate(16, (i) => i * 7);
  final box = await cg.AesCbc.with256bits(
    macAlgorithm: cg.MacAlgorithm.empty,
  ).encrypt(plain, secretKey: cg.SecretKey(keys.encryption), nonce: iv);
  final mac = crypto.Hmac(
    crypto.sha256,
    keys.mac,
  ).convert([...iv, ...box.cipherText]).bytes;
  return '2.${base64.encode(iv)}|${base64.encode(box.cipherText)}|'
      '${base64.encode(mac)}';
}

void main() {
  final now = DateTime.utc(2026, 11, 19, 12);

  group('Bitwarden JSON', () {
    test('items, types, folders and fields; the trash left out, a passkey '
        'named', () async {
      final source = await tomSecretsReadBitwardenJson(
        _read('$_bitwarden/export.json'),
      );
      expect(source.source, 'bitwarden');
      expect(source.notImported.single.title, 'Demo Passkey Site');
      final vault = DemoVault();
      final report = tomSecretsImport(source, file: vault.file, now: now);
      expect(report.count(TomSecretsImportOutcome.added), 6);
      final server = _find(vault.file, 'Demo Server');
      expect(_pathOf(server), ['Bitwarden', 'Vault', 'Work', 'Servers']);
      expect(_text(server, 'UserName'), 'demo-user');
      expect(_text(server, 'Password'), 'demo-server-pw');
      expect(_text(server, 'URL'), 'https://demo.example.com');
      expect(_text(server, 'Region'), 'eu-demo');
      expect(server.getString(const KdbxKey('PIN')), isA<ProtectedValue>());
      expect(_text(server, 'Linked'), isNull);
      expect(TomSecretsTotp.fromEntry(server), isNotNull);
      expect(
        _text(server, 'tsm.import.bitwarden.id'),
        '10000000-0000-4000-8000-000000000001',
      );
      expect(server.tags.get(), contains('favorite'));
      expect(
        server.history.map((h) => _text(h, 'Password')),
        contains('demo-old-pw-1'),
      );
      final note = _find(vault.file, 'Demo Note');
      expect(_text(note, 'tsm.type'), 'note');
      final card = _find(vault.file, 'Demo Card');
      expect(_pathOf(card), contains('Credit Cards'));
      expect(card.getString(const KdbxKey('Number')), isA<ProtectedValue>());
      expect(_text(card, 'Cardholder name'), 'Demo Person');
      final identity = _find(vault.file, 'Demo Identity');
      expect(_pathOf(identity), contains('Identities'));
      expect(_text(identity, 'Email'), 'demo@example.com');
      final ssh = _find(vault.file, 'Demo SSH key');
      expect(_text(ssh, 'tsm.type'), 'ssh-key');
      expect(tomSecretsSshKeyOf(ssh)?.info.keyType, 'ssh-ed25519');
      expect(
        vault.file.body.rootGroup.getAllEntries().map((e) => e.label),
        isNot(contains('Demo Trashed')),
      );

      // Re-imported: nothing new.
      final again = tomSecretsImport(
        await tomSecretsReadBitwardenJson(_read('$_bitwarden/export.json')),
        file: vault.file,
        now: now,
      );
      expect(again.count(TomSecretsImportOutcome.added), 0);
      expect(again.count(TomSecretsImportOutcome.unchanged), 6);
    });

    test('password-protected (PBKDF2): opened with the password, the same '
        'items; a wrong or missing password refused', () async {
      final text = _read('$_bitwarden/export_encrypted.json');
      expect(tomSecretsBitwardenNeedsPassword(text), isTrue);
      expect(
        tomSecretsBitwardenNeedsPassword(_read('$_bitwarden/export.json')),
        isFalse,
      );
      final source = await tomSecretsReadBitwardenJson(
        text,
        password: 'demo-export-password',
      );
      expect(source.vaults.single.items, hasLength(7));
      await expectLater(
        tomSecretsReadBitwardenJson(text, password: 'wrong'),
        throwsA(
          isA<TomSecretsImportFormatException>().having(
            (e) => e.message,
            'message',
            contains('password is wrong'),
          ),
        ),
      );
      await expectLater(
        tomSecretsReadBitwardenJson(text),
        throwsA(isA<TomSecretsImportFormatException>()),
      );
    });

    test(
      'password-protected (Argon2id) and account-restricted exports',
      () async {
        const salt = 'demo-argon-salt';
        final keys = await tomSecretsBitwardenExportKeys(
          password: 'demo-pw',
          salt: salt,
          kdfType: 1,
          iterations: 1,
          memoryMiB: 1,
          parallelism: 1,
        );
        final plain = _read('$_bitwarden/export.json');
        final text = jsonEncode({
          'encrypted': true,
          'passwordProtected': true,
          'salt': salt,
          'kdfType': 1,
          'kdfIterations': 1,
          'kdfMemory': 1,
          'kdfParallelism': 1,
          'encKeyValidation_DO_NOT_EDIT': await _encrypt(
            utf8.encode('x'),
            keys,
          ),
          'data': await _encrypt(utf8.encode(plain), keys),
        });
        final source = await tomSecretsReadBitwardenJson(
          text,
          password: 'demo-pw',
        );
        expect(source.vaults.single.items, hasLength(7));
        await expectLater(
          tomSecretsReadBitwardenJson(
            jsonEncode({'encrypted': true, 'items': []}),
          ),
          throwsA(
            isA<TomSecretsImportFormatException>().having(
              (e) => e.message,
              'message',
              contains('account-restricted'),
            ),
          ),
        );
      },
    );
  });

  group('browser CSV', () {
    test('Chrome (or Edge, named by the caller), Firefox and Safari', () {
      final chrome = tomSecretsReadBrowserCsv(_read('$_browser/chrome.csv'));
      expect(chrome.source, 'chrome');
      final items = chrome.vaults.single.items;
      expect(items.map((i) => i.title), ['Demo Mail', 'Demo Shop']);
      expect(items.last.notes, 'Two-line\nnote');
      final edge = tomSecretsReadBrowserCsv(
        _read('$_browser/chrome.csv'),
        browser: TomSecretsCsvBrowser.edge,
      );
      expect(edge.source, 'edge');

      final firefox = tomSecretsReadBrowserCsv(_read('$_browser/firefox.csv'));
      expect(firefox.source, 'firefox');
      expect(firefox.vaults.single.items.map((i) => i.title), [
        'mail.example.com',
        'forum.example.net',
      ]);

      final safari = tomSecretsReadBrowserCsv(_read('$_browser/safari.csv'));
      expect(safari.source, 'safari');
      expect(safari.vaults.single.items.single.totp, startsWith('otpauth://'));
      expect(
        () => tomSecretsReadBrowserCsv('a,b\n1,2'),
        throwsA(isA<TomSecretsImportFormatException>()),
      );
    });

    test('identified by the same hash as a 1Password CSV row; a re-import '
        'updates a changed password without a duplicate', () {
      final browser = tomSecretsReadBrowserCsv(_read('$_browser/chrome.csv'));
      final onePassword = tomSecretsRead1PasswordCsv(
        'Title,Url,Username,Password\n'
        'Demo Mail,https://mail.example.com/login,demo-user,other-pw\n',
      );
      expect(
        browser.vaults.single.items.first.sourceId,
        onePassword.vaults.single.items.single.sourceId,
      );
      final vault = DemoVault();
      tomSecretsImport(browser, file: vault.file, now: now);
      final changed = tomSecretsReadBrowserCsv(
        _read('$_browser/chrome.csv').replaceAll('demo-mail-pw', 'new-pw'),
      );
      final report = tomSecretsImport(changed, file: vault.file, now: now);
      expect(report.count(TomSecretsImportOutcome.updated), 1);
      expect(report.count(TomSecretsImportOutcome.added), 0);
      expect(_text(_find(vault.file, 'Demo Mail'), 'Password'), 'new-pw');
    });
  });

  group('KeePass', () {
    KdbxFile other() {
      final file = newTestVault(demoCredentials, 'other');
      final work = file.createGroup(parent: file.body.rootGroup, name: 'Work');
      final e = KdbxEntry.create(file, work)..label = 'Keep login';
      work.addEntry(e);
      e.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('demo-k'));
      e.tags.set('team');
      final root = KdbxEntry.create(file, file.body.rootGroup)
        ..label = 'Top entry';
      file.body.rootGroup.addEntry(root);
      TomSecretsMetadata(store: 'other').writeTo(file);
      return file;
    }

    test('as a group: groups and entries copied with their fields, the '
        'metadata entry left behind; a second import gets its own name', () {
      final vault = DemoVault();
      final source = other();
      final r = tomSecretsImportKdbxAsGroup(
        vault.file,
        source,
        name: 'KeePass',
        parent: ['Imports'],
      );
      expect(r.group, ['Imports', 'KeePass']);
      expect(r.entries, 2);
      expect(r.groups, 1);
      final login = _find(vault.file, 'Keep login');
      expect(_pathOf(login), ['Imports', 'KeePass', 'Work']);
      expect(_text(login, 'Password'), 'demo-k');
      expect(login.getString(KdbxKeyCommon.PASSWORD), isA<ProtectedValue>());
      expect(login.tags.get(), 'team');
      expect(
        vault.file.body.rootGroup.getAllEntries().where(
          (e) => e.label == tomSecretsMetadataTitle,
        ),
        isEmpty,
      );
      final second = tomSecretsImportKdbxAsGroup(
        vault.file,
        source,
        name: 'KeePass',
        parent: ['Imports'],
      );
      expect(second.group, ['Imports', 'KeePass (2)']);
      // The second copy got new UUIDs: no entry twice under one id.
      final ids = vault.file.body.rootGroup
          .getAllEntries()
          .map((e) => e.uuid.uuid)
          .toList();
      expect(ids.toSet(), hasLength(ids.length));
    });

    test('merged: a copy of the same vault edited elsewhere; another vault '
        'refused', () async {
      final vault = DemoVault();
      vault.add('Shared', password: 'demo-a');
      final copy = await KdbxFormat().read(
        await vault.file.save(),
        demoCredentials,
      );
      final added = KdbxEntry.create(copy, copy.body.rootGroup)
        ..label = 'Added elsewhere';
      copy.body.rootGroup.addEntry(added);
      final result = tomSecretsImportKdbxMerged(vault.file, copy, now: now);
      expect(result.conflicts, isEmpty);
      expect(_find(vault.file, 'Added elsewhere'), isNotNull);
      expect(
        () => tomSecretsImportKdbxMerged(vault.file, other()),
        throwsA(isA<TomMergeRefusedException>()),
      );
    });
  });

  group('exports', () {
    DemoVault sample() {
      final vault = DemoVault(store: 'demo');
      final login = vault.add(
        'Work/Mail',
        password: 'demo-mail-pw',
        fields: {
          'UserName': 'demo-user',
          'URL': 'https://mail.example.com',
          'Notes': 'line one\nline, two',
          'Region': 'eu',
        },
      );
      login.tags.set('favorite;team');
      login.setString(const KdbxKey('PIN'), ProtectedValue.fromString('0000'));
      vault.add(
        'Token',
        password: 'demo-tok',
        fields: {'tsm.type': 'api-token'},
      );
      vault.add('Note', fields: {'tsm.type': 'note', 'Notes': 'n'});
      return vault;
    }

    test('CSV: a header and a row per entry, quoted, read back by the '
        'browser CSV reader; the metadata entry left out', () {
      final vault = sample();
      final export = tomSecretsExportCsv(vault.file);
      expect(export.items, 3);
      expect(
        export.text,
        startsWith('Title,URL,Username,Password,Notes,OTPAuth,Group,Tags\r\n'),
      );
      expect(export.text, contains('"line one\nline, two"'));
      expect(export.text, isNot(contains(tomSecretsMetadataTitle)));
      expect(export.lost, contains('custom fields (1 entries)'));
      final back = tomSecretsReadBrowserCsv(export.text);
      final mail = back.vaults.single.items.firstWhere(
        (i) => i.title == 'Mail',
      );
      expect(mail.password, 'demo-mail-pw');
      expect(mail.notes, 'line one\nline, two');
      expect(export.text, contains('Work'));
    });

    test('Bitwarden JSON: folders, types and custom fields; read back by '
        'the Bitwarden importer', () async {
      final vault = sample();
      final export = tomSecretsExportBitwardenJson(vault.file, now: now);
      final json = jsonDecode(export.text) as Map<String, Object?>;
      expect(json['encrypted'], false);
      expect((json['folders'] as List).single, containsPair('name', 'Work'));
      final items = (json['items'] as List).cast<Map<String, Object?>>();
      final mail = items.firstWhere((i) => i['name'] == 'Mail');
      expect(mail['type'], 1);
      expect(mail['favorite'], true);
      expect(
        (mail['fields'] as List).map((f) => (f as Map)['name']),
        containsAll(['Region', 'PIN']),
      );
      expect(
        (mail['fields'] as List).firstWhere((f) => (f as Map)['name'] == 'PIN'),
        containsPair('type', 1),
      );
      expect(items.firstWhere((i) => i['name'] == 'Note')['type'], 2);
      expect(export.lost, contains('tags other than favorite: team'));

      final back = await tomSecretsReadBitwardenJson(export.text);
      final read = back.vaults.single.items.firstWhere(
        (i) => i.title == 'Mail',
      );
      expect(read.password, 'demo-mail-pw');
      expect(read.folders, ['Work']);
      expect(read.userName, 'demo-user');
    });

    test('Bitwarden JSON round trip: imported cards, identities and SSH keys '
        'go back as their types', () async {
      final vault = DemoVault();
      tomSecretsImport(
        await tomSecretsReadBitwardenJson(_read('$_bitwarden/export.json')),
        file: vault.file,
        now: now,
      );
      final items =
          ((jsonDecode(tomSecretsExportBitwardenJson(vault.file).text)
                      as Map)['items']
                  as List)
              .cast<Map<String, Object?>>();
      final card = items.firstWhere((i) => i['name'] == 'Demo Card');
      expect(card['type'], 3);
      expect((card['card'] as Map)['number'], '4111111111111111');
      expect(card['fields'], isEmpty);
      final identity = items.firstWhere((i) => i['name'] == 'Demo Identity');
      expect(identity['type'], 4);
      expect((identity['identity'] as Map)['email'], 'demo@example.com');
      final ssh = items.firstWhere((i) => i['name'] == 'Demo SSH key');
      expect(ssh['type'], 5);
      expect(
        (ssh['sshKey'] as Map)['privateKey'],
        startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'),
      );
    });

    test('KDBX: a vault of its own under a new password, without the '
        'product\'s groups', () async {
      final vault = sample();
      final grants = vault.file.createGroup(
        parent: vault.file.body.rootGroup,
        name: tomSecretsGrantsGroup,
      );
      KdbxEntry.create(vault.file, grants).label = 'grant';
      final newKey = Credentials(ProtectedValue.fromString('demo-new-pw'));
      final Uint8List bytes = await tomSecretsExportKdbx(
        vault.file,
        newKey,
        name: 'Copy',
        argon2: testArgon2,
      );
      final copy = await KdbxFormat().read(bytes, newKey);
      final mail = _find(copy, 'Mail');
      expect(_pathOf(mail), ['Work']);
      expect(_text(mail, 'Password'), 'demo-mail-pw');
      expect(
        copy.body.rootGroup.getAllEntries().map((e) => e.label),
        isNot(contains(tomSecretsMetadataTitle)),
      );
      expect(
        copy.body.rootGroup.getAllGroups().map((g) => g.name.get()),
        isNot(contains(tomSecretsGrantsGroup)),
      );
      await expectLater(
        KdbxFormat().read(bytes, demoCredentials),
        throwsA(anything),
      );
    });
  });
}
