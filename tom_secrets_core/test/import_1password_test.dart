// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The 1Password import (part-password-manager, DP-34, DP-35, DP-36) on the
/// synthetic fixtures in test/fixtures/1password: 1PUX and CSV, the target
/// group per source vault, archived items left out by default, categories
/// into subgroups, re-import without duplicates, and the report.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const fixtures = 'test/fixtures/1password';
const idField = KdbxKey('tsm.import.1password.id');

/// The 1PUX fixture zipped in memory as 1Password writes it; [edit] changes
/// its export.data first.
Uint8List onePux({void Function(Map<String, dynamic> data)? edit}) {
  final dir = '$fixtures/1pux_v3';
  final data =
      jsonDecode(File('$dir/export.data').readAsStringSync())
          as Map<String, dynamic>;
  edit?.call(data);
  final archive = Archive()
    ..add(ArchiveFile.bytes('export.data', utf8.encode(jsonEncode(data))))
    ..add(
      ArchiveFile.bytes(
        'export.attributes',
        File('$dir/export.attributes').readAsBytesSync(),
      ),
    );
  for (final f in Directory('$dir/files').listSync().whereType<File>()) {
    archive.add(
      ArchiveFile.bytes(
        'files/${f.uri.pathSegments.last}',
        f.readAsBytesSync(),
      ),
    );
  }
  return Uint8List.fromList(ZipEncoder().encodeBytes(archive));
}

List<Map<String, dynamic>> itemsOf(Map<String, dynamic> data, int vault) =>
    (((data['accounts'] as List).first as Map)['vaults']
            as List)[vault]['items']
        .cast<Map<String, dynamic>>();

KdbxGroup? groupAt(KdbxFile file, List<String> path) {
  KdbxGroup? group = file.body.rootGroup;
  for (final name in path) {
    group = group?.groups.where((g) => g.name.get() == name).firstOrNull;
  }
  return group;
}

KdbxEntry entryAt(KdbxFile file, List<String> path, String title) =>
    groupAt(file, path)!.entries.firstWhere((e) => e.label == title);

String? text(KdbxEntry e, String field) =>
    e.getString(KdbxKey(field))?.getText();

Future<KdbxFile> reopen(KdbxFile file) async =>
    KdbxFormat().read(await file.save(), demoCredentials);

void main() {
  final now = DateTime.utc(2026, 11, 13, 12);
  const personal = ['1Password', 'Personal'];

  group('reading the exports', () {
    test('1PUX: vaults, items, categories and the passkey notice', () {
      final source = tomSecretsRead1Pux(onePux());
      expect(source.source, '1password');
      expect(source.format, '1pux');
      expect(source.vaults.map((v) => v.name), ['Personal', '@Shared']);
      final items = {for (final i in source.vaults.first.items) i.sourceId: i};
      expect(items, hasLength(14));
      expect(items['demo-login-1']!.kind, TomSecretsImportKind.login);
      expect(items['demo-note-1']!.kind, TomSecretsImportKind.note);
      expect(items['demo-api-1']!.kind, TomSecretsImportKind.apiToken);
      expect(items['demo-server-1']!.kind, TomSecretsImportKind.login);
      expect(items['demo-ssh-1']!.kind, TomSecretsImportKind.sshKey);
      expect(items['demo-card-1']!.kind, TomSecretsImportKind.other);
      expect(items['demo-card-1']!.category, 'Credit Cards');
      expect(items['demo-archived-1']!.archived, isTrue);
      expect(items['demo-login-1']!.version, '2023-11-15T22:13:20.000Z');
      expect(source.notImported.single.title, 'Demo Passkey Site');
      expect(
        source.lost,
        contains('passkeys (1Password does not export them)'),
      );
    });

    test('not a 1PUX, or not readable: refused', () {
      expect(
        () => tomSecretsRead1Pux(Uint8List.fromList([1, 2, 3])),
        throwsA(isA<TomSecretsImportFormatException>()),
      );
      final noData = Uint8List.fromList(
        ZipEncoder().encodeBytes(
          Archive()..add(ArchiveFile.bytes('other.txt', [1])),
        ),
      );
      expect(
        () => tomSecretsRead1Pux(noData),
        throwsA(isA<TomSecretsImportFormatException>()),
      );
      expect(
        () => tomSecretsRead1PasswordCsv('Url,Password\nx,y\n'),
        throwsA(isA<TomSecretsImportFormatException>()),
      );
    });

    test('CSV: quoted fields with doubled quotes, commas and line breaks', () {
      expect(tomSecretsParseCsv('a,"b ""c"", d"\r\n"x\ny",z\n'), [
        ['a', 'b "c", d'],
        ['x\ny', 'z'],
      ]);
      expect(tomSecretsParseCsv('﻿h1,h2\n1,'), [
        ['h1', 'h2'],
        ['1', ''],
      ]);
      expect(
        () => tomSecretsParseCsv('"open'),
        throwsA(isA<TomSecretsImportFormatException>()),
      );
    });
  });

  group('a 1PUX import into a new vault', () {
    late KdbxFile vault;
    late TomSecretsImportReport report;

    setUp(() async {
      final file = newTestVault(demoCredentials, 'personal');
      report = tomSecretsImport(
        tomSecretsRead1Pux(onePux()),
        file: file,
        now: now,
      );
      vault = await reopen(file);
    });

    test('a login: fields, URLs, tags, TOTP, history, times, origin', () {
      final e = entryAt(vault, personal, 'Demo Mail');
      expect(text(e, 'UserName'), 'demo.user@example.com');
      expect(e.getString(KdbxKeyCommon.PASSWORD), isA<ProtectedValue>());
      expect(text(e, 'Password'), 'demo-pw-current');
      expect(text(e, 'URL'), 'https://mail.example.com');
      expect(text(e, 'KP2A_URL_1'), 'https://webmail.example.com');
      expect(text(e, 'Notes'), 'Demo notes\nsecond line');
      expect(text(e, 'pin'), 'demo-pin-1234', reason: 'a form field');
      expect(e.getString(const KdbxKey('pin')), isA<ProtectedValue>());
      expect(text(e, 'PIN'), '0000');
      expect(e.getString(const KdbxKey('PIN')), isA<ProtectedValue>());
      expect(text(e, 'Account no'), 'DEMO-42');
      expect(text(e, 'Empty'), isNull, reason: 'empty fields dropped');
      expect(
        e.tags.get()!.split(';'),
        unorderedEquals(['mail', 'demo', 'favorite']),
      );
      expect(text(e, 'tsm.type'), 'login');
      expect(text(e, 'tsm.import.1password.id'), 'demo-login-1');
      expect(
        text(e, 'tsm.import.1password.updated'),
        '2023-11-15T22:13:20.000Z',
      );
      final totp = TomSecretsTotp.fromEntry(e)!;
      expect(totp.issuer, 'Demo');
      expect(
        totp.code(DateTime.utc(2026)),
        TomSecretsTotp.tryParseUri(
          'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP',
        )!.code(DateTime.utc(2026)),
      );
      expect(text(e, 'TimeOtp-Secret-Base32'), 'JBSWY3DPEHPK3PXP');
      expect(e.history.map((h) => text(h, 'Password')), [
        'demo-pw-old-1',
        'demo-pw-old-2',
      ]);
      expect(
        e.history.first.times.lastModificationTime.get(),
        DateTime.fromMillisecondsSinceEpoch(
          (1700000000 - 200000) * 1000,
          isUtc: true,
        ),
      );
      expect(
        e.times.creationTime.get(),
        DateTime.utc(2023, 11, 14, 22, 13, 20),
      );
      expect(
        e.times.lastModificationTime.get(),
        DateTime.utc(2023, 11, 15, 22, 13, 20),
      );
    });

    test('a bare TOTP secret becomes an otpauth URI named after the item', () {
      final e = entryAt(vault, personal, 'Demo Password');
      expect(text(e, 'Password'), 'demo-only-pw');
      final uri = text(e, 'otp')!;
      expect(uri, startsWith('otpauth://totp/Demo%20Password'));
      expect(TomSecretsTotp.fromEntry(e)!.issuer, 'Demo Password');
    });

    test('notes, API credentials and servers are the product\'s types', () {
      expect(text(entryAt(vault, personal, 'Demo Note'), 'tsm.type'), 'note');
      final api = entryAt(vault, personal, 'Demo API');
      expect(text(api, 'tsm.type'), 'api-token');
      expect(text(api, 'Password'), 'demo-token-abc');
      expect(text(api, 'UserName'), 'demo-bot');
      expect(text(api, 'URL'), 'api.example.com');
      expect(text(api, 'type'), 'bearer');
      expect(api.times.expires.get(), isTrue);
      expect(api.times.expiryTime.get(), DateTime.utc(2030));
      final server = entryAt(vault, personal, 'Demo Server');
      expect(text(server, 'tsm.type'), 'login');
      expect(text(server, 'URL'), 'ssh://demo.example.com');
      expect(text(server, 'UserName'), 'root');
      expect(text(server, 'Password'), 'demo-server-pw');
      expect(text(server, 'admin console URL'), 'https://panel.example.com');
    });

    test('other categories go into subgroups with every field (DP-35)', () {
      final card = entryAt(vault, [...personal, 'Credit Cards'], 'Demo Card');
      expect(text(card, 'tsm.type'), isNull);
      expect(text(card, 'tsm.import.1password.category'), 'Credit Cards');
      expect(text(card, 'cardholder name'), 'Demo Holder');
      expect(text(card, 'type'), 'visa');
      expect(text(card, 'number'), '4111111111111111');
      expect(card.getString(const KdbxKey('number')), isA<ProtectedValue>());
      expect(text(card, 'verification number'), '123');
      expect(text(card, 'expiry date'), '2028-07');
      final id = entryAt(vault, [...personal, 'Identities'], 'Demo Identity');
      expect(text(id, 'first name'), 'Demo');
      expect(text(id, 'birth date'), '2000-01-01');
      expect(text(id, 'address'), '1 Demo Street, Demo City, 12345, de');
      expect(text(id, 'email'), 'demo@example.com');
      final doc = entryAt(vault, [...personal, 'Documents'], 'Demo Document');
      expect(
        utf8.decode(doc.getBinary(const KdbxKey('demo-document.txt'))!.value),
        'A demo document, no secret\n',
      );
    });

    test('an SSH key without a readable key stays a note with the key '
        'attached; a file field is an attachment', () {
      final ssh = entryAt(vault, personal, 'Demo SSH Key');
      expect(text(ssh, 'tsm.type'), 'note');
      expect(text(ssh, 'tsm.import.1password.category'), 'SSH Keys');
      expect(
        utf8.decode(ssh.getBinary(const KdbxKey('private_key'))!.value),
        contains('DEMO-NOT-A-REAL-KEY'),
      );
      expect(text(ssh, 'public key'), 'ssh-ed25519 AAAADEMO demo@example');
      final attached = entryAt(vault, personal, 'Demo With Attachment');
      expect(
        utf8.decode(attached.getBinary(const KdbxKey('recovery.txt'))!.value),
        'demo-recovery-codes\n',
      );
    });

    test('target groups per source vault; a reserved name is escaped; same '
        'titles stay separate', () {
      expect(
        entryAt(vault, ['1Password', '%40Shared'], 'Demo Team Login'),
        isNotNull,
      );
      expect(
        groupAt(
          vault,
          personal,
        )!.entries.where((e) => e.label == 'Demo Same Title'),
        hasLength(2),
      );
    });

    test('archived items are left out by default; the report names every '
        'entry and holds no value', () {
      expect(groupAt(vault, [...personal, 'Archive']), isNull);
      expect(report.count(TomSecretsImportOutcome.leftOut), 1);
      expect(
        report.withOutcome(TomSecretsImportOutcome.leftOut).single.reason,
        'archived',
      );
      expect(report.count(TomSecretsImportOutcome.added), 14);
      expect(
        report.withOutcome(TomSecretsImportOutcome.notImported).single.title,
        'Demo Passkey Site',
      );
      expect(
        report.summary,
        'Import from 1Password: 14 added, 0 updated, 0 conflicts',
      );
      expect(report.lost, tomSecretsOnePuxLosses);
      final everything = [
        report.toString(),
        for (final l in report.lines) l.toString(),
      ].join('\n');
      for (final secret in [
        'demo-pw-current',
        'demo-token-abc',
        '4111111111111111',
        'demo-pin-1234',
      ]) {
        expect(everything, isNot(contains(secret)));
      }
      expect(report.largestAttachments.first.name, isNotEmpty);
      expect(
        report.largestAttachments.map((a) => a.bytes),
        orderedEquals(
          [...report.largestAttachments.map((a) => a.bytes)]
            ..sort((a, b) => b - a),
        ),
      );
    });
  });

  test(
    'archived items included go into Archive with the tag archived (DP-34)',
    () {
      final file = newTestVault(demoCredentials, 'v');
      tomSecretsImport(
        tomSecretsRead1Pux(onePux()),
        file: file,
        includeArchived: true,
        now: now,
      );
      final e = entryAt(file, [...personal, 'Archive'], 'Demo Archived');
      expect(e.tags.get(), 'archived');
    },
  );

  test('the preview writes nothing; progress is reported per item', () {
    final file = newTestVault(demoCredentials, 'v');
    final progress = <int>[];
    final preview = tomSecretsImport(
      tomSecretsRead1Pux(onePux()),
      file: file,
      dryRun: true,
      onProgress: (done, total) {
        expect(total, 15);
        progress.add(done);
      },
    );
    expect(preview.dryRun, isTrue);
    expect(preview.count(TomSecretsImportOutcome.added), 14);
    expect(file.body.rootGroup.getAllEntries(), isEmpty);
    expect(file.body.rootGroup.groups, isEmpty);
    expect(progress, List.generate(15, (i) => i + 1));
  });

  test('a source vault into a KDBX file of its own, in a group the user '
      'chose', () {
    final main = newTestVault(demoCredentials, 'main');
    final team = newTestVault(demoCredentials, 'team');
    tomSecretsImport(
      tomSecretsRead1Pux(onePux()),
      file: main,
      targets: {
        'demo-vault-shared': TomSecretsImportTarget(team, ['Team', 'Logins']),
      },
      now: now,
    );
    expect(entryAt(team, ['Team', 'Logins'], 'Demo Team Login'), isNotNull);
    expect(groupAt(main, ['1Password', '%40Shared']), isNull);
    expect(entryAt(main, personal, 'Demo Mail'), isNotNull);
  });

  group('re-import', () {
    Future<KdbxFile> imported() async {
      final file = newTestVault(demoCredentials, 'v');
      tomSecretsImport(tomSecretsRead1Pux(onePux()), file: file, now: now);
      return reopen(file);
    }

    test('the same export again: nothing added, nothing duplicated', () async {
      final vault = await imported();
      final before = vault.body.rootGroup.getAllEntries().length;
      final again = tomSecretsImport(
        tomSecretsRead1Pux(onePux()),
        file: vault,
        now: now,
      );
      expect(again.count(TomSecretsImportOutcome.added), 0);
      expect(again.count(TomSecretsImportOutcome.unchanged), 14);
      expect(vault.body.rootGroup.getAllEntries().length, before);
    });

    test(
      'a newer export: updated when only 1Password changed, a conflict '
      'when both did, listed when gone, never re-added when deleted',
      () async {
        var vault = await imported();
        // In the vault: an edit of Demo Server, Demo Note deleted.
        entryAt(
          vault,
          personal,
          'Demo Server',
        ).setString(const KdbxKey('Notes'), PlainValue('edited in the vault'));
        vault.deleteEntry(entryAt(vault, personal, 'Demo Note'));
        vault = await reopen(vault);

        final newer = onePux(
          edit: (data) {
            final items = itemsOf(data, 0);
            Map<String, dynamic> item(String id) =>
                items.firstWhere((i) => i['uuid'] == id);
            final later = 1700000000 + 30 * 86400;
            final mail = item('demo-login-1');
            mail['updatedAt'] = later;
            ((mail['details'] as Map)['loginFields'] as List)[1]['value'] =
                'demo-pw-newer';
            final server = item('demo-server-1');
            server['updatedAt'] = later;
            (server['details'] as Map)['notesPlain'] = 'changed in 1Password';
            item('demo-note-1')['updatedAt'] = later;
            items.removeWhere((i) => i['uuid'] == 'demo-card-1');
          },
        );
        final report = tomSecretsImport(
          tomSecretsRead1Pux(newer),
          file: vault,
          now: now,
        );
        expect(report.count(TomSecretsImportOutcome.added), 0);

        expect(
          report.withOutcome(TomSecretsImportOutcome.updated).single.title,
          'Demo Mail',
        );
        final mail = entryAt(vault, personal, 'Demo Mail');
        expect(text(mail, 'Password'), 'demo-pw-newer');
        expect(
          text(mail.history.last, 'Password'),
          'demo-pw-current',
          reason: 'the old values in the history',
        );

        expect(
          report.withOutcome(TomSecretsImportOutcome.conflict).single.title,
          'Demo Server',
        );
        final server = entryAt(vault, personal, 'Demo Server');
        final conflicts = tomSecretsConflictsOf(server);
        expect(conflicts.single.fields, contains('field:Notes'));
        expect(
          text(server, 'Notes'),
          'edited in the vault',
          reason: 'the vault\'s edit is newer than 1Password\'s change',
        );
        expect(
          server.history.map((h) => text(h, 'Notes')),
          contains('changed in 1Password'),
          reason: 'the other side is kept in the history',
        );

        final deleted = report
            .withOutcome(TomSecretsImportOutcome.notImported)
            .where((l) => l.title == 'Demo Note');
        expect(deleted.single.reason, 'deleted in the vault');
        expect(
          report.withOutcome(TomSecretsImportOutcome.notInExport).single.title,
          'Demo Card',
        );
        expect(
          entryAt(vault, [...personal, 'Credit Cards'], 'Demo Card'),
          isNotNull,
          reason: 'never deleted',
        );

        final reopened = await reopen(vault);
        final third = tomSecretsImport(
          tomSecretsRead1Pux(newer),
          file: reopened,
          now: now,
        );
        expect(
          third.count(TomSecretsImportOutcome.conflict),
          0,
          reason: 'the same export is no change the next time',
        );
        expect(third.count(TomSecretsImportOutcome.updated), 0);
      },
    );
  });

  group('CSV', () {
    TomSecretsImportSource csv([String Function(String text)? edit]) {
      final text = File('$fixtures/csv/export.csv').readAsStringSync();
      return tomSecretsRead1PasswordCsv(edit == null ? text : edit(text));
    }

    test('rows into one target; archived left out; the losses named', () async {
      final file = newTestVault(demoCredentials, 'v');
      final report = tomSecretsImport(csv(), file: file, now: now);
      final vault = await reopen(file);
      const target = ['1Password', 'CSV'];
      final mail = entryAt(vault, target, 'Demo CSV Mail');
      expect(text(mail, 'UserName'), 'csv.user@example.com');
      expect(text(mail, 'Password'), 'csv-pw-1');
      expect(
        text(mail, 'Notes'),
        'Line one\nline two with "quotes", and a comma',
      );
      expect(
        mail.tags.get()!.split(';'),
        unorderedEquals(['mail', 'demo', 'favorite']),
      );
      expect(TomSecretsTotp.fromEntry(mail), isNotNull);
      expect(text(mail, 'tsm.import.1password.id'), startsWith('csv:'));
      expect(
        text(entryAt(vault, target, 'Demo CSV Plain'), 'tsm.type'),
        'note',
      );
      expect(report.count(TomSecretsImportOutcome.leftOut), 1);
      expect(report.lost, contains('attachments and documents'));
      expect(report.source, '1Password (csv)');
    });

    test('re-import matches rows by title, URL and user name', () async {
      final file = newTestVault(demoCredentials, 'v');
      tomSecretsImport(csv(), file: file, now: now);
      final vault = await reopen(file);
      final same = tomSecretsImport(csv(), file: vault, now: now);
      expect(same.count(TomSecretsImportOutcome.unchanged), 2);
      expect(same.count(TomSecretsImportOutcome.added), 0);
      final changed = tomSecretsImport(
        csv((t) => t.replaceFirst('csv-pw-1', 'csv-pw-2')),
        file: vault,
        now: now,
      );
      expect(
        changed.withOutcome(TomSecretsImportOutcome.updated).single.title,
        'Demo CSV Mail',
      );
      expect(
        text(entryAt(vault, ['1Password', 'CSV'], 'Demo CSV Mail'), 'Password'),
        'csv-pw-2',
      );
    });
  });

  test('group names the product reserves are escaped', () {
    expect(tomSecretsImportGroupName('@env'), '%40env');
    expect(tomSecretsImportGroupName('tsm.grants'), '%74sm.grants');
    expect(tomSecretsImportGroupName('.tom-secrets'), '%2Etom-secrets');
    expect(tomSecretsImportGroupName('  '), '(no name)');
    expect(tomSecretsImportGroupName('Work / Home'), 'Work / Home');
  });
}
