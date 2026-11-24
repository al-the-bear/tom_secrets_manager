// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The cleaner on every format it reads (the core's synthetic fixtures):
// the cleaned export still imports with the core's own reader, with the
// same items, field counts and attachment sizes; none of the original
// secrets, user names, titles or hosts is left in it. Demo data only.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_import_cleaner/tom_secrets_import_cleaner.dart';

Uint8List _fixture(String path) =>
    File('test/fixtures/$path').readAsBytesSync();

/// The 1PUX fixture folder as a ZIP.
Uint8List _pux() {
  final archive = Archive();
  final dir = Directory('test/fixtures/1password/1pux_v3');
  for (final f in dir.listSync(recursive: true).whereType<File>()) {
    final name = f.path.substring(dir.path.length + 1).replaceAll(r'\', '/');
    final bytes = f.readAsBytesSync();
    archive.addFile(ArchiveFile(name, bytes.length, bytes));
  }
  return Uint8List.fromList(ZipEncoder().encode(archive));
}

/// The strings worth hiding in [source]: passwords, user names, notes,
/// field values, titles and URL hosts, each at least 4 characters.
Set<String> _secretsOf(TomSecretsImportSource source) => <String>{
  for (final v in source.vaults)
    for (final i in v.items) ...[
      ?i.password,
      ?i.userName,
      ?i.totp,
      i.title,
      if (i.notes != null) ...i.notes!.split('\n'),
      for (final f in i.fields) f.value,
      for (final u in i.urls) ?Uri.tryParse(u)?.host,
      for (final h in i.passwordHistory) h.value,
    ],
}.where((s) => s.trim().length >= 8 && s != '(untitled)').toSet();

/// Every value of [before]'s items differs in [after] (same order).
void _valuesReplaced(
  TomSecretsImportSource before,
  TomSecretsImportSource after,
) {
  final a = [for (final v in before.vaults) ...v.items];
  final b = [for (final v in after.vaults) ...v.items];
  for (var n = 0; n < a.length; n++) {
    void differs(String? x, String? y, String what) {
      if (x == null || x.trim().isEmpty) return;
      expect(y, isNot(x), reason: '${a[n].title}: $what kept');
    }

    differs(a[n].title, b[n].title, 'title');
    differs(a[n].password, b[n].password, 'password');
    differs(a[n].userName, b[n].userName, 'user name');
    differs(a[n].notes, b[n].notes, 'notes');
    differs(a[n].totp, b[n].totp, 'one-time code');
    for (var f = 0; f < a[n].fields.length && f < b[n].fields.length; f++) {
      differs(a[n].fields[f].value, b[n].fields[f].value, 'a field');
    }
  }
}

/// The shape of [source] that cleaning keeps.
List<Object> _shape(TomSecretsImportSource source) => [
  for (final v in source.vaults)
    for (final i in v.items)
      [
        // A CSV item's id is a hash of its title, URL and user name, which
        // the cleaning replaces; an export's own ids are kept.
        if (!i.sourceId.startsWith('csv:')) i.sourceId,
        i.kind,
        i.fields.length,
        i.urls.length,
        i.password != null,
        i.userName != null,
        // An SSH key's private key is emptied: its key file goes with it.
        if (i.kind != TomSecretsImportKind.sshKey)
          for (final a in i.attachments) a.bytes.length,
      ],
];

void _checkClean(
  Uint8List original,
  TomSecretsImportSource Function(Uint8List bytes) read,
  TomSecretsCleanerFormat format,
) {
  final before = read(original);
  final cleaned = tomSecretsCleanExport(original);
  expect(cleaned.report.format, format);
  final after = read(cleaned.bytes);
  expect(_shape(after), _shape(before), reason: 'the same items and fields');
  _valuesReplaced(before, after);
  final text = latin1.decode(cleaned.bytes);
  for (final secret in _secretsOf(before)) {
    expect(text.contains(secret), isFalse, reason: '"$secret" is left');
  }
  // Titles are stand-ins: `Item <n>`, or the host's stand-in where the
  // export has no title column (Firefox).
  final titles = [
    for (final v in after.vaults)
      for (final i in v.items) i.title,
  ];
  expect(
    titles.every(
      (t) =>
          t.startsWith('Item ') ||
          t == '(untitled)' ||
          t.endsWith('.example.com'),
    ),
    isTrue,
    reason: '$titles',
  );
}

void main() {
  test('Enpass JSON', () {
    _checkClean(
      _fixture('enpass/export.json'),
      (b) => tomSecretsReadEnpassJson(utf8.decode(b)),
      TomSecretsCleanerFormat.enpassJson,
    );
  });

  test('Enpass CSV, its header kept and the labels with it', () {
    final original = _fixture('enpass/export.csv');
    _checkClean(
      original,
      (b) => tomSecretsReadEnpassCsv(utf8.decode(b)),
      TomSecretsCleanerFormat.enpassCsv,
    );
    final cleaned = utf8.decode(tomSecretsCleanExport(original).bytes);
    expect(cleaned, startsWith('Title,Field,Value'));
    expect(cleaned, contains('Username'));
  });

  test(
    'Bitwarden JSON (unencrypted); an encrypted export is refused',
    () async {
      final original = _fixture('bitwarden/export.json');
      final before = await tomSecretsReadBitwardenJson(utf8.decode(original));
      final cleaned = tomSecretsCleanExport(original);
      expect(cleaned.report.format, TomSecretsCleanerFormat.bitwardenJson);
      final after = await tomSecretsReadBitwardenJson(
        utf8.decode(cleaned.bytes),
      );
      expect(_shape(after), _shape(before));
      _valuesReplaced(before, after);
      final text = utf8.decode(cleaned.bytes);
      for (final secret in _secretsOf(before)) {
        expect(text.contains(secret), isFalse, reason: '"$secret" is left');
      }
      expect(
        () =>
            tomSecretsCleanExport(_fixture('bitwarden/export_encrypted.json')),
        throwsA(isA<TomSecretsCleanerException>()),
      );
    },
  );

  test('1Password 1PUX: export.data cleaned, the files zeroed', () {
    _checkClean(
      _pux(),
      tomSecretsRead1Pux,
      TomSecretsCleanerFormat.onePasswordPux,
    );
  });

  test('1Password CSV and the browsers\' CSV', () {
    _checkClean(
      _fixture('1password/export.csv'),
      (b) => tomSecretsRead1PasswordCsv(utf8.decode(b)),
      TomSecretsCleanerFormat.csvWithHeader,
    );
    for (final (file, browser) in [
      ('chrome.csv', TomSecretsCsvBrowser.chrome),
      ('firefox.csv', TomSecretsCsvBrowser.firefox),
      ('safari.csv', TomSecretsCsvBrowser.safari),
    ]) {
      _checkClean(
        _fixture('browser/$file'),
        (b) => tomSecretsReadBrowserCsv(utf8.decode(b), browser: browser),
        TomSecretsCleanerFormat.csvWithHeader,
      );
    }
  });

  test('the same value gets the same stand-in; masks keep lengths and '
      'line breaks; attachments keep their size', () {
    final export = {
      'folders': <Object>[],
      'items': [
        for (final i in [1, 2])
          {
            'uuid': '0f8fad5b-d9cb-469f-a165-70867728950$i',
            'title': 'Demo shop',
            'template_type': 'login.default',
            'category': 'login',
            'note': 'line one\nline two',
            'fields': [
              {
                'type': 'username',
                'label': 'Username',
                'value': 'demo@example.org',
              },
              {
                'type': 'url',
                'label': 'Website',
                'value': 'https://shop.example.org/a/b',
              },
              {'type': 'password', 'label': 'Password', 'value': 'demo-pw-$i'},
            ],
            'attachments': [
              {'name': 'scan.jpg', 'data': base64.encode(List.filled(300, i))},
            ],
          },
      ],
    };
    final cleaned =
        jsonDecode(
              utf8.decode(
                tomSecretsCleanExport(
                  Uint8List.fromList(utf8.encode(jsonEncode(export))),
                ).bytes,
              ),
            )
            as Map;
    final items = (cleaned['items'] as List).cast<Map>();
    expect(items[0]['title'], items[1]['title']);
    expect(items[0]['note'], 'XXXX XXX\nXXXX XXX');
    final fields = (items[0]['fields'] as List).cast<Map>();
    expect(fields[0]['value'], 'user1@example.com');
    expect(fields[1]['value'], 'https://site1.example.com/x/x');
    expect(fields[2]['value'], 'XXXXXXXXX');
    expect(fields[2]['label'], 'Password');
    final data = base64.decode(
      ((items[1]['attachments'] as List).single as Map)['data'] as String,
    );
    expect(data.length, 300);
    expect(data.every((b) => b == 0), isTrue);
    expect(items[0]['uuid'], export['items'] is List ? isNotNull : null);
  });

  test('a KDBX file and unknown JSON are refused', () {
    expect(
      () => tomSecretsCleanExport(
        Uint8List.fromList([0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]),
      ),
      throwsA(isA<TomSecretsCleanerException>()),
    );
    expect(
      () => tomSecretsCleanExport(Uint8List.fromList(utf8.encode('{"a":1}'))),
      throwsA(isA<TomSecretsCleanerException>()),
    );
  });

  test('the default output name', () {
    expect(tomSecretsCleanedPathOf('a/export.json'), 'a/export.cleaned.json');
    expect(tomSecretsCleanedPathOf('export'), 'export.cleaned');
  });
}
