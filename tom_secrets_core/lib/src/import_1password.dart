// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Reading 1Password's exports (part-password-manager, DP-36) into a
/// [TomSecretsImportSource] for [tomSecretsImport]:
///
/// - **1PUX** ([tomSecretsRead1Pux], recommended): the ZIP 1Password 8
///   writes, read in memory without extracting it — `export.data` (accounts →
///   vaults → items), and `files/` with the attachments and documents.
/// - **CSV** ([tomSecretsRead1PasswordCsv]): one row per item, no vaults, no
///   sections, no attachments, no history and no stable id (matched on
///   re-import by a hash of title, first URL and user name).
///
/// The formats are 1Password's and change with its versions; the importer
/// follows the layout its tests' fixtures pin, and a real export is checked
/// against it before the user's import (see the README).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart' as crypto;

import 'import.dart';

/// The source name of 1Password imports (`tsm.import.1password.id`).
const String tomSecretsOnePasswordSource = '1password';

/// An export that cannot be read.
final class TomSecretsImportFormatException implements Exception {
  /// Unreadable for [message].
  TomSecretsImportFormatException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsImportFormatException: $message';
}

/// What a 1PUX import loses, named in every report.
const List<String> tomSecretsOnePuxLosses = [
  'vault sharing and permissions',
  'item links (related items)',
  'Watchtower state',
  'custom icons',
  'the order of fields inside sections',
  'passkeys (1Password does not export them)',
];

/// What a CSV import loses besides [tomSecretsOnePuxLosses].
const List<String> tomSecretsOnePasswordCsvLosses = [
  ...tomSecretsOnePuxLosses,
  'vaults (every row goes into one target)',
  'sections and custom fields',
  'attachments and documents',
  'password history',
  'created and updated times',
];

/// 1Password's categories by `categoryUuid`: how each is typed, and the
/// subgroup an `other` category goes into.
const Map<String, (TomSecretsImportKind, String)>
tomSecretsOnePasswordCategories = {
  '001': (TomSecretsImportKind.login, 'Login'),
  '002': (TomSecretsImportKind.other, 'Credit Cards'),
  '003': (TomSecretsImportKind.note, 'Secure Note'),
  '004': (TomSecretsImportKind.other, 'Identities'),
  '005': (TomSecretsImportKind.login, 'Password'),
  '006': (TomSecretsImportKind.other, 'Documents'),
  '100': (TomSecretsImportKind.other, 'Software Licenses'),
  '101': (TomSecretsImportKind.other, 'Bank Accounts'),
  '102': (TomSecretsImportKind.login, 'Database'),
  '103': (TomSecretsImportKind.other, 'Driver Licenses'),
  '104': (TomSecretsImportKind.other, 'Outdoor Licenses'),
  '105': (TomSecretsImportKind.other, 'Memberships'),
  '106': (TomSecretsImportKind.other, 'Passports'),
  '107': (TomSecretsImportKind.other, 'Reward Programs'),
  '108': (TomSecretsImportKind.other, 'Social Security Numbers'),
  '109': (TomSecretsImportKind.login, 'Wireless Router'),
  '110': (TomSecretsImportKind.login, 'Server'),
  '111': (TomSecretsImportKind.other, 'Email Accounts'),
  '112': (TomSecretsImportKind.apiToken, 'API Credential'),
  '113': (TomSecretsImportKind.other, 'Medical Records'),
  '114': (TomSecretsImportKind.sshKey, 'SSH Keys'),
  '115': (TomSecretsImportKind.other, 'Crypto Wallets'),
};

/// Reads a 1PUX export ([zip], the file's bytes) in memory.
TomSecretsImportSource tomSecretsRead1Pux(Uint8List zip) {
  final Archive archive;
  try {
    archive = ZipDecoder().decodeBytes(zip);
  } on Object catch (e) {
    throw TomSecretsImportFormatException('not a ZIP file ($e)');
  }
  ArchiveFile? data;
  final files = <String, ArchiveFile>{};
  for (final f in archive.files) {
    if (!f.isFile) continue;
    if (f.name == 'export.data') data = f;
    if (f.name.startsWith('files/')) files[f.name.substring(6)] = f;
  }
  if (data == null) {
    throw TomSecretsImportFormatException('no export.data: not a 1PUX export');
  }
  final Object? json;
  try {
    json = jsonDecode(utf8.decode(data.content));
  } on FormatException catch (e) {
    throw TomSecretsImportFormatException('export.data is not JSON ($e)');
  }
  if (json is! Map || json['accounts'] is! List) {
    throw TomSecretsImportFormatException('export.data holds no accounts');
  }

  Uint8List? fileOf(String? documentId, String? name) {
    if (documentId == null) return null;
    for (final MapEntry(:key, :value) in files.entries) {
      if (key == '${documentId}__$name' || key.startsWith('${documentId}__')) {
        return Uint8List.fromList(value.content);
      }
    }
    return null;
  }

  final vaults = <TomSecretsImportVault>[];
  final notImported = <TomSecretsImportNotice>[];
  for (final account in (json['accounts'] as List).cast<Map>()) {
    for (final vault in (account['vaults'] as List? ?? const []).cast<Map>()) {
      final attrs = (vault['attrs'] as Map?) ?? const {};
      final items = <TomSecretsImportItem>[];
      for (final raw in (vault['items'] as List? ?? const []).cast<Map>()) {
        final item = _OnePuxItem(raw, fileOf);
        if (item.state == 'deleted' || item.state == 'trashed') continue;
        items.add(item.toImport());
        if (item.hasPasskey) {
          notImported.add(
            TomSecretsImportNotice(
              'passkey (not exportable from 1Password; keep using it there '
              'until phase C)',
              title: item.title,
            ),
          );
        }
      }
      vaults.add(
        TomSecretsImportVault(
          id: '${attrs['uuid'] ?? attrs['name'] ?? vaults.length}',
          name: '${attrs['name'] ?? 'Vault ${vaults.length + 1}'}',
          items: items,
        ),
      );
    }
  }
  return TomSecretsImportSource(
    source: tomSecretsOnePasswordSource,
    displayName: '1Password',
    format: '1pux',
    vaults: vaults,
    lost: tomSecretsOnePuxLosses,
    notImported: notImported,
  );
}

/// One 1PUX item.
final class _OnePuxItem {
  _OnePuxItem(this.raw, this.fileOf);

  final Map raw;
  final Uint8List? Function(String? documentId, String? name) fileOf;

  Map get _overview => (raw['overview'] as Map?) ?? const {};
  Map get _details => (raw['details'] as Map?) ?? const {};

  String get title => '${_overview['title'] ?? ''}'.trim();
  String? get state => raw['state'] as String?;

  bool get hasPasskey {
    if (_details.containsKey('passkey')) return true;
    for (final section in _sections) {
      for (final field in _fieldsOf(section)) {
        final value = field['value'];
        if (value is Map && value.containsKey('passkey')) return true;
      }
    }
    return false;
  }

  Iterable<Map> get _sections =>
      (_details['sections'] as List? ?? const []).whereType<Map>();

  static Iterable<Map> _fieldsOf(Map section) =>
      (section['fields'] as List? ?? const []).whereType<Map>();

  static DateTime? _time(Object? seconds) => seconds is num && seconds > 0
      ? DateTime.fromMillisecondsSinceEpoch(seconds.toInt() * 1000, isUtc: true)
      : null;

  TomSecretsImportItem toImport() {
    final category =
        tomSecretsOnePasswordCategories[raw['categoryUuid']] ??
        (TomSecretsImportKind.other, 'Other Items');
    final kind = category.$1;
    String? userName;
    String? password;
    String? url;
    String? totp;
    DateTime? expires;
    final fields = <TomSecretsImportField>[];
    final attachments = <TomSecretsImportAttachment>[];

    // Login fields: the designated user name and password; any other form
    // field as a custom field.
    for (final f
        in (_details['loginFields'] as List? ?? const []).whereType<Map>()) {
      final value = '${f['value'] ?? ''}';
      if (value.isEmpty) continue;
      switch (f['designation']) {
        case 'username' when userName == null:
          userName = value;
        case 'password' when password == null:
          password = value;
        default:
          fields.add(
            TomSecretsImportField(
              '${f['name'] ?? f['id'] ?? 'field'}',
              value,
              isProtected: f['fieldType'] == 'P',
            ),
          );
      }
    }

    for (final section in _sections) {
      final sectionTitle = '${section['title'] ?? ''}'.trim();
      for (final f in _fieldsOf(section)) {
        final id = '${f['id'] ?? ''}';
        final label = '${f['title'] ?? ''}'.trim().isEmpty
            ? id
            : '${f['title']}'.trim();
        final name = sectionTitle.isEmpty ? label : '$sectionTitle · $label';
        final value = f['value'];
        if (value is! Map || value.isEmpty) continue;
        final type = value.keys.first as String;
        final content = value[type];
        switch (type) {
          case 'totp':
            if ('$content'.isNotEmpty) totp ??= '$content';
            continue;
          case 'file':
            final file = content is Map ? content : const {};
            final bytes = fileOf(
              file['documentId'] as String?,
              file['fileName'] as String?,
            );
            if (bytes != null) {
              attachments.add(
                TomSecretsImportAttachment('${file['fileName']}', bytes),
              );
            }
            continue;
          case 'sshKey':
            final key = content is Map ? content : const {};
            final private = '${key['privateKey'] ?? ''}';
            if (private.isNotEmpty) {
              attachments.add(
                TomSecretsImportAttachment(
                  'private_key',
                  Uint8List.fromList(utf8.encode(private)),
                ),
              );
            }
            final meta = key['metadata'];
            if (meta is Map && meta['publicKey'] != null) {
              fields.add(
                TomSecretsImportField(
                  sectionTitle.isEmpty
                      ? 'public key'
                      : '$sectionTitle · public key',
                  '${meta['publicKey']}',
                ),
              );
            }
            continue;
          case 'reference':
            continue; // an item link: lost, named in the report
        }
        final (text, concealed) = _text(type, content);
        if (text.isEmpty) continue;
        // Designated fields of the typed categories go where the type puts
        // them; everything else is a custom field.
        if (kind != TomSecretsImportKind.other) {
          if (id == 'expires' && type == 'date') {
            expires = _time(content);
            if (kind == TomSecretsImportKind.apiToken) continue;
          }
          if ((id == 'username') && userName == null) {
            userName = text;
            continue;
          }
          if ((id == 'password' || id == 'credential') && password == null) {
            password = text;
            continue;
          }
          if ((id == 'url' || id == 'hostname' || id == 'server') &&
              url == null) {
            url = text;
            continue;
          }
        }
        fields.add(TomSecretsImportField(name, text, isProtected: concealed));
      }
    }

    final document = _details['documentAttributes'];
    if (document is Map) {
      final bytes = fileOf(
        document['documentId'] as String?,
        document['fileName'] as String?,
      );
      if (bytes != null) {
        attachments.add(
          TomSecretsImportAttachment('${document['fileName']}', bytes),
        );
      }
    }

    final urls = <String>[
      for (final u in (_overview['urls'] as List? ?? const []).whereType<Map>())
        if ('${u['url'] ?? ''}'.isNotEmpty) '${u['url']}',
    ];
    final primary = '${_overview['url'] ?? ''}';
    if (urls.isEmpty && primary.isNotEmpty) urls.add(primary);
    if (url != null && !urls.contains(url)) urls.insert(0, url);

    final updated = _time(raw['updatedAt']);
    return TomSecretsImportItem(
      sourceId: '${raw['uuid']}',
      version: updated?.toIso8601String() ?? _hash([jsonEncode(raw)]),
      title: title.isEmpty ? '(untitled)' : title,
      kind: kind,
      category: category.$2,
      userName: userName,
      password: password,
      urls: urls,
      notes: (_details['notesPlain'] as String?)?.trim(),
      tags: [
        for (final t in (_overview['tags'] as List? ?? const []))
          if ('$t'.trim().isNotEmpty) '$t'.trim(),
      ],
      favorite: (raw['favIndex'] as num? ?? 0) > 0,
      archived: state == 'archived',
      fields: fields,
      totp: totp,
      attachments: attachments,
      passwordHistory: [
        for (final p
            in (_details['passwordHistory'] as List? ?? const [])
                .whereType<Map>())
          if ('${p['value'] ?? ''}'.isNotEmpty && _time(p['time']) != null)
            TomSecretsImportOldPassword('${p['value']}', _time(p['time'])!),
      ],
      created: _time(raw['createdAt']),
      updated: updated,
      expires: expires,
    );
  }

  /// A field value as text, and whether it is concealed.
  static (String, bool) _text(String type, Object? content) {
    switch (type) {
      case 'concealed' || 'creditCardNumber':
        return ('${content ?? ''}', true);
      case 'date':
        final t = _time(content);
        return (t == null ? '' : t.toIso8601String().substring(0, 10), false);
      case 'monthYear':
        final n = content is num ? content.toInt() : int.tryParse('$content');
        if (n == null || n < 100) return ('', false);
        return ('${n ~/ 100}-${(n % 100).toString().padLeft(2, '0')}', false);
      case 'email':
        if (content is Map) return ('${content['email_address'] ?? ''}', false);
        return ('${content ?? ''}', false);
      case 'address':
        if (content is Map) {
          return (
            [
              for (final k in ['street', 'city', 'zip', 'state', 'country'])
                if ('${content[k] ?? ''}'.isNotEmpty) '${content[k]}',
            ].join(', '),
            false,
          );
        }
        return ('${content ?? ''}', false);
    }
    if (content is Map || content is List) return (jsonEncode(content), false);
    return ('${content ?? ''}', false);
  }
}

String _hash(List<String> parts) =>
    'sha256:${crypto.sha256.convert(utf8.encode(parts.join('\u0000')))}';

/// Reads 1Password's CSV export: one vault `CSV`, one item per row. The
/// header names the columns (any case): `Title`, `Url`/`Website`, `Username`,
/// `Password`, `OTPAuth`/`One-time password`, `Favorite`, `Archived`, `Tags`,
/// `Notes`.
TomSecretsImportSource tomSecretsRead1PasswordCsv(String text) {
  final rows = tomSecretsParseCsv(text);
  if (rows.isEmpty) {
    throw TomSecretsImportFormatException('an empty CSV file');
  }
  final header = [for (final h in rows.first) h.trim().toLowerCase()];
  int? column(List<String> names) {
    for (final n in names) {
      final i = header.indexOf(n);
      if (i >= 0) return i;
    }
    return null;
  }

  final title = column(['title', 'name']);
  if (title == null) {
    throw TomSecretsImportFormatException('the CSV has no Title column');
  }
  final url = column(['url', 'website', 'login_uri']);
  final user = column(['username', 'user name', 'login_username']);
  final password = column(['password', 'login_password']);
  final otp = column(['otpauth', 'one-time password', 'otp', 'totp']);
  final favorite = column(['favorite', 'favourite']);
  final archived = column(['archived']);
  final tags = column(['tags']);
  final notes = column(['notes', 'notesplain']);

  bool flag(String? value) =>
      ['true', '1', 'yes', 'y'].contains(value?.trim().toLowerCase());

  final items = <TomSecretsImportItem>[];
  for (final row in rows.skip(1)) {
    if (row.every((c) => c.trim().isEmpty)) continue;
    String? at(int? i) {
      if (i == null || i >= row.length) return null;
      final v = row[i].trim();
      return v.isEmpty ? null : v;
    }

    final rowTitle = at(title) ?? '(untitled)';
    final rowUrl = at(url);
    final rowUser = at(user);
    final rowPassword = at(password);
    final rowNotes = at(notes);
    items.add(
      TomSecretsImportItem(
        sourceId:
            'csv:${_hash([rowTitle, rowUrl ?? '', rowUser ?? '']).substring(7, 39)}',
        version: _hash(row),
        title: rowTitle,
        kind: rowUser == null && rowPassword == null && rowUrl == null
            ? TomSecretsImportKind.note
            : TomSecretsImportKind.login,
        userName: rowUser,
        password: rowPassword,
        urls: [?rowUrl],
        notes: rowNotes,
        totp: at(otp),
        favorite: flag(at(favorite)),
        archived: flag(at(archived)),
        tags: [
          for (final t in (at(tags) ?? '').split(RegExp('[,;]')))
            if (t.trim().isNotEmpty) t.trim(),
        ],
      ),
    );
  }
  return TomSecretsImportSource(
    source: tomSecretsOnePasswordSource,
    displayName: '1Password',
    format: 'csv',
    vaults: [TomSecretsImportVault(id: 'csv', name: 'CSV', items: items)],
    lost: tomSecretsOnePasswordCsvLosses,
  );
}

/// The rows of a CSV text (RFC 4180: quoted fields with doubled quotes and
/// line breaks inside, CRLF or LF; a leading byte order mark is dropped).
List<List<String>> tomSecretsParseCsv(String text) {
  final rows = <List<String>>[];
  var row = <String>[];
  final field = StringBuffer();
  var quoted = false;
  var i = text.startsWith('﻿') ? 1 : 0;
  var any = false;
  void endField() {
    row.add(field.toString());
    field.clear();
  }

  void endRow() {
    endField();
    rows.add(row);
    row = <String>[];
    any = false;
  }

  while (i < text.length) {
    final c = text[i];
    if (quoted) {
      if (c == '"') {
        if (i + 1 < text.length && text[i + 1] == '"') {
          field.write('"');
          i += 2;
          continue;
        }
        quoted = false;
      } else {
        field.write(c);
      }
      i++;
      continue;
    }
    switch (c) {
      case '"':
        quoted = true;
        any = true;
      case ',':
        endField();
        any = true;
      case '\r':
        if (i + 1 < text.length && text[i + 1] == '\n') i++;
        endRow();
      case '\n':
        endRow();
      default:
        field.write(c);
        any = true;
    }
    i++;
  }
  if (quoted) throw TomSecretsImportFormatException('an unclosed quote');
  if (any || field.isNotEmpty || row.isNotEmpty) endRow();
  return rows;
}
