// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Reading Enpass 6's exports (part-password-manager, DP-36, DP-120) into a
/// [TomSecretsImportSource] for [tomSecretsImport]. Enpass exports one vault
/// at a time.
///
/// - **JSON** ([tomSecretsReadEnpassJson], recommended): `folders` (nested by
///   `parent_uuid`) and `items` with their ordered `fields`; attachments,
///   password history and passkeys where the export carries them.
/// - **CSV** ([tomSecretsReadEnpassCsv]): one row per item, the title first,
///   then label and value pairs, the note last; no folders, no categories,
///   no attachments, no stable id (matched by a hash of title, first URL and
///   user name).
/// - The text export has no reliable structure and is not read.
///
/// The layout follows the fixtures in the tests; a real export is checked
/// against it before the user's import (see the README).
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'import.dart';
import 'import_1password.dart'
    show TomSecretsImportFormatException, tomSecretsParseCsv;
import 'passkey.dart';

/// The source name of Enpass imports (`tsm.import.enpass.id`).
const String tomSecretsEnpassSource = 'enpass';

/// What an Enpass JSON import loses, named in every report.
const List<String> tomSecretsEnpassJsonLosses = [
  'item icons',
  'the order of fields where KDBX has none',
  'the subtitle when it only repeats a field',
  'shared vaults\' sharing',
];

/// What an Enpass CSV import loses besides [tomSecretsEnpassJsonLosses].
const List<String> tomSecretsEnpassCsvLosses = [
  ...tomSecretsEnpassJsonLosses,
  'folders',
  'categories (every row is a login or a note)',
  'sections, and which fields are sensitive',
  'attachments',
  'password history',
  'created and updated times',
  'passkeys',
];

/// Enpass's categories: how each is typed, and the subgroup another
/// category goes into.
const Map<String, (TomSecretsImportKind, String)> tomSecretsEnpassCategories = {
  'login': (TomSecretsImportKind.login, 'Logins'),
  'password': (TomSecretsImportKind.login, 'Passwords'),
  'note': (TomSecretsImportKind.note, 'Notes'),
  'computer': (TomSecretsImportKind.login, 'Computers'),
  'creditcard': (TomSecretsImportKind.other, 'Credit Cards'),
  'identity': (TomSecretsImportKind.other, 'Identities'),
  'finance': (TomSecretsImportKind.other, 'Finance'),
  'license': (TomSecretsImportKind.other, 'Licenses'),
  'travel': (TomSecretsImportKind.other, 'Travel'),
  'misc': (TomSecretsImportKind.other, 'Miscellaneous'),
};

String _hash(List<String> parts) =>
    'sha256:${crypto.sha256.convert(utf8.encode(parts.join('\u0000')))}';

DateTime? _time(Object? seconds) => seconds is num && seconds > 0
    ? DateTime.fromMillisecondsSinceEpoch(seconds.toInt() * 1000, isUtc: true)
    : null;

bool _flag(Object? value) =>
    value == true || value == 1 || value == '1' || value == 'true';

/// Reads an Enpass JSON export of the vault [vaultName].
TomSecretsImportSource tomSecretsReadEnpassJson(
  String json, {
  String vaultName = 'Vault',
}) {
  final Object? data;
  try {
    data = jsonDecode(json);
  } on FormatException catch (e) {
    throw TomSecretsImportFormatException('not JSON ($e)');
  }
  if (data is! Map || data['items'] is! List) {
    throw TomSecretsImportFormatException('no items: not an Enpass export');
  }
  final folders = <String, Map>{
    for (final f in (data['folders'] as List? ?? const []).whereType<Map>())
      '${f['uuid']}': f,
  };
  List<String> pathOf(String uuid) {
    final path = <String>[];
    final seen = <String>{};
    for (var at = folders[uuid]; at != null && seen.add('${at['uuid']}');) {
      path.insert(0, '${at['title'] ?? ''}');
      at = folders['${at['parent_uuid'] ?? ''}'];
    }
    return path;
  }

  final items = <TomSecretsImportItem>[];
  final notImported = <TomSecretsImportNotice>[];
  for (final raw in (data['items'] as List).whereType<Map>()) {
    final (item, notice) = _enpassItem(raw, pathOf, folders);
    items.add(item);
    if (notice != null) notImported.add(notice);
  }
  return TomSecretsImportSource(
    source: tomSecretsEnpassSource,
    displayName: 'Enpass',
    format: 'json',
    vaults: [
      TomSecretsImportVault(id: vaultName, name: vaultName, items: items),
    ],
    lost: tomSecretsEnpassJsonLosses,
    notImported: notImported,
  );
}

(TomSecretsImportItem, TomSecretsImportNotice?) _enpassItem(
  Map raw,
  List<String> Function(String uuid) pathOf,
  Map<String, Map> folders,
) {
  final title = '${raw['title'] ?? ''}'.trim();
  final categoryName = '${raw['category'] ?? 'misc'}';
  final category =
      tomSecretsEnpassCategories[categoryName] ??
      (
        TomSecretsImportKind.other,
        categoryName.isEmpty
            ? 'Miscellaneous'
            : '${categoryName[0].toUpperCase()}${categoryName.substring(1)}',
      );
  final fields = [
    for (final f in (raw['fields'] as List? ?? const []).whereType<Map>())
      if (!_flag(f['deleted'])) f,
  ];
  int? firstOf(String type) {
    final i = fields.indexWhere((f) => f['type'] == type);
    return i < 0 ? null : i;
  }

  final userField = firstOf('username') ?? firstOf('email');
  final passwordField = firstOf('password');
  String? userName;
  String? password;
  String? totp;
  final urls = <String>[];
  final custom = <TomSecretsImportField>[];
  final history = <TomSecretsImportOldPassword>[];
  Object? passkeyRaw = raw['passkey'];
  for (var i = 0; i < fields.length; i++) {
    final f = fields[i];
    final type = '${f['type'] ?? 'text'}';
    final label = '${f['label'] ?? ''}'.trim();
    // A section is only a heading in Enpass: its fields keep their own
    // labels (a label used twice gets a number when written).
    if (type == 'section') continue;
    if (type == 'passkey') {
      passkeyRaw ??= f['value'];
      continue;
    }
    final value = '${f['value'] ?? ''}';
    if (i == passwordField) {
      for (final h in (f['history'] as List? ?? const []).whereType<Map>()) {
        final old = '${h['value'] ?? ''}';
        final at = _time(h['updated_at'] ?? h['time']);
        if (old.isNotEmpty && at != null) {
          history.add(TomSecretsImportOldPassword(old, at));
        }
      }
    }
    if (value.trim().isEmpty) continue;
    if (i == userField) {
      userName = value;
    } else if (i == passwordField) {
      password = value;
    } else if (type == 'url') {
      urls.add(value);
    } else if (type == 'totp' && totp == null) {
      totp = value;
    } else {
      custom.add(
        TomSecretsImportField(
          label.isEmpty ? type : label,
          value,
          isProtected:
              _flag(f['sensitive']) || type == 'password' || type == 'totp',
        ),
      );
    }
  }
  for (final h
      in (raw['password_history'] as List? ?? const []).whereType<Map>()) {
    final old = '${h['value'] ?? h['password'] ?? ''}';
    final at = _time(h['updated_at'] ?? h['time']);
    if (old.isNotEmpty && at != null) {
      history.add(TomSecretsImportOldPassword(old, at));
    }
  }

  final attachments = <TomSecretsImportAttachment>[
    for (final a in (raw['attachments'] as List? ?? const []).whereType<Map>())
      if (a['data'] is String && a['name'] != null)
        TomSecretsImportAttachment(
          '${a['name']}',
          tomSecretsDecodeBase64(a['data'] as String),
        ),
  ];

  final folderIds = [
    for (final id in raw['folders'] as List? ?? const []) '$id',
  ];
  final known = [
    for (final id in folderIds)
      if (folders.containsKey(id)) id,
  ];

  TomSecretsPasskey? passkey;
  TomSecretsImportNotice? notice;
  if (passkeyRaw != null) {
    // Why: one passkey this reader cannot convert must not abort the
    // import of every other item; the item comes without it, named.
    String? unreadable;
    try {
      passkey = _passkeyOf(passkeyRaw, userName: userName, urls: urls);
    } on TomSecretsPasskeyException catch (e) {
      unreadable = e.message;
    } on FormatException {
      // Its message can quote the input, which is key material.
      unreadable = 'not valid JSON or base64';
    }
    if (unreadable != null) {
      notice = TomSecretsImportNotice(
        'passkey that could not be read ($unreadable)',
        title: title,
      );
    } else if (passkey == null) {
      notice = TomSecretsImportNotice(
        'passkey without its private key (register a new one in phase C)',
        title: title,
      );
    }
  }

  final updated = _time(raw['updated_at']);
  return (
    TomSecretsImportItem(
      sourceId: '${raw['uuid']}',
      version: updated?.toIso8601String() ?? _hash([jsonEncode(raw)]),
      title: title.isEmpty ? '(untitled)' : title,
      kind: category.$1,
      category: category.$2,
      userName: userName,
      password: password,
      urls: urls,
      notes: '${raw['note'] ?? ''}'.trim(),
      tags: [
        for (final id in known.skip(1))
          if ('${folders[id]!['title'] ?? ''}'.trim().isNotEmpty)
            '${folders[id]!['title']}'.trim(),
      ],
      favorite: _flag(raw['favorite']),
      archived: _flag(raw['archived']),
      trashed: _flag(raw['trashed']),
      fields: custom,
      totp: totp,
      attachments: attachments,
      passwordHistory: history,
      created: _time(raw['createdAt'] ?? raw['created_at']),
      updated: updated,
      folders: known.isEmpty ? const [] : pathOf(known.first),
      passkey: passkey,
    ),
    notice,
  );
}

/// The passkey of an Enpass passkey value (a map or its JSON text), or null
/// when it carries no private key. Throws [TomSecretsPasskeyException] or
/// [FormatException] when a value it holds cannot be read. Field names are read in the spellings
/// seen in exports (`rpId`/`relyingParty`, `credentialId`, `userHandle`,
/// `userName`, `privateKey` as PEM, base64 DER or a JWK).
TomSecretsPasskey? _passkeyOf(
  Object raw, {
  String? userName,
  required List<String> urls,
}) {
  Map? map = raw is Map ? raw : null;
  if (raw is String && raw.trim().startsWith('{')) {
    final decoded = jsonDecode(raw);
    if (decoded is Map) map = decoded;
  }
  if (map == null) return null;
  Object? pick(List<String> names) {
    for (final n in names) {
      final v = map![n];
      if (v != null && '$v'.isNotEmpty) return v;
    }
    return null;
  }

  final key = pick(['privateKey', 'private_key', 'key', 'privateKeyPem']);
  final credentialId = pick(['credentialId', 'credential_id', 'id']);
  var rp = pick(['rpId', 'rp_id', 'relyingParty', 'relying_party']);
  if (rp == null && urls.isNotEmpty) rp = Uri.tryParse(urls.first)?.host;
  if (key == null || credentialId == null || rp == null) return null;
  final handle = pick(['userHandle', 'user_handle']);
  final account =
      '${pick(['userName', 'username', 'user_name']) ?? userName ?? ''}';
  return TomSecretsPasskey(
    relyingParty: '$rp',
    credentialId: tomSecretsBase64Url('$credentialId'),
    privateKeyPem: tomSecretsPasskeyPem(key is Map ? key : '$key'),
    userHandle: handle == null ? null : tomSecretsBase64Url('$handle'),
    userName: account.isEmpty ? null : account,
  );
}

const _userLabels = {'username', 'user name', 'login', 'e-mail', 'email'};
const _urlLabels = {'url', 'website', 'web site'};
const _totpLabels = {'totp', 'one-time code', 'authenticator key', 'otp'};
const _sensitiveWords = ['password', 'pin', 'cvc', 'cvv', 'secret', 'key'];

/// Reads an Enpass CSV export of the vault [vaultName]: per row the title,
/// label and value pairs, the note; a header row (`Title`, …, `Note`) is
/// skipped.
TomSecretsImportSource tomSecretsReadEnpassCsv(
  String text, {
  String vaultName = 'Vault',
}) {
  final rows = tomSecretsParseCsv(text);
  final items = <TomSecretsImportItem>[];
  for (final (i, row) in rows.indexed) {
    if (row.every((c) => c.trim().isEmpty)) continue;
    if (i == 0 &&
        row.first.trim().toLowerCase() == 'title' &&
        row.last.trim().toLowerCase().startsWith('note')) {
      continue;
    }
    if (row.length < 2) {
      throw TomSecretsImportFormatException(
        'row ${i + 1} has no note column: not an Enpass CSV',
      );
    }
    final title = row.first.trim();
    final note = row.last.trim();
    String? userName;
    String? password;
    String? totp;
    final urls = <String>[];
    final custom = <TomSecretsImportField>[];
    // Between the title and the note: label and value pairs.
    final pairs = row.sublist(1, row.length - 1);
    for (var p = 0; p + 1 < pairs.length; p += 2) {
      final label = pairs[p].trim();
      final value = pairs[p + 1];
      if (value.trim().isEmpty) continue;
      final lower = label.toLowerCase();
      if (_userLabels.contains(lower) && userName == null) {
        userName = value;
      } else if (lower == 'password' && password == null) {
        password = value;
      } else if (_urlLabels.contains(lower)) {
        urls.add(value);
      } else if (_totpLabels.contains(lower) && totp == null) {
        totp = value;
      } else {
        custom.add(
          TomSecretsImportField(
            label.isEmpty ? 'field' : label,
            value,
            isProtected: _sensitiveWords.any(lower.contains),
          ),
        );
      }
    }
    final url = urls.isEmpty ? '' : urls.first;
    items.add(
      TomSecretsImportItem(
        sourceId: 'csv:${_hash([title, url, userName ?? '']).substring(7, 39)}',
        version: _hash(row),
        title: title.isEmpty ? '(untitled)' : title,
        kind: userName == null && password == null && urls.isEmpty
            ? TomSecretsImportKind.note
            : TomSecretsImportKind.login,
        userName: userName,
        password: password,
        urls: urls,
        notes: note,
        totp: totp,
        fields: custom,
      ),
    );
  }
  return TomSecretsImportSource(
    source: tomSecretsEnpassSource,
    displayName: 'Enpass',
    format: 'csv',
    vaults: [
      TomSecretsImportVault(id: vaultName, name: vaultName, items: items),
    ],
    lost: tomSecretsEnpassCsvLosses,
  );
}
