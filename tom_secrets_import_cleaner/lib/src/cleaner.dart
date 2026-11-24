// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Cleaning a password manager's export so it can be handed to someone for
/// testing the import: every secret and every personal value is replaced,
/// the structure is kept.
///
/// - **Masked** (`X` for every character, whitespace kept, so lengths and
///   line breaks stay): passwords, notes, custom field values, one-time
///   code secrets, password histories: every string the rules below do not
///   keep or replace.
/// - **Emptied**: private key material (a passkey's or an SSH key's
///   `privateKey`), so the importers name the key as missing.
/// - **Replaced by a stand-in** that stays unique, so the importers that
///   match items by title, URL and user name still see distinct items:
///   titles (`Item <n>`), e-mail addresses (`user<n>@example.com`) and URLs
///   (`https://site<n>.example.com/` with the path masked). The same
///   original always gets the same stand-in.
/// - **Zeroed**: attachments (the same number of bytes, all zero).
/// - **Kept**: the structure (keys, lists, numbers, booleans, timestamps),
///   ids and references (UUIDs, `...Id` and `uuid` keys), and the words that
///   say what a thing is (`type`, `category`, `kind`, `designation`, field
///   labels, ...).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';

/// The export formats the cleaner reads.
enum TomSecretsCleanerFormat {
  /// Enpass 6, JSON.
  enpassJson('Enpass JSON'),

  /// Bitwarden, unencrypted JSON.
  bitwardenJson('Bitwarden JSON'),

  /// 1Password's 1PUX (a ZIP with `export.data` and `files/`).
  onePasswordPux('1Password 1PUX'),

  /// A CSV with a header row: 1Password, Bitwarden, Chrome, Edge, Firefox,
  /// Safari and the other browsers.
  csvWithHeader('CSV with a header'),

  /// Enpass's CSV: title, label and value pairs, the note last (a header
  /// `Title, Field, Value, ..., Note` when the export has one).
  enpassCsv('Enpass CSV');

  const TomSecretsCleanerFormat(this.label);

  /// For the user.
  final String label;
}

/// An export the cleaner cannot read.
final class TomSecretsCleanerException implements Exception {
  /// The problem [message].
  const TomSecretsCleanerException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => message;
}

/// What a clean did.
final class TomSecretsCleanReport {
  /// The counts of a clean of [format].
  TomSecretsCleanReport(this.format);

  /// The format read.
  final TomSecretsCleanerFormat format;

  /// Strings masked.
  int masked = 0;

  /// Titles, e-mail addresses and URLs replaced by stand-ins.
  int replaced = 0;

  /// Attachments zeroed, and their bytes.
  int attachments = 0;

  /// The attachments' bytes, zeroed.
  int attachmentBytes = 0;

  /// Strings kept (ids, types, labels).
  int kept = 0;

  @override
  String toString() =>
      '${format.label}: $masked values masked, $replaced replaced by '
      'stand-ins, $attachments attachments zeroed '
      '(${(attachmentBytes / 1024).ceil()} KiB), $kept kept';
}

/// The format of [bytes], or throws [TomSecretsCleanerException].
TomSecretsCleanerFormat tomSecretsCleanerFormatOf(Uint8List bytes) {
  if (bytes.length > 4 && bytes[0] == 0x50 && bytes[1] == 0x4b) {
    return TomSecretsCleanerFormat.onePasswordPux;
  }
  if (bytes.length > 4 &&
      bytes[0] == 0x03 &&
      bytes[1] == 0xd9 &&
      bytes[2] == 0xa2 &&
      bytes[3] == 0x9a) {
    throw const TomSecretsCleanerException(
      'a KDBX file: it is encrypted and opens only with its keys; export '
      'it from KeePass as CSV or XML, or clean the export of the password '
      'manager it came from',
    );
  }
  final text = _text(bytes).trimLeft();
  if (text.startsWith('{')) {
    final Object? json;
    try {
      json = jsonDecode(text);
    } on FormatException catch (e) {
      throw TomSecretsCleanerException('not JSON: $e');
    }
    if (json is Map && json['items'] is List && json['encrypted'] != true) {
      final items = json['items'] as List;
      // Enpass's items carry a template and a category name; Bitwarden's
      // a numeric type and a login.
      final enpass = items.whereType<Map>().any(
        (i) => i.containsKey('template_type') || i['category'] is String,
      );
      return enpass
          ? TomSecretsCleanerFormat.enpassJson
          : TomSecretsCleanerFormat.bitwardenJson;
    }
    if (json is Map && json['encrypted'] == true) {
      throw const TomSecretsCleanerException(
        'an encrypted Bitwarden export: its values are encrypted already; '
        'export it unencrypted to clean it',
      );
    }
    throw const TomSecretsCleanerException(
      'a JSON file with no items: not an export the cleaner knows',
    );
  }
  final rows = _parseCsv(text);
  if (rows.isEmpty) throw const TomSecretsCleanerException('an empty file');
  if (_isEnpassCsvHeader(rows.first)) return TomSecretsCleanerFormat.enpassCsv;
  final header = rows.first.map((c) => c.trim().toLowerCase()).toSet();
  const known = {
    'title',
    'name',
    'url',
    'username',
    'login_username',
    'password',
    'login_password',
    'notes',
    'note',
    'website',
    'login_uri',
  };
  return header.intersection(known).length >= 2
      ? TomSecretsCleanerFormat.csvWithHeader
      : TomSecretsCleanerFormat.enpassCsv;
}

/// Cleans the export [bytes]; answers the cleaned bytes and the report.
({Uint8List bytes, TomSecretsCleanReport report}) tomSecretsCleanExport(
  Uint8List bytes, {
  TomSecretsCleanerFormat? format,
}) {
  final f = format ?? tomSecretsCleanerFormatOf(bytes);
  final cleaner = _Cleaner(TomSecretsCleanReport(f));
  final Uint8List out = switch (f) {
    TomSecretsCleanerFormat.enpassJson ||
    TomSecretsCleanerFormat.bitwardenJson => _utf8(cleaner.json(_text(bytes))),
    TomSecretsCleanerFormat.onePasswordPux => cleaner.pux(bytes),
    TomSecretsCleanerFormat.csvWithHeader => _utf8(
      cleaner.csv(_text(bytes), header: true),
    ),
    TomSecretsCleanerFormat.enpassCsv => _utf8(
      cleaner.csv(_text(bytes), header: false),
    ),
  };
  return (bytes: out, report: cleaner.report);
}

String _text(Uint8List bytes) {
  var text = utf8.decode(bytes, allowMalformed: true);
  if (text.startsWith('﻿')) text = text.substring(1);
  return text;
}

Uint8List _utf8(String text) => Uint8List.fromList(utf8.encode(text));

/// Keys whose string values say what a thing is, and are kept.
const Set<String> _structuralKeys = {
  'type',
  'kind',
  'category',
  'category_name',
  'categoryUuid',
  'designation',
  'fieldType',
  'template_type',
  'state',
  'label',
  'icon',
  'file',
  'format',
  'version',
  'match',
  'reprompt',
  'k',
  'algorithm',
  'subtitle_type',
};

/// Keys whose string values are titles: replaced by `Item <n>`.
const Set<String> _titleKeys = {'title', 'name'};

/// Keys whose string values are URLs.
const Set<String> _urlKeys = {'url', 'uri', 'website', 'login_uri', 'href'};

/// Keys holding private key material (a passkey's, an SSH key's): emptied,
/// whatever they hold, so the importers name the key as missing.
const Set<String> _privateKeyKeys = {
  'privateKey',
  'private_key',
  'privateKeyPem',
  'private_key_pem',
};

/// Keys whose string values are a relying party's host (passkeys).
const Set<String> _hostKeys = {
  'rpId',
  'rp_id',
  'relyingParty',
  'relying_party',
};

/// Keys whose string values are attachment data in base64.
const Set<String> _attachmentKeys = {'data'};

final RegExp _uuid = RegExp(
  r'^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$',
);
final RegExp _hexId = RegExp(r'^[0-9a-zA-Z]{20,32}$');
final RegExp _email = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$');
final RegExp _url = RegExp(r'^[a-zA-Z][a-zA-Z0-9+.-]*://');

bool _isIdKey(String key) =>
    key == 'id' ||
    key == 'uuid' ||
    key == 'uid' ||
    key.endsWith('Id') ||
    key.endsWith('Ids') ||
    key.endsWith('_uuid') ||
    key.endsWith('Uuid') ||
    key == 'folders' ||
    key == 'collectionIds';

final class _Cleaner {
  _Cleaner(this.report);

  final TomSecretsCleanReport report;
  final Map<String, String> _titles = {};
  final Map<String, String> _emails = {};
  final Map<String, String> _hosts = {};

  /// Every non-whitespace character as `X`.
  String mask(String value) {
    if (value.isEmpty) return value;
    report.masked++;
    return value.replaceAll(RegExp(r'\S'), 'X');
  }

  String title(String value) {
    if (value.trim().isEmpty) return value;
    report.replaced++;
    return _titles.putIfAbsent(value, () => 'Item ${_titles.length + 1}');
  }

  String email(String value) {
    report.replaced++;
    return _emails.putIfAbsent(
      value.toLowerCase(),
      () => 'user${_emails.length + 1}@example.com',
    );
  }

  String host(String value) {
    final h = value.trim().toLowerCase();
    if (h.isEmpty) return value;
    report.replaced++;
    return _hosts.putIfAbsent(h, () => 'site${_hosts.length + 1}.example.com');
  }

  String url(String value) {
    final uri = Uri.tryParse(value.trim());
    if (uri == null || uri.host.isEmpty) return mask(value);
    report.replaced++;
    final host = _hosts.putIfAbsent(
      uri.host.toLowerCase(),
      () => 'site${_hosts.length + 1}.example.com',
    );
    final path = uri.path.isEmpty || uri.path == '/'
        ? '/'
        : uri.path.replaceAll(RegExp(r'[^/]'), 'x');
    return '${uri.scheme}://$host$path';
  }

  /// A string that is not structural: an e-mail address, a URL, else
  /// masked.
  String value(String value) {
    final t = value.trim();
    if (_email.hasMatch(t)) return email(t);
    if (_url.hasMatch(t)) return url(t);
    return mask(value);
  }

  String base64Zeros(String value) {
    final List<int> decoded;
    try {
      decoded = base64.decode(
        base64.normalize(value.replaceAll(RegExp(r'\s'), '')),
      );
    } on FormatException {
      return mask(value);
    }
    report.attachments++;
    report.attachmentBytes += decoded.length;
    return base64.encode(Uint8List(decoded.length));
  }

  /// [node] under [key]; [inValue] while inside a field's `value` (1PUX:
  /// `{"concealed": ...}`, `{"monthYear": 202807}`), whose numbers are
  /// content too.
  Object? walk(
    Object? node,
    String key,
    String parentKey, {
    bool inValue = false,
  }) {
    if (_privateKeyKeys.contains(key) && node != null) {
      report.masked++;
      return '';
    }
    final value_ = inValue || key == 'value';
    if (node is Map) {
      return {
        for (final MapEntry(key: k, value: v) in node.entries)
          k: walk(v, '$k', key, inValue: value_),
      };
    }
    if (node is List) {
      return [for (final v in node) walk(v, key, parentKey, inValue: inValue)];
    }
    if (node is num && value_) {
      // A number that is a field's content (a card's expiry, a date): its
      // digit count kept, its digits not.
      report.masked++;
      final digits = '${node.abs().truncate()}'.length;
      return node is int ? int.parse('1${'0' * (digits - 1)}') : 0.0;
    }
    if (node is! String) return node; // numbers, booleans, null
    if (_hostKeys.contains(key)) return host(node);
    if (_isIdKey(key) || _uuid.hasMatch(node)) {
      report.kept++;
      return node;
    }
    if (_structuralKeys.contains(key)) {
      report.kept++;
      return node;
    }
    if (_attachmentKeys.contains(key) && node.length > 16) {
      return base64Zeros(node);
    }
    if (_titleKeys.contains(key)) {
      // A field's or a folder's name stays a name, an item's a title.
      return title(node);
    }
    if (_urlKeys.contains(key)) {
      return _url.hasMatch(node.trim()) ? url(node) : value(node);
    }
    if (_hexId.hasMatch(node) && key.toLowerCase().contains('id')) {
      report.kept++;
      return node;
    }
    return value(node);
  }

  String json(String text) {
    final Object? data;
    try {
      data = jsonDecode(text);
    } on FormatException catch (e) {
      throw TomSecretsCleanerException('not JSON: $e');
    }
    return const JsonEncoder.withIndent('    ').convert(walk(data, '', ''));
  }

  Uint8List pux(Uint8List bytes) {
    final Archive archive;
    try {
      archive = ZipDecoder().decodeBytes(bytes);
    } on Object catch (e) {
      throw TomSecretsCleanerException('not a 1PUX (ZIP) file: $e');
    }
    if (archive.findFile('export.data') == null) {
      throw const TomSecretsCleanerException(
        'no export.data: not a 1PUX export',
      );
    }
    final out = Archive();
    for (final f in archive.files) {
      if (!f.isFile) continue;
      final content = f.content;
      final List<int> data;
      if (f.name == 'export.data') {
        data = utf8.encode(json(utf8.decode(content, allowMalformed: true)));
      } else if (f.name.startsWith('files/')) {
        report.attachments++;
        report.attachmentBytes += content.length;
        data = Uint8List(content.length);
      } else {
        data = content;
      }
      out.addFile(ArchiveFile(f.name, data.length, data));
    }
    return Uint8List.fromList(ZipEncoder().encode(out));
  }

  String csv(String text, {required bool header}) {
    final rows = _parseCsv(text);
    final out = <List<String>>[];
    List<String>? names;
    for (var r = 0; r < rows.length; r++) {
      final row = rows[r];
      if (header && r == 0) {
        names = [for (final c in row) c.trim().toLowerCase()];
        report.kept += row.length;
        out.add(row);
        continue;
      }
      final cells = <String>[];
      for (var c = 0; c < row.length; c++) {
        final cell = row[c];
        if (names != null) {
          final name = c < names.length ? names[c] : '';
          if (_titleKeys.contains(name) || name == 'title') {
            cells.add(title(cell));
          } else if (_urlKeys.contains(name) || name.contains('url')) {
            cells.add(cell.trim().isEmpty ? cell : url(cell));
          } else if (name == 'type' ||
              name == 'folder' ||
              name == 'favorite' ||
              name == 'archived' ||
              name == 'reprompt' ||
              name == 'collections') {
            report.kept++;
            cells.add(cell);
          } else {
            cells.add(cell.trim().isEmpty ? cell : value(cell));
          }
        } else if (r == 0 && _isEnpassCsvHeader(row)) {
          report.kept++;
          cells.add(cell);
        } else {
          // Enpass CSV: the title, label and value pairs, the note last.
          final last = c == row.length - 1 && row.length.isEven;
          if (c == 0) {
            cells.add(title(cell));
          } else if (!last && c.isOdd) {
            report.kept++;
            cells.add(cell); // a label
          } else {
            cells.add(cell.trim().isEmpty ? cell : value(cell));
          }
        }
      }
      out.add(cells);
    }
    return _writeCsv(out);
  }
}

/// Enpass's CSV header: `Title`, then `Field`, `Value` pairs, `Note`.
bool _isEnpassCsvHeader(List<String> row) =>
    row.length >= 3 &&
    row[0].trim().toLowerCase() == 'title' &&
    row[1].trim().toLowerCase() == 'field' &&
    row[2].trim().toLowerCase() == 'value';

/// RFC 4180 CSV: quoted fields with doubled quotes and line breaks inside.
List<List<String>> _parseCsv(String text) {
  final rows = <List<String>>[];
  var row = <String>[];
  final field = StringBuffer();
  var quoted = false;
  var i = 0;
  while (i < text.length) {
    final ch = text[i];
    if (quoted) {
      if (ch == '"') {
        if (i + 1 < text.length && text[i + 1] == '"') {
          field.write('"');
          i += 2;
          continue;
        }
        quoted = false;
      } else {
        field.write(ch);
      }
      i++;
      continue;
    }
    switch (ch) {
      case '"':
        quoted = true;
      case ',':
        row.add(field.toString());
        field.clear();
      case '\r':
        break;
      case '\n':
        row.add(field.toString());
        field.clear();
        rows.add(row);
        row = <String>[];
      default:
        field.write(ch);
    }
    i++;
  }
  if (field.isNotEmpty || row.isNotEmpty) {
    row.add(field.toString());
    rows.add(row);
  }
  return rows;
}

String _writeCsv(List<List<String>> rows) {
  String cell(String c) => c.contains(RegExp(r'[",\r\n]')) || c.startsWith(' ')
      ? '"${c.replaceAll('"', '""')}"'
      : c;
  return '${rows.map((r) => r.map(cell).join(',')).join('\n')}\n';
}
