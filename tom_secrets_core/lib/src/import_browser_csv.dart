// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The browsers' password exports (part-password-manager): the CSV files
/// Chrome, Edge, Firefox and Safari write, read into a
/// [TomSecretsImportSource] that [tomSecretsImport] writes like the others.
///
/// - **Columns** (any case, any order): the title (`name`, `title`; Firefox
///   has none, so the site's host is the title), `url`, `username`,
///   `password`, the notes (`note`, `notes`) and Safari's `OTPAuth`.
/// - **Which browser** is read from the header: Firefox's has `httpRealm`
///   and `guid`, Safari's `OTPAuth`; Chrome and Edge write the same columns,
///   so the caller names which ([TomSecretsCsvBrowser.chrome] by default).
/// - **Re-import:** an item is identified by the same hash of title, URL and
///   user name as an Enpass or 1Password CSV row, its state by the hash of
///   its row; the import id is `tsm.import.<browser>.id`.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

import 'import.dart';
import 'import_1password.dart'
    show TomSecretsImportFormatException, tomSecretsParseCsv;

/// A browser whose password export is read.
enum TomSecretsCsvBrowser {
  /// Google Chrome (and other Chromium browsers).
  chrome('chrome', 'Chrome'),

  /// Microsoft Edge.
  edge('edge', 'Edge'),

  /// Mozilla Firefox.
  firefox('firefox', 'Firefox'),

  /// Apple Safari (and the macOS Passwords app).
  safari('safari', 'Safari');

  const TomSecretsCsvBrowser(this.source, this.displayName);

  /// The source name in `tsm.import.<source>.id`.
  final String source;

  /// How the user reads it.
  final String displayName;
}

/// What a browser CSV import loses, named in every report.
const List<String> tomSecretsBrowserCsvLosses = [
  'folders (every row goes into one target)',
  'password history',
  'created and updated times',
  'passkeys (browsers do not export them)',
];

/// The browser whose export [text]'s header looks like: Firefox or Safari
/// by their own columns, else null (Chrome and Edge look alike).
TomSecretsCsvBrowser? tomSecretsBrowserOfCsv(String text) {
  final rows = tomSecretsParseCsv(text);
  if (rows.isEmpty) return null;
  final header = {for (final h in rows.first) h.trim().toLowerCase()};
  if (header.contains('httprealm') || header.contains('guid')) {
    return TomSecretsCsvBrowser.firefox;
  }
  if (header.contains('otpauth')) return TomSecretsCsvBrowser.safari;
  return null;
}

/// Reads a browser's password export [text]. [browser] names Chrome or
/// Edge (whose files look alike); Firefox and Safari are told from the
/// header. Throws [TomSecretsImportFormatException] when it has no `url`
/// or `password` column.
TomSecretsImportSource tomSecretsReadBrowserCsv(
  String text, {
  TomSecretsCsvBrowser browser = TomSecretsCsvBrowser.chrome,
}) {
  final rows = tomSecretsParseCsv(text);
  if (rows.isEmpty) {
    throw TomSecretsImportFormatException('an empty CSV file');
  }
  final which = tomSecretsBrowserOfCsv(text) ?? browser;
  final header = [for (final h in rows.first) h.trim().toLowerCase()];
  int? column(List<String> names) {
    for (final n in names) {
      final i = header.indexOf(n);
      if (i >= 0) return i;
    }
    return null;
  }

  final url = column(['url', 'website', 'origin']);
  final password = column(['password']);
  if (url == null || password == null) {
    throw TomSecretsImportFormatException(
      'the CSV has no url and password columns: not a browser export',
    );
  }
  final title = column(['name', 'title']);
  final user = column(['username', 'user name', 'login']);
  final notes = column(['note', 'notes', 'comment', 'comments']);
  final otp = column(['otpauth']);

  final items = <TomSecretsImportItem>[];
  for (final row in rows.skip(1)) {
    if (row.every((c) => c.trim().isEmpty)) continue;
    String? at(int? i) {
      if (i == null || i >= row.length) return null;
      final v = row[i].trim();
      return v.isEmpty ? null : v;
    }

    final rowUrl = at(url);
    final rowTitle = at(title) ?? _hostOf(rowUrl) ?? '(untitled)';
    final rowUser = at(user);
    items.add(
      TomSecretsImportItem(
        sourceId:
            'csv:${_hash([rowTitle, rowUrl ?? '', rowUser ?? '']).substring(7, 39)}',
        version: _hash(row),
        title: rowTitle,
        userName: rowUser,
        password: at(password),
        urls: [?rowUrl],
        notes: at(notes),
        totp: at(otp),
      ),
    );
  }
  return TomSecretsImportSource(
    source: which.source,
    displayName: which.displayName,
    format: 'csv',
    vaults: [TomSecretsImportVault(id: 'csv', name: 'Passwords', items: items)],
    lost: tomSecretsBrowserCsvLosses,
  );
}

String? _hostOf(String? url) {
  if (url == null) return null;
  final host = Uri.tryParse(url)?.host ?? '';
  return host.isEmpty ? null : host;
}

String _hash(List<String> parts) =>
    'sha256:${crypto.sha256.convert(utf8.encode(parts.join('\u0000')))}';
