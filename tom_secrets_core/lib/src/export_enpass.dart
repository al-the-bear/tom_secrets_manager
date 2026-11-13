// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The Enpass JSON export (part-password-manager, DP-40): a vault, or one of
/// its groups, written in the layout of Enpass 6's own JSON export, so the
/// data can go back to Enpass where Enpass's import reads it (checked against
/// Enpass itself before it is offered; otherwise Enpass is served by CSV).
/// The file holds every password in plaintext; the app says so.
///
/// Groups become folders (nested by `parent_uuid`), entries items with their
/// ordered fields: user name, password (with its history), URLs, the TOTP as
/// one `totp` field, every other field as a text field, under a `section`
/// field where its name is `<section> · <label>`, protected fields
/// `sensitive`. The product's own groups and `tsm.*` fields stay behind;
/// passkeys are not exported and are named in [TomSecretsEnpassExport.lost].
library;

import 'dart:convert';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';
import 'passkey.dart';
import 'totp.dart';

/// An Enpass JSON export and what it left behind.
final class TomSecretsEnpassExport {
  const TomSecretsEnpassExport._({
    required this.json,
    required this.items,
    required this.folders,
    required this.lost,
  });

  /// The export's text.
  final String json;

  /// How many items it holds.
  final int items;

  /// How many folders it holds.
  final int folders;

  /// What the export does not carry, with the entries concerned.
  final List<String> lost;
}

const _totpFields = {
  'otp',
  'OTPAuth',
  'TimeOtp-Secret-Base32',
  'TimeOtp-Length',
  'TimeOtp-Period',
  'TimeOtp-Algorithm',
};

/// Writes [group] (default: the whole vault [file]) as an Enpass JSON
/// export. The recycle bin, the product's groups (`.tom-secrets`,
/// `tsm.grants`) and `tsm.*` fields are left out.
TomSecretsEnpassExport tomSecretsExportEnpassJson(
  KdbxFile file, {
  KdbxGroup? group,
  DateTime? now,
}) {
  final at = (now ?? DateTime.now()).toUtc().millisecondsSinceEpoch ~/ 1000;
  final root = group ?? file.body.rootGroup;
  final bin = file.recycleBin;
  final folders = <Map<String, Object?>>[];
  final items = <Map<String, Object?>>[];
  final passkeys = <String>[];
  final tags = <String>{};

  bool skipped(KdbxGroup g) {
    final name = g.name.get() ?? '';
    return (bin != null && g.uuid == bin.uuid) ||
        name == '.tom-secrets' ||
        name == tomSecretsGrantsGroup ||
        name.startsWith(TomSecretsEntryFields.reservedPrefix);
  }

  void walk(KdbxGroup g, String? folder) {
    for (final e in g.entries) {
      items.add(_item(e, folder, at, passkeys, tags));
    }
    for (final child in g.groups) {
      if (skipped(child)) continue;
      final id = _uuid(child.uuid);
      folders.add({
        'icon': '1008',
        'parent_uuid': folder ?? '',
        'title': child.name.get() ?? '',
        'updated_at': at,
        'uuid': id,
      });
      walk(child, id);
    }
  }

  walk(root, null);
  return TomSecretsEnpassExport._(
    json: const JsonEncoder.withIndent(
      '    ',
    ).convert({'folders': folders, 'items': items}),
    items: items.length,
    folders: folders.length,
    lost: [
      'entry history other than former passwords',
      'expiry dates',
      'overlay bindings (the @ groups are written as plain folders)',
      if (tags.isNotEmpty) 'tags other than favorite: ${tags.join(', ')}',
      if (passkeys.isNotEmpty) 'passkeys of: ${passkeys.join(', ')}',
    ],
  );
}

/// The 8-4-4-4-12 hex form of [uuid].
String _uuid(KdbxUuid uuid) {
  final hex = tomSecretsUuidHex(uuid);
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

int _seconds(DateTime? t, int fallback) =>
    t == null ? fallback : t.toUtc().millisecondsSinceEpoch ~/ 1000;

Map<String, Object?> _item(
  KdbxEntry e,
  String? folder,
  int at,
  List<String> passkeys,
  Set<String> otherTags,
) {
  String? text(String name) => e.getString(KdbxKey(name))?.getText();
  final updated = _seconds(e.times.lastModificationTime.get(), at);
  final fields = <Map<String, Object?>>[];
  void add(
    String type,
    String label,
    String value, {
    bool sensitive = false,
    List<Map<String, Object?>>? history,
  }) => fields.add({
    'deleted': 0,
    if (history != null && history.isNotEmpty) 'history': history,
    'label': label,
    'order': fields.length + 1,
    'sensitive': sensitive ? 1 : 0,
    'type': type,
    'uid': fields.length + 10,
    'updated_at': updated,
    'value': value,
    'value_updated_at': updated,
  });

  final type = TomSecretsEntryType.of(text(TomSecretsEntryFields.type.key));
  final isOther =
      text(TomSecretsEntryFields.type.key) == null &&
      e.stringEntries.any(
        (f) =>
            f.key.key.startsWith(TomSecretsEntryFields.importPrefix) &&
            f.key.key.endsWith('.category'),
      );
  final category = isOther
      ? 'misc'
      : switch (type) {
          TomSecretsEntryType.note => 'note',
          _ => 'login',
        };

  if (category != 'note') {
    add('username', 'Username', text('UserName') ?? '');
    final current = text('Password') ?? '';
    final history = <Map<String, Object?>>[];
    final seen = {current};
    for (final h in e.history.reversed) {
      final old = h.getString(KdbxKeyCommon.PASSWORD)?.getText() ?? '';
      if (old.isEmpty || !seen.add(old)) continue;
      history.add({
        'updated_at': _seconds(h.times.lastModificationTime.get(), at),
        'value': old,
      });
    }
    add('password', 'Password', current, sensitive: true, history: history);
    add('url', 'URL', text('URL') ?? '');
    for (
      var i = 1;
      text('${TomSecretsEntryFields.extraUrlPrefix}_$i') != null;
      i++
    ) {
      add('url', 'URL $i', text('${TomSecretsEntryFields.extraUrlPrefix}_$i')!);
    }
  }
  final totp = TomSecretsTotp.fromEntry(e);
  if (totp != null) add('totp', 'TOTP', totp.toUri(), sensitive: true);

  String? section;
  for (final MapEntry(:key, :value) in e.stringEntries) {
    final name = key.key;
    if (const {
          'Title',
          'UserName',
          'Password',
          'URL',
          'Notes',
        }.contains(name) ||
        name.startsWith(TomSecretsEntryFields.extraUrlPrefix) ||
        name.startsWith(TomSecretsEntryFields.reservedPrefix) ||
        _totpFields.contains(name) ||
        tomSecretsIsPasskeyField(name)) {
      continue;
    }
    final v = value?.getText() ?? '';
    if (v.isEmpty) continue;
    final dot = name.indexOf(' · ');
    final fieldSection = dot < 0 ? null : name.substring(0, dot);
    if (fieldSection != section) {
      section = fieldSection;
      add('section', fieldSection ?? '', '');
    }
    add(
      'text',
      dot < 0 ? name : name.substring(dot + 3),
      v,
      sensitive: value is ProtectedValue,
    );
  }

  if (TomSecretsPasskey.fromEntry(e) != null) passkeys.add(e.label ?? '');
  final tags = (e.tags.get() ?? '')
      .split(RegExp('[;,]'))
      .map((t) => t.trim())
      .where((t) => t.isNotEmpty)
      .toSet();
  otherTags.addAll(tags.difference({tomSecretsFavoriteTag, 'archived'}));

  final attachments = [
    for (final (i, b) in e.binaryEntries.indexed)
      {
        'data': base64.encode(b.value.value),
        'kind': 'application/octet-stream',
        'name': b.key.key,
        'order': i + 1,
        'updated_at': updated,
      },
  ];
  final title = e.label ?? '';
  return {
    'archived': tags.contains('archived') ? 1 : 0,
    if (attachments.isNotEmpty) 'attachments': attachments,
    'auto_submit': 1,
    'category': category,
    'createdAt': _seconds(e.times.creationTime.get(), at),
    'favorite': tags.contains(tomSecretsFavoriteTag) ? 1 : 0,
    'fields': fields,
    'folders': [?folder],
    'note': text('Notes') ?? '',
    'subtitle': text('UserName') ?? '',
    'template_type': '$category.default',
    'title': title,
    'trashed': 0,
    'updated_at': updated,
    'uuid': _uuid(e.uuid),
  };
}
