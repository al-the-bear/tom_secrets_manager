// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The exports of a vault (part-password-manager, DP-40), besides Enpass's
/// JSON (`export_enpass.dart`):
///
/// - **KDBX** ([tomSecretsExportKdbx]): a copy of the vault, or one of its
///   groups, as a KDBX file of its own under a new password (and key file),
///   for KeePass and every tool that reads KDBX; the only export that is
///   encrypted.
/// - **CSV** ([tomSecretsExportCsv]): one row per entry, for other tools:
///   `Title`, `URL`, `Username`, `Password`, `Notes`, `OTPAuth`, `Group`,
///   `Tags`.
/// - **Bitwarden JSON** ([tomSecretsExportBitwardenJson]): Bitwarden's own
///   unencrypted JSON export, so a move to Bitwarden keeps the folders, the
///   item types (logins, secure notes, cards, identities, SSH keys) and the
///   custom fields.
///
/// Every export leaves out the recycle bin, the product's own groups
/// (`.tom-secrets`, `tsm.grants`), the metadata entry and the `tsm.*`
/// fields. CSV and Bitwarden JSON hold every password in plaintext: the app
/// says so before writing one. Each export names what it does not carry
/// ([TomSecretsExport.lost]).
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'import_bitwarden.dart'
    show
        tomSecretsBitwardenCardFields,
        tomSecretsBitwardenIdentityFields,
        tomSecretsCardsCategory,
        tomSecretsIdentitiesCategory;
import 'mapping.dart';
import 'metadata.dart';
import 'new_vault.dart';
import 'primary.dart';
import 'ssh_key.dart';
import 'totp.dart';
import 'vault_merge.dart';

/// A plaintext export and what it left behind.
final class TomSecretsExport {
  const TomSecretsExport._({
    required this.text,
    required this.items,
    required this.lost,
  });

  /// The file's text.
  final String text;

  /// How many entries it holds.
  final int items;

  /// What it does not carry.
  final List<String> lost;
}

/// The entries an export writes: [group] of [file] (default the whole
/// vault) without the recycle bin, the product's groups and the metadata
/// entry, each with its group path below [group].
List<(KdbxEntry, List<String>)> tomSecretsExportEntries(
  KdbxFile file, {
  KdbxGroup? group,
}) {
  final bin = file.recycleBin;
  final metadata = tomSecretsMetadataEntry(file);
  final out = <(KdbxEntry, List<String>)>[];
  void walk(KdbxGroup g, List<String> path) {
    for (final e in g.entries) {
      if (!identical(e, metadata)) out.add((e, path));
    }
    for (final child in g.groups) {
      final name = child.name.get() ?? '';
      if ((bin != null && child.uuid == bin.uuid) ||
          name == tomSecretsProductGroup ||
          name == tomSecretsGrantsGroup ||
          name.startsWith(TomSecretsEntryFields.reservedPrefix)) {
        continue;
      }
      walk(child, [...path, name]);
    }
  }

  walk(group ?? file.body.rootGroup, const []);
  return out;
}

/// Whether [name] is a field an export writes as a custom field: not a
/// standard KDBX field, not a product (`tsm.*`) field, not a TOTP or
/// passkey field.
bool _custom(String name) =>
    !const {
      'Title',
      'UserName',
      'Password',
      'URL',
      'Notes',
      'otp',
      'OTPAuth',
      'TimeOtp-Secret-Base32',
      'TimeOtp-Length',
      'TimeOtp-Period',
      'TimeOtp-Algorithm',
    }.contains(name) &&
    !tomSecretsIsReservedName(name) &&
    !tomSecretsIsPasskeyField(name);

String? _text(KdbxEntry e, String name) {
  final v = e.getString(KdbxKey(name))?.getText();
  return v == null || v.isEmpty ? null : v;
}

List<String> _tags(KdbxEntry e) => [
  for (final t in (e.tags.get() ?? '').split(RegExp('[;,]')))
    if (t.trim().isNotEmpty) t.trim(),
];

TomSecretsEntryType _type(KdbxEntry e) =>
    TomSecretsEntryType.of(_text(e, TomSecretsEntryFields.type.key));

/// The CSV columns of [tomSecretsExportCsv].
const List<String> tomSecretsCsvExportColumns = [
  'Title',
  'URL',
  'Username',
  'Password',
  'Notes',
  'OTPAuth',
  'Group',
  'Tags',
];

/// Writes [group] (default the whole vault [file]) as CSV: a header, then
/// one row per entry ([tomSecretsCsvExportColumns]; `Group` the group path
/// with `/`, `Tags` joined with `;`), RFC 4180 quoting, CRLF line ends.
TomSecretsExport tomSecretsExportCsv(KdbxFile file, {KdbxGroup? group}) {
  final entries = tomSecretsExportEntries(file, group: group);
  final rows = <List<String>>[tomSecretsCsvExportColumns];
  var custom = 0;
  var attachments = 0;
  for (final (e, path) in entries) {
    if (e.stringEntries.any((f) => _custom(f.key.key))) custom++;
    if (e.binaryEntries.isNotEmpty) attachments++;
    rows.add([
      e.label ?? '',
      _text(e, 'URL') ?? '',
      _text(e, 'UserName') ?? '',
      _text(e, 'Password') ?? '',
      _text(e, 'Notes') ?? '',
      TomSecretsTotp.fromEntry(e)?.toUri() ?? '',
      path.join('/'),
      _tags(e).join(';'),
    ]);
  }
  String quote(String field) => field.contains(RegExp('[",\r\n]'))
      ? '"${field.replaceAll('"', '""')}"'
      : field;
  return TomSecretsExport._(
    text: '${rows.map((r) => r.map(quote).join(',')).join('\r\n')}\r\n',
    items: entries.length,
    lost: [
      'entry history',
      'expiry dates and entry types',
      if (custom > 0) 'custom fields ($custom entries)',
      if (attachments > 0) 'attachments ($attachments entries)',
      'passkeys',
    ],
  );
}

/// Writes [group] (default the whole vault [file]) as Bitwarden's
/// unencrypted JSON export: groups become folders (`A/B` names), entries
/// items — logins (`login`, API tokens included), secure notes, SSH keys
/// (`sshKey`, the private key from the entry's key attachment), and cards
/// and identities where an import put them (`Credit Cards`, `Identities`,
/// their fields by name); every other field a custom field (protected ones
/// hidden, type 1), the former passwords as `passwordHistory`, the
/// `favorite` tag as favourite. [random] makes the folder ids (tests pass a
/// seeded one).
TomSecretsExport tomSecretsExportBitwardenJson(
  KdbxFile file, {
  KdbxGroup? group,
  DateTime? now,
  Random? random,
}) {
  final at = (now ?? DateTime.now()).toUtc().toIso8601String();
  final rng = random ?? Random.secure();
  final entries = tomSecretsExportEntries(file, group: group);
  final folders = <String, String>{};
  String folderId(List<String> path) {
    final name = path.join('/');
    return folders.putIfAbsent(name, () => _uuid(rng));
  }

  final items = <Map<String, Object?>>[];
  final tagged = <String>{};
  var attachments = 0;
  var expiring = 0;
  final passkeys = <String>[];
  for (final (e, path) in entries) {
    for (final t in _tags(e)) {
      if (t != tomSecretsFavoriteTag) tagged.add(t);
    }
    if (e.times.expires.get() == true) expiring++;
    final type = _type(e);
    final category = [
      for (final f in e.stringEntries)
        if (f.key.key.startsWith(TomSecretsEntryFields.importPrefix) &&
            f.key.key.endsWith('.category'))
          f.value?.getText(),
    ].firstOrNull;
    final used = <String>{};
    Map<String, Object?>? section(List<(String, String, bool)> layout) {
      final out = <String, Object?>{};
      for (final (key, label, _) in layout) {
        for (final f in e.stringEntries) {
          if (f.key.key.toLowerCase() == label.toLowerCase()) {
            out[key] = f.value?.getText();
            used.add(f.key.key);
          }
        }
      }
      return out;
    }

    final item = <String, Object?>{
      'id': _hexUuid(e.uuid),
      'organizationId': null,
      'folderId': path.isEmpty ? null : folderId(path),
      'name': e.label ?? '',
      'notes': _text(e, 'Notes'),
      'favorite': _tags(e).contains(tomSecretsFavoriteTag),
      'reprompt': 0,
      'creationDate':
          e.times.creationTime.get()?.toUtc().toIso8601String() ?? at,
      'revisionDate':
          e.times.lastModificationTime.get()?.toUtc().toIso8601String() ?? at,
      'deletedDate': null,
      'collectionIds': null,
    };
    if (category == tomSecretsCardsCategory) {
      item['type'] = 3;
      item['card'] = section(tomSecretsBitwardenCardFields);
    } else if (category == tomSecretsIdentitiesCategory) {
      item['type'] = 4;
      item['identity'] = section(tomSecretsBitwardenIdentityFields);
    } else if (type == TomSecretsEntryType.sshKey) {
      final key = tomSecretsSshKeyOf(e);
      item['type'] = 5;
      item['sshKey'] = {
        'privateKey': key == null ? null : utf8.decode(key.bytes),
        'publicKey': key?.info.publicKey,
        'keyFingerprint': key?.info.fingerprint,
      };
      if (key != null) used.add('attachment:${key.name}');
    } else if (type == TomSecretsEntryType.note) {
      item['type'] = 2;
      item['secureNote'] = {'type': 0};
    } else {
      item['type'] = 1;
      final urls = [
        ?_text(e, 'URL'),
        for (final f in e.stringEntries)
          if (f.key.key.startsWith(TomSecretsEntryFields.extraUrlPrefix))
            ?f.value?.getText(),
      ];
      final current = _text(e, 'Password');
      final history = <Map<String, Object?>>[];
      final seen = {?current};
      for (final h in e.history.reversed) {
        final old = _text(h, 'Password');
        if (old == null || !seen.add(old)) continue;
        history.add({
          'lastUsedDate':
              h.times.lastModificationTime.get()?.toUtc().toIso8601String() ??
              at,
          'password': old,
        });
      }
      item['passwordHistory'] = history.isEmpty ? null : history;
      item['login'] = {
        'fido2Credentials': const <Object?>[],
        'uris': [
          for (final u in urls) {'match': null, 'uri': u},
        ],
        'username': _text(e, 'UserName'),
        'password': current,
        'totp': TomSecretsTotp.fromEntry(e)?.toUri(),
      };
    }
    if (e.stringEntries.any((f) => tomSecretsIsPasskeyField(f.key.key))) {
      passkeys.add(e.label ?? '');
    }
    final skippedAttachment = e.binaryEntries.any(
      (b) =>
          b.key.key != tomSecretsKeeAgentSettingsName &&
          !used.contains('attachment:${b.key.key}'),
    );
    if (skippedAttachment) attachments++;
    item['fields'] = [
      for (final f in e.stringEntries)
        if (_custom(f.key.key) &&
            !used.contains(f.key.key) &&
            !f.key.key.startsWith(TomSecretsEntryFields.extraUrlPrefix))
          {
            'name': f.key.key,
            'value': f.value?.getText() ?? '',
            'type': f.value is ProtectedValue ? 1 : 0,
            'linkedId': null,
          },
    ];
    items.add(item);
  }
  return TomSecretsExport._(
    text: const JsonEncoder.withIndent('  ').convert({
      'encrypted': false,
      'folders': [
        for (final MapEntry(key: name, value: id) in folders.entries)
          {'id': id, 'name': name},
      ],
      'items': items,
    }),
    items: entries.length,
    lost: [
      'entry history other than former passwords',
      if (tagged.isNotEmpty) 'tags other than favorite: ${tagged.join(', ')}',
      if (expiring > 0) 'expiry dates ($expiring entries)',
      if (attachments > 0)
        'attachments ($attachments entries; Bitwarden\'s JSON has none)',
      if (passkeys.isNotEmpty) 'passkeys of: ${passkeys.join(', ')}',
      'overlay bindings (the @ groups are written as plain folders)',
    ],
  );
}

/// Writes [group] (default the whole vault [file]) as a KDBX file of its
/// own under [credentials]: a new vault named [name] holding copies of its
/// groups and entries (with their history and attachments), without the
/// product's groups, the metadata entry and the recycle bin. [argon2] is
/// its key derivation (default the product's).
Future<Uint8List> tomSecretsExportKdbx(
  KdbxFile file,
  Credentials credentials, {
  required String name,
  KdbxGroup? group,
  KdbxArgon2 argon2 = tomSecretsDefaultArgon2,
}) async {
  final copy = tomSecretsNewVault(credentials, name, argon2: argon2);
  final bin = file.recycleBin;
  final metadata = tomSecretsMetadataEntry(file);
  void walk(KdbxGroup from, KdbxGroup into) {
    for (final e in from.entries) {
      if (!identical(e, metadata)) tomSecretsCopyEntry(copy, into, e);
    }
    for (final child in from.groups) {
      final childName = child.name.get() ?? '';
      if ((bin != null && child.uuid == bin.uuid) ||
          childName == tomSecretsProductGroup ||
          childName == tomSecretsGrantsGroup ||
          childName.startsWith(TomSecretsEntryFields.reservedPrefix)) {
        continue;
      }
      walk(child, copy.createGroup(parent: into, name: childName));
    }
  }

  walk(group ?? file.body.rootGroup, copy.body.rootGroup);
  return copy.save();
}

String _hexUuid(KdbxUuid uuid) {
  final hex = tomSecretsUuidHex(uuid);
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

String _uuid(Random rng) {
  final b = List.generate(16, (_) => rng.nextInt(256));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  final hex = b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}
