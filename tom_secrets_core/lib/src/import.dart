// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// What every import shares (part-password-manager): the importers for
/// 1Password and Enpass read their exports into [TomSecretsImportSource];
/// [tomSecretsImport] writes it into a vault the same way for both.
///
/// - **Target group** per source vault ([TomSecretsImportTarget]): a group
///   path in a file — by default `<source>/<vault name>` in the vault given,
///   or a KDBX file of its own.
/// - **Archived items** are left out by default and counted; included, they
///   go into `Archive` inside the target group with the tag `archived`
///   (DP-34).
/// - **Categories**: logins, notes and API credentials become the product's
///   types; every other category goes into a subgroup of the target named
///   after it, with all its fields as custom fields (DP-35).
/// - **Re-import without duplicates**: entries are matched by
///   `tsm.import.<source>.id`; unchanged items are skipped, items changed
///   only in the source are updated (the old values into the entry's
///   history), items changed on both sides are imported as a conflict
///   (`tsm.conflict`), items no longer in the export are listed and never
///   deleted.
/// - **The report** names entries and counts, never values. A dry run
///   ([tomSecretsImport] with `dryRun`) is the preview: it writes nothing.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';
import 'ssh_key.dart';
import 'passkey.dart';
import 'totp.dart';
import 'vault_merge.dart';

/// How an imported item is typed.
enum TomSecretsImportKind {
  /// A login (`tsm.type` `login`).
  login,

  /// A note (`note`).
  note,

  /// An API credential (`api-token`).
  apiToken,

  /// An SSH key: kept as a `note` with the key as an attachment in phase A
  /// (the `ssh-key` type is phase B's, which retypes it).
  sshKey,

  /// Any other category: an entry in the category's subgroup, all its fields
  /// as custom fields (DP-35).
  other,
}

/// A custom field of an imported item.
final class TomSecretsImportField {
  /// The field [name] with [value]; [isProtected] for a concealed value.
  const TomSecretsImportField(
    this.name,
    this.value, {
    this.isProtected = false,
  });

  /// Its name.
  final String name;

  /// Its value.
  final String value;

  /// Whether the vault keeps it protected.
  final bool isProtected;
}

/// An attachment of an imported item.
final class TomSecretsImportAttachment {
  /// The file [name] with its [bytes].
  const TomSecretsImportAttachment(this.name, this.bytes);

  /// The file name.
  final String name;

  /// The content.
  final Uint8List bytes;
}

/// One former password with the time it was replaced.
final class TomSecretsImportOldPassword {
  /// [value], used until [time].
  const TomSecretsImportOldPassword(this.value, this.time);

  /// The old password.
  final String value;

  /// When it was replaced.
  final DateTime time;
}

/// One item of an export, as the importers read it.
final class TomSecretsImportItem {
  /// An item; [sourceId] identifies it across exports (the source's UUID, or
  /// a hash where the format has none) and [version] says which state of it
  /// this is (its updated time, or a hash of its values).
  const TomSecretsImportItem({
    required this.sourceId,
    required this.version,
    required this.title,
    this.kind = TomSecretsImportKind.login,
    this.category,
    this.userName,
    this.password,
    this.urls = const [],
    this.notes,
    this.tags = const [],
    this.favorite = false,
    this.archived = false,
    this.fields = const [],
    this.totp,
    this.attachments = const [],
    this.passwordHistory = const [],
    this.created,
    this.updated,
    this.expires,
    this.folders = const [],
    this.trashed = false,
    this.passkey,
  });

  /// The item's identity across exports.
  final String sourceId;

  /// The item's state (updated time or a content hash).
  final String version;

  /// The title.
  final String title;

  /// How it is typed.
  final TomSecretsImportKind kind;

  /// The category's subgroup name (plural, e.g. `Credit Cards`) for
  /// [TomSecretsImportKind.other], and the category's name otherwise.
  final String? category;

  /// The user name.
  final String? userName;

  /// The password (credential).
  final String? password;

  /// The URLs, the primary one first.
  final List<String> urls;

  /// The notes.
  final String? notes;

  /// The tags.
  final List<String> tags;

  /// Whether it is a favourite.
  final bool favorite;

  /// Whether the source has it archived.
  final bool archived;

  /// Every other field.
  final List<TomSecretsImportField> fields;

  /// The one-time password: an `otpauth://` URI or a bare base32 secret.
  final String? totp;

  /// The attachments and documents.
  final List<TomSecretsImportAttachment> attachments;

  /// The former passwords, any order.
  final List<TomSecretsImportOldPassword> passwordHistory;

  /// When it was created, when known.
  final DateTime? created;

  /// When it was last changed in the source, when known.
  final DateTime? updated;

  /// When it expires, when it does.
  final DateTime? expires;

  /// The folder path inside the target group (the source's nested folders),
  /// empty for the target group itself.
  final List<String> folders;

  /// Whether the source has it in its trash: always left out.
  final bool trashed;

  /// A passkey with its private key, kept in the `KPEX_PASSKEY_*` fields
  /// (DP-120).
  final TomSecretsPasskey? passkey;
}

/// One vault of an export.
final class TomSecretsImportVault {
  /// The vault [id] named [name] with its [items].
  const TomSecretsImportVault({
    required this.id,
    required this.name,
    required this.items,
  });

  /// Its identity in the export.
  final String id;

  /// Its name.
  final String name;

  /// Its items.
  final List<TomSecretsImportItem> items;
}

/// Something of an export that is not imported, named in the report.
final class TomSecretsImportNotice {
  /// [what] of the item [title] (or of the export, without one).
  const TomSecretsImportNotice(this.what, {this.title});

  /// What was not imported.
  final String what;

  /// The item it belongs to, or null.
  final String? title;
}

/// An export as read: its vaults, what its format loses, and what of it is
/// not imported.
final class TomSecretsImportSource {
  /// The export of [source] (`1password`, the import id's name) shown as
  /// [displayName], in [format].
  const TomSecretsImportSource({
    required this.source,
    required this.displayName,
    required this.format,
    required this.vaults,
    this.lost = const [],
    this.notImported = const [],
  });

  /// The source's name in `tsm.import.<source>.id`.
  final String source;

  /// Its display name, the default target group's first segment.
  final String displayName;

  /// The export format (`1pux`, `csv`, ...).
  final String format;

  /// The vaults.
  final List<TomSecretsImportVault> vaults;

  /// What the format loses, for the report.
  final List<String> lost;

  /// What the export holds but is not imported (passkeys, ...).
  final List<TomSecretsImportNotice> notImported;
}

/// Where a source vault goes: [group] (a path of group names) in [file].
final class TomSecretsImportTarget {
  /// The group path [group] in [file].
  const TomSecretsImportTarget(this.file, this.group);

  /// The vault written to.
  final KdbxFile file;

  /// The target group's path from the root.
  final List<String> group;
}

/// What happened to one item.
enum TomSecretsImportOutcome {
  /// New in the vault.
  added,

  /// Changed in the source only: updated, the old values in the history.
  updated,

  /// Unchanged in the source since the last import: skipped.
  unchanged,

  /// Changed on both sides: imported as a conflict.
  conflict,

  /// Left out by choice (archived).
  leftOut,

  /// Not imported (deleted in the vault, a passkey, ...).
  notImported,

  /// In the vault from an earlier import, no longer in the export: kept.
  notInExport,

  /// A passkey kept in the entry, not yet usable (phase C uses it).
  passkeyKept,
}

/// One line of the report: an entry and what happened to it, no values.
final class TomSecretsImportLine {
  /// [outcome] for [title] in the group [group] (null: of the export).
  const TomSecretsImportLine(
    this.outcome,
    this.title, {
    this.group,
    this.reason,
  });

  /// What happened.
  final TomSecretsImportOutcome outcome;

  /// The item's title.
  final String title;

  /// The group path it went to, or is in.
  final String? group;

  /// Why, when it was not imported or left out.
  final String? reason;

  @override
  String toString() =>
      '${outcome.name}: ${group == null ? '' : '$group/'}$title'
      '${reason == null ? '' : ' ($reason)'}';
}

/// An attachment of the import, by size, for the preview.
final class TomSecretsImportAttachmentSize {
  /// [name] of the item [title], [bytes] long.
  const TomSecretsImportAttachmentSize(this.title, this.name, this.bytes);

  /// The item.
  final String title;

  /// The file name.
  final String name;

  /// Its size.
  final int bytes;
}

/// What an import did (or, as a preview, would do).
final class TomSecretsImportReport {
  TomSecretsImportReport._({
    required this.source,
    required this.dryRun,
    required this.lines,
    required this.lost,
    required this.largestAttachments,
  });

  /// The source and format, e.g. `1Password (1pux)`.
  final String source;

  /// Whether nothing was written (the preview).
  final bool dryRun;

  /// One line per item, in export order, then the entries no longer in the
  /// export.
  final List<TomSecretsImportLine> lines;

  /// What the format loses.
  final List<String> lost;

  /// The largest attachments the import writes, largest first (at most 10).
  final List<TomSecretsImportAttachmentSize> largestAttachments;

  /// How many lines have [outcome].
  int count(TomSecretsImportOutcome outcome) =>
      lines.where((l) => l.outcome == outcome).length;

  /// The lines with [outcome].
  List<TomSecretsImportLine> withOutcome(TomSecretsImportOutcome outcome) => [
    for (final l in lines)
      if (l.outcome == outcome) l,
  ];

  /// The commit message of an import into a GitHub vault: "Import from
  /// 1Password: n added, m updated, k conflicts".
  String get summary {
    final name = source.split(' (').first;
    return 'Import from $name: ${count(TomSecretsImportOutcome.added)} added, '
        '${count(TomSecretsImportOutcome.updated)} updated, '
        '${count(TomSecretsImportOutcome.conflict)} conflicts';
  }

  @override
  String toString() => [
    summary,
    for (final o in TomSecretsImportOutcome.values)
      if (count(o) > 0) '  ${o.name}: ${count(o)}',
  ].join('\n');
}

/// The import origin's version field (`tsm.import.<source>.updated`).
KdbxKey tomSecretsImportVersionField(String source) =>
    KdbxKey('${TomSecretsEntryFields.importPrefix}$source.updated');

/// When the import last wrote the entry (`tsm.import.<source>.imported`):
/// an entry modified later was changed in the vault.
KdbxKey tomSecretsImportedAtField(String source) =>
    KdbxKey('${TomSecretsEntryFields.importPrefix}$source.imported');

/// The source category field (`tsm.import.<source>.category`).
KdbxKey tomSecretsImportCategoryField(String source) =>
    KdbxKey('${TomSecretsEntryFields.importPrefix}$source.category');

/// [name] as a group name: empty becomes `(no name)`, and a name the product
/// reserves (an `@` overlay group, a `tsm.` or `.tom-secrets` name) has its
/// first character percent-encoded as part-structure writes it (`%40…`).
String tomSecretsImportGroupName(String name) {
  final trimmed = name.trim();
  if (trimmed.isEmpty) return '(no name)';
  if (trimmed.startsWith('@') ||
      trimmed.startsWith(TomSecretsEntryFields.reservedPrefix) ||
      trimmed.startsWith('.tom-secrets')) {
    final first = utf8
        .encode(trimmed[0])
        .map((b) => '%${b.toRadixString(16).toUpperCase().padLeft(2, '0')}')
        .join();
    return '$first${trimmed.substring(1)}';
  }
  return trimmed;
}

const _standard = {'Title', 'UserName', 'Password', 'URL', 'Notes'};

/// Imports [source] into [file]: each source vault into its target
/// ([targets] by vault id, default `<displayName>/<vault name>` in [file]),
/// archived items only with [includeArchived]. With [dryRun] nothing is
/// written and the report is the preview. [onProgress] is told after each
/// item. Saving (and the commit, named by [TomSecretsImportReport.summary])
/// is the caller's, after the user confirmed.
TomSecretsImportReport tomSecretsImport(
  TomSecretsImportSource source, {
  required KdbxFile file,
  Map<String, TomSecretsImportTarget> targets = const {},
  bool includeArchived = false,
  bool dryRun = false,
  DateTime? now,
  void Function(int done, int total)? onProgress,
}) {
  final at = _seconds((now ?? DateTime.now()).toUtc());
  final idField = TomSecretsEntryFields.importId(source.source);
  final lines = <TomSecretsImportLine>[];
  final sizes = <TomSecretsImportAttachmentSize>[];
  final indexes = <KdbxFile, _Index>{};
  final seen = <String>{};
  final total = source.vaults.fold(0, (n, v) => n + v.items.length);
  var done = 0;

  for (final vault in source.vaults) {
    final target =
        targets[vault.id] ??
        TomSecretsImportTarget(file, [source.displayName, vault.name]);
    final index = indexes.putIfAbsent(
      target.file,
      () => _Index(target.file, idField),
    );
    for (final item in vault.items) {
      seen.add(item.sourceId);
      final path = [
        for (final s in target.group) tomSecretsImportGroupName(s),
        if (item.archived) 'Archive',
        for (final f in item.folders) tomSecretsImportGroupName(f),
        if (item.kind == TomSecretsImportKind.other)
          tomSecretsImportGroupName(item.category ?? 'Other Items'),
      ];
      final groupText = path.join('/');
      void line(TomSecretsImportOutcome o, {String? reason, String? group}) =>
          lines.add(
            TomSecretsImportLine(
              o,
              item.title,
              group: group ?? groupText,
              reason: reason,
            ),
          );

      if (item.trashed) {
        line(TomSecretsImportOutcome.leftOut, reason: 'trashed');
      } else if (item.archived && !includeArchived) {
        line(TomSecretsImportOutcome.leftOut, reason: 'archived');
      } else if (index.binned.contains(item.sourceId)) {
        line(
          TomSecretsImportOutcome.notImported,
          reason: 'deleted in the vault',
        );
      } else {
        final existing = index.live[item.sourceId];
        final writer = _Writer(target.file, source.source, item, at);
        if (existing == null) {
          line(TomSecretsImportOutcome.added);
          for (final a in item.attachments) {
            sizes.add(
              TomSecretsImportAttachmentSize(
                item.title,
                a.name,
                a.bytes.length,
              ),
            );
          }
          if (!dryRun) {
            final group = _groupAt(target.file, path);
            final entry = KdbxEntry.create(target.file, group);
            group.addEntry(entry);
            writer.writeNew(entry);
            index.live[item.sourceId] = entry;
          }
        } else {
          final group = _pathOf(existing);
          final storedVersion = existing
              .getString(tomSecretsImportVersionField(source.source))
              ?.getText();
          final importedAt = DateTime.tryParse(
            existing
                    .getString(tomSecretsImportedAtField(source.source))
                    ?.getText() ??
                '',
          );
          final modified = existing.times.lastModificationTime.get();
          final vaultChanged =
              importedAt == null ||
              modified == null ||
              modified.difference(importedAt).inSeconds.abs() > 1;
          if (storedVersion == item.version) {
            line(TomSecretsImportOutcome.unchanged, group: group);
          } else if (!vaultChanged) {
            line(TomSecretsImportOutcome.updated, group: group);
            if (!dryRun) writer.writeOver(existing);
          } else {
            line(TomSecretsImportOutcome.conflict, group: group);
            if (!dryRun) writer.writeConflict(existing, at);
          }
        }
        if (item.passkey != null) {
          line(
            TomSecretsImportOutcome.passkeyKept,
            reason: 'passkey kept, not yet usable',
          );
        }
      }
      onProgress?.call(++done, total);
    }
  }

  for (final index in indexes.values) {
    for (final MapEntry(key: id, value: entry) in index.live.entries) {
      if (seen.contains(id)) continue;
      lines.add(
        TomSecretsImportLine(
          TomSecretsImportOutcome.notInExport,
          entry.label ?? '',
          group: _pathOf(entry),
        ),
      );
    }
  }
  for (final notice in source.notImported) {
    lines.add(
      TomSecretsImportLine(
        TomSecretsImportOutcome.notImported,
        notice.title ?? '',
        reason: notice.what,
      ),
    );
  }

  sizes.sort((a, b) => b.bytes.compareTo(a.bytes));
  return TomSecretsImportReport._(
    source: '${source.displayName} (${source.format})',
    dryRun: dryRun,
    lines: lines,
    lost: source.lost,
    largestAttachments: sizes.take(10).toList(),
  );
}

DateTime _seconds(DateTime t) => DateTime.fromMillisecondsSinceEpoch(
  t.millisecondsSinceEpoch ~/ 1000 * 1000,
  isUtc: true,
);

/// The entries of a file carrying an import id, live and in the recycle bin.
final class _Index {
  _Index(KdbxFile file, KdbxKey idField) {
    final bin = file.recycleBin;
    for (final e in file.body.rootGroup.getAllEntries()) {
      final id = e.getString(idField)?.getText();
      if (id == null || id.isEmpty) continue;
      if (bin != null && _inGroup(e, bin)) {
        binned.add(id);
      } else {
        live[id] = e;
      }
    }
  }

  final Map<String, KdbxEntry> live = {};
  final Set<String> binned = {};

  static bool _inGroup(KdbxEntry e, KdbxGroup group) {
    for (KdbxGroup? g = e.parent; g != null; g = g.parent) {
      if (g.uuid == group.uuid) return true;
    }
    return false;
  }
}

/// The group at [path] below the root, made where missing.
KdbxGroup _groupAt(KdbxFile file, List<String> path) {
  var group = file.body.rootGroup;
  for (final name in path) {
    group =
        group.groups.where((g) => g.name.get() == name).firstOrNull ??
        file.createGroup(parent: group, name: name);
  }
  return group;
}

/// The group path of [entry] below the root.
String _pathOf(KdbxEntry entry) {
  final names = <String>[];
  for (var g = entry.parent; g != null && g.parent != null; g = g.parent) {
    names.insert(0, g.name.get() ?? '');
  }
  return names.join('/');
}

/// Writes one item into entries.
final class _Writer {
  _Writer(this.file, this.source, this.item, this.now);

  final KdbxFile file;
  final String source;
  final TomSecretsImportItem item;
  final DateTime now;

  DateTime get _modified => _seconds((item.updated ?? now).toUtc());

  /// The string fields of the item, by name.
  Map<String, StringValue> _strings() {
    final out = <String, StringValue>{};
    void put(String name, String? value, {bool protected = false}) {
      if (value == null || value.isEmpty) return;
      var key = name;
      for (var n = 2; out.containsKey(key); n++) {
        key = '$name ($n)';
      }
      out[key] = protected
          ? ProtectedValue.fromString(value)
          : PlainValue(value);
    }

    put('Title', item.title);
    put('UserName', item.userName);
    put('Password', item.password, protected: true);
    if (item.urls.isNotEmpty) put('URL', item.urls.first);
    put('Notes', item.notes);
    for (var i = 1; i < item.urls.length; i++) {
      put('${TomSecretsEntryFields.extraUrlPrefix}_$i', item.urls[i]);
    }
    for (final f in item.fields) {
      final name =
          _standard.contains(f.name) ||
              tomSecretsIsReservedName(f.name) ||
              tomSecretsIsPasskeyField(f.name)
          ? '${f.name} (${item.category ?? 'imported'})'
          : f.name;
      put(name, f.value, protected: f.isProtected);
    }
    put(TomSecretsEntryFields.type.key, switch (item.kind) {
      TomSecretsImportKind.login => TomSecretsEntryType.login.wireName,
      TomSecretsImportKind.apiToken => TomSecretsEntryType.apiToken.wireName,
      TomSecretsImportKind.note => TomSecretsEntryType.note.wireName,
      // An SSH key whose key the export carries is typed (phase B, DP-5);
      // without one it stays a note.
      TomSecretsImportKind.sshKey =>
        item.attachments.any((a) => TomSecretsSshKeyInfo.parse(a.bytes) != null)
            ? TomSecretsEntryType.sshKey.wireName
            : TomSecretsEntryType.note.wireName,
      TomSecretsImportKind.other => null,
    });
    put(TomSecretsEntryFields.importId(source).key, item.sourceId);
    put(tomSecretsImportVersionField(source).key, item.version);
    put(tomSecretsImportedAtField(source).key, _modified.toIso8601String());
    put(tomSecretsImportCategoryField(source).key, item.category);
    final passkey = item.passkey;
    if (passkey != null) {
      for (final MapEntry(:key, :value) in passkey.fields.entries) {
        out[key.key] = value;
      }
    }
    return out;
  }

  TomSecretsTotp? _totp() {
    final text = item.totp?.trim();
    if (text == null || text.isEmpty) return null;
    final uri = TomSecretsTotp.tryParseUri(text);
    if (uri != null) return uri;
    final secret = tomSecretsBase32Decode(text.replaceAll(' ', ''));
    if (secret == null || secret.isEmpty) return null;
    return TomSecretsTotp(secret, issuer: item.title);
  }

  String? _tags() {
    final tags = [
      ...item.tags,
      if (item.favorite) tomSecretsFavoriteTag,
      if (item.archived) 'archived',
    ];
    return tags.isEmpty ? null : tags.toSet().join(';');
  }

  /// Writes every value of the item into [entry], replacing what is there.
  void _fill(KdbxEntry entry) {
    final strings = _strings();
    final totp = _totp();
    entry.modify(() {
      for (final MapEntry(:key, :value) in strings.entries) {
        entry.setString(KdbxKey(key), value);
      }
      totp?.writeTo(entry);
      final keep = {
        ...strings.keys,
        if (totp != null) ...[
          TomSecretsTotpFields.otp.key,
          TomSecretsTotpFields.otpAuth.key,
          TomSecretsTotpFields.secretBase32.key,
          TomSecretsTotpFields.length.key,
          TomSecretsTotpFields.period.key,
          TomSecretsTotpFields.algorithm.key,
        ],
      };
      for (final MapEntry(:key) in entry.stringEntries.toList()) {
        if (!keep.contains(key.key)) entry.removeString(key);
      }
      for (final MapEntry(:key) in entry.binaryEntries.toList()) {
        entry.removeBinary(key);
      }
      for (final a in item.attachments) {
        entry.createBinary(isProtected: true, name: a.name, bytes: a.bytes);
      }
      if (item.kind == TomSecretsImportKind.sshKey) {
        // The key as KeePassXC's SSH agent finds it.
        final key = tomSecretsSshKeyOf(entry);
        if (key != null) {
          entry.createBinary(
            isProtected: false,
            name: tomSecretsKeeAgentSettingsName,
            bytes: TomSecretsKeeAgentSettings(
              attachmentName: key.name,
            ).toBytes(),
          );
        }
      }
      entry.tags.set(_tags());
      final expires = item.expires;
      entry.times.expires.set(expires != null);
      entry.times.expiryTime.set(expires?.toUtc());
    });
    entry.times.lastModificationTime.set(_modified);
  }

  /// A new entry: the item, its password history as history versions, its
  /// times.
  void writeNew(KdbxEntry entry) {
    _fill(entry);
    final history = [...item.passwordHistory]
      ..sort((a, b) => a.time.compareTo(b.time));
    for (final old in history) {
      final version = KdbxEntry.create(
        file,
        entry.parent!,
        isHistoryEntry: true,
      );
      for (final key in [
        KdbxKeyCommon.TITLE,
        KdbxKeyCommon.USER_NAME,
        KdbxKeyCommon.URL,
      ]) {
        final value = entry.getString(key);
        if (value != null) version.setString(key, value);
      }
      version.setString(
        KdbxKeyCommon.PASSWORD,
        ProtectedValue.fromString(old.value),
      );
      version.times.lastModificationTime.set(_seconds(old.time.toUtc()));
      entry.history.add(version);
    }
    entry.times.creationTime.set(_seconds((item.created ?? now).toUtc()));
    entry.times.lastModificationTime.set(_modified);
  }

  /// An entry changed only in the source: the old values go to the history
  /// (the first change of an entry read from the file pushes them), the
  /// item's values replace them.
  void writeOver(KdbxEntry entry) => _fill(entry);

  /// Changed on both sides: the newer side's values stay current, the other
  /// side's go to the history, and a conflict record names the fields.
  void writeConflict(KdbxEntry entry, DateTime at) {
    final vaultModified =
        entry.times.lastModificationTime.get() ?? DateTime.utc(1970);
    final before = {
      for (final MapEntry(:key, :value) in entry.stringEntries)
        key.key: value?.getText() ?? '',
    };
    final itemIsNewer = _modified.isAfter(vaultModified);
    DateTime loserModified;
    if (itemIsNewer) {
      _fill(entry);
      loserModified = vaultModified;
    } else {
      final version = KdbxEntry.create(
        file,
        entry.parent!,
        isHistoryEntry: true,
      );
      _fill(version);
      entry.history.add(version);
      loserModified = _modified;
      // The vault's values stay current; the import's state is recorded, so
      // the same export is no change the next time.
      entry.setString(
        tomSecretsImportVersionField(source),
        PlainValue(item.version),
      );
      entry.times.lastModificationTime.set(vaultModified);
    }
    final incoming = {
      for (final MapEntry(:key, :value) in _strings().entries)
        key: value.getText() ?? '',
    };
    final fields = <String>{
      for (final k in {...before.keys, ...incoming.keys})
        if (!k.startsWith(TomSecretsEntryFields.importPrefix) &&
            before[k] != incoming[k])
          'field:$k',
    }.toList()..sort();
    final records = [
      ...tomSecretsConflictsOf(entry),
      TomSecretsEntryConflict(
        entryUuid: entry.uuid.uuid,
        fields: fields,
        loserModified: loserModified,
        at: at,
      ),
    ];
    entry.customData[tomSecretsConflictKey] = jsonEncode([
      for (final r in records) r.toJson(),
    ]);
    final modified = entry.times.lastModificationTime.get() ?? at;
    entry.setString(
      tomSecretsImportedAtField(source),
      PlainValue(_seconds(modified.toUtc()).toIso8601String()),
    );
    entry.times.lastModificationTime.set(modified);
  }
}
