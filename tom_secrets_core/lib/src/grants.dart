// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The grants group of the primary vault (part-structure, DP-19):
/// `tsm.grants/<host>`, one entry per signed object (a grant, a revocation,
/// an approval record, a key-change statement), its members as string
/// fields and its signature list as JSON, so the desktop app shows and
/// revokes the grants of every host. References never resolve into it.
library;

import 'dart:convert';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';
import 'signed_objects.dart';

/// The kind of a signed object in the grants group.
enum TomSecretsSignedKind {
  /// A grant (7.3).
  grant('grant', TomSecretsSignedLabels.grant),

  /// A revocation.
  revocation('revocation', TomSecretsSignedLabels.revoke),

  /// An approval record (an answer to a waiting code).
  approval('approval', TomSecretsSignedLabels.approval),

  /// A key-change statement.
  keyChange('keychange', TomSecretsSignedLabels.keyChange);

  const TomSecretsSignedKind(this.wireName, this.label);

  /// The `tsm.kind` field's value.
  final String wireName;

  /// The signed object's domain label.
  final String label;

  /// The members besides the signed ones that the entry keeps.
  static const extraFields = ['lastUsed'];
}

/// The field naming an entry's kind.
const String _kindField = 'tsm.kind';

const String _signaturesField = 'signatures';

/// The grants group of a primary vault [file].
final class TomSecretsGrantsGroup {
  /// The group of [file].
  TomSecretsGrantsGroup(this.file);

  /// The primary vault.
  final KdbxFile file;

  KdbxGroup? _group(String host, {bool create = false}) {
    final root = file.body.rootGroup;
    var grants = root.groups
        .where((g) => g.name.get() == tomSecretsGrantsGroup)
        .firstOrNull;
    if (grants == null) {
      if (!create) return null;
      grants = file.createGroup(parent: root, name: tomSecretsGrantsGroup);
    }
    var hostGroup = grants.groups
        .where((g) => g.name.get() == host)
        .firstOrNull;
    if (hostGroup == null && create) {
      hostGroup = file.createGroup(parent: grants, name: host);
    }
    return hostGroup;
  }

  /// The hosts that have a subgroup.
  List<String> get hosts {
    final grants = file.body.rootGroup.groups
        .where((g) => g.name.get() == tomSecretsGrantsGroup)
        .firstOrNull;
    return [
      for (final g in grants?.groups ?? const <KdbxGroup>[]) g.name.get() ?? '',
    ];
  }

  static String _titleOf(TomSecretsSignedKind kind, Map<String, Object?> o) =>
      switch (kind) {
        TomSecretsSignedKind.grant => o['id']! as String,
        TomSecretsSignedKind.revocation => 'revoke ${o['grantId']}',
        TomSecretsSignedKind.approval => 'approval ${o['code']}',
        TomSecretsSignedKind.keyChange => 'keychange ${o['newKeyId']}',
      };

  /// The objects of [kind] in [host]'s subgroup, as stored (signatures not
  /// yet checked: the reader accepts them against its recorded keys).
  List<Map<String, Object?>> read(String host, TomSecretsSignedKind kind) {
    final group = _group(host);
    if (group == null) return const [];
    final out = <Map<String, Object?>>[];
    for (final entry in group.entries) {
      if (entry.getString(const KdbxKey(_kindField))?.getText() !=
          kind.wireName) {
        continue;
      }
      String? text(String name) => entry.getString(KdbxKey(name))?.getText();
      final object = <String, Object?>{};
      for (final name in [
        ...tomSecretsSignedFields[kind.label]!,
        ...TomSecretsSignedKind.extraFields,
      ]) {
        final value = text(name);
        if (value == null) continue;
        object[name] = name == 'pin' && value.startsWith('{')
            ? jsonDecode(value)
            : value;
      }
      try {
        object[_signaturesField] = jsonDecode(text(_signaturesField) ?? '[]');
      } on FormatException {
        object[_signaturesField] = const [];
      }
      out.add(object);
    }
    return out;
  }

  /// Writes [object] (of [kind], signed) into [host]'s subgroup, replacing
  /// an entry for the same object.
  void write(
    String host,
    TomSecretsSignedKind kind,
    Map<String, Object?> object,
  ) {
    final group = _group(host, create: true)!;
    final title = _titleOf(kind, object);
    var entry = group.entries
        .where(
          (e) =>
              e.label == title &&
              e.getString(const KdbxKey(_kindField))?.getText() ==
                  kind.wireName,
        )
        .firstOrNull;
    if (entry == null) {
      entry = KdbxEntry.create(file, group);
      group.addEntry(entry);
    }
    entry
      ..setString(KdbxKeyCommon.TITLE, PlainValue(title))
      ..setString(const KdbxKey(_kindField), PlainValue(kind.wireName));
    for (final name in [
      ...tomSecretsSignedFields[kind.label]!,
      ...TomSecretsSignedKind.extraFields,
    ]) {
      final value = object[name];
      if (value == null) continue;
      entry.setString(
        KdbxKey(name),
        PlainValue(value is String ? value : jsonEncode(value)),
      );
    }
    entry.setString(
      const KdbxKey(_signaturesField),
      PlainValue(jsonEncode(object[_signaturesField] ?? const [])),
    );
  }

  /// Sets the unsigned `lastUsed` of the grant [grantId] in [host]'s
  /// subgroup (protocol.md 7.3); whether the grant was there.
  bool setLastUsed(String host, String grantId, DateTime time) {
    final entry = _group(host)?.entries
        .where(
          (e) =>
              e.label == grantId &&
              e.getString(const KdbxKey(_kindField))?.getText() ==
                  TomSecretsSignedKind.grant.wireName,
        )
        .firstOrNull;
    if (entry == null) return false;
    entry.setString(
      const KdbxKey('lastUsed'),
      PlainValue(time.toUtc().toIso8601String()),
    );
    return true;
  }

  /// Removes [kind]'s entry of [title] (as [read] names it) from [host]'s
  /// subgroup; whether one was there.
  bool remove(String host, TomSecretsSignedKind kind, Map<String, Object?> o) {
    final group = _group(host);
    if (group == null) return false;
    final title = _titleOf(kind, o);
    final entry = group.entries
        .where(
          (e) =>
              e.label == title &&
              e.getString(const KdbxKey(_kindField))?.getText() ==
                  kind.wireName,
        )
        .firstOrNull;
    if (entry == null) return false;
    // Deleted for good and recorded as deleted, so a merge does not bring
    // the entry back.
    file.deletePermanently(entry);
    return true;
  }
}
