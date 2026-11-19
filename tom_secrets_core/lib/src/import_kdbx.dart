// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The KeePass import (part-password-manager): another KDBX file, opened
/// with its own password or key file, brought into a vault in one of two
/// ways.
///
/// - **As a group** ([tomSecretsImportKdbxAsGroup]): its groups and entries
///   copied into a new group of the vault, each entry with its fields,
///   attachments, tags, expiry, times and history. A file from any KeePass
///   tool works.
/// - **Merged** ([tomSecretsImportKdbxMerged]): entry by entry with the same
///   merge as two machines' edits (part-stores), for a copy of the same
///   vault edited elsewhere (KeePassXC, an old backup); a file of another
///   vault (another root group) is refused, to be imported as a group.
///
/// The recycle bin, the product's own groups (`.tom-secrets`, `tsm.grants`)
/// and the metadata entry stay behind when importing as a group.
library;

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';
import 'metadata.dart';
import 'primary.dart';
import 'vault_merge.dart';

/// What [tomSecretsImportKdbxAsGroup] did.
final class TomSecretsKdbxImportResult {
  const TomSecretsKdbxImportResult._({
    required this.group,
    required this.entries,
    required this.groups,
  });

  /// The new group's path from the root.
  final List<String> group;

  /// How many entries were copied.
  final int entries;

  /// How many groups were made below the new group.
  final int groups;
}

bool _skipped(KdbxFile file, KdbxGroup group) {
  final bin = file.recycleBin;
  final name = group.name.get() ?? '';
  return (bin != null && group.uuid == bin.uuid) ||
      name == tomSecretsProductGroup ||
      name == tomSecretsGrantsGroup ||
      name.startsWith(TomSecretsEntryFields.reservedPrefix);
}

/// Copies [source]'s groups and entries into a new group [name] under the
/// group path [parent] of [target] (made where missing); a name already
/// taken there gets ` (2)`, ` (3)`, … Answers what was copied.
TomSecretsKdbxImportResult tomSecretsImportKdbxAsGroup(
  KdbxFile target,
  KdbxFile source, {
  required String name,
  List<String> parent = const [],
}) {
  var at = target.body.rootGroup;
  for (final part in parent) {
    at =
        at.groups.where((g) => g.name.get() == part).firstOrNull ??
        target.createGroup(parent: at, name: part);
  }
  final base = name.trim().isEmpty ? 'KeePass' : name.trim();
  var unique = base;
  for (var n = 2; at.groups.any((g) => g.name.get() == unique); n++) {
    unique = '$base ($n)';
  }
  final top = target.createGroup(parent: at, name: unique);
  var entries = 0;
  var groups = 0;
  final metadata = tomSecretsMetadataEntry(source);
  void copy(KdbxGroup from, KdbxGroup into) {
    for (final entry in from.entries) {
      if (identical(entry, metadata)) continue;
      tomSecretsCopyEntry(target, into, entry);
      entries++;
    }
    for (final child in from.groups) {
      if (_skipped(source, child)) continue;
      final made = target.createGroup(
        parent: into,
        name: child.name.get() ?? '',
      );
      groups++;
      copy(child, made);
    }
  }

  copy(source.body.rootGroup, top);
  return TomSecretsKdbxImportResult._(
    group: [...parent, unique],
    entries: entries,
    groups: groups,
  );
}

/// Merges [source], a copy of the same vault edited elsewhere, into
/// [target] entry by entry (part-stores, without a common base: what only
/// one side holds is kept, an entry both changed keeps the newer state with
/// the other in its history and a conflict record). Throws
/// `TomMergeRefusedException` for a file of another vault.
TomSecretsMergeResult tomSecretsImportKdbxMerged(
  KdbxFile target,
  KdbxFile source, {
  DateTime? now,
}) => tomSecretsMergeVaults(
  base: null,
  ours: target,
  theirs: source,
  now: now,
  location: 'the imported file',
);
