// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The three-way merge of two copies of a vault against their base
/// (part-stores, DP-7): entries and groups are records keyed by UUID, merged
/// through `tom_core_sync`'s `tomMergeKeyed`; within an entry a field only one
/// side changed takes that side; a real conflict keeps the newer value, the
/// losing version in the entry's history and a conflict record in the entry's
/// custom data `tsm.conflict`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:tom_core_sync/tom_core_sync.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

/// The custom-data key of an entry's open conflicts.
const String tomSecretsConflictKey = 'tsm.conflict';

/// The database custom-data key of the product's format version.
const String tomSecretsFormatKey = 'tsm.format';

/// The product format version this library writes (`major.minor`).
const String tomSecretsFormatVersion = '1.0';

const String _recycleBin = 'recycle-bin';

/// One open conflict of an entry: both sides changed [fields] differently;
/// the merged entry holds the newer values, and the loser is the entry's
/// history version whose modification time is [loserModified].
final class TomSecretsEntryConflict {
  /// A conflict record.
  const TomSecretsEntryConflict({
    required this.entryUuid,
    required this.fields,
    required this.loserModified,
    required this.at,
  });

  /// From the JSON kept in `tsm.conflict`.
  factory TomSecretsEntryConflict.fromJson(Map<String, Object?> json) =>
      TomSecretsEntryConflict(
        entryUuid: json['entry']! as String,
        fields: (json['fields']! as List).cast<String>(),
        loserModified: DateTime.parse(json['loser']! as String),
        at: DateTime.parse(json['at']! as String),
      );

  /// The entry's UUID (KDBX base64 form).
  final String entryUuid;

  /// The attributes both sides changed (`field:Password`, `tags`, ...).
  final List<String> fields;

  /// The modification time of the losing version, kept in the history.
  final DateTime loserModified;

  /// When the merge met the conflict.
  final DateTime at;

  /// The JSON kept in `tsm.conflict`.
  Map<String, Object?> toJson() => {
    'entry': entryUuid,
    'fields': fields,
    'loser': loserModified.toUtc().toIso8601String(),
    'at': at.toUtc().toIso8601String(),
  };

  /// The `TomConflictRecord` of `tom_core_sync`: the entry's key and the
  /// locator of the retained loser (its modification time).
  TomConflictRecord<String> get record => TomConflictRecord<String>(
    key: entryUuid,
    retained: loserModified.toUtc().toIso8601String(),
  );
}

/// The open conflicts recorded on [entry].
List<TomSecretsEntryConflict> tomSecretsConflictsOf(KdbxEntry entry) {
  final text = entry.customData[tomSecretsConflictKey];
  if (text == null || text.isEmpty) return const [];
  return [
    for (final item in jsonDecode(text) as List)
      TomSecretsEntryConflict.fromJson((item as Map).cast<String, Object?>()),
  ];
}

/// Settles [entry]'s conflicts: the record goes; the history keeps the loser.
void tomSecretsSettleConflicts(KdbxEntry entry) =>
    entry.customData.remove(tomSecretsConflictKey);

/// What a merge did.
final class TomSecretsMergeResult {
  TomSecretsMergeResult._(
    this.conflicts,
    this.editsAgainstDeletion,
    this.keptGroups,
  );

  /// The real conflicts it met, one per entry (also recorded in the vault).
  final List<TomSecretsEntryConflict> conflicts;

  /// Entries one side deleted and the other edited: the edit stands.
  final List<String> editsAgainstDeletion;

  /// Groups one side deleted that still hold something after the merge, and
  /// were kept.
  final List<String> keptGroups;

  /// Whether the merge met nothing to report.
  bool get isClean =>
      conflicts.isEmpty && editsAgainstDeletion.isEmpty && keptGroups.isEmpty;
}

/// Merges [theirs] into [ours] against their common [base] (null: an empty
/// base, the force-pushed case, where everything present counts as added).
/// [ours] becomes the merged copy; [base] and [theirs] are only read.
///
/// Refuses copies of different product format major versions, or of
/// different vaults (different root groups), with a
/// `TomMergeRefusedException` before anything changes.
TomSecretsMergeResult tomSecretsMergeVaults({
  required KdbxFile? base,
  required KdbxFile ours,
  required KdbxFile theirs,
  DateTime? now,
  String? location,
}) {
  final at = (now ?? DateTime.now()).toUtc();
  if (ours.body.rootGroup.uuid != theirs.body.rootGroup.uuid) {
    throw TomMergeRefusedException(
      'their root groups differ, so they are not copies of one vault.',
      location: location,
    );
  }
  final b = base == null ? _Snapshot.empty() : _Snapshot.of(base);
  final o = _Snapshot.of(ours);
  final t = _Snapshot.of(theirs);

  // Meta custom data, three-way per key; it carries the format version.
  final metaMerge = tomMergeKeyed<_Attr>(
    base: b.meta,
    ours: o.meta,
    theirs: t.meta,
    codec: const _AttrCodec(),
    formatVersions: (
      ours: o.meta[tomSecretsFormatKey]?.value ?? tomSecretsFormatVersion,
      theirs: t.meta[tomSecretsFormatKey]?.value ?? tomSecretsFormatVersion,
    ),
    location: location,
  );

  final groupMerge = tomMergeKeyed<_GroupRecord>(
    base: b.groups,
    ours: o.groups,
    theirs: t.groups,
    codec: const _GroupCodec(),
  );

  final entryMerge = tomMergeKeyed<_EntryRecord>(
    base: b.entries,
    ours: o.entries,
    theirs: t.entries,
    codec: const _EntryCodec(),
    deleteEdit: TomDeleteEditPolicy.keepEditAndReport,
  );

  final merged = Map.of(entryMerge.merged);
  final conflicts = <TomSecretsEntryConflict>[];
  final losers = <String, _EntryRecord>{};
  final editsAgainstDeletion = <String>[];
  for (final c in entryMerge.conflicts) {
    final our = c.ours;
    final their = c.theirs;
    if (our == null || their == null) {
      editsAgainstDeletion.add(c.key);
      continue;
    }
    // Both edited the entry: merge it attribute by attribute (DP-7).
    final ancestor = c.base?.attrs ?? const <String, _Attr>{};
    final attrMerge = tomMergeKeyed<_Attr>(
      base: ancestor,
      ours: _stamped(our),
      theirs: _stamped(their),
      codec: const _AttrCodec(),
    );
    final newer = _newer(our, their);
    final record = _EntryRecord(
      uuid: c.key,
      attrs: {
        for (final MapEntry(:key, :value) in attrMerge.merged.entries)
          key: value.unstamped,
      },
      modified: newer.modified,
      created: our.created ?? their.created,
      source: newer.source,
      history: [...our.history, ...their.history],
      conflicts: [...our.conflicts, ...their.conflicts],
    );
    merged[c.key] = record;
    if (attrMerge.conflicts.isNotEmpty) {
      final loser = identical(newer, our) ? their : our;
      losers[c.key] = loser;
      final conflict = TomSecretsEntryConflict(
        entryUuid: c.key,
        fields: [for (final a in attrMerge.conflicts) a.key]..sort(),
        loserModified: loser.modified ?? at,
        at: at,
      );
      conflicts.add(conflict);
    }
  }
  // Copy every loser now: a loser may be our own live entry, which applying
  // the merge overwrites.
  final loserCopies = <String, KdbxEntry>{
    for (final MapEntry(:key, :value) in losers.entries)
      if (value.source case final source?)
        key: _detachedCopy(ours, _entryByUuid(ours, key) ?? source, source),
  };
  _apply(
    ours: ours,
    theirs: theirs,
    groups: groupMerge.merged,
    entries: merged,
    losers: loserCopies,
    newConflicts: {for (final c in conflicts) c.entryUuid: c},
    oursSnapshot: o,
    theirsSnapshot: t,
    meta: metaMerge.merged,
  );
  final keptGroups = [
    for (final key in {...o.groups.keys, ...t.groups.keys})
      if (!groupMerge.merged.containsKey(key) &&
          _groupByUuid(ours, key) != null)
        key,
  ];
  return TomSecretsMergeResult._(conflicts, editsAgainstDeletion, keptGroups);
}

_EntryRecord _newer(_EntryRecord a, _EntryRecord b) {
  final x = a.modified;
  final y = b.modified;
  if (x != null && y != null && y.isAfter(x)) return b;
  return a;
}

Map<String, _Attr> _stamped(_EntryRecord e) => {
  for (final MapEntry(:key, :value) in e.attrs.entries)
    key: _Attr(key, value.value, value.bytes, e.modified),
};

// ── Snapshots ─────────────────────────────────────────────────────────────

/// One attribute of an entry, or one meta custom-data value.
final class _Attr {
  const _Attr(this.key, this.value, [this.bytes, this.modified]);
  final String key;

  /// The canonical text of the value (for a binary: protection and SHA-256).
  final String value;

  /// A binary's bytes.
  final Uint8List? bytes;

  /// The stamp of the side it came from (attribute-level merge only).
  final DateTime? modified;

  _Attr get unstamped => _Attr(key, value, bytes);
}

final class _AttrCodec implements TomRecordCodec<_Attr> {
  const _AttrCodec();
  @override
  String idOf(_Attr record) => record.key;
  @override
  DateTime? modifiedOf(_Attr record) => record.modified;
  @override
  Uint8List canonicalBytes(_Attr record) => utf8.encode(record.value);
}

final class _GroupRecord {
  const _GroupRecord(this.uuid, this.name, this.parent, this.customData);
  final String uuid;
  final String name;

  /// The parent's UUID, [_recycleBin], or null for the root.
  final String? parent;
  final Map<String, String> customData;
}

final class _GroupCodec implements TomRecordCodec<_GroupRecord> {
  const _GroupCodec();
  @override
  String idOf(_GroupRecord record) => record.uuid;
  @override
  DateTime? modifiedOf(_GroupRecord record) => null;
  @override
  Uint8List canonicalBytes(_GroupRecord record) => utf8.encode(
    jsonEncode([
      record.name,
      record.parent,
      [
        for (final k in record.customData.keys.toList()..sort())
          [k, record.customData[k]],
      ],
    ]),
  );
}

final class _EntryRecord {
  const _EntryRecord({
    required this.uuid,
    required this.attrs,
    required this.modified,
    required this.created,
    required this.source,
    required this.history,
    required this.conflicts,
  });

  final String uuid;

  /// `field:<name>`, `binary:<name>`, `tags`, `expiry`, `group`,
  /// `autotype`, `custom:<key>` (not `tsm.conflict`, which is [conflicts]).
  final Map<String, _Attr> attrs;
  final DateTime? modified;
  final DateTime? created;

  /// The entry the record was read from (history and binaries come from it).
  final KdbxEntry? source;
  final List<KdbxEntry> history;
  final List<TomSecretsEntryConflict> conflicts;
}

final class _EntryCodec implements TomRecordCodec<_EntryRecord> {
  const _EntryCodec();
  @override
  String idOf(_EntryRecord record) => record.uuid;
  @override
  DateTime? modifiedOf(_EntryRecord record) => record.modified;
  @override
  Uint8List canonicalBytes(_EntryRecord record) => utf8.encode(
    jsonEncode([
      for (final k in record.attrs.keys.toList()..sort())
        [k, record.attrs[k]!.value],
    ]),
  );
}

final class _Snapshot {
  _Snapshot(this.entries, this.groups, this.meta);

  factory _Snapshot.empty() => _Snapshot({}, {}, {});

  factory _Snapshot.of(KdbxFile file) {
    final root = file.body.rootGroup;
    final bin = file.recycleBin;
    String? parentOf(KdbxGroup g) {
      final p = g.parent;
      if (p == null) return null;
      if (bin != null && p.uuid == bin.uuid) return _recycleBin;
      return p.uuid.uuid;
    }

    final groups = <String, _GroupRecord>{};
    final entries = <String, _EntryRecord>{};
    void entriesOf(KdbxGroup g, String groupKey) {
      for (final e in g.entries) {
        entries[e.uuid.uuid] = _entryRecord(e, groupKey);
      }
    }

    entriesOf(root, root.uuid.uuid);
    for (final g in root.getAllGroups()) {
      final isBin = bin != null && g.uuid == bin.uuid;
      if (!isBin) {
        groups[g.uuid.uuid] = _GroupRecord(
          g.uuid.uuid,
          g.name.get() ?? '',
          parentOf(g),
          {for (final e in g.customData.entries) e.key: e.value},
        );
      }
      entriesOf(g, isBin ? _recycleBin : g.uuid.uuid);
    }
    final meta = {
      for (final e in file.body.meta.customData.entries)
        e.key: _Attr(e.key, e.value),
    };
    return _Snapshot(entries, groups, meta);
  }

  final Map<String, _EntryRecord> entries;
  final Map<String, _GroupRecord> groups;
  final Map<String, _Attr> meta;
}

_EntryRecord _entryRecord(KdbxEntry e, String group) {
  final attrs = <String, _Attr>{};
  void put(String key, String value, [Uint8List? bytes]) =>
      attrs[key] = _Attr(key, value, bytes);
  for (final MapEntry(key: key, value: value) in e.stringEntries) {
    final text = value?.getText() ?? '';
    put('field:${key.key}', '${value is ProtectedValue ? 'p' : 't'}:$text');
  }
  for (final MapEntry(key: key, value: binary) in e.binaryEntries) {
    put(
      'binary:${key.key}',
      '${binary.isProtected ? 'p' : 't'}:${crypto.sha256.convert(binary.value)}',
      binary.value,
    );
  }
  final tags = e.tags.get();
  if (tags != null) put('tags', tags);
  if (e.times.expires.get() == true) {
    put('expiry', e.times.expiryTime.get()?.toIso8601String() ?? '');
  }
  put('group', group);
  final autoType = e.autoType;
  if (autoType != const KdbxAutoTypeSettings()) {
    put(
      'autotype',
      jsonEncode({
        'enabled': autoType.enabled,
        'sequence': autoType.defaultSequence,
        'windows': [
          for (final a in autoType.associations) [a.window, a.sequence],
        ],
      }),
    );
  }
  for (final c in e.customData.entries) {
    if (c.key != tomSecretsConflictKey) put('custom:${c.key}', c.value);
  }
  return _EntryRecord(
    uuid: e.uuid.uuid,
    attrs: attrs,
    modified: e.times.lastModificationTime.get(),
    created: e.times.creationTime.get(),
    source: e,
    history: List.of(e.history),
    conflicts: tomSecretsConflictsOf(e),
  );
}

// ── Applying the merged records to ours ──────────────────────────────────

KdbxGroup? _groupByUuid(KdbxFile file, String uuid) {
  final root = file.body.rootGroup;
  if (root.uuid.uuid == uuid) return root;
  for (final g in root.getAllGroups()) {
    if (g.uuid.uuid == uuid) return g;
  }
  return null;
}

KdbxEntry? _entryByUuid(KdbxFile file, String uuid) {
  for (final e in file.body.rootGroup.getAllEntries()) {
    if (e.uuid.uuid == uuid) return e;
  }
  return null;
}

/// The recycle bin of [file], made when it has none.
KdbxGroup _bin(KdbxFile file) {
  final existing = file.recycleBin;
  if (existing != null) return existing;
  // The store makes the bin when an entry is deleted; a scratch entry makes
  // it here and leaves no trace.
  final root = file.body.rootGroup;
  final scratch = KdbxEntry.create(file, root);
  root.addEntry(scratch);
  file.deleteEntry(scratch);
  final bin = file.recycleBin!;
  file.deletePermanently(scratch);
  file.clearDeletion(scratch.uuid);
  return bin;
}

void _apply({
  required KdbxFile ours,
  required KdbxFile theirs,
  required Map<String, _GroupRecord> groups,
  required Map<String, _EntryRecord> entries,
  required Map<String, KdbxEntry> losers,
  required Map<String, TomSecretsEntryConflict> newConflicts,
  required _Snapshot oursSnapshot,
  required _Snapshot theirsSnapshot,
  required Map<String, _Attr> meta,
}) {
  final root = ours.body.rootGroup;
  KdbxGroup parentFor(String? key) => switch (key) {
    null => root,
    _recycleBin => _bin(ours),
    _ => _groupByUuid(ours, key) ?? root,
  };

  // Groups: create the missing ones (parents first), then name and place.
  var pending = groups.values.where((g) => _groupByUuid(ours, g.uuid) == null);
  while (pending.isNotEmpty) {
    final ready = pending
        .where(
          (g) =>
              g.parent == null ||
              g.parent == _recycleBin ||
              _groupByUuid(ours, g.parent!) != null ||
              !groups.containsKey(g.parent),
        )
        .toList();
    if (ready.isEmpty) break;
    for (final g in ready) {
      ours
          .createGroup(parent: parentFor(g.parent), name: g.name)
          .assignUuid(KdbxUuid(g.uuid));
    }
    pending = groups.values.where((g) => _groupByUuid(ours, g.uuid) == null);
  }
  for (final g in groups.values) {
    final group = _groupByUuid(ours, g.uuid);
    if (group == null || group.uuid == root.uuid) continue;
    if (group.name.get() != g.name) group.name.set(g.name);
    final parent = parentFor(g.parent);
    if (group.parent?.uuid != parent.uuid) ours.moveGroup(group, parent);
    for (final key in group.customData.keys.toList()) {
      if (!g.customData.containsKey(key)) group.customData.remove(key);
    }
    for (final MapEntry(:key, :value) in g.customData.entries) {
      if (group.customData[key] != value) group.customData[key] = value;
    }
  }

  // Entries.
  final codec = const _EntryCodec();
  for (final record in entries.values) {
    var entry = _entryByUuid(ours, record.uuid);
    final groupKey = record.attrs['group']?.value;
    final target = groupKey == _recycleBin
        ? _bin(ours)
        : (groupKey == null ? root : (_groupByUuid(ours, groupKey) ?? root));
    final current = oursSnapshot.entries[record.uuid];
    final changed =
        current == null ||
        !_sameBytes(
          codec.canonicalBytes(current),
          codec.canonicalBytes(record),
        );
    if (entry == null) {
      entry = KdbxEntry.create(ours, target)..assignUuid(KdbxUuid(record.uuid));
      target.addEntry(entry);
      _writeAttrs(entry, record);
    } else if (changed) {
      _writeAttrs(entry, record);
      if (entry.parent?.uuid != target.uuid) ours.move(entry, target);
    }
    if (record.modified != null) {
      entry.times.lastModificationTime.set(record.modified);
    }
    if (record.created != null) entry.times.creationTime.set(record.created);
    _mergeHistory(ours, entry, record, losers[record.uuid]);
    final open = <String, TomSecretsEntryConflict>{
      for (final c in [...record.conflicts, ?newConflicts[record.uuid]])
        '${c.loserModified.toIso8601String()} ${c.fields.join(',')}': c,
    };
    if (open.isEmpty) {
      entry.customData.remove(tomSecretsConflictKey);
    } else {
      entry.customData[tomSecretsConflictKey] = jsonEncode([
        for (final c in open.values) c.toJson(),
      ]);
    }
  }
  // Entries the merge deleted.
  for (final uuid in oursSnapshot.entries.keys) {
    if (entries.containsKey(uuid)) continue;
    final entry = _entryByUuid(ours, uuid);
    if (entry != null) ours.deletePermanently(entry);
  }
  // Groups the merge deleted, when nothing is left in them.
  for (final uuid in oursSnapshot.groups.keys) {
    if (groups.containsKey(uuid)) continue;
    final group = _groupByUuid(ours, uuid);
    if (group == null) continue;
    if (group.getAllEntries().isEmpty &&
        group.getAllGroups().every((g) => !groups.containsKey(g.uuid.uuid))) {
      ours.deleteGroupPermanently(group);
    }
  }
  // Deletions theirs recorded, unless the merge kept the object.
  for (final uuid in theirs.deletedObjects) {
    if (entries.containsKey(uuid.uuid) || groups.containsKey(uuid.uuid)) {
      continue;
    }
    ours.recordDeletion(uuid, theirs.deletedAt(uuid) ?? DateTime.now());
  }
  // Meta custom data.
  final custom = ours.body.meta.customData;
  for (final key in custom.keys.toList()) {
    if (!meta.containsKey(key)) custom.remove(key);
  }
  for (final MapEntry(:key, :value) in meta.entries) {
    if (custom[key] != value.value) custom[key] = value.value;
  }
}

bool _sameBytes(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Writes [record]'s attributes into [entry] (fields, binaries, tags,
/// expiry, custom data), removing what the record does not hold.
void _writeAttrs(KdbxEntry entry, _EntryRecord record) {
  _copyAttrs(entry, record.attrs);
}

void _copyAttrs(KdbxEntry entry, Map<String, _Attr> attrs) {
  entry.modify(() {
    final fields = {
      for (final a in attrs.values)
        if (a.key.startsWith('field:')) a.key.substring(6): a.value,
    };
    for (final MapEntry(key: key) in entry.stringEntries.toList()) {
      if (!fields.containsKey(key.key)) entry.removeString(key);
    }
    for (final MapEntry(key: name, value: value) in fields.entries) {
      final text = value.substring(2);
      entry.setString(
        KdbxKey(name),
        value.startsWith('p:')
            ? ProtectedValue.fromString(text)
            : PlainValue(text),
      );
    }
    final binaries = {
      for (final a in attrs.values)
        if (a.key.startsWith('binary:')) a.key.substring(7): a,
    };
    for (final MapEntry(key: key, value: existing)
        in entry.binaryEntries.toList()) {
      final want = binaries[key.key];
      final same =
          want != null &&
          want.value ==
              '${existing.isProtected ? 'p' : 't'}:${crypto.sha256.convert(existing.value)}';
      if (!same) entry.removeBinary(key);
      if (same) binaries.remove(key.key);
    }
    for (final MapEntry(key: name, value: a) in binaries.entries) {
      entry.createBinary(
        isProtected: a.value.startsWith('p:'),
        name: name,
        bytes: a.bytes ?? Uint8List(0),
      );
    }
    final tags = attrs['tags']?.value;
    if (entry.tags.get() != tags) entry.tags.set(tags);
  });
  final expiry = attrs['expiry']?.value;
  entry.times.expires.set(expiry != null);
  if (expiry != null && expiry.isNotEmpty) {
    entry.times.expiryTime.set(DateTime.parse(expiry));
  }
  final custom = {
    for (final a in attrs.values)
      if (a.key.startsWith('custom:')) a.key.substring(7): a.value,
  };
  for (final key in entry.customData.keys.toList()) {
    if (key != tomSecretsConflictKey && !custom.containsKey(key)) {
      entry.customData.remove(key);
    }
  }
  for (final MapEntry(:key, :value) in custom.entries) {
    if (entry.customData[key] != value) entry.customData[key] = value;
  }
  final autoType = _autoTypeOf(attrs['autotype']?.value);
  if (entry.autoType != autoType) entry.autoType = autoType;
}

/// The auto-type settings an `autotype` attribute holds (absent: the
/// default ones).
KdbxAutoTypeSettings _autoTypeOf(String? json) {
  if (json == null) return const KdbxAutoTypeSettings();
  final map = jsonDecode(json) as Map<String, Object?>;
  return KdbxAutoTypeSettings(
    enabled: map['enabled'] as bool? ?? true,
    defaultSequence: map['sequence'] as String?,
    associations: [
      for (final w in map['windows'] as List? ?? const [])
        KdbxAutoTypeAssociation('${(w as List)[0]}', '${w[1]}'),
    ],
  );
}

/// The entry's history: the union of both sides' versions and the conflict
/// loser, by modification time, pruned to the vault's limit; versions an
/// open conflict names are never pruned.
void _mergeHistory(
  KdbxFile ours,
  KdbxEntry entry,
  _EntryRecord record,
  KdbxEntry? loser,
) {
  final byTime = <String, KdbxEntry>{};
  String stamp(KdbxEntry e) =>
      e.times.lastModificationTime.get()?.toIso8601String() ?? '';
  final current = stamp(entry);
  void keep(KdbxEntry version) {
    final s = stamp(version);
    if (s == current) return; // the live version is not history
    byTime.putIfAbsent(s, () => _detachedCopy(ours, entry, version));
  }

  for (final v in entry.history) {
    byTime[stamp(v)] = v;
  }
  for (final v in record.history) {
    if (!identical(v.file, ours)) keep(v);
  }
  if (loser != null) byTime.putIfAbsent(stamp(loser), () => loser);
  byTime.remove(current);
  final protected = {
    for (final c in [...record.conflicts, ...tomSecretsConflictsOf(entry)])
      c.loserModified.toIso8601String(),
    if (loser?.times.lastModificationTime.get() case final m?)
      m.toIso8601String(),
  };
  final ordered = byTime.keys.toList()..sort();
  final limit = ours.body.meta.historyMaxItems.get();
  var drop = limit == null || limit < 0 ? 0 : ordered.length - limit;
  final kept = <String>[];
  for (final key in ordered) {
    if (drop > 0 && !protected.contains(key)) {
      drop--;
      continue;
    }
    kept.add(key);
  }
  entry.history
    ..clear()
    ..addAll([for (final k in kept) byTime[k]!]);
}

/// A history entry of [ours] with [version]'s content and times.
/// A copy of [from] (an entry of another file) added to [group] of [into]:
/// its fields (protected ones protected), attachments, tags, expiry, custom
/// data, times and history. It keeps [from]'s UUID unless [into] holds that
/// UUID already, then it gets a new one. An open conflict record stays
/// behind.
KdbxEntry tomSecretsCopyEntry(KdbxFile into, KdbxGroup group, KdbxEntry from) {
  final entry = KdbxEntry.create(into, group);
  if (_entryByUuid(into, from.uuid.uuid) == null) entry.assignUuid(from.uuid);
  group.addEntry(entry);
  _copyAttrs(entry, _entryRecord(from, '').attrs);
  for (final version in from.history) {
    entry.history.add(_detachedCopy(into, entry, version));
  }
  entry.times.lastModificationTime.set(from.times.lastModificationTime.get());
  entry.times.creationTime.set(from.times.creationTime.get());
  return entry;
}

KdbxEntry _detachedCopy(KdbxFile ours, KdbxEntry owner, KdbxEntry version) {
  final copy = KdbxEntry.create(
    ours,
    owner.parent ?? ours.body.rootGroup,
    isHistoryEntry: true,
  )..assignUuid(owner.uuid);
  final record = _entryRecord(version, '');
  _copyAttrs(copy, record.attrs);
  copy.times.lastModificationTime.set(version.times.lastModificationTime.get());
  copy.times.creationTime.set(version.times.creationTime.get());
  return copy;
}
