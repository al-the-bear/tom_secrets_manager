// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The rotation record of the guided rotation with a migration
/// period (part-key-rotation, DP-85): one entry per rotation in the group
/// `.tom-secrets/rotations` of the primary vault (for a shared vault's keys,
/// of the shared vault itself), naming the kind of key, its target, the old
/// and new key ids, when it started and switched, when its migration
/// period ends (default 14 days) and who still has to take up the new key.
///
/// The record is the lock: one rotation per target at a time. A second
/// device that wants to rotate the same target finds the record and waits;
/// two devices starting at once both commit one, the second push is
/// refused and that device reads the first one's record.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'primary.dart' show tomSecretsProductGroup;

/// The subgroup of the product group holding the rotation records.
const String tomSecretsRotationsGroup = 'rotations';

/// The default migration period of a rotation (DP-85).
const Duration tomSecretsRotationPeriod = Duration(days: 14);

/// The kind of key a rotation replaces.
enum TomSecretsRotationKind {
  /// The user's member key (target: the old key's fingerprint).
  memberKey('member-key'),

  /// A shared vault's key file and repository key (target: its store).
  sharedVault('shared-vault'),

  /// A vault's key file or master password (target: its store).
  vaultKeys('vault-keys'),

  /// A repository's outer key (target: `owner/repository`).
  repositoryKey('repository-key');

  const TomSecretsRotationKind(this.wireName);

  /// The name the record keeps.
  final String wireName;

  /// The kind of [name]; null for one this version does not know.
  static TomSecretsRotationKind? of(String? name) =>
      values.where((k) => k.wireName == name).firstOrNull;
}

/// A rotation that cannot start or go on.
final class TomSecretsRotationException implements Exception {
  /// A refusal told by [message]; [rotation] is the record in the way.
  const TomSecretsRotationException(this.message, {this.rotation});

  /// For people.
  final String message;

  /// The rotation of the same target already running, when that is why.
  final TomSecretsRotation? rotation;

  @override
  String toString() => 'TomSecretsRotationException: $message';
}

/// One rotation record.
final class TomSecretsRotation {
  /// A rotation of [kind] of [target] from [oldKeyId] to [newKeyId], started
  /// by [by] at [started]; [switched] once the target runs under the new
  /// key; its migration period ends at [endsAt]; [pending] still have to take
  /// up the new key.
  const TomSecretsRotation({
    required this.kind,
    required this.target,
    required this.oldKeyId,
    required this.newKeyId,
    required this.started,
    required this.endsAt,
    required this.by,
    this.switched,
    this.pending = const [],
  });

  /// The kind of key.
  final TomSecretsRotationKind kind;

  /// What it rotates: a store, a repository or a member key's fingerprint.
  final String target;

  /// The old key's id.
  final String oldKeyId;

  /// The new key's id.
  final String newKeyId;

  /// When it started.
  final DateTime started;

  /// When the target started to run under the new key, or null before.
  final DateTime? switched;

  /// When its migration period ends.
  final DateTime endsAt;

  /// The device that started it.
  final String by;

  /// The devices, members or vaults still to take up the new key.
  final List<String> pending;

  /// Whether its migration period is over at [now].
  bool isDueAt(DateTime now) => !now.toUtc().isBefore(endsAt.toUtc());

  /// This record with [switched] and [pending] replaced.
  TomSecretsRotation copyWith({DateTime? switched, List<String>? pending}) =>
      TomSecretsRotation(
        kind: kind,
        target: target,
        oldKeyId: oldKeyId,
        newKeyId: newKeyId,
        started: started,
        endsAt: endsAt,
        by: by,
        switched: switched ?? this.switched,
        pending: pending ?? this.pending,
      );

  /// The record's title in its group: `<kind> <target>`, unique per target.
  String get title => '${kind.wireName} $target';
}

/// The key id of [bytes] (a key file's bytes, a repository key's): the first
/// 8 bytes of their SHA-256 in hex.
String tomSecretsKeyId(List<int> bytes) =>
    crypto.sha256.convert(bytes).toString().substring(0, 16);

const _kind = KdbxKey('tsm.rotation.kind');
const _target = KdbxKey('tsm.rotation.target');
const _oldKeyId = KdbxKey('tsm.rotation.old-key-id');
const _newKeyId = KdbxKey('tsm.rotation.new-key-id');
const _started = KdbxKey('tsm.rotation.started');
const _switched = KdbxKey('tsm.rotation.switched');
const _endsAt = KdbxKey('tsm.rotation.ends');
const _by = KdbxKey('tsm.rotation.by');
const _pending = KdbxKey('tsm.rotation.pending');

/// The rotation records of [file] (the primary vault, or a shared vault).
final class TomSecretsRotations {
  /// The records of [file].
  TomSecretsRotations(this.file);

  /// The vault holding them.
  final KdbxFile file;

  KdbxGroup? _group({bool create = false}) {
    final root = file.body.rootGroup;
    var product = root.groups
        .where((g) => g.name.get() == tomSecretsProductGroup)
        .firstOrNull;
    if (product == null) {
      if (!create) return null;
      product = file.createGroup(parent: root, name: tomSecretsProductGroup);
    }
    final rotations = product.groups
        .where((g) => g.name.get() == tomSecretsRotationsGroup)
        .firstOrNull;
    if (rotations != null || !create) return rotations;
    return file.createGroup(parent: product, name: tomSecretsRotationsGroup);
  }

  /// Every record this version reads, in file order.
  List<TomSecretsRotation> list() => [
    for (final e in _group()?.entries ?? const <KdbxEntry>[]) ?_read(e),
  ];

  /// The running rotation of [kind] of [target], or null.
  TomSecretsRotation? of(TomSecretsRotationKind kind, String target) =>
      list().where((r) => r.kind == kind && r.target == target).firstOrNull;

  /// Starts [rotation]: refused ([TomSecretsRotationException]) while one of
  /// the same kind and target runs (the record is the lock).
  void start(TomSecretsRotation rotation) {
    final running = of(rotation.kind, rotation.target);
    if (running != null) {
      throw TomSecretsRotationException(
        'a rotation of ${rotation.target} runs already, started by '
        '${running.by} on ${running.started.toUtc().toIso8601String().substring(0, 10)}',
        rotation: running,
      );
    }
    final group = _group(create: true)!;
    final entry = KdbxEntry.create(file, group)..label = rotation.title;
    group.addEntry(entry);
    _write(entry, rotation);
  }

  /// Writes [rotation] over its record (its switch, who is still pending).
  void update(TomSecretsRotation rotation) {
    final entry = _entryOf(rotation.kind, rotation.target);
    if (entry == null) {
      throw TomSecretsRotationException('no rotation of ${rotation.target}');
    }
    entry.modify(() => _write(entry, rotation));
  }

  /// Ends the rotation of [kind] of [target] (finished or cancelled): its
  /// record goes. Answers whether there was one.
  bool end(TomSecretsRotationKind kind, String target) {
    final entry = _entryOf(kind, target);
    if (entry == null) return false;
    file.deletePermanently(entry);
    return true;
  }

  KdbxEntry? _entryOf(TomSecretsRotationKind kind, String target) {
    for (final e in _group()?.entries ?? const <KdbxEntry>[]) {
      final r = _read(e);
      if (r != null && r.kind == kind && r.target == target) return e;
    }
    return null;
  }

  static void _write(KdbxEntry entry, TomSecretsRotation r) {
    void set(KdbxKey key, String? value) =>
        entry.setString(key, value == null ? null : PlainValue(value));
    String time(DateTime at) => at.toUtc().toIso8601String();
    set(_kind, r.kind.wireName);
    set(_target, r.target);
    set(_oldKeyId, r.oldKeyId);
    set(_newKeyId, r.newKeyId);
    set(_started, time(r.started));
    set(_switched, r.switched == null ? null : time(r.switched!));
    set(_endsAt, time(r.endsAt));
    set(_by, r.by);
    set(_pending, jsonEncode(r.pending));
  }

  static TomSecretsRotation? _read(KdbxEntry e) {
    String? text(KdbxKey k) => e.getString(k)?.getText();
    final kind = TomSecretsRotationKind.of(text(_kind));
    final target = text(_target);
    final started = DateTime.tryParse(text(_started) ?? '');
    final endsAt = DateTime.tryParse(text(_endsAt) ?? '');
    if (kind == null || target == null || started == null || endsAt == null) {
      return null;
    }
    List<String> pending;
    try {
      pending = [
        for (final p in jsonDecode(text(_pending) ?? '[]') as List) '$p',
      ];
    } on Object {
      pending = const [];
    }
    return TomSecretsRotation(
      kind: kind,
      target: target,
      oldKeyId: text(_oldKeyId) ?? '',
      newKeyId: text(_newKeyId) ?? '',
      started: started,
      switched: DateTime.tryParse(text(_switched) ?? ''),
      endsAt: endsAt,
      by: text(_by) ?? '',
      pending: pending,
    );
  }
}
