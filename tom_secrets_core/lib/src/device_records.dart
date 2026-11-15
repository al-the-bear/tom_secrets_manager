// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The device records of a primary vault (part-sharing, DP-62): every
/// device paired into the user's fleet, with its platform, when it was
/// paired, the ids of the keys it received, its own approver and link key
/// ids and since when they are in use (so every desktop shows the key-pair
/// dates, tsm_a_rem1), and when it was revoked. Kept under `.tom-secrets/
/// devices`, never resolved into; a lost device shows at once what to
/// rotate.
library;

import 'dart:convert';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'primary.dart';

/// The subgroup of the product group holding the device records.
const String tomSecretsDevicesGroup = 'devices';

const _platform = KdbxKey('tsm.platform');
const _paired = KdbxKey('tsm.paired');
const _pairedBy = KdbxKey('tsm.paired-by');
const _keyIds = KdbxKey('tsm.key-ids');
const _approverKeyId = KdbxKey('tsm.approver-key-id');
const _linkKeySince = KdbxKey('tsm.link-key-since');
const _approverKeySince = KdbxKey('tsm.approver-key-since');
const _revoked = KdbxKey('tsm.revoked');

/// One paired device.
final class TomSecretsDeviceRecord {
  /// A record of [device].
  const TomSecretsDeviceRecord({
    required this.device,
    required this.paired,
    this.platform,
    this.pairedBy,
    this.keyIds = const [],
    this.approverKeyId,
    this.approverKeySince,
    this.linkKeySince,
    this.revoked,
  });

  /// The device's name.
  final String device;

  /// Its platform (`macos`, `linux`, `windows`, …), when known.
  final String? platform;

  /// When it was paired (last).
  final DateTime paired;

  /// The device that paired it.
  final String? pairedBy;

  /// The ids of the keys it received: the key files' hashes and the
  /// repository keys' ids.
  final List<String> keyIds;

  /// Its approver key's id, when it approves.
  final String? approverKeyId;

  /// Since when its approver key pair is in use.
  final DateTime? approverKeySince;

  /// Since when its approval-link key pair is in use.
  final DateTime? linkKeySince;

  /// When it was revoked, or null.
  final DateTime? revoked;

  /// Whether it was revoked.
  bool get isRevoked => revoked != null;

  /// The record as the wire carries it (`pair.list`).
  Map<String, Object?> toJson() => {
    'device': device,
    'platform': ?platform,
    'paired': paired.toUtc().toIso8601String(),
    'pairedBy': ?pairedBy,
    'keyIds': keyIds,
    'approverKeyId': ?approverKeyId,
    if (approverKeySince != null)
      'approverKeySince': approverKeySince!.toUtc().toIso8601String(),
    if (linkKeySince != null)
      'linkKeySince': linkKeySince!.toUtc().toIso8601String(),
    if (revoked != null) 'revoked': revoked!.toUtc().toIso8601String(),
  };
}

/// The device records of the primary vault [file].
final class TomSecretsDeviceRecords {
  /// The records of [file].
  TomSecretsDeviceRecords(this.file);

  /// The primary vault.
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
    final devices = product.groups
        .where((g) => g.name.get() == tomSecretsDevicesGroup)
        .firstOrNull;
    if (devices != null || !create) return devices;
    return file.createGroup(parent: product, name: tomSecretsDevicesGroup);
  }

  /// Every record, in file order.
  List<TomSecretsDeviceRecord> list() => [
    for (final e in _group()?.entries ?? const <KdbxEntry>[]) ?_read(e),
  ];

  /// The record of [device], or null.
  TomSecretsDeviceRecord? byDevice(String device) =>
      list().where((r) => r.device == device).firstOrNull;

  /// Writes [record], replacing the record of the same device (a device
  /// paired again is updated, never duplicated).
  void put(TomSecretsDeviceRecord record) {
    final group = _group(create: true)!;
    var entry = group.entries
        .where((e) => e.label == record.device)
        .firstOrNull;
    if (entry == null) {
      entry = KdbxEntry.create(file, group);
      group.addEntry(entry);
      entry.label = record.device;
    }
    final target = entry;
    void set(KdbxKey key, String? value) =>
        target.setString(key, value == null ? null : PlainValue(value));
    String? time(DateTime? at) => at?.toUtc().toIso8601String();
    target.modify(() {
      set(_platform, record.platform);
      set(_paired, time(record.paired));
      set(_pairedBy, record.pairedBy);
      set(_keyIds, jsonEncode(record.keyIds));
      set(_approverKeyId, record.approverKeyId);
      set(_approverKeySince, time(record.approverKeySince));
      set(_linkKeySince, time(record.linkKeySince));
      set(_revoked, time(record.revoked));
    });
  }

  /// Marks [device] revoked at [at]; whether it had a record.
  bool revoke(String device, DateTime at) {
    final record = byDevice(device);
    if (record == null) return false;
    put(
      TomSecretsDeviceRecord(
        device: record.device,
        platform: record.platform,
        paired: record.paired,
        pairedBy: record.pairedBy,
        keyIds: record.keyIds,
        approverKeyId: record.approverKeyId,
        approverKeySince: record.approverKeySince,
        linkKeySince: record.linkKeySince,
        revoked: at,
      ),
    );
    return true;
  }

  static TomSecretsDeviceRecord? _read(KdbxEntry e) {
    String? text(KdbxKey key) => e.getString(key)?.getText();
    DateTime? time(KdbxKey key) {
      final t = text(key);
      return t == null ? null : DateTime.tryParse(t)?.toUtc();
    }

    final device = e.label;
    final paired = time(_paired);
    if (device == null || device.isEmpty || paired == null) return null;
    List<String> ids;
    try {
      ids = [
        for (final id in (jsonDecode(text(_keyIds) ?? '[]') as List)) '$id',
      ];
    } on Object {
      ids = const [];
    }
    return TomSecretsDeviceRecord(
      device: device,
      platform: text(_platform),
      paired: paired,
      pairedBy: text(_pairedBy),
      keyIds: ids,
      approverKeyId: text(_approverKeyId),
      approverKeySince: time(_approverKeySince),
      linkKeySince: time(_linkKeySince),
      revoked: time(_revoked),
    );
  }
}
