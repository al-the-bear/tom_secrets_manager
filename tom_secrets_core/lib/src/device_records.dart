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
const _githubAuth = KdbxKey('tsm.github-auth');
const _githubTokenExpires = KdbxKey('tsm.github-token-expires');
const _serviceKey = KdbxKey('tsm.service-key');

/// How a device reaches the vault repositories on GitHub (part-key-rotation
/// §3, DP-83): signed in through the user's GitHub App (`app`), or with a
/// fine-grained token pasted on it (`token`). It decides what cuts off a
/// lost device: deleting its token, or revoking the App's authorization
/// (every signed-in device then signs in again).
enum TomSecretsGitHubAuth {
  /// Signed in with the GitHub App (device flow).
  app,

  /// A pasted fine-grained personal access token.
  token;

  /// The kind written as [text], or null.
  static TomSecretsGitHubAuth? of(String? text) =>
      values.where((v) => v.name == text).firstOrNull;
}

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
    this.githubAuth,
    this.githubTokenExpires,
    this.serviceKey,
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

  /// How it reaches GitHub, when it said so.
  final TomSecretsGitHubAuth? githubAuth;

  /// When its GitHub token expires: a pasted token's expiry, or a signed-in
  /// device's refresh token's (its sign-in lasts that long unused).
  final DateTime? githubTokenExpires;

  /// The public identity key of its secrets service (base64, protocol.md
  /// 6.1), when it runs one and said so: what the other devices show as
  /// words, to compare with what that machine's `tsm status` shows.
  final String? serviceKey;

  /// This record with [serviceKey] replaced.
  TomSecretsDeviceRecord withServiceKey(String? key) => TomSecretsDeviceRecord(
    device: device,
    platform: platform,
    paired: paired,
    pairedBy: pairedBy,
    keyIds: keyIds,
    approverKeyId: approverKeyId,
    approverKeySince: approverKeySince,
    linkKeySince: linkKeySince,
    revoked: revoked,
    githubAuth: githubAuth,
    githubTokenExpires: githubTokenExpires,
    serviceKey: key,
  );

  /// This record with [githubAuth] and [githubTokenExpires] replaced.
  TomSecretsDeviceRecord withGitHub(
    TomSecretsGitHubAuth? auth,
    DateTime? expires,
  ) => TomSecretsDeviceRecord(
    device: device,
    platform: platform,
    paired: paired,
    pairedBy: pairedBy,
    keyIds: keyIds,
    approverKeyId: approverKeyId,
    approverKeySince: approverKeySince,
    linkKeySince: linkKeySince,
    revoked: revoked,
    githubAuth: auth,
    githubTokenExpires: expires,
    serviceKey: serviceKey,
  );

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
    'serviceKey': ?serviceKey,
    if (approverKeySince != null)
      'approverKeySince': approverKeySince!.toUtc().toIso8601String(),
    if (linkKeySince != null)
      'linkKeySince': linkKeySince!.toUtc().toIso8601String(),
    if (revoked != null) 'revoked': revoked!.toUtc().toIso8601String(),
    'githubAuth': ?githubAuth?.name,
    if (githubTokenExpires != null)
      'githubTokenExpires': githubTokenExpires!.toUtc().toIso8601String(),
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

  /// Every record, in file order, one per device. Two devices may each
  /// write a record of the same device before their copies of the primary
  /// meet (the giving machine at the pairing, the new machine's service at
  /// its first unlock), and the merge keeps both entries: they are read as
  /// one, the entry changed last deciding each field it holds, the key ids
  /// joined, the earliest pairing kept. The next [put] leaves one entry.
  List<TomSecretsDeviceRecord> list() {
    final entries = [..._group()?.entries ?? const <KdbxEntry>[]];
    final byDevice = <String, List<KdbxEntry>>{};
    for (final e in entries) {
      final device = e.label;
      if (device != null) byDevice.putIfAbsent(device, () => []).add(e);
    }
    return [for (final same in byDevice.values) ?_joined(same)];
  }

  static DateTime _changed(KdbxEntry e) =>
      e.times.lastModificationTime.get() ??
      DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

  static TomSecretsDeviceRecord? _joined(List<KdbxEntry> same) {
    final records = [
      for (final e in [
        ...same,
      ]..sort((a, b) => _changed(a).compareTo(_changed(b))))
        ?_read(e),
    ];
    if (records.length < 2) return records.firstOrNull;
    var joined = records.first;
    for (final r in records.skip(1)) {
      joined = TomSecretsDeviceRecord(
        device: joined.device,
        platform: r.platform ?? joined.platform,
        paired: r.paired.isBefore(joined.paired) ? r.paired : joined.paired,
        pairedBy: r.pairedBy ?? joined.pairedBy,
        keyIds: {...joined.keyIds, ...r.keyIds}.toList(),
        approverKeyId: r.approverKeyId ?? joined.approverKeyId,
        approverKeySince: r.approverKeySince ?? joined.approverKeySince,
        linkKeySince: r.linkKeySince ?? joined.linkKeySince,
        revoked: r.revoked ?? joined.revoked,
        githubAuth: r.githubAuth ?? joined.githubAuth,
        githubTokenExpires: r.githubTokenExpires ?? joined.githubTokenExpires,
        serviceKey: r.serviceKey ?? joined.serviceKey,
      );
    }
    return joined;
  }

  /// The record of [device], or null.
  TomSecretsDeviceRecord? byDevice(String device) =>
      list().where((r) => r.device == device).firstOrNull;

  /// Writes [record], replacing the record of the same device (a device
  /// paired again is updated, never duplicated).
  void put(TomSecretsDeviceRecord record) {
    final group = _group(create: true)!;
    final same = [
      for (final e in group.entries)
        if (e.label == record.device) e,
    ];
    // Entries two devices each made for it: one stays.
    for (final extra in same.skip(1)) {
      file.deletePermanently(extra);
    }
    var entry = same.firstOrNull;
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
      set(_githubAuth, record.githubAuth?.name);
      set(_serviceKey, record.serviceKey);
      set(_githubTokenExpires, time(record.githubTokenExpires));
    });
  }

  /// Records how [device] reaches GitHub ([auth], [expires]); whether it
  /// had a record (a device never paired, the first one, has none) and it
  /// changed.
  bool setGitHub(String device, TomSecretsGitHubAuth? auth, DateTime? expires) {
    final record = byDevice(device);
    if (record == null) return false;
    if (record.githubAuth == auth &&
        record.githubTokenExpires?.toUtc() == expires?.toUtc()) {
      return false;
    }
    put(record.withGitHub(auth, expires));
    return true;
  }

  /// **[C]** Records that [device] holds the keys [ids] (a guided rotation's
  /// next keys it took, part-key-rotation): added to its record's key ids;
  /// a device without a record yet (the first one, never paired) gets one,
  /// paired at [now]. Whether the record changed.
  bool takeKeyIds(
    String device,
    Iterable<String> ids, {
    required DateTime now,
  }) {
    final record = byDevice(device);
    final have = record?.keyIds ?? const <String>[];
    final add = [
      for (final id in ids)
        if (!have.contains(id)) id,
    ];
    if (add.isEmpty && record != null) return false;
    put(
      TomSecretsDeviceRecord(
        device: device,
        platform: record?.platform,
        paired: record?.paired ?? now,
        pairedBy: record?.pairedBy,
        keyIds: [...have, ...add],
        approverKeyId: record?.approverKeyId,
        approverKeySince: record?.approverKeySince,
        linkKeySince: record?.linkKeySince,
        revoked: record?.revoked,
        githubAuth: record?.githubAuth,
        githubTokenExpires: record?.githubTokenExpires,
        serviceKey: record?.serviceKey,
      ),
    );
    return true;
  }

  /// Records the public identity key [key] (base64) of [device]'s secrets
  /// service; a device without a record yet (the first one, never paired)
  /// gets one, paired at [now]. Whether the record changed.
  bool setServiceKey(String device, String key, {required DateTime now}) {
    final record = byDevice(device);
    if (record?.serviceKey == key) return false;
    put(
      (record ?? TomSecretsDeviceRecord(device: device, paired: now))
          .withServiceKey(key),
    );
    return true;
  }

  /// **[C]** The devices not revoked that do not hold the key [keyId]: those
  /// a guided rotation still waits for.
  List<TomSecretsDeviceRecord> missingKey(String keyId) => [
    for (final r in list())
      if (!r.isRevoked && !r.keyIds.contains(keyId)) r,
  ];

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
        githubAuth: record.githubAuth,
        githubTokenExpires: record.githubTokenExpires,
        serviceKey: record.serviceKey,
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
      githubAuth: TomSecretsGitHubAuth.of(text(_githubAuth)),
      githubTokenExpires: time(_githubTokenExpires),
      serviceKey: text(_serviceKey),
    );
  }
}
