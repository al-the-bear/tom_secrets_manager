// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The device settings container (part-service, BP-43): `tom_kdbx_store`'s
/// [TomKdbxSettingsContainer], namespace `tsm`, local and not synced, opened
/// after the unlock. Its key is kept where `bootstrap.yaml` says (DP-15):
/// the OS keychain, the primary vault (the overlay entry
/// `@host:<host>/.tom-secrets/device`), or a key file beside the container;
/// `auto` takes the keychain where one is available, else the vault.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:tom_core_storage/io.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'first_run.dart' show tomSecretsPrimaryKeyMonths;
import 'primary.dart';
import 'trust.dart';

/// The settings namespace of the product.
const String tomSecretsDeviceNamespace = 'tsm';

/// The settings group the device settings are kept in, as one fragment.
const String tomSecretsDeviceGroup = 'device';

/// The container's group of the device's trust material (keys, recorded
/// approvers and hosts).
const String tomSecretsTrustGroup = 'trust';

/// Where the device settings container's key is kept (DP-15).
enum TomSecretsDeviceKeyMode {
  /// The keychain where one is available, else [vault] (the default).
  auto,

  /// The OS keychain; the service refuses to start without an unlocked one.
  keychain,

  /// The primary vault, overlay entry `@host:<host>/.tom-secrets/device`.
  vault,

  /// A key file (mode 0600; on Windows an ACL of the user) beside the
  /// container.
  keyfile;

  /// The mode named [name].
  static TomSecretsDeviceKeyMode parse(String name) => values.firstWhere(
    (m) => m.name == name,
    orElse: () => throw FormatException(
      'device_key "$name" is not one of '
      '${values.map((m) => m.name).join(', ')}',
    ),
  );
}

/// How a lock policy relocks.
enum TomSecretsLockMode {
  /// (a) Automatic locking is off.
  never,

  /// (b) Relock after an idle period; unlock again with the master password.
  idle,

  /// (c) Relock after an idle period or at the screen lock; unlock again
  /// with the OS unlock (Touch ID, Windows Hello) through the attached app,
  /// which senses the screen lock (part-os-unlock). Without an app, and on
  /// Linux, where there is no OS unlock, it behaves like [idle].
  osUnlock,
}

/// A lock policy.
final class TomSecretsLockPolicy {
  /// A policy of [mode] relocking after [idle] input idle time; [maxUnlocked]
  /// caps the unlocked time whatever the input (null: off); [lockOnSleep]
  /// asks the app to lock the service on system sleep.
  const TomSecretsLockPolicy({
    this.mode = TomSecretsLockMode.idle,
    this.idle = const Duration(minutes: 30),
    this.maxUnlocked,
    this.lockOnSleep = false,
  });

  /// From the stored JSON.
  factory TomSecretsLockPolicy.fromJson(Map<String, Object?> json) {
    const d = TomSecretsLockPolicy();
    return TomSecretsLockPolicy(
      mode:
          TomSecretsLockMode.values
              .where((m) => m.name == json['mode'])
              .firstOrNull ??
          d.mode,
      idle: json['idleSeconds'] is int
          ? Duration(seconds: json['idleSeconds']! as int)
          : d.idle,
      maxUnlocked: json['maxUnlockedSeconds'] is int
          ? Duration(seconds: json['maxUnlockedSeconds']! as int)
          : null,
      lockOnSleep: json['lockOnSleep'] == true,
    );
  }

  /// The mode.
  final TomSecretsLockMode mode;

  /// The idle period of modes (b) and (c).
  final Duration idle;

  /// The longest unlocked time, or null.
  final Duration? maxUnlocked;

  /// Whether the app locks the service on system sleep.
  final bool lockOnSleep;

  /// The JSON kept in the device settings.
  Map<String, Object?> toJson() => {
    'mode': mode.name,
    'idleSeconds': idle.inSeconds,
    'maxUnlockedSeconds': ?maxUnlocked?.inSeconds,
    'lockOnSleep': lockOnSleep,
  };

  /// Whether to lock now, the input having been idle [idle] (null: cannot be
  /// measured, headless) and the service unlocked for [unlockedFor].
  bool shouldLock({required Duration? idle, required Duration unlockedFor}) {
    if (idle == null) return false; // headless never locks automatically
    final max = maxUnlocked;
    if (max != null && unlockedFor >= max) return true;
    return mode != TomSecretsLockMode.never && idle >= this.idle;
  }
}

/// The device settings container's key could not be had.
final class TomSecretsDeviceKeyException implements Exception {
  /// A problem described by [message].
  TomSecretsDeviceKeyException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsDeviceKeyException: $message';
}

/// What the device settings hold (part-service's configuration table). The
/// keys of later parts (approver and approval-link keys, the audit-log key)
/// are added by their parts.
final class TomSecretsDeviceSettings {
  /// Settings with the defaults for every value not given.
  const TomSecretsDeviceSettings({
    this.serviceLock = const TomSecretsLockPolicy(),
    this.appLock = const TomSecretsLockPolicy(idle: Duration(minutes: 10)),
    this.defaultEnvironment,
    this.servedStores,
    this.refreshMinutes = 5,
    this.offlineCache = false,
    this.memoryOnlyApplied = true,
    this.keyExpiryWarningDays = 14,
    this.approvalTimeout = const Duration(seconds: 60),
    this.codeTimeout = const Duration(minutes: 5),
    this.approvalLink,
    this.otherKeyWarningDays = 30,
    this.keyPairAgeMonths = 24,
    this.primaryKeyAgeMonths = tomSecretsPrimaryKeyMonths,
    this.vaultKeyAgeMonths = 12,
    this.memberKeyAgeMonths = 24,
    this.quickUnlockPin = false,
  });

  /// From the stored JSON; a value missing takes its default, and a key
  /// this version does not know (such as the retired `startAtLogin`) is
  /// ignored.
  factory TomSecretsDeviceSettings.fromJson(Map<String, Object?> json) {
    const d = TomSecretsDeviceSettings();
    int intOf(String key, int fallback) =>
        json[key] is int ? json[key]! as int : fallback;
    return TomSecretsDeviceSettings(
      serviceLock: json['serviceLock'] is Map
          ? TomSecretsLockPolicy.fromJson(
              (json['serviceLock']! as Map).cast<String, Object?>(),
            )
          : d.serviceLock,
      appLock: json['appLock'] is Map
          ? TomSecretsLockPolicy.fromJson(
              (json['appLock']! as Map).cast<String, Object?>(),
            )
          : d.appLock,
      defaultEnvironment: json['defaultEnvironment'] as String?,
      servedStores: (json['servedStores'] as List?)?.cast<String>(),
      refreshMinutes: intOf('refreshMinutes', d.refreshMinutes),
      offlineCache: json['offlineCache'] is bool
          ? json['offlineCache']! as bool
          : d.offlineCache,
      // Settings written before vaults were kept in memory by default carry
      // no marker: the service applies the new default to them once.
      memoryOnlyApplied: json['memoryOnlyApplied'] == true,
      keyExpiryWarningDays: intOf(
        'keyExpiryWarningDays',
        d.keyExpiryWarningDays,
      ),
      approvalTimeout: Duration(
        seconds: intOf('approvalTimeoutSeconds', d.approvalTimeout.inSeconds),
      ),
      codeTimeout: Duration(
        seconds: intOf('codeTimeoutSeconds', d.codeTimeout.inSeconds),
      ),
      approvalLink: json['approvalLink'] as String?,
      otherKeyWarningDays: intOf('otherKeyWarningDays', d.otherKeyWarningDays),
      keyPairAgeMonths: intOf('keyPairAgeMonths', d.keyPairAgeMonths),
      primaryKeyAgeMonths: intOf('primaryKeyAgeMonths', d.primaryKeyAgeMonths),
      vaultKeyAgeMonths: intOf('vaultKeyAgeMonths', d.vaultKeyAgeMonths),
      memberKeyAgeMonths: intOf('memberKeyAgeMonths', d.memberKeyAgeMonths),
      quickUnlockPin: json['quickUnlockPin'] == true,
    );
  }

  /// Whether quick unlock with a PIN is on (part-app, Unlocking): the only
  /// thing kept about the PIN. The PIN itself, a verifier and the keys it
  /// seals live in the running service's memory only; after a restart the
  /// app asks for the master password once and then for the PIN again.
  final bool quickUnlockPin;

  /// The service's lock mode (DP-14).
  final TomSecretsLockPolicy serviceLock;

  /// The app's lock mode (DP-14), kept here for the app.
  final TomSecretsLockPolicy appLock;

  /// The machine's default environment (`env`), or null.
  final String? defaultEnvironment;

  /// The stores this machine serves, or null for every one.
  final List<String>? servedStores;

  /// The refresh interval in minutes; 0 switches it off.
  final int refreshMinutes;

  /// Whether the offline cache is kept: the last fetched file of each
  /// `github:` vault on the disk (`<data>/cache`). Off by default: the
  /// vaults are kept in memory only, and a restarted service fetches them
  /// again.
  final bool offlineCache;

  /// Whether these settings have taken the in-memory default: true for every
  /// settings value made now; false only for settings stored before it
  /// (no `memoryOnlyApplied` key), which the service turns the cache off for
  /// once, deleting the cache ([withMemoryOnlyApplied]).
  final bool memoryOnlyApplied;

  /// These settings with the in-memory default applied: the offline cache
  /// off and [memoryOnlyApplied] set; every other value kept.
  TomSecretsDeviceSettings withMemoryOnlyApplied() =>
      TomSecretsDeviceSettings.fromJson({
        ...toJson(),
        'offlineCache': false,
        'memoryOnlyApplied': true,
      });

  /// These settings with [quickUnlockPin] set to [on]; every other value
  /// kept.
  TomSecretsDeviceSettings withQuickUnlockPin(bool on) =>
      TomSecretsDeviceSettings.fromJson({...toJson(), 'quickUnlockPin': on});

  /// How many days before a key expires the reminders start.
  final int keyExpiryWarningDays;

  /// How long a request waits for an unlock or an approval.
  final Duration approvalTimeout;

  /// How long an approval code is valid.
  final Duration codeTimeout;

  /// Where this host's approval link listens (`address:port`, its VPN or
  /// LAN address, never all interfaces); null: no link (protocol.md 9.7).
  final String? approvalLink;

  /// How many days before its due date the reminders of a key other than
  /// the GitHub token start (part-key-rotation, Reminders; DP-85: 30).
  final int otherKeyWarningDays;

  /// The rotation age of the approver and approval-link key pairs, in
  /// months (DP-85: 24).
  final int keyPairAgeMonths;

  /// The rotation age a new key file or repository key of the primary vault
  /// gets, in months (DP-85: 24; rotating them means pairing again).
  final int primaryKeyAgeMonths;

  /// The rotation age a new key file or repository key of every other vault
  /// gets, in months (DP-85: 12).
  final int vaultKeyAgeMonths;

  /// **[C]** The rotation age of the user's member key, in months (DP-85:
  /// 24), counted from its `member-key` entry's creation.
  final int memberKeyAgeMonths;

  /// The JSON kept in the container.
  Map<String, Object?> toJson() => {
    'serviceLock': serviceLock.toJson(),
    'appLock': appLock.toJson(),
    'defaultEnvironment': ?defaultEnvironment,
    'servedStores': ?servedStores,
    'refreshMinutes': refreshMinutes,
    'offlineCache': offlineCache,
    'memoryOnlyApplied': memoryOnlyApplied,
    'keyExpiryWarningDays': keyExpiryWarningDays,
    'approvalTimeoutSeconds': approvalTimeout.inSeconds,
    'codeTimeoutSeconds': codeTimeout.inSeconds,
    'approvalLink': ?approvalLink,
    'otherKeyWarningDays': otherKeyWarningDays,
    'keyPairAgeMonths': keyPairAgeMonths,
    'primaryKeyAgeMonths': primaryKeyAgeMonths,
    'quickUnlockPin': ?(quickUnlockPin ? true : null),
    'vaultKeyAgeMonths': vaultKeyAgeMonths,
    'memberKeyAgeMonths': memberKeyAgeMonths,
  };
}

/// The container's key, by the mode `bootstrap.yaml` names (DP-15).
final class TomSecretsDeviceKeys {
  /// Keys for the container at [containerPath] of [host]; [keychain] the OS
  /// keychain, null where none is available.
  TomSecretsDeviceKeys({
    required this.mode,
    required this.host,
    required this.containerPath,
    this.keychain,
  });

  /// The configured mode.
  final TomSecretsDeviceKeyMode mode;

  /// This machine's host name.
  final String host;

  /// The container's file.
  final String containerPath;

  /// The OS keychain, or null.
  final TomSecretStore? keychain;

  /// The keychain handle of this machine's container key.
  String get keychainHandle => 'tsm.device-settings.$host';

  /// The key file beside the container.
  String get keyFilePath => '$containerPath.key';

  /// The overlay path of the vault entry holding the key.
  List<String> get vaultPath => [
    '@host:$host',
    tomSecretsProductGroup,
    'device',
  ];

  /// Whether a keychain answers (a read that fails means none is
  /// available, or it is locked).
  ///
  /// A store that can say so ([TomSecretStoreAvailability], e.g.
  /// `TomDesktopSecretStore`) is asked; another is probed with a read.
  Future<bool> keychainAvailable() async {
    final store = keychain;
    if (store == null) return false;
    if (store is TomSecretStoreAvailability) {
      return (store as TomSecretStoreAvailability).isAvailable();
    }
    try {
      await store.read(keychainHandle);
      return true;
    } on Object {
      return false;
    }
  }

  /// The mode in effect: [mode], with `auto` decided (keychain where one is
  /// available, else vault). Throws [TomSecretsDeviceKeyException] for
  /// `keychain` without an available keychain: the service refuses to start.
  Future<TomSecretsDeviceKeyMode> effectiveMode() async {
    switch (mode) {
      case TomSecretsDeviceKeyMode.auto:
        return await keychainAvailable()
            ? TomSecretsDeviceKeyMode.keychain
            : TomSecretsDeviceKeyMode.vault;
      case TomSecretsDeviceKeyMode.keychain:
        if (!await keychainAvailable()) {
          throw TomSecretsDeviceKeyException(
            'device_key is keychain, and no unlocked keychain is available',
          );
        }
        return mode;
      case TomSecretsDeviceKeyMode.vault || TomSecretsDeviceKeyMode.keyfile:
        return mode;
    }
  }

  /// The container's key, minted on first use. [primary] is the unlocked
  /// primary vault; with the `vault` mode a new key is written into it and
  /// [savePrimary] saves it.
  Future<String> keyFor({
    required KdbxFile primary,
    required Future<void> Function() savePrimary,
  }) async {
    final effective = await effectiveMode();
    switch (effective) {
      case TomSecretsDeviceKeyMode.keychain:
        final store = keychain!;
        final existing = await store.read(keychainHandle);
        if (existing != null && existing.isNotEmpty) return existing;
        final minted = _mint();
        await store.write(keychainHandle, minted);
        return minted;
      case TomSecretsDeviceKeyMode.vault:
        final entry = _vaultEntry(primary, create: false);
        final existing = entry?.getString(KdbxKeyCommon.PASSWORD)?.getText();
        if (existing != null && existing.isNotEmpty) return existing;
        final minted = _mint();
        _vaultEntry(
          primary,
          create: true,
        )!.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(minted));
        await savePrimary();
        return minted;
      case TomSecretsDeviceKeyMode.keyfile:
        final file = File(keyFilePath);
        if (await file.exists()) {
          final text = (await file.readAsString()).trim();
          if (text.isNotEmpty) return text;
        }
        final minted = _mint();
        await file.parent.create(recursive: true);
        await file.writeAsString('$minted\n', flush: true);
        await _restrict(file.path);
        return minted;
      case TomSecretsDeviceKeyMode.auto:
        throw StateError('auto is decided by effectiveMode');
    }
  }

  KdbxEntry? _vaultEntry(KdbxFile primary, {required bool create}) {
    var group = primary.body.rootGroup;
    for (final name in vaultPath.take(2)) {
      final next = group.groups.where((g) => g.name.get() == name).firstOrNull;
      if (next == null) {
        if (!create) return null;
        group = primary.createGroup(parent: group, name: name);
      } else {
        group = next;
      }
    }
    final existing = group.entries
        .where((e) => e.label == vaultPath.last)
        .firstOrNull;
    if (existing != null || !create) return existing;
    final entry = KdbxEntry.create(primary, group)
      ..setString(KdbxKeyCommon.TITLE, PlainValue(vaultPath.last));
    group.addEntry(entry);
    return entry;
  }

  static String _mint() {
    final random = Random.secure();
    return base64Url.encode(List.generate(32, (_) => random.nextInt(256)));
  }

  static Future<void> _restrict(String path) async {
    final result = Platform.isWindows
        ? await Process.run('icacls', [
            path,
            '/inheritance:r',
            '/grant:r',
            '${Platform.environment['USERNAME']}:F',
          ])
        : await Process.run('chmod', ['600', path]);
    if (result.exitCode != 0) {
      throw TomSecretsDeviceKeyException(
        'the key file could not be restricted: ${result.stderr}',
      );
    }
  }
}

/// The device settings container, opened with its key.
final class TomSecretsDeviceContainer {
  TomSecretsDeviceContainer._(this._container, this.settings, this._trust);

  /// Opens (or creates in memory) the container at [path] with [key].
  static Future<TomSecretsDeviceContainer> open(String path, String key) async {
    final keys = TomKdbxKeyProvider()
      ..setKeyFor(path, Credentials(ProtectedValue.fromString(key)));
    final container = TomKdbxSettingsContainer(
      locator: path,
      storage: TomLocalFileSystemStorage(),
      keys: keys,
      namespace: tomSecretsDeviceNamespace,
    );
    final store = await container.load();
    final fragment = store.readFragment(tomSecretsDeviceGroup);
    final settings = fragment == null
        ? const TomSecretsDeviceSettings()
        : TomSecretsDeviceSettings.fromJson(
            (jsonDecode(fragment) as Map).cast<String, Object?>(),
          );
    final trust = store.readFragment(tomSecretsTrustGroup);
    return TomSecretsDeviceContainer._(
      container,
      settings,
      trust == null
          ? null
          : TomSecretsTrust.fromJson(
              (jsonDecode(trust) as Map).cast<String, Object?>(),
            ),
    );
  }

  TomSecretsTrust? _trust;

  /// The device's trust material (its keys, the approvers and hosts it
  /// recorded), created for [device] (its key pairs dated [now]) and
  /// committed when the container holds none yet.
  Future<TomSecretsTrust> trust(String device, {DateTime? now}) async {
    final existing = _trust;
    if (existing != null) return existing;
    final created = TomSecretsTrust.create(device, now: now);
    await writeTrust(created);
    return created;
  }

  /// Replaces the trust material and commits the container.
  Future<void> writeTrust(TomSecretsTrust value) async {
    _container.store!.writeFragment(
      tomSecretsTrustGroup,
      jsonEncode(value.toJson()),
    );
    await _container.save(message: 'tsm: trust');
    _trust = value;
  }

  final TomKdbxSettingsContainer _container;

  /// The settings as read (defaults for what is not stored).
  TomSecretsDeviceSettings settings;

  /// Replaces the settings and commits the container.
  Future<void> write(TomSecretsDeviceSettings value) async {
    _container.store!.writeFragment(
      tomSecretsDeviceGroup,
      jsonEncode(value.toJson()),
    );
    await _container.save(message: 'tsm: device settings');
    settings = value;
  }
}
