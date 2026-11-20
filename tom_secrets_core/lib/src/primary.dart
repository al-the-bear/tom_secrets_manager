// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The primary vault's group `.tom-secrets/vaults` (part-stores, BP-8): one
/// entry per further vault with its locator, master password, key file,
/// outer key and GitHub token, so unlocking the primary opens everything.
library;

import 'dart:typed_data';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'locator.dart';

/// The root group holding the product's own groups (never resolved into).
const String tomSecretsProductGroup = '.tom-secrets';

/// The subgroup holding the further vaults.
const String tomSecretsVaultsGroup = 'vaults';

/// The fields of a vault entry.
abstract final class TomSecretsVaultFields {
  /// The vault's locator.
  static const locator = KdbxKey('tsm.locator');

  /// The repository's outer key (base64), when it has one.
  static const outerKey = KdbxKey('tsm.outer-key');

  /// A GitHub token for the vault's repository, when it differs from the
  /// primary's.
  static const githubToken = KdbxKey('tsm.github-token');

  /// When [githubToken] expires (ISO 8601), as recorded when it was entered.
  static const githubTokenExpires = KdbxKey('tsm.github-token-expires');

  /// The attachment holding the key file.
  static const keyFile = KdbxKey('keyfile');

  /// **[C]** The next master password of a guided rotation
  /// (part-key-rotation), until its switch.
  static const nextPassword = KdbxKey('tsm.next-password');

  /// **[C]** The next repository key (base64) of a guided rotation.
  static const nextOuterKey = KdbxKey('tsm.next-outer-key');

  /// **[C]** The attachment holding the next key file of a guided rotation.
  static const nextKeyFile = KdbxKey('next-keyfile');

  /// **[C]** The repository key (base64) the vault's file keeps a second slot
  /// for after a guided rotation's switch, until its finish.
  static const previousOuterKey = KdbxKey('tsm.previous-outer-key');
}

/// What the primary keeps about one further vault.
final class TomSecretsVaultKeys {
  /// A vault [name] at [locator] opened with [password] (and [keyFile]).
  TomSecretsVaultKeys({
    required this.name,
    required this.locator,
    this.password,
    this.keyFile,
    this.outerKey,
    this.githubToken,
    this.githubTokenExpires,
    this.expires,
    this.nextPassword,
    this.nextKeyFile,
    this.nextOuterKey,
    this.previousOuterKey,
  });

  /// The entry's title: the vault's name.
  final String name;

  /// Where the vault is.
  final String locator;

  /// Its master password, or null.
  final String? password;

  /// Its key file, or null.
  final Uint8List? keyFile;

  /// The repository's outer key (base64), or null.
  final String? outerKey;

  /// A GitHub token for its repository, or null (the primary's applies).
  final String? githubToken;

  /// When [githubToken] expires, as recorded when it was entered, or null.
  final DateTime? githubTokenExpires;

  /// When its key file and repository key are due for rotation: the entry's
  /// KDBX Expires (part-key-rotation), or null when the entry does not
  /// expire.
  final DateTime? expires;

  /// **[C]** The next master password of a guided rotation (prepared, not
  /// switched yet), or null.
  final String? nextPassword;

  /// **[C]** The next key file of a guided rotation, or null.
  final Uint8List? nextKeyFile;

  /// **[C]** The next repository key (base64) of a guided rotation, or null.
  final String? nextOuterKey;

  /// **[C]** The old repository key (base64) whose slot the file keeps
  /// during a guided rotation's migration period (after the switch, until
  /// the finish), or null.
  final String? previousOuterKey;

  /// **[C]** Whether a guided rotation prepared next keys for it.
  bool get hasNext =>
      nextPassword != null || nextKeyFile != null || nextOuterKey != null;

  /// **[C]** The repository keys its file is written with: [outerKey], and
  /// [previousOuterKey] during a migration period (`,`-separated, the
  /// newest first: `tomSecretsJoinOuterKeys`), or null.
  String? get writtenOuterKeys {
    final keys = [?outerKey, ?previousOuterKey];
    return keys.isEmpty ? null : keys.join(',');
  }

  /// **[C]** The same keys with the changes given; `clearNext` drops the next
  /// keys, `clearPrevious` the previous repository key.
  TomSecretsVaultKeys copyWith({
    String? githubToken,
    DateTime? githubTokenExpires,
    String? password,
    Uint8List? keyFile,
    bool removeKeyFile = false,
    String? outerKey,
    String? nextPassword,
    Uint8List? nextKeyFile,
    String? nextOuterKey,
    bool clearNext = false,
    String? previousOuterKey,
    bool clearPrevious = false,
    DateTime? expires,
  }) => TomSecretsVaultKeys(
    name: name,
    locator: locator,
    password: password ?? this.password,
    keyFile: removeKeyFile ? null : (keyFile ?? this.keyFile),
    outerKey: outerKey ?? this.outerKey,
    githubToken: githubToken ?? this.githubToken,
    githubTokenExpires: githubTokenExpires ?? this.githubTokenExpires,
    expires: expires ?? this.expires,
    nextPassword: clearNext ? null : (nextPassword ?? this.nextPassword),
    nextKeyFile: clearNext ? null : (nextKeyFile ?? this.nextKeyFile),
    nextOuterKey: clearNext ? null : (nextOuterKey ?? this.nextOuterKey),
    previousOuterKey: clearPrevious
        ? null
        : (previousOuterKey ?? this.previousOuterKey),
  );

  /// The credentials that open the vault (`Credentials.composite` takes the
  /// key file's bytes and derives the key itself).
  Credentials get credentials => Credentials.composite(
    password == null ? null : ProtectedValue.fromString(password!),
    keyFile,
  );

  @override
  String toString() => 'TomSecretsVaultKeys($name, $locator, ***)';
}

/// A primary vault's further vaults.
final class TomSecretsPrimaryVaults {
  /// The further vaults of the primary vault [file] at [primaryLocator].
  TomSecretsPrimaryVaults(this.file, {this.primaryLocator});

  /// The primary vault.
  final KdbxFile file;

  /// The primary's own locator, which its list may not hold.
  final String? primaryLocator;

  KdbxGroup? _group({bool create = false}) {
    final root = file.body.rootGroup;
    var product = root.groups
        .where((g) => g.name.get() == tomSecretsProductGroup)
        .firstOrNull;
    if (product == null) {
      if (!create) return null;
      product = file.createGroup(parent: root, name: tomSecretsProductGroup);
    }
    final vaults = product.groups
        .where((g) => g.name.get() == tomSecretsVaultsGroup)
        .firstOrNull;
    if (vaults != null || !create) return vaults;
    return file.createGroup(parent: product, name: tomSecretsVaultsGroup);
  }

  /// Every further vault, in file order. An entry without a readable locator,
  /// or naming the primary itself, is left out.
  List<TomSecretsVaultKeys> list() => [
    for (final e in _group()?.entries ?? const <KdbxEntry>[]) ?_read(e),
  ];

  /// The vault [name], or null.
  TomSecretsVaultKeys? byName(String name) =>
      list().where((v) => v.name == name).firstOrNull;

  TomSecretsVaultKeys? _read(KdbxEntry e) {
    final locator = e.getString(TomSecretsVaultFields.locator)?.getText();
    if (locator == null || locator == primaryLocator) return null;
    try {
      TomSecretsVaultLocator.parse(locator);
    } on TomSecretsLocatorException {
      return null;
    }
    String? text(KdbxKey key) {
      final t = e.getString(key)?.getText();
      return t == null || t.isEmpty ? null : t;
    }

    return TomSecretsVaultKeys(
      name: e.label ?? '',
      locator: locator,
      password: text(KdbxKeyCommon.PASSWORD),
      keyFile: e.getBinary(TomSecretsVaultFields.keyFile)?.value,
      outerKey: text(TomSecretsVaultFields.outerKey),
      githubToken: text(TomSecretsVaultFields.githubToken),
      githubTokenExpires: switch (text(
        TomSecretsVaultFields.githubTokenExpires,
      )) {
        null => null,
        final at => DateTime.tryParse(at)?.toUtc(),
      },
      expires: e.times.expires.get() == true
          ? e.times.expiryTime.get()?.toUtc()
          : null,
      nextPassword: text(TomSecretsVaultFields.nextPassword),
      nextKeyFile: e.getBinary(TomSecretsVaultFields.nextKeyFile)?.value,
      nextOuterKey: text(TomSecretsVaultFields.nextOuterKey),
      previousOuterKey: text(TomSecretsVaultFields.previousOuterKey),
    );
  }

  /// Writes [keys] (a new entry, or the entry of the same name): adding a
  /// vault, or changing its password in the same save as the vault itself.
  ///
  /// Throws [ArgumentError] for the primary's own locator or a bad locator.
  void put(TomSecretsVaultKeys keys) {
    TomSecretsVaultLocator.parse(keys.locator);
    if (keys.locator == primaryLocator) {
      throw ArgumentError.value(keys.locator, 'locator', 'the primary itself');
    }
    final group = _group(create: true)!;
    var entry = group.entries.where((e) => e.label == keys.name).firstOrNull;
    if (entry == null) {
      entry = KdbxEntry.create(file, group);
      group.addEntry(entry);
      entry.label = keys.name;
    }
    final target = entry;
    void set(KdbxKey key, String? value, {bool secret = true}) =>
        target.setString(
          key,
          value == null
              ? null
              : (secret ? ProtectedValue.fromString(value) : PlainValue(value)),
        );
    target.modify(() {
      set(TomSecretsVaultFields.locator, keys.locator, secret: false);
      set(KdbxKeyCommon.PASSWORD, keys.password);
      set(TomSecretsVaultFields.outerKey, keys.outerKey);
      set(TomSecretsVaultFields.githubToken, keys.githubToken);
      set(
        TomSecretsVaultFields.githubTokenExpires,
        keys.githubTokenExpires?.toUtc().toIso8601String(),
        secret: false,
      );
      target.times.expires.set(keys.expires != null);
      if (keys.expires != null) target.times.expiryTime.set(keys.expires);
      target.removeBinary(TomSecretsVaultFields.keyFile);
      if (keys.keyFile != null) {
        target.createBinary(
          isProtected: true,
          name: TomSecretsVaultFields.keyFile.key,
          bytes: keys.keyFile!,
        );
      }
      set(TomSecretsVaultFields.nextPassword, keys.nextPassword);
      set(TomSecretsVaultFields.nextOuterKey, keys.nextOuterKey);
      set(TomSecretsVaultFields.previousOuterKey, keys.previousOuterKey);
      target.removeBinary(TomSecretsVaultFields.nextKeyFile);
      if (keys.nextKeyFile != null) {
        target.createBinary(
          isProtected: true,
          name: TomSecretsVaultFields.nextKeyFile.key,
          bytes: keys.nextKeyFile!,
        );
      }
    });
  }

  /// Removes the vault [name]; answers whether it was there.
  bool remove(String name) {
    final group = _group();
    final entry = group?.entries.where((e) => e.label == name).firstOrNull;
    if (entry == null) return false;
    file.deleteEntry(entry);
    return true;
  }
}

/// **[C]** The subgroup of the product group holding the primary's own next
/// keys during a guided rotation of them (part-key-rotation).
const String tomSecretsNextKeysGroup = 'next-keys';

/// **[C]** The primary vault's own keys during a guided rotation: the new key
/// file and repository key every device takes into its keychain before the
/// switch (the primary's keys live on the devices, not in the primary), and
/// after the switch the old repository key its file keeps a slot for until
/// the finish. Kept in `.tom-secrets/next-keys` as the entry `primary`.
final class TomSecretsPrimaryNextKeys {
  /// The primary's next keys: [keyFile] and [outerKey] (base64), and after
  /// the switch [previousOuterKey].
  const TomSecretsPrimaryNextKeys({
    this.keyFile,
    this.outerKey,
    this.previousOuterKey,
  });

  /// The new key file, or null (the key file does not change, or the
  /// primary has none).
  final Uint8List? keyFile;

  /// The new repository key (base64), or null.
  final String? outerKey;

  /// After the switch: the old repository key the file keeps a slot for.
  final String? previousOuterKey;

  static const _entry = 'primary';

  static KdbxGroup? _group(KdbxFile file, {bool create = false}) {
    final root = file.body.rootGroup;
    var product = root.groups
        .where((g) => g.name.get() == tomSecretsProductGroup)
        .firstOrNull;
    if (product == null) {
      if (!create) return null;
      product = file.createGroup(parent: root, name: tomSecretsProductGroup);
    }
    final group = product.groups
        .where((g) => g.name.get() == tomSecretsNextKeysGroup)
        .firstOrNull;
    if (group != null || !create) return group;
    return file.createGroup(parent: product, name: tomSecretsNextKeysGroup);
  }

  /// The primary [file]'s next keys, or null when no rotation of them runs.
  static TomSecretsPrimaryNextKeys? of(KdbxFile file) {
    final e = _group(file)?.entries.where((e) => e.label == _entry).firstOrNull;
    if (e == null) return null;
    String? text(KdbxKey key) {
      final t = e.getString(key)?.getText();
      return t == null || t.isEmpty ? null : t;
    }

    return TomSecretsPrimaryNextKeys(
      keyFile: e.getBinary(TomSecretsVaultFields.keyFile)?.value,
      outerKey: text(TomSecretsVaultFields.outerKey),
      previousOuterKey: text(TomSecretsVaultFields.previousOuterKey),
    );
  }

  /// Writes these keys into the primary [file] (over earlier ones).
  void writeTo(KdbxFile file) {
    final group = _group(file, create: true)!;
    var entry = group.entries.where((e) => e.label == _entry).firstOrNull;
    if (entry == null) {
      entry = KdbxEntry.create(file, group);
      group.addEntry(entry);
      entry.label = _entry;
    }
    final target = entry;
    target.modify(() {
      target.setString(
        TomSecretsVaultFields.outerKey,
        outerKey == null ? null : ProtectedValue.fromString(outerKey!),
      );
      target.setString(
        TomSecretsVaultFields.previousOuterKey,
        previousOuterKey == null
            ? null
            : ProtectedValue.fromString(previousOuterKey!),
      );
      target.removeBinary(TomSecretsVaultFields.keyFile);
      if (keyFile != null) {
        target.createBinary(
          isProtected: true,
          name: TomSecretsVaultFields.keyFile.key,
          bytes: keyFile!,
        );
      }
    });
  }

  /// Removes the primary [file]'s next keys for good (no recycle bin: they
  /// are keys); answers whether there were any.
  static bool clear(KdbxFile file) {
    final e = _group(file)?.entries.where((e) => e.label == _entry).firstOrNull;
    if (e == null) return false;
    file.deletePermanently(e);
    return true;
  }

  @override
  String toString() => 'TomSecretsPrimaryNextKeys(***)';
}
