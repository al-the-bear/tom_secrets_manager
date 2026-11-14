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
