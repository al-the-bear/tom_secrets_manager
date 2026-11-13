// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Builds demo vaults in memory (demo data under a demo key; no real secret).
library;

import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

/// The demo key every test file is written with.
final demoCredentials = Credentials(ProtectedValue.fromString('demo-key'));

/// The Argon2id the tests' vaults are keyed with: light, so a test opens a
/// vault in milliseconds (the product's is `tomSecretsDefaultArgon2`).
const testArgon2 = KdbxArgon2(
  type: KdbxArgon2Type.argon2id,
  memory: 1 << 20,
  iterations: 1,
);

/// A new vault as the product creates one, keyed with [testArgon2].
KdbxFile newTestVault(Credentials credentials, String name) =>
    tomSecretsNewVault(credentials, name, argon2: testArgon2);

/// A vault being built.
final class DemoVault {
  /// A new vault; [binding] is its file binding (`tsm.dimensions`), [store]
  /// its `tsm.store`, [config] its `tsm.config`.
  DemoVault({
    Map<String, String> binding = const {},
    String? store,
    String? config,
  }) : file = newTestVault(demoCredentials, 'demo') {
    if (binding.isNotEmpty || store != null || config != null) {
      TomSecretsMetadata(
        store: store,
        binding: binding,
        configYaml: config,
      ).writeTo(file);
    }
  }

  /// The file.
  final KdbxFile file;

  /// Adds an entry at [path] (`Group/Sub/Title`, overlay groups included),
  /// with [password] and the other [fields]; answers it.
  KdbxEntry add(
    String path, {
    String? password,
    String? key,
    Map<String, String> fields = const {},
  }) {
    final parts = path.split('/');
    var group = file.body.rootGroup;
    for (final name in parts.sublist(0, parts.length - 1)) {
      group =
          group.groups.where((g) => g.name.get() == name).firstOrNull ??
          file.createGroup(parent: group, name: name);
    }
    final entry = KdbxEntry.create(file, group);
    group.addEntry(entry);
    entry.label = parts.last;
    if (password != null) {
      entry.setString(
        KdbxKeyCommon.PASSWORD,
        ProtectedValue.fromString(password),
      );
    }
    if (key != null) {
      entry.setString(TomSecretsEntryFields.key, PlainValue(key));
    }
    for (final MapEntry(key: name, value: text) in fields.entries) {
      entry.setString(KdbxKey(name), PlainValue(text));
    }
    return entry;
  }

  /// The store of this vault under [name].
  TomSecretsStore store(String name) =>
      TomSecretsStore.fromFile(file, name: name);
}

/// A resolver over [stores] with [config] (default: the built-ins) for a
/// machine [host] on [platform] with [values].
TomSecretsResolver resolver(
  List<TomSecretsStore> stores, {
  required String host,
  String platform = 'linux',
  Map<String, String> values = const {},
  TomSecretsConfig? config,
}) => TomSecretsResolver(
  stores: stores,
  config: config ?? TomSecretsConfig.builtIn(),
  machine: TomSecretsMachine(host: host, platform: platform, values: values),
);
