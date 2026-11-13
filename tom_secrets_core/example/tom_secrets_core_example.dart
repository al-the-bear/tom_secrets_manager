// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// Builds a demo vault in memory (demo data under a demo key) and resolves a
// key on two machines: the shared entry, and a host's overlay.

import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

void main() {
  final file = KdbxFormat().create(
    Credentials(ProtectedValue.fromString('demo-key')),
    'demo',
  );
  final root = file.body.rootGroup;
  void add(List<String> groups, String title, String password) {
    var group = root;
    for (final name in groups) {
      group =
          group.groups.where((g) => g.name.get() == name).firstOrNull ??
          file.createGroup(parent: group, name: name);
    }
    final entry = KdbxEntry.create(file, group);
    group.addEntry(entry);
    entry
      ..label = title
      ..setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString(password))
      ..setString(TomSecretsEntryFields.key, PlainValue('telegram.bot_token'));
  }

  add(['Telegram'], 'Bot', 'demo-shared-token');
  add(['@host:bomber', 'Telegram'], 'Bot', 'demo-bomber-token');
  final store = TomSecretsStore.fromFile(file, name: 'fleet');

  for (final host in ['mbp', 'bomber']) {
    final resolver = TomSecretsResolver(
      stores: [store],
      config: TomSecretsConfig.builtIn(),
      machine: TomSecretsMachine(host: host, platform: 'linux'),
    );
    final resolution = resolver.resolve('telegram.bot_token');
    print(
      '$host: ${resolution.entry.store}/${resolution.entry.pathText} '
      'bound ${resolution.bound} -> ${resolution.value.text}',
    );
    resolution.value.dispose();
  }
}
