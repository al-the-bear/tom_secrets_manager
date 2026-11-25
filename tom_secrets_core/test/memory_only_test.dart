// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Vaults in memory only by default: the device settings' offline cache is
/// off for new settings, settings stored before carry no marker and take
/// the default once, and the cache's wipe overwrites every file before it
/// deletes it. Demo data only.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

void main() {
  test('new settings keep no offline cache and have the default applied', () {
    const fresh = TomSecretsDeviceSettings();
    expect(fresh.offlineCache, isFalse);
    expect(fresh.memoryOnlyApplied, isTrue);
    final back = TomSecretsDeviceSettings.fromJson(fresh.toJson());
    expect(back.offlineCache, isFalse);
    expect(back.memoryOnlyApplied, isTrue);
  });

  test('settings stored before carry no marker; the default applied turns '
      'the cache off and keeps every other value', () {
    final old = TomSecretsDeviceSettings.fromJson({
      'offlineCache': true,
      'refreshMinutes': 7,
      'servedStores': ['team'],
    });
    expect(old.offlineCache, isTrue);
    expect(old.memoryOnlyApplied, isFalse);
    final applied = old.withMemoryOnlyApplied();
    expect(applied.offlineCache, isFalse);
    expect(applied.memoryOnlyApplied, isTrue);
    expect(applied.refreshMinutes, 7);
    expect(applied.servedStores, ['team']);

    // A user who turns the cache on afterwards keeps it on.
    final chosen = TomSecretsDeviceSettings.fromJson({
      ...applied.toJson(),
      'offlineCache': true,
    });
    expect(chosen.offlineCache, isTrue);
    expect(chosen.memoryOnlyApplied, isTrue);
  });

  test('wipe overwrites every cached file with zeros before it deletes '
      'it, then the folder', () async {
    final root = Directory('.dart_tool/memory_only_test')
      ..createSync(recursive: true);
    final dir = root.createTempSync('run');
    addTearDown(() {
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    });
    final cache = TomSecretsOfflineCache(Directory('${dir.path}/cache'));
    expect(await cache.isEmpty, isTrue);
    final bytes = Uint8List.fromList(List.generate(200000, (i) => i % 251 + 1));
    await cache.put(
      TomSecretsCachedVault(
        locator: 'github:demo-owner/demo-vaults/primary.kdbx',
        bytes: bytes,
        head: 'demo-head',
        blobId: tomSecretsBlobId(bytes),
        fetchedAt: DateTime.utc(2026, 11, 25),
      ),
    );
    expect(await cache.isEmpty, isFalse);
    final file = cache.fileFor('github:demo-owner/demo-vaults/primary.kdbx');
    // A hard link keeps the file's blocks readable after its name is gone:
    // what it reads then is what the wipe left in them.
    final witness = '${dir.path}/witness';
    if (!Platform.isWindows) {
      expect((await Process.run('ln', [file.path, witness])).exitCode, 0);
    }
    expect(await cache.wipe(), 2, reason: 'the file and its record');
    expect(cache.root.existsSync(), isFalse);
    if (!Platform.isWindows) {
      final left = File(witness).readAsBytesSync();
      expect(left, hasLength(bytes.length));
      expect(left.every((b) => b == 0), isTrue, reason: 'overwritten');
    }
    expect(await cache.isEmpty, isTrue);
    expect(await cache.wipe(), 0);
  });
}
