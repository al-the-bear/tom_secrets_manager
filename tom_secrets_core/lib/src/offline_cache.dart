// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The offline cache (part-key-rotation, part-stores, DP-75): on a desktop
/// and on the service, the last file retrieved of each vault, stored exactly
/// as it came from the remote (`<vault>.kdbx` or `<vault>.kdbx.tsmx`, still
/// encrypted), with a record of where and when it came from. It is the
/// cycle's merge base and the file a vault opens from when the remote cannot
/// be reached or refuses the token. The mobile app keeps no cache (it passes
/// none), and neither does a vault marked never to be stored on the device.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'locator.dart';

/// The git blob id of [bytes]: SHA-1 over `blob <length>\0` and the bytes,
/// the id the remote's tree names the file by.
String tomSecretsBlobId(List<int> bytes) => crypto.sha1.convert([
  ...ascii.encode('blob ${bytes.length}'),
  0,
  ...bytes,
]).toString();

/// One cached vault file with its record.
final class TomSecretsCachedVault {
  /// The file [bytes] of [locator] as read at commit [head] at [fetchedAt].
  TomSecretsCachedVault({
    required this.locator,
    required this.bytes,
    required this.head,
    required this.fetchedAt,
    String? blobId,
  }) : blobId = blobId ?? tomSecretsBlobId(bytes);

  /// The vault.
  final String locator;

  /// The file as stored on the remote.
  final Uint8List bytes;

  /// The head the storage read the file at (`TomStorage.headOf`; for
  /// `TomGitHubStorage` the file's blob id), which a save expects.
  final String head;

  /// The file's git blob id.
  final String blobId;

  /// When it was retrieved (UTC).
  final DateTime fetchedAt;

  /// How old the copy is at [now].
  Duration ageAt(DateTime now) => now.toUtc().difference(fetchedAt);

  /// Whether the notice "offline copy" turns into a warning at [now]: older
  /// than [staleAfter] (default [TomSecretsOfflineCache.defaultStaleAfter]).
  /// Never a reason to stop serving it: there is no age limit (DP-75).
  bool isStaleAt(DateTime now, {Duration? staleAfter}) =>
      ageAt(now) > (staleAfter ?? TomSecretsOfflineCache.defaultStaleAfter);

  @override
  String toString() =>
      'TomSecretsCachedVault($locator @ $head, ${bytes.length} bytes, '
      'fetched $fetchedAt)';
}

/// The cache directory: `<root>/<repository>/<path>` per vault, beside it
/// `<path>.tsm-cache.json` with the locator, the head it was read at, the
/// blob id and the time it was fetched. No commit id is kept: the cycle finds
/// its base in the remote's history by the blob id.
final class TomSecretsOfflineCache {
  /// The cache under [root] (the app's or service's data directory,
  /// `cache/`).
  TomSecretsOfflineCache(this.root);

  /// The age after which an offline copy is shown as a warning.
  static const Duration defaultStaleAfter = Duration(days: 7);

  static const _recordSuffix = '.tsm-cache.json';

  /// The cache directory.
  final Directory root;

  /// The file [locator] is cached in: `<owner>/<repository>/<path>` for a
  /// `github:` vault, the locator's name made safe otherwise.
  File fileFor(String locator) {
    final segments = _segments(locator);
    return File([root.path, ...segments].join(Platform.pathSeparator));
  }

  static List<String> _segments(String locator) {
    TomSecretsVaultLocator? parsed;
    try {
      parsed = TomSecretsVaultLocator.parse(locator);
    } on TomSecretsLocatorException {
      parsed = null;
    }
    final raw = switch (parsed) {
      TomSecretsGitHubLocator(:final owner, :final repository, :final path) => [
        owner,
        repository,
        ...path.split('/'),
      ],
      _ => ['_other', ..._safe(locator).split('/')],
    };
    return [
      for (final s in raw)
        if (s.isNotEmpty && s != '.' && s != '..') _safeSegment(s),
    ];
  }

  static String _safe(String locator) =>
      locator.replaceAll(RegExp(r'[:\\]+'), '/');

  static String _safeSegment(String s) =>
      s.replaceAll(RegExp(r'[^A-Za-z0-9._@+-]'), '_');

  File _recordFor(File file) => File('${file.path}$_recordSuffix');

  /// Keeps [vault], replacing what was cached for its locator. The file is
  /// written first and the record last, each through a temporary file and a
  /// rename, so a record never names a file that is not there.
  Future<void> put(TomSecretsCachedVault vault) async {
    final file = fileFor(vault.locator);
    await file.parent.create(recursive: true);
    await _replace(file, vault.bytes);
    await _replace(
      _recordFor(file),
      utf8.encode(
        const JsonEncoder.withIndent('  ').convert({
          'locator': vault.locator,
          'head': vault.head,
          'blobId': vault.blobId,
          'fetchedAt': vault.fetchedAt.toUtc().toIso8601String(),
        }),
      ),
    );
  }

  static Future<void> _replace(File target, List<int> bytes) async {
    final temp = File('${target.path}.tmp');
    await temp.writeAsBytes(bytes, flush: true);
    await temp.rename(target.path);
  }

  /// What is cached for [locator], or null: nothing cached, a record of
  /// another locator, or a file that is not the one its record names (a
  /// write that did not finish).
  Future<TomSecretsCachedVault?> get(String locator) async {
    final file = fileFor(locator);
    final record = _recordFor(file);
    if (!await file.exists() || !await record.exists()) return null;
    final Map<String, dynamic> json;
    try {
      json = jsonDecode(await record.readAsString()) as Map<String, dynamic>;
    } on FormatException {
      return null;
    }
    if (json['locator'] != locator) return null;
    final bytes = await file.readAsBytes();
    final blobId = json['blobId'] as String?;
    if (blobId != tomSecretsBlobId(bytes)) return null;
    return TomSecretsCachedVault(
      locator: locator,
      bytes: bytes,
      head: json['head'] as String,
      blobId: blobId,
      fetchedAt: DateTime.parse(json['fetchedAt'] as String).toUtc(),
    );
  }

  /// Whether nothing is cached: no file below [root] (or no [root]).
  Future<bool> get isEmpty async {
    if (!await root.exists()) return true;
    return !await root
        .list(recursive: true, followLinks: false)
        .any((e) => e is File);
  }

  /// Deletes the whole cache (the setting turned off, the in-memory
  /// default applied): every file is overwritten with zeros, flushed, and
  /// deleted, then [root] itself. Where the file system keeps old blocks
  /// elsewhere (copy-on-write, SSD wear levelling) the overwrite cannot
  /// reach them; the files are encrypted as stored either way. Answers how
  /// many files were deleted.
  Future<int> wipe() async {
    if (!await root.exists()) return 0;
    var count = 0;
    await for (final entry in root.list(recursive: true, followLinks: false)) {
      if (entry is! File) continue;
      final length = await entry.length();
      final out = await entry.open(mode: FileMode.writeOnlyAppend);
      try {
        await out.setPosition(0);
        const chunk = 64 * 1024;
        final zeros = List<int>.filled(chunk, 0);
        for (var left = length; left > 0; left -= chunk) {
          await out.writeFrom(zeros, 0, left < chunk ? left : chunk);
        }
        await out.flush();
      } finally {
        await out.close();
      }
      await entry.delete();
      count++;
    }
    await root.delete(recursive: true);
    return count;
  }

  /// Deletes what is cached for [locator] (a vault removed from the device,
  /// or the device revoked); answers whether anything was there.
  Future<bool> remove(String locator) async {
    final file = fileFor(locator);
    var removed = false;
    for (final f in [file, _recordFor(file)]) {
      if (await f.exists()) {
        await f.delete();
        removed = true;
      }
    }
    return removed;
  }
}
