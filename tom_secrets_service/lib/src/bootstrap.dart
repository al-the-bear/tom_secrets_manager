// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The bootstrap file `bootstrap.yaml` (part-service, BP-43): plain text, no
/// secret, the only configuration readable before the unlock.
///
/// ```yaml
/// primary: file:/Users/me/vaults/primary.kdbx   # or github:owner/repo/path
/// cache_dir: /Users/me/.tsm/cache               # default <data>/cache
/// runtime_dir: /run/user/1000/tsm                # default protocol.md 3.1
/// device_key: auto                               # auto|keychain|vault|keyfile
/// device_container: /Users/me/.tsm/device.kdbx  # default <data>/device-settings.kdbx
/// host: bigbeast                                 # default the host name
/// log_level: info                               # info|debug, default info
/// admin_executables:                            # who may administer, besides
///   - /Applications/Tom Secrets Manager.app/Contents/MacOS/tom_secrets_desktop
///                                                # tsm and the app beside the service
/// ```
library;

import 'dart:io';

import 'package:tom_secrets_core/tom_secrets_core.dart'
    show TomSecretsDeviceKeyMode;
import 'package:yaml/yaml.dart';

import 'log.dart';

/// The bootstrap file.
final class TomSecretsBootstrap {
  /// A bootstrap of [primary] with the given places; [dataDirectory] is where
  /// the defaults go.
  TomSecretsBootstrap({
    required this.primary,
    required this.dataDirectory,
    String? cacheDirectory,
    String? deviceContainer,
    this.runtimeDirectory,
    this.deviceKey = TomSecretsDeviceKeyMode.auto,
    this.host,
    this.logLevel = TomSecretsLogLevel.info,
    this.adminExecutables = const [],
  }) : cacheDirectory =
           cacheDirectory ?? '$dataDirectory${Platform.pathSeparator}cache',
       deviceContainer =
           deviceContainer ??
           '$dataDirectory${Platform.pathSeparator}device-settings.kdbx';

  /// The bootstrap file at [path]; its folder is the data directory.
  static Future<TomSecretsBootstrap> read(String path) async =>
      TomSecretsBootstrap.parse(
        await File(path).readAsString(),
        dataDirectory: File(path).parent.path,
      );

  /// The bootstrap of [yaml] with [dataDirectory] for the defaults.
  factory TomSecretsBootstrap.parse(
    String yaml, {
    required String dataDirectory,
  }) {
    final doc = loadYaml(yaml);
    if (doc is! YamlMap) {
      throw const FormatException('bootstrap.yaml is not a mapping');
    }
    String? text(String key) {
      final value = doc[key];
      if (value == null) return null;
      if (value is! String || value.trim().isEmpty) {
        throw FormatException('$key must be a non-empty string');
      }
      return value.trim();
    }

    final primary = text('primary');
    if (primary == null) {
      throw const FormatException('bootstrap.yaml names no primary file');
    }
    return TomSecretsBootstrap(
      primary: primary,
      dataDirectory: dataDirectory,
      cacheDirectory: text('cache_dir'),
      runtimeDirectory: text('runtime_dir'),
      deviceKey: TomSecretsDeviceKeyMode.parse(text('device_key') ?? 'auto'),
      deviceContainer: text('device_container'),
      host: text('host'),
      logLevel: TomSecretsLogLevel.parse(text('log_level') ?? 'info'),
      adminExecutables: switch (doc['admin_executables']) {
        null => const [],
        final YamlList list when list.every((e) => e is String) => [
          for (final e in list) (e as String).trim(),
        ],
        _ => throw const FormatException(
          'admin_executables is a list of paths',
        ),
      },
    );
  }

  /// The primary file's locator.
  final String primary;

  /// The app's data directory.
  final String dataDirectory;

  /// The offline cache's directory.
  final String cacheDirectory;

  /// The runtime directory override, or null.
  final String? runtimeDirectory;

  /// Where the device settings container's key is kept.
  final TomSecretsDeviceKeyMode deviceKey;

  /// The device settings container's file.
  final String deviceContainer;

  /// The host name override, or null.
  final String? host;

  /// How much the operational log says.
  final TomSecretsLogLevel logLevel;

  /// Further executables that may administer the service (the manager app
  /// where it is not installed beside the service, a development build),
  /// besides `tsm` and the app beside the service's own executable.
  final List<String> adminExecutables;

  /// The operational log's file, `<data>/service.log`.
  String get logFile => '$dataDirectory${Platform.pathSeparator}service.log';
}
