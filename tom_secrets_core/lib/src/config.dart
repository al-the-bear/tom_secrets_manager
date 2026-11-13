// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The shared configuration `tsm.config` (the primary vault's metadata
/// entry): the dimensions with their priority, configured defaults and
/// `fallback_to_default` (BP-39, BP-43, DP-12, DP-90), and the stores per
/// environment.
library;

import 'package:yaml/yaml.dart';

/// The reserved value every dimension has (DP-12).
const String tomSecretsDefaultValue = 'default';

/// The dimensions every configuration has, in their default priority order.
const List<String> tomSecretsBuiltInDimensions = ['host', 'platform', 'env'];

/// The values of the built-in `platform` dimension.
const Set<String> tomSecretsPlatforms = {
  'macos',
  'linux',
  'windows',
  'ios',
  'android',
};

final RegExp _name = RegExp(r'^[a-z][a-z0-9_-]*$');
final RegExp _store = RegExp(r'^[a-z0-9][a-z0-9_-]*$');

/// A configuration that cannot be read.
final class TomSecretsConfigException implements Exception {
  /// A configuration problem described by [message].
  TomSecretsConfigException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsConfigException: $message';
}

/// One dimension of the configuration.
final class TomSecretsDimension {
  /// A dimension [name], with an optional configured [defaultValue] and the
  /// [fallbackToDefault] switch (off unless set, DP-90).
  const TomSecretsDimension(
    this.name, {
    this.defaultValue,
    this.fallbackToDefault = false,
  });

  /// The dimension's name.
  final String name;

  /// The configured default, used on a machine that sets no value; null when
  /// there is none (DP-12).
  final String? defaultValue;

  /// Whether an entry bound `<name>:default` also serves a request naming
  /// another value, ranked below an entry bound to that value (DP-90).
  final bool fallbackToDefault;

  /// Whether this is `host`, `platform` or `env`.
  bool get isBuiltIn => tomSecretsBuiltInDimensions.contains(name);
}

/// Where a store's file is kept (BP-43).
sealed class TomSecretsStoreLocation {
  const TomSecretsStoreLocation();
}

/// A file on the local disk.
final class TomSecretsLocalLocation extends TomSecretsStoreLocation {
  /// The file at [path].
  const TomSecretsLocalLocation(this.path);

  /// The file's path.
  final String path;
}

/// A file in a GitHub repository.
final class TomSecretsGitHubLocation extends TomSecretsStoreLocation {
  /// The file [path] in [repository] (`owner/name`).
  const TomSecretsGitHubLocation(this.repository, this.path);

  /// `owner/name`.
  final String repository;

  /// The file's path in the repository.
  final String path;
}

/// One store of an environment: its name and where its file is.
final class TomSecretsStoreSpec {
  /// The store [name] at [location].
  const TomSecretsStoreSpec(this.name, this.location);

  /// The store name.
  final String name;

  /// Where its file is.
  final TomSecretsStoreLocation location;
}

/// The shared configuration.
///
/// `dimensions` lists the dimensions in priority order. The built-in
/// dimensions the list leaves out come first, in the default order `host`,
/// `platform`, `env`, then the listed ones: a list that only sets `env`'s
/// default or fallback keeps the default order, and a declared `region` ranks
/// below the built-ins. Without a list the order is `host`, `platform`, `env`.
final class TomSecretsConfig {
  /// A configuration of [dimensions] (priority order) and [stores] (by
  /// environment).
  TomSecretsConfig({
    List<TomSecretsDimension> dimensions = const [],
    Map<String, List<TomSecretsStoreSpec>> stores = const {},
  }) : dimensions = List.unmodifiable(_withBuiltIns(dimensions)),
       stores = Map.unmodifiable({
         for (final MapEntry(:key, :value) in stores.entries)
           key: List<TomSecretsStoreSpec>.unmodifiable(value),
       });

  /// The configuration of a vault without `tsm.config`: the built-ins in
  /// their default order, no defaults, no fallback, no stores.
  factory TomSecretsConfig.builtIn() => TomSecretsConfig();

  /// Reads the YAML of `tsm.config`:
  ///
  /// ```yaml
  /// dimensions:
  ///   - name: host
  ///   - name: env
  ///     default: dev
  ///     fallback_to_default: false
  ///   - name: region
  /// stores:
  ///   prod:
  ///     - name: prod
  ///       github: {repository: al-the-bear/vault, path: prod.kdbx}
  ///   dev:
  ///     - name: dev
  ///       path: /srv/tsm/dev.kdbx
  /// ```
  factory TomSecretsConfig.parse(String yaml) {
    final Object? doc;
    try {
      doc = loadYaml(yaml);
    } on YamlException catch (e) {
      throw TomSecretsConfigException('tsm.config is not YAML: ${e.message}');
    }
    if (doc == null) return TomSecretsConfig.builtIn();
    if (doc is! Map) {
      throw TomSecretsConfigException('tsm.config is not a mapping');
    }
    final dimensions = <TomSecretsDimension>[];
    final names = <String>{};
    final rawDimensions = doc['dimensions'];
    if (rawDimensions != null && rawDimensions is! List) {
      throw TomSecretsConfigException('dimensions is not a list');
    }
    for (final raw in (rawDimensions as List? ?? const [])) {
      if (raw is! Map || raw['name'] is! String) {
        throw TomSecretsConfigException('a dimension without a name: $raw');
      }
      final name = raw['name'] as String;
      if (!_name.hasMatch(name)) {
        throw TomSecretsConfigException('not a dimension name: $name');
      }
      if (!names.add(name)) {
        throw TomSecretsConfigException('dimension $name is declared twice');
      }
      final defaultValue = raw['default'];
      if (defaultValue != null &&
          (defaultValue is! String || defaultValue.isEmpty)) {
        throw TomSecretsConfigException('the default of $name is no value');
      }
      final fallback = raw['fallback_to_default'] ?? false;
      if (fallback is! bool) {
        throw TomSecretsConfigException(
          'fallback_to_default of $name is not true or false',
        );
      }
      if (name == 'platform' &&
          defaultValue != null &&
          !tomSecretsPlatforms.contains(defaultValue) &&
          defaultValue != tomSecretsDefaultValue) {
        throw TomSecretsConfigException('not a platform: $defaultValue');
      }
      dimensions.add(
        TomSecretsDimension(
          name,
          defaultValue: defaultValue as String?,
          fallbackToDefault: fallback,
        ),
      );
    }
    final stores = <String, List<TomSecretsStoreSpec>>{};
    final rawStores = doc['stores'];
    if (rawStores != null && rawStores is! Map) {
      throw TomSecretsConfigException('stores is not a mapping');
    }
    for (final MapEntry(:key, :value)
        in (rawStores as Map? ?? const {}).entries) {
      if (key is! String || value is! List) {
        throw TomSecretsConfigException('stores of $key is not a list');
      }
      final seen = <String>{};
      stores[key] = [for (final s in value) _storeSpec(key, s, seen)];
    }
    return TomSecretsConfig(dimensions: dimensions, stores: stores);
  }

  static TomSecretsStoreSpec _storeSpec(
    String environment,
    Object? raw,
    Set<String> seen,
  ) {
    if (raw is! Map || raw['name'] is! String) {
      throw TomSecretsConfigException('a store of $environment has no name');
    }
    final name = raw['name'] as String;
    if (!_store.hasMatch(name)) {
      throw TomSecretsConfigException('not a store name: $name');
    }
    if (!seen.add(name)) {
      throw TomSecretsConfigException('store $name twice in $environment');
    }
    final path = raw['path'];
    final github = raw['github'];
    if ((path == null) == (github == null)) {
      throw TomSecretsConfigException(
        'store $name needs exactly one of path and github',
      );
    }
    if (path is String && path.isNotEmpty) {
      return TomSecretsStoreSpec(name, TomSecretsLocalLocation(path));
    }
    if (github is Map &&
        github['repository'] is String &&
        github['path'] is String) {
      return TomSecretsStoreSpec(
        name,
        TomSecretsGitHubLocation(
          github['repository'] as String,
          github['path'] as String,
        ),
      );
    }
    throw TomSecretsConfigException('store $name has no usable location');
  }

  static List<TomSecretsDimension> _withBuiltIns(
    List<TomSecretsDimension> declared,
  ) => [
    for (final name in tomSecretsBuiltInDimensions)
      if (!declared.any((d) => d.name == name)) TomSecretsDimension(name),
    ...declared,
  ];

  /// The dimensions in priority order (built-ins included).
  final List<TomSecretsDimension> dimensions;

  /// The stores of each environment.
  final Map<String, List<TomSecretsStoreSpec>> stores;

  /// The dimension [name], or null when it is not declared.
  TomSecretsDimension? dimension(String name) {
    for (final d in dimensions) {
      if (d.name == name) return d;
    }
    return null;
  }

  /// This configuration as `tsm.config` YAML (what [TomSecretsConfig.parse]
  /// reads back).
  String toYaml() {
    final out = StringBuffer('dimensions:\n');
    for (final d in dimensions) {
      out.writeln('  - name: ${d.name}');
      if (d.defaultValue != null) {
        out.writeln('    default: ${_scalar(d.defaultValue!)}');
      }
      if (d.fallbackToDefault) out.writeln('    fallback_to_default: true');
    }
    if (stores.isNotEmpty) {
      out.writeln('stores:');
      for (final MapEntry(:key, :value) in stores.entries) {
        out.writeln('  ${_scalar(key)}:');
        for (final s in value) {
          out.writeln('    - name: ${s.name}');
          switch (s.location) {
            case TomSecretsLocalLocation(:final path):
              out.writeln('      path: ${_scalar(path)}');
            case TomSecretsGitHubLocation(:final repository, :final path):
              out
                ..writeln('      github:')
                ..writeln('        repository: ${_scalar(repository)}')
                ..writeln('        path: ${_scalar(path)}');
          }
        }
      }
    }
    return out.toString();
  }

  // A double-quoted YAML scalar, so no value is read as another type.
  static String _scalar(String text) =>
      '"${text.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';
}
