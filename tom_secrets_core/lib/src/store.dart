// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A store: one KDBX file the service serves under a store name, indexed for
/// resolution — every entry with its logical path, its bindings (the file
/// binding and its overlay groups) and its flat key (part-structure).
library;

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';
import 'metadata.dart';
import 'primary.dart';

final RegExp _storeName = RegExp(r'^[a-z0-9][a-z0-9_-]*$');
final RegExp _dimensionName = RegExp(r'^[a-z][a-z0-9_-]*$');
final RegExp _key = RegExp(r'^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$');

/// The binding an overlay group's [name] stands for (`@host:bomber`), or null
/// when the name is not one.
(String, String)? tomSecretsOverlayBinding(String name) {
  if (!name.startsWith(tomSecretsOverlayPrefix)) return null;
  final colon = name.indexOf(':');
  if (colon < 2 || colon == name.length - 1) return null;
  final dimension = name.substring(1, colon);
  if (!_dimensionName.hasMatch(dimension)) return null;
  return (dimension, name.substring(colon + 1));
}

/// One entry of a store as resolution sees it.
final class TomSecretsIndexedEntry {
  TomSecretsIndexedEntry._({
    required this.store,
    required this.entry,
    required this.path,
    required this.bindings,
    required this.overlayBindings,
    required this.key,
  });

  /// The store's name.
  final String store;

  /// The KDBX entry.
  final KdbxEntry entry;

  /// The logical path: the groups below the root group without the overlay
  /// groups, then the title.
  final List<String> path;

  /// Every binding the entry carries: the file binding and its overlays.
  final Map<String, String> bindings;

  /// The bindings of its overlay groups alone.
  final Map<String, String> overlayBindings;

  /// Its flat key (`tsm.key`), or null.
  final String? key;

  /// Whether it sits in overlay groups.
  bool get isOverlay => overlayBindings.isNotEmpty;

  /// The entry's UUID as 32 lower-case hex digits.
  String get uuid => tomSecretsUuidHex(entry.uuid);

  /// The logical path as one text, segments joined with `/` (unescaped).
  String get pathText => path.join('/');

  /// Whether this entry's logical path is [other].
  bool hasPath(List<String> other) {
    if (other.length != path.length) return false;
    for (var i = 0; i < path.length; i++) {
      if (path[i] != other[i]) return false;
    }
    return true;
  }

  @override
  String toString() => 'TomSecretsIndexedEntry($store/$pathText $bindings)';
}

/// A store: a KDBX file under its store name, with its metadata and index.
final class TomSecretsStore {
  TomSecretsStore._(this.name, this.file, this.metadata) {
    reindex();
  }

  /// The store [file] under [name] (the machine's configuration), else its
  /// metadata's `tsm.store`, else [fileName] without `.kdbx`.
  factory TomSecretsStore.fromFile(
    KdbxFile file, {
    String? name,
    String? fileName,
  }) {
    final metadata = TomSecretsMetadata.read(file);
    final fromFile = fileName
        ?.split(RegExp(r'[/\\]'))
        .last
        .replaceFirst(RegExp(r'\.kdbx$', caseSensitive: false), '');
    final chosen = name ?? metadata.store ?? fromFile;
    if (chosen == null || !_storeName.hasMatch(chosen)) {
      throw ArgumentError.value(chosen, 'name', 'not a store name');
    }
    return TomSecretsStore._(chosen, file, metadata);
  }

  /// The store name.
  final String name;

  /// The open file.
  final KdbxFile file;

  /// Its metadata entry.
  final TomSecretsMetadata metadata;

  final List<TomSecretsIndexedEntry> _entries = [];
  final List<String> _warnings = [];

  /// Every entry resolution may reach (not the recycle bin, the metadata
  /// entry, the grants group, nor an invalid overlay).
  List<TomSecretsIndexedEntry> get entries => List.unmodifiable(_entries);

  /// What the index skipped and why, for the service's log.
  List<String> get warnings => List.unmodifiable(_warnings);

  /// Builds the index again (after the file changed).
  void reindex() {
    _entries.clear();
    _warnings.clear();
    final root = file.body.rootGroup;
    final bin = file.recycleBin;
    void walk(KdbxGroup group, List<String> groups) {
      for (final entry in group.entries) {
        if (groups.isEmpty && entry.label == tomSecretsMetadataTitle) continue;
        _add(entry, groups);
      }
      for (final child in group.groups) {
        if (bin != null && child.uuid == bin.uuid) continue;
        final childName = child.name.get() ?? '';
        if (groups.isEmpty &&
            (childName == tomSecretsGrantsGroup ||
                childName == tomSecretsProductGroup)) {
          continue;
        }
        walk(child, [...groups, childName]);
      }
    }

    walk(root, const []);
  }

  void _add(KdbxEntry entry, List<String> groups) {
    final title = entry.label ?? '';
    String where() => [...groups, title].join('/');
    // Leading overlay groups (the root placement) and trailing ones (inside
    // the entry's own group); none may stand between ordinary groups.
    var lead = 0;
    while (lead < groups.length && groups[lead].startsWith('@')) {
      lead++;
    }
    var trail = groups.length;
    while (trail > lead && groups[trail - 1].startsWith('@')) {
      trail--;
    }
    final middle = groups.sublist(lead, trail);
    if (middle.any((g) => g.startsWith('@'))) {
      _warnings.add('${where()}: an overlay group between ordinary groups');
      return;
    }
    final overlay = <String, String>{};
    final bindings = <String, String>{...metadata.binding};
    for (final g in [...groups.sublist(0, lead), ...groups.sublist(trail)]) {
      final binding = tomSecretsOverlayBinding(g);
      if (binding == null) {
        _warnings.add('${where()}: "$g" is not an overlay group name');
        return;
      }
      final (dimension, value) = binding;
      final bound = bindings[dimension];
      if (bound != null && bound != value) {
        _warnings.add(
          '${where()}: $dimension bound twice ($bound and $value); skipped',
        );
        return;
      }
      bindings[dimension] = value;
      overlay[dimension] = value;
    }
    var key = entry.getString(TomSecretsEntryFields.key)?.getText();
    if (key != null && key.isEmpty) key = null;
    if (key != null && !_key.hasMatch(key)) {
      _warnings.add('${where()}: tsm.key "$key" is not a key; ignored');
      key = null;
    }
    _entries.add(
      TomSecretsIndexedEntry._(
        store: name,
        entry: entry,
        path: List.unmodifiable([...middle, title]),
        bindings: Map.unmodifiable(bindings),
        overlayBindings: Map.unmodifiable(overlay),
        key: key,
      ),
    );
  }
}
