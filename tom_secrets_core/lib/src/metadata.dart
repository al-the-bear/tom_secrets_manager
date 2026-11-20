// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The metadata entry `.tom-secrets` in the root group of every file the
/// product writes (part-structure, BP-36).
library;

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'config.dart';
import 'relay.dart';

/// The title of the metadata entry.
const String tomSecretsMetadataTitle = '.tom-secrets';

/// The metadata format this library reads and writes.
const int tomSecretsMetadataFormat = 1;

/// The field names of the metadata entry.
abstract final class TomSecretsMetadataFields {
  /// The metadata format.
  static const format = KdbxKey('tsm.format');

  /// The suggested store name.
  static const store = KdbxKey('tsm.store');

  /// `personal`, `shared` or `system`.
  static const kind = KdbxKey('tsm.kind');

  /// Free text shown in the app.
  static const purpose = KdbxKey('tsm.purpose');

  /// The file binding, `env=prod;region=eu`.
  static const dimensions = KdbxKey('tsm.dimensions');

  /// The shared configuration (primary vault only).
  static const config = KdbxKey('tsm.config');

  /// When this vault's own key file and repository key are due for
  /// rotation (ISO 8601). Read for the primary (part-key-rotation); a
  /// further vault's date is the Expires of its entry in the primary.
  static const keysDue = KdbxKey('tsm.keys-due');

  /// `true`: every signature the ssh-agent makes with a key of this vault
  /// is confirmed by the user (part-os-integration).
  static const sshConfirm = KdbxKey('tsm.ssh-confirm');

  /// The client id of the user's GitHub App for the vault repositories
  /// (part-key-rotation §3, DP-83, DP-155; primary vault only): every device
  /// learns it with the primary and signs in with it.
  static const githubAppClientId = KdbxKey('tsm.github-app-client-id');

  /// **[C]** The relay whose mailbox this shared vault's members use
  /// (part-relay, the relay settings): a relay id (`github:<owner>/<repo>`,
  /// `tsm:<url>`); absent: the vault's own repository's inbox folders.
  static const mailboxRelay = KdbxKey('tsm.mailbox-relay');
}

/// What a vault is for (BP-25).
enum TomSecretsVaultKind {
  /// A person's own secrets (the default).
  personal,

  /// Shared between people.
  shared,

  /// System secrets for processes.
  system,
}

/// Metadata that cannot be read.
final class TomSecretsMetadataException implements Exception {
  /// A metadata problem described by [message].
  TomSecretsMetadataException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsMetadataException: $message';
}

final RegExp _name = RegExp(r'^[a-z][a-z0-9_-]*$');
final RegExp _store = RegExp(r'^[a-z0-9][a-z0-9_-]*$');

/// Reads a file binding (`env=prod;region=eu`); an empty text binds nothing.
Map<String, String> tomSecretsParseFileBinding(String text) {
  final out = <String, String>{};
  for (final part in text.split(';')) {
    final item = part.trim();
    if (item.isEmpty) continue;
    final eq = item.indexOf('=');
    if (eq <= 0 || eq == item.length - 1) {
      throw TomSecretsMetadataException('not a binding: "$item"');
    }
    final name = item.substring(0, eq).trim();
    final value = item.substring(eq + 1).trim();
    if (!_name.hasMatch(name) || value.isEmpty) {
      throw TomSecretsMetadataException('not a binding: "$item"');
    }
    if (out.containsKey(name)) {
      throw TomSecretsMetadataException('the file binds $name twice');
    }
    out[name] = value;
  }
  return out;
}

/// The content of a metadata entry.
final class TomSecretsMetadata {
  /// Metadata with these members.
  TomSecretsMetadata({
    this.format = tomSecretsMetadataFormat,
    this.store,
    this.kind = TomSecretsVaultKind.personal,
    this.purpose,
    Map<String, String> binding = const {},
    this.configYaml,
    this.keysDue,
    this.sshConfirm = false,
    this.githubAppClientId,
    this.mailboxRelay,
  }) : binding = Map.unmodifiable(binding);

  /// The metadata of a file without a metadata entry: no binding, kind
  /// `personal`, the store name from the file name.
  factory TomSecretsMetadata.absent() => TomSecretsMetadata();

  /// The metadata entry of [file] (`.tom-secrets` in the root group), or
  /// [TomSecretsMetadata.absent] when it has none.
  factory TomSecretsMetadata.read(KdbxFile file) {
    final entry = tomSecretsMetadataEntry(file);
    if (entry == null) return TomSecretsMetadata.absent();
    String? text(KdbxKey key) {
      final value = entry.getString(key)?.getText();
      return value == null || value.isEmpty ? null : value;
    }

    final formatText = text(TomSecretsMetadataFields.format);
    final format = formatText == null ? 1 : int.tryParse(formatText);
    if (format == null) {
      throw TomSecretsMetadataException('tsm.format is "$formatText"');
    }
    if (format > tomSecretsMetadataFormat) {
      throw TomSecretsMetadataException(
        'tsm.format $format is newer than this library ($tomSecretsMetadataFormat)',
      );
    }
    final store = text(TomSecretsMetadataFields.store);
    if (store != null && !_store.hasMatch(store)) {
      throw TomSecretsMetadataException(
        'tsm.store is not a store name: $store',
      );
    }
    final kindText = text(TomSecretsMetadataFields.kind);
    final kind = kindText == null
        ? TomSecretsVaultKind.personal
        : TomSecretsVaultKind.values
              .where((k) => k.name == kindText)
              .firstOrNull;
    if (kind == null) {
      throw TomSecretsMetadataException('tsm.kind is "$kindText"');
    }
    return TomSecretsMetadata(
      format: format,
      store: store,
      kind: kind,
      purpose: text(TomSecretsMetadataFields.purpose),
      binding: tomSecretsParseFileBinding(
        text(TomSecretsMetadataFields.dimensions) ?? '',
      ),
      configYaml: text(TomSecretsMetadataFields.config),
      keysDue: switch (text(TomSecretsMetadataFields.keysDue)) {
        null => null,
        final due =>
          DateTime.tryParse(due)?.toUtc() ??
              (throw TomSecretsMetadataException('tsm.keys-due is "$due"')),
      },
      sshConfirm: text(TomSecretsMetadataFields.sshConfirm) == 'true',
      githubAppClientId: text(TomSecretsMetadataFields.githubAppClientId),
      mailboxRelay: switch (text(TomSecretsMetadataFields.mailboxRelay)) {
        null => null,
        final relay => _relayId(relay),
      },
    );
  }

  static TomSecretsRelayId _relayId(String text) {
    try {
      return TomSecretsRelayId.parse(text);
    } on FormatException {
      throw TomSecretsMetadataException('tsm.mailbox-relay is "$text"');
    }
  }

  /// The metadata format.
  final int format;

  /// The suggested store name, or null.
  final String? store;

  /// What the vault is for.
  final TomSecretsVaultKind kind;

  /// Free text, or null.
  final String? purpose;

  /// The file binding: every entry of the file carries these bindings.
  final Map<String, String> binding;

  /// `tsm.config` as written, or null (only the primary vault has one).
  final String? configYaml;

  /// When the vault's own key file and repository key are due for rotation
  /// (`tsm.keys-due`), or null. The primary's is reminded of; a further
  /// vault's date is the Expires of its entry in the primary.
  final DateTime? keysDue;

  /// Whether the ssh-agent confirms every signature with a key of this
  /// vault (`tsm.ssh-confirm`).
  final bool sshConfirm;

  /// The client id of the user's GitHub App (`tsm.github-app-client-id`,
  /// the primary only), or null when none is registered.
  final String? githubAppClientId;

  /// **[C]** The relay whose mailbox the shared vault's members use
  /// (`tsm.mailbox-relay`), or null for the vault's own repository.
  final TomSecretsRelayId? mailboxRelay;

  /// This metadata with the members given replaced.
  TomSecretsMetadata copyWith({
    String? store,
    TomSecretsVaultKind? kind,
    String? purpose,
    Map<String, String>? binding,
    String? configYaml,
    DateTime? keysDue,
    bool? sshConfirm,
    String? githubAppClientId,
    bool clearGithubAppClientId = false,
    TomSecretsRelayId? mailboxRelay,
    bool clearMailboxRelay = false,
  }) => TomSecretsMetadata(
    format: format,
    store: store ?? this.store,
    kind: kind ?? this.kind,
    purpose: purpose ?? this.purpose,
    binding: binding ?? this.binding,
    configYaml: configYaml ?? this.configYaml,
    keysDue: keysDue ?? this.keysDue,
    sshConfirm: sshConfirm ?? this.sshConfirm,
    githubAppClientId: clearGithubAppClientId
        ? null
        : githubAppClientId ?? this.githubAppClientId,
    mailboxRelay: clearMailboxRelay ? null : mailboxRelay ?? this.mailboxRelay,
  );

  /// The shared configuration of `tsm.config`, or null when absent.
  TomSecretsConfig? get config =>
      configYaml == null ? null : TomSecretsConfig.parse(configYaml!);

  /// Writes this metadata into [file]'s metadata entry, creating it when the
  /// file has none.
  void writeTo(KdbxFile file) {
    final root = file.body.rootGroup;
    var entry = tomSecretsMetadataEntry(file);
    if (entry == null) {
      entry = KdbxEntry.create(file, root);
      root.addEntry(entry);
      entry.label = tomSecretsMetadataTitle;
    }
    final target = entry;
    void set(KdbxKey key, String? value) => target.setString(
      key,
      value == null || value.isEmpty ? null : PlainValue(value),
    );
    target.modify(() {
      set(TomSecretsMetadataFields.format, '$format');
      set(TomSecretsMetadataFields.store, store);
      set(TomSecretsMetadataFields.kind, kind.name);
      set(TomSecretsMetadataFields.purpose, purpose);
      set(
        TomSecretsMetadataFields.dimensions,
        binding.entries.map((e) => '${e.key}=${e.value}').join(';'),
      );
      set(TomSecretsMetadataFields.config, configYaml);
      set(TomSecretsMetadataFields.keysDue, keysDue?.toUtc().toIso8601String());
      set(TomSecretsMetadataFields.sshConfirm, sshConfirm ? 'true' : null);
      set(TomSecretsMetadataFields.githubAppClientId, githubAppClientId);
      set(TomSecretsMetadataFields.mailboxRelay, mailboxRelay?.text);
    });
  }
}

/// The metadata entry of [file], or null.
KdbxEntry? tomSecretsMetadataEntry(KdbxFile file) {
  for (final entry in file.body.rootGroup.entries) {
    if (entry.label == tomSecretsMetadataTitle) return entry;
  }
  return null;
}
