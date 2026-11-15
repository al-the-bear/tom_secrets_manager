// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Resolution: from a reference and the request's dimension values to one
/// entry's field (part-structure: candidates, match, rank, ambiguity, field;
/// DP-12, DP-90, DP-120).
library;

import 'dart:typed_data';
import 'dart:io';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart'
    show
        TomSecretReference,
        TomSecretKeyTarget,
        TomSecretPathTarget,
        TomSecretUuidTarget,
        TomSecretsClientException,
        TomSecretsErrorKind;

import 'config.dart';
import 'mapping.dart';
import 'store.dart';
import 'totp.dart';

/// A reference that does not resolve: `not_found`, `ambiguous`, `malformed`
/// or `denied`, with the protocol's `details` (never a value).
final class TomSecretsResolveException implements Exception {
  /// A failure of [kind] with [message] and [details].
  TomSecretsResolveException(
    this.kind,
    this.message, {
    this.details = const {},
  });

  /// The protocol's error kind.
  final TomSecretsErrorKind kind;

  /// For people.
  final String message;

  /// `reason`, `dimensions`, `candidates`, `entry`, `field` (protocol.md 10).
  final Map<String, Object?> details;

  /// `details['reason']`, when there is one.
  String? get reason => details['reason'] as String?;

  @override
  String toString() =>
      'TomSecretsResolveException(${kind.wireName}'
      '${reason == null ? '' : ', $reason'}): $message';
}

/// The machine a request is resolved for: its current value per dimension.
final class TomSecretsMachine {
  /// A machine [host] on [platform] with the [values] of `env` and the other
  /// declared dimensions (unset ones absent).
  const TomSecretsMachine({
    required this.host,
    required this.platform,
    this.values = const {},
  });

  /// This machine: its short host name in lower case (unless [host] overrides
  /// it), its OS as `platform`, and [values].
  factory TomSecretsMachine.current({
    String? host,
    Map<String, String> values = const {},
  }) => TomSecretsMachine(
    host: host ?? Platform.localHostname.split('.').first.toLowerCase(),
    platform: Platform.operatingSystem,
    values: values,
  );

  /// The `host` dimension's value.
  final String host;

  /// The `platform` dimension's value.
  final String platform;

  /// The values of `env` and the declared dimensions.
  final Map<String, String> values;

  /// The machine's value of [dimension], or null when unset.
  String? valueOf(String dimension) => switch (dimension) {
    'host' => host,
    'platform' => platform,
    _ => values[dimension],
  };
}

/// One kept candidate with its rank vector (one rank per dimension, in
/// priority order: 2 bound to the request's value, 1 bound to `default` and
/// kept by the fallback, 0 unbound).
final class TomSecretsRankedCandidate {
  TomSecretsRankedCandidate._(this.entry, this.vector);

  /// The candidate.
  final TomSecretsIndexedEntry entry;

  /// Its ranks, in priority order.
  final List<int> vector;

  @override
  String toString() => '$entry ${vector.join(',')}';
}

/// A resolved reference: the winning entry and the field's value.
final class TomSecretsResolution {
  TomSecretsResolution._({
    required this.entry,
    required this.field,
    required this.value,
    required this.requestValues,
    required this.ranked,
  });

  /// The winner.
  final TomSecretsIndexedEntry entry;

  /// The field read.
  final String field;

  /// The field's value.
  final TomSecretsFieldValue value;

  /// The request's value per dimension.
  final Map<String, String> requestValues;

  /// Every kept candidate, best first.
  final List<TomSecretsRankedCandidate> ranked;

  /// The winner's bindings (`value.bound`).
  Map<String, String> get bound => entry.bindings;

  /// When the winner last changed.
  DateTime? get modified => entry.entry.times.lastModificationTime.get();

  /// When the winner expires, when its Expires flag is set.
  DateTime? get expires => entry.entry.times.expires.get() == true
      ? entry.entry.times.expiryTime.get()
      : null;

  /// The winner's type.
  TomSecretsEntryType get type => TomSecretsEntryType.of(
    entry.entry.getString(TomSecretsEntryFields.type)?.getText(),
  );
}

/// One candidate of an explained request (step 1) and what step 2 did with
/// it: kept with its rank vector, or dropped by one of its bindings.
final class TomSecretsExplainedCandidate {
  const TomSecretsExplainedCandidate._(
    this.entry, {
    this.vector,
    this.dropDimension,
    this.dropBound,
  });

  /// The candidate.
  final TomSecretsIndexedEntry entry;

  /// Its ranks in priority order (2 bound to the request's value, 1 bound
  /// to `default` and kept by the fallback, 0 unbound), or null when it was
  /// dropped.
  final List<int>? vector;

  /// The dimension whose binding dropped it, or null when kept.
  final String? dropDimension;

  /// The value it is bound to on [dropDimension], or null when kept.
  final String? dropBound;

  /// Whether it was kept.
  bool get kept => vector != null;

  @override
  String toString() => kept
      ? '$entry ${vector!.join(',')}'
      : '$entry dropped by $dropDimension:$dropBound';
}

/// How an explained request ends (step 3).
enum TomSecretsExplainOutcome {
  /// One candidate ranks best: it serves the request.
  resolved,

  /// Several candidates rank equal: the request is refused.
  ambiguous,

  /// No candidate is kept: the request finds nothing.
  notFound,
}

/// A request explained step by step ([TomSecretsResolver.explain]): the
/// request's values, every candidate kept (best first) or dropped (in the
/// order found), and the outcome with its winner or the tied candidates.
final class TomSecretsExplanation {
  const TomSecretsExplanation._({
    required this.requestValues,
    required this.candidates,
    required this.outcome,
  });

  /// The request's value per dimension, in priority order.
  final Map<String, String> requestValues;

  /// Every candidate: the kept ones best first, then the dropped ones.
  final List<TomSecretsExplainedCandidate> candidates;

  /// How the request ends.
  final TomSecretsExplainOutcome outcome;

  /// The kept candidates, best first.
  List<TomSecretsExplainedCandidate> get kept =>
      candidates.where((c) => c.kept).toList();

  /// The dropped candidates.
  List<TomSecretsExplainedCandidate> get dropped =>
      candidates.where((c) => !c.kept).toList();

  /// The winner when [outcome] is resolved, else null.
  TomSecretsIndexedEntry? get winner =>
      outcome == TomSecretsExplainOutcome.resolved
      ? candidates.first.entry
      : null;

  /// The candidates ranking equal best when [outcome] is ambiguous.
  List<TomSecretsIndexedEntry> get tied {
    if (outcome != TomSecretsExplainOutcome.ambiguous) return const [];
    final best = candidates.first.vector!;
    return [
      for (final c in kept)
        if (TomSecretsResolver._compare(c.vector!, best) == 0) c.entry,
    ];
  }
}

/// Resolves references over [stores] under [config] for [machine].
final class TomSecretsResolver {
  /// A resolver.
  TomSecretsResolver({
    required List<TomSecretsStore> stores,
    required this.config,
    required this.machine,
  }) : stores = List.unmodifiable(stores) {
    final names = <String>{};
    for (final s in stores) {
      if (!names.add(s.name)) {
        throw ArgumentError('store ${s.name} is served twice');
      }
    }
  }

  /// The stores served.
  final List<TomSecretsStore> stores;

  /// The shared configuration.
  final TomSecretsConfig config;

  /// The machine.
  final TomSecretsMachine machine;

  /// Resolves [reference] with the call's [dimensions] and [field] (the
  /// field when the reference names none); [now] is the time of a `totp`
  /// code.
  TomSecretsResolution resolve(
    String reference, {
    Map<String, String> dimensions = const {},
    String? field,
    DateTime? now,
  }) {
    final TomSecretReference parsed;
    try {
      parsed = TomSecretReference.parse(reference);
    } on TomSecretsClientException catch (e) {
      throw TomSecretsResolveException(
        TomSecretsErrorKind.malformed,
        e.message,
        details: e.details,
      );
    }
    if (parsed.fieldGiven && field != null) {
      throw TomSecretsResolveException(
        TomSecretsErrorKind.malformed,
        'the field is named in the reference and as field',
        details: {'reason': 'field_twice'},
      );
    }
    final fieldName = field ?? parsed.field;
    if (tomSecretsIsPasskeyField(fieldName)) {
      throw TomSecretsResolveException(
        TomSecretsErrorKind.denied,
        'a passkey field is never served',
        details: {'reason': 'reserved_field'},
      );
    }
    final values = requestValues(parsed, dimensions);
    final ranked = [
      for (final c in _explain(parsed, values))
        if (c.vector case final vector?)
          TomSecretsRankedCandidate._(c.entry, vector),
    ];
    if (ranked.isEmpty) {
      throw TomSecretsResolveException(
        TomSecretsErrorKind.notFound,
        'no entry for $reference with ${_describe(values)}',
        details: {'dimensions': values},
      );
    }
    final best = ranked.where(
      (r) => _compare(r.vector, ranked.first.vector) == 0,
    );
    if (best.length > 1) {
      throw TomSecretsResolveException(
        TomSecretsErrorKind.ambiguous,
        '${best.length} entries rank equal for $reference',
        details: {
          'candidates': [for (final r in best) _location(r.entry)],
        },
      );
    }
    final winner = ranked.first.entry;
    return TomSecretsResolution._(
      entry: winner,
      field: fieldName,
      value: _field(winner, fieldName, now ?? DateTime.now()),
      requestValues: values,
      ranked: List.unmodifiable(ranked),
    );
  }

  /// Explains [reference] with the call's [dimensions] the way [resolve]
  /// ranks it, without reading a field: the request's values, every
  /// candidate (step 1) kept with its rank vector or dropped by the binding
  /// that drops it (step 2), and the outcome (step 3). Throws
  /// [TomSecretsResolveException] (`malformed`) for a reference or dimension
  /// [resolve] refuses before ranking.
  TomSecretsExplanation explain(
    String reference, {
    Map<String, String> dimensions = const {},
  }) {
    final TomSecretReference parsed;
    try {
      parsed = TomSecretReference.parse(reference);
    } on TomSecretsClientException catch (e) {
      throw TomSecretsResolveException(
        TomSecretsErrorKind.malformed,
        e.message,
        details: e.details,
      );
    }
    final values = requestValues(parsed, dimensions);
    final candidates = _explain(parsed, values);
    final kept = candidates.where((c) => c.kept).toList();
    final TomSecretsExplainOutcome outcome;
    if (kept.isEmpty) {
      outcome = TomSecretsExplainOutcome.notFound;
    } else if (kept.length > 1 &&
        _compare(kept[0].vector!, kept[1].vector!) == 0) {
      outcome = TomSecretsExplainOutcome.ambiguous;
    } else {
      outcome = TomSecretsExplainOutcome.resolved;
    }
    return TomSecretsExplanation._(
      requestValues: values,
      candidates: List.unmodifiable(candidates),
      outcome: outcome,
    );
  }

  /// Steps 1 and 2 for [parsed] with the request's [values]: every
  /// candidate, the kept ones best first, then the dropped ones in the order
  /// found. [resolve] and [explain] both rank through here.
  List<TomSecretsExplainedCandidate> _explain(
    TomSecretReference parsed,
    Map<String, String> values,
  ) {
    final kept = <TomSecretsExplainedCandidate>[];
    final dropped = <TomSecretsExplainedCandidate>[];
    for (final c in _candidates(parsed)) {
      final rank = _rank(c, values);
      if (rank.vector != null) {
        kept.add(TomSecretsExplainedCandidate._(c, vector: rank.vector));
      } else {
        dropped.add(
          TomSecretsExplainedCandidate._(
            c,
            dropDimension: rank.dimension,
            dropBound: rank.bound,
          ),
        );
      }
    }
    kept.sort((a, b) => _compare(b.vector!, a.vector!));
    return [...kept, ...dropped];
  }

  /// The request's value of every declared dimension: a binding in the
  /// brackets, else one passed beside the reference ([call]), else the
  /// machine's value, else the configured default, else `default`.
  Map<String, String> requestValues(
    TomSecretReference parsed,
    Map<String, String> call,
  ) {
    final brackets = {for (final b in parsed.qualifiers) b.dimension: b.value};
    for (final name in {...brackets.keys, ...call.keys}) {
      if (config.dimension(name) == null) {
        throw TomSecretsResolveException(
          TomSecretsErrorKind.malformed,
          'dimension $name is not declared',
          details: {'reason': 'undeclared_dimension', 'dimension': name},
        );
      }
      if (brackets.containsKey(name) &&
          call.containsKey(name) &&
          brackets[name] != call[name]) {
        throw TomSecretsResolveException(
          TomSecretsErrorKind.malformed,
          'dimension $name is ${brackets[name]} in the brackets and '
          '${call[name]} beside them',
          details: {'reason': 'conflicting_dimension', 'dimension': name},
        );
      }
    }
    return {
      for (final d in config.dimensions)
        d.name:
            brackets[d.name] ??
            call[d.name] ??
            machine.valueOf(d.name) ??
            d.defaultValue ??
            tomSecretsDefaultValue,
    };
  }

  List<TomSecretsIndexedEntry> _candidates(TomSecretReference parsed) {
    final out = <TomSecretsIndexedEntry>[];
    void add(TomSecretsIndexedEntry e) {
      if (!out.any((o) => identical(o, e))) out.add(e);
    }

    switch (parsed.target) {
      case TomSecretPathTarget(:final store, :final segments):
        final s = _store(store);
        if (s == null) return out;
        s.entries.where((e) => e.hasPath(segments)).forEach(add);
      case TomSecretUuidTarget(:final store, :final uuid):
        final s = _store(store);
        if (s == null) return out;
        final entry = s.entries.where((e) => e.uuid == uuid).firstOrNull;
        if (entry == null) return out;
        add(entry);
        s.entries
            .where((e) => e.isOverlay && e.hasPath(entry.path))
            .forEach(add);
      case TomSecretKeyTarget(:final key):
        for (final s in stores) {
          for (final keyed in s.entries.where((e) => e.key == key)) {
            add(keyed);
            s.entries
                .where(
                  (e) =>
                      e.isOverlay &&
                      e.hasPath(keyed.path) &&
                      (e.key == null || e.key == key),
                )
                .forEach(add);
          }
        }
    }
    return out;
  }

  TomSecretsStore? _store(String name) =>
      stores.where((s) => s.name == name).firstOrNull;

  /// The candidate's rank vector, or the binding that drops it in step 2.
  ({List<int>? vector, String? dimension, String? bound}) _rank(
    TomSecretsIndexedEntry c,
    Map<String, String> values,
  ) {
    for (final MapEntry(key: dimension, value: bound) in c.bindings.entries) {
      final d = config.dimension(dimension);
      // Bound on a dimension nobody declared.
      if (d == null) return (vector: null, dimension: dimension, bound: bound);
      final requested = values[dimension]!;
      final keep =
          bound == requested ||
          (bound == tomSecretsDefaultValue && d.fallbackToDefault);
      if (!keep) return (vector: null, dimension: dimension, bound: bound);
    }
    final vector = [
      for (final d in config.dimensions)
        switch (c.bindings[d.name]) {
          null => 0,
          final bound when bound == values[d.name] => 2,
          _ => 1, // bound to `default`, kept by the fallback
        },
    ];
    return (vector: vector, dimension: null, bound: null);
  }

  static int _compare(List<int> a, List<int> b) {
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
  }

  static Map<String, Object?> _location(TomSecretsIndexedEntry e) => {
    'store': e.store,
    'path': e.pathText,
    'uuid': e.uuid,
  };

  static String _describe(Map<String, String> values) =>
      values.entries.map((e) => '${e.key}=${e.value}').join(', ');

  TomSecretsFieldValue _field(
    TomSecretsIndexedEntry winner,
    String field,
    DateTime now,
  ) {
    TomSecretsResolveException missing() => TomSecretsResolveException(
      TomSecretsErrorKind.notFound,
      '${winner.store}/${winner.pathText} has no field $field',
      details: {'entry': _location(winner), 'field': field},
    );
    if (field == TomSecretsEntryFields.totp) {
      final totp = TomSecretsTotp.fromEntry(winner.entry);
      if (totp == null) throw missing();
      return TomSecretsFieldValue.text(totp.code(now), isProtected: true);
    }
    if (field.startsWith(TomSecretsEntryFields.attachmentPrefix)) {
      final name = field.substring(
        TomSecretsEntryFields.attachmentPrefix.length,
      );
      final binary = winner.entry.getBinary(KdbxKey(name));
      if (binary == null) throw missing();
      // A copy: the field value consumes its buffer, and the attachment
      // stays in the vault.
      return TomSecretsFieldValue.bytes(
        Uint8List.fromList(binary.value),
        isProtected: binary.isProtected,
      );
    }
    final value = winner.entry.getString(KdbxKey(field));
    if (value is ProtectedValue) {
      // Its bytes, never a String: binaryValue is a copy the field value
      // consumes.
      return TomSecretsFieldValue.utf8Bytes(
        value.binaryValue,
        isProtected: true,
      );
    }
    final text = value?.getText();
    if (value == null || text == null) throw missing();
    return TomSecretsFieldValue.text(text);
  }
}
