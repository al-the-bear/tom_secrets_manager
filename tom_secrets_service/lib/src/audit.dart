// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The audit log (part-service): who asked for what and what they got, never
/// a value. Not in the device settings container (a commit per `get` would
/// rewrite the whole KDBX file): an append-only file per day in the data
/// directory (`audit/<yyyy-mm-dd>.log`), one record per line, each
/// XChaCha20-Poly1305-encrypted under the audit-log key the container holds;
/// flushed in batches, files past the retention (default 90 days) deleted.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

/// One audit record (protocol.md 6.3 `audit.query`).
final class TomSecretsAuditRecord {
  /// A record of [refs] asked by [identity] on [host] at [time], ending in
  /// [outcome] (`allowed`, `denied:<reason>`, `timeout`, an error kind), by
  /// the grant [grantId] or the approver [approver], for the entries
  /// [entries] (their UUIDs).
  const TomSecretsAuditRecord({
    required this.time,
    required this.host,
    required this.identity,
    required this.refs,
    required this.outcome,
    this.grantId,
    this.approver,
    this.entries = const [],
    this.ssh,
  });

  /// When.
  final DateTime time;

  /// The host.
  final String host;

  /// The client's identity (protocol.md 7.1).
  final Map<String, Object?> identity;

  /// The references.
  final List<String> refs;

  /// The outcome.
  final String outcome;

  /// The grant that answered, when one did.
  final String? grantId;

  /// The approver that answered a prompt, when one did.
  final String? approver;

  /// The resolved entries' UUIDs.
  final List<String> entries;

  /// An ssh-agent signature's key, destination and purpose
  /// (`TomSecretsSshUse.toJson`), or null.
  final Map<String, Object?>? ssh;

  /// The record as `audit.query` answers it.
  Map<String, Object?> toJson() => {
    'time': time.toUtc().toIso8601String(),
    'host': host,
    'identity': identity,
    'refs': refs,
    'outcome': outcome,
    'grantId': ?grantId,
    'approver': ?approver,
    if (entries.isNotEmpty) 'entries': entries,
    'ssh': ?ssh,
  };

  /// From [toJson].
  factory TomSecretsAuditRecord.fromJson(Map<String, Object?> json) =>
      TomSecretsAuditRecord(
        time: DateTime.parse(json['time']! as String),
        host: json['host']! as String,
        identity: (json['identity']! as Map).cast(),
        refs: (json['refs']! as List).cast(),
        outcome: json['outcome']! as String,
        grantId: json['grantId'] as String?,
        approver: json['approver'] as String?,
        entries: ((json['entries'] as List?) ?? const []).cast(),
        ssh: (json['ssh'] as Map?)?.cast(),
      );
}

/// The audit log in [directory] under [key] (32 bytes).
final class TomSecretsAuditLog {
  /// A log; records are written every [flushInterval], files older than
  /// [retention] deleted.
  TomSecretsAuditLog(
    this.directory,
    List<int> key, {
    this.flushInterval = const Duration(seconds: 2),
    this.retention = const Duration(days: 90),
  }) : _key = SecretKey(List<int>.from(key));

  /// The directory (`<data>/audit`).
  final String directory;

  /// How often buffered records are written.
  final Duration flushInterval;

  /// How long a day's file is kept.
  final Duration retention;

  final SecretKey _key;
  final Xchacha20 _cipher = Xchacha20.poly1305Aead();
  final List<TomSecretsAuditRecord> _buffer = [];
  Timer? _timer;
  Future<void> _writing = Future<void>.value();

  String _fileOf(DateTime day) {
    final d = day.toUtc();
    String two(int v) => v.toString().padLeft(2, '0');
    return '$directory${Platform.pathSeparator}${d.year}-${two(d.month)}-${two(d.day)}.log';
  }

  /// Adds [record]; it is written with the next batch.
  void add(TomSecretsAuditRecord record) {
    _buffer.add(record);
    _timer ??= Timer(flushInterval, () => unawaited(flush()));
  }

  /// Writes the buffered records now.
  Future<void> flush() => _writing = _writing.then((_) async {
    _timer?.cancel();
    _timer = null;
    if (_buffer.isEmpty) return;
    final batch = [..._buffer];
    _buffer.clear();
    await Directory(directory).create(recursive: true);
    final byFile = <String, StringBuffer>{};
    for (final record in batch) {
      final nonce = _nonce();
      final box = await _cipher.encrypt(
        utf8.encode(jsonEncode(record.toJson())),
        secretKey: _key,
        nonce: nonce,
      );
      (byFile[_fileOf(record.time)] ??= StringBuffer()).writeln(
        base64.encode([...nonce, ...box.cipherText, ...box.mac.bytes]),
      );
    }
    for (final MapEntry(key: path, value: text) in byFile.entries) {
      await File(
        path,
      ).writeAsString(text.toString(), mode: FileMode.append, flush: true);
    }
    await _rotate();
  });

  static List<int> _nonce() {
    final r = Random.secure();
    return List.generate(24, (_) => r.nextInt(256));
  }

  Future<void> _rotate() async {
    final dir = Directory(directory);
    if (!await dir.exists()) return;
    final cutoff = DateTime.now().toUtc().subtract(retention);
    await for (final f in dir.list()) {
      final name = f.uri.pathSegments.last;
      final m = RegExp(r'^(\d{4})-(\d{2})-(\d{2})\.log$').firstMatch(name);
      if (m == null) continue;
      final day = DateTime.utc(
        int.parse(m[1]!),
        int.parse(m[2]!),
        int.parse(m[3]!),
      );
      if (day.add(const Duration(days: 1)).isBefore(cutoff)) {
        await f.delete();
      }
    }
  }

  /// The records from [from] to [to], of a client whose identity names
  /// [subject] (its exe, script or interpreter) and of reference [ref], when
  /// given; records that do not decrypt are left out.
  Future<List<TomSecretsAuditRecord>> query({
    required DateTime from,
    required DateTime to,
    String? subject,
    String? ref,
  }) async {
    await flush();
    final out = <TomSecretsAuditRecord>[];
    var day = DateTime.utc(from.year, from.month, from.day);
    final last = to.toUtc();
    while (!day.isAfter(last)) {
      final file = File(_fileOf(day));
      if (await file.exists()) {
        for (final line in await file.readAsLines()) {
          final record = await _decrypt(line);
          if (record == null ||
              record.time.isBefore(from) ||
              record.time.isAfter(to)) {
            continue;
          }
          if (subject != null &&
              ![
                'exe',
                'script',
                'interpreter',
              ].any((k) => record.identity[k] == subject)) {
            continue;
          }
          if (ref != null && !record.refs.contains(ref)) continue;
          out.add(record);
        }
      }
      day = day.add(const Duration(days: 1));
    }
    return out;
  }

  Future<TomSecretsAuditRecord?> _decrypt(String line) async {
    try {
      final bytes = base64.decode(line.trim());
      final clear = await _cipher.decrypt(
        SecretBox(
          bytes.sublist(24, bytes.length - 16),
          nonce: bytes.sublist(0, 24),
          mac: Mac(bytes.sublist(bytes.length - 16)),
        ),
        secretKey: _key,
      );
      return TomSecretsAuditRecord.fromJson(
        (jsonDecode(utf8.decode(clear)) as Map).cast(),
      );
    } on Object {
      return null;
    }
  }

  /// Writes what is buffered and stops the timer.
  Future<void> close() => flush();
}
