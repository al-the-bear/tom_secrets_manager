// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service's operational log (part-service): `service.log` in the data
/// directory, one line per event, rotated by size.
///
/// What it holds is fixed by its callers' discipline and checked by the
/// tests: **never a value, password, key or token**; an exception as its
/// type and a code (an error kind, an OS error number), never its message,
/// which may quote its input; references and client identities at `debug`
/// level only. A line is
///
/// ```text
/// 2026-11-13T18:02:11.123Z INFO unlock stores=3 current=2
/// ```
library;

import 'dart:io';

import 'package:tom_secrets_client/tom_secrets_client.dart'
    show TomSecretsFrameException;
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show KdbxInvalidKeyException, TomSecretsResolveException;

/// How much the log says.
enum TomSecretsLogLevel {
  /// Events and outcomes.
  info,

  /// Also references and client identities.
  debug;

  /// The level `log_level` names (`info`, `debug`).
  static TomSecretsLogLevel parse(String name) => switch (name) {
    'info' => info,
    'debug' => debug,
    _ => throw FormatException('log_level is info or debug, not "$name"'),
  };
}

/// The operational log.
final class TomSecretsLog {
  /// A log at [path] (`<data>/service.log`) at [level], rotated when a line
  /// would take it past [maxBytes], keeping [keep] older files
  /// (`service.log.1` the newest).
  TomSecretsLog(
    this.path, {
    this.level = TomSecretsLogLevel.info,
    this.maxBytes = 1024 * 1024,
    this.keep = 3,
  });

  /// A log that writes nothing.
  TomSecretsLog.off()
    : path = null,
      level = TomSecretsLogLevel.info,
      maxBytes = 0,
      keep = 0;

  /// The file, or null for [TomSecretsLog.off].
  final String? path;

  /// How much it says.
  final TomSecretsLogLevel level;

  /// The size a file is rotated at.
  final int maxBytes;

  /// How many rotated files are kept.
  final int keep;

  /// Whether `debug` lines are written.
  bool get isDebug => level == TomSecretsLogLevel.debug;

  /// An event at `info` level with [fields].
  void info(String event, [Map<String, Object?> fields = const {}]) =>
      _write('INFO', event, fields);

  /// An event at `debug` level: references and identities go here only.
  void debug(String event, [Map<String, Object?> fields = const {}]) {
    if (isDebug) _write('DEBUG', event, fields);
  }

  /// An event that failed with [error]: its type and code, never its
  /// message.
  void error(
    String event,
    Object error, [
    Map<String, Object?> fields = const {},
  ]) => _write('ERROR', event, {
    ...fields,
    'error': error.runtimeType.toString(),
    'code': ?codeOf(error),
  });

  /// The code of [error]: a resolution's error kind, an OS error number, a
  /// known exception's fixed code; null otherwise.
  static String? codeOf(Object error) => switch (error) {
    TomSecretsResolveException(:final kind) => kind.wireName,
    FileSystemException(:final osError?) => '${osError.errorCode}',
    SocketException(:final osError?) => '${osError.errorCode}',
    ProcessException(:final errorCode) => '$errorCode',
    KdbxInvalidKeyException() => 'bad_key',
    TomSecretsFrameException() => 'frame',
    _ => null,
  };

  static final RegExp _unsafe = RegExp(r'[\x00-\x1f\x7f]');

  static String _field(Object? value) {
    final text = switch (value) {
      Iterable() => value.join(','),
      _ => '$value',
    }.replaceAll(_unsafe, '?');
    final short = text.length > 200 ? '${text.substring(0, 200)}…' : text;
    return short.contains(' ') || short.contains('=') || short.isEmpty
        ? '"${short.replaceAll('"', "'")}"'
        : short;
  }

  void _write(String tag, String event, Map<String, Object?> fields) {
    final path = this.path;
    if (path == null) return;
    final line = StringBuffer()
      ..write(DateTime.now().toUtc().toIso8601String())
      ..write(' $tag $event');
    for (final e in fields.entries) {
      if (e.value == null) continue;
      line.write(' ${e.key}=${_field(e.value)}');
    }
    line.write('\n');
    final text = line.toString();
    try {
      final file = File(path);
      if (!file.parent.existsSync()) file.parent.createSync(recursive: true);
      if (file.existsSync() && file.lengthSync() + text.length > maxBytes) {
        _rotate(path);
      }
      file.writeAsStringSync(text, mode: FileMode.append, flush: true);
    } on FileSystemException {
      // The log is best effort: a full disk does not stop the service.
    }
  }

  void _rotate(String path) {
    for (var i = keep; i >= 1; i--) {
      final older = File('$path.$i');
      if (!older.existsSync()) continue;
      if (i == keep) {
        older.deleteSync();
      } else {
        older.renameSync('$path.${i + 1}');
      }
    }
    if (keep == 0) {
      File(path).deleteSync();
    } else {
      File(path).renameSync('$path.1');
    }
  }
}
