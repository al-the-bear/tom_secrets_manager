// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Who is asking (part-protocol, BP-19, BP-21, DP-18; protocol.md 7.1): the
/// identity of a measured process, interpreted clients recognised by their
/// interpreter and script, file hashes cached by path, size and modification
/// time, and pinning by hash with its development relaxation.
library;

import 'dart:io';

import 'package:crypto/crypto.dart';

/// What a process is, measured by the service (never what it says).
final class TomSecretsProcessInfo {
  /// Process [pid] running [exe] (its real path) with [args] (`argv[1..]`),
  /// in [cwd], started at [startTime] (an OS value, compared only for
  /// equality), child of [parentPid], owned by [uid].
  const TomSecretsProcessInfo({
    required this.pid,
    required this.exe,
    required this.args,
    required this.cwd,
    required this.startTime,
    required this.parentPid,
    required this.uid,
  });

  /// The process id.
  final int pid;

  /// The executable's real path.
  final String exe;

  /// The arguments after the program name; null when they could not be read.
  final List<String>? args;

  /// The working directory, or null when it could not be read.
  final String? cwd;

  /// The start time, as the OS gives it.
  final int startTime;

  /// The parent's process id, or null.
  final int? parentPid;

  /// The OS user: a number on Linux and macOS, a SID string on Windows.
  final Object uid;
}

/// The identity of a client (protocol.md 7.1): shown, matched and audited.
final class TomSecretsIdentity {
  /// An identity of [kind] (`exe`, `script`, `interpreter`).
  const TomSecretsIdentity({
    required this.kind,
    required this.exe,
    required this.args,
    required this.cwd,
    required this.uid,
    this.pid,
    this.exeHash,
    this.interpreter,
    this.script,
    this.scriptHash,
    this.packageRoot,
    this.parent,
    this.complete = true,
  });

  /// Whether the arguments and the working directory could be read (an
  /// elevated Windows process may hide them): a grant that needs them is
  /// not matched on an incomplete identity (`unidentifiable`, never a
  /// guess). Not part of the protocol's identity object.
  final bool complete;

  /// `exe`, `script` or `interpreter`.
  final String kind;

  /// The executable's real path.
  final String exe;

  /// Its SHA-256 in hex, when computed (for a pinned grant).
  final String? exeHash;

  /// The interpreter (the executable) of an interpreted client.
  final String? interpreter;

  /// The script (a real path), module, target or class.
  final String? script;

  /// The script file's SHA-256 in hex, when it is a file.
  final String? scriptHash;

  /// The package root (`dart run`, `python -m`) or class path (`java -cp`).
  final String? packageRoot;

  /// The arguments.
  final List<String> args;

  /// The working directory ('' when it could not be read).
  final String cwd;

  /// The parent process: `{exe, args?}`.
  final Map<String, Object?>? parent;

  /// The OS user: a number, or a SID string on Windows.
  final Object uid;

  /// The measured process id (not part of the protocol's identity).
  final int? pid;

  /// The same identity with [exeHash].
  TomSecretsIdentity withExeHash(String exeHash) => TomSecretsIdentity(
    kind: kind,
    exe: exe,
    args: args,
    cwd: cwd,
    uid: uid,
    pid: pid,
    exeHash: exeHash,
    interpreter: interpreter,
    script: script,
    scriptHash: scriptHash,
    packageRoot: packageRoot,
    parent: parent,
    complete: complete,
  );

  /// An identity as [toJson] wrote it (a paired host's prompt, read by the
  /// approving device). Throws [FormatException] for a record that is not
  /// one.
  factory TomSecretsIdentity.fromJson(Map<String, Object?> json) {
    final kind = json['kind'];
    final exe = json['exe'];
    final args = json['args'];
    final cwd = json['cwd'];
    if (kind is! String || exe is! String || args is! List || cwd is! String) {
      throw const FormatException('an identity names kind, exe, args, cwd');
    }
    return TomSecretsIdentity(
      kind: kind,
      exe: exe,
      args: [for (final a in args) '$a'],
      cwd: cwd,
      uid: json['uid'] ?? 0,
      exeHash: json['exeHash'] as String?,
      interpreter: json['interpreter'] as String?,
      script: json['script'] as String?,
      scriptHash: json['scriptHash'] as String?,
      packageRoot: json['packageRoot'] as String?,
      parent: (json['parent'] as Map?)?.cast<String, Object?>(),
    );
  }

  /// The protocol's identity object (7.1).
  Map<String, Object?> toJson() => {
    'kind': kind,
    'exe': exe,
    'exeHash': ?exeHash,
    'interpreter': ?interpreter,
    'script': ?script,
    'scriptHash': ?scriptHash,
    'packageRoot': ?packageRoot,
    'args': args,
    'cwd': cwd,
    'parent': ?parent,
    'uid': uid,
  };

  @override
  String toString() => 'TomSecretsIdentity($kind, $exe, ${script ?? '-'})';
}

// ── Interpreted clients (BP-21) ──────────────────────────────────────────

/// How an interpreter's command line names what it runs.
enum TomSecretsInterpreterRule {
  /// `python [opts] script.py`, `python -m pkg`, `python -c` (no script).
  python,

  /// `node [opts] script.js`; `bun [run] x`, `deno run [opts] x`.
  node,

  /// `dart run [target]` (the package root), `dart [opts] file.dart`; the
  /// VM (`dartvm`) the `dart` command starts reads the same.
  dart,

  /// `java -jar x.jar`, `java -cp path Main`.
  java,

  /// `ruby`, `perl`, the shells: the first argument that is no option, `-c`
  /// / `-e` (no script).
  script,

  /// `pwsh -File x.ps1`, `-Command` (no script).
  powershell,
}

/// The default interpreter table (part-protocol), by the executable's base
/// name (without `.exe`, any case); `python3.*` matches every minor version.
/// The user extends it with [TomSecretsInterpreters].
const Map<String, TomSecretsInterpreterRule> tomSecretsDefaultInterpreters = {
  'python': TomSecretsInterpreterRule.python,
  'python3': TomSecretsInterpreterRule.python,
  'python3.*': TomSecretsInterpreterRule.python,
  'node': TomSecretsInterpreterRule.node,
  'bun': TomSecretsInterpreterRule.node,
  'deno': TomSecretsInterpreterRule.node,
  'dart': TomSecretsInterpreterRule.dart,
  'dartvm': TomSecretsInterpreterRule.dart,
  'ruby': TomSecretsInterpreterRule.script,
  'perl': TomSecretsInterpreterRule.script,
  'java': TomSecretsInterpreterRule.java,
  'bash': TomSecretsInterpreterRule.script,
  'sh': TomSecretsInterpreterRule.script,
  'zsh': TomSecretsInterpreterRule.script,
  'fish': TomSecretsInterpreterRule.script,
  'pwsh': TomSecretsInterpreterRule.powershell,
  'powershell': TomSecretsInterpreterRule.powershell,
};

/// The interpreter table: the default and the user's additions.
final class TomSecretsInterpreters {
  /// The table of [entries] (base name or `prefix.*` → rule).
  const TomSecretsInterpreters([this.entries = tomSecretsDefaultInterpreters]);

  /// Base name (or `prefix.*`) → rule.
  final Map<String, TomSecretsInterpreterRule> entries;

  /// The rule for the executable [exe], or null when it is no interpreter.
  TomSecretsInterpreterRule? ruleFor(String exe) {
    var name = exe.split(RegExp(r'[/\\]')).last.toLowerCase();
    if (name.endsWith('.exe')) name = name.substring(0, name.length - 4);
    final exact = entries[name];
    if (exact != null) return exact;
    for (final e in entries.entries) {
      if (e.key.endsWith('.*') &&
          name.startsWith(e.key.substring(0, e.key.length - 1))) {
        return e.value;
      }
    }
    return null;
  }
}

/// What an interpreter's command line runs.
final class _Target {
  const _Target({this.script, this.isPath = false, this.packageRoot});

  /// The script, module, target or class; null: the interpreter alone.
  final String? script;

  /// Whether [script] is a file path (resolved against the working
  /// directory, its hash taken).
  final bool isPath;

  /// The package root or class path.
  final String? packageRoot;
}

/// The first argument that is no option, after skipping [valueOptions]
/// (options that take the next argument) and [stop] options (which mean no
/// script: `-c`, `-e`, `-Command`).
int _firstOperand(
  List<String> args, {
  int from = 0,
  Set<String> valueOptions = const {},
  Set<String> stop = const {},
}) {
  for (var i = from; i < args.length; i++) {
    final a = args[i];
    if (stop.contains(a)) return -1;
    if (a == '--') return i + 1 < args.length ? i + 1 : -1;
    if (a.startsWith('-')) {
      if (valueOptions.contains(a)) i++;
      continue;
    }
    return i;
  }
  return -1;
}

String? _nearestWith(String? cwd, List<String> markers) {
  if (cwd == null || cwd.isEmpty) return null;
  var dir = Directory(cwd).absolute;
  while (true) {
    for (final m in markers) {
      if (File('${dir.path}${Platform.pathSeparator}$m').existsSync()) {
        return dir.path;
      }
    }
    final parent = dir.parent;
    if (parent.path == dir.path) return null;
    dir = parent;
  }
}

_Target _target(
  TomSecretsInterpreterRule rule,
  List<String> args,
  String? cwd,
) {
  switch (rule) {
    case TomSecretsInterpreterRule.python:
      for (var i = 0; i < args.length; i++) {
        final a = args[i];
        if (a == '-c') return const _Target();
        if (a == '-m' && i + 1 < args.length) {
          return _Target(
            script: args[i + 1],
            packageRoot:
                _nearestWith(cwd, [
                  'pyproject.toml',
                  'setup.py',
                  'setup.cfg',
                ]) ??
                cwd,
          );
        }
        if (a == '-W' || a == '-X') {
          i++;
          continue;
        }
        if (a.startsWith('-')) continue;
        return _Target(script: a, isPath: true);
      }
      return const _Target();
    case TomSecretsInterpreterRule.node:
      var i = _firstOperand(args, valueOptions: {'-r', '--require'});
      if (i >= 0 && args[i] == 'run') {
        i = _firstOperand(args, from: i + 1);
      }
      if (i < 0) return const _Target();
      return _Target(script: args[i], isPath: true);
    case TomSecretsInterpreterRule.dart:
      final i = _firstOperand(args, valueOptions: {'--packages'});
      if (i < 0) return const _Target();
      if (args[i] == 'run') {
        final root = _nearestWith(cwd, ['pubspec.yaml']) ?? cwd;
        final t = _firstOperand(args, from: i + 1);
        return _Target(
          script: t < 0 ? '' : args[t],
          isPath: t >= 0 && args[t].endsWith('.dart'),
          packageRoot: root,
        );
      }
      return _Target(script: args[i], isPath: true);
    case TomSecretsInterpreterRule.java:
      for (var i = 0; i < args.length; i++) {
        final a = args[i];
        if (a == '-jar' && i + 1 < args.length) {
          return _Target(script: args[i + 1], isPath: true);
        }
        if ((a == '-cp' || a == '-classpath' || a == '--class-path') &&
            i + 1 < args.length) {
          final main = _firstOperand(args, from: i + 2);
          return _Target(
            script: main < 0 ? null : args[main],
            packageRoot: args[i + 1],
          );
        }
      }
      final main = _firstOperand(args);
      return main < 0 ? const _Target() : _Target(script: args[main]);
    case TomSecretsInterpreterRule.script:
      final i = _firstOperand(args, stop: {'-c', '-e', '-E'});
      return i < 0 ? const _Target() : _Target(script: args[i], isPath: true);
    case TomSecretsInterpreterRule.powershell:
      for (var i = 0; i < args.length; i++) {
        final a = args[i].toLowerCase();
        if (a == '-command' || a == '-c' || a == '-encodedcommand') {
          return const _Target();
        }
        if ((a == '-file' || a == '-f') && i + 1 < args.length) {
          return _Target(script: args[i + 1], isPath: true);
        }
      }
      final i = _firstOperand(args);
      return i < 0 ? const _Target() : _Target(script: args[i], isPath: true);
  }
}

/// [path] resolved against [cwd] to its real path (symbolic links followed);
/// unresolved when it is relative and [cwd] is unknown.
String tomSecretsRealPath(String path, String? cwd) {
  final absolute = File(path).isAbsolute;
  if (!absolute && (cwd == null || cwd.isEmpty)) return path;
  final full = absolute ? path : '$cwd${Platform.pathSeparator}$path';
  try {
    return File(full).resolveSymbolicLinksSync();
  } on FileSystemException {
    return File(full).absolute.path;
  }
}

/// The process whose child [process] counts as, for its grants: its
/// [parent], except for the browser host (an executable named
/// `tsm-browser-host`) started through a shell, `cmd.exe` (Chrome and the
/// other Chromium browsers start a native-messaging host on Windows with
/// `cmd /c`): then the shell's parent, the browser, read with [infoOf]. A
/// grant of the browser host names its browser (`exe-from`, DP-44), which
/// the shell alone would not tell apart.
TomSecretsProcessInfo? tomSecretsLauncherOf(
  TomSecretsProcessInfo process,
  TomSecretsProcessInfo? parent,
  TomSecretsProcessInfo? Function(int pid) infoOf,
) {
  if (parent == null) return null;
  String base(String path) {
    final name = path.split(RegExp(r'[/\\]')).last.toLowerCase();
    return name.endsWith('.exe') ? name.substring(0, name.length - 4) : name;
  }

  if (base(process.exe) != 'tsm-browser-host' || base(parent.exe) != 'cmd') {
    return parent;
  }
  final above = parent.parentPid;
  if (above == null || above == 0) return parent;
  return infoOf(above) ?? parent;
}

/// The identity of [process] (the client) with its [parent], classified by
/// [interpreters]; a script's hash from [hashes].
TomSecretsIdentity tomSecretsIdentityOf(
  TomSecretsProcessInfo process, {
  TomSecretsProcessInfo? parent,
  TomSecretsInterpreters interpreters = const TomSecretsInterpreters(),
  TomSecretsFileHashes? hashes,
}) {
  final args = process.args ?? const <String>[];
  final complete = process.args != null && process.cwd != null;
  final parentJson = parent == null
      ? null
      : {'exe': parent.exe, 'args': ?parent.args};
  final rule = interpreters.ruleFor(process.exe);
  if (rule == null) {
    return TomSecretsIdentity(
      kind: 'exe',
      exe: process.exe,
      args: args,
      cwd: process.cwd ?? '',
      uid: process.uid,
      pid: process.pid,
      parent: parentJson,
      complete: complete,
    );
  }
  final target = _target(rule, args, process.cwd);
  if (target.script == null) {
    return TomSecretsIdentity(
      kind: 'interpreter',
      exe: process.exe,
      interpreter: process.exe,
      args: args,
      cwd: process.cwd ?? '',
      uid: process.uid,
      pid: process.pid,
      parent: parentJson,
      complete: complete,
    );
  }
  final script = target.isPath
      ? tomSecretsRealPath(target.script!, process.cwd)
      : target.script!;
  final scriptHash = target.isPath ? hashes?.hashOf(script) : null;
  return TomSecretsIdentity(
    kind: 'script',
    exe: process.exe,
    interpreter: process.exe,
    script: script,
    scriptHash: scriptHash,
    packageRoot: target.packageRoot,
    args: args,
    cwd: process.cwd ?? '',
    uid: process.uid,
    pid: process.pid,
    parent: parentJson,
    complete: complete,
  );
}

// ── Hashes (DP-18) ───────────────────────────────────────────────────────

/// SHA-256 hashes of files, cached by path, size and modification time:
/// computed on demand, for a pinned grant.
final class TomSecretsFileHashes {
  final Map<String, (int, DateTime, String)> _cache = {};

  /// How many hashes were computed (not taken from the cache).
  int computed = 0;

  /// The SHA-256 (hex) of the file at [path], or null when it cannot be
  /// read.
  String? hashOf(String path) {
    final file = File(path);
    try {
      final stat = file.statSync();
      if (stat.type != FileSystemEntityType.file) return null;
      final cached = _cache[path];
      if (cached != null &&
          cached.$1 == stat.size &&
          cached.$2 == stat.modified) {
        return cached.$3;
      }
      final hash = sha256.convert(file.readAsBytesSync()).toString();
      computed++;
      _cache[path] = (stat.size, stat.modified, hash);
      return hash;
    } on FileSystemException {
      return null;
    }
  }
}

// ── Pinning (DP-18) ──────────────────────────────────────────────────────

/// A grant's pin (protocol.md 7.2 `pin`): `hash`, `off`, or relaxed until a
/// time.
sealed class TomSecretsPin {
  const TomSecretsPin();

  /// The pin of the protocol's `pin` value: `hash`, `off` or
  /// `{relaxedUntil}`.
  static TomSecretsPin parse(Object? value) => switch (value) {
    'hash' => const TomSecretsPinHash(),
    'off' => const TomSecretsPinOff(),
    {'relaxedUntil': final String until} => TomSecretsPinRelaxed(
      DateTime.parse(until).toUtc(),
    ),
    _ => throw FormatException('a pin is hash, off or {relaxedUntil}: $value'),
  };

  /// The protocol's `pin` value.
  Object toJson();

  /// Checks a file whose hash is [current] (null: it cannot be read) against
  /// the grant's [recorded] hash at [now].
  TomSecretsPinCheck check({
    required String? recorded,
    required String? current,
    DateTime? now,
  });
}

/// On: a changed hash is no grant, and the request goes to approval.
final class TomSecretsPinHash extends TomSecretsPin {
  /// The pin.
  const TomSecretsPinHash();

  @override
  Object toJson() => 'hash';

  @override
  TomSecretsPinCheck check({
    required String? recorded,
    required String? current,
    DateTime? now,
  }) => current != null && current == recorded
      ? const TomSecretsPinCheck.accepted()
      : const TomSecretsPinCheck.changed();
}

/// Off: the path alone, like an executable.
final class TomSecretsPinOff extends TomSecretsPin {
  /// The pin.
  const TomSecretsPinOff();

  @override
  Object toJson() => 'off';

  @override
  TomSecretsPinCheck check({
    required String? recorded,
    required String? current,
    DateTime? now,
  }) => const TomSecretsPinCheck.accepted();
}

/// Relaxed until [until]: before it a changed file is accepted and its new
/// hash recorded; from then on the pin is on with the last recorded hash.
final class TomSecretsPinRelaxed extends TomSecretsPin {
  /// Relaxed until [until].
  const TomSecretsPinRelaxed(this.until);

  /// The end of the relaxation.
  final DateTime until;

  @override
  Object toJson() => {'relaxedUntil': until.toUtc().toIso8601String()};

  @override
  TomSecretsPinCheck check({
    required String? recorded,
    required String? current,
    DateTime? now,
  }) {
    if (current != null && current == recorded) {
      return const TomSecretsPinCheck.accepted();
    }
    if (current != null && (now ?? DateTime.now()).toUtc().isBefore(until)) {
      return TomSecretsPinCheck.accepted(record: current);
    }
    return const TomSecretsPinCheck.changed();
  }
}

/// What a pin says about a file.
final class TomSecretsPinCheck {
  /// The grant holds; [record] is a new hash for the grant to keep (a
  /// relaxed pin accepting a change).
  const TomSecretsPinCheck.accepted({this.record}) : accepted = true;

  /// The file changed: no grant, the request goes to approval.
  const TomSecretsPinCheck.changed() : accepted = false, record = null;

  /// Whether the grant holds.
  final bool accepted;

  /// The hash to record, when it changed under a relaxed pin.
  final String? record;
}
