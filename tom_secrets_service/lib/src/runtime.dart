// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The runtime directory (part-service, protocol.md 3): per OS user, the
/// user's alone (mode 0700; on Windows an ACL of the user and SYSTEM),
/// checked for owner and mode at every start; the single-instance lock
/// `service.lock`, `service.json`, and the endpoint files.
library;

import 'dart:convert';
import 'dart:io';

import 'package:tom_secrets_client/tom_secrets_client.dart';

/// A runtime directory that is not the user's alone, or cannot be made.
final class TomSecretsRuntimeException implements Exception {
  /// A problem described by [message].
  TomSecretsRuntimeException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsRuntimeException: $message';
}

/// Another service already holds the lock: the starter attaches to it.
final class TomSecretsAlreadyRunning implements Exception {
  /// The running service's `service.json`, when it could be read.
  TomSecretsAlreadyRunning(this.info);

  /// `service.json` of the running service, or null.
  final Map<String, Object?>? info;

  @override
  String toString() => 'TomSecretsAlreadyRunning';
}

/// How the endpoints are offered: Unix domain sockets (Linux, macOS) or
/// localhost TCP ports with a client token (Windows).
enum TomSecretsTransport {
  /// `client.sock`, `admin.sock`.
  unix,

  /// `client.port` + `client.token`, `admin.port`.
  tcp,
}

/// The runtime directory of this OS user.
final class TomSecretsRuntime {
  /// The runtime directory at [directory], its endpoints offered over
  /// [transport].
  TomSecretsRuntime(this.directory, {required this.transport});

  /// The runtime directory protocol.md 3.1 names for this process (or
  /// [environment] and [operatingSystem]); Unix sockets except on Windows.
  factory TomSecretsRuntime.current({
    Map<String, String>? environment,
    String? operatingSystem,
  }) {
    final os = operatingSystem ?? Platform.operatingSystem;
    final location = discoverTomSecrets(
      operatingSystem: os,
      environment: environment ?? Platform.environment,
    );
    if (location is! TomSecretsEndpoints) {
      throw TomSecretsRuntimeException(
        'no runtime directory: neither LOCALAPPDATA nor USERPROFILE is set',
      );
    }
    return TomSecretsRuntime(
      location.directory,
      transport: os == 'windows'
          ? TomSecretsTransport.tcp
          : TomSecretsTransport.unix,
    );
  }

  /// The directory.
  final String directory;

  /// How the endpoints are offered.
  final TomSecretsTransport transport;

  String _path(String name) => '$directory${Platform.pathSeparator}$name';

  /// `client.sock`.
  String get clientSocket => _path('client.sock');

  /// `admin.sock`.
  String get adminSocket => _path('admin.sock');

  /// `client.port`.
  String get clientPortFile => _path('client.port');

  /// `client.token`.
  String get clientTokenFile => _path('client.token');

  /// `admin.port`.
  String get adminPortFile => _path('admin.port');

  /// `service.lock`.
  String get lockFile => _path('service.lock');

  /// `service.json`.
  String get infoFile => _path('service.json');

  /// The endpoint files of [transport], every one a start writes.
  List<String> get endpointFiles => switch (transport) {
    TomSecretsTransport.unix => [clientSocket, adminSocket],
    TomSecretsTransport.tcp => [clientPortFile, clientTokenFile, adminPortFile],
  };

  /// Makes the directory the user's alone when missing, then checks it:
  /// owned by this user with no access for anyone else (POSIX: mode 0700;
  /// Windows: the inheritance cut and only the user and SYSTEM granted).
  /// A directory of someone else, or one others can read, is refused.
  Future<void> prepare() async {
    final dir = Directory(directory);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
      if (Platform.isWindows) {
        await _windowsRestrict();
      } else {
        await _run('chmod', ['700', directory]);
      }
    }
    await check();
  }

  /// Checks owner and mode (see [prepare]).
  Future<void> check() async {
    if (Platform.isWindows) {
      final out = await _run('icacls', [directory]);
      final user = Platform.environment['USERNAME'] ?? '';
      final lines = out
          .split(RegExp(r'\r?\n'))
          .map((l) => l.replaceFirst(directory, '').trim())
          .where((l) => l.contains(':('))
          .toList();
      for (final line in lines) {
        final who = line.split(':(').first.split(r'\').last.toLowerCase();
        if (who != user.toLowerCase() && who != 'system' && who != 'system-') {
          throw TomSecretsRuntimeException(
            'the runtime directory grants $who access',
          );
        }
      }
      return;
    }
    final stat = await FileStat.stat(directory);
    if (stat.type != FileSystemEntityType.directory) {
      throw TomSecretsRuntimeException('$directory is not a directory');
    }
    if (stat.mode & 0x3F != 0) {
      throw TomSecretsRuntimeException(
        'the runtime directory is open to others '
        '(mode ${(stat.mode & 0x1FF).toRadixString(8)})',
      );
    }
    final owner = int.parse(
      (await _run('stat', [
        Platform.isMacOS ? '-f' : '-c',
        '%u',
        directory,
      ])).trim(),
    );
    final me = currentUid();
    if (me != null && owner != me) {
      throw TomSecretsRuntimeException(
        'the runtime directory belongs to user $owner',
      );
    }
  }

  Future<void> _windowsRestrict() async {
    final user = Platform.environment['USERNAME'] ?? '';
    await _run('icacls', [
      directory,
      '/inheritance:r',
      '/grant:r',
      '$user:(OI)(CI)F',
      '/grant:r',
      'SYSTEM:(OI)(CI)F',
    ]);
  }

  static Future<String> _run(String executable, List<String> args) async {
    final result = await Process.run(executable, args);
    if (result.exitCode != 0) {
      throw TomSecretsRuntimeException(
        '$executable ${args.first} failed: ${result.stderr}',
      );
    }
    return result.stdout as String;
  }

  RandomAccessFile? _lock;

  // POSIX record locks belong to the process: a second lock of the same file
  // from this process would succeed, so the locks held here are remembered.
  static final Set<String> _held = {};

  /// Takes the exclusive single-instance lock on `service.lock`; the OS
  /// releases it when the process dies. Throws [TomSecretsAlreadyRunning]
  /// when another service (another process, or this one) holds it.
  Future<void> acquire() async {
    final key = File(lockFile).absolute.path;
    if (_held.contains(key)) throw TomSecretsAlreadyRunning(await readInfo());
    final file = await File(lockFile).open(mode: FileMode.append);
    try {
      await file.lock(FileLock.exclusive);
    } on FileSystemException {
      await file.close();
      throw TomSecretsAlreadyRunning(await readInfo());
    }
    _lock = file;
    _held.add(key);
  }

  /// Releases the lock.
  Future<void> release() async {
    final lock = _lock;
    _lock = null;
    if (lock == null) return;
    _held.remove(File(lockFile).absolute.path);
    await lock.unlock();
    await lock.close();
  }

  /// Deletes the endpoint files a dead instance left (only after [acquire]).
  Future<void> removeStaleEndpoints() async {
    // A socket is not a File to `exists`; its type is asked instead.
    for (final name in endpointFiles) {
      if (await FileSystemEntity.type(name, followLinks: false) !=
          FileSystemEntityType.notFound) {
        await File(name).delete();
      }
    }
  }

  /// Deletes the endpoint files and `service.json` (a stop).
  Future<void> removeEndpoints() async {
    await removeStaleEndpoints();
    final info = File(infoFile);
    if (await info.exists()) await info.delete();
  }

  /// Writes `service.json`: PID, start, protocol, the endpoints; no secret.
  Future<void> writeInfo({
    required int start,
    required Map<String, Object?> client,
    required Map<String, Object?> admin,
  }) => _writeFile(
    infoFile,
    jsonEncode({
      'pid': pid,
      'start': start,
      'protocol': 1,
      'client': client,
      'admin': admin,
    }),
  );

  /// `service.json`, or null.
  Future<Map<String, Object?>?> readInfo() async {
    try {
      return (jsonDecode(await File(infoFile).readAsString()) as Map)
          .cast<String, Object?>();
    } on Object {
      return null;
    }
  }

  /// Writes [text] to [path] through a temporary file and a rename.
  static Future<void> _writeFile(String path, String text) async {
    final temp = File('$path.tmp');
    await temp.writeAsString(text, flush: true);
    await temp.rename(path);
  }

  /// Writes a port file.
  Future<void> writePort(String path, int port) => _writeFile(path, '$port\n');

  /// Writes the client token.
  Future<void> writeToken(String token) =>
      _writeFile(clientTokenFile, '$token\n');
}
