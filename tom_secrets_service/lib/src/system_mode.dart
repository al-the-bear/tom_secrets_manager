// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The system-installed service on Linux (`tsm install --system`,
/// tsm_d11): the executable is root's and set-group-ID to
/// [tomSecretsSystemGroup], which alone reaches the directory of the
/// identity keys. Started by a user, it runs as that user with the group's
/// rights; the kernel's secure mode then keeps the user's other processes
/// out of its memory (no debugger, no `/proc/<pid>/mem`) and the loader
/// ignores `LD_PRELOAD` and the like.
///
/// The group's rights serve one step: the key of the real user
/// (`<uid>.json`, the path from the real user id alone, never from the
/// environment) is read, or made, and then the group is dropped for good,
/// before anything the environment names is read or started. From then on
/// the service runs as the user alone, with the user's own runtime
/// directory and data directory, taken from the user's account, not from
/// variables the caller could set.
library;

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

/// The ids of this process.
typedef TomSecretsProcessIds = ({
  int uid,
  int gid,
  int egid,
  String? egidName,
  String? home,
});

/// A refusal of the system mode's start (exit code 9).
final class TomSecretsSystemModeException implements Exception {
  /// Why.
  const TomSecretsSystemModeException(this.message);

  /// Why, for the operator.
  final String message;

  @override
  String toString() => 'TomSecretsSystemModeException: $message';
}

/// The system mode of a set-group-ID start.
final class TomSecretsSystemMode {
  /// The mode for the real user [uid] (home [home]) with the identity keys
  /// in [identityDirectory].
  TomSecretsSystemMode({
    required this.uid,
    required this.home,
    this.identityDirectory = tomSecretsSystemIdentityDirectory,
    this.runUserDirectory = '/run/user',
  });

  /// The system mode of this process: set-group-ID to
  /// [tomSecretsSystemGroup] on Linux; else null. Any other set-group-ID
  /// start drops the foreign group at once and runs as usual.
  static TomSecretsSystemMode? detect() {
    if (!Platform.isLinux) return null;
    final ids = tomSecretsProcessIds();
    if (ids.egid == ids.gid) return null;
    if (ids.egidName != tomSecretsSystemGroup || ids.home == null) {
      tomSecretsDropGroup();
      return null;
    }
    return TomSecretsSystemMode(uid: ids.uid, home: ids.home!);
  }

  /// The real user id.
  final int uid;

  /// The user's home, from the account.
  final String home;

  /// Where the identity keys are.
  final String identityDirectory;

  /// The parent of the users' runtime directories (`/run/user`).
  final String runUserDirectory;

  /// The real user's key file.
  File get identityFile => File('$identityDirectory/$uid.json');

  /// The environment the service's directories are taken from: the
  /// account's home, and `/run/user/<uid>` when the system made it.
  Map<String, String> get environment {
    final run = '$runUserDirectory/$uid';
    return {
      'HOME': home,
      if (Directory(run).existsSync()) 'XDG_RUNTIME_DIR': run,
    };
  }

  /// The user's data directory (the default one: the variables that move
  /// it are not taken).
  String get dataDirectory => tomSecretsDataDirectory(
    environment: environment,
    operatingSystem: 'linux',
  );

  /// The user's bootstrap, the only one the service starts with.
  String get bootstrapPath => '$dataDirectory/bootstrap.yaml';

  /// The user's runtime directory.
  TomSecretsRuntime get runtime => TomSecretsRuntime.current(
    environment: environment,
    operatingSystem: 'linux',
  );

  /// Reads (or makes) the user's identity key, with the group's rights,
  /// then drops the group for good. A key the service kept in the data
  /// directory before the install signs the new one, which every admin
  /// that pinned it follows, and is removed. Throws
  /// [TomSecretsSystemModeException] when the key cannot be had or the
  /// group cannot be dropped.
  Future<TomSecretsServiceIdentityKey> takeIdentity({
    void Function()? drop,
  }) async {
    TomSecretsServiceIdentityKey key;
    try {
      key = await TomSecretsServiceIdentityKey.loadOrCreateFile(
        identityFile,
        kept: 'system',
        previous: File('$dataDirectory/$tomSecretsServiceIdentityFile'),
      );
    } on FileSystemException catch (e) {
      (drop ?? tomSecretsDropGroup)();
      throw TomSecretsSystemModeException(
        'the identity key in $identityDirectory cannot be read or made '
        '(${e.message}); is the system install complete (tsm install '
        '--system)?',
      );
    }
    (drop ?? tomSecretsDropGroup)();
    return key;
  }
}

typedef _GetIdN = Uint32 Function();
typedef _GetIdD = int Function();

/// The real and effective ids of this process, the effective group's name
/// and the real user's home (Linux).
TomSecretsProcessIds tomSecretsProcessIds() {
  final libc = DynamicLibrary.process();
  int id(String name) => libc.lookupFunction<_GetIdN, _GetIdD>(name)();
  final uid = id('getuid');
  final gid = id('getgid');
  final egid = id('getegid');
  String? egidName;
  final group = libc
      .lookupFunction<
        Pointer<Pointer<Utf8>> Function(Uint32),
        Pointer<Pointer<Utf8>> Function(int)
      >('getgrgid')(egid);
  // struct group: gr_name first.
  if (group != nullptr && group.value != nullptr) {
    egidName = group.value.toDartString();
  }
  String? home;
  final passwd = libc
      .lookupFunction<
        Pointer<Uint8> Function(Uint32),
        Pointer<Uint8> Function(int)
      >('getpwuid')(uid);
  // struct passwd on 64-bit Linux: pw_name, pw_passwd (pointers), pw_uid,
  // pw_gid (32 bits each), pw_gecos, pw_dir (pointers): pw_dir at 32.
  if (passwd != nullptr) {
    final dir = Pointer<Pointer<Utf8>>.fromAddress(passwd.address + 32).value;
    if (dir != nullptr) home = dir.toDartString();
  }
  return (uid: uid, gid: gid, egid: egid, egidName: egidName, home: home);
}

/// Drops the set-group-ID group for good (real, effective and saved group
/// the real one), and checks it is gone.
void tomSecretsDropGroup() {
  final libc = DynamicLibrary.process();
  final gid = libc.lookupFunction<_GetIdN, _GetIdD>('getgid')();
  final set = libc
      .lookupFunction<
        Int32 Function(Uint32, Uint32, Uint32),
        int Function(int, int, int)
      >('setresgid');
  if (set(gid, gid, gid) != 0) {
    throw const TomSecretsSystemModeException(
      'the service could not drop its group',
    );
  }
  final ids = calloc<Uint32>(3);
  try {
    final get = libc
        .lookupFunction<
          Int32 Function(Pointer<Uint32>, Pointer<Uint32>, Pointer<Uint32>),
          int Function(Pointer<Uint32>, Pointer<Uint32>, Pointer<Uint32>)
        >('getresgid');
    if (get(ids, ids + 1, ids + 2) != 0 ||
        ids[0] != gid ||
        ids[1] != gid ||
        ids[2] != gid) {
      throw const TomSecretsSystemModeException(
        'the service\'s group is still there after it was dropped',
      );
    }
  } finally {
    calloc.free(ids);
  }
}
