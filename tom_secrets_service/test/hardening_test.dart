// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The process hardening (part-service, Memory hygiene), checked from
/// outside a hardened child process: Linux no core file and not dumpable
/// (`/proc/<pid>/` then belongs to root); macOS no core file; Windows the
/// process DACL refusing `PROCESS_VM_READ` to the same user, and the error
/// mode set.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:test/test.dart';

void main() {
  test('a hardened process is what status.hardening says, seen from '
      'outside', () async {
    final child = await Process.start(Platform.resolvedExecutable, [
      'test/support/harden_child.dart',
    ]);
    addTearDown(() async {
      await child.stdin.close();
      child.kill();
    });
    final line = await child.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .first;
    final report = jsonDecode(line) as Map;
    final achieved = (report['achieved'] as Map).cast<String, bool>();
    // The hardened process: on Windows dart.exe runs the script in a child.
    final hardened = report['pid'] as int;

    if (Platform.isLinux) {
      expect(achieved, {'noCoreDumps': true, 'notDumpable': true});
      final limits = File('/proc/$hardened/limits').readAsStringSync();
      expect(
        limits,
        matches(RegExp(r'Max core file size\s+0\s+0\s', multiLine: true)),
      );
      // A process that is not dumpable has its /proc files owned by root.
      final owner = await Process.run('stat', [
        '-c',
        '%u',
        '/proc/$hardened/environ',
      ]);
      expect((owner.stdout as String).trim(), '0');
    } else if (Platform.isMacOS) {
      expect(achieved, {'noCoreDumps': true});
    } else if (Platform.isWindows) {
      expect(achieved, {'noCoreDumps': true, 'memoryAccessDenied': true});
      final kernel32 = DynamicLibrary.open('kernel32.dll');
      final openProcess = kernel32
          .lookupFunction<
            IntPtr Function(Uint32, Int32, Uint32),
            int Function(int, int, int)
          >('OpenProcess');
      final closeHandle = kernel32
          .lookupFunction<Int32 Function(IntPtr), int Function(int)>(
            'CloseHandle',
          );
      // An elevated session (an administrator over SSH) may hold
      // SeDebugPrivilege enabled, which opens any process whatever its
      // DACL; the check is what an ordinary process of the same user can
      // do, so this process drops it first.
      _disableDebugPrivilege();
      const processVmRead = 0x0010;
      const processQueryLimited = 0x1000;
      expect(
        openProcess(processVmRead, 0, hardened),
        0,
        reason: 'the same user may not read its memory',
      );
      final query = openProcess(processQueryLimited, 0, hardened);
      expect(query, isNot(0), reason: 'other access stays');
      closeHandle(query);
    }
  });
}

/// Disables SeDebugPrivilege in this process's token (Windows).
void _disableDebugPrivilege() {
  final advapi32 = DynamicLibrary.open('advapi32.dll');
  final kernel32 = DynamicLibrary.open('kernel32.dll');
  final currentProcess = kernel32
      .lookupFunction<IntPtr Function(), int Function()>('GetCurrentProcess');
  final openToken = advapi32
      .lookupFunction<
        Int32 Function(IntPtr, Uint32, Pointer<IntPtr>),
        int Function(int, int, Pointer<IntPtr>)
      >('OpenProcessToken');
  final lookup = advapi32
      .lookupFunction<
        Int32 Function(Pointer<Utf16>, Pointer<Utf16>, Pointer<Uint32>),
        int Function(Pointer<Utf16>, Pointer<Utf16>, Pointer<Uint32>)
      >('LookupPrivilegeValueW');
  final adjust = advapi32
      .lookupFunction<
        Int32 Function(
          IntPtr,
          Int32,
          Pointer<Uint32>,
          Uint32,
          Pointer<Void>,
          Pointer<Void>,
        ),
        int Function(
          int,
          int,
          Pointer<Uint32>,
          int,
          Pointer<Void>,
          Pointer<Void>,
        )
      >('AdjustTokenPrivileges');
  const tokenAdjustPrivileges = 0x0020;
  const tokenQuery = 0x0008;
  final token = calloc<IntPtr>();
  final name = 'SeDebugPrivilege'.toNativeUtf16();
  // TOKEN_PRIVILEGES with one LUID_AND_ATTRIBUTES: count, LUID (low, high),
  // attributes 0 (disabled).
  final privileges = calloc<Uint32>(4);
  try {
    expect(
      openToken(currentProcess(), tokenAdjustPrivileges | tokenQuery, token),
      isNot(0),
    );
    expect(lookup(nullptr, name, privileges + 1), isNot(0));
    privileges[0] = 1;
    privileges[3] = 0;
    expect(adjust(token.value, 0, privileges, 0, nullptr, nullptr), isNot(0));
  } finally {
    calloc
      ..free(token)
      ..free(name)
      ..free(privileges);
  }
}
