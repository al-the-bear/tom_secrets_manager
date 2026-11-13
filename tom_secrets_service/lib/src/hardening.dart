// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The service's process hardening at start (part-service, Memory hygiene),
/// best effort, through FFI; what was achieved is `status.hardening`:
///
/// - `noCoreDumps`: no core file (Linux and macOS: `setrlimit(RLIMIT_CORE,
///   0)`, read back with `getrlimit`); on Windows `SetErrorMode` keeps the
///   crash dialog and its dump from being offered;
/// - `notDumpable` (Linux): `prctl(PR_SET_DUMPABLE, 0)`, read back with
///   `PR_GET_DUMPABLE`; other users' and same-user debuggers cannot attach,
///   and `/proc/<pid>/` belongs to root;
/// - `memoryAccessDenied` (Windows): the process DACL grants SYSTEM all
///   access and the owner all but `PROCESS_VM_READ` / `PROCESS_VM_WRITE`.
///
/// The macOS hardened runtime is a signing flag of the build, not a call.
library;

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// Applies the hardening of this OS to the running process and answers what
/// it achieved, by measure. Never throws: a measure that fails is `false`.
Map<String, bool> tomSecretsHardenProcess() {
  if (Platform.isLinux) {
    return {'noCoreDumps': _noCoreDumps(), 'notDumpable': _notDumpable()};
  }
  if (Platform.isMacOS) return {'noCoreDumps': _noCoreDumps()};
  if (Platform.isWindows) {
    return {
      'noCoreDumps': _windowsErrorMode(),
      'memoryAccessDenied': _windowsDacl(),
    };
  }
  return const {};
}

// ── Linux and macOS ──────────────────────────────────────────────────────

/// `RLIMIT_CORE` on Linux and macOS.
const int _rlimitCore = 4;

final class _RLimit extends Struct {
  @Uint64()
  external int current;

  @Uint64()
  external int maximum;
}

bool _noCoreDumps() {
  try {
    final libc = DynamicLibrary.process();
    final setrlimit = libc
        .lookupFunction<
          Int32 Function(Int32, Pointer<_RLimit>),
          int Function(int, Pointer<_RLimit>)
        >('setrlimit');
    final getrlimit = libc
        .lookupFunction<
          Int32 Function(Int32, Pointer<_RLimit>),
          int Function(int, Pointer<_RLimit>)
        >('getrlimit');
    final limit = calloc<_RLimit>();
    try {
      limit.ref
        ..current = 0
        ..maximum = 0;
      if (setrlimit(_rlimitCore, limit) != 0) return false;
      limit.ref
        ..current = -1
        ..maximum = -1;
      if (getrlimit(_rlimitCore, limit) != 0) return false;
      return limit.ref.current == 0 && limit.ref.maximum == 0;
    } finally {
      calloc.free(limit);
    }
  } on Object {
    return false;
  }
}

const int _prGetDumpable = 3;
const int _prSetDumpable = 4;

bool _notDumpable() {
  try {
    final prctl = DynamicLibrary.process()
        .lookupFunction<
          Int32 Function(Int32, VarArgs<(UnsignedLong,)>),
          int Function(int, int)
        >('prctl');
    if (prctl(_prSetDumpable, 0) != 0) return false;
    return prctl(_prGetDumpable, 0) == 0;
  } on Object {
    return false;
  }
}

// ── Windows ──────────────────────────────────────────────────────────────

/// SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX.
const int _errorMode = 0x0001 | 0x0002 | 0x8000;

bool _windowsErrorMode() {
  try {
    final kernel32 = DynamicLibrary.open('kernel32.dll');
    final setErrorMode = kernel32
        .lookupFunction<Uint32 Function(Uint32), int Function(int)>(
          'SetErrorMode',
        );
    final getErrorMode = kernel32
        .lookupFunction<Uint32 Function(), int Function()>('GetErrorMode');
    setErrorMode(_errorMode);
    return getErrorMode() & _errorMode == _errorMode;
  } on Object {
    return false;
  }
}

/// SYSTEM: all access; the owner (`OW`, Owner Rights, which also takes the
/// owner's implicit rights away): all but PROCESS_VM_READ (0x10) and
/// PROCESS_VM_WRITE (0x20); nobody else. `P`: not inherited.
const String _processSddl = 'D:P(A;;0x1FFFFF;;;SY)(A;;0x1FFFCF;;;OW)';

const int _seKernelObject = 6;
const int _daclSecurityInformation = 0x4;
const int _protectedDaclSecurityInformation = 0x80000000;

bool _windowsDacl() {
  try {
    final advapi32 = DynamicLibrary.open('advapi32.dll');
    final kernel32 = DynamicLibrary.open('kernel32.dll');
    final convert = advapi32
        .lookupFunction<
          Int32 Function(
            Pointer<Utf16>,
            Uint32,
            Pointer<Pointer<Void>>,
            Pointer<Uint32>,
          ),
          int Function(
            Pointer<Utf16>,
            int,
            Pointer<Pointer<Void>>,
            Pointer<Uint32>,
          )
        >('ConvertStringSecurityDescriptorToSecurityDescriptorW');
    final getDacl = advapi32
        .lookupFunction<
          Int32 Function(
            Pointer<Void>,
            Pointer<Int32>,
            Pointer<Pointer<Void>>,
            Pointer<Int32>,
          ),
          int Function(
            Pointer<Void>,
            Pointer<Int32>,
            Pointer<Pointer<Void>>,
            Pointer<Int32>,
          )
        >('GetSecurityDescriptorDacl');
    final setSecurityInfo = advapi32
        .lookupFunction<
          Uint32 Function(
            IntPtr,
            Int32,
            Uint32,
            Pointer<Void>,
            Pointer<Void>,
            Pointer<Void>,
            Pointer<Void>,
          ),
          int Function(
            int,
            int,
            int,
            Pointer<Void>,
            Pointer<Void>,
            Pointer<Void>,
            Pointer<Void>,
          )
        >('SetSecurityInfo');
    final currentProcess = kernel32
        .lookupFunction<IntPtr Function(), int Function()>('GetCurrentProcess');
    final localFree = kernel32
        .lookupFunction<
          Pointer<Void> Function(Pointer<Void>),
          Pointer<Void> Function(Pointer<Void>)
        >('LocalFree');

    final sddl = _processSddl.toNativeUtf16();
    final descriptor = calloc<Pointer<Void>>();
    final present = calloc<Int32>();
    final dacl = calloc<Pointer<Void>>();
    final defaulted = calloc<Int32>();
    try {
      if (convert(sddl, 1, descriptor, nullptr) == 0) return false;
      try {
        if (getDacl(descriptor.value, present, dacl, defaulted) == 0 ||
            present.value == 0) {
          return false;
        }
        return setSecurityInfo(
              currentProcess(),
              _seKernelObject,
              _daclSecurityInformation | _protectedDaclSecurityInformation,
              nullptr,
              nullptr,
              dacl.value,
              nullptr,
            ) ==
            0;
      } finally {
        localFree(descriptor.value);
      }
    } finally {
      calloc
        ..free(sddl)
        ..free(descriptor)
        ..free(present)
        ..free(dacl)
        ..free(defaulted);
    }
  } on Object {
    return false;
  }
}
