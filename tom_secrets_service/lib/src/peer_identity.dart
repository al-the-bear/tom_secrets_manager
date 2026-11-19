// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Measuring the process at the other end of an accepted connection
/// (part-protocol, "Who is asking: the peer identity"), each OS through its
/// own means:
///
/// | | Linux | macOS | Windows |
/// | --- | --- | --- | --- |
/// | peer PID, uid | `SO_PEERCRED` | `LOCAL_PEERPID`, `LOCAL_PEERCRED` | `GetExtendedTcpTable`; the token's SID |
/// | executable | `/proc/<pid>/exe` | `proc_pidpath` | `QueryFullProcessImageNameW` |
/// | arguments | `/proc/<pid>/cmdline` | `sysctl(KERN_PROCARGS2)` | `NtQueryInformationProcess(ProcessCommandLineInformation)` |
/// | working directory | `/proc/<pid>/cwd` | `proc_pidinfo(PROC_PIDVNODEPATHINFO)` | the process parameters block (`ReadProcessMemory`) |
/// | start time, parent | `/proc/<pid>/stat` | `proc_pidinfo(PROC_PIDTBSDINFO)` | `GetProcessTimes`, the process snapshot |
///
/// The start time is read before and after the inspection; a process that
/// changed under the measurement (PID reuse) is not identified. A peer of
/// another OS user is refused outright.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'identity.dart';

/// The outcome of measuring a peer.
sealed class TomSecretsPeerMeasurement {
  const TomSecretsPeerMeasurement();
}

/// The peer was measured.
final class TomSecretsPeerMeasured extends TomSecretsPeerMeasurement {
  /// The peer of [identity].
  const TomSecretsPeerMeasured(this.identity);

  /// Its identity.
  final TomSecretsIdentity identity;
}

/// The peer is refused: `other_user` (another OS user) or `unidentifiable`
/// (it could not be measured, or changed under the measurement).
final class TomSecretsPeerRefused extends TomSecretsPeerMeasurement {
  /// Refused for [reason].
  const TomSecretsPeerRefused(this.reason, [this.detail]);

  /// `other_user` or `unidentifiable`.
  final String reason;

  /// What failed (for the log; never a value).
  final String? detail;
}

/// Measures the process at the other end of an accepted [Socket].
abstract interface class TomSecretsPeerMeasurer {
  /// The measurement of [socket]'s peer.
  Future<TomSecretsPeerMeasurement> measure(Socket socket);
}

/// The measurer of this OS.
final class TomSecretsSystemPeerMeasurer implements TomSecretsPeerMeasurer {
  /// A measurer classifying with [interpreters], hashing scripts through
  /// [hashes].
  TomSecretsSystemPeerMeasurer({
    this.interpreters = const TomSecretsInterpreters(),
    TomSecretsFileHashes? hashes,
  }) : hashes = hashes ?? TomSecretsFileHashes();

  /// The interpreter table.
  final TomSecretsInterpreters interpreters;

  /// The hash cache.
  final TomSecretsFileHashes hashes;

  @override
  Future<TomSecretsPeerMeasurement> measure(Socket socket) async {
    final ({int pid, Object? uid})? peer;
    try {
      peer = tomSecretsPeerOf(socket);
    } on Object catch (e) {
      return TomSecretsPeerRefused('unidentifiable', 'peer: ${e.runtimeType}');
    }
    if (peer == null) {
      return const TomSecretsPeerRefused('unidentifiable', 'no peer pid');
    }
    return measureProcess(peer.pid, uid: peer.uid);
  }

  /// The measurement of process [pid] (a named pipe's client, Windows'
  /// `GetNamedPipeClientProcessId`), whose OS user is [uid] when the
  /// transport told it.
  TomSecretsPeerMeasurement measureProcess(int pid, {Object? uid}) {
    final own = tomSecretsOwnUid();
    if (uid != null && own != null && uid != own) {
      return const TomSecretsPeerRefused('other_user');
    }
    final before = tomSecretsStartTimeOf(pid);
    final process = tomSecretsProcessInfo(pid);
    final after = tomSecretsStartTimeOf(pid);
    if (process == null || before == null || before != after) {
      return const TomSecretsPeerRefused('unidentifiable', 'process');
    }
    if (process.startTime != before) {
      return const TomSecretsPeerRefused('unidentifiable', 'pid reused');
    }
    if (own != null && process.uid != own) {
      return const TomSecretsPeerRefused('other_user');
    }
    final parent = tomSecretsLauncherOf(
      process,
      process.parentPid == null || process.parentPid == 0
          ? null
          : tomSecretsProcessInfo(process.parentPid!),
      tomSecretsProcessInfo,
    );
    return TomSecretsPeerMeasured(
      tomSecretsIdentityOf(
        process,
        parent: parent,
        interpreters: interpreters,
        hashes: hashes,
      ),
    );
  }
}

/// The PID (and, on Linux and macOS, the uid) of [socket]'s peer, or null.
({int pid, Object? uid})? tomSecretsPeerOf(Socket socket) {
  if (Platform.isLinux) {
    // SO_PEERCRED (SOL_SOCKET 1, option 17): struct ucred {pid, uid, gid}.
    final raw = socket.getRawOption(RawSocketOption(1, 17, Uint8List(12)));
    final data = ByteData.sublistView(raw);
    final pid = data.getInt32(0, Endian.host);
    return pid <= 0 ? null : (pid: pid, uid: data.getUint32(4, Endian.host));
  }
  if (Platform.isMacOS) {
    // LOCAL_PEERPID (SOL_LOCAL 0, option 2) and LOCAL_PEERCRED (option 1):
    // struct xucred {cr_version, cr_uid, ...}.
    final pidRaw = socket.getRawOption(RawSocketOption(0, 2, Uint8List(4)));
    final pid = ByteData.sublistView(pidRaw).getInt32(0, Endian.host);
    final cred = socket.getRawOption(RawSocketOption(0, 1, Uint8List(76)));
    final uid = ByteData.sublistView(cred).getUint32(4, Endian.host);
    return pid <= 0 ? null : (pid: pid, uid: uid);
  }
  if (Platform.isWindows) {
    final pid = _windowsTcpPeer(socket.remotePort, socket.port);
    return pid == null ? null : (pid: pid, uid: null);
  }
  return null;
}

/// This process's OS user: a number on Linux and macOS, a SID string on
/// Windows; null when it cannot be read.
Object? tomSecretsOwnUid() {
  try {
    if (Platform.isWindows) return _windowsSid(pid);
    return DynamicLibrary.process()
        .lookupFunction<Uint32 Function(), int Function()>('getuid')();
  } on Object {
    return null;
  }
}

/// The start time of process [pid] as the OS gives it, or null.
int? tomSecretsStartTimeOf(int pid) {
  try {
    if (Platform.isLinux) return _linuxStat(pid)?.start;
    if (Platform.isMacOS) return _macBsdInfo(pid)?.start;
    if (Platform.isWindows) return _windowsStartTime(pid);
  } on Object {
    return null;
  }
  return null;
}

/// What process [pid] is, or null when it cannot be read.
TomSecretsProcessInfo? tomSecretsProcessInfo(int pid) {
  try {
    if (Platform.isLinux) return _linuxInfo(pid);
    if (Platform.isMacOS) return _macInfo(pid);
    if (Platform.isWindows) return _windowsInfo(pid);
  } on Object {
    return null;
  }
  return null;
}

// ── Linux: /proc ─────────────────────────────────────────────────────────

({int ppid, int start})? _linuxStat(int pid) {
  final stat = File('/proc/$pid/stat').readAsStringSync();
  // The command name in parentheses may hold spaces: fields count from the
  // last ')'. Field 3 is the state, 4 the parent, 22 the start time.
  final rest = stat.substring(stat.lastIndexOf(')') + 2).split(' ');
  return (ppid: int.parse(rest[1]), start: int.parse(rest[19]));
}

TomSecretsProcessInfo? _linuxInfo(int pid) {
  final exe = Link('/proc/$pid/exe').targetSync();
  final stat = _linuxStat(pid);
  if (stat == null) return null;
  List<String>? args;
  try {
    final cmdline = File('/proc/$pid/cmdline').readAsBytesSync();
    final parts = utf8.decode(cmdline, allowMalformed: true).split('\u0000');
    if (parts.isNotEmpty && parts.last.isEmpty) parts.removeLast();
    args = parts.isEmpty ? const [] : parts.sublist(1);
  } on FileSystemException {
    args = null;
  }
  String? cwd;
  try {
    cwd = Link('/proc/$pid/cwd').targetSync();
  } on FileSystemException {
    cwd = null;
  }
  final uidLine = File(
    '/proc/$pid/status',
  ).readAsLinesSync().firstWhere((l) => l.startsWith('Uid:'));
  return TomSecretsProcessInfo(
    pid: pid,
    exe: tomSecretsRealPath(exe, null),
    args: args,
    cwd: cwd,
    startTime: stat.start,
    parentPid: stat.ppid,
    uid: int.parse(uidLine.split(RegExp(r'\s+'))[1]),
  );
}

// ── macOS: libproc and sysctl ────────────────────────────────────────────

final DynamicLibrary _libc = DynamicLibrary.process();

const int _procPidTbsdInfo = 3;
const int _procPidVnodePathInfo = 9;

final int Function(int, int, int, Pointer<Void>, int) _procPidInfo = _libc
    .lookupFunction<
      Int32 Function(Int32, Int32, Uint64, Pointer<Void>, Int32),
      int Function(int, int, int, Pointer<Void>, int)
    >('proc_pidinfo');

/// `struct proc_bsdinfo`: pbi_ppid at 16, pbi_uid at 20, the start time
/// (seconds, microseconds) at 120 and 128; 136 bytes.
({int ppid, int uid, int start})? _macBsdInfo(int pid) {
  final buf = calloc<Uint8>(136);
  try {
    if (_procPidInfo(pid, _procPidTbsdInfo, 0, buf.cast(), 136) != 136) {
      return null;
    }
    final view = ByteData.sublistView(buf.asTypedList(136));
    return (
      ppid: view.getUint32(16, Endian.host),
      uid: view.getUint32(20, Endian.host),
      start:
          view.getUint64(120, Endian.host) * 1000000 +
          view.getUint64(128, Endian.host),
    );
  } finally {
    calloc.free(buf);
  }
}

String? _macPath(int pid) {
  final procPidPath = _libc
      .lookupFunction<
        Int32 Function(Int32, Pointer<Uint8>, Uint32),
        int Function(int, Pointer<Uint8>, int)
      >('proc_pidpath');
  final buf = calloc<Uint8>(4096);
  try {
    final n = procPidPath(pid, buf, 4096);
    return n <= 0 ? null : utf8.decode(buf.asTypedList(n));
  } finally {
    calloc.free(buf);
  }
}

String? _macCwd(int pid) {
  // struct proc_vnodepathinfo: pvi_cdir (struct vnode_info, 152 bytes, then
  // the 1024-byte path), pvi_rdir the same: 2352 bytes.
  const size = 2352;
  final buf = calloc<Uint8>(size);
  try {
    if (_procPidInfo(pid, _procPidVnodePathInfo, 0, buf.cast(), size) != size) {
      return null;
    }
    final path = buf.asTypedList(size).sublist(152, 152 + 1024);
    final end = path.indexOf(0);
    return utf8.decode(path.sublist(0, end < 0 ? path.length : end));
  } finally {
    calloc.free(buf);
  }
}

List<String>? _macArgs(int pid) {
  final sysctl = _libc
      .lookupFunction<
        Int32 Function(
          Pointer<Int32>,
          Uint32,
          Pointer<Void>,
          Pointer<Size>,
          Pointer<Void>,
          Size,
        ),
        int Function(
          Pointer<Int32>,
          int,
          Pointer<Void>,
          Pointer<Size>,
          Pointer<Void>,
          int,
        )
      >('sysctl');
  final mib = calloc<Int32>(3);
  final size = calloc<Size>();
  final argmax = calloc<Int32>();
  try {
    // KERN_ARGMAX (CTL_KERN 1, 8): the size of the argument area.
    mib[0] = 1;
    mib[1] = 8;
    size.value = 4;
    if (sysctl(mib, 2, argmax.cast(), size, nullptr, 0) != 0) return null;
    final buf = calloc<Uint8>(argmax.value);
    try {
      // KERN_PROCARGS2 (49): argc, the exec path, padding, argv, environ.
      mib[1] = 49;
      mib[2] = pid;
      size.value = argmax.value;
      if (sysctl(mib, 3, buf.cast(), size, nullptr, 0) != 0) return null;
      final bytes = buf.asTypedList(size.value);
      final argc = ByteData.sublistView(bytes).getInt32(0, Endian.host);
      var i = 4;
      while (i < bytes.length && bytes[i] != 0) {
        i++;
      }
      while (i < bytes.length && bytes[i] == 0) {
        i++;
      }
      final argv = <String>[];
      while (argv.length < argc && i < bytes.length) {
        final start = i;
        while (i < bytes.length && bytes[i] != 0) {
          i++;
        }
        argv.add(utf8.decode(bytes.sublist(start, i), allowMalformed: true));
        i++;
      }
      return argv.isEmpty ? const [] : argv.sublist(1);
    } finally {
      calloc.free(buf);
    }
  } finally {
    calloc
      ..free(mib)
      ..free(size)
      ..free(argmax);
  }
}

TomSecretsProcessInfo? _macInfo(int pid) {
  final info = _macBsdInfo(pid);
  final exe = _macPath(pid);
  if (info == null || exe == null) return null;
  return TomSecretsProcessInfo(
    pid: pid,
    exe: tomSecretsRealPath(exe, null),
    args: _macArgs(pid),
    cwd: _macCwd(pid),
    startTime: info.start,
    parentPid: info.ppid,
    uid: info.uid,
  );
}

// ── Windows: iphlpapi, kernel32, ntdll ───────────────────────────────────

const int _processQueryLimitedInformation = 0x1000;
const int _processQueryInformation = 0x0400;
const int _processVmRead = 0x0010;

DynamicLibrary get _kernel32 => DynamicLibrary.open('kernel32.dll');
DynamicLibrary get _advapi32 => DynamicLibrary.open('advapi32.dll');
DynamicLibrary get _ntdll => DynamicLibrary.open('ntdll.dll');

int _openProcess(int access, int pid) =>
    _kernel32.lookupFunction<
      IntPtr Function(Uint32, Int32, Uint32),
      int Function(int, int, int)
    >('OpenProcess')(access, 0, pid);

void _closeHandle(int handle) =>
    _kernel32.lookupFunction<Int32 Function(IntPtr), int Function(int)>(
      'CloseHandle',
    )(handle);

/// The PID owning the localhost TCP connection from [clientPort] to
/// [servicePort] (`TCP_TABLE_OWNER_PID_CONNECTIONS`).
int? _windowsTcpPeer(int clientPort, int servicePort) {
  final getTable = DynamicLibrary.open('iphlpapi.dll')
      .lookupFunction<
        Uint32 Function(
          Pointer<Void>,
          Pointer<Uint32>,
          Int32,
          Uint32,
          Uint32,
          Uint32,
        ),
        int Function(Pointer<Void>, Pointer<Uint32>, int, int, int, int)
      >('GetExtendedTcpTable');
  const afInet = 2;
  const ownerPidConnections = 4;
  final size = calloc<Uint32>();
  try {
    getTable(nullptr, size, 0, afInet, ownerPidConnections, 0);
    final buf = calloc<Uint8>(size.value + 1024);
    try {
      size.value += 1024;
      if (getTable(buf.cast(), size, 0, afInet, ownerPidConnections, 0) != 0) {
        return null;
      }
      final data = ByteData.sublistView(buf.asTypedList(size.value));
      final count = data.getUint32(0, Endian.little);
      int port(int dw) => ((dw & 0xff) << 8) | ((dw >> 8) & 0xff);
      for (var r = 0; r < count; r++) {
        // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr,
        // remotePort, owningPid; 24 bytes.
        final o = 4 + r * 24;
        if (port(data.getUint32(o + 8, Endian.little)) == clientPort &&
            port(data.getUint32(o + 16, Endian.little)) == servicePort) {
          return data.getUint32(o + 20, Endian.little);
        }
      }
      return null;
    } finally {
      calloc.free(buf);
    }
  } finally {
    calloc.free(size);
  }
}

String? _windowsSid(int pid) {
  final handle = _openProcess(_processQueryLimitedInformation, pid);
  if (handle == 0) return null;
  final openToken = _advapi32
      .lookupFunction<
        Int32 Function(IntPtr, Uint32, Pointer<IntPtr>),
        int Function(int, int, Pointer<IntPtr>)
      >('OpenProcessToken');
  final getInfo = _advapi32
      .lookupFunction<
        Int32 Function(IntPtr, Int32, Pointer<Void>, Uint32, Pointer<Uint32>),
        int Function(int, int, Pointer<Void>, int, Pointer<Uint32>)
      >('GetTokenInformation');
  final toString = _advapi32
      .lookupFunction<
        Int32 Function(Pointer<Void>, Pointer<Pointer<Utf16>>),
        int Function(Pointer<Void>, Pointer<Pointer<Utf16>>)
      >('ConvertSidToStringSidW');
  final localFree = _kernel32
      .lookupFunction<
        Pointer<Void> Function(Pointer<Void>),
        Pointer<Void> Function(Pointer<Void>)
      >('LocalFree');
  final token = calloc<IntPtr>();
  final buf = calloc<Uint8>(256);
  final length = calloc<Uint32>();
  final text = calloc<Pointer<Utf16>>();
  try {
    if (openToken(handle, 0x0008, token) == 0) return null; // TOKEN_QUERY
    try {
      // TokenUser (1): TOKEN_USER {SID_AND_ATTRIBUTES {PSID, attributes}}.
      if (getInfo(token.value, 1, buf.cast(), 256, length) == 0) return null;
      final sid = buf.cast<Pointer<Void>>().value;
      if (toString(sid, text) == 0) return null;
      final result = text.value.toDartString();
      localFree(text.value.cast());
      return result;
    } finally {
      _closeHandle(token.value);
    }
  } finally {
    _closeHandle(handle);
    calloc
      ..free(token)
      ..free(buf)
      ..free(length)
      ..free(text);
  }
}

int? _windowsStartTime(int pid) {
  final handle = _openProcess(_processQueryLimitedInformation, pid);
  if (handle == 0) return null;
  final times = calloc<Uint64>(4);
  try {
    final getTimes = _kernel32
        .lookupFunction<
          Int32 Function(
            IntPtr,
            Pointer<Uint64>,
            Pointer<Uint64>,
            Pointer<Uint64>,
            Pointer<Uint64>,
          ),
          int Function(
            int,
            Pointer<Uint64>,
            Pointer<Uint64>,
            Pointer<Uint64>,
            Pointer<Uint64>,
          )
        >('GetProcessTimes');
    if (getTimes(handle, times, times + 1, times + 2, times + 3) == 0) {
      return null;
    }
    return times[0];
  } finally {
    calloc.free(times);
    _closeHandle(handle);
  }
}

String? _windowsExe(int handle) {
  final query = _kernel32
      .lookupFunction<
        Int32 Function(IntPtr, Uint32, Pointer<Utf16>, Pointer<Uint32>),
        int Function(int, int, Pointer<Utf16>, Pointer<Uint32>)
      >('QueryFullProcessImageNameW');
  final buf = calloc<Uint16>(32768);
  final size = calloc<Uint32>()..value = 32768;
  try {
    if (query(handle, 0, buf.cast(), size) == 0) return null;
    return buf.cast<Utf16>().toDartString(length: size.value);
  } finally {
    calloc
      ..free(buf)
      ..free(size);
  }
}

int Function(int, int, Pointer<Void>, int, Pointer<Uint32>) get _ntQuery =>
    _ntdll.lookupFunction<
      Int32 Function(IntPtr, Int32, Pointer<Void>, Uint32, Pointer<Uint32>),
      int Function(int, int, Pointer<Void>, int, Pointer<Uint32>)
    >('NtQueryInformationProcess');

/// A UNICODE_STRING at [p] (x64: length, maximum length, padding, buffer).
String _unicodeString(Pointer<Uint8> p) {
  final length = p.cast<Uint16>().value;
  final buffer = Pointer<Uint16>.fromAddress((p + 8).cast<IntPtr>().value);
  return buffer.cast<Utf16>().toDartString(length: length ~/ 2);
}

List<String>? _windowsArgs(int handle) {
  // ProcessCommandLineInformation (60): a UNICODE_STRING and its text.
  final length = calloc<Uint32>();
  try {
    _ntQuery(handle, 60, nullptr, 0, length);
    if (length.value == 0) return null;
    final buf = calloc<Uint8>(length.value);
    try {
      if (_ntQuery(handle, 60, buf.cast(), length.value, length) != 0) {
        return null;
      }
      final line = _unicodeString(buf);
      return _splitCommandLine(line);
    } finally {
      calloc.free(buf);
    }
  } finally {
    calloc.free(length);
  }
}

List<String> _splitCommandLine(String line) {
  final toArgv = DynamicLibrary.open('shell32.dll')
      .lookupFunction<
        Pointer<Pointer<Utf16>> Function(Pointer<Utf16>, Pointer<Int32>),
        Pointer<Pointer<Utf16>> Function(Pointer<Utf16>, Pointer<Int32>)
      >('CommandLineToArgvW');
  final localFree = _kernel32
      .lookupFunction<
        Pointer<Void> Function(Pointer<Void>),
        Pointer<Void> Function(Pointer<Void>)
      >('LocalFree');
  final text = line.toNativeUtf16();
  final count = calloc<Int32>();
  try {
    final argv = toArgv(text, count);
    if (argv == nullptr) return const [];
    final args = [for (var i = 1; i < count.value; i++) argv[i].toDartString()];
    localFree(argv.cast());
    return args;
  } finally {
    calloc
      ..free(text)
      ..free(count);
  }
}

/// The working directory from the process parameters block (x64: the PEB's
/// ProcessParameters at 0x20, CurrentDirectory.DosPath at 0x38); null when
/// the process cannot be read.
String? _windowsCwd(int pid) {
  final handle = _openProcess(_processQueryInformation | _processVmRead, pid);
  if (handle == 0) return null;
  final read = _kernel32
      .lookupFunction<
        Int32 Function(IntPtr, IntPtr, Pointer<Void>, IntPtr, Pointer<IntPtr>),
        int Function(int, int, Pointer<Void>, int, Pointer<IntPtr>)
      >('ReadProcessMemory');
  final basic = calloc<Uint8>(48);
  final ptr = calloc<IntPtr>();
  final string = calloc<Uint8>(16);
  try {
    if (_ntQuery(handle, 0, basic.cast(), 48, nullptr) != 0) return null;
    final peb = (basic + 8).cast<IntPtr>().value;
    if (read(handle, peb + 0x20, ptr.cast(), 8, nullptr) == 0) return null;
    if (read(handle, ptr.value + 0x38, string.cast(), 16, nullptr) == 0) {
      return null;
    }
    final length = string.cast<Uint16>().value;
    final address = (string + 8).cast<IntPtr>().value;
    final text = calloc<Uint16>(length ~/ 2 + 1);
    try {
      if (read(handle, address, text.cast(), length, nullptr) == 0) {
        return null;
      }
      var cwd = text.cast<Utf16>().toDartString(length: length ~/ 2);
      if (cwd.length > 3 && cwd.endsWith('\\')) {
        cwd = cwd.substring(0, cwd.length - 1);
      }
      return cwd;
    } finally {
      calloc.free(text);
    }
  } finally {
    calloc
      ..free(basic)
      ..free(ptr)
      ..free(string);
    _closeHandle(handle);
  }
}

int? _windowsParent(int pid) {
  final snapshot = _kernel32
      .lookupFunction<IntPtr Function(Uint32, Uint32), int Function(int, int)>(
        'CreateToolhelp32Snapshot',
      )(2, 0); // TH32CS_SNAPPROCESS
  if (snapshot == -1) return null;
  final first = _kernel32
      .lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>),
        int Function(int, Pointer<Uint8>)
      >('Process32FirstW');
  final next = _kernel32
      .lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>),
        int Function(int, Pointer<Uint8>)
      >('Process32NextW');
  // PROCESSENTRY32W (x64): dwSize, cntUsage, th32ProcessID at 8,
  // th32ParentProcessID at 32; 568 bytes.
  const size = 568;
  final entry = calloc<Uint8>(size);
  try {
    entry.cast<Uint32>().value = size;
    for (var ok = first(snapshot, entry); ok != 0; ok = next(snapshot, entry)) {
      final view = ByteData.sublistView(entry.asTypedList(size));
      if (view.getUint32(8, Endian.little) == pid) {
        return view.getUint32(32, Endian.little);
      }
    }
    return null;
  } finally {
    calloc.free(entry);
    _closeHandle(snapshot);
  }
}

TomSecretsProcessInfo? _windowsInfo(int pid) {
  final handle = _openProcess(_processQueryLimitedInformation, pid);
  if (handle == 0) return null;
  try {
    final exe = _windowsExe(handle);
    final start = _windowsStartTime(pid);
    final uid = _windowsSid(pid);
    if (exe == null || start == null || uid == null) return null;
    return TomSecretsProcessInfo(
      pid: pid,
      exe: tomSecretsRealPath(exe, null),
      args: _windowsArgs(handle),
      cwd: _windowsCwd(pid),
      startTime: start,
      parentPid: _windowsParent(pid),
      uid: uid,
    );
  } finally {
    _closeHandle(handle);
  }
}
