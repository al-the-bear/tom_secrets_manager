// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The ssh-agent's named pipe on Windows (part-os-integration): `dart:io`
/// cannot serve a named pipe, so the service serves it through FFI
/// (`CreateNamedPipeW`, `ConnectNamedPipe`, `ReadFile`, `WriteFile`) and
/// reads the client's process with `GetNamedPipeClientProcessId`.
///
/// - The pipe's ACL grants only this user and SYSTEM; remote clients are
///   rejected (`PIPE_REJECT_REMOTE_CLIENTS`); a second service cannot open
///   the same name (`FILE_FLAG_FIRST_PIPE_INSTANCE`).
/// - The waiting calls run in isolates: one waits for connections, one per
///   connection reads a whole agent message, hands it to the service, waits
///   for the answer and writes it before it reads on (the agent protocol
///   answers every message once).
/// - The handles are overlapped, each isolate waits on its own operation,
///   and the service ends a wait with `CancelIoEx` from its own isolate (a
///   stop flag in shared memory tells the isolate to end): a waiting
///   isolate never keeps the service's process from ending.
library;

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show tomSecretsSshAgentMaxMessage;

import 'agent.dart';
import 'peer_identity.dart';

/// Shared memory between the service and one waiting isolate: the handle
/// it waits on (`[0]`) and the stop flag (`[1]`).
final class _Control {
  _Control() : cell = calloc<IntPtr>(2);
  _Control.at(int address) : cell = Pointer<IntPtr>.fromAddress(address);

  final Pointer<IntPtr> cell;

  int get address => cell.address;

  int get handle => cell[0];
  set handle(int h) => cell[0] = h;

  bool get stopped => cell[1] != 0;

  /// Stops the isolate: the flag set, its wait cancelled (again, until it
  /// has seen the flag; [done] completes when it has).
  Future<void> stop(Future<void> done) async {
    cell[1] = 1;
    for (var i = 0; i < 40; i++) {
      final h = handle;
      if (h != 0) _cancelIoEx(h, nullptr);
      final ended = await done
          .then((_) => true)
          .timeout(const Duration(milliseconds: 50), onTimeout: () => false);
      if (ended) break;
    }
  }

  void free() => calloc.free(cell);
}

/// The agent's named pipe server.
final class TomSecretsAgentPipeServer {
  TomSecretsAgentPipeServer._(this.name, this._control, this._ended);

  /// Serves [name], handing each connection to [onChannel]; [measure]
  /// measures a client by its process id. Throws [StateError] when the pipe
  /// cannot be made (another process serves the name, no Windows).
  static Future<TomSecretsAgentPipeServer> start(
    String name, {
    required void Function(TomSecretsAgentChannel channel) onChannel,
    required Future<TomSecretsPeerMeasurement> Function(int pid) measure,
  }) async {
    if (!Platform.isWindows) throw StateError('named pipes are Windows only');
    final sid = tomSecretsOwnUid();
    if (sid is! String) throw StateError('no SID of this user');
    final control = _Control();
    final port = ReceivePort();
    final events = StreamIterator(port);
    final ended = Completer<void>();
    await Isolate.spawn(
      _listen,
      _ListenArgs(
        name,
        'D:P(A;;GA;;;$sid)(A;;GA;;;SY)',
        port.sendPort,
        control.address,
      ),
    );
    if (!await events.moveNext() || events.current != 'ready') {
      final why = events.current;
      port.close();
      control.free();
      throw StateError('the pipe $name cannot be served: $why');
    }
    final server = TomSecretsAgentPipeServer._(name, control, ended.future);
    unawaited(() async {
      while (await events.moveNext()) {
        final m = events.current;
        if (m == null) break;
        if (m is List && m.length == 2) {
          onChannel(await _PipeChannel.open(m[0] as int, m[1] as int, measure));
        }
      }
      port.close();
      ended.complete();
    }());
    return server;
  }

  /// The pipe's name.
  final String name;
  final _Control _control;
  final Future<void> _ended;

  /// Stops accepting; the listening isolate ends.
  Future<void> close() async {
    await _control.stop(_ended);
    _control.free();
  }
}

final class _ListenArgs {
  const _ListenArgs(this.name, this.sddl, this.port, this.control);
  final String name;
  final String sddl;
  final SendPort port;
  final int control;
}

const int _pipeAccessDuplex = 0x3;
const int _fileFlagOverlapped = 0x40000000;
const int _firstPipeInstance = 0x00080000;
const int _pipeRejectRemote = 0x8;
const int _errorPipeConnected = 535;

/// An OVERLAPPED with its own manual-reset event (32 bytes on x64; hEvent at
/// 24).
final class _Overlapped {
  _Overlapped() : pointer = calloc<Uint8>(32) {
    event = _createEvent(nullptr, 1, 0, nullptr);
    (pointer + 24).cast<IntPtr>().value = event;
  }

  final Pointer<Uint8> pointer;
  late final int event;

  Pointer<Void> get ov => pointer.cast();

  void reset() {
    pointer.asTypedList(24).fillRange(0, 24, 0);
    _resetEvent(event);
  }

  void free() {
    _closeHandle(event);
    calloc.free(pointer);
  }
}

/// `STATUS_PENDING`, which `OVERLAPPED.Internal` holds while an operation
/// is queued.
const int _statusPending = 0x103;

/// Finishes an overlapped call that answered [ok] on [handle]: waits for a
/// queued one. Whether it succeeded; [transferred] gets the bytes. Queued
/// is read from the OVERLAPPED's status (as `HasOverlappedIoCompleted`
/// does), never from `GetLastError`, which another call of the runtime may
/// have overwritten.
bool _finish(int handle, _Overlapped o, int ok, Pointer<Uint32> transferred) {
  if (ok != 0) return true;
  if (o.pointer.cast<IntPtr>().value != _statusPending) return false;
  return _getOverlappedResult(handle, o.ov, transferred, 1) != 0;
}

/// The listening isolate: makes a pipe instance, waits for a client, hands
/// the connected handle and the client's process id over, and makes the
/// next instance, until it is stopped.
Future<void> _listen(_ListenArgs args) async {
  final control = _Control.at(args.control);
  final name = args.name.toNativeUtf16();
  final sddl = args.sddl.toNativeUtf16();
  final descriptor = calloc<Pointer<Void>>();
  final attributes = calloc<Uint8>(24);
  final o = _Overlapped();
  final count = calloc<Uint32>();
  final pid = calloc<Uint32>();
  try {
    if (_convertSddl(sddl, 1, descriptor, nullptr) == 0) {
      args.port.send('sddl ${_getLastError()}');
      return;
    }
    attributes.cast<Uint32>()[0] = 24;
    (attributes + 8).cast<Pointer<Void>>().value = descriptor.value;
    var first = true;
    while (!control.stopped) {
      final handle = _createNamedPipe(
        name,
        _pipeAccessDuplex |
            _fileFlagOverlapped |
            (first ? _firstPipeInstance : 0),
        _pipeRejectRemote,
        255,
        65536,
        65536,
        0,
        attributes.cast(),
      );
      if (handle == -1) {
        args.port.send(first ? 'create ${_getLastError()}' : null);
        return;
      }
      if (first) {
        args.port.send('ready');
        first = false;
      }
      control.handle = handle;
      o.reset();
      final ok = _connectNamedPipe(handle, o.ov);
      final connected =
          (ok == 0 && _getLastError() == _errorPipeConnected) ||
          _finish(handle, o, ok, count);
      control.handle = 0;
      if (!connected || control.stopped) {
        _closeHandle(handle);
        continue;
      }
      pid.value = 0;
      _getClientProcessId(handle, pid);
      args.port.send([handle, pid.value]);
    }
    args.port.send(null);
  } finally {
    o.free();
    calloc
      ..free(name)
      ..free(sddl)
      ..free(descriptor)
      ..free(attributes)
      ..free(count)
      ..free(pid);
  }
}

/// One connection on the service's side.
final class _PipeChannel implements TomSecretsAgentChannel {
  _PipeChannel._(this.pid, this._measure, this._control);

  static Future<_PipeChannel> open(
    int handle,
    int pid,
    Future<TomSecretsPeerMeasurement> Function(int pid) measure,
  ) async {
    final control = _Control();
    final channel = _PipeChannel._(pid, measure, control);
    final port = ReceivePort();
    final events = StreamIterator(port);
    await Isolate.spawn(
      _serve,
      _ServeArgs(handle, port.sendPort, control.address),
    );
    await events.moveNext();
    channel._to = events.current as SendPort;
    unawaited(() async {
      while (await events.moveNext()) {
        final m = events.current;
        if (m is TransferableTypedData) {
          channel._input.add(m.materialize().asUint8List());
        } else {
          break;
        }
      }
      port.close();
      channel._ended.complete();
      await channel._input.close();
    }());
    return channel;
  }

  final int pid;
  final Future<TomSecretsPeerMeasurement> Function(int pid) _measure;
  final _Control _control;
  final StreamController<List<int>> _input = StreamController();
  final Completer<void> _ended = Completer();
  late final SendPort _to;
  bool _closed = false;

  @override
  Stream<List<int>> get input => _input.stream;

  @override
  void send(List<int> bytes) {
    if (_ended.isCompleted) return;
    _to.send(TransferableTypedData.fromList([Uint8List.fromList(bytes)]));
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    if (!_ended.isCompleted) _to.send(null);
    await _control.stop(_ended.future);
    _control.free();
  }

  @override
  Future<TomSecretsPeerMeasurement> measure() => _measure(pid);
}

final class _ServeArgs {
  const _ServeArgs(this.handle, this.port, this.control);
  final int handle;
  final SendPort port;
  final int control;
}

/// A connection's isolate: reads one whole agent message, hands it over,
/// writes the answer, and again, until the client or the service ends it.
Future<void> _serve(_ServeArgs args) async {
  final handle = args.handle;
  final control = _Control.at(args.control);
  final port = ReceivePort();
  args.port.send(port.sendPort);
  final answers = StreamIterator(port);
  final count = calloc<Uint32>();
  final buffer = calloc<Uint8>(65536);
  final o = _Overlapped();

  Uint8List? readExact(int n) {
    final out = Uint8List(n);
    var got = 0;
    while (got < n) {
      if (control.stopped) return null;
      final want = n - got > 65536 ? 65536 : n - got;
      o.reset();
      control.handle = handle;
      final ok = _readFile(handle, buffer, want, count, o.ov);
      final done = _finish(handle, o, ok, count);
      control.handle = 0;
      if (!done || count.value == 0) return null;
      out.setRange(got, got + count.value, buffer.asTypedList(count.value));
      got += count.value;
    }
    return out;
  }

  bool writeAll(Uint8List bytes) {
    final out = calloc<Uint8>(bytes.length);
    try {
      out.asTypedList(bytes.length).setAll(0, bytes);
      var at = 0;
      while (at < bytes.length) {
        o.reset();
        control.handle = handle;
        final ok = _writeFile(handle, out + at, bytes.length - at, count, o.ov);
        final done = _finish(handle, o, ok, count);
        control.handle = 0;
        if (!done) return false;
        at += count.value;
      }
      return true;
    } finally {
      calloc.free(out);
    }
  }

  try {
    while (!control.stopped) {
      final header = readExact(4);
      if (header == null) break;
      final length = ByteData.sublistView(header).getUint32(0);
      if (length == 0 || length > tomSecretsSshAgentMaxMessage) break;
      final body = readExact(length);
      if (body == null) break;
      args.port.send(TransferableTypedData.fromList([header, body]));
      if (!await answers.moveNext()) break;
      final answer = answers.current;
      if (answer is! TransferableTypedData) break;
      if (!writeAll(answer.materialize().asUint8List())) break;
    }
  } finally {
    _disconnect(handle);
    _closeHandle(handle);
    o.free();
    calloc
      ..free(count)
      ..free(buffer);
    args.port.send(null);
    port.close();
  }
}

// ── kernel32 / advapi32 ──────────────────────────────────────────────────
//
// Looked up once per isolate (top-level finals are initialised on first
// use): a lookup between a call and its `GetLastError` would overwrite the
// error.

final DynamicLibrary _kernel32 = DynamicLibrary.open('kernel32.dll');
final DynamicLibrary _advapi32 = DynamicLibrary.open('advapi32.dll');

final int Function(Pointer<Utf16>, int, int, int, int, int, int, Pointer<Void>)
_createNamedPipe = _kernel32
    .lookupFunction<
      IntPtr Function(
        Pointer<Utf16>,
        Uint32,
        Uint32,
        Uint32,
        Uint32,
        Uint32,
        Uint32,
        Pointer<Void>,
      ),
      int Function(Pointer<Utf16>, int, int, int, int, int, int, Pointer<Void>)
    >('CreateNamedPipeW');

final int Function(int, Pointer<Void>) _connectNamedPipe = _kernel32
    .lookupFunction<
      Int32 Function(IntPtr, Pointer<Void>),
      int Function(int, Pointer<Void>)
    >('ConnectNamedPipe');

final int Function(int, Pointer<Uint32>) _getClientProcessId = _kernel32
    .lookupFunction<
      Int32 Function(IntPtr, Pointer<Uint32>),
      int Function(int, Pointer<Uint32>)
    >('GetNamedPipeClientProcessId');

final int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, Pointer<Void>)
_readFile = _kernel32
    .lookupFunction<
      Int32 Function(
        IntPtr,
        Pointer<Uint8>,
        Uint32,
        Pointer<Uint32>,
        Pointer<Void>,
      ),
      int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, Pointer<Void>)
    >('ReadFile');

final int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, Pointer<Void>)
_writeFile = _kernel32
    .lookupFunction<
      Int32 Function(
        IntPtr,
        Pointer<Uint8>,
        Uint32,
        Pointer<Uint32>,
        Pointer<Void>,
      ),
      int Function(int, Pointer<Uint8>, int, Pointer<Uint32>, Pointer<Void>)
    >('WriteFile');

final int Function(int, Pointer<Void>, Pointer<Uint32>, int)
_getOverlappedResult = _kernel32
    .lookupFunction<
      Int32 Function(IntPtr, Pointer<Void>, Pointer<Uint32>, Int32),
      int Function(int, Pointer<Void>, Pointer<Uint32>, int)
    >('GetOverlappedResult');

final int Function(int, Pointer<Void>) _cancelIoEx = _kernel32
    .lookupFunction<
      Int32 Function(IntPtr, Pointer<Void>),
      int Function(int, Pointer<Void>)
    >('CancelIoEx');

final int Function(Pointer<Void>, int, int, Pointer<Utf16>) _createEvent =
    _kernel32.lookupFunction<
      IntPtr Function(Pointer<Void>, Int32, Int32, Pointer<Utf16>),
      int Function(Pointer<Void>, int, int, Pointer<Utf16>)
    >('CreateEventW');

final int Function(int) _resetEvent = _kernel32
    .lookupFunction<Int32 Function(IntPtr), int Function(int)>('ResetEvent');

final int Function(int) _disconnect = _kernel32
    .lookupFunction<Int32 Function(IntPtr), int Function(int)>(
      'DisconnectNamedPipe',
    );

final int Function(int) _closeHandle = _kernel32
    .lookupFunction<Int32 Function(IntPtr), int Function(int)>('CloseHandle');

final int Function() _getLastError = _kernel32
    .lookupFunction<Uint32 Function(), int Function()>('GetLastError');

final int Function(Pointer<Utf16>, int, Pointer<Pointer<Void>>, Pointer<Uint32>)
_convertSddl = _advapi32
    .lookupFunction<
      Int32 Function(
        Pointer<Utf16>,
        Uint32,
        Pointer<Pointer<Void>>,
        Pointer<Uint32>,
      ),
      int Function(Pointer<Utf16>, int, Pointer<Pointer<Void>>, Pointer<Uint32>)
    >('ConvertStringSecurityDescriptorToSecurityDescriptorW');
