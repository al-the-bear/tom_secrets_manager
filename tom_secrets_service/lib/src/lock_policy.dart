// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Lock modes (part-service, IDEA-8, DP-14), for the app and the service
/// each: (a) never relock, (b) relock after the user's input has been idle
/// for a while; also a hard maximum unlocked time (off by default). Lock on
/// system sleep is the app's to sense: it sends `lock` when the service's
/// policy says so. Client inactivity is never a trigger.
///
/// **Headless never locks automatically**: where the input idle time cannot
/// be measured (a Linux server reached over SSH, no desktop session) the
/// service ignores the mode, the idle time and the maximum time, and locks
/// only on an explicit `lock`, `stop` or shutdown. Times are measured with a
/// monotonic stopwatch, so a jumping clock changes nothing.
library;

import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show TomSecretsLockPolicy;

/// The user's input idle time on the desktop session.
abstract interface class TomSecretsIdleSource {
  /// The idle time, or null when it cannot be measured (headless).
  Future<Duration?> idleTime();
}

/// The idle source of this OS: CoreGraphics on macOS, `GetLastInputInfo` on
/// Windows, logind's idle hint on Linux (none without a desktop session).
TomSecretsIdleSource tomSecretsSystemIdleSource() {
  if (Platform.isMacOS) return _MacIdleSource();
  if (Platform.isWindows) return _WindowsIdleSource();
  return _LogindIdleSource();
}

final class _MacIdleSource implements TomSecretsIdleSource {
  // CGEventSourceSecondsSinceLastEventType(kCGEventSourceStateCombined
  // SessionState = 0, kCGAnyInputEventType = ~0).
  late final double Function(int, int)? _call = () {
    try {
      final lib = DynamicLibrary.open(
        '/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics',
      );
      return lib.lookupFunction<
        Double Function(Int32, Uint32),
        double Function(int, int)
      >('CGEventSourceSecondsSinceLastEventType');
    } on Object {
      return null;
    }
  }();

  @override
  Future<Duration?> idleTime() async {
    final call = _call;
    if (call == null) return null;
    final seconds = call(0, 0xFFFFFFFF);
    if (seconds.isNaN || seconds < 0) return null;
    return Duration(milliseconds: (seconds * 1000).round());
  }
}

final class _LastInputInfo extends Struct {
  @Uint32()
  external int cbSize;

  @Uint32()
  external int dwTime;
}

final class _WindowsIdleSource implements TomSecretsIdleSource {
  @override
  Future<Duration?> idleTime() async {
    try {
      final user32 = DynamicLibrary.open('user32.dll');
      final kernel32 = DynamicLibrary.open('kernel32.dll');
      final getLastInputInfo = user32
          .lookupFunction<
            Int32 Function(Pointer<_LastInputInfo>),
            int Function(Pointer<_LastInputInfo>)
          >('GetLastInputInfo');
      final getTickCount = kernel32
          .lookupFunction<Uint32 Function(), int Function()>('GetTickCount');
      final info = calloc<_LastInputInfo>();
      try {
        info.ref.cbSize = sizeOf<_LastInputInfo>();
        if (getLastInputInfo(info) == 0) return null;
        final idle = (getTickCount() - info.ref.dwTime) & 0xFFFFFFFF;
        return Duration(milliseconds: idle);
      } finally {
        calloc.free(info);
      }
    } on Object {
      return null;
    }
  }
}

final class _LogindIdleSource implements TomSecretsIdleSource {
  @override
  Future<Duration?> idleTime() async {
    final env = Platform.environment;
    final session = env['XDG_SESSION_ID'];
    final graphical =
        (env['DISPLAY'] ?? '').isNotEmpty ||
        (env['WAYLAND_DISPLAY'] ?? '').isNotEmpty;
    if (session == null || !graphical) return null;
    try {
      final result = await Process.run('loginctl', [
        'show-session',
        session,
        '-p',
        'IdleHint',
        '-p',
        'IdleSinceHintMonotonic',
      ]);
      if (result.exitCode != 0) return null;
      final values = {
        for (final line in (result.stdout as String).split('\n'))
          if (line.contains('='))
            line.substring(0, line.indexOf('=')): line
                .substring(line.indexOf('=') + 1)
                .trim(),
      };
      if (values['IdleHint'] != 'yes') return Duration.zero;
      final since = int.tryParse(values['IdleSinceHintMonotonic'] ?? '');
      final uptime = double.tryParse(
        (await File('/proc/uptime').readAsString()).split(' ').first,
      );
      if (since == null || uptime == null) return null;
      final idle = (uptime * 1e6).round() - since;
      return Duration(microseconds: idle < 0 ? 0 : idle);
    } on Object {
      return null;
    }
  }
}

/// Watches the policy while the service is unlocked and locks it when the
/// policy says so.
final class TomSecretsLockTimer {
  /// A timer checking every [interval] with [source], calling [lock].
  TomSecretsLockTimer({
    required this.source,
    required this.lock,
    this.interval = const Duration(seconds: 15),
  });

  /// The idle source.
  final TomSecretsIdleSource source;

  /// Locks the service.
  final Future<void> Function(String reason) lock;

  /// How often the policy is checked.
  final Duration interval;

  Timer? _timer;
  final Stopwatch _unlocked = Stopwatch();
  TomSecretsLockPolicy _policy = const TomSecretsLockPolicy();
  bool _checking = false;

  /// How long the service has been unlocked (monotonic).
  Duration get unlockedFor => _unlocked.elapsed;

  /// Starts watching [policy] (at an unlock).
  void start(TomSecretsLockPolicy policy) {
    _policy = policy;
    _unlocked
      ..reset()
      ..start();
    _timer?.cancel();
    _timer = Timer.periodic(interval, (_) => check());
  }

  /// Stops watching (at a lock).
  void stop() {
    _timer?.cancel();
    _timer = null;
    _unlocked
      ..stop()
      ..reset();
  }

  /// Checks the policy once; locks when it says so.
  Future<void> check() async {
    if (_checking || _timer == null) return;
    _checking = true;
    try {
      final idle = await source.idleTime();
      if (_timer != null &&
          _policy.shouldLock(idle: idle, unlockedFor: unlockedFor)) {
        stop();
        await lock(
          idle != null &&
                  _policy.maxUnlocked != null &&
                  unlockedFor >= _policy.maxUnlocked!
              ? 'maximum unlocked time'
              : 'idle',
        );
      }
    } finally {
      _checking = false;
    }
  }
}
