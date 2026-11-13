// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The secrets service (part-service): the runtime directory and its lock,
/// the client endpoint (read-only `get`), the admin endpoint (the mutual
/// challenge or `claim`, then unlock, lock, status, subscribe, shutdown),
/// the vaults while unlocked, the device settings container, and the lock
/// policy.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:tom_core_storage/settings.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'access.dart';
import 'admin_auth.dart';
import 'bootstrap.dart';
import 'connection.dart';
import 'identity.dart';
import 'lock_policy.dart';
import 'log.dart';
import 'peer_identity.dart';
import 'runtime.dart';
import 'secret_frame.dart';
import 'vault_set.dart';

/// The service name of the product's items in the OS keychain.
const String tomSecretsKeychainService = 'tom-secrets-manager';

/// The service's version, sent in `welcome` and `challenge`.
const String tomSecretsServiceVersion = '0.1.0';

/// The admin requests of later parts the service does not answer yet; they
/// are answered `unsupported` like an unknown `op`.
const Set<String> tomSecretsLaterAdminOps = {
  'reload',
  'approve',
  'approval.redeem',
  'approval.issue',
  'grants.list',
  'grants.add',
  'grants.revoke',
  'approvers.cliSwitch',
  'audit.query',
};

/// What a service is started with.
final class TomSecretsServiceConfig {
  /// A configuration; [adminKey] is the key the starter handed over.
  TomSecretsServiceConfig({
    required this.runtime,
    required this.bootstrap,
    required this.adminKey,
    this.opener = const TomSecretsFileOpener(),
    TomSecretsIdleSource? idleSource,
    this.keychain,
    this.policy = const TomSecretsDenyAllPolicy(),
    String? host,
    this.lockCheckInterval = const Duration(seconds: 15),
    this.authDelay = tomSecretsAuthDelay,
    this.harden,
    TomSecretsLog? log,
    TomSecretsPeerMeasurer? peerMeasurer,
    this.adminExecutables,
  }) : peerMeasurer = peerMeasurer ?? TomSecretsSystemPeerMeasurer(),
       idleSource = idleSource ?? tomSecretsSystemIdleSource(),
       host =
           host ??
           bootstrap.host ??
           Platform.localHostname.split('.').first.toLowerCase(),
       log = log ?? TomSecretsLog(bootstrap.logFile, level: bootstrap.logLevel);

  /// The runtime directory.
  final TomSecretsRuntime runtime;

  /// The bootstrap file.
  final TomSecretsBootstrap bootstrap;

  /// The admin key (32 bytes).
  final Uint8List adminKey;

  /// Opens and saves vault files.
  final TomSecretsVaultOpener opener;

  /// The input idle time (lock mode (b)).
  final TomSecretsIdleSource idleSource;

  /// The OS keychain, or null where none is available.
  final TomSecretStore? keychain;

  /// Who may read a value.
  final TomSecretsAccessPolicy policy;

  /// This machine's host name.
  final String host;

  /// How often the lock policy is checked.
  final Duration lockCheckInterval;

  /// The delay after a number of failed admin authentications.
  final Duration Function(int failures) authDelay;

  /// Hardens the process at start and answers what it achieved
  /// (`status.hardening`); the binary passes `tomSecretsHardenProcess`, an
  /// in-process service (tests) none.
  final Map<String, bool> Function()? harden;

  /// The operational log (default `<data>/service.log`).
  final TomSecretsLog log;

  /// Measures the process at the other end of each accepted connection
  /// (part-protocol, the peer identity); default this OS's.
  final TomSecretsPeerMeasurer peerMeasurer;

  /// The real paths of the executables an admin may be (the manager app's,
  /// `tsm`'s; protocol.md 6.1): any other admin is refused even with the
  /// right key (`denied`, `wrong_executable`). The binary always passes the
  /// set; null (an in-process service in tests) does not check.
  final Set<String>? adminExecutables;
}

/// The executables that may administer a service started from
/// [serviceExecutable] with [bootstrap] (protocol.md 6.1), as real paths:
/// `tsm` and the manager app (`tom_secrets_desktop`, `tom_secrets_app`)
/// beside the service's executable, and the bootstrap's
/// `admin_executables`.
Set<String> tomSecretsAdminExecutables(
  String serviceExecutable,
  TomSecretsBootstrap bootstrap,
) {
  final dir = File(serviceExecutable).parent.path;
  final ext = Platform.isWindows ? '.exe' : '';
  return {
    for (final name in ['tsm', 'tom_secrets_desktop', 'tom_secrets_app'])
      tomSecretsRealPath('$dir${Platform.pathSeparator}$name$ext', null),
    for (final path in bootstrap.adminExecutables)
      tomSecretsRealPath(path, null),
  };
}

/// A running service.
final class TomSecretsService {
  TomSecretsService._(this.config) : _adminKey = config.adminKey;

  /// Starts the service: prepares and locks the runtime directory, checks
  /// the device key's mode (a `keychain` mode without a keychain refuses the
  /// start), removes a dead instance's endpoint files, opens both endpoints
  /// and writes `service.json`. It starts locked. Throws
  /// [TomSecretsAlreadyRunning] when another service holds the lock.
  static Future<TomSecretsService> launch(
    TomSecretsServiceConfig config,
  ) async {
    final service = TomSecretsService._(config);
    service._hardening = config.harden?.call() ?? const {};
    final runtime = config.runtime;
    await runtime.prepare();
    await runtime.acquire();
    try {
      await service._deviceKeys.effectiveMode();
      await runtime.removeStaleEndpoints();
      await service._bind();
    } on Object catch (e) {
      config.log.error('start_failed', e);
      await service._closeServers();
      await runtime.removeEndpoints();
      await runtime.release();
      rethrow;
    }
    config.log.info('start', {
      'version': tomSecretsServiceVersion,
      'pid': pid,
      'platform': Platform.operatingSystem,
      'transport': runtime.transport.name,
      'host': config.host,
      for (final e in service._hardening.entries) e.key: e.value,
    });
    return service;
  }

  Map<String, bool> _hardening = const {};

  /// The operational log.
  TomSecretsLog get log => config.log;

  /// The configuration.
  final TomSecretsServiceConfig config;

  /// The start time, milliseconds since the epoch.
  final int startedAt = DateTime.now().millisecondsSinceEpoch;

  Uint8List _adminKey;
  late final TomSecretsVaultSet _vaults = TomSecretsVaultSet(
    opener: config.opener,
  );
  late final TomSecretsDeviceKeys _deviceKeys = TomSecretsDeviceKeys(
    mode: config.bootstrap.deviceKey,
    host: config.host,
    containerPath: config.bootstrap.deviceContainer,
    keychain: config.keychain,
  );
  late final TomSecretsLockTimer _lockTimer = TomSecretsLockTimer(
    source: config.idleSource,
    lock: (reason) => lock(reason: reason),
    interval: config.lockCheckInterval,
  );
  TomSecretsDeviceContainer? _device;
  ServerSocket? _clientServer;
  ServerSocket? _adminServer;
  String _clientToken = '';
  final Set<_ClientSession> _clients = {};
  final Set<_AdminSession> _admins = {};
  int _authFailures = 0;
  final Completer<void> _done = Completer<void>();
  Completer<void> _unlocked = Completer<void>();
  bool _stopping = false;

  /// Completes when the service has stopped.
  Future<void> get done => _done.future;

  /// Whether the service is locked.
  bool get isLocked => !_vaults.isUnlocked;

  /// The device settings (defaults while locked).
  TomSecretsDeviceSettings get settings =>
      _device?.settings ?? const TomSecretsDeviceSettings();

  /// The device settings container, open while unlocked.
  TomSecretsDeviceContainer? get deviceContainer => _device;

  /// The vaults.
  TomSecretsVaultSet get vaults => _vaults;

  /// The client token of this start (TCP transport).
  String get clientToken => _clientToken;

  /// The machine resolution runs for.
  TomSecretsMachine get machine => TomSecretsMachine.current(
    host: config.host,
    values: {'env': ?settings.defaultEnvironment},
  );

  Future<void> _bind() async {
    final runtime = config.runtime;
    switch (runtime.transport) {
      case TomSecretsTransport.unix:
        _clientServer = await ServerSocket.bind(
          InternetAddress(runtime.clientSocket, type: InternetAddressType.unix),
          0,
        );
        _adminServer = await ServerSocket.bind(
          InternetAddress(runtime.adminSocket, type: InternetAddressType.unix),
          0,
        );
      case TomSecretsTransport.tcp:
        _clientServer = await ServerSocket.bind(
          InternetAddress.loopbackIPv4,
          0,
        );
        _adminServer = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        _clientToken = base64.encode(tomSecretsRandomBytes());
        await runtime.writeToken(_clientToken);
        await runtime.writePort(runtime.clientPortFile, _clientServer!.port);
        await runtime.writePort(runtime.adminPortFile, _adminServer!.port);
    }
    _clientServer!.listen((socket) => _ClientSession(this, socket));
    _adminServer!.listen((socket) => _AdminSession(this, socket));
    Map<String, Object?> endpoint(ServerSocket server, String socket) =>
        runtime.transport == TomSecretsTransport.unix
        ? {'socket': socket}
        : {'port': server.port};
    await runtime.writeInfo(
      start: startedAt,
      client: endpoint(_clientServer!, runtime.clientSocket),
      admin: endpoint(_adminServer!, runtime.adminSocket),
    );
  }

  Future<void> _closeServers() async {
    await _clientServer?.close();
    await _adminServer?.close();
  }

  /// Unlocks with [keys] (the master password and key file, which the
  /// service holds masked while unlocked): opens the primary, the device
  /// settings container (its key where `bootstrap.yaml` says), then the
  /// stores the machine serves; starts the lock policy. Throws
  /// [KdbxInvalidKeyException] for a wrong password; [keys] are disposed
  /// when the unlock fails.
  Future<void> unlock(TomSecretsHeldKeys keys) async {
    final primaryLocator = config.bootstrap.primary;
    final TomSecretsOpenedVault primary;
    try {
      primary = await _vaults.openPrimary(primaryLocator, keys);
    } on Object {
      keys.dispose();
      rethrow;
    }
    try {
      final key = await _deviceKeys.keyFor(
        primary: primary.file,
        savePrimary: _vaults.writePrimary,
      );
      _device = await TomSecretsDeviceContainer.open(
        config.bootstrap.deviceContainer,
        key,
      );
      await _vaults.openStores(machine: machine, served: settings.servedStores);
    } on Object {
      _vaults.lock();
      _device = null;
      rethrow;
    }
    _lockTimer.start(settings.serviceLock);
    if (!_unlocked.isCompleted) _unlocked.complete();
    final states = _vaults.status.map((s) => s.state.wireName).toList();
    log.info('unlock', {
      'stores': states.length,
      'current': states.where((s) => s == 'current').length,
      'needsUnlock': states.where((s) => s == 'needs_unlock').length,
      'unavailable': states.where((s) => s == 'unavailable').length,
    });
    _emit({'op': 'unlocked'});
  }

  /// Locks: drops the vaults, the index, the device settings and every
  /// protected value the service holds; the admin key survives.
  Future<void> lock({String reason = 'admin'}) async {
    if (isLocked) return;
    _lockTimer.stop();
    _vaults.lock();
    _device = null;
    _unlocked = Completer<void>();
    log.info('lock', {'reason': reason});
    _emit({'op': 'locked'});
  }

  /// Stops: locks, closes the endpoints, deletes the endpoint files and
  /// `service.json`, releases the lock.
  Future<void> stop() async {
    if (_stopping) return _done.future;
    _stopping = true;
    await lock(reason: 'stop');
    await _closeServers();
    for (final c in [..._clients]) {
      await c.connection.close();
    }
    for (final a in [..._admins]) {
      await a.connection.close();
    }
    await config.runtime.removeEndpoints();
    await config.runtime.release();
    log.info('stop');
    if (!_done.isCompleted) _done.complete();
  }

  /// Waits up to [timeout] for an unlock; whether the service is unlocked.
  Future<bool> waitUnlocked(Duration timeout) async {
    if (!isLocked) return true;
    try {
      await _unlocked.future.timeout(timeout);
    } on TimeoutException {
      return false;
    }
    return !isLocked;
  }

  bool get _hasSubscribers => _admins.any((a) => a.subscribed);

  void _emit(Map<String, Object?> event) {
    for (final a in _admins) {
      if (a.subscribed) a.connection.send(event);
    }
  }

  /// The `statusReport` members.
  Map<String, Object?> statusReport() => {
    'locked': isLocked,
    'lockMode': settings.serviceLock.mode.name,
    'protocol': 1,
    'service': {'version': tomSecretsServiceVersion, 'start': startedAt},
    'stores': [for (final s in _vaults.status) s.toJson()],
    'admins': _admins.where((a) => a.authenticated).length,
    'hardening': _hardening,
  };

  /// Takes the app's edited file of [store] (protocol.md 6.4), tells the
  /// subscribers (`store_changed`) and logs it.
  Future<TomSecretsSaveResult> save(
    String store,
    Uint8List stored, {
    String? baseRevision,
  }) async {
    final result = await _vaults.save(
      store,
      stored,
      baseRevision: baseRevision,
    );
    log.info('save', {
      'store': store,
      'merged': result.merged,
      'conflicts': result.conflicts,
    });
    _emit({'op': 'store_changed', 'store': store, 'revision': result.revision});
    return result;
  }
}

/// The keys a request's `password` and `keyFile` (base64) carry, held masked;
/// null when they cannot be read.
TomSecretsHeldKeys? _keysOf(Map<String, Object?> m) {
  final password = m['password'];
  final keyFile = m['keyFile'];
  if (password is! String || (keyFile != null && keyFile is! String)) {
    return null;
  }
  try {
    return TomSecretsHeldKeys.of(
      password: password,
      keyFile: keyFile == null ? null : base64.decode(keyFile as String),
    );
  } on FormatException {
    return null;
  }
}

const int _maxId = 9007199254740991; // 2^53 - 1

bool _validId(Object? id) => id is int && id >= 1 && id <= _maxId;

/// One client connection.
final class _ClientSession {
  _ClientSession(this.service, Socket socket) {
    // Measured once, when accepted (part-protocol); messages wait for it,
    // in the order they came.
    final measured = _measure(socket);
    connection = TomSecretsConnection(
      socket,
      onMessage: (m) => measured.then((ok) {
        if (ok) {
          _message(m);
        } else {
          // Refused: the answer went out; its hello is read, then it ends.
          unawaited(connection.close());
        }
      }),
      onClosed: () => service._clients.remove(this),
    );
    service._clients.add(this);
  }

  final TomSecretsService service;
  late final TomSecretsConnection connection;
  TomSecretsIdentity? _identity;
  bool _greeted = false;

  Future<bool> _measure(Socket socket) async {
    final measurement = await service.config.peerMeasurer.measure(socket);
    switch (measurement) {
      case TomSecretsPeerMeasured(:final identity):
        _identity = identity;
        service.log.debug('client_identity', {
          'kind': identity.kind,
          'exe': identity.exe,
          'script': identity.script,
          'pid': identity.pid,
        });
        return true;
      case TomSecretsPeerRefused(:final reason, :final detail):
        service.log.info('client_refused', {
          'reason': reason,
          'detail': detail,
        });
        // Answered at once and closed once its hello has come (or after 5
        // s): closed before that, the client's hello would meet a closed
        // socket and never read the answer.
        connection.sendError(null, 'denied', 'the client is refused', {
          'reason': reason,
        });
        Timer(const Duration(seconds: 5), () => unawaited(connection.close()));
        return false;
    }
  }

  Map<String, Object?> _client = const {};
  final Set<int> _open = {};

  void _message(Map<String, Object?> m) {
    final op = m['op'] as String;
    if (!_greeted) {
      _hello(op, m);
      return;
    }
    final id = m['id'];
    if (op == 'get' || op == 'getMany') {
      if (!_validId(id)) {
        connection.sendError(null, 'malformed', 'a request carries an id', {
          'reason': 'frame',
        });
        unawaited(connection.close());
        return;
      }
      if (!_open.add(id as int)) {
        connection.sendError(id, 'malformed', 'the id is in use', {
          'reason': 'duplicate_id',
        });
        return;
      }
      unawaited(_request(id, op, m).whenComplete(() => _open.remove(id)));
      return;
    }
    connection.sendError(
      _validId(id) ? id : null,
      'unsupported',
      'unknown op $op',
      {'op': op},
    );
  }

  void _hello(String op, Map<String, Object?> m) {
    if (op != 'hello') {
      connection.sendError(null, 'malformed', 'the first frame is hello', {
        'reason': 'frame',
      });
      unawaited(connection.close());
      return;
    }
    if (m['protocol'] != 1) {
      connection.sendError(
        null,
        'unsupported',
        'the service speaks protocol 1',
        {
          'protocols': [1],
        },
      );
      unawaited(connection.close());
      return;
    }
    if (service.config.runtime.transport == TomSecretsTransport.tcp) {
      final token = m['token'];
      if (token is! String ||
          !tomSecretsConstantTimeEquals(
            utf8.encode(token),
            utf8.encode(service.clientToken),
          )) {
        connection.sendError(null, 'denied', 'the client token is wrong', {
          'reason': 'bad_token',
        });
        unawaited(connection.close());
        return;
      }
    }
    _greeted = true;
    final client = m['client'];
    _client = client is Map ? client.cast<String, Object?>() : const {};
    service.log.debug('client', {
      'name': _client['name'],
      'version': _client['version'],
      'language': _client['language'],
    });
    connection.send({
      'op': 'welcome',
      'protocol': 1,
      'service': {'version': tomSecretsServiceVersion},
      'features': const <String>[],
      'host': service.config.host,
      'platform': Platform.operatingSystem,
    });
  }

  Future<void> _request(int id, String op, Map<String, Object?> m) async {
    final List<Map<String, Object?>> items;
    if (op == 'get') {
      items = [m];
    } else {
      final refs = m['refs'];
      if (refs is! List || refs.isEmpty || refs.length > 256) {
        connection.sendError(id, 'malformed', 'refs is a list of 1 to 256', {
          'reason': 'refs',
        });
        return;
      }
      if (refs.any((r) => r is! Map)) {
        connection.sendError(id, 'malformed', 'each ref is an object', {
          'reason': 'refs',
        });
        return;
      }
      items = [for (final r in refs) (r as Map).cast<String, Object?>()];
    }
    if (service.isLocked) {
      final wait = m['wait'] != false;
      final timeoutMs = m['timeoutMs'];
      var timeout = service.settings.approvalTimeout;
      if (timeoutMs is int &&
          timeoutMs >= 0 &&
          timeoutMs < timeout.inMilliseconds) {
        timeout = Duration(milliseconds: timeoutMs);
      }
      if (wait && service._hasSubscribers) {
        service._emit({'op': 'unlock_needed', 'identity': _identity!.toJson()});
        connection.send({'op': 'progress', 'id': id, 'pending': 'unlock'});
        if (!await service.waitUnlocked(timeout)) {
          connection.sendError(id, 'locked', 'the service is locked');
          return;
        }
      } else {
        connection.sendError(id, 'locked', 'the service is locked');
        return;
      }
    }
    // The values stay masked until the frame is written from their bytes,
    // and are zeroed right after.
    final held = <TomSecretsFieldValue>[];
    try {
      final results = [for (final item in items) await _resolve(item, held)];
      if (op == 'get') {
        connection.send({...results.single, 'id': id});
      } else {
        connection.send({'op': 'values', 'id': id, 'results': results});
      }
      service.log.info(op, {
        'outcome': [for (final r in results) r['kind'] ?? 'value'],
      });
      service.log.debug(op, {
        'refs': [for (final item in items) item['ref']],
      });
    } finally {
      for (final value in held) {
        value.dispose();
      }
    }
  }

  Map<String, Object?> _error(
    String kind,
    String message, [
    Map<String, Object?>? details,
  ]) => {'op': 'error', 'kind': kind, 'message': message, 'details': ?details};

  /// The answer to [item]; its value, as a [TomSecretsSecretSlot], is added
  /// to [held] for the caller to dispose once the frame is written.
  Future<Map<String, Object?>> _resolve(
    Map<String, Object?> item,
    List<TomSecretsFieldValue> held,
  ) async {
    final ref = item['ref'];
    if (ref is! String) {
      return _error('malformed', 'ref is missing', {'reason': 'ref'});
    }
    if (utf8.encode(ref).length > 1024) {
      return _error('malformed', 'the reference is over 1 KiB', {
        'reason': 'too_long',
      });
    }
    final dims = item['dimensions'];
    if (dims != null &&
        (dims is! Map || dims.values.any((v) => v is! String))) {
      return _error('malformed', 'dimensions map names to strings', {
        'reason': 'dimensions',
      });
    }
    final field = item['field'];
    if (field != null && field is! String) {
      return _error('malformed', 'field is a string', {'reason': 'field'});
    }
    final storeName = _storeOf(ref);
    final status = storeName == null
        ? null
        : service.vaults.statusOf(storeName);
    if (status?.state == TomSecretsStoreState.needsUnlock) {
      return _error('needs_unlock', 'the store needs its own unlock', {
        'store': storeName,
      });
    }
    if (status?.state == TomSecretsStoreState.unavailable) {
      return _error('unavailable', 'the store could not be opened', {
        'store': storeName,
        'reason': 'no_cache',
      });
    }
    final resolver = service.vaults.resolver;
    if (resolver == null) return _error('locked', 'the service is locked');
    final TomSecretsResolution resolution;
    try {
      resolution = resolver.resolve(
        ref,
        dimensions: dims == null
            ? const {}
            : (dims as Map).cast<String, String>(),
        field: field as String?,
      );
    } on TomSecretsResolveException catch (e) {
      return _error(e.kind.wireName, e.message, e.details);
    }
    final access = await service.config.policy.check(
      TomSecretsAccessRequest(
        reference: ref,
        resolution: resolution,
        client: _client,
        identity: _identity!,
      ),
    );
    final value = resolution.value;
    held.add(value);
    if (access is TomSecretsAccessDenied) {
      return _error('denied', 'not allowed', {'reason': access.reason});
    }
    final entry = resolution.entry;
    final storeStatus = service.vaults.statusOf(entry.store);
    final fetchedAt = (storeStatus?.fetchedAt ?? DateTime.now()).toUtc();
    return {
      'op': 'value',
      'value': TomSecretsSecretSlot.ofValue(value),
      'encoding': value.isText ? 'utf8' : 'base64',
      'entry': {
        'store': entry.store,
        'uuid': tomSecretsUuidHex(entry.entry.uuid),
        'source': storeStatus?.wireSource ?? 'github',
        'fetchedAt': fetchedAt.toIso8601String(),
      },
      'bound': resolution.bound,
      'version': {
        'modified': (resolution.modified?.toUtc() ?? fetchedAt)
            .toIso8601String(),
        'revision': storeStatus?.revision ?? '',
      },
      'expires': ?resolution.expires?.toUtc().toIso8601String(),
    };
  }

  static String? _storeOf(String ref) {
    try {
      final target = TomSecretReference.parse(ref).target;
      return switch (target) {
        TomSecretPathTarget(:final store) => store,
        TomSecretUuidTarget(:final store) => store,
        _ => null,
      };
    } on Object {
      return null;
    }
  }
}

/// One admin connection.
final class _AdminSession {
  _AdminSession(this.service, Socket socket) {
    _measured = service.config.peerMeasurer.measure(socket);
    connection = TomSecretsConnection(
      socket,
      onMessage: (m) => unawaited(_message(m)),
      onClosed: () => service._admins.remove(this),
    );
    service._admins.add(this);
    connection.send({
      'op': 'challenge',
      'serviceNonce': base64.encode(_serviceNonce),
      'serviceStart': service.startedAt,
      'protocol': 1,
      'service': {'version': tomSecretsServiceVersion},
    });
  }

  final TomSecretsService service;
  late final TomSecretsConnection connection;
  final Uint8List _serviceNonce = tomSecretsRandomBytes();
  bool authenticated = false;
  bool subscribed = false;
  bool _authenticating = false;
  late final Future<TomSecretsPeerMeasurement> _measured;

  /// Whether the admin's measured executable may administer (protocol.md
  /// 6.1); refuses and closes the connection otherwise.
  Future<bool> _checkExecutable() async {
    final measurement = await _measured;
    final String reason;
    switch (measurement) {
      case TomSecretsPeerRefused(reason: final r):
        reason = r;
      case TomSecretsPeerMeasured(:final identity):
        final allowed = service.config.adminExecutables;
        if (allowed == null || allowed.contains(identity.exe)) return true;
        reason = 'wrong_executable';
        service.log.debug('admin_executable', {'exe': identity.exe});
    }
    service.log.info('admin_refused', {'reason': reason});
    connection.sendError(null, 'denied', 'this program may not administer', {
      'reason': reason,
    });
    await connection.close();
    return false;
  }

  Future<void> _message(Map<String, Object?> m) async {
    final op = m['op'] as String;
    if (!authenticated) {
      if (_authenticating) return;
      if (op != 'auth' && op != 'claim') {
        connection.sendError(null, 'malformed', 'authenticate first', {
          'reason': 'frame',
        });
        await connection.close();
        return;
      }
      _authenticating = true;
      // Who is asking first: the right key from the wrong program is
      // refused (protocol.md 6.1).
      if (!await _checkExecutable()) return;
      final delay = service.config.authDelay(service._authFailures);
      if (delay > Duration.zero) await Future<void>.delayed(delay);
      if (op == 'auth') {
        await _auth(m);
      } else {
        await _claim(m);
      }
      _authenticating = false;
      return;
    }
    final id = m['id'];
    if (!_validId(id)) {
      connection.sendError(null, 'malformed', 'a request carries an id', {
        'reason': 'frame',
      });
      await connection.close();
      return;
    }
    await _request(id as int, op, m);
  }

  Future<void> _fail(String reason, String message) async {
    service._authFailures++;
    service.log.info('admin_refused', {
      'reason': reason,
      'failures': service._authFailures,
    });
    connection.sendError(null, 'denied', message, {'reason': reason});
    await connection.close();
  }

  Future<void> _auth(Map<String, Object?> m) async {
    final Uint8List adminNonce;
    final Uint8List mac;
    try {
      adminNonce = base64.decode(m['adminNonce'] as String);
      mac = base64.decode(m['mac'] as String);
    } on Object {
      return _fail('bad_mac', 'the authentication cannot be read');
    }
    if (adminNonce.length != tomSecretsKeyBytes) {
      return _fail('bad_mac', 'the admin nonce is not 32 bytes');
    }
    final expected = tomSecretsChallengeMac(
      service._adminKey,
      tomSecretsAdminLabel,
      _serviceNonce,
      adminNonce,
      service.startedAt,
    );
    if (!tomSecretsConstantTimeEquals(mac, expected)) {
      return _fail('bad_mac', 'the authentication is wrong');
    }
    service._authFailures = 0;
    authenticated = true;
    service.log.info('admin_authed');
    connection.send({
      'op': 'authed',
      'mac2': base64.encode(
        tomSecretsChallengeMac(
          service._adminKey,
          tomSecretsServiceLabel,
          _serviceNonce,
          adminNonce,
          service.startedAt,
        ),
      ),
    });
  }

  Future<void> _claim(Map<String, Object?> m) async {
    final keys = _keysOf(m);
    final bool ok;
    try {
      ok =
          keys != null &&
          await service.vaults.checkPrimary(
            service.config.bootstrap.primary,
            keys.credentials,
          );
    } finally {
      keys?.dispose();
    }
    if (!ok) return _fail('bad_password', 'the master password is wrong');
    service.log.info('claim');
    service._authFailures = 0;
    service._adminKey = tomSecretsRandomBytes();
    // The old key is revoked: every admin authenticated with it is dropped.
    for (final other in [...service._admins]) {
      if (other != this && other.authenticated) {
        await other.connection.close();
      }
    }
    authenticated = true;
    connection.send({
      'op': 'claimed',
      'adminKey': base64.encode(service._adminKey),
    });
  }

  Future<void> _request(int id, String op, Map<String, Object?> m) async {
    switch (op) {
      case 'unlock':
        final keys = _keysOf(m);
        if (keys == null) {
          connection.sendError(id, 'malformed', 'unlock needs a password', {
            'reason': 'password',
          });
          return;
        }
        if (!service.isLocked) {
          keys.dispose();
          connection.send({'op': 'ok', 'id': id});
          return;
        }
        try {
          await service.unlock(keys);
          connection.send({'op': 'ok', 'id': id});
        } on KdbxInvalidKeyException {
          service._authFailures++;
          service.log.info('unlock_refused', {'reason': 'bad_password'});
          connection.sendError(id, 'denied', 'the master password is wrong', {
            'reason': 'bad_password',
          });
        } on Object catch (e) {
          service.log.error('unlock_failed', e);
          connection.sendError(id, 'internal', 'the unlock failed', {
            'code': e.runtimeType.toString(),
          });
        }
      case 'unlockStore':
        final keys = _keysOf(m);
        final store = m['store'];
        if (keys == null || store is! String) {
          keys?.dispose();
          connection.sendError(id, 'malformed', 'store and password', {
            'reason': 'store',
          });
          return;
        }
        if (service.isLocked) {
          keys.dispose();
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        try {
          await service.vaults.unlockStore(
            store,
            keys,
            machine: service.machine,
          );
          service.log.info('unlock_store', {'store': store});
          connection.send({'op': 'ok', 'id': id});
        } on KdbxInvalidKeyException {
          keys.dispose();
          service.log.info('unlock_store_refused', {
            'store': store,
            'reason': 'bad_password',
          });
          connection.sendError(id, 'denied', 'the password is wrong', {
            'reason': 'bad_password',
          });
        } on StateError {
          keys.dispose();
          connection.sendError(id, 'not_found', 'no store $store');
        }
      case 'vaultKeys':
        final stores = m['stores'];
        if (stores != null &&
            (stores is! List || stores.any((s) => s is! String))) {
          connection.sendError(id, 'malformed', 'stores is a list of names', {
            'reason': 'stores',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        try {
          final keys = service.vaults.vaultKeys(
            stores: (stores as List?)?.cast<String>(),
          );
          connection.send({'op': 'vaultKeySet', 'id': id, 'stores': keys});
          service.log.info('vault_keys', {'stores': keys.length});
        } on StateError catch (e) {
          connection.sendError(id, 'not_found', 'no open store ${e.message}', {
            'store': e.message,
          });
        }
      case 'save':
        final store = m['store'];
        final bytes = m['bytes'];
        final base = m['baseRevision'];
        if (store is! String ||
            bytes is! String ||
            (base != null && base is! String)) {
          connection.sendError(
            id,
            'malformed',
            'save carries store and bytes',
            {'reason': 'save'},
          );
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        final Uint8List stored;
        try {
          stored = base64.decode(bytes);
        } on FormatException {
          connection.sendError(id, 'malformed', 'bytes is not base64', {
            'reason': 'bytes',
          });
          return;
        }
        try {
          await service.save(store, stored, baseRevision: base as String?);
          connection.send({'op': 'ok', 'id': id});
        } on TomSecretsSaveException catch (e) {
          service.log.info('save_refused', {
            'store': store,
            'kind': e.kind,
            'reason': e.reason,
          });
          connection.sendError(id, e.kind, e.message, {
            if (e.kind == 'needs_unlock' || e.kind == 'unavailable')
              'store': store,
            'reason': ?e.reason,
          });
        } on Object catch (e) {
          service.log.error('save_failed', e, {'store': store});
          connection.sendError(id, 'internal', 'the save failed', {
            'code': e.runtimeType.toString(),
          });
        }
      case 'lock':
        await service.lock();
        connection.send({'op': 'ok', 'id': id});
      case 'shutdown':
        connection.send({'op': 'ok', 'id': id});
        await connection.close();
        await service.stop();
      case 'status':
        connection.send({
          'op': 'statusReport',
          'id': id,
          ...service.statusReport(),
        });
      case 'subscribe':
        subscribed = true;
        connection.send({'op': 'ok', 'id': id});
      default:
        connection.sendError(id, 'unsupported', 'unknown op $op', {'op': op});
    }
  }
}
