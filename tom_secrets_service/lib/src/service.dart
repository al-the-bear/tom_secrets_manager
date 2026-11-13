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
import 'lock_policy.dart';
import 'runtime.dart';
import 'vault_set.dart';

/// The service name of the product's items in the OS keychain.
const String tomSecretsKeychainService = 'tom-secrets-manager';

/// The service's version, sent in `welcome` and `challenge`.
const String tomSecretsServiceVersion = '0.1.0';

/// The admin requests of later parts the service does not answer yet; they
/// are answered `unsupported` like an unknown `op`.
const Set<String> tomSecretsLaterAdminOps = {
  'reload',
  'vaultKeys',
  'save',
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
  }) : idleSource = idleSource ?? tomSecretsSystemIdleSource(),
       host =
           host ??
           bootstrap.host ??
           Platform.localHostname.split('.').first.toLowerCase();

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
    final runtime = config.runtime;
    await runtime.prepare();
    await runtime.acquire();
    try {
      await service._deviceKeys.effectiveMode();
      await runtime.removeStaleEndpoints();
      await service._bind();
    } on Object {
      await service._closeServers();
      await runtime.removeEndpoints();
      await runtime.release();
      rethrow;
    }
    return service;
  }

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

  /// Unlocks with [credentials]: opens the primary, the device settings
  /// container (its key where `bootstrap.yaml` says), then the stores the
  /// machine serves; starts the lock policy. Throws
  /// [KdbxInvalidKeyException] for a wrong password.
  Future<void> unlock(Credentials credentials) async {
    final primaryLocator = config.bootstrap.primary;
    final primary = await _vaults.openPrimary(primaryLocator, credentials);
    try {
      final key = await _deviceKeys.keyFor(
        primary: primary.file,
        savePrimary: () => config.opener.save(primaryLocator, primary.file),
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
    'hardening': const <String>[],
  };
}

/// Reads a `Credentials` from a request's `password` and `keyFile` (base64).
Credentials? _credentialsOf(Map<String, Object?> m) {
  final password = m['password'];
  final keyFile = m['keyFile'];
  if (password is! String || (keyFile != null && keyFile is! String)) {
    return null;
  }
  return Credentials.composite(
    ProtectedValue.fromString(password),
    keyFile == null
        ? null
        : Credentials.keyFileKey(base64.decode(keyFile as String)),
  );
}

const int _maxId = 9007199254740991; // 2^53 - 1

bool _validId(Object? id) => id is int && id >= 1 && id <= _maxId;

/// One client connection.
final class _ClientSession {
  _ClientSession(this.service, Socket socket) {
    connection = TomSecretsConnection(
      socket,
      onMessage: _message,
      onClosed: () => service._clients.remove(this),
    );
    service._clients.add(this);
  }

  final TomSecretsService service;
  late final TomSecretsConnection connection;
  bool _greeted = false;
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
        service._emit({
          'op': 'unlock_needed',
          'identity': {'client': _client},
        });
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
    final results = [for (final item in items) await _resolve(item)];
    if (op == 'get') {
      connection.send({...results.single, 'id': id});
    } else {
      connection.send({'op': 'values', 'id': id, 'results': results});
    }
  }

  Map<String, Object?> _error(
    String kind,
    String message, [
    Map<String, Object?>? details,
  ]) => {'op': 'error', 'kind': kind, 'message': message, 'details': ?details};

  Future<Map<String, Object?>> _resolve(Map<String, Object?> item) async {
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
      ),
    );
    if (access is TomSecretsAccessDenied) {
      return _error('denied', 'not allowed', {'reason': access.reason});
    }
    final value = resolution.value;
    final entry = resolution.entry;
    final storeStatus = service.vaults.statusOf(entry.store);
    final fetchedAt = (storeStatus?.fetchedAt ?? DateTime.now()).toUtc();
    try {
      return {
        'op': 'value',
        'value': value.isText ? value.text : base64.encode(value.bytes),
        'encoding': value.isText ? 'utf8' : 'base64',
        'entry': {
          'store': entry.store,
          'uuid': tomSecretsUuidHex(entry.entry.uuid),
          // `file:` vaults read in this cycle answer `github` too: the
          // protocol knows only `github` and `cache` (a fresh read or the
          // offline copy).
          'source': storeStatus?.source == 'cache' ? 'cache' : 'github',
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
    } finally {
      value.dispose();
    }
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
    final credentials = _credentialsOf(m);
    if (credentials == null ||
        !await service.vaults.checkPrimary(
          service.config.bootstrap.primary,
          credentials,
        )) {
      return _fail('bad_password', 'the master password is wrong');
    }
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
        final credentials = _credentialsOf(m);
        if (credentials == null) {
          connection.sendError(id, 'malformed', 'unlock needs a password', {
            'reason': 'password',
          });
          return;
        }
        if (!service.isLocked) {
          connection.send({'op': 'ok', 'id': id});
          return;
        }
        try {
          await service.unlock(credentials);
          connection.send({'op': 'ok', 'id': id});
        } on KdbxInvalidKeyException {
          service._authFailures++;
          connection.sendError(id, 'denied', 'the master password is wrong', {
            'reason': 'bad_password',
          });
        } on Object catch (e) {
          connection.sendError(id, 'internal', 'the unlock failed', {
            'code': e.runtimeType.toString(),
          });
        }
      case 'unlockStore':
        final credentials = _credentialsOf(m);
        final store = m['store'];
        if (credentials == null || store is! String) {
          connection.sendError(id, 'malformed', 'store and password', {
            'reason': 'store',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        try {
          await service.vaults.unlockStore(
            store,
            credentials,
            machine: service.machine,
          );
          connection.send({'op': 'ok', 'id': id});
        } on KdbxInvalidKeyException {
          connection.sendError(id, 'denied', 'the password is wrong', {
            'reason': 'bad_password',
          });
        } on StateError {
          connection.sendError(id, 'not_found', 'no store $store');
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
