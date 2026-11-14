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

import 'package:http/http.dart' as http;
import 'package:tom_core_storage/settings.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_crypto/protected_value.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'access.dart';
import 'approvals.dart';
import 'audit.dart';
import 'bootstrap.dart';
import 'connection.dart';
import 'github_opener.dart';
import 'identity.dart';
import 'key_expiry.dart';
import 'link_server.dart';
import 'lock_policy.dart';
import 'log.dart';
import 'peer_identity.dart';
import 'secret_frame.dart';
import 'vault_set.dart';

/// The service's version, sent in `welcome` and `challenge`.
const String tomSecretsServiceVersion = '0.1.0';

/// What a service is started with.
final class TomSecretsServiceConfig {
  /// A configuration; [adminKey] is the key the starter handed over.
  TomSecretsServiceConfig({
    required this.runtime,
    required this.bootstrap,
    required this.adminKey,
    this.opener,
    this.githubBaseUrl = 'https://api.github.com',
    this.githubClient,
    this.githubRemoteFor,
    this.githubReaderFor,
    this.refreshTick = const Duration(minutes: 1),
    DateTime Function()? clock,
    TomSecretsIdleSource? idleSource,
    this.keychain,
    this.policy,
    String? host,
    this.lockCheckInterval = const Duration(seconds: 15),
    this.authDelay = tomSecretsAuthDelay,
    this.harden,
    TomSecretsLog? log,
    TomSecretsPeerMeasurer? peerMeasurer,
    this.adminExecutables,
    this.lastUsedInterval,
  }) : clock = clock ?? DateTime.now,
       peerMeasurer = peerMeasurer ?? TomSecretsSystemPeerMeasurer(),
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

  /// Opens and saves vault files; null (the default): `file:` vaults on the
  /// disk and `github:` vaults through the GitHub opener, with the offline
  /// cache in `bootstrap.cacheDirectory` and each repository's token from
  /// the keychain or the primary's vault list.
  final TomSecretsVaultOpener? opener;

  /// GitHub's API, for `github:` vaults.
  final String githubBaseUrl;

  /// The HTTP client `github:` vaults are fetched through (null: its own).
  final http.Client? githubClient;

  /// The git remote a compaction pushes to (null: GitHub's smart HTTP).
  final TomSecretsGitRemoteFor? githubRemoteFor;

  /// The commit reader a compaction reads with (null: GitHub's REST API).
  final TomSecretsCommitReaderFor? githubReaderFor;

  /// How often the refresh looks for stores that are due; each store is
  /// fetched every `refreshMinutes` (the device settings), or after its
  /// backoff.
  final Duration refreshTick;

  /// The time of the refresh and the key-expiry reminders.
  final DateTime Function() clock;

  /// The input idle time (lock mode (b)).
  final TomSecretsIdleSource idleSource;

  /// The OS keychain, or null where none is available.
  final TomSecretStore? keychain;

  /// Who may read a value; null (the default): the service's own approvals
  /// and grants ([TomSecretsApprovals]).
  final TomSecretsAccessPolicy? policy;

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

  /// How often the grants' last use is written to the primary vault; null:
  /// the refresh interval (`refreshMinutes`, so a `github:` primary is not
  /// committed more often than it is fetched), or an hour with refresh off.
  final Duration? lastUsedInterval;
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
final class TomSecretsService implements TomSecretsApprovalHost {
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
  @override
  TomSecretsLog get log => config.log;

  /// The configuration.
  final TomSecretsServiceConfig config;

  /// The start time, milliseconds since the epoch.
  final int startedAt = DateTime.now().millisecondsSinceEpoch;

  Uint8List _adminKey;

  /// The `github:` opener, when the service built its own.
  late final TomSecretsGitHubOpener? _github = config.opener == null
      ? TomSecretsGitHubOpener(
          device: config.host,
          tokens: _githubToken,
          cacheDirectory: config.bootstrap.cacheDirectory,
          useCache: () => settings.offlineCache,
          baseUrl: config.githubBaseUrl,
          httpClient: config.githubClient,
          clock: config.clock,
          remoteFor: config.githubRemoteFor,
          readerFor: config.githubReaderFor,
        )
      : null;
  late final TomSecretsVaultSet _vaults = TomSecretsVaultSet(
    opener: config.opener ?? TomSecretsLocatorOpener(github: _github),
    clock: config.clock,
  );
  Timer? _refreshTimer;
  final Map<String, String> _reminded = {};
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
  TomSecretsTrust? _trust;
  TomSecretsApprovals? _approvals;
  TomSecretsAuditLog? _audit;
  TomSecretsLinkServer? _linkServer;
  Timer? _lastUsedTimer;
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
  @override
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
      final refreshMinutes = settings.refreshMinutes;
      _vaults.refreshInterval = Duration(
        minutes: refreshMinutes > 0 ? refreshMinutes : 5,
      );
      await _vaults.openStores(machine: machine, served: settings.servedStores);
      final trust = _trust = await _device!.trust(config.host, now: now);
      // Trust material written before the key dates were kept counts its
      // keys' rotation age from this unlock.
      if (trust.stampKeyDates(now)) await _device!.writeTrust(trust);
      _audit = TomSecretsAuditLog(
        '${config.bootstrap.dataDirectory}${Platform.pathSeparator}audit',
        _trust!.auditKey,
      );
      final approvals = _approvals = TomSecretsApprovals(this);
      await approvals.reload();
      final refresh = settings.refreshMinutes;
      _lastUsedTimer = Timer.periodic(
        config.lastUsedInterval ??
            Duration(minutes: refresh > 0 ? refresh : 60),
        (_) => unawaited(_flushLastUsed()),
      );
      final link = settings.approvalLink;
      if (link != null) {
        _linkServer = await TomSecretsLinkServer.start(
          address: link,
          trust: _trust!,
          host: config.host,
          approvals: approvals,
          log: log,
        );
        log.info('link_listening', {'address': _linkServer!.address});
      }
    } on Object {
      await _dropApprovals();
      _vaults.lock();
      _device = null;
      rethrow;
    }
    _lockTimer.start(settings.serviceLock);
    if (settings.refreshMinutes > 0) {
      _refreshTimer = Timer.periodic(
        config.refreshTick,
        (_) => unawaited(_tick()),
      );
    }
    if (!_unlocked.isCompleted) _unlocked.complete();
    final states = _vaults.status.map((s) => s.state.wireName).toList();
    log.info('unlock', {
      'stores': states.length,
      'current': states.where((s) => s == 'current').length,
      'needsUnlock': states.where((s) => s == 'needs_unlock').length,
      'unavailable': states.where((s) => s == 'unavailable').length,
    });
    _emit({'op': 'unlocked'});
    await _readTokenExpiries();
    _remindKeys();
  }

  bool _ticking = false;

  Future<void> _tick() async {
    if (_ticking || isLocked) return;
    _ticking = true;
    try {
      await refresh();
    } on Object catch (e) {
      log.error('refresh_failed', e);
    } finally {
      _ticking = false;
    }
  }

  Future<void> _queue = Future<void>.value();

  /// Runs [body] after every refresh and save before it: a refresh and a
  /// save never interleave on one store.
  Future<T> _serial<T>(Future<T> Function() body) {
    final result = _queue.then((_) => body());
    _queue = result.then((_) {}, onError: (_) {});
    return result;
  }

  /// Fetches the stores that are due ([force]: every store, the `reload`)
  /// and reopens the moved ones (part-service, Refresh), then tells the
  /// subscribers: `store_state` for every store whose state or source
  /// changed, `store_changed` for every store reopened with new content; and
  /// sends the key-expiry reminders that are due.
  Future<TomSecretsRefreshReport> refresh({bool force = false}) =>
      _serial(() async {
        if (isLocked) return const TomSecretsRefreshReport();
        final report = await _vaults.refresh(force: force);
        if (isLocked) return report;
        report.states.forEach(_emitState);
        for (final name in report.reopened) {
          _emit({
            'op': 'store_changed',
            'store': name,
            'revision': ?_vaults.statusOf(name)?.revision,
          });
        }
        // The primary holds the grants and the approval records.
        if (report.reopened.contains(_vaults.primaryName)) {
          await _approvals?.reload();
        }
        if (force || report.states.isNotEmpty || report.reopened.isNotEmpty) {
          log.info('refresh', {
            'forced': force,
            'reopened': report.reopened.length,
            'states': [
              for (final s in report.states) '${s.name}:${s.state.wireName}',
            ],
          });
        }
        await _readTokenExpiries();
        _remindKeys();
        return report;
      });

  /// Answers `compact {repository}` (part-stores, `tsm compact`): the cut
  /// of [repository]'s history through the GitHub opener, in turn with the
  /// refresh and the saves.
  Future<void> _compact(
    int id,
    String repository,
    TomSecretsConnection connection,
  ) async {
    final github = _github;
    if (github == null || !github.repositories.contains(repository)) {
      connection.sendError(id, 'not_found', 'no open vault in $repository', {
        'repository': repository,
      });
      return;
    }
    try {
      final result = await _serial(() => github.compact(repository));
      log.info('compact', {
        'repository': repository,
        'compacted': result.compacted,
        'kept': result.kept,
      });
      connection.send({
        'op': 'compacted',
        'id': id,
        'repository': repository,
        'compacted': result.compacted,
        'oldHead': result.oldHead,
        'newHead': result.newHead,
        'kept': result.kept,
      });
    } on TomSecretsCompactionException catch (e) {
      // Saves kept landing on every attempt: the user tries again later.
      if (e.race) {
        connection.sendError(id, 'denied', e.message, {
          'reason': 'branch_moving',
        });
      } else {
        log.error('compact_failed', e, {'repository': repository});
        connection.sendError(id, 'internal', e.message, {'code': 'compaction'});
      }
    } on Object catch (e) {
      final failure = tomSecretsFetchFailureOf(e);
      if (failure == null) rethrow;
      final state = TomSecretsStoreState.offlineFor(failure);
      connection.sendError(
        id,
        state.wireName,
        state == TomSecretsStoreState.offline
            ? 'GitHub could not be reached'
            : 'GitHub refused the token',
        {
          'stores': [
            for (final s in _vaults.status)
              if ((s.locator ?? '').startsWith('github:$repository/') ||
                  (s.locator ?? '').startsWith('github:$repository@'))
                s.name,
          ],
        },
      );
    }
  }

  /// The token of [vault]'s repository: the device keychain's
  /// (`tsm.github-token.<owner>:<repository>`), else one the primary's vault
  /// list keeps for a vault in that repository, never for the primary's own
  /// repository (part-stores).
  Future<String?> _githubToken(TomSecretsGitHubLocator vault) async {
    final keychain = config.keychain;
    if (keychain != null) {
      try {
        final token = await keychain.read(vault.tokenHandle);
        if (token != null && token.isNotEmpty) return token;
      } on TomSecretStoreException catch (e) {
        log.error('keychain_failed', e);
      }
    }
    final primary = _vaults.primary;
    if (primary == null) return null;
    final own = TomSecretsVaultLocator.parse(primary.locator);
    if (own is TomSecretsGitHubLocator &&
        own.repositorySlug == vault.repositorySlug) {
      return null;
    }
    for (final keys in TomSecretsPrimaryVaults(primary.file).list()) {
      final at = TomSecretsVaultLocator.parse(keys.locator);
      if (keys.githubToken != null &&
          at is TomSecretsGitHubLocator &&
          at.repositorySlug == vault.repositorySlug) {
        return keys.githubToken;
      }
    }
    return null;
  }

  /// The expiry recorded with each repository's GitHub token when it was
  /// entered (`owner/repository` → UTC): the keychain's
  /// (`tsm.github-token-expiry.<owner>:<repository>`), else the primary's
  /// vault list's for a vault in that repository.
  final Map<String, DateTime> _storedTokenExpiries = {};

  /// Reads [_storedTokenExpiries] for the repositories of the vaults open
  /// or listed.
  Future<void> _readTokenExpiries() async {
    final primary = _vaults.primary;
    if (primary == null) return;
    final repositories = <String, TomSecretsGitHubLocator>{};
    final listed = <String, DateTime>{};
    for (final locator in [
      primary.locator,
      for (final keys in _vaults.listed) keys.locator,
    ]) {
      final parsed = TomSecretsVaultLocator.parse(locator);
      if (parsed is TomSecretsGitHubLocator) {
        repositories[parsed.repositorySlug] = parsed;
      }
    }
    for (final keys in _vaults.listed) {
      final parsed = TomSecretsVaultLocator.parse(keys.locator);
      final at = keys.githubTokenExpires;
      if (parsed is TomSecretsGitHubLocator && at != null) {
        listed[parsed.repositorySlug] = at;
      }
    }
    _storedTokenExpiries.clear();
    for (final MapEntry(key: slug, value: vault) in repositories.entries) {
      DateTime? at;
      final keychain = config.keychain;
      if (keychain != null) {
        try {
          final text = await keychain.read(vault.tokenExpiryHandle);
          at = text == null ? null : DateTime.tryParse(text)?.toUtc();
        } on TomSecretStoreException catch (e) {
          log.error('keychain_failed', e);
        }
      }
      at ??= listed[slug];
      if (at != null) _storedTokenExpiries[slug] = at;
    }
  }

  /// The keys due for a reminder now (part-key-rotation):
  /// - each repository's GitHub token, from `keyExpiryWarningDays` before
  ///   the expiry GitHub reported for it, else the one recorded with it;
  /// - the key file and repository key of each further vault, from 30 days
  ///   before the Expires of its entry in the primary, and of the primary,
  ///   from 30 days before its metadata's `tsm.keys-due`;
  /// - this device's approver and approval-link key pairs and those of the
  ///   peers it recorded, from 30 days before their rotation age (24
  ///   months, DP-85) is over.
  List<TomSecretsExpiringKey> get expiring {
    final now = this.now;
    return [for (final k in keys) ?k.dueAt(now)];
  }

  /// Every key the service knows a due date of (`tsm keys`), whether or not
  /// a reminder is due: the GitHub tokens, the vaults' key files and
  /// repository keys, the key pairs; [expiring] are those due now.
  List<TomSecretsKeyDate> get keys {
    if (isLocked) return const [];
    final trust = _trust;
    final tokens = {..._storedTokenExpiries, ...?_github?.tokenExpiries};
    final primary = _vaults.primary;
    final primaryName = _vaults.primaryName;
    DateTime? primaryDue;
    try {
      primaryDue = primary == null
          ? null
          : TomSecretsMetadata.read(primary.file).keysDue;
    } on TomSecretsMetadataException {
      // An unreadable date reminds of nothing; the app shows the metadata.
      primaryDue = null;
    }
    TomSecretsKeyDate? other(
      String kind,
      String key,
      DateTime? expiresAt, {
      String? vault,
    }) => expiresAt == null
        ? null
        : TomSecretsKeyDate(
            kind: kind,
            key: key,
            vault: vault,
            expiresAt: expiresAt,
            firstDays: TomSecretsExpiringKey.otherKeyDays,
          );
    TomSecretsKeyDate? pair(String kind, String key, DateTime? since) =>
        other(kind, key, TomSecretsExpiringKey.keyPairDue(since));
    return [
      for (final MapEntry(key: slug, value: at) in tokens.entries)
        TomSecretsKeyDate(
          kind: 'github_token',
          key: 'github-token:$slug',
          expiresAt: at,
          firstDays: settings.keyExpiryWarningDays,
        ),
      if (primaryName != null)
        ?other(
          'vault_keys',
          'vault-keys:$primaryName',
          primaryDue,
          vault: primaryName,
        ),
      for (final keys in _vaults.listed)
        ?other(
          'vault_keys',
          'vault-keys:${keys.name}',
          keys.expires,
          vault: keys.name,
        ),
      if (trust != null) ...[
        ?pair(
          'approver_key',
          'approver-key:${trust.device}',
          trust.approverKeySince,
        ),
        ?pair('link_key', 'link-key:${trust.device}', trust.linkKeySince),
        for (final a in trust.approvers) ...[
          ?pair('approver_key', 'approver-key:${a.device}', a.approverKeySince),
          if (a.linkKey != null)
            ?pair('link_key', 'link-key:${a.device}', a.linkKeySince),
        ],
        for (final h in trust.hosts)
          ?pair('link_key', 'link-key:${h.host}', h.linkKeySince),
      ],
    ];
  }

  /// Sends `key_expiry` for every key that reached a new reminder step to
  /// the subscribers; with none attached nothing is recorded, so the next
  /// check after one attaches sends it.
  void _remindKeys() {
    if (!_hasSubscribers) return;
    for (final key in expiring) {
      if (_reminded[key.key] == key.step) continue;
      _reminded[key.key] = key.step;
      _emit(key.toEvent());
      log.info('key_expiry', {'key': key.key, 'daysLeft': key.daysLeft});
    }
  }

  /// Locks: drops the vaults, the index, the device settings and every
  /// protected value the service holds; the admin key survives.
  Future<void> lock({String reason = 'admin'}) async {
    if (isLocked) return;
    _lockTimer.stop();
    _refreshTimer?.cancel();
    _refreshTimer = null;
    await _dropApprovals();
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
    _github?.close();
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
    // The protocol's letters (DP-14): (a) never relock, (b) on idle.
    'lockMode': switch (settings.serviceLock.mode) {
      TomSecretsLockMode.never => 'a',
      TomSecretsLockMode.idle => 'b',
    },
    'protocol': 1,
    'service': {'version': tomSecretsServiceVersion, 'start': startedAt},
    'stores': [for (final s in _vaults.status) s.toJson()],
    'expiring': [for (final k in expiring) k.toJson()],
    'admins': _admins.where((a) => a.authenticated).length,
    'hardening': _hardening,
  };

  /// Writes the grants' last use now (the timer, the lock).
  Future<void> _flushLastUsed() async {
    try {
      await _approvals?.flushLastUsed();
    } on Object catch (e) {
      log.error('last_used_failed', e);
    }
  }

  Future<void> _dropApprovals() async {
    _lastUsedTimer?.cancel();
    _lastUsedTimer = null;
    await _flushLastUsed();
    _approvals?.abandonAll();
    await _approvals?.closeLinks();
    await _linkServer?.close();
    await _audit?.close();
    _approvals = null;
    _linkServer = null;
    _audit = null;
    _trust = null;
  }

  /// The approvals and grants, while unlocked.
  TomSecretsApprovals? get approvals => _approvals;

  /// The approval link's listener, while unlocked and configured.
  TomSecretsLinkServer? get linkServer => _linkServer;

  // ── TomSecretsApprovalHost ───────────────────────────────────────────

  @override
  String get host => config.host;

  @override
  TomSecretsTrust get trust => _trust!;

  @override
  DateTime get now => config.clock().toUtc();

  @override
  KdbxFile? get primary => _vaults.primary?.file;

  /// Runs [write] and sends `store_state` for every store whose state or
  /// source it changed (a write that found the remote unreachable).
  Future<T> _tellingStates<T>(Future<T> Function() write) async {
    final before = {for (final s in _vaults.status) s.name: s};
    try {
      return await write();
    } finally {
      for (final s in _vaults.status) {
        final was = before[s.name];
        if (was != null &&
            (was.state != s.state || was.wireSource != s.wireSource)) {
          _emitState(s);
        }
      }
    }
  }

  void _emitState(TomSecretsStoreStatus status) => _emit({
    'op': 'store_state',
    'store': status.name,
    'state': status.state.wireName,
    'source': status.wireSource,
    'fetchedAt': ?status.fetchedAt?.toUtc().toIso8601String(),
    'notPushed': status.notPushed,
  });

  /// Writes the service's own edits of the primary (grants, revocations,
  /// approval records, their last use). When the remote cannot be reached
  /// or refuses the token, the edits stay in the held copy, in effect on
  /// this host, and the next refresh delivers them
  /// ([TomSecretsVaultSet.primaryWritePending]); that is no failure of the
  /// change itself. Any other failure is thrown.
  @override
  Future<void> savePrimary() async {
    // In turn with the refresh and the saves: they share the primary's
    // held copy and, for a `github:` primary, its unit.
    final String revision;
    try {
      revision = await _serial(() => _tellingStates(_vaults.writePrimary));
    } on Object catch (e) {
      if (!_vaults.primaryWritePending || tomSecretsFetchFailureOf(e) == null) {
        rethrow;
      }
      log.info('primary_write_pending', {'code': e.runtimeType.toString()});
      return;
    }
    // The service's own write (grants, their last use): an attached app sees
    // the new revision.
    _emit({
      'op': 'store_changed',
      'store': _vaults.primaryName,
      'revision': revision,
    });
  }

  @override
  Future<void> writeTrust() => _device!.writeTrust(_trust!);

  @override
  bool get hasLocalApprover => _admins.any((a) => a.subscribed && a.isApprover);

  @override
  void emitToApprovers(Map<String, Object?> event) {
    for (final a in _admins) {
      if (a.subscribed && a.isApprover) a.connection.send(event);
    }
  }

  @override
  TomSecretsAuditLog? get audit => _audit;

  /// Takes the app's edited file of [store] (protocol.md 6.4), tells the
  /// subscribers (`store_changed`) and logs it.
  Future<TomSecretsSaveResult> save(
    String store,
    Uint8List stored, {
    String? baseRevision,
  }) async {
    final result = await _serial(
      () => _tellingStates(
        () => _vaults.save(store, stored, baseRevision: baseRevision),
      ),
    );
    log.info('save', {
      'store': store,
      'merged': result.merged,
      'conflicts': result.conflicts,
    });
    _emit({'op': 'store_changed', 'store': store, 'revision': result.revision});
    // The primary holds the grants and the approval records.
    if (store == _vaults.primaryName) await _approvals?.reload();
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
  String? _clientTokenHash;
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
      unawaited(
        _request(id, op, m)
            .catchError((Object e) {
              // A request never goes unanswered, and its failure never ends
              // the service.
              service.log.error('client_request_failed', e, {'op': op});
              connection.sendError(id, 'internal', 'the request failed', {
                'code': e.runtimeType.toString(),
              });
            })
            .whenComplete(() => _open.remove(id)),
      );
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
    // A client token from an earlier `always` (protocol.md 7.4): only its
    // hash is kept; an unreadable one is no token (the bare executable).
    final token = m['clientToken'];
    if (token is String) {
      try {
        final bytes = base64.decode(token);
        if (bytes.length == 32) {
          _clientTokenHash = tomSecretsClientTokenHash(bytes);
        }
        bytes.fillRange(0, bytes.length, 0);
      } on FormatException {
        _clientTokenHash = null;
      }
    }
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
      final resolved = [for (final item in items) _resolve(item, held)];
      final batch = [
        for (final r in resolved)
          if (r case (final TomSecretsAccessRequest request, null)) request,
      ];
      final decisions = batch.isEmpty
          ? const <TomSecretsAccess>[]
          : await (service.config.policy ?? service.approvals!).check(
              TomSecretsAccessBatch(
                identity: _identity!,
                client: _client,
                items: batch,
                timeout: switch (m['timeoutMs']) {
                  final int ms when ms >= 0 => Duration(milliseconds: ms),
                  _ => null,
                },
                onProgress: (p) =>
                    connection.send({'op': 'progress', 'id': id, ...p}),
                clientTokenHash: _clientTokenHash,
              ),
            );
      var next = 0;
      final results = [
        for (final (request, error) in resolved)
          error ?? _answer(request!, decisions[next++]),
      ];
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

  /// [item] resolved, or the error it ends in; the resolved value is added
  /// to [held] for the caller to dispose once the frame is written.
  (TomSecretsAccessRequest?, Map<String, Object?>?) _resolve(
    Map<String, Object?> item,
    List<TomSecretsFieldValue> held,
  ) {
    (TomSecretsAccessRequest?, Map<String, Object?>?) fail(
      Map<String, Object?> error,
    ) => (null, error);
    final ref = item['ref'];
    if (ref is! String) {
      return fail(_error('malformed', 'ref is missing', {'reason': 'ref'}));
    }
    if (utf8.encode(ref).length > 1024) {
      return fail(
        _error('malformed', 'the reference is over 1 KiB', {
          'reason': 'too_long',
        }),
      );
    }
    final dims = item['dimensions'];
    if (dims != null &&
        (dims is! Map || dims.values.any((v) => v is! String))) {
      return fail(
        _error('malformed', 'dimensions map names to strings', {
          'reason': 'dimensions',
        }),
      );
    }
    final field = item['field'];
    if (field != null && field is! String) {
      return fail(
        _error('malformed', 'field is a string', {'reason': 'field'}),
      );
    }
    final storeName = _storeOf(ref);
    final status = storeName == null
        ? null
        : service.vaults.statusOf(storeName);
    if (status?.state == TomSecretsStoreState.needsUnlock) {
      return fail(
        _error('needs_unlock', 'the store needs its own unlock', {
          'store': storeName,
        }),
      );
    }
    if (status?.state == TomSecretsStoreState.unavailable) {
      return fail(
        _error('unavailable', 'the store could not be opened', {
          'store': storeName,
          'reason': 'no_cache',
        }),
      );
    }
    final resolver = service.vaults.resolver;
    if (resolver == null) {
      return fail(_error('locked', 'the service is locked'));
    }
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
      return fail(_error(e.kind.wireName, e.message, e.details));
    }
    held.add(resolution.value);
    return (
      TomSecretsAccessRequest(
        reference: ref,
        resolution: resolution,
        client: _client,
        identity: _identity!,
        wantClientToken: item['wantClientToken'] == true,
      ),
      null,
    );
  }

  /// The answer to [request] under [access]: its value, or the refusal.
  Map<String, Object?> _answer(
    TomSecretsAccessRequest request,
    TomSecretsAccess access,
  ) {
    if (access case TomSecretsAccessDenied(
      :final kind,
      :final reason,
      :final details,
    )) {
      return _error(kind, 'not allowed', {
        if (kind == 'denied') 'reason': reason,
        ...details,
      });
    }
    final resolution = request.resolution;
    final value = resolution.value;
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
      if (access case TomSecretsAccessAllowed(:final clientToken?))
        'clientToken': TomSecretsSecretSlot.ofText(
          TomProtectedValue.of(clientToken),
        ),
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
  TomSecretsIdentity? _identity;

  String get _exeName => (_identity?.exe ?? '')
      .split(RegExp(r'[/\\]'))
      .last
      .toLowerCase()
      .replaceAll('.exe', '');

  /// Whether this admin is `tsm` (which cannot answer a prompt, DP-19).
  bool get isTsm => _exeName == 'tsm';

  /// Whether this admin is an approver: subscribed and not `tsm` (the
  /// manager app, or, without an executable check, any admin).
  bool get isApprover => !isTsm;

  /// Whether this admin is the manager app's executable (or no executable
  /// check is configured: an in-process service in tests).
  bool get isApp =>
      !isTsm &&
      (service.config.adminExecutables == null ||
          const {'tom_secrets_desktop', 'tom_secrets_app'}.contains(_exeName));

  /// Whether the admin's measured executable may administer (protocol.md
  /// 6.1); refuses and closes the connection otherwise.
  Future<bool> _checkExecutable() async {
    final measurement = await _measured;
    final String reason;
    switch (measurement) {
      case TomSecretsPeerRefused(reason: final r):
        reason = r;
      case TomSecretsPeerMeasured(:final identity):
        _identity = identity;
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
    try {
      await _request(id as int, op, m);
    } on Object catch (e) {
      // A request never goes unanswered, and its failure never ends the
      // service.
      service.log.error('admin_request_failed', e, {'op': op});
      connection.sendError(id, 'internal', 'the request failed', {
        'code': e.runtimeType.toString(),
      });
    }
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

  /// The approval and grant requests (protocol.md 6.3, 7.2 to 7.5).
  Future<void> _approvalRequest(
    int id,
    String op,
    Map<String, Object?> m,
  ) async {
    void malformed(String reason) => connection.sendError(
      id,
      'malformed',
      'the request cannot be read',
      {'reason': reason},
    );
    void notAllowed() => connection.sendError(
      id,
      'denied',
      'not from this program',
      {'reason': 'not_allowed_op'},
    );
    final approvals = service.approvals;
    if (approvals == null) {
      connection.sendError(id, 'locked', 'unlock the service first');
      return;
    }
    // tsm pre-approves and issues tokens only where command-line approvals
    // are switched on (DP-19), and never answers a prompt.
    final cli = service.trust.cliApprovals;
    switch (op) {
      case 'approve':
        if (isTsm) return notAllowed();
        final approvalId = m['approvalId'];
        final decision = m['decision'];
        final secret = m['secret'];
        final clientToken = m['clientToken'];
        if (approvalId is! String ||
            decision is! String ||
            secret is! String ||
            (clientToken != null && clientToken is! String)) {
          return malformed('approve');
        }
        try {
          await approvals.approve(
            approvalId,
            TomSecretsApprovalAnswer(
              decision: decision,
              secret: secret,
              folder: m['folder'] as String?,
              pin: m['pin'],
              approver: service.trust.device,
              // The app made the token (DP-20); this device signs its grant.
              clientToken: clientToken as String?,
            ),
          );
          connection.send({'op': 'ok', 'id': id});
        } on StateError {
          connection.sendError(id, 'not_found', 'no prompt $approvalId');
        } on ArgumentError {
          malformed('approve');
        }
      case 'approval.redeem':
        final token = m['token'];
        if (token is! String) return malformed('token');
        final outcome = approvals.redeem(token);
        if (outcome == 'answered') {
          connection.send({'op': 'ok', 'id': id});
        } else {
          // A token that fails counts as a failed authentication (9.6).
          if (outcome == 'bad') service._authFailures++;
          service.log.info('token_refused', {'outcome': outcome});
          connection.sendError(id, 'denied', 'the token answers nothing', {
            'reason': 'bad_token',
          });
        }
      case 'approval.issue':
        if (isTsm && !cli) return notAllowed();
        final host = m['host'];
        final code = m['code'];
        final decision = m['decision'];
        if (host is! String ||
            code is! String ||
            decision is! String ||
            !tomSecretsDecisions.contains(decision)) {
          return malformed('approval');
        }
        try {
          connection.send({
            'op': 'approvalToken',
            'id': id,
            'token': approvals.issue(host, code, decision),
          });
        } on StateError {
          connection.sendError(id, 'not_found', 'no paired host $host');
        }
      case 'grants.list':
        final host = m['host'];
        if (host != null && host is! String) return malformed('host');
        connection.send({
          'op': 'grantList',
          'id': id,
          'grants': await approvals.listGrants(host as String?),
        });
      case 'grants.add':
        if (isTsm && !cli) return notAllowed();
        final grant = m['grant'];
        if (grant is! Map) return malformed('grant');
        final spec = grant.cast<String, Object?>();
        final subject = spec['subject'];
        final secret = spec['secret'];
        if (spec['host'] is! String ||
            subject is! String ||
            !RegExp(
              r'^(exe|script|interpreter|folder|tsm-command) \S',
            ).hasMatch(subject) ||
            secret is! String ||
            !(secret == 'all' ||
                secret.startsWith('store ') ||
                _parses(secret)) ||
            !const ['allow', 'never'].contains(spec['decision'])) {
          return malformed('grant');
        }
        final pin = spec['pin'];
        if (pin != null) {
          try {
            TomSecretsPin.parse(pin);
          } on FormatException {
            return malformed('pin');
          }
        }
        await approvals.addGrant({
          'host': spec['host'],
          'subject': subject,
          'secret': secret == 'all' || secret.startsWith('store ')
              ? secret
              : TomSecretReference.parse(secret).canonical,
          'decision': spec['decision'],
          'pin': ?pin,
        });
        connection.send({'op': 'ok', 'id': id});
      case 'grants.revoke':
        final host = m['host'];
        final grantId = m['grantId'];
        if (host is! String || grantId is! String) return malformed('grant');
        await approvals.revokeGrant(host, grantId);
        connection.send({'op': 'ok', 'id': id});
      case 'approvers.cliSwitch':
        final on = m['on'];
        if (on is! bool) return malformed('on');
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        service.trust.cliApprovals = on;
        await service.writeTrust();
        service.log.info('cli_approvals', {'on': on});
        connection.send({'op': 'ok', 'id': id});
      case 'audit.query':
        final DateTime from;
        final DateTime to;
        try {
          from = DateTime.parse(m['from']! as String).toUtc();
          to = DateTime.parse(m['to']! as String).toUtc();
        } on Object {
          return malformed('time');
        }
        final records = await service.audit!.query(
          from: from,
          to: to,
          subject: m['subject'] as String?,
          ref: switch (m['ref']) {
            final String r when _parses(r) => TomSecretReference.parse(
              r,
            ).canonical,
            final String r => r,
            _ => null,
          },
        );
        connection.send({
          'op': 'auditRecords',
          'id': id,
          'records': [for (final r in records) r.toJson()],
        });
    }
  }

  static bool _parses(String ref) {
    try {
      TomSecretReference.parse(ref);
      return true;
    } on Object {
      return false;
    }
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
      case 'vaultFile':
        final store = m['store'];
        if (store is! String) {
          connection.sendError(id, 'malformed', 'vaultFile names a store', {
            'reason': 'store',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        final ({String location, String revision, Uint8List stored}) file;
        try {
          file = service.vaults.vaultFile(store);
        } on StateError catch (e) {
          connection.sendError(id, 'not_found', 'no open store ${e.message}', {
            'store': e.message,
          });
          return;
        }
        final bytes = base64.encode(file.stored);
        // An answer frame holds at most 1 MiB (protocol.md 2.3); a larger
        // file waits for the binary chunks of phase B.
        if (bytes.length + 1024 > tomSecretsMaxAnswerPayload) {
          connection.sendError(
            id,
            'unsupported',
            'the file of $store is too large for one answer frame',
            {'reason': 'too_large', 'size': file.stored.length},
          );
          return;
        }
        connection.send({
          'op': 'vaultFileData',
          'id': id,
          'store': store,
          'location': file.location,
          'revision': file.revision,
          'bytes': bytes,
        });
        service.log.info('vault_file', {
          'store': store,
          'size': file.stored.length,
        });
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
            if (e.kind == 'offline' || e.kind == 'token_expired')
              'stores': [store],
            'reason': ?e.reason,
          });
        } on Object catch (e) {
          service.log.error('save_failed', e, {'store': store});
          connection.sendError(id, 'internal', 'the save failed', {
            'code': e.runtimeType.toString(),
          });
        }
      case 'reload':
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        await service.refresh(force: true);
        List<String> named(TomSecretsStoreState state) => [
          for (final s in service.vaults.status)
            if (s.state == state) s.name,
        ];
        final refused = named(TomSecretsStoreState.tokenExpired);
        final offline = named(TomSecretsStoreState.offline);
        if (refused.isNotEmpty) {
          connection.sendError(
            id,
            'token_expired',
            'GitHub refused the token',
            {'stores': refused},
          );
        } else if (offline.isNotEmpty) {
          connection.sendError(id, 'offline', 'GitHub could not be reached', {
            'stores': offline,
          });
        } else {
          connection.send({'op': 'ok', 'id': id});
        }
      case 'keys':
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        final now = service.now;
        connection.send({
          'op': 'keyList',
          'id': id,
          'keys': [for (final k in service.keys) k.toJson(now)],
        });
      case 'approvals.list':
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        connection.send({
          'op': 'approvalList',
          'id': id,
          'approvals': [
            for (final event in service.approvals?.waitingEvents ?? const [])
              {
                for (final e in event.entries)
                  if (e.key != 'op') e.key: e.value,
              },
          ],
        });
      case 'compact':
        final repository = m['repository'];
        if (repository is! String ||
            !RegExp(r'^[^/\s]+/[^/\s]+$').hasMatch(repository)) {
          connection.sendError(id, 'malformed', 'repository is owner/name', {
            'reason': 'repository',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        await service._compact(id, repository, connection);
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
        // A prompt that waits gets to an approver who attaches late.
        if (isApprover) {
          for (final event in service.approvals?.waitingEvents ?? const []) {
            connection.send(event);
          }
        }
        // The reminders due now, to an app that attached after they were
        // first sent.
        for (final key in service.expiring) {
          service._reminded[key.key] = key.step;
          connection.send(key.toEvent());
        }
      case 'approve' ||
          'approval.redeem' ||
          'approval.issue' ||
          'grants.list' ||
          'grants.add' ||
          'grants.revoke' ||
          'approvers.cliSwitch' ||
          'audit.query':
        await _approvalRequest(id, op, m);
      default:
        connection.sendError(id, 'unsupported', 'unknown op $op', {'op': op});
    }
  }
}
