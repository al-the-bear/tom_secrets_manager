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

import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;
import 'package:tom_core_storage/settings.dart';
import 'package:tom_core_storage/tom_core_storage.dart'
    show TomKeyRequiredException;
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_crypto/protected_value.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'access.dart';
import 'agent.dart';
import 'approvals.dart';
import 'approver_links.dart';
import 'audit.dart';
import 'bootstrap.dart';
import 'connection.dart';
import 'github_app.dart';
import 'github_opener.dart';
import 'identity.dart';
import 'key_expiry.dart';
import 'link_client.dart';
import 'link_server.dart';
import 'lock_policy.dart';
import 'log.dart';
import 'peer_identity.dart';
import 'rate_limits.dart';
import 'secret_frame.dart';
import 'token_check.dart';
import 'vault_set.dart';

/// The service's version, sent in `welcome` and `challenge`.
const String tomSecretsServiceVersion = '0.23.0';

/// What a service is started with.
final class TomSecretsServiceConfig {
  /// A configuration; [adminKey] is the key the starter handed over.
  TomSecretsServiceConfig({
    required this.runtime,
    required this.bootstrap,
    required this.adminKey,
    this.opener,
    this.githubBaseUrl = 'https://api.github.com',
    this.githubWebUrl = 'https://github.com',
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
    this.browserHostExecutables,
    this.helperExecutables,
    this.lastUsedInterval,
    this.approverLinkRetry = const Duration(seconds: 5),
    this.rateLimits = const TomSecretsRateLimitSettings(),
    this.rateLimitClock,
    this.sshAgent = true,
    this.agentPipe = TomSecretsRuntime.agentPipe,
    String? knownHostsFile,
  }) : knownHostsFile = knownHostsFile ?? tomSecretsDefaultKnownHosts(),
       clock = clock ?? DateTime.now,
       peerMeasurer = peerMeasurer ?? TomSecretsSystemPeerMeasurer(),
       idleSource = idleSource ?? tomSecretsSystemIdleSource(),
       host = host ?? bootstrap.host ?? tomSecretsDefaultHost(),
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

  /// GitHub's web endpoints, for the App's device flow (part-key-rotation
  /// §3).
  final String githubWebUrl;

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

  /// The real paths of the browser host (`tsm-browser-host`), the client
  /// `match` and `propose` answer (protocol.md 5.5); null (an in-process
  /// service in tests): any executable of that file name.
  final Set<String>? browserHostExecutables;

  /// The real paths of the developer-tool helpers (`tsm`, which
  /// `git-credential-tsm` and `docker-credential-tsm` resolve to, or copies
  /// of those names), which `match` answers too; null: by file name.
  final Set<String>? helperExecutables;

  /// How often the grants' last use is written to the primary vault; null:
  /// the refresh interval (`refreshMinutes`, so a `github:` primary is not
  /// committed more often than it is fetched), or an hour with refresh off.
  final Duration? lastUsedInterval;

  /// The first pause before a session to a paired host is opened again
  /// (doubling up to five minutes); tests make it short.
  final Duration approverLinkRetry;

  /// The client endpoint's rate limits (protocol.md 11).
  final TomSecretsRateLimitSettings rateLimits;

  /// The clock the rate limits run on (tests); null: the system clock.
  final DateTime Function()? rateLimitClock;

  /// Whether the ssh-agent endpoint is offered (part-os-integration).
  final bool sshAgent;

  /// The ssh-agent's named pipe on Windows; one name per machine, so tests
  /// that run services side by side give each its own.
  final String agentPipe;

  /// The user's `known_hosts`, read for the names of a destination in an
  /// agent prompt; null: none.
  final String? knownHostsFile;
}

/// `~/.ssh/known_hosts` of this user, or null when no home is set.
String? tomSecretsDefaultKnownHosts() {
  final home =
      Platform.environment['HOME'] ?? Platform.environment['USERPROFILE'];
  if (home == null || home.isEmpty) return null;
  final sep = Platform.pathSeparator;
  return '$home$sep.ssh${sep}known_hosts';
}

/// The executables that may administer a service started from
/// [serviceExecutable] with [bootstrap] (protocol.md 6.1), as real paths:
/// `tsm` and the manager app (`tom_secrets_desktop`, `tom_secrets_app`)
/// beside the service's executable, the app of the distribution the service
/// is part of (`tomSecretsDistributionApp`: the app carries `tsm` and the
/// service in its `tsm/bin` folder), and the bootstrap's
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
    tomSecretsRealPath(
      tomSecretsDistributionApp(dir, operatingSystem: Platform.operatingSystem),
      null,
    ),
    for (final path in bootstrap.adminExecutables)
      tomSecretsRealPath(path, null),
  };
}

/// The file name of the browser host (protocol.md 5.5), without `.exe`.
const String tomSecretsBrowserHostName = 'tsm-browser-host';

/// The file names the developer-tool helpers run as (protocol.md 5.5),
/// without `.exe`: `tsm` and its multi-call names.
const List<String> tomSecretsHelperNames = [
  'tsm',
  'git-credential-tsm',
  'docker-credential-tsm',
];

/// The browser host and the helpers of a service started from
/// [serviceExecutable], as real paths beside it (protocol.md 5.5).
({Set<String> browserHosts, Set<String> helpers}) tomSecretsLookupExecutables(
  String serviceExecutable,
) {
  final dir = File(serviceExecutable).parent.path;
  final ext = Platform.isWindows ? '.exe' : '';
  String at(String name) =>
      tomSecretsRealPath('$dir${Platform.pathSeparator}$name$ext', null);
  return (
    browserHosts: {at(tomSecretsBrowserHostName)},
    helpers: {for (final name in tomSecretsHelperNames) at(name)},
  );
}

/// The optional features this service offers (protocol.md 8).
const List<String> tomSecretsServiceFeatures = [
  'binary',
  'getFile',
  'match',
  'propose',
];

/// The size of a `getFile` chunk (protocol.md 2.5: at most 1 MiB less the
/// 8 id bytes).
const int tomSecretsFileChunkSize = 256 * 1024;

/// A running service.
final class TomSecretsService
    implements TomSecretsApprovalHost, TomSecretsAgentHost {
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
      try {
        await service._githubApp.load();
      } on Object catch (e) {
        config.log.error('github_app_unreadable', e);
      }
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
  )..onPrimaryKeysChanged = _primaryKeysTaken;

  /// The set took up the primary's next keys (part-key-rotation): they are
  /// its keys in the keychain from now on.
  Future<void> _primaryKeysTaken(TomSecretsHeldKeys keys) async {
    await _keepPrimaryKeys(_primaryLocator, keys);
    log.info('primary_next_keys_taken', {});
  }

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

  /// The primary's locator: the bootstrap's, until a move of the primary
  /// (`vault.move`) changes it (and the bootstrap file with it).
  late String _primaryLocator = config.bootstrap.primary;
  TomSecretsApprovals? _approvals;
  TomSecretsApproverLinks? _approverLinks;
  TomSecretsAuditLog? _audit;
  TomSecretsLinkServer? _linkServer;
  Timer? _lastUsedTimer;
  ServerSocket? _clientServer;
  ServerSocket? _adminServer;
  String _clientToken = '';
  final Set<_ClientSession> _clients = {};

  /// The client endpoint's rate limits, per measured identity.
  late final TomSecretsRateLimits _rateLimits = TomSecretsRateLimits(
    settings: config.rateLimits,
    now: config.rateLimitClock,
  );
  final Set<_AdminSession> _admins = {};
  int _authFailures = 0;

  /// The logins a browser prompt allowed `once` (protocol.md 5.5): by the
  /// browser host as started by its browser (the grant subject an `always`
  /// would have written), the entries (`<store>/<uuid>`) and until when. The
  /// browser host lists them and reads each once until then; the extension's
  /// list and its fill are separate host processes, so this is the
  /// service's, not one connection's. Forgotten at the lock.
  final Map<String, Map<String, DateTime>> _browserOnce = {};

  /// How long a browser prompt's `once` holds.
  static const browserOnceFor = Duration(minutes: 10);
  final Completer<void> _done = Completer<void>();
  Completer<void> _unlocked = Completer<void>();
  bool _stopping = false;

  /// Completes when the service has stopped.
  Future<void> get done => _done.future;

  /// Whether the service is locked.
  @override
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
    if (config.sshAgent) {
      // The agent is an extra: a start goes on without it (another process
      // holds the pipe, a socket path too long), and says so in the log.
      try {
        switch (runtime.transport) {
          case TomSecretsTransport.unix:
            await _agent.listenSocket(runtime.agentSocket);
          case TomSecretsTransport.tcp:
            await _agent.listenPipe(config.agentPipe);
        }
      } on Object catch (e) {
        config.log.error('agent_unavailable', e);
      }
    }
    Map<String, Object?> endpoint(ServerSocket server, String socket) =>
        runtime.transport == TomSecretsTransport.unix
        ? {'socket': socket}
        : {'port': server.port};
    await runtime.writeInfo(
      start: startedAt,
      client: endpoint(_clientServer!, runtime.clientSocket),
      admin: endpoint(_adminServer!, runtime.adminSocket),
      agent: _agent.endpoint,
    );
  }

  Future<void> _closeServers() async {
    await _clientServer?.close();
    await _adminServer?.close();
    await _agent.close();
  }

  // ── The GitHub App sign-in (part-key-rotation §3, DP-83) ────────────────

  late final TomSecretsGitHubApp _githubApp = TomSecretsGitHubApp(
    keychain: config.keychain,
    webBaseUrl: config.githubWebUrl,
    apiBaseUrl: config.githubBaseUrl,
    client: config.githubClient,
    clock: config.clock,
  );

  /// The device's App sign-in.
  TomSecretsGitHubApp get githubApp => _githubApp;

  /// The client id of the user's GitHub App the primary names, or null.
  String? get githubAppClientId {
    final primary = _vaults.primary;
    if (primary == null) return null;
    try {
      return TomSecretsMetadata.read(primary.file).githubAppClientId;
    } on TomSecretsMetadataException {
      return null;
    }
  }

  /// Writes the App's client id into the primary's metadata ([clientId]
  /// empty: removes it) and saves the primary; every device learns it with
  /// its next refresh.
  Future<void> setGitHubAppClientId(String clientId) async {
    final primary = _vaults.primary;
    if (primary == null) throw StateError('locked');
    final m = TomSecretsMetadata.read(primary.file);
    (clientId.isEmpty
            ? m.copyWith(clearGithubAppClientId: true)
            : m.copyWith(githubAppClientId: clientId))
        .writeTo(primary.file);
    await savePrimary();
  }

  /// Starts "Sign in with GitHub" for the App the primary names (or
  /// [clientId] when the service is locked and the primary unread): the
  /// device code; the outcome comes as the event `github_sign_in`, and a
  /// sign-in fetches every store again with the new token.
  Future<TomSecretsDeviceCode> startGitHubSignIn([String? clientId]) {
    final id = githubAppClientId ?? clientId;
    if (id == null || id.isEmpty) {
      throw const TomSecretsGitHubAppException(
        'not_configured',
        'no GitHub App is registered',
      );
    }
    return _githubApp.startSignIn(
      id,
      onDone: (outcome, {login}) {
        log.info('github_sign_in', {'outcome': outcome});
        _emit({'op': 'github_sign_in', 'outcome': outcome, 'login': ?login});
        if (outcome == 'signed_in') {
          unawaited(_recordGitHubAuth(TomSecretsGitHubAuth.app));
          if (!isLocked) unawaited(refresh(force: true));
        }
      },
    );
  }

  /// Signs the device out of the App: its pasted tokens are used again.
  Future<void> signOutOfGitHub() async {
    await _githubApp.signOut();
    log.info('github_signed_out', {});
    _emit({'op': 'github_sign_in', 'outcome': 'signed_out'});
    await _recordGitHubAuth(null);
    if (!isLocked) unawaited(refresh(force: true));
  }

  /// This device's record in the primary names how it reaches GitHub
  /// (part-sharing; the Pairing screen's lost-device advice reads it).
  Future<void> _recordGitHubAuth(
    TomSecretsGitHubAuth? auth, {
    DateTime? expires,
  }) async {
    final primary = _vaults.primary;
    if (primary == null) return;
    try {
      final changed = TomSecretsDeviceRecords(primary.file).setGitHub(
        config.host,
        auth,
        auth == TomSecretsGitHubAuth.app ? _githubApp.refreshExpires : expires,
      );
      if (changed) await savePrimary();
    } on Object catch (e) {
      log.error('device_record_failed', e);
    }
  }

  DateTime? _lastForcedRenewal;

  /// GitHub refused the App's token (401) on a store: the token is renewed
  /// once (at most once a minute) and the stores fetched again.
  Future<bool> _renewAfterRefusal(TomSecretsRefreshReport report) async {
    if (!report.states.any(
      (s) => s.state == TomSecretsStoreState.tokenExpired,
    )) {
      return false;
    }
    if (!await _githubApp.signedIn) return false;
    final now = config.clock();
    final last = _lastForcedRenewal;
    if (last != null && now.difference(last) < const Duration(minutes: 1)) {
      return false;
    }
    _lastForcedRenewal = now;
    return await _githubApp.accessToken(force: true) != null;
  }

  // ── The ssh-agent (part-os-integration) ─────────────────────────────────

  late final TomSecretsSshAgent _agent = TomSecretsSshAgent(this);

  /// The agent's endpoint as `service.json` names it (`{socket}` or
  /// `{pipe}`), or null when it is not offered.
  Map<String, Object?>? get agentEndpoint => _agent.endpoint;

  @override
  bool askUnlock(TomSecretsIdentity identity) {
    if (!_hasSubscribers) return false;
    _emit({'op': 'unlock_needed', 'identity': identity.toJson()});
    return true;
  }

  @override
  Duration get approvalTimeout => settings.approvalTimeout;

  @override
  TomSecretsResolver? get resolver => _vaults.resolver;

  @override
  TomSecretsAccessPolicy? get agentPolicy => config.policy ?? _approvals;

  @override
  TomSecretsPeerMeasurer get peerMeasurer => config.peerMeasurer;

  @override
  String get agentKeysFile =>
      '${config.bootstrap.dataDirectory}${Platform.pathSeparator}agent_keys.json';

  @override
  String? get knownHostsFile => config.knownHostsFile;

  /// Unlocks with [keys] (the master password and key file, which the
  /// service holds masked while unlocked): opens the primary, the device
  /// settings container (its key where `bootstrap.yaml` says), then the
  /// stores the machine serves; starts the lock policy. Throws
  /// [KdbxInvalidKeyException] for a wrong password; [keys] are disposed
  /// when the unlock fails.
  Future<void> unlock(TomSecretsHeldKeys given) async {
    final primaryLocator = _primaryLocator;
    final TomSecretsOpenedVault primary;
    var keys = await _withKeychainKeys(primaryLocator, given);
    TomSecretsOpenedVault? opened;
    Object? refused;
    StackTrace? refusedTrace;
    try {
      opened = await _vaults.openPrimary(primaryLocator, keys);
    } on Object catch (e, trace) {
      if (e is! KdbxInvalidKeyException && e is! TomKeyRequiredException) {
        keys.dispose();
        rethrow;
      }
      refused = e;
      refusedTrace = trace;
    }
    if (opened == null ||
        opened.offlineReason is TomSecretsKeyChangedException) {
      // Another device switched a guided rotation of the primary's keys
      // (part-key-rotation): the next keys this device took before are in
      // its keychain.
      final next = await _withNextKeychainKeys(primaryLocator, keys);
      if (next != null) {
        try {
          final withNext = await _vaults.openPrimary(primaryLocator, next);
          if (withNext.offlineReason == null) {
            keys.dispose();
            keys = next;
            opened = withNext;
            await _keepPrimaryKeys(primaryLocator, next);
          } else {
            next.dispose();
          }
        } on Object {
          next.dispose();
        }
      }
    }
    if (opened == null) {
      keys.dispose();
      Error.throwWithStackTrace(refused!, refusedTrace!);
    }
    primary = opened;
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
      // The sessions to the paired hosts this device approves for.
      _approverLinks = TomSecretsApproverLinks(
        this,
        approvals,
        retry: config.approverLinkRetry,
      )..start();
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
    await _takeNextKeys();
    await _readTokenExpiries();
    _remindKeys();
  }

  /// **[C]** This device taking the keys of the guided rotations running in
  /// the primary (part-key-rotation, step 1), at every unlock, refresh and
  /// save of the primary: the primary's own next keys go into the keychain
  /// beside its keys (`<handle>.next`, where the unlock and the refresh find
  /// them after another device switched), the set holds them, and the ids
  /// of the keys this device now holds go into its device record, so the
  /// app lists the devices still missing. A finished rotation's next keys
  /// leave the keychain.
  Future<void> _takeNextKeys() async {
    final primary = _vaults.primary;
    final trust = _trust;
    if (primary == null || trust == null) return;
    final next = TomSecretsPrimaryNextKeys.of(primary.file);
    _vaults.primaryNextKeys = next;
    final ids = <String>[];
    if (next != null) {
      if (await _keepPrimaryNextKeys(next)) {
        ids.addAll(
          tomSecretsVaultKeyIds(keyFile: next.keyFile, outerKey: next.outerKey),
        );
      }
    } else {
      await _dropPrimaryNextKeys();
    }
    if (await _serial(_vaults.adoptPrimaryNext)) {
      final status = _vaults.statusOf(_vaults.primaryName ?? '');
      if (status != null) _emitState(status);
    }
    if (tomSecretsTakeNextKeys(
      primary.file,
      device: trust.device,
      now: now,
      primaryKeyIds: ids,
    )) {
      log.info('next_keys_taken', {'device': trust.device});
      await savePrimary();
    }
  }

  /// Keeps the primary's next keys in the keychain beside its keys; answers
  /// whether this device holds them now (none needed, or kept).
  Future<bool> _keepPrimaryNextKeys(TomSecretsPrimaryNextKeys next) async {
    final keychain = config.keychain;
    if (keychain == null) return false;
    try {
      final vault = TomSecretsVaultLocator.parse(_primaryLocator);
      if (next.keyFile != null) {
        await keychain.write(
          '${vault.keyFileHandle}.next',
          base64.encode(next.keyFile!),
        );
      }
      if (next.outerKey != null) {
        await keychain.write(
          '${vault.repositoryKeyHandle}.next',
          next.outerKey!,
        );
      }
      return true;
    } on TomSecretStoreException catch (e) {
      log.error('keychain_failed', e);
      return false;
    }
  }

  Future<void> _dropPrimaryNextKeys() async {
    final keychain = config.keychain;
    if (keychain == null) return;
    try {
      final vault = TomSecretsVaultLocator.parse(_primaryLocator);
      await keychain.delete('${vault.keyFileHandle}.next');
      await keychain.delete('${vault.repositoryKeyHandle}.next');
    } on TomSecretStoreException catch (e) {
      log.error('keychain_failed', e);
    }
  }

  /// The primary's keys [held] with the next keys this device took into
  /// its keychain before (`<handle>.next`), or null when it holds none.
  Future<TomSecretsHeldKeys?> _withNextKeychainKeys(
    String locator,
    TomSecretsHeldKeys held,
  ) async {
    final keychain = config.keychain;
    if (keychain == null) return null;
    try {
      final vault = TomSecretsVaultLocator.parse(locator);
      final keyFile = await keychain.read('${vault.keyFileHandle}.next');
      final outerKey = await keychain.read('${vault.repositoryKeyHandle}.next');
      if ((keyFile == null || keyFile.isEmpty) &&
          (outerKey == null || outerKey.isEmpty)) {
        return null;
      }
      if (keyFile != null && keyFile.isNotEmpty && held.compositeKey != null) {
        // The OS unlock's composite key binds the old key file.
        return null;
      }
      return TomSecretsHeldKeys(
        password: held.password == null
            ? null
            : TomProtectedValue.of(held.password!.reveal()),
        keyFile: keyFile != null && keyFile.isNotEmpty
            ? TomProtectedValue.fromBytes(base64.decode(keyFile))
            : (held.keyFile == null
                  ? null
                  : TomProtectedValue.fromBytes(
                      held.keyFile!.withRevealed(Uint8List.fromList),
                    )),
        outerKey: outerKey != null && outerKey.isNotEmpty
            ? TomProtectedValue.of(outerKey)
            : (held.outerKey == null
                  ? null
                  : TomProtectedValue.of(held.outerKey!.reveal())),
        compositeKey: held.compositeKey == null
            ? null
            : TomProtectedValue.fromBytes(
                held.compositeKey!.withRevealed(Uint8List.fromList),
              ),
      );
    } on Object catch (e) {
      log.error('keychain_failed', e);
      return null;
    }
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
        var report = await _vaults.refresh(force: force);
        if (isLocked) return report;
        if (await _renewAfterRefusal(report)) {
          report = await _vaults.refresh(force: true);
          if (isLocked) return report;
        }
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
      }).then((report) async {
        // Outside the refresh's turn: a host that did not answer must not
        // hold up the saves.
        if (!isLocked) await deliverToHosts();
        if (!isLocked && report.reopened.contains(_vaults.primaryName)) {
          await _takeNextKeys();
        }
        return report;
      });

  /// Answers `compact {repository}` (part-stores, `tsm compact`): the cut
  /// of [repository]'s history through the GitHub opener, in turn with the
  /// refresh and the saves.
  Future<void> _compact(
    int id,
    String repository,
    TomSecretsConnection connection, {
    int? retentionDays,
  }) async {
    final github = _github;
    if (github == null || !github.repositories.contains(repository)) {
      connection.sendError(id, 'not_found', 'no open vault in $repository', {
        'repository': repository,
      });
      return;
    }
    try {
      final result = await _serial(
        () => github.compact(repository, retentionDays: retentionDays),
      );
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

  /// Keeps the primary's re-keyed [keys] in the device keychain, where the
  /// unlock takes them (part-stores): its key file (`tsm.key-file.<id>`,
  /// removed when the primary has none any more) and for a `.tsmx` primary
  /// its repository key (`tsm.repository-key.<id>`). A keychain that fails
  /// is logged; the keys are still held until the lock.
  Future<void> _keepPrimaryKeys(String locator, TomSecretsHeldKeys keys) async {
    final keychain = config.keychain;
    if (keychain == null) return;
    try {
      final vault = TomSecretsVaultLocator.parse(locator);
      final keyFile = keys.keyFile;
      if (keyFile == null) {
        await keychain.delete(vault.keyFileHandle);
      } else {
        await keychain.write(
          vault.keyFileHandle,
          keyFile.withRevealed(base64.encode),
        );
      }
      final outerKey = keys.newestOuterKey;
      if (vault.fileName.endsWith(tomSecretsOuterSuffix) && outerKey != null) {
        await keychain.write(vault.repositoryKeyHandle, outerKey);
      }
      log.info('keychain_keys_replaced', {'store': vault.fileName});
    } on TomSecretStoreException catch (e) {
      log.error('keychain_failed', e);
    }
  }

  /// [given] (the master password and the key file the unlock carries)
  /// completed from the device keychain for the primary at [locator]
  /// (part-stores): its key file when [given] carries none
  /// (`tsm.key-file.<id>`, base64), and for a `.tsmx` primary its
  /// repository key (`tsm.repository-key.<id>`). A keychain that fails is
  /// logged, and the unlock goes on with what it has.
  Future<TomSecretsHeldKeys> _withKeychainKeys(
    String locator,
    TomSecretsHeldKeys given,
  ) async {
    final keychain = config.keychain;
    if (keychain == null) return given;
    // A store that can say it is not available (a locked keychain) is not
    // read: the unlock goes on with what it carries.
    if (keychain is TomSecretStoreAvailability &&
        !await (keychain as TomSecretStoreAvailability).isAvailable()) {
      return given;
    }
    final TomSecretsVaultLocator vault;
    try {
      vault = TomSecretsVaultLocator.parse(locator);
    } on TomSecretsLocatorException {
      return given;
    }
    Future<String?> read(String handle) async {
      try {
        final value = await keychain.read(handle);
        return value == null || value.isEmpty ? null : value;
      } on TomSecretStoreException catch (e) {
        log.error('keychain_failed', e);
        return null;
      }
    }

    // A composite key (an OS unlock) already holds the key file's part; the
    // key file is still kept beside it, for the editing path's `vaultKeys`
    // (pairing, the emergency sheet, a new vault sharing it), while the
    // composite key opens the vault.
    final keyFile = given.keyFile == null
        ? await read(vault.keyFileHandle)
        : null;
    final outerKey =
        given.outerKey == null && vault.fileName.endsWith(tomSecretsOuterSuffix)
        ? await read(vault.repositoryKeyHandle)
        : null;
    if (keyFile == null && outerKey == null) return given;
    final Uint8List? keyFileBytes;
    try {
      keyFileBytes = keyFile == null ? null : base64.decode(keyFile);
    } on FormatException {
      log.info('keychain_key_file_unreadable', {'store': vault.fileName});
      return given;
    }
    final keys = TomSecretsHeldKeys(
      password: given.password,
      keyFile: keyFileBytes == null
          ? given.keyFile
          : TomProtectedValue.fromBytes(keyFileBytes),
      outerKey: outerKey == null
          ? given.outerKey
          : TomProtectedValue.of(outerKey),
      compositeKey: given.compositeKey,
    );
    return keys;
  }

  /// The token of [vault]'s repository: the device keychain's
  /// (`tsm.github-token.<owner>:<repository>`), else one the primary's vault
  /// list keeps for a vault in that repository, never for the primary's own
  /// repository (part-stores).
  Future<String?> _githubToken(TomSecretsGitHubLocator vault) async {
    final offered = _offeredTokens[vault.repositorySlug];
    if (offered != null) return offered;
    // Signed in with the GitHub App (DP-83): its user token, renewed first
    // when it runs out; a device that must sign in again has none.
    if (await _githubApp.signedIn) return _githubApp.accessToken();
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
  /// - the key file and repository key of each further vault, from
  ///   `otherKeyWarningDays` (default 30) before the Expires of its entry in
  ///   the primary, and of the primary, before its metadata's
  ///   `tsm.keys-due`;
  /// - this device's approver and approval-link key pairs and those of the
  ///   peers it recorded, from `otherKeyWarningDays` before their rotation
  ///   age (`keyPairAgeMonths`, default 24, DP-85) is over.
  List<TomSecretsExpiringKey> get expiring {
    final now = this.now;
    return [for (final k in keys) ?k.dueAt(now)];
  }

  /// The typed certificate and PGP key entries of [file] that expire, with
  /// their reminder kind (`certificate`, `pgp_key`); the recycle bin and
  /// history versions left out.
  static List<(String, KdbxEntry)> _typedKeyEntries(KdbxFile file) {
    final bin = file.recycleBin;
    final out = <(String, KdbxEntry)>[];
    void walk(KdbxGroup group) {
      if (bin != null && group.uuid == bin.uuid) return;
      for (final e in group.entries) {
        if (e.times.expires.get() != true) continue;
        final type = TomSecretsEntryType.of(
          e.getString(TomSecretsEntryFields.type)?.getText(),
        );
        if (type == TomSecretsEntryType.certificate) {
          out.add(('certificate', e));
        } else if (type == TomSecretsEntryType.pgpKey) {
          out.add(('pgp_key', e));
        }
      }
      group.groups.forEach(walk);
    }

    walk(file.body.rootGroup);
    return out;
  }

  /// Every key the service knows a due date of (`tsm keys`), whether or not
  /// a reminder is due: the GitHub tokens, the vaults' key files and
  /// repository keys, the key pairs, **[C]** the member key and the typed
  /// certificates and PGP keys of the stores served; [expiring] are those due now.
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
      bool own = false,
    }) => expiresAt == null
        ? null
        : TomSecretsKeyDate(
            kind: kind,
            key: key,
            vault: vault,
            expiresAt: expiresAt,
            firstDays: settings.otherKeyWarningDays,
            own: own,
          );
    TomSecretsKeyDate? pair(
      String kind,
      String key,
      DateTime? since, {
      bool own = false,
    }) => other(
      kind,
      key,
      TomSecretsExpiringKey.keyPairDue(
        since,
        months: settings.keyPairAgeMonths,
      ),
      own: own,
    );
    final appRefresh = _githubApp.refreshExpires;
    return [
      if (appRefresh != null)
        TomSecretsKeyDate(
          kind: 'github_app',
          key: 'github-app:${config.host}',
          expiresAt: appRefresh,
          firstDays: settings.keyExpiryWarningDays,
        ),
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
      // [C] Typed certificates and PGP keys (part-sharing, BP-33): their
      // own expiry, copied into the entry's Expires (a certificate's
      // notAfter), reminded of 30 days before (otherKeyWarningDays).
      for (final MapEntry(key: store, value: file) in _vaults.openFiles.entries)
        for (final entry in _typedKeyEntries(file))
          ?other(
            entry.$1,
            '${entry.$1 == 'certificate' ? 'certificate' : 'pgp-key'}:'
            '$store/${entry.$2.label ?? ''}',
            entry.$2.times.expiryTime.get(),
            vault: store,
          ),
      // [C] The user's member key (part-sharing): its rotation age counted
      // from its entry's creation; one in rotation (the old key kept until
      // the finish) is reminded of by its newest key only.
      if (primary != null)
        if (tomSecretsMemberKeyEntries(primary.file).firstOrNull
            case final memberKey?)
          if (tomSecretsMemberKeyRecipientOf(memberKey) case final recipient?)
            ?other(
              'member_key',
              'member-key:${recipient.fingerprint.substring(0, 16)}',
              TomSecretsExpiringKey.keyPairDue(
                memberKey.times.creationTime.get(),
                months: settings.memberKeyAgeMonths,
              ),
              own: true,
            ),
      if (trust != null) ...[
        ?pair(
          'approver_key',
          'approver-key:${trust.device}',
          trust.approverKeySince,
          own: true,
        ),
        ?pair(
          'link_key',
          'link-key:${trust.device}',
          trust.linkKeySince,
          own: true,
        ),
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
  @override
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

  /// Sends [event] to every subscribed manager app (not `tsm`); whether one
  /// got it (protocol.md 5.5 `propose`: with none attached the proposal is
  /// dropped).
  bool _emitToApps(Map<String, Object?> event) {
    var sent = false;
    for (final a in _admins) {
      if (a.subscribed && a.isApp) {
        a.connection.send(event);
        sent = true;
      }
    }
    return sent;
  }

  void _emit(Map<String, Object?> event) {
    for (final a in _admins) {
      if (a.subscribed) a.connection.send(event);
    }
  }

  /// The `statusReport` members.
  Map<String, Object?> statusReport() => {
    'locked': isLocked,
    // The protocol's letters (DP-14): (a) never relock, (b) on idle, (c) on
    // idle or at the screen lock (part-os-unlock).
    'lockMode': switch (settings.serviceLock.mode) {
      TomSecretsLockMode.never => 'a',
      TomSecretsLockMode.idle => 'b',
      TomSecretsLockMode.osUnlock => 'c',
    },
    'protocol': 1,
    'service': {'version': tomSecretsServiceVersion, 'start': startedAt},
    'stores': [for (final s in _vaults.status) s.toJson()],
    'expiring': [for (final k in expiring) k.toJson()],
    'admins': _admins.where((a) => a.authenticated).length,
    'hardening': _hardening,
    // [B] The ssh-agent's endpoint, when it runs (part-os-integration).
    'agent': ?_agent.endpoint,
    // [B] The GitHub App sign-in (part-key-rotation §3).
    'github': {
      'state': _githubApp.state(githubAppClientId).wireName,
      'login': ?_githubApp.describe(null)['login'],
    },
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
    await _approverLinks?.stop();
    _approverLinks = null;
    _approvals?.abandonAll();
    _browserOnce.clear();
    await _approvals?.closeLinks();
    await _linkServer?.close();
    await _audit?.close();
    _approvals = null;
    _linkServer = null;
    _audit = null;
    _trust = null;
    _pendingStatement = null;
    _statementDelivered.clear();
    _lastDelivery = null;
  }

  /// The approvals and grants, while unlocked.
  TomSecretsApprovals? get approvals => _approvals;

  /// The sessions to the paired hosts this device approves for, while
  /// unlocked.
  TomSecretsApproverLinks? get approverLinks => _approverLinks;

  /// What waits for an answer: this host's prompts and those of the paired
  /// hosts this device approves for.
  List<Map<String, Object?>> get waitingPrompts => [
    ...?_approvals?.waitingEvents,
    ...?_approverLinks?.waitingEvents,
  ];

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
            (was.state != s.state ||
                was.wireSource != s.wireSource ||
                was.rewrittenHead != s.rewrittenHead)) {
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
    if (status.rewrittenHead != null)
      'rewritten': {'head': status.rewrittenHead},
    if (status.keyChanged) 'keyChanged': true,
  });

  /// Answers the rewritten branch of [store] (`history.resolve`, protocol.md
  /// 6.3), tells the subscribers (`store_state`, `store_changed`) and logs
  /// it.
  Future<TomSecretsSaveResult> resolveRewritten(
    String store, {
    required bool takeRemote,
  }) async {
    final result = await _serial(
      () => _tellingStates(
        () => _vaults.resolveRewritten(store, takeRemote: takeRemote),
      ),
    );
    log.info('history_resolved', {
      'store': store,
      'take': takeRemote ? 'remote' : 'merge',
      'conflicts': result.conflicts,
    });
    _emit({'op': 'store_changed', 'store': store, 'revision': result.revision});
    if (store == _vaults.primaryName) await _approvals?.reload();
    return result;
  }

  /// Replaces the GitHub token of [repository] (`owner/name`, the
  /// repository of the primary or of a vault the primary lists) with
  /// [token] (`token.set`, part-key-rotation §3): first checks it with
  /// [tomSecretsCheckGitHubToken] (it sees the repository and can write
  /// there; the expiry GitHub reports), then writes it where the old one
  /// lives — the device keychain's `tsm.github-token.<owner>:<repository>`
  /// with its expiry (`tsm.github-token-expiry.…`), else the entries of the
  /// primary's vault list that keep a token for that repository (never for
  /// the primary's own repository) — and fetches every store again. A
  /// repository with no token yet takes the keychain, else the vault list.
  /// Throws [StateError] for a repository no vault is in,
  /// [TomSecretsTokenCheckException] for a refused token, and
  /// [UnsupportedError] when there is nowhere to keep it (no keychain, the
  /// primary's own repository).
  Future<({String where, DateTime? expiresAt})> setGitHubToken(
    String repository,
    String token,
  ) async {
    final primary = _vaults.primary;
    if (primary == null) throw StateError('locked');
    final listed = TomSecretsPrimaryVaults(primary.file).list();
    TomSecretsGitHubLocator? vault;
    for (final locator in [
      primary.locator,
      for (final k in listed) k.locator,
    ]) {
      final parsed = TomSecretsVaultLocator.parse(locator);
      if (parsed is TomSecretsGitHubLocator &&
          parsed.repositorySlug == repository) {
        vault = parsed;
        break;
      }
    }
    if (vault == null) throw StateError(repository);
    final expiresAt = await tomSecretsCheckGitHubToken(
      owner: vault.owner,
      repository: vault.repository,
      token: token,
      baseUrl: config.githubBaseUrl,
      client: config.githubClient,
    );
    final own = TomSecretsVaultLocator.parse(primary.locator);
    final ownRepository =
        own is TomSecretsGitHubLocator && own.repositorySlug == repository;
    bool inRepository(TomSecretsVaultKeys k) {
      final at = TomSecretsVaultLocator.parse(k.locator);
      return at is TomSecretsGitHubLocator && at.repositorySlug == repository;
    }

    final holders = [
      if (!ownRepository)
        for (final k in listed)
          if (inRepository(k) && k.githubToken != null) k,
    ];
    final keychain = config.keychain;
    var inKeychain = false;
    if (keychain != null) {
      try {
        final old = await keychain.read(vault.tokenHandle);
        inKeychain = old != null && old.isNotEmpty;
      } on TomSecretStoreException catch (e) {
        log.error('keychain_failed', e);
      }
    }
    final String where;
    if (keychain != null && (inKeychain || holders.isEmpty)) {
      await keychain.write(vault.tokenHandle, token);
      if (expiresAt == null) {
        await keychain.delete(vault.tokenExpiryHandle);
      } else {
        await keychain.write(
          vault.tokenExpiryHandle,
          expiresAt.toUtc().toIso8601String(),
        );
      }
      where = 'keychain';
    } else if (!ownRepository) {
      final list = TomSecretsPrimaryVaults(primary.file);
      final targets = holders.isEmpty ? listed.where(inRepository) : holders;
      for (final k in targets) {
        list.put(
          TomSecretsVaultKeys(
            name: k.name,
            locator: k.locator,
            password: k.password,
            keyFile: k.keyFile,
            outerKey: k.outerKey,
            githubToken: token,
            githubTokenExpires: expiresAt,
            expires: k.expires,
            // A guided rotation's keys stay (part-key-rotation).
            nextPassword: k.nextPassword,
            nextKeyFile: k.nextKeyFile,
            nextOuterKey: k.nextOuterKey,
            previousOuterKey: k.previousOuterKey,
          ),
        );
      }
      await savePrimary();
      where = 'primary';
    } else {
      throw UnsupportedError(
        'no keychain on this device to keep the token of the primary\'s '
        'repository in',
      );
    }
    log.info('token_set', {'repository': repository, 'where': where});
    // A device not signed in with the App reaches GitHub with this pasted
    // token: its record says so (part-sharing).
    if (!await _githubApp.signedIn) {
      await _recordGitHubAuth(TomSecretsGitHubAuth.token, expires: expiresAt);
    }
    await refresh(force: true);
    return (where: where, expiresAt: expiresAt);
  }

  /// Rotates this device's key pairs by hand (`keys.rotate`,
  /// part-key-rotation §4): with [approver] a new approver pair, every grant
  /// and revocation this device signed signed again with it, and the
  /// key-change statement written into the group of every host it approves
  /// for (the primary saved); with [link] a new approval-link pair, the
  /// previous one kept for the hosts the new one has not reached and the
  /// approvers that connect here, for the migration period (14 days). Then
  /// both go to every recorded host with a link address at once
  /// ([deliverToHosts]). An approver device puts both into one rotation.
  Future<TomSecretsPairsRotated> rotateKeyPairs({
    bool approver = true,
    bool link = true,
  }) async {
    final trust = _trust;
    final approvals = _approvals;
    if (trust == null || approvals == null) throw StateError('locked');
    if (!approver && !link) {
      throw ArgumentError('nothing to rotate');
    }
    Map<String, Object?>? statement;
    var resigned = 0;
    if (approver) {
      statement = await trust.rotateApproverKey(now: now);
      resigned = await approvals.resignAfterRotation(statement);
      _pendingStatement = statement;
    }
    if (link) trust.rotateLinkKey(now: now);
    await writeTrust();
    if (approver) await savePrimary();
    log.info('pairs_rotated', {
      'approver': approver,
      'link': link,
      'resigned': resigned,
    });
    final delivery = await deliverToHosts(force: true);
    _remindKeys();
    return TomSecretsPairsRotated(
      approverKeyId: approver ? (await trust.approverKey()).keyId : null,
      resigned: resigned,
      delivered: delivery.delivered,
      pending: delivery.pending,
    );
  }

  /// The key-change statement of this device's last approver rotation,
  /// sent to the hosts the link reaches; a host not reached finds it in the
  /// vault. Kept until the lock.
  Map<String, Object?>? _pendingStatement;

  /// The hosts the statement reached over the link since the rotation.
  final Set<String> _statementDelivered = {};

  DateTime? _lastDelivery;

  /// Sends this device's new link key (and the key-change statement of a
  /// rotation in this unlock) to every recorded host with a link address
  /// that has not received it, over a link session under the key that host
  /// knows; a host that answers `ok` is marked delivered. Without [force],
  /// at most every 15 minutes (the refresh calls it). Drops the previous
  /// link key once the migration period is over.
  Future<({List<String> delivered, List<String> pending})> deliverToHosts({
    bool force = false,
  }) async {
    final trust = _trust;
    if (trust == null) return (delivered: <String>[], pending: <String>[]);
    if (trust.expirePreviousLinkKey(now)) await writeTrust();
    final statement = _pendingStatement;
    final due = [
      for (final h in trust.hosts)
        if (!h.linkKeyDelivered ||
            (statement != null && !_statementDelivered.contains(h.host)))
          h,
    ];
    if (due.isEmpty) return (delivered: <String>[], pending: <String>[]);
    final last = _lastDelivery;
    if (!force &&
        last != null &&
        now.difference(last) < const Duration(minutes: 15)) {
      return (delivered: <String>[], pending: [for (final h in due) h.host]);
    }
    _lastDelivery = now;
    final link = (await trust.linkKey()).publicKey;
    final delivered = <String>[];
    final pending = <String>[];
    var changed = false;
    for (final host in due) {
      final address = host.address;
      if (address == null) {
        pending.add(host.host);
        continue;
      }
      final sendStatement =
          statement != null && !_statementDelivered.contains(host.host);
      try {
        await tomSecretsDeliverOverLink(
          address: address,
          me: await trust.linkKeyFor(host.host, now: now),
          hostKey: host.linkKey,
          device: trust.device,
          // The host rotated its own link key: it is recorded at once.
          onHostLinkKey: (key) async {
            host
              ..linkKey = key
              ..linkKeySince = now;
            changed = true;
            log.info('host_link_key_taken', {'host': host.host});
          },
          messages: [
            if (sendStatement) {'op': 'keychange', 'statement': statement},
            if (!host.linkKeyDelivered)
              {
                'op': 'linkKey',
                'device': trust.device,
                'x25519': base64.encode(link.x25519),
                'mlKem768': base64.encode(link.mlKem768),
              },
          ],
        );
        if (sendStatement) _statementDelivered.add(host.host);
        if (!host.linkKeyDelivered) {
          trust.markLinkKeyDelivered(host.host);
          changed = true;
        }
        delivered.add(host.host);
      } on TomSecretsLinkDeliveryException catch (e) {
        log.info('link_delivery_failed', {'host': host.host, 'kind': e.kind});
        pending.add(host.host);
      }
    }
    if (changed) await writeTrust();
    log.info('link_delivery', {
      'delivered': delivered.length,
      'pending': pending.length,
    });
    return (delivered: delivered, pending: pending);
  }

  /// Moves [store] to [location] (`vault.move`, protocol.md 6.4): its outer
  /// encryption added or removed ([TomSecretsVaultSet.move]). For the
  /// primary, the bootstrap file's `primary:` takes the new locator (the
  /// next start opens it there), and the device keychain the keys under the
  /// new locator's handles: its key file (`tsm.key-file.<id>` of the new
  /// path; the old handle removed) and, for a `.tsmx` primary, its
  /// repository key. Answers the new revision; tells the subscribers.
  Future<String> moveVault(
    String store,
    String location,
    Uint8List stored, {
    String? baseRevision,
    required TomSecretsHeldKeys newKeys,
  }) async {
    final isPrimary = store == _vaults.primaryName;
    final from = _vaults.statusOf(store)?.locator;
    final revision = await _serial(
      () => _tellingStates(
        () => _vaults.move(
          store,
          location,
          stored,
          baseRevision: baseRevision,
          newKeys: newKeys,
        ),
      ),
    );
    log.info('vault_moved', {
      'store': store,
      'outer': location.endsWith(tomSecretsOuterSuffix),
    });
    if (isPrimary) {
      _primaryLocator = location;
      await _rewriteBootstrap(location);
      if (from != null) await _keepMovedPrimaryKeys(from, location, newKeys);
      await _approvals?.reload();
    }
    _emit({'op': 'store_changed', 'store': store, 'revision': revision});
    return revision;
  }

  /// **[C]** The recipients file of the shared vault [store], or of the
  /// vault at [location] not listed yet (`vault.recipients`, part-sharing:
  /// joining it), read with [githubToken] for that repository when given
  /// (held for this read only). Null when the vault has none.
  Future<({String location, Uint8List bytes, String revision})?> recipients({
    String? store,
    String? location,
    String? githubToken,
  }) async {
    final at = location ?? (store == null ? null : _vaults.locatorOf(store));
    if (at == null) {
      throw TomSecretsSaveException('not_found', 'no store $store');
    }
    final parsed = TomSecretsVaultLocator.parse(at);
    final slug = parsed is TomSecretsGitHubLocator
        ? parsed.repositorySlug
        : null;
    if (githubToken != null && slug != null) _offeredTokens[slug] = githubToken;
    try {
      final read = await _vaults.recipientsAt(at);
      return read == null
          ? null
          : (location: at, bytes: read.bytes, revision: read.revision);
    } finally {
      if (slug != null) _offeredTokens.remove(slug);
    }
  }

  /// **[C]** The packages in the inbox folders beside the store [store]
  /// (`inbox.list`, part-sharing).
  Future<List<({String member, String name, String revision})>> inbox(
    String store,
  ) => _vaults.inbox(store);

  /// **[C]** Runs [io] on the relay folder of the `github:` store [store]'s
  /// repository (its root; `relay.*`, part-relay: GitHub as the relay for the app's
  /// pairing), failures mapped as for the files beside a store.
  Future<T> relay<T>(
    String store,
    Future<T> Function(TomSecretsRelayFolder folder) io,
  ) {
    final folder = _vaults.relayFolder(store);
    return _vaults.relayIo(() => io(folder));
  }

  /// **[C]** One package of the inbox of [member] beside [store]
  /// (`inbox.read`), or null when it is gone.
  Future<({Uint8List bytes, String revision})?> inboxFile(
    String store,
    String member,
    String name,
  ) => _vaults.inboxFile(store, member, name);

  /// **[C]** Puts the package [bytes] into the inboxes of [members] beside
  /// [store] (`inbox.put`); answers its file name.
  Future<String> inboxPut(
    String store,
    List<String> members,
    Uint8List bytes,
  ) async {
    final name = await _serial(() => _vaults.inboxPut(store, members, bytes));
    log.info('inbox_put', {'store': store, 'members': members.length});
    return name;
  }

  /// **[C]** Deletes [files] from the inbox folders beside [store]
  /// (`inbox.delete`).
  Future<void> inboxDelete(
    String store,
    List<({String member, String name})> files,
  ) async {
    await _serial(() => _vaults.inboxDelete(store, files));
    log.info('inbox_deleted', {'store': store, 'files': files.length});
  }

  /// GitHub tokens a request brings for one read of a repository not listed
  /// yet ([recipients]), by `owner/repository`.
  final Map<String, String> _offeredTokens = {};

  /// **[C]** Writes the recipients file of the shared vault [store]
  /// (`vault.recipients.set`, part-sharing: a member added) over
  /// [baseRevision]; answers its new revision.
  Future<String> setRecipients(
    String store,
    Uint8List bytes, {
    required String? baseRevision,
  }) async {
    final revision = await _serial(
      () => _vaults.setRecipients(store, bytes, baseRevision: baseRevision),
    );
    log.info('recipients_written', {'store': store});
    return revision;
  }

  /// Creates the further vault [store] at [location] (`vault.create`,
  /// protocol.md 6.4) as [TomSecretsVaultSet.create] says: the file written
  /// where it lives, then listed in the primary with its keys. Answers the
  /// new vault's revision; tells the subscribers about both stores.
  Future<String> createVault(
    String store,
    String location,
    Uint8List stored, {
    required TomSecretsHeldKeys keys,
    String? githubToken,
    DateTime? keysDue,
    Uint8List? recipients,
  }) async {
    final revision = await _serial(
      () => _tellingStates(
        () => _vaults.create(
          store,
          location,
          stored,
          keys: keys,
          githubToken: githubToken,
          keysDue: keysDue,
          recipients: recipients,
        ),
      ),
    );
    log.info('vault_created', {
      'store': store,
      'github': location.startsWith('github:'),
      'outer': location.endsWith(tomSecretsOuterSuffix),
      if (recipients != null) 'shared': true,
    });
    final primary = _vaults.primaryName;
    if (primary != null) {
      _emit({
        'op': 'store_changed',
        'store': primary,
        'revision': ?_vaults.statusOf(primary)?.revision,
      });
    }
    _emit({'op': 'store_changed', 'store': store, 'revision': revision});
    return revision;
  }

  /// Writes [primary] into the bootstrap file (`bootstrap.yaml` in the data
  /// directory), when there is one; a failure is logged (this run already
  /// serves the moved primary, the next start would not find it).
  Future<void> _rewriteBootstrap(String primary) async {
    final file = File(
      '${config.bootstrap.dataDirectory}${Platform.pathSeparator}bootstrap.yaml',
    );
    try {
      if (!file.existsSync()) return;
      final text = await file.readAsString();
      final temp = File('${file.path}.tmp');
      await temp.writeAsString(tomSecretsBootstrapWithPrimary(text, primary));
      await temp.rename(file.path);
      log.info('bootstrap_primary_written', {});
    } on Object catch (e) {
      log.error('bootstrap_write_failed', e);
    }
  }

  /// Keeps the moved primary's keys in the device keychain under the
  /// handles of its new locator [to] (the key file's handle names the
  /// vault's path), removing the key file under [from]'s.
  Future<void> _keepMovedPrimaryKeys(
    String from,
    String to,
    TomSecretsHeldKeys keys,
  ) async {
    final keychain = config.keychain;
    if (keychain == null) return;
    try {
      final old = TomSecretsVaultLocator.parse(from);
      final vault = TomSecretsVaultLocator.parse(to);
      final keyFile = keys.keyFile;
      if (keyFile != null) {
        await keychain.write(
          vault.keyFileHandle,
          keyFile.withRevealed(base64.encode),
        );
      }
      if (old.keyFileHandle != vault.keyFileHandle) {
        await keychain.delete(old.keyFileHandle);
      }
      final outerKey = keys.newestOuterKey;
      if (outerKey != null) {
        await keychain.write(vault.repositoryKeyHandle, outerKey);
      }
      log.info('keychain_keys_moved', {'store': vault.fileName});
    } on TomSecretStoreException catch (e) {
      log.error('keychain_failed', e);
    }
  }

  /// This device's public keys for a pairing (`pair.identity`,
  /// part-sharing): its approver key, its approval-link key and the address
  /// its link listens on (null when it does not).
  Future<TomSecretsPairingPeerKeys> pairingIdentity() async {
    final trust = _trust;
    if (trust == null) throw StateError('locked');
    return TomSecretsPairingPeerKeys(
      linkKey: (await trust.linkKey()).publicKey,
      approverKey: (await trust.approverKey()).publicKey,
      linkAddress: _linkServer?.address,
    );
  }

  /// Records what a pairing gave (`pair.record`, part-sharing): the peer
  /// [device] as an approver of this host (its approver and link keys) and
  /// as a host this device approves for (its link key and address), with
  /// the approval-token key both derived, every key dated now; a device
  /// paired again replaces what was recorded. With [record] the giving
  /// side's device record goes into the primary (DP-62).
  Future<void> recordPairing({
    required String device,
    required Uint8List tokenKey,
    TomSecretsApproverPublicKey? approverKey,
    TomSecretsLinkPublicKey? approverLinkKey,
    TomSecretsLinkPublicKey? hostLinkKey,
    String? hostAddress,
    ({String? platform, List<String> keyIds})? record,
  }) async {
    final trust = _trust;
    final primary = _vaults.primary;
    if (trust == null || primary == null) throw StateError('locked');
    final at = now;
    trust.recordPeer(
      device: device,
      tokenKey: tokenKey,
      at: at,
      approverKey: approverKey,
      approverLinkKey: approverLinkKey,
      hostLinkKey: hostLinkKey,
      hostAddress: hostAddress,
    );
    await writeTrust();
    if (record != null) {
      TomSecretsDeviceRecords(primary.file).put(
        TomSecretsDeviceRecord(
          device: device,
          platform: record.platform,
          paired: at,
          pairedBy: trust.device,
          keyIds: record.keyIds,
          approverKeyId: approverKey?.keyId,
          approverKeySince: approverKey == null ? null : at,
          linkKeySince: hostLinkKey == null && approverLinkKey == null
              ? null
              : at,
        ),
      );
      await savePrimary();
    }
    await _approvals?.reload();
    _approverLinks?.refresh();
    log.info('paired', {
      'device': device,
      'approver': approverKey != null,
      'host': hostLinkKey != null,
    });
    _remindKeys();
  }

  /// Revokes the paired [device] (`pair.revoke`): what this device recorded
  /// of it goes (it approves here no longer, this device approves for it no
  /// longer), and its device record in the primary is marked revoked.
  /// Whether anything was recorded of it.
  Future<bool> revokePairing(String device) async {
    final trust = _trust;
    final primary = _vaults.primary;
    if (trust == null || primary == null) throw StateError('locked');
    final before = trust.approvers.length + trust.hosts.length;
    trust.approvers.removeWhere((a) => a.device == device);
    trust.hosts.removeWhere((h) => h.host == device);
    final trusted = trust.approvers.length + trust.hosts.length != before;
    if (trusted) await writeTrust();
    final recorded = TomSecretsDeviceRecords(primary.file).revoke(device, now);
    if (recorded) await savePrimary();
    await _approvals?.reload();
    _approverLinks?.refresh();
    log.info('pairing_revoked', {'device': device});
    return trusted || recorded;
  }

  /// The device records of the primary (`pair.list`).
  List<TomSecretsDeviceRecord> get pairedDevices {
    final primary = _vaults.primary;
    return primary == null
        ? const []
        : TomSecretsDeviceRecords(primary.file).list();
  }

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

  /// The device settings of `settings.get` (protocol.md 6.3): the settings,
  /// the command-line approval switch and the stores the primary names.
  Map<String, Object?> settingsReport() => {
    'device': settings.toJson(),
    'cliApprovals': _trust?.cliApprovals ?? false,
    'stores': [
      ?_vaults.primaryName,
      for (final k in _vaults.listed) k.name,
      for (final k in _vaults.unserved) k.name,
    ],
  };

  /// Writes [value] as the device settings (`settings.set`) and applies what
  /// can change while unlocked: the lock policy, the refresh interval and
  /// timer, the timeouts (read when used), the offline cache and the
  /// reminder period. Answers the settings that apply at the next unlock
  /// (the stores served, the default environment, the approval link).
  Future<List<String>> writeSettings(TomSecretsDeviceSettings value) async {
    final old = settings;
    await _device!.write(value);
    _lockTimer.update(value.serviceLock);
    _vaults.refreshInterval = Duration(
      minutes: value.refreshMinutes > 0 ? value.refreshMinutes : 5,
    );
    if (value.refreshMinutes > 0 && _refreshTimer == null) {
      _refreshTimer = Timer.periodic(
        config.refreshTick,
        (_) => unawaited(_tick()),
      );
    } else if (value.refreshMinutes <= 0) {
      _refreshTimer?.cancel();
      _refreshTimer = null;
    }
    bool sameList(List<String>? a, List<String>? b) =>
        a == null || b == null ? a == b : a.join('\u0000') == b.join('\u0000');
    return [
      if (!sameList(old.servedStores, value.servedStores)) 'servedStores',
      if (old.defaultEnvironment != value.defaultEnvironment)
        'defaultEnvironment',
      if (old.approvalLink != value.approvalLink) 'approvalLink',
    ];
  }

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
  ///
  /// A re-keyed file (part-key-rotation) is taken as [TomSecretsVaultSet.save]
  /// says: a further vault's with the keys the primary lists for it now, the
  /// primary's with [newKeys]; the primary's new key file and repository
  /// key then replace the old ones in the device keychain, where the unlock
  /// takes them.
  Future<TomSecretsSaveResult> save(
    String store,
    Uint8List stored, {
    String? baseRevision,
    TomSecretsHeldKeys? newKeys,
    Uint8List? recipients,
  }) async {
    final primaryLocator = _vaults.primary?.locator;
    final result = await _serial(
      () => _tellingStates(
        () => _vaults.save(
          store,
          stored,
          baseRevision: baseRevision,
          newKeys: newKeys,
          recipients: recipients,
        ),
      ),
    );
    log.info('save', {
      'store': store,
      'merged': result.merged,
      'conflicts': result.conflicts,
      if (result.rekeyed) 'rekeyed': true,
    });
    if (result.rekeyed && newKeys != null && primaryLocator != null) {
      await _keepPrimaryKeys(primaryLocator, newKeys);
    }
    _emit({'op': 'store_changed', 'store': store, 'revision': result.revision});
    // The primary holds the grants and the approval records.
    if (store == _vaults.primaryName) {
      await _approvals?.reload();
      await _takeNextKeys();
    }
    return result;
  }
}

/// What makes [device] unacceptable as device settings (`settings.set`), or
/// null: the types and ranges a setting must have. Members it does not know
/// are ignored, as every reader does (protocol.md 8).
String? tomSecretsSettingsProblem(Map<String, Object?> device) {
  String? range(String key, int min, int max) {
    final v = device[key];
    if (v == null) return null;
    if (v is! int || v < min || v > max) return '$key is $min..$max';
    return null;
  }

  String? lock(String key) {
    final v = device[key];
    if (v == null) return null;
    if (v is! Map) return '$key is an object';
    final mode = v['mode'];
    if (mode != null && !TomSecretsLockMode.values.any((m) => m.name == mode)) {
      return '$key.mode is never or idle';
    }
    for (final k in ['idleSeconds', 'maxUnlockedSeconds']) {
      final s = v[k];
      if (s != null && (s is! int || s < 60 || s > 7 * 24 * 3600)) {
        return '$key.$k is 60..604800';
      }
    }
    return null;
  }

  final served = device['servedStores'];
  if (served != null && (served is! List || served.any((s) => s is! String))) {
    return 'servedStores is a list of store names';
  }
  for (final key in ['defaultEnvironment', 'approvalLink']) {
    final v = device[key];
    if (v != null && (v is! String || v.isEmpty)) return '$key is a string';
  }
  final link = device['approvalLink'];
  if (link is String) {
    // Port 0: the system picks one (a machine's own tests).
    final problem = tomSecretsApprovalLinkProblem(link, anyPort: true);
    if (problem != null) return problem;
  }
  if (device['offlineCache'] case final v? when v is! bool) {
    return 'offlineCache is true or false';
  }
  return lock('serviceLock') ??
      lock('appLock') ??
      range('refreshMinutes', 0, 24 * 60) ??
      range('keyExpiryWarningDays', 1, 365) ??
      range('otherKeyWarningDays', 1, 365) ??
      range('keyPairAgeMonths', 1, 120) ??
      range('primaryKeyAgeMonths', 1, 120) ??
      range('vaultKeyAgeMonths', 1, 120) ??
      range('memberKeyAgeMonths', 1, 120) ??
      range('approvalTimeoutSeconds', 5, 3600) ??
      range('codeTimeoutSeconds', 60, 3600);
}

/// The keys a request's `password` and `keyFile` (base64) carry, held masked;
/// null when they cannot be read.
TomSecretsHeldKeys? _keysOf(
  Map<String, Object?> m, {
  bool keyFileOnly = false,
}) {
  final password = m['password'];
  final keyFile = m['keyFile'];
  // A shared vault (part-sharing) is opened by its key file alone.
  final passwordOk =
      password is String ||
      (keyFileOnly && password == null && keyFile is String);
  if (!passwordOk || (keyFile != null && keyFile is! String)) {
    return null;
  }
  try {
    return TomSecretsHeldKeys.of(
      password: password as String?,
      keyFile: keyFile == null ? null : base64.decode(keyFile as String),
    );
  } on FormatException {
    return null;
  }
}

/// The primary's new keys a re-keyed `save` carries (`keys`, protocol.md
/// 6.4): `password`, `keyFile` (base64) and `outerKey` (a repository key,
/// base64); null when they cannot be read.
///
/// With [allowComposite] (the primary's own keys of `save` and `vault.move`)
/// `compositeKey` (32 bytes, base64) may take the place of `password` and
/// `keyFile`: a service unlocked by an OS unlock holds no password, and the
/// app hands back what it was given (protocol.md 6.4); `keyFile` may still
/// come with it, for the keychain.
TomSecretsHeldKeys? _newKeysOf(
  Map<String, Object?> m, {
  bool allowComposite = false,
  bool keyFileOnly = false,
}) {
  final composite = m['compositeKey'];
  TomSecretsHeldKeys? keys;
  if (allowComposite && composite != null) {
    final keyFile = m['keyFile'];
    if (composite is! String || (keyFile != null && keyFile is! String)) {
      return null;
    }
    try {
      final bytes = base64.decode(composite);
      if (bytes.length != 32) return null;
      keys = TomSecretsHeldKeys(
        compositeKey: TomProtectedValue.fromBytes(bytes),
        keyFile: keyFile == null
            ? null
            : TomProtectedValue.fromBytes(base64.decode(keyFile as String)),
      );
    } on FormatException {
      return null;
    }
  } else {
    keys = _keysOf(m, keyFileOnly: keyFileOnly);
  }
  final outerKey = m['outerKey'];
  if (keys == null) return null;
  if (outerKey == null) return keys;
  if (outerKey is! String) {
    keys.dispose();
    return null;
  }
  // [C] During a guided rotation's migration period the old repository key
  // the file keeps a slot for (part-key-rotation).
  final previous = m['previousOuterKey'];
  if (previous != null && previous is! String) {
    keys.dispose();
    return null;
  }
  try {
    TomSecretsRepositoryKey.fromBase64(outerKey);
    if (previous is String) TomSecretsRepositoryKey.fromBase64(previous);
  } on Object {
    keys.dispose();
    return null;
  }
  return keys.withOuterKey(
    TomProtectedValue.of(
      tomSecretsJoinOuterKeys([outerKey, previous as String?])!,
    ),
  );
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
      onClosed: () {
        service._clients.remove(this);
        final key = _admitted;
        if (key != null) service._rateLimits.release(key);
      },
    );
    service._clients.add(this);
  }

  /// The identity key this connection counts under, once admitted.
  String? _admitted;

  static String _keyOf(TomSecretsIdentity i) =>
      '${i.kind}|${i.exe}|${i.script}';

  final TomSecretsService service;
  late final TomSecretsConnection connection;
  TomSecretsIdentity? _identity;
  String? _clientTokenHash;
  bool _greeted = false;

  Future<bool> _measure(Socket socket) async {
    final measurement = await service.config.peerMeasurer.measure(socket);
    switch (measurement) {
      case TomSecretsPeerMeasured(:final identity):
        final key = _keyOf(identity);
        if (!service._rateLimits.admit(key)) {
          service.log.info('client_refused', {'reason': 'connections'});
          connection.sendError(
            null,
            'rate_limited',
            'too many connections are open',
            {'reason': 'connections', 'retryAfterMs': 1000},
          );
          Timer(
            const Duration(seconds: 5),
            () => unawaited(connection.close()),
          );
          return false;
        }
        _admitted = key;
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

  /// The features both sides named (protocol.md 8): the client's
  /// `hello.features` that this service offers.
  Set<String> _features = const {};

  String get _exeName {
    final exe = _identity?.exe ?? '';
    final name = exe.split(RegExp(r'[/\\]')).last;
    return name.toLowerCase().endsWith('.exe')
        ? name.substring(0, name.length - 4)
        : name;
  }

  /// Whether the client is the browser host (protocol.md 5.5).
  bool get _isBrowserHost {
    final allowed = service.config.browserHostExecutables;
    return allowed == null
        ? _exeName == tomSecretsBrowserHostName
        : allowed.contains(_identity?.exe);
  }

  /// Whether the client is a developer-tool helper (protocol.md 5.5).
  bool get _isHelper {
    final allowed = service.config.helperExecutables;
    return allowed == null
        ? tomSecretsHelperNames.contains(_exeName)
        : allowed.contains(_identity?.exe);
  }

  void _message(Map<String, Object?> m) {
    final op = m['op'] as String;
    if (!_greeted) {
      _hello(op, m);
      return;
    }
    final id = m['id'];
    if (const {'get', 'getMany', 'getFile', 'match', 'propose'}.contains(op)) {
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
      final wait = service._rateLimits.take(_admitted!);
      if (wait != null) {
        _open.remove(id);
        connection.sendError(id, 'rate_limited', 'too many requests', {
          'reason': 'requests',
          'retryAfterMs': wait.inMilliseconds < 1 ? 1 : wait.inMilliseconds,
        });
        return;
      }
      final Future<void> work = switch (op) {
        'match' => _match(id, m),
        'propose' => _propose(id, m),
        _ => _request(id, op, m),
      };
      unawaited(
        work
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
    final features = m['features'];
    _features = {
      if (features is List)
        for (final f in features)
          if (f is String && tomSecretsServiceFeatures.contains(f)) f,
    };
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
      'features': tomSecretsServiceFeatures,
      'host': service.config.host,
      'platform': Platform.operatingSystem,
    });
  }

  /// Waits for an unlock as `get` does (protocol.md 5.6 step 3): true when
  /// the service is unlocked, else the client was answered `locked`.
  Future<bool> _unlocked(int id, Map<String, Object?> m) async {
    if (!service.isLocked) return true;
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
      if (await service.waitUnlocked(timeout)) return true;
    }
    connection.sendError(id, 'locked', 'the service is locked');
    return false;
  }

  Future<void> _request(int id, String op, Map<String, Object?> m) async {
    final List<Map<String, Object?>> items;
    if (op == 'getFile') {
      final missing = [
        for (final f in const ['binary', 'getFile'])
          if (!_features.contains(f)) f,
      ];
      if (missing.isNotEmpty) {
        connection.sendError(
          id,
          'unsupported',
          'getFile needs the features binary and getFile in hello',
          {'op': op, 'features': missing},
        );
        return;
      }
    }
    if (op == 'get' || op == 'getFile') {
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
    // An identity slowed down by repeated refusals waits (protocol.md 11).
    final delay = service._rateLimits.delayFor(_admitted!);
    if (delay > Duration.zero) await Future<void>.delayed(delay);
    if (!await _unlocked(id, m)) return;
    // The values stay masked until the frame is written from their bytes,
    // and are zeroed right after.
    final held = <TomSecretsFieldValue>[];
    try {
      final resolved = [for (final item in items) _resolve(item, held)];
      final requests = [
        for (final r in resolved)
          if (r case (final TomSecretsAccessRequest request, null)) request,
      ];
      // A login picked `once` at this connection's pick prompt is read once
      // without asking again (protocol.md 5.5).
      final picked = <int, TomSecretsAccess>{};
      for (var i = 0; i < requests.length; i++) {
        final entry = requests[i].resolution.entry;
        final key = '${entry.store}/${entry.uuid}';
        if (_pickedOnce.containsKey(key)) {
          final approver = _pickedOnce.remove(key);
          picked[i] = TomSecretsAccessAllowed(approver: approver);
          _auditPicked(requests[i], approver);
        }
      }
      // A login a browser prompt allowed `once`: every field of it this
      // request reads (a fill reads user name, password and code at once),
      // then it is spent.
      if (_isBrowserHost) {
        final once = _browserOnceEntries();
        final spent = <String>{};
        for (var i = 0; i < requests.length; i++) {
          final entry = requests[i].resolution.entry;
          final key = '${entry.store}/${entry.uuid}';
          if (!picked.containsKey(i) && once.contains(key)) {
            picked[i] = const TomSecretsAccessAllowed();
            _auditPicked(requests[i], null);
            spent.add(key);
          }
        }
        service._browserOnce[_browserSubject()]?.removeWhere(
          (key, _) => spent.contains(key),
        );
      }
      final batch = [
        for (var i = 0; i < requests.length; i++)
          if (!picked.containsKey(i)) requests[i],
      ];
      final checked = batch.isEmpty
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
      var nextChecked = 0;
      final decisions = [
        for (var i = 0; i < requests.length; i++)
          picked[i] ?? checked[nextChecked++],
      ];
      var next = 0;
      final results = [
        for (final (request, error) in resolved)
          error ?? _answer(request!, decisions[next++]),
      ];
      service._rateLimits.refused(
        _admitted!,
        [
          for (final r in results)
            if (r['op'] == 'error' &&
                tomSecretsRefusalKinds.contains(r['kind']))
              r,
        ].length,
      );
      if (op == 'getFile') {
        final result = results.single;
        if (result['op'] == 'value') {
          _sendFile(id, resolved.single.$1!);
        } else {
          connection.send({...result, 'id': id});
        }
      } else if (op == 'get') {
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

  /// Streams the value of [request] (protocol.md 5.5 `getFile`): `file
  /// {id, name, size}`, the binary chunks, `end {id, sha256}`. The name is
  /// the field's (an attachment's without `attachment:`). Each chunk is
  /// zeroed once its frame is built.
  void _sendFile(int id, TomSecretsAccessRequest request) {
    final resolution = request.resolution;
    final field = resolution.field;
    final name = field.startsWith(TomSecretsEntryFields.attachmentPrefix)
        ? field.substring(TomSecretsEntryFields.attachmentPrefix.length)
        : field;
    resolution.value.withBytes((bytes) {
      connection.send({
        'op': 'file',
        'id': id,
        'name': name,
        'size': bytes.length,
      });
      for (var at = 0; at < bytes.length; at += tomSecretsFileChunkSize) {
        final end = at + tomSecretsFileChunkSize < bytes.length
            ? at + tomSecretsFileChunkSize
            : bytes.length;
        connection.sendChunk(id, Uint8List.sublistView(bytes, at, end));
      }
      connection.send({
        'op': 'end',
        'id': id,
        'sha256': crypto.sha256.convert(bytes).toString(),
      });
    });
  }

  void _auditPicked(TomSecretsAccessRequest request, String? approver) =>
      service.audit?.add(
        TomSecretsAuditRecord(
          time: DateTime.now().toUtc(),
          host: service.host,
          identity: _identity!.toJson(),
          refs: [request.reference],
          outcome: 'allowed',
          approver: approver,
          entries: [request.resolution.entry.uuid],
        ),
      );

  /// The coverage of this client's grants (protocol.md 5.5).
  Future<TomSecretsCoverage> _coverage(TomSecretsResolver resolver) async {
    final policy = service.config.policy ?? service.approvals;
    if (policy is! TomSecretsLookupPolicy) return TomSecretsCoverage.none;
    return (policy as TomSecretsLookupPolicy).coverage(
      _identity!,
      clientTokenHash: _clientTokenHash,
      entryOf: (reference) {
        try {
          final resolution = resolver.resolve(reference);
          resolution.value.dispose();
          return (store: resolution.entry.store, uuid: resolution.entry.uuid);
        } on Object {
          return null;
        }
      },
    );
  }

  void _auditLookup(String what, String outcome, [List<String>? uuids]) =>
      service.audit?.add(
        TomSecretsAuditRecord(
          time: DateTime.now().toUtc(),
          host: service.host,
          identity: _identity!.toJson(),
          refs: [what],
          outcome: outcome,
          entries: uuids ?? const [],
        ),
      );

  /// `match` (protocol.md 5.5): the login entries of a page that this
  /// client's grants cover (with `userName`, only that user's), never a
  /// value; only for the browser host and the helpers; audited. The browser
  /// host gets no entry of a system vault; when no grant covers a login of
  /// the page it asks the approvers (the browser prompt, DP-44). A helper's
  /// `pick` answers one login, asking the user to pick when the grants do
  /// not decide.
  Future<void> _match(int id, Map<String, Object?> m) async {
    final url = m['url'];
    final frameUrl = m['frameUrl'];
    final userName = m['userName'];
    final pick = m['pick'] ?? false;
    if (url is! String ||
        url.isEmpty ||
        url.length > 4096 ||
        (frameUrl != null && (frameUrl is! String || frameUrl.length > 4096)) ||
        (userName != null && userName is! String) ||
        pick is! bool) {
      connection.sendError(id, 'malformed', 'match carries a url', {
        'reason': 'url',
      });
      return;
    }
    final site = TomSecretsSiteUrl.parse(url)?.host ?? '';
    final browser = _isBrowserHost;
    // A pick prompt is for the developer-tool helpers (git asks one
    // credential; the browser host shows its own list).
    if ((!browser && !_isHelper) || (pick && !_isHelper)) {
      service._rateLimits.refused(_admitted!, 1);
      _auditLookup('match $site', 'denied:not_allowed_op');
      connection.sendError(id, 'denied', 'match is not for this client', {
        'reason': 'not_allowed_op',
      });
      return;
    }
    final delay = service._rateLimits.delayFor(_admitted!);
    if (delay > Duration.zero) await Future<void>.delayed(delay);
    if (!await _unlocked(id, m)) return;
    final resolver = service.vaults.resolver;
    if (resolver == null) {
      connection.sendError(id, 'locked', 'the service is locked');
      return;
    }
    final coverage = await _coverage(resolver);
    final eligible = [
      for (final store in resolver.stores)
        if (!browser || store.metadata.kind != TomSecretsVaultKind.system)
          ...store.entries,
    ];
    List<TomSecretsLoginMatch> matching(Iterable<TomSecretsIndexedEntry> e) => [
      for (final f in tomSecretsMatchLogins(
        e,
        url,
        frameUrl: frameUrl as String?,
      ))
        // A helper's pick looks up by the host rule (part-os-integration:
        // git asks for one host), not the entries' own (by default the
        // site).
        if ((userName == null || f.userName == userName) &&
            (!pick || f.level == TomSecretsUrlMatchLevel.exactHost))
          f,
    ];
    final once = browser ? _browserOnceEntries() : const <String>{};
    bool listed(TomSecretsIndexedEntry e) =>
        coverage.covers(e.store, e.uuid) ||
        once.contains('${e.store}/${e.uuid}');
    var found = matching(eligible.where(listed));
    if (pick) {
      found = await _picked(id, url, found, coverage, eligible, matching);
    } else if (browser && found.isEmpty) {
      found = await _browserApproved(id, url, matching(eligible));
    }
    connection.send({
      'op': 'matches',
      'id': id,
      'candidates': [
        for (final f in found)
          {
            'entryId': '${f.entry.store}/~${f.entry.uuid}',
            'title': f.title,
            'userName': f.userName,
            'matchedUrl': f.matchedUrl,
            'hasTotp': f.hasTotp,
          },
      ],
    });
    _auditLookup('match $site', 'matched', [
      for (final f in found) f.entry.uuid,
    ]);
    service.log.info('match', {'candidates': found.length});
  }

  /// The browser host's `once` entries (`<store>/<uuid>`) still held.
  Set<String> _browserOnceEntries() {
    final held = service._browserOnce[_browserSubject()];
    if (held == null) return const {};
    final now = DateTime.now();
    held.removeWhere((_, until) => !until.isAfter(now));
    return held.keys.toSet();
  }

  /// The browser host as its grants name it: started by its browser.
  String _browserSubject() => tomSecretsGrantSubject(
    _identity!,
    const TomSecretsApprovalAnswer(
      decision: 'always',
      secret: 'all',
      approver: '',
    ),
    browser: true,
  );

  /// The browser host's `match` that no grant covers (protocol.md 5.5,
  /// DP-44): when the page has logins in the personal and shared vaults
  /// ([options]), the approvers are asked once for all of them
  /// (`approval_needed` with `browser` and `url`). `always` writes the
  /// grants for the browser host as started by its browser (`exe-from`) with
  /// the scope picked, `never` its never grants; `once` lets it list those
  /// logins and read each once for [TomSecretsService.browserOnceFor]. The
  /// logins allowed are listed. No approver connected, refused or
  /// unanswered: none.
  Future<List<TomSecretsLoginMatch>> _browserApproved(
    int id,
    String url,
    List<TomSecretsLoginMatch> options,
  ) async {
    if (options.isEmpty) return const [];
    final policy = service.config.policy ?? service.approvals;
    final resolver = service.vaults.resolver;
    if (policy is! TomSecretsApprovals || resolver == null) return const [];
    final items = <TomSecretsAccessRequest>[];
    for (final f in options) {
      final resolution = resolver.resolve(
        '${f.entry.store}/~${f.entry.uuid}',
        field: 'Title',
      );
      resolution.value.dispose();
      items.add(
        TomSecretsAccessRequest(
          reference: '${f.entry.store}/~${f.entry.uuid}',
          resolution: resolution,
          client: _client,
          identity: _identity!,
        ),
      );
    }
    final answers = await policy.askBrowser(
      TomSecretsAccessBatch(
        identity: _identity!,
        client: _client,
        items: items,
        onProgress: (p) => connection.send({'op': 'progress', 'id': id, ...p}),
        clientTokenHash: _clientTokenHash,
      ),
      url,
    );
    if (answers == null) return const [];
    final allowed = [
      for (var i = 0; i < options.length; i++)
        if (answers[i] is TomSecretsAccessAllowed) options[i],
    ];
    // An `always` wrote grants; a `once` did not: remember it.
    final coverage = await _coverage(resolver);
    final held = service._browserOnce.putIfAbsent(_browserSubject(), () => {});
    final until = DateTime.now().add(TomSecretsService.browserOnceFor);
    for (final f in allowed) {
      if (!coverage.covers(f.entry.store, f.entry.uuid)) {
        held['${f.entry.store}/${f.entry.uuid}'] = until;
      }
    }
    return allowed;
  }

  /// The entries this connection may read once without asking: a login the
  /// user picked `once` at a helper's pick prompt (protocol.md 5.5), by
  /// `<store>/<uuid>`; the next `get` of it takes it.
  final Map<String, String?> _pickedOnce = {};

  /// `match` with `pick` (protocol.md 5.5, part-os-integration): one login
  /// for a helper. One covered login answers; of several, the one an allow
  /// grant names by its reference (a remembered pick); else, when the vaults
  /// hold logins of the site (covered or not), the approvers pick one of
  /// them at a prompt (the covered ones when there are several): `always`
  /// writes a grant for it, `once` lets this connection read it once.
  /// Refused, unanswered or with no approver: none.
  Future<List<TomSecretsLoginMatch>> _picked(
    int id,
    String url,
    List<TomSecretsLoginMatch> covered,
    TomSecretsCoverage coverage,
    List<TomSecretsIndexedEntry> eligible,
    List<TomSecretsLoginMatch> Function(Iterable<TomSecretsIndexedEntry>)
    matching,
  ) async {
    if (covered.length == 1) return covered;
    if (covered.length > 1) {
      final named = [
        for (final f in covered)
          if (coverage.named(f.entry.store, f.entry.uuid)) f,
      ];
      if (named.length == 1) return named;
    }
    final options = covered.length > 1 ? covered : matching(eligible);
    if (options.isEmpty) return const [];
    final policy = service.config.policy ?? service.approvals;
    final resolver = service.vaults.resolver;
    if (policy is! TomSecretsApprovals || resolver == null) return const [];
    final items = <TomSecretsAccessRequest>[];
    for (final f in options) {
      final ref = '${f.entry.store}/~${f.entry.uuid}';
      final resolution = resolver.resolve(ref, field: 'Title');
      resolution.value.dispose();
      items.add(
        TomSecretsAccessRequest(
          reference: ref,
          resolution: resolution,
          client: _client,
          identity: _identity!,
        ),
      );
    }
    final answer = await policy.askPick(
      TomSecretsAccessBatch(
        identity: _identity!,
        client: _client,
        items: items,
        onProgress: (p) => connection.send({'op': 'progress', 'id': id, ...p}),
        clientTokenHash: _clientTokenHash,
      ),
      [
        for (final f in options)
          {
            'entryId': '${f.entry.store}/~${f.entry.uuid}',
            'title': f.title,
            'userName': f.userName,
            'matchedUrl': f.matchedUrl,
          },
      ],
      url,
    );
    if (answer == null) return const [];
    final picked = options[answer.index];
    _pickedOnce['${picked.entry.store}/${picked.entry.uuid}'] = answer.approver;
    return [picked];
  }

  /// `propose` (protocol.md 5.5): a login the browser host or a helper
  /// (git's `store`) proposes, passed to the attached manager app as the
  /// event `proposal`; nothing is kept. Only for a client holding an `allow`
  /// grant; a helper's credential the vaults hold already is ignored
  /// (`accepted` with `known`, DP-52).
  Future<void> _propose(int id, Map<String, Object?> m) async {
    final url = m['url'];
    final title = m['title'];
    final userName = m['userName'];
    final password = m['password'];
    if (url is! String ||
        url.isEmpty ||
        url.length > 4096 ||
        userName is! String ||
        password is! String ||
        (title != null && title is! String)) {
      connection.sendError(
        id,
        'malformed',
        'propose carries url, userName and password',
        {'reason': 'propose'},
      );
      return;
    }
    final site = TomSecretsSiteUrl.parse(url)?.host ?? '';
    Future<void> refuse() async {
      service._rateLimits.refused(_admitted!, 1);
      _auditLookup('propose $site', 'denied:not_allowed_op');
      connection.sendError(id, 'denied', 'propose is not for this client', {
        'reason': 'not_allowed_op',
      });
    }

    final helper = !_isBrowserHost && _isHelper;
    if (!_isBrowserHost && !helper) return refuse();
    if (!await _unlocked(id, m)) return;
    final resolver = service.vaults.resolver;
    if (resolver == null) {
      connection.sendError(id, 'locked', 'the service is locked');
      return;
    }
    if (!(await _coverage(resolver)).hasAllowGrant) return refuse();
    // A helper's `store` (git saw the credential work, DP-52): a credential
    // the vaults hold already is ignored; only a new one is proposed.
    if (helper && _known(resolver, url, userName, password)) {
      _auditLookup('propose $site', 'known');
      connection.send({'op': 'accepted', 'id': id, 'known': true});
      return;
    }
    final sent = service._emitToApps({
      'op': 'proposal',
      'url': url,
      'title': ?title,
      'userName': userName,
      'password': password,
    });
    if (!sent) {
      _auditLookup('propose $site', 'unavailable');
      connection.sendError(id, 'unavailable', 'no app is attached', {
        'reason': 'no_app',
      });
      return;
    }
    _auditLookup('propose $site', 'accepted');
    service.log.info('proposal', {});
    connection.send({'op': 'accepted', 'id': id});
  }

  /// Whether a login of the vaults matching [url] holds [userName] and
  /// [password].
  static bool _known(
    TomSecretsResolver resolver,
    String url,
    String userName,
    String password,
  ) {
    for (final f in tomSecretsMatchLogins([
      for (final store in resolver.stores) ...store.entries,
    ], url)) {
      if (f.userName != userName) continue;
      final value = f.entry.entry.getString(KdbxKeyCommon.PASSWORD);
      if (value?.getText() == password) return true;
    }
    return false;
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
    // A copy under the old key (part-key-rotation, keyChanged) is served
    // read-only during the migration period.
    if (status?.state == TomSecretsStoreState.needsUnlock &&
        !status!.keyChanged) {
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
      final dimensions = dims == null
          ? const <String, String>{}
          : (dims as Map).cast<String, String>();
      var want = field as String?;
      if (item['op'] == 'getFile' &&
          want == null &&
          !TomSecretReference.parse(ref).fieldGiven) {
        // [C] getFile of a typed key without a field (part-protocol): a
        // certificate's private key (or PKCS#12 bundle), a PGP key's secret
        // key (else its public key). The entry is found by its title first,
        // which every entry has.
        final found = resolver.resolve(
          ref,
          dimensions: dimensions,
          field: KdbxKeyCommon.TITLE.key,
        );
        found.value.dispose();
        want = tomSecretsTypedFileField(found.entry.entry);
      }
      resolution = resolver.resolve(ref, dimensions: dimensions, field: want);
    } on TomSecretsResolveException catch (e) {
      return fail(_error(e.kind.wireName, e.message, e.details));
    }
    held.add(resolution.value);
    if (_isBrowserHost && _isSystemStore(resolver, resolution.entry.store)) {
      // DP-44: a system vault is never served to the browser, whatever a
      // grant says.
      _auditLookup(_canonicalRef(ref), 'denied:system_vault', [
        resolution.entry.uuid,
      ]);
      return fail(
        _error('denied', 'a system vault is not served to the browser', {
          'reason': 'system_vault',
        }),
      );
    }
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

  bool _isSystemStore(TomSecretsResolver resolver, String store) =>
      resolver.stores.any(
        (s) => s.name == store && s.metadata.kind == TomSecretsVaultKind.system,
      );

  static String _canonicalRef(String ref) {
    try {
      return TomSecretReference.parse(ref).canonical;
    } on Object {
      return ref;
    }
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
      onClosed: () {
        service._admins.remove(this);
        _bundleKey?.fillRange(0, _bundleKey!.length, 0);
      },
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
  // The OS unlock's bundle key of this connection (protocol.md 6.4); null
  // before `auth` and on a connection that claimed the service.
  Uint8List? _bundleKey;
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
    _bundleKey = tomSecretsBundleKey(
      service._adminKey,
      _serviceNonce,
      adminNonce,
    );
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
            service._primaryLocator,
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
        final sshHost = m['sshHost'] ?? false;
        final withParent = m['withParent'] ?? false;
        if (approvalId is! String ||
            decision is! String ||
            secret is! String ||
            (clientToken != null && clientToken is! String) ||
            sshHost is! bool ||
            withParent is! bool) {
          return malformed('approve');
        }
        final answer = TomSecretsApprovalAnswer(
          decision: decision,
          secret: secret,
          folder: m['folder'] as String?,
          pin: m['pin'],
          approver: service.trust.device,
          // The app made the token (DP-20); this device signs its grant.
          clientToken: clientToken as String?,
          sshHost: sshHost,
          withParent: withParent,
          pick: m['pick'] is String ? m['pick'] as String : null,
        );
        try {
          // A paired host's prompt goes back over its approval link.
          final links = service.approverLinks;
          final remote = links?.hostOf(approvalId);
          if (links != null && remote != null) {
            try {
              await links.approve(approvalId, answer);
            } on TomSecretsLinkDeliveryException catch (e) {
              connection.sendError(id, 'unavailable', e.message, {
                'host': remote,
                'reason': ?e.kind,
              });
              return;
            }
          } else {
            await approvals.approve(approvalId, answer);
          }
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
        final ssh = secret is String
            ? TomSecretsSshGrantSecret.parse(secret)
            : null;
        bool target(String t) =>
            t == 'all' || t.startsWith('store ') || _parses(t);
        if (spec['host'] is! String ||
            subject is! String ||
            (!RegExp(
                  r'^(exe|script|interpreter|folder|tsm-command) \S',
                ).hasMatch(subject) &&
                !RegExp(r'^exe-from \S.* => \S').hasMatch(subject)) ||
            secret is! String ||
            (secret.startsWith(TomSecretsSshGrantSecret.prefix)
                ? ssh == null || !ssh.valid || !target(ssh.target)
                : !target(secret)) ||
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
          'secret': ssh != null
              ? TomSecretsSshGrantSecret(
                  _canonicalTarget(ssh.target),
                  hosts: ssh.hosts,
                  forward: ssh.forward,
                ).text
              : _canonicalTarget(secret),
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

  /// A grant's secret target as written: `all` and `store <name>` as they
  /// are, a reference canonical.
  static String _canonicalTarget(String t) =>
      t == 'all' || t.startsWith('store ')
      ? t
      : TomSecretReference.parse(t).canonical;

  static bool _parses(String ref) {
    try {
      TomSecretReference.parse(ref);
      return true;
    } on Object {
      return false;
    }
  }

  /// **[C]** The inbox requests (protocol.md 6.4, part-sharing): the
  /// packages in a shared vault's `inbox/<member-id>/` folders listed, read,
  /// put and deleted; the app encrypts and decrypts them.
  Future<void> _inbox(int id, String op, Map<String, Object?> m) async {
    void malformed(String text) =>
        connection.sendError(id, 'malformed', text, {'reason': 'inbox'});
    final store = m['store'];
    if (store is! String) return malformed('$op names a store');
    try {
      switch (op) {
        case 'inbox.list':
          final files = await service.inbox(store);
          connection.send({
            'op': 'inbox',
            'id': id,
            'store': store,
            'files': [
              for (final f in files)
                {'member': f.member, 'name': f.name, 'revision': f.revision},
            ],
          });
        case 'inbox.read':
          final member = m['member'];
          final name = m['name'];
          if (member is! String || name is! String) {
            return malformed('inbox.read names a member and a name');
          }
          final file = await service.inboxFile(store, member, name);
          if (file == null) {
            connection.sendError(id, 'not_found', 'the package is gone', {
              'reason': 'inbox',
            });
            return;
          }
          connection.send({
            'op': 'inboxFile',
            'id': id,
            'store': store,
            'member': member,
            'name': name,
            'revision': file.revision,
            'bytes': base64.encode(file.bytes),
          });
        case 'inbox.put':
          final members = m['members'];
          final bytes = m['bytes'];
          if (members is! List ||
              members.isEmpty ||
              members.any((x) => x is! String) ||
              bytes is! String) {
            return malformed('inbox.put carries members and bytes');
          }
          final Uint8List package;
          try {
            package = base64.decode(bytes);
          } on FormatException {
            return malformed('bytes is not base64');
          }
          final name = await service.inboxPut(
            store,
            members.cast<String>(),
            package,
          );
          connection.send({'op': 'ok', 'id': id, 'name': name});
        case 'inbox.delete':
          final files = m['files'];
          if (files is! List ||
              files.any(
                (f) =>
                    f is! Map || f['member'] is! String || f['name'] is! String,
              )) {
            return malformed('inbox.delete carries files (member, name)');
          }
          await service.inboxDelete(store, [
            for (final f in files.cast<Map<Object?, Object?>>())
              (member: f['member']! as String, name: f['name']! as String),
          ]);
          connection.send({'op': 'ok', 'id': id});
      }
    } on TomSecretsSaveException catch (e) {
      connection.sendError(id, e.kind, e.message, {'reason': ?e.reason});
    } on Object catch (e) {
      service.log.error('inbox_failed', e, {'store': store, 'op': op});
      connection.sendError(id, 'internal', 'the inbox request failed', {
        'code': e.runtimeType.toString(),
      });
    }
  }

  /// The largest relay file (a pairing frame is at most 1 MiB).
  static const _relayMaxBytes = 1 << 20;

  static final RegExp _relayPathPattern = RegExp(
    r'^relay(/[A-Za-z0-9][A-Za-z0-9._-]*)+$',
  );

  /// **[C]** The relay requests (protocol.md 6.4, part-relay): the files of
  /// a `github:` store's `relay/` folder, which carry the app's pairing
  /// through GitHub — revision, list, read, create (once), delete.
  Future<void> _relay(int id, String op, Map<String, Object?> m) async {
    void malformed(String text) =>
        connection.sendError(id, 'malformed', text, {'reason': 'relay'});
    final store = m['store'];
    if (store is! String) return malformed('$op names a store');
    final key =
        op == 'relay.revision' ||
            op == 'relay.list' ||
            op == 'relay.deleteFolder'
        ? 'folder'
        : 'path';
    final path = m[key];
    if (path is! String ||
        !_relayPathPattern.hasMatch(path) ||
        path.split('/').any((p) => p == '..' || p == '.')) {
      return malformed('$op names a $key below relay/');
    }
    try {
      switch (op) {
        case 'relay.revision':
          final revision = await service.relay(
            store,
            (f) => f.revisionOf(path),
          );
          connection.send({
            'op': 'relayRevision',
            'id': id,
            'revision': revision,
          });
        case 'relay.list':
          final files = await service.relay(store, (f) => f.list(path));
          connection.send({'op': 'relayFiles', 'id': id, 'files': files});
        case 'relay.read':
          final bytes = await service.relay(store, (f) => f.read(path));
          connection.send({
            'op': 'relayFile',
            'id': id,
            'bytes': bytes == null ? null : base64.encode(bytes),
          });
        case 'relay.create':
          final text = m['bytes'];
          if (text is! String) return malformed('relay.create carries bytes');
          final Uint8List bytes;
          try {
            bytes = base64.decode(text);
          } on FormatException {
            return malformed('bytes is not base64');
          }
          if (bytes.length > _relayMaxBytes) {
            return malformed('a relay file is 1 MiB at most');
          }
          final message = m['message'];
          try {
            await service.relay(
              store,
              (f) => f.create(
                path,
                bytes,
                message: message is String && message.isNotEmpty
                    ? message
                    : 'tsm: relay file',
              ),
            );
          } on TomSecretsRelayFileExists {
            connection.sendError(id, 'denied', 'the file is there already', {
              'reason': 'exists',
            });
            return;
          }
          connection.send({'op': 'ok', 'id': id});
        case 'relay.deleteFolder':
          await service.relay(store, (f) => f.deleteFolder(path));
          connection.send({'op': 'ok', 'id': id});
        case 'relay.deleteFile':
          await service.relay(store, (f) => f.deleteFile(path));
          connection.send({'op': 'ok', 'id': id});
      }
    } on TomSecretsSaveException catch (e) {
      connection.sendError(id, e.kind, e.message, {'reason': ?e.reason});
    } on Object catch (e) {
      service.log.error('relay_failed', e, {'store': store, 'op': op});
      connection.sendError(id, 'internal', 'the relay request failed', {
        'code': e.runtimeType.toString(),
      });
    }
  }

  /// The pairing requests (protocol.md 6.3, part-sharing): the app runs the
  /// pairing itself; the service gives this device's public keys and keeps
  /// what the pairing gave.
  Future<void> _pairing(int id, String op, Map<String, Object?> m) async {
    Never malformed(String reason) => throw FormatException(reason);
    try {
      switch (op) {
        case 'pair.identity':
          final keys = await service.pairingIdentity();
          connection.send({
            'op': 'pairIdentity',
            'id': id,
            'device': service.trust.device,
            ...keys.toJson(),
          });
        case 'pair.record':
          final device = m['device'];
          final tokenKey = m['tokenKey'];
          if (device is! String || device.isEmpty || tokenKey is! String) {
            malformed('pair.record names a device and its tokenKey');
          }
          final token = base64.decode(tokenKey);
          if (token.length != 32) malformed('tokenKey is 32 bytes');
          final approver = m['approver'];
          final host = m['host'];
          final record = m['record'];
          if ((approver != null && approver is! Map) ||
              (host != null && host is! Map) ||
              (record != null && record is! Map) ||
              (approver == null && host == null)) {
            malformed('pair.record carries an approver, a host or both');
          }
          final a = (approver as Map?)?.cast<String, Object?>();
          final h = (host as Map?)?.cast<String, Object?>();
          final r = (record as Map?)?.cast<String, Object?>();
          await service.recordPairing(
            device: device,
            tokenKey: token,
            approverKey: a == null
                ? null
                : TomSecretsApproverPublicKey.fromJson(
                    (a['approverKey']! as Map).cast(),
                  ),
            approverLinkKey: a?['linkKey'] == null
                ? null
                : TomSecretsLinkPublicKey.fromJson(
                    (a!['linkKey']! as Map).cast(),
                  ),
            hostLinkKey: h == null
                ? null
                : TomSecretsLinkPublicKey.fromJson(
                    (h['linkKey']! as Map).cast(),
                  ),
            hostAddress: h?['address'] as String?,
            record: r == null
                ? null
                : (
                    platform: r['platform'] as String?,
                    keyIds: [
                      for (final k in (r['keyIds'] as List? ?? const [])) '$k',
                    ],
                  ),
          );
          connection.send({'op': 'ok', 'id': id});
        case 'pair.revoke':
          final device = m['device'];
          if (device is! String) malformed('pair.revoke names a device');
          if (!await service.revokePairing(device)) {
            connection.sendError(id, 'not_found', 'no paired device $device');
            return;
          }
          connection.send({'op': 'ok', 'id': id});
        case 'pair.list':
          connection.send({
            'op': 'pairedDevices',
            'id': id,
            'devices': [for (final d in service.pairedDevices) d.toJson()],
          });
      }
    } on ArgumentError catch (e) {
      connection.sendError(id, 'malformed', '${e.message}', {'reason': 'pair'});
    } on FormatException catch (e) {
      connection.sendError(id, 'malformed', e.message, {'reason': 'pair'});
    } on TypeError {
      connection.sendError(id, 'malformed', 'a key cannot be read', {
        'reason': 'pair',
      });
    }
  }

  /// `unlock {vault, bundle}` (protocol.md 6.4): the OS unlock's key bundle,
  /// sealed under this connection's bundle key. While the service is locked
  /// it unlocks the service, the bundle being the primary's (checked once
  /// the primary is open: another store's name locks again); unlocked, it
  /// opens the store [vault] names, as `unlockStore` does.
  Future<void> _unlockWithBundle(int id, Map<String, Object?> m) async {
    final vault = m['vault'];
    final sealed = m['bundle'];
    if (vault is! String || sealed is! Map) {
      connection.sendError(id, 'malformed', 'vault and bundle', {
        'reason': 'bundle',
      });
      return;
    }
    final key = _bundleKey;
    if (key == null) {
      connection.sendError(
        id,
        'unsupported',
        'a connection that claimed the service sends no bundle',
      );
      return;
    }
    final TomSecretsUnlockBundle bundle;
    try {
      final plain = await tomSecretsOpenBundle(
        bundleKey: key,
        vault: vault,
        serviceStart: service.startedAt,
        bundle: sealed.cast<String, Object?>(),
      );
      try {
        bundle = TomSecretsUnlockBundle.decode(plain);
      } finally {
        plain.fillRange(0, plain.length, 0);
      }
    } on TomSecretsBundleException {
      service._authFailures++;
      service.log.info('unlock_refused', {'reason': 'bad_bundle'});
      connection.sendError(id, 'denied', 'the key bundle does not open', {
        'reason': 'bad_bundle',
      });
      return;
    }
    final keys = TomSecretsHeldKeys.ofBundle(bundle);
    bundle.dispose();
    void refusedKey() {
      service.log.info('unlock_refused', {
        'reason': 'bad_password',
        'via': 'bundle',
      });
      connection.sendError(
        id,
        'denied',
        'the key bundle no longer opens the vault',
        {'reason': 'bad_password'},
      );
    }

    if (service.isLocked) {
      try {
        await service.unlock(keys);
      } on KdbxInvalidKeyException {
        // A re-keyed vault: not a failed authentication, the bundle opened.
        return refusedKey();
      } on Object catch (e) {
        service.log.error('unlock_failed', e);
        connection.sendError(id, 'internal', 'the unlock failed', {
          'code': e.runtimeType.toString(),
        });
        return;
      }
      if (service.vaults.primaryName != vault) {
        await service.lock(reason: 'bundle_vault');
        connection.sendError(id, 'not_found', 'no primary $vault');
        return;
      }
      service.log.info('unlock', {'via': 'bundle'});
      connection.send({'op': 'ok', 'id': id});
      return;
    }
    if (vault == service.vaults.primaryName) {
      keys.dispose();
      connection.send({'op': 'ok', 'id': id});
      return;
    }
    try {
      await service.vaults.unlockStore(vault, keys, machine: service.machine);
      service.log.info('unlock_store', {'store': vault, 'via': 'bundle'});
      connection.send({'op': 'ok', 'id': id});
    } on KdbxInvalidKeyException {
      keys.dispose();
      refusedKey();
    } on StateError {
      keys.dispose();
      connection.sendError(id, 'not_found', 'no store $vault');
    }
  }

  Future<void> _request(int id, String op, Map<String, Object?> m) async {
    switch (op) {
      case 'unlock' when m['bundle'] != null:
        await _unlockWithBundle(id, m);
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
          connection.send({
            'op': 'vaultKeySet',
            'id': id,
            'stores': keys,
            'unserved': [
              for (final v in service.vaults.unserved)
                {'store': v.name, 'location': v.locator},
            ],
          });
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
        final ({
          String location,
          String revision,
          Uint8List stored,
          bool served,
        })
        file;
        try {
          file = await service.vaults.vaultFile(store);
        } on StateError catch (e) {
          connection.sendError(id, 'not_found', 'no store ${e.message}', {
            'store': e.message,
          });
          return;
        } on KdbxInvalidKeyException {
          connection.sendError(
            id,
            'needs_unlock',
            'the listed keys do not open $store',
            {'store': store},
          );
          return;
        } on TomKeyRequiredException {
          connection.sendError(
            id,
            'needs_unlock',
            'the listed keys do not open $store',
            {'store': store},
          );
          return;
        } on Object catch (e) {
          final failure = tomSecretsFetchFailureOf(e);
          if (failure != null) {
            final kind = TomSecretsStoreState.offlineFor(failure).wireName;
            connection.sendError(id, kind, '$store cannot be read now', {
              'stores': [store],
            });
          } else {
            service.log.error('vault_file_failed', e, {'store': store});
            connection.sendError(id, 'unavailable', '$store cannot be read', {
              'store': store,
            });
          }
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
          if (!file.served) 'served': false,
          'bytes': bytes,
        });
        service.log.info('vault_file', {
          'store': store,
          'size': file.stored.length,
          if (!file.served) 'served': false,
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
        final wireKeys = m['keys'];
        final wireRecipients = m['recipients'];
        final Uint8List? recipients;
        try {
          recipients = wireRecipients is String
              ? base64.decode(wireRecipients)
              : null;
        } on FormatException {
          connection.sendError(id, 'malformed', 'recipients is not base64', {
            'reason': 'recipients',
          });
          return;
        }
        if (wireRecipients != null && wireRecipients is! String) {
          connection.sendError(id, 'malformed', 'recipients is base64', {
            'reason': 'recipients',
          });
          return;
        }
        final newKeys = wireKeys is Map
            ? _newKeysOf(
                wireKeys.cast<String, Object?>(),
                allowComposite: store == service.vaults.primaryName,
              )
            : null;
        if (wireKeys != null && newKeys == null) {
          connection.sendError(
            id,
            'malformed',
            'keys carries the primary\'s password, keyFile? and outerKey?',
            {'reason': 'keys'},
          );
          return;
        }
        try {
          await service.save(
            store,
            stored,
            baseRevision: base as String?,
            newKeys: newKeys,
            recipients: recipients,
          );
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
            // This host's prompts (tsm approvals); a paired host's prompts
            // go to the app's subscription only.
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
        final retention = m['retentionDays'];
        if (retention != null && (retention is! int || retention < 0)) {
          connection.sendError(
            id,
            'malformed',
            'retentionDays is a whole number of at least 0',
            {'reason': 'retentionDays'},
          );
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        await service._compact(
          id,
          repository,
          connection,
          retentionDays: retention as int?,
        );
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
          for (final event in service.waitingPrompts) {
            connection.send(event);
          }
        }
        // The reminders due now, to an app that attached after they were
        // first sent.
        for (final key in service.expiring) {
          service._reminded[key.key] = key.step;
          connection.send(key.toEvent());
        }
      case 'history.resolve':
        final store = m['store'];
        final take = m['take'];
        if (store is! String || (take != 'remote' && take != 'merge')) {
          connection.sendError(
            id,
            'malformed',
            'history.resolve names a store and take: remote or merge',
            {'reason': 'history'},
          );
          return;
        }
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        try {
          final result = await service.resolveRewritten(
            store,
            takeRemote: take == 'remote',
          );
          connection.send({
            'op': 'ok',
            'id': id,
            'revision': result.revision,
            'conflicts': result.conflicts,
          });
        } on TomSecretsSaveException catch (e) {
          connection.sendError(id, e.kind, e.message, {
            if (e.kind == 'offline' || e.kind == 'token_expired')
              'stores': [store],
            'reason': ?e.reason,
          });
        }
      case 'vault.move':
        final store = m['store'];
        final location = m['location'];
        final bytes = m['bytes'];
        final base = m['baseRevision'];
        final wireKeys = m['keys'];
        if (store is! String ||
            location is! String ||
            bytes is! String ||
            (base != null && base is! String) ||
            wireKeys is! Map) {
          connection.sendError(
            id,
            'malformed',
            'vault.move carries store, location, bytes and keys',
            {'reason': 'move'},
          );
          return;
        }
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        final newKeys = _newKeysOf(
          wireKeys.cast<String, Object?>(),
          allowComposite: store == service.vaults.primaryName,
        );
        final Uint8List stored;
        try {
          stored = base64.decode(bytes);
        } on FormatException {
          newKeys?.dispose();
          connection.sendError(id, 'malformed', 'bytes is not base64', {
            'reason': 'bytes',
          });
          return;
        }
        if (newKeys == null) {
          connection.sendError(id, 'malformed', 'keys cannot be read', {
            'reason': 'keys',
          });
          return;
        }
        try {
          final revision = await service.moveVault(
            store,
            location,
            stored,
            baseRevision: base as String?,
            newKeys: newKeys,
          );
          connection.send({
            'op': 'ok',
            'id': id,
            'location': location,
            'revision': revision,
          });
        } on TomSecretsSaveException catch (e) {
          service.log.info('move_refused', {
            'store': store,
            'kind': e.kind,
            'reason': e.reason,
          });
          connection.sendError(id, e.kind, e.message, {
            if (e.kind == 'offline' || e.kind == 'token_expired')
              'stores': [store],
            'reason': ?e.reason,
          });
        }
      case 'vault.create':
        final store = m['store'];
        final location = m['location'];
        final bytes = m['bytes'];
        final wireKeys = m['keys'];
        final token = m['githubToken'];
        final due = m['keysDue'];
        final keysDue = due is String ? DateTime.tryParse(due) : null;
        final wireRecipients = m['recipients'];
        if (store is! String ||
            location is! String ||
            bytes is! String ||
            wireKeys is! Map ||
            (token != null && (token is! String || token.isEmpty)) ||
            (due != null && keysDue == null) ||
            (wireRecipients != null && wireRecipients is! String)) {
          connection.sendError(
            id,
            'malformed',
            'vault.create carries store, location, bytes and keys',
            {'reason': 'create'},
          );
          return;
        }
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        final newKeys = _newKeysOf(
          wireKeys.cast<String, Object?>(),
          keyFileOnly: wireRecipients != null,
        );
        if (newKeys == null) {
          connection.sendError(id, 'malformed', 'keys cannot be read', {
            'reason': 'keys',
          });
          return;
        }
        final Uint8List stored;
        final Uint8List? recipients;
        try {
          stored = base64.decode(bytes);
          recipients = wireRecipients == null
              ? null
              : base64.decode(wireRecipients as String);
        } on FormatException {
          newKeys.dispose();
          connection.sendError(id, 'malformed', 'bytes is not base64', {
            'reason': 'bytes',
          });
          return;
        }
        try {
          final revision = await service.createVault(
            store,
            location,
            stored,
            keys: newKeys,
            githubToken: token as String?,
            keysDue: keysDue,
            recipients: recipients,
          );
          connection.send({
            'op': 'ok',
            'id': id,
            'store': store,
            'location': location,
            'revision': revision,
          });
        } on TomSecretsSaveException catch (e) {
          service.log.info('create_refused', {
            'store': store,
            'kind': e.kind,
            'reason': e.reason,
          });
          connection.sendError(id, e.kind, e.message, {
            if (e.kind == 'offline' || e.kind == 'token_expired')
              'stores': [store],
            'reason': ?e.reason,
          });
        } on Object catch (e) {
          service.log.error('create_failed', e, {'store': store});
          connection.sendError(id, 'internal', 'the vault was not created', {
            'code': e.runtimeType.toString(),
          });
        }
      case 'vault.recipients':
        final store = m['store'];
        final location = m['location'];
        final token = m['githubToken'];
        if ((store == null) == (location == null) ||
            (store != null && store is! String) ||
            (location != null && location is! String) ||
            (token != null && (token is! String || token.isEmpty))) {
          connection.sendError(
            id,
            'malformed',
            'vault.recipients names a store or a location',
            {'reason': 'recipients'},
          );
          return;
        }
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        try {
          final read = await service.recipients(
            store: store as String?,
            location: location as String?,
            githubToken: token as String?,
          );
          if (read == null) {
            connection.sendError(
              id,
              'not_found',
              'the vault has no recipients file',
              {'reason': 'no_recipients'},
            );
            return;
          }
          connection.send({
            'op': 'recipientsData',
            'id': id,
            'store': ?store,
            'location': read.location,
            'revision': read.revision,
            'bytes': base64.encode(read.bytes),
          });
        } on TomSecretsSaveException catch (e) {
          connection.sendError(id, e.kind, e.message, {'reason': ?e.reason});
        } on TomSecretsLocatorException {
          connection.sendError(id, 'malformed', '$location is no locator', {
            'reason': 'location',
          });
        } on Object catch (e) {
          final failure = tomSecretsFetchFailureOf(e);
          if (failure != null) {
            connection.sendError(
              id,
              TomSecretsStoreState.offlineFor(failure).wireName,
              'the recipients file cannot be read now',
            );
          } else {
            service.log.error('recipients_failed', e);
            connection.sendError(
              id,
              'unavailable',
              'the recipients file cannot be read',
            );
          }
        }
      case 'vault.recipients.set':
        final store = m['store'];
        final bytes = m['bytes'];
        final base = m['baseRevision'];
        if (store is! String ||
            bytes is! String ||
            (base != null && base is! String)) {
          connection.sendError(
            id,
            'malformed',
            'vault.recipients.set carries store and bytes',
            {'reason': 'recipients'},
          );
          return;
        }
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        final Uint8List file;
        try {
          file = base64.decode(bytes);
        } on FormatException {
          connection.sendError(id, 'malformed', 'bytes is not base64', {
            'reason': 'bytes',
          });
          return;
        }
        try {
          final revision = await service.setRecipients(
            store,
            file,
            baseRevision: base as String?,
          );
          connection.send({'op': 'ok', 'id': id, 'revision': revision});
        } on TomSecretsSaveException catch (e) {
          connection.sendError(id, e.kind, e.message, {'reason': ?e.reason});
        } on Object catch (e) {
          service.log.error('recipients_write_failed', e, {'store': store});
          connection.sendError(
            id,
            'internal',
            'the recipients file was not written',
            {'code': e.runtimeType.toString()},
          );
        }
      case 'inbox.list' || 'inbox.read' || 'inbox.put' || 'inbox.delete':
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        await _inbox(id, op, m);
      case 'relay.revision' ||
          'relay.list' ||
          'relay.read' ||
          'relay.create' ||
          'relay.deleteFolder' ||
          'relay.deleteFile':
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        await _relay(id, op, m);
      case 'pair.identity' || 'pair.record' || 'pair.revoke' || 'pair.list':
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        await _pairing(id, op, m);
      case 'keys.rotate':
        final approver = m['approver'] ?? true;
        final link = m['link'] ?? true;
        if (approver is! bool || link is! bool || (!approver && !link)) {
          connection.sendError(
            id,
            'malformed',
            'keys.rotate takes approver and link, at least one true',
            {'reason': 'keys'},
          );
          return;
        }
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        final rotated = await service.rotateKeyPairs(
          approver: approver,
          link: link,
        );
        connection.send({
          'op': 'keysRotated',
          'id': id,
          'approverKeyId': ?rotated.approverKeyId,
          'resigned': rotated.resigned,
          'delivered': rotated.delivered,
          'pending': rotated.pending,
        });
      case 'token.set':
        final repository = m['repository'];
        final token = m['token'];
        if (repository is! String ||
            !RegExp(r'^[^/\s]+/[^/\s]+$').hasMatch(repository) ||
            token is! String ||
            token.trim().isEmpty) {
          connection.sendError(
            id,
            'malformed',
            'token.set names a repository owner/name and a token',
            {'reason': 'token'},
          );
          return;
        }
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        try {
          final set = await service.setGitHubToken(repository, token.trim());
          connection.send({
            'op': 'tokenSet',
            'id': id,
            'repository': repository,
            'where': set.where,
            if (set.expiresAt != null)
              'expiresAt': set.expiresAt!.toUtc().toIso8601String(),
          });
        } on TomSecretsTokenCheckException catch (e) {
          service.log.info('token_refused', {
            'repository': repository,
            'reason': e.reason,
          });
          if (e.problem == TomSecretsTokenProblem.unreachable) {
            connection.sendError(id, 'offline', e.message, {
              'repository': repository,
            });
          } else {
            connection.sendError(id, 'denied', e.message, {'reason': e.reason});
          }
        } on StateError {
          connection.sendError(id, 'not_found', 'no vault in $repository', {
            'repository': repository,
          });
        } on UnsupportedError catch (e) {
          connection.sendError(id, 'unsupported', '${e.message}', {
            'reason': 'no_keychain',
          });
        }
      case 'settings.get':
        if (service.isLocked || service.deviceContainer == null) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        connection.send({
          'op': 'deviceSettings',
          'id': id,
          ...service.settingsReport(),
        });
      case 'settings.set':
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked || service.deviceContainer == null) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        final device = m['device'];
        final problem = device is Map
            ? tomSecretsSettingsProblem(device.cast<String, Object?>())
            : 'device is an object';
        if (problem != null) {
          connection.sendError(id, 'malformed', problem, {
            'reason': 'settings',
          });
          return;
        }
        final value = TomSecretsDeviceSettings.fromJson(
          (device! as Map).cast<String, Object?>(),
        );
        final later = await service.writeSettings(value);
        service.log.info('settings', {'nextUnlock': later.length});
        connection.send({'op': 'ok', 'id': id, 'nextUnlock': later});
      case 'github.app':
        connection.send({
          'op': 'githubApp',
          'id': id,
          ...service.githubApp.describe(service.githubAppClientId),
        });
      case 'github.app.configure':
        final clientId = m['clientId'];
        if (clientId is! String ||
            (clientId.isNotEmpty &&
                !RegExp(r'^[A-Za-z0-9._-]{4,64}$').hasMatch(clientId))) {
          connection.sendError(id, 'malformed', 'a client id', {
            'reason': 'clientId',
          });
          return;
        }
        if (!isApp) {
          connection.sendError(id, 'denied', 'only the manager app', {
            'reason': 'wrong_executable',
          });
          return;
        }
        if (service.isLocked) {
          connection.sendError(id, 'locked', 'unlock the service first');
          return;
        }
        await service.setGitHubAppClientId(clientId);
        connection.send({'op': 'ok', 'id': id});
      case 'github.signIn':
        final clientId = m['clientId'];
        if (clientId != null && clientId is! String) {
          connection.sendError(id, 'malformed', 'a client id', {
            'reason': 'clientId',
          });
          return;
        }
        try {
          final code = await service.startGitHubSignIn(clientId as String?);
          connection.send({
            'op': 'deviceCode',
            'id': id,
            'userCode': code.userCode,
            'verificationUri': code.verificationUri,
            'expiresIn': code.expiresIn.inSeconds,
            'interval': code.interval.inSeconds,
          });
        } on TomSecretsGitHubAppException catch (e) {
          switch (e.kind) {
            case 'not_configured':
              connection.sendError(id, 'not_found', e.message, {
                'reason': 'no_github_app',
              });
            case 'no_keychain':
              connection.sendError(id, 'unsupported', e.message, {
                'reason': 'no_keychain',
              });
            default:
              connection.sendError(id, 'denied', e.message, {'reason': e.kind});
          }
        } on Object catch (e) {
          service.log.error('github_sign_in_failed', e);
          connection.sendError(id, 'offline', 'GitHub could not be reached');
        }
      case 'github.signOut':
        await service.signOutOfGitHub();
        connection.send({'op': 'ok', 'id': id});
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

/// What `keys.rotate` did.
final class TomSecretsPairsRotated {
  /// The result.
  const TomSecretsPairsRotated({
    required this.approverKeyId,
    required this.resigned,
    required this.delivered,
    required this.pending,
  });

  /// The new approver key's id, or null when it was not rotated.
  final String? approverKeyId;

  /// The grants and revocations signed again.
  final int resigned;

  /// The hosts the new keys reached over the link.
  final List<String> delivered;

  /// The hosts not reached: they find the key change in the vault at their
  /// next refresh, and the new link key is sent again at the refresh.
  final List<String> pending;
}
