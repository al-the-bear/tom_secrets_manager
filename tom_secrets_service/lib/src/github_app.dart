// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// "Sign in with GitHub" (part-key-rotation §3, DP-6, DP-83, DP-155): user
/// tokens of the user's GitHub App through the device flow, the default way
/// a device reaches the vault repositories once the App is registered.
///
/// - The service is the single owner of the device's tokens (two processes
///   renewing one refresh token would spend it twice): it runs the device
///   flow, keeps the access and the refresh token in the device keychain
///   (`tsm.github-app.session`, with the client id they belong to), and
///   renews both before the access token's 8 hours run out or at GitHub's
///   first 401, writing them back before using them.
/// - A refresh GitHub refuses (`bad_refresh_token`: 6 months unused, or the
///   App's authorization revoked) leaves the device "sign in again".
/// - No App private key or client secret exists anywhere: a device-flow
///   token is refreshed with the client id alone.
library;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:tom_core_storage/settings.dart'
    show TomSecretStore, TomSecretStoreAvailability;

/// The keychain handle of the device's GitHub App session.
const String tomSecretsGitHubAppHandle = 'tsm.github-app.session';

/// How long before the access token runs out it is renewed.
const Duration tomSecretsGitHubAppRenewAhead = Duration(minutes: 5);

/// Where the device's App sign-in stands.
enum TomSecretsGitHubAppState {
  /// The primary names no App client id and the device is not signed in.
  notConfigured('not_configured'),

  /// An App is named, the device is not signed in.
  signedOut('signed_out'),

  /// A device flow waits for the user to enter its code.
  pending('pending'),

  /// The device holds a working sign-in.
  signedIn('signed_in'),

  /// GitHub refused the refresh token: the device signs in again.
  signInAgain('sign_in_again');

  const TomSecretsGitHubAppState(this.wireName);

  /// As the protocol writes it.
  final String wireName;
}

/// A device flow's code, as `github.signIn` answers it.
final class TomSecretsDeviceCode {
  /// A code the user enters at [verificationUri].
  const TomSecretsDeviceCode({
    required this.deviceCode,
    required this.userCode,
    required this.verificationUri,
    required this.expiresIn,
    required this.interval,
  });

  /// The code the service polls with (never shown).
  final String deviceCode;

  /// The code the user enters (`WDJB-MJHT`).
  final String userCode;

  /// Where the user enters it (`https://github.com/login/device`).
  final String verificationUri;

  /// How long the code is valid.
  final Duration expiresIn;

  /// The least time between two polls.
  final Duration interval;
}

/// A sign-in refused by GitHub: [kind] (`denied`, `expired`,
/// `device_flow_disabled`, `bad_client_id`, `bad_refresh_token`, `failed`).
final class TomSecretsGitHubAppException implements Exception {
  /// A refusal of [kind].
  const TomSecretsGitHubAppException(this.kind, [this.message = '']);

  /// The reason, as the protocol writes it.
  final String kind;

  /// GitHub's description, never a token.
  final String message;

  @override
  String toString() => 'TomSecretsGitHubAppException: $kind $message';
}

/// The device's tokens of the App.
final class _Session {
  _Session({
    required this.clientId,
    required this.access,
    required this.accessExpires,
    required this.refresh,
    required this.refreshExpires,
    this.login,
    this.refused = false,
  });

  factory _Session.fromJson(Map<String, Object?> j) => _Session(
    clientId: j['clientId']! as String,
    access: j['access']! as String,
    accessExpires: DateTime.tryParse(j['accessExpires'] as String? ?? ''),
    refresh: j['refresh'] as String?,
    refreshExpires: DateTime.tryParse(j['refreshExpires'] as String? ?? ''),
    login: j['login'] as String?,
    refused: j['refused'] == true,
  );

  final String clientId;
  final String access;
  final DateTime? accessExpires;
  final String? refresh;
  final DateTime? refreshExpires;
  final String? login;
  final bool refused;

  Map<String, Object?> toJson() => {
    'clientId': clientId,
    'access': access,
    'accessExpires': ?accessExpires?.toUtc().toIso8601String(),
    'refresh': ?refresh,
    'refreshExpires': ?refreshExpires?.toUtc().toIso8601String(),
    'login': ?login,
    if (refused) 'refused': true,
  };
}

/// The device's GitHub App sign-in.
final class TomSecretsGitHubApp {
  /// The sign-in kept in [keychain], reaching GitHub's web endpoints at
  /// [webBaseUrl] (the device flow) and its API at [apiBaseUrl] (the user's
  /// login) through [client].
  TomSecretsGitHubApp({
    required this.keychain,
    this.webBaseUrl = 'https://github.com',
    this.apiBaseUrl = 'https://api.github.com',
    http.Client? client,
    DateTime Function()? clock,
    this.onChanged,
  }) : _client = client ?? http.Client(),
       _clock = clock ?? DateTime.now;

  /// The device keychain, or null where none answers (no sign-in then).
  final TomSecretStore? keychain;

  /// `https://github.com` (tests: a fake).
  final String webBaseUrl;

  /// `https://api.github.com` (tests: a fake).
  final String apiBaseUrl;

  /// Told after the session changed (signed in, renewed, refused, out).
  final void Function()? onChanged;

  final http.Client _client;
  final DateTime Function() _clock;
  _Session? _session;
  bool _loaded = false;
  Future<String?>? _renewing;
  TomSecretsDeviceCode? _pending;
  int _flow = 0;

  /// Reads the session from the keychain (once; the service at its start).
  Future<void> load() => _load();

  Future<void> _load() async {
    if (_loaded) return;
    _loaded = true;
    final store = keychain;
    if (store == null) return;
    // A keychain that says it cannot be used is not read (a locked or
    // absent one: no sign-in on this device then).
    if (store is TomSecretStoreAvailability &&
        !await (store as TomSecretStoreAvailability).isAvailable()) {
      return;
    }
    final text = await store.read(tomSecretsGitHubAppHandle);
    if (text == null) return;
    try {
      _session = _Session.fromJson((jsonDecode(text) as Map).cast());
    } on Object {
      _session = null;
    }
  }

  Future<void> _store(_Session? session) async {
    _session = session;
    final store = keychain;
    if (store != null) {
      if (session == null) {
        await store.delete(tomSecretsGitHubAppHandle);
      } else {
        await store.write(
          tomSecretsGitHubAppHandle,
          jsonEncode(session.toJson()),
        );
      }
    }
    onChanged?.call();
  }

  /// Where the sign-in stands, with [clientId] the App the primary names
  /// (after [load]).
  TomSecretsGitHubAppState state(String? clientId) {
    final s = _session;
    if (_pending != null) return TomSecretsGitHubAppState.pending;
    if (s != null) {
      return s.refused
          ? TomSecretsGitHubAppState.signInAgain
          : TomSecretsGitHubAppState.signedIn;
    }
    return clientId == null || clientId.isEmpty
        ? TomSecretsGitHubAppState.notConfigured
        : TomSecretsGitHubAppState.signedOut;
  }

  /// Whether the device is signed in (also while it must sign in again: its
  /// pasted tokens are then not used either, so the stores say so).
  Future<bool> get signedIn async {
    await _load();
    return _session != null;
  }

  /// What `github.app` answers about the session.
  Map<String, Object?> describe(String? clientId) {
    final s = _session;
    return {
      'state': state(clientId).wireName,
      'clientId': ?clientId,
      if (s != null) ...{
        'signedInClientId': s.clientId,
        'login': ?s.login,
        'accessExpiresAt': ?s.accessExpires?.toUtc().toIso8601String(),
        'refreshExpiresAt': ?s.refreshExpires?.toUtc().toIso8601String(),
      },
      if (_pending case final p?) ...{
        'userCode': p.userCode,
        'verificationUri': p.verificationUri,
      },
    };
  }

  /// When the refresh token runs out (the sign-in lasts that long unused),
  /// or null.
  DateTime? get refreshExpires => _session?.refreshExpires;

  /// The access token, renewed first when it runs out within
  /// [tomSecretsGitHubAppRenewAhead] or when [force] (GitHub answered 401);
  /// null when the device is not signed in or must sign in again. One
  /// renewal at a time: concurrent callers wait for it.
  Future<String?> accessToken({bool force = false}) async {
    await _load();
    final s = _session;
    if (s == null || s.refused) return null;
    final expires = s.accessExpires;
    final due =
        force ||
        (expires != null &&
            !_clock().toUtc().isBefore(
              expires.toUtc().subtract(tomSecretsGitHubAppRenewAhead),
            ));
    if (!due) return s.access;
    return _renewing ??= _renew(s).whenComplete(() => _renewing = null);
  }

  Future<String?> _renew(_Session s) async {
    final refresh = s.refresh;
    if (refresh == null) return s.access;
    final Map<String, Object?> answer;
    try {
      answer = await _token({
        'client_id': s.clientId,
        'grant_type': 'refresh_token',
        'refresh_token': refresh,
      });
    } on TomSecretsGitHubAppException catch (e) {
      if (e.kind == 'bad_refresh_token') {
        await _store(
          _Session(
            clientId: s.clientId,
            access: s.access,
            accessExpires: s.accessExpires,
            refresh: null,
            refreshExpires: s.refreshExpires,
            login: s.login,
            refused: true,
          ),
        );
        return null;
      }
      // GitHub not reachable: the old token is tried; the stores say so.
      return s.access;
    } on Object {
      return s.access;
    }
    final next = _sessionOf(s.clientId, answer, login: s.login);
    await _store(next);
    return next.access;
  }

  _Session _sessionOf(
    String clientId,
    Map<String, Object?> answer, {
    String? login,
  }) {
    final now = _clock().toUtc();
    final access = answer['access_token'];
    if (access is! String || access.isEmpty) {
      throw const TomSecretsGitHubAppException('failed', 'no access token');
    }
    Duration? seconds(Object? v) => v is int
        ? Duration(seconds: v)
        : v is String
        ? Duration(seconds: int.tryParse(v) ?? 0)
        : null;
    final accessIn = seconds(answer['expires_in']);
    final refreshIn = seconds(answer['refresh_token_expires_in']);
    return _Session(
      clientId: clientId,
      access: access,
      accessExpires: accessIn == null ? null : now.add(accessIn),
      refresh: answer['refresh_token'] as String?,
      refreshExpires: refreshIn == null ? null : now.add(refreshIn),
      login: login,
    );
  }

  /// Starts a device flow for the App [clientId]: answers the code the user
  /// enters; the service then polls GitHub until the user confirmed it
  /// (signed in), refused it, or the code ran out, and reports through
  /// [onDone] (`signed_in` with the login, or a refusal's kind). A new start
  /// ends a flow still polling.
  Future<TomSecretsDeviceCode> startSignIn(
    String clientId, {
    required void Function(String outcome, {String? login}) onDone,
  }) async {
    if (keychain == null) {
      throw const TomSecretsGitHubAppException(
        'no_keychain',
        'no device keychain to keep the tokens in',
      );
    }
    await _load();
    final answer = await _post('/login/device/code', {'client_id': clientId});
    final code = TomSecretsDeviceCode(
      deviceCode: answer['device_code']! as String,
      userCode: answer['user_code']! as String,
      verificationUri:
          answer['verification_uri'] as String? ?? '$webBaseUrl/login/device',
      expiresIn: Duration(seconds: (answer['expires_in'] as int?) ?? 900),
      interval: Duration(seconds: (answer['interval'] as int?) ?? 5),
    );
    _pending = code;
    final flow = ++_flow;
    onChanged?.call();
    unawaited(_poll(flow, clientId, code, onDone));
    return code;
  }

  Future<void> _poll(
    int flow,
    String clientId,
    TomSecretsDeviceCode code,
    void Function(String outcome, {String? login}) onDone,
  ) async {
    final end = _clock().add(code.expiresIn);
    var interval = code.interval;
    void finish(String outcome, {String? login}) {
      if (flow != _flow) return;
      _pending = null;
      onChanged?.call();
      onDone(outcome, login: login);
    }

    while (flow == _flow) {
      await Future<void>.delayed(interval);
      if (flow != _flow) return;
      if (_clock().isAfter(end)) return finish('expired');
      try {
        final answer = await _token({
          'client_id': clientId,
          'device_code': code.deviceCode,
          'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        });
        final session = _sessionOf(clientId, answer);
        final login = await _login(session.access);
        if (flow != _flow) return;
        await _store(
          _Session(
            clientId: session.clientId,
            access: session.access,
            accessExpires: session.accessExpires,
            refresh: session.refresh,
            refreshExpires: session.refreshExpires,
            login: login,
          ),
        );
        return finish('signed_in', login: login);
      } on TomSecretsGitHubAppException catch (e) {
        switch (e.kind) {
          case 'authorization_pending':
            continue;
          case 'slow_down':
            interval += const Duration(seconds: 5);
            continue;
          case 'expired_token' || 'token_expired':
            return finish('expired');
          case 'access_denied':
            return finish('denied');
          case 'device_flow_disabled':
            return finish('device_flow_disabled');
          case 'incorrect_client_credentials':
            return finish('bad_client_id');
          default:
            return finish('failed');
        }
      } on Object {
        // Not reachable for a moment: poll again.
        continue;
      }
    }
  }

  /// Ends a device flow still polling.
  void cancelSignIn() {
    if (_pending == null) return;
    _flow++;
    _pending = null;
    onChanged?.call();
  }

  /// Signs the device out: the tokens leave the keychain (GitHub keeps the
  /// App's authorization; revoking it there cuts off every signed-in
  /// device). The pasted tokens are used again.
  Future<void> signOut() async {
    cancelSignIn();
    await _load();
    await _store(null);
  }

  Future<String?> _login(String access) async {
    try {
      final r = await _client.get(
        Uri.parse('$apiBaseUrl/user'),
        headers: {
          'Authorization': 'Bearer $access',
          'Accept': 'application/vnd.github+json',
        },
      );
      if (r.statusCode != 200) return null;
      return (jsonDecode(r.body) as Map)['login'] as String?;
    } on Object {
      return null;
    }
  }

  Future<Map<String, Object?>> _token(Map<String, String> body) =>
      _post('/login/oauth/access_token', body);

  /// Posts [body] to GitHub's web endpoint [path]: the JSON answer, or a
  /// [TomSecretsGitHubAppException] of its `error`.
  Future<Map<String, Object?>> _post(
    String path,
    Map<String, String> body,
  ) async {
    final r = await _client.post(
      Uri.parse('$webBaseUrl$path'),
      headers: {'Accept': 'application/json'},
      body: body,
    );
    Map<String, Object?> answer;
    try {
      answer = (jsonDecode(r.body) as Map).cast<String, Object?>();
    } on FormatException {
      answer = Uri.splitQueryString(r.body);
    }
    final error = answer['error'];
    if (error is String) {
      throw TomSecretsGitHubAppException(
        error,
        (answer['error_description'] as String?) ?? '',
      );
    }
    if (r.statusCode ~/ 100 != 2) {
      throw TomSecretsGitHubAppException('failed', 'HTTP ${r.statusCode}');
    }
    return answer;
  }
}
