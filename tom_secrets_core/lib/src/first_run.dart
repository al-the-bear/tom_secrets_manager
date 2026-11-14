// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The first run of a machine (part-app, Screens › First run; DP-80, DP-83,
/// DP-84, BP-18): what the wizard sets up before the service can start.
///
/// 1. The primary vault, created or opened, local (`file:`) or in a GitHub
///    repository (`github:`); the GitHub token kept in the device keychain
///    with its expiry.
/// 2. Its protection layers, each optional: a key file and the repository's
///    outer key (`.tsmx`, one key slot, XChaCha20-Poly1305 by default or
///    AES-256-GCM); a new primary with either gets `tsm.keys-due` 24 months
///    on (DP-85). Both are kept in the device keychain, where the service
///    takes them at the unlock.
/// 3. The machine's settings, written into the device settings container,
///    and `bootstrap.yaml`, written last: its presence means the machine is
///    set up.
///
/// The service is not running during the first run, so the first run writes
/// the primary itself; afterwards the service is its one writer (DP-13).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/settings.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'device_settings.dart';
import 'github_token.dart';
import 'locator.dart';
import 'metadata.dart';
import 'new_vault.dart';
import 'outer.dart';
import 'stored_vault.dart';
import 'vault_sync.dart';

/// The host name the service goes by when `bootstrap.yaml` names none: the
/// machine's name up to its first dot, in lower case.
String tomSecretsDefaultHost() =>
    Platform.localHostname.split('.').first.toLowerCase();

/// How long a new primary's key file and repository key are good for before
/// they are due for rotation (DP-85).
const int tomSecretsPrimaryKeyMonths = 24;

/// The due date of keys created at [created]: [months] later, the day kept
/// (the last of the month where that month is shorter).
DateTime tomSecretsKeysDue(DateTime created, {int months = 24}) {
  final utc = created.toUtc();
  final month = utc.month - 1 + months;
  final year = utc.year + month ~/ 12;
  final m = month % 12 + 1;
  final last = DateTime.utc(year, m + 1, 0).day;
  return DateTime.utc(
    year,
    m,
    utc.day > last ? last : utc.day,
    utc.hour,
    utc.minute,
  );
}

/// Why the first run cannot go on.
enum TomSecretsFirstRunProblem {
  /// GitHub refused the token (401, or 403 without a rate limit).
  tokenRefused,

  /// The repository does not exist, or the token cannot see it.
  repositoryNotFound,

  /// The repository has no commit yet: GitHub cannot take a file into it
  /// through the REST API. Create it with a README.
  repositoryEmpty,

  /// GitHub (or the disk) could not be reached.
  unreachable,

  /// A new primary would replace a file that is already there.
  primaryExists,

  /// The primary to open is not there.
  primaryNotFound,

  /// The master password (with the key file) does not open the primary.
  wrongPassword,

  /// The primary is outer encrypted and no repository key was given.
  repositoryKeyNeeded,

  /// The repository key given has no slot in the primary, or the file is
  /// damaged.
  repositoryKeyWrong,

  /// The file is not a vault this product reads.
  notAVault,

  /// The locator, the protection layers and the file name do not agree (a
  /// `.tsmx` name without a repository key, or the other way round).
  inconsistent,

  /// Keys are to be kept and there is no keychain.
  keychainNeeded,

  /// The machine is set up already: `bootstrap.yaml` is there.
  alreadySetUp,
}

/// The first run cannot go on, for [problem].
final class TomSecretsFirstRunException implements Exception {
  /// A [problem] described by [message].
  TomSecretsFirstRunException(this.problem, this.message);

  /// What is wrong.
  final TomSecretsFirstRunProblem problem;

  /// What it means, for the user.
  final String message;

  @override
  String toString() => 'TomSecretsFirstRunException(${problem.name}): $message';
}

/// A GitHub repository as a token sees it.
final class TomSecretsGitHubRepositoryCheck {
  /// The repository's [defaultBranch]; the token [expires] then (null: no
  /// expiry reported).
  const TomSecretsGitHubRepositoryCheck({
    required this.defaultBranch,
    this.expires,
  });

  /// The repository's default branch.
  final String defaultBranch;

  /// When the token expires, as GitHub reports it, or null.
  final DateTime? expires;
}

/// What the first run sets up.
final class TomSecretsFirstRunSetup {
  /// A setup of the primary at [primary], [create]d or opened, with
  /// [masterPassword] and the optional layers; [settings] and [deviceKey]
  /// for this machine.
  TomSecretsFirstRunSetup({
    required this.primary,
    required this.create,
    required this.masterPassword,
    this.keyFile,
    this.repositoryKey,
    this.cipher = TomSecretsOuterCipher.xchacha20Poly1305,
    this.githubToken,
    this.githubTokenExpires,
    this.settings = const TomSecretsDeviceSettings(),
    this.deviceKey = TomSecretsDeviceKeyMode.auto,
    this.host,
  });

  /// Where the primary is.
  final TomSecretsVaultLocator primary;

  /// Whether a new primary is created (else an existing one is opened).
  final bool create;

  /// The master password.
  final String masterPassword;

  /// The key file's bytes (a new one from `TomSecretsKeyFile.toBytes`, or
  /// one chosen), or null for none.
  final Uint8List? keyFile;

  /// The repository's outer key, or null for none.
  final TomSecretsRepositoryKey? repositoryKey;

  /// The outer cipher of a new primary (an existing one keeps its own).
  final TomSecretsOuterCipher cipher;

  /// The GitHub token for the primary's repository (a `github:` primary).
  final String? githubToken;

  /// The token's expiry as entered, or null (then GitHub's report is kept).
  final DateTime? githubTokenExpires;

  /// The machine's settings: its default environment, the files it serves,
  /// the lock modes.
  final TomSecretsDeviceSettings settings;

  /// Where the device settings container's key is kept (DP-15).
  final TomSecretsDeviceKeyMode deviceKey;

  /// The host name, when it is to differ from [tomSecretsDefaultHost].
  final String? host;
}

/// What the first run did.
final class TomSecretsFirstRunResult {
  /// The result.
  const TomSecretsFirstRunResult({
    required this.bootstrapPath,
    required this.created,
    required this.deviceKey,
    this.keysDue,
    this.githubTokenExpires,
  });

  /// The `bootstrap.yaml` written.
  final String bootstrapPath;

  /// Whether a new primary was written.
  final bool created;

  /// Where the device settings container's key went (`auto` decided).
  final TomSecretsDeviceKeyMode deviceKey;

  /// The primary's `tsm.keys-due`, when one was set.
  final DateTime? keysDue;

  /// The GitHub token's expiry kept, or null.
  final DateTime? githubTokenExpires;
}

/// The first run of a machine, writing into [dataDirectory] and [keychain].
final class TomSecretsFirstRun {
  /// A first run for the data directory [dataDirectory] (where
  /// `bootstrap.yaml` goes), keeping keys in [keychain] (null: none on this
  /// machine), reaching GitHub at [githubBaseUrl] through [httpClient];
  /// new vaults keyed with [argon2].
  TomSecretsFirstRun({
    required this.dataDirectory,
    required this.keychain,
    http.Client? httpClient,
    this.githubBaseUrl = 'https://api.github.com',
    this.argon2 = tomSecretsDefaultArgon2,
    DateTime Function()? clock,
  }) : _httpClient = httpClient,
       _clock = clock ?? DateTime.now;

  /// The data directory.
  final String dataDirectory;

  /// The device keychain, or null.
  final TomSecretStore? keychain;

  /// GitHub's API.
  final String githubBaseUrl;

  /// The key derivation of a new vault.
  final KdbxArgon2 argon2;

  final http.Client? _httpClient;
  final DateTime Function() _clock;

  /// The bootstrap file the first run writes.
  String get bootstrapPath =>
      '$dataDirectory${Platform.pathSeparator}bootstrap.yaml';

  /// The device settings container's file (the bootstrap's default).
  String get deviceContainerPath =>
      '$dataDirectory${Platform.pathSeparator}device-settings.kdbx';

  GitHubApiClient _github(String token) => GitHubApiClient(
    token: token,
    httpClient: _httpClient,
    baseUrl: githubBaseUrl,
    minMutativeInterval: Duration.zero,
  );

  /// Checks that [token] sees [owner]/[repository]: answers its default
  /// branch and the token's expiry GitHub reports. Throws
  /// [TomSecretsFirstRunException] (`tokenRefused`, `repositoryNotFound`,
  /// `unreachable`).
  Future<TomSecretsGitHubRepositoryCheck> checkGitHub({
    required String owner,
    required String repository,
    required String token,
  }) async {
    final recorder = _ExpiryRecorder(_httpClient ?? http.Client());
    final client = GitHubApiClient(
      token: token,
      httpClient: recorder,
      baseUrl: githubBaseUrl,
    );
    try {
      final repo = await client.getRepository(owner: owner, repo: repository);
      return TomSecretsGitHubRepositoryCheck(
        defaultBranch: repo.defaultBranch,
        expires: recorder.expiry,
      );
    } on GitHubAuthException {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.tokenRefused,
        'GitHub refused the token: it may be mistyped, expired or revoked.',
      );
    } on GitHubNotFoundException {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.repositoryNotFound,
        'GitHub knows no repository $owner/$repository the token can see: '
        'check the name, and that the token is granted this repository.',
      );
    } on GitHubException catch (e) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.unreachable,
        'GitHub answered ${e.statusCode}: ${e.message}',
      );
    } on Object catch (e) {
      if (e is SocketException || e is http.ClientException) {
        throw TomSecretsFirstRunException(
          TomSecretsFirstRunProblem.unreachable,
          'GitHub could not be reached: $e',
        );
      }
      rethrow;
    } finally {
      if (_httpClient == null) recorder.close();
    }
  }

  /// Sets the machine up as [setup] says; see the library comment for the
  /// order. Throws [TomSecretsFirstRunException]; nothing is written to the
  /// keychain, the container or the bootstrap before the primary opened (or
  /// was written), and the bootstrap only when everything else succeeded.
  Future<TomSecretsFirstRunResult> run(TomSecretsFirstRunSetup setup) async {
    if (File(bootstrapPath).existsSync()) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.alreadySetUp,
        'This machine is set up already: $bootstrapPath is there.',
      );
    }
    final locator = setup.primary;
    final outer = locator.fileName.endsWith(tomSecretsOuterSuffix);
    if (outer && setup.repositoryKey == null) {
      throw TomSecretsFirstRunException(
        setup.create
            ? TomSecretsFirstRunProblem.inconsistent
            : TomSecretsFirstRunProblem.repositoryKeyNeeded,
        setup.create
            ? 'A ${locator.fileName} file is outer encrypted: give it a '
                  'repository key, or name it without $tomSecretsOuterSuffix.'
            : '${locator.fileName} is outer encrypted: give the repository '
                  'key.',
      );
    }
    if (!outer && setup.repositoryKey != null) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.inconsistent,
        'A repository key protects a file named …$tomSecretsOuterSuffix; '
        '${locator.fileName} is a plain vault.',
      );
    }
    final store = keychain;
    final keysToKeep =
        setup.keyFile != null ||
        setup.repositoryKey != null ||
        locator is TomSecretsGitHubLocator;
    if (keysToKeep && store == null) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.keychainNeeded,
        'This machine has no keychain to keep the key file, the repository '
        'key or the GitHub token in.',
      );
    }
    if (locator is TomSecretsGitHubLocator && setup.githubToken == null) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.tokenRefused,
        'A primary in a GitHub repository needs a GitHub token.',
      );
    }
    final host = setup.host ?? tomSecretsDefaultHost();
    final credentials = tomSecretsVaultCredentials(
      password: setup.masterPassword,
      keyFile: setup.keyFile,
    );
    final outerKey = setup.repositoryKey?.toBase64();
    final primary = switch (locator) {
      TomSecretsFileLocator() => _FilePrimary(locator, outerKey, setup.cipher),
      TomSecretsGitHubLocator() => _GitHubPrimary(
        locator,
        outerKey,
        setup.cipher,
        _github(setup.githubToken!),
        host,
      ),
      TomSecretsGitLocator() => throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.inconsistent,
        'git: vaults are not offered as the primary in phase A.',
      ),
    };
    try {
      DateTime? keysDue;
      final KdbxFile file;
      if (setup.create) {
        await primary.checkAbsent();
        file = tomSecretsNewVault(credentials, 'primary', argon2: argon2);
        if (setup.keyFile != null || setup.repositoryKey != null) {
          keysDue = tomSecretsKeysDue(
            _clock(),
            months: tomSecretsPrimaryKeyMonths,
          );
          TomSecretsMetadata(keysDue: keysDue).writeTo(file);
        }
      } else {
        file = await primary.open(credentials);
      }

      // The container's key, in the mode asked for; the vault mode writes it
      // into the primary, which a new primary carries in its first write.
      final deviceKeys = TomSecretsDeviceKeys(
        mode: setup.deviceKey,
        host: host,
        containerPath: deviceContainerPath,
        keychain: store,
      );
      final mode = await deviceKeys.effectiveMode();
      var primaryChanged = false;
      final containerKey = await deviceKeys.keyFor(
        primary: file,
        savePrimary: () async => primaryChanged = true,
      );
      if (setup.create) {
        await primary.create(file);
      } else if (primaryChanged) {
        await primary.save(file);
      }

      DateTime? expires;
      if (locator is TomSecretsGitHubLocator) {
        expires = setup.githubTokenExpires?.toUtc();
        await store!.write(locator.tokenHandle, setup.githubToken!);
        if (expires != null) {
          await store.write(
            locator.tokenExpiryHandle,
            expires.toUtc().toIso8601String(),
          );
        }
      }
      if (setup.keyFile != null) {
        await store!.write(
          locator.keyFileHandle,
          base64.encode(setup.keyFile!),
        );
      }
      if (outerKey != null) {
        await store!.write(locator.repositoryKeyHandle, outerKey);
      }

      final container = await TomSecretsDeviceContainer.open(
        deviceContainerPath,
        containerKey,
      );
      await container.write(setup.settings);

      await _writeBootstrap(
        primary: locator.text,
        deviceKey: setup.deviceKey,
        host: setup.host,
      );
      return TomSecretsFirstRunResult(
        bootstrapPath: bootstrapPath,
        created: setup.create,
        deviceKey: mode,
        keysDue: keysDue,
        githubTokenExpires: expires,
      );
    } finally {
      primary.close();
    }
  }

  Future<void> _writeBootstrap({
    required String primary,
    required TomSecretsDeviceKeyMode deviceKey,
    String? host,
  }) async {
    final text = StringBuffer()
      ..writeln('# Written by the first run of Tom Secrets Manager.')
      ..writeln('# Plain text, no secret: the only configuration the service')
      ..writeln('# reads before the unlock (part-service, BP-43).')
      ..writeln('primary: ${_yamlString(primary)}')
      ..writeln('device_key: ${deviceKey.name}');
    if (host != null) text.writeln('host: ${_yamlString(host)}');
    final file = File(bootstrapPath);
    await file.parent.create(recursive: true);
    final temp = File('$bootstrapPath.tmp');
    await temp.writeAsString(text.toString(), flush: true);
    await temp.rename(file.path);
  }
}

/// [value] as a YAML double-quoted scalar.
String _yamlString(String value) => jsonEncode(value);

/// The first bytes of a KDBX file (KeePass 2.x).
const List<int> _kdbxSignature = [
  0x03,
  0xD9,
  0xA2,
  0x9A,
  0x67,
  0xFB,
  0x4B,
  0xB5,
];

/// The first bytes of a `.tsmx` file.
const List<int> _tsmxMagic = [0x54, 0x53, 0x4D, 0x58];

bool _startsWith(Uint8List bytes, List<int> prefix) {
  if (bytes.length < prefix.length) return false;
  for (var i = 0; i < prefix.length; i++) {
    if (bytes[i] != prefix[i]) return false;
  }
  return true;
}

/// The primary's file, wherever it is.
sealed class _Primary {
  _Primary(this.locator, this.outerKey, this.cipher);

  final TomSecretsVaultLocator locator;
  final String? outerKey;
  final TomSecretsOuterCipher cipher;

  Future<void> checkAbsent();

  Future<KdbxFile> open(Credentials credentials);

  Future<void> create(KdbxFile file);

  Future<void> save(KdbxFile file);

  void close() {}

  Future<KdbxFile> decode(Uint8List stored, Credentials credentials) async {
    // tom_kdbx_store passes a damaged file's error on as its library's own
    // type; the signatures tell a file this product does not read first.
    final outer = locator.fileName.endsWith(tomSecretsOuterSuffix);
    if (!_startsWith(stored, outer ? _tsmxMagic : _kdbxSignature)) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.notAVault,
        '${locator.fileName} is not a${outer ? 'n outer-encrypted' : ''} '
        'vault.',
      );
    }
    try {
      return await tomSecretsDecodeStored(
        locator.text,
        stored,
        credentials,
        outerKey: outerKey,
      );
    } on KdbxInvalidKeyException {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.wrongPassword,
        'The master password (with the key file) does not open '
        '${locator.fileName}.',
      );
    } on TomKeyRequiredException {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.repositoryKeyWrong,
        'The repository key given has no key slot in ${locator.fileName}.',
      );
    } on TomSecretsOuterException catch (e) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.repositoryKeyWrong,
        '${locator.fileName} does not open: ${e.message}',
      );
    } on FormatException catch (e) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.notAVault,
        '${locator.fileName} is not a vault: ${e.message}',
      );
    }
  }

  Future<Uint8List> encode(KdbxFile file) => tomSecretsEncodeStored(
    locator.text,
    file,
    outerKey: outerKey,
    cipher: cipher,
  );
}

final class _FilePrimary extends _Primary {
  _FilePrimary(
    TomSecretsFileLocator super.locator,
    super.outerKey,
    super.cipher,
  );

  File get _file => File((locator as TomSecretsFileLocator).path);

  Uint8List? _stored;

  @override
  Future<void> checkAbsent() async {
    if (_file.existsSync()) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.primaryExists,
        '${_file.path} is there already: open it instead, or choose another '
        'name.',
      );
    }
  }

  @override
  Future<KdbxFile> open(Credentials credentials) async {
    if (!_file.existsSync()) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.primaryNotFound,
        'There is no file ${_file.path}.',
      );
    }
    final stored = _stored = await _file.readAsBytes();
    return decode(stored, credentials);
  }

  @override
  Future<void> create(KdbxFile file) => _write(file);

  @override
  Future<void> save(KdbxFile file) => _write(file);

  Future<void> _write(KdbxFile file) async {
    final stored = _stored;
    final bytes = await tomSecretsEncodeStored(
      locator.text,
      file,
      outerKey: outerKey,
      like: stored,
      cipher: cipher,
    );
    await _file.parent.create(recursive: true);
    final temp = File('${_file.path}.tmp');
    await temp.writeAsBytes(bytes, flush: true);
    await temp.rename(_file.path);
  }
}

final class _GitHubPrimary extends _Primary {
  _GitHubPrimary(
    TomSecretsGitHubLocator super.locator,
    super.outerKey,
    super.cipher,
    GitHubApiClient client,
    this.host,
  ) : _storage = TomGitHubStorage.withClient(
        client,
        committer: tomSecretsDeviceCommitter(host),
      );

  final String host;
  final TomGitHubStorage _storage;
  TomSecretsVaultUnit? _unit;

  TomSecretsVaultCodec get _codec =>
      tomSecretsOuterCodecFor(locator.fileName, outerKey, cipher: cipher) ??
      const TomSecretsPlainCodec();

  T _mapped<T>(Object error, StackTrace stack) {
    if (error is TomSecretsFirstRunException) throw error;
    if (error is TomTokenRejectedException ||
        error is TomTokenRequiredException ||
        error is GitHubAuthException) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.tokenRefused,
        'GitHub refused the token for '
        '${(locator as TomSecretsGitHubLocator).repositorySlug}.',
      );
    }
    if (error is GitHubException && error.statusCode == 409) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.repositoryEmpty,
        '${(locator as TomSecretsGitHubLocator).repositorySlug} has no '
        'commit yet: create it with a README, then try again.',
      );
    }
    if (error is GitHubNotFoundException) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.repositoryNotFound,
        'GitHub knows no repository '
        '${(locator as TomSecretsGitHubLocator).repositorySlug} (or branch) '
        'the token can see.',
      );
    }
    if (error is TomUnreachableException ||
        error is SocketException ||
        error is http.ClientException) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.unreachable,
        'GitHub could not be reached: $error',
      );
    }
    Error.throwWithStackTrace(error, stack);
  }

  @override
  Future<void> checkAbsent() async {
    final String? head;
    try {
      head = await _storage.headOf(locator.text);
    } on TomContainerNotFoundException {
      return;
    } on Object catch (e, s) {
      return _mapped(e, s);
    }
    if (head == null) return;
    final exists = await _storage
        .readBytes(locator.text)
        .then((_) => true, onError: (Object _) => false);
    if (exists) {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.primaryExists,
        '${(locator as TomSecretsGitHubLocator).path} is in the repository '
        'already: open it instead, or choose another name.',
      );
    }
  }

  @override
  Future<KdbxFile> open(Credentials credentials) async {
    final Uint8List stored;
    try {
      (stored, _) = await TomSecretsVaultUnit.readAtHead(
        _storage,
        locator.text,
      );
    } on TomContainerNotFoundException {
      throw TomSecretsFirstRunException(
        TomSecretsFirstRunProblem.primaryNotFound,
        'There is no ${(locator as TomSecretsGitHubLocator).path} in '
        '${(locator as TomSecretsGitHubLocator).repositorySlug}.',
      );
    } on Object catch (e, s) {
      return _mapped(e, s);
    }
    // Checked first, so a wrong password is told as such; the unit then
    // reads it once more as the base of the save that may follow.
    await decode(stored, credentials);
    try {
      final unit = _unit = await TomSecretsVaultUnit.open(
        locator: locator.text,
        storage: _storage,
        credentials: credentials,
        device: host,
        codec: _codec,
      );
      return unit.working;
    } on Object catch (e, s) {
      return _mapped(e, s);
    }
  }

  @override
  Future<void> create(KdbxFile file) async {
    try {
      _unit = await TomSecretsVaultUnit.create(
        locator: locator.text,
        storage: _storage,
        file: file,
        device: host,
        codec: _codec,
      );
    } on Object catch (e, s) {
      return _mapped(e, s);
    }
  }

  @override
  Future<void> save(KdbxFile file) async {
    final unit = _unit!;
    try {
      await unit.push();
    } on Object catch (e, s) {
      return _mapped(e, s);
    }
  }

  @override
  void close() {
    final unit = _unit;
    if (unit != null) unawaited(unit.dispose());
    _storage.close();
  }
}

/// Passes requests to [_inner] and keeps the token expiry GitHub reports.
final class _ExpiryRecorder extends http.BaseClient {
  _ExpiryRecorder(this._inner);

  final http.Client _inner;

  /// The expiry reported last, or null.
  DateTime? expiry;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await _inner.send(request);
    final header = response.headers[tomSecretsTokenExpirationHeader];
    if (header != null) expiry = tomSecretsParseTokenExpiration(header);
    return response;
  }

  @override
  void close() => _inner.close();
}
