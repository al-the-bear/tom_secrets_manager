// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `github:` vaults for the service (part-service, part-stores): opened
/// through tom_secrets_core's `TomSecretsVaultUnit` over `TomGitHubStorage`,
/// kept in the offline cache and opened from it when GitHub cannot be reached
/// or refuses the token. The token of each repository is asked for on every
/// request, so a token the user replaces takes effect at the next fetch; the
/// expiry GitHub reports for it (`GitHub-Authentication-Token-Expiration`)
/// is recorded for the key-expiry reminders.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:tom_basics/diagnostics.dart';
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_github_api/tom_github_api.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'vault_set.dart';

/// The GitHub token for [vault]'s repository, or null when there is none.
typedef TomSecretsGitHubTokens =
    Future<String?> Function(TomSecretsGitHubLocator vault);

/// The header GitHub answers a token with an expiry with.
const String tomSecretsTokenExpirationHeader =
    'github-authentication-token-expiration';

/// The time in a `GitHub-Authentication-Token-Expiration` header
/// (`2026-12-01 10:00:00 UTC`, or with a numeric offset), in UTC; null when
/// it cannot be read.
DateTime? tomSecretsParseTokenExpiration(String value) {
  var text = value.trim();
  if (text.endsWith(' UTC')) {
    text = '${text.substring(0, text.length - 4)}Z';
  }
  text = text.replaceFirstMapped(
    RegExp(r'\s+([+-]\d{2}:?\d{2})$'),
    (m) => m[1]!,
  );
  return DateTime.tryParse(text.replaceFirst(' ', 'T'))?.toUtc();
}

/// Opens, reads and writes `github:` vaults.
final class TomSecretsGitHubOpener implements TomSecretsVaultOpener {
  /// An opener committing as [device], asking [tokens] for each repository's
  /// token, keeping the offline cache under [cacheDirectory] while
  /// [useCache] answers true (null: no cache), reaching GitHub at [baseUrl]
  /// through [httpClient] (null: its own).
  TomSecretsGitHubOpener({
    required this.device,
    required this.tokens,
    this.cacheDirectory,
    bool Function()? useCache,
    this.baseUrl = 'https://api.github.com',
    http.Client? httpClient,
    DateTime Function()? clock,
  }) : _useCache = useCache ?? _always,
       _httpClient = httpClient,
       _clock = clock ?? DateTime.now;

  static bool _always() => true;

  /// This device's name, in commit messages.
  final String device;

  /// The token source.
  final TomSecretsGitHubTokens tokens;

  /// The offline cache's directory, or null.
  final String? cacheDirectory;

  /// GitHub's API.
  final String baseUrl;

  final bool Function() _useCache;
  final http.Client? _httpClient;
  final DateTime Function() _clock;
  final Map<String, _Repository> _repositories = {};
  final Map<String, String> _heads = {};
  final Map<String, DateTime> _tokenExpiries = {};

  /// The expiry GitHub reported for each repository's token
  /// (`owner/repository` → UTC), as last seen; a token without an expiry
  /// carries no header and has no entry.
  Map<String, DateTime> get tokenExpiries => Map.unmodifiable(_tokenExpiries);

  static TomSecretsGitHubLocator _parse(String locator) {
    final parsed = TomSecretsVaultLocator.parse(locator);
    if (parsed is! TomSecretsGitHubLocator) {
      throw UnsupportedError('$locator is not a github: vault');
    }
    return parsed;
  }

  _Repository _repository(TomSecretsGitHubLocator vault) => _repositories
      .putIfAbsent(vault.repositorySlug, () => _Repository(this, vault));

  TomSecretsVaultCodec _codec(
    TomSecretsGitHubLocator vault,
    String? outerKey,
  ) =>
      tomSecretsOuterCodecFor(vault.fileName, outerKey) ??
      const TomSecretsPlainCodec();

  @override
  Future<TomSecretsOpenedVault> open(
    String locator,
    Credentials credentials, {
    String? outerKey,
  }) async {
    final vault = _parse(locator);
    final repository = _repository(vault);
    repository.watch.servedOffline = false;
    final unit = await TomSecretsVaultUnit.open(
      locator: locator,
      storage: repository.storage,
      credentials: credentials,
      device: device,
      codec: _codec(vault, outerKey),
      cache: cacheDirectory != null && _useCache()
          ? TomSecretsOfflineCache(Directory(cacheDirectory!))
          : null,
      history: await repository.history(vault.branch),
      clock: () => _clock().toUtc(),
    );
    // The service only reads through the unit: a save goes through
    // [write], so the unit's edit stream is never used.
    await unit.dispose();
    final head = unit.head!;
    _heads[locator] = head;
    // The storage answered from the tree it holds because GitHub did not
    // answer: what was read is the copy held, not a fetch.
    final unanswered = repository.watch.servedOffline
        ? TomUnreachableException(locator, 'GitHub could not be reached')
        : null;
    final cached =
        unit.source == TomSecretsVaultSource.cache || unanswered != null;
    return TomSecretsOpenedVault(
      locator: locator,
      file: unit.working,
      stored: unit.baseBytes,
      revision: head,
      source: cached ? 'cache' : 'github',
      fetchedAt: unit.fetchedAt,
      offlineReason: unit.offlineReason ?? unanswered,
    );
  }

  @override
  Future<String> revision(String locator) async {
    final repository = _repository(_parse(locator));
    repository.watch.servedOffline = false;
    final head = await repository.storage.headOf(locator);
    if (repository.watch.servedOffline) {
      throw TomUnreachableException(locator, 'GitHub could not be reached');
    }
    if (head == null) throw TomContainerNotFoundException(locator);
    return head;
  }

  @override
  Future<Uint8List> read(String locator) async {
    final vault = _parse(locator);
    final (bytes, head) = await TomSecretsVaultUnit.readAtHead(
      _repository(vault).storage,
      locator,
    );
    _heads[locator] = head;
    return bytes;
  }

  @override
  Future<KdbxFile> decode(
    String locator,
    Uint8List stored,
    Credentials credentials, {
    String? outerKey,
  }) async => KdbxFormat().read(
    await _codec(_parse(locator), outerKey).decode(stored),
    credentials,
  );

  @override
  Future<Uint8List> encode(
    String locator,
    KdbxFile file, {
    String? outerKey,
  }) async => _codec(_parse(locator), outerKey).encode(await file.save());

  /// Commits [stored] to [locator] over the head last read or opened there:
  /// a branch that moved since refuses the commit
  /// (`TomCasConflictException`) rather than overwriting what it holds.
  @override
  Future<void> write(String locator, Uint8List stored) async {
    final vault = _parse(locator);
    _heads[locator] = await _repository(vault).storage.commit(
      locator,
      TomChangeset.singleFile(stored),
      expectedHead: _heads[locator],
      message: TomSecretsVaultUnit.commitMessageFor(vault.fileName, device),
    );
  }

  /// Closes the connections.
  void close() {
    for (final r in _repositories.values) {
      r.storage.close();
    }
    _repositories.clear();
    _heads.clear();
  }
}

/// One repository: its storage (one per repository, so each asks for its own
/// token) and its commit reader.
final class _Repository {
  _Repository(this.opener, this.vault) {
    storage = TomGitHubStorage(
      tokens: _RepositoryTokens(this),
      clientFactory: _client,
      committer: tomSecretsDeviceCommitter(opener.device),
      diagnostics: watch,
    );
  }

  final TomSecretsGitHubOpener opener;
  final TomSecretsGitHubLocator vault;
  late final TomGitHubStorage storage;
  final _OfflineWatch watch = _OfflineWatch();

  GitHubApiClient _client(String token) => GitHubApiClient(
    token: token,
    httpClient: _ExpiryRecorder(
      opener._httpClient,
      (expiry) => expiry == null
          ? opener._tokenExpiries.remove(vault.repositorySlug)
          : opener._tokenExpiries[vault.repositorySlug] = expiry,
    ),
    baseUrl: opener.baseUrl,
  );

  /// The commit reader of [branch], when a token is there; without one the
  /// unit merges a moved head as usual (the service never pushes).
  Future<TomSecretsCommitReader?> history(String? branch) async {
    final token = await opener.tokens(vault);
    if (token == null) return null;
    return TomSecretsGitHubCommitReader(
      _client(token),
      vault.owner,
      vault.repository,
      branch: branch,
    );
  }
}

/// Notices the storage serving the tree it holds because GitHub did not
/// answer (`TomGitHubStorage` does that silently, for its editors).
final class _OfflineWatch implements TomDiagnostics {
  bool servedOffline = false;

  @override
  void log(TomDiagnosticEvent event) {
    if (event.operation == 'github.snapshot.served-offline') {
      servedOffline = true;
    }
  }
}

final class _RepositoryTokens extends TomTokenSource {
  _RepositoryTokens(this.repository);

  final _Repository repository;

  @override
  Future<TomToken?> tokenFor(String host) async {
    final secret = await repository.opener.tokens(repository.vault);
    return secret == null ? null : TomToken(host: host, secret: secret);
  }
}

/// Passes requests to [inner] and records the token expiry GitHub reports:
/// an answer that took the token without the header means a token without
/// an expiry.
final class _ExpiryRecorder extends http.BaseClient {
  _ExpiryRecorder(http.Client? inner, this.onExpiry)
    : _inner = inner ?? http.Client(),
      _owned = inner == null;

  final http.Client _inner;
  final bool _owned;
  final void Function(DateTime? expiry) onExpiry;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await _inner.send(request);
    final header = response.headers[tomSecretsTokenExpirationHeader];
    final expiry = header == null
        ? null
        : tomSecretsParseTokenExpiration(header);
    if (expiry != null || response.statusCode ~/ 100 == 2) onExpiry(expiry);
    return response;
  }

  @override
  void close() {
    if (_owned) _inner.close();
  }
}
