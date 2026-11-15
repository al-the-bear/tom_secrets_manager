// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The check of a new GitHub token before it replaces the old one
/// (part-key-rotation §3, `token.set`): it reaches the vault repository and
/// can write there — a short-lived branch `tsm-token-check-<random>` is
/// created at the default branch's head and deleted again (the vault
/// repositories' only workflow runs on a schedule or by hand, so the branch
/// starts nothing) — and the expiry GitHub reports for it
/// (`GitHub-Authentication-Token-Expiration`).
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;
import 'package:tom_secrets_core/tom_secrets_core.dart';

/// Why a token was refused.
enum TomSecretsTokenProblem {
  /// GitHub refused the token: mistyped, expired or revoked (401).
  refused,

  /// The token does not see the repository (404): it is not granted it.
  noAccess,

  /// The token sees the repository but may not write to it (403/404 on the
  /// branch).
  readOnly,

  /// GitHub could not be reached.
  unreachable,
}

/// A token [check] refused.
final class TomSecretsTokenCheckException implements Exception {
  /// A refusal for [problem].
  const TomSecretsTokenCheckException(this.problem, this.message);

  /// Why.
  final TomSecretsTokenProblem problem;

  /// For the user.
  final String message;

  /// The `denied` reason of `token.set` (protocol.md 6.3).
  String get reason => switch (problem) {
    TomSecretsTokenProblem.refused => 'token_refused',
    TomSecretsTokenProblem.noAccess => 'token_no_access',
    TomSecretsTokenProblem.readOnly => 'token_read_only',
    TomSecretsTokenProblem.unreachable => 'unreachable',
  };

  @override
  String toString() => 'TomSecretsTokenCheckException: $message';
}

/// Checks [token] against the repository [owner]/[repository] on the GitHub
/// API at [baseUrl]: it sees the repository and can create and delete a
/// branch there. Answers the expiry GitHub reported (null: none, a token
/// that does not expire). Throws [TomSecretsTokenCheckException].
Future<DateTime?> tomSecretsCheckGitHubToken({
  required String owner,
  required String repository,
  required String token,
  String baseUrl = 'https://api.github.com',
  http.Client? client,
}) async {
  final transport = client ?? http.Client();
  DateTime? expiry;
  final base = baseUrl.endsWith('/')
      ? baseUrl.substring(0, baseUrl.length - 1)
      : baseUrl;
  final repo = '$base/repos/$owner/$repository';
  final headers = {
    'Authorization': 'Bearer $token',
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };

  Future<_Answer> send(String method, String url, [Object? body]) async {
    final request = _request(method, url, headers, body);
    final http.StreamedResponse streamed;
    try {
      streamed = await transport.send(request);
    } on SocketException catch (e) {
      throw TomSecretsTokenCheckException(
        TomSecretsTokenProblem.unreachable,
        'GitHub could not be reached: ${e.message}',
      );
    } on http.ClientException catch (e) {
      throw TomSecretsTokenCheckException(
        TomSecretsTokenProblem.unreachable,
        'GitHub could not be reached: $e',
      );
    }
    final header = streamed.headers[tomSecretsTokenExpirationHeader];
    if (header != null) expiry = tomSecretsParseTokenExpiration(header);
    final text = await streamed.stream.bytesToString();
    if (streamed.statusCode == 401) {
      throw const TomSecretsTokenCheckException(
        TomSecretsTokenProblem.refused,
        'GitHub refused the token: it may be mistyped, expired or revoked.',
      );
    }
    return _Answer(streamed.statusCode, text);
  }

  try {
    final about = await send('GET', repo);
    if (about.status == 404 || about.status == 403) {
      throw TomSecretsTokenCheckException(
        TomSecretsTokenProblem.noAccess,
        'The token does not see $owner/$repository: grant it this '
        'repository.',
      );
    }
    _expectOk(about, 'reading $owner/$repository');
    final branch = (about.json as Map)['default_branch'] as String;
    final ref = await send('GET', '$repo/git/ref/heads/$branch');
    _expectOk(ref, 'reading the branch $branch');
    final sha = (((ref.json as Map)['object'] as Map)['sha']) as String;
    final random = Random.secure();
    final probe =
        'tsm-token-check-'
        '${List.generate(6, (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0')).join()}';
    final created = await send('POST', '$repo/git/refs', {
      'ref': 'refs/heads/$probe',
      'sha': sha,
    });
    if (created.status == 403 || created.status == 404) {
      throw TomSecretsTokenCheckException(
        TomSecretsTokenProblem.readOnly,
        'The token may read $owner/$repository but not write to it: give '
        'it the permission Contents: Read and write.',
      );
    }
    _expectOk(created, 'creating the check branch');
    final deleted = await send('DELETE', '$repo/git/refs/heads/$probe');
    _expectOk(deleted, 'deleting the check branch $probe');
    return expiry;
  } finally {
    if (client == null) transport.close();
  }
}

http.Request _request(
  String method,
  String url,
  Map<String, String> headers,
  Object? body,
) {
  final request = http.Request(method, Uri.parse(url))..headers.addAll(headers);
  if (body != null) {
    request
      ..headers['Content-Type'] = 'application/json'
      ..body = jsonEncode(body);
  }
  return request;
}

void _expectOk(_Answer answer, String what) {
  if (answer.status >= 200 && answer.status < 300) return;
  throw TomSecretsTokenCheckException(
    TomSecretsTokenProblem.unreachable,
    'GitHub answered ${answer.status} while $what.',
  );
}

final class _Answer {
  _Answer(this.status, this.text);

  final int status;
  final String text;

  Object? get json => text.isEmpty ? null : jsonDecode(text);
}
