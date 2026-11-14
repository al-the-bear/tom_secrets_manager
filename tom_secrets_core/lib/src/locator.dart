// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Vault locators (part-stores): `file:<absolute path>`,
/// `github:<owner>/<repo>[@<branch>]/<path>`, and
/// `git:<https url>[@<branch>]/<path>` (recognised, not advertised in
/// phase A).
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;

/// A locator that cannot be read.
final class TomSecretsLocatorException implements Exception {
  /// A locator problem described by [message].
  TomSecretsLocatorException(this.message);

  /// What is wrong.
  final String message;

  @override
  String toString() => 'TomSecretsLocatorException: $message';
}

/// Where a vault is.
sealed class TomSecretsVaultLocator {
  const TomSecretsVaultLocator();

  /// Reads [text].
  factory TomSecretsVaultLocator.parse(String text) {
    if (text.startsWith('file:')) {
      final path = text.substring(5);
      final absolute =
          path.startsWith('/') || RegExp(r'^[A-Za-z]:[\\/]').hasMatch(path);
      if (!absolute) {
        throw TomSecretsLocatorException(
          'a file: locator needs an absolute path',
        );
      }
      return TomSecretsFileLocator(path);
    }
    if (text.startsWith('github:')) {
      final match = RegExp(
        r'^github:([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)(?:@([^/]+))?/(.+)$',
      ).firstMatch(text);
      if (match == null) {
        throw TomSecretsLocatorException(
          'a github: locator is github:<owner>/<repo>[@<branch>]/<path>',
        );
      }
      final path = match[4]!;
      if (path.split('/').any((s) => s.isEmpty || s == '.' || s == '..')) {
        throw TomSecretsLocatorException(
          'the path of $text is not a file path',
        );
      }
      return TomSecretsGitHubLocator(
        owner: match[1]!,
        repository: match[2]!,
        branch: match[3],
        path: path,
      );
    }
    if (text.startsWith('git:https://')) return TomSecretsGitLocator(text);
    throw TomSecretsLocatorException('not a vault locator: $text');
  }

  /// The locator as written.
  String get text;

  /// The vault file's name (`fleet.kdbx`).
  String get fileName;

  /// The vault's identity: the locator without a branch, so a key kept for
  /// the vault holds whichever branch is read.
  String get vaultIdentity => text;

  /// The identity of the repository the vault is in: its GitHub
  /// repository, or for a `file:` vault its folder. The outer layer's
  /// repository key belongs to it (part-stores, BP-18).
  String get repositoryIdentity;

  /// The device keychain's handle of the vault's key file (part-stores: on a
  /// device the key file is kept in the keychain).
  String get keyFileHandle => tomSecretsKeyFileHandle(this);

  /// The device keychain's handle of the repository key of the vault's
  /// repository.
  String get repositoryKeyHandle => tomSecretsRepositoryKeyHandle(this);

  @override
  String toString() => text;
}

/// A KDBX file on this device.
final class TomSecretsFileLocator extends TomSecretsVaultLocator {
  /// The file at [path].
  const TomSecretsFileLocator(this.path);

  /// The absolute path.
  final String path;

  @override
  String get text => 'file:$path';

  @override
  String get fileName => path.split(RegExp(r'[/\\]')).last;

  @override
  String get repositoryIdentity =>
      'file:${path.substring(0, path.length - fileName.length)}';
}

/// A KDBX file in a private GitHub repository, read and written through the
/// REST API (DP-81).
final class TomSecretsGitHubLocator extends TomSecretsVaultLocator {
  /// The file [path] in [owner]/[repository] on [branch] (null: the default
  /// branch).
  const TomSecretsGitHubLocator({
    required this.owner,
    required this.repository,
    required this.path,
    this.branch,
  });

  /// The repository's owner.
  final String owner;

  /// The repository's name.
  final String repository;

  /// The branch, or null for the default branch.
  final String? branch;

  /// The file's path in the repository.
  final String path;

  @override
  String get text =>
      'github:$owner/$repository${branch == null ? '' : '@$branch'}/$path';

  @override
  String get fileName => path.split('/').last;

  @override
  String get vaultIdentity => 'github:$owner/$repository/$path';

  @override
  String get repositoryIdentity => 'github:$owner/$repository';

  /// `owner/repository`.
  String get repositorySlug => '$owner/$repository';

  /// The handle of the repository's GitHub token in the device keychain
  /// (`TomSecretStore`): one token per repository (part-stores).
  String get tokenHandle => tomSecretsGitHubTokenHandle(owner, repository);

  /// The keychain handle of the expiry recorded with that token.
  String get tokenExpiryHandle =>
      tomSecretsGitHubTokenExpiryHandle(owner, repository);
}

/// The device keychain's handle of the GitHub token for [owner]/[repository].
String tomSecretsGitHubTokenHandle(String owner, String repository) =>
    'tsm.github-token.$owner:$repository';

/// The device keychain's handle of the expiry (ISO 8601) recorded with the
/// GitHub token for [owner]/[repository] when it was entered.
String tomSecretsGitHubTokenExpiryHandle(String owner, String repository) =>
    'tsm.github-token-expiry.$owner:$repository';

/// The device keychain's handle of the key file of the vault at [locator]:
/// `tsm.key-file.<id>`, the id the first 16 hex digits of SHA-256 over the
/// vault's identity (an OS keychain refuses `/` in an item's name).
String tomSecretsKeyFileHandle(TomSecretsVaultLocator locator) =>
    'tsm.key-file.${_handleId(locator.vaultIdentity)}';

/// The device keychain's handle of the repository key (base64) of the
/// repository the vault at [locator] is in: `tsm.repository-key.<id>`, the
/// id as for [tomSecretsKeyFileHandle] over the repository's identity.
String tomSecretsRepositoryKeyHandle(TomSecretsVaultLocator locator) =>
    'tsm.repository-key.${_handleId(locator.repositoryIdentity)}';

String _handleId(String identity) =>
    crypto.sha256.convert(utf8.encode(identity)).toString().substring(0, 16);

/// A KDBX file on another git server over smart HTTP; recognised, not
/// advertised in phase A.
final class TomSecretsGitLocator extends TomSecretsVaultLocator {
  /// The locator [text].
  const TomSecretsGitLocator(this.text);

  @override
  final String text;

  @override
  String get fileName => text.split('/').last;

  @override
  String get repositoryIdentity =>
      text.substring(0, text.length - fileName.length - 1);
}
