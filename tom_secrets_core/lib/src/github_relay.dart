// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** GitHub as the relay (part-relay, 3.): a repository both sides can
/// push to carries the messages as files, beside a vault's file, with no
/// server of our own.
///
/// - **Pairing**, only when the new device reaches the repository already
///   (the user signed it in to GitHub, or pasted a token): the hosting side
///   claims `relay/pair/<nameplate>/offer` (a small JSON, no secret); each
///   side writes its frames as files numbered in order (`h-0001`, … for the
///   host, `j-0001`, … for the joining side), and polls the folder every 2
///   seconds — a conditional request through `TomGitHubStorage`, free while
///   nothing moved. Each side ends with an `h-end` / `j-end` marker; the one
///   that closes second deletes the folder, and folders older than an hour
///   are deleted by the next host. Every frame is a commit; they hold no
///   secret (the PAKE frames reveal nothing about the code, the bundle is
///   sealed under the hybrid session key).
/// - **Mailbox**: the inbox folders of part-sharing,
///   `inbox/<member-id>/<date>-<random>.age`, for members of the same
///   shared repository; expired after 30 days by whichever app syncs next.
/// - **No link**: the approval link needs a standing channel, which a
///   repository is not.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:tom_core_storage/github.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_github_api/tom_github_api.dart' show GitHubApiClient;

import 'member_keys.dart';
import 'relay.dart';
import 'share.dart';
import 'vault_sync.dart' show tomSecretsDeviceCommitter;

/// The files a relay keeps in a repository folder: what the GitHub relay
/// needs of it, so the app can reach it through the service and a machine
/// being set up directly.
abstract interface class TomSecretsRelayFolder {
  /// The revision of [folder] (it changes whenever a file below it does),
  /// or null when nothing is there. Cheap: GitHub answers an unchanged
  /// branch with a conditional request.
  Future<String?> revisionOf(String folder);

  /// The files below [folder] (paths relative to it) with their revisions;
  /// empty when nothing is there.
  Future<Map<String, String>> list(String folder);

  /// The bytes of the file [path], or null when it is not there.
  Future<Uint8List?> read(String path);

  /// Creates the file [path] with [bytes] in one commit; throws
  /// [TomSecretsRelayFileExists] when it is there already.
  Future<void> create(String path, Uint8List bytes, {required String message});

  /// Deletes [folder] with everything below it (one commit); nothing when
  /// it is not there.
  Future<void> deleteFolder(String folder);

  /// Deletes the file [path]; nothing when it is not there.
  Future<void> deleteFile(String path);
}

/// A relay file that exists already ([TomSecretsRelayFolder.create]).
final class TomSecretsRelayFileExists implements Exception {
  /// The file [path].
  const TomSecretsRelayFileExists(this.path);

  /// The file's path.
  final String path;

  @override
  String toString() => 'TomSecretsRelayFileExists: $path';
}

/// A [TomSecretsRelayFolder] over a `tom_core_storage` backend: the files
/// under [base], a container locator (`github:<owner>/<repo>[@<branch>]`,
/// optionally with the vault's folder after it).
final class TomSecretsStorageRelayFolder implements TomSecretsRelayFolder {
  /// The folder [base] of [storage].
  TomSecretsStorageRelayFolder(this.storage, this.base);

  /// The backend.
  final TomStorage storage;

  /// The base locator; the relay's paths follow it after a `/`.
  final String base;

  String _locator(String path) => '$base/$path';

  @override
  Future<String?> revisionOf(String folder) async {
    try {
      return await storage.headOf(_locator(folder));
    } on TomContainerNotFoundException {
      return null;
    }
  }

  @override
  Future<Map<String, String>> list(String folder) async {
    try {
      return {
        for (final e in await storage.list(_locator(folder)))
          if (e.isFile && e.path.isNotEmpty) e.path: e.revision ?? '',
      };
    } on TomContainerNotFoundException {
      return const {};
    }
  }

  @override
  Future<Uint8List?> read(String path) async {
    try {
      return await storage.readBytes(_locator(path));
    } on TomContainerNotFoundException {
      return null;
    }
  }

  @override
  Future<void> create(
    String path,
    Uint8List bytes, {
    required String message,
  }) async {
    try {
      await storage.commit(
        _locator(path),
        TomChangeset.singleFile(bytes),
        message: message,
      );
    } on TomCasConflictException {
      throw TomSecretsRelayFileExists(path);
    }
  }

  @override
  Future<void> deleteFolder(String folder) => storage.delete(_locator(folder));

  @override
  Future<void> deleteFile(String path) => storage.delete(_locator(path));
}

/// The folder of a repository's pairing rendezvous.
const tomSecretsRelayPairFolder = 'relay/pair';

/// How old a pairing folder may get before the next host deletes it.
const tomSecretsRelayStaleAfter = Duration(hours: 1);

/// GitHub as a relay ([TomSecretsRelay]) over a repository: the pairing
/// rendezvous at its root (`relay/pair/…`, the same for both sides, who
/// know only `github:<owner>/<repo>`), the mailbox in the inbox folders
/// beside a shared vault ([mailboxFolder]).
final class TomSecretsGitHubRelay implements TomSecretsRelay {
  /// The relay [id] (`github:<owner>/<repo>`) over [folder], the
  /// repository's root; the mailbox in [mailboxFolder] (the shared vault's
  /// folder, '' for the root); frames are polled every [pollInterval];
  /// [device] names this side in the commit messages.
  TomSecretsGitHubRelay(
    this.id,
    this.folder, {
    this.mailboxFolder = '',
    this.device = 'tsm',
    this.pollInterval = const Duration(seconds: 2),
    Random? random,
    DateTime Function()? clock,
  }) : _random = random ?? Random.secure(),
       _clock = clock ?? DateTime.now {
    if (id.kind != TomSecretsRelayKind.github) {
      throw ArgumentError.value(id, 'id', 'not a GitHub relay');
    }
  }

  /// The relay of [id] reached directly with [token] (a machine being set
  /// up, before any service holds a token), on [branch] (default the
  /// repository's default branch), its mailbox in [mailboxFolder].
  factory TomSecretsGitHubRelay.withToken(
    TomSecretsRelayId id,
    String token, {
    String? branch,
    String mailboxFolder = '',
    String device = 'tsm',
    http.Client? httpClient,
    String baseUrl = 'https://api.github.com',
    Duration pollInterval = const Duration(seconds: 2),
  }) {
    final client = GitHubApiClient(
      token: token,
      httpClient: httpClient,
      baseUrl: baseUrl,
      minMutativeInterval: Duration.zero,
    );
    final storage = TomGitHubStorage.withClient(
      client,
      committer: tomSecretsDeviceCommitter(device),
    );
    final repo = branch == null ? id.address : '${id.address}@$branch';
    return TomSecretsGitHubRelay(
      id,
      TomSecretsStorageRelayFolder(storage, 'github:$repo'),
      mailboxFolder: mailboxFolder,
      device: device,
      pollInterval: pollInterval,
    );
  }

  @override
  final TomSecretsRelayId id;

  /// The repository's root, where the files live.
  final TomSecretsRelayFolder folder;

  /// The folder of the shared vault whose inbox is the mailbox ('' the
  /// root).
  final String mailboxFolder;

  /// This side's name in the commit messages.
  final String device;

  /// How often a pairing channel polls.
  final Duration pollInterval;

  final Random _random;
  final DateTime Function() _clock;

  @override
  Set<TomSecretsRelayService> get services => id.services;

  TomSecretsRelayException _failure(String message) =>
      TomSecretsRelayException(id.text, message);

  Future<T> _guard<T>(String what, Future<T> Function() body) async {
    try {
      return await body();
    } on TomSecretsRelayException {
      rethrow;
    } on TomSecretsRelayFileExists {
      rethrow;
    } on Object catch (e) {
      throw _failure('$what failed: $e');
    }
  }

  String _dir(String nameplate) => '$tomSecretsRelayPairFolder/$nameplate';

  /// Deletes the pairing folders older than [tomSecretsRelayStaleAfter]
  /// (or with no readable offer); answers how many.
  Future<int> deleteStale() => _guard('cleaning up old pairings', () async {
    final files = await folder.list(tomSecretsRelayPairFolder);
    final nameplates = {for (final p in files.keys) p.split('/').first};
    var deleted = 0;
    for (final n in nameplates) {
      final created = await _offerCreated(n);
      if (created == null ||
          _clock().toUtc().difference(created) > tomSecretsRelayStaleAfter) {
        await folder.deleteFolder(_dir(n));
        deleted++;
      }
    }
    return deleted;
  });

  Future<DateTime?> _offerCreated(String nameplate) async {
    final bytes = await folder.read('${_dir(nameplate)}/offer');
    if (bytes == null) return null;
    try {
      final json = jsonDecode(utf8.decode(bytes));
      return json is Map && json['created'] is String
          ? DateTime.tryParse(json['created'] as String)?.toUtc()
          : null;
    } on FormatException {
      return null;
    }
  }

  @override
  Future<TomSecretsPairingChannel> host() =>
      _guard('hosting a pairing', () async {
        try {
          await deleteStale();
        } on TomSecretsRelayException {
          // Old folders stay for the next host; this pairing goes on.
        }
        final used = {
          for (final p in (await folder.list(tomSecretsRelayPairFolder)).keys)
            p.split('/').first,
        };
        for (var attempt = 0; attempt < 8; attempt++) {
          final n = '${1 + _random.nextInt(999)}';
          if (used.contains(n)) continue;
          final offer = utf8.encode(
            jsonEncode({
              'version': 1,
              'created': _clock().toUtc().toIso8601String(),
            }),
          );
          try {
            await folder.create(
              '${_dir(n)}/offer',
              Uint8List.fromList(offer),
              message: 'tsm: pairing $n opened by $device',
            );
          } on TomSecretsRelayFileExists {
            used.add(n);
            continue;
          }
          return _GitHubPairingChannel(this, n, host: true);
        }
        throw _failure('no free nameplate in ${id.text}; try again');
      });

  @override
  Future<TomSecretsPairingChannel> join(String nameplate) =>
      _guard('joining pairing $nameplate', () async {
        final n = int.tryParse(nameplate);
        if (n == null || n < 1 || n > 999) {
          throw _failure('not a nameplate: $nameplate');
        }
        final created = await _offerCreated('$n');
        if (created == null ||
            _clock().toUtc().difference(created) > tomSecretsRelayStaleAfter) {
          throw _failure(
            'no pairing waits under $n in ${id.text}: is the code from a '
            'pairing opened on this relay, and still open?',
          );
        }
        return _GitHubPairingChannel(this, '$n', host: false);
      });

  @override
  Future<TomSecretsPairingChannel> link(String linkId) async =>
      throw TomSecretsRelayException(
        id.text,
        'a GitHub repository carries no approval link; it runs over the VPN, '
        'the LAN or a relay server',
        unsupported: true,
      );

  String _inbox(String member) {
    if (!tomSecretsIsInboxMember(member)) {
      throw _failure('not a member id: $member');
    }
    return mailboxFolder.isEmpty
        ? '$tomSecretsInboxFolder/$member'
        : '$mailboxFolder/$tomSecretsInboxFolder/$member';
  }

  static void _checkItemId(String itemId) {
    if (itemId.isEmpty ||
        itemId.contains('/') ||
        itemId.startsWith('.') ||
        !itemId.endsWith('.age')) {
      throw ArgumentError.value(itemId, 'itemId', 'not an inbox package name');
    }
  }

  @override
  Future<void> put(TomSecretsMailboxItem item) => _guard('putting', () async {
    _checkItemId(item.itemId);
    final days = item.expires.difference(_clock()).inDays;
    if (days > tomSecretsInboxExpiry.inDays) {
      throw _failure('a mailbox item is kept 30 days at most');
    }
    try {
      await folder.create(
        '${_inbox(item.recipient)}/${item.itemId}',
        item.bytes,
        message: 'tsm: a package for ${item.recipient.substring(0, 8)}',
      );
    } on TomSecretsRelayFileExists {
      throw _failure('the item ${item.itemId} is there already');
    }
  });

  @override
  Future<List<TomSecretsMailboxEntry>> list(TomSecretsMemberKey me) =>
      _guard('listing the mailbox', () async {
        final files = await folder.list(_inbox(me.recipient.fingerprint));
        return [
          for (final name in files.keys)
            if (!name.contains('/'))
              TomSecretsMailboxEntry(
                itemId: name,
                received: tomSecretsInboxDate(name),
                expires: tomSecretsInboxDate(name)?.add(tomSecretsInboxExpiry),
              ),
        ]..sort((a, b) => a.itemId.compareTo(b.itemId));
      });

  @override
  Future<Uint8List> fetch(TomSecretsMemberKey me, String itemId) =>
      _guard('fetching $itemId', () async {
        _checkItemId(itemId);
        final bytes = await folder.read(
          '${_inbox(me.recipient.fingerprint)}/$itemId',
        );
        if (bytes == null) throw _failure('the item $itemId is gone');
        return bytes;
      });

  @override
  Future<void> delete(TomSecretsMemberKey me, String itemId) =>
      _guard('deleting $itemId', () async {
        _checkItemId(itemId);
        await folder.deleteFile('${_inbox(me.recipient.fingerprint)}/$itemId');
      });
}

/// A pairing channel through a repository folder: this side's frames as
/// numbered files, the other side's polled.
final class _GitHubPairingChannel implements TomSecretsPairingChannel {
  _GitHubPairingChannel(this.relay, this.nameplate, {required this.host})
    : _dir = '$tomSecretsRelayPairFolder/$nameplate' {
    unawaited(_poll());
  }

  final TomSecretsGitHubRelay relay;

  @override
  final String nameplate;

  /// Whether this is the hosting side.
  final bool host;

  final String _dir;
  final StreamController<List<int>> _in = StreamController();
  final Completer<void> _joined = Completer();
  Future<void> _writes = Future.value();
  Object? _writeError;
  int _sent = 0;
  int _received = 0;
  bool _closed = false;
  bool _otherEnded = false;

  String get _mine => host ? 'h' : 'j';
  String get _theirs => host ? 'j' : 'h';

  static String _seq(int n) => n.toString().padLeft(4, '0');

  @override
  Stream<List<int>> get incoming => _in.stream;

  @override
  Future<void> get joined => _joined.future;

  @override
  void send(List<int> bytes) {
    if (_closed) return;
    final seq = ++_sent;
    final copy = Uint8List.fromList(bytes);
    _writes = _writes.then((_) async {
      if (_writeError != null) return;
      try {
        await relay.folder.create(
          '$_dir/$_mine-${_seq(seq)}',
          copy,
          message: 'tsm: pairing $nameplate, frame $seq',
        );
      } on Object catch (e) {
        _writeError = e;
        _fail('writing a frame failed: $e');
      }
    });
  }

  void _fail(String message) {
    final error = TomSecretsRelayException(relay.id.text, message);
    if (!_joined.isCompleted) {
      _joined.completeError(error);
      // Observed by whoever waits on it; never an unhandled error.
      unawaited(_joined.future.catchError((Object _) {}));
    }
    if (_in.isClosed) return;
    _in.addError(error);
    unawaited(_in.close());
  }

  Future<void> _poll() async {
    String? seen;
    while (!_closed && !_in.isClosed) {
      try {
        final revision = await relay.folder.revisionOf(_dir);
        if (revision == null) {
          // The folder is gone: the other side closed and cleaned up.
          if (_received > 0 || _otherEnded) {
            unawaited(_in.close());
          } else {
            _fail('the pairing $nameplate is gone from ${relay.id.text}');
          }
          return;
        }
        if (revision != seen) {
          seen = revision;
          final files = await relay.folder.list(_dir);
          while (files.containsKey('$_theirs-${_seq(_received + 1)}')) {
            final bytes = await relay.folder.read(
              '$_dir/$_theirs-${_seq(_received + 1)}',
            );
            if (bytes == null) break;
            _received++;
            if (!_joined.isCompleted) _joined.complete();
            if (!_in.isClosed) _in.add(bytes);
          }
          if (files.containsKey('$_theirs-end')) {
            _otherEnded = true;
            unawaited(_in.close());
            return;
          }
        }
      } on Object catch (e) {
        _fail('polling failed: $e');
        return;
      }
      await Future<void>.delayed(relay.pollInterval);
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _writes;
    try {
      final files = await relay.folder.list(_dir);
      final theirs = files.keys.any((p) => p.startsWith('$_theirs-'));
      if (_otherEnded ||
          files.containsKey('$_theirs-end') ||
          (host && !theirs)) {
        // The other side ended first, or nobody joined: this side cleans up.
        await relay.folder.deleteFolder(_dir);
      } else if (files.isNotEmpty) {
        await relay.folder.create(
          '$_dir/$_mine-end',
          Uint8List(0),
          message: 'tsm: pairing $nameplate, ${host ? 'host' : 'guest'} done',
        );
      }
    } on Object {
      // Left for the next host's clean-up (an hour).
    }
    if (!_in.isClosed) unawaited(_in.close());
  }
}
