// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The relay interface and GitHub as the relay (part-relay): relay ids and
// their services; a pairing hosted on a GitHub repository folder (frames as
// numbered files, polled) running the pairing protocol unchanged, its code
// built from the nameplate, the window taking the first device (relay or
// LAN) and burning the code; the folder deleted by the side that ends
// second, stale folders by the next host; a relay that fails named in the
// error; the mailbox on the inbox folders; no link; a machine set up through
// the relay with its own GitHub token; the TomStorage adapter. In memory,
// demo keys only.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

/// A repository folder in memory: every create a commit.
final class _MemoryFolder implements TomSecretsRelayFolder {
  final Map<String, Uint8List> files = {};
  final List<String> commits = [];

  /// When set, the next create throws it.
  Object? failCreate;

  /// When set, every revision read throws it (GitHub gone while polling).
  Object? failRevision;

  Map<String, Uint8List> _under(String folder) => {
    for (final e in files.entries)
      if (e.key.startsWith('$folder/'))
        e.key.substring(folder.length + 1): e.value,
  };

  @override
  Future<String?> revisionOf(String folder) async {
    final f = failRevision;
    if (f != null) throw f;
    final under = _under(folder);
    if (under.isEmpty) return null;
    final keys = under.keys.toList()..sort();
    return crypto.sha1
        .convert(
          utf8.encode(
            [for (final k in keys) '$k=${under[k]!.length}'].join(';'),
          ),
        )
        .toString();
  }

  @override
  Future<Map<String, String>> list(String folder) async => {
    for (final e in _under(folder).entries) e.key: '${e.value.length}',
  };

  @override
  Future<Uint8List?> read(String path) async => files[path];

  @override
  Future<void> create(
    String path,
    Uint8List bytes, {
    required String message,
  }) async {
    final f = failCreate;
    if (f != null) {
      failCreate = null;
      throw f;
    }
    if (files.containsKey(path)) throw TomSecretsRelayFileExists(path);
    files[path] = bytes;
    commits.add(message);
  }

  @override
  Future<void> deleteFolder(String folder) async {
    final before = files.length;
    files.removeWhere((k, _) => k.startsWith('$folder/'));
    if (files.length != before) commits.add('delete $folder');
  }

  @override
  Future<void> deleteFile(String path) async {
    if (files.remove(path) != null) commits.add('delete $path');
  }
}

final _id = TomSecretsRelayId.parse('github:demo-owner/demo-vaults');

TomSecretsGitHubRelay _relay(
  _MemoryFolder folder, {
  DateTime Function()? clock,
  Random? random,
}) => TomSecretsGitHubRelay(
  _id,
  folder,
  pollInterval: const Duration(milliseconds: 5),
  clock: clock,
  random: random,
);

late TomSecretsPairingPeerKeys _peer;

TomSecretsPairingPeerKeys _keys() => _peer;

void main() {
  setUpAll(() async {
    _peer = TomSecretsPairingPeerKeys(
      linkKey: (await TomSecretsTrust.create('demo').linkKey()).publicKey,
    );
  });

  group('relay ids', () {
    test('the three kinds and their services (part-relay\'s table)', () {
      final github = TomSecretsRelayId.parse('github:owner/repo');
      expect(github.kind, TomSecretsRelayKind.github);
      expect(github.services, {
        TomSecretsRelayService.pairing,
        TomSecretsRelayService.mailbox,
      });
      expect(github.text, 'github:owner/repo');
      expect(
        TomSecretsRelayId.parse('tsm:https://relay.example').services,
        TomSecretsRelayService.values.toSet(),
      );
      expect(
        TomSecretsRelayId.parse(
          'wormhole:wss://relay.example:4000/v1',
        ).services,
        {TomSecretsRelayService.pairing},
      );
      expect(TomSecretsRelayId.github('a', 'b').text, 'github:a/b');
      for (final bad in [
        'github:owner',
        'github:owner/repo/more',
        'tsm:ftp://x',
        'wormhole:https://x',
        'mail:x',
        'nothing',
      ]) {
        expect(
          () => TomSecretsRelayId.parse(bad),
          throwsFormatException,
          reason: bad,
        );
      }
    });
  });

  group('pairing through GitHub', () {
    late _MemoryFolder folder;
    setUp(() => folder = _MemoryFolder());

    test('the pairing protocol runs unchanged over the repository folder; '
        'the folder is gone afterwards', () async {
      final giver = _relay(folder);
      final channel = await giver.host();
      final number = int.parse(channel.nameplate);
      expect(number, inInclusiveRange(1, 999));
      expect(folder.files.keys, ['relay/pair/$number/offer']);
      final code = TomSecretsPairingCode(number, ['guitar', 'orbit']);
      final window = await TomSecretsPairingWindow.open(
        addresses: const [],
        relayChannel: channel,
        code: code,
        device: 'mbp',
        bundleFor: (receiver) async => TomSecretsPairingBundle(
          vaults: [
            TomSecretsPairingVault(
              name: 'primary',
              locator: 'github:demo-owner/demo-vaults/primary.kdbx',
              primary: true,
            ),
          ],
          giverKeys: _keys(),
        ),
      );
      final received = await tomSecretsReceivePairingVia(
        _relay(folder),
        code: TomSecretsPairingCode.parse('$number guitar orbit'),
        device: 'bigbeast',
        keysFor: (giverName, bundle) async {
          expect(giverName, 'mbp');
          return _keys();
        },
      );
      final given = await window.result;
      expect(given.receiver, 'bigbeast');
      expect(received.giver, 'mbp');
      expect(received.bundle.vaults.single.name, 'primary');
      expect(received.tokenKey, given.tokenKey);
      // Each side's frames were files, read in order; the side that ended
      // second deleted the folder.
      await _settle(() => folder.files.isEmpty);
      expect(folder.files, isEmpty);
      expect(
        folder.commits.where((c) => c.contains('frame')).length,
        greaterThanOrEqualTo(8),
      );
      expect(folder.commits.last, 'delete relay/pair/$number');
    });

    test(
      'a wrong code fails at the key confirmation and burns the code',
      () async {
        final channel = await _relay(folder).host();
        final number = int.parse(channel.nameplate);
        final window = await TomSecretsPairingWindow.open(
          addresses: const [],
          relayChannel: channel,
          code: TomSecretsPairingCode(number, ['guitar', 'orbit']),
          device: 'mbp',
          bundleFor: (_) async => fail('no bundle for a wrong code'),
        );
        final outcome = expectLater(
          window.result,
          throwsA(
            isA<TomSecretsPairingException>().having(
              (e) => e.failure,
              'failure',
              TomSecretsPairingFailure.wrongCode,
            ),
          ),
        );
        await expectLater(
          tomSecretsReceivePairingVia(
            _relay(folder),
            code: TomSecretsPairingCode(number, ['guitar', 'ocean']),
            device: 'intruder',
            keysFor: (_, _) async => _keys(),
          ),
          throwsA(isA<TomSecretsPairingException>()),
        );
        await outcome;
        await _settle(() => folder.files.isEmpty);
        // The code is burnt: nobody joins under it any more.
        await expectLater(
          _relay(folder).join('$number'),
          throwsA(isA<TomSecretsRelayException>()),
        );
      },
    );

    test('a LAN connection that comes first takes the code; the relay '
        'pairing is closed and its folder deleted', () async {
      final channel = await _relay(folder).host();
      final number = int.parse(channel.nameplate);
      final code = TomSecretsPairingCode(number, ['guitar', 'orbit']);
      final window = await TomSecretsPairingWindow.open(
        addresses: [InternetAddress.loopbackIPv4],
        allowLoopback: true,
        relayChannel: channel,
        code: code,
        device: 'mbp',
        bundleFor: (_) async =>
            TomSecretsPairingBundle(vaults: const [], giverKeys: _keys()),
      );
      final received = await tomSecretsReceivePairingAt(
        '127.0.0.1',
        window.port,
        code: code,
        device: 'bomber',
        keysFor: (_, _) async => _keys(),
      );
      expect(received.giver, 'mbp');
      expect((await window.result).receiver, 'bomber');
      await _settle(() => folder.files.isEmpty);
      expect(folder.files, isEmpty);
    });

    test('a relay channel must carry the code\'s number', () async {
      final channel = await _relay(folder).host();
      final other = int.parse(channel.nameplate) % 999 + 1;
      await expectLater(
        TomSecretsPairingWindow.open(
          addresses: const [],
          relayChannel: channel,
          code: TomSecretsPairingCode(other, ['guitar', 'orbit']),
          device: 'mbp',
          bundleFor: (_) async => null,
        ),
        throwsArgumentError,
      );
      await channel.close();
    });

    test(
      'joining a nameplate nobody hosts, or an old one, names the relay',
      () async {
        await expectLater(
          _relay(folder).join('77'),
          throwsA(
            isA<TomSecretsRelayException>()
                .having(
                  (e) => e.relay,
                  'relay',
                  'github:demo-owner/demo-vaults',
                )
                .having((e) => e.message, 'message', contains('77')),
          ),
        );
        var now = DateTime.utc(2026, 11, 20, 10);
        final old = await _relay(folder, clock: () => now).host();
        now = now.add(const Duration(hours: 2));
        await expectLater(
          _relay(folder, clock: () => now).join(old.nameplate),
          throwsA(isA<TomSecretsRelayException>()),
        );
        await expectLater(
          _relay(folder).join('1000'),
          throwsA(isA<TomSecretsRelayException>()),
        );
      },
    );

    test('folders older than an hour are deleted by the next host', () async {
      var now = DateTime.utc(2026, 11, 20, 10);
      final first = await _relay(folder, clock: () => now).host();
      // A frame left behind, as by a side that crashed.
      await folder.create(
        'relay/pair/${first.nameplate}/j-0001',
        Uint8List(3),
        message: 'left',
      );
      now = now.add(const Duration(minutes: 61));
      final second = await _relay(folder, clock: () => now).host();
      expect(
        folder.files.keys.where((k) => k.contains('/${first.nameplate}/')),
        isEmpty,
      );
      expect(
        folder.files.keys,
        contains('relay/pair/${second.nameplate}/offer'),
      );
      expect(await _relay(folder, clock: () => now).deleteStale(), 0);
    });

    test('a nameplate in use is not taken twice', () async {
      // A random source that names 5 twice, then 6.
      final random = _Sequence([4, 4, 5]);
      final a = await _relay(folder, random: random).host();
      final b = await _relay(folder, random: random).host();
      expect([a.nameplate, b.nameplate], ['5', '6']);
    });

    test('a relay that fails while pairing is named in the error', () async {
      final channel = await _relay(folder).host();
      final number = int.parse(channel.nameplate);
      final window = await TomSecretsPairingWindow.open(
        addresses: const [],
        relayChannel: channel,
        code: TomSecretsPairingCode(number, ['guitar', 'orbit']),
        device: 'mbp',
        bundleFor: (_) async => null,
      );
      // The joining side's first frame does not get through.
      folder.failCreate = const SocketException('GitHub not reachable');
      await expectLater(
        tomSecretsReceivePairingVia(
          _relay(folder),
          code: TomSecretsPairingCode(number, ['guitar', 'orbit']),
          device: 'bigbeast',
          keysFor: (_, _) async => _keys(),
          timeout: const Duration(seconds: 5),
        ),
        throwsA(
          isA<TomSecretsRelayException>()
              .having((e) => e.relay, 'relay', _id.text)
              .having((e) => e.message, 'message', contains('reachable')),
        ),
      );
      final closed = expectLater(
        window.result,
        throwsA(isA<TomSecretsPairingException>()),
      );
      await window.close();
      await closed;
    });

    test('a relay that fails before anyone came: a window on the LAN stays '
        'open there and says so; one on the relay alone ends', () async {
      final channel = await _relay(folder).host();
      final number = int.parse(channel.nameplate);
      final code = TomSecretsPairingCode(number, ['guitar', 'orbit']);
      folder.failRevision = const SocketException('GitHub not reachable');
      final window = await TomSecretsPairingWindow.open(
        addresses: [InternetAddress.loopbackIPv4],
        allowLoopback: true,
        relayChannel: channel,
        code: code,
        device: 'mbp',
        bundleFor: (_) async =>
            TomSecretsPairingBundle(vaults: const [], giverKeys: _keys()),
      );
      await _settle(() => window.relayError != null);
      expect(
        window.relayError,
        isA<TomSecretsRelayException>().having(
          (e) => e.relay,
          'relay',
          _id.text,
        ),
      );
      final received = await tomSecretsReceivePairingAt(
        '127.0.0.1',
        window.port,
        code: code,
        device: 'bomber',
        keysFor: (_, _) async => _keys(),
      );
      expect(received.giver, 'mbp');
      expect((await window.result).receiver, 'bomber');

      folder.failRevision = null;
      final alone = await _relay(folder).host();
      folder.failRevision = const SocketException('GitHub not reachable');
      final relayOnly = await TomSecretsPairingWindow.open(
        addresses: const [],
        relayChannel: alone,
        code: TomSecretsPairingCode(int.parse(alone.nameplate), [
          'guitar',
          'orbit',
        ]),
        device: 'mbp',
        bundleFor: (_) async => null,
      );
      await expectLater(
        relayOnly.result,
        throwsA(isA<TomSecretsRelayException>()),
      );
      folder.failRevision = null;
    });

    test('GitHub carries no approval link', () async {
      await expectLater(
        _relay(folder).link('abc'),
        throwsA(
          isA<TomSecretsRelayException>().having(
            (e) => e.unsupported,
            'unsupported',
            isTrue,
          ),
        ),
      );
    });
  });

  group('the mailbox through GitHub', () {
    test('put, list, fetch and delete on the inbox folders; an item id is '
        'used once; 30 days at most', () async {
      final folder = _MemoryFolder();
      final relay = _relay(folder);
      final me = await TomSecretsMemberKey.generate();
      final member = me.recipient.fingerprint;
      final name = tomSecretsNewInboxName(now: DateTime.utc(2026, 11, 20));
      await relay.put(
        TomSecretsMailboxItem(
          recipient: member,
          itemId: name,
          bytes: Uint8List.fromList([1, 2, 3]),
          expires: DateTime.now().add(const Duration(days: 30)),
        ),
      );
      expect(folder.files.keys, ['inbox/$member/$name']);
      final listed = await relay.list(me);
      expect(listed.single.itemId, name);
      expect(listed.single.received, DateTime.utc(2026, 11, 20));
      expect(listed.single.expires, DateTime.utc(2026, 12, 20));
      expect(await relay.fetch(me, name), [1, 2, 3]);
      await expectLater(
        relay.put(
          TomSecretsMailboxItem(
            recipient: member,
            itemId: name,
            bytes: Uint8List(1),
            expires: DateTime.now(),
          ),
        ),
        throwsA(isA<TomSecretsRelayException>()),
        reason: 'a replayed item id',
      );
      await expectLater(
        relay.put(
          TomSecretsMailboxItem(
            recipient: member,
            itemId: tomSecretsNewInboxName(),
            bytes: Uint8List(1),
            expires: DateTime.now().add(const Duration(days: 40)),
          ),
        ),
        throwsA(isA<TomSecretsRelayException>()),
      );
      await relay.delete(me, name);
      expect(await relay.list(me), isEmpty);
      // A shared vault in a folder: its inbox beside it.
      final shared = TomSecretsGitHubRelay(
        _id,
        folder,
        mailboxFolder: 'shared',
      );
      await shared.put(
        TomSecretsMailboxItem(
          recipient: member,
          itemId: name,
          bytes: Uint8List(1),
          expires: DateTime.now(),
        ),
      );
      expect(folder.files.keys, ['shared/inbox/$member/$name']);
      expect((await shared.list(me)).single.itemId, name);
      expect(await relay.list(me), isEmpty);
      await expectLater(
        relay.fetch(me, name),
        throwsA(isA<TomSecretsRelayException>()),
      );
    });
  });

  group('a machine set up through the relay', () {
    test('a GitHub primary without a token in the bundle is taken with the '
        'token the machine brought itself', () async {
      final folder = _MemoryFolder();
      TomSecretsPairingBundle bundle() => TomSecretsPairingBundle(
        vaults: [
          TomSecretsPairingVault(
            name: 'primary',
            locator: 'github:demo-owner/demo-vaults/primary.kdbx',
            primary: true,
          ),
        ],
        giverKeys: _keys(),
      );
      expect(tomSecretsPairingSetupProblem(bundle()), contains('token'));
      expect(
        tomSecretsPairingSetupProblem(
          bundle(),
          ownTokens: {'demo-owner/demo-vaults'},
        ),
        isNull,
      );

      final channel = await _relay(folder).host();
      final number = int.parse(channel.nameplate);
      final code = TomSecretsPairingCode(number, ['guitar', 'orbit']);
      final window = await TomSecretsPairingWindow.open(
        addresses: const [],
        relayChannel: channel,
        code: code,
        device: 'mbp',
        bundleFor: (_) async => bundle(),
      );
      final receipt = await tomSecretsReceivePairingForSetup(
        relay: _relay(folder),
        ownTokens: const {'demo-owner/demo-vaults': 'demo-token'},
        code: code,
        device: 'newbox',
      );
      await window.result;
      expect(receipt.tokenFor('demo-owner/demo-vaults')!.token, 'demo-token');
      expect(receipt.primary.name, 'primary');
    });
  });

  group('the relay settings in a shared vault', () {
    test('the mailbox relay is kept in the metadata entry, so every member '
        'reads the same one', () {
      final file = newTestVault(demoCredentials, 'crew');
      final relay = TomSecretsRelayId.parse('tsm:https://relay.example');
      TomSecretsMetadata(
        kind: TomSecretsVaultKind.shared,
        mailboxRelay: relay,
      ).writeTo(file);
      final read = TomSecretsMetadata.read(file);
      expect(read.mailboxRelay, relay);
      read.copyWith(clearMailboxRelay: true).writeTo(file);
      expect(TomSecretsMetadata.read(file).mailboxRelay, isNull);
      tomSecretsMetadataEntry(file)!.setString(
        TomSecretsMetadataFields.mailboxRelay,
        PlainValue('ftp:nothing'),
      );
      expect(
        () => TomSecretsMetadata.read(file),
        throwsA(isA<TomSecretsMetadataException>()),
      );
    });
  });

  group('the TomStorage adapter', () {
    test(
      'files below a base locator: create once, list, read, delete',
      () async {
        final storage = _TreeStorage();
        final folder = TomSecretsStorageRelayFolder(
          storage,
          'github:demo-owner/demo-vaults',
        );
        expect(await folder.revisionOf('relay/pair/5'), isNull);
        expect(await folder.list('relay/pair'), isEmpty);
        await folder.create(
          'relay/pair/5/offer',
          utf8.encode('{}'),
          message: 'open',
        );
        await expectLater(
          folder.create('relay/pair/5/offer', Uint8List(0), message: 'again'),
          throwsA(isA<TomSecretsRelayFileExists>()),
        );
        await folder.create('relay/pair/5/h-0001', Uint8List(2), message: 'f');
        final r1 = await folder.revisionOf('relay/pair/5');
        expect(r1, isNotNull);
        expect((await folder.list('relay/pair')).keys, {'5/offer', '5/h-0001'});
        expect(utf8.decode((await folder.read('relay/pair/5/offer'))!), '{}');
        expect(await folder.read('relay/pair/5/none'), isNull);
        await folder.deleteFile('relay/pair/5/h-0001');
        expect(await folder.revisionOf('relay/pair/5'), isNot(r1));
        await folder.deleteFolder('relay/pair/5');
        expect(await folder.list('relay/pair'), isEmpty);
        expect(
          storage.files.keys,
          isEmpty,
          reason: 'the paths were the base locator\'s',
        );
      },
    );
  });
}

/// Polls [done] until it holds (the other side's clean-up runs a little
/// after the result).
Future<void> _settle(bool Function() done) async {
  for (var i = 0; i < 200 && !done(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

final class _Sequence implements Random {
  _Sequence(this._values);
  final List<int> _values;
  int _i = 0;

  @override
  int nextInt(int max) => _values[_i++ % _values.length];

  @override
  bool nextBool() => false;

  @override
  double nextDouble() => 0;
}

/// A tree-shaped storage like GitHub's: a locator names a file or a folder.
final class _TreeStorage extends TomStorage {
  final Map<String, Uint8List> files = {};
  static const _prefix = 'github:demo-owner/demo-vaults/';

  String _path(String locator) {
    if (!locator.startsWith(_prefix)) throw ArgumentError(locator);
    return locator.substring(_prefix.length);
  }

  Map<String, Uint8List> _under(String path) => {
    for (final e in files.entries)
      if (e.key.startsWith('$path/')) e.key.substring(path.length + 1): e.value,
  };

  @override
  bool handles(String locator) => locator.startsWith('github:');

  @override
  Future<List<TomStorageEntry>> list(String locator) async {
    final path = _path(locator);
    final under = _under(path);
    if (under.isEmpty) throw TomContainerNotFoundException(locator);
    return [
      for (final e in under.entries)
        TomStorageEntry(
          name: e.key.split('/').last,
          path: e.key,
          kind: TomEntryKind.file,
          revision: '${e.value.length}',
        ),
    ];
  }

  @override
  Future<Uint8List> readBytes(String locator) async =>
      files[_path(locator)] ?? (throw TomContainerNotFoundException(locator));

  @override
  Future<TomBundleMedium> readBundle(String locator) =>
      throw UnimplementedError();

  @override
  Future<String> commit(
    String locator,
    TomChangeset changeset, {
    String? expectedHead,
    String? message,
    TomCommitProgressSink? onProgress,
  }) async {
    final path = _path(locator);
    if (expectedHead == null && files.containsKey(path)) {
      throw TomCasConflictException(
        locator,
        expectedHead: null,
        actualHead: 'x',
      );
    }
    files[path] = changeset.containerBytes;
    return 'h${files.length}';
  }

  @override
  Future<void> delete(String locator) async {
    final path = _path(locator);
    files.remove(path);
    files.removeWhere((k, _) => k.startsWith('$path/'));
  }

  @override
  Future<String?> headOf(String locator) async {
    final path = _path(locator);
    if (files.containsKey(path)) return 'f${files[path]!.length}';
    final under = _under(path);
    if (under.isEmpty) return null;
    return (under.keys.toList()..sort()).join(',');
  }
}
