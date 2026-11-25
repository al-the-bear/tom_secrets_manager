// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Pairing (part-sharing, DP-60, DP-177): SPAKE2 against RFC 9382's test
/// vectors, the pairing code, and the whole pairing over an in-memory
/// channel: the bundle delivered and the receiving side's keys back, the
/// same approval-token key on both sides, a wrong code burnt at the key
/// confirmation, a declined device, a tampered frame refused. Demo data
/// only.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

Uint8List _hex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);

String _toHex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Two ends of an in-memory channel; [tamper] may change the frames A sends.
final class _Pipe implements TomSecretsApprovalChannel {
  _Pipe(this._in, this._out, [this.tamper]);

  final StreamController<List<int>> _in;
  final StreamController<List<int>> _out;
  final List<int> Function(List<int> bytes)? tamper;

  static (_Pipe, _Pipe) pair({List<int> Function(List<int>)? tamperA}) {
    final a = StreamController<List<int>>();
    final b = StreamController<List<int>>();
    return (_Pipe(a, b, tamperA), _Pipe(b, a));
  }

  @override
  Stream<List<int>> get incoming => _in.stream;

  @override
  void send(List<int> bytes) {
    if (!_out.isClosed) _out.add(tamper?.call(bytes) ?? bytes);
  }

  @override
  Future<void> close() async {
    if (!_out.isClosed) await _out.close();
  }
}

Future<TomSecretsPairingBundle> _bundle() async => TomSecretsPairingBundle(
  vaults: [
    const TomSecretsPairingVault(
      name: 'primary',
      locator: 'github:al-the-bear/demo-vaults/primary.kdbx.tsmx',
      primary: true,
      repositoryKey: 'ZGVtby1yZXBvc2l0b3J5LWtleS0wMDAwMDAwMDAwMDA=',
    ),
    TomSecretsPairingVault(
      name: 'team',
      locator: 'github:al-the-bear/demo-vaults/team.kdbx',
      keyFile: TomSecretsKeyFile.generate().toBytes(),
    ),
  ],
  giverKeys: TomSecretsPairingPeerKeys(
    linkKey: (await TomSecretsTrust.create('mbp').linkKey()).publicKey,
    approverKey: (await TomSecretsTrust.create('mbp').approverKey()).publicKey,
    linkAddress: '10.8.0.7:47731',
  ),
  configYaml: 'dimensions: [host]\n',
  tokens: [
    TomSecretsPairingToken(
      repository: 'al-the-bear/demo-vaults',
      token: 'github_pat_demo_for_bigbeast',
      expires: DateTime.utc(2027, 2, 1),
    ),
  ],
);

void main() {
  group('SPAKE2 (RFC 9382, Appendix B)', () {
    final vectors =
        (jsonDecode(
                  File('test/fixtures/rfc9382_vectors.json').readAsStringSync(),
                )
                as Map)['vectors']!
            as List;
    for (final v in vectors.cast<Map>()) {
      test("A='${v['A']}', B='${v['B']}'", () {
        BigInt big(String key) => BigInt.parse(v[key] as String, radix: 16);
        final a = utf8.encode(v['A'] as String);
        final b = utf8.encode(v['B'] as String);
        TomSecretsSpake2.withAad('', () {
          final sideA = TomSecretsSpake2.a(big('w'), a: a, b: b, x: big('x'));
          final sideB = TomSecretsSpake2.b(big('w'), a: a, b: b, y: big('y'));
          expect(_toHex(sideA.message), v['pA']);
          expect(_toHex(sideB.message), v['pB']);
          final keysA = sideA.finish(sideB.message);
          final keysB = sideB.finish(sideA.message);
          expect(_toHex(keysA.tt), v['TT']);
          expect(_toHex(keysB.tt), v['TT']);
          expect(_toHex(keysA.ke), v['Ke']);
          expect(_toHex(keysA.confirmA), v['A conf']);
          expect(_toHex(keysA.confirmB), v['B conf']);
          expect(_toHex(keysB.confirmA), v['A conf']);
          expect(_toHex(keysB.confirmB), v['B conf']);
        });
      });
    }

    test('a message that is no point of the curve is refused', () {
      final a = TomSecretsSpake2.a(BigInt.two, a: const [], b: const []);
      final valid = TomSecretsSpake2.b(
        BigInt.two,
        a: const [],
        b: const [],
      ).message;
      for (final bad in [
        _hex('04${'00' * 64}'),
        [...valid]..[64] ^= 1, // y changed: off the curve
        valid.sublist(0, 33), // not uncompressed
        <int>[],
      ]) {
        expect(() => a.finish(bad), throwsA(isA<FormatException>()));
      }
      expect(() => a.finish(valid), returnsNormally);
    });
  });

  group('the code', () {
    test('<number>-<word>-<word>, parsed loosely, refused otherwise', () {
      final code = TomSecretsPairingCode.generate(random: Random(7));
      expect(code.text, matches(RegExp(r'^\d{1,3}-[a-z]+-[a-z]+$')));
      expect(
        TomSecretsPairingCode.parse('  ${code.text.toUpperCase()} ').text,
        code.text,
      );
      expect(
        TomSecretsPairingCode.parse('7 guitar  orbit').text,
        '7-guitar-orbit',
      );
      for (final bad in [
        '',
        '7-guitar',
        '0-guitar-orbit',
        '7-guitar-xyzzy',
        'x-guitar-orbit',
      ]) {
        expect(() => TomSecretsPairingCode.parse(bad), throwsFormatException);
      }
      expect(tomSecretsPairingWords.toSet(), hasLength(256));
      expect(code.w, isNot(TomSecretsPairingCode.parse('7-guitar-orbit').w));
    });
  });

  group('a pairing', () {
    final code = TomSecretsPairingCode.parse('7-guitar-orbit');

    Future<TomSecretsPairingPeerKeys> receiverKeys() async {
      final trust = TomSecretsTrust.create('bigbeast');
      return TomSecretsPairingPeerKeys(
        linkKey: (await trust.linkKey()).publicKey,
        approverKey: (await trust.approverKey()).publicKey,
        linkAddress: '10.8.0.1:47731',
      );
    }

    test('the bundle reaches the receiver, its keys reach the giver; both '
        'derive the same approval-token key', () async {
      final (a, b) = _Pipe.pair();
      final bundle = await _bundle();
      final mine = await receiverKeys();
      String? askedFor;
      final giving = tomSecretsGivePairing(
        b,
        code: code,
        device: 'mbp',
        bundleFor: (receiver) async {
          askedFor = receiver;
          return bundle;
        },
      );
      String? giverSeen;
      final received = await tomSecretsReceivePairing(
        a,
        code: TomSecretsPairingCode.parse('7 GUITAR orbit'),
        device: 'bigbeast',
        keysFor: (giver, bundle) async {
          giverSeen = giver;
          return mine;
        },
      );
      final given = await giving;
      expect(askedFor, 'bigbeast');
      expect(giverSeen, 'mbp');
      expect(received.giver, 'mbp');
      expect(given.receiver, 'bigbeast');
      expect(received.tokenKey, hasLength(32));
      expect(received.tokenKey, given.tokenKey);
      expect(jsonEncode(received.bundle.toJson()), jsonEncode(bundle.toJson()));
      expect(received.bundle.vaults[1].keyFile, bundle.vaults[1].keyFile);
      expect(
        received.bundle.tokens.single.token,
        'github_pat_demo_for_bigbeast',
      );
      expect(given.receiverKeys.approverKey!.keyId, mine.approverKey!.keyId);
      expect(given.receiverKeys.linkAddress, '10.8.0.1:47731');
      expect(
        given.receiverPlatform,
        Platform.operatingSystem,
        reason: 'the receiver names its platform in its done answer',
      );
    });

    test('the receiver\'s platform in done: named, or left out when it is '
        'no platform name', () async {
      Future<String?> pairAs(String platform) async {
        final (a, b) = _Pipe.pair();
        final bundle = await _bundle();
        final mine = await receiverKeys();
        final giving = tomSecretsGivePairing(
          b,
          code: code,
          device: 'mbp',
          bundleFor: (receiver) async => bundle,
        );
        await tomSecretsReceivePairing(
          a,
          code: TomSecretsPairingCode.parse('7 GUITAR orbit'),
          device: 'phone',
          platform: platform,
          keysFor: (giver, bundle) async => mine,
        );
        return (await giving).receiverPlatform;
      }

      expect(await pairAs('android'), 'android');
      expect(await pairAs('ios'), 'ios');
      expect(await pairAs('Not A Platform!'), isNull);
    });

    test('a wrong code fails at the key confirmation on both sides', () async {
      final (a, b) = _Pipe.pair();
      var asked = false;
      final giving = tomSecretsGivePairing(
        b,
        code: code,
        device: 'mbp',
        bundleFor: (_) async {
          asked = true;
          return _bundle();
        },
      );
      final receiving = tomSecretsReceivePairing(
        a,
        code: TomSecretsPairingCode.parse('7-guitar-orchid'),
        device: 'bigbeast',
        keysFor: (_, _) => receiverKeys(),
      );
      await expectLater(
        giving,
        throwsA(
          isA<TomSecretsPairingException>().having(
            (e) => e.failure,
            'failure',
            TomSecretsPairingFailure.wrongCode,
          ),
        ),
      );
      await expectLater(
        receiving,
        throwsA(
          isA<TomSecretsPairingException>().having(
            (e) => e.failure,
            'failure',
            TomSecretsPairingFailure.wrongCode,
          ),
        ),
      );
      expect(asked, isFalse, reason: 'nothing is offered before the code');
    });

    test('a declined device gets nothing', () async {
      final (a, b) = _Pipe.pair();
      final giving = expectLater(
        tomSecretsGivePairing(
          b,
          code: code,
          device: 'mbp',
          bundleFor: (_) async => null,
        ),
        throwsA(isA<TomSecretsPairingException>()),
      );
      var stored = false;
      await expectLater(
        tomSecretsReceivePairing(
          a,
          code: code,
          device: 'bigbeast',
          keysFor: (_, _) async {
            stored = true;
            return receiverKeys();
          },
        ),
        throwsA(
          isA<TomSecretsPairingException>().having(
            (e) => e.failure,
            'failure',
            TomSecretsPairingFailure.declined,
          ),
        ),
      );
      await giving;
      expect(stored, isFalse);
    });

    test('a tampered frame under the pairing key is refused', () async {
      var frames = 0;
      final (a, b) = _Pipe.pair(
        tamperA: (bytes) {
          frames++;
          // The fourth frame A sends is its ML-KEM encapsulation key, the
          // first under the SPAKE2 key: one bit flipped.
          if (frames != 4) return bytes;
          return [...bytes]..[bytes.length - 1] ^= 1;
        },
      );
      final giving = tomSecretsGivePairing(
        b,
        code: code,
        device: 'mbp',
        bundleFor: (_) => _bundle(),
        timeout: const Duration(seconds: 3),
      );
      final receiving = tomSecretsReceivePairing(
        a,
        code: code,
        device: 'bigbeast',
        keysFor: (_, _) => receiverKeys(),
        timeout: const Duration(seconds: 3),
      );
      await expectLater(
        giving,
        throwsA(
          isA<TomSecretsPairingException>().having(
            (e) => e.failure,
            'failure',
            TomSecretsPairingFailure.protocol,
          ),
        ),
      );
      await expectLater(receiving, throwsA(isA<TomSecretsPairingException>()));
    });
  });

  group('the pairing window over TCP', () {
    final code = TomSecretsPairingCode.parse('12-cedar-orbit');
    final loopback = [InternetAddress.loopbackIPv4];

    Future<TomSecretsPairingPeerKeys> keys() async {
      final trust = TomSecretsTrust.create('bigbeast');
      return TomSecretsPairingPeerKeys(
        linkKey: (await trust.linkKey()).publicKey,
      );
    }

    test(
      'the first connection pairs; the window then refuses others',
      () async {
        final window = await TomSecretsPairingWindow.open(
          addresses: loopback,
          allowLoopback: true,
          code: code,
          device: 'mbp',
          bundleFor: (_) => _bundle(),
        );
        final received = await tomSecretsReceivePairingAt(
          '127.0.0.1',
          window.port,
          code: code,
          device: 'bigbeast',
          keysFor: (_, _) => keys(),
        );
        final given = await window.result;
        expect(received.tokenKey, given.tokenKey);
        expect(given.receiver, 'bigbeast');
        await expectLater(
          tomSecretsReceivePairingAt(
            '127.0.0.1',
            window.port,
            code: code,
            device: 'intruder',
            keysFor: (_, _) => keys(),
          ),
          throwsA(isA<TomSecretsPairingException>()),
        );
      },
    );

    test('a wrong code burns the window', () async {
      final window = await TomSecretsPairingWindow.open(
        addresses: loopback,
        allowLoopback: true,
        code: code,
        device: 'mbp',
        bundleFor: (_) => _bundle(),
      );
      final result = expectLater(
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
        tomSecretsReceivePairingAt(
          '127.0.0.1',
          window.port,
          code: TomSecretsPairingCode.parse('12-cedar-otter'),
          device: 'bigbeast',
          keysFor: (_, _) => keys(),
        ),
        throwsA(isA<TomSecretsPairingException>()),
      );
      await result;
      // The right code now finds nothing.
      await expectLater(
        tomSecretsReceivePairingAt(
          '127.0.0.1',
          window.port,
          code: code,
          device: 'bigbeast',
          keysFor: (_, _) => keys(),
        ),
        throwsA(isA<TomSecretsPairingException>()),
      );
    });

    test(
      'the window ends after its time; only LAN and VPN addresses',
      () async {
        final window = await TomSecretsPairingWindow.open(
          addresses: loopback,
          allowLoopback: true,
          code: code,
          device: 'mbp',
          bundleFor: (_) => _bundle(),
          window: const Duration(milliseconds: 200),
        );
        await expectLater(
          window.result,
          throwsA(
            isA<TomSecretsPairingException>().having(
              (e) => e.failure,
              'failure',
              TomSecretsPairingFailure.closed,
            ),
          ),
        );
        await expectLater(
          TomSecretsPairingWindow.open(
            addresses: loopback,
            code: code,
            device: 'mbp',
            bundleFor: (_) => _bundle(),
          ),
          throwsArgumentError,
          reason: 'loopback is no LAN address',
        );
        for (final (text, ok) in [
          ('10.8.0.7', true),
          ('192.168.1.20', true),
          ('172.20.0.3', true),
          ('172.32.0.3', false),
          ('8.8.8.8', false),
          ('127.0.0.1', false),
          ('fd12::1', true),
          ('2001:db8::1', false),
        ]) {
          expect(
            tomSecretsIsPairingAddress(InternetAddress(text)),
            ok,
            reason: text,
          );
        }
      },
    );
  });

  group('the device records', () {
    test('put, updated when paired again, revoked; never resolved', () {
      final file = tomSecretsNewVault(
        Credentials(ProtectedValue.fromString('demo-master')),
        'primary',
        argon2: testArgon2,
      );
      final records = TomSecretsDeviceRecords(file);
      final at = DateTime.utc(2026, 11, 15, 12);
      records.put(
        TomSecretsDeviceRecord(
          device: 'bigbeast',
          platform: 'linux',
          paired: at,
          pairedBy: 'mbp',
          keyIds: const ['0123abcd'],
          linkKeySince: at,
        ),
      );
      records.put(
        TomSecretsDeviceRecord(
          device: 'bigbeast',
          platform: 'linux',
          paired: at.add(const Duration(days: 1)),
          pairedBy: 'mbp',
          keyIds: const ['0123abcd', '4567ef01'],
          approverKeyId: 'feedbeef',
          approverKeySince: at,
          linkKeySince: at,
        ),
      );
      expect(records.list(), hasLength(1), reason: 'updated, not duplicated');
      final r = records.byDevice('bigbeast')!;
      expect(r.keyIds, ['0123abcd', '4567ef01']);
      expect(r.approverKeyId, 'feedbeef');
      expect(r.isRevoked, isFalse);
      expect(
        records.revoke('bigbeast', at.add(const Duration(days: 2))),
        isTrue,
      );
      expect(
        records.byDevice('bigbeast')!.revoked,
        at.add(const Duration(days: 2)),
      );
      expect(records.revoke('nobody', at), isFalse);
      final store = TomSecretsStore.fromFile(file, name: 'primary');
      expect(store.entries.where((e) => e.entry.label == 'bigbeast'), isEmpty);
    });

    test("a device's GitHub kind and token expiry (DP-83): recorded, kept "
        'through a revocation, only for a recorded device', () {
      final file = tomSecretsNewVault(
        Credentials(ProtectedValue.fromString('demo-master')),
        'primary',
        argon2: testArgon2,
      );
      final records = TomSecretsDeviceRecords(file);
      final at = DateTime.utc(2026, 11, 15, 12);
      records.put(TomSecretsDeviceRecord(device: 'phone', paired: at));
      final expires = DateTime.utc(2027, 5, 15);
      expect(
        records.setGitHub('phone', TomSecretsGitHubAuth.app, expires),
        isTrue,
      );
      expect(
        records.setGitHub('phone', TomSecretsGitHubAuth.app, expires),
        isFalse,
        reason: 'unchanged',
      );
      expect(
        records.setGitHub('nobody', TomSecretsGitHubAuth.token, at),
        isFalse,
      );
      records.revoke('phone', at);
      final r = records.byDevice('phone')!;
      expect(r.githubAuth, TomSecretsGitHubAuth.app);
      expect(r.githubTokenExpires, expires);
      expect(r.toJson()['githubAuth'], 'app');
    });

    test("the GitHub App's client id in the primary's metadata", () {
      final file = tomSecretsNewVault(
        Credentials(ProtectedValue.fromString('demo-master')),
        'primary',
        argon2: testArgon2,
      );
      expect(TomSecretsMetadata.read(file).githubAppClientId, isNull);
      TomSecretsMetadata.read(
        file,
      ).copyWith(githubAppClientId: 'Iv23demoClientId').writeTo(file);
      expect(
        TomSecretsMetadata.read(file).githubAppClientId,
        'Iv23demoClientId',
      );
      TomSecretsMetadata.read(
        file,
      ).copyWith(clearGithubAppClientId: true).writeTo(file);
      expect(TomSecretsMetadata.read(file).githubAppClientId, isNull);
    });
  });
}
