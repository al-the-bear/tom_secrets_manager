// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The core's signed objects, approval codes and approval link against the
/// protocol's vectors (protocol.md 9.9: signatures.json,
/// approval_codes.json, link_handshake.json), and a link session end to end
/// over an in-memory channel; the grants group and the trust material.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
// The vectors fix the encapsulation coins, which only the backend takes.
// ignore: implementation_imports
import 'package:tom_pqc/src/pqc_backend.dart' show pqcBackend;
import 'package:tom_pqc/tom_pqc.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const _vectors = '../../secrets_clients/protocol/vectors';

Map<String, Object?> _load(String name) =>
    (jsonDecode(File('$_vectors/$name.json').readAsStringSync()) as Map)
        .cast<String, Object?>();

Uint8List _b(Object? text) => base64.decode(text! as String);

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// The vectors' randomness: fixed ephemeral seeds and encapsulation coins.
final class _FixedRandom implements TomSecretsLinkRandom {
  _FixedRandom(this.x25519Seed, this.mlKemSeed, this.coins);

  final Uint8List x25519Seed;
  final Uint8List? mlKemSeed;
  final List<Uint8List> coins;

  @override
  Future<SimpleKeyPair> ephemeralX25519() =>
      X25519().newKeyPairFromSeed(x25519Seed);

  @override
  MlKem768KeyPair ephemeralMlKem() =>
      MlKem768.keyPairFromSeed(SecretBytes.fromBytes(mlKemSeed!));

  @override
  MlKem768Encapsulation encapsulate(Uint8List publicKey) =>
      pqcBackend.mlKem768Encapsulate(publicKey, coins: coins.removeAt(0));
}

/// Two ends of an in-memory channel.
final class _Pipe implements TomSecretsApprovalChannel {
  _Pipe(this._in, this._out);

  final StreamController<List<int>> _in;
  final StreamController<List<int>> _out;

  static (_Pipe, _Pipe) pair() {
    final a = StreamController<List<int>>();
    final b = StreamController<List<int>>();
    return (_Pipe(a, b), _Pipe(b, a));
  }

  @override
  Stream<List<int>> get incoming => _in.stream;

  @override
  void send(List<int> bytes) {
    if (!_out.isClosed) _out.add(bytes);
  }

  @override
  Future<void> close() async {
    if (!_out.isClosed) await _out.close();
  }
}

void main() {
  group('signed objects (signatures.json)', () {
    final v = _load('signatures');
    final keys = (v['keys']! as Map).cast<String, Object?>();
    TomSecretsApproverPublicKey publicOf(String name) {
      final k = (keys[name]! as Map).cast<String, Object?>();
      return TomSecretsApproverPublicKey(
        _b(k['ed25519Public']),
        _b(k['mlDsa65Public']),
      );
    }

    test('approver keys from their seeds, with their ids', () async {
      for (final MapEntry(key: name, value: k as Map) in keys.entries) {
        final key = await TomSecretsApproverKey.fromSeeds(
          _b(k['ed25519Seed']),
          _b(k['mlDsa65Seed']),
        );
        expect(key.keyId, k['keyId'], reason: name);
        expect(key.publicKey.ed25519, _b(k['ed25519Public']));
        expect(key.publicKey.mlDsa65, _b(k['mlDsa65Public']));
      }
    });

    test('every accepted object: its signed bytes, accepted under the '
        'recorded key', () async {
      final recorded = [publicOf('approver')];
      expect((v['recorded']! as List).single, recorded.single.keyId);
      for (final a in (v['accepted']! as List).cast<Map>()) {
        final label = a['label']! as String;
        final object = (a['object']! as Map).cast<String, Object?>();
        expect(
          _hex(tomSecretsSignedBytes(label, object)),
          a['signedBytesHex'],
          reason: '${a['name']}',
        );
        if (label == TomSecretsSignedLabels.keyChange) {
          final newKey = await tomSecretsAcceptKeyChange(
            object,
            recorded.single,
          );
          expect(newKey?.keyId, publicOf('approverRotated').keyId);
        } else {
          expect(
            await tomSecretsAcceptedBy(label, object, recorded),
            isNotNull,
            reason: '${a['name']}',
          );
        }
      }
    });

    test('every refused object is refused', () async {
      final recorded = [publicOf('approver')];
      for (final r in (v['rejected']! as List).cast<Map>()) {
        final label = r['label']! as String;
        final object = (r['object']! as Map).cast<String, Object?>();
        if (label == TomSecretsSignedLabels.keyChange) {
          expect(
            await tomSecretsAcceptKeyChange(object, recorded.single),
            isNull,
            reason: '${r['name']}',
          );
        } else {
          expect(
            await tomSecretsAcceptedBy(label, object, recorded),
            isNull,
            reason: '${r['name']}',
          );
        }
      }
    });

    test(
      'a hedged signature made here is accepted; another label is not',
      () async {
        final k = (keys['approver']! as Map).cast<String, Object?>();
        final key = await TomSecretsApproverKey.fromSeeds(
          _b(k['ed25519Seed']),
          _b(k['mlDsa65Seed']),
        );
        final grant = await key.signObject(TomSecretsSignedLabels.grant, {
          'id': 'g-1',
          'host': 'bigbeast',
          'subject': 'exe /usr/bin/backup',
          'secret': 'all',
          'decision': 'allow',
          'created': '2026-11-13T10:00:00Z',
          'pin': {'relaxedUntil': '2026-12-01T00:00:00Z'},
          'approver': 'mbp',
        });
        expect(
          await tomSecretsAcceptedBy(TomSecretsSignedLabels.grant, grant, [
            key.publicKey,
          ]),
          isNotNull,
        );
        expect(
          await tomSecretsAcceptedBy(TomSecretsSignedLabels.revoke, grant, [
            key.publicKey,
          ]),
          isNull,
        );
      },
    );
  });

  group('approval codes and tokens (approval_codes.json)', () {
    final v = _load('approval_codes');

    test('request digests and codes', () {
      for (final c in (v['codes']! as List).cast<Map>()) {
        final identity = (c['identity']! as Map).cast<String, Object?>();
        final refs = (c['refs']! as List).cast<String>();
        expect(
          _hex(tomSecretsRequestDigest(identity, refs)),
          c['requestDigestHex'],
          reason: '${c['name']}',
        );
        expect(
          tomSecretsApprovalCode(
            c['host']! as String,
            c['approvalId']! as String,
            identity,
            refs,
          ),
          c['code'],
        );
      }
    });

    test('tokens for every decision', () {
      for (final t in (v['tokens']! as List).cast<Map>()) {
        expect(
          tomSecretsCodeToken(
            _b(t['tokenKey']),
            t['host']! as String,
            t['code']! as String,
            t['decision']! as String,
          ),
          t['token'],
        );
      }
    });

    test('redemption', () {
      final r = (v['redeem']! as Map).cast<String, Object?>();
      final waiting = (r['waiting']! as Map).cast<String, String>();
      final tokenKeys = [for (final k in r['tokenKeys']! as List) _b(k)];
      for (final c in (r['cases']! as List).cast<Map>()) {
        final match = tomSecretsRedeemToken(
          c['token']! as String,
          waiting.keys,
          tokenKeys,
          r['host']! as String,
        );
        final outcome = c['outcome'] as List?;
        expect(
          match == null ? null : [waiting[match.code], match.decision],
          outcome,
          reason: '${c['name']}',
        );
      }
    });
  });

  group('the approval link (link_handshake.json)', () {
    final v = _load('link_handshake');
    Future<TomSecretsLinkKey> keyOf(String side) {
      final k = (v[side]! as Map).cast<String, Object?>();
      return TomSecretsLinkKey.fromSeeds(
        _b(k['x25519Seed']),
        _b(k['mlKem768Seed']),
      );
    }

    test(
      'the handshake, byte for byte, and the transport with its rekeys',
      () async {
        final approver = await keyOf('approver');
        final host = await keyOf('host');
        final ar = (v['approverRandom']! as Map).cast<String, Object?>();
        final hr = (v['hostRandom']! as Map).cast<String, Object?>();
        final initiator = TomSecretsLinkInitiator(
          approver,
          host.publicKey,
          random: _FixedRandom(
            _b(ar['ephemeralX25519Seed']),
            _b(ar['ephemeralMlKem768Seed']),
            [_b(ar['coinsToHostStatic'])],
          ),
        );
        final responder = TomSecretsLinkResponder(
          host,
          approver.publicKey,
          random: _FixedRandom(_b(hr['ephemeralX25519Seed']), null, [
            _b(hr['coinsToApproverEphemeral']),
            _b(hr['coinsToApproverStatic']),
          ]),
        );
        final m1 = await initiator.writeMessage1(
          utf8.encode(v['payload1Text']! as String),
        );
        expect(_hex(m1), v['message1Hex']);
        expect(_hex(tomSecretsLinkFrame(m1)), v['message1FrameHex']);
        expect(
          utf8.decode(await responder.readMessage1(m1)),
          v['payload1Text'],
        );
        expect(_hex(responder.handshakeHash), v['handshakeHashAfterMessage1']);
        final (m2, hostKeys) = await responder.writeMessage2(
          utf8.encode(v['payload2Text']! as String),
        );
        expect(_hex(m2), v['message2Hex']);
        final (payload2, approverKeys) = await initiator.readMessage2(m2);
        expect(utf8.decode(payload2), v['payload2Text']);
        expect(_hex(approverKeys.handshakeHash), v['handshakeHash']);
        expect(_hex(approverKeys.initiatorToResponder), v['approverToHostKey']);
        expect(_hex(hostKeys.responderToInitiator), v['hostToApproverKey']);

        final send = {
          'approver': TomSecretsLinkCipher(approverKeys.initiatorToResponder),
          'host': TomSecretsLinkCipher(hostKeys.responderToInitiator),
        };
        final receive = {
          'approver': TomSecretsLinkCipher(hostKeys.initiatorToResponder),
          'host': TomSecretsLinkCipher(approverKeys.responderToInitiator),
        };
        for (final t in (v['transport']! as List).cast<Map>()) {
          final from = t['from']! as String;
          final c = await send[from]!.encrypt(
            utf8.encode(t['plaintext']! as String),
          );
          expect(_hex(c), t['ciphertextHex'], reason: '$from ${t['n']}');
          expect(utf8.decode(await receive[from]!.decrypt(c)), t['plaintext']);
          if (t['keyAfterRekeyHex'] != null) {
            await send[from]!.rekey();
            await receive[from]!.rekey();
            expect(_hex(send[from]!.key), t['keyAfterRekeyHex']);
          }
        }
      },
    );

    test('an altered or truncated message 1, an unrecorded approver, a '
        'replayed transport frame: refused', () async {
      final approver = await keyOf('approver');
      final host = await keyOf('host');
      final stranger = await TomSecretsLinkKey.fromSeeds(
        Uint8List(32)..[0] = 7,
        Uint8List(64)..[0] = 7,
      );
      final m1 = await TomSecretsLinkInitiator(
        approver,
        host.publicKey,
      ).writeMessage1(utf8.encode('{"protocol":1,"device":"mbp"}'));
      Future<void> refused(Uint8List message, TomSecretsLinkKey from) =>
          expectLater(
            TomSecretsLinkResponder(host, from.publicKey).readMessage1(message),
            throwsA(isA<TomSecretsLinkException>()),
          );
      await refused(Uint8List.fromList(m1)..last ^= 1, approver);
      await refused(Uint8List.fromList(m1)..[32 + 1184] ^= 1, approver);
      await refused(m1.sublist(0, 2000), approver);
      await refused(m1, stranger);
      final cipher = TomSecretsLinkCipher(Uint8List(32));
      final frame = await cipher.encrypt(utf8.encode('{"op":"ready"}'));
      final reader = TomSecretsLinkCipher(Uint8List(32));
      await reader.decrypt(frame);
      await expectLater(
        reader.decrypt(frame),
        throwsA(isA<TomSecretsLinkException>()),
      );
    });

    test('after a rotation of the host\'s link key, an approver that '
        'still holds the previous one is answered under it', () async {
      final approver = await keyOf('approver');
      final previous = await keyOf('host');
      final current = await TomSecretsLinkKey.fromSeeds(
        Uint8List(32)..[2] = 4,
        Uint8List(64)..[2] = 4,
      );
      for (final (hostKey, expected) in [
        (previous.publicKey, 'previous'),
        (current.publicKey, 'current'),
      ]) {
        final (a, h) = _Pipe.pair();
        final hostSide = TomSecretsLinkSession.respond(
          h,
          me: current,
          previousMe: previous,
          approvers: [(device: 'mbp', key: approver.publicKey)],
          host: 'bigbeast',
        );
        final approverSession = await TomSecretsLinkSession.initiate(
          a,
          me: approver,
          hostKey: hostKey,
          device: 'mbp',
        );
        final hostSession = await hostSide;
        expect(hostSession.peerDevice, 'mbp', reason: expected);
        expect(hostSession.underPreviousKey, expected == 'previous');
        expect(approverSession.underPreviousKey, isFalse);
        await approverSession.close();
        await hostSession.close();
      }
      // Without previousMe the previous key is no longer answered.
      final (a, h) = _Pipe.pair();
      final refused = TomSecretsLinkSession.respond(
        h,
        me: current,
        approvers: [(device: 'mbp', key: approver.publicKey)],
        host: 'bigbeast',
      );
      unawaited(
        TomSecretsLinkSession.initiate(
          a,
          me: approver,
          hostKey: previous.publicKey,
          device: 'mbp',
          timeout: const Duration(seconds: 2),
        ).then((_) {}, onError: (Object _) {}),
      );
      await expectLater(refused, throwsA(isA<TomSecretsLinkException>()));
    });

    test('a session over a channel: ready, messages both ways, rekey; an '
        'unknown approver and a wrong device id are closed', () async {
      final approver = await keyOf('approver');
      final host = await keyOf('host');
      final (a, h) = _Pipe.pair();
      final hostSide = TomSecretsLinkSession.respond(
        h,
        me: host,
        approvers: [(device: 'mbp', key: approver.publicKey)],
        host: 'bigbeast',
      );
      final approverSession = await TomSecretsLinkSession.initiate(
        a,
        me: approver,
        hostKey: host.publicKey,
        device: 'mbp',
      );
      final hostSession = await hostSide;
      expect(hostSession.peerDevice, 'mbp');
      expect(approverSession.peerDevice, 'bigbeast');
      expect(hostSession.handshakeHash, approverSession.handshakeHash);
      final toApprover = approverSession.messages.first;
      await hostSession.send({'op': 'approval_needed', 'approvalId': 'a-1'});
      expect((await toApprover)['approvalId'], 'a-1');
      TomSecretsLinkSession.rekeyFrames = 2;
      addTearDown(() => TomSecretsLinkSession.rekeyFrames = 1 << 20);
      // Listened to before anything is sent: a broadcast stream keeps
      // nothing for a late listener.
      final received = hostSession.messages.take(3).toList();
      for (var i = 0; i < 3; i++) {
        await approverSession.send({'op': 'approve', 'id': i});
      }
      // The third crosses the sender's rekey (after two frames).
      expect([for (final m in await received) m['id']], [0, 1, 2]);
      await approverSession.close();
      await hostSession.close();

      final (a2, h2) = _Pipe.pair();
      final wrongDevice = TomSecretsLinkSession.respond(
        h2,
        me: host,
        approvers: [(device: 'bomber', key: approver.publicKey)],
        host: 'bigbeast',
      );
      unawaited(
        TomSecretsLinkSession.initiate(
          a2,
          me: approver,
          hostKey: host.publicKey,
          device: 'mbp',
          timeout: const Duration(seconds: 2),
        ).then((_) {}, onError: (Object _) {}),
      );
      await expectLater(wrongDevice, throwsA(isA<TomSecretsLinkException>()));

      final (a3, h3) = _Pipe.pair();
      final unknown = TomSecretsLinkSession.respond(
        h3,
        me: host,
        approvers: [
          (
            device: 'mbp',
            key: (await TomSecretsLinkKey.fromSeeds(
              Uint8List(32)..[1] = 9,
              Uint8List(64)..[1] = 9,
            )).publicKey,
          ),
        ],
        host: 'bigbeast',
      );
      unawaited(
        TomSecretsLinkSession.initiate(
          a3,
          me: approver,
          hostKey: host.publicKey,
          device: 'mbp',
          timeout: const Duration(seconds: 2),
        ).then((_) {}, onError: (Object _) {}),
      );
      await expectLater(unknown, throwsA(isA<TomSecretsLinkException>()));
    });
  });

  group('the grants group and the trust material', () {
    test('signed objects written and read back per host; references never '
        'resolve into the group', () async {
      final vault = DemoVault(store: 'fleet')
        ..add('Db/Main', password: 'demo', key: 'db.main');
      final group = TomSecretsGrantsGroup(vault.file);
      final key = await TomSecretsApproverKey.fromSeeds(
        Uint8List(32)..[0] = 1,
        Uint8List(32)..[0] = 2,
      );
      final grant = await key.signObject(TomSecretsSignedLabels.grant, {
        'id': 'g-1',
        'host': 'bigbeast',
        'subject': 'exe /usr/bin/backup',
        'secret': 'db.main',
        'decision': 'allow',
        'created': '2026-11-13T10:00:00Z',
        'pin': {'relaxedUntil': '2026-12-01T00:00:00Z'},
        'approver': 'mbp',
      });
      group.write('bigbeast', TomSecretsSignedKind.grant, grant);
      group.write('bomber', TomSecretsSignedKind.grant, {
        ...grant,
        'host': 'bomber',
      });
      final read = group.read('bigbeast', TomSecretsSignedKind.grant).single;
      expect(read['pin'], {'relaxedUntil': '2026-12-01T00:00:00Z'});
      expect(
        await tomSecretsAcceptedBy(TomSecretsSignedLabels.grant, read, [
          key.publicKey,
        ]),
        isNotNull,
      );
      expect(group.hosts, ['bigbeast', 'bomber']);
      expect(group.read('bigbeast', TomSecretsSignedKind.revocation), isEmpty);
      final store = TomSecretsStore.fromFile(vault.file, name: 'fleet');
      expect(
        store.entries.map((e) => e.pathText),
        isNot(contains(startsWith('tsm.grants'))),
      );
      expect(
        group.remove('bigbeast', TomSecretsSignedKind.grant, read),
        isTrue,
      );
      expect(group.read('bigbeast', TomSecretsSignedKind.grant), isEmpty);
    });

    test(
      'trust material round-trips; the keys come back from their seeds',
      () async {
        final created = DateTime.utc(2026, 11, 14, 8);
        final trust = TomSecretsTrust.create('mbp', now: created);
        expect(trust.approverKeySince, created);
        expect(trust.linkKeySince, created);
        final peerKey = (await trust.approverKey()).publicKey;
        final peerLink = (await trust.linkKey()).publicKey;
        trust
          ..approvers.add(
            TomSecretsRecordedApprover(
              device: 'bigbeast',
              approverKey: peerKey,
              linkKey: peerLink,
              tokenKey: Uint8List(32),
              approverKeySince: created,
            ),
          )
          ..hosts.add(
            TomSecretsRecordedHost(
              host: 'bomber',
              linkKey: peerLink,
              tokenKey: Uint8List(32),
            ),
          );
        final again = TomSecretsTrust.fromJson(
          (jsonDecode(jsonEncode(trust.toJson())) as Map).cast(),
        );
        expect(again.approverKeySince, created);
        expect(again.linkKeySince, created);
        expect(again.approver('bigbeast')!.approverKeySince, created);
        expect(again.approver('bigbeast')!.linkKeySince, isNull);
        expect(again.host('bomber')!.linkKeySince, isNull);
        final later = created.add(const Duration(days: 2));
        expect(again.stampKeyDates(later), isTrue, reason: 'two undated');
        expect(again.approver('bigbeast')!.linkKeySince, later);
        expect(again.host('bomber')!.linkKeySince, later);
        expect(again.approverKeySince, created, reason: 'a date stays');
        expect(again.stampKeyDates(later), isFalse);
        expect(
          (await again.approverKey()).keyId,
          (await trust.approverKey()).keyId,
        );
        expect(
          (await again.linkKey()).publicKey.sameAs(
            (await trust.linkKey()).publicKey,
          ),
          isTrue,
        );
        expect(again.auditKey, trust.auditKey);
        expect(
          trust.toString(),
          isNot(contains(base64.encode(trust.auditKey))),
        );
      },
    );
  });
}
