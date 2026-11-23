// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// A magic-wormhole mailbox server as a relay (part-relay, DP-66, DP-180)
// against a fake of the server in this process: the mailbox protocol, the
// app's own application id, pairing only, the nameplate released once both
// sides are there, a code no pairing waits under, a crowded pairing, the
// app's own lifetime, the welcome's error and proof of work, and a full
// pairing (SPAKE2 with ML-KEM-768 inside) through the mailbox. The real
// server runs the same pairing in wormhole_server_test.dart.

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/fake_wormhole.dart';

late TomSecretsPairingPeerKeys _peer;

void main() {
  late FakeWormhole fake;
  setUpAll(() async {
    _peer = TomSecretsPairingPeerKeys(
      linkKey: (await TomSecretsTrust.create('demo').linkKey()).publicKey,
    );
  });
  setUp(() async => fake = await FakeWormhole.start());
  tearDown(() => fake.close());

  TomSecretsWormholeRelay relay({Duration? lifetime}) =>
      TomSecretsWormholeRelay(
        TomSecretsRelayId.parse(fake.relayId),
        timeout: const Duration(seconds: 5),
        lifetime: lifetime ?? tomSecretsWormholeLifetime,
      );

  Future<void> settle(bool Function() done) async {
    for (var i = 0; i < 100 && !done(); i++) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  group('Hashcash', () {
    test('the protocol\'s example stamp has its 6 bits', () {
      expect(
        tomSecretsHashcashBits(
          '1:6:210723:resource-string::NmZNF4eIbk87mqYz:000003n',
        ),
        greaterThanOrEqualTo(6),
      );
    });

    test('a stamp: version 1, the bits, the date, the resource, its bits '
        'of zeros', () {
      final stamp = tomSecretsHashcashStamp(
        12,
        'mailbox.example',
        now: DateTime.utc(2026, 11, 23, 18),
        random: Random(7),
      );
      final parts = stamp.split(':');
      expect(parts, hasLength(7));
      expect(parts.take(5), ['1', '12', '261123', 'mailbox.example', '']);
      expect(tomSecretsHashcashBits(stamp), greaterThanOrEqualTo(12));
      expect(() => tomSecretsHashcashStamp(4, 'a:b'), throwsArgumentError);
    });
  });

  test('pairing only; the other services are refused as unsupported', () async {
    final r = relay();
    expect(r.services, {TomSecretsRelayService.pairing});
    for (final call in <Future<Object?> Function()>[
      () => r.link('link-abcdef12'),
      () async => r.list(await TomSecretsMemberKey.generate()),
    ]) {
      await expectLater(
        call(),
        throwsA(
          isA<TomSecretsRelayException>().having(
            (e) => e.unsupported,
            'unsupported',
            isTrue,
          ),
        ),
      );
    }
    expect(
      tomSecretsRelayFor(TomSecretsRelayId.parse(fake.relayId)),
      isA<TomSecretsWormholeRelay>(),
    );
    expect(
      () => TomSecretsWormholeRelay(TomSecretsRelayId.parse('github:a/b')),
      throwsArgumentError,
    );
  });

  test('host and join: the app\'s own application id, frames as mailbox '
      'messages both ways, the nameplate released, a close ends the other '
      'side', () async {
    final host = await relay().host();
    final number = int.parse(host.nameplate);
    expect(number, inInclusiveRange(1, 999));
    final joiner = await relay().join(host.nameplate);
    final atHost = StreamIterator(host.incoming);
    final atJoiner = StreamIterator(joiner.incoming);
    joiner.send([1, 2, 3]);
    await host.joined;
    expect(await atHost.moveNext(), isTrue);
    expect(atHost.current, [1, 2, 3]);
    host.send(utf8.encode('hi'));
    expect(await atJoiner.moveNext(), isTrue);
    expect(utf8.decode(atJoiner.current), 'hi');
    await joiner.joined;

    final binds = fake.received.where((m) => m['type'] == 'bind').toList();
    expect(binds, hasLength(2));
    expect(binds.map((m) => m['appid']).toSet(), {tomSecretsWormholeAppId});
    final adds = fake.received.where((m) => m['type'] == 'add').toList();
    expect(adds.map((m) => m['phase']), containsAll(['host', '0']));
    expect(adds.firstWhere((m) => m['phase'] == '0')['body'], isNotEmpty);
    // Both sides have the mailbox: the nameplate is gone.
    await settle(() => fake.nameplates[tomSecretsWormholeAppId]!.isEmpty);
    expect(fake.nameplates[tomSecretsWormholeAppId], isEmpty);

    await host.close();
    expect(await atJoiner.moveNext(), isFalse);
    await joiner.close();
    expect(fake.moods.values.single.values.toSet(), {'happy'});
  });

  for (final disallowList in [false, true]) {
    test(
      'a code no pairing waits under is said'
      '${disallowList ? ', also when the server refuses its list' : ''}',
      () async {
        fake.disallowList = disallowList;
        await expectLater(
          relay().join('42'),
          throwsA(
            isA<TomSecretsRelayException>()
                .having((e) => e.relay, 'relay', fake.relayId)
                .having((e) => e.message, 'message', contains('no pairing')),
          ),
        );
        // The empty nameplate the claim made is given back.
        await settle(
          () => fake.nameplates[tomSecretsWormholeAppId]?.isEmpty ?? true,
        );
        expect(fake.nameplates[tomSecretsWormholeAppId] ?? {}, isEmpty);
        // A hosted one is found.
        final host = await relay().host();
        final joiner = await relay().join(host.nameplate);
        await joiner.close();
        await host.close();
      },
    );
  }

  test('a third device in the pairing is refused (crowded)', () async {
    final host = await relay().host();
    // A third side claims while the joining one still holds the nameplate.
    fake.nameplates[tomSecretsWormholeAppId]![host.nameplate]!.sides.add(
      'someone',
    );
    await expectLater(
      relay().join(host.nameplate),
      throwsA(
        isA<TomSecretsRelayException>().having(
          (e) => e.message,
          'message',
          contains('two devices are in this pairing'),
        ),
      ),
    );
    await host.close();
  });

  test('no one joins within the app\'s lifetime: the hosting side says so '
      'and closes its mailbox lonely', () async {
    expect(tomSecretsWormholeLifetime, const Duration(minutes: 10));
    final host = await relay(
      lifetime: const Duration(milliseconds: 200),
    ).host();
    await expectLater(
      host.incoming.first,
      throwsA(
        isA<TomSecretsRelayException>().having(
          (e) => e.message,
          'message',
          contains('no one joined pairing ${host.nameplate}'),
        ),
      ),
    );
    await settle(() => fake.moods.isNotEmpty);
    expect(fake.moods.values.single.values.single, 'lonely');
  });

  test('a welcome error refuses, naming the server\'s words', () async {
    fake.welcome = {'error': 'this server is closed for maintenance'};
    await expectLater(
      relay().host(),
      throwsA(
        isA<TomSecretsRelayException>().having(
          (e) => e.message,
          'message',
          contains('closed for maintenance'),
        ),
      ),
    );
  });

  test(
    'a proof of work asked for in the welcome is given before bind',
    () async {
      fake.welcome = {
        'motd': 'be nice',
        'permission-required': {
          'hashcash': {'bits': 10, 'resource': 'fake-mailbox'},
        },
      };
      final host = await relay().host();
      expect(fake.stamps, hasLength(1));
      expect(
        tomSecretsHashcashBits(fake.stamps.single),
        greaterThanOrEqualTo(10),
      );
      final types = fake.received.map((m) => m['type']).toList();
      expect(
        types.indexOf('submit-permissions'),
        lessThan(types.indexOf('bind')),
      );
      await host.close();

      // `none` among the methods: nothing to prove.
      fake
        ..stamps.clear()
        ..welcome = {
          'permission-required': {
            'none': <String, Object?>{},
            'hashcash': {'bits': 10, 'resource': 'fake-mailbox'},
          },
        };
      await (await relay().host()).close();
      expect(fake.stamps, isEmpty);

      // Only a method the app does not know: said.
      fake.welcome = {
        'permission-required': {'captcha': <String, Object?>{}},
      };
      await expectLater(
        relay().host(),
        throwsA(
          isA<TomSecretsRelayException>().having(
            (e) => e.message,
            'message',
            contains('captcha'),
          ),
        ),
      );
    },
  );

  test('a pairing through the mailbox: the giving side\'s window hosted '
      'there, the receiving side joins with the code', () async {
    final channel = await relay().host();
    final number = int.parse(channel.nameplate);
    final window = await TomSecretsPairingWindow.open(
      addresses: const [],
      relayChannel: channel,
      code: TomSecretsPairingCode(number, ['guitar', 'orbit']),
      device: 'mbp',
      bundleFor: (receiver) async => TomSecretsPairingBundle(
        vaults: [
          TomSecretsPairingVault(
            name: 'primary',
            locator: 'github:demo-owner/demo-vaults/primary.kdbx',
            primary: true,
          ),
        ],
        giverKeys: _peer,
      ),
    );
    final received = await tomSecretsReceivePairingVia(
      relay(),
      code: TomSecretsPairingCode.parse('$number guitar orbit'),
      device: 'bigbeast',
      keysFor: (giverName, bundle) async {
        expect(giverName, 'mbp');
        return _peer;
      },
    );
    final given = await window.result;
    expect(given.receiver, 'bigbeast');
    expect(received.giver, 'mbp');
    expect(received.bundle.vaults.single.name, 'primary');
    expect(received.tokenKey, given.tokenKey);
    // The pairing's frames were mailbox messages, the server saw only hex
    // of ciphertext.
    final bodies = fake.received
        .where(
          (m) =>
              m['type'] == 'add' && '${m['phase']}'.startsWith(RegExp('[0-9]')),
        )
        .map((m) => utf8.decode(_hex('${m['body']}'), allowMalformed: true));
    expect(bodies, isNotEmpty);
    expect(bodies.any((b) => b.contains('primary.kdbx')), isFalse);
  });
}

List<int> _hex(String s) => [
  for (var i = 0; i + 1 < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
];
