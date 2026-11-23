// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The approval link's relay at pairing (part-relay): the link id, which
// side's relay and id win, and the channels both sides record.

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

void main() {
  late TomSecretsLinkPublicKey giverLink;
  late TomSecretsLinkPublicKey receiverLink;
  late TomSecretsApproverPublicKey giverApprover;
  late TomSecretsApproverPublicKey receiverApprover;
  setUpAll(() async {
    final g = TomSecretsTrust.create('mbp');
    final r = TomSecretsTrust.create('server1');
    giverLink = (await g.linkKey()).publicKey;
    receiverLink = (await r.linkKey()).publicKey;
    giverApprover = (await g.approverKey()).publicKey;
    receiverApprover = (await r.approverKey()).publicKey;
  });

  test('a link id has 128 random bits in base64url', () {
    final a = tomSecretsNewLinkId();
    expect(a, hasLength(22));
    expect(tomSecretsLinkIdPattern.hasMatch(a), isTrue);
    expect(tomSecretsNewLinkId(), isNot(a));
  });

  test('the peer keys carry the relay link; one that cannot be used is '
      'none', () {
    final keys = TomSecretsPairingPeerKeys(
      linkKey: giverLink,
      linkRelay: 'tsm:https://relay.example',
      linkId: 'abcdefgh12345678',
    );
    final back = TomSecretsPairingPeerKeys.fromJson(keys.toJson());
    expect(back.linkRelay, 'tsm:https://relay.example');
    expect(back.linkId, 'abcdefgh12345678');
    for (final bad in <Map<String, Object?>>[
      {'linkRelay': 'github:a/b', 'linkId': 'abcdefgh12345678'},
      {'linkRelay': 'tsm:https://relay.example', 'linkId': 'short'},
      {'linkRelay': 'tsm:https://relay.example', 'linkId': 'with space 1234'},
      {'linkRelay': 'tsm:https://relay.example'},
      {'linkId': 'abcdefgh12345678'},
    ]) {
      final read = TomSecretsPairingPeerKeys.fromJson({
        'linkKey': giverLink.toJson(),
        ...bad,
      });
      expect(read.linkRelay, isNull, reason: '$bad');
      expect(read.linkId, isNull, reason: '$bad');
    }
    // An older peer names none.
    expect(
      TomSecretsPairingPeerKeys.fromJson({
        'linkKey': giverLink.toJson(),
      }).linkRelay,
      isNull,
    );
  });

  test('the giving side\'s relay link wins, else the receiving side\'s', () {
    final giver = TomSecretsPairingPeerKeys(
      linkKey: giverLink,
      linkRelay: 'tsm:https://a.example',
      linkId: 'giver-link-id-0001',
    );
    final receiver = TomSecretsPairingPeerKeys(
      linkKey: receiverLink,
      linkRelay: 'tsm:https://b.example',
      linkId: 'receiver-link-id-01',
    );
    final plain = TomSecretsPairingPeerKeys(linkKey: giverLink);
    expect(tomSecretsPairingLink(giver, receiver), (
      relay: 'tsm:https://a.example',
      linkId: 'giver-link-id-0001',
    ));
    expect(tomSecretsPairingLink(plain, receiver), (
      relay: 'tsm:https://b.example',
      linkId: 'receiver-link-id-01',
    ));
    expect(tomSecretsPairingLink(plain, plain), isNull);
  });

  test('both sides record the same channel for each direction', () {
    final link = (relay: 'tsm:https://relay.example', linkId: 'L0123456789');
    final token = Uint8List(32);
    final at = DateTime.utc(2026, 11, 23);
    // The giving side records the receiver as a host and an approver.
    final giver = TomSecretsTrust.create('mbp')
      ..recordPeer(
        device: 'server1',
        tokenKey: token,
        at: at,
        approverKey: receiverApprover,
        approverLinkKey: receiverLink,
        hostLinkKey: receiverLink,
        link: link,
      );
    // The receiving side records the giver (peerIsGiver).
    final receiver = TomSecretsTrust.create('server1')
      ..recordPeer(
        device: 'mbp',
        tokenKey: token,
        at: at,
        approverKey: giverApprover,
        approverLinkKey: giverLink,
        hostLinkKey: giverLink,
        link: link,
        peerIsGiver: true,
      );
    // The receiver as the host: its waiting channel is the giver's way in.
    expect(giver.hosts.single.linkId, 'L0123456789-r');
    expect(receiver.approvers.single.linkId, 'L0123456789-r');
    // The giver as the host.
    expect(receiver.hosts.single.linkId, 'L0123456789-g');
    expect(giver.approvers.single.linkId, 'L0123456789-g');
    for (final r in [
      giver.hosts.single.relay,
      giver.approvers.single.relay,
      receiver.hosts.single.relay,
    ]) {
      expect(r, 'tsm:https://relay.example');
    }
    // Kept in the stored trust material.
    final back = TomSecretsTrust.fromJson(giver.toJson());
    expect(back.hosts.single.linkId, 'L0123456789-r');
    expect(back.approvers.single.relay, 'tsm:https://relay.example');
  });
}
