// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The approval link through a relay server (part-relay, DP-64):
/// at pairing the two devices agree on a relay server and a random link id
/// (the giving side's when it names one, else the receiving side's,
/// [tomSecretsPairingLink]); each direction of the link has its own channel
/// on the relay (`<link id>-g` for the giving device as the host, `-r` for
/// the receiving device, [tomSecretsLinkChannelId]), recorded with the host
/// and the approver in the trust material. A host keeps the channel of each
/// of its approvers open while unlocked; an approver opens the one of each
/// host it approves for when the host's address does not answer.
library;

import 'dart:convert';
import 'dart:math';

import 'pairing.dart';
import 'relay.dart';

/// What a link id (and a channel id) is: 8–128 of `A-Z a-z 0-9 _ -`.
final RegExp tomSecretsLinkIdPattern = RegExp(r'^[A-Za-z0-9_-]{8,128}$');

final _random = Random.secure();

/// A new link id: 16 random bytes (128 bits) in base64url without padding.
String tomSecretsNewLinkId() => base64Url
    .encode(List<int>.generate(16, (_) => _random.nextInt(256)))
    .replaceAll('=', '');

/// The relay link two sides of a pairing agree on: the giving side's
/// relay and link id when it names them, else the receiving side's; null
/// when neither names a relay server with a link id (an older peer, or no
/// relay server).
({String relay, String linkId})? tomSecretsPairingLink(
  TomSecretsPairingPeerKeys giver,
  TomSecretsPairingPeerKeys receiver,
) {
  for (final keys in [giver, receiver]) {
    final relay = keys.linkRelay;
    final id = keys.linkId;
    if (relay != null && id != null) return (relay: relay, linkId: id);
  }
  return null;
}

/// The channel on the relay of the link whose host is the giving side
/// ([hostIsGiver]) or the receiving side, under the pairing's [linkId].
String tomSecretsLinkChannelId(String linkId, {required bool hostIsGiver}) =>
    '$linkId-${hostIsGiver ? 'g' : 'r'}';

/// Whether [relay] names a relay server that carries a link (`tsm:<url>`).
bool tomSecretsIsLinkRelay(String relay) {
  try {
    return TomSecretsRelayId.parse(
      relay,
    ).services.contains(TomSecretsRelayService.link);
  } on FormatException {
    return false;
  }
}
