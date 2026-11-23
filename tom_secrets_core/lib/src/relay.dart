// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The relay interface (part-relay, BP-35, DP-64, DP-100): one
/// interface, several transports behind it, so pairing and sharing never
/// know which one carries them.
///
/// - **What a relay is:** a carrier of ciphertext only. It sees encrypted
///   bytes, times, sizes and the address it is reached from, never a key or
///   a plaintext; it is not trusted (it can drop, delay or replay, nothing
///   more: a tampered pairing fails at the key confirmation, a replayed
///   mailbox item is known by its id).
/// - **Three services:** `pairing` (a rendezvous of two online devices for
///   minutes, a byte channel between them), `mailbox` (an `age` package
///   waiting for one recipient up to 30 days), `link` (a standing channel
///   between two paired devices for the approval link).
/// - **The transports:** the own relay server (`tsm:<url>`: all three), a
///   magic-wormhole mailbox server (`wormhole:<url>`: pairing), GitHub
///   (`github:<owner>/<repo>`: pairing when the new device reaches the
///   repository already, the mailbox for members of a shared repository).
/// - **Unchanged protocols:** a [TomSecretsPairingChannel] is a
///   [TomSecretsApprovalChannel], so the pairing (and the approval link)
///   run over a relay exactly as over TCP.
library;

import 'dart:typed_data';
import 'package:tom_secrets_age/tom_secrets_age.dart';

import 'approval_link.dart';

/// What a relay offers.
enum TomSecretsRelayService {
  /// A rendezvous of two online devices with a byte channel.
  pairing,

  /// Store and forward of `age` packages to one recipient.
  mailbox,

  /// A standing channel between two paired devices (the approval link).
  link,
}

/// The kind of a relay, from its id's scheme.
enum TomSecretsRelayKind {
  /// The own relay server, `tom_secrets_relay` (`tsm:<https url>`).
  server('tsm', {
    TomSecretsRelayService.pairing,
    TomSecretsRelayService.mailbox,
    TomSecretsRelayService.link,
  }),

  /// A magic-wormhole mailbox server (`wormhole:<ws(s) url>`).
  wormhole('wormhole', {TomSecretsRelayService.pairing}),

  /// A GitHub repository both sides can push to (`github:<owner>/<repo>`).
  github('github', {
    TomSecretsRelayService.pairing,
    TomSecretsRelayService.mailbox,
  });

  const TomSecretsRelayKind(this.scheme, this.services);

  /// The id's scheme.
  final String scheme;

  /// The services a relay of this kind offers (part-relay's table).
  final Set<TomSecretsRelayService> services;
}

/// A relay's id: `tsm:https://relay.example`, `wormhole:wss://…`,
/// `github:<owner>/<repo>`. It names the relay in the settings, in the
/// pairing QR code and in a shared vault's metadata, so both sides use the
/// same one.
final class TomSecretsRelayId {
  const TomSecretsRelayId._(this.kind, this.address);

  /// The id of a GitHub repository `owner/repo` as a relay.
  factory TomSecretsRelayId.github(String owner, String repository) =>
      TomSecretsRelayId.parse('github:$owner/$repository');

  /// The relay [text] names; throws [FormatException] for anything else.
  factory TomSecretsRelayId.parse(String text) {
    final t = text.trim();
    final colon = t.indexOf(':');
    if (colon <= 0) throw FormatException('not a relay id: $text');
    final scheme = t.substring(0, colon);
    final address = t.substring(colon + 1);
    final kind = TomSecretsRelayKind.values
        .where((k) => k.scheme == scheme)
        .firstOrNull;
    if (kind == null) {
      throw FormatException(
        'not a relay id: $text (tsm:, wormhole: or github:)',
      );
    }
    switch (kind) {
      case TomSecretsRelayKind.github:
        if (!RegExp(r'^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$').hasMatch(address)) {
          throw FormatException(
            'not a GitHub relay (github:owner/repo): $text',
          );
        }
      case TomSecretsRelayKind.server:
        final uri = Uri.tryParse(address);
        if (uri == null ||
            (uri.scheme != 'https' && uri.scheme != 'http') ||
            uri.host.isEmpty) {
          throw FormatException('not a relay server (tsm:https://…): $text');
        }
      case TomSecretsRelayKind.wormhole:
        final uri = Uri.tryParse(address);
        if (uri == null ||
            (uri.scheme != 'wss' && uri.scheme != 'ws') ||
            uri.host.isEmpty) {
          throw FormatException(
            'not a magic-wormhole server (wormhole:wss://…): $text',
          );
        }
    }
    return TomSecretsRelayId._(kind, address);
  }

  /// The relay's kind.
  final TomSecretsRelayKind kind;

  /// What follows the scheme: the URL, or `owner/repo`.
  final String address;

  /// The services it offers.
  Set<TomSecretsRelayService> get services => kind.services;

  /// The id as text.
  String get text => '${kind.scheme}:$address';

  @override
  bool operator ==(Object other) =>
      other is TomSecretsRelayId && other.text == text;

  @override
  int get hashCode => text.hashCode;

  @override
  String toString() => text;
}

/// A relay that failed or refused: [relay] names it, so the app says which
/// relay failed and offers the next one (part-relay: never switching
/// silently).
final class TomSecretsRelayException implements Exception {
  /// A failure of [relay], told by [message].
  const TomSecretsRelayException(
    this.relay,
    this.message, {
    this.unsupported = false,
  });

  /// The relay's id.
  final String relay;

  /// For people.
  final String message;

  /// Whether the relay does not offer what was asked (a service it lacks).
  final bool unsupported;

  @override
  String toString() => 'TomSecretsRelayException($relay): $message';
}

/// A pairing's or the approval link's byte channel through a relay: the
/// approval link's channel (length-prefixed frames, DP-64), with the
/// nameplate it was opened under.
abstract interface class TomSecretsPairingChannel
    implements TomSecretsApprovalChannel {
  /// The nameplate (a pairing's number, or the link id).
  String get nameplate;

  /// Completes when the other side's first bytes arrived (a host learns
  /// that someone joined; the bytes stay in [incoming]).
  Future<void> get joined;
}

/// A mailbox item to put: an `age` package for one recipient.
final class TomSecretsMailboxItem {
  /// The package [bytes] for the member [recipient] (its member id, the
  /// recipient's fingerprint) under [itemId], kept until [expires].
  const TomSecretsMailboxItem({
    required this.recipient,
    required this.itemId,
    required this.bytes,
    required this.expires,
  });

  /// The recipient's member id.
  final String recipient;

  /// The item's id, unique per recipient (a replayed item is recognised by
  /// it).
  final String itemId;

  /// The `age` package.
  final Uint8List bytes;

  /// When the relay may delete it (at most 30 days on).
  final DateTime expires;
}

/// A mailbox item waiting, as a listing tells it.
final class TomSecretsMailboxEntry {
  /// The item [itemId] of [size] bytes (0 when unknown), received at
  /// [received], kept until [expires] (null when unknown).
  const TomSecretsMailboxEntry({
    required this.itemId,
    this.size = 0,
    this.received,
    this.expires,
  });

  /// The item's id.
  final String itemId;

  /// Its size in bytes, 0 when the relay does not say.
  final int size;

  /// When it arrived, when the relay says.
  final DateTime? received;

  /// When it expires, when the relay says.
  final DateTime? expires;
}

/// A relay (part-relay): its id and services, the pairing rendezvous
/// ([host], [join]), the approval link ([link]) and the mailbox ([put],
/// [list], [fetch], [delete]). A service the relay does not offer throws
/// [TomSecretsRelayException] with `unsupported`; any other failure is a
/// [TomSecretsRelayException] naming the relay.
abstract interface class TomSecretsRelay {
  /// The relay's id.
  TomSecretsRelayId get id;

  /// The services it offers.
  Set<TomSecretsRelayService> get services;

  /// Allocates a nameplate (a number 1–999, the pairing code's number) and
  /// opens the hosting side's channel under it.
  Future<TomSecretsPairingChannel> host();

  /// Opens the joining side's channel under [nameplate].
  Future<TomSecretsPairingChannel> join(String nameplate);

  /// Opens the approval link between two paired devices under [linkId].
  Future<TomSecretsPairingChannel> link(String linkId);

  /// Puts [item] into its recipient's mailbox.
  Future<void> put(TomSecretsMailboxItem item);

  /// The items waiting for [me].
  Future<List<TomSecretsMailboxEntry>> list(TomSecretsMemberKey me);

  /// The package of [itemId] for [me].
  Future<Uint8List> fetch(TomSecretsMemberKey me, String itemId);

  /// Deletes [itemId] from [me]'s mailbox.
  Future<void> delete(TomSecretsMemberKey me, String itemId);
}
