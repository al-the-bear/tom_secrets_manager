// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The host's end of the approval link (protocol.md 9.7, DP-100): a TCP
/// listener on the host's VPN or LAN address only (never all interfaces),
/// open while the service is unlocked. Each connection is a handshake as
/// the responder against the approvers recorded at pairing (their current
/// link key and, during its migration period, the one it replaced); an
/// accepted session goes to the approvals.
library;

import 'dart:async';
import 'dart:io';

import 'package:tom_secrets_client/admin.dart'
    show tomSecretsApprovalLinkProblem;
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'approvals.dart';
import 'log.dart';

/// The approval link's listener.
final class TomSecretsLinkServer {
  TomSecretsLinkServer._(this._server, this.address);

  final ServerSocket _server;

  /// The address it listens on (`address:port`).
  final String address;

  /// The port it listens on (0 in the settings picks one).
  int get port => _server.port;

  /// Listens on [address] (`host:port`) and hands every accepted session of
  /// a recorded approver to [approvals]. Throws [FormatException] for an
  /// address that is not `host:port` or names every interface.
  static Future<TomSecretsLinkServer> start({
    required String address,
    required TomSecretsTrust trust,
    required String host,
    required TomSecretsApprovals approvals,
    required TomSecretsLog log,
  }) async {
    final problem = tomSecretsApprovalLinkProblem(address, anyPort: true);
    if (problem != null) throw FormatException(problem);
    final colon = address.lastIndexOf(':');
    var name = address.substring(0, colon);
    if (name.startsWith('[')) name = name.substring(1, name.length - 1);
    final port = int.parse(address.substring(colon + 1));
    final server = await ServerSocket.bind(name, port);
    server.listen((socket) async {
      // Read at each connection: a rotation of this device's link key takes
      // effect at once, its previous key answered during the migration.
      final me = await trust.linkKey();
      final previousMe = await trust.previousLinkKey();
      final approvers = [
        for (final a in trust.approvers) ...[
          if (a.linkKey != null) (device: a.device, key: a.linkKey!),
          if (a.previousLinkKey != null)
            (device: a.device, key: a.previousLinkKey!),
        ],
      ];
      try {
        final session = await TomSecretsLinkSession.respond(
          TomSecretsSocketChannel(socket),
          me: me,
          previousMe: previousMe,
          approvers: approvers,
          host: host,
        );
        approvals.addLinkSession(session, linkKey: me.publicKey);
      } on Object catch (e) {
        log.info('link_refused', {
          'error': e.runtimeType.toString(),
          'detail': e is TomSecretsLinkException ? e.message : null,
          'peer': socket.remoteAddress.address,
        });
      }
    });
    return TomSecretsLinkServer._(server, '$name:${server.port}');
  }

  /// Stops listening.
  Future<void> close() => _server.close();
}
