// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A client process for identity_test.dart: connects to the address in its
/// arguments (a Unix socket path, or `tcp:<port>`), prints its own pid, and
/// stays connected until its standard input closes.
library;

import 'dart:io';

Future<void> main(List<String> args) async {
  final target = args.first;
  final socket = target.startsWith('tcp:')
      ? await Socket.connect(
          InternetAddress.loopbackIPv4,
          int.parse(target.substring(4)),
        )
      : await Socket.connect(
          InternetAddress(target, type: InternetAddressType.unix),
          0,
        );
  stdout.writeln(pid);
  await stdout.flush();
  await stdin.drain<void>();
  socket.destroy();
}
