// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The client endpoint in the macOS app's App Group container
/// (part-browser, Safari): the group read from the app bundle around the
/// service (none outside a bundle, none for the ad-hoc build), and a
/// service that offers its client endpoint there too, served like the
/// runtime directory's and removed at the stop. Demo data only.
@TestOn('mac-os || linux')
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// An app bundle under [root] whose Info.plist names [group] (the build's
/// `TSMAppGroup`), with the service in its tools folder; answers the
/// service's path.
String _bundle(Directory root, String? group) {
  final contents = Directory('${root.path}/Tom Secrets Manager.app/Contents')
    ..createSync(recursive: true);
  final key = group == null
      ? ''
      : '  <key>TSMAppGroup</key>\n  <string>$group</string>\n';
  File('${contents.path}/Info.plist').writeAsStringSync(
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<plist version="1.0">\n<dict>\n'
    '  <key>CFBundleIdentifier</key>\n'
    '  <string>com.althebear.tomSecretsApp</string>\n'
    '$key</dict>\n</plist>\n',
  );
  final bin = Directory('${contents.path}/Resources/tsm/bin')
    ..createSync(recursive: true);
  return '${bin.path}/tom_secrets_service';
}

void main() {
  group('the App Group of the app around the service', () {
    late Directory root;
    setUp(() {
      root = Directory.systemTemp.createTempSync('tsmgrp');
      addTearDown(() => root.deleteSync(recursive: true));
    });

    test('the team-signed build names it; the socket is in its container', () {
      final service = _bundle(root, 'ABCDE12345.tom.secrets');
      expect(tomSecretsAppGroupOf(service), 'ABCDE12345.tom.secrets');
      expect(
        tomSecretsAppGroupClientSocketFor(
          service,
          environment: const {'HOME': '/Users/demo'},
          operatingSystem: 'macos',
        ),
        '/Users/demo/Library/Group Containers/ABCDE12345.tom.secrets/tsm/'
        'client.sock',
      );
      expect(
        tomSecretsAppGroupClientSocketFor(
          service,
          environment: const {'HOME': '/home/demo'},
          operatingSystem: 'linux',
        ),
        isNull,
      );
    });

    test('none for the ad-hoc build, a bundle without the key, or a service '
        'outside a bundle', () {
      expect(tomSecretsAppGroupOf(_bundle(root, '.tom.secrets')), isNull);
      expect(tomSecretsAppGroupOf(_bundle(root, null)), isNull);
      expect(tomSecretsAppGroupOf('/opt/tsm/bin/tom_secrets_service'), isNull);
    });
  });

  test('the service offers its client endpoint in the group container too: '
      'a client there is served, and the socket goes at the stop', () async {
    final demo = await Demo.create();
    // A short path: a Unix socket path is limited to 104 bytes on macOS.
    final group = Directory.systemTemp.createTempSync('tsmg');
    addTearDown(() => group.deleteSync(recursive: true));
    final socket = '${group.path}/tsm/client.sock';
    final service = await demo.start(groupClientSocket: socket);
    expect(
      FileSystemEntity.typeSync(socket, followLinks: false),
      FileSystemEntityType.unixDomainSock,
    );
    final mode = Directory('${group.path}/tsm').statSync().mode & 0x1ff;
    expect(mode, 0x1c0, reason: "the folder is only the user's");

    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    final client = await TomSecretsClient.connect(
      clientName: 'demo-safari-host',
      environment: {'TSM_RUNTIME_DIR': '${group.path}/tsm'},
    );
    addTearDown(client.close);
    final value = await client.get('primary/Db/Main');
    expect(value.text, 'demo-db-pw');
    value.dispose();

    await service.stop();
    expect(
      FileSystemEntity.typeSync(socket, followLinks: false),
      FileSystemEntityType.notFound,
    );
  });
}
