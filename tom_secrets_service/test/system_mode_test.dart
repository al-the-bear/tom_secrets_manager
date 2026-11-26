// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The system install's start (tsm_d11), what can be checked without root:
/// the directories come from the account, the key from the real user id,
/// the group is dropped once the key is had, also when it cannot be had.
/// The install itself is checked as root in a container (tom_secrets_build
/// `:system`). Demo keys only.
@TestOn('vm')
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart' show currentUid;
import 'package:tom_secrets_core/tom_secrets_core.dart'
    show TomSecretsServiceIdentityKey, tomSecretsServiceIdentityFile;
import 'package:tom_secrets_service/tom_secrets_service.dart';

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('tsmsysmode'));
  tearDown(() => dir.deleteSync(recursive: true));

  TomSecretsSystemMode mode({String? run}) => TomSecretsSystemMode(
    uid: 4242,
    home: '${dir.path}/home',
    identityDirectory: '${dir.path}/identity',
    runUserDirectory: run ?? '${dir.path}/run/user',
  );

  test('the directories come from the account, never from the caller\'s '
      'variables', () {
    final m = mode();
    expect(m.environment, {'HOME': '${dir.path}/home'});
    expect(
      m.dataDirectory,
      '${dir.path}/home/.local/share/tom-secrets-manager',
    );
    expect(
      m.bootstrapPath,
      '${dir.path}/home/.local/share/tom-secrets-manager/bootstrap.yaml',
    );
    expect(m.runtime.directory, '/tmp/tsm-${currentUid()}');
    Directory('${dir.path}/run/user/4242').createSync(recursive: true);
    expect(m.runtime.directory, '${dir.path}/run/user/4242/tsm');
    expect(m.identityFile.path, '${dir.path}/identity/4242.json');
  });

  test('the key of the real user is made, read back the same, and the group '
      'dropped each time; a key from the data directory signs the new one '
      'and is removed', () async {
    var drops = 0;
    final previous = await TomSecretsServiceIdentityKey.loadOrCreate(
      mode().dataDirectory,
    );
    final key = await mode().takeIdentity(drop: () => drops++);
    expect(drops, 1);
    expect(key.keptIn, 'system');
    expect(key.changes.single.from, previous.publicKey);
    expect(
      File(
        '${mode().dataDirectory}/$tomSecretsServiceIdentityFile',
      ).existsSync(),
      isFalse,
    );
    final again = await mode().takeIdentity(drop: () => drops++);
    expect(drops, 2);
    expect(again.publicKey, key.publicKey);
  });

  test('a key that cannot be had stops the start, the group dropped all '
      'the same', () async {
    File('${dir.path}/identity/4242.json')
      ..createSync(recursive: true)
      ..writeAsStringSync('not a key');
    var drops = 0;
    await expectLater(
      mode().takeIdentity(drop: () => drops++),
      throwsA(isA<TomSecretsSystemModeException>()),
    );
    expect(drops, 1);
  });

  test('an ordinary start is no system start', () {
    // This process is not set-group-ID.
    expect(TomSecretsSystemMode.detect(), isNull);
  });
}
