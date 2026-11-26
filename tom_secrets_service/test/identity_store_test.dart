// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The stores of the service's identity key per platform (tsm_d11): the
/// macOS keychain item made by the process itself, whose access list trusts
/// that process alone (in a scratch keychain, never the login keychain);
/// Windows' DPAPI blob, which only this user's logon opens. Demo keys only.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/src/identity_store.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart'
    show tomSecretsProcessInfo;

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('tsmks'));
  tearDown(() => dir.deleteSync(recursive: true));

  group('macOS keychain', () {
    late String keychain;
    setUp(() {
      keychain = '${dir.path}/scratch.keychain-db';
      for (final args in [
        ['create-keychain', '-p', 'demo-keychain-pw', keychain],
        ['unlock-keychain', '-p', 'demo-keychain-pw', keychain],
        ['set-keychain-settings', keychain],
      ]) {
        final r = Process.runSync('security', args);
        expect(r.exitCode, 0, reason: '${r.stderr}');
      }
    });
    tearDown(() => Process.runSync('security', ['delete-keychain', keychain]));

    test('kept in an item whose access list trusts this process alone; read '
        'back, replaced by a rotated key, gone once forgotten', () async {
      final store = TomSecretsKeychainIdentityStore(keychainPath: keychain);
      final key = await TomSecretsServiceIdentityKey.loadOrCreate(
        dir.path,
        secretStore: store,
      );
      expect(key.keptIn, 'keychain');
      final file = File('${dir.path}/$tomSecretsServiceIdentityFile');
      final json = jsonDecode(file.readAsStringSync()) as Map;
      expect(json.containsKey('secretKey'), isFalse);
      final sealed = (json['secret']! as Map).cast<String, Object?>();
      expect(sealed['store'], 'keychain');
      expect(sealed['account'], tomSecretsIdentityKeychainAccount(file));

      final again = await TomSecretsServiceIdentityKey.loadOrCreate(
        dir.path,
        secretStore: store,
      );
      expect(again.publicKey, key.publicKey);

      // The access list: only the process that made it decrypts it without
      // a prompt (the test's VM here, the service in a real install).
      final dump =
          Process.runSync('security', ['dump-keychain', '-a', keychain]).stdout
              as String;
      final item = dump.substring(dump.indexOf(sealed['account']! as String));
      final decrypt = item.substring(item.indexOf('decrypt'));
      final apps = RegExp(
        r'applications \((\d+)\):\n\s+0: (.*?) \(',
      ).firstMatch(decrypt)!;
      expect(apps[1], '1', reason: 'one trusted program');
      expect(
        File(apps[2]!).resolveSymbolicLinksSync(),
        // The process's own executable, as the OS measures it.
        File(tomSecretsProcessInfo(pid)!.exe).resolveSymbolicLinksSync(),
      );

      final rotated = await again.rotate();
      final read = await TomSecretsServiceIdentityKey.loadOrCreate(
        dir.path,
        secretStore: store,
      );
      expect(read.publicKey, rotated.publicKey);

      await store.forget(sealed, file);
      await expectLater(
        TomSecretsServiceIdentityKey.loadOrCreate(dir.path, secretStore: store),
        throwsA(
          isA<TomSecretsIdentityKeyUnavailable>().having(
            (e) => e.message,
            'message',
            contains('gone'),
          ),
        ),
      );
    });
  }, testOn: 'mac-os');

  group('Windows DPAPI', () {
    test('the file holds a protected blob, opened by this user; a blob that '
        'was changed or made for something else does not open', () async {
      const store = TomSecretsDpapiIdentityStore();
      final file = File('${dir.path}/$tomSecretsServiceIdentityFile');
      final probe = Uint8List.fromList(List.generate(64, (i) => i));
      final Map<String, Object?> sealed;
      try {
        sealed = await store.seal(probe, file);
      } on TomSecretsIdentityKeyUnavailable catch (e) {
        // A key-based SSH logon has no credentials DPAPI could use.
        markTestSkipped('DPAPI is not available in this logon: ${e.message}');
        return;
      }
      final blob = base64.decode(sealed['blob']! as String);
      expect(blob, isNot(containsAllInOrder(probe.sublist(0, 16))));
      expect(await store.open(sealed, file), probe);

      final key = await TomSecretsServiceIdentityKey.loadOrCreate(
        dir.path,
        secretStore: store,
      );
      expect(key.keptIn, 'dpapi');
      final again = await TomSecretsServiceIdentityKey.loadOrCreate(
        dir.path,
        secretStore: store,
      );
      expect(again.publicKey, key.publicKey);

      final changed = Uint8List.fromList(blob)..[blob.length - 1] ^= 1;
      await expectLater(
        store.open({'blob': base64.encode(changed)}, file),
        throwsA(isA<TomSecretsIdentityKeyUnavailable>()),
      );
    });
  }, testOn: 'windows');

  test('this platform\'s store', () {
    final store = tomSecretsPlatformIdentityStore();
    expect(
      store?.name,
      Platform.isMacOS
          ? 'keychain'
          : Platform.isWindows
          ? 'dpapi'
          : null,
    );
  });
}
