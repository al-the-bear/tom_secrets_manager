// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The protection layers (part-stores, BP-18): key files in the composite
/// key, and the `.tsmx` outer format with key slots under XChaCha20-Poly1305
/// (the default, DP-80) or AES-256-GCM (DP-8, DP-84).
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:tom_core_storage/testing.dart';
import 'package:tom_core_storage/tom_core_storage.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

Uint8List hex(String text) {
  final clean = text.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList([
    for (var i = 0; i < clean.length; i += 2)
      int.parse(clean.substring(i, i + 2), radix: 16),
  ]);
}

String toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Matcher outerFails(String what) => throwsA(
  isA<TomSecretsOuterException>().having(
    (e) => e.message,
    'message',
    contains(what),
  ),
);

void main() {
  group('key files', () {
    test('a generated key file is KeePass 2.0 XML that the KDBX layer reads '
        'as its 32 bytes', () {
      final file = TomSecretsKeyFile.generate();
      final bytes = file.toBytes();
      final text = utf8.decode(bytes);
      expect(text, contains('<Version>2.0</Version>'));
      expect(text, contains('<Data Hash="${file.hash}">'));
      expect(Credentials.keyFileKey(bytes), file.key);
      expect(TomSecretsKeyFile.parse(bytes).key, file.key);
      expect(file.toString(), isNot(contains(toHex(file.key).toUpperCase())));
    });

    test('KeePass\'s own 2.0 key file (the KDBX corpus) parses, its hash '
        'checked', () {
      final corpus = File(
        '../../kdbx_store/test/corpus/keys/corpus_v2.keyx',
      ).readAsBytesSync();
      final file = TomSecretsKeyFile.parse(corpus);
      expect(
        toHex(file.key),
        '0b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186',
      );
      expect(file.hash, '83B7A8ED');
      expect(
        Credentials.keyFileKey(file.toBytes()),
        Credentials.keyFileKey(corpus),
      );
    });

    test('a wrong hash, another version or a short key is refused', () {
      final good = utf8.decode(TomSecretsKeyFile.generate().toBytes());
      for (final bad in [
        good.replaceFirst(RegExp(r'Hash="[0-9A-F]{8}"'), 'Hash="00000000"'),
        good.replaceFirst('<Version>2.0</Version>', '<Version>1.0</Version>'),
        good.replaceFirst(
          RegExp(r'\t\t\t[0-9A-F ]+\n\t\t</Data>'),
          '\t\t</Data>',
        ),
        'not a key file',
      ]) {
        expect(
          () => TomSecretsKeyFile.parse(Uint8List.fromList(utf8.encode(bad))),
          throwsA(isA<TomSecretsKeyFileException>()),
        );
      }
    });

    test('a vault under password plus key file opens with both, not with the '
        'password alone or another key file', () async {
      final keyFile = TomSecretsKeyFile.generate();
      final file = newTestVault(keyFile.credentials('demo-pw'), 'kf');
      final bytes = await file.save();
      expect(
        (await KdbxFormat().read(bytes, keyFile.credentials('demo-pw'))).body,
        isNotNull,
      );
      await expectLater(
        KdbxFormat().read(
          bytes,
          Credentials(ProtectedValue.fromString('demo-pw')),
        ),
        throwsA(isA<KdbxInvalidKeyException>()),
      );
      await expectLater(
        KdbxFormat().read(
          bytes,
          TomSecretsKeyFile.generate().credentials('demo-pw'),
        ),
        throwsA(isA<KdbxInvalidKeyException>()),
      );
    });

    test('the primary vault keeps the key file, and its credentials open the '
        'vault', () async {
      final keyFile = TomSecretsKeyFile.generate();
      final fleet = newTestVault(keyFile.credentials('fleet-pw'), 'f');
      final fleetBytes = await fleet.save();
      final primary = TomSecretsPrimaryVaults(DemoVault().file)
        ..put(
          TomSecretsVaultKeys(
            name: 'fleet',
            locator: 'github:o/r/vaults/fleet.kdbx',
            password: 'fleet-pw',
            keyFile: keyFile.toBytes(),
          ),
        );
      final keys = primary.byName('fleet')!;
      expect(TomSecretsKeyFile.parse(keys.keyFile!).key, keyFile.key);
      expect(
        (await KdbxFormat().read(fleetBytes, keys.credentials)).body,
        isNotNull,
      );
    });
  });

  group('the primitives against published vectors', () {
    test('XChaCha20-Poly1305: draft-irtf-cfrg-xchacha A.3.1', () async {
      final box = await Xchacha20.poly1305Aead().encrypt(
        utf8.encode(
          'Ladies and Gentlemen of the class of \'99: If I could offer you only '
          'one tip for the future, sunscreen would be it.',
        ),
        secretKey: SecretKey(
          hex(
            '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
          ),
        ),
        nonce: hex('404142434445464748494a4b4c4d4e4f5051525354555657'),
        aad: hex('50515253c0c1c2c3c4c5c6c7'),
      );
      expect(
        toHex(box.cipherText),
        'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb'
        '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452'
        '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9'
        '21f9664c97637da9768812f615c68b13b52e',
      );
      expect(toHex(box.mac.bytes), 'c0875924c1c7987947deafd8780acf49');
    });

    test('AES-256-GCM: GCM spec test cases 13 and 14', () async {
      final key = SecretKey(Uint8List(32));
      final empty = await AesGcm.with256bits().encrypt(
        const <int>[],
        secretKey: key,
        nonce: Uint8List(12),
      );
      expect(toHex(empty.mac.bytes), '530f8afbc74536b9a963b4f1c4cb738b');
      final block = await AesGcm.with256bits().encrypt(
        Uint8List(16),
        secretKey: key,
        nonce: Uint8List(12),
      );
      expect(toHex(block.cipherText), 'cea7403d4d606b6e074ec5d3baf39d18');
      expect(toHex(block.mac.bytes), 'd0d1c8a799996bf0265b98b5d48ab919');
    });
  });

  group('the .tsmx outer format', () {
    final content = Uint8List.fromList(utf8.encode('demo KDBX bytes ' * 100));
    const path = 'vaults/fleet.kdbx.tsmx';
    late TomSecretsRepositoryKey key;
    setUp(() => key = TomSecretsRepositoryKey.generate());

    for (final cipher in TomSecretsOuterCipher.values) {
      test('${cipher.name}: round trip, and the layout byte by byte', () async {
        final file = await tomSecretsOuterEncrypt(
          content,
          path: path,
          keys: [key],
          cipher: cipher,
        );
        expect(file.sublist(0, 4), ascii.encode('TSMX'));
        expect(file[4], 1, reason: 'format version');
        expect(file[5], cipher.id);
        expect(file[6], 1, reason: 'one slot');
        expect(file.sublist(7, 15), key.keyId);
        expect(key.keyId, crypto.sha256.convert(key.bytes).bytes.sublist(0, 8));
        final slot = 8 + cipher.nonceLength + 32 + 16;
        expect(slot, inInclusiveRange(68, 80), reason: 'about 70 bytes');
        final header = 7 + slot + cipher.nonceLength;
        expect(file.length, header + content.length + 16);
        expect(
          await tomSecretsOuterDecrypt(file, path: path, keys: [key]),
          content,
        );
        expect(tomSecretsOuterKeyIds(file), [key.keyIdHex]);
      });
    }

    test('XChaCha20-Poly1305 is the default; cipher ids 1 and 2', () async {
      final file = await tomSecretsOuterEncrypt(
        content,
        path: path,
        keys: [key],
      );
      expect(file[5], 2);
      expect(TomSecretsOuterCipher.aes256Gcm.id, 1);
      expect(TomSecretsOuterCipher.ofId(9), isNull);
    });

    test('every write draws a fresh file key and nonces', () async {
      final a = await tomSecretsOuterEncrypt(content, path: path, keys: [key]);
      final b = await tomSecretsOuterEncrypt(content, path: path, keys: [key]);
      expect(toHex(a), isNot(toHex(b)));
      expect(a.sublist(15, 15 + 24), isNot(b.sublist(15, 15 + 24)));
    });

    test('two slots (a rotation\'s migration period): either key opens it, '
        'with no change of the format', () async {
      final second = TomSecretsRepositoryKey.generate();
      final file = await tomSecretsOuterEncrypt(
        content,
        path: path,
        keys: [key, second],
      );
      expect(file[6], 2);
      expect(tomSecretsOuterKeyIds(file), [key.keyIdHex, second.keyIdHex]);
      expect(
        await tomSecretsOuterDecrypt(file, path: path, keys: [second]),
        content,
      );
      expect(
        await tomSecretsOuterDecrypt(file, path: path, keys: [key]),
        content,
      );
    });

    test('a key without a slot is TomKeyRequiredException (the engine asks '
        'for a key)', () async {
      final file = await tomSecretsOuterEncrypt(
        content,
        path: path,
        keys: [key],
      );
      await expectLater(
        tomSecretsOuterDecrypt(
          file,
          path: path,
          keys: [TomSecretsRepositoryKey.generate()],
        ),
        throwsA(isA<TomKeyRequiredException>()),
      );
    });

    test('another path, an altered byte anywhere, a truncated or foreign file '
        'is refused', () async {
      final file = await tomSecretsOuterEncrypt(
        content,
        path: path,
        keys: [key],
      );
      await expectLater(
        tomSecretsOuterDecrypt(
          file,
          path: 'vaults/prod.kdbx.tsmx',
          keys: [key],
        ),
        outerFails('does not open'),
      );
      for (final at in [5, 20, 60, 120, file.length - 1]) {
        final altered = Uint8List.fromList(file)..[at] ^= 1;
        await expectLater(
          tomSecretsOuterDecrypt(altered, path: path, keys: [key]),
          throwsA(isA<Exception>()),
          reason: 'byte $at',
        );
      }
      await expectLater(
        tomSecretsOuterDecrypt(file.sublist(0, 40), path: path, keys: [key]),
        outerFails('truncated'),
      );
      await expectLater(
        tomSecretsOuterDecrypt(content, path: path, keys: [key]),
        outerFails('not a .tsmx file'),
      );
      final v2 = Uint8List.fromList(file)..[4] = 2;
      await expectLater(
        tomSecretsOuterDecrypt(v2, path: path, keys: [key]),
        outerFails('format version 2'),
      );
    });

    test('the format is fixed: a seeded write is these exact bytes', () async {
      final seededKey = TomSecretsRepositoryKey.fromBytes(
        List.generate(32, (i) => i),
      );
      for (final (cipher, digest) in [
        (
          TomSecretsOuterCipher.xchacha20Poly1305,
          'e90680f2588955b570b01034499c54af769ff075eca073d461466221d7d44bee',
        ),
        (
          TomSecretsOuterCipher.aes256Gcm,
          '0c3c4e1919259fec8ac95dee6f042d8c6d3edaa78f350e7b489e2c0f1ad8cfe7',
        ),
      ]) {
        final file = await tomSecretsOuterEncrypt(
          Uint8List.fromList(utf8.encode('fixed content')),
          path: 'vaults/fixed.kdbx.tsmx',
          keys: [seededKey],
          cipher: cipher,
          random: _CountingRandom(),
        );
        expect(
          crypto.sha256.convert(file).toString(),
          digest,
          reason: cipher.name,
        );
      }
    });

    test(
      'the committed phase-A fixtures still open (fixtures/outer)',
      () async {
        final seededKey = TomSecretsRepositoryKey.fromBytes(
          List.generate(32, (i) => i),
        );
        for (final cipher in TomSecretsOuterCipher.values) {
          final file = File(
            'test/fixtures/outer/${cipher.name}.tsmx',
          ).readAsBytesSync();
          expect(file[5], cipher.id);
          expect(
            utf8.decode(
              await tomSecretsOuterDecrypt(
                file,
                path: 'vaults/fixed.kdbx.tsmx',
                keys: [seededKey],
              ),
            ),
            'fixed content',
          );
        }
      },
    );

    test('the repository key moves as base64 (the primary vault\'s '
        'tsm.outer-key)', () {
      final back = TomSecretsRepositoryKey.fromBase64(key.toBase64());
      expect(back.bytes, key.bytes);
      expect(back.keyIdHex, key.keyIdHex);
      expect(key.toString(), isNot(contains(key.toBase64())));
      expect(
        () => TomSecretsRepositoryKey.fromBytes([1, 2, 3]),
        throwsArgumentError,
      );
    });
  });

  group('the outer layer in the GitHub cycle', () {
    test('a vault stored as .kdbx.tsmx: written, read by another device with '
        'the key, refused without it', () async {
      final remote = TomMemoryRemote();
      const locator = 'mem:vaults/fleet.kdbx.tsmx';
      final key = TomSecretsRepositoryKey.generate();
      TomSecretsOuterCodec codec([List<TomSecretsRepositoryKey>? keys]) =>
          TomSecretsOuterCodec(
            path: 'vaults/fleet.kdbx.tsmx',
            keys: keys ?? [key],
          );
      final vault = DemoVault(store: 'fleet')
        ..add('Db/Main', password: 'db0', key: 'db.main');
      final a = await TomSecretsVaultUnit.create(
        locator: locator,
        storage: TomMemoryStorage(remote),
        file: vault.file,
        device: 'mbp',
        codec: codec(),
      );
      final stored = remote.snapshot(locator)[TomChangeset.containerPath]!;
      expect(ascii.decode(stored.sublist(0, 4)), 'TSMX');
      expect(
        utf8.decode(stored, allowMalformed: true),
        isNot(contains('KeePass')),
      );

      final b = await TomSecretsVaultUnit.open(
        locator: locator,
        storage: TomMemoryStorage(remote),
        credentials: demoCredentials,
        device: 'bigbeast',
        codec: codec(),
      );
      b.working.body.rootGroup
          .getAllEntries()
          .firstWhere((e) => e.label == 'Main')
          .setString(KdbxKeyCommon.USER_NAME, PlainValue('u'));
      b.markEdited();
      await b.push();
      expect(await a.pull((await a.storage.headOf(locator))!), isEmpty);
      expect(
        a.working.body.rootGroup
            .getAllEntries()
            .firstWhere((e) => e.label == 'Main')
            .getString(KdbxKeyCommon.USER_NAME)!
            .getText(),
        'u',
      );

      await expectLater(
        TomSecretsVaultUnit.open(
          locator: locator,
          storage: TomMemoryStorage(remote),
          credentials: demoCredentials,
          device: 'bomber',
          codec: codec([TomSecretsRepositoryKey.generate()]),
        ),
        throwsA(isA<TomKeyRequiredException>()),
      );
    });
  });
}

/// A generator whose sequence never changes (dart:math's seeded Random may
/// change between SDK versions): byte i is (37 * i + 11) mod 256.
final class _CountingRandom implements Random {
  int _i = 0;

  @override
  int nextInt(int max) => (37 * _i++ + 11) % max;

  @override
  bool nextBool() => nextInt(2) == 1;

  @override
  double nextDouble() => nextInt(1 << 30) / (1 << 30);
}
