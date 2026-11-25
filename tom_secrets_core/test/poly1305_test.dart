// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The vault content's Poly1305 against RFC 8439's vectors and, for random
// keys and lengths (every length around the block and buffer borders, parts
// cut anywhere), against package:cryptography's.
@TestOn('vm')
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_core/src/poly1305.dart';

Uint8List _hex(String text) {
  final t = text.replaceAll(RegExp(r'[\s:]'), '');
  return Uint8List.fromList([
    for (var i = 0; i < t.length; i += 2)
      int.parse(t.substring(i, i + 2), radix: 16),
  ]);
}

void main() {
  test('RFC 8439 2.5.2: the tag of the example message', () {
    final key = _hex(
      '85d6be7857556d337f4452fe42d506a8'
      '0103808afb0db2fd4abff6af4149f51b',
    );
    final message = Uint8List.fromList(
      'Cryptographic Forum Research Group'.codeUnits,
    );
    expect(
      tomSecretsPoly1305(key, [message]),
      _hex('a8061dc1305136c6c22b8baf0c0127a9'),
    );
  });

  test('RFC 8439 A.3: the vectors that carry and wrap', () {
    // #1: all zero. #4-#6 exercise the final reduction.
    expect(tomSecretsPoly1305(Uint8List(32), [Uint8List(64)]), Uint8List(16));
    final r2 = _hex(
      '02000000000000000000000000000000'
      '00000000000000000000000000000000',
    );
    expect(
      tomSecretsPoly1305(r2, [_hex('ffffffffffffffffffffffffffffffff')]),
      _hex('03000000000000000000000000000000'),
      reason: 'A.3 #5: 2^130 - 5 wraps',
    );
    final r2s = _hex(
      '02000000000000000000000000000000'
      'ffffffffffffffffffffffffffffffff',
    );
    expect(
      tomSecretsPoly1305(r2s, [_hex('02000000000000000000000000000000')]),
      _hex('03000000000000000000000000000000'),
      reason: 'A.3 #6: the sum with s wraps',
    );
    final r1 = _hex(
      '01000000000000000000000000000000'
      '00000000000000000000000000000000',
    );
    expect(
      tomSecretsPoly1305(r1, [
        _hex(
          'ffffffffffffffffffffffffffffffff'
          'f0ffffffffffffffffffffffffffffff'
          '11000000000000000000000000000000',
        ),
      ]),
      _hex('05000000000000000000000000000000'),
      reason: 'A.3 #7',
    );
    expect(
      tomSecretsPoly1305(r1, [
        _hex(
          'ffffffffffffffffffffffffffffffff'
          'fbfefefefefefefefefefefefefefefe'
          '01010101010101010101010101010101',
        ),
      ]),
      Uint8List(16),
      reason: 'A.3 #8',
    );
    expect(
      tomSecretsPoly1305(r2, [_hex('fdffffffffffffffffffffffffffffff')]),
      _hex('faffffffffffffffffffffffffffffff'),
      reason: 'A.3 #9',
    );
    final r4 = _hex(
      '01000000000000000400000000000000'
      '00000000000000000000000000000000',
    );
    final blocks = _hex(
      'e33594d7505e43b90000000000000000'
      '3394d7505e4379cd0100000000000000'
      '00000000000000000000000000000000'
      '01000000000000000000000000000000',
    );
    expect(
      tomSecretsPoly1305(r4, [blocks]),
      _hex('14000000000000005500000000000000'),
      reason: 'A.3 #10',
    );
    expect(
      tomSecretsPoly1305(r4, [Uint8List.sublistView(blocks, 0, 48)]),
      _hex('13000000000000000000000000000000'),
      reason: 'A.3 #11',
    );
    // An empty message: the tag is s (the general implementation pads it
    // as a block, which the AEAD never asks for).
    final key = _hex(
      '85d6be7857556d337f4452fe42d506a8'
      '0103808afb0db2fd4abff6af4149f51b',
    );
    expect(
      tomSecretsPoly1305(key, [Uint8List(0)]),
      _hex('0103808afb0db2fd4abff6af4149f51b'),
    );
  });

  test('the same as package:cryptography for random keys, every length from 1 '
      'to 80 and around larger borders, and parts cut anywhere', () async {
    final random = Random(42);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));
    final reference = Poly1305();
    final lengths = [
      for (var n = 1; n <= 80; n++) n,
      255,
      256,
      257,
      1023,
      1024,
      1025,
      4095,
      4097,
      65535,
      65536,
      65537,
      1000003,
    ];
    for (final n in lengths) {
      // Keys of all ones too: the largest limbs.
      for (final key in [bytes(32), Uint8List(32)..fillRange(0, 32, 255)]) {
        final message = n % 7 == 3
            ? (Uint8List(n)..fillRange(0, n, 255))
            : bytes(n);
        final expected = (await reference.calculateMac(
          message,
          secretKey: SecretKey(key),
        )).bytes;
        expect(tomSecretsPoly1305(key, [message]), expected, reason: 'n=$n');
        // The same message in parts.
        final cut1 = n == 0 ? 0 : random.nextInt(n + 1);
        final cut2 = cut1 + (n == cut1 ? 0 : random.nextInt(n - cut1 + 1));
        expect(
          tomSecretsPoly1305(key, [
            Uint8List.sublistView(message, 0, cut1),
            Uint8List(0),
            Uint8List.sublistView(message, cut1, cut2),
            Uint8List.sublistView(message, cut2),
          ]),
          expected,
          reason: 'n=$n cut at $cut1, $cut2',
        );
      }
    }
  });

  test('XChaCha20-Poly1305 over a content: the same ciphertext and tag as '
      'package:cryptography\'s AEAD, each opens the other\'s, and a changed '
      'byte of the ciphertext, the tag or the associated data opens '
      'nothing', () async {
    final random = Random(7);
    Uint8List bytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));
    final reference = Xchacha20.poly1305Aead();
    for (final n in [0, 1, 15, 16, 17, 63, 64, 65, 1000, 65536, 300001]) {
      final key = bytes(32);
      final nonce = bytes(24);
      final aad = bytes(n % 5 == 0 ? 0 : 7 + n % 40);
      final content = bytes(n);
      final box = await reference.encrypt(
        content,
        secretKey: SecretKey(key),
        nonce: nonce,
        aad: aad,
      );
      final sealed = await tomSecretsXchachaSeal(content, key, nonce, aad);
      expect(sealed.cipherText, box.cipherText, reason: 'n=$n');
      expect(sealed.tag, box.mac.bytes, reason: 'n=$n');
      expect(
        await tomSecretsXchachaOpen(
          Uint8List.fromList(box.cipherText),
          box.mac.bytes,
          key,
          nonce,
          aad,
        ),
        content,
        reason: 'n=$n',
      );
      expect(
        await reference.decrypt(
          SecretBox(sealed.cipherText, nonce: nonce, mac: Mac(sealed.tag)),
          secretKey: SecretKey(key),
          aad: aad,
        ),
        content,
      );
      Future<void> refused(Uint8List text, List<int> tag, Uint8List data) =>
          expectLater(
            tomSecretsXchachaOpen(text, tag, key, nonce, data),
            throwsA(isA<SecretBoxAuthenticationError>()),
            reason: 'n=$n',
          );
      final badTag = [...sealed.tag]..[n % 16] ^= 1;
      await refused(sealed.cipherText, badTag, aad);
      await refused(sealed.cipherText, sealed.tag, bytes(aad.length + 1));
      if (n > 0) {
        final badText = Uint8List.fromList(sealed.cipherText)..[n ~/ 2] ^= 0x80;
        await refused(badText, sealed.tag, aad);
      }
    }
  });

  test('the tags compare without a shortcut', () {
    expect(tomSecretsTagsEqual([1, 2, 3], [1, 2, 3]), isTrue);
    expect(tomSecretsTagsEqual([1, 2, 3], [1, 2, 4]), isFalse);
    expect(tomSecretsTagsEqual([1, 2, 3], [1, 2]), isFalse);
  });
}
