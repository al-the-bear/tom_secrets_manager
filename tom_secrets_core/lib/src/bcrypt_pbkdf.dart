// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `bcrypt_pbkdf`, the key derivation OpenSSH encrypts its private key
/// files with (`openssh-key-v1`, kdf `bcrypt`), as OpenBSD's
/// `bcrypt_pbkdf.c` defines it: SHA-512 of the passphrase and of the salt
/// with a counter, hashed by eksblowfish ("OxychromaticBlowfishSwatDynamite"
/// encrypted 64 times), XORed over the rounds and spread over the output.
///
/// Blowfish's initial state is the fractional part of π in hexadecimal
/// (18 P words, then the four S-boxes), computed here once with Machin's
/// formula instead of being carried as a table.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// The [length] bytes `bcrypt_pbkdf` derives from [passphrase] and [salt] in
/// [rounds] rounds. Throws [ArgumentError] for an empty output or salt, or
/// fewer than one round.
Uint8List tomSecretsBcryptPbkdf(
  List<int> passphrase,
  List<int> salt,
  int length,
  int rounds,
) {
  if (length < 1 || length > 1024 || salt.isEmpty || rounds < 1) {
    throw ArgumentError('length, salt and rounds');
  }
  const hashSize = 32;
  final key = Uint8List(length);
  final stride = (length + hashSize - 1) ~/ hashSize;
  var amount = (length + stride - 1) ~/ stride;
  final sha2pass = crypto.sha512.convert(passphrase).bytes;
  var remaining = length;
  for (var count = 1; remaining > 0; count++) {
    final countSalt = [
      ...salt,
      (count >> 24) & 0xff,
      (count >> 16) & 0xff,
      (count >> 8) & 0xff,
      count & 0xff,
    ];
    var sha2salt = crypto.sha512.convert(countSalt).bytes;
    var tmp = _bcryptHash(sha2pass, sha2salt);
    final out = Uint8List.fromList(tmp);
    for (var i = 1; i < rounds; i++) {
      sha2salt = crypto.sha512.convert(tmp).bytes;
      tmp = _bcryptHash(sha2pass, sha2salt);
      for (var j = 0; j < out.length; j++) {
        out[j] ^= tmp[j];
      }
    }
    if (amount > remaining) amount = remaining;
    var i = 0;
    for (; i < amount; i++) {
      final dest = i * stride + (count - 1);
      if (dest >= length) break;
      key[dest] = out[i];
    }
    remaining -= i;
  }
  return key;
}

const String _magic = 'OxychromaticBlowfishSwatDynamite';

Uint8List _bcryptHash(List<int> sha2pass, List<int> sha2salt) {
  final state = _Blowfish.initial()..expandState(sha2salt, sha2pass);
  for (var i = 0; i < 64; i++) {
    state
      ..expand0State(sha2salt)
      ..expand0State(sha2pass);
  }
  final cdata = Uint32List(8);
  var j = 0;
  final magic = _magic.codeUnits;
  for (var i = 0; i < 8; i++) {
    cdata[i] = _streamToWord(magic, j);
    j = (j + 4) % magic.length;
  }
  for (var i = 0; i < 64; i++) {
    for (var b = 0; b < 8; b += 2) {
      state.encipher(cdata, b);
    }
  }
  final out = Uint8List(32);
  for (var i = 0; i < 8; i++) {
    out[4 * i + 3] = (cdata[i] >> 24) & 0xff;
    out[4 * i + 2] = (cdata[i] >> 16) & 0xff;
    out[4 * i + 1] = (cdata[i] >> 8) & 0xff;
    out[4 * i] = cdata[i] & 0xff;
  }
  return out;
}

/// Four bytes of [data] from [at], wrapping around, big-endian.
int _streamToWord(List<int> data, int at) {
  var w = 0;
  for (var i = 0; i < 4; i++) {
    w = (w << 8) | data[(at + i) % data.length];
  }
  return w;
}

/// The Blowfish state eksblowfish works on.
final class _Blowfish {
  _Blowfish(this.p, this.s);

  factory _Blowfish.initial() {
    final pi = _piWords();
    return _Blowfish(
      Uint32List.fromList(pi.sublist(0, 18)),
      Uint32List.fromList(pi.sublist(18)),
    );
  }

  /// The 18 P words.
  final Uint32List p;

  /// The four S-boxes, one after another (1024 words).
  final Uint32List s;

  int _f(int x) =>
      ((((s[(x >> 24) & 0xff] + s[256 + ((x >> 16) & 0xff)]) & 0xffffffff) ^
              s[512 + ((x >> 8) & 0xff)]) +
          s[768 + (x & 0xff)]) &
      0xffffffff;

  /// Encrypts the block at [data][at], [data][at + 1] in place.
  void encipher(Uint32List data, int at) {
    var l = data[at];
    var r = data[at + 1];
    l ^= p[0];
    for (var i = 1; i <= 16; i += 2) {
      r ^= _f(l) ^ p[i];
      l ^= _f(r) ^ p[i + 1];
    }
    data[at] = r ^ p[17];
    data[at + 1] = l;
  }

  void _xorKey(List<int> key) {
    var j = 0;
    for (var i = 0; i < 18; i++) {
      p[i] ^= _streamToWord(key, j);
      j = (j + 4) % key.length;
    }
  }

  /// `Blowfish_expandstate`: the key into P, then P and the S-boxes
  /// rewritten by encrypting the salt [data] chained.
  void expandState(List<int> data, List<int> key) {
    _xorKey(key);
    var j = 0;
    final block = Uint32List(2);
    void next(Uint32List into, int at) {
      block[0] ^= _streamToWord(data, j);
      j = (j + 4) % data.length;
      block[1] ^= _streamToWord(data, j);
      j = (j + 4) % data.length;
      encipher(block, 0);
      into[at] = block[0];
      into[at + 1] = block[1];
    }

    for (var i = 0; i < 18; i += 2) {
      next(p, i);
    }
    for (var i = 0; i < 1024; i += 2) {
      next(s, i);
    }
  }

  /// `Blowfish_expand0state`: the key into P, then P and the S-boxes
  /// rewritten by encrypting a zero block chained.
  void expand0State(List<int> key) {
    _xorKey(key);
    final block = Uint32List(2);
    for (var i = 0; i < 18; i += 2) {
      encipher(block, 0);
      p[i] = block[0];
      p[i + 1] = block[1];
    }
    for (var i = 0; i < 1024; i += 2) {
      encipher(block, 0);
      s[i] = block[0];
      s[i + 1] = block[1];
    }
  }
}

List<int>? _pi;

/// The first 1042 32-bit words of π's fractional part (Blowfish's P and S
/// initial values), computed once.
List<int> _piWords() => _pi ??= () {
  const words = 18 + 1024;
  const bits = words * 32 + 64;
  final one = BigInt.one << bits;
  BigInt arctanInverse(int x) {
    final xx = BigInt.from(x * x);
    var term = one ~/ BigInt.from(x);
    var sum = term;
    var k = 1;
    while (term != BigInt.zero) {
      term = term ~/ xx;
      final t = term ~/ BigInt.from(2 * k + 1);
      sum = k.isOdd ? sum - t : sum + t;
      k++;
    }
    return sum;
  }

  final pi =
      (arctanInverse(5) * BigInt.from(16)) -
      (arctanInverse(239) * BigInt.from(4));
  final fraction = (pi - (BigInt.from(3) << bits)) >> 64;
  final mask = BigInt.from(0xffffffff);
  return [
    for (var i = words - 1; i >= 0; i--)
      ((fraction >> (i * 32)) & mask).toInt(),
  ];
}();
