// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Poly1305 (RFC 8439 2.5) and the ChaCha20-Poly1305 tag over associated
/// data and a ciphertext (RFC 8439 2.8), for the content of an outer
/// encrypted vault: with five 26-bit limbs in 64-bit integers it authenticates
/// a vault with tens of megabytes of attachments in a fraction of the time
/// the general implementation needs. Its output is the same, byte for byte;
/// the tests compare the two.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// The Poly1305 tag (16 bytes) under the one-time [key] (32 bytes) of the
/// [parts], taken as one message.
Uint8List tomSecretsPoly1305(Uint8List key, List<Uint8List> parts) {
  if (key.length != 32) {
    throw ArgumentError.value(key.length, 'key', '32 bytes');
  }
  final mac = _Poly1305(key);
  for (final part in parts) {
    mac.add(part);
  }
  return mac.finish();
}

/// The tag of ChaCha20-Poly1305 (RFC 8439 2.8) under the one-time [key]:
/// over [aad] and [cipherText], each padded to 16 bytes, then their lengths
/// as 8 bytes little-endian each.
Uint8List tomSecretsAeadTag(
  Uint8List key,
  Uint8List aad,
  Uint8List cipherText,
) {
  final lengths = ByteData(16)
    ..setUint64(0, aad.length, Endian.little)
    ..setUint64(8, cipherText.length, Endian.little);
  return tomSecretsPoly1305(key, [
    aad,
    Uint8List((16 - aad.length % 16) % 16),
    cipherText,
    Uint8List((16 - cipherText.length % 16) % 16),
    lengths.buffer.asUint8List(),
  ]);
}

/// Whether [a] and [b] are equal, in time independent of where they differ.
bool tomSecretsTagsEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

const int _mask = 0x3ffffff;

final class _Poly1305 {
  _Poly1305(Uint8List key) {
    final k = ByteData.sublistView(key);
    // r, clamped (RFC 8439 2.5.1), as five 26-bit limbs.
    _r0 = k.getUint32(0, Endian.little) & 0x3ffffff;
    _r1 = (k.getUint32(3, Endian.little) >> 2) & 0x3ffff03;
    _r2 = (k.getUint32(6, Endian.little) >> 4) & 0x3ffc0ff;
    _r3 = (k.getUint32(9, Endian.little) >> 6) & 0x3f03fff;
    _r4 = (k.getUint32(12, Endian.little) >> 8) & 0x00fffff;
    _s = Uint8List.fromList(Uint8List.sublistView(key, 16, 32));
  }

  late final int _r0, _r1, _r2, _r3, _r4;
  late final Uint8List _s;
  int _h0 = 0, _h1 = 0, _h2 = 0, _h3 = 0, _h4 = 0;

  // A block not yet complete (a part that does not end on 16 bytes).
  final Uint8List _buffer = Uint8List(16);
  int _buffered = 0;

  void add(Uint8List data) {
    var at = 0;
    if (_buffered > 0) {
      final take = 16 - _buffered < data.length ? 16 - _buffered : data.length;
      _buffer.setRange(_buffered, _buffered + take, data);
      _buffered += take;
      at = take;
      if (_buffered < 16) return;
      _blocks(_buffer, 0, 16, 1 << 24);
      _buffered = 0;
    }
    final whole = (data.length - at) & ~15;
    if (whole > 0) _blocks(data, at, whole, 1 << 24);
    at += whole;
    if (at < data.length) {
      _buffer.setRange(0, data.length - at, data, at);
      _buffered = data.length - at;
    }
  }

  /// [length] bytes (a multiple of 16) of [data] from [offset]; [hibit] is
  /// the bit above a full block, 0 for the padded last one.
  void _blocks(Uint8List data, int offset, int length, int hibit) {
    final m = ByteData.sublistView(data, offset, offset + length);
    final r0 = _r0, r1 = _r1, r2 = _r2, r3 = _r3, r4 = _r4;
    final s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    var h0 = _h0, h1 = _h1, h2 = _h2, h3 = _h3, h4 = _h4;
    for (var i = 0; i < length; i += 16) {
      h0 += m.getUint32(i, Endian.little) & _mask;
      h1 += (m.getUint32(i + 3, Endian.little) >> 2) & _mask;
      h2 += (m.getUint32(i + 6, Endian.little) >> 4) & _mask;
      h3 += (m.getUint32(i + 9, Endian.little) >> 6) & _mask;
      h4 += (m.getUint32(i + 12, Endian.little) >> 8) | hibit;
      // h *= r, modulo 2^130 - 5: every product stays below 2^58.
      final d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
      var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
      var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
      var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
      var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
      var c = d0 >>> 26;
      h0 = d0 & _mask;
      d1 += c;
      c = d1 >>> 26;
      h1 = d1 & _mask;
      d2 += c;
      c = d2 >>> 26;
      h2 = d2 & _mask;
      d3 += c;
      c = d3 >>> 26;
      h3 = d3 & _mask;
      d4 += c;
      c = d4 >>> 26;
      h4 = d4 & _mask;
      h0 += c * 5;
      c = h0 >>> 26;
      h0 &= _mask;
      h1 += c;
    }
    _h0 = h0;
    _h1 = h1;
    _h2 = h2;
    _h3 = h3;
    _h4 = h4;
  }

  Uint8List finish() {
    if (_buffered > 0) {
      // The last block: a 1 after its bytes, zeros to 16.
      _buffer[_buffered] = 1;
      _buffer.fillRange(_buffered + 1, 16, 0);
      _blocks(_buffer, 0, 16, 0);
    }
    var h0 = _h0, h1 = _h1, h2 = _h2, h3 = _h3, h4 = _h4;
    // Carry fully.
    var c = h1 >>> 26;
    h1 &= _mask;
    h2 += c;
    c = h2 >>> 26;
    h2 &= _mask;
    h3 += c;
    c = h3 >>> 26;
    h3 &= _mask;
    h4 += c;
    c = h4 >>> 26;
    h4 &= _mask;
    h0 += c * 5;
    c = h0 >>> 26;
    h0 &= _mask;
    h1 += c;
    // g = h + 5 - 2^130; taken when h >= 2^130 - 5.
    var g0 = h0 + 5;
    c = g0 >>> 26;
    g0 &= _mask;
    var g1 = h1 + c;
    c = g1 >>> 26;
    g1 &= _mask;
    var g2 = h2 + c;
    c = g2 >>> 26;
    g2 &= _mask;
    var g3 = h3 + c;
    c = g3 >>> 26;
    g3 &= _mask;
    final g4 = h4 + c - (1 << 26);
    // All ones when g is not negative (h >= p), else zero; no branch.
    final take = ((g4 >>> 63) - 1) & 0xffffffffffffffff;
    final keep = ~take;
    h0 = (h0 & keep) | (g0 & take);
    h1 = (h1 & keep) | (g1 & take);
    h2 = (h2 & keep) | (g2 & take);
    h3 = (h3 & keep) | (g3 & take);
    h4 = (h4 & keep) | (g4 & take & _mask);
    // h as four 32-bit words, plus s, modulo 2^128.
    final w0 = (h0 | (h1 << 26)) & 0xffffffff;
    final w1 = ((h1 >>> 6) | (h2 << 20)) & 0xffffffff;
    final w2 = ((h2 >>> 12) | (h3 << 14)) & 0xffffffff;
    final w3 = ((h3 >>> 18) | (h4 << 8)) & 0xffffffff;
    final s = ByteData.sublistView(_s);
    final out = ByteData(16);
    var f = w0 + s.getUint32(0, Endian.little);
    out.setUint32(0, f & 0xffffffff, Endian.little);
    f = w1 + s.getUint32(4, Endian.little) + (f >>> 32);
    out.setUint32(4, f & 0xffffffff, Endian.little);
    f = w2 + s.getUint32(8, Endian.little) + (f >>> 32);
    out.setUint32(8, f & 0xffffffff, Endian.little);
    f = w3 + s.getUint32(12, Endian.little) + (f >>> 32);
    out.setUint32(12, f & 0xffffffff, Endian.little);
    _s.fillRange(0, 16, 0);
    _buffer.fillRange(0, 16, 0);
    return out.buffer.asUint8List();
  }
}

// XChaCha20-Poly1305 over a vault's content, as the AEAD defines it (RFC
// 8439 2.8 with the XChaCha20 stream): the Poly1305 key is the first 32
// bytes of the key stream, the content is encrypted from its second block
// (byte 64), and the tag covers the associated data and the ciphertext. The
// stream is package:cryptography's; the tag is computed here, in a
// fraction of the time for the same bytes. The output is that package's
// own `Xchacha20.poly1305Aead()`, byte for byte (poly1305_test.dart).
final Xchacha20 _xchachaStream = Xchacha20(macAlgorithm: MacAlgorithm.empty);

Future<Uint8List> _xchachaMacKey(List<int> key, List<int> nonce) async {
  final block = await _xchachaStream.encrypt(
    Uint8List(32),
    secretKey: SecretKey(key),
    nonce: nonce,
  );
  final text = block.cipherText;
  return text is Uint8List ? text : Uint8List.fromList(text);
}

/// [content] sealed with XChaCha20-Poly1305 under [key] (32 bytes) and
/// [nonce] (24 bytes), [aad] authenticated with it.
Future<({Uint8List cipherText, List<int> tag})> tomSecretsXchachaSeal(
  Uint8List content,
  List<int> key,
  List<int> nonce,
  Uint8List aad,
) async {
  final macKey = await _xchachaMacKey(key, nonce);
  try {
    final box = await _xchachaStream.encrypt(
      content,
      secretKey: SecretKey(key),
      nonce: nonce,
      keyStreamIndex: 64,
    );
    final text = box.cipherText;
    final cipherText = text is Uint8List ? text : Uint8List.fromList(text);
    return (
      cipherText: cipherText,
      tag: tomSecretsAeadTag(macKey, aad, cipherText),
    );
  } finally {
    macKey.fillRange(0, macKey.length, 0);
  }
}

/// [cipherText] opened with XChaCha20-Poly1305. Throws
/// [SecretBoxAuthenticationError] when [tag] is not the tag of [cipherText]
/// and [aad]: nothing is decrypted then.
Future<Uint8List> tomSecretsXchachaOpen(
  Uint8List cipherText,
  List<int> tag,
  List<int> key,
  List<int> nonce,
  Uint8List aad,
) async {
  final macKey = await _xchachaMacKey(key, nonce);
  try {
    if (!tomSecretsTagsEqual(tomSecretsAeadTag(macKey, aad, cipherText), tag)) {
      throw SecretBoxAuthenticationError();
    }
  } finally {
    macKey.fillRange(0, macKey.length, 0);
  }
  final opened = await _xchachaStream.decrypt(
    SecretBox(cipherText, nonce: nonce, mac: Mac.empty),
    secretKey: SecretKey(key),
    keyStreamIndex: 64,
  );
  return opened is Uint8List ? opened : Uint8List.fromList(opened);
}
