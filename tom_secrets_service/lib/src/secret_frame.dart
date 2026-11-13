// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Frames that carry secrets (part-service, Memory hygiene): a value, a
/// password or a key is written into the frame buffer straight from bytes
/// that are zeroed afterwards, never through a `String`, so the only copy
/// left is the frame itself, which the connection wipes once the socket has
/// sent it.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:tom_crypto/protected_value.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'admin_auth.dart' show tomSecretsRandomBytes;

/// Reads a secret's bytes for the duration of a callback, zeroing them after.
typedef TomSecretsBytesReader = T Function<T>(T Function(Uint8List bytes) use);

/// A secret in a message, written into the frame as a JSON string: the text
/// of UTF-8 bytes, escaped, or the base64 of any bytes.
final class TomSecretsSecretSlot {
  /// The text whose UTF-8 bytes [read] gives.
  const TomSecretsSecretSlot.text(this.read) : isBase64 = false;

  /// The base64 of the bytes [read] gives.
  const TomSecretsSecretSlot.base64(this.read) : isBase64 = true;

  /// A value as `get` answers it: text as text, bytes as base64.
  factory TomSecretsSecretSlot.ofValue(TomSecretsFieldValue value) =>
      value.isText
      ? TomSecretsSecretSlot.text(value.withBytes)
      : TomSecretsSecretSlot.base64(value.withBytes);

  /// The text of a protected value.
  factory TomSecretsSecretSlot.ofText(TomProtectedValue value) =>
      TomSecretsSecretSlot.text(value.withRevealed);

  /// The base64 of a protected value's bytes.
  factory TomSecretsSecretSlot.ofBytes(TomProtectedValue value) =>
      TomSecretsSecretSlot.base64(value.withRevealed);

  /// Reads the bytes.
  final TomSecretsBytesReader read;

  /// Whether the bytes are written as base64 (else as escaped UTF-8 text).
  final bool isBase64;

  /// The length of the JSON string literal, quotes included.
  int _literalLength() => read(
    (bytes) => 2 + (isBase64 ? _base64Length(bytes.length) : _escaped(bytes)),
  );

  /// Writes the literal into [out] at [offset]; the offset after it.
  int _writeInto(Uint8List out, int offset) => read((bytes) {
    var i = offset;
    out[i++] = _quote;
    i = isBase64 ? _writeBase64(bytes, out, i) : _writeEscaped(bytes, out, i);
    out[i++] = _quote;
    return i;
  });

  @override
  String toString() => 'TomSecretsSecretSlot(***)';
}

const int _quote = 0x22;
const int _backslash = 0x5c;

int _base64Length(int n) => (n + 2) ~/ 3 * 4;

/// The short escapes JSON has (and `jsonEncode` writes).
const Map<int, int> _shortEscapes = {
  0x08: 0x62, // b
  0x09: 0x74, // t
  0x0a: 0x6e, // n
  0x0c: 0x66, // f
  0x0d: 0x72, // r
  _quote: _quote,
  _backslash: _backslash,
};

int _escaped(Uint8List bytes) {
  var n = 0;
  for (final b in bytes) {
    n += _shortEscapes.containsKey(b) ? 2 : (b < 0x20 ? 6 : 1);
  }
  return n;
}

const String _hex = '0123456789abcdef';

int _writeEscaped(Uint8List bytes, Uint8List out, int offset) {
  var i = offset;
  for (final b in bytes) {
    final short = _shortEscapes[b];
    if (short != null) {
      out[i++] = _backslash;
      out[i++] = short;
    } else if (b < 0x20) {
      out[i++] = _backslash;
      out[i++] = 0x75; // u
      out[i++] = 0x30;
      out[i++] = 0x30;
      out[i++] = _hex.codeUnitAt(b >> 4);
      out[i++] = _hex.codeUnitAt(b & 0xf);
    } else {
      // UTF-8 bytes above 0x7f are copied as they are: JSON text is UTF-8.
      out[i++] = b;
    }
  }
  return i;
}

const String _alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

int _writeBase64(Uint8List bytes, Uint8List out, int offset) {
  var i = offset;
  var j = 0;
  for (; j + 3 <= bytes.length; j += 3) {
    final n = bytes[j] << 16 | bytes[j + 1] << 8 | bytes[j + 2];
    out[i++] = _alphabet.codeUnitAt(n >> 18 & 63);
    out[i++] = _alphabet.codeUnitAt(n >> 12 & 63);
    out[i++] = _alphabet.codeUnitAt(n >> 6 & 63);
    out[i++] = _alphabet.codeUnitAt(n & 63);
  }
  final rest = bytes.length - j;
  if (rest > 0) {
    final n = bytes[j] << 16 | (rest == 2 ? bytes[j + 1] << 8 : 0);
    out[i++] = _alphabet.codeUnitAt(n >> 18 & 63);
    out[i++] = _alphabet.codeUnitAt(n >> 12 & 63);
    out[i++] = rest == 2 ? _alphabet.codeUnitAt(n >> 6 & 63) : 0x3d;
    out[i++] = 0x3d;
  }
  return i;
}

/// A message's frame (protocol.md 2): the compact JSON of [message], every
/// [TomSecretsSecretSlot] in it written from its bytes. Byte for byte what
/// `tomSecretsJsonFrame` writes for the same message with the secrets as
/// strings. Returns null when the payload exceeds [maxPayload]; nothing of a
/// secret is then left in memory.
Uint8List? tomSecretsSecretFrame(
  Map<String, Object?> message, {
  int maxPayload = tomSecretsMaxAnswerPayload,
}) {
  final slots = <TomSecretsSecretSlot>[];
  final nonce = base64Url.encode(tomSecretsRandomBytes(12));
  String token(int i) => 'tsm-slot:$nonce:$i';
  Object? replace(Object? value) => switch (value) {
    TomSecretsSecretSlot() => token((slots..add(value)).length - 1),
    Map() => {for (final e in value.entries) e.key as String: replace(e.value)},
    List() => [for (final v in value) replace(v)],
    _ => value,
  };
  final skeleton = utf8.encode(jsonEncode(replace(message)));
  if (slots.isEmpty) {
    if (skeleton.length > maxPayload) return null;
    return tomSecretsEncodeFrame(tomSecretsFrameJson, skeleton);
  }
  // Each token appears once, as a JSON string literal: "tsm-slot:...:i".
  final positions = <int>[];
  final lengths = <int>[];
  var size = skeleton.length;
  for (var i = 0; i < slots.length; i++) {
    final literal = utf8.encode('"${token(i)}"');
    final at = _indexOf(skeleton, literal);
    if (at < 0) throw StateError('slot $i was not encoded');
    positions.add(at);
    lengths.add(literal.length);
    size += slots[i]._literalLength() - literal.length;
  }
  if (size > maxPayload) return null;
  final order = List<int>.generate(slots.length, (i) => i)
    ..sort((a, b) => positions[a].compareTo(positions[b]));
  final out = Uint8List(5 + size);
  ByteData.sublistView(out).setUint32(0, size);
  out[4] = tomSecretsFrameJson;
  var o = 5;
  var s = 0;
  for (final i in order) {
    out.setRange(o, o + positions[i] - s, skeleton, s);
    o += positions[i] - s;
    o = slots[i]._writeInto(out, o);
    s = positions[i] + lengths[i];
  }
  out.setRange(o, out.length, skeleton, s);
  return out;
}

int _indexOf(Uint8List haystack, List<int> needle) {
  outer:
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}
