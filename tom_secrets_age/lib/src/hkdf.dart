// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// HKDF-SHA-256 (RFC 5869), shared by the `age` format and the pairing.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// HKDF-SHA-256 (RFC 5869) of [ikm] with [salt] and [info], [length] bytes.
Uint8List tomSecretsHkdf(
  List<int> ikm, {
  required List<int> salt,
  required List<int> info,
  required int length,
}) {
  final prk = _hmac(salt.isEmpty ? List.filled(32, 0) : salt, ikm);
  final out = BytesBuilder();
  var previous = <int>[];
  for (var i = 1; out.length < length; i++) {
    previous = _hmac(prk, [...previous, ...info, i]);
    out.add(previous);
  }
  return Uint8List.fromList(out.toBytes().sublist(0, length));
}

Uint8List _hmac(List<int> key, List<int> data) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);
