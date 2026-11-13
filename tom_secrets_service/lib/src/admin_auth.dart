// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The admin channel's mutual challenge (protocol.md 6.1): both sides prove
/// they hold the admin key, the key never crosses the channel.
///
/// `mac = HMAC-SHA256(adminKey, "tsm-admin-v1" || serviceNonce || adminNonce
/// || serviceStart)`, `mac2` the same under `tsm-service-v1`; the nonces are
/// 32 raw bytes each, `serviceStart` 8 bytes big-endian.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// The admin's label.
const String tomSecretsAdminLabel = 'tsm-admin-v1';

/// The service's label.
const String tomSecretsServiceLabel = 'tsm-service-v1';

/// The length of an admin key and of a nonce.
const int tomSecretsKeyBytes = 32;

/// The MAC input: [label]'s ASCII, both nonces, [serviceStart] as 8 bytes
/// big-endian.
Uint8List tomSecretsChallengeInput(
  String label,
  List<int> serviceNonce,
  List<int> adminNonce,
  int serviceStart,
) {
  if (serviceNonce.length != tomSecretsKeyBytes ||
      adminNonce.length != tomSecretsKeyBytes) {
    throw ArgumentError('a nonce is $tomSecretsKeyBytes bytes');
  }
  final start = ByteData(8)..setUint64(0, serviceStart);
  return Uint8List.fromList([
    ...ascii.encode(label),
    ...serviceNonce,
    ...adminNonce,
    ...start.buffer.asUint8List(),
  ]);
}

/// The MAC of [label] over the challenge under [adminKey].
Uint8List tomSecretsChallengeMac(
  List<int> adminKey,
  String label,
  List<int> serviceNonce,
  List<int> adminNonce,
  int serviceStart,
) => Uint8List.fromList(
  crypto.Hmac(crypto.sha256, adminKey)
      .convert(
        tomSecretsChallengeInput(label, serviceNonce, adminNonce, serviceStart),
      )
      .bytes,
);

/// Whether [a] equals [b], in time independent of where they differ.
bool tomSecretsConstantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// [count] bytes from the OS's secure generator.
Uint8List tomSecretsRandomBytes([int count = tomSecretsKeyBytes]) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(count, (_) => random.nextInt(256)));
}

/// The delay before the next authentication after [failures] failed ones:
/// 0, then 1 s, 2 s, 4 s … up to 60 s (protocol.md 6.1).
Duration tomSecretsAuthDelay(int failures) {
  if (failures <= 0) return Duration.zero;
  final seconds = 1 << (failures - 1).clamp(0, 6);
  return Duration(seconds: seconds > 60 ? 60 : seconds);
}
