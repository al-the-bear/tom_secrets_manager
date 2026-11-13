// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// TOTP (RFC 6238) and its three KDBX conventions (DP-38): `otp` as KeePassXC
/// writes it and `OTPAuth` as AuthPass writes it (both an `otpauth://` URI),
/// and KeePass 2.47+'s `TimeOtp-Secret-Base32` with `TimeOtp-Length`,
/// `TimeOtp-Period` and `TimeOtp-Algorithm`.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

/// The TOTP field names.
abstract final class TomSecretsTotpFields {
  /// KeePassXC's `otpauth://` URI.
  static const otp = KdbxKey('otp');

  /// AuthPass's `otpauth://` URI.
  static const otpAuth = KdbxKey('OTPAuth');

  /// KeePass's base32 secret.
  static const secretBase32 = KdbxKey('TimeOtp-Secret-Base32');

  /// KeePass's code length.
  static const length = KdbxKey('TimeOtp-Length');

  /// KeePass's period in seconds.
  static const period = KdbxKey('TimeOtp-Period');

  /// KeePass's algorithm: `HMAC-SHA-1`, `HMAC-SHA-256`, `HMAC-SHA-512`.
  static const algorithm = KdbxKey('TimeOtp-Algorithm');
}

/// The hash a TOTP code is made with.
enum TomSecretsTotpAlgorithm {
  /// HMAC-SHA-1 (the default).
  sha1('SHA1', 'HMAC-SHA-1'),

  /// HMAC-SHA-256.
  sha256('SHA256', 'HMAC-SHA-256'),

  /// HMAC-SHA-512.
  sha512('SHA512', 'HMAC-SHA-512');

  const TomSecretsTotpAlgorithm(this.uriName, this.keepassName);

  /// The name in an `otpauth://` URI.
  final String uriName;

  /// The name in `TimeOtp-Algorithm`.
  final String keepassName;
}

/// A TOTP secret with its parameters.
final class TomSecretsTotp {
  /// A TOTP of [secret] (raw bytes).
  TomSecretsTotp(
    this.secret, {
    this.digits = 6,
    this.period = 30,
    this.algorithm = TomSecretsTotpAlgorithm.sha1,
    this.issuer,
    this.account,
  }) {
    if (secret.isEmpty) throw ArgumentError('an empty TOTP secret');
    if (digits < 6 || digits > 10) throw ArgumentError('digits $digits');
    if (period <= 0) throw ArgumentError('period $period');
  }

  /// The secret's bytes.
  final Uint8List secret;

  /// The code length.
  final int digits;

  /// The period in seconds.
  final int period;

  /// The hash.
  final TomSecretsTotpAlgorithm algorithm;

  /// The issuer and the account label (from the URI), or null.
  final String? issuer;

  /// The account label, or null.
  final String? account;

  /// The TOTP of [entry], read in the order `otp`, `OTPAuth`, `TimeOtp-*`;
  /// null when it has none that reads.
  static TomSecretsTotp? fromEntry(KdbxEntry entry) {
    for (final key in [
      TomSecretsTotpFields.otp,
      TomSecretsTotpFields.otpAuth,
    ]) {
      final text = entry.getString(key)?.getText();
      if (text == null || text.isEmpty) continue;
      final parsed = tryParseUri(text);
      if (parsed != null) return parsed;
    }
    final base32 = entry
        .getString(TomSecretsTotpFields.secretBase32)
        ?.getText();
    if (base32 == null || base32.isEmpty) return null;
    final secret = tomSecretsBase32Decode(base32);
    if (secret == null || secret.isEmpty) return null;
    final algorithmName = entry
        .getString(TomSecretsTotpFields.algorithm)
        ?.getText();
    final algorithm = TomSecretsTotpAlgorithm.values
        .where((a) => a.keepassName == algorithmName)
        .firstOrNull;
    try {
      return TomSecretsTotp(
        secret,
        digits:
            int.tryParse(
              entry.getString(TomSecretsTotpFields.length)?.getText() ?? '',
            ) ??
            6,
        period:
            int.tryParse(
              entry.getString(TomSecretsTotpFields.period)?.getText() ?? '',
            ) ??
            30,
        algorithm: algorithm ?? TomSecretsTotpAlgorithm.sha1,
      );
    } on ArgumentError {
      return null;
    }
  }

  /// The TOTP of an `otpauth://totp/...` URI, or null.
  static TomSecretsTotp? tryParseUri(String text) {
    final Uri uri;
    try {
      uri = Uri.parse(text.trim());
    } on FormatException {
      return null;
    }
    if (uri.scheme != 'otpauth' || uri.host != 'totp') return null;
    final secret = tomSecretsBase32Decode(uri.queryParameters['secret'] ?? '');
    if (secret == null || secret.isEmpty) return null;
    final label = Uri.decodeComponent(
      uri.path.startsWith('/') ? uri.path.substring(1) : uri.path,
    );
    final colon = label.indexOf(':');
    final algorithmName = uri.queryParameters['algorithm']?.toUpperCase();
    final algorithm = algorithmName == null
        ? TomSecretsTotpAlgorithm.sha1
        : TomSecretsTotpAlgorithm.values
              .where((a) => a.uriName == algorithmName)
              .firstOrNull;
    if (algorithm == null) return null;
    try {
      return TomSecretsTotp(
        secret,
        digits: int.tryParse(uri.queryParameters['digits'] ?? '') ?? 6,
        period: int.tryParse(uri.queryParameters['period'] ?? '') ?? 30,
        algorithm: algorithm,
        issuer:
            uri.queryParameters['issuer'] ??
            (colon > 0 ? label.substring(0, colon) : null),
        account: colon > 0
            ? label.substring(colon + 1)
            : (label.isEmpty ? null : label),
      );
    } on ArgumentError {
      return null;
    }
  }

  /// The code at [time] (RFC 6238).
  String code(DateTime time) {
    final counter = time.toUtc().millisecondsSinceEpoch ~/ 1000 ~/ period;
    final message = Uint8List(8);
    ByteData.sublistView(message).setUint64(0, counter);
    final hash = switch (algorithm) {
      TomSecretsTotpAlgorithm.sha1 => crypto.sha1,
      TomSecretsTotpAlgorithm.sha256 => crypto.sha256,
      TomSecretsTotpAlgorithm.sha512 => crypto.sha512,
    };
    final mac = crypto.Hmac(hash, secret).convert(message).bytes;
    final offset = mac.last & 0x0f;
    final binary =
        ((mac[offset] & 0x7f) << 24) |
        (mac[offset + 1] << 16) |
        (mac[offset + 2] << 8) |
        mac[offset + 3];
    var modulus = 1;
    for (var i = 0; i < digits; i++) {
      modulus *= 10;
    }
    return (binary % modulus).toString().padLeft(digits, '0');
  }

  /// The `otpauth://` URI of this TOTP.
  String toUri() {
    final label = [?issuer, ?account].join(':');
    return Uri(
      scheme: 'otpauth',
      host: 'totp',
      path: '/$label',
      queryParameters: {
        'secret': tomSecretsBase32Encode(secret),
        'issuer': ?issuer,
        'algorithm': algorithm.uriName,
        'digits': '$digits',
        'period': '$period',
      },
    ).toString();
  }

  /// Writes the three conventions together (DP-38), so KeePassXC, KeePass,
  /// AuthPass and the product show the same code. The secret is protected.
  void writeTo(KdbxEntry entry) {
    final uri = toUri();
    entry.modify(() {
      entry
        ..setString(TomSecretsTotpFields.otp, ProtectedValue.fromString(uri))
        ..setString(
          TomSecretsTotpFields.otpAuth,
          ProtectedValue.fromString(uri),
        )
        ..setString(
          TomSecretsTotpFields.secretBase32,
          ProtectedValue.fromString(tomSecretsBase32Encode(secret)),
        )
        ..setString(TomSecretsTotpFields.length, PlainValue('$digits'))
        ..setString(TomSecretsTotpFields.period, PlainValue('$period'))
        ..setString(
          TomSecretsTotpFields.algorithm,
          PlainValue(algorithm.keepassName),
        );
    });
  }

  @override
  String toString() =>
      'TomSecretsTotp(${algorithm.uriName}, $digits, ${period}s, ***)';
}

const String _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/// RFC 4648 base32 without padding.
String tomSecretsBase32Encode(List<int> bytes) {
  final out = StringBuffer();
  var buffer = 0;
  var bits = 0;
  for (final b in bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out.write(_alphabet[(buffer >> (bits - 5)) & 31]);
      bits -= 5;
    }
  }
  if (bits > 0) out.write(_alphabet[(buffer << (5 - bits)) & 31]);
  return out.toString();
}

/// RFC 4648 base32, any case, spaces, dashes and padding ignored; null when
/// it is not base32.
Uint8List? tomSecretsBase32Decode(String text) {
  final clean = text.toUpperCase().replaceAll(RegExp(r'[\s=-]'), '');
  final out = <int>[];
  var buffer = 0;
  var bits = 0;
  for (final ch in clean.split('')) {
    final value = _alphabet.indexOf(ch);
    if (value < 0) return null;
    buffer = ((buffer << 5) | value) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.add((buffer >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8List.fromList(out);
}
