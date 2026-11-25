// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// TOTP (RFC 6238) and its three KDBX conventions (DP-38): `otp` as KeePassXC
/// writes it and `OTPAuth` as AuthPass writes it (both an `otpauth://` URI),
/// and KeePass 2.47+'s `TimeOtp-Secret-Base32` with `TimeOtp-Length`,
/// `TimeOtp-Period` and `TimeOtp-Algorithm` (its secret read also from
/// `TimeOtp-Secret`, `TimeOtp-Secret-Hex` and `TimeOtp-Secret-Base64`).
/// What a user types or a QR code holds (an `otpauth://` URI, Google
/// Authenticator's `otpauth-migration://` export, a base32 or a hex secret)
/// is read by [TomSecretsTotp.parse].
library;

import 'dart:convert';
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

  /// KeePass's secret as UTF-8 text.
  static const secretText = KdbxKey('TimeOtp-Secret');

  /// KeePass's hex secret.
  static const secretHex = KdbxKey('TimeOtp-Secret-Hex');

  /// KeePass's base64 secret.
  static const secretBase64 = KdbxKey('TimeOtp-Secret-Base64');

  /// KeePass's code length.
  static const length = KdbxKey('TimeOtp-Length');

  /// KeePass's period in seconds.
  static const period = KdbxKey('TimeOtp-Period');

  /// KeePass's algorithm: `HMAC-SHA-1`, `HMAC-SHA-256`, `HMAC-SHA-512`.
  static const algorithm = KdbxKey('TimeOtp-Algorithm');

  /// Every TOTP field: what [TomSecretsTotp.writeTo] replaces and an editor
  /// leaves to the TOTP section.
  static const all = [
    otp,
    otpAuth,
    secretText,
    secretHex,
    secretBase32,
    secretBase64,
    length,
    period,
    algorithm,
  ];
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
  /// null when it has none that reads. KeePass's secret is read as KeePass
  /// 2.47 reads it: the first of `TimeOtp-Secret` (UTF-8), `-Hex`,
  /// `-Base32` and `-Base64` the entry holds.
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
    final secret = _keepassSecret(entry);
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

  static Uint8List? _keepassSecret(KdbxEntry entry) {
    String? text(KdbxKey key) {
      final value = entry.getString(key)?.getText();
      return value == null || value.isEmpty ? null : value;
    }

    if (text(TomSecretsTotpFields.secretText) case final utf8Text?) {
      return Uint8List.fromList(utf8.encode(utf8Text));
    }
    if (text(TomSecretsTotpFields.secretHex) case final hex?) {
      return tomSecretsHexDecode(hex);
    }
    if (text(TomSecretsTotpFields.secretBase32) case final base32?) {
      return tomSecretsBase32Decode(base32);
    }
    if (text(TomSecretsTotpFields.secretBase64) case final b64?) {
      try {
        return base64.decode(b64.replaceAll(RegExp(r'\s'), ''));
      } on FormatException {
        return null;
      }
    }
    return null;
  }

  /// The TOTP a user set up from [text]: an `otpauth://totp/` URI, an
  /// `otpauth-migration://` export holding one TOTP account (Google
  /// Authenticator), a secret marked `hex:`, a base32 secret, or a hex
  /// secret (0-9 and a-f, an even number of them). Null for empty text.
  ///
  /// A text that is both base32 and hex (only `a`-`f` and `2`-`7`) is read
  /// as base32, the usual form; `hex:` marks it hex. Throws a
  /// [FormatException] saying what the text is otherwise.
  static TomSecretsTotp? parse(String text) {
    final t = text.trim();
    if (t.isEmpty) return null;
    if (t.toLowerCase().startsWith('otpauth://')) {
      final uri = tryParseUri(t);
      if (uri == null) {
        throw const FormatException(
          'an otpauth:// URI that is not a readable TOTP (a counter-based '
          'HOTP code is not supported)',
        );
      }
      return uri;
    }
    if (t.toLowerCase().startsWith('otpauth-migration://')) {
      final migration = TomSecretsTotpMigration.tryParse(t);
      if (migration == null) {
        throw const FormatException(
          'an otpauth-migration:// export it cannot read',
        );
      }
      return migration.single;
    }
    if (t.toLowerCase().startsWith('hex:')) {
      final hex = tomSecretsHexDecode(t.substring(4));
      if (hex == null || hex.isEmpty) {
        throw const FormatException(
          'a hex: secret that is not hex (0-9 and a-f, an even number)',
        );
      }
      return TomSecretsTotp(hex);
    }
    final base32 = tomSecretsBase32Decode(t);
    if (base32 != null && base32.isNotEmpty) return TomSecretsTotp(base32);
    final hex = tomSecretsHexDecode(t);
    if (hex != null && hex.isNotEmpty) return TomSecretsTotp(hex);
    throw const FormatException(
      'neither an otpauth:// URI nor a base32 or hex secret',
    );
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
  /// KeePass's other secret fields (UTF-8, hex, base64) are removed: KeePass
  /// reads `TimeOtp-Secret` before the base32 one, so an old one left would
  /// win there.
  void writeTo(KdbxEntry entry) {
    final uri = toUri();
    entry.modify(() {
      for (final key in [
        TomSecretsTotpFields.secretText,
        TomSecretsTotpFields.secretHex,
        TomSecretsTotpFields.secretBase64,
      ]) {
        entry.removeString(key);
      }
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

/// The bytes of a hex secret: 0-9 and a-f in either case, an even number of
/// them, spaces ignored; null when it is not hex.
Uint8List? tomSecretsHexDecode(String text) {
  final clean = text.replaceAll(RegExp(r'\s'), '');
  if (clean.length.isOdd || !RegExp(r'^[0-9a-fA-F]*$').hasMatch(clean)) {
    return null;
  }
  return Uint8List.fromList([
    for (var i = 0; i < clean.length; i += 2)
      int.parse(clean.substring(i, i + 2), radix: 16),
  ]);
}

/// Google Authenticator's export (`otpauth-migration://offline?data=…`):
/// a protobuf `MigrationPayload` of accounts. Only its TOTP accounts are
/// read; counter-based (HOTP) ones and MD5 are counted in [skipped].
final class TomSecretsTotpMigration {
  TomSecretsTotpMigration._(this.totps, this.skipped);

  /// The TOTP accounts, in the export's order.
  final List<TomSecretsTotp> totps;

  /// The accounts it holds that are not read (HOTP, MD5, unreadable).
  final int skipped;

  /// The one TOTP account of the export, which an editor takes; a
  /// [FormatException] names what it holds otherwise.
  TomSecretsTotp get single {
    if (totps.length == 1 && skipped == 0) return totps.single;
    if (totps.isEmpty) {
      throw FormatException(
        skipped == 1
            ? 'an export of a counter-based (HOTP) code, which is not supported'
            : 'an export without a TOTP account',
      );
    }
    throw FormatException(
      'an export of ${totps.length + skipped} accounts: export them one at '
      'a time in Google Authenticator, one per entry',
    );
  }

  /// The export [text] reads as, or null when it is no
  /// `otpauth-migration://` URI with a readable payload.
  static TomSecretsTotpMigration? tryParse(String text) {
    final Uri uri;
    try {
      uri = Uri.parse(text.trim());
    } on FormatException {
      return null;
    }
    if (uri.scheme != 'otpauth-migration') return null;
    final data = uri.queryParameters['data'];
    if (data == null || data.isEmpty) return null;
    final Uint8List payload;
    try {
      payload = base64.decode(base64.normalize(data.replaceAll(' ', '+')));
    } on FormatException {
      return null;
    }
    final totps = <TomSecretsTotp>[];
    var skipped = 0;
    try {
      for (final (field, value) in _Protobuf(payload).fields()) {
        if (field != 1 || value is! Uint8List) continue;
        final totp = _account(value);
        if (totp == null) {
          skipped++;
        } else {
          totps.add(totp);
        }
      }
    } on FormatException {
      return null;
    }
    return TomSecretsTotpMigration._(totps, skipped);
  }

  /// One `OtpParameters`: secret 1, name 2, issuer 3, algorithm 4
  /// (1 SHA1, 2 SHA256, 3 SHA512, 4 MD5), digits 5 (1 six, 2 eight), type 6
  /// (1 HOTP, 2 TOTP).
  static TomSecretsTotp? _account(Uint8List bytes) {
    Uint8List? secret;
    String? name;
    String? issuer;
    var algorithm = 1;
    var digits = 1;
    var type = 2;
    for (final (field, value) in _Protobuf(bytes).fields()) {
      switch ((field, value)) {
        case (1, final Uint8List v):
          secret = v;
        case (2, final Uint8List v):
          name = utf8.decode(v, allowMalformed: true);
        case (3, final Uint8List v):
          issuer = utf8.decode(v, allowMalformed: true);
        case (4, final int v):
          algorithm = v;
        case (5, final int v):
          digits = v;
        case (6, final int v):
          type = v;
      }
    }
    if (type != 2 || secret == null || secret.isEmpty) return null;
    final hash = switch (algorithm) {
      0 || 1 => TomSecretsTotpAlgorithm.sha1,
      2 => TomSecretsTotpAlgorithm.sha256,
      3 => TomSecretsTotpAlgorithm.sha512,
      _ => null,
    };
    if (hash == null) return null;
    var account = name;
    if (issuer != null && account != null && account.startsWith('$issuer:')) {
      account = account.substring(issuer.length + 1);
    }
    return TomSecretsTotp(
      secret,
      digits: digits == 2 ? 8 : 6,
      algorithm: hash,
      issuer: issuer == null || issuer.isEmpty ? null : issuer,
      account: account == null || account.isEmpty ? null : account,
    );
  }
}

/// A minimal protobuf reader: varints and length-delimited fields; the
/// other wire types are skipped.
final class _Protobuf {
  _Protobuf(this.bytes);
  final Uint8List bytes;
  var _at = 0;

  int _varint() {
    var result = 0;
    var shift = 0;
    while (true) {
      if (_at >= bytes.length || shift > 63) {
        throw const FormatException('a truncated varint');
      }
      final b = bytes[_at++];
      result |= (b & 0x7f) << shift;
      if (b & 0x80 == 0) return result;
      shift += 7;
    }
  }

  Iterable<(int, Object)> fields() sync* {
    while (_at < bytes.length) {
      final key = _varint();
      final field = key >> 3;
      switch (key & 7) {
        case 0:
          yield (field, _varint());
        case 1:
          _at += 8;
        case 2:
          final length = _varint();
          if (length < 0 || _at + length > bytes.length) {
            throw const FormatException('a truncated field');
          }
          yield (field, Uint8List.sublistView(bytes, _at, _at + length));
          _at += length;
        case 5:
          _at += 4;
        default:
          throw const FormatException('a wire type it cannot read');
      }
      if (_at > bytes.length) throw const FormatException('truncated');
    }
  }
}
