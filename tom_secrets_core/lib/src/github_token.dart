// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The expiry GitHub reports for a token (part-key-rotation): every answer
/// to a request with a fine-grained token that expires carries it in a
/// header.
library;

/// The header GitHub answers a token with an expiry with.
const String tomSecretsTokenExpirationHeader =
    'github-authentication-token-expiration';

/// The time in a `GitHub-Authentication-Token-Expiration` header
/// (`2026-12-01 10:00:00 UTC`, or with a numeric offset), in UTC; null when
/// it cannot be read.
DateTime? tomSecretsParseTokenExpiration(String value) {
  var text = value.trim();
  if (text.endsWith(' UTC')) {
    text = '${text.substring(0, text.length - 4)}Z';
  }
  text = text.replaceFirstMapped(
    RegExp(r'\s+([+-]\d{2}:?\d{2})$'),
    (m) => m[1]!,
  );
  return DateTime.tryParse(text.replaceFirst(' ', 'T'))?.toUtc();
}
