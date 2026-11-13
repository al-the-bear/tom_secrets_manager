// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The approval code and its token (protocol.md 9.5, 9.6; TD-3): a waiting
/// request on a host without a connected approver shows a ten-character
/// code; a trusted device answers it with a 26-character single-use token,
/// an HMAC-SHA256 tag under the approval-token key the two share.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:tom_secrets_client/tom_secrets_client.dart'
    show TomSecretReference;

import 'signed_objects.dart';

/// The decisions a prompt or a token carries.
const List<String> tomSecretsDecisions = ['once', 'always', 'folder', 'never'];

const String _alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/// RFC 4648 base32 of [bytes], upper case, without padding.
String tomSecretsBase32(List<int> bytes) {
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

/// The request digest (9.5): what the waiting request is, from the
/// identity's `kind`, `exe`, `interpreter`, `script`, `cwd`, `uid` and
/// `args` (protocol.md 7.1) and the references in canonical form.
Uint8List tomSecretsRequestDigest(
  Map<String, Object?> identity,
  List<String> refs,
) {
  final data = BytesBuilder()..add(tomSecretsLps('tsm-approval-request-v1'));
  for (final name in ['kind', 'exe', 'interpreter', 'script', 'cwd']) {
    data.add(tomSecretsLps((identity[name] as String?) ?? ''));
  }
  data
    ..add(tomSecretsLps('${identity['uid']}'))
    ..add(
      tomSecretsLpList([
        for (final a in (identity['args'] as List?) ?? const []) '$a',
      ]),
    )
    ..add(
      tomSecretsLpList([
        for (final ref in refs) TomSecretReference.parse(ref).canonical,
      ]),
    );
  return Uint8List.fromList(crypto.sha256.convert(data.toBytes()).bytes);
}

/// The approval code (9.5): the first ten base32 characters of
/// SHA-256(lps("tsm-approval-code-v1") || lps(host) || lps(approvalId) ||
/// requestDigest).
String tomSecretsApprovalCode(
  String host,
  String approvalId,
  Map<String, Object?> identity,
  List<String> refs,
) {
  final digest = crypto.sha256.convert([
    ...tomSecretsLps('tsm-approval-code-v1'),
    ...tomSecretsLps(host),
    ...tomSecretsLps(approvalId),
    ...tomSecretsRequestDigest(identity, refs),
  ]);
  return tomSecretsBase32(digest.bytes).substring(0, 10);
}

/// The token a trusted device computes for [code] shown on [host] (9.6):
/// base32 of the first 16 bytes of HMAC-SHA256(tokenKey,
/// lps("tsm-code-token-v1") || lps(host) || lps(code) || lps(decision)).
String tomSecretsCodeToken(
  List<int> tokenKey,
  String host,
  String code,
  String decision,
) {
  if (tokenKey.length != 32 || !tomSecretsDecisions.contains(decision)) {
    throw ArgumentError('a 32-byte key and a known decision');
  }
  final tag = crypto.Hmac(crypto.sha256, tokenKey).convert([
    ...tomSecretsLps('tsm-code-token-v1'),
    ...tomSecretsLps(host),
    ...tomSecretsLps(code.toUpperCase()),
    ...tomSecretsLps(decision),
  ]);
  return tomSecretsBase32(tag.bytes.sublist(0, 16));
}

/// A token or code as typed: upper case, without spaces.
String tomSecretsNormalizeCode(String text) =>
    text.replaceAll(RegExp(r'\s'), '').toUpperCase();

/// Whether [token] is 26 base32 characters (after [tomSecretsNormalizeCode]).
bool tomSecretsIsToken(String token) =>
    RegExp(r'^[A-Z2-7]{26}$').hasMatch(token);

/// Compares two texts in constant time (in their length).
bool tomSecretsSameText(String a, String b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
  }
  return diff == 0;
}

/// What a token answers (9.6): the request waiting with [code], with
/// [decision].
typedef TomSecretsTokenMatch = ({String code, String decision});

/// The request [token] answers among the [codes] waiting on [host], under
/// one of [tokenKeys]; null when it matches nothing or is malformed. Every
/// candidate is compared in constant time.
TomSecretsTokenMatch? tomSecretsRedeemToken(
  String token,
  Iterable<String> codes,
  Iterable<List<int>> tokenKeys,
  String host,
) {
  final normal = tomSecretsNormalizeCode(token);
  if (!tomSecretsIsToken(normal)) return null;
  TomSecretsTokenMatch? found;
  for (final code in codes) {
    for (final key in tokenKeys) {
      for (final decision in tomSecretsDecisions) {
        if (tomSecretsSameText(
          tomSecretsCodeToken(key, host, code, decision),
          normal,
        )) {
          found ??= (code: code, decision: decision);
        }
      }
    }
  }
  return found;
}
