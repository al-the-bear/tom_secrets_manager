// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** Member keys and `age` recipients (part-sharing, DP-63, DP-177):
/// each person's hybrid post-quantum `age` key pair and the public keys
/// received from other people, without any vault format.
///
/// - A member key is an `age` v1.3 hybrid identity, `AGE-SECRET-KEY-PQ-1…`:
///   a 32-byte seed from which `age`'s `mlkem768x25519` recipient type
///   derives an X25519 + ML-KEM-768 key pair (X-Wing, `tom_pqc`'s
///   [MlKem768X25519]). Its public key is the recipient `age1pq1…`, the
///   1,216-byte encapsulation key in Bech32, about 1,960 characters.
/// - Other people's classical `age1…` (X25519) recipients are accepted, for
///   exports to them only.
/// - The fingerprint is the SHA-256 of the recipient string in base32
///   (RFC 4648, lower case, no padding, 52 characters); it is also the
///   member id of the inbox folders and the relay's mailboxes. People
///   compare its first 20 characters, [TomSecretsAgeRecipient.shortFingerprint].
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:tom_pqc/tom_pqc.dart';

/// Why a key or an entry was refused.
enum TomSecretsMemberKeyFailure {
  /// Not an `age` key: not Bech32, a bad checksum, mixed case, an unknown
  /// prefix, the wrong length.
  malformed,

  /// An `age` plugin recipient (`age1<plugin>1…`), which the product does
  /// not run.
  plugin,

  /// A classical identity (`AGE-SECRET-KEY-1…`): a member key is hybrid.
  classicalIdentity,

  /// The recipient's ML-KEM-768 half fails FIPS 203's check, or its X25519
  /// half is a low-order point.
  invalidKey,

  /// The directory holds this recipient already.
  duplicate,

  /// The recipient is the user's own member key.
  ownKey,
}

/// A refused key, with the [reason] the app shows.
final class TomSecretsMemberKeyException implements Exception {
  /// A refusal for [reason], told by [message].
  const TomSecretsMemberKeyException(this.reason, this.message);

  /// Why.
  final TomSecretsMemberKeyFailure reason;

  /// For people; never a private key.
  final String message;

  @override
  String toString() => 'TomSecretsMemberKeyException(${reason.name}): $message';
}

/// The kind of an `age` recipient.
enum TomSecretsAgeRecipientKind {
  /// `age1pq1…`: X25519 + ML-KEM-768 (`mlkem768x25519`), a member key.
  hybrid,

  /// `age1…`: X25519 alone, for exports only.
  classical,
}

/// An `age` public key: a hybrid member key or another person's classical
/// key. Equal by its canonical (lower-case) string.
final class TomSecretsAgeRecipient {
  TomSecretsAgeRecipient._(this.kind, this.publicKey, this.encoded);

  /// The Bech32 prefix of a hybrid recipient.
  static const hybridPrefix = 'age1pq';

  /// The Bech32 prefix of a classical recipient.
  static const classicalPrefix = 'age';

  /// The hybrid recipient of the 1,216-byte X-Wing [publicKey].
  factory TomSecretsAgeRecipient.hybrid(Uint8List publicKey) {
    if (publicKey.length != MlKem768X25519.publicKeyLength) {
      throw ArgumentError(
        'a hybrid key is ${MlKem768X25519.publicKeyLength} '
        'bytes, not ${publicKey.length}',
      );
    }
    return TomSecretsAgeRecipient._(
      TomSecretsAgeRecipientKind.hybrid,
      Uint8List.fromList(publicKey),
      _bech32Encode(hybridPrefix, publicKey),
    );
  }

  /// Parses an `age` recipient: `age1pq1…` or `age1…`, in lower case or,
  /// as Bech32 allows, all upper case (canonicalised to lower case, the
  /// only form `age` reads), surrounding white space ignored. Throws
  /// [TomSecretsMemberKeyException] otherwise.
  factory TomSecretsAgeRecipient.parse(String text) {
    final (hrp, data) = _bech32Decode(text.trim());
    switch (hrp) {
      case hybridPrefix:
        if (data.length != MlKem768X25519.publicKeyLength) {
          throw _malformed('a hybrid age key of ${data.length} bytes');
        }
        return TomSecretsAgeRecipient._(
          TomSecretsAgeRecipientKind.hybrid,
          data,
          _bech32Encode(hrp, data),
        );
      case classicalPrefix:
        if (data.length != 32) {
          throw _malformed('a classical age key of ${data.length} bytes');
        }
        return TomSecretsAgeRecipient._(
          TomSecretsAgeRecipientKind.classical,
          data,
          _bech32Encode(hrp, data),
        );
      default:
        if (hrp.startsWith('age1')) {
          throw TomSecretsMemberKeyException(
            TomSecretsMemberKeyFailure.plugin,
            'an age plugin key (${hrp.substring(4)}), which Tom Secrets '
            'Manager does not use',
          );
        }
        throw _malformed('not an age public key');
    }
  }

  /// Hybrid or classical.
  final TomSecretsAgeRecipientKind kind;

  /// The public key: 1,216 bytes (ML-KEM-768 then X25519) or 32 (X25519).
  final Uint8List publicKey;

  /// The recipient string, lower case: what `age -r` takes.
  final String encoded;

  /// Whether it is a hybrid (post-quantum) key.
  bool get isHybrid => kind == TomSecretsAgeRecipientKind.hybrid;

  /// The SHA-256 of [encoded] in base32 (lower case, no padding, 52
  /// characters): the member id.
  String get fingerprint =>
      _base32(sha256.convert(ascii.encode(encoded)).bytes);

  /// The first 20 characters of [fingerprint] in groups of four
  /// (`abcd efgh ijkl mnop qrst`, 100 bits): what people compare.
  String get shortFingerprint {
    final f = fingerprint.substring(0, 20);
    return [for (var i = 0; i < 20; i += 4) f.substring(i, i + 4)].join(' ');
  }

  /// Checks the key as `age` would on encrypting to it: a hybrid key's
  /// ML-KEM-768 half passes FIPS 203's modulus check and its X25519 half
  /// is not a low-order point (an encapsulation to it succeeds). Throws
  /// [TomSecretsMemberKeyFailure.invalidKey] otherwise; a classical key's
  /// 32 bytes are any X25519 point.
  Future<void> check() async {
    if (!isHybrid) return;
    try {
      final e = await MlKem768X25519.encapsulate(publicKey);
      e.sharedSecret.dispose();
    } on TomPqcException catch (e) {
      throw TomSecretsMemberKeyException(
        TomSecretsMemberKeyFailure.invalidKey,
        'the key does not hold a valid public key (${e.message})',
      );
    }
  }

  @override
  bool operator ==(Object other) =>
      other is TomSecretsAgeRecipient && other.encoded == encoded;

  @override
  int get hashCode => encoded.hashCode;

  @override
  String toString() => encoded;
}

/// The user's member key: a hybrid `age` identity and its recipient. Holds
/// the 32-byte seed in native memory ([SecretBytes]); [dispose] zeroes it.
final class TomSecretsMemberKey {
  TomSecretsMemberKey._(this._seed, this.recipient);

  /// The Bech32 prefix of a hybrid identity (written in upper case).
  static const identityPrefix = 'age-secret-key-pq-';

  /// A new member key from fresh randomness.
  static Future<TomSecretsMemberKey> generate() async {
    final pair = await MlKem768X25519.generateKeyPair();
    return TomSecretsMemberKey._(
      pair.secretKey,
      TomSecretsAgeRecipient.hybrid(pair.publicKey),
    );
  }

  /// The member key of an `AGE-SECRET-KEY-PQ-1…` identity (an existing
  /// `age-keygen -pq` key, or the `member-key` entry's). A classical
  /// identity is refused ([TomSecretsMemberKeyFailure.classicalIdentity]).
  static Future<TomSecretsMemberKey> parse(String identity) async {
    final (hrp, data) = _bech32Decode(identity.trim());
    if (hrp == 'age-secret-key-') {
      data.fillRange(0, data.length, 0);
      throw const TomSecretsMemberKeyException(
        TomSecretsMemberKeyFailure.classicalIdentity,
        'a classical age key; a member key is a hybrid one '
        '(age-keygen -pq)',
      );
    }
    if (hrp != identityPrefix ||
        data.length != MlKem768X25519.secretKeyLength) {
      data.fillRange(0, data.length, 0);
      throw _malformed('not a hybrid age identity');
    }
    final seed = SecretBytes.fromBytes(data);
    data.fillRange(0, data.length, 0);
    final pair = await MlKem768X25519.keyPairFromSeed(seed);
    return TomSecretsMemberKey._(
      seed,
      TomSecretsAgeRecipient.hybrid(pair.publicKey),
    );
  }

  final SecretBytes _seed;

  /// The public key, given to other people.
  final TomSecretsAgeRecipient recipient;

  /// The identity, `AGE-SECRET-KEY-PQ-1…` (what `age -d -i` reads). A
  /// `String` the library cannot overwrite: the caller writes it into the
  /// vault and drops it.
  String revealIdentity() {
    final seed = _seed.extractBytes();
    try {
      return _bech32Encode(identityPrefix, seed).toUpperCase();
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  /// The seed, for the `age` decryption of a later phase; owned by this key.
  SecretBytes get seed => _seed;

  /// Zeroes the seed.
  void dispose() => _seed.dispose();
}

/// One public key read from a key file or a pasted block: the recipient
/// and the name its file gave, if any.
typedef TomSecretsReceivedMemberKey = ({
  TomSecretsAgeRecipient recipient,
  String? name,
});

/// The text of a published member key: `age`'s recipients-file format, so
/// `age -R <file>` encrypts to it, with the name, fingerprint and date as
/// comments for people.
String tomSecretsMemberKeyFile(
  TomSecretsAgeRecipient recipient, {
  required String name,
  DateTime? created,
}) {
  final day = (created ?? DateTime.now()).toUtc().toIso8601String();
  return [
    '# Tom Secrets Manager member key (age, X25519 + ML-KEM-768)',
    '# name: ${name.replaceAll(RegExp(r'[\r\n]'), ' ').trim()}',
    '# fingerprint: ${recipient.shortFingerprint}',
    '# created: ${day.substring(0, 10)}',
    recipient.encoded,
    '',
  ].join('\n');
}

/// The file name of [name]'s published member key.
String tomSecretsMemberKeyFileName(String name) {
  final slug = name
      .trim()
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9]+'), '_')
      .replaceAll(RegExp(r'^_+|_+$'), '');
  return '${slug.isEmpty ? 'member' : slug}.age-recipient.txt';
}

/// The public keys in [text]: a published key file, a recipients file with
/// several, a pasted recipient or a scanned QR code's text. Blank lines and
/// `#` comments are skipped; a `# name: …` comment names the key after it.
/// A line that is no `age` recipient is refused, naming its line.
List<TomSecretsReceivedMemberKey> tomSecretsReadMemberKeys(String text) {
  final out = <TomSecretsReceivedMemberKey>[];
  String? name;
  final lines = const LineSplitter().convert(text);
  for (var i = 0; i < lines.length; i++) {
    final line = lines[i].trim();
    if (line.isEmpty) continue;
    if (line.startsWith('#')) {
      final m = RegExp(
        r'^#\s*name:\s*(.*)$',
        caseSensitive: false,
      ).firstMatch(line);
      if (m != null) name = m.group(1)!.trim();
      continue;
    }
    try {
      out.add((
        recipient: TomSecretsAgeRecipient.parse(line),
        name: (name?.isEmpty ?? true) ? null : name,
      ));
    } on TomSecretsMemberKeyException catch (e) {
      throw TomSecretsMemberKeyException(
        e.reason,
        lines.length == 1 ? e.message : 'line ${i + 1}: ${e.message}',
      );
    }
    name = null;
  }
  if (out.isEmpty) throw _malformed('no age public key in the text');
  return out;
}

/// The data of the Bech32 string [text] whose prefix must be [hrp] and whose
/// data must be [length] bytes (`age`'s Bech32: no length limit, either
/// case). Throws [TomSecretsMemberKeyException] otherwise.
Uint8List tomSecretsBech32Data(String hrp, String text, int length) {
  final (found, data) = _bech32Decode(text);
  if (found != hrp || data.length != length) {
    data.fillRange(0, data.length, 0);
    throw _malformed('not a $hrp key of $length bytes');
  }
  return data;
}

TomSecretsMemberKeyException _malformed(String why) =>
    TomSecretsMemberKeyException(TomSecretsMemberKeyFailure.malformed, why);

// Bech32 (BIP 173) as age uses it: the checksum of Bech32 (not Bech32m)
// and no limit on the length.

const _charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

int _polymod(List<int> values) {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  var chk = 1;
  for (final v in values) {
    final top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (var i = 0; i < 5; i++) {
      if ((top >> i) & 1 == 1) chk ^= gen[i];
    }
  }
  return chk;
}

List<int> _hrpExpand(String hrp) => [
  for (final c in hrp.codeUnits) c >> 5,
  0,
  for (final c in hrp.codeUnits) c & 31,
];

List<int>? _convertBits(List<int> data, int from, int to, {required bool pad}) {
  var acc = 0;
  var bits = 0;
  final out = <int>[];
  final maxv = (1 << to) - 1;
  // Only the bits not yet written are kept, so acc stays small.
  final maxAcc = (1 << (from + to - 1)) - 1;
  for (final v in data) {
    acc = ((acc << from) | v) & maxAcc;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.add((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.add((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
    return null;
  }
  return out;
}

String _bech32Encode(String hrp, List<int> data) {
  final values = _convertBits(data, 8, 5, pad: true)!;
  final poly = _polymod([..._hrpExpand(hrp), ...values, 0, 0, 0, 0, 0, 0]) ^ 1;
  final checksum = [for (var i = 0; i < 6; i++) (poly >> (5 * (5 - i))) & 31];
  return '${hrp}1${[...values, ...checksum].map((v) => _charset[v]).join()}';
}

(String, Uint8List) _bech32Decode(String text) {
  if (text != text.toLowerCase() && text != text.toUpperCase()) {
    throw _malformed('mixed upper and lower case');
  }
  final s = text.toLowerCase();
  final sep = s.lastIndexOf('1');
  if (sep < 1 || sep + 7 > s.length) throw _malformed('not Bech32');
  final hrp = s.substring(0, sep);
  if (hrp.codeUnits.any((c) => c < 33 || c > 126)) {
    throw _malformed('not Bech32');
  }
  final values = <int>[];
  for (final c in s.substring(sep + 1).split('')) {
    final v = _charset.indexOf(c);
    if (v < 0) throw _malformed('a character Bech32 does not use');
    values.add(v);
  }
  if (_polymod([..._hrpExpand(hrp), ...values]) != 1) {
    throw _malformed('the checksum does not match (a character changed?)');
  }
  final data = _convertBits(
    values.sublist(0, values.length - 6),
    5,
    8,
    pad: false,
  );
  if (data == null) throw _malformed('not Bech32');
  return (hrp, Uint8List.fromList(data));
}

String _base32(List<int> bytes) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  final out = StringBuffer();
  var acc = 0;
  var bits = 0;
  for (final b in bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.write(alphabet[(acc >> bits) & 31]);
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out.write(alphabet[(acc << (5 - bits)) & 31]);
  return out.toString();
}
