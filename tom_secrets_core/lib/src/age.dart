// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The `age` v1 file format (C2SP age.md, part-sharing, DP-63,
/// DP-177): what recipients files and exports are written in, so the `age`
/// command line (v1.3.0 on) opens them too.
///
/// - **Recipients:** the hybrid `mlkem768x25519` type of `age` v1.3 (HPKE
///   base mode with the X-Wing KEM, HKDF-SHA256 and ChaCha20-Poly1305, info
///   `age-encryption.org/mlkem768x25519`) for member keys, and `X25519` for
///   other people's classical keys. A file is written to hybrid recipients
///   or to classical ones, never both: `age` refuses the mix, since it would
///   lose the post-quantum protection.
/// - **The file:** the header (`age-encryption.org/v1`, one stanza per
///   recipient, the HMAC-SHA256 under a key derived from the 16-byte file
///   key), then a 16-byte nonce and the payload in 64 KiB ChaCha20-Poly1305
///   chunks (STREAM: an 11-byte counter and the last-chunk flag as nonce).
/// - **Armour:** `-----BEGIN AGE ENCRYPTED FILE-----`, base64 in lines of
///   64 characters, `-----END AGE ENCRYPTED FILE-----`, for a package
///   pasted into a message.
///
/// The reader is checked against the age testkit's hybrid vectors (C2SP
/// CCTV), the writer against `filippo.io/age`.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:tom_pqc/tom_pqc.dart';

import 'member_keys.dart';
import 'pairing.dart' show tomSecretsHkdf;

/// Why an `age` file could not be written or read.
enum TomSecretsAgeFailure {
  /// None of the identities given opens the file.
  noMatch,

  /// The header breaks the format, or its MAC does not verify.
  header,

  /// The payload does not authenticate (changed or cut off).
  payload,

  /// The armour breaks the format.
  armor,

  /// No recipient, or hybrid and classical recipients together.
  recipients,
}

/// A refused `age` file.
final class TomSecretsAgeException implements Exception {
  /// A refusal for [reason], told by [message].
  const TomSecretsAgeException(this.reason, this.message);

  /// Why.
  final TomSecretsAgeFailure reason;

  /// For people; never a key.
  final String message;

  @override
  String toString() => 'TomSecretsAgeException(${reason.name}): $message';
}

/// An identity that opens `age` files: a member key ([TomSecretsMemberKey],
/// hybrid) or a classical X25519 identity ([TomSecretsAgeX25519Identity]).
sealed class TomSecretsAgeIdentity {
  const TomSecretsAgeIdentity();
}

/// A member key as an `age` identity.
final class TomSecretsAgeHybridIdentity extends TomSecretsAgeIdentity {
  /// [key] as an identity; the key stays the caller's to dispose.
  const TomSecretsAgeHybridIdentity(this.key);

  /// The member key.
  final TomSecretsMemberKey key;
}

/// A classical `age` identity, `AGE-SECRET-KEY-1…` (X25519): the product
/// makes none, but reads a file written to one (another person's export
/// opened with their key, the testkit). [dispose] zeroes it.
final class TomSecretsAgeX25519Identity extends TomSecretsAgeIdentity {
  TomSecretsAgeX25519Identity._(this._secret);

  /// The identity of an `AGE-SECRET-KEY-1…` string.
  factory TomSecretsAgeX25519Identity.parse(String identity) =>
      TomSecretsAgeX25519Identity._(tomSecretsAgeClassicalSecret(identity));

  final Uint8List _secret;

  /// Zeroes the secret.
  void dispose() => _secret.fillRange(0, _secret.length, 0);
}

const _version = 'age-encryption.org/v1';
const _hybridType = 'mlkem768x25519';
const _x25519Type = 'X25519';
const _hybridInfo = 'age-encryption.org/mlkem768x25519';
const _x25519Info = 'age-encryption.org/v1/X25519';
const _chunk = 64 * 1024;
const _armorBegin = '-----BEGIN AGE ENCRYPTED FILE-----';
const _armorEnd = '-----END AGE ENCRYPTED FILE-----';

final _random = Random.secure();
final _aead = Chacha20.poly1305Aead();
final _x25519 = X25519();

Uint8List _randomBytes(int n) =>
    Uint8List.fromList([for (var i = 0; i < n; i++) _random.nextInt(256)]);

/// [plaintext] encrypted to [recipients] as an `age` v1 file: all hybrid
/// (member keys) or all classical. Throws [TomSecretsAgeException]
/// ([TomSecretsAgeFailure.recipients]) for none or a mix.
Future<Uint8List> tomSecretsAgeEncrypt(
  List<int> plaintext,
  List<TomSecretsAgeRecipient> recipients,
) async {
  if (recipients.isEmpty) {
    throw const TomSecretsAgeException(
      TomSecretsAgeFailure.recipients,
      'an age file needs at least one recipient',
    );
  }
  final hybrid = recipients.first.isHybrid;
  if (recipients.any((r) => r.isHybrid != hybrid)) {
    throw const TomSecretsAgeException(
      TomSecretsAgeFailure.recipients,
      'hybrid and classical keys cannot share one file: it would lose the '
      'protection against a quantum computer',
    );
  }
  final fileKey = _randomBytes(16);
  try {
    final header = StringBuffer('$_version\n');
    for (final r in recipients) {
      final (args, body) = r.isHybrid
          ? await _wrapHybrid(r, fileKey)
          : await _wrapX25519(r, fileKey);
      header.write('-> ${args.join(' ')}\n');
      header.write(_wrappedBase64(body));
    }
    header.write('---');
    final macInput = ascii.encode(header.toString());
    final macKey = tomSecretsHkdf(
      fileKey,
      salt: const [],
      info: ascii.encode('header'),
      length: 32,
    );
    final mac = crypto.Hmac(crypto.sha256, macKey).convert(macInput).bytes;
    final out = BytesBuilder(copy: false)
      ..add(macInput)
      ..add(ascii.encode(' ${_base64(mac)}\n'));
    final nonce = _randomBytes(16);
    final payloadKey = tomSecretsHkdf(
      fileKey,
      salt: nonce,
      info: ascii.encode('payload'),
      length: 32,
    );
    out.add(nonce);
    var counter = 0;
    var pos = 0;
    do {
      final end = min(pos + _chunk, plaintext.length);
      final last = end == plaintext.length;
      final box = await _aead.encrypt(
        plaintext.sublist(pos, end),
        secretKey: SecretKey(payloadKey),
        nonce: _streamNonce(counter, last),
      );
      out
        ..add(box.cipherText)
        ..add(box.mac.bytes);
      pos = end;
      counter++;
    } while (pos < plaintext.length);
    payloadKey.fillRange(0, payloadKey.length, 0);
    return out.toBytes();
  } finally {
    fileKey.fillRange(0, fileKey.length, 0);
  }
}

/// The plaintext of the `age` file [file] (binary or armoured), opened with
/// the first of [identities] that a stanza is for. Throws
/// [TomSecretsAgeException]: [TomSecretsAgeFailure.noMatch] when none
/// opens it, `header`, `payload` or `armor` when the file is broken.
Future<Uint8List> tomSecretsAgeDecrypt(
  Uint8List file,
  Iterable<TomSecretsAgeIdentity> identities,
) async {
  if (tomSecretsIsAgeArmor(file)) file = tomSecretsAgeDearmor(file);
  final header = _Header.parse(file);
  Uint8List? fileKey;
  for (final identity in identities) {
    fileKey = await _unwrap(header.stanzas, identity);
    if (fileKey != null) break;
  }
  if (fileKey == null) {
    throw const TomSecretsAgeException(
      TomSecretsAgeFailure.noMatch,
      'the file is not encrypted to this key',
    );
  }
  try {
    final macKey = tomSecretsHkdf(
      fileKey,
      salt: const [],
      info: ascii.encode('header'),
      length: 32,
    );
    final mac = crypto.Hmac(
      crypto.sha256,
      macKey,
    ).convert(header.macInput).bytes;
    if (!_equal(mac, header.mac)) {
      throw const TomSecretsAgeException(
        TomSecretsAgeFailure.header,
        'the header does not verify',
      );
    }
    return await _payload(Uint8List.sublistView(file, header.length), fileKey);
  } finally {
    fileKey.fillRange(0, fileKey.length, 0);
  }
}

/// Whether [file] begins with the `age` armour (white space before it
/// allowed).
bool tomSecretsIsAgeArmor(List<int> file) {
  var i = 0;
  while (i < file.length && const [9, 10, 13, 32].contains(file[i])) {
    i++;
  }
  final begin = ascii.encode(_armorBegin);
  if (file.length - i < begin.length) return false;
  for (var j = 0; j < begin.length; j++) {
    if (file[i + j] != begin[j]) return false;
  }
  return true;
}

/// [file] in the `age` armour, for pasting into a message.
String tomSecretsAgeArmor(List<int> file) {
  final b = base64.encode(file);
  final lines = [
    for (var i = 0; i < b.length; i += 64)
      b.substring(i, min(i + 64, b.length)),
  ];
  return '$_armorBegin\n${lines.join('\n')}${lines.isEmpty ? '' : '\n'}'
      '$_armorEnd\n';
}

/// The binary file inside the armoured [text] (white space around it and
/// CRLF line ends allowed). Throws [TomSecretsAgeFailure.armor] otherwise.
Uint8List tomSecretsAgeDearmor(List<int> text) {
  Never bad(String why) =>
      throw TomSecretsAgeException(TomSecretsAgeFailure.armor, why);
  final String s;
  try {
    s = ascii.decode(text).trim();
  } on FormatException {
    bad('the armour is not ASCII');
  }
  final lines = s.split(RegExp(r'\r?\n'));
  if (lines.length < 2 ||
      lines.first != _armorBegin ||
      lines.last != _armorEnd) {
    bad('not an armoured age file');
  }
  final body = lines.sublist(1, lines.length - 1);
  for (final (i, l) in body.indexed) {
    if (l.length > 64 || (i < body.length - 1 && l.length != 64)) {
      bad('an armour line of ${l.length} characters');
    }
  }
  try {
    final joined = body.join();
    final bytes = base64.decode(joined);
    if (base64.encode(bytes) != joined) bad('the armour is not canonical');
    return bytes;
  } on FormatException {
    bad('the armour is not base64');
  }
}

/// The 32-byte secret of a classical `AGE-SECRET-KEY-1…` identity.
Uint8List tomSecretsAgeClassicalSecret(String identity) {
  try {
    return tomSecretsBech32Data('age-secret-key-', identity.trim(), 32);
  } on TomSecretsMemberKeyException {
    throw const TomSecretsMemberKeyException(
      TomSecretsMemberKeyFailure.malformed,
      'not a classical age identity',
    );
  }
}

Future<(List<String>, Uint8List)> _wrapHybrid(
  TomSecretsAgeRecipient r,
  Uint8List fileKey,
) async {
  final encapsulation = await MlKem768X25519.encapsulate(r.publicKey);
  final ss = encapsulation.sharedSecret.extractBytes();
  encapsulation.sharedSecret.dispose();
  try {
    final (key, nonce) = _hpkeKeySchedule(ss, ascii.encode(_hybridInfo));
    final box = await _aead.encrypt(
      fileKey,
      secretKey: SecretKey(key),
      nonce: nonce,
    );
    key.fillRange(0, key.length, 0);
    return (
      [_hybridType, _base64(encapsulation.ciphertext)],
      Uint8List.fromList([...box.cipherText, ...box.mac.bytes]),
    );
  } finally {
    ss.fillRange(0, ss.length, 0);
  }
}

Future<(List<String>, Uint8List)> _wrapX25519(
  TomSecretsAgeRecipient r,
  Uint8List fileKey,
) async {
  final ephemeral = await _x25519.newKeyPair();
  final share = (await ephemeral.extractPublicKey()).bytes;
  final shared = await (await _x25519.sharedSecretKey(
    keyPair: ephemeral,
    remotePublicKey: SimplePublicKey(r.publicKey, type: KeyPairType.x25519),
  )).extractBytes();
  if (shared.every((b) => b == 0)) {
    throw const TomSecretsAgeException(
      TomSecretsAgeFailure.recipients,
      'the classical key is a low-order point',
    );
  }
  final key = tomSecretsHkdf(
    shared,
    salt: [...share, ...r.publicKey],
    info: ascii.encode(_x25519Info),
    length: 32,
  );
  final box = await _aead.encrypt(
    fileKey,
    secretKey: SecretKey(key),
    nonce: Uint8List(12),
  );
  key.fillRange(0, key.length, 0);
  return (
    [_x25519Type, _base64(share)],
    Uint8List.fromList([...box.cipherText, ...box.mac.bytes]),
  );
}

/// HPKE's key schedule in base mode (RFC 9180 §5.1) for the suite X-Wing
/// (0x647a), HKDF-SHA256 (0x0001), ChaCha20-Poly1305 (0x0003): the key and
/// the base nonce of [sharedSecret] under [info].
(Uint8List, Uint8List) _hpkeKeySchedule(
  List<int> sharedSecret,
  List<int> info,
) {
  final suite = [...ascii.encode('HPKE'), 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03];
  final v1 = ascii.encode('HPKE-v1');
  Uint8List hmac(List<int> key, List<int> data) =>
      Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);
  Uint8List extract(List<int> salt, String label, List<int> ikm) => hmac(
    salt.isEmpty ? List<int>.filled(32, 0) : salt,
    [...v1, ...suite, ...ascii.encode(label), ...ikm],
  );
  Uint8List expand(List<int> prk, String label, List<int> ctx, int length) {
    final labeled = [
      length >> 8,
      length & 0xff,
      ...v1,
      ...suite,
      ...ascii.encode(label),
      ...ctx,
    ];
    final out = BytesBuilder();
    var t = <int>[];
    for (var i = 1; out.length < length; i++) {
      t = hmac(prk, [...t, ...labeled, i]);
      out.add(t);
    }
    return Uint8List.sublistView(out.toBytes(), 0, length);
  }

  final context = [
    0, // mode_base
    ...extract(const [], 'psk_id_hash', const []),
    ...extract(const [], 'info_hash', info),
  ];
  final secret = extract(sharedSecret, 'secret', const []);
  try {
    return (
      expand(secret, 'key', context, 32),
      expand(secret, 'base_nonce', context, 12),
    );
  } finally {
    secret.fillRange(0, secret.length, 0);
  }
}

typedef _Stanza = ({List<String> args, Uint8List body});

TomSecretsAgeException _headerFailure(String why) =>
    TomSecretsAgeException(TomSecretsAgeFailure.header, why);

final class _Header {
  _Header(this.stanzas, this.macInput, this.mac, this.length);

  final List<_Stanza> stanzas;
  final Uint8List macInput;
  final Uint8List mac;
  final int length;

  static _Header parse(Uint8List file) {
    var pos = 0;
    String line() {
      final end = file.indexOf(0x0a, pos);
      if (end < 0) throw _headerFailure('the header is not terminated');
      final bytes = Uint8List.sublistView(file, pos, end);
      if (bytes.any((b) => b < 0x20 || b > 0x7e)) {
        throw _headerFailure('a header byte that is not printable');
      }
      pos = end + 1;
      return ascii.decode(bytes);
    }

    if (line() != _version) {
      throw _headerFailure('not an age v1 file');
    }
    final stanzas = <_Stanza>[];
    while (true) {
      final start = pos;
      final l = line();
      if (l.startsWith('--- ')) {
        final mac = _canonicalBase64(l.substring(4));
        if (mac == null || mac.length != 32) {
          throw _headerFailure('the header MAC is malformed');
        }
        return _Header(
          stanzas,
          Uint8List.sublistView(file, 0, start + 3),
          mac,
          pos,
        );
      }
      if (!l.startsWith('-> ')) throw _headerFailure('a malformed stanza');
      final args = l.substring(3).split(' ');
      if (args.any((a) => a.isEmpty)) {
        throw _headerFailure('a stanza with an empty argument');
      }
      final body = BytesBuilder();
      while (true) {
        final b = line();
        final bytes = _canonicalBase64(b);
        if (bytes == null || b.length > 64) {
          throw _headerFailure('a stanza body that is not canonical base64');
        }
        body.add(bytes);
        if (b.length < 64) break;
      }
      stanzas.add((args: args, body: body.toBytes()));
    }
  }
}

Future<Uint8List?> _unwrap(
  List<_Stanza> stanzas,
  TomSecretsAgeIdentity identity,
) async {
  switch (identity) {
    case TomSecretsAgeHybridIdentity(:final key):
      for (final s in stanzas.where((s) => s.args.first == _hybridType)) {
        if (s.args.length != 2) {
          throw _headerFailure('an mlkem768x25519 stanza with extra arguments');
        }
        final enc = _canonicalBase64(s.args[1]);
        if (enc == null || enc.length != MlKem768X25519.ciphertextLength) {
          throw _headerFailure('a malformed mlkem768x25519 share');
        }
        if (s.body.length != 32) {
          throw _headerFailure('an mlkem768x25519 body of ${s.body.length}');
        }
        final SecretBytes shared;
        try {
          shared = await MlKem768X25519.decapsulate(enc, key.seed);
        } on TomPqcException catch (e) {
          throw _headerFailure(e.message);
        }
        final ss = shared.extractBytes();
        shared.dispose();
        final (k, nonce) = _hpkeKeySchedule(ss, ascii.encode(_hybridInfo));
        ss.fillRange(0, ss.length, 0);
        final opened = await _open(k, nonce, s.body);
        k.fillRange(0, k.length, 0);
        if (opened != null) return opened;
      }
      return null;
    case TomSecretsAgeX25519Identity(:final _secret):
      final pair = await _x25519.newKeyPairFromSeed(_secret);
      final own = (await pair.extractPublicKey()).bytes;
      for (final s in stanzas.where((s) => s.args.first == _x25519Type)) {
        if (s.args.length != 2) {
          throw _headerFailure('an X25519 stanza with extra arguments');
        }
        final share = _canonicalBase64(s.args[1]);
        if (share == null || share.length != 32) {
          throw _headerFailure('a malformed X25519 share');
        }
        if (s.body.length != 32) {
          throw _headerFailure('an X25519 body of ${s.body.length}');
        }
        final shared = await (await _x25519.sharedSecretKey(
          keyPair: pair,
          remotePublicKey: SimplePublicKey(share, type: KeyPairType.x25519),
        )).extractBytes();
        if (shared.every((b) => b == 0)) {
          throw _headerFailure('an X25519 share of low order');
        }
        final k = tomSecretsHkdf(
          shared,
          salt: [...share, ...own],
          info: ascii.encode(_x25519Info),
          length: 32,
        );
        final opened = await _open(k, Uint8List(12), s.body);
        k.fillRange(0, k.length, 0);
        if (opened != null) return opened;
      }
      return null;
  }
}

Future<Uint8List> _payload(Uint8List rest, Uint8List fileKey) async {
  Never bad() => throw const TomSecretsAgeException(
    TomSecretsAgeFailure.payload,
    'the payload does not authenticate',
  );
  if (rest.length < 16) bad();
  final key = tomSecretsHkdf(
    fileKey,
    salt: Uint8List.sublistView(rest, 0, 16),
    info: ascii.encode('payload'),
    length: 32,
  );
  final out = BytesBuilder(copy: false);
  try {
    const sealed = _chunk + 16;
    var pos = 16;
    var counter = 0;
    while (true) {
      final end = min(pos + sealed, rest.length);
      final last = end == rest.length;
      final plain = await _open(
        key,
        _streamNonce(counter, last),
        Uint8List.sublistView(rest, pos, end),
      );
      if (plain == null || (plain.isEmpty && counter > 0)) bad();
      out.add(plain);
      if (last) break;
      pos = end;
      counter++;
    }
    return out.toBytes();
  } finally {
    key.fillRange(0, key.length, 0);
  }
}

Uint8List _streamNonce(int counter, bool last) {
  final nonce = Uint8List(12);
  var c = counter;
  for (var i = 10; i >= 0; i--) {
    nonce[i] = c & 0xff;
    c >>= 8;
  }
  if (last) nonce[11] = 1;
  return nonce;
}

Future<Uint8List?> _open(
  List<int> key,
  List<int> nonce,
  Uint8List sealed,
) async {
  if (sealed.length < 16) return null;
  try {
    return Uint8List.fromList(
      await _aead.decrypt(
        SecretBox(
          Uint8List.sublistView(sealed, 0, sealed.length - 16),
          nonce: nonce,
          mac: Mac(Uint8List.sublistView(sealed, sealed.length - 16)),
        ),
        secretKey: SecretKey(key),
      ),
    );
  } on SecretBoxAuthenticationError {
    return null;
  }
}

String _base64(List<int> bytes) => base64.encode(bytes).replaceAll('=', '');

/// [body] as a stanza writes it: unpadded base64 in lines of 64 characters,
/// the last one shorter (an empty line when the length is a multiple).
String _wrappedBase64(List<int> body) {
  final b = _base64(body);
  final out = StringBuffer();
  var i = 0;
  for (; i + 64 <= b.length; i += 64) {
    out.write('${b.substring(i, i + 64)}\n');
  }
  out.write('${b.substring(i)}\n');
  return out.toString();
}

Uint8List? _canonicalBase64(String text) {
  if (text.contains('=')) return null;
  try {
    final bytes = base64.decode(text.padRight((text.length + 3) ~/ 4 * 4, '='));
    return _base64(bytes) == text ? bytes : null;
  } on FormatException {
    return null;
  }
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
