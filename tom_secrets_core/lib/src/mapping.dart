// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The product's concepts on standard KDBX fields (part-structure, BP-36):
/// reserved names, the flat key, the entry type, attachments, passkeys and
/// what an entry's value looks like when it is read.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

/// The field names the product reserves (`tsm.` prefix) and the foreign
/// conventions it reads.
abstract final class TomSecretsEntryFields {
  /// The flat key, a dotted name (`telegram.bot_token`).
  static const key = KdbxKey('tsm.key');

  /// The entry type.
  static const type = KdbxKey('tsm.type');

  /// The prefix of the product's reserved names.
  static const reservedPrefix = 'tsm.';

  /// The prefix of an import origin, `tsm.import.<source>.id`.
  static const importPrefix = 'tsm.import.';

  /// The passkey fields KeePassXC writes; never served on the client
  /// endpoint (DP-120).
  static const passkeyPrefix = 'KPEX_PASSKEY_';

  /// The extra URL fields for autofill.
  static const extraUrlPrefix = 'KP2A_URL';

  /// The virtual field: the current TOTP code.
  static const totp = 'totp';

  /// The prefix of an attachment field, `attachment:<name>`.
  static const attachmentPrefix = 'attachment:';

  /// The import origin field of [source] (`tsm.import.1password.id`).
  static KdbxKey importId(String source) => KdbxKey('$importPrefix$source.id');
}

/// The group holding the grants of every host (primary vault only); never a
/// place references resolve into.
const String tomSecretsGrantsGroup = 'tsm.grants';

/// The first character of an overlay group's name.
const String tomSecretsOverlayPrefix = '@';

/// The tag that marks a favourite.
const String tomSecretsFavoriteTag = 'favorite';

/// What kind of secret an entry holds (`tsm.type`).
enum TomSecretsEntryType {
  /// A login (the default).
  login('login'),

  /// An API token in `Password`, with Expires and the service in `URL`.
  apiToken('api-token'),

  /// A note.
  note('note'),

  /// **[B]** An SSH key.
  sshKey('ssh-key'),

  /// **[C]** A certificate.
  certificate('certificate'),

  /// **[C]** A PGP key.
  pgpKey('pgp-key');

  const TomSecretsEntryType(this.wireName);

  /// The value of `tsm.type`.
  final String wireName;

  /// The type of a `tsm.type` value; absent or unknown is [login].
  static TomSecretsEntryType of(String? value) =>
      values.where((t) => t.wireName == value).firstOrNull ?? login;
}

/// Whether [field] is a passkey field the client endpoint never serves.
bool tomSecretsIsPasskeyField(String field) =>
    field.startsWith(TomSecretsEntryFields.passkeyPrefix);

/// Whether [name] is reserved for the product (`tsm.` names, `@` groups).
bool tomSecretsIsReservedName(String name) =>
    name.startsWith(TomSecretsEntryFields.reservedPrefix) ||
    name.startsWith(tomSecretsOverlayPrefix);

/// The 32 lower-case hex digits of [uuid], as `~uuid` references write it.
String tomSecretsUuidHex(KdbxUuid uuid) => base64
    .decode(uuid.uuid)
    .map((b) => b.toRadixString(16).padLeft(2, '0'))
    .join();

/// The [KdbxUuid] of 32 hex digits.
KdbxUuid tomSecretsUuidFromHex(String hex) {
  final bytes = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return KdbxUuid.fromBytes(bytes);
}

/// The value of one field of an entry: text (a string field, the TOTP code)
/// or bytes (an attachment). [dispose] overwrites the buffer.
final class TomSecretsFieldValue {
  /// A text value.
  TomSecretsFieldValue.text(String text, {this.isProtected = false})
    : isText = true,
      _bytes = Uint8List.fromList(utf8.encode(text));

  /// A binary value.
  TomSecretsFieldValue.bytes(Uint8List bytes, {this.isProtected = false})
    : isText = false,
      _bytes = bytes;

  final Uint8List _bytes;

  /// Whether the value is text (sent as `utf8`); otherwise bytes (`base64`).
  final bool isText;

  /// Whether the file keeps it protected (in-memory protection).
  final bool isProtected;

  /// The value's bytes (text as its UTF-8).
  Uint8List get bytes => _bytes;

  /// The text of a text value.
  String get text {
    if (!isText) throw StateError('a binary value has no text');
    return utf8.decode(_bytes);
  }

  /// Overwrites the buffer with zeros.
  void dispose() => _bytes.fillRange(0, _bytes.length, 0);

  @override
  String toString() =>
      'TomSecretsFieldValue(${isText ? 'text' : 'bytes'}: ***)';
}
