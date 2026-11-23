// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** Single-entry exports and the inbox folders (part-sharing, BP-34,
/// DP-63, DP-177): one or more entries written as one encrypted package for
/// another person, and the `inbox/<member-id>/` folders a shared vault's
/// repository carries them in.
///
/// - **The package** ([TomSecretsShare]): the entries as a small JSON
///   document (`{"format": "tsm.share", "version": 1, ...}`): per entry its
///   title, fields (with their protection), tags, attachments, expiry, the
///   entry type (`tsm.type`) and its `tsm.key`; never the vault's metadata,
///   history or other `tsm.*` fields. It names who sent it, as the sender
///   says (`from`: name and member-key fingerprint).
/// - **Encryption** ([tomSecretsWriteShare]): an `age` v1 file to members'
///   hybrid keys (the default), under a passphrase (`age`'s scrypt
///   recipient) or to classical keys alone, which is not protected against a
///   future quantum computer.
/// - **Forms:** the armoured text ([tomSecretsAgeArmor]), a QR code of that
///   text while it fits ([tomSecretsShareFitsQr]), a `.tsmshare` file (the
///   binary `age` file).
/// - **The inbox:** `inbox/<member-id>/<date>-<random>.age` beside a shared
///   vault, the member id the recipient's fingerprint; read and deleted by
///   the recipient, expired after 30 days by whichever member syncs next
///   ([tomSecretsInboxExpired]).
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_age/tom_secrets_age.dart';

import 'mapping.dart';

/// The `format` of a share's JSON document.
const tomSecretsShareFormat = 'tsm.share';

/// The version of the share's JSON document this code writes and reads.
const tomSecretsShareVersion = 1;

/// The file extension of a share saved as a file.
const tomSecretsShareExtension = '.tsmshare';

/// The most characters a QR code holds (version 40, error correction L,
/// byte mode): a share is shown as a QR code only while its armoured text
/// fits.
const tomSecretsQrCapacity = 2953;

/// The folder beside a shared vault that holds the members' inboxes.
const tomSecretsInboxFolder = 'inbox';

/// How long a package stays in an inbox before any member's sync deletes
/// it.
const tomSecretsInboxExpiry = Duration(days: 30);

/// Why a share could not be written or read.
enum TomSecretsShareFailure {
  /// The decrypted document is not a share this version reads.
  format,

  /// Neither recipients nor a passphrase, or both.
  protection,
}

/// A refused share.
final class TomSecretsShareException implements Exception {
  /// A refusal for [reason], told by [message].
  const TomSecretsShareException(this.reason, this.message);

  /// Why.
  final TomSecretsShareFailure reason;

  /// For people; never a secret.
  final String message;

  @override
  String toString() => 'TomSecretsShareException(${reason.name}): $message';
}

/// One field of a shared entry.
typedef TomSecretsSharedField = ({String value, bool protected});

/// One attachment of a shared entry.
typedef TomSecretsSharedAttachment = ({Uint8List bytes, bool protected});

/// One entry of a share.
final class TomSecretsSharedEntry {
  /// An entry: its [fields] (the title among them), [tags], [attachments]
  /// and [expires] (null: does not expire).
  const TomSecretsSharedEntry({
    required this.fields,
    this.tags = const [],
    this.attachments = const {},
    this.expires,
  });

  /// The fields by name, `Title` and the product's `tsm.type` / `tsm.key`
  /// among them.
  final Map<String, TomSecretsSharedField> fields;

  /// The tags.
  final List<String> tags;

  /// The attachments by name.
  final Map<String, TomSecretsSharedAttachment> attachments;

  /// When it expires, or null.
  final DateTime? expires;

  /// The title.
  String get title => fields['Title']?.value ?? '';

  /// The entry type.
  TomSecretsEntryType get type =>
      TomSecretsEntryType.of(fields[TomSecretsEntryFields.type.key]?.value);

  Map<String, Object?> _toJson() => {
    'fields': {
      for (final MapEntry(:key, :value) in fields.entries)
        key: {'value': value.value, if (value.protected) 'protected': true},
    },
    if (tags.isNotEmpty) 'tags': tags,
    if (attachments.isNotEmpty)
      'attachments': {
        for (final MapEntry(:key, :value) in attachments.entries)
          key: {
            'data': base64.encode(value.bytes),
            if (value.protected) 'protected': true,
          },
      },
    if (expires != null) 'expires': expires!.toUtc().toIso8601String(),
  };

  static TomSecretsSharedEntry _fromJson(Object? json) {
    if (json is! Map) throw _malformed('an entry is not an object');
    final fields = json['fields'];
    if (fields is! Map) throw _malformed('an entry without fields');
    final attachments = json['attachments'] ?? const {};
    if (attachments is! Map) throw _malformed('malformed attachments');
    final tags = json['tags'] ?? const [];
    if (tags is! List || tags.any((t) => t is! String)) {
      throw _malformed('malformed tags');
    }
    final expires = json['expires'];
    return TomSecretsSharedEntry(
      fields: {
        for (final MapEntry(:key, :value) in fields.entries)
          _string(key, 'a field name'): (
            value: _string(
              value is Map ? value['value'] : null,
              'the value of $key',
            ),
            protected: value is Map && value['protected'] == true,
          ),
      },
      tags: tags.cast<String>(),
      attachments: {
        for (final MapEntry(:key, :value) in attachments.entries)
          _string(key, 'an attachment name'): (
            bytes: _base64(value is Map ? value['data'] : null, key),
            protected: value is Map && value['protected'] == true,
          ),
      },
      expires: expires == null
          ? null
          : DateTime.tryParse(_string(expires, 'expires')) ??
                (throw _malformed('expires is not a time')),
    );
  }
}

/// Who sent a share, as the sender says: their name and the fingerprint of
/// their member key.
typedef TomSecretsShareSender = ({String name, String fingerprint});

/// A share: entries for another person, and who sent them when.
final class TomSecretsShare {
  /// A share of [entries] from [from], made at [created].
  const TomSecretsShare({
    required this.entries,
    required this.created,
    this.from,
  });

  /// The entries.
  final List<TomSecretsSharedEntry> entries;

  /// When it was made.
  final DateTime created;

  /// Who sent it, as they say, or null.
  final TomSecretsShareSender? from;

  /// The JSON document, UTF-8.
  Uint8List encode() => utf8.encode(
    jsonEncode({
      'format': tomSecretsShareFormat,
      'version': tomSecretsShareVersion,
      'created': created.toUtc().toIso8601String(),
      if (from != null)
        'from': {'name': from!.name, 'fingerprint': from!.fingerprint},
      'entries': [for (final e in entries) e._toJson()],
    }),
  );

  /// The share of the JSON document [bytes]. Throws
  /// [TomSecretsShareException] ([TomSecretsShareFailure.format]) for one
  /// that is not a share this version reads.
  factory TomSecretsShare.decode(List<int> bytes) {
    final Object? json;
    try {
      json = jsonDecode(utf8.decode(bytes));
    } on FormatException {
      throw _malformed('not a JSON document');
    }
    if (json is! Map || json['format'] != tomSecretsShareFormat) {
      throw _malformed('not a Tom Secrets Manager share');
    }
    if (json['version'] != tomSecretsShareVersion) {
      throw _malformed(
        'a share of version ${json['version']}: update the app to read it',
      );
    }
    final entries = json['entries'];
    if (entries is! List || entries.isEmpty) {
      throw _malformed('a share without entries');
    }
    final from = json['from'];
    return TomSecretsShare(
      entries: [for (final e in entries) TomSecretsSharedEntry._fromJson(e)],
      created:
          DateTime.tryParse(_string(json['created'], 'created')) ??
          (throw _malformed('created is not a time')),
      from: from is Map
          ? (
              name: _string(from['name'], 'the sender name'),
              fingerprint: _string(from['fingerprint'], 'the fingerprint'),
            )
          : null,
    );
  }
}

TomSecretsShareException _malformed(String why) =>
    TomSecretsShareException(TomSecretsShareFailure.format, why);

String _string(Object? v, String what) =>
    v is String ? v : throw _malformed('$what is not a string');

Uint8List _base64(Object? v, String name) {
  try {
    return base64.decode(_string(v, 'the attachment $name'));
  } on FormatException {
    throw _malformed('the attachment $name is not base64');
  }
}

/// The share of [entries] (live entries of a vault), from [from], made at
/// [now]: every field but the product's other `tsm.*` fields and overlay
/// fields, the tags, the attachments and the expiry.
TomSecretsShare tomSecretsShareOf(
  List<KdbxEntry> entries, {
  TomSecretsShareSender? from,
  DateTime? now,
}) {
  const kept = {'tsm.type', 'tsm.key'};
  TomSecretsSharedEntry one(KdbxEntry e) => TomSecretsSharedEntry(
    fields: {
      for (final MapEntry(:key, :value) in e.stringEntries)
        if (value != null &&
            (!tomSecretsIsReservedName(key.key) || kept.contains(key.key)))
          key.key: (
            value: value.getText() ?? '',
            protected: value is ProtectedValue,
          ),
    },
    tags: [
      for (final t in (e.tags.get() ?? '').split(RegExp('[;,]')))
        if (t.trim().isNotEmpty) t.trim(),
    ],
    attachments: {
      for (final MapEntry(:key, :value) in e.binaryEntries)
        key.key: (
          bytes: Uint8List.fromList(value.value),
          protected: value.isProtected,
        ),
    },
    expires: e.times.expires.get() == true
        ? e.times.expiryTime.get()?.toUtc()
        : null,
  );

  return TomSecretsShare(
    entries: [for (final e in entries) one(e)],
    created: (now ?? DateTime.now()).toUtc(),
    from: from,
  );
}

/// The entries of [share] added to [group] of [file] as new entries (new
/// UUIDs, so a share imported twice does not collide). Answers them.
List<KdbxEntry> tomSecretsImportShare(
  KdbxFile file,
  KdbxGroup group,
  TomSecretsShare share,
) {
  final out = <KdbxEntry>[];
  for (final s in share.entries) {
    final entry = KdbxEntry.create(file, group);
    group.addEntry(entry);
    entry.modify(() {
      for (final MapEntry(:key, :value) in s.fields.entries) {
        entry.setString(
          KdbxKey(key),
          value.protected
              ? ProtectedValue.fromString(value.value)
              : PlainValue(value.value),
        );
      }
      for (final MapEntry(:key, :value) in s.attachments.entries) {
        entry.createBinary(
          isProtected: value.protected,
          name: key,
          bytes: value.bytes,
        );
      }
      if (s.tags.isNotEmpty) entry.tags.set(s.tags.join(';'));
      if (s.expires != null) {
        entry.times.expires.set(true);
        entry.times.expiryTime.set(s.expires);
      }
    });
    out.add(entry);
  }
  return out;
}

/// [share] encrypted as an `age` file: to [recipients] (all hybrid member
/// keys, or all classical keys) or under [passphrase] (`age`'s scrypt
/// recipient, [workFactor] its log2 N). Exactly one of the two. Throws
/// [TomSecretsShareException] ([TomSecretsShareFailure.protection]) else,
/// and [TomSecretsAgeException] for a mix of hybrid and classical keys.
Future<Uint8List> tomSecretsWriteShare(
  TomSecretsShare share, {
  List<TomSecretsAgeRecipient>? recipients,
  String? passphrase,
  int workFactor = tomSecretsAgeDefaultWorkFactor,
}) async {
  if ((recipients == null || recipients.isEmpty) == (passphrase == null)) {
    throw const TomSecretsShareException(
      TomSecretsShareFailure.protection,
      'a share is written to recipients or under a passphrase',
    );
  }
  if (passphrase != null && passphrase.isEmpty) {
    throw const TomSecretsShareException(
      TomSecretsShareFailure.protection,
      'the passphrase is empty',
    );
  }
  final plain = share.encode();
  try {
    return passphrase != null
        ? await tomSecretsAgeEncryptPassphrase(
            plain,
            passphrase,
            workFactor: workFactor,
          )
        : await tomSecretsAgeEncrypt(plain, recipients!);
  } finally {
    plain.fillRange(0, plain.length, 0);
  }
}

/// The share in [bytes] (a `.tsmshare` file, the armoured text or a QR
/// code's text as bytes), opened with the first of [identities] that fits
/// (member keys, a [TomSecretsAgePassphraseIdentity]). Throws
/// [TomSecretsAgeException] when none opens it or the file is broken, and
/// [TomSecretsShareException] when it is not a share.
Future<TomSecretsShare> tomSecretsReadShare(
  List<int> bytes,
  Iterable<TomSecretsAgeIdentity> identities,
) async {
  final plain = await tomSecretsAgeDecrypt(
    Uint8List.fromList(bytes),
    identities,
  );
  try {
    return TomSecretsShare.decode(plain);
  } finally {
    plain.fillRange(0, plain.length, 0);
  }
}

/// Whether [text] (pasted, scanned) holds a share: an armoured `age` file.
bool tomSecretsLooksLikeShare(String text) =>
    tomSecretsIsAgeArmor(utf8.encode(text));

/// Whether the share [file] fits a QR code as armoured text.
bool tomSecretsShareFitsQr(List<int> file) =>
    tomSecretsAgeArmor(file).length <= tomSecretsQrCapacity;

final _member = RegExp(r'^[a-z2-7]{16,}$');
final _name = RegExp(r'^(\d{4})-(\d{2})-(\d{2})-[0-9a-f]{16}\.age$');
final _random = Random.secure();

/// Whether [id] is a member id an inbox folder may be named by (a member
/// key's fingerprint).
bool tomSecretsIsInboxMember(String id) => _member.hasMatch(id);

/// Whether [name] is the name of a package in an inbox.
bool tomSecretsIsInboxName(String name) => _name.hasMatch(name);

/// The path, relative to a shared vault's folder, of the package [name] in
/// the inbox of the member [memberId].
String tomSecretsInboxPath(String memberId, String name) {
  if (!tomSecretsIsInboxMember(memberId)) {
    throw ArgumentError.value(memberId, 'memberId', 'not a member id');
  }
  if (!tomSecretsIsInboxName(name)) {
    throw ArgumentError.value(name, 'name', 'not an inbox package name');
  }
  return '$tomSecretsInboxFolder/$memberId/$name';
}

/// A new package name, `<date>-<random>.age` (the date in UTC at [now]).
String tomSecretsNewInboxName({DateTime? now}) {
  final at = (now ?? DateTime.now()).toUtc();
  String two(int n) => n.toString().padLeft(2, '0');
  final random = [
    for (var i = 0; i < 8; i++) _random.nextInt(256).toRadixString(16),
  ].map((h) => h.padLeft(2, '0')).join();
  return '${at.year.toString().padLeft(4, '0')}-${two(at.month)}-'
      '${two(at.day)}-$random.age';
}

/// The day a package named [name] was put into an inbox (UTC), or null for
/// a name that is not a package's.
DateTime? tomSecretsInboxDate(String name) {
  final m = _name.firstMatch(name);
  if (m == null) return null;
  return DateTime.utc(
    int.parse(m.group(1)!),
    int.parse(m.group(2)!),
    int.parse(m.group(3)!),
  );
}

/// Whether the package [name] is past the inbox expiry at [now]: put in
/// more than 30 days ago. A file whose name is not a package's is never
/// expired: it is not the product's to delete.
bool tomSecretsInboxExpired(String name, DateTime now) {
  final day = tomSecretsInboxDate(name);
  return day != null && now.toUtc().difference(day) > tomSecretsInboxExpiry;
}
