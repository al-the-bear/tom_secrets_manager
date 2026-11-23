// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** Member keys (part-sharing, BP-32, DP-63, DP-177): each person's
/// hybrid post-quantum `age` key pair, the public keys received from other
/// people, and how both are kept in the primary vault.
///
/// - A member key is an `age` v1.3 hybrid identity, `AGE-SECRET-KEY-PQ-1…`:
///   a 32-byte seed from which `age`'s `mlkem768x25519` recipient type
///   derives an X25519 + ML-KEM-768 key pair (X-Wing, `tom_pqc`'s
///   [MlKem768X25519]). Its public key is the recipient `age1pq1…`, the
///   1,216-byte encapsulation key in Bech32, about 1,960 characters: passed
///   as a file, a pasted block or a QR code, compared by its fingerprint.
/// - Other people's classical `age1…` (X25519) recipients are accepted, for
///   exports to them only: `age` encrypts no file to hybrid and classical
///   recipients together, so a shared vault's recipients file takes hybrid
///   keys alone.
/// - The fingerprint is the SHA-256 of the recipient string in base32
///   (RFC 4648, lower case, no padding, 52 characters); it is also the
///   member id of the inbox folders and the relay's mailboxes. People
///   compare its first 20 characters, [TomSecretsAgeRecipient.shortFingerprint].
/// - In the primary vault the group `tsm.sharing` (at the root; never
///   resolved into, never exported) holds the `member-key` entry (the
///   identity in `Password`) and one `member` entry per received key (its
///   name, recipient, fingerprint and the date it was checked).
library;

import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_age/tom_secrets_age.dart';

import 'mapping.dart';

/// The fields of the `member-key` and `member` entries.
abstract final class TomSecretsMemberFields {
  /// The `age` recipient string (`age1pq1…`, or a member's `age1…`).
  static const recipient = KdbxKey('tsm.recipient');

  /// The recipient's fingerprint, for display in other KeePass programs.
  static const fingerprint = KdbxKey('tsm.fingerprint');

  /// When the user compared a member's fingerprint with its owner (an
  /// ISO 8601 date), absent until then.
  static const checked = KdbxKey('tsm.checked');
}

/// A received public key in the primary vault (a `member` entry).
final class TomSecretsMember {
  TomSecretsMember._(this.entry, this.recipient);

  /// The entry.
  final KdbxEntry entry;

  /// The member's public key.
  final TomSecretsAgeRecipient recipient;

  /// The name the user gave the member (the entry's title).
  String get name => entry.label ?? '';

  /// When the user compared the fingerprint with the member, or null.
  DateTime? get checked {
    final text = entry.getString(TomSecretsMemberFields.checked)?.getText();
    return text == null ? null : DateTime.tryParse(text);
  }

  /// Whether the key can join shared vaults (hybrid), not only receive
  /// exports (classical).
  bool get canJoinSharedVaults => recipient.isHybrid;
}

/// The `tsm.sharing` group at the root of [file], made when [create].
KdbxGroup? tomSecretsSharingGroupOf(KdbxFile file, {bool create = false}) {
  final root = file.body.rootGroup;
  final found = root.groups
      .where((g) => g.name.get() == tomSecretsSharingGroup)
      .firstOrNull;
  if (found != null || !create) return found;
  return file.createGroup(parent: root, name: tomSecretsSharingGroup);
}

Iterable<KdbxEntry> _ofType(KdbxFile file, TomSecretsEntryType type) =>
    (tomSecretsSharingGroupOf(file)?.entries ?? const <KdbxEntry>[]).where(
      (e) =>
          TomSecretsEntryType.of(
            e.getString(TomSecretsEntryFields.type)?.getText(),
          ) ==
          type,
    );

/// The `member-key` entries of [file], the newest first (a rotation keeps
/// the old key until it finishes, part-key-rotation).
List<KdbxEntry> tomSecretsMemberKeyEntries(KdbxFile file) =>
    _ofType(file, TomSecretsEntryType.memberKey).toList()..sort(
      (a, b) => (b.times.creationTime.get() ?? DateTime(0)).compareTo(
        a.times.creationTime.get() ?? DateTime(0),
      ),
    );

/// The member key an entry holds (its identity in `Password`).
Future<TomSecretsMemberKey> tomSecretsMemberKeyOf(KdbxEntry entry) {
  final identity = entry.getString(KdbxKeyCommon.PASSWORD)?.getText();
  if (identity == null) throw _malformed('the entry holds no member key');
  return TomSecretsMemberKey.parse(identity);
}

/// The public key a `member-key` entry names, read without its identity.
TomSecretsAgeRecipient? tomSecretsMemberKeyRecipientOf(KdbxEntry entry) {
  final text = entry.getString(TomSecretsMemberFields.recipient)?.getText();
  if (text == null) return null;
  try {
    return TomSecretsAgeRecipient.parse(text);
  } on TomSecretsMemberKeyException {
    return null;
  }
}

/// Writes [key] into [file] as a new `member-key` entry titled [title] in
/// `tsm.sharing`: the identity protected in `Password`, the recipient and
/// fingerprint beside it. Answers the entry.
KdbxEntry tomSecretsAddMemberKey(
  KdbxFile file,
  TomSecretsMemberKey key, {
  String title = 'Member key',
}) {
  final group = tomSecretsSharingGroupOf(file, create: true)!;
  final entry = KdbxEntry.create(file, group)..label = title;
  entry.setString(
    TomSecretsEntryFields.type,
    PlainValue(TomSecretsEntryType.memberKey.wireName),
  );
  entry.setString(
    KdbxKeyCommon.PASSWORD,
    ProtectedValue.fromString(key.revealIdentity()),
  );
  entry.setString(
    TomSecretsMemberFields.recipient,
    PlainValue(key.recipient.encoded),
  );
  entry.setString(
    TomSecretsMemberFields.fingerprint,
    PlainValue(key.recipient.fingerprint),
  );
  group.addEntry(entry);
  return entry;
}

/// The members of [file] whose entry holds a readable recipient, by name.
List<TomSecretsMember> tomSecretsMembers(KdbxFile file) => [
  for (final e in _ofType(file, TomSecretsEntryType.member))
    if (tomSecretsMemberKeyRecipientOf(e) case final r?)
      TomSecretsMember._(e, r),
]..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

/// Adds [recipient] to [file]'s directory as a `member` entry named [name],
/// after [TomSecretsAgeRecipient.check]. Refused: a recipient the directory
/// holds already ([TomSecretsMemberKeyFailure.duplicate]) or one of the
/// user's own member keys ([TomSecretsMemberKeyFailure.ownKey]).
Future<TomSecretsMember> tomSecretsAddMember(
  KdbxFile file, {
  required String name,
  required TomSecretsAgeRecipient recipient,
  DateTime? checked,
}) async {
  for (final own in tomSecretsMemberKeyEntries(file)) {
    if (tomSecretsMemberKeyRecipientOf(own) == recipient) {
      throw const TomSecretsMemberKeyException(
        TomSecretsMemberKeyFailure.ownKey,
        'this is your own member key',
      );
    }
  }
  final existing = tomSecretsMembers(
    file,
  ).where((m) => m.recipient == recipient).firstOrNull;
  if (existing != null) {
    throw TomSecretsMemberKeyException(
      TomSecretsMemberKeyFailure.duplicate,
      'the key is in the directory already, as ${existing.name}',
    );
  }
  await recipient.check();
  final group = tomSecretsSharingGroupOf(file, create: true)!;
  final entry = KdbxEntry.create(file, group)..label = name.trim();
  entry.setString(
    TomSecretsEntryFields.type,
    PlainValue(TomSecretsEntryType.member.wireName),
  );
  entry.setString(
    TomSecretsMemberFields.recipient,
    PlainValue(recipient.encoded),
  );
  entry.setString(
    TomSecretsMemberFields.fingerprint,
    PlainValue(recipient.fingerprint),
  );
  group.addEntry(entry);
  if (checked != null) tomSecretsMarkMemberChecked(entry, checked);
  return TomSecretsMember._(entry, recipient);
}

/// Records that the user compared the fingerprint of [entry] with its owner
/// on [when] (its date); the entry as it was goes to its history.
void tomSecretsMarkMemberChecked(KdbxEntry entry, DateTime when) {
  final day = when.toUtc().toIso8601String().substring(0, 10);
  entry.modify(() {
    entry.setString(TomSecretsMemberFields.checked, PlainValue(day));
  });
}

TomSecretsMemberKeyException _malformed(String why) =>
    TomSecretsMemberKeyException(TomSecretsMemberKeyFailure.malformed, why);
