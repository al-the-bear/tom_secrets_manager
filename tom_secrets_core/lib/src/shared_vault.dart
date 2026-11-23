// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** Shared vaults (part-sharing, part-stores, BP-32, DP-177): an
/// ordinary vault (kind `shared`) in a repository every member can push to,
/// opened by a key file alone — no master password — and, when the
/// repository is outer encrypted, its repository key. Both travel in the
/// **recipients file** `<vault>.keys.age` beside the vault, an `age` file
/// encrypted to every member's hybrid recipient (`age1pq1…`), so a member's
/// app opens the vault with their member key and the `age` command line
/// (v1.3.0 on) opens the file too.
///
/// The recipients file's plaintext is UTF-8 JSON
/// (`tsm-shared-vault-keys/1`): the vault's name, its key file (base64),
/// its repository key (base64, when outer encrypted) and the members (name
/// and recipient), so any member can encrypt it again for one member more
/// or one less. An `age` header does not say whom a file is for.
///
/// - **Adding a member:** the recipients file written again for the
///   members and the new one; the vault and its keys stay.
/// - **Removing a member:** a new key file (and a new repository key) — the
///   vault re-keyed to it and the recipients file written for the members
///   left, in one commit. The removed member keeps what they already saw;
///   older recipients files stay in the git history, so they still open
///   older versions of the vault, never the new ones.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_age/tom_secrets_age.dart';

import 'key_file.dart';
import 'metadata.dart';
import 'new_vault.dart';
import 'outer.dart';
import 'rotation.dart' show tomSecretsKeyId;
import 'stored_vault.dart';

/// The format of a recipients file's plaintext.
const String tomSecretsSharedVaultKeysFormat = 'tsm-shared-vault-keys/1';

/// The suffix of a recipients file, after the vault's name.
const String tomSecretsRecipientsSuffix = '.keys.age';

/// One member a shared vault's recipients file is written for.
typedef TomSecretsSharedVaultMember = ({
  String name,
  TomSecretsAgeRecipient recipient,
});

/// Why a shared vault's keys could not be read or written.
enum TomSecretsSharedVaultFailure {
  /// The recipients file is not for this member key.
  notAMember,

  /// The recipients file opens but holds no readable keys.
  malformed,

  /// A member without a hybrid key, no member, or one twice.
  members,
}

/// A refused recipients file or member change.
final class TomSecretsSharedVaultException implements Exception {
  /// A refusal for [reason], told by [message].
  const TomSecretsSharedVaultException(this.reason, this.message);

  /// Why.
  final TomSecretsSharedVaultFailure reason;

  /// For people; never a key.
  final String message;

  @override
  String toString() =>
      'TomSecretsSharedVaultException(${reason.name}): $message';
}

/// What a shared vault's recipients file holds: the vault's keys and its
/// members. [dispose] zeroes the keys.
final class TomSecretsSharedVaultKeys {
  TomSecretsSharedVaultKeys._({
    required this.vault,
    required this.keyFile,
    required this.repositoryKey,
    required List<TomSecretsSharedVaultMember> members,
  }) : members = List.unmodifiable(members);

  /// New keys for the shared vault [vault] (a fresh KeePass key file of 32
  /// random bytes; a fresh repository key when [outer]) for [members].
  /// Throws [TomSecretsSharedVaultException] for members it cannot take
  /// ([tomSecretsCheckSharedVaultMembers]).
  factory TomSecretsSharedVaultKeys.generate(
    String vault, {
    required List<TomSecretsSharedVaultMember> members,
    bool outer = false,
  }) {
    tomSecretsCheckSharedVaultMembers(members);
    return TomSecretsSharedVaultKeys._(
      vault: vault,
      keyFile: TomSecretsKeyFile.generate().toBytes(),
      repositoryKey: outer
          ? TomSecretsRepositoryKey.generate().toBase64()
          : null,
      members: members,
    );
  }

  /// The keys of a recipients file's plaintext [json]. Throws
  /// [TomSecretsSharedVaultException] ([TomSecretsSharedVaultFailure.malformed]).
  factory TomSecretsSharedVaultKeys.fromJson(Map<String, Object?> json) {
    Never bad(String why) => throw TomSecretsSharedVaultException(
      TomSecretsSharedVaultFailure.malformed,
      'the recipients file holds no readable keys: $why',
    );
    if (json['format'] != tomSecretsSharedVaultKeysFormat) {
      bad('format ${json['format']}');
    }
    final vault = json['vault'];
    final keyFile = json['keyFile'];
    final repositoryKey = json['repositoryKey'];
    final members = json['members'];
    if (vault is! String ||
        keyFile is! String ||
        (repositoryKey != null && repositoryKey is! String) ||
        members is! List) {
      bad('a member is missing');
    }
    final read = <TomSecretsSharedVaultMember>[];
    for (final m in members) {
      if (m is! Map || m['name'] is! String || m['recipient'] is! String) {
        bad('a malformed member');
      }
      try {
        read.add((
          name: m['name'] as String,
          recipient: TomSecretsAgeRecipient.parse(m['recipient'] as String),
        ));
      } on TomSecretsMemberKeyException catch (e) {
        bad(e.message);
      }
    }
    try {
      if (repositoryKey != null) {
        TomSecretsRepositoryKey.fromBase64(repositoryKey as String);
      }
      return TomSecretsSharedVaultKeys._(
        vault: vault,
        keyFile: base64.decode(keyFile),
        repositoryKey: repositoryKey as String?,
        members: read,
      );
    } on Object {
      bad('a key is not base64');
    }
  }

  /// The vault's store name.
  final String vault;

  /// The KDBX key file's bytes: the vault's only credential.
  final Uint8List keyFile;

  /// The repository's outer key (base64), when the vault is outer
  /// encrypted.
  final String? repositoryKey;

  /// The members it is written for, in their order.
  final List<TomSecretsSharedVaultMember> members;

  /// The credentials that open the vault.
  Credentials get credentials =>
      tomSecretsVaultCredentials(keyFile: Uint8List.fromList(keyFile));

  /// Whether [recipient] is a member.
  bool hasMember(TomSecretsAgeRecipient recipient) =>
      members.any((m) => m.recipient == recipient);

  /// The same keys for the members and [member] (adding a member: the
  /// vault and its keys stay). Refused for a member already there or one
  /// without a hybrid key.
  TomSecretsSharedVaultKeys withMember(TomSecretsSharedVaultMember member) {
    final next = [...members, member];
    tomSecretsCheckSharedVaultMembers(next);
    return TomSecretsSharedVaultKeys._(
      vault: vault,
      keyFile: Uint8List.fromList(keyFile),
      repositoryKey: repositoryKey,
      members: next,
    );
  }

  /// New keys for the members but [recipient] (removing a member): a new
  /// key file and, for an outer-encrypted vault, a new repository key; the
  /// vault is to be re-keyed to them. Refused when [recipient] is no member
  /// or would leave none.
  TomSecretsSharedVaultKeys withoutMember(TomSecretsAgeRecipient recipient) {
    if (!hasMember(recipient)) {
      throw const TomSecretsSharedVaultException(
        TomSecretsSharedVaultFailure.members,
        'the key is not a member of the vault',
      );
    }
    return TomSecretsSharedVaultKeys.generate(
      vault,
      members: [
        for (final m in members)
          if (m.recipient != recipient) m,
      ],
      outer: repositoryKey != null,
    );
  }

  /// The same keys without the recipient [recipient] (part-key-rotation:
  /// a member's old key dropped at the finish of its rotation, the same
  /// person still a member under the new one). Refused when it is no member
  /// or would leave none. The vault is not re-keyed: use [withoutMember]
  /// to remove a person.
  TomSecretsSharedVaultKeys withoutRecipient(TomSecretsAgeRecipient recipient) {
    if (!hasMember(recipient)) {
      throw const TomSecretsSharedVaultException(
        TomSecretsSharedVaultFailure.members,
        'the key is not a member of the vault',
      );
    }
    final next = [
      for (final m in members)
        if (m.recipient != recipient) m,
    ];
    tomSecretsCheckSharedVaultMembers(next);
    return TomSecretsSharedVaultKeys._(
      vault: vault,
      keyFile: Uint8List.fromList(keyFile),
      repositoryKey: repositoryKey,
      members: next,
    );
  }

  /// New keys for the same members (part-key-rotation: a shared vault's key
  /// rotated without removing anyone); the vault is to be re-keyed to them.
  TomSecretsSharedVaultKeys rotated() => TomSecretsSharedVaultKeys.generate(
    vault,
    members: members,
    outer: repositoryKey != null,
  );

  /// The id of the key file (`tomSecretsKeyId`), as a rotation record names
  /// it.
  String get keyId => tomSecretsKeyId(keyFile);

  /// The plaintext of the recipients file.
  Map<String, Object?> toJson() => {
    'format': tomSecretsSharedVaultKeysFormat,
    'vault': vault,
    'keyFile': base64.encode(keyFile),
    'repositoryKey': ?repositoryKey,
    'members': [
      for (final m in members)
        {'name': m.name, 'recipient': m.recipient.encoded},
    ],
  };

  /// Zeroes the key file (the repository key is a `String` the caller
  /// drops).
  void dispose() => keyFile.fillRange(0, keyFile.length, 0);

  @override
  String toString() => 'TomSecretsSharedVaultKeys($vault, ***)';
}

/// Checks [members] for a recipients file: at least one, every one with a
/// hybrid key (`age` mixes no classical recipients in), none twice.
void tomSecretsCheckSharedVaultMembers(
  List<TomSecretsSharedVaultMember> members,
) {
  Never bad(String why) => throw TomSecretsSharedVaultException(
    TomSecretsSharedVaultFailure.members,
    why,
  );
  if (members.isEmpty) bad('a shared vault needs at least one member');
  for (final m in members) {
    if (!m.recipient.isHybrid) {
      bad(
        '${m.name} has a classical key: a shared vault takes hybrid keys '
        'only (they make one with age-keygen -pq)',
      );
    }
  }
  final seen = <TomSecretsAgeRecipient>{};
  for (final m in members) {
    if (!seen.add(m.recipient)) bad('${m.name} is a member twice');
  }
}

/// The recipients file of [keys]: its JSON encrypted with `age` to every
/// member's recipient.
Future<Uint8List> tomSecretsWriteRecipientsFile(
  TomSecretsSharedVaultKeys keys,
) async {
  tomSecretsCheckSharedVaultMembers(keys.members);
  final plain = utf8.encode(jsonEncode(keys.toJson()));
  try {
    return await tomSecretsAgeEncrypt(plain, [
      for (final m in keys.members) m.recipient,
    ]);
  } finally {
    plain.fillRange(0, plain.length, 0);
  }
}

/// The keys of the recipients file [file], opened with [memberKey]. Throws
/// [TomSecretsSharedVaultException]: [TomSecretsSharedVaultFailure.notAMember]
/// when the file is not for that key, `malformed` when it holds no keys;
/// [TomSecretsAgeException] for a broken file.
Future<TomSecretsSharedVaultKeys> tomSecretsReadRecipientsFile(
  Uint8List file,
  TomSecretsMemberKey memberKey,
) async {
  final Uint8List plain;
  try {
    plain = await tomSecretsAgeDecrypt(file, [
      TomSecretsAgeHybridIdentity(memberKey),
    ]);
  } on TomSecretsAgeException catch (e) {
    if (e.reason != TomSecretsAgeFailure.noMatch) rethrow;
    throw const TomSecretsSharedVaultException(
      TomSecretsSharedVaultFailure.notAMember,
      'the vault is not shared with your member key',
    );
  }
  try {
    final json = jsonDecode(utf8.decode(plain));
    if (json is! Map<String, Object?>) {
      throw const TomSecretsSharedVaultException(
        TomSecretsSharedVaultFailure.malformed,
        'the recipients file holds no readable keys',
      );
    }
    return TomSecretsSharedVaultKeys.fromJson(json);
  } on FormatException {
    throw const TomSecretsSharedVaultException(
      TomSecretsSharedVaultFailure.malformed,
      'the recipients file holds no readable keys',
    );
  } finally {
    plain.fillRange(0, plain.length, 0);
  }
}

/// The file name of the recipients file beside the vault file [fileName]
/// (`team.kdbx` or `team.kdbx.tsmx` → `team.keys.age`).
String tomSecretsRecipientsFileName(String fileName) =>
    '${fileName.replaceFirst(RegExp(r'\.kdbx(\.tsmx)?$', caseSensitive: false), '')}'
    '$tomSecretsRecipientsSuffix';

/// A new shared vault [name] opened by [keys] (kind `shared`, the product's
/// format, Argon2id [argon2]); write [keys]' recipients file beside it.
KdbxFile tomSecretsNewSharedVault(
  String name,
  TomSecretsSharedVaultKeys keys, {
  String? purpose,
  KdbxArgon2 argon2 = tomSecretsDefaultArgon2,
}) {
  final file = tomSecretsNewVault(keys.credentials, name, argon2: argon2);
  TomSecretsMetadata(
    store: name,
    kind: TomSecretsVaultKind.shared,
    purpose: purpose,
  ).writeTo(file);
  return file;
}
