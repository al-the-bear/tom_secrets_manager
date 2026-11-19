// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The Bitwarden import (part-password-manager): Bitwarden's JSON export,
/// unencrypted or password-protected, read into a [TomSecretsImportSource]
/// that [tomSecretsImport] writes like 1Password's.
///
/// - **Password-protected exports** (`passwordProtected: true`): the key is
///   derived from the export password with the export's KDF (PBKDF2-SHA256,
///   or Argon2id over the SHA-256 of the salt), stretched with HKDF-Expand
///   into an encryption and a MAC key; `data` and the validation string are
///   Bitwarden's type-2 cipher strings (`2.<iv>|<data>|<mac>`: AES-256-CBC,
///   HMAC-SHA256 over IV and data, checked first). A wrong password is
///   refused. The account-restricted export (encrypted with the account's
///   key) cannot be read outside Bitwarden and is refused with that said.
/// - **Folders** (`A/B` names) become nested groups inside the target;
///   an organisation export's collections stand for folders.
/// - **Types** map as 1Password's do: logins, secure notes, cards into
///   `Credit Cards`, identities into `Identities` (their fields as custom
///   fields), SSH keys as typed SSH key entries.
/// - **Identity:** the item id goes into `tsm.import.bitwarden.id`; its
///   `revisionDate` says which state it is.
/// - **Left out:** items in the trash; passkeys (FIDO2 credentials) are
///   named in the report as not imported.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;

import 'import.dart';
import 'import_1password.dart' show TomSecretsImportFormatException;

/// The source name of Bitwarden imports (`tsm.import.bitwarden.id`).
const String tomSecretsBitwardenSource = 'bitwarden';

/// What a Bitwarden JSON import loses, named in every report.
const List<String> tomSecretsBitwardenLosses = [
  'attachments (Bitwarden\'s JSON export does not carry them)',
  'the URI match rules of each login',
  'linked custom fields (their value is the field they link to)',
  'master password re-prompt',
  'collections beyond the first, and organisation permissions',
];

/// The card fields: Bitwarden's key, the custom field's name, protected.
const List<(String, String, bool)> tomSecretsBitwardenCardFields = [
  ('cardholderName', 'Cardholder name', false),
  ('brand', 'Brand', false),
  ('number', 'Number', true),
  ('expMonth', 'Expiration month', false),
  ('expYear', 'Expiration year', false),
  ('code', 'Security code', true),
];

/// The identity fields: Bitwarden's key, the custom field's name,
/// protected.
const List<(String, String, bool)> tomSecretsBitwardenIdentityFields = [
  ('title', 'Title', false),
  ('firstName', 'First name', false),
  ('middleName', 'Middle name', false),
  ('lastName', 'Last name', false),
  ('address1', 'Address 1', false),
  ('address2', 'Address 2', false),
  ('address3', 'Address 3', false),
  ('city', 'City', false),
  ('state', 'State', false),
  ('postalCode', 'Postal code', false),
  ('country', 'Country', false),
  ('company', 'Company', false),
  ('email', 'Email', false),
  ('phone', 'Phone', false),
  ('ssn', 'Social security number', true),
  ('username', 'Username', false),
  ('passportNumber', 'Passport number', true),
  ('licenseNumber', 'License number', true),
];

/// The subgroup of Bitwarden's cards, as 1Password's.
const String tomSecretsCardsCategory = 'Credit Cards';

/// The subgroup of Bitwarden's identities, as 1Password's.
const String tomSecretsIdentitiesCategory = 'Identities';

/// Whether [text] is a password-protected Bitwarden export: it needs the
/// export password ([tomSecretsReadBitwardenJson]'s `password`).
bool tomSecretsBitwardenNeedsPassword(String text) {
  try {
    final json = jsonDecode(text);
    return json is Map &&
        json['encrypted'] == true &&
        json['passwordProtected'] == true;
  } on FormatException {
    return false;
  }
}

/// Reads Bitwarden's JSON export [text]; a password-protected one is opened
/// with [password]. Throws [TomSecretsImportFormatException] when the text
/// is no Bitwarden export, the password is missing or wrong, or the export
/// is account-restricted.
Future<TomSecretsImportSource> tomSecretsReadBitwardenJson(
  String text, {
  String? password,
}) async {
  final Object? decoded;
  try {
    decoded = jsonDecode(text);
  } on FormatException {
    throw TomSecretsImportFormatException('not JSON: not a Bitwarden export');
  }
  if (decoded is! Map) {
    throw TomSecretsImportFormatException('not a Bitwarden export');
  }
  var json = decoded.cast<String, Object?>();
  if (json['encrypted'] == true) {
    if (json['passwordProtected'] != true) {
      throw TomSecretsImportFormatException(
        'an account-restricted Bitwarden export, encrypted with the '
        'account\'s key: only Bitwarden reads it. Export again as "JSON" or '
        '"JSON (Encrypted)" with "Password protected"',
      );
    }
    if (password == null || password.isEmpty) {
      throw TomSecretsImportFormatException(
        'a password-protected export: its password is needed',
      );
    }
    json = await _decrypt(json, password);
  }
  final items = json['items'];
  if (items is! List) {
    throw TomSecretsImportFormatException('no items: not a Bitwarden export');
  }
  final folders = <String, List<String>>{
    for (final f in [
      ...(json['folders'] as List? ?? const []),
      ...(json['collections'] as List? ?? const []),
    ])
      if (f is Map && f['id'] != null)
        '${f['id']}': [
          for (final part in '${f['name'] ?? ''}'.split('/'))
            if (part.trim().isNotEmpty) part.trim(),
        ],
  };
  final read = <TomSecretsImportItem>[];
  final notImported = <TomSecretsImportNotice>[];
  for (final raw in items) {
    if (raw is! Map) continue;
    final item = raw.cast<String, Object?>();
    final title = _string(item['name']) ?? '(untitled)';
    final login = (item['login'] as Map?)?.cast<String, Object?>();
    final passkeys = login?['fido2Credentials'];
    if (passkeys is List && passkeys.isNotEmpty) {
      notImported.add(
        TomSecretsImportNotice(
          'a passkey (Bitwarden\'s passkeys are not imported)',
          title: title,
        ),
      );
    }
    final collections = item['collectionIds'];
    final folder =
        folders[_string(item['folderId'])] ??
        (collections is List && collections.isNotEmpty
            ? folders['${collections.first}']
            : null) ??
        const <String>[];
    read.add(_item(item, title, login, folder));
  }
  return TomSecretsImportSource(
    source: tomSecretsBitwardenSource,
    displayName: 'Bitwarden',
    format: 'json',
    vaults: [
      TomSecretsImportVault(id: 'bitwarden', name: 'Vault', items: read),
    ],
    lost: tomSecretsBitwardenLosses,
    notImported: notImported,
  );
}

TomSecretsImportItem _item(
  Map<String, Object?> item,
  String title,
  Map<String, Object?>? login,
  List<String> folder,
) {
  final fields = <TomSecretsImportField>[];
  for (final raw in item['fields'] as List? ?? const []) {
    if (raw is! Map) continue;
    final type = raw['type'];
    final name = _string(raw['name']) ?? 'field';
    if (type == 3) {
      // A linked field names another field of the item: nothing of its own.
      continue;
    }
    fields.add(
      TomSecretsImportField(
        name,
        _string(raw['value']) ?? '',
        isProtected: type == 1,
      ),
    );
  }
  void section(Object? content, List<(String, String, bool)> layout) {
    if (content is! Map) return;
    for (final (key, label, protected) in layout) {
      final value = _string(content[key]);
      if (value != null) {
        fields.add(TomSecretsImportField(label, value, isProtected: protected));
      }
    }
  }

  final attachments = <TomSecretsImportAttachment>[];
  var kind = TomSecretsImportKind.login;
  String? category;
  switch (item['type']) {
    case 2:
      kind = TomSecretsImportKind.note;
    case 3:
      kind = TomSecretsImportKind.other;
      category = tomSecretsCardsCategory;
      section(item['card'], tomSecretsBitwardenCardFields);
    case 4:
      kind = TomSecretsImportKind.other;
      category = tomSecretsIdentitiesCategory;
      section(item['identity'], tomSecretsBitwardenIdentityFields);
    case 5:
      kind = TomSecretsImportKind.sshKey;
      final key = item['sshKey'];
      if (key is Map) {
        final private = _string(key['privateKey']);
        if (private != null) {
          attachments.add(
            TomSecretsImportAttachment(
              'private_key',
              Uint8List.fromList(utf8.encode(private)),
            ),
          );
        }
        final public = _string(key['publicKey']);
        if (public != null) {
          fields.add(TomSecretsImportField('public key', public));
        }
      }
  }
  final history = <TomSecretsImportOldPassword>[
    for (final h in item['passwordHistory'] as List? ?? const [])
      if (h is Map && _string(h['password']) != null)
        TomSecretsImportOldPassword(
          _string(h['password'])!,
          _date(h['lastUsedDate']) ?? DateTime.utc(1970),
        ),
  ];
  final updated = _date(item['revisionDate']);
  return TomSecretsImportItem(
    sourceId: _string(item['id']) ?? _contentId(item),
    version: _string(item['revisionDate']) ?? _contentId(item),
    title: title,
    kind: kind,
    category: category,
    userName: _string(login?['username']),
    password: _string(login?['password']),
    urls: [
      for (final u in login?['uris'] as List? ?? const [])
        if (u is Map && _string(u['uri']) != null) _string(u['uri'])!,
    ],
    notes: _string(item['notes']),
    favorite: item['favorite'] == true,
    fields: fields,
    totp: _string(login?['totp']),
    attachments: attachments,
    passwordHistory: history,
    created: _date(item['creationDate']),
    updated: updated,
    folders: folder,
    trashed: item['deletedDate'] != null,
  );
}

String? _string(Object? value) {
  if (value == null) return null;
  final text = '$value';
  return text.isEmpty ? null : text;
}

DateTime? _date(Object? value) =>
    value == null ? null : DateTime.tryParse('$value');

String _contentId(Map<String, Object?> item) =>
    'sha256:${crypto.sha256.convert(utf8.encode(jsonEncode(item)))}';

// ── Password-protected exports ────────────────────────────────────────────

Future<Map<String, Object?>> _decrypt(
  Map<String, Object?> json,
  String password,
) async {
  final salt = _string(json['salt']);
  final data = _string(json['data']);
  if (salt == null || data == null) {
    throw TomSecretsImportFormatException(
      'a password-protected export without its salt or data',
    );
  }
  final keys = await tomSecretsBitwardenExportKeys(
    password: password,
    salt: salt,
    kdfType: (json['kdfType'] as num?)?.toInt() ?? 0,
    iterations: (json['kdfIterations'] as num?)?.toInt() ?? 600000,
    memoryMiB: (json['kdfMemory'] as num?)?.toInt(),
    parallelism: (json['kdfParallelism'] as num?)?.toInt(),
  );
  final validation = _string(json['encKeyValidation_DO_NOT_EDIT']);
  if (validation != null) {
    await tomSecretsBitwardenDecrypt(validation, keys);
  }
  final plain = await tomSecretsBitwardenDecrypt(data, keys);
  final Object? inner;
  try {
    inner = jsonDecode(utf8.decode(plain));
  } on FormatException {
    throw TomSecretsImportFormatException('the decrypted data is not JSON');
  }
  if (inner is! Map) {
    throw TomSecretsImportFormatException('the decrypted data is no export');
  }
  return inner.cast<String, Object?>();
}

/// The encryption and MAC keys of a Bitwarden export password.
final class TomSecretsBitwardenKeys {
  /// [encryption] and [mac], 32 bytes each.
  const TomSecretsBitwardenKeys(this.encryption, this.mac);

  /// The AES-256 key.
  final Uint8List encryption;

  /// The HMAC-SHA256 key.
  final Uint8List mac;
}

/// The keys of a password-protected export: the KDF ([kdfType] 0 PBKDF2-
/// SHA256 over the salt's UTF-8 with [iterations]; 1 Argon2id over the
/// SHA-256 of the salt with [iterations], [memoryMiB] and [parallelism]),
/// then HKDF-Expand (SHA-256) with `enc` and `mac`.
Future<TomSecretsBitwardenKeys> tomSecretsBitwardenExportKeys({
  required String password,
  required String salt,
  int kdfType = 0,
  int iterations = 600000,
  int? memoryMiB,
  int? parallelism,
}) async {
  final List<int> master;
  switch (kdfType) {
    case 0:
      final key = await cg.Pbkdf2(
        macAlgorithm: cg.Hmac.sha256(),
        iterations: iterations,
        bits: 256,
      ).deriveKeyFromPassword(password: password, nonce: utf8.encode(salt));
      master = await key.extractBytes();
    case 1:
      final key =
          await cg.Argon2id(
            parallelism: parallelism ?? 4,
            memory: (memoryMiB ?? 64) * 1024,
            iterations: iterations,
            hashLength: 32,
          ).deriveKeyFromPassword(
            password: password,
            nonce: crypto.sha256.convert(utf8.encode(salt)).bytes,
          );
      master = await key.extractBytes();
    default:
      throw TomSecretsImportFormatException('an unknown KDF ($kdfType)');
  }
  return TomSecretsBitwardenKeys(
    _expand(master, 'enc'),
    _expand(master, 'mac'),
  );
}

/// HKDF-Expand (RFC 5869) to 32 bytes: one HMAC-SHA256 block.
Uint8List _expand(List<int> key, String info) => Uint8List.fromList(
  crypto.Hmac(crypto.sha256, key).convert([...utf8.encode(info), 1]).bytes,
);

/// Decrypts a type-2 cipher string (`2.<iv>|<data>|<mac>`, base64 parts)
/// with [keys]; a MAC that does not match (a wrong password) is refused.
Future<Uint8List> tomSecretsBitwardenDecrypt(
  String cipherString,
  TomSecretsBitwardenKeys keys,
) async {
  final dot = cipherString.indexOf('.');
  final parts = cipherString.substring(dot + 1).split('|');
  if (dot < 0 || cipherString.substring(0, dot) != '2' || parts.length != 3) {
    throw TomSecretsImportFormatException(
      'an encrypted value of an unknown kind',
    );
  }
  final Uint8List iv, data, mac;
  try {
    iv = base64.decode(parts[0]);
    data = base64.decode(parts[1]);
    mac = base64.decode(parts[2]);
  } on FormatException {
    throw TomSecretsImportFormatException('an encrypted value is not base64');
  }
  final expected = crypto.Hmac(
    crypto.sha256,
    keys.mac,
  ).convert([...iv, ...data]).bytes;
  var same = expected.length == mac.length;
  for (var i = 0; i < expected.length && i < mac.length; i++) {
    same &= expected[i] == mac[i];
  }
  if (!same) {
    throw TomSecretsImportFormatException(
      'the export password is wrong (the data does not authenticate)',
    );
  }
  final plain = await cg.AesCbc.with256bits(macAlgorithm: cg.MacAlgorithm.empty)
      .decrypt(
        cg.SecretBox(data, nonce: iv, mac: cg.Mac.empty),
        secretKey: cg.SecretKey(keys.encryption),
      );
  return Uint8List.fromList(plain);
}
