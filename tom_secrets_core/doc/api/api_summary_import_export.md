# Tom Secrets Core API Reference: Import and Export Module

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Types](#types)
  - [TomSecretsImportKind](#tomsecretsimportkind)
  - [TomSecretsImportField](#tomsecretsimportfield)
  - [TomSecretsImportAttachment](#tomsecretsimportattachment)
  - [TomSecretsImportOldPassword](#tomsecretsimportoldpassword)
  - [TomSecretsImportItem](#tomsecretsimportitem)
  - [TomSecretsImportVault](#tomsecretsimportvault)
  - [TomSecretsImportNotice](#tomsecretsimportnotice)
  - [TomSecretsImportSource](#tomsecretsimportsource)
  - [TomSecretsImportTarget](#tomsecretsimporttarget)
  - [TomSecretsImportOutcome](#tomsecretsimportoutcome)
  - [TomSecretsImportLine](#tomsecretsimportline)
  - [TomSecretsImportAttachmentSize](#tomsecretsimportattachmentsize)
  - [TomSecretsImportReport](#tomsecretsimportreport)
  - [TomSecretsImportFormatException](#tomsecretsimportformatexception)
  - [TomSecretsEnpassExport](#tomsecretsenpassexport)
  - [TomSecretsPasskeyFields](#tomsecretspasskeyfields)
  - [TomSecretsPasskeyException](#tomsecretspasskeyexception)
  - [TomSecretsPasskey](#tomsecretspasskey)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The import and export module reads 1Password (1PUX, CSV) and Enpass (JSON, CSV) exports into one source model and writes it into a vault the same way for every source, with re-import matching, a dry-run preview and a report that names entries but never values; passkeys are kept in KeePassXC's `KPEX_PASSKEY_*` fields; a vault or a group is written back in Enpass's JSON export layout.

Source files: `lib/src/import.dart`, `lib/src/import_1password.dart`, `lib/src/import_enpass.dart`, `lib/src/export_enpass.dart`, `lib/src/passkey.dart`.

---

## Class Hierarchy

```text
Object
├── TomSecretsImportKind (enum)
├── TomSecretsImportField
├── TomSecretsImportAttachment
├── TomSecretsImportOldPassword
├── TomSecretsImportItem
├── TomSecretsImportVault
├── TomSecretsImportNotice
├── TomSecretsImportSource
├── TomSecretsImportTarget
├── TomSecretsImportOutcome (enum)
├── TomSecretsImportLine
├── TomSecretsImportAttachmentSize
├── TomSecretsImportReport
├── TomSecretsImportFormatException
├── TomSecretsEnpassExport
├── TomSecretsPasskeyFields
├── TomSecretsPasskeyException
└── TomSecretsPasskey
```

---

## Types

### TomSecretsImportKind

How an imported item is typed.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `login` | A login (`tsm.type` `login`). |
| `note` | A note (`note`). |
| `apiToken` | An API credential (`api-token`). |
| `sshKey` | An SSH key: kept as a `note` with the key as an attachment in phase A (the `ssh-key` type is phase B's, which retypes it). |
| `other` | Any other category: an entry in the category's subgroup, all its fields as custom fields. |

---

### TomSecretsImportField

A custom field of an imported item.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportField(name, value, {isProtected})` | const | The field `name` with `value`; `isProtected` for a concealed value. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `name` | `String` | Its name. |
| `value` | `String` | Its value. |
| `isProtected` | `bool` | Whether the vault keeps it protected. |

---

### TomSecretsImportAttachment

An attachment of an imported item.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportAttachment(name, bytes)` | const | The file `name` with its `bytes`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `name` | `String` | The file name. |
| `bytes` | `Uint8List` | The content. |

---

### TomSecretsImportOldPassword

One former password with the time it was replaced.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportOldPassword(value, time)` | const | `value`, used until `time`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `value` | `String` | The old password. |
| `time` | `DateTime` | When it was replaced. |

---

### TomSecretsImportItem

One item of an export, as the importers read it.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportItem({sourceId, version, title, kind, category, userName, password, urls, notes, tags, favorite, archived, fields, totp, attachments, passwordHistory, created, updated, expires, folders, trashed, passkey})` | const | An item; `sourceId` identifies it across exports (the source's UUID, or a hash where the format has none) and `version` says which state of it this is (its updated time, or a hash of its values). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `sourceId` | `String` | The item's identity across exports. |
| `version` | `String` | The item's state (updated time or a content hash). |
| `title` | `String` | The title. |
| `kind` | `TomSecretsImportKind` | How it is typed. |
| `category` | `String?` | The category's subgroup name (plural, e.g. `Credit Cards`) for `TomSecretsImportKind.other`, and the category's name otherwise. |
| `userName` | `String?` | The user name. |
| `password` | `String?` | The password (credential). |
| `urls` | `List<String>` | The URLs, the primary one first. |
| `notes` | `String?` | The notes. |
| `tags` | `List<String>` | The tags. |
| `favorite` | `bool` | Whether it is a favourite. |
| `archived` | `bool` | Whether the source has it archived. |
| `fields` | `List<TomSecretsImportField>` | Every other field. |
| `totp` | `String?` | The one-time password: an `otpauth://` URI or a bare base32 secret. |
| `attachments` | `List<TomSecretsImportAttachment>` | The attachments and documents. |
| `passwordHistory` | `List<TomSecretsImportOldPassword>` | The former passwords, any order. |
| `created` | `DateTime?` | When it was created, when known. |
| `updated` | `DateTime?` | When it was last changed in the source, when known. |
| `expires` | `DateTime?` | When it expires, when it does. |
| `folders` | `List<String>` | The folder path inside the target group (the source's nested folders), empty for the target group itself. |
| `trashed` | `bool` | Whether the source has it in its trash: always left out. |
| `passkey` | `TomSecretsPasskey?` | A passkey with its private key, kept in the `KPEX_PASSKEY_*` fields. |

---

### TomSecretsImportVault

One vault of an export.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportVault({id, name, items})` | const | The vault `id` named `name` with its `items`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `id` | `String` | Its identity in the export. |
| `name` | `String` | Its name. |
| `items` | `List<TomSecretsImportItem>` | Its items. |

---

### TomSecretsImportNotice

Something of an export that is not imported, named in the report.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportNotice(what, {title})` | const | `what` of the item `title` (or of the export, without one). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `what` | `String` | What was not imported. |
| `title` | `String?` | The item it belongs to, or null. |

---

### TomSecretsImportSource

An export as read: its vaults, what its format loses, and what of it is not imported.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportSource({source, displayName, format, vaults, lost, notImported})` | const | The export of `source` (`1password`, the import id's name) shown as `displayName`, in `format`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `source` | `String` | The source's name in `tsm.import.<source>.id`. |
| `displayName` | `String` | Its display name, the default target group's first segment. |
| `format` | `String` | The export format (`1pux`, `csv`, ...). |
| `vaults` | `List<TomSecretsImportVault>` | The vaults. |
| `lost` | `List<String>` | What the format loses, for the report. |
| `notImported` | `List<TomSecretsImportNotice>` | What the export holds but is not imported (passkeys, ...). |

---

### TomSecretsImportTarget

Where a source vault goes: `group` (a path of group names) in `file`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportTarget(file, group)` | const | The group path `group` in `file`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `file` | `KdbxFile` | The vault written to. |
| `group` | `List<String>` | The target group's path from the root. |

---

### TomSecretsImportOutcome

What happened to one item.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `added` | New in the vault. |
| `updated` | Changed in the source only: updated, the old values in the history. |
| `unchanged` | Unchanged in the source since the last import: skipped. |
| `conflict` | Changed on both sides: imported as a conflict. |
| `leftOut` | Left out by choice (archived). |
| `notImported` | Not imported (deleted in the vault, a passkey, ...). |
| `notInExport` | In the vault from an earlier import, no longer in the export: kept. |
| `passkeyKept` | A passkey kept in the entry, not yet usable (phase C uses it). |

---

### TomSecretsImportLine

One line of the report: an entry and what happened to it, no values.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportLine(outcome, title, {group, reason})` | const | `outcome` for `title` in the group `group` (null: of the export). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `outcome` | `TomSecretsImportOutcome` | What happened. |
| `title` | `String` | The item's title. |
| `group` | `String?` | The group path it went to, or is in. |
| `reason` | `String?` | Why, when it was not imported or left out. |

---

### TomSecretsImportAttachmentSize

An attachment of the import, by size, for the preview.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportAttachmentSize(title, name, bytes)` | const | `name` of the item `title`, `bytes` long. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `title` | `String` | The item. |
| `name` | `String` | The file name. |
| `bytes` | `int` | Its size. |

---

### TomSecretsImportReport

What an import did (or, as a preview, would do).

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `source` | `String` | The source and format, e.g. `1Password (1pux)`. |
| `dryRun` | `bool` | Whether nothing was written (the preview). |
| `lines` | `List<TomSecretsImportLine>` | One line per item, in export order, then the entries no longer in the export. |
| `lost` | `List<String>` | What the format loses. |
| `largestAttachments` | `List<TomSecretsImportAttachmentSize>` | The largest attachments the import writes, largest first (at most 10). |
| `summary` | `String` | The commit message of an import into a GitHub vault: "Import from 1Password: n added, m updated, k conflicts". |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `count(outcome)` | `int` | How many lines have `outcome`. |
| `withOutcome(outcome)` | `List<TomSecretsImportLine>` | The lines with `outcome`. |

---

### TomSecretsImportFormatException

An export that cannot be read.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsImportFormatException(message)` | — | Unreadable for `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong. |

---

### TomSecretsEnpassExport

An Enpass JSON export and what it left behind.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `json` | `String` | The export's text. |
| `items` | `int` | How many items it holds. |
| `folders` | `int` | How many folders it holds. |
| `lost` | `List<String>` | What the export does not carry, with the entries concerned. |

---

### TomSecretsPasskeyFields

KeePassXC's passkey attributes.

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `relyingParty` | `KdbxKey` | The relying party (the site's domain). |
| `credentialId` | `KdbxKey` | The credential id, base64url without padding. |
| `privateKeyPem` | `KdbxKey` | The private key, PKCS#8 PEM (protected). |
| `userHandle` | `KdbxKey` | The user handle, base64url without padding. |
| `userName` | `KdbxKey` | The account name at the relying party. |

---

### TomSecretsPasskeyException

A passkey's private key that cannot be read.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPasskeyException(message)` | — | Unreadable for `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong. |

---

### TomSecretsPasskey

A passkey with its private key.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPasskey({relyingParty, credentialId, privateKeyPem, userHandle, userName})` | const | A passkey of `relyingParty` for `userName`; `credentialId` and `userHandle` base64url, `privateKeyPem` PKCS#8 PEM. |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fromEntry(entry)` | `TomSecretsPasskey?` | The passkey stored in `entry`, or null. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `relyingParty` | `String` | The relying party. |
| `credentialId` | `String` | The credential id (base64url, no padding). |
| `privateKeyPem` | `String` | The private key (PKCS#8 PEM). |
| `userHandle` | `String?` | The user handle (base64url, no padding), when known. |
| `userName` | `String?` | The account name, when known. |
| `fields` | `Map<KdbxKey, StringValue>` | The fields KeePassXC reads, by name. |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsOnePasswordSource` | `String` | The source name of 1Password imports (`tsm.import.1password.id`). |
| `tomSecretsOnePuxLosses` | `List<String>` | What a 1PUX import loses, named in every report. |
| `tomSecretsOnePasswordCsvLosses` | `List<String>` | What a CSV import loses besides `tomSecretsOnePuxLosses`. |
| `tomSecretsOnePasswordCategories` | `Map<String, (TomSecretsImportKind, String)>` | 1Password's categories by `categoryUuid`: how each is typed, and the subgroup an `other` category goes into. |
| `tomSecretsEnpassSource` | `String` | The source name of Enpass imports (`tsm.import.enpass.id`). |
| `tomSecretsEnpassJsonLosses` | `List<String>` | What an Enpass JSON import loses, named in every report. |
| `tomSecretsEnpassCsvLosses` | `List<String>` | What an Enpass CSV import loses besides `tomSecretsEnpassJsonLosses`. |
| `tomSecretsEnpassCategories` | `Map<String, (TomSecretsImportKind, String)>` | Enpass's categories: how each is typed, and the subgroup another category goes into. |

### Functions

| Function | Signature | Description |
| --- | --- | --- |
| `tomSecretsImportVersionField` | `KdbxKey tomSecretsImportVersionField(String source)` | The import origin's version field (`tsm.import.<source>.updated`). |
| `tomSecretsImportedAtField` | `KdbxKey tomSecretsImportedAtField(String source)` | When the import last wrote the entry (`tsm.import.<source>.imported`): an entry modified later was changed in the vault. |
| `tomSecretsImportCategoryField` | `KdbxKey tomSecretsImportCategoryField(String source)` | The source category field (`tsm.import.<source>.category`). |
| `tomSecretsImportGroupName` | `String tomSecretsImportGroupName(String name)` | `name` as a group name: empty becomes `(no name)`, and a name the product reserves (an `@` overlay group, a `tsm.` or `.tom-secrets` name) has its first character percent-encoded as the product writes it (`%40…`). |
| `tomSecretsImport` | `TomSecretsImportReport tomSecretsImport(TomSecretsImportSource source, {required KdbxFile file, Map<String, TomSecretsImportTarget> targets = const {}, bool includeArchived = false, bool dryRun = false, DateTime? now, void Function(int done, int total)? onProgress})` | Imports `source` into `file`: each source vault into its target (`targets` by vault id, default `<displayName>/<vault name>` in `file`), archived items only with `includeArchived`. |
| `tomSecretsRead1Pux` | `TomSecretsImportSource tomSecretsRead1Pux(Uint8List zip)` | Reads a 1PUX export (`zip`, the file's bytes) in memory. |
| `tomSecretsRead1PasswordCsv` | `TomSecretsImportSource tomSecretsRead1PasswordCsv(String text)` | Reads 1Password's CSV export: one vault `CSV`, one item per row. The header names the columns (any case): `Title`, `Url`/`Website`, `Username`, `Password`, `OTPAuth`/`One-time password`, `Favorite`, `Archived`, `Tags`, `Notes`. |
| `tomSecretsParseCsv` | `List<List<String>> tomSecretsParseCsv(String text)` | The rows of a CSV text (RFC 4180: quoted fields with doubled quotes and line breaks inside, CRLF or LF; a leading byte order mark is dropped). |
| `tomSecretsReadEnpassJson` | `TomSecretsImportSource tomSecretsReadEnpassJson(String json, {String vaultName = 'Vault'})` | Reads an Enpass JSON export of the vault `vaultName`. |
| `tomSecretsReadEnpassCsv` | `TomSecretsImportSource tomSecretsReadEnpassCsv(String text, {String vaultName = 'Vault'})` | Reads an Enpass CSV export of the vault `vaultName`: per row the title, label and value pairs, the note; a header row (`Title`, …, `Note`) is skipped. |
| `tomSecretsExportEnpassJson` | `TomSecretsEnpassExport tomSecretsExportEnpassJson(KdbxFile file, {KdbxGroup? group, DateTime? now})` | Writes `group` (default: the whole vault `file`) as an Enpass JSON export. The recycle bin, the product's groups (`.tom-secrets`, `tsm.grants`) and `tsm.*` fields are left out. |
| `tomSecretsBase64Url` | `String tomSecretsBase64Url(String text)` | `text` (base64, base64url, padded or not) as base64url without padding. |
| `tomSecretsDecodeBase64` | `Uint8List tomSecretsDecodeBase64(String text)` | The bytes of base64 or base64url `text`, padded or not. |
| `tomSecretsPasskeyPem` | `String tomSecretsPasskeyPem(Object key)` | `key` as PKCS#8 PEM: a PEM (PKCS#8 as it is; SEC1 `EC PRIVATE KEY` converted), base64 or base64url DER (PKCS#8 or SEC1), 32 raw bytes or their base64 (a P-256 scalar), or a JWK (a map or its JSON text; `EC` on `P-256`, or `OKP` on `Ed25519`). |
