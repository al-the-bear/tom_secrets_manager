# Tom Secrets Core API Reference: Vaults and Resolution Module

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Types](#types)
  - [TomSecretsConfigException](#tomsecretsconfigexception)
  - [TomSecretsDimension](#tomsecretsdimension)
  - [TomSecretsStoreLocation](#tomsecretsstorelocation)
  - [TomSecretsLocalLocation](#tomsecretslocallocation)
  - [TomSecretsGitHubLocation](#tomsecretsgithublocation)
  - [TomSecretsStoreSpec](#tomsecretsstorespec)
  - [TomSecretsConfig](#tomsecretsconfig)
  - [TomSecretsLocatorException](#tomsecretslocatorexception)
  - [TomSecretsVaultLocator](#tomsecretsvaultlocator)
  - [TomSecretsFileLocator](#tomsecretsfilelocator)
  - [TomSecretsGitHubLocator](#tomsecretsgithublocator)
  - [TomSecretsGitLocator](#tomsecretsgitlocator)
  - [TomSecretsMetadataFields](#tomsecretsmetadatafields)
  - [TomSecretsVaultKind](#tomsecretsvaultkind)
  - [TomSecretsMetadataException](#tomsecretsmetadataexception)
  - [TomSecretsMetadata](#tomsecretsmetadata)
  - [TomSecretsEntryFields](#tomsecretsentryfields)
  - [TomSecretsEntryType](#tomsecretsentrytype)
  - [TomSecretsFieldValue](#tomsecretsfieldvalue)
  - [TomSecretsIndexedEntry](#tomsecretsindexedentry)
  - [TomSecretsStore](#tomsecretsstore)
  - [TomSecretsResolveException](#tomsecretsresolveexception)
  - [TomSecretsMachine](#tomsecretsmachine)
  - [TomSecretsRankedCandidate](#tomsecretsrankedcandidate)
  - [TomSecretsResolution](#tomsecretsresolution)
  - [TomSecretsExplainedCandidate](#tomsecretsexplainedcandidate)
  - [TomSecretsExplainOutcome](#tomsecretsexplainoutcome)
  - [TomSecretsExplanation](#tomsecretsexplanation)
  - [TomSecretsResolver](#tomsecretsresolver)
  - [TomSecretsTotpFields](#tomsecretstotpfields)
  - [TomSecretsTotpAlgorithm](#tomsecretstotpalgorithm)
  - [TomSecretsTotp](#tomsecretstotp)
  - [TomSecretsUrlMatchRule](#tomsecretsurlmatchrule)
  - [TomSecretsUrlMatchLevel](#tomsecretsurlmatchlevel)
  - [TomSecretsSiteUrl](#tomsecretssiteurl)
  - [TomSecretsLoginMatch](#tomsecretsloginmatch)
  - [TomSecretsSshKeyFormat](#tomsecretssshkeyformat)
  - [TomSecretsSshKeyInfo](#tomsecretssshkeyinfo)
  - [TomSecretsSshKeyAlgorithm](#tomsecretssshkeyalgorithm)
  - [TomSecretsGeneratedSshKey](#tomsecretsgeneratedsshkey)
  - [TomSecretsKeeAgentSettings](#tomsecretskeeagentsettings)
  - [TomSecretsSshAgentServing](#tomsecretssshagentserving)
  - [TomSecretsSshPrivateKey](#tomsecretssshprivatekey)
  - [TomSecretsSshKeyException](#tomsecretssshkeyexception)
  - [TomSecretsSshAgentConnection](#tomsecretssshagentconnection)
  - [TomSecretsSshAgentMessage](#tomsecretssshagentmessage)
  - [TomSecretsSshGrantSecret](#tomsecretssshgrantsecret)
  - [TomSecretsCharacterClass](#tomsecretscharacterclass)
  - [TomSecretsPasswordPolicy](#tomsecretspasswordpolicy)
  - [TomSecretsPasswordGenerator](#tomsecretspasswordgenerator)
  - [TomSecretsVaultFields](#tomsecretsvaultfields)
  - [TomSecretsVaultKeys](#tomsecretsvaultkeys)
  - [TomSecretsPrimaryVaults](#tomsecretsprimaryvaults)
  - [TomSecretsPrimaryNextKeys](#tomsecretsprimarynextkeys)
  - [TomSecretsAutoTypeKey](#tomsecretsautotypekey)
  - [TomSecretsAutoTypeModifier](#tomsecretsautotypemodifier)
  - [TomSecretsAutoTypeAction](#tomsecretsautotypeaction)
  - [TomSecretsAutoTypeText](#tomsecretsautotypetext)
  - [TomSecretsAutoTypeKeyPress](#tomsecretsautotypekeypress)
  - [TomSecretsAutoTypeDelay](#tomsecretsautotypedelay)
  - [TomSecretsAutoTypeKeyDelay](#tomsecretsautotypekeydelay)
  - [TomSecretsAutoTypeException](#tomsecretsautotypeexception)
  - [TomSecretsAutoTypeCandidate](#tomsecretsautotypecandidate)
  - [TomSecretsHealthIssue](#tomsecretshealthissue)
  - [TomSecretsHealthPolicy](#tomsecretshealthpolicy)
  - [TomSecretsPasswordStrength](#tomsecretspasswordstrength)
  - [TomSecretsKeyStrength](#tomsecretskeystrength)
  - [TomSecretsHealthEntry](#tomsecretshealthentry)
  - [TomSecretsHealthFinding](#tomsecretshealthfinding)
  - [TomSecretsHealthReport](#tomsecretshealthreport)
  - [TomSecretsBreachCheck](#tomsecretsbreachcheck)
  - [TomSecretsBreachCheckException](#tomsecretsbreachcheckexception)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The vaults and resolution module covers what a vault is to the product and how a secret reference resolves: the shared configuration `tsm.config` with its dimensions and stores, vault locators (`file:`, `github:`, `git:`), the metadata entry `.tom-secrets`, the product's conventions on standard KDBX fields (flat key, entry type, attachments, passkey fields), new vaults keyed through Argon2id, stores indexed with their overlays, the resolver with its rank vectors and its explanation, TOTP codes in the three KDBX conventions, the password generator, the health report with its breach check, auto-type's sequences and window matching, and the primary vault's list of further vaults.

Source files: `lib/src/config.dart`, `lib/src/locator.dart`, `lib/src/metadata.dart`, `lib/src/mapping.dart`, `lib/src/new_vault.dart`, `lib/src/store.dart`, `lib/src/resolution.dart`, `lib/src/totp.dart`, `lib/src/password_generator.dart`, `lib/src/primary.dart`, `lib/src/url_match.dart`, `lib/src/ssh_key.dart`, `lib/src/ssh_private_key.dart`, `lib/src/ssh_agent.dart`, `lib/src/bcrypt_pbkdf.dart`, `lib/src/health.dart`, `lib/src/auto_type.dart`.

---

## Class Hierarchy

```text
Object
├── TomSecretsConfigException
├── TomSecretsDimension
├── TomSecretsStoreLocation
│   ├── TomSecretsLocalLocation
│   ├── TomSecretsGitHubLocation
├── TomSecretsStoreSpec
├── TomSecretsConfig
├── TomSecretsLocatorException
├── TomSecretsVaultLocator
│   ├── TomSecretsFileLocator
│   ├── TomSecretsGitHubLocator
│   ├── TomSecretsGitLocator
├── TomSecretsMetadataFields
├── TomSecretsVaultKind (enum)
├── TomSecretsMetadataException
├── TomSecretsMetadata
├── TomSecretsEntryFields
├── TomSecretsEntryType (enum)
├── TomSecretsFieldValue
├── TomSecretsIndexedEntry
├── TomSecretsStore
├── TomSecretsResolveException
├── TomSecretsMachine
├── TomSecretsRankedCandidate
├── TomSecretsResolution
├── TomSecretsExplainedCandidate
├── TomSecretsExplainOutcome (enum)
├── TomSecretsExplanation
├── TomSecretsResolver
├── TomSecretsTotpFields
├── TomSecretsTotpAlgorithm (enum)
├── TomSecretsTotp
├── TomSecretsCharacterClass (enum)
├── TomSecretsPasswordPolicy
├── TomSecretsPasswordGenerator
├── TomSecretsVaultFields
├── TomSecretsVaultKeys
├── TomSecretsPrimaryVaults
├── TomSecretsPrimaryNextKeys
├── TomSecretsHealthIssue (enum)
├── TomSecretsHealthPolicy
├── TomSecretsPasswordStrength
├── TomSecretsKeyStrength
├── TomSecretsHealthEntry
├── TomSecretsHealthFinding
├── TomSecretsHealthReport
├── TomSecretsBreachCheck
├── TomSecretsBreachCheckException
├── TomSecretsAutoTypeKey (enum)
├── TomSecretsAutoTypeModifier (enum)
├── TomSecretsAutoTypeAction
│   ├── TomSecretsAutoTypeText
│   ├── TomSecretsAutoTypeKeyPress
│   ├── TomSecretsAutoTypeDelay
│   └── TomSecretsAutoTypeKeyDelay
├── TomSecretsAutoTypeException
└── TomSecretsAutoTypeCandidate
```

---

## Types

### TomSecretsConfigException

A configuration that cannot be read.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsConfigException(message)` | — | A configuration problem described by `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong. |

---

### TomSecretsDimension

One dimension of the configuration.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsDimension(name, {defaultValue, fallbackToDefault})` | const | A dimension `name`, with an optional configured `defaultValue` and the `fallbackToDefault` switch (off unless set). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `name` | `String` | The dimension's name. |
| `defaultValue` | `String?` | The configured default, used on a machine that sets no value; null when there is none. |
| `fallbackToDefault` | `bool` | Whether an entry bound `<name>:default` also serves a request naming another value, ranked below an entry bound to that value. |
| `isBuiltIn` | `bool` | Whether this is `host`, `platform` or `env`. |

---

### TomSecretsStoreLocation

Where a store's file is kept.

**Kind:** `sealed class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsStoreLocation()` | const | Creates the base of the subtypes. |

---

### TomSecretsLocalLocation

A file on the local disk.

**Kind:** `final class` · **Extends:** `TomSecretsStoreLocation`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLocalLocation(path)` | const | The file at `path`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `path` | `String` | The file's path. |

---

### TomSecretsGitHubLocation

A file in a GitHub repository.

**Kind:** `final class` · **Extends:** `TomSecretsStoreLocation`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsGitHubLocation(repository, path)` | const | The file `path` in `repository` (`owner/name`). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `repository` | `String` | `owner/name`. |
| `path` | `String` | The file's path in the repository. |

---

### TomSecretsStoreSpec

One store of an environment: its name and where its file is.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsStoreSpec(name, location)` | const | The store `name` at `location`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `name` | `String` | The store name. |
| `location` | `TomSecretsStoreLocation` | Where its file is. |

---

### TomSecretsConfig

The shared configuration. `dimensions` lists the dimensions in priority order. The built-in dimensions the list leaves out come first, in the default order `host`, `platform`, `env`, then the listed ones: a list that only sets `env`'s default or fallback keeps the default order, and a declared `region` ranks below the built-ins. Without a list the order is `host`, `platform`, `env`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsConfig({dimensions, stores})` | — | A configuration of `dimensions` (priority order) and `stores` (by environment). |
| `TomSecretsConfig.builtIn()` | factory | The configuration of a vault without `tsm.config`: the built-ins in their default order, no defaults, no fallback, no stores. |
| `TomSecretsConfig.parse(yaml)` | factory | Reads the YAML of `tsm.config`: |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `dimensions` | `List<TomSecretsDimension>` | The dimensions in priority order (built-ins included). |
| `stores` | `Map<String, List<TomSecretsStoreSpec>>` | The stores of each environment. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `dimension(name)` | `TomSecretsDimension?` | The dimension `name`, or null when it is not declared. |
| `toYaml()` | `String` | This configuration as `tsm.config` YAML (what `TomSecretsConfig.parse` reads back). |

---

### TomSecretsLocatorException

A locator that cannot be read.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLocatorException(message)` | — | A locator problem described by `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong. |

---

### TomSecretsVaultLocator

Where a vault is.

**Kind:** `sealed class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsVaultLocator()` | const | Creates the base of the subtypes. |
| `TomSecretsVaultLocator.parse(text)` | factory | Reads `text`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `text` | `String` | The locator as written. |
| `fileName` | `String` | The vault file's name (`fleet.kdbx`). |
| `vaultIdentity` | `String` | The vault's identity: the locator without a branch, so a key kept for the vault holds whichever branch is read. |
| `repositoryIdentity` | `String` | The identity of the repository the vault is in: its GitHub repository, or for a `file:` vault its folder. The outer layer's repository key belongs to it. |
| `keyFileHandle` | `String` | The device keychain's handle of the vault's key file. |
| `repositoryKeyHandle` | `String` | The device keychain's handle of the repository key of the vault's repository. |

---

### TomSecretsFileLocator

A KDBX file on this device.

**Kind:** `final class` · **Extends:** `TomSecretsVaultLocator`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsFileLocator(path)` | const | The file at `path`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `path` | `String` | The absolute path. |
| `text` | `String` | The locator as written. |
| `fileName` | `String` | The vault file's name (`fleet.kdbx`). |
| `repositoryIdentity` | `String` | The identity of the repository the vault is in: its GitHub repository, or for a `file:` vault its folder. The outer layer's repository key belongs to it. |

---

### TomSecretsGitHubLocator

A KDBX file in a private GitHub repository, read and written through the REST API.

**Kind:** `final class` · **Extends:** `TomSecretsVaultLocator`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsGitHubLocator({owner, repository, path, branch})` | const | The file `path` in `owner`/`repository` on `branch` (null: the default branch). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `owner` | `String` | The repository's owner. |
| `repository` | `String` | The repository's name. |
| `branch` | `String?` | The branch, or null for the default branch. |
| `path` | `String` | The file's path in the repository. |
| `text` | `String` | The locator as written. |
| `fileName` | `String` | The vault file's name (`fleet.kdbx`). |
| `vaultIdentity` | `String` | The vault's identity: the locator without a branch, so a key kept for the vault holds whichever branch is read. |
| `repositoryIdentity` | `String` | The identity of the repository the vault is in: its GitHub repository, or for a `file:` vault its folder. The outer layer's repository key belongs to it. |
| `repositorySlug` | `String` | `owner/repository`. |
| `tokenHandle` | `String` | The handle of the repository's GitHub token in the device keychain (`TomSecretStore`): one token per repository. |
| `tokenExpiryHandle` | `String` | The keychain handle of the expiry recorded with that token. |

---

### TomSecretsGitLocator

A KDBX file on another git server over smart HTTP; recognised, not advertised in phase A.

**Kind:** `final class` · **Extends:** `TomSecretsVaultLocator`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsGitLocator(text)` | const | The locator `text`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `text` | `String` | The locator as written. |
| `fileName` | `String` | The vault file's name (`fleet.kdbx`). |
| `repositoryIdentity` | `String` | The identity of the repository the vault is in: its GitHub repository, or for a `file:` vault its folder. The outer layer's repository key belongs to it. |

---

### TomSecretsMetadataFields

The field names of the metadata entry.

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `format` | `KdbxKey` | The metadata format. |
| `store` | `KdbxKey` | The suggested store name. |
| `kind` | `KdbxKey` | `personal`, `shared` or `system`. |
| `purpose` | `KdbxKey` | Free text shown in the app. |
| `dimensions` | `KdbxKey` | The file binding, `env=prod;region=eu`. |
| `config` | `KdbxKey` | The shared configuration (primary vault only). |
| `keysDue` | `KdbxKey` | When this vault's own key file and repository key are due for rotation (ISO 8601). Read for the primary; a further vault's date is the Expires of its entry in the primary. |
| `sshConfirm` | `KdbxKey` | `tsm.ssh-confirm`: `true` when every ssh-agent signature with a key of this vault is confirmed. |
| `githubAppClientId` | `KdbxKey` | `tsm.github-app-client-id`: the client id of the user's GitHub App (primary only); every device signs in with it. |

---

### TomSecretsVaultKind

What a vault is for.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `personal` | A person's own secrets (the default). |
| `shared` | Shared between people. |
| `system` | System secrets for processes. |

---

### TomSecretsMetadataException

Metadata that cannot be read.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsMetadataException(message)` | — | A metadata problem described by `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong. |

---

### TomSecretsMetadata

The content of a metadata entry.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsMetadata({format, store, kind, purpose, binding, configYaml, keysDue, sshConfirm = false, githubAppClientId})` | — | Metadata with these members. |
| `TomSecretsMetadata.absent()` | factory | The metadata of a file without a metadata entry: no binding, kind `personal`, the store name from the file name. |
| `TomSecretsMetadata.read(file)` | factory | The metadata entry of `file` (`.tom-secrets` in the root group), or `TomSecretsMetadata.absent` when it has none. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `format` | `int` | The metadata format. |
| `store` | `String?` | The suggested store name, or null. |
| `kind` | `TomSecretsVaultKind` | What the vault is for. |
| `purpose` | `String?` | Free text, or null. |
| `binding` | `Map<String, String>` | The file binding: every entry of the file carries these bindings. |
| `configYaml` | `String?` | `tsm.config` as written, or null (only the primary vault has one). |
| `keysDue` | `DateTime?` | When the vault's own key file and repository key are due for rotation (`tsm.keys-due`), or null. The primary's is reminded of; a further vault's date is the Expires of its entry in the primary. |
| `sshConfirm` | `bool` | Whether the ssh-agent confirms every signature with a key of this vault (`tsm.ssh-confirm`). |
| `githubAppClientId` | `String?` | The client id of the user's GitHub App (`tsm.github-app-client-id`), or null. |
| `config` | `TomSecretsConfig?` | The shared configuration of `tsm.config`, or null when absent. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `writeTo(file)` | `void` | Writes this metadata into `file`'s metadata entry, creating it when the file has none. |
| `copyWith({store, kind, purpose, binding, configYaml, keysDue, sshConfirm, githubAppClientId, clearGithubAppClientId})` | `TomSecretsMetadata` | This metadata with the members given replaced. |

---

### TomSecretsEntryFields

The field names the product reserves (`tsm.` prefix) and the foreign conventions it reads.

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `key` | `KdbxKey` | The flat key, a dotted name (`telegram.bot_token`). |
| `type` | `KdbxKey` | The entry type. |
| `reservedPrefix` | `String` | The prefix of the product's reserved names. |
| `importPrefix` | `String` | The prefix of an import origin, `tsm.import.<source>.id`. |
| `passkeyPrefix` | `String` | The passkey fields KeePassXC writes; never served on the client endpoint. |
| `extraUrlPrefix` | `String` | The extra URL fields for autofill. |
| `urlMatch` | `KdbxKey` | How the entry's URLs match a web page: `domain` (the default), `host`, `exact` or `never`. |
| `totp` | `String` | The virtual field: the current TOTP code. |
| `attachmentPrefix` | `String` | The prefix of an attachment field, `attachment:<name>`. |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `importId(source)` | `KdbxKey` | The import origin field of `source` (`tsm.import.1password.id`). |

---

### TomSecretsEntryType

What kind of secret an entry holds (`tsm.type`).

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `login` | A login (the default). |
| `apiToken` | An API token in `Password`, with Expires and the service in `URL`. |
| `note` | A note. |
| `sshKey` | An SSH key (phase B). |
| `certificate` | A certificate (phase C). |
| `pgpKey` | A PGP key (phase C). |
| `memberKey` | `member-key`: the user's member key, a hybrid `age` identity, in the primary vault's `tsm.sharing` group (phase C). |
| `member` | `member`: another person's public `age` key in the directory of members (phase C). |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `of(value)` | `TomSecretsEntryType` | The type of a `tsm.type` value; absent or unknown is `login`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `wireName` | `String` | The value of `tsm.type`. |

---

### TomSecretsFieldValue

The value of one field of an entry: text (a string field, the TOTP code) or bytes (an attachment), held as a `TomProtectedValue` (masked, read through `withBytes`). `dispose` zeroes it.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsFieldValue.text(text, {isProtected})` | — | A text value. The `String` handed in is the caller's to drop. |
| `TomSecretsFieldValue.utf8Bytes(bytes, {isProtected})` | — | A text value from its UTF-8 `bytes`, which are consumed (zeroed). |
| `TomSecretsFieldValue.bytes(bytes, {isProtected})` | — | A binary value; `bytes` are consumed (zeroed): pass a copy of bytes that must stay. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `isText` | `bool` | Whether the value is text (sent as `utf8`); otherwise bytes (`base64`). |
| `isProtected` | `bool` | Whether the file keeps it protected (in-memory protection). |
| `length` | `int` | The number of bytes (a text's UTF-8). |
| `bytes` | `Uint8List` | A copy of the value's bytes (a text's UTF-8); the caller zeroes it. |
| `text` | `String` | The text of a text value, as a `String` that cannot be wiped: prefer `withBytes` where bytes do. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `withBytes<T>(use)` | `T` | Calls `use` with the value's bytes (a text's UTF-8) and zeroes them when it returns: the way to read a value without leaving a copy behind. |
| `dispose()` | `void` | Zeroes the value; reading it afterwards throws a `StateError`. |

---

### TomSecretsIndexedEntry

One entry of a store as resolution sees it.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `store` | `String` | The store's name. |
| `entry` | `KdbxEntry` | The KDBX entry. |
| `path` | `List<String>` | The logical path: the groups below the root group without the overlay groups, then the title. |
| `bindings` | `Map<String, String>` | Every binding the entry carries: the file binding and its overlays. |
| `overlayBindings` | `Map<String, String>` | The bindings of its overlay groups alone. |
| `key` | `String?` | Its flat key (`tsm.key`), or null. |
| `isOverlay` | `bool` | Whether it sits in overlay groups. |
| `uuid` | `String` | The entry's UUID as 32 lower-case hex digits. |
| `pathText` | `String` | The logical path as one text, segments joined with `/` (unescaped). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `hasPath(other)` | `bool` | Whether this entry's logical path is `other`. |

---

### TomSecretsStore

A store: a KDBX file under its store name, with its metadata and index.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsStore.fromFile(file, {name, fileName})` | factory | The store `file` under `name` (the machine's configuration), else its metadata's `tsm.store`, else `fileName` without `.kdbx` (and without the outer layer's `.kdbx.tsmx`). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `name` | `String` | The store name. |
| `file` | `KdbxFile` | The open file. |
| `metadata` | `TomSecretsMetadata` | Its metadata entry. |
| `entries` | `List<TomSecretsIndexedEntry>` | Every entry resolution may reach (not the recycle bin, the metadata entry, the grants group, nor an invalid overlay). |
| `warnings` | `List<String>` | What the index skipped and why, for the service's log. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `reindex()` | `void` | Builds the index again (after the file changed). |

---

### TomSecretsResolveException

A reference that does not resolve: `not_found`, `ambiguous`, `malformed` or `denied`, with the protocol's `details` (never a value).

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsResolveException(kind, message, {details})` | — | A failure of `kind` with `message` and `details`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `kind` | `TomSecretsErrorKind` | The protocol's error kind. |
| `message` | `String` | For people. |
| `details` | `Map<String, Object?>` | `reason`, `dimensions`, `candidates`, `entry`, `field`. |
| `reason` | `String?` | `details['reason']`, when there is one. |

---

### TomSecretsMachine

The machine a request is resolved for: its current value per dimension.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsMachine({host, platform, values})` | const | A machine `host` on `platform` with the `values` of `env` and the other declared dimensions (unset ones absent). |
| `TomSecretsMachine.current({host, values})` | factory | This machine: its short host name in lower case (unless `host` overrides it), its OS as `platform`, and `values`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `host` | `String` | The `host` dimension's value. |
| `platform` | `String` | The `platform` dimension's value. |
| `values` | `Map<String, String>` | The values of `env` and the declared dimensions. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `valueOf(dimension)` | `String?` | The machine's value of `dimension`, or null when unset. |

---

### TomSecretsRankedCandidate

One kept candidate with its rank vector (one rank per dimension, in priority order: 2 bound to the request's value, 1 bound to `default` and kept by the fallback, 0 unbound).

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `entry` | `TomSecretsIndexedEntry` | The candidate. |
| `vector` | `List<int>` | Its ranks, in priority order. |

---

### TomSecretsResolution

A resolved reference: the winning entry and the field's value.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `entry` | `TomSecretsIndexedEntry` | The winner. |
| `field` | `String` | The field read. |
| `value` | `TomSecretsFieldValue` | The field's value. |
| `requestValues` | `Map<String, String>` | The request's value per dimension. |
| `ranked` | `List<TomSecretsRankedCandidate>` | Every kept candidate, best first. |
| `bound` | `Map<String, String>` | The winner's bindings (`value.bound`). |
| `modified` | `DateTime?` | When the winner last changed. |
| `expires` | `DateTime?` | When the winner expires, when its Expires flag is set. |
| `type` | `TomSecretsEntryType` | The winner's type. |

---

### TomSecretsExplainedCandidate

One candidate of an explained request (step 1) and what step 2 did with it: kept with its rank vector, or dropped by one of its bindings.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `entry` | `TomSecretsIndexedEntry` | The candidate. |
| `vector` | `List<int>?` | Its ranks in priority order (2 bound to the request's value, 1 bound to `default` and kept by the fallback, 0 unbound), or null when it was dropped. |
| `dropDimension` | `String?` | The dimension whose binding dropped it, or null when kept. |
| `dropBound` | `String?` | The value it is bound to on `dropDimension`, or null when kept. |
| `kept` | `bool` | Whether it was kept. |

---

### TomSecretsExplainOutcome

How an explained request ends (step 3).

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `resolved` | One candidate ranks best: it serves the request. |
| `ambiguous` | Several candidates rank equal: the request is refused. |
| `notFound` | No candidate is kept: the request finds nothing. |

---

### TomSecretsExplanation

A request explained step by step (`TomSecretsResolver.explain`): the request's values, every candidate kept (best first) or dropped (in the order found), and the outcome with its winner or the tied candidates.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `requestValues` | `Map<String, String>` | The request's value per dimension, in priority order. |
| `candidates` | `List<TomSecretsExplainedCandidate>` | Every candidate: the kept ones best first, then the dropped ones. |
| `outcome` | `TomSecretsExplainOutcome` | How the request ends. |
| `kept` | `List<TomSecretsExplainedCandidate>` | The kept candidates, best first. |
| `dropped` | `List<TomSecretsExplainedCandidate>` | The dropped candidates. |
| `winner` | `TomSecretsIndexedEntry?` | The winner when `outcome` is resolved, else null. |
| `tied` | `List<TomSecretsIndexedEntry>` | The candidates ranking equal best when `outcome` is ambiguous. |

---

### TomSecretsResolver

Resolves references over `stores` under `config` for `machine`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsResolver({stores, config, machine})` | — | A resolver. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `stores` | `List<TomSecretsStore>` | The stores served. |
| `config` | `TomSecretsConfig` | The shared configuration. |
| `machine` | `TomSecretsMachine` | The machine. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `resolve(reference, {dimensions, field, now})` | `TomSecretsResolution` | Resolves `reference` with the call's `dimensions` and `field` (the field when the reference names none); `now` is the time of a `totp` code. |
| `explain(reference, {dimensions})` | `TomSecretsExplanation` | Explains `reference` with the call's `dimensions` the way `resolve` ranks it, without reading a field: the request's values, every candidate (step 1) kept with its rank vector or dropped by the binding that drops it (step 2), and the outcome (step 3). |
| `requestValues(parsed, call)` | `Map<String, String>` | The request's value of every declared dimension: a binding in the brackets, else one passed beside the reference (`call`), else the machine's value, else the configured default, else `default`. |

---

### TomSecretsTotpFields

The TOTP field names.

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `otp` | `KdbxKey` | KeePassXC's `otpauth://` URI. |
| `otpAuth` | `KdbxKey` | AuthPass's `otpauth://` URI. |
| `secretBase32` | `KdbxKey` | KeePass's base32 secret. |
| `length` | `KdbxKey` | KeePass's code length. |
| `period` | `KdbxKey` | KeePass's period in seconds. |
| `algorithm` | `KdbxKey` | KeePass's algorithm: `HMAC-SHA-1`, `HMAC-SHA-256`, `HMAC-SHA-512`. |

---

### TomSecretsTotpAlgorithm

The hash a TOTP code is made with.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `sha1` | HMAC-SHA-1 (the default). |
| `sha256` | HMAC-SHA-256. |
| `sha512` | HMAC-SHA-512. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `uriName` | `String` | The name in an `otpauth://` URI. |
| `keepassName` | `String` | The name in `TimeOtp-Algorithm`. |

---

### TomSecretsTotp

A TOTP secret with its parameters.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsTotp(secret, {digits, period, algorithm, issuer, account})` | — | A TOTP of `secret` (raw bytes). |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fromEntry(entry)` | `TomSecretsTotp?` | The TOTP of `entry`, read in the order `otp`, `OTPAuth`, `TimeOtp-*`; null when it has none that reads. |
| `tryParseUri(text)` | `TomSecretsTotp?` | The TOTP of an `otpauth://totp/...` URI, or null. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `secret` | `Uint8List` | The secret's bytes. |
| `digits` | `int` | The code length. |
| `period` | `int` | The period in seconds. |
| `algorithm` | `TomSecretsTotpAlgorithm` | The hash. |
| `issuer` | `String?` | The issuer and the account label (from the URI), or null. |
| `account` | `String?` | The account label, or null. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `code(time)` | `String` | The code at `time` (RFC 6238). |
| `toUri()` | `String` | The `otpauth://` URI of this TOTP. |
| `writeTo(entry)` | `void` | Writes the three conventions together, so KeePassXC, KeePass, AuthPass and the product show the same code. The secret is protected. |

---

### TomSecretsUrlMatchRule

How an entry's URLs match a page: the entry field `tsm.urlMatch` (part-browser).

| Value | Meaning |
| --- | --- |
| `domain` | The registrable domain (the default, also for an unknown value) |
| `host` | The exact host, any path |
| `exact` | Scheme, host, port and a path prefix |
| `never` | Never offered |

| Static Method | Return Type | Description |
| --- | --- | --- |
| `of(String? value)` | `TomSecretsUrlMatchRule` | The rule a `tsm.urlMatch` value names; absent or unknown is `domain` |

---

### TomSecretsUrlMatchLevel

How closely an entry matches: `exactHost` before `domain`.

---

### TomSecretsSiteUrl

A web URL as matching reads it: `http` or `https`, the host lower-case with non-ASCII labels as punycode, the port (null when the scheme's default) and the path (`/` at least); a text without a scheme is read as `https`.

| Member | Type | Description |
| --- | --- | --- |
| `parse(String text)` (static) | `TomSecretsSiteUrl?` | The URL normalised, or null when it is not a web URL (`androidapp://`, `mailto:`, no host) |
| `scheme`, `host`, `port`, `path` | `String`, `String`, `int?`, `String` | The parts |
| `isAddressOrLocalhost` | `bool` | An IP address or `localhost`: matches by host and port exactly |
| `registrableDomain` | `String?` | The registrable domain after the Public Suffix List, or null |

---

### TomSecretsLoginMatch

A login entry matching a page: `entry` (`TomSecretsIndexedEntry`), `matchedUrl` (the entry URL that matched, as written), `level`, and `title`, `userName`, `hasTotp`, `lastUsed` (its last access, else its last change).

---

### TomSecretsSshKeyFormat

How a private key file is written: `openssh` (`openssh-key-v1`), `pkcs1` (`RSA PRIVATE KEY`), `sec1` (`EC PRIVATE KEY`), `pkcs8`, `pkcs8Encrypted`, `dsa`.

---

### TomSecretsSshKeyInfo

What a private key file says about its key, read without its passphrase.

| Member | Type | Description |
| --- | --- | --- |
| `parse(List<int> bytes)` (static) | `TomSecretsSshKeyInfo?` | The key in a private key file, or null when it holds none |
| `format` | `TomSecretsSshKeyFormat` | How the file is written |
| `encrypted` | `bool` | Whether the key is encrypted under a passphrase (the entry's `Password`) |
| `keyType` | `String?` | `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, ...; null when the file does not say it without its passphrase |
| `publicKeyBlob` | `Uint8List?` | The public key in SSH's wire form: from an OpenSSH file (encrypted or not), an unencrypted PKCS#1, SEC1 or PKCS#8 RSA/ECDSA key; null otherwise |
| `bits` | `int?` | RSA's modulus size, the curve's size, 256 for Ed25519 |
| `comment` | `String?` | The key's comment, when the file carries it unencrypted |
| `publicKey` | `String?` | The public key as `authorized_keys` writes it |
| `fingerprint` | `String?` | `SHA256:<base64>`, as `ssh-keygen -l` prints it |

---

### TomSecretsSshKeyAlgorithm

The algorithm of a generated key (DP-179): `ed25519` (the default) or `rsa` (4096 bits, for a tool that needs RSA).

---

### TomSecretsGeneratedSshKey

A generated key: `privateKey` (the OpenSSH private key file, without a passphrase: the vault protects it) and `info`.

---

### TomSecretsKeeAgentSettings

KeePassXC's (and KeeAgent's) per-entry SSH agent settings, the `KeeAgent.settings` attachment: `allowUseOfSshKey`, `addAtDatabaseOpen`, `removeAtDatabaseClose`, `useConfirmConstraintWhenAdding`, `useLifetimeConstraintWhenAdding`, `lifetimeConstraintDuration`, `selectedType` (`attachment` or `file`), `attachmentName`, `saveAttachmentToTempFile`, `fileName`.

| Member | Return Type | Description |
| --- | --- | --- |
| `parse(List<int> bytes)` (static) | `TomSecretsKeeAgentSettings?` | The settings from UTF-8 or UTF-16 XML, or null |
| `toXml()` | `String` | The XML as KeePassXC writes it |
| `toBytes()` | `Uint8List` | The attachment: UTF-16 little-endian with a byte order mark, as KeeAgent reads it |
| `copyWith({allowUseOfSshKey, addAtDatabaseOpen, useConfirmConstraintWhenAdding})` | `TomSecretsKeeAgentSettings` | These settings with the flags given replaced |

---

### TomSecretsSshAgentServing

Whether the ssh-agent serves an entry's key: `served`, `notSshKey`, `noKey`, `notAllowed` (KeeAgent's "allow" off), `notAdded` (KeeAgent's "add when the vault opens" off), `keyFileOutside` (the key is a file outside the vault), `unsupported` (DSA, security keys), `passphraseMissing` (an encrypted key without a `Password`).

---

### TomSecretsSshPrivateKey

A decoded private key as the agent signs with it.

| Member | Type | Description |
| --- | --- | --- |
| `decode(List<int> file, {String? passphrase})` (static) | `Future<TomSecretsSshPrivateKey>` | The key of a private key file: OpenSSH (unencrypted, or `bcrypt_pbkdf` with `aes{128,192,256}-ctr`, `aes{128,192,256}-cbc`, `aes{128,256}-gcm@openssh.com`), PEM PKCS#1 / SEC1 (also `DEK-Info` AES-CBC or DES-EDE3-CBC), PKCS#8 (also PBES2 with PBKDF2 and AES-CBC). Throws `TomSecretsSshKeyException` |
| `keyType` | `String` | `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256` / `384` / `521` |
| `publicKeyBlob` | `Uint8List` | The public key in SSH's wire form |
| `comment` | `String` | The comment the file carries, or empty |
| `sign(List<int> data, {int flags = 0})` | `Future<Uint8List>` | SSH's signature blob: Ed25519; ECDSA with the curve's SHA-2 and RFC 6979 nonces; RSA with `TomSecretsSshSignFlags.rsaSha256` or `rsaSha512` only (SHA-1 throws `StateError`) |
| `dispose()` | `void` | Forgets the key (the Ed25519 seed zeroed) |

---

### TomSecretsSshKeyException

A key file that cannot be used: `problem` (`TomSecretsSshKeyProblem`: `malformed`, `passphraseNeeded`, `wrongPassphrase`, `unsupported`) and `detail` (the type, cipher or OID; never key material).

---

### TomSecretsSshAgentConnection

One connection of the SSH agent protocol (draft-miller-ssh-agent) over a `TomSecretsSshAgentBackend` (`identities(bindings)`, `sign(request)`): `REQUEST_IDENTITIES`, `SIGN_REQUEST`, `session-bind@openssh.com` (the host key's signature of the session id checked; no binding after one for authentication; at most 16); everything else `FAILURE`. A user authentication on a bound connection must name the last binding's session (and, host-bound, its host key). `TomSecretsSshAgentFramer` splits a byte stream into messages (at most 256 KiB) and frames answers.

| Member | Type | Description |
| --- | --- | --- |
| `handle(Uint8List message)` | `Future<Uint8List>` | The answer to one message (without its length) |
| `bindings` | `List<TomSecretsSshBinding>` | The connection's `session-bind`s: `hostKey`, `sessionId`, `forwarded`, `hostKeyFingerprint` |
| `backend` | `TomSecretsSshAgentBackend` | The backend |

`TomSecretsSshAgentIdentity(publicKeyBlob, comment)` is a key the agent offers: its public key in SSH's wire form and its comment (shown by `ssh-add -l`).

`TomSecretsSshSignRequest` carries `publicKeyBlob`, `data`, `flags`, `bindings`, `purpose` (`TomSecretsSshSignPurpose`: `userAuth`, `sshSig`, `other`), `namespace` (an `SSHSIG`'s), `destination` (the last binding), `forwarded` (an earlier binding was) and `keyFingerprint`.

---

### TomSecretsSshAgentMessage

The agent protocol's message numbers.

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `failure` | `int` | `SSH_AGENT_FAILURE` (5). |
| `success` | `int` | `SSH_AGENT_SUCCESS` (6). |
| `requestIdentities` | `int` | `SSH_AGENTC_REQUEST_IDENTITIES` (11). |
| `identitiesAnswer` | `int` | `SSH_AGENT_IDENTITIES_ANSWER` (12). |
| `signRequest` | `int` | `SSH_AGENTC_SIGN_REQUEST` (13). |
| `signResponse` | `int` | `SSH_AGENT_SIGN_RESPONSE` (14). |
| `extension` | `int` | `SSH_AGENTC_EXTENSION` (27). |

---

### TomSecretsSshGrantSecret

An agent grant's `secret` (protocol.md 7.6): `ssh-key [host <fingerprint>[,…]] [forward] <target>`.

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsSshGrantSecret(target, {hosts, forward})` | constructor | Keys of `target` (a canonical reference, `store <name>` or `all`), for `hosts` (empty: any) and with `forward` |
| `parse(String secret)` (static) | `TomSecretsSshGrantSecret?` | The agent secret, or null when `secret` is none |
| `text` | `String` | As written into the grant |
| `valid` | `bool` | Forwarding only for one key and named hosts |
| `prefix` (static) | `String` | `ssh-key `, the prefix of an agent grant's secret |

---

### TomSecretsCharacterClass

The character classes a generated password draws from.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `lower` | `a`–`z`. |
| `upper` | `A`–`Z`. |
| `digits` | `0`–`9`. |
| `symbols` | The printable ASCII symbols. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `characters` | `String` | Its characters. |

---

### TomSecretsPasswordPolicy

What a generated password is made of.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPasswordPolicy({length, classes, excludeAmbiguous})` | — | A password of `length` characters from `classes`, each class present at least once; `excludeAmbiguous` leaves out `tomSecretsAmbiguousCharacters`. Throws `ArgumentError` for no class or a length shorter than the number of classes or longer than 1024. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `length` | `int` | The number of characters. |
| `classes` | `Set<TomSecretsCharacterClass>` | The classes drawn from, each at least once. |
| `excludeAmbiguous` | `bool` | Whether `tomSecretsAmbiguousCharacters` are left out. |
| `alphabet` | `String` | Every character a password may hold, in class order. |
| `entropyBits` | `double` | The password's strength in bits, as if every character were drawn from `alphabet` alone (the guarantee of one per class takes off a fraction of a bit, which this leaves out). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `charactersOf(cls)` | `String` | The characters of `cls` under this policy. |
| `copyWith({length, classes, excludeAmbiguous})` | `TomSecretsPasswordPolicy` | The policy with the given parts changed. |

---

### TomSecretsPasswordGenerator

Generates passwords under a `TomSecretsPasswordPolicy`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPasswordGenerator({random})` | — | A generator drawing from `random`, by default `Random.secure` (a test passes a seeded one). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `generate([policy])` | `String` | A new password: one character of every class of `policy`, the rest from its whole alphabet, the order shuffled. |

---

### TomSecretsVaultFields

The fields of a vault entry.

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `locator` | `KdbxKey` | The vault's locator. |
| `outerKey` | `KdbxKey` | The repository's outer key (base64), when it has one. |
| `githubToken` | `KdbxKey` | A GitHub token for the vault's repository, when it differs from the primary's. |
| `githubTokenExpires` | `KdbxKey` | When `githubToken` expires (ISO 8601), as recorded when it was entered. |
| `keyFile` | `KdbxKey` | The attachment holding the key file. |
| `nextPassword` | `KdbxKey` | **[C]** The next master password of a guided rotation, until its switch. |
| `nextOuterKey` | `KdbxKey` | **[C]** The next repository key (base64) of a guided rotation. |
| `nextKeyFile` | `KdbxKey` | **[C]** The attachment holding the next key file of a guided rotation. |
| `previousOuterKey` | `KdbxKey` | **[C]** The repository key (base64) the vault's file keeps a second slot for after a guided rotation's switch, until its finish. |

---

### TomSecretsVaultKeys

What the primary keeps about one further vault.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsVaultKeys({name, locator, password, keyFile, outerKey, githubToken, githubTokenExpires, expires, nextPassword, nextKeyFile, nextOuterKey, previousOuterKey})` | — | A vault `name` at `locator` opened with `password` (and `keyFile`). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `name` | `String` | The entry's title: the vault's name. |
| `locator` | `String` | Where the vault is. |
| `password` | `String?` | Its master password, or null. |
| `keyFile` | `Uint8List?` | Its key file, or null. |
| `outerKey` | `String?` | The repository's outer key (base64), or null. |
| `githubToken` | `String?` | A GitHub token for its repository, or null (the primary's applies). |
| `githubTokenExpires` | `DateTime?` | When `githubToken` expires, as recorded when it was entered, or null. |
| `expires` | `DateTime?` | When its key file and repository key are due for rotation: the entry's KDBX Expires, or null when the entry does not expire. |
| `nextPassword` | `String?` | **[C]** The next master password of a guided rotation (prepared, not switched yet), or null. |
| `nextKeyFile` | `Uint8List?` | **[C]** The next key file of a guided rotation, or null. |
| `nextOuterKey` | `String?` | **[C]** The next repository key (base64) of a guided rotation, or null. |
| `previousOuterKey` | `String?` | **[C]** The old repository key whose slot the file keeps during a guided rotation's migration period, or null. |
| `hasNext` | `bool` | **[C]** Whether a guided rotation prepared next keys for it. |
| `writtenOuterKeys` | `String?` | **[C]** The repository keys its file is written with: `outerKey`, and `previousOuterKey` during a migration period (`,`-separated, the newest first). |
| `credentials` | `Credentials` | The credentials that open the vault (`Credentials.composite` takes the key file's bytes and derives the key itself). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `copyWith({githubToken, githubTokenExpires, password, keyFile, removeKeyFile, outerKey, nextPassword, nextKeyFile, nextOuterKey, clearNext, previousOuterKey, clearPrevious, expires})` | `TomSecretsVaultKeys` | **[C]** The same keys with the changes given; `clearNext` drops the next keys, `clearPrevious` the previous repository key. |

---

### TomSecretsPrimaryVaults

A primary vault's further vaults.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPrimaryVaults(file, {primaryLocator})` | — | The further vaults of the primary vault `file` at `primaryLocator`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `file` | `KdbxFile` | The primary vault. |
| `primaryLocator` | `String?` | The primary's own locator, which its list may not hold. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `list()` | `List<TomSecretsVaultKeys>` | Every further vault, in file order. An entry without a readable locator, or naming the primary itself, is left out. |
| `byName(name)` | `TomSecretsVaultKeys?` | The vault `name`, or null. |
| `put(keys)` | `void` | Writes `keys` (a new entry, or the entry of the same name): adding a vault, or changing its password in the same save as the vault itself. |
| `remove(name)` | `bool` | Removes the vault `name`; answers whether it was there. |

---

### TomSecretsPrimaryNextKeys

**[C]** The primary vault's own keys during a guided rotation: the new key file and repository key every device takes into its keychain before the switch, and after the switch the old repository key its file keeps a slot for until the finish; the entry `primary` of `.tom-secrets/next-keys`.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsPrimaryNextKeys({keyFile, outerKey, previousOuterKey})` | const | The primary's next keys. |
| `TomSecretsPrimaryNextKeys.of(file)` | static | The primary `file`'s next keys, or null when no rotation of them runs. |
| `TomSecretsPrimaryNextKeys.clear(file)` | static `bool` | Removes them for good; whether there were any. |
| `keyFile` | `Uint8List?` | The new key file, or null. |
| `outerKey` | `String?` | The new repository key (base64), or null. |
| `previousOuterKey` | `String?` | After the switch: the old repository key the file keeps a slot for. |
| `writeTo(file)` | `void` | Writes them into the primary `file` (over earlier ones). |

---

### TomSecretsHealthIssue

What the health report flags.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `weak` | A password an attacker guesses quickly. |
| `reused` | A password two or more entries share. |
| `old` | A password unchanged for longer than the policy's age. |
| `expiring` | An entry that expires soon, or has expired. |
| `shortKey` | A key shorter than today's guidance (DP-179). |
| `breached` | A password found in known breaches. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `label` | `String` | The heading the Health screen shows. |

---

### TomSecretsHealthPolicy

The report's thresholds.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsHealthPolicy({oldAfter, expiringWithin})` | `const` | Passwords count as old after `oldAfter` (one year); entries as expiring within `expiringWithin` (30 days) of their Expires time. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `oldAfter` | `Duration` | The age after which a password counts as old. |
| `expiringWithin` | `Duration` | How long before its Expires time an entry counts as expiring. |

---

### TomSecretsPasswordStrength

How guessable a password is (zxcvbn).

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `score` | `int` | zxcvbn's score, 0 (guessed at once) to 4. |
| `guessesLog10` | `double` | The estimated guesses, as a power of ten. |
| `warning` | `String?` | What makes it guessable, when zxcvbn names it. |
| `weak` | `bool` | Whether the report flags it: a score below 3. |

---

### TomSecretsKeyStrength

Today's minimum key lengths (DP-179).

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `rsaMinimumBits` | `int` | 3072: RSA below it is flagged. |
| `ecMinimumBits` | `int` | 256: an elliptic curve below it is flagged. |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `shortness(keyType, bits)` | `String?` | Why a key of an SSH key type and size is short (DSA always), or null when it passes or its length cannot be read. |

---

### TomSecretsHealthEntry

An entry the health report reads.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsHealthEntry(store, entry)` | `const` | `entry` of the vault `store`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `store` | `String` | The store. |
| `entry` | `KdbxEntry` | The entry. |
| `type` | `TomSecretsEntryType` | Its type. |
| `password` | `String?` | Its password when it is a login with one, else null. |

---

### TomSecretsHealthFinding

One flag of the health report.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `issue` | `TomSecretsHealthIssue` | What is flagged. |
| `store` | `String` | The entry's store. |
| `entry` | `KdbxEntry` | The entry. |
| `detail` | `String` | Why, for the user; never a value. |

---

### TomSecretsHealthReport

The health report: its findings by issue, then by store and title.

**Kind:** `final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `empty` | `TomSecretsHealthReport` | The empty report. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `findings` | `List<TomSecretsHealthFinding>` | Every finding. |
| `checkedPasswords` | `int` | How many login passwords were checked. |
| `healthy` | `bool` | Whether nothing is flagged. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `of(issue)` | `List<TomSecretsHealthFinding>` | The findings of `issue`. |

---

### TomSecretsBreachCheck

The breach check over the Have I Been Pwned range API: only a password's five-character SHA-1 prefix leaves the device, with `Add-Padding: true`; counts cached per hash in memory.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsBreachCheck({client, endpoint, parallel = 4, userAgent})` | — | A check over `client` (default a new one) against `endpoint` (default `defaultEndpoint`), at most `parallel` requests at a time. |

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `defaultEndpoint` | `Uri` | `https://api.pwnedpasswords.com/range/`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `endpoint` | `Uri` | Where the prefixes are sent (`<endpoint><prefix>`). |
| `parallel` | `int` | How many requests run at once. |
| `userAgent` | `String` | The `User-Agent` the API asks for. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `cached(password)` | `int?` | How often `password` was seen, when asked already; else null. |
| `count(password)` | `Future<int>` | How often `password` was seen in breaches. |
| `countAll(passwords)` | `Future<Map<String, int>>` | How often each was seen, one request per prefix not asked before; a failed request throws `TomSecretsBreachCheckException`. |
| `close()` | `void` | Closes the client it made. |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `parseRange(body)` | `Map<String, int>` | The suffixes of a range answer with their counts, the padding lines (count 0) left out. |

---

### TomSecretsBreachCheckException

The breach check could not ask.

**Kind:** `final class`

**Implements:** `Exception`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What went wrong. |

---

### TomSecretsAutoTypeKey

A key auto-type presses that is no character.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `tab` | Tab. |
| `enter` | Enter. |
| `space` | Space. |
| `backspace` | Backspace. |
| `delete` | Delete (forward). |
| `escape` | Escape. |
| `up` | Arrow up. |
| `down` | Arrow down. |
| `left` | Arrow left. |
| `right` | Arrow right. |
| `home` | Home. |
| `end` | End. |
| `pageUp` | Page up. |
| `pageDown` | Page down. |
| `insert` | Insert. |
| `function` | F1 … F16 (the key press names which). |

---

### TomSecretsAutoTypeModifier

A modifier held while a key is pressed.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `shift` | Shift (`+`). |
| `control` | Control (`^`). |
| `alt` | Alt or Option (`%`). |
| `meta` | The Windows key, or Command on macOS (`@`). |

---

### TomSecretsAutoTypeAction

One step of a parsed auto-type sequence.

**Kind:** `sealed class`

Subclasses: `TomSecretsAutoTypeText`, `TomSecretsAutoTypeKeyPress`, `TomSecretsAutoTypeDelay`, `TomSecretsAutoTypeKeyDelay`.

---

### TomSecretsAutoTypeText

Text typed as characters, each as Unicode where the OS allows.

**Kind:** `final class`

**Extends:** `TomSecretsAutoTypeAction`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `text` | `String` | The characters. |

---

### TomSecretsAutoTypeKeyPress

A special key or a character pressed with modifiers.

**Kind:** `final class`

**Extends:** `TomSecretsAutoTypeAction`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsAutoTypeKeyPress({key, character, function = 0, modifiers})` | `const` | A special key or a character, with the modifiers held. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `key` | `TomSecretsAutoTypeKey?` | The special key, or null for a character. |
| `character` | `String?` | The character, or null for a special key. |
| `function` | `int` | For a function key, its number. |
| `modifiers` | `Set<TomSecretsAutoTypeModifier>` | The modifiers held. |

---

### TomSecretsAutoTypeDelay

A pause (`{DELAY n}`).

**Kind:** `final class`

**Extends:** `TomSecretsAutoTypeAction`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `duration` | `Duration` | How long. |

---

### TomSecretsAutoTypeKeyDelay

The pause between keys from here on (`{DELAY=n}`).

**Kind:** `final class`

**Extends:** `TomSecretsAutoTypeAction`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `duration` | `Duration` | How long. |

---

### TomSecretsAutoTypeException

A sequence that cannot be typed.

**Kind:** `final class`

**Implements:** `Exception`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong (never a value). |

---

### TomSecretsAutoTypeCandidate

An entry auto-type may type into a window, and why.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `store` | `String` | The entry's store. |
| `entry` | `KdbxEntry` | The entry. |
| `byAssociation` | `bool` | Whether a window association matched (else its title). |
| `sequence` | `String` | The sequence it types there. |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsDefaultValue` | `String` | The reserved value every dimension has. |
| `tomSecretsBuiltInDimensions` | `List<String>` | The dimensions every configuration has, in their default priority order. |
| `tomSecretsPlatforms` | `Set<String>` | The values of the built-in `platform` dimension. |
| `tomSecretsMetadataTitle` | `String` | The title of the metadata entry. |
| `tomSecretsMetadataFormat` | `int` | The metadata format this library reads and writes. |
| `tomSecretsGrantsGroup` | `String` | The group holding the grants of every host (primary vault only); never a place references resolve into. |
| `tomSecretsSharingGroup` | `String` | The group of the primary vault holding the member key and the directory of members (part-sharing); never a place references resolve into, never exported. |
| `tomSecretsOverlayPrefix` | `String` | The first character of an overlay group's name. |
| `tomSecretsFavoriteTag` | `String` | The tag that marks a favourite. |
| `tomSecretsDefaultArgon2` | `KdbxArgon2` | The key derivation of a new vault: Argon2id over 64 MiB, 3 iterations, 1 lane. The app tunes it at creation so unlocking takes about one second on the slowest of the user's devices, and passes the result as `argon2` to `tomSecretsNewVault`. |
| `tomSecretsAmbiguousCharacters` | `String` | The characters `TomSecretsPasswordPolicy.excludeAmbiguous` leaves out, because they are easily confused when read or typed. |
| `tomSecretsProductGroup` | `String` | The root group holding the product's own groups (never resolved into). |
| `tomSecretsVaultsGroup` | `String` | The subgroup holding the further vaults. |
| `tomSecretsNextKeysGroup` | `String` | **[C]** The subgroup holding the primary's own next keys during a guided rotation of them: `next-keys`. |
| `tomSecretsPublicSuffixListVersion` | `String` | The version of the Public Suffix List the URL matching carries (regenerated with `tool/update_public_suffix_list.py`). |
| `tomSecretsKeeAgentSettingsName` | `String` | `KeeAgent.settings`, the attachment KeePassXC's SSH agent reads an entry's settings from. |
| `tomSecretsStrengthMaxLength` | `int` | The longest prefix of a password the strength estimator reads (100). |
| `tomSecretsBreachCheckField` | `KdbxKey` | `tsm.breachCheck`, the field that keeps an entry out of the breach check (`off`). |
| `tomSecretsSshAgentMaxMessage` | `int` | The largest message the agent reads, 256 KiB (OpenSSH's `AGENT_MAX_LEN`). |
| `tomSecretsSshAgentMaxBindings` | `int` | At most this many `session-bind`s per connection, 16 (OpenSSH's `AGENT_MAX_SESSION_IDS`). |
| `tomSecretsSshAgentKeyTypes` | `Set<String>` | The key types the agent signs with. |
| `tomSecretsDefaultAutoTypeSequence` | `String` | `{USERNAME}{TAB}{PASSWORD}{ENTER}`, typed when neither the entry nor its groups name a sequence. |

### Functions

| Function | Signature | Description |
| --- | --- | --- |
| `tomSecretsGitHubTokenHandle` | `String tomSecretsGitHubTokenHandle(String owner, String repository)` | The device keychain's handle of the GitHub token for `owner`/`repository`. |
| `tomSecretsGitHubTokenExpiryHandle` | `String tomSecretsGitHubTokenExpiryHandle(String owner, String repository)` | The device keychain's handle of the expiry (ISO 8601) recorded with the GitHub token for `owner`/`repository` when it was entered. |
| `tomSecretsKeyFileHandle` | `String tomSecretsKeyFileHandle(TomSecretsVaultLocator locator)` | The device keychain's handle of the key file of the vault at `locator`: `tsm.key-file.<id>`, the id the first 16 hex digits of SHA-256 over the vault's identity (an OS keychain refuses `/` in an item's name). |
| `tomSecretsRepositoryKeyHandle` | `String tomSecretsRepositoryKeyHandle(TomSecretsVaultLocator locator)` | The device keychain's handle of the repository key (base64) of the repository the vault at `locator` is in: `tsm.repository-key.<id>`, the id as for `tomSecretsKeyFileHandle` over the repository's identity. |
| `tomSecretsParseFileBinding` | `Map<String, String> tomSecretsParseFileBinding(String text)` | Reads a file binding (`env=prod;region=eu`); an empty text binds nothing. |
| `tomSecretsMetadataEntry` | `KdbxEntry? tomSecretsMetadataEntry(KdbxFile file)` | The metadata entry of `file`, or null. |
| `tomSecretsIsPasskeyField` | `bool tomSecretsIsPasskeyField(String field)` | Whether `field` is a passkey field the client endpoint never serves. |
| `tomSecretsIsReservedName` | `bool tomSecretsIsReservedName(String name)` | Whether `name` is reserved for the product (`tsm.` names, `@` groups). |
| `tomSecretsUuidHex` | `String tomSecretsUuidHex(KdbxUuid uuid)` | The 32 lower-case hex digits of `uuid`, as `~uuid` references write it. |
| `tomSecretsUuidFromHex` | `KdbxUuid tomSecretsUuidFromHex(String hex)` | The `KdbxUuid` of 32 hex digits. |
| `tomSecretsNewVault` | `KdbxFile tomSecretsNewVault(Credentials credentials, String name, {KdbxArgon2 argon2 = tomSecretsDefaultArgon2})` | A new, empty vault named `name`, opened with `credentials` (a password, a key file or both): KDBX 4.1, its key derived through `argon2`, which must be Argon2id, and the product's format version in its custom data. A primary vault is such a vault holding `.tom-secrets/vaults` (`TomSecretsPrimaryVaults`). |
| `tomSecretsOverlayBinding` | `(String, String)? tomSecretsOverlayBinding(String name)` | The binding an overlay group's `name` stands for (`@host:build-01`), or null when the name is not one. |
| `tomSecretsBase32Encode` | `String tomSecretsBase32Encode(List<int> bytes)` | RFC 4648 base32 without padding. |
| `tomSecretsBase32Decode` | `Uint8List? tomSecretsBase32Decode(String text)` | RFC 4648 base32, any case, spaces, dashes and padding ignored; null when it is not base32. |
| `tomSecretsGenerateSshKey` | `Future<TomSecretsGeneratedSshKey> tomSecretsGenerateSshKey({TomSecretsSshKeyAlgorithm algorithm = TomSecretsSshKeyAlgorithm.ed25519, String comment = '', int rsaBits = 4096, Random? random})` | A new SSH key (DP-179): Ed25519, or RSA 4096; the private key in OpenSSH's format without a passphrase. |
| `tomSecretsSshKeyOf` | `({String name, Uint8List bytes, TomSecretsSshKeyInfo info})? tomSecretsSshKeyOf(KdbxEntry entry)` | An entry's SSH key: the attachment its `KeeAgent.settings` names, else the first attachment holding a private key. |
| `tomSecretsWriteSshKey` | `void tomSecretsWriteSshKey(KdbxEntry entry, {required String attachmentName, required Uint8List privateKey, String? passphrase})` | Makes an entry an SSH key entry: `tsm.type` `ssh-key`, the key as a protected attachment, `KeeAgent.settings` naming it, the passphrase in `Password`. |
| `tomSecretsSshKeyCandidates` | `List<KdbxEntry> tomSecretsSshKeyCandidates(KdbxFile file)` | The entries holding an SSH private key that are not typed `ssh-key`: phase A's notes and KeePassXC's entries. |
| `tomSecretsMigrateSshKeys` | `List<KdbxEntry> tomSecretsMigrateSshKeys(KdbxFile file)` | Retypes them as SSH key entries (DP-5), each one's old state in its history. |
| `tomSecretsKeeAgentSettingsOf` | `TomSecretsKeeAgentSettings? tomSecretsKeeAgentSettingsOf(KdbxEntry entry)` | An entry's `KeeAgent.settings`, or null. |
| `tomSecretsWriteKeeAgentSettings` | `void tomSecretsWriteKeeAgentSettings(KdbxEntry entry, TomSecretsKeeAgentSettings settings)` | Writes an entry's `KeeAgent.settings`, its old state in its history. |
| `tomSecretsSshAgentStateOf` | `({TomSecretsSshAgentServing state, ({String name, Uint8List bytes, TomSecretsSshKeyInfo info})? key, bool confirm}) tomSecretsSshAgentStateOf(KdbxEntry entry)` | Whether the agent serves the entry's key, the key, and whether KeeAgent asks to confirm each use. |
| `tomSecretsSshVerify` | `Future<bool> tomSecretsSshVerify(List<int> publicKeyBlob, List<int> signature, List<int> data)` | Whether an SSH signature blob verifies (Ed25519, ECDSA, `rsa-sha2-256` / `-512`); used for `session-bind`. |
| `tomSecretsSshFingerprint` | `String tomSecretsSshFingerprint(List<int> blob)` | `SHA256:<base64>` of a public key. |
| `tomSecretsKnownHostNames` | `List<String> tomSecretsKnownHostNames(String text, List<int> hostKey)` | The plain names `known_hosts` lists for a host key (hashed, revoked and wildcard lines left out). |
| `tomSecretsBcryptPbkdf` | `Uint8List tomSecretsBcryptPbkdf(List<int> passphrase, List<int> salt, int length, int rounds)` | OpenBSD's `bcrypt_pbkdf`, the KDF of encrypted OpenSSH keys. |
| `tomSecretsMatchLogins` | `List<TomSecretsLoginMatch> tomSecretsMatchLogins(Iterable<TomSecretsIndexedEntry> entries, String url, {String? frameUrl})` | The login entries (type `login`, no overlays) whose URLs match the page by their `tsm.urlMatch` rule; with `frameUrl` the frame is matched, only when it is the same site as the page. Ordered: the exact host first, then the last used, then by title (protocol.md 5.7). |
| `tomSecretsMatchSiteUrl` | `TomSecretsUrlMatchLevel? tomSecretsMatchSiteUrl(TomSecretsSiteUrl entry, TomSecretsSiteUrl page, {TomSecretsUrlMatchRule rule = TomSecretsUrlMatchRule.domain})` | How an entry URL matches a page under a rule, or null; `https` never on `http`, addresses and `localhost` by host and port. |
| `tomSecretsEntryUrls` | `List<String> tomSecretsEntryUrls(KdbxEntry entry)` | The entry's `URL`, then its `KP2A_URL*` fields in name order; empty ones left out. |
| `tomSecretsRegistrableDomain` | `String? tomSecretsRegistrableDomain(String host)` | The registrable domain of an ASCII host after the Public Suffix List (both sections), or null for a public suffix. |
| `tomSecretsAsciiHost` | `String tomSecretsAsciiHost(String host)` | The host lower-case, a trailing dot dropped, non-ASCII labels as punycode (RFC 3492), an IPv6 address without brackets. |
| `tomSecretsPasswordStrength` | `TomSecretsPasswordStrength tomSecretsPasswordStrength(String password, {List<String> userInputs = const []})` | The strength of `password` (zxcvbn, its first 100 characters); `userInputs` are words it should not be built from (the entry's title, user name, site). |
| `tomSecretsBreachCheckExcluded` | `bool tomSecretsBreachCheckExcluded(KdbxEntry entry)` | Whether an entry is kept out of the breach check (`tsm.breachCheck` `off`). |
| `tomSecretsSetBreachCheckExcluded` | `void tomSecretsSetBreachCheckExcluded(KdbxEntry entry, bool excluded)` | Keeps an entry out of the breach check, or lets it in again; its old state in its history. |
| `tomSecretsPasswordOf` | `String? tomSecretsPasswordOf(KdbxEntry entry)` | An entry's password, or null when it has none. |
| `tomSecretsPasswordChanged` | `DateTime? tomSecretsPasswordChanged(KdbxEntry entry)` | When an entry's current password was set, read from its history. |
| `tomSecretsPasswordHash` | `String tomSecretsPasswordHash(String password)` | The SHA-1 of a password in upper-case hex, as the range API compares it; kept in memory only. |
| `tomSecretsHealthReport` | `TomSecretsHealthReport tomSecretsHealthReport(Iterable<TomSecretsHealthEntry> entries, {required DateTime now, TomSecretsHealthPolicy policy = const TomSecretsHealthPolicy(), int? Function(TomSecretsHealthEntry entry, String password)? breachCount})` | The health report: weak, reused, old and breached login passwords, expiring entries, short SSH keys. |
| `tomSecretsAutoTypeValues` | `String? Function(String name) tomSecretsAutoTypeValues(KdbxEntry entry, {DateTime? now})` | An entry's placeholder values: `{USERNAME}`, `{PASSWORD}`, `{TITLE}`, `{URL}`, `{NOTES}`, `{TOTP}`, `{S:<field>}`. |
| `tomSecretsParseAutoType` | `List<TomSecretsAutoTypeAction> tomSecretsParseAutoType(String sequence, {required String? Function(String name) values})` | Parses a sequence in KeePass's syntax: placeholders as text, special keys with repeat counts, `+ ^ % @` modifiers on a key or a group, `~`, `{DELAY n}`, `{DELAY=n}`, escaped characters. |
| `tomSecretsAutoTypeWindowMatches` | `bool tomSecretsAutoTypeWindowMatches(String pattern, String title)` | Whether a window title matches an association pattern: `*`/`?` wildcards over the whole title or `//regex//`, any case. |
| `tomSecretsAutoTypeEnabled` | `bool tomSecretsAutoTypeEnabled(KdbxEntry entry)` | Whether auto-type is on for an entry (its own setting and the nearest group's). |
| `tomSecretsAutoTypeSequenceFor` | `String? tomSecretsAutoTypeSequenceFor(KdbxEntry entry, {String? windowTitle})` | The sequence typed for an entry into a window: a matching association's, else the entry's, the group's, the default; null when off. |
| `tomSecretsAutoTypeCandidates` | `List<TomSecretsAutoTypeCandidate> tomSecretsAutoTypeCandidates(Iterable<(String, KdbxEntry)> entries, String windowTitle)` | The logins and API tokens fitting a window: a matching association first, then titles the window title holds. |
