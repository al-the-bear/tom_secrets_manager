# Tom Secrets Age API Reference

The public API of `package:tom_secrets_age/tom_secrets_age.dart`: the `age` v1 file format (hybrid `mlkem768x25519`, classical `X25519` and passphrase `scrypt` recipients, the armour), member keys (hybrid `age` identities and their recipients, fingerprints, the published key file) and HKDF-SHA-256. `tom_secrets_core` re-exports it.

## Table of Contents

- [Class Hierarchy](#class-hierarchy)
- [Types](#types)
  - [TomSecretsMemberKeyFailure](#tomsecretsmemberkeyfailure)
  - [TomSecretsMemberKeyException](#tomsecretsmemberkeyexception)
  - [TomSecretsAgeRecipientKind](#tomsecretsagerecipientkind)
  - [TomSecretsAgeRecipient](#tomsecretsagerecipient)
  - [TomSecretsMemberKey](#tomsecretsmemberkey)
  - [TomSecretsReceivedMemberKey](#tomsecretsreceivedmemberkey)
  - [TomSecretsAgeFailure](#tomsecretsagefailure)
  - [TomSecretsAgeException](#tomsecretsageexception)
  - [TomSecretsAgeIdentity](#tomsecretsageidentity)
  - [TomSecretsAgeHybridIdentity](#tomsecretsagehybrididentity)
  - [TomSecretsAgeX25519Identity](#tomsecretsagex25519identity)
  - [TomSecretsAgePassphraseIdentity](#tomsecretsagepassphraseidentity)
- [Constants](#constants)
- [Functions](#functions)

---

## Class Hierarchy

```text
Object
├── TomSecretsMemberKeyFailure (enum)
├── TomSecretsMemberKeyException
├── TomSecretsAgeRecipientKind (enum)
├── TomSecretsAgeRecipient
├── TomSecretsMemberKey
├── TomSecretsReceivedMemberKey (typedef)
├── TomSecretsAgeFailure (enum)
├── TomSecretsAgeException
├── TomSecretsAgeIdentity (sealed)
├── TomSecretsAgeHybridIdentity
├── TomSecretsAgeX25519Identity
└── TomSecretsAgePassphraseIdentity
```

---

## Types

### TomSecretsMemberKeyFailure

Why a key or an entry was refused.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `malformed` | Not an `age` key: not Bech32, a bad checksum, mixed case, an unknown prefix, the wrong length. |
| `plugin` | An `age` plugin recipient (`age1<plugin>1…`), which the product does not run. |
| `classicalIdentity` | A classical identity (`AGE-SECRET-KEY-1…`): a member key is hybrid. |
| `invalidKey` | The recipient's ML-KEM-768 half fails FIPS 203's check, or its X25519 half is a low-order point. |
| `duplicate` | The directory holds this recipient already. |
| `ownKey` | The recipient is the user's own member key. |

---

### TomSecretsMemberKeyException

A refused key, with the `reason` the app shows.

**Kind:** `final class`

**Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsMemberKeyException(reason, message)` | const | A refusal for `reason`, told by `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `reason` | `TomSecretsMemberKeyFailure` | Why. |
| `message` | `String` | For people; never a private key. |

---

### TomSecretsAgeRecipientKind

The kind of an `age` recipient.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `hybrid` | `age1pq1…`: X25519 + ML-KEM-768 (`mlkem768x25519`), a member key. |
| `classical` | `age1…`: X25519 alone, for exports only. |

---

### TomSecretsAgeRecipient

An `age` public key: a hybrid member key or another person's classical key. Equal by its canonical (lower-case) string.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsAgeRecipient.hybrid(publicKey)` | factory | The hybrid recipient of the 1,216-byte X-Wing `publicKey` (ML-KEM-768, then X25519). |
| `TomSecretsAgeRecipient.parse(text)` | factory | Parses `age1pq1…` or `age1…`, lower case or all upper case (canonicalised to lower case, the only form `age` reads), white space around it ignored; throws `TomSecretsMemberKeyException` otherwise. |

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `hybridPrefix` | `String` | `age1pq`, the Bech32 prefix of a hybrid recipient. |
| `classicalPrefix` | `String` | `age`, the Bech32 prefix of a classical recipient. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `kind` | `TomSecretsAgeRecipientKind` | Hybrid or classical. |
| `publicKey` | `Uint8List` | The public key: 1,216 bytes (ML-KEM-768 then X25519) or 32 (X25519). |
| `encoded` | `String` | The recipient string, lower case: what `age -r` takes (a hybrid one is 1,959 characters). |
| `isHybrid` | `bool` | Whether it is a hybrid (post-quantum) key. |
| `fingerprint` | `String` | The SHA-256 of `encoded` in base32 (RFC 4648, lower case, no padding, 52 characters): the member id of the inbox folders and the relay's mailboxes. |
| `shortFingerprint` | `String` | The first 20 characters of `fingerprint` in groups of four (100 bits): what people compare. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `check()` | `Future<void>` | Checks the key as `age` would on encrypting to it (a hybrid key: an encapsulation to it succeeds); throws `TomSecretsMemberKeyException` (`invalidKey`) otherwise. |

---

### TomSecretsMemberKey

The user's member key: a hybrid `age` identity and its recipient. Holds the 32-byte seed in native memory (`SecretBytes`); `dispose` zeroes it.

**Kind:** `final class`

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `generate()` | `Future<TomSecretsMemberKey>` | A new member key from fresh randomness. |
| `parse(identity)` | `Future<TomSecretsMemberKey>` | The member key of an `AGE-SECRET-KEY-PQ-1…` identity (an existing `age-keygen -pq` key, or the `member-key` entry's); a classical identity is refused (`classicalIdentity`). |

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `identityPrefix` | `String` | `age-secret-key-pq-`, the Bech32 prefix of a hybrid identity (written in upper case). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `recipient` | `TomSecretsAgeRecipient` | The public key, given to other people. |
| `seed` | `SecretBytes` | The seed, for the `age` decryption of a later phase; owned by this key. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `revealIdentity()` | `String` | The identity, `AGE-SECRET-KEY-PQ-1…` (what `age -d -i` reads); a `String` the caller writes into the vault and drops. |
| `dispose()` | `void` | Zeroes the seed. |

---

### TomSecretsReceivedMemberKey

One public key read from a key file or a pasted block.

**Kind:** `typedef` = `({TomSecretsAgeRecipient recipient, String? name})`

| Field | Type | Description |
| --- | --- | --- |
| `recipient` | `TomSecretsAgeRecipient` | The key. |
| `name` | `String?` | The name its file gave (`# name: …`), if any. |

---

### TomSecretsAgeFailure

Why an `age` file could not be written or read.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `noMatch` | None of the identities given opens the file. |
| `header` | The header breaks the format, or its MAC does not verify. |
| `payload` | The payload does not authenticate (changed or cut off). |
| `armor` | The armour breaks the format. |
| `recipients` | No recipient, or hybrid and classical recipients together. |

---

### TomSecretsAgeException

A refused `age` file.

**Kind:** `final class`

#### Members

| Constructor / Property | Type | Description |
| --- | --- | --- |
| `TomSecretsAgeException(reason, message)` | const | A refusal for `reason`, told by `message`. |
| `reason` | `TomSecretsAgeFailure` | Why. |
| `message` | `String` | For people; never a key. |

---

### TomSecretsAgeIdentity

An identity that opens `age` files: `TomSecretsAgeHybridIdentity` (a member key) or `TomSecretsAgeX25519Identity` (a classical identity).

**Kind:** `sealed class`

---

### TomSecretsAgeHybridIdentity

A member key as an `age` identity.

**Kind:** `final class`

#### Members

| Constructor / Property | Type | Description |
| --- | --- | --- |
| `TomSecretsAgeHybridIdentity(key)` | const | `key` as an identity; the key stays the caller's to dispose. |
| `key` | `TomSecretsMemberKey` | The member key. |

---

### TomSecretsAgeX25519Identity

A classical `age` identity, `AGE-SECRET-KEY-1…` (X25519): the product makes none, but reads a file written to one.

**Kind:** `final class`

#### Members

| Constructor / Method | Type | Description |
| --- | --- | --- |
| `TomSecretsAgeX25519Identity.parse(identity)` | factory | The identity of an `AGE-SECRET-KEY-1…` string. |
| `dispose()` | `void` | Zeroes the secret. |

---

### TomSecretsAgePassphraseIdentity

A passphrase as an `age` identity: opens a file written with the `scrypt` recipient; a work factor above `maxWorkFactor` is refused (`header`).

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsAgePassphraseIdentity(passphrase, {maxWorkFactor = 22})` | const | `passphrase` as an identity. |
| `passphrase` | `String` | The passphrase. |
| `maxWorkFactor` | `int` | The highest work factor (log2 N) it computes. |

---

## Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsAgeDefaultWorkFactor` | `int` | The work factor (log2 N) a passphrase file is written with: 18, `age`'s own. |
| `tomSecretsAgeMaxWorkFactor` | `int` | The highest work factor (log2 N) the reader computes: 22, as `age`. |

## Functions

| Function | Signature | Description |
| --- | --- | --- |
| `tomSecretsHkdf` | `Uint8List tomSecretsHkdf(List<int> ikm, {required List<int> salt, required List<int> info, required int length})` | HKDF-SHA-256 (RFC 5869) of `ikm` with `salt` and `info`, `length` bytes. |
| `tomSecretsMemberKeyFile` | `String tomSecretsMemberKeyFile(TomSecretsAgeRecipient recipient, {required String name, DateTime? created})` | The text of a published member key: `age`'s recipients-file format (so `age -R <file>` encrypts to it), with the name, short fingerprint and date as `#` comments. |
| `tomSecretsMemberKeyFileName` | `String tomSecretsMemberKeyFileName(String name)` | The file name of `name`'s published member key: `<name>.age-recipient.txt` (lower case, other characters as `_`). |
| `tomSecretsReadMemberKeys` | `List<TomSecretsReceivedMemberKey> tomSecretsReadMemberKeys(String text)` | The public keys in `text` (a key file, a recipients file with several, a pasted recipient, a scanned QR code's text); blank lines and `#` comments skipped, a `# name: …` comment names the key after it; a line that is no `age` recipient is refused, naming its line. |
| `tomSecretsAgeEncrypt` | `Future<Uint8List> tomSecretsAgeEncrypt(List<int> plaintext, List<TomSecretsAgeRecipient> recipients)` | `plaintext` as an `age` v1 file to `recipients`, all hybrid (`mlkem768x25519`) or all classical (`X25519`); throws `TomSecretsAgeException` (`recipients`) for none or a mix. |
| `tomSecretsAgeDecrypt` | `Future<Uint8List> tomSecretsAgeDecrypt(Uint8List file, Iterable<TomSecretsAgeIdentity> identities)` | The plaintext of the `age` file `file` (binary or armoured), opened with the first identity a stanza is for; throws `TomSecretsAgeException` (`noMatch`, `header`, `payload`, `armor`). |
| `tomSecretsIsAgeArmor` | `bool tomSecretsIsAgeArmor(List<int> file)` | Whether `file` begins with the `age` armour (white space before it allowed). |
| `tomSecretsAgeArmor` | `String tomSecretsAgeArmor(List<int> file)` | `file` in the `age` armour (`-----BEGIN AGE ENCRYPTED FILE-----`, base64 in lines of 64), for pasting into a message. |
| `tomSecretsAgeDearmor` | `Uint8List tomSecretsAgeDearmor(List<int> text)` | The binary file inside the armoured `text` (white space around it and CRLF allowed); throws `TomSecretsAgeException` (`armor`). |
| `tomSecretsAgeClassicalSecret` | `Uint8List tomSecretsAgeClassicalSecret(String identity)` | The 32-byte secret of a classical `AGE-SECRET-KEY-1…` identity. |
| `tomSecretsBech32Data` | `Uint8List tomSecretsBech32Data(String hrp, String text, int length)` | The data of the Bech32 string `text` whose prefix must be `hrp` and whose data must be `length` bytes (age's Bech32: no length limit, either case). |
| `tomSecretsAgeEncryptPassphrase` | `Future<Uint8List> tomSecretsAgeEncryptPassphrase(List<int> plaintext, String passphrase, {int workFactor = tomSecretsAgeDefaultWorkFactor})` | `plaintext` as an `age` v1 file under `passphrase`: one `scrypt` stanza, `workFactor` its log2 N (1 to 22, `ArgumentError` otherwise); scrypt runs in another isolate. |
| `tomSecretsAgeIsPassphrase` | `bool tomSecretsAgeIsPassphrase(List<int> file)` | Whether the `age` file `file` (binary or armoured) is written under a passphrase, so a reader asks for one. |
