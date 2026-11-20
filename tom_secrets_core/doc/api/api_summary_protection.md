# Tom Secrets Core API Reference: Key Files and Outer Encryption Module

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Types](#types)
  - [TomSecretsKeyFileException](#tomsecretskeyfileexception)
  - [TomSecretsKeyFile](#tomsecretskeyfile)
  - [TomSecretsOuterCipher](#tomsecretsoutercipher)
  - [TomSecretsOuterException](#tomsecretsouterexception)
  - [TomSecretsRepositoryKey](#tomsecretsrepositorykey)
  - [TomSecretsOuterCodec](#tomsecretsoutercodec)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The protection module holds the layers around a vault's KDBX encryption: KeePass 2.0 XML key files (the composite key KeePass and KeePassXC read), the outer encryption that stores a vault as `<vault>.kdbx.tsmx` under one or more repository keys (XChaCha20-Poly1305 by default, AES-256-GCM selectable), and the codecs that read and write a vault file as its store keeps it.

Source files: `lib/src/key_file.dart`, `lib/src/outer.dart`, `lib/src/stored_vault.dart`.

---

## Class Hierarchy

```text
Object
├── TomSecretsKeyFileException
├── TomSecretsKeyFile
├── TomSecretsOuterCipher (enum)
├── TomSecretsOuterException
├── TomSecretsRepositoryKey
└── TomSecretsOuterCodec
```

---

## Types

### TomSecretsKeyFileException

A key file that is not a KeePass 2.0 key file or whose hash is wrong.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsKeyFileException(message)` | — | A key-file problem described by `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong. |

---

### TomSecretsKeyFile

A KeePass 2.0 XML key file.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsKeyFile.generate({random})` | factory | A new key file of 32 random bytes from `random` (default: the OS's secure generator). |
| `TomSecretsKeyFile.fromKey(key)` | factory | The key file of the 32 bytes `key`. |
| `TomSecretsKeyFile.parse(bytes)` | factory | Reads a KeePass 2.0 key file's `bytes` and checks its hash. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `key` | `Uint8List` | The 32 bytes the key file contributes to the composite key. |
| `hash` | `String` | The first 4 bytes of the key's SHA-256, upper-case hex, as KeePass writes it in `Hash`. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toBytes()` | `Uint8List` | The file, as KeePass 2.5x writes it: the key in upper-case hex, in groups of 8 digits, two lines. |
| `credentials(password)` | `Credentials` | The credential of `password` plus this key file (`Credentials.composite`, which takes the file's bytes and derives the key itself, as KeePass does); a null `password` is the key file alone. |
| `dispose()` | `void` | Overwrites the key with zeros. |

---

### TomSecretsOuterCipher

The content and slot cipher of a repository.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `aes256Gcm` | AES-256-GCM, 96-bit random nonce per write; selectable per repository. |
| `xchacha20Poly1305` | XChaCha20-Poly1305, 192-bit random nonce; the default. |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `ofId(id)` | `TomSecretsOuterCipher?` | The cipher of header id `id`, or null. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `id` | `int` | The cipher id in the header. |
| `nonceLength` | `int` | The nonce length in bytes. |

---

### TomSecretsOuterException

A file that is not a `.tsmx` file, of a format or cipher this library does not read, or that fails its authentication (altered, truncated, or moved to another path).

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsOuterException(message)` | — | A problem described by `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong. |

---

### TomSecretsRepositoryKey

A 256-bit repository key.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsRepositoryKey.generate({random})` | factory | A new key from `random` (default: the OS's secure generator). |
| `TomSecretsRepositoryKey.fromBytes(bytes)` | factory | The key of 32 `bytes`. |
| `TomSecretsRepositoryKey.fromBase64(text)` | factory | The key of its base64 (as the primary vault keeps it, `tsm.outer-key`). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `bytes` | `Uint8List` | The key's bytes. |
| `keyId` | `Uint8List` | The first 8 bytes of SHA-256 over the key: the slot's key id. |
| `keyIdHex` | `String` | The key id as hex. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toBase64()` | `String` | The key as base64. |
| `dispose()` | `void` | Overwrites the key with zeros. |

---

### TomSecretsOuterCodec

The outer layer as the GitHub cycle's codec: decrypts with whichever of `keys` has a slot, encrypts with a slot for each of `keys` under `cipher`, for the file at `path` in its repository.

**Kind:** `final class` · **Implements:** `TomSecretsVaultCodec`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsOuterCodec({path, keys, cipher, random})` | — | A codec for `path` (the file's path in the repository, e.g. `vaults/fleet.kdbx.tsmx`). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `path` | `String` | The file's path in its repository (part of the authenticated data). |
| `keys` | `List<TomSecretsRepositoryKey>` | The repository keys held; every write gets a slot for each. |
| `cipher` | `TomSecretsOuterCipher` | The cipher of a new file. Once the codec decoded a file, it writes with that file's cipher (`written`): a rewrite never switches the repository's cipher. |
| `written` | `TomSecretsOuterCipher` | The cipher `encode` writes with. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `decode(bytes)` | `Future<Uint8List>` | The KDBX bytes of the stored `bytes`. |
| `encode(bytes)` | `Future<Uint8List>` | The stored bytes of the KDBX `bytes`. |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsOuterSuffix` | `String` | The suffix of an outer-encrypted vault file. |
| `tomSecretsOuterVersion` | `int` | The `.tsmx` format version this library writes and reads. |

### Functions

| Function | Signature | Description |
| --- | --- | --- |
| `tomSecretsOuterCipherOf` | `TomSecretsOuterCipher tomSecretsOuterCipherOf(Uint8List file)` | The cipher of the `.tsmx` `file`, read from its header without decrypting anything: a rewrite of the file keeps it (the cipher is the repository's). |
| `tomSecretsOuterKeyIds` | `List<String> tomSecretsOuterKeyIds(Uint8List file)` | The key ids of the slots of a `.tsmx` file, without decrypting anything. |
| `tomSecretsOuterEncrypt` | `Future<Uint8List> tomSecretsOuterEncrypt(Uint8List content, {required String path, required List<TomSecretsRepositoryKey> keys, TomSecretsOuterCipher cipher = TomSecretsOuterCipher.xchacha20Poly1305, Random? random})` | Encrypts `content` (the KDBX bytes) as a `.tsmx` file for `path`, with a fresh random file key wrapped under each of `keys` (phase A and B write one; the guided rotation writes two). |
| `tomSecretsOuterDecrypt` | `Future<Uint8List> tomSecretsOuterDecrypt(Uint8List file, {required String path, required List<TomSecretsRepositoryKey> keys})` | Decrypts the `.tsmx` `file` for `path` with whichever of `keys` has a slot. |
| `tomSecretsOuterCodecFor` | `TomSecretsOuterCodec? tomSecretsOuterCodecFor(String fileName, String? outerKey, {TomSecretsOuterCipher cipher = TomSecretsOuterCipher.xchacha20Poly1305})` | The outer layer of a vault file named `fileName`: a `.tsmx` file opened with `outerKey` (base64), written under `cipher` until it decodes a file (then under that file's), or null for a plain `.kdbx`. **[C]** `outerKey` may name several repository keys, `,`-separated, the newest first: the file opens with whichever has a slot, and every write gets a slot for each. |
| `tomSecretsOuterKeyList` | `List<String> tomSecretsOuterKeyList(String? outerKey)` | **[C]** The repository keys (base64) an outer key text names: one, or several separated by `,`, the newest first. |
| `tomSecretsJoinOuterKeys` | `String? tomSecretsJoinOuterKeys(Iterable<String?> keys)` | **[C]** `keys` (the newest first; nulls and repeats left out) as one outer key text, or null for none. |
| `tomSecretsVaultKeyIds` | `List<String> tomSecretsVaultKeyIds({List<int>? keyFile, String? outerKey})` | **[C]** The ids of a vault's keys as device records and rotation records name them: the key file's hash and each repository key's id. |
| `tomSecretsVaultCredentials` | `Credentials tomSecretsVaultCredentials({String? password, Uint8List? keyFile, Uint8List? compositeKey})` | The credentials of a vault with `password` and the bytes of a `keyFile`, either of them optional; or of its `compositeKey` alone (the OS unlock's), which takes the place of both. |
| `tomSecretsCompositeKey` | `Uint8List tomSecretsCompositeKey({String? password, Uint8List? keyFile})` | The 32-byte composite key of a password and a key file: what the OS unlock keeps instead of the password text; valid across saves, changed by a re-key. |
| `tomSecretsDecodeStored` | `Future<KdbxFile> tomSecretsDecodeStored(String locator, Uint8List stored, Credentials credentials, {String? outerKey})` | `stored`, the file at `locator` as its store keeps it, opened with `credentials` (and `outerKey` for a `.tsmx` file). Throws `KdbxInvalidKeyException` for wrong credentials, `TomKeyRequiredException` (`tom_core_storage`) when no outer key given opens it, and `TomSecretsOuterException` for a damaged outer layer. |
| `tomSecretsEncodeStored` | `Future<Uint8List> tomSecretsEncodeStored(String locator, KdbxFile file, {String? outerKey, Uint8List? like, TomSecretsOuterCipher cipher = TomSecretsOuterCipher.xchacha20Poly1305})` | `file` saved as the store at `locator` keeps it: its KDBX bytes, under the outer layer with `outerKey` for a `.tsmx` file. The outer layer keeps the cipher of `like` (the file as stored before, so a rewrite never switches the repository's cipher), else uses `cipher`. |
