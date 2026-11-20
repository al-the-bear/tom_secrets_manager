# Tom Secrets Core API Reference: Trust, Approvals and Pairing Module

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Types](#types)
  - [TomSecretsRecordedApprover](#tomsecretsrecordedapprover)
  - [TomSecretsRecordedHost](#tomsecretsrecordedhost)
  - [TomSecretsTrust](#tomsecretstrust)
  - [TomSecretsClientTokenRecord](#tomsecretsclienttokenrecord)
  - [TomSecretsSignedLabels](#tomsecretssignedlabels)
  - [TomSecretsApproverPublicKey](#tomsecretsapproverpublickey)
  - [TomSecretsApproverKey](#tomsecretsapproverkey)
  - [TomSecretsSignedKind](#tomsecretssignedkind)
  - [TomSecretsGrantsGroup](#tomsecretsgrantsgroup)
  - [TomSecretsTokenMatch](#tomsecretstokenmatch)
  - [TomSecretsLinkException](#tomsecretslinkexception)
  - [TomSecretsLinkPublicKey](#tomsecretslinkpublickey)
  - [TomSecretsLinkKey](#tomsecretslinkkey)
  - [TomSecretsLinkRandom](#tomsecretslinkrandom)
  - [TomSecretsSystemLinkRandom](#tomsecretssystemlinkrandom)
  - [TomSecretsLinkKeys](#tomsecretslinkkeys)
  - [TomSecretsLinkInitiator](#tomsecretslinkinitiator)
  - [TomSecretsLinkResponder](#tomsecretslinkresponder)
  - [TomSecretsLinkCipher](#tomsecretslinkcipher)
  - [TomSecretsApprovalChannel](#tomsecretsapprovalchannel)
  - [TomSecretsSocketChannel](#tomsecretssocketchannel)
  - [TomSecretsLinkFrameReader](#tomsecretslinkframereader)
  - [TomSecretsLinkSession](#tomsecretslinksession)
  - [TomSecretsPairingCode](#tomsecretspairingcode)
  - [TomSecretsSpake2Keys](#tomsecretsspake2keys)
  - [TomSecretsSpake2](#tomsecretsspake2)
  - [TomSecretsPairingVault](#tomsecretspairingvault)
  - [TomSecretsPairingToken](#tomsecretspairingtoken)
  - [TomSecretsPairingPeerKeys](#tomsecretspairingpeerkeys)
  - [TomSecretsPairingBundle](#tomsecretspairingbundle)
  - [TomSecretsPairingFailure](#tomsecretspairingfailure)
  - [TomSecretsPairingRefusal](#tomsecretspairingrefusal)
  - [TomSecretsPairingException](#tomsecretspairingexception)
  - [TomSecretsPairingReceived](#tomsecretspairingreceived)
  - [TomSecretsPairingGiven](#tomsecretspairinggiven)
  - [TomSecretsPairingWindow](#tomsecretspairingwindow)
  - [TomSecretsPairingReceipt](#tomsecretspairingreceipt)
  - [TomSecretsDeviceRecord](#tomsecretsdevicerecord)
  - [TomSecretsDeviceRecords](#tomsecretsdevicerecords)
  - [TomSecretsMemberFields](#tomsecretsmemberfields)
  - [TomSecretsMemberKeyFailure](#tomsecretsmemberkeyfailure)
  - [TomSecretsMemberKeyException](#tomsecretsmemberkeyexception)
  - [TomSecretsAgeRecipientKind](#tomsecretsagerecipientkind)
  - [TomSecretsAgeRecipient](#tomsecretsagerecipient)
  - [TomSecretsMemberKey](#tomsecretsmemberkey)
  - [TomSecretsReceivedMemberKey](#tomsecretsreceivedmemberkey)
  - [TomSecretsMember](#tomsecretsmember)
  - [TomSecretsAgeFailure](#tomsecretsagefailure)
  - [TomSecretsAgeException](#tomsecretsageexception)
  - [TomSecretsAgeIdentity](#tomsecretsageidentity)
  - [TomSecretsAgeHybridIdentity](#tomsecretsagehybrididentity)
  - [TomSecretsAgeX25519Identity](#tomsecretsagex25519identity)
  - [TomSecretsAgePassphraseIdentity](#tomsecretsagepassphraseidentity)
  - [TomSecretsSharedVaultMember](#tomsecretssharedvaultmember)
  - [TomSecretsSharedVaultFailure](#tomsecretssharedvaultfailure)
  - [TomSecretsSharedVaultException](#tomsecretssharedvaultexception)
  - [TomSecretsSharedVaultKeys](#tomsecretssharedvaultkeys)
  - [TomSecretsRotationKind](#tomsecretsrotationkind)
  - [TomSecretsRotationException](#tomsecretsrotationexception)
  - [TomSecretsRotation](#tomsecretsrotation)
  - [TomSecretsRotations](#tomsecretsrotations)
  - [TomSecretsShareFailure](#tomsecretssharefailure)
  - [TomSecretsShareException](#tomsecretsshareexception)
  - [TomSecretsSharedField](#tomsecretssharedfield)
  - [TomSecretsSharedAttachment](#tomsecretssharedattachment)
  - [TomSecretsSharedEntry](#tomsecretssharedentry)
  - [TomSecretsShareSender](#tomsecretssharesender)
  - [TomSecretsShare](#tomsecretsshare)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The sharing module holds everything one device of the user's fleet needs to trust another: a device's trust material (approver, link and audit-log keys, the approvers and hosts it recorded) with key rotation; signed objects (grants, revocations, approval records, key-change statements) signed with Ed25519 and ML-DSA-65; the grants group of the primary vault; the approval code and its single-use token; the approval link (Noise KK with ML-KEM-768 paired to every Diffie-Hellman, ChaCha20-Poly1305 transport); pairing by a short code through SPAKE2 (RFC 9382) with an ML-KEM-768 exchange inside; the device records of the primary vault; and, for sharing with people (phase C), the member keys: hybrid `age` v1.3 identities and recipients (`age1pq1…`, X25519 + ML-KEM-768), other people's classical recipients for exports, the published key file, and the `member-key` and `member` entries of the primary vault's `tsm.sharing` group; the `age` v1 file format (hybrid and classical recipients, a passphrase, armour); shared vaults with their recipients file; the rotation records of the guided rotation with a migration period; and single-entry exports (shares) with the inbox folders that carry them.

Source files: `lib/src/trust.dart`, `lib/src/signed_objects.dart`, `lib/src/grants.dart`, `lib/src/approval_code.dart`, `lib/src/approval_link.dart`, `lib/src/pairing.dart`, `lib/src/pairing_setup.dart`, `lib/src/pairing_words.dart`, `lib/src/device_records.dart`, `lib/src/member_keys.dart`, `lib/src/age.dart`, `lib/src/shared_vault.dart`, `lib/src/rotation.dart`.

---

## Class Hierarchy

```text
Object
├── TomSecretsRecordedApprover
├── TomSecretsRecordedHost
├── TomSecretsTrust
├── TomSecretsClientTokenRecord
├── TomSecretsSignedLabels
├── TomSecretsApproverPublicKey
├── TomSecretsApproverKey
├── TomSecretsSignedKind (enum)
├── TomSecretsGrantsGroup
├── TomSecretsTokenMatch (typedef)
├── TomSecretsLinkException
├── TomSecretsLinkPublicKey
├── TomSecretsLinkKey
├── TomSecretsLinkRandom
│   └── TomSecretsSystemLinkRandom (implements)
├── TomSecretsLinkKeys
├── TomSecretsLinkInitiator
├── TomSecretsLinkResponder
├── TomSecretsLinkCipher
├── TomSecretsApprovalChannel
│   └── TomSecretsSocketChannel (implements)
├── TomSecretsLinkFrameReader
├── TomSecretsLinkSession
├── TomSecretsPairingCode
├── TomSecretsSpake2Keys
├── TomSecretsSpake2
├── TomSecretsPairingVault
├── TomSecretsPairingToken
├── TomSecretsPairingPeerKeys
├── TomSecretsPairingBundle
├── TomSecretsPairingFailure (enum)
├── TomSecretsPairingRefusal
├── TomSecretsPairingException
├── TomSecretsPairingReceived
├── TomSecretsPairingGiven
├── TomSecretsPairingWindow
├── TomSecretsPairingReceipt
├── TomSecretsDeviceRecord
├── TomSecretsDeviceRecords
├── TomSecretsMemberFields
├── TomSecretsMemberKeyFailure (enum)
├── TomSecretsMemberKeyException
├── TomSecretsAgeRecipientKind (enum)
├── TomSecretsAgeRecipient
├── TomSecretsMemberKey
├── TomSecretsReceivedMemberKey (typedef)
├── TomSecretsMember
├── TomSecretsAgeFailure (enum)
├── TomSecretsAgeException
├── TomSecretsAgeIdentity (sealed)
├── TomSecretsAgeHybridIdentity
├── TomSecretsAgeX25519Identity
├── TomSecretsAgePassphraseIdentity
├── TomSecretsSharedVaultMember (typedef)
├── TomSecretsSharedVaultFailure (enum)
├── TomSecretsSharedVaultException
├── TomSecretsSharedVaultKeys
├── TomSecretsRotationKind (enum)
├── TomSecretsRotationException
├── TomSecretsRotation
├── TomSecretsRotations
├── TomSecretsShareFailure (enum)
├── TomSecretsShareException
├── TomSecretsSharedField (typedef)
├── TomSecretsSharedAttachment (typedef)
├── TomSecretsSharedEntry
├── TomSecretsShareSender (typedef)
└── TomSecretsShare
```

---

## Types

### TomSecretsRecordedApprover

An approver device a host recorded at pairing.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsRecordedApprover({device, approverKey, tokenKey, linkKey, previousLinkKey, approverKeySince, linkKeySince})` | — | The approver `device` with its `approverKey`, its `linkKey` (null when it never connects over the link), the `tokenKey` the two share, a link key it replaced and is still accepted during the migration period (`previousLinkKey`), and since when each key is recorded (`approverKeySince`, `linkKeySince`). |
| `TomSecretsRecordedApprover.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `device` | `String` | The approver's device id. |
| `approverKey` | `TomSecretsApproverPublicKey` | Its approver public key. |
| `linkKey` | `TomSecretsLinkPublicKey?` | Its approval-link public key. |
| `previousLinkKey` | `TomSecretsLinkPublicKey?` | The link key it replaced, accepted for the migration period. |
| `tokenKey` | `Uint8List` | The approval-token key (32 bytes). |
| `approverKeySince` | `DateTime?` | When `approverKey` was recorded (at pairing, or its key change): the start of its rotation age. |
| `linkKeySince` | `DateTime?` | When `linkKey` was recorded (at pairing, or a new link key). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The stored JSON. |

---

### TomSecretsRecordedHost

A host this device approves for (recorded at pairing on the approver).

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsRecordedHost({host, linkKey, tokenKey, address, linkKeySince, linkKeyDelivered})` | — | The `host` with its `linkKey`, the `tokenKey` the two share, the `address` (`host:port`) its link listens on, and since when the link key is recorded (`linkKeySince`). |
| `TomSecretsRecordedHost.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `host` | `String` | The host's name. |
| `linkKey` | `TomSecretsLinkPublicKey` | Its approval-link public key. |
| `tokenKey` | `Uint8List` | The approval-token key (32 bytes). |
| `address` | `String?` | Where its link listens (`address:port`), when known. |
| `linkKeySince` | `DateTime?` | When `linkKey` was recorded (at pairing, or a new link key). |
| `linkKeyDelivered` | `bool` | Whether this device's current approval-link key reached the host (`linkKey` over the link): until then this device connects to it with its previous link key, during the migration period. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The stored JSON. |

---

### TomSecretsTrust

A device's trust material.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsTrust.create(device, {now})` | factory | New trust material for `device`: fresh key pairs (created `now`, default the current time) and audit-log key, no approver or host recorded, command-line approvals off. |
| `TomSecretsTrust.fromJson(json)` | factory | From the stored JSON. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `device` | `String` | This device's id (its approver identity at pairing). |
| `previousLinkUntil` | `DateTime?` | Until when the previous link key is used (`rotateLinkKey`). |
| `auditKey` | `Uint8List` | The audit-log key (32 bytes, XChaCha20-Poly1305). |
| `approvers` | `List<TomSecretsRecordedApprover>` | The approvers this host recorded at pairing. |
| `hosts` | `List<TomSecretsRecordedHost>` | The hosts this device approves for. |
| `cliApprovals` | `bool` | Whether `tsm` on this device may pre-approve and issue tokens; switched only from the manager app. |
| `approverKeySince` | `DateTime?` | When this device's approver key pair was created: the start of its rotation age; null in trust material written before the date was kept (`stampKeyDates`). |
| `linkKeySince` | `DateTime?` | When this device's approval-link key pair was created. |
| `pins` | `Map<String, String>` | The SHA-256 recorded for each pinned grant of this host (grant id → hex): a grant's signed members carry no hash, and the host keeps it here, out of the synced vault, so no one who can write the vault can move a pin. |
| `clientTokens` | `Map<String, TomSecretsClientTokenRecord>` | The client tokens of this host's `exe-token` grants (token id → record): only the token's hash, never the token. |
| `linkKeyPending` | `List<TomSecretsRecordedHost>` | The hosts the current link key has not reached yet while the previous one is in use. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `recordPeer({device, tokenKey, at, approverKey, approverLinkKey, hostLinkKey, hostAddress})` | `void` | Records what a pairing with the peer `device` gave: it approves for this host with `approverKey` (reached over the approval link with `approverLinkKey`), and this device approves for it as a host with `hostLinkKey` at `hostAddress`; `tokenKey` is the approval-token key both sides derived. |
| `stampKeyDates(now)` | `bool` | Gives every key without a recorded date the date `now`: trust material written before the dates were kept counts its keys' age from then. Whether anything changed (the caller writes the trust back). |
| `clientTokenIdOf(hash)` | `String?` | The token id whose hash is `hash` (hex), or null. |
| `approverKey()` | `Future<TomSecretsApproverKey>` | This device's approver key pair. |
| `linkKey()` | `Future<TomSecretsLinkKey>` | This device's approval-link key pair. |
| `rotateApproverKey({now})` | `Future<Map<String, Object?>>` | Rotates this device's approver key pair: a new hybrid pair (Ed25519 + ML-DSA-65) replaces it from `now` on, and the key-change statement (9.4, `tsm-keychange-v1`) is answered, signed by the old and the new pair with both algorithms (four signatures). |
| `rotateLinkKey({now, migration})` | `void` | Rotates this device's approval-link key pair: a new pair from `now` on; the previous one stays in use for every recorded host until the new key reached it (`markLinkKeyDelivered`) or `migration` is over. |
| `linkKeyFor(host, {now})` | `Future<TomSecretsLinkKey>` | The link key pair this device connects to `host` with at `now`: the current one, or the previous one while the new one has not reached that host and the migration period lasts. |
| `previousLinkKey({now})` | `Future<TomSecretsLinkKey?>` | The previous link key pair while the migration period lasts at `now` (an approver that still holds it is answered under it), else null. |
| `markLinkKeyDelivered(host)` | `void` | Records that the current link key reached `host`; once every host has it, and no approver connects to this device, the previous key is dropped. |
| `expirePreviousLinkKey(now)` | `bool` | Drops the previous link key when every host has the new one or the migration period is over at `now`; whether it dropped it. |
| `grantKeys()` | `Future<List<TomSecretsApproverPublicKey>>` | The approver keys a grant on this host may be signed by: every recorded approver's, and this device's own (the attached app approves through this service, which signs). |
| `approver(device)` | `TomSecretsRecordedApprover?` | The recorded approver of `device`, or null. |
| `host(host)` | `TomSecretsRecordedHost?` | The recorded host `host`, or null. |
| `toJson()` | `Map<String, Object?>` | The stored JSON. |

---

### TomSecretsClientTokenRecord

What a host keeps of a client token: its `hash`, when it was `created`, and the identity of the client that first and last brought it in `hello.clientToken` (so access can later be narrowed to it).

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsClientTokenRecord({hash, created, firstIdentity, lastIdentity, lastSeen})` | — | A record of `hash`. |
| `TomSecretsClientTokenRecord.fromJson(json)` | factory | From the stored JSON. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `hash` | `String` | The token's hash (hex). |
| `created` | `DateTime` | When the host received it. |
| `firstIdentity` | `Map<String, Object?>?` | The measured identity of the first client that brought it. |
| `lastIdentity` | `Map<String, Object?>?` | The measured identity of the last client that brought it. |
| `lastSeen` | `DateTime?` | When a client last brought it. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The stored JSON. |

---

### TomSecretsSignedLabels

The domain labels of the signed objects.

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `grant` | `String` | A grant. |
| `revoke` | `String` | A revocation. |
| `approval` | `String` | An approval record. |
| `keyChange` | `String` | A key-change statement. |
| `approverKey` | `String` | An approver key's id. |

---

### TomSecretsApproverPublicKey

The public half of an approver key, as a host records it at pairing.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsApproverPublicKey(ed25519, mlDsa65)` | — | The key of `ed25519` (32 bytes) and `mlDsa65` (1,952 bytes). |
| `TomSecretsApproverPublicKey.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `ed25519` | `Uint8List` | The Ed25519 public key. |
| `mlDsa65` | `Uint8List` | The ML-DSA-65 public key. |
| `keyId` | `String` | Its key id. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | `{ed25519, mlDsa65}` in base64. |

---

### TomSecretsApproverKey

An approver key pair: an Ed25519 and an ML-DSA-65 key used together, made from two 32-byte seeds (which the device settings keep).

**Kind:** `final class`

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fromSeeds(ed25519Seed, mlDsaSeed)` | `Future<TomSecretsApproverKey>` | The pair from its seeds. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `publicKey` | `TomSecretsApproverPublicKey` | The public half. |
| `keyId` | `String` | Its key id. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `sign(label, bytes)` | `Future<List<Map<String, Object?>>>` | The two signature items of `bytes` under `label` (9.3): Ed25519, and ML-DSA-65 hedged with `label` as its context. |
| `signObject(label, object)` | `Future<Map<String, Object?>>` | `object` (of `label`) with its `signatures` made by this key. |

---

### TomSecretsSignedKind

The kind of a signed object in the grants group.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `grant` | A grant (7.3). |
| `revocation` | A revocation. |
| `approval` | An approval record (an answer to a waiting code). |
| `keyChange` | A key-change statement. |

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `extraFields` | `List` | The members besides the signed ones that the entry keeps. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `wireName` | `String` | The `tsm.kind` field's value. |
| `label` | `String` | The signed object's domain label. |

---

### TomSecretsGrantsGroup

The grants group of a primary vault `file`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsGrantsGroup(file)` | — | The group of `file`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `file` | `KdbxFile` | The primary vault. |
| `hosts` | `List<String>` | The hosts that have a subgroup. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `read(host, kind)` | `List<Map<String, Object?>>` | The objects of `kind` in `host`'s subgroup, as stored (signatures not yet checked: the reader accepts them against its recorded keys). |
| `write(host, kind, object)` | `void` | Writes `object` (of `kind`, signed) into `host`'s subgroup, replacing an entry for the same object. |
| `setLastUsed(host, grantId, time)` | `bool` | Sets the unsigned `lastUsed` of the grant `grantId` in `host`'s subgroup; whether the grant was there. |
| `remove(host, kind, o)` | `bool` | Removes `kind`'s entry of `title` (as `read` names it) from `host`'s subgroup; whether one was there. |

---

### TomSecretsTokenMatch

What a token answers (9.6): the request waiting with `code`, with `decision`.

**Kind:** `typedef`

```dart
typedef TomSecretsTokenMatch = ({String code, String decision});
```

---

### TomSecretsLinkException

The handshake or the transport failed: the link closes.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLinkException(message)` | — | A failure: `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What failed. |

---

### TomSecretsLinkPublicKey

The public half of a link key: X25519 and ML-KEM-768, as pairing records it.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLinkPublicKey(x25519, mlKem768)` | const | The key of `x25519` (32 bytes) and `mlKem768` (1,184 bytes). |
| `TomSecretsLinkPublicKey.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `x25519` | `Uint8List` | The X25519 public key. |
| `mlKem768` | `Uint8List` | The ML-KEM-768 encapsulation key. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | `{x25519, mlKem768}` in base64. |
| `sameAs(other)` | `bool` | Whether both halves are `other`'s. |

---

### TomSecretsLinkKey

One side's static link key: X25519 and ML-KEM-768, from two 32-byte seeds (which the device settings keep; the ML-KEM seed is FIPS 203's 64 bytes, d \|\| z).

**Kind:** `final class`

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fromSeeds(x25519Seed, mlKemSeed)` | `Future<TomSecretsLinkKey>` | The key of `x25519Seed` (32 bytes) and `mlKemSeed` (64 bytes). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `publicKey` | `TomSecretsLinkPublicKey` | The public half. |

---

### TomSecretsLinkRandom

The randomness of a handshake: system randomness by default; the tests give the vectors' seeds and coins.

**Kind:** `abstract interface class`

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `ephemeralX25519()` | `Future<SimpleKeyPair>` | A fresh ephemeral X25519 key. |
| `ephemeralMlKem()` | `MlKem768KeyPair` | A fresh ephemeral ML-KEM-768 key. |
| `encapsulate(publicKey)` | `MlKem768Encapsulation` | An encapsulation to `publicKey`. |

---

### TomSecretsSystemLinkRandom

System randomness.

**Kind:** `final class` · **Implements:** `TomSecretsLinkRandom`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsSystemLinkRandom()` | const | The randomness. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `ephemeralX25519()` | `Future<SimpleKeyPair>` | A fresh ephemeral X25519 key. |
| `ephemeralMlKem()` | `MlKem768KeyPair` | A fresh ephemeral ML-KEM-768 key. |
| `encapsulate(publicKey)` | `MlKem768Encapsulation` | An encapsulation to `publicKey`. |

---

### TomSecretsLinkKeys

What a finished handshake yields.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `initiatorToResponder` | `Uint8List` | The approver-to-host key. |
| `responderToInitiator` | `Uint8List` | The host-to-approver key. |
| `handshakeHash` | `Uint8List` | The final handshake hash. |

---

### TomSecretsLinkInitiator

The approver's side of the handshake (the initiator, who connects).

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLinkInitiator(me, responder, {random})` | — | The approver `me` connecting to the host whose recorded key is `responder`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `me` | `TomSecretsLinkKey` | This approver's static key. |
| `responder` | `TomSecretsLinkPublicKey` | The host's recorded public key. |
| `random` | `TomSecretsLinkRandom` | The randomness. |
| `handshakeHash` | `Uint8List` | The handshake hash so far. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `writeMessage1(payload)` | `Future<Uint8List>` | Message 1: e (32) \|\| ephemeral ML-KEM key (1,184) \|\| ciphertext to the host's static ML-KEM key (1,088) \|\| the encrypted `payload`. |
| `readMessage2(message)` | `Future<(Uint8List, TomSecretsLinkKeys)>` | Reads message 2: its payload and the session keys. |

---

### TomSecretsLinkResponder

The host's side of the handshake (the responder).

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLinkResponder(me, initiator, {random})` | — | The host `me` answering an approver whose recorded key is `initiator`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `me` | `TomSecretsLinkKey` | This host's static key. |
| `initiator` | `TomSecretsLinkPublicKey` | The approver's recorded public key. |
| `random` | `TomSecretsLinkRandom` | The randomness. |
| `handshakeHash` | `Uint8List` | The handshake hash so far. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `readMessage1(message)` | `Future<Uint8List>` | Reads message 1: its payload. Throws `TomSecretsLinkException` when it does not come from `initiator`. |
| `writeMessage2(payload)` | `Future<(Uint8List, TomSecretsLinkKeys)>` | Message 2: e (32) \|\| ciphertext to the approver's ephemeral ML-KEM key (1,088) \|\| ciphertext to its static ML-KEM key (1,088) \|\| the encrypted `payload`; and the session keys. |

---

### TomSecretsLinkCipher

One direction of the transport: ChaCha20-Poly1305 with a counter nonce, empty associated data, REKEY on demand.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLinkCipher(key)` | — | A cipher under `key`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `key` | `Uint8List` | The current key. |
| `n` | `int` | The counter. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `encrypt(plaintext)` | `Future<Uint8List>` | The ciphertext of `plaintext`. |
| `decrypt(ciphertext)` | `Future<Uint8List>` | The plaintext of `ciphertext`; throws `TomSecretsLinkException`. |
| `rekey()` | `Future<void>` | Replaces the key by Noise's REKEY; the counter goes on. |

---

### TomSecretsApprovalChannel

The approval link's byte stream: a TCP connection in phase A, the relay in phase C.

**Kind:** `abstract interface class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `incoming` | `Stream<List<int>>` | The bytes that arrive. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `send(bytes)` | `void` | Sends `bytes`. |
| `close()` | `Future<void>` | Ends the channel. |

---

### TomSecretsSocketChannel

A channel over a TCP `Socket`.

**Kind:** `final class` · **Implements:** `TomSecretsApprovalChannel`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsSocketChannel(socket)` | — | The channel of `socket`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `socket` | `Socket` | The socket. |
| `incoming` | `Stream<List<int>>` | The bytes that arrive. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `send(bytes)` | `void` | Sends `bytes`. |
| `close()` | `Future<void>` | Ends the channel. |

---

### TomSecretsLinkFrameReader

The frames of a channel read one by one (`next`), for the protocols that share the approval link's framing (pairing): a frame over 1 MiB, or the channel's end, ends it.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLinkFrameReader(channel)` | — | The reader of `channel`'s frames. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `next(timeout)` | `Future<Uint8List?>` | The next frame, or null when the channel ended or `timeout` passed. |
| `cancel()` | `Future<void>` | Stops reading. |

---

### TomSecretsLinkSession

An established approval link: JSON messages both ways, encrypted per direction, `rekey` handled, closed on any failure.

**Kind:** `final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `rekeyFrames` | `int` | After how many frames, or how long, a side sends `rekey` (9.7). |
| `rekeyAge` | `Duration` | See `rekeyFrames`. |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `initiate(channel, {me, hostKey, device, random, timeout})` | `Future<TomSecretsLinkSession>` | The approver's side: the handshake with the host recorded as `hostKey`, sending `device` (this approver's device id); then `ready`. Throws `TomSecretsLinkException` when the host is not the recorded one. |
| `respond(channel, {me, approvers, host, previousMe, random, timeout})` | `Future<TomSecretsLinkSession>` | The host's side: reads message 1 from one of the `approvers` (a device id with a recorded link key; a device may appear twice, its previous key during the migration period), answers as `host`, and waits for `ready`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `peerDevice` | `String` | The peer: the approver's device id (on the host) or the host's name (on the approver). |
| `underPreviousKey` | `bool` | On the host: whether the approver connected under the host's previous link key (`respond(previousMe:)`) — it does not know the new one yet, and the host passes it (`linkKey`). Always false on the approver. |
| `handshakeHash` | `Uint8List` | The handshake hash. |
| `messages` | `Stream<Map<String, Object?>>` | The messages the peer sends (`rekey` is handled here, not passed on). |
| `isClosed` | `bool` | Whether the link has ended. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `send(message)` | `Future<void>` | Sends `message` (JSON with `op`); after `rekeyFrames` frames or `rekeyAge` it sends `rekey` first and replaces its key. |
| `close()` | `Future<void>` | Ends the link. |

---

### TomSecretsPairingCode

A pairing code: `<number>-<word>-<word>` (e.g. `7-guitar-orbit`), the number 1..999 (it finds the giving side, e.g. in its mDNS record), the words from `tomSecretsPairingWords`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPairingCode(number, words)` | — | The code of `number` and `words`. |
| `TomSecretsPairingCode.generate({random})` | factory | A fresh random code. |
| `TomSecretsPairingCode.parse(text)` | factory | The code typed as `text`: spaces and case do not matter; throws `FormatException` for anything else. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `number` | `int` | The number. |
| `words` | `List<String>` | The two words. |
| `text` | `String` | `<number>-<word>-<word>`. |
| `w` | `BigInt` | SPAKE2's w: HKDF-SHA-256 over `text` (salt `tsm-pair-code-v1`), 40 bytes (64 bits more than the group order's), reduced mod the order (RFC 9382 §3.2). The code is one-time and an attacker gets one guess at it, so no memory-hard function is needed. |

---

### TomSecretsSpake2Keys

What SPAKE2 derives (RFC 9382 §4): the shared secret `ke`, the transcript `tt`, and both confirmation MACs.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `ke` | `Uint8List` | Ke, the shared secret (16 bytes). |
| `tt` | `Uint8List` | TT, the transcript. |
| `confirmA` | `Uint8List` | cA = MAC(KcA, TT). |
| `confirmB` | `Uint8List` | cB = MAC(KcB, TT). |

---

### TomSecretsSpake2

One side of SPAKE2-P256-SHA256-HKDF-HMAC: A (the receiving side, uses M) or B (the giving side, uses N).

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsSpake2.a(w, {a, b, x})` | factory | Side A with password scalar `w`, identities `a` and `b`; `x` is its secret scalar (random when not given; given only by tests). |
| `TomSecretsSpake2.b(w, {a, b, y})` | factory | Side B; see `TomSecretsSpake2.a`. |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `withAad<T>(aad, body)` | `T` | Runs `body` with SPAKE2's AAD set to `aad` (the RFC's test vectors use none); for tests only. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `Uint8List` | This side's message: pA = w*M + x*P, or pB = w*N + y*P (uncompressed). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `finish(peer)` | `TomSecretsSpake2Keys` | The keys from the peer's message `peer` (pB on A, pA on B). Throws `FormatException` for a message that is no point of the curve or is the identity. |

---

### TomSecretsPairingVault

One vault the bundle hands over: its locator and the keys a device needs beyond the master password.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPairingVault({name, locator, primary, keyFile, repositoryKey})` | const | The vault `name` at `locator`. |
| `TomSecretsPairingVault.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `name` | `String` | Its store name. |
| `locator` | `String` | Its locator. |
| `primary` | `bool` | Whether it is the primary. |
| `keyFile` | `Uint8List?` | Its key file's bytes, or null. |
| `repositoryKey` | `String?` | Its repository key (base64), or null. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The JSON the bundle carries. |

---

### TomSecretsPairingToken

A GitHub token the user pasted on the giving side for the receiving device: never the giving side's own.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPairingToken({repository, token, expires})` | const | The `token` for `repository` (`owner/name`), expiring at `expires`. |
| `TomSecretsPairingToken.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `repository` | `String` | The repository. |
| `token` | `String` | The token. |
| `expires` | `DateTime?` | Its expiry, or null. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The JSON the bundle carries. |

---

### TomSecretsPairingPeerKeys

A device's public keys for the approvals: its approver key pair (null when it is no approver) and its approval-link key, with the address its link listens on (null when it does not listen).

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPairingPeerKeys({linkKey, approverKey, linkAddress})` | const | The keys. |
| `TomSecretsPairingPeerKeys.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `linkKey` | `TomSecretsLinkPublicKey` | The approval-link public key. |
| `approverKey` | `TomSecretsApproverPublicKey?` | The approver public key, or null for a device that approves nothing. |
| `linkAddress` | `String?` | Where its approval link listens (`address:port`), or null. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The JSON. |

---

### TomSecretsPairingBundle

What the giving side hands over (the pairing bundle): the vaults chosen with their keys, the shared configuration, a token pasted for this device, and the giving device's public keys. Never a private approver or link key, a master password, the allow list or the audit log.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPairingBundle({vaults, giverKeys, configYaml, tokens})` | const | A bundle. |
| `TomSecretsPairingBundle.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `vaults` | `List<TomSecretsPairingVault>` | The vaults, the primary among them when it was chosen. |
| `giverKeys` | `TomSecretsPairingPeerKeys` | The giving device's public keys. |
| `configYaml` | `String?` | The dimension configuration (`tsm.config`), or null. |
| `tokens` | `List<TomSecretsPairingToken>` | Tokens pasted for the receiving device. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The JSON sent. |

---

### TomSecretsPairingFailure

Why a pairing ended without a result.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `wrongCode` | The code did not match (the key confirmation failed); the code is burnt. |
| `declined` | The giving side's user declined the device. |
| `version` | The peer speaks another protocol version. |
| `protocol` | The peer sent something the protocol does not expect, or a frame did not open. |
| `closed` | The channel ended or a step timed out. |
| `refused` | The receiving device refused the bundle (it cannot be set up from it, `TomSecretsPairingRefusal`); nothing was stored there. |

---

### TomSecretsPairingRefusal

Thrown by a receiving side's `keysFor` that cannot take the bundle (a new machine needs the primary, a `github:` primary its token): the giving side is told `reason` and the pairing ends with `TomSecretsPairingFailure.refused` on both sides.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPairingRefusal(reason)` | const | A refusal for `reason`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `reason` | `String` | Why, for the user on both sides. |

---

### TomSecretsPairingException

A pairing that ended without a result.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPairingException(failure, message)` | const | A failure of `failure` with `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `failure` | `TomSecretsPairingFailure` | Why. |
| `message` | `String` | For the user and the log. |

---

### TomSecretsPairingReceived

What a pairing gave the receiving side.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `giver` | `String` | The giving device's name. |
| `bundle` | `TomSecretsPairingBundle` | The bundle. |
| `tokenKey` | `Uint8List` | The approval-token key both sides derived (32 bytes). |

---

### TomSecretsPairingGiven

What a pairing gave the giving side.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `receiver` | `String` | The receiving device's name. |
| `receiverKeys` | `TomSecretsPairingPeerKeys` | The receiving device's public keys. |
| `tokenKey` | `Uint8List` | The approval-token key both sides derived (32 bytes). |

---

### TomSecretsPairingWindow

The giving side's pairing window: it listens on the addresses given (the LAN and VPN ones, `tomSecretsPairingAddresses`), takes the first connection and runs `tomSecretsGivePairing` over it. Any further connection is refused, and the window closes after that one attempt (the code is burnt, right or wrong) or when `window` ends.

**Kind:** `final class`

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `open({addresses, code, device, bundleFor, port, window, stepTimeout, allowLoopback})` | `Future<TomSecretsPairingWindow>` | Opens a window on `addresses` (at `port`, 0: one the system picks) for `code`, this machine being `device`; `bundleFor` as for `tomSecretsGivePairing`. Throws `ArgumentError` for an address that is no LAN or VPN address, `SocketException` when none can be bound. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `port` | `int` | The port it listens on (the same on every address). |
| `addresses` | `List<InternetAddress>` | The addresses it listens on. |
| `result` | `Future<TomSecretsPairingGiven>` | What the pairing gave, or the `TomSecretsPairingException` it ended with (`closed` when the window ended without a connection). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `close()` | `Future<void>` | Closes the window (a pairing already running goes on). |

---

### TomSecretsPairingReceipt

A pairing received by a machine being set up, held in memory until the setup: the bundle, the approval-token key, and this machine's fresh trust material (whose public keys the giving side recorded).

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `received` | `TomSecretsPairingReceived` | What the pairing gave. |
| `trust` | `TomSecretsTrust` | This machine's trust material, made for the pairing. |
| `giver` | `String` | The giving device's name. |
| `bundle` | `TomSecretsPairingBundle` | The bundle. |
| `primary` | `TomSecretsPairingVault` | The primary vault of the bundle. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `tokenFor(repository)` | `TomSecretsPairingToken?` | The token pasted for `repository` (`owner/name`), or null. |

---

### TomSecretsDeviceRecord

One paired device.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsDeviceRecord({device, paired, platform, pairedBy, keyIds, approverKeyId, approverKeySince, linkKeySince, revoked, githubAuth, githubTokenExpires})` | const | A record of `device`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `device` | `String` | The device's name. |
| `platform` | `String?` | Its platform (`macos`, `linux`, `windows`, …), when known. |
| `paired` | `DateTime` | When it was paired (last). |
| `pairedBy` | `String?` | The device that paired it. |
| `keyIds` | `List<String>` | The ids of the keys it received: the key files' hashes and the repository keys' ids. |
| `approverKeyId` | `String?` | Its approver key's id, when it approves. |
| `approverKeySince` | `DateTime?` | Since when its approver key pair is in use. |
| `linkKeySince` | `DateTime?` | Since when its approval-link key pair is in use. |
| `revoked` | `DateTime?` | When it was revoked, or null. |
| `isRevoked` | `bool` | Whether it was revoked. |
| `githubAuth` | `TomSecretsGitHubAuth?` | How it reaches GitHub: `app` (signed in with the GitHub App) or `token` (a pasted fine-grained token), when it said so. |
| `githubTokenExpires` | `DateTime?` | When its GitHub token expires (a signed-in device: its refresh token). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The record as the wire carries it (`pair.list`). |
| `withGitHub(auth, expires)` | `TomSecretsDeviceRecord` | This record with `githubAuth` and `githubTokenExpires` replaced. |

---

### TomSecretsDeviceRecords

The device records of the primary vault `file`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsDeviceRecords(file)` | — | The records of `file`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `file` | `KdbxFile` | The primary vault. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `list()` | `List<TomSecretsDeviceRecord>` | Every record, in file order. |
| `byDevice(device)` | `TomSecretsDeviceRecord?` | The record of `device`, or null. |
| `put(record)` | `void` | Writes `record`, replacing the record of the same device (a device paired again is updated, never duplicated). |
| `setGitHub(device, auth, expires)` | `bool` | Records how `device` reaches GitHub; whether it had a record and it changed. |
| `takeKeyIds(device, ids, {required now})` | `bool` | **[C]** Records that `device` holds the keys `ids` (a guided rotation's next keys it took); a device without a record gets one, paired at `now`. Whether the record changed. |
| `missingKey(keyId)` | `List<TomSecretsDeviceRecord>` | **[C]** The devices not revoked that do not hold the key `keyId`: those a guided rotation still waits for. |
| `revoke(device, at)` | `bool` | Marks `device` revoked at `at`; whether it had a record. |

---

### TomSecretsMemberFields

The fields of the `member-key` and `member` entries.

**Kind:** `abstract final class`

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `recipient` | `KdbxKey` | `tsm.recipient`: the `age` recipient string (`age1pq1…`, or a member's `age1…`). |
| `fingerprint` | `KdbxKey` | `tsm.fingerprint`: the recipient's fingerprint, for display in other KeePass programs. |
| `checked` | `KdbxKey` | `tsm.checked`: when the user compared a member's fingerprint with its owner (an ISO 8601 date), absent until then. |

---

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

### TomSecretsMember

A received public key in the primary vault (a `member` entry).

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `entry` | `KdbxEntry` | The entry. |
| `recipient` | `TomSecretsAgeRecipient` | The member's public key. |
| `name` | `String` | The name the user gave the member (the entry's title). |
| `checked` | `DateTime?` | When the user compared the fingerprint with the member, or null. |
| `canJoinSharedVaults` | `bool` | Whether the key can join shared vaults (hybrid), not only receive exports (classical). |

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

### TomSecretsSharedVaultMember

One member a shared vault's recipients file is written for: `({String name, TomSecretsAgeRecipient recipient})`.

**Kind:** `typedef`

---

### TomSecretsSharedVaultFailure

Why a shared vault's keys could not be read or written.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `notAMember` | The recipients file is not for this member key. |
| `malformed` | The recipients file opens but holds no readable keys. |
| `members` | A member without a hybrid key, no member, or one twice. |

---

### TomSecretsSharedVaultException

A refused recipients file or member change.

**Kind:** `final class`

#### Members

| Constructor / Property | Type | Description |
| --- | --- | --- |
| `TomSecretsSharedVaultException(reason, message)` | const | A refusal for `reason`, told by `message`. |
| `reason` | `TomSecretsSharedVaultFailure` | Why. |
| `message` | `String` | For people; never a key. |

---

### TomSecretsSharedVaultKeys

What a shared vault's recipients file holds: the vault's keys (a key file, a repository key when outer encrypted) and its members.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsSharedVaultKeys.generate(vault, {members, outer = false})` | factory | New keys (a fresh KeePass key file of 32 random bytes; a fresh repository key when `outer`) for `members`. |
| `TomSecretsSharedVaultKeys.fromJson(json)` | factory | The keys of a recipients file's plaintext; throws `TomSecretsSharedVaultException` (`malformed`). |
| `vault` | `String` | The vault's store name. |
| `keyFile` | `Uint8List` | The KDBX key file's bytes: the vault's only credential. |
| `repositoryKey` | `String?` | The repository's outer key (base64), when outer encrypted. |
| `members` | `List<TomSecretsSharedVaultMember>` | The members it is written for. |
| `credentials` | `Credentials` | The credentials that open the vault. |
| `hasMember(recipient)` | `bool` | Whether `recipient` is a member. |
| `withMember(member)` | `TomSecretsSharedVaultKeys` | The same keys for the members and `member` (adding a member). |
| `withoutMember(recipient)` | `TomSecretsSharedVaultKeys` | New keys for the members but `recipient` (removing a member): a new key file and, when outer encrypted, a new repository key. |
| `withoutRecipient(recipient)` | `TomSecretsSharedVaultKeys` | The same keys without `recipient` (a member's old key dropped at the finish of its rotation); the vault is not re-keyed. |
| `rotated()` | `TomSecretsSharedVaultKeys` | New keys for the same members (the vault's key rotated without removing anyone). |
| `keyId` | `String` | The key file's id (`tomSecretsKeyId`), as a rotation record names it. |
| `toJson()` | `Map<String, Object?>` | The plaintext of the recipients file (`tsm-shared-vault-keys/1`). |
| `dispose()` | `void` | Zeroes the key file. |

---

### TomSecretsRotationKind

The kind of key a rotation replaces.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `memberKey` | `member-key`: the user's member key (target: the old key's fingerprint). |
| `sharedVault` | `shared-vault`: a shared vault's key file and repository key (target: its store). |
| `vaultKeys` | `vault-keys`: a vault's key file or master password (target: its store). |
| `repositoryKey` | `repository-key`: a repository's outer key (target: `owner/repository`). |

`TomSecretsRotationKind.of(name)` answers the kind of a record's name, null for one this version does not know; `wireName` is that name.

---

### TomSecretsRotationException

A rotation that cannot start or go on.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsRotationException(message, {rotation})` | const | A refusal told by `message`. |
| `message` | `String` | For people. |
| `rotation` | `TomSecretsRotation?` | The rotation of the same target already running, when that is why. |

---

### TomSecretsRotation

One rotation record: its kind and target, the old and new key ids, when it started and switched, when its migration period ends, who started it, who is still to take up the new key.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsRotation({kind, target, oldKeyId, newKeyId, started, endsAt, by, switched, pending})` | const | A record. |
| `kind` | `TomSecretsRotationKind` | The kind of key. |
| `target` | `String` | A store, a repository or a member key's fingerprint. |
| `oldKeyId`, `newKeyId` | `String` | The old and the new key's ids. |
| `started` | `DateTime` | When it started. |
| `switched` | `DateTime?` | When the target started to run under the new key. |
| `endsAt` | `DateTime` | When its migration period ends. |
| `by` | `String` | Who started it. |
| `pending` | `List<String>` | The devices, members or vaults still to take up the new key. |
| `isDueAt(now)` | `bool` | Whether the migration period is over at `now`. |
| `copyWith({switched, pending})` | `TomSecretsRotation` | The record with those replaced. |
| `title` | `String` | `<kind> <target>`, the record's title in its group. |

---

### TomSecretsRotations

The rotation records of a vault (the primary, or a shared vault): the group `.tom-secrets/rotations`; the record is the lock, one rotation per target.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsRotations(file)` | — | The records of `file`. |
| `list()` | `List<TomSecretsRotation>` | Every record this version reads. |
| `of(kind, target)` | `TomSecretsRotation?` | The running rotation of that kind and target. |
| `start(rotation)` | `void` | Starts it; refused (`TomSecretsRotationException`) while one of the same kind and target runs. |
| `update(rotation)` | `void` | Writes it over its record (the switch, who is pending). |
| `end(kind, target)` | `bool` | Removes the record (finished or cancelled); whether there was one. |

---

### TomSecretsShareFailure

Why a share could not be written or read.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `format` | The decrypted document is not a share this version reads. |
| `protection` | Neither recipients nor a passphrase, or both, or an empty passphrase. |

---

### TomSecretsShareException

A refused share.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsShareException(reason, message)` | const | A refusal for `reason`, told by `message`. |
| `reason` | `TomSecretsShareFailure` | Why. |
| `message` | `String` | For people; never a secret. |

---

### TomSecretsSharedField

One field of a shared entry: `({String value, bool protected})`.

**Kind:** `typedef`

---

### TomSecretsSharedAttachment

One attachment of a shared entry: `({Uint8List bytes, bool protected})`.

**Kind:** `typedef`

---

### TomSecretsSharedEntry

One entry of a share: its fields (the title, `tsm.type` and `tsm.key` among them), tags, attachments and expiry.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsSharedEntry({required fields, tags, attachments, expires})` | const | An entry. |
| `fields` | `Map<String, TomSecretsSharedField>` | The fields by name. |
| `tags` | `List<String>` | The tags. |
| `attachments` | `Map<String, TomSecretsSharedAttachment>` | The attachments by name. |
| `expires` | `DateTime?` | When it expires, or null. |
| `title` | `String` | The title. |
| `type` | `TomSecretsEntryType` | The entry type (`tsm.type`). |

---

### TomSecretsShareSender

Who sent a share, as the sender says: `({String name, String fingerprint})`, the fingerprint of their member key.

**Kind:** `typedef`

---

### TomSecretsShare

A share (single-entry export): entries for another person, who sent them, when; its JSON document `{"format": "tsm.share", "version": 1, ...}`.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsShare({required entries, required created, from})` | const | A share. |
| `TomSecretsShare.decode(bytes)` | factory | The share of the JSON document `bytes`; throws `TomSecretsShareException` (`format`) for one this version does not read. |
| `entries` | `List<TomSecretsSharedEntry>` | The entries. |
| `created` | `DateTime` | When it was made. |
| `from` | `TomSecretsShareSender?` | Who sent it, as they say. |
| `encode()` | `Uint8List` | The JSON document, UTF-8. |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsLinkKeyMigration` | `Duration` | How long a device's previous approval-link key stays in use for the hosts its new key has not reached yet. |
| `tomSecretsSignedFields` | `Map<String, List<String>>` | The members of each signed object, in the order they are signed (9.4). |
| `tomSecretsDecisions` | `List<String>` | The decisions a prompt or a token carries. |
| `tomSecretsLinkProtocolName` | `String` | The protocol name hashed into the handshake. |
| `tomSecretsLinkMaxFrame` | `int` | The largest frame on the channel. |
| `tomSecretsPairingVersion` | `int` | The pairing protocol's version (each side's first message carries it). |
| `tomSecretsPairingAad` | `String` | SPAKE2's associated data: the protocol and its version, so both sides agree on them (RFC 9382 §3.2, against a downgrade). |
| `tomSecretsPairingWindow` | `Duration` | How long the giving side's pairing window stays open. |
| `tomSecretsPairingWords` | `List<String>` | The 256 words of a pairing code, in their fixed order. |
| `tomSecretsDevicesGroup` | `String` | The subgroup of the product group holding the device records. |
| `tomSecretsSharedVaultKeysFormat` | `String` | The format of a recipients file's plaintext: `tsm-shared-vault-keys/1`. |
| `tomSecretsRecipientsSuffix` | `String` | The suffix of a recipients file, after the vault's name: `.keys.age`. |
| `tomSecretsRotationsGroup` | `String` | The subgroup of the product group holding the rotation records: `rotations`. |
| `tomSecretsRotationPeriod` | `Duration` | The default migration period of a rotation: 14 days (DP-85). |
| `tomSecretsAgeDefaultWorkFactor` | `int` | The work factor (log2 N) a passphrase file is written with: 18, `age`'s own. |
| `tomSecretsAgeMaxWorkFactor` | `int` | The highest work factor (log2 N) the reader computes: 22, as `age`. |
| `tomSecretsShareFormat` | `String` | The `format` of a share's JSON document: `tsm.share`. |
| `tomSecretsShareVersion` | `int` | The version of the share's JSON document this code writes and reads: 1. |
| `tomSecretsShareExtension` | `String` | The extension of a share saved as a file: `.tsmshare`. |
| `tomSecretsQrCapacity` | `int` | The most characters a QR code holds (version 40, level L, byte mode): 2953. |
| `tomSecretsInboxFolder` | `String` | The folder beside a shared vault holding the members' inboxes: `inbox`. |
| `tomSecretsInboxExpiry` | `Duration` | How long a package stays in an inbox before any member's sync deletes it: 30 days. |

### Functions

| Function | Signature | Description |
| --- | --- | --- |
| `tomSecretsClientTokenId` | `String tomSecretsClientTokenId(String hash)` | A client token's id: the first 16 bytes, in lower-case hex, of its `hash`; the approving device derives it from the token, and the host checks the grant's `exe-token <path> <tokenId>` against the token it is sent. |
| `tomSecretsClientTokenHash` | `String tomSecretsClientTokenHash(List<int> token)` | A client token's hash: SHA-256(lps("tsm-client-token-v1") \|\| token), hex. |
| `tomSecretsLp` | `Uint8List tomSecretsLp(List<int> bytes)` | `lp(x)`: the length of `bytes` as 4 bytes big-endian, then the bytes. |
| `tomSecretsLps` | `Uint8List tomSecretsLps(String text)` | `lp` of a text's UTF-8. |
| `tomSecretsLpList` | `Uint8List tomSecretsLpList(List<String> items)` | A list: its item count as 4 bytes big-endian, then `lps` of each item. |
| `tomSecretsPinText` | `String tomSecretsPinText(Object? pin)` | The text a `pin` member is signed as: `hash`, `off`, `relaxed:<relaxedUntil>`, or empty when absent. |
| `tomSecretsSignedBytes` | `Uint8List tomSecretsSignedBytes(String label, Map<String, Object?> object)` | The signed bytes of `object` under `label`: `lps(label)`, then `lps` of each member of `tomSecretsSignedFields` (an absent one as empty). |
| `tomSecretsApproverKeyId` | `String tomSecretsApproverKeyId(List<int> ed25519, List<int> mlDsa65)` | An approver key's id (9.2): the first 16 bytes, in lower-case hex, of SHA-256(lps("tsm-approver-key-v1") \|\| lp(Ed25519 public) \|\| lp(ML-DSA-65 public)). |
| `tomSecretsVerifiedBy` | `Future<bool> tomSecretsVerifiedBy(TomSecretsApproverPublicKey key, String label, Uint8List bytes, List<Map<String, Object?>> signatures)` | Whether `signatures` carry, for `key`, an Ed25519 item and an ML-DSA-65 item that both verify over `bytes` under `label` (9.3). |
| `tomSecretsAcceptedBy` | `Future<TomSecretsApproverPublicKey?> tomSecretsAcceptedBy(String label, Map<String, Object?> object, Iterable<TomSecretsApproverPublicKey> recorded)` | The recorded key that signed `object` (a grant, revocation or approval record of `label`) with both algorithms, or null: the object is accepted only then. |
| `tomSecretsAcceptKeyChange` | `Future<TomSecretsApproverPublicKey?> tomSecretsAcceptKeyChange(Map<String, Object?> statement, TomSecretsApproverPublicKey oldKey)` | The new key of a key-change `statement` when it is accepted (9.4): its old key is `oldKey`, `newKeyId` is the id of the keys it carries, and the old and the new key both signed it with both algorithms. Null otherwise. |
| `tomSecretsBase32` | `String tomSecretsBase32(List<int> bytes)` | RFC 4648 base32 of `bytes`, upper case, without padding. |
| `tomSecretsRequestDigest` | `Uint8List tomSecretsRequestDigest(Map<String, Object?> identity, List<String> refs)` | The request digest (9.5): what the waiting request is, from the identity's `kind`, `exe`, `interpreter`, `script`, `cwd`, `uid` and `args` and the references in canonical form. |
| `tomSecretsApprovalCode` | `String tomSecretsApprovalCode(String host, String approvalId, Map<String, Object?> identity, List<String> refs)` | The approval code (9.5): the first ten base32 characters of SHA-256(lps("tsm-approval-code-v1") \|\| lps(host) \|\| lps(approvalId) \|\| requestDigest). |
| `tomSecretsCodeToken` | `String tomSecretsCodeToken(List<int> tokenKey, String host, String code, String decision)` | The token a trusted device computes for `code` shown on `host` (9.6): base32 of the first 16 bytes of HMAC-SHA256(tokenKey, lps("tsm-code-token-v1") \|\| lps(host) \|\| lps(code) \|\| lps(decision)). |
| `tomSecretsNormalizeCode` | `String tomSecretsNormalizeCode(String text)` | A token or code as typed: upper case, without spaces. |
| `tomSecretsIsToken` | `bool tomSecretsIsToken(String token)` | Whether `token` is 26 base32 characters (after `tomSecretsNormalizeCode`). |
| `tomSecretsSameText` | `bool tomSecretsSameText(String a, String b)` | Compares two texts in constant time (in their length). |
| `tomSecretsRedeemToken` | `TomSecretsTokenMatch? tomSecretsRedeemToken(String token, Iterable<String> codes, Iterable<List<int>> tokenKeys, String host)` | The request `token` answers among the `codes` waiting on `host`, under one of `tokenKeys`; null when it matches nothing or is malformed. Every candidate is compared in constant time. |
| `tomSecretsNoiseHkdf` | `(Uint8List, Uint8List) tomSecretsNoiseHkdf(List<int> chainingKey, List<int> ikm)` | Noise's HKDF with HMAC-SHA256: two 32-byte outputs. |
| `tomSecretsLinkRekey` | `Future<Uint8List> tomSecretsLinkRekey(List<int> key)` | Noise's REKEY: the first 32 bytes of ENCRYPT(k, 2^64 - 1, empty, zeros). |
| `tomSecretsLinkFrame` | `Uint8List tomSecretsLinkFrame(List<int> bytes)` | A frame on the channel: the length as 4 bytes big-endian, then `bytes`. |
| `tomSecretsHkdf` | `Uint8List tomSecretsHkdf(List<int> ikm, {required List<int> salt, required List<int> info, required int length})` | HKDF-SHA-256 (RFC 5869) of `ikm` with `salt` and `info`, `length` bytes. |
| `tomSecretsGivePairing` | `Future<TomSecretsPairingGiven> tomSecretsGivePairing(TomSecretsApprovalChannel channel, {required TomSecretsPairingCode code, required String device, required Future<TomSecretsPairingBundle?> Function(String receiver) bundleFor, Duration timeout = const Duration(seconds: 30), BigInt? y})` | The giving side of a pairing over `channel`: it showed `code`; `device` is its name. |
| `tomSecretsReceivePairing` | `Future<TomSecretsPairingReceived> tomSecretsReceivePairing(TomSecretsApprovalChannel channel, {required TomSecretsPairingCode code, required String device, required Future<TomSecretsPairingPeerKeys> Function(String giver, TomSecretsPairingBundle bundle) keysFor, Duration timeout = const Duration(minutes: 5), BigInt? x})` | The receiving side of a pairing over `channel`: the user typed `code`; `device` is its name. |
| `tomSecretsIsPairingAddress` | `bool tomSecretsIsPairingAddress(InternetAddress address)` | Whether `address` is a LAN or VPN address a pairing window may listen on: a private IPv4 address (10/8, which the fleet's VPN uses, 172.16/12, 192.168/16) or an IPv6 unique local address (fc00::/7); never a public, loopback or wildcard address. |
| `tomSecretsPairingAddresses` | `Future<List<InternetAddress>> tomSecretsPairingAddresses()` | This machine's LAN and VPN addresses (`tomSecretsIsPairingAddress`). |
| `tomSecretsReceivePairingAt` | `Future<TomSecretsPairingReceived> tomSecretsReceivePairingAt(String address, int port, {required TomSecretsPairingCode code, required String device, required Future<TomSecretsPairingPeerKeys> Function(String giver, TomSecretsPairingBundle bundle) keysFor, Duration connectTimeout = const Duration(seconds: 10)})` | The receiving side connecting to a pairing window at `address`:`port` (`tomSecretsReceivePairing` over TCP). Throws `TomSecretsPairingException` (`closed` when nothing answers there). |
| `tomSecretsPairingSetupProblem` | `String? tomSecretsPairingSetupProblem(TomSecretsPairingBundle bundle)` | Why a bundle cannot set a machine up, or null when it can: the primary must be in it, with its token when it is in a GitHub repository. |
| `tomSecretsReceivePairingForSetup` | `Future<TomSecretsPairingReceipt> tomSecretsReceivePairingForSetup({required String address, required int port, required TomSecretsPairingCode code, required String device, String? linkAddress, DateTime? now, Duration connectTimeout = const Duration(seconds: 10)})` | Receives a pairing for a machine being set up as `device`: connects to the giving machine's window at `address`:`port` with `code`, answers with the public keys of fresh trust material (made `now`) and `linkAddress`, where this machine's approval link will listen (the giver records it and opens the link), and refuses a bundle it cannot be set up from (`tomSecretsPairingSetupProblem`); a `linkAddress` that is no approval link throws `ArgumentError`. |
| `tomSecretsParsePairingAddress` | `(String host, int port) tomSecretsParsePairingAddress(String text)` | Splits `host:port` (an IPv6 address in brackets: `[fd00::1]:47900`) as the giving machine's Pairing screen shows it. Throws `FormatException`. |
| `tomSecretsMemberKeyFile` | `String tomSecretsMemberKeyFile(TomSecretsAgeRecipient recipient, {required String name, DateTime? created})` | The text of a published member key: `age`'s recipients-file format (so `age -R <file>` encrypts to it), with the name, short fingerprint and date as `#` comments. |
| `tomSecretsMemberKeyFileName` | `String tomSecretsMemberKeyFileName(String name)` | The file name of `name`'s published member key: `<name>.age-recipient.txt` (lower case, other characters as `_`). |
| `tomSecretsReadMemberKeys` | `List<TomSecretsReceivedMemberKey> tomSecretsReadMemberKeys(String text)` | The public keys in `text` (a key file, a recipients file with several, a pasted recipient, a scanned QR code's text); blank lines and `#` comments skipped, a `# name: …` comment names the key after it; a line that is no `age` recipient is refused, naming its line. |
| `tomSecretsSharingGroupOf` | `KdbxGroup? tomSecretsSharingGroupOf(KdbxFile file, {bool create = false})` | The `tsm.sharing` group at the root of `file`, made when `create`. |
| `tomSecretsMemberKeyEntries` | `List<KdbxEntry> tomSecretsMemberKeyEntries(KdbxFile file)` | The `member-key` entries of `file`, the newest first. |
| `tomSecretsMemberKeyOf` | `Future<TomSecretsMemberKey> tomSecretsMemberKeyOf(KdbxEntry entry)` | The member key an entry holds (its identity in `Password`). |
| `tomSecretsMemberKeyRecipientOf` | `TomSecretsAgeRecipient? tomSecretsMemberKeyRecipientOf(KdbxEntry entry)` | The public key a `member-key` or `member` entry names (`tsm.recipient`), read without the identity; null when absent or unreadable. |
| `tomSecretsAddMemberKey` | `KdbxEntry tomSecretsAddMemberKey(KdbxFile file, TomSecretsMemberKey key, {String title = 'Member key'})` | Writes `key` into `file` as a new `member-key` entry in `tsm.sharing`: the identity protected in `Password`, the recipient and fingerprint beside it. |
| `tomSecretsMembers` | `List<TomSecretsMember> tomSecretsMembers(KdbxFile file)` | The members of `file` whose entry holds a readable recipient, by name. |
| `tomSecretsAddMember` | `Future<TomSecretsMember> tomSecretsAddMember(KdbxFile file, {required String name, required TomSecretsAgeRecipient recipient, DateTime? checked})` | Adds `recipient` to the directory as a `member` entry named `name`, after `TomSecretsAgeRecipient.check`; refuses a recipient the directory holds (`duplicate`) and the user's own key (`ownKey`). |
| `tomSecretsMarkMemberChecked` | `void tomSecretsMarkMemberChecked(KdbxEntry entry, DateTime when)` | Records that the user compared the fingerprint of `entry` with its owner on `when` (its date, `tsm.checked`); the entry as it was goes to its history. |
| `tomSecretsAgeEncrypt` | `Future<Uint8List> tomSecretsAgeEncrypt(List<int> plaintext, List<TomSecretsAgeRecipient> recipients)` | `plaintext` as an `age` v1 file to `recipients`, all hybrid (`mlkem768x25519`) or all classical (`X25519`); throws `TomSecretsAgeException` (`recipients`) for none or a mix. |
| `tomSecretsAgeDecrypt` | `Future<Uint8List> tomSecretsAgeDecrypt(Uint8List file, Iterable<TomSecretsAgeIdentity> identities)` | The plaintext of the `age` file `file` (binary or armoured), opened with the first identity a stanza is for; throws `TomSecretsAgeException` (`noMatch`, `header`, `payload`, `armor`). |
| `tomSecretsIsAgeArmor` | `bool tomSecretsIsAgeArmor(List<int> file)` | Whether `file` begins with the `age` armour (white space before it allowed). |
| `tomSecretsAgeArmor` | `String tomSecretsAgeArmor(List<int> file)` | `file` in the `age` armour (`-----BEGIN AGE ENCRYPTED FILE-----`, base64 in lines of 64), for pasting into a message. |
| `tomSecretsAgeDearmor` | `Uint8List tomSecretsAgeDearmor(List<int> text)` | The binary file inside the armoured `text` (white space around it and CRLF allowed); throws `TomSecretsAgeException` (`armor`). |
| `tomSecretsAgeClassicalSecret` | `Uint8List tomSecretsAgeClassicalSecret(String identity)` | The 32-byte secret of a classical `AGE-SECRET-KEY-1…` identity. |
| `tomSecretsBech32Data` | `Uint8List tomSecretsBech32Data(String hrp, String text, int length)` | The data of the Bech32 string `text` whose prefix must be `hrp` and whose data must be `length` bytes (age's Bech32: no length limit, either case). |
| `tomSecretsCheckSharedVaultMembers` | `void tomSecretsCheckSharedVaultMembers(List<TomSecretsSharedVaultMember> members)` | Checks `members` for a recipients file: at least one, each with a hybrid key, none twice. |
| `tomSecretsWriteRecipientsFile` | `Future<Uint8List> tomSecretsWriteRecipientsFile(TomSecretsSharedVaultKeys keys)` | The recipients file of `keys`: its JSON encrypted with `age` to every member's recipient. |
| `tomSecretsReadRecipientsFile` | `Future<TomSecretsSharedVaultKeys> tomSecretsReadRecipientsFile(Uint8List file, TomSecretsMemberKey memberKey)` | The keys of the recipients file `file`, opened with `memberKey`; throws `TomSecretsSharedVaultException` (`notAMember`, `malformed`) or `TomSecretsAgeException` for a broken file. |
| `tomSecretsRecipientsFileName` | `String tomSecretsRecipientsFileName(String fileName)` | The recipients file beside the vault file `fileName` (`team.kdbx`, `team.kdbx.tsmx` → `team.keys.age`). |
| `tomSecretsNewSharedVault` | `KdbxFile tomSecretsNewSharedVault(String name, TomSecretsSharedVaultKeys keys, {String? purpose, KdbxArgon2 argon2 = tomSecretsDefaultArgon2})` | A new shared vault `name` (kind `shared`) opened by `keys`' key file alone. |
| `tomSecretsKeyId` | `String tomSecretsKeyId(List<int> bytes)` | The key id of `bytes` (a key file's, a repository key's): the first 8 bytes of their SHA-256 in hex. |
| `tomSecretsTakeNextKeys` | `bool tomSecretsTakeNextKeys(KdbxFile file, {required String device, required DateTime now, Iterable<String> primaryKeyIds = const []})` | **[C]** A device taking the keys of the guided rotations running in the primary `file`: the ids of the new keys it holds (the vaults' next and, while a rotation runs, current keys, and `primaryKeyIds`) go into its device record, and it leaves every rotation's `pending` whose new key it holds. Whether the primary changed. |
| `tomSecretsAgeEncryptPassphrase` | `Future<Uint8List> tomSecretsAgeEncryptPassphrase(List<int> plaintext, String passphrase, {int workFactor = tomSecretsAgeDefaultWorkFactor})` | `plaintext` as an `age` v1 file under `passphrase`: one `scrypt` stanza, `workFactor` its log2 N (1 to 22, `ArgumentError` otherwise); scrypt runs in another isolate. |
| `tomSecretsAgeIsPassphrase` | `bool tomSecretsAgeIsPassphrase(List<int> file)` | Whether the `age` file `file` (binary or armoured) is written under a passphrase, so a reader asks for one. |
| `tomSecretsShareOf` | `TomSecretsShare tomSecretsShareOf(List<KdbxEntry> entries, {TomSecretsShareSender? from, DateTime? now})` | The share of `entries`: every field but the product's other `tsm.*` fields and overlay fields, the tags, attachments and expiry. |
| `tomSecretsImportShare` | `List<KdbxEntry> tomSecretsImportShare(KdbxFile file, KdbxGroup group, TomSecretsShare share)` | The entries of `share` added to `group` of `file` as new entries (new UUIDs). |
| `tomSecretsWriteShare` | `Future<Uint8List> tomSecretsWriteShare(TomSecretsShare share, {List<TomSecretsAgeRecipient>? recipients, String? passphrase, int workFactor = tomSecretsAgeDefaultWorkFactor})` | `share` as an `age` file to `recipients` (all hybrid or all classical) or under `passphrase`, exactly one; throws `TomSecretsShareException` (`protection`) else. |
| `tomSecretsReadShare` | `Future<TomSecretsShare> tomSecretsReadShare(List<int> bytes, Iterable<TomSecretsAgeIdentity> identities)` | The share in `bytes` (a `.tsmshare` file or the armoured text), opened with the first of `identities` that fits; throws `TomSecretsAgeException` or `TomSecretsShareException`. |
| `tomSecretsLooksLikeShare` | `bool tomSecretsLooksLikeShare(String text)` | Whether `text` (pasted, scanned) holds an armoured `age` file. |
| `tomSecretsShareFitsQr` | `bool tomSecretsShareFitsQr(List<int> file)` | Whether the share `file` fits a QR code as armoured text (`tomSecretsQrCapacity`). |
| `tomSecretsIsInboxMember` | `bool tomSecretsIsInboxMember(String id)` | Whether `id` is a member id an inbox folder may be named by (a member key's fingerprint). |
| `tomSecretsIsInboxName` | `bool tomSecretsIsInboxName(String name)` | Whether `name` is a package name, `<YYYY-MM-DD>-<16 hex>.age`. |
| `tomSecretsInboxPath` | `String tomSecretsInboxPath(String memberId, String name)` | The path of the package `name` in the inbox of `memberId`, relative to the shared vault's folder: `inbox/<member>/<name>`; `ArgumentError` for another member id or name. |
| `tomSecretsNewInboxName` | `String tomSecretsNewInboxName({DateTime? now})` | A new package name: the UTC date at `now` and 16 random hex digits. |
| `tomSecretsInboxDate` | `DateTime? tomSecretsInboxDate(String name)` | The day a package named `name` was put in (UTC), or null for another name. |
| `tomSecretsInboxExpired` | `bool tomSecretsInboxExpired(String name, DateTime now)` | Whether the package `name` was put in more than 30 days before `now`; a file that is no package is never expired. |
