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
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The sharing module holds everything one device of the user's fleet needs to trust another: a device's trust material (approver, link and audit-log keys, the approvers and hosts it recorded) with key rotation; signed objects (grants, revocations, approval records, key-change statements) signed with Ed25519 and ML-DSA-65; the grants group of the primary vault; the approval code and its single-use token; the approval link (Noise KK with ML-KEM-768 paired to every Diffie-Hellman, ChaCha20-Poly1305 transport); pairing by a short code through SPAKE2 (RFC 9382) with an ML-KEM-768 exchange inside; and the device records of the primary vault.

Source files: `lib/src/trust.dart`, `lib/src/signed_objects.dart`, `lib/src/grants.dart`, `lib/src/approval_code.dart`, `lib/src/approval_link.dart`, `lib/src/pairing.dart`, `lib/src/pairing_setup.dart`, `lib/src/pairing_words.dart`, `lib/src/device_records.dart`.

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
└── TomSecretsDeviceRecords
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
| `TomSecretsDeviceRecord({device, paired, platform, pairedBy, keyIds, approverKeyId, approverKeySince, linkKeySince, revoked})` | const | A record of `device`. |

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

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The record as the wire carries it (`pair.list`). |

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
| `revoke(device, at)` | `bool` | Marks `device` revoked at `at`; whether it had a record. |

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
