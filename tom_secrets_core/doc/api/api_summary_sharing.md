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
  - [TomSecretsRelayService](#tomsecretsrelayservice)
  - [TomSecretsRelayKind](#tomsecretsrelaykind)
  - [TomSecretsRelayId](#tomsecretsrelayid)
  - [TomSecretsRelayException](#tomsecretsrelayexception)
  - [TomSecretsPairingChannel](#tomsecretspairingchannel)
  - [TomSecretsMailboxItem](#tomsecretsmailboxitem)
  - [TomSecretsMailboxEntry](#tomsecretsmailboxentry)
  - [TomSecretsRelay](#tomsecretsrelay)
  - [TomSecretsRelayFolder](#tomsecretsrelayfolder)
  - [TomSecretsRelayFileExists](#tomsecretsrelayfileexists)
  - [TomSecretsStorageRelayFolder](#tomsecretsstoragerelayfolder)
  - [TomSecretsGitHubRelay](#tomsecretsgithubrelay)
  - [TomSecretsServerRelay](#tomsecretsserverrelay)
  - [TomSecretsRelayUpgradeRefused](#tomsecretsrelayupgraderefused)
  - [TomSecretsRelayBudget](#tomsecretsrelaybudget)
  - [TomSecretsRelayBudgetSpent](#tomsecretsrelaybudgetspent)
  - [TomSecretsRelayPacer](#tomsecretsrelaypacer)
  - [TomSecretsDeviceRecord](#tomsecretsdevicerecord)
  - [TomSecretsDeviceRecords](#tomsecretsdevicerecords)
  - [TomSecretsMemberFields](#tomsecretsmemberfields)
  - [TomSecretsMember](#tomsecretsmember)
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
├── TomSecretsMember
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
| `TomSecretsRecordedApprover({device, approverKey, tokenKey, linkKey, previousLinkKey, approverKeySince, linkKeySince, relay, linkId})` | — | The approver `device` with its `approverKey`, its `linkKey` (null when it never connects over the link), the `tokenKey` the two share, a link key it replaced and is still accepted during the migration period (`previousLinkKey`), and since when each key is recorded (`approverKeySince`, `linkKeySince`). |
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
| `relay` | `String?` | **[C]** The relay server the approver's link may come through (`tsm:<url>`), or null. |
| `linkId` | `String?` | **[C]** The channel on `relay` this host's link to the approver waits on (`tomSecretsLinkChannelId`). |

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
| `TomSecretsRecordedHost({host, linkKey, tokenKey, address, linkKeySince, linkKeyDelivered, relay, linkId})` | — | The `host` with its `linkKey`, the `tokenKey` the two share, the `address` (`host:port`) its link listens on, and since when the link key is recorded (`linkKeySince`). |
| `TomSecretsRecordedHost.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `host` | `String` | The host's name. |
| `linkKey` | `TomSecretsLinkPublicKey` | Its approval-link public key. |
| `tokenKey` | `Uint8List` | The approval-token key (32 bytes). |
| `address` | `String?` | Where its link listens (`address:port`), when known. |
| `linkKeySince` | `DateTime?` | When `linkKey` was recorded (at pairing, or a new link key). |
| `relay` | `String?` | **[C]** The relay server the host's link may also be reached through (`tsm:<url>`), or null. |
| `linkId` | `String?` | **[C]** The channel on `relay` the host waits on (`tomSecretsLinkChannelId`). |
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
| `recordPeer({device, tokenKey, at, approverKey, approverLinkKey, hostLinkKey, hostAddress, link, peerIsGiver})` | `void` | Records what a pairing with the peer `device` gave: it approves for this host with `approverKey` (reached over the approval link with `approverLinkKey`), and this device approves for it as a host with `hostLinkKey` at `hostAddress`; `tokenKey` is the approval-token key both sides derived. **[C]** With `link` (the relay server and link id the pairing agreed on) each record keeps the relay and its channel; `peerIsGiver` tells which side gave the pairing. |
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

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `error` | `Object?` | The error the channel ended with (a relay that failed), or null. |

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
| `TomSecretsPairingPeerKeys({linkKey, approverKey, linkAddress, linkRelay, linkId})` | const | The keys. |
| `TomSecretsPairingPeerKeys.fromJson(json)` | factory | From `toJson`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `linkKey` | `TomSecretsLinkPublicKey` | The approval-link public key. |
| `approverKey` | `TomSecretsApproverPublicKey?` | The approver public key, or null for a device that approves nothing. |
| `linkAddress` | `String?` | Where its approval link listens (`address:port`), or null. |
| `linkRelay` | `String?` | **[C]** The relay server its approval link may also go through (`tsm:<url>`), or null; `fromJson` drops a relay or link id that cannot be used (an older peer names none). |
| `linkId` | `String?` | **[C]** The random link id (128 bits, base64url) of that relay link. |

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

The giving side's pairing window: it listens on the addresses given (the LAN and VPN ones, `tomSecretsPairingAddresses`) and, when given, waits on a relay channel hosted under the code's number; it takes the first device that comes and runs `tomSecretsGivePairing` with it. Anything after is refused (the other way is closed), and the window closes after that one attempt (the code is burnt, right or wrong) or when `window` ends.

**Kind:** `final class`

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `open({addresses, code, device, bundleFor, port, window, stepTimeout, allowLoopback, relayChannel, relayStepTimeout})` | `Future<TomSecretsPairingWindow>` | Opens a window on `addresses` (at `port`, 0: one the system picks) for `code`, this machine being `device`; `bundleFor` as for `tomSecretsGivePairing`; with `relayChannel` (hosted under the code's number) it also waits there and `addresses` may be empty. Throws `ArgumentError` for an address that is no LAN or VPN address, a relay channel under another number, or no address and no relay; `SocketException` when none can be bound. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `port` | `int` | The port it listens on (the same on every address). |
| `addresses` | `List<InternetAddress>` | The addresses it listens on. |
| `relayChannel` | `TomSecretsPairingChannel?` | The relay channel it also waits on, or null. |
| `relayError` | `Object?` | The error the relay failed with before anyone came (a window on the LAN stays open there; one on the relay alone ends with it), or null. |
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
| `ownKeys` | `TomSecretsPairingPeerKeys?` | **[C]** The public keys this machine answered with (its relay link among them). |
| `link` | `({String relay, String linkId})?` | **[C]** The relay link the two sides agreed on (`tomSecretsPairingLink`), or null. |
| `ownTokens` | `Map<String, String>` | The GitHub tokens this machine brought itself, by `owner/name` (a pairing through GitHub). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `tokenFor(repository)` | `TomSecretsPairingToken?` | The token pasted for `repository` (`owner/name`), else the one this machine brought itself, or null. |

---

### TomSecretsRelayService

**[C]** What a relay offers (part-relay): `pairing` (a rendezvous of two online devices), `mailbox` (store and forward of `age` packages), `link` (a standing channel for the approval link).

**Kind:** `enum`

---

### TomSecretsRelayKind

**[C]** A relay's kind from its id's scheme, with the services it offers: `server` (`tsm:`, all three), `wormhole` (`wormhole:`, pairing), `github` (`github:`, pairing and mailbox).

**Kind:** `enum`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `scheme` | `String` | The id's scheme. |
| `services` | `Set<TomSecretsRelayService>` | The services a relay of this kind offers. |

---

### TomSecretsRelayId

**[C]** A relay's id: `tsm:https://relay.example`, `wormhole:wss://…`, `github:<owner>/<repo>`; it names the relay in the settings, the pairing QR code and a shared vault's metadata.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsRelayId.parse(text)` | — | The relay `text` names; throws `FormatException`. |
| `TomSecretsRelayId.github(owner, repository)` | — | A GitHub repository as a relay. |
| `kind` | `TomSecretsRelayKind` | Its kind. |
| `address` | `String` | What follows the scheme: the URL or `owner/repo`. |
| `services` | `Set<TomSecretsRelayService>` | The services it offers. |
| `text` | `String` | The id as text. |

---

### TomSecretsRelayException

**[C]** A relay that failed or refused, naming it (`relay`, the id), so the app says which relay failed; `unsupported` for a service the relay lacks; `message` for people.

**Kind:** `final class`

---

### TomSecretsPairingChannel

**[C]** A pairing's or the approval link's byte channel through a relay: a `TomSecretsApprovalChannel` (so the pairing runs over it unchanged) with its `nameplate`, and `joined`, completing when the other side's first bytes arrived (failing with the relay's error).

**Kind:** `abstract interface class`

---

### TomSecretsMailboxItem

**[C]** A mailbox item to put: the `age` package `bytes` for the member `recipient` (its member id) under `itemId`, kept until `expires`.

**Kind:** `final class`

---

### TomSecretsMailboxEntry

**[C]** A mailbox item waiting: `itemId`, `size` (0 when unknown), `received` and `expires` when the relay says.

**Kind:** `final class`

---

### TomSecretsRelay

**[C]** A relay (part-relay): one interface, the transports behind it. A service it lacks throws `TomSecretsRelayException` with `unsupported`.

**Kind:** `abstract interface class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `id` | `TomSecretsRelayId` | The relay's id. |
| `services` | `Set<TomSecretsRelayService>` | What it offers. |
| `host()` | `Future<TomSecretsPairingChannel>` | Allocates a nameplate (1–999, the pairing code's number) and opens the hosting side. |
| `join(nameplate)` | `Future<TomSecretsPairingChannel>` | Opens the joining side. |
| `link(linkId)` | `Future<TomSecretsPairingChannel>` | Opens the approval link between two paired devices. |
| `put(item)` | `Future<void>` | Puts an item into its recipient's mailbox. |
| `list(me)` | `Future<List<TomSecretsMailboxEntry>>` | The items waiting for the member key `me`. |
| `fetch(me, itemId)` | `Future<Uint8List>` | One package. |
| `delete(me, itemId)` | `Future<void>` | Deletes one package. |

---

### TomSecretsRelayFolder

**[C]** The files the GitHub relay keeps in a repository: `revisionOf(folder)` (cheap, null when nothing is there), `list(folder)` (paths relative to it with revisions), `read(path)`, `create(path, bytes, message:)` (one commit; `TomSecretsRelayFileExists` when there), `deleteFolder(folder)`, `deleteFile(path)`. The app reaches it through the service (`relay.*`), a machine being set up directly.

**Kind:** `abstract interface class`

---

### TomSecretsRelayFileExists

**[C]** A relay file that exists already (`path`).

**Kind:** `final class`

---

### TomSecretsStorageRelayFolder

**[C]** A `TomSecretsRelayFolder` over a `tom_core_storage` backend: the files under `base`, a container locator such as `github:<owner>/<repo>[@<branch>]`; through `TomGitHubStorage`, an unchanged branch is answered by a conditional request.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsStorageRelayFolder(storage, base)` | — | The folder `base` of `storage`. |
| `storage` | `TomStorage` | The backend. |
| `base` | `String` | The base locator. |

---

### TomSecretsGitHubRelay

**[C]** GitHub as the relay (part-relay 3.): pairing at the repository's root (`relay/pair/<nameplate>/offer`, frames `h-0001`…/`j-0001`… polled every 2 seconds, end markers, the second side to end deletes the folder, folders older than an hour deleted by the next host), the mailbox on a shared vault's inbox folders; no link.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsGitHubRelay(id, folder, {mailboxFolder, device, pollInterval, random, clock})` | — | The relay `id` over `folder` (the repository root); the mailbox in `mailboxFolder`. |
| `TomSecretsGitHubRelay.withToken(id, token, {branch, mailboxFolder, device, httpClient, baseUrl, pollInterval})` | — | Reached directly with a token (a machine being set up). |
| `folder` | `TomSecretsRelayFolder` | The repository's root. |
| `mailboxFolder` | `String` | The shared vault's folder ('' the root). |
| `device` | `String` | This side's name in commit messages. |
| `pollInterval` | `Duration` | How often a pairing channel polls. |
| `deleteStale()` | `Future<int>` | Deletes the pairing folders older than an hour; answers how many. |

---

### TomSecretsServerRelay

**[C]** The own relay server as the relay (`tsm:<url>`, part-relay 1.): all three services over `tom_secrets_relay`'s `/v1` API. Pairing: `POST /v1/pair` allocates the nameplate, both sides open the WebSocket `/v1/pair/<nameplate>`. Link: the WebSocket `/v1/link/<link-id>` with the instance token. Mailbox: `PUT` with the instance token and `Tsm-Expires`; listing, fetching and deleting with the recipient's proof (the relay's challenge decrypted with the member key, kept 4 minutes, asked again once when refused). Credentials travel as `Authorization: Bearer`. Every request and WebSocket opened waits for its turn on the relay's `TomSecretsRelayPacer`; a `429` with `Retry-After` is waited out and asked again once.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsServerRelay(id, {token, httpClient, connect, clock, pacer, timeout})` | — | The relay `id` with the instance `token` (null: none; pairing needs none); requests through `httpClient`, WebSockets through `connect` (default `tomSecretsRelayWebSocket`), each in its turn on `pacer` (default `TomSecretsRelayPacer.of(id.address)`). |
| `token` | `String?` | The instance token. |
| `pacer` | `TomSecretsRelayPacer` | Where the requests wait for their turn. |
| `timeout` | `Duration` | How long a request may take (30 seconds). |
| `close()` | `void` | Closes the HTTP client. |

---

### TomSecretsRelayUpgradeRefused

A WebSocket upgrade the relay answered with `status` instead of 101, with the relay's `message` (its JSON `error`), if any.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsRelayUpgradeRefused(status, message, {retryAfter})` | const | A refusal; `retryAfter` from the answer's `Retry-After`. |
| `status` | `int` | The HTTP status. |
| `message` | `String?` | What the relay said. |
| `retryAfter` | `Duration?` | How long the relay asks to wait (a `429`), or null. |

---

### TomSecretsRelayBudget

**[C]** One budget of the relay client: `({int limit, Duration window})`, at most `limit` requests within `window`.

**Kind:** `typedef`

---

### TomSecretsRelayBudgetSpent

**[C]** A request's turn is further away than the pacer's longest wait (the day's budget spent): thrown instead of holding the caller for hours.

**Kind:** `final class` (implements `Exception`)

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsRelayBudgetSpent(until)` | const | Spent until `until`. |
| `until` | `DateTime` | When the next request may go. |

---

### TomSecretsRelayPacer

**[C]** The turns of the requests to one relay server (part-relay, DP-65): a sliding window per budget (`tomSecretsRelayClientBudgets`: 5 a second, 60 a minute, 1,000 a day, about half the relay's per-address defaults), so a device stays under the relay's limits with room for the other processes and devices behind the same address. One pacer per relay address in the process, shared by every `TomSecretsServerRelay` of it; frames inside an open channel are not requests.

**Kind:** `final class`

#### Members

| Member | Type | Description |
| --- | --- | --- |
| `TomSecretsRelayPacer({budgets, longestWait, clock, sleep})` | — | A pacer spending `budgets`, the time read from `clock`, waiting with `sleep` (tests replace both). |
| `of(address)` | `static TomSecretsRelayPacer` | The pacer of the relay at `address` in this process. |
| `budgets` | `List<TomSecretsRelayBudget>` | The budgets. |
| `longestWait` | `Duration` | The longest wait before `turn` refuses. |
| `turn()` | `Future<void>` | Waits for this request's turn (in the order asked) and counts it; throws `TomSecretsRelayBudgetSpent` when the turn is further away than `longestWait` (nothing counted). |
| `waitOut(retryAfter)` | `Future<bool>` | A request the relay refused for its limits is asked again once after waiting `retryAfter`, when it is no longer than `longestWait`; true when it may be asked again. |

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
| `tomSecretsRelayPairFolder` | `String` | **[C]** The folder of a repository's pairing rendezvous: `relay/pair`. |
| `tomSecretsRelayStaleAfter` | `Duration` | **[C]** How old a pairing folder may get before the next host deletes it: one hour. |
| `tomSecretsLinkIdPattern` | `RegExp` | **[C]** What a link id (and a channel id) is: 8–128 of `A-Z a-z 0-9 _ -`. |
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
| `tomSecretsShareFormat` | `String` | The `format` of a share's JSON document: `tsm.share`. |
| `tomSecretsShareVersion` | `int` | The version of the share's JSON document this code writes and reads: 1. |
| `tomSecretsShareExtension` | `String` | The extension of a share saved as a file: `.tsmshare`. |
| `tomSecretsQrCapacity` | `int` | The most characters a QR code holds (version 40, level L, byte mode): 2953. |
| `tomSecretsInboxFolder` | `String` | The folder beside a shared vault holding the members' inboxes: `inbox`. |
| `tomSecretsInboxExpiry` | `Duration` | How long a package stays in an inbox before any member's sync deletes it: 30 days. |
| `tomSecretsRelayClientBudgets` | `List<TomSecretsRelayBudget>` | **[C]** What the relay client spends on one relay: 5 a second, 60 a minute, 1,000 a day. |
| `tomSecretsRelayLongestWait` | `Duration` | **[C]** The longest a relay request waits for its turn: 70 seconds. |

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
| `tomSecretsGivePairing` | `Future<TomSecretsPairingGiven> tomSecretsGivePairing(TomSecretsApprovalChannel channel, {required TomSecretsPairingCode code, required String device, required Future<TomSecretsPairingBundle?> Function(String receiver) bundleFor, Duration timeout = const Duration(seconds: 30), BigInt? y})` | The giving side of a pairing over `channel`: it showed `code`; `device` is its name. |
| `tomSecretsReceivePairing` | `Future<TomSecretsPairingReceived> tomSecretsReceivePairing(TomSecretsApprovalChannel channel, {required TomSecretsPairingCode code, required String device, required Future<TomSecretsPairingPeerKeys> Function(String giver, TomSecretsPairingBundle bundle) keysFor, Duration timeout = const Duration(minutes: 5), BigInt? x})` | The receiving side of a pairing over `channel`: the user typed `code`; `device` is its name. |
| `tomSecretsIsPairingAddress` | `bool tomSecretsIsPairingAddress(InternetAddress address)` | Whether `address` is a LAN or VPN address a pairing window may listen on: a private IPv4 address (10/8, which the fleet's VPN uses, 172.16/12, 192.168/16) or an IPv6 unique local address (fc00::/7); never a public, loopback or wildcard address. |
| `tomSecretsPairingAddresses` | `Future<List<InternetAddress>> tomSecretsPairingAddresses()` | This machine's LAN and VPN addresses (`tomSecretsIsPairingAddress`). |
| `tomSecretsReceivePairingAt` | `Future<TomSecretsPairingReceived> tomSecretsReceivePairingAt(String address, int port, {required TomSecretsPairingCode code, required String device, required Future<TomSecretsPairingPeerKeys> Function(String giver, TomSecretsPairingBundle bundle) keysFor, Duration connectTimeout = const Duration(seconds: 10)})` | The receiving side connecting to a pairing window at `address`:`port` (`tomSecretsReceivePairing` over TCP). Throws `TomSecretsPairingException` (`closed` when nothing answers there). |
| `tomSecretsReceivePairingVia` | `Future<TomSecretsPairingReceived> tomSecretsReceivePairingVia(TomSecretsRelay relay, {required TomSecretsPairingCode code, required String device, required Future<TomSecretsPairingPeerKeys> Function(String giver, TomSecretsPairingBundle bundle) keysFor, Duration timeout = const Duration(minutes: 5)})` | **[C]** The receiving side through a relay: joins the pairing hosted under the code's number and runs `tomSecretsReceivePairing` over the channel. Throws `TomSecretsRelayException` naming the relay when it fails. |
| `tomSecretsRelayWebSocket` | `Future<WebSocket> tomSecretsRelayWebSocket(Uri url, Map<String, String> headers)` | **[C]** Opens the WebSocket `url` with `headers`, doing the handshake itself so a refusal keeps its status, the relay's message and its `Retry-After` (`TomSecretsRelayUpgradeRefused`). |
| `tomSecretsRetryAfter` | `Duration? tomSecretsRetryAfter(String? header)` | **[C]** A `Retry-After` header's delay in seconds, or null (a date or anything else). |
| `tomSecretsRelayFor` | `TomSecretsRelay tomSecretsRelayFor(TomSecretsRelayId id, {String? token, String device = 'tsm', String? githubApi})` | **[C]** The relay `id` names, built for this device: GitHub with this machine's GitHub `token` (required), the relay server with its instance `token` (optional); a magic-wormhole server throws `TomSecretsRelayException` (`unsupported`). |
| `tomSecretsRelayNeedsToken` | `bool tomSecretsRelayNeedsToken(TomSecretsRelayId id)` | **[C]** Whether pairing through `id` needs a token of this machine's own (GitHub's repository token; a relay server's instance token is not needed to pair). |
| `tomSecretsNewLinkId` | `String tomSecretsNewLinkId()` | **[C]** A new link id: 16 random bytes (128 bits) in base64url without padding. |
| `tomSecretsPairingLink` | `({String relay, String linkId})? tomSecretsPairingLink(TomSecretsPairingPeerKeys giver, TomSecretsPairingPeerKeys receiver)` | **[C]** The relay link two sides of a pairing agree on: the giving side's relay and link id when it names them, else the receiving side's; null when neither names one. |
| `tomSecretsLinkChannelId` | `String tomSecretsLinkChannelId(String linkId, {required bool hostIsGiver})` | **[C]** The channel on the relay of the link whose host is the giving side (`<linkId>-g`) or the receiving side (`<linkId>-r`). |
| `tomSecretsIsLinkRelay` | `bool tomSecretsIsLinkRelay(String relay)` | **[C]** Whether `relay` names a relay server that carries a link (`tsm:<url>`). |
| `tomSecretsPairingSetupProblem` | `String? tomSecretsPairingSetupProblem(TomSecretsPairingBundle bundle, {Set<String> ownTokens = const {}})` | Why a bundle cannot set a machine up, or null when it can: the primary must be in it, with its token when it is in a GitHub repository (in the bundle, or one this machine holds itself for one of `ownTokens`). |
| `tomSecretsReceivePairingForSetup` | `Future<TomSecretsPairingReceipt> tomSecretsReceivePairingForSetup({String? address, int? port, TomSecretsRelay? relay, Map<String, String> ownTokens = const {}, required TomSecretsPairingCode code, required String device, String? linkAddress, String? linkRelay, DateTime? now, Duration connectTimeout = const Duration(seconds: 10)})` | Receives a pairing for a machine being set up as `device`: connects to the giving machine's window at `address`:`port` with `code` — or, with `relay`, joins the pairing hosted there (`ownTokens`: this machine's own GitHub tokens, by `owner/name`) — answers with the public keys of fresh trust material (made `now`) and `linkAddress`, where this machine's approval link will listen (the giver records it and opens the link), and refuses a bundle it cannot be set up from (`tomSecretsPairingSetupProblem`); **[C]** `linkRelay`, a relay server the approval link may also go through, goes with a fresh link id; a `linkAddress` that is no approval link, or a `linkRelay` that is no relay server, throws `ArgumentError`. |
| `tomSecretsParsePairingAddress` | `(String host, int port) tomSecretsParsePairingAddress(String text)` | Splits `host:port` (an IPv6 address in brackets: `[fd00::1]:47900`) as the giving machine's Pairing screen shows it. Throws `FormatException`. |
| `tomSecretsSharingGroupOf` | `KdbxGroup? tomSecretsSharingGroupOf(KdbxFile file, {bool create = false})` | The `tsm.sharing` group at the root of `file`, made when `create`. |
| `tomSecretsMemberKeyEntries` | `List<KdbxEntry> tomSecretsMemberKeyEntries(KdbxFile file)` | The `member-key` entries of `file`, the newest first. |
| `tomSecretsMemberKeyOf` | `Future<TomSecretsMemberKey> tomSecretsMemberKeyOf(KdbxEntry entry)` | The member key an entry holds (its identity in `Password`). |
| `tomSecretsMemberKeyRecipientOf` | `TomSecretsAgeRecipient? tomSecretsMemberKeyRecipientOf(KdbxEntry entry)` | The public key a `member-key` or `member` entry names (`tsm.recipient`), read without the identity; null when absent or unreadable. |
| `tomSecretsAddMemberKey` | `KdbxEntry tomSecretsAddMemberKey(KdbxFile file, TomSecretsMemberKey key, {String title = 'Member key'})` | Writes `key` into `file` as a new `member-key` entry in `tsm.sharing`: the identity protected in `Password`, the recipient and fingerprint beside it. |
| `tomSecretsMembers` | `List<TomSecretsMember> tomSecretsMembers(KdbxFile file)` | The members of `file` whose entry holds a readable recipient, by name. |
| `tomSecretsAddMember` | `Future<TomSecretsMember> tomSecretsAddMember(KdbxFile file, {required String name, required TomSecretsAgeRecipient recipient, DateTime? checked})` | Adds `recipient` to the directory as a `member` entry named `name`, after `TomSecretsAgeRecipient.check`; refuses a recipient the directory holds (`duplicate`) and the user's own key (`ownKey`). |
| `tomSecretsMarkMemberChecked` | `void tomSecretsMarkMemberChecked(KdbxEntry entry, DateTime when)` | Records that the user compared the fingerprint of `entry` with its owner on `when` (its date, `tsm.checked`); the entry as it was goes to its history. |
| `tomSecretsCheckSharedVaultMembers` | `void tomSecretsCheckSharedVaultMembers(List<TomSecretsSharedVaultMember> members)` | Checks `members` for a recipients file: at least one, each with a hybrid key, none twice. |
| `tomSecretsWriteRecipientsFile` | `Future<Uint8List> tomSecretsWriteRecipientsFile(TomSecretsSharedVaultKeys keys)` | The recipients file of `keys`: its JSON encrypted with `age` to every member's recipient. |
| `tomSecretsReadRecipientsFile` | `Future<TomSecretsSharedVaultKeys> tomSecretsReadRecipientsFile(Uint8List file, TomSecretsMemberKey memberKey)` | The keys of the recipients file `file`, opened with `memberKey`; throws `TomSecretsSharedVaultException` (`notAMember`, `malformed`) or `TomSecretsAgeException` for a broken file. |
| `tomSecretsRecipientsFileName` | `String tomSecretsRecipientsFileName(String fileName)` | The recipients file beside the vault file `fileName` (`team.kdbx`, `team.kdbx.tsmx` → `team.keys.age`). |
| `tomSecretsNewSharedVault` | `KdbxFile tomSecretsNewSharedVault(String name, TomSecretsSharedVaultKeys keys, {String? purpose, KdbxArgon2 argon2 = tomSecretsDefaultArgon2})` | A new shared vault `name` (kind `shared`) opened by `keys`' key file alone. |
| `tomSecretsKeyId` | `String tomSecretsKeyId(List<int> bytes)` | The key id of `bytes` (a key file's, a repository key's): the first 8 bytes of their SHA-256 in hex. |
| `tomSecretsTakeNextKeys` | `bool tomSecretsTakeNextKeys(KdbxFile file, {required String device, required DateTime now, Iterable<String> primaryKeyIds = const []})` | **[C]** A device taking the keys of the guided rotations running in the primary `file`: the ids of the new keys it holds (the vaults' next and, while a rotation runs, current keys, and `primaryKeyIds`) go into its device record, and it leaves every rotation's `pending` whose new key it holds. Whether the primary changed. |
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
