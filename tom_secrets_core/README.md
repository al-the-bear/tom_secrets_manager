# tom_secrets_core

> Part of the **Tom Secrets Manager** by al-the-bear.
> © 2026 Peter Nicolai Alexis Kyaw — BSD-3-Clause, see [LICENSE](LICENSE).

The core of the Tom Secrets Manager: secret stores over KDBX files, overlays,
dimensions and the resolution of secret references, the GitHub vault cycle and
the outer encryption.

## Overview

`tom_secrets_core` is the pure-Dart library the secrets service, the desktop
app and the mobile app share. It holds no Flutter and no I/O policy of its
own: the service and the apps decide where files live and when to sync; the
core says what a vault is and what each operation does to it.

- **Vaults and locators.** A vault is a KDBX 4.1 file keyed through Argon2id
  (`tomSecretsNewVault`). A locator names where it lives: `file:<absolute
  path>`, `github:<owner>/<repo>[@<branch>]/<path>`, or `git:` (recognised).
  The primary vault lists every further vault with its keys, so unlocking the
  primary opens everything.
- **The KDBX mapping.** The core reads and writes KDBX only through
  `tom_kdbx_store`, and maps the product's concepts onto standard KDBX fields:
  the metadata entry `.tom-secrets` (store name, kind, file binding, the shared
  configuration `tsm.config`), the flat key `tsm.key`, the entry type, TOTP in
  the three conventions KeePassXC, AuthPass and KeePass write, attachments and
  KeePassXC's passkey fields. A file the product writes still opens in KeePass
  and KeePassXC.
- **Resolution and overlays.** A store is one KDBX file indexed for
  resolution. A group named `@<dimension>:<value>` (`@host:build-01`) binds
  every entry below it, so one logical path can hold a value per host,
  platform, environment or any declared dimension. The resolver ranks the
  candidates of a reference (a path, a `~uuid` or a flat key) against the
  request's dimension values, reports ambiguity, and reads the requested field
  as a masked value zeroed after use. `explain` shows the same ranking without
  reading a value.
- **The GitHub cycle and the offline cache.** A vault in a GitHub repository is
  one `tom_core_sync` sync unit over `tom_core_storage`'s GitHub backend (the
  REST API, no clone): open reads the head and the file, save commits on top
  of the base without force, a moved branch is merged three-way and committed
  again. The last file retrieved of each vault is kept, still encrypted, so a
  vault opens offline and an offline edit merges on reconnecting.
- **Merge.** Entries and groups are records keyed by UUID; a field only one
  side changed takes that side, a real conflict keeps the newer value, puts
  the loser into the entry's history and records the conflict until it is
  settled.
- **Key files and outer encryption.** A vault's credential may add a KeePass
  2.0 XML key file. A vault in a repository may also be stored as
  `<vault>.kdbx.tsmx`: encrypted once under a random file key wrapped under
  each repository key (XChaCha20-Poly1305 by default, AES-256-GCM
  selectable).
- **Compaction.** A history compaction rewrites a vault branch to one root
  commit (after a key change, or keeping the repository's retention), pushed
  over the git protocol; the cycle tells a compaction (followed silently) from
  a force push (the user chooses).
- **Importers.** 1Password (1PUX, CSV) and Enpass (JSON, CSV) exports are read
  into one source model and written into a vault the same way, with re-import
  matching, a dry-run preview and a report that names entries but never
  values. A vault or a group can be written back in Enpass's JSON layout.
- **Trust material, signed objects and grants.** Each device keeps its own
  approver and approval-link key pairs, an audit-log key and the approvers and
  hosts it recorded. Grants, revocations, approval records and key-change
  statements are signed with Ed25519 and ML-DSA-65 and accepted only when one
  recorded key signed with both; the grants live in the primary vault.
- **Approval codes and the approval link.** A waiting request shows a
  ten-character approval code, which a trusted device answers with a
  single-use token. The approval link connects a host's service and an
  approver's app: a Noise KK handshake with ML-KEM-768 paired to every
  Diffie-Hellman, then a ChaCha20-Poly1305 transport.
- **Pairing.** Two of the user's machines pair with a short code
  (`<number>-<word>-<word>`): SPAKE2 (RFC 9382), an ML-KEM-768 exchange inside,
  then the giving side's bundle of vault keys. The device records of the
  primary vault say what every device received.
- **First run and device settings.** The first run sets a machine up: the
  primary vault created or opened (local or on GitHub), its protection layers,
  the keys kept in the device keychain, or everything taken from a pairing.
  The device settings (lock policies, served stores, timeouts, key ages) live
  in a local settings container whose key is kept in the OS keychain, the
  primary vault or a key file.

## Installation

```bash
dart pub add tom_secrets_core
```

```yaml
dependencies:
  tom_secrets_core: ^0.2.1
```

Requires Dart SDK `^3.10.0`. The post-quantum algorithms come from `tom_pqc`,
whose build hook compiles its C sources for the target, so building an
application that uses this package needs the platform's C compiler as `tom_pqc`
describes it (clang on macOS and Linux, MSVC on Windows). The library re-exports the KDBX types a caller handles
(`Credentials`, `ProtectedValue`, `KdbxFile`, `KdbxEntry`, `KdbxGroup`,
`KdbxFormat`, ...) from `tom_kdbx_store`; using the GitHub cycle also needs
`tom_core_storage` for the storage backend.

## Features

### Vault model

| Feature | API |
| --- | --- |
| New vault, KDBX 4.1 with Argon2id | `tomSecretsNewVault`, `tomSecretsDefaultArgon2` |
| Vault locators (`file:`, `github:`, `git:`) | `TomSecretsVaultLocator.parse` |
| Metadata entry and shared configuration | `TomSecretsMetadata`, `TomSecretsConfig` |
| Stores indexed with overlays and flat keys | `TomSecretsStore`, `TomSecretsIndexedEntry` |
| Resolution with rank vectors, ambiguity and explanation | `TomSecretsResolver.resolve`, `TomSecretsResolver.explain` |
| Masked field values zeroed after use | `TomSecretsFieldValue` |
| TOTP in three KDBX conventions | `TomSecretsTotp` |
| Password generator | `TomSecretsPasswordGenerator`, `TomSecretsPasswordPolicy` |
| Auto-type: KeePass's sequence syntax, window associations, which entries fit a window | `tomSecretsParseAutoType`, `tomSecretsAutoTypeSequenceFor`, `tomSecretsAutoTypeCandidates` |
| Health report: weak (zxcvbn), reused, old, expiring and breached passwords, short keys (DP-179); the breach check over the Have I Been Pwned range API (the hash prefix only, padded) | `tomSecretsHealthReport`, `tomSecretsPasswordStrength`, `TomSecretsKeyStrength`, `TomSecretsBreachCheck` |
| URL matching of login entries (the Public Suffix List, `tsm.urlMatch`) | `tomSecretsMatchLogins`, `TomSecretsSiteUrl` |
| SSH keys: the typed `ssh-key` entry with `KeeAgent.settings`, reading a key file, generating Ed25519 or RSA 4096, retyping phase A's notes | `TomSecretsSshKeyInfo`, `tomSecretsGenerateSshKey`, `tomSecretsWriteSshKey`, `tomSecretsMigrateSshKeys` |
| The ssh-agent's side of SSH: private keys decoded with their passphrase and signing, the agent protocol with `session-bind`, agent grants per host and forwarding, what the agent serves | `TomSecretsSshPrivateKey`, `TomSecretsSshAgentConnection`, `TomSecretsSshGrantSecret`, `tomSecretsSshAgentStateOf` |
| The primary vault's list of further vaults | `TomSecretsPrimaryVaults`, `TomSecretsVaultKeys` |

### Protection

| Feature | API |
| --- | --- |
| KeePass 2.0 XML key files | `TomSecretsKeyFile` |
| Outer encryption `.tsmx`, key slots per repository key | `tomSecretsOuterEncrypt`, `tomSecretsOuterDecrypt`, `TomSecretsRepositoryKey` |
| A vault file as its store keeps it | `tomSecretsEncodeStored`, `tomSecretsDecodeStored` |

### Sync

| Feature | API |
| --- | --- |
| The GitHub cycle as a sync unit | `TomSecretsVaultUnit` |
| Three-way vault merge with conflict records | `tomSecretsMergeVaults`, `tomSecretsSettleConflicts` |
| Offline cache | `TomSecretsOfflineCache` |
| Compaction or force push | `tomSecretsClassifyMove`, `TomSecretsCommitReader` |
| History compaction and the repository's workflow files | `tomSecretsCompact`, `tomSecretsCompactionFiles` |

### Sharing

| Feature | API |
| --- | --- |
| Device trust material and key rotation | `TomSecretsTrust` |
| Signed objects (Ed25519 + ML-DSA-65) | `TomSecretsApproverKey`, `tomSecretsSignedBytes`, `tomSecretsAcceptedBy`, `tomSecretsAcceptKeyChange` |
| Grants group of the primary vault | `TomSecretsGrantsGroup` |
| Approval code and single-use token | `tomSecretsApprovalCode`, `tomSecretsCodeToken`, `tomSecretsRedeemToken` |
| Approval link (Noise KK + ML-KEM-768) | `TomSecretsLinkSession`, `TomSecretsApprovalChannel` |
| Pairing (SPAKE2, RFC 9382) | `TomSecretsPairingCode`, `tomSecretsGivePairing`, `tomSecretsReceivePairing`, `TomSecretsPairingWindow` |
| Device records | `TomSecretsDeviceRecords` |
| The `age` v1 file format (phase C): hybrid `mlkem768x25519` and classical `X25519` recipients, a passphrase (`scrypt`), the armour; checked against the age testkit and `filippo.io/age` | `tomSecretsAgeEncrypt`, `tomSecretsAgeEncryptPassphrase`, `tomSecretsAgeDecrypt`, `tomSecretsAgeArmor`, `TomSecretsAgeIdentity` |
| Single-entry exports (phase C): entries as a share for members' keys, a passphrase or a classical key, as armoured text, a QR code or a `.tsmshare` file; the `inbox/<member>/` folders' names and expiry | `TomSecretsShare`, `tomSecretsShareOf`, `tomSecretsWriteShare`, `tomSecretsReadShare`, `tomSecretsImportShare`, `tomSecretsShareFitsQr`, `tomSecretsInboxPath`, `tomSecretsInboxExpired` |
| Shared vaults (phase C): a key file alone, the recipients file `<vault>.keys.age` to the members' hybrid keys, adding and removing members | `TomSecretsSharedVaultKeys`, `tomSecretsWriteRecipientsFile`, `tomSecretsReadRecipientsFile`, `tomSecretsNewSharedVault` |
| The rotation record of the guided rotation with a migration period (phase C): one per target in `.tom-secrets/rotations` (the lock), its switch, migration end and who is still pending; the next keys in the primary, taken by every device, two-slot `.tsmx` files | `TomSecretsRotations`, `TomSecretsRotation`, `tomSecretsKeyId`, `TomSecretsPrimaryNextKeys`, `tomSecretsTakeNextKeys`, `tomSecretsJoinOuterKeys` |
| Member keys (phase C): hybrid `age` v1.3 keys (`age1pq1…`, X25519 + ML-KEM-768), other people's classical `age1…` keys for exports, fingerprints, the published key file, the `member-key` and `member` entries | `TomSecretsMemberKey`, `TomSecretsAgeRecipient`, `tomSecretsMemberKeyFile`, `tomSecretsReadMemberKeys`, `tomSecretsAddMemberKey`, `tomSecretsAddMember` |

### Import, export and device

| Feature | API |
| --- | --- |
| 1Password 1PUX and CSV | `tomSecretsRead1Pux`, `tomSecretsRead1PasswordCsv` |
| Enpass JSON and CSV | `tomSecretsReadEnpassJson`, `tomSecretsReadEnpassCsv` |
| Bitwarden JSON, plain or password-protected | `tomSecretsReadBitwardenJson`, `tomSecretsBitwardenNeedsPassword` |
| Browser CSV (Chrome, Edge, Firefox, Safari) | `tomSecretsReadBrowserCsv`, `TomSecretsCsvBrowser` |
| Another KDBX file, as a group or merged | `tomSecretsImportKdbxAsGroup`, `tomSecretsImportKdbxMerged` |
| One import for every source, with preview and re-import | `tomSecretsImport`, `TomSecretsImportReport` |
| Exports: KDBX under a new password, CSV, Bitwarden JSON, Enpass JSON | `tomSecretsExportKdbx`, `tomSecretsExportCsv`, `tomSecretsExportBitwardenJson`, `tomSecretsExportEnpassJson` |
| Passkeys in KeePassXC's fields | `TomSecretsPasskey`, `tomSecretsPasskeyPem` |
| First run, fresh or from a pairing | `TomSecretsFirstRun.run`, `TomSecretsFirstRun.runPaired` |
| Device settings container | `TomSecretsDeviceSettings`, `TomSecretsDeviceContainer`, `TomSecretsDeviceKeys` |

## Quick start

A vault in memory with one entry and an overlay of it for one host, resolved
by its flat key on two machines:

```dart
import 'package:tom_secrets_core/tom_secrets_core.dart';

void main() {
  final vault = tomSecretsNewVault(
    Credentials(ProtectedValue.fromString('demo-master-password')),
    'fleet',
  );

  // Telegram/Bot with the flat key telegram.bot_token ...
  final telegram = vault.createGroup(
    parent: vault.body.rootGroup,
    name: 'Telegram',
  );
  final bot = KdbxEntry.create(vault, telegram);
  telegram.addEntry(bot);
  bot.label = 'Bot';
  bot.setString(
    KdbxKeyCommon.PASSWORD,
    ProtectedValue.fromString('demo-shared'),
  );
  bot.setString(TomSecretsEntryFields.key, PlainValue('telegram.bot_token'));

  // ... and an overlay of it for the host build-01.
  final overlay = vault.createGroup(parent: telegram, name: '@host:build-01');
  final botOnHost = KdbxEntry.create(vault, overlay);
  overlay.addEntry(botOnHost);
  botOnHost.label = 'Bot';
  botOnHost.setString(
    KdbxKeyCommon.PASSWORD,
    ProtectedValue.fromString('demo-build-01'),
  );

  final store = TomSecretsStore.fromFile(vault, name: 'fleet');
  for (final host in ['build-01', 'laptop']) {
    final resolver = TomSecretsResolver(
      stores: [store],
      config: TomSecretsConfig.builtIn(),
      machine: TomSecretsMachine(host: host, platform: 'linux'),
    );
    final resolution = resolver.resolve('telegram.bot_token');
    print('$host: ${resolution.entry.pathText} ${resolution.value.text}');
    resolution.value.dispose();
  }
  // build-01: Telegram/Bot demo-build-01
  // laptop: Telegram/Bot demo-shared
}
```

## Examples

The package has no `example/` folder. The test suite's
`test/worked_examples_test.dart` runs the resolution examples of the design
row by row, and `test/support/vaults.dart` builds demo vaults in memory the
way the snippets below do.

## Usage

### Vaults and resolution

The shared configuration declares the dimensions in priority order (the
built-ins `host`, `platform` and `env` come first unless listed) and the
stores per environment:

```dart
final config = TomSecretsConfig.parse('''
dimensions:
  - name: env
    default: dev
    fallback_to_default: true
  - name: region
stores:
  prod:
    - name: fleet
      github: {repository: example-org/vault, path: fleet.kdbx.tsmx}
''');
print(config.dimensions.map((d) => d.name).toList());
// [host, platform, env, region]

final locator = TomSecretsVaultLocator.parse(
  'github:example-org/vault@main/fleet.kdbx.tsmx',
) as TomSecretsGitHubLocator;
print('${locator.repositorySlug} ${locator.branch} ${locator.fileName}');
// example-org/vault main fleet.kdbx.tsmx
```

A reference is a path (`fleet/Telegram/Bot`), a `~uuid` or a flat key, with
optional bindings (`[env:prod]db.main#UserName`). `resolve` answers the entry,
the field's value and every ranked candidate; it throws a
`TomSecretsResolveException` whose `kind` and `details` follow the client
protocol (not found, ambiguous, malformed, denied). `explain` answers the
request's values, every candidate kept with its rank vector or dropped by the
binding that drops it, and the outcome. A field value is a
`TomSecretsFieldValue`: read it with `withBytes` (the bytes are zeroed after
the callback) or `text`, and `dispose` it when done.

TOTP codes and generated passwords:

```dart
final totp = TomSecretsTotp.tryParseUri(
  'otpauth://totp/Example:demo?secret=JBSWY3DPEHPK3PXP&issuer=Example',
)!;
print(totp.code(DateTime.utc(2026, 1, 1)).length); // 6

final password = TomSecretsPasswordGenerator().generate(
  TomSecretsPasswordPolicy(
    length: 24,
    classes: {TomSecretsCharacterClass.lower, TomSecretsCharacterClass.digits},
  ),
);
print(password.length); // 24
```

Which login entries belong to a web page (the service's `match`, the OS
autofill): an entry's `URL` and `KP2A_URL*` fields, compared by its
`tsm.urlMatch` rule, by default the same site after the Public Suffix List:

```dart
final matches = tomSecretsMatchLogins(store.entries, 'https://login.example.com/');
for (final m in matches) {
  print('${m.title} ${m.userName} ${m.level.name}'); // exactHost before domain
}
print(tomSecretsRegistrableDomain('a.example.github.io')); // example.github.io
```

An SSH key entry (`tsm.type` `ssh-key`) holds the private key as an
attachment and a `KeeAgent.settings` attachment naming it, as KeePassXC's
SSH agent reads it; a passphrase, when the key has one, is in `Password`:

```dart
final key = await tomSecretsGenerateSshKey(comment: 'deploy@example'); // Ed25519
tomSecretsWriteSshKey(entry, attachmentName: 'id_ed25519', privateKey: key.privateKey);
print(key.info.publicKey);   // ssh-ed25519 AAAA... deploy@example
print(key.info.fingerprint); // SHA256:...
final retyped = tomSecretsMigrateSshKeys(vault); // phase A's notes holding a key
```

The service's ssh-agent signs with such a key without it leaving the
service: the key is decoded with its passphrase, and the agent protocol is a
connection over a backend that decides each signature:

```dart
final private = await TomSecretsSshPrivateKey.decode(
  key.privateKey,
  passphrase: entry.getString(KdbxKeyCommon.PASSWORD)?.getText(),
);
final signature = await private.sign(data); // ssh-ed25519 signature blob
private.dispose();

final connection = TomSecretsSshAgentConnection(backend); // one per socket
socket.add(TomSecretsSshAgentFramer.frame(await connection.handle(message)));
```

### Key files and outer encryption

A key file adds to the master password; the outer layer wraps the stored file
under a repository key. `tomSecretsEncodeStored` and `tomSecretsDecodeStored`
write and read a vault file as its store keeps it (`.kdbx`, or `.kdbx.tsmx`
when an outer key is given):

```dart
final keyFile = TomSecretsKeyFile.generate();
final credentials = keyFile.credentials('demo-master-password');
final vault = tomSecretsNewVault(credentials, 'fleet');

final outerKey = TomSecretsRepositoryKey.generate().toBase64();
const locator = 'github:example-org/vault/fleet.kdbx.tsmx';
final stored = await tomSecretsEncodeStored(locator, vault, outerKey: outerKey);
print(String.fromCharCodes(stored.sublist(0, 4))); // TSMX

final keyFileAgain = TomSecretsKeyFile.parse(keyFile.toBytes());
final reopened = await tomSecretsDecodeStored(
  locator,
  stored,
  keyFileAgain.credentials('demo-master-password'),
  outerKey: outerKey,
);
print(reopened.body.rootGroup.name.get()); // fleet
```

The key file is a KeePass 2.0 XML key file, so the same file opens the vault
in KeePass and KeePassXC. A `.tsmx` file no held key has a slot for throws
`TomKeyRequiredException`; an altered or moved file throws
`TomSecretsOuterException`. The fixtures in `test/fixtures/outer/` are files
every later version must still open.

### Sync, merge and compaction

`TomSecretsVaultUnit` keeps one vault converged with its remote. Its storage is
a `TomStorage` of `tom_core_storage` (`TomGitHubStorage` for a `github:`
vault); `TomSyncEngine` of `tom_core_sync` can drive it, or the caller pushes
directly:

```dart
Future<void> addEntry(TomStorage storage, Credentials credentials) async {
  final unit = await TomSecretsVaultUnit.open(
    locator: 'github:example-org/vault/fleet.kdbx.tsmx',
    storage: storage,
    credentials: credentials,
    device: 'build-01',
    codec: TomSecretsOuterCodec(
      path: 'fleet.kdbx.tsmx',
      keys: [TomSecretsRepositoryKey.fromBase64(demoOuterKeyBase64)],
    ),
    cache: TomSecretsOfflineCache(Directory('cache')),
  );
  final entry = KdbxEntry.create(unit.working, unit.working.body.rootGroup);
  unit.working.body.rootGroup.addEntry(entry);
  entry.label = 'New entry';
  unit.markEdited();
  final conflicts = await unit.push();
  print('${conflicts.length} conflicts, opened from ${unit.source}');
  await unit.dispose();
}
```

A save commits on top of the base and moves the branch without force; when
the branch moved, the unit reads the new head, merges three-way and commits
again, up to `maxPushAttempts`. Commit messages name the vault and the device
(`tsm: fleet.kdbx from build-01`); with
`TomGitHubStorage(committer: tomSecretsDeviceCommitter(device))` the device is
also the commit's author. When the remote cannot be reached or refuses the
token, the vault opens from the offline cache (`source`, `fetchedAt`,
`offlineReason`). `rekey` commits a re-keyed file as it is and switches the
unit to the new credentials.

The merge can also be called on its own:

```dart
final result = tomSecretsMergeVaults(base: base, ours: ours, theirs: theirs);
print(result.isClean);
for (final conflict in result.conflicts) {
  print('${conflict.entryUuid}: ${conflict.fields}');
}
```

A real conflict is recorded in the entry's custom data `tsm.conflict` until
`tomSecretsSettleConflicts`; a null `base` merges a force-pushed branch.

With a `TomSecretsCommitReader` (the GitHub REST API or a `tom_git`
repository), `tomSecretsClassifyMove` tells how the branch moved: ahead of the
base (merged), a compaction's root (`Tsm-Compacted-From`, followed silently),
or rewritten otherwise (a `TomSecretsHistoryRewritten` conflict; the user
chooses `takeRemote` or `mergeOverRemote`). `tomSecretsCompact` writes the
compaction over the git protocol with the old head as the expected value, and
`tomSecretsCompactionFiles` answers the workflow, script and configuration
each vault repository carries.

### Trust, approvals and pairing

Signed objects carry two signatures and are accepted only when one recorded
key made both:

```dart
final trust = TomSecretsTrust.create('laptop');
final approver = await trust.approverKey();
final grant = await approver.signObject(TomSecretsSignedLabels.grant, {
  'id': 'demo-grant',
  'host': 'build-01',
  'subject': 'exe:/usr/bin/demo',
  'secret': 'telegram.bot_token',
  'decision': 'always',
  'created': '2026-01-01T00:00:00Z',
  'approver': approver.keyId,
});
final accepted = await tomSecretsAcceptedBy(
  TomSecretsSignedLabels.grant,
  grant,
  [approver.publicKey],
);
print(accepted?.keyId == approver.keyId); // true
```

An approval code and the token a trusted device answers it with:

```dart
final code = tomSecretsApprovalCode(
  'build-01',
  'demo-approval',
  {'kind': 'exe', 'exe': '/usr/bin/demo', 'uid': 1000},
  ['telegram.bot_token'],
);
final tokenKey = List<int>.filled(32, 7); // demo key
final token = tomSecretsCodeToken(tokenKey, 'build-01', code, 'once');
final match = tomSecretsRedeemToken(token, [code], [tokenKey], 'build-01');
print('${code.length} ${token.length} ${match?.decision}'); // 10 26 once
```

The approval link runs over a `TomSecretsApprovalChannel`
(`TomSecretsSocketChannel` for TCP): the approver initiates
(`TomSecretsLinkSession.initiate`), the host responds
(`TomSecretsLinkSession.respond`). `TomSecretsTrust` rotates its key pairs:
`rotateApproverKey` answers the key-change statement signed by the old and the
new pair, `rotateLinkKey` keeps the previous link key for hosts the new one has
not reached yet (`linkKeyFor`).

Pairing starts from a code the giving side shows:

```dart
final pairing = TomSecretsPairingCode.generate();
print(pairing); // e.g. 558-clock-emerald
final typed = TomSecretsPairingCode.parse('558 Clock Emerald');
```

The giving side opens a `TomSecretsPairingWindow` and runs
`tomSecretsGivePairing`; the receiving side runs `tomSecretsReceivePairing`
(or `tomSecretsReceivePairingAt` over TCP). A machine being set up receives
with `tomSecretsReceivePairingForSetup` and is set up by
`TomSecretsFirstRun.runPaired`; its `linkAddress` tells the giving machine
where this one's approval link will listen (the device setting
`approvalLink` it is set up with), so the giver opens the link at once.

A person's **member key** (phase C) is a hybrid `age` v1.3 identity,
`AGE-SECRET-KEY-PQ-1…`, whose public key is the recipient `age1pq1…`
(X25519 + ML-KEM-768 through `tom_pqc`, about 1,960 characters). Both work
with the `age` command line from v1.3.0 on. People compare the
fingerprint, the base32 SHA-256 of the recipient:

```dart
final key = await TomSecretsMemberKey.generate();
print(key.recipient.shortFingerprint); // e.g. wgel hhnt 6gbn ci7u taaz
final published = tomSecretsMemberKeyFile(key.recipient, name: 'Alice');
tomSecretsAddMemberKey(primary, key); // the member-key entry, tsm.sharing

final [received] = tomSecretsReadMemberKeys(textFromBob);
await tomSecretsAddMember(primary, name: 'Bob', recipient: received.recipient);
key.dispose();
```

The published file is `age`'s recipients-file format (`age -R` reads it).
A classical `age1…` recipient is accepted for exports to that person only
(`canJoinSharedVaults` is false). The group `tsm.sharing` is never resolved
into and never exported.

Recipients files and exports are `age` v1 files (`tomSecretsAgeEncrypt`,
`tomSecretsAgeDecrypt`, `tomSecretsAgeArmor`): to hybrid recipients
(`mlkem768x25519`, HPKE with X-Wing) or to classical ones (`X25519`), never
both. A **shared vault** is opened by a key file alone; its keys travel in
the recipients file beside it, `<vault>.keys.age`, written to every
member's hybrid key:

```dart
final keys = TomSecretsSharedVaultKeys.generate('team', members: [
  (name: 'Alice', recipient: alice.recipient),
  (name: 'Bob', recipient: bob.recipient),
]);
final vault = tomSecretsNewSharedVault('team', keys);
final recipients = await tomSecretsWriteRecipientsFile(keys);

final opened = await tomSecretsReadRecipientsFile(recipients, bob);
final withCarol = keys.withMember((name: 'Carol', recipient: carol));
final withoutBob = withCarol.withoutMember(bob.recipient); // new keys
```

Its plaintext (`tsm-shared-vault-keys/1`) holds the key file, the
repository key and the members, so any member writes it again; removing a
member makes new keys, to which the vault is re-keyed in the same commit.

A **rotation with a migration period** (part-key-rotation) is recorded in
the vault's `.tom-secrets/rotations` group (`TomSecretsRotations`): one
record per target is the lock, and it names the old and new key ids, when
the period ends (`tomSecretsRotationPeriod`, 14 days) and who is still to
take up the new key. A member key rotates with the old and the new
recipient side by side in each recipients file (`withMember`, then
`withoutRecipient` at the finish); a shared vault's key with `rotated()`
(new keys, the same members).

The **guided rotation of the own vaults** keeps the next keys in the
primary: a vault's entry holds them beside its keys
(`TomSecretsVaultKeys.nextKeyFile`, `nextOuterKey`) and, after the switch,
the old repository key whose slot the file keeps (`previousOuterKey`); the
primary's own next keys are `TomSecretsPrimaryNextKeys`. Every device takes
them with `tomSecretsTakeNextKeys` (the key ids into its device record,
`TomSecretsDeviceRecords.missingKey` lists who still lacks one). An outer
key text may name several repository keys, the newest first
(`tomSecretsJoinOuterKeys`): `tomSecretsOuterCodecFor` then writes a slot
for each, so a device holding only the old key keeps reading the file.

A **share** (a single-entry export, BP-34) carries chosen entries to another
person as one `age` file: their fields, tags, attachments, expiry, type and
`tsm.key`, never the vault's metadata or history. It is written to members'
hybrid keys, under a passphrase (`age`'s `scrypt` recipient, work factor 18,
which the `age` command line opens with `age -d`) or to classical keys
alone:

```dart
final share = tomSecretsShareOf([entry],
    from: (name: 'Alice', fingerprint: alice.recipient.fingerprint));
final file = await tomSecretsWriteShare(share, recipients: [bob.recipient]);
final text = tomSecretsAgeArmor(file); // paste into a message
final qr = tomSecretsShareFitsQr(file); // one password to one member fits

final read = await tomSecretsReadShare(utf8.encode(text),
    [TomSecretsAgeHybridIdentity(bob)]);
tomSecretsImportShare(theirVault, group, read); // new entries
```

A shared vault's repository carries packages in `inbox/<member>/` folders
beside the vault (`tomSecretsInboxPath`, the member id the recipient's
fingerprint), named `<date>-<random>.age` (`tomSecretsNewInboxName`); a
package more than 30 days old is expired (`tomSecretsInboxExpired`) and
deleted by whichever member syncs next.

### Import and export

```dart
final source = tomSecretsReadEnpassJson(exportJson, vaultName: 'Personal');
final preview = tomSecretsImport(source, file: vault, dryRun: true);
print(preview.summary); // Import from Enpass: 13 added, 0 updated, 0 conflicts
final report = tomSecretsImport(source, file: vault);
final back = tomSecretsExportEnpassJson(vault);
print('${back.items} items, lost: ${back.lost}');
```

Each source vault goes to a target group (default `<source>/<vault name>`, or
a file of its own). Archived items are left out unless `includeArchived`.
Logins, notes and API credentials get the product's types; every other
category becomes a subgroup with all fields as custom fields. A re-import
matches `tsm.import.<source>.id`: unchanged items are skipped, items changed
only in the source are updated (old values into the history), items changed
on both sides become a conflict. Saving the vault after the user confirms is
the caller's. Passkeys that carry their private key are written into
KeePassXC's `KPEX_PASSKEY_*` fields (`tomSecretsPasskeyPem` converts PEM, DER,
a raw P-256 scalar or a JWK).

Bitwarden's JSON export (`tomSecretsReadBitwardenJson`, awaited: a
password-protected export derives its key) and the browsers' CSV exports
(`tomSecretsReadBrowserCsv`) read into the same source model. Another KDBX
file is copied into a new group (`tomSecretsImportKdbxAsGroup`) or, a copy
of the same vault, merged like two machines' edits
(`tomSecretsImportKdbxMerged`). The exports write a vault or a group as
KDBX under new credentials (`tomSecretsExportKdbx`), CSV
(`tomSecretsExportCsv`) or Bitwarden's JSON
(`tomSecretsExportBitwardenJson`), each naming what it does not carry; CSV
and the JSON exports hold every password in plaintext. The fixtures in
`test/fixtures/` (1Password, Enpass, Bitwarden, browser) are synthetic.

### First run and device settings

`TomSecretsFirstRun.run` sets a machine up from a `TomSecretsFirstRunSetup`:
the primary vault created or opened (`file:` or `github:`, the GitHub token
kept in the device keychain with its expiry), its key file and outer key, the
machine's settings and `bootstrap.yaml`. Nothing is written before the primary
opened. The settings are a `TomSecretsDeviceSettings` (lock modes of the
service and the app, default environment, served stores, refresh interval,
offline cache, timeouts, key ages) kept in a `TomSecretsDeviceContainer`,
whose key `TomSecretsDeviceKeys` keeps in the OS keychain, in the primary
vault (`@host:<host>/.tom-secrets/device`) or in a key file.

## Architecture

```text
 reference + request values
            │
            ▼
   TomSecretsResolver ──► TomSecretsStore (index, overlays) ──► KdbxFile
            │                                                     ▲
            ▼                                                     │
   TomSecretsResolution (entry, masked value)          tomSecretsDecodeStored
                                                       (.kdbx / .kdbx.tsmx)
                                                                  ▲
   TomSecretsVaultUnit ── TomStorage (GitHub REST) ───────────────┤
        │  merge: tomSecretsMergeVaults                           │
        └─ TomSecretsOfflineCache (last file, still encrypted) ───┘
```

### Key types

| Type | Responsibility |
| --- | --- |
| `TomSecretsConfig` | The shared configuration `tsm.config`: dimensions in priority order and stores per environment. |
| `TomSecretsVaultLocator` | Where a vault lives: `file:`, `github:` or `git:`. |
| `TomSecretsMetadata` | The metadata entry `.tom-secrets` of a vault file. |
| `TomSecretsEntryFields` | The product's reserved KDBX field names. |
| `TomSecretsStore` | One KDBX file under its store name, indexed for resolution. |
| `TomSecretsResolver` | Resolves and explains references over the stores for a machine. |
| `TomSecretsFieldValue` | A resolved value, masked and zeroed after use. |
| `TomSecretsTotp` | A TOTP secret in the three KDBX conventions, and its codes. |
| `TomSecretsPrimaryVaults` | The primary vault's list of further vaults with their keys. |
| `TomSecretsKeyFile` | A KeePass 2.0 XML key file and the composite credential. |
| `TomSecretsRepositoryKey` | A repository key of the outer encryption. |
| `TomSecretsOuterCodec` | The outer encryption as the sync cycle's codec. |
| `TomSecretsVaultUnit` | One vault kept converged with its remote. |
| `TomSecretsOfflineCache` | The last file retrieved of each vault. |
| `TomSecretsCommitReader` | Reads a vault branch's history to classify a move. |
| `TomSecretsTrust` | A device's trust material and key rotation. |
| `TomSecretsApproverKey` | A hybrid Ed25519 + ML-DSA-65 approver key pair that signs objects. |
| `TomSecretsGrantsGroup` | The grants group `tsm.grants/<host>` of the primary vault. |
| `TomSecretsLinkSession` | One approval-link session over a channel. |
| `TomSecretsPairingCode` | The short pairing code. |
| `TomSecretsDeviceRecords` | The primary vault's records of every paired device. |
| `TomSecretsImportSource` | An export read into the one source model. |
| `TomSecretsImportReport` | What an import did or would do, without values. |
| `TomSecretsFirstRun` | Sets a machine up, fresh or from a pairing. |
| `TomSecretsDeviceSettings` | The machine's local settings. |
| `TomSecretsDeviceContainer` | The device settings container and the trust material in it. |

## Ecosystem

```text
   tom_secrets_service        manager app (desktop, mobile)
              │                         │
              └────────────┬────────────┘
                           ▼
                   tom_secrets_core ───────────► tom_secrets_client
                           │                     (reference grammar)
      ┌──────────────┬─────┴──────────┬───────────────┐
      ▼              ▼                ▼               ▼
 tom_kdbx_store  tom_core_storage  tom_core_sync    tom_pqc
 (KDBX files)    (GitHub backend)  (sync, merge)   (ML-DSA, ML-KEM)
```

## Further documentation

- [API summaries](doc/api/api_summary_index.md): every public type, function
  and constant, by module and alphabetically.
- [The client protocol](https://github.com/al-the-bear/tom_secrets_clients/blob/main/protocol/protocol.md):
  references, the error kinds, signed objects, approval codes, the approval
  link and pairing, as the clients and the service speak them.
- [tom_secrets_service](../tom_secrets_service/README.md): the secrets service
  built on this core.
- `tom_kdbx_store`, `tom_core_storage` and `tom_core_sync`: the KDBX layer, the
  storage backends and the sync engine this package builds on.

## Status

Version 0.2.17. The test suite (`dart test`) covers the model, resolution, the
merge and the GitHub cycle against a fake GitHub server, the offline cache,
compaction, the outer encryption against the fixtures in `test/fixtures/outer/`,
the importers against synthetic exports, trust rotation, and the approval
material byte for byte against the protocol's vectors (signatures, approval
codes, the link handshake, RFC 9382's SPAKE2 vectors), the member keys
against keys `filippo.io/age` v1.3.2 made, and the `age` reader against the
age testkit's hybrid and scrypt vectors (`test/fixtures/age/`,
`test/fixtures/age_scrypt/`, C2SP CCTV); passphrase files and shares were
checked both ways with `filippo.io/age` v1.3.2.

### The live check on github.com

`test/live_github_compaction_test.dart` runs the compaction and the
force-push detection against a real repository: GitHub's receive-pack taking
the root commit and refusing a stale one, the REST reader finding the base's
blob and the compaction's root. It skips unless both variables are set; run it
by hand against a throwaway private repository holding nothing else (the test
rewrites its default branch), demo data only:

```bash
TSM_LIVE_GITHUB_TOKEN=$(gh auth token) \
TSM_LIVE_GITHUB_REPO=<owner>/<repo> \
  dart test test/live_github_compaction_test.dart
```

## Licence

BSD-3-Clause, see [LICENSE](LICENSE). The package carries the Public Suffix
List as data (`lib/src/public_suffix_list.g.dart`), which is under the
Mozilla Public License 2.0; see [THIRD_PARTY.md](THIRD_PARTY.md).
