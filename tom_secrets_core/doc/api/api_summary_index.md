# Tom Secrets Core API Reference: Index

The public API of `package:tom_secrets_core/tom_secrets_core.dart`, one summary per module. Every type, function and constant of `lib/src/` is listed in exactly one module summary; this index links them by module and alphabetically.

The library also re-exports the KDBX types the service and the apps handle from `tom_kdbx_store` (`Credentials`, `KdbxAutoTypeAssociation`, `KdbxAutoTypeSettings`, `KdbxEntry`, `KdbxFile`, `KdbxFormat`, `KdbxFormatException`, `KdbxGroup`, `KdbxInvalidKeyException`, `KdbxKey`, `KdbxKeyCommon`, `KdbxUuid`, `PlainValue`, `ProtectedValue`, `StringValue`); they are documented with that package.

## Table of Contents

- [Quick Navigation](#quick-navigation)
- [Vaults and Resolution Module](#vaults-and-resolution-module)
- [Key Files and Outer Encryption Module](#key-files-and-outer-encryption-module)
- [Sync, Merge and Compaction Module](#sync-merge-and-compaction-module)
- [Trust, Approvals and Pairing Module](#trust-approvals-and-pairing-module)
- [Import and Export Module](#import-and-export-module)
- [First Run and Device Settings Module](#first-run-and-device-settings-module)
- [Alphabetical Type Index](#alphabetical-type-index)
- [Alphabetical Function Index](#alphabetical-function-index)
- [Alphabetical Constant Index](#alphabetical-constant-index)

---

## Quick Navigation

| Module Reference | Module Guide | Description |
| --- | --- | --- |
| [Vaults and Resolution](api_summary_vaults.md) | [README](../../README.md#vaults-and-resolution) | Configuration, locators, the metadata entry, KDBX field conventions, new vaults, stores, resolution, TOTP, the password generator and the primary vault. |
| [Key Files and Outer Encryption](api_summary_protection.md) | [README](../../README.md#key-files-and-outer-encryption) | KeePass key files, the `.tsmx` outer encryption under repository keys, and the stored-vault codecs. |
| [Sync, Merge and Compaction](api_summary_sync.md) | [README](../../README.md#sync-merge-and-compaction) | The GitHub cycle as a sync unit, the three-way vault merge, the offline cache, history classification and compaction. |
| [Trust, Approvals and Pairing](api_summary_sharing.md) | [README](../../README.md#trust-approvals-and-pairing) | Trust material, signed objects and grants, approval codes, the approval link, pairing, device records, member keys, the `age` format, shared vaults, rotation records and shares. |
| [Import and Export](api_summary_import_export.md) | [README](../../README.md#import-and-export) | 1Password and Enpass imports, passkeys, and the Enpass JSON export. |
| [First Run and Device Settings](api_summary_device.md) | [README](../../README.md#first-run-and-device-settings) | The first run of a machine and the device settings container. |

---

## Vaults and Resolution Module

### Types

| Type | Kind | Description | Link |
| --- | --- | --- | --- |
| `TomSecretsConfigException` | final class | A configuration that cannot be read. | [→](api_summary_vaults.md#tomsecretsconfigexception) |
| `TomSecretsDimension` | final class | One dimension of the configuration. | [→](api_summary_vaults.md#tomsecretsdimension) |
| `TomSecretsStoreLocation` | sealed class | Where a store's file is kept. | [→](api_summary_vaults.md#tomsecretsstorelocation) |
| `TomSecretsLocalLocation` | final class | A file on the local disk. | [→](api_summary_vaults.md#tomsecretslocallocation) |
| `TomSecretsGitHubLocation` | final class | A file in a GitHub repository. | [→](api_summary_vaults.md#tomsecretsgithublocation) |
| `TomSecretsStoreSpec` | final class | One store of an environment: its name and where its file is. | [→](api_summary_vaults.md#tomsecretsstorespec) |
| `TomSecretsConfig` | final class | The shared configuration. | [→](api_summary_vaults.md#tomsecretsconfig) |
| `TomSecretsLocatorException` | final class | A locator that cannot be read. | [→](api_summary_vaults.md#tomsecretslocatorexception) |
| `TomSecretsVaultLocator` | sealed class | Where a vault is. | [→](api_summary_vaults.md#tomsecretsvaultlocator) |
| `TomSecretsFileLocator` | final class | A KDBX file on this device. | [→](api_summary_vaults.md#tomsecretsfilelocator) |
| `TomSecretsGitHubLocator` | final class | A KDBX file in a private GitHub repository, read and written through the REST API. | [→](api_summary_vaults.md#tomsecretsgithublocator) |
| `TomSecretsGitLocator` | final class | A KDBX file on another git server over smart HTTP; recognised, not advertised in phase A. | [→](api_summary_vaults.md#tomsecretsgitlocator) |
| `TomSecretsMetadataFields` | abstract final class | The field names of the metadata entry. | [→](api_summary_vaults.md#tomsecretsmetadatafields) |
| `TomSecretsVaultKind` | enum | What a vault is for. | [→](api_summary_vaults.md#tomsecretsvaultkind) |
| `TomSecretsMetadataException` | final class | Metadata that cannot be read. | [→](api_summary_vaults.md#tomsecretsmetadataexception) |
| `TomSecretsMetadata` | final class | The content of a metadata entry. | [→](api_summary_vaults.md#tomsecretsmetadata) |
| `TomSecretsEntryFields` | abstract final class | The field names the product reserves (`tsm.` prefix) and the foreign conventions it reads. | [→](api_summary_vaults.md#tomsecretsentryfields) |
| `TomSecretsEntryType` | enum | What kind of secret an entry holds (`tsm.type`). | [→](api_summary_vaults.md#tomsecretsentrytype) |
| `TomSecretsFieldValue` | final class | The value of one field of an entry: text (a string field, the TOTP code) or bytes (an attachment), held as a `TomProtectedValue` (masked, read through `withBytes`). | [→](api_summary_vaults.md#tomsecretsfieldvalue) |
| `TomSecretsIndexedEntry` | final class | One entry of a store as resolution sees it. | [→](api_summary_vaults.md#tomsecretsindexedentry) |
| `TomSecretsStore` | final class | A store: a KDBX file under its store name, with its metadata and index. | [→](api_summary_vaults.md#tomsecretsstore) |
| `TomSecretsResolveException` | final class | A reference that does not resolve: `not_found`, `ambiguous`, `malformed` or `denied`, with the protocol's `details` (never a value). | [→](api_summary_vaults.md#tomsecretsresolveexception) |
| `TomSecretsMachine` | final class | The machine a request is resolved for: its current value per dimension. | [→](api_summary_vaults.md#tomsecretsmachine) |
| `TomSecretsRankedCandidate` | final class | One kept candidate with its rank vector (one rank per dimension, in priority order: 2 bound to the request's value, 1 bound to `default` and kept by the fallback, 0 unbound). | [→](api_summary_vaults.md#tomsecretsrankedcandidate) |
| `TomSecretsResolution` | final class | A resolved reference: the winning entry and the field's value. | [→](api_summary_vaults.md#tomsecretsresolution) |
| `TomSecretsExplainedCandidate` | final class | One candidate of an explained request (step 1) and what step 2 did with it: kept with its rank vector, or dropped by one of its bindings. | [→](api_summary_vaults.md#tomsecretsexplainedcandidate) |
| `TomSecretsExplainOutcome` | enum | How an explained request ends (step 3). | [→](api_summary_vaults.md#tomsecretsexplainoutcome) |
| `TomSecretsExplanation` | final class | A request explained step by step (`TomSecretsResolver.explain`): the request's values, every candidate kept (best first) or dropped (in the order found), and the outcome with its winner or the tied candidates. | [→](api_summary_vaults.md#tomsecretsexplanation) |
| `TomSecretsResolver` | final class | Resolves references over `stores` under `config` for `machine`. | [→](api_summary_vaults.md#tomsecretsresolver) |
| `TomSecretsTotpFields` | abstract final class | The TOTP field names. | [→](api_summary_vaults.md#tomsecretstotpfields) |
| `TomSecretsTotpAlgorithm` | enum | The hash a TOTP code is made with. | [→](api_summary_vaults.md#tomsecretstotpalgorithm) |
| `TomSecretsTotp` | final class | A TOTP secret with its parameters. | [→](api_summary_vaults.md#tomsecretstotp) |
| `TomSecretsUrlMatchRule` | enum | How an entry's URLs match a page (`tsm.urlMatch`). | [→](api_summary_vaults.md#tomsecretsurlmatchrule) |
| `TomSecretsUrlMatchLevel` | enum | How closely an entry matches: exact host, domain. | [→](api_summary_vaults.md#tomsecretsurlmatchlevel) |
| `TomSecretsSiteUrl` | final class | A web URL normalised for matching. | [→](api_summary_vaults.md#tomsecretssiteurl) |
| `TomSecretsLoginMatch` | final class | A login entry matching a page. | [→](api_summary_vaults.md#tomsecretsloginmatch) |
| `TomSecretsSshKeyFormat` | enum | How a private key file is written. | [→](api_summary_vaults.md#tomsecretssshkeyformat) |
| `TomSecretsSshKeyInfo` | final class | A private key file's type, public key and fingerprint. | [→](api_summary_vaults.md#tomsecretssshkeyinfo) |
| `TomSecretsSshKeyAlgorithm` | enum | Ed25519 or RSA, for a generated key. | [→](api_summary_vaults.md#tomsecretssshkeyalgorithm) |
| `TomSecretsGeneratedSshKey` | final class | A generated SSH key. | [→](api_summary_vaults.md#tomsecretsgeneratedsshkey) |
| `TomSecretsCertificateKeyType` | enum | A certificate's key algorithm | [→](api_summary_vaults.md#tomsecretscertificatekeytype) |
| `TomSecretsCertificateException` | final class | A certificate refused as unreadable: `message`. | [→](api_summary_vaults.md#tomsecretscertificateexception) |
| `TomSecretsCertificateInfo` | final class | **[C]** What an X.509 certificate says (part-structure, DP-179). | [→](api_summary_vaults.md#tomsecretscertificateinfo) |
| `TomSecretsCertificateAlgorithm` | enum | The key a certificate is generated with (DP-179) | [→](api_summary_vaults.md#tomsecretscertificatealgorithm) |
| `TomSecretsGeneratedCertificate` | final class | A generated certificate: `certificatePem` (self-signed), `privateKeyPem` (unencrypted: the vault protects it), `csrPem` (a PKCS#10 request for a CA) and `info`. | [→](api_summary_vaults.md#tomsecretsgeneratedcertificate) |
| `TomSecretsPgpKeyException` | final class | A PGP key refused as unreadable: `message`. | [→](api_summary_vaults.md#tomsecretspgpkeyexception) |
| `TomSecretsPgpKeyInfo` | final class | **[C]** What an OpenPGP key says (part-structure, DP-179), read through `dart_pg`. | [→](api_summary_vaults.md#tomsecretspgpkeyinfo) |
| `TomSecretsPgpKeyAlgorithm` | enum | The key a PGP key is generated with (DP-179) | [→](api_summary_vaults.md#tomsecretspgpkeyalgorithm) |
| `TomSecretsGeneratedPgpKey` | final class | A generated PGP key: `privateArmored` (locked with `passphrase`), `publicArmored`, the generated `passphrase` and `info`. | [→](api_summary_vaults.md#tomsecretsgeneratedpgpkey) |
| `TomSecretsSshAgentServing` | enum | Whether the ssh-agent serves an entry's key, and why not. | [→](api_summary_vaults.md#tomsecretssshagentserving) |
| `TomSecretsSshPrivateKey` | final class | A decoded private key the agent signs with. | [→](api_summary_vaults.md#tomsecretssshprivatekey) |
| `TomSecretsSshKeyException` | final class | A key file that cannot be used. | [→](api_summary_vaults.md#tomsecretssshkeyexception) |
| `TomSecretsSshAgentConnection` | final class | One connection of the SSH agent protocol. | [→](api_summary_vaults.md#tomsecretssshagentconnection) |
| `TomSecretsSshAgentIdentity` | final class | A key the agent offers. | [→](api_summary_vaults.md#tomsecretssshagentconnection) |
| `TomSecretsSshAgentMessage` | abstract final class | The agent protocol's message numbers. | [→](api_summary_vaults.md#tomsecretssshagentmessage) |
| `TomSecretsSshGrantSecret` | final class | An agent grant's secret: keys, hosts, forwarding. | [→](api_summary_vaults.md#tomsecretssshgrantsecret) |
| `TomSecretsKeeAgentSettings` | final class | The `KeeAgent.settings` attachment. | [→](api_summary_vaults.md#tomsecretskeeagentsettings) |
| `TomSecretsCharacterClass` | enum | The character classes a generated password draws from. | [→](api_summary_vaults.md#tomsecretscharacterclass) |
| `TomSecretsPasswordPolicy` | final class | What a generated password is made of. | [→](api_summary_vaults.md#tomsecretspasswordpolicy) |
| `TomSecretsPasswordGenerator` | final class | Generates passwords under a `TomSecretsPasswordPolicy`. | [→](api_summary_vaults.md#tomsecretspasswordgenerator) |
| `TomSecretsVaultFields` | abstract final class | The fields of a vault entry. | [→](api_summary_vaults.md#tomsecretsvaultfields) |
| `TomSecretsVaultKeys` | final class | What the primary keeps about one further vault. | [→](api_summary_vaults.md#tomsecretsvaultkeys) |
| `TomSecretsPrimaryVaults` | final class | A primary vault's further vaults. | [→](api_summary_vaults.md#tomsecretsprimaryvaults) |
| `TomSecretsPrimaryNextKeys` | final class | The primary vault's own keys during a guided rotation, in `.tom-secrets/next-keys`. | [→](api_summary_vaults.md#tomsecretsprimarynextkeys) |
| `TomSecretsHealthIssue` | enum | What the health report flags. | [→](api_summary_vaults.md#tomsecretshealthissue) |
| `TomSecretsHealthPolicy` | final class | The report's thresholds. | [→](api_summary_vaults.md#tomsecretshealthpolicy) |
| `TomSecretsPasswordStrength` | final class | How guessable a password is (zxcvbn). | [→](api_summary_vaults.md#tomsecretspasswordstrength) |
| `TomSecretsKeyStrength` | abstract final class | Today's minimum key lengths (DP-179). | [→](api_summary_vaults.md#tomsecretskeystrength) |
| `TomSecretsHealthEntry` | final class | An entry the health report reads. | [→](api_summary_vaults.md#tomsecretshealthentry) |
| `TomSecretsHealthFinding` | final class | One flag of the health report. | [→](api_summary_vaults.md#tomsecretshealthfinding) |
| `TomSecretsHealthReport` | final class | The health report: its findings by issue, then by store and title. | [→](api_summary_vaults.md#tomsecretshealthreport) |
| `TomSecretsBreachCheck` | final class | The breach check over the Have I Been Pwned range API: only a password's five-character SHA-1 prefix leaves the device, with `Add-Padding: true`; counts cached per hash in memory. | [→](api_summary_vaults.md#tomsecretsbreachcheck) |
| `TomSecretsBreachCheckException` | final class | The breach check could not ask. | [→](api_summary_vaults.md#tomsecretsbreachcheckexception) |
| `TomSecretsAutoTypeKey` | enum | A key auto-type presses that is no character. | [→](api_summary_vaults.md#tomsecretsautotypekey) |
| `TomSecretsAutoTypeModifier` | enum | A modifier held while a key is pressed. | [→](api_summary_vaults.md#tomsecretsautotypemodifier) |
| `TomSecretsAutoTypeAction` | sealed class | One step of a parsed auto-type sequence. | [→](api_summary_vaults.md#tomsecretsautotypeaction) |
| `TomSecretsAutoTypeText` | final class | Text typed as characters, each as Unicode where the OS allows. | [→](api_summary_vaults.md#tomsecretsautotypetext) |
| `TomSecretsAutoTypeKeyPress` | final class | A special key or a character pressed with modifiers. | [→](api_summary_vaults.md#tomsecretsautotypekeypress) |
| `TomSecretsAutoTypeDelay` | final class | A pause (`{DELAY n}`). | [→](api_summary_vaults.md#tomsecretsautotypedelay) |
| `TomSecretsAutoTypeKeyDelay` | final class | The pause between keys from here on (`{DELAY=n}`). | [→](api_summary_vaults.md#tomsecretsautotypekeydelay) |
| `TomSecretsAutoTypeException` | final class | A sequence that cannot be typed. | [→](api_summary_vaults.md#tomsecretsautotypeexception) |
| `TomSecretsAutoTypeCandidate` | final class | An entry auto-type may type into a window, and why. | [→](api_summary_vaults.md#tomsecretsautotypecandidate) |

### Functions

| Function | Description | Link |
| --- | --- | --- |
| `tomSecretsGitHubTokenHandle` | The device keychain's handle of the GitHub token for `owner`/`repository`. | [→](api_summary_vaults.md#functions) |
| `tomSecretsGitHubTokenExpiryHandle` | The device keychain's handle of the expiry (ISO 8601) recorded with the GitHub token for `owner`/`repository` when it was entered. | [→](api_summary_vaults.md#functions) |
| `tomSecretsKeyFileHandle` | The device keychain's handle of the key file of the vault at `locator`: `tsm.key-file.<id>`, the id the first 16 hex digits of SHA-256 over the vault's identity (an OS keychain refuses `/` in an item's name). | [→](api_summary_vaults.md#functions) |
| `tomSecretsRepositoryKeyHandle` | The device keychain's handle of the repository key (base64) of the repository the vault at `locator` is in: `tsm.repository-key.<id>`, the id as for `tomSecretsKeyFileHandle` over the repository's identity. | [→](api_summary_vaults.md#functions) |
| `tomSecretsParseFileBinding` | Reads a file binding (`env=prod;region=eu`); an empty text binds nothing. | [→](api_summary_vaults.md#functions) |
| `tomSecretsMetadataEntry` | The metadata entry of `file`, or null. | [→](api_summary_vaults.md#functions) |
| `tomSecretsIsPasskeyField` | Whether `field` is a passkey field the client endpoint never serves. | [→](api_summary_vaults.md#functions) |
| `tomSecretsIsReservedName` | Whether `name` is reserved for the product (`tsm.` names, `@` groups). | [→](api_summary_vaults.md#functions) |
| `tomSecretsUuidHex` | The 32 lower-case hex digits of `uuid`, as `~uuid` references write it. | [→](api_summary_vaults.md#functions) |
| `tomSecretsUuidFromHex` | The `KdbxUuid` of 32 hex digits. | [→](api_summary_vaults.md#functions) |
| `tomSecretsNewVault` | A new, empty vault named `name`, opened with `credentials` (a password, a key file or both): KDBX 4.1, its key derived through `argon2`, which must be Argon2id, and the product's format version in its custom data. | [→](api_summary_vaults.md#functions) |
| `tomSecretsOverlayBinding` | The binding an overlay group's `name` stands for (`@host:build-01`), or null when the name is not one. | [→](api_summary_vaults.md#functions) |
| `tomSecretsBase32Encode` | RFC 4648 base32 without padding. | [→](api_summary_vaults.md#functions) |
| `tomSecretsMatchLogins` | The login entries of a page, in their order. | [→](api_summary_vaults.md#functions) |
| `tomSecretsGenerateSshKey` | A new SSH key, Ed25519 or RSA 4096. | [→](api_summary_vaults.md#functions) |
| `tomSecretsGenerateCertificate` | A new certificate (DP-179): its key on ECDSA P-384, or RSA 4096; self-signed with SHA-384 (SHA-256 for RSA), with a CSR beside it. | [→](api_summary_vaults.md#functions) |
| `tomSecretsWriteCertificate` | Makes `entry` a `certificate` entry: the PEM certificate and private key, or a PKCS#12 bundle, as attachments, the passphrase in `Password`, Expires from `notAfter` (a bundle's by hand). Answers what the certificate says, or null for a bundle. | [→](api_summary_vaults.md#functions) |
| `tomSecretsCertificateOf` | What the certificate of a `certificate` entry says, or null (a PKCS#12 bundle, a broken PEM). | [→](api_summary_vaults.md#functions) |
| `tomSecretsIsPkcs12` | Whether `bytes` look like a PKCS#12 bundle (DER, not PEM text). | [→](api_summary_vaults.md#functions) |
| `tomSecretsGeneratePgpKey` | A new OpenPGP key (DP-179): ECDSA P-384 with an ECDH subkey, or RSA 4096; its secret key locked with `passphrase` (default 32 random characters). | [→](api_summary_vaults.md#functions) |
| `tomSecretsWritePgpKey` | Makes `entry` a `pgp-key` entry: the secret and public key as attachments (the public key read from the secret one when not given), the passphrase in `Password`, Expires the key's expiry. Answers what the key says, or null for one the library does not read. | [→](api_summary_vaults.md#functions) |
| `tomSecretsPgpKeyOf` | What the key of a `pgp-key` entry says (read from its public key), or null. | [→](api_summary_vaults.md#functions) |
| `tomSecretsPgpPublicOf` | The public key block of a secret key block, as `gpg --export` writes it. | [→](api_summary_vaults.md#functions) |
| `tomSecretsTypedFileField` | The field `getFile` serves for a typed key entry asked without a field: a certificate's private key (or PKCS#12 bundle, else its certificate), a PGP key's secret key (else its public key); null for other entries. | [→](api_summary_vaults.md#functions) |
| `tomSecretsSshKeyOf` | An entry's SSH key. | [→](api_summary_vaults.md#functions) |
| `tomSecretsWriteSshKey` | Makes an entry an SSH key entry. | [→](api_summary_vaults.md#functions) |
| `tomSecretsSshKeyCandidates` | The untyped entries holding an SSH key. | [→](api_summary_vaults.md#functions) |
| `tomSecretsMigrateSshKeys` | Retypes them as SSH key entries. | [→](api_summary_vaults.md#functions) |
| `tomSecretsSshAgentStateOf` | Whether the agent serves an entry's key. | [→](api_summary_vaults.md#functions) |
| `tomSecretsKeeAgentSettingsOf` | An entry's KeeAgent settings. | [→](api_summary_vaults.md#functions) |
| `tomSecretsWriteKeeAgentSettings` | Writes an entry's KeeAgent settings. | [→](api_summary_vaults.md#functions) |
| `tomSecretsSshVerify` | Whether an SSH signature verifies. | [→](api_summary_vaults.md#functions) |
| `tomSecretsSshFingerprint` | A public key's `SHA256:` fingerprint. | [→](api_summary_vaults.md#functions) |
| `tomSecretsKnownHostNames` | The names `known_hosts` lists for a host key. | [→](api_summary_vaults.md#functions) |
| `tomSecretsBcryptPbkdf` | OpenBSD's `bcrypt_pbkdf`. | [→](api_summary_vaults.md#functions) |
| `tomSecretsMatchSiteUrl` | How an entry URL matches a page under a rule. | [→](api_summary_vaults.md#functions) |
| `tomSecretsEntryUrls` | An entry's `URL` and `KP2A_URL*` fields. | [→](api_summary_vaults.md#functions) |
| `tomSecretsRegistrableDomain` | The registrable domain after the Public Suffix List. | [→](api_summary_vaults.md#functions) |
| `tomSecretsAsciiHost` | A host lower-case with punycode labels. | [→](api_summary_vaults.md#functions) |
| `tomSecretsBase32Decode` | RFC 4648 base32, any case, spaces, dashes and padding ignored; null when it is not base32. | [→](api_summary_vaults.md#functions) |
| `tomSecretsPasswordStrength` | The strength of `password` (zxcvbn, its first 100 characters); `userInputs` are words it should not be built from (the entry's title, user name, site). | [→](api_summary_vaults.md#functions) |
| `tomSecretsBreachCheckExcluded` | Whether an entry is kept out of the breach check (`tsm.breachCheck` `off`). | [→](api_summary_vaults.md#functions) |
| `tomSecretsSetBreachCheckExcluded` | Keeps an entry out of the breach check, or lets it in again; its old state in its history. | [→](api_summary_vaults.md#functions) |
| `tomSecretsPasswordOf` | An entry's password, or null when it has none. | [→](api_summary_vaults.md#functions) |
| `tomSecretsPasswordChanged` | When an entry's current password was set, read from its history. | [→](api_summary_vaults.md#functions) |
| `tomSecretsPasswordHash` | The SHA-1 of a password in upper-case hex, as the range API compares it; kept in memory only. | [→](api_summary_vaults.md#functions) |
| `tomSecretsHealthReport` | The health report: weak, reused, old and breached login passwords, expiring entries, short SSH keys. | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeValues` | An entry's placeholder values: `{USERNAME}`, `{PASSWORD}`, `{TITLE}`, `{URL}`, `{NOTES}`, `{TOTP}`, `{S:<field>}`. | [→](api_summary_vaults.md#functions) |
| `tomSecretsParseAutoType` | Parses a sequence in KeePass's syntax: placeholders as text, special keys with repeat counts, `+ ^ % @` modifiers on a key or a group, `~`, `{DELAY n}`, `{DELAY=n}`, escaped characters. | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeWindowMatches` | Whether a window title matches an association pattern: `*`/`?` wildcards over the whole title or `//regex//`, any case. | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeEnabled` | Whether auto-type is on for an entry (its own setting and the nearest group's). | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeSequenceFor` | The sequence typed for an entry into a window: a matching association's, else the entry's, the group's, the default; null when off. | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeCandidates` | The logins and API tokens fitting a window: a matching association first, then titles the window title holds. | [→](api_summary_vaults.md#functions) |

### Global Variables

| Variable | Type | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsDefaultValue` | `String` | The reserved value every dimension has. | [→](api_summary_vaults.md#constants) |
| `tomSecretsBuiltInDimensions` | `List<String>` | The dimensions every configuration has, in their default priority order. | [→](api_summary_vaults.md#constants) |
| `tomSecretsPlatforms` | `Set<String>` | The values of the built-in `platform` dimension. | [→](api_summary_vaults.md#constants) |
| `tomSecretsMetadataTitle` | `String` | The title of the metadata entry. | [→](api_summary_vaults.md#constants) |
| `tomSecretsMetadataFormat` | `int` | The metadata format this library reads and writes. | [→](api_summary_vaults.md#constants) |
| `tomSecretsGrantsGroup` | `String` | The group holding the grants of every host (primary vault only); never a place references resolve into. | [→](api_summary_vaults.md#constants) |
| `tomSecretsSharingGroup` | `String` | The group of the primary vault holding the member key and the directory of members (part-sharing); never a place references resolve into, never exported. | [→](api_summary_vaults.md#constants) |
| `tomSecretsOverlayPrefix` | `String` | The first character of an overlay group's name. | [→](api_summary_vaults.md#constants) |
| `tomSecretsFavoriteTag` | `String` | The tag that marks a favourite. | [→](api_summary_vaults.md#constants) |
| `tomSecretsDefaultArgon2` | `KdbxArgon2` | The key derivation of a new vault: Argon2id over 64 MiB, 3 iterations, 1 lane. | [→](api_summary_vaults.md#constants) |
| `tomSecretsAmbiguousCharacters` | `String` | The characters `TomSecretsPasswordPolicy.excludeAmbiguous` leaves out, because they are easily confused when read or typed. | [→](api_summary_vaults.md#constants) |
| `tomSecretsProductGroup` | `String` | The root group holding the product's own groups (never resolved into). | [→](api_summary_vaults.md#constants) |
| `tomSecretsVaultsGroup` | `String` | The subgroup holding the further vaults. | [→](api_summary_vaults.md#constants) |
| `tomSecretsCertificateAttachment` | `String` | The attachment holding a certificate entry's certificate (and chain): `certificate.pem`. | [→](api_summary_vaults.md#constants) |
| `tomSecretsCertificateKeyAttachment` | `String` | The attachment holding a certificate entry's private key: `private-key.pem`. | [→](api_summary_vaults.md#constants) |
| `tomSecretsPkcs12Attachment` | `String` | The attachment holding a certificate entry's PKCS#12 bundle: `certificate.p12`. | [→](api_summary_vaults.md#constants) |
| `tomSecretsPgpPrivateAttachment` | `String` | The attachment holding a PGP key entry's armoured secret key: `private-key.asc`. | [→](api_summary_vaults.md#constants) |
| `tomSecretsPgpPublicAttachment` | `String` | The attachment holding a PGP key entry's armoured public key: `public-key.asc`. | [→](api_summary_vaults.md#constants) |
| `tomSecretsNextKeysGroup` | `String` | The subgroup holding the primary's own next keys during a guided rotation. | [→](api_summary_vaults.md#constants) |
| `tomSecretsStrengthMaxLength` | `int` | The longest prefix of a password the strength estimator reads (100). | [→](api_summary_vaults.md#constants) |
| `tomSecretsBreachCheckField` | `KdbxKey` | `tsm.breachCheck`, the field that keeps an entry out of the breach check (`off`). | [→](api_summary_vaults.md#constants) |
| `tomSecretsSshAgentMaxMessage` | `int` | The largest message the agent reads, 256 KiB. | [→](api_summary_vaults.md#constants) |
| `tomSecretsSshAgentMaxBindings` | `int` | At most this many `session-bind`s per connection, 16. | [→](api_summary_vaults.md#constants) |
| `tomSecretsSshAgentKeyTypes` | `Set<String>` | The key types the agent signs with. | [→](api_summary_vaults.md#constants) |
| `tomSecretsDefaultAutoTypeSequence` | `String` | `{USERNAME}{TAB}{PASSWORD}{ENTER}`, typed when neither the entry nor its groups name a sequence. | [→](api_summary_vaults.md#constants) |

---

## Key Files and Outer Encryption Module

### Types

| Type | Kind | Description | Link |
| --- | --- | --- | --- |
| `TomSecretsKeyFileException` | final class | A key file that is not a KeePass 2.0 key file or whose hash is wrong. | [→](api_summary_protection.md#tomsecretskeyfileexception) |
| `TomSecretsKeyFile` | final class | A KeePass 2.0 XML key file. | [→](api_summary_protection.md#tomsecretskeyfile) |
| `TomSecretsOuterCipher` | enum | The content and slot cipher of a repository. | [→](api_summary_protection.md#tomsecretsoutercipher) |
| `TomSecretsOuterException` | final class | A file that is not a `.tsmx` file, of a format or cipher this library does not read, or that fails its authentication (altered, truncated, or moved to another path). | [→](api_summary_protection.md#tomsecretsouterexception) |
| `TomSecretsRepositoryKey` | final class | A 256-bit repository key. | [→](api_summary_protection.md#tomsecretsrepositorykey) |
| `TomSecretsOuterCodec` | final class | The outer layer as the GitHub cycle's codec: decrypts with whichever of `keys` has a slot, encrypts with a slot for each of `keys` under `cipher`, for the file at `path` in its repository. | [→](api_summary_protection.md#tomsecretsoutercodec) |

### Functions

| Function | Description | Link |
| --- | --- | --- |
| `tomSecretsOuterCipherOf` | The cipher of the `.tsmx` `file`, read from its header without decrypting anything: a rewrite of the file keeps it (the cipher is the repository's). | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterKeyIds` | The key ids of the slots of a `.tsmx` file, without decrypting anything. | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterEncrypt` | Encrypts `content` (the KDBX bytes) as a `.tsmx` file for `path`, with a fresh random file key wrapped under each of `keys` (phase A and B write one; the guided rotation writes two). | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterDecrypt` | Decrypts the `.tsmx` `file` for `path` with whichever of `keys` has a slot. | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterCodecFor` | The outer layer of a vault file named `fileName`: a `.tsmx` file opened with `outerKey` (base64), written under `cipher` until it decodes a file (then under that file's), or null for a plain `.kdbx`. | [→](api_summary_protection.md#functions) |
| `tomSecretsVaultCredentials` | The credentials of a vault with `password` and the bytes of a `keyFile`, either of them optional, or of its `compositeKey`. | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterKeyList` | The repository keys an outer key text names, the newest first. | [→](api_summary_protection.md#functions) |
| `tomSecretsJoinOuterKeys` | Repository keys as one outer key text, the newest first. | [→](api_summary_protection.md#functions) |
| `tomSecretsVaultKeyIds` | The ids of a vault's keys as device records and rotation records name them. | [→](api_summary_protection.md#functions) |
| `tomSecretsCompositeKey` | The 32-byte composite key of a password and a key file, which the OS unlock keeps. | [→](api_summary_protection.md#functions) |
| `tomSecretsDecodeStored` | `stored`, the file at `locator` as its store keeps it, opened with `credentials` (and `outerKey` for a `.tsmx` file). | [→](api_summary_protection.md#functions) |
| `tomSecretsEncodeStored` | `file` saved as the store at `locator` keeps it: its KDBX bytes, under the outer layer with `outerKey` for a `.tsmx` file. | [→](api_summary_protection.md#functions) |

### Global Variables

| Variable | Type | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsOuterSuffix` | `String` | The suffix of an outer-encrypted vault file. | [→](api_summary_protection.md#constants) |
| `tomSecretsOuterVersion` | `int` | The `.tsmx` format version this library writes and reads. | [→](api_summary_protection.md#constants) |

---

## Sync, Merge and Compaction Module

### Types

| Type | Kind | Description | Link |
| --- | --- | --- | --- |
| `TomSecretsVaultCodec` | abstract interface class | Turns a vault file's stored bytes into KDBX bytes and back: the outer encryption layer plugs in here; the identity when a repository has none. | [→](api_summary_sync.md#tomsecretsvaultcodec) |
| `TomSecretsPlainCodec` | final class | No outer layer. | [→](api_summary_sync.md#tomsecretsplaincodec) |
| `TomSecretsVaultConflict` | final class | The merge conflicts of one entry, as the sync engine queues them. | [→](api_summary_sync.md#tomsecretsvaultconflict) |
| `TomSecretsVaultSource` | enum | Where an open vault's file came from. | [→](api_summary_sync.md#tomsecretsvaultsource) |
| `TomSecretsHistoryRewritten` | final class | The remote's history was rewritten without a compaction (a force push): nothing was merged; the user chooses `TomSecretsVaultUnit.takeRemote` or `TomSecretsVaultUnit.mergeOverRemote`. | [→](api_summary_sync.md#tomsecretshistoryrewritten) |
| `TomSecretsVaultUnit` | final class | One vault kept converged with its remote. | [→](api_summary_sync.md#tomsecretsvaultunit) |
| `TomSecretsEntryConflict` | final class | One open conflict of an entry: both sides changed `fields` differently; the merged entry holds the newer values, and the loser is the entry's history version whose modification time is `loserModified`. | [→](api_summary_sync.md#tomsecretsentryconflict) |
| `TomSecretsMergeResult` | final class | What a merge did. | [→](api_summary_sync.md#tomsecretsmergeresult) |
| `TomSecretsCachedVault` | final class | One cached vault file with its record. | [→](api_summary_sync.md#tomsecretscachedvault) |
| `TomSecretsOfflineCache` | final class | The cache directory: `<root>/<repository>/<path>` per vault, beside it `<path>.tsm-cache.json` with the locator, the head it was read at, the blob id and the time it was fetched. | [→](api_summary_sync.md#tomsecretsofflinecache) |
| `TomSecretsCommit` | final class | One commit as the cycle and the compaction read it. | [→](api_summary_sync.md#tomsecretscommit) |
| `TomSecretsCommitReader` | abstract interface class | Reads the commits of one branch of a repository. | [→](api_summary_sync.md#tomsecretscommitreader) |
| `TomSecretsGitHubCommitReader` | final class | Commits read through the GitHub REST API (`GET git/commits/{sha}`), one request each. | [→](api_summary_sync.md#tomsecretsgithubcommitreader) |
| `TomSecretsGitCommitReader` | final class | Commits read from a `tom_git` repository (a `git:` vault's clone, or a repository a compaction fetched into). | [→](api_summary_sync.md#tomsecretsgitcommitreader) |
| `TomSecretsBranchMove` | sealed class | How a branch moved from a base to a new head. | [→](api_summary_sync.md#tomsecretsbranchmove) |
| `TomSecretsBranchAhead` | final class | The new head descends from the base: merge as usual. | [→](api_summary_sync.md#tomsecretsbranchahead) |
| `TomSecretsBranchCompacted` | final class | The history was compacted: the base left it, and the new history starts at a root commit carrying `Tsm-Compacted-From`. | [→](api_summary_sync.md#tomsecretsbranchcompacted) |
| `TomSecretsBranchRewritten` | final class | The history was rewritten without a compaction's trailer (a force push), or could not be followed within the walk's limit: the user decides. | [→](api_summary_sync.md#tomsecretsbranchrewritten) |
| `TomSecretsCompactionException` | final class | A compaction that could not be pushed. | [→](api_summary_sync.md#tomsecretscompactionexception) |
| `TomSecretsCompactionSettings` | final class | A repository's compaction configuration (`.tsm/compaction.yaml`). | [→](api_summary_sync.md#tomsecretscompactionsettings) |
| `TomSecretsCompactionResult` | final class | What a compaction did. | [→](api_summary_sync.md#tomsecretscompactionresult) |

### Functions

| Function | Description | Link |
| --- | --- | --- |
| `tomSecretsDeviceCommitter` | The committer and author of the cycle's commits for `device`: the device name with a placeholder address, `<device>@tsm.invalid` (`.invalid` never resolves, RFC 2606). | [→](api_summary_sync.md#functions) |
| `tomSecretsConflictsOf` | The open conflicts recorded on `entry`. | [→](api_summary_sync.md#functions) |
| `tomSecretsSettleConflicts` | Settles `entry`'s conflicts: the record goes; the history keeps the loser. | [→](api_summary_sync.md#functions) |
| `tomSecretsMergeVaults` | Merges `theirs` into `ours` against their common `base` (null: an empty base, the force-pushed case, where everything present counts as added). | [→](api_summary_sync.md#functions) |
| `tomSecretsBlobId` | The git blob id of `bytes`: SHA-1 over `blob <length>\0` and the bytes, the id the remote's tree names the file by. | [→](api_summary_sync.md#functions) |
| `tomSecretsClassifyMove` | How the branch moved from the base to `head`: the history behind `head` is walked (newest first, every parent) until a commit whose file at `path` is `baseBlob` is found, or every path ends at a root commit, or `maxCommits` commits were read. | [→](api_summary_sync.md#functions) |
| `tomSecretsCompactionMessage` | The root commit's message: a subject naming who compacted, then the trailers. | [→](api_summary_sync.md#functions) |
| `tomSecretsCompact` | Compacts `branch` of `remote` for `device`: a new root commit holding the files as they were `retentionDays` days before `now` (0: as they are now), every later commit of the first-parent line re-created on it with the same tree, message, author and committer, the older ones dropped. | [→](api_summary_sync.md#functions) |
| `tomSecretsGitHubRemote` | The git remote of a `github:` vault's repository for `tomSecretsCompact`: `https://github.com/<owner>/<repository>.git` over smart HTTP, the vault token sent as `x-access-token` (the GitHub token the cycle uses; a compaction needs contents write, no more). | [→](api_summary_sync.md#functions) |
| `tomSecretsCompactionFiles` | The files the app places in a vault repository: the workflow, its script and the configuration `settings`, by path. | [→](api_summary_sync.md#functions) |
| `tomSecretsCompactionSettingsOf` | `settings` read from the configuration file's `text`, or the defaults when there is none. | [→](api_summary_sync.md#functions) |
| `tomSecretsParseTokenExpiration` | The time in a `GitHub-Authentication-Token-Expiration` header (`2026-12-01 10:00:00 UTC`, or with a numeric offset), in UTC; null when it cannot be read. | [→](api_summary_sync.md#functions) |
| `tomSecretsCopyEntry` | A copy of another file's entry with its fields, attachments and history. | [→](api_summary_sync.md#functions) |

### Global Variables

| Variable | Type | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsConflictKey` | `String` | The custom-data key of an entry's open conflicts. | [→](api_summary_sync.md#constants) |
| `tomSecretsFormatKey` | `String` | The database custom-data key of the product's format version. | [→](api_summary_sync.md#constants) |
| `tomSecretsFormatVersion` | `String` | The product format version this library writes (`major.minor`). | [→](api_summary_sync.md#constants) |
| `tomSecretsCompactedFromTrailer` | `String` | The trailer naming the head a compaction replaced. | [→](api_summary_sync.md#constants) |
| `tomSecretsRetentionTrailer` | `String` | The trailer naming the retention, in days, a compaction kept. | [→](api_summary_sync.md#constants) |
| `tomSecretsCompactionWorkflowPath` | `String` | The workflow file's path in a vault repository. | [→](api_summary_sync.md#constants) |
| `tomSecretsCompactionScriptPath` | `String` | The script's path in a vault repository. | [→](api_summary_sync.md#constants) |
| `tomSecretsCompactionConfigPath` | `String` | The configuration's path in a vault repository. | [→](api_summary_sync.md#constants) |
| `tomSecretsTokenExpirationHeader` | `String` | The header GitHub answers a token with an expiry with. | [→](api_summary_sync.md#constants) |

---

## Trust, Approvals and Pairing Module

### Types

| Type | Kind | Description | Link |
| --- | --- | --- | --- |
| `TomSecretsRecordedApprover` | final class | An approver device a host recorded at pairing. | [→](api_summary_sharing.md#tomsecretsrecordedapprover) |
| `TomSecretsRecordedHost` | final class | A host this device approves for (recorded at pairing on the approver). | [→](api_summary_sharing.md#tomsecretsrecordedhost) |
| `TomSecretsTrust` | final class | A device's trust material. | [→](api_summary_sharing.md#tomsecretstrust) |
| `TomSecretsClientTokenRecord` | final class | What a host keeps of a client token: its `hash`, when it was `created`, and the identity of the client that first and last brought it in `hello.clientToken` (so access can later be narrowed to it). | [→](api_summary_sharing.md#tomsecretsclienttokenrecord) |
| `TomSecretsSignedLabels` | abstract final class | The domain labels of the signed objects. | [→](api_summary_sharing.md#tomsecretssignedlabels) |
| `TomSecretsApproverPublicKey` | final class | The public half of an approver key, as a host records it at pairing. | [→](api_summary_sharing.md#tomsecretsapproverpublickey) |
| `TomSecretsApproverKey` | final class | An approver key pair: an Ed25519 and an ML-DSA-65 key used together, made from two 32-byte seeds (which the device settings keep). | [→](api_summary_sharing.md#tomsecretsapproverkey) |
| `TomSecretsSignedKind` | enum | The kind of a signed object in the grants group. | [→](api_summary_sharing.md#tomsecretssignedkind) |
| `TomSecretsGrantsGroup` | final class | The grants group of a primary vault `file`. | [→](api_summary_sharing.md#tomsecretsgrantsgroup) |
| `TomSecretsTokenMatch` | typedef | What a token answers (9.6): the request waiting with `code`, with `decision`. | [→](api_summary_sharing.md#tomsecretstokenmatch) |
| `TomSecretsLinkException` | final class | The handshake or the transport failed: the link closes. | [→](api_summary_sharing.md#tomsecretslinkexception) |
| `TomSecretsLinkPublicKey` | final class | The public half of a link key: X25519 and ML-KEM-768, as pairing records it. | [→](api_summary_sharing.md#tomsecretslinkpublickey) |
| `TomSecretsLinkKey` | final class | One side's static link key: X25519 and ML-KEM-768, from two 32-byte seeds (which the device settings keep; the ML-KEM seed is FIPS 203's 64 bytes, d \|\| z). | [→](api_summary_sharing.md#tomsecretslinkkey) |
| `TomSecretsLinkRandom` | abstract interface class | The randomness of a handshake: system randomness by default; the tests give the vectors' seeds and coins. | [→](api_summary_sharing.md#tomsecretslinkrandom) |
| `TomSecretsSystemLinkRandom` | final class | System randomness. | [→](api_summary_sharing.md#tomsecretssystemlinkrandom) |
| `TomSecretsLinkKeys` | final class | What a finished handshake yields. | [→](api_summary_sharing.md#tomsecretslinkkeys) |
| `TomSecretsLinkInitiator` | final class | The approver's side of the handshake (the initiator, who connects). | [→](api_summary_sharing.md#tomsecretslinkinitiator) |
| `TomSecretsLinkResponder` | final class | The host's side of the handshake (the responder). | [→](api_summary_sharing.md#tomsecretslinkresponder) |
| `TomSecretsLinkCipher` | final class | One direction of the transport: ChaCha20-Poly1305 with a counter nonce, empty associated data, REKEY on demand. | [→](api_summary_sharing.md#tomsecretslinkcipher) |
| `TomSecretsApprovalChannel` | abstract interface class | The approval link's byte stream: a TCP connection in phase A, the relay in phase C. | [→](api_summary_sharing.md#tomsecretsapprovalchannel) |
| `TomSecretsSocketChannel` | final class | A channel over a TCP `Socket`. | [→](api_summary_sharing.md#tomsecretssocketchannel) |
| `TomSecretsLinkFrameReader` | final class | The frames of a channel read one by one (`next`), for the protocols that share the approval link's framing (pairing): a frame over 1 MiB, or the channel's end, ends it. | [→](api_summary_sharing.md#tomsecretslinkframereader) |
| `TomSecretsLinkSession` | final class | An established approval link: JSON messages both ways, encrypted per direction, `rekey` handled, closed on any failure. | [→](api_summary_sharing.md#tomsecretslinksession) |
| `TomSecretsPairingCode` | final class | A pairing code: `<number>-<word>-<word>` (e.g. `7-guitar-orbit`), the number 1..999 (it finds the giving side, e.g. in its mDNS record), the words from `tomSecretsPairingWords`. | [→](api_summary_sharing.md#tomsecretspairingcode) |
| `TomSecretsSpake2Keys` | final class | What SPAKE2 derives (RFC 9382 §4): the shared secret `ke`, the transcript `tt`, and both confirmation MACs. | [→](api_summary_sharing.md#tomsecretsspake2keys) |
| `TomSecretsSpake2` | final class | One side of SPAKE2-P256-SHA256-HKDF-HMAC: A (the receiving side, uses M) or B (the giving side, uses N). | [→](api_summary_sharing.md#tomsecretsspake2) |
| `TomSecretsPairingVault` | final class | One vault the bundle hands over: its locator and the keys a device needs beyond the master password. | [→](api_summary_sharing.md#tomsecretspairingvault) |
| `TomSecretsPairingToken` | final class | A GitHub token the user pasted on the giving side for the receiving device: never the giving side's own. | [→](api_summary_sharing.md#tomsecretspairingtoken) |
| `TomSecretsPairingPeerKeys` | final class | A device's public keys for the approvals: its approver key pair (null when it is no approver) and its approval-link key, with the address its link listens on (null when it does not listen). | [→](api_summary_sharing.md#tomsecretspairingpeerkeys) |
| `TomSecretsPairingBundle` | final class | What the giving side hands over (the pairing bundle): the vaults chosen with their keys, the shared configuration, a token pasted for this device, and the giving device's public keys. | [→](api_summary_sharing.md#tomsecretspairingbundle) |
| `TomSecretsPairingFailure` | enum | Why a pairing ended without a result. | [→](api_summary_sharing.md#tomsecretspairingfailure) |
| `TomSecretsPairingRefusal` | final class | Thrown by a receiving side's `keysFor` that cannot take the bundle (a new machine needs the primary, a `github:` primary its token): the giving side is told `reason` and the pairing ends with `TomSecretsPairingFailure.refused` on both sides. | [→](api_summary_sharing.md#tomsecretspairingrefusal) |
| `TomSecretsPairingException` | final class | A pairing that ended without a result. | [→](api_summary_sharing.md#tomsecretspairingexception) |
| `TomSecretsPairingReceived` | final class | What a pairing gave the receiving side. | [→](api_summary_sharing.md#tomsecretspairingreceived) |
| `TomSecretsPairingGiven` | final class | What a pairing gave the giving side. | [→](api_summary_sharing.md#tomsecretspairinggiven) |
| `TomSecretsPairingWindow` | final class | The giving side's pairing window: it listens on the addresses given (the LAN and VPN ones, `tomSecretsPairingAddresses`), takes the first connection and runs `tomSecretsGivePairing` over it. | [→](api_summary_sharing.md#tomsecretspairingwindow) |
| `TomSecretsPairingReceipt` | final class | A pairing received by a machine being set up, held in memory until the setup: the bundle, the approval-token key, and this machine's fresh trust material (whose public keys the giving side recorded). | [→](api_summary_sharing.md#tomsecretspairingreceipt) |
| `TomSecretsRelayService` | enum | What a relay offers (part-relay) | [→](api_summary_sharing.md#tomsecretsrelayservice) |
| `TomSecretsRelayKind` | enum | A relay's kind from its id's scheme, with the services it offers | [→](api_summary_sharing.md#tomsecretsrelaykind) |
| `TomSecretsRelayId` | final class | A relay's id | [→](api_summary_sharing.md#tomsecretsrelayid) |
| `TomSecretsRelayException` | final class | A relay that failed or refused, naming it | [→](api_summary_sharing.md#tomsecretsrelayexception) |
| `TomSecretsPairingChannel` | abstract interface class | A pairing's or the approval link's byte channel through a relay | [→](api_summary_sharing.md#tomsecretspairingchannel) |
| `TomSecretsMailboxItem` | final class | A mailbox item to put | [→](api_summary_sharing.md#tomsecretsmailboxitem) |
| `TomSecretsMailboxEntry` | final class | A mailbox item waiting | [→](api_summary_sharing.md#tomsecretsmailboxentry) |
| `TomSecretsRelay` | abstract interface class | A relay | [→](api_summary_sharing.md#tomsecretsrelay) |
| `TomSecretsRelayFolder` | abstract interface class | The files the GitHub relay keeps in a repository | [→](api_summary_sharing.md#tomsecretsrelayfolder) |
| `TomSecretsRelayFileExists` | final class | A relay file that exists already | [→](api_summary_sharing.md#tomsecretsrelayfileexists) |
| `TomSecretsStorageRelayFolder` | final class | A `TomSecretsRelayFolder` over a `tom_core_storage` backend | [→](api_summary_sharing.md#tomsecretsstoragerelayfolder) |
| `TomSecretsGitHubRelay` | final class | GitHub as the relay | [→](api_summary_sharing.md#tomsecretsgithubrelay) |
| `TomSecretsDeviceRecord` | final class | One paired device. | [→](api_summary_sharing.md#tomsecretsdevicerecord) |
| `TomSecretsGitHubAuth` | enum | How a device reaches GitHub: the App sign-in or a pasted token. | [→](api_summary_sharing.md#tomsecretsdevicerecord) |
| `TomSecretsDeviceRecords` | final class | The device records of the primary vault `file`. | [→](api_summary_sharing.md#tomsecretsdevicerecords) |
| `TomSecretsMemberFields` | abstract final class | The fields of the `member-key` and `member` entries. | [→](api_summary_sharing.md#tomsecretsmemberfields) |
| `TomSecretsMemberKeyFailure` | enum | Why a key or an entry was refused. | [→](api_summary_sharing.md#tomsecretsmemberkeyfailure) |
| `TomSecretsMemberKeyException` | final class | A refused key, with the `reason` the app shows. | [→](api_summary_sharing.md#tomsecretsmemberkeyexception) |
| `TomSecretsAgeRecipientKind` | enum | The kind of an `age` recipient. | [→](api_summary_sharing.md#tomsecretsagerecipientkind) |
| `TomSecretsAgeRecipient` | final class | An `age` public key: a hybrid member key (`age1pq1…`) or another person's classical key (`age1…`). | [→](api_summary_sharing.md#tomsecretsagerecipient) |
| `TomSecretsMemberKey` | final class | The user's member key: a hybrid `age` identity (`AGE-SECRET-KEY-PQ-1…`) and its recipient. | [→](api_summary_sharing.md#tomsecretsmemberkey) |
| `TomSecretsReceivedMemberKey` | typedef | One public key read from a key file or a pasted block: the recipient and the name its file gave, if any. | [→](api_summary_sharing.md#tomsecretsreceivedmemberkey) |
| `TomSecretsMember` | final class | A received public key in the primary vault (a `member` entry). | [→](api_summary_sharing.md#tomsecretsmember) |
| `TomSecretsAgeFailure` | enum | Why an `age` file could not be written or read. | [→](api_summary_sharing.md#tomsecretsagefailure) |
| `TomSecretsAgeException` | final class | A refused `age` file. | [→](api_summary_sharing.md#tomsecretsageexception) |
| `TomSecretsAgeIdentity` | sealed class | An identity that opens `age` files: `TomSecretsAgeHybridIdentity` (a member key) or `TomSecretsAgeX25519Identity` (a classical identity). | [→](api_summary_sharing.md#tomsecretsageidentity) |
| `TomSecretsAgeHybridIdentity` | final class | A member key as an `age` identity. | [→](api_summary_sharing.md#tomsecretsagehybrididentity) |
| `TomSecretsAgeX25519Identity` | final class | A classical `age` identity, `AGE-SECRET-KEY-1…` (X25519): the product makes none, but reads a file written to one. | [→](api_summary_sharing.md#tomsecretsagex25519identity) |
| `TomSecretsAgePassphraseIdentity` | final class | A passphrase as an `age` identity: opens a file written with the `scrypt` recipient; a work factor above `maxWorkFactor` is refused (`header`). | [→](api_summary_sharing.md#tomsecretsagepassphraseidentity) |
| `TomSecretsSharedVaultMember` | typedef | One member a shared vault's recipients file is written for: `({String name, TomSecretsAgeRecipient recipient})`. | [→](api_summary_sharing.md#tomsecretssharedvaultmember) |
| `TomSecretsSharedVaultFailure` | enum | Why a shared vault's keys could not be read or written. | [→](api_summary_sharing.md#tomsecretssharedvaultfailure) |
| `TomSecretsSharedVaultException` | final class | A refused recipients file or member change. | [→](api_summary_sharing.md#tomsecretssharedvaultexception) |
| `TomSecretsSharedVaultKeys` | final class | What a shared vault's recipients file holds: the vault's keys (a key file, a repository key when outer encrypted) and its members. | [→](api_summary_sharing.md#tomsecretssharedvaultkeys) |
| `TomSecretsRotationKind` | enum | The kind of key a rotation replaces. | [→](api_summary_sharing.md#tomsecretsrotationkind) |
| `TomSecretsRotationException` | final class | A rotation that cannot start or go on. | [→](api_summary_sharing.md#tomsecretsrotationexception) |
| `TomSecretsRotation` | final class | One rotation record: its kind and target, the old and new key ids, when it started and switched, when its migration period ends, who started it, who is still to take up the new key. | [→](api_summary_sharing.md#tomsecretsrotation) |
| `TomSecretsRotations` | final class | The rotation records of a vault (the primary, or a shared vault): the group `.tom-secrets/rotations`; the record is the lock, one rotation per target. | [→](api_summary_sharing.md#tomsecretsrotations) |
| `TomSecretsShareFailure` | enum | Why a share could not be written or read. | [→](api_summary_sharing.md#tomsecretssharefailure) |
| `TomSecretsShareException` | final class | A refused share. | [→](api_summary_sharing.md#tomsecretsshareexception) |
| `TomSecretsSharedField` | typedef | One field of a shared entry: `({String value, bool protected})`. | [→](api_summary_sharing.md#tomsecretssharedfield) |
| `TomSecretsSharedAttachment` | typedef | One attachment of a shared entry: `({Uint8List bytes, bool protected})`. | [→](api_summary_sharing.md#tomsecretssharedattachment) |
| `TomSecretsSharedEntry` | final class | One entry of a share: its fields (the title, `tsm.type` and `tsm.key` among them), tags, attachments and expiry. | [→](api_summary_sharing.md#tomsecretssharedentry) |
| `TomSecretsShareSender` | typedef | Who sent a share, as the sender says: `({String name, String fingerprint})`, the fingerprint of their member key. | [→](api_summary_sharing.md#tomsecretssharesender) |
| `TomSecretsShare` | final class | A share (single-entry export): entries for another person, who sent them, when; its JSON document `{"format": "tsm.share", "version": 1, ...}`. | [→](api_summary_sharing.md#tomsecretsshare) |

### Functions

| Function | Description | Link |
| --- | --- | --- |
| `tomSecretsClientTokenId` | A client token's id: the first 16 bytes, in lower-case hex, of its `hash`; the approving device derives it from the token, and the host checks the grant's `exe-token <path> <tokenId>` against the token it is sent. | [→](api_summary_sharing.md#functions) |
| `tomSecretsClientTokenHash` | A client token's hash: SHA-256(lps("tsm-client-token-v1") \|\| token), hex. | [→](api_summary_sharing.md#functions) |
| `tomSecretsLp` | `lp(x)`: the length of `bytes` as 4 bytes big-endian, then the bytes. | [→](api_summary_sharing.md#functions) |
| `tomSecretsLps` | `lp` of a text's UTF-8. | [→](api_summary_sharing.md#functions) |
| `tomSecretsLpList` | A list: its item count as 4 bytes big-endian, then `lps` of each item. | [→](api_summary_sharing.md#functions) |
| `tomSecretsPinText` | The text a `pin` member is signed as: `hash`, `off`, `relaxed:<relaxedUntil>`, or empty when absent. | [→](api_summary_sharing.md#functions) |
| `tomSecretsSignedBytes` | The signed bytes of `object` under `label`: `lps(label)`, then `lps` of each member of `tomSecretsSignedFields` (an absent one as empty). | [→](api_summary_sharing.md#functions) |
| `tomSecretsApproverKeyId` | An approver key's id (9.2): the first 16 bytes, in lower-case hex, of SHA-256(lps("tsm-approver-key-v1") \|\| lp(Ed25519 public) \|\| lp(ML-DSA-65 public)). | [→](api_summary_sharing.md#functions) |
| `tomSecretsVerifiedBy` | Whether `signatures` carry, for `key`, an Ed25519 item and an ML-DSA-65 item that both verify over `bytes` under `label` (9.3). | [→](api_summary_sharing.md#functions) |
| `tomSecretsAcceptedBy` | The recorded key that signed `object` (a grant, revocation or approval record of `label`) with both algorithms, or null: the object is accepted only then. | [→](api_summary_sharing.md#functions) |
| `tomSecretsAcceptKeyChange` | The new key of a key-change `statement` when it is accepted (9.4): its old key is `oldKey`, `newKeyId` is the id of the keys it carries, and the old and the new key both signed it with both algorithms. | [→](api_summary_sharing.md#functions) |
| `tomSecretsBase32` | RFC 4648 base32 of `bytes`, upper case, without padding. | [→](api_summary_sharing.md#functions) |
| `tomSecretsRequestDigest` | The request digest (9.5): what the waiting request is, from the identity's `kind`, `exe`, `interpreter`, `script`, `cwd`, `uid` and `args` and the references in canonical form. | [→](api_summary_sharing.md#functions) |
| `tomSecretsApprovalCode` | The approval code (9.5): the first ten base32 characters of SHA-256(lps("tsm-approval-code-v1") \|\| lps(host) \|\| lps(approvalId) \|\| requestDigest). | [→](api_summary_sharing.md#functions) |
| `tomSecretsCodeToken` | The token a trusted device computes for `code` shown on `host` (9.6): base32 of the first 16 bytes of HMAC-SHA256(tokenKey, lps("tsm-code-token-v1") \|\| lps(host) \|\| lps(code) \|\| lps(decision)). | [→](api_summary_sharing.md#functions) |
| `tomSecretsNormalizeCode` | A token or code as typed: upper case, without spaces. | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsToken` | Whether `token` is 26 base32 characters (after `tomSecretsNormalizeCode`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsSameText` | Compares two texts in constant time (in their length). | [→](api_summary_sharing.md#functions) |
| `tomSecretsRedeemToken` | The request `token` answers among the `codes` waiting on `host`, under one of `tokenKeys`; null when it matches nothing or is malformed. | [→](api_summary_sharing.md#functions) |
| `tomSecretsNoiseHkdf` | Noise's HKDF with HMAC-SHA256: two 32-byte outputs. | [→](api_summary_sharing.md#functions) |
| `tomSecretsLinkRekey` | Noise's REKEY: the first 32 bytes of ENCRYPT(k, 2^64 - 1, empty, zeros). | [→](api_summary_sharing.md#functions) |
| `tomSecretsLinkFrame` | A frame on the channel: the length as 4 bytes big-endian, then `bytes`. | [→](api_summary_sharing.md#functions) |
| `tomSecretsHkdf` | HKDF-SHA-256 (RFC 5869) of `ikm` with `salt` and `info`, `length` bytes. | [→](api_summary_sharing.md#functions) |
| `tomSecretsGivePairing` | The giving side of a pairing over `channel`: it showed `code`; `device` is its name. | [→](api_summary_sharing.md#functions) |
| `tomSecretsReceivePairing` | The receiving side of a pairing over `channel`: the user typed `code`; `device` is its name. | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsPairingAddress` | Whether `address` is a LAN or VPN address a pairing window may listen on: a private IPv4 address (10/8, which the fleet's VPN uses, 172.16/12, 192.168/16) or an IPv6 unique local address (fc00::/7); never a public, loopback or wildcard address. | [→](api_summary_sharing.md#functions) |
| `tomSecretsPairingAddresses` | This machine's LAN and VPN addresses (`tomSecretsIsPairingAddress`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsReceivePairingAt` | The receiving side connecting to a pairing window at `address`:`port` (`tomSecretsReceivePairing` over TCP). | [→](api_summary_sharing.md#functions) |
| `tomSecretsReceivePairingVia` | The receiving side through a relay. | [→](api_summary_sharing.md#functions) |
| `tomSecretsPairingSetupProblem` | Why a bundle cannot set a machine up, or null when it can: the primary must be in it, with its token when it is in a GitHub repository. | [→](api_summary_sharing.md#functions) |
| `tomSecretsReceivePairingForSetup` | Receives a pairing for a machine being set up as `device`: connects to the giving machine's window at `address`:`port` with `code`, answers with the public keys of fresh trust material (made `now`) and `linkAddress`, where this machine's approval link will listen (the giver records it and opens the link), and refuses a bundle it cannot be set up from (`tomSecretsPairingSetupProblem`); a `linkAddress` that is no approval link throws `ArgumentError`. | [→](api_summary_sharing.md#functions) |
| `tomSecretsParsePairingAddress` | Splits `host:port` (an IPv6 address in brackets: `[fd00::1]:47900`) as the giving machine's Pairing screen shows it. | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyFile` | The text of a published member key: `age`'s recipients-file format (so `age -R <file>` encrypts to it), with the name, short fingerprint and date as `#` comments. | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyFileName` | The file name of `name`'s published member key: `<name>.age-recipient.txt` (lower case, other characters as `_`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsReadMemberKeys` | The public keys in `text` (a key file, a recipients file with several, a pasted recipient, a scanned QR code's text); blank lines and `#` comments skipped, a `# name: …` comment names the key after it; a line that is no `age` recipient is refused, naming its line. | [→](api_summary_sharing.md#functions) |
| `tomSecretsSharingGroupOf` | The `tsm.sharing` group at the root of `file`, made when `create`. | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyEntries` | The `member-key` entries of `file`, the newest first. | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyOf` | The member key an entry holds (its identity in `Password`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyRecipientOf` | The public key a `member-key` or `member` entry names (`tsm.recipient`), read without the identity; null when absent or unreadable. | [→](api_summary_sharing.md#functions) |
| `tomSecretsAddMemberKey` | Writes `key` into `file` as a new `member-key` entry in `tsm.sharing`: the identity protected in `Password`, the recipient and fingerprint beside it. | [→](api_summary_sharing.md#functions) |
| `tomSecretsMembers` | The members of `file` whose entry holds a readable recipient, by name. | [→](api_summary_sharing.md#functions) |
| `tomSecretsAddMember` | Adds `recipient` to the directory as a `member` entry named `name`, after `TomSecretsAgeRecipient.check`; refuses a recipient the directory holds (`duplicate`) and the user's own key (`ownKey`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsMarkMemberChecked` | Records that the user compared the fingerprint of `entry` with its owner on `when` (its date, `tsm.checked`); the entry as it was goes to its history. | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeEncrypt` | `plaintext` as an `age` v1 file to `recipients`, all hybrid (`mlkem768x25519`) or all classical (`X25519`); throws `TomSecretsAgeException` (`recipients`) for none or a mix. | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeDecrypt` | The plaintext of the `age` file `file` (binary or armoured), opened with the first identity a stanza is for; throws `TomSecretsAgeException` (`noMatch`, `header`, `payload`, `armor`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsAgeArmor` | Whether `file` begins with the `age` armour (white space before it allowed). | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeArmor` | `file` in the `age` armour (`-----BEGIN AGE ENCRYPTED FILE-----`, base64 in lines of 64), for pasting into a message. | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeDearmor` | The binary file inside the armoured `text` (white space around it and CRLF allowed); throws `TomSecretsAgeException` (`armor`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeClassicalSecret` | The 32-byte secret of a classical `AGE-SECRET-KEY-1…` identity. | [→](api_summary_sharing.md#functions) |
| `tomSecretsBech32Data` | The data of the Bech32 string `text` whose prefix must be `hrp` and whose data must be `length` bytes (age's Bech32: no length limit, either case). | [→](api_summary_sharing.md#functions) |
| `tomSecretsCheckSharedVaultMembers` | Checks `members` for a recipients file: at least one, each with a hybrid key, none twice. | [→](api_summary_sharing.md#functions) |
| `tomSecretsWriteRecipientsFile` | The recipients file of `keys`: its JSON encrypted with `age` to every member's recipient. | [→](api_summary_sharing.md#functions) |
| `tomSecretsReadRecipientsFile` | The keys of the recipients file `file`, opened with `memberKey`; throws `TomSecretsSharedVaultException` (`notAMember`, `malformed`) or `TomSecretsAgeException` for a broken file. | [→](api_summary_sharing.md#functions) |
| `tomSecretsRecipientsFileName` | The recipients file beside the vault file `fileName` (`team.kdbx`, `team.kdbx.tsmx` → `team.keys.age`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsNewSharedVault` | A new shared vault `name` (kind `shared`) opened by `keys`' key file alone. | [→](api_summary_sharing.md#functions) |
| `tomSecretsKeyId` | The key id of `bytes` (a key file's, a repository key's): the first 8 bytes of their SHA-256 in hex. | [→](api_summary_sharing.md#functions) |
| `tomSecretsTakeNextKeys` | A device taking the keys of the guided rotations running in the primary. | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeEncryptPassphrase` | `plaintext` as an `age` v1 file under `passphrase`: one `scrypt` stanza, `workFactor` its log2 N (1 to 22, `ArgumentError` otherwise); scrypt runs in another isolate. | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeIsPassphrase` | Whether the `age` file `file` (binary or armoured) is written under a passphrase, so a reader asks for one. | [→](api_summary_sharing.md#functions) |
| `tomSecretsShareOf` | The share of `entries`: every field but the product's other `tsm.*` fields and overlay fields, the tags, attachments and expiry. | [→](api_summary_sharing.md#functions) |
| `tomSecretsImportShare` | The entries of `share` added to `group` of `file` as new entries (new UUIDs). | [→](api_summary_sharing.md#functions) |
| `tomSecretsWriteShare` | `share` as an `age` file to `recipients` (all hybrid or all classical) or under `passphrase`, exactly one; throws `TomSecretsShareException` (`protection`) else. | [→](api_summary_sharing.md#functions) |
| `tomSecretsReadShare` | The share in `bytes` (a `.tsmshare` file or the armoured text), opened with the first of `identities` that fits; throws `TomSecretsAgeException` or `TomSecretsShareException`. | [→](api_summary_sharing.md#functions) |
| `tomSecretsLooksLikeShare` | Whether `text` (pasted, scanned) holds an armoured `age` file. | [→](api_summary_sharing.md#functions) |
| `tomSecretsShareFitsQr` | Whether the share `file` fits a QR code as armoured text (`tomSecretsQrCapacity`). | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsInboxMember` | Whether `id` is a member id an inbox folder may be named by (a member key's fingerprint). | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsInboxName` | Whether `name` is a package name, `<YYYY-MM-DD>-<16 hex>.age`. | [→](api_summary_sharing.md#functions) |
| `tomSecretsInboxPath` | The path of the package `name` in the inbox of `memberId`, relative to the shared vault's folder: `inbox/<member>/<name>`; `ArgumentError` for another member id or name. | [→](api_summary_sharing.md#functions) |
| `tomSecretsNewInboxName` | A new package name: the UTC date at `now` and 16 random hex digits. | [→](api_summary_sharing.md#functions) |
| `tomSecretsInboxDate` | The day a package named `name` was put in (UTC), or null for another name. | [→](api_summary_sharing.md#functions) |
| `tomSecretsInboxExpired` | Whether the package `name` was put in more than 30 days before `now`; a file that is no package is never expired. | [→](api_summary_sharing.md#functions) |

### Global Variables

| Variable | Type | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsLinkKeyMigration` | `Duration` | How long a device's previous approval-link key stays in use for the hosts its new key has not reached yet. | [→](api_summary_sharing.md#constants) |
| `tomSecretsSignedFields` | `Map<String, List<String>>` | The members of each signed object, in the order they are signed (9.4). | [→](api_summary_sharing.md#constants) |
| `tomSecretsDecisions` | `List<String>` | The decisions a prompt or a token carries. | [→](api_summary_sharing.md#constants) |
| `tomSecretsLinkProtocolName` | `String` | The protocol name hashed into the handshake. | [→](api_summary_sharing.md#constants) |
| `tomSecretsLinkMaxFrame` | `int` | The largest frame on the channel. | [→](api_summary_sharing.md#constants) |
| `tomSecretsPairingVersion` | `int` | The pairing protocol's version (each side's first message carries it). | [→](api_summary_sharing.md#constants) |
| `tomSecretsPairingAad` | `String` | SPAKE2's associated data: the protocol and its version, so both sides agree on them (RFC 9382 §3.2, against a downgrade). | [→](api_summary_sharing.md#constants) |
| `tomSecretsPairingWindow` | `Duration` | How long the giving side's pairing window stays open. | [→](api_summary_sharing.md#constants) |
| `tomSecretsPairingWords` | `List<String>` | The 256 words of a pairing code, in their fixed order. | [→](api_summary_sharing.md#constants) |
| `tomSecretsDevicesGroup` | `String` | The subgroup of the product group holding the device records. | [→](api_summary_sharing.md#constants) |
| `tomSecretsSharedVaultKeysFormat` | `String` | The format of a recipients file's plaintext: `tsm-shared-vault-keys/1`. | [→](api_summary_sharing.md#constants) |
| `tomSecretsRecipientsSuffix` | `String` | The suffix of a recipients file, after the vault's name: `.keys.age`. | [→](api_summary_sharing.md#constants) |
| `tomSecretsRotationsGroup` | `String` | The subgroup of the product group holding the rotation records: `rotations`. | [→](api_summary_sharing.md#constants) |
| `tomSecretsRotationPeriod` | `Duration` | The default migration period of a rotation: 14 days (DP-85). | [→](api_summary_sharing.md#constants) |
| `tomSecretsAgeDefaultWorkFactor` | `int` | The work factor (log2 N) a passphrase file is written with: 18, `age`'s own. | [→](api_summary_sharing.md#constants) |
| `tomSecretsAgeMaxWorkFactor` | `int` | The highest work factor (log2 N) the reader computes: 22, as `age`. | [→](api_summary_sharing.md#constants) |
| `tomSecretsShareFormat` | `String` | The `format` of a share's JSON document: `tsm.share`. | [→](api_summary_sharing.md#constants) |
| `tomSecretsShareVersion` | `int` | The version of the share's JSON document this code writes and reads: 1. | [→](api_summary_sharing.md#constants) |
| `tomSecretsShareExtension` | `String` | The extension of a share saved as a file: `.tsmshare`. | [→](api_summary_sharing.md#constants) |
| `tomSecretsQrCapacity` | `int` | The most characters a QR code holds (version 40, level L, byte mode): 2953. | [→](api_summary_sharing.md#constants) |
| `tomSecretsInboxFolder` | `String` | The folder beside a shared vault holding the members' inboxes: `inbox`. | [→](api_summary_sharing.md#constants) |
| `tomSecretsRelayPairFolder` | `String` | The folder of a repository's pairing rendezvous: `relay/pair`. | [→](api_summary_sharing.md#constants) |
| `tomSecretsRelayStaleAfter` | `Duration` | How old a pairing folder may get before the next host deletes it: one hour. | [→](api_summary_sharing.md#constants) |
| `tomSecretsInboxExpiry` | `Duration` | How long a package stays in an inbox before any member's sync deletes it: 30 days. | [→](api_summary_sharing.md#constants) |

---

## Import and Export Module

### Types

| Type | Kind | Description | Link |
| --- | --- | --- | --- |
| `TomSecretsImportKind` | enum | How an imported item is typed. | [→](api_summary_import_export.md#tomsecretsimportkind) |
| `TomSecretsImportField` | final class | A custom field of an imported item. | [→](api_summary_import_export.md#tomsecretsimportfield) |
| `TomSecretsImportAttachment` | final class | An attachment of an imported item. | [→](api_summary_import_export.md#tomsecretsimportattachment) |
| `TomSecretsImportOldPassword` | final class | One former password with the time it was replaced. | [→](api_summary_import_export.md#tomsecretsimportoldpassword) |
| `TomSecretsImportItem` | final class | One item of an export, as the importers read it. | [→](api_summary_import_export.md#tomsecretsimportitem) |
| `TomSecretsImportVault` | final class | One vault of an export. | [→](api_summary_import_export.md#tomsecretsimportvault) |
| `TomSecretsImportNotice` | final class | Something of an export that is not imported, named in the report. | [→](api_summary_import_export.md#tomsecretsimportnotice) |
| `TomSecretsImportSource` | final class | An export as read: its vaults, what its format loses, and what of it is not imported. | [→](api_summary_import_export.md#tomsecretsimportsource) |
| `TomSecretsImportTarget` | final class | Where a source vault goes: `group` (a path of group names) in `file`. | [→](api_summary_import_export.md#tomsecretsimporttarget) |
| `TomSecretsImportOutcome` | enum | What happened to one item. | [→](api_summary_import_export.md#tomsecretsimportoutcome) |
| `TomSecretsImportLine` | final class | One line of the report: an entry and what happened to it, no values. | [→](api_summary_import_export.md#tomsecretsimportline) |
| `TomSecretsImportAttachmentSize` | final class | An attachment of the import, by size, for the preview. | [→](api_summary_import_export.md#tomsecretsimportattachmentsize) |
| `TomSecretsImportReport` | final class | What an import did (or, as a preview, would do). | [→](api_summary_import_export.md#tomsecretsimportreport) |
| `TomSecretsImportFormatException` | final class | An export that cannot be read. | [→](api_summary_import_export.md#tomsecretsimportformatexception) |
| `TomSecretsEnpassExport` | final class | An Enpass JSON export and what it left behind. | [→](api_summary_import_export.md#tomsecretsenpassexport) |
| `TomSecretsPasskeyFields` | abstract final class | KeePassXC's passkey attributes. | [→](api_summary_import_export.md#tomsecretspasskeyfields) |
| `TomSecretsPasskeyException` | final class | A passkey's private key that cannot be read. | [→](api_summary_import_export.md#tomsecretspasskeyexception) |
| `TomSecretsPasskey` | final class | A passkey with its private key. | [→](api_summary_import_export.md#tomsecretspasskey) |
| `TomSecretsBitwardenKeys` | final class | The encryption and MAC keys of a Bitwarden export password. | [→](api_summary_import_export.md#tomsecretsbitwardenkeys) |
| `TomSecretsCsvBrowser` | enum | A browser whose password export is read. | [→](api_summary_import_export.md#tomsecretscsvbrowser) |
| `TomSecretsKdbxImportResult` | final class | What `tomSecretsImportKdbxAsGroup` did. | [→](api_summary_import_export.md#tomsecretskdbximportresult) |
| `TomSecretsExport` | final class | A plaintext export (CSV, Bitwarden JSON) and what it left behind. | [→](api_summary_import_export.md#tomsecretsexport) |

### Functions

| Function | Description | Link |
| --- | --- | --- |
| `tomSecretsImportVersionField` | The import origin's version field (`tsm.import.<source>.updated`). | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportedAtField` | When the import last wrote the entry (`tsm.import.<source>.imported`): an entry modified later was changed in the vault. | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportCategoryField` | The source category field (`tsm.import.<source>.category`). | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportGroupName` | `name` as a group name: empty becomes `(no name)`, and a name the product reserves (an `@` overlay group, a `tsm.` or `.tom-secrets` name) has its first character percent-encoded as the product writes it (`%40…`). | [→](api_summary_import_export.md#functions) |
| `tomSecretsImport` | Imports `source` into `file`: each source vault into its target (`targets` by vault id, default `<displayName>/<vault name>` in `file`), archived items only with `includeArchived`. | [→](api_summary_import_export.md#functions) |
| `tomSecretsRead1Pux` | Reads a 1PUX export (`zip`, the file's bytes) in memory. | [→](api_summary_import_export.md#functions) |
| `tomSecretsRead1PasswordCsv` | Reads 1Password's CSV export: one vault `CSV`, one item per row. | [→](api_summary_import_export.md#functions) |
| `tomSecretsParseCsv` | The rows of a CSV text (RFC 4180: quoted fields with doubled quotes and line breaks inside, CRLF or LF; a leading byte order mark is dropped). | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadEnpassJson` | Reads an Enpass JSON export of the vault `vaultName`. | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadEnpassCsv` | Reads an Enpass CSV export of the vault `vaultName`: per row the title, label and value pairs, the note; a header row (`Title`, …, `Note`) is skipped. | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportEnpassJson` | Writes `group` (default: the whole vault `file`) as an Enpass JSON export. | [→](api_summary_import_export.md#functions) |
| `tomSecretsBase64Url` | `text` (base64, base64url, padded or not) as base64url without padding. | [→](api_summary_import_export.md#functions) |
| `tomSecretsDecodeBase64` | The bytes of base64 or base64url `text`, padded or not. | [→](api_summary_import_export.md#functions) |
| `tomSecretsPasskeyPem` | `key` as PKCS#8 PEM: a PEM (PKCS#8 as it is; SEC1 `EC PRIVATE KEY` converted), base64 or base64url DER (PKCS#8 or SEC1), 32 raw bytes or their base64 (a P-256 scalar), or a JWK (a map or its JSON text; `EC` on `P-256`, or `OKP` on `Ed25519`). | [→](api_summary_import_export.md#functions) |
| `tomSecretsBitwardenNeedsPassword` | Whether a Bitwarden export is password-protected (its password is needed). | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadBitwardenJson` | Reads Bitwarden's JSON export, a password-protected one with `password`; folders become groups, types map as 1Password's, the item id into `tsm.import.bitwarden.id`; a wrong password and an account-restricted export are refused. | [→](api_summary_import_export.md#functions) |
| `tomSecretsBitwardenExportKeys` | The keys of a password-protected export: PBKDF2-SHA256 (0) or Argon2id over the SHA-256 of the salt (1), then HKDF-Expand with `enc` and `mac`. | [→](api_summary_import_export.md#functions) |
| `tomSecretsBitwardenDecrypt` | Decrypts a type-2 cipher string (AES-256-CBC, HMAC-SHA256 checked first). | [→](api_summary_import_export.md#functions) |
| `tomSecretsBrowserOfCsv` | The browser a CSV header looks like (Firefox, Safari), or null for Chrome and Edge. | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadBrowserCsv` | Reads a browser's password export (Chrome, Edge, Firefox, Safari), identified by the same hash as an Enpass or 1Password CSV row. | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportKdbxAsGroup` | Copies another KDBX file's groups and entries into a new group (` (2)` where the name is taken). | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportKdbxMerged` | Merges a copy of the same vault edited elsewhere entry by entry; another vault is refused. | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportEntries` | The entries an export writes, with their group paths: no recycle bin, product groups or metadata entry. | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportCsv` | A vault or group as CSV, one row per entry. | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportBitwardenJson` | A vault or group as Bitwarden's unencrypted JSON export: folders, item types, custom fields, password history. | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportKdbx` | A vault or group as a KDBX file of its own under new credentials. | [→](api_summary_import_export.md#functions) |

### Global Variables

| Variable | Type | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsOnePasswordSource` | `String` | The source name of 1Password imports (`tsm.import.1password.id`). | [→](api_summary_import_export.md#constants) |
| `tomSecretsOnePuxLosses` | `List<String>` | What a 1PUX import loses, named in every report. | [→](api_summary_import_export.md#constants) |
| `tomSecretsOnePasswordCsvLosses` | `List<String>` | What a CSV import loses besides `tomSecretsOnePuxLosses`. | [→](api_summary_import_export.md#constants) |
| `tomSecretsOnePasswordCategories` | `Map<String, (TomSecretsImportKind, String)>` | 1Password's categories by `categoryUuid`: how each is typed, and the subgroup an `other` category goes into. | [→](api_summary_import_export.md#constants) |
| `tomSecretsEnpassSource` | `String` | The source name of Enpass imports (`tsm.import.enpass.id`). | [→](api_summary_import_export.md#constants) |
| `tomSecretsEnpassJsonLosses` | `List<String>` | What an Enpass JSON import loses, named in every report. | [→](api_summary_import_export.md#constants) |
| `tomSecretsEnpassCsvLosses` | `List<String>` | What an Enpass CSV import loses besides `tomSecretsEnpassJsonLosses`. | [→](api_summary_import_export.md#constants) |
| `tomSecretsEnpassCategories` | `Map<String, (TomSecretsImportKind, String)>` | Enpass's categories: how each is typed, and the subgroup another category goes into. | [→](api_summary_import_export.md#constants) |
| `tomSecretsBitwardenSource` | `String` | `bitwarden`, the source name of Bitwarden imports. | [→](api_summary_import_export.md#constants) |
| `tomSecretsBitwardenLosses` | `List<String>` | What a Bitwarden JSON import loses, named in every report. | [→](api_summary_import_export.md#constants) |
| `tomSecretsBitwardenCardFields` | `List<(String, String, bool)>` | The card fields: Bitwarden's key, the custom field's name, protected. | [→](api_summary_import_export.md#constants) |
| `tomSecretsBitwardenIdentityFields` | `List<(String, String, bool)>` | The identity fields: Bitwarden's key, the custom field's name, protected. | [→](api_summary_import_export.md#constants) |
| `tomSecretsCardsCategory` | `String` | `Credit Cards`, the subgroup of cards (as 1Password's). | [→](api_summary_import_export.md#constants) |
| `tomSecretsIdentitiesCategory` | `String` | `Identities`, the subgroup of identities (as 1Password's). | [→](api_summary_import_export.md#constants) |
| `tomSecretsBrowserCsvLosses` | `List<String>` | What a browser CSV import loses, named in every report. | [→](api_summary_import_export.md#constants) |
| `tomSecretsCsvExportColumns` | `List<String>` | The CSV export's columns: `Title`, `URL`, `Username`, `Password`, `Notes`, `OTPAuth`, `Group`, `Tags`. | [→](api_summary_import_export.md#constants) |

---

## First Run and Device Settings Module

### Types

| Type | Kind | Description | Link |
| --- | --- | --- | --- |
| `TomSecretsFirstRunProblem` | enum | Why the first run cannot go on. | [→](api_summary_device.md#tomsecretsfirstrunproblem) |
| `TomSecretsFirstRunException` | final class | The first run cannot go on, for `problem`. | [→](api_summary_device.md#tomsecretsfirstrunexception) |
| `TomSecretsGitHubRepositoryCheck` | final class | A GitHub repository as a token sees it. | [→](api_summary_device.md#tomsecretsgithubrepositorycheck) |
| `TomSecretsFirstRunSetup` | final class | What the first run sets up. | [→](api_summary_device.md#tomsecretsfirstrunsetup) |
| `TomSecretsFirstRunResult` | final class | What the first run did. | [→](api_summary_device.md#tomsecretsfirstrunresult) |
| `TomSecretsFirstRun` | final class | The first run of a machine, writing into `dataDirectory` and `keychain`. | [→](api_summary_device.md#tomsecretsfirstrun) |
| `TomSecretsDeviceKeyMode` | enum | Where the device settings container's key is kept. | [→](api_summary_device.md#tomsecretsdevicekeymode) |
| `TomSecretsLockMode` | enum | How a lock policy relocks. | [→](api_summary_device.md#tomsecretslockmode) |
| `TomSecretsLockPolicy` | final class | A lock policy. | [→](api_summary_device.md#tomsecretslockpolicy) |
| `TomSecretsDeviceKeyException` | final class | The device settings container's key could not be had. | [→](api_summary_device.md#tomsecretsdevicekeyexception) |
| `TomSecretsDeviceSettings` | final class | What the device settings hold. | [→](api_summary_device.md#tomsecretsdevicesettings) |
| `TomSecretsDeviceKeys` | final class | The container's key, by the mode `bootstrap.yaml` names. | [→](api_summary_device.md#tomsecretsdevicekeys) |
| `TomSecretsDeviceContainer` | final class | The device settings container, opened with its key. | [→](api_summary_device.md#tomsecretsdevicecontainer) |

### Functions

| Function | Description | Link |
| --- | --- | --- |
| `tomSecretsDefaultHost` | The host name the service goes by when `bootstrap.yaml` names none: the machine's name up to its first dot, in lower case. | [→](api_summary_device.md#functions) |
| `tomSecretsKeysDue` | The due date of keys created at `created`: `months` later, the day kept (the last of the month where that month is shorter). | [→](api_summary_device.md#functions) |

### Global Variables

| Variable | Type | Description | Link |
| --- | --- | --- | --- |
| `tomSecretsPrimaryKeyMonths` | `int` | How long a new primary's key file and repository key are good for before they are due for rotation. | [→](api_summary_device.md#constants) |
| `tomSecretsDeviceNamespace` | `String` | The settings namespace of the product. | [→](api_summary_device.md#constants) |
| `tomSecretsDeviceGroup` | `String` | The settings group the device settings are kept in, as one fragment. | [→](api_summary_device.md#constants) |
| `tomSecretsTrustGroup` | `String` | The container's group of the device's trust material (keys, recorded approvers and hosts). | [→](api_summary_device.md#constants) |

---

## Alphabetical Type Index

| Name | Module | Link |
| --- | --- | --- |
| `TomSecretsAgeException` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsageexception) |
| `TomSecretsAgeFailure` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsagefailure) |
| `TomSecretsAgeHybridIdentity` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsagehybrididentity) |
| `TomSecretsAgeIdentity` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsageidentity) |
| `TomSecretsAgePassphraseIdentity` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsagepassphraseidentity) |
| `TomSecretsAgeRecipient` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsagerecipient) |
| `TomSecretsAgeRecipientKind` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsagerecipientkind) |
| `TomSecretsAgeX25519Identity` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsagex25519identity) |
| `TomSecretsApprovalChannel` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsapprovalchannel) |
| `TomSecretsApproverKey` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsapproverkey) |
| `TomSecretsApproverPublicKey` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsapproverpublickey) |
| `TomSecretsAutoTypeAction` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypeaction) |
| `TomSecretsAutoTypeCandidate` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypecandidate) |
| `TomSecretsAutoTypeDelay` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypedelay) |
| `TomSecretsAutoTypeException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypeexception) |
| `TomSecretsAutoTypeKey` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypekey) |
| `TomSecretsAutoTypeKeyDelay` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypekeydelay) |
| `TomSecretsAutoTypeKeyPress` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypekeypress) |
| `TomSecretsAutoTypeModifier` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypemodifier) |
| `TomSecretsAutoTypeText` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsautotypetext) |
| `TomSecretsBitwardenKeys` | Import and Export | [→](api_summary_import_export.md#tomsecretsbitwardenkeys) |
| `TomSecretsBranchAhead` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsbranchahead) |
| `TomSecretsBranchCompacted` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsbranchcompacted) |
| `TomSecretsBranchMove` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsbranchmove) |
| `TomSecretsBranchRewritten` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsbranchrewritten) |
| `TomSecretsBreachCheck` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsbreachcheck) |
| `TomSecretsBreachCheckException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsbreachcheckexception) |
| `TomSecretsCachedVault` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretscachedvault) |
| `TomSecretsCertificateAlgorithm` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretscertificatealgorithm) |
| `TomSecretsCertificateException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretscertificateexception) |
| `TomSecretsCertificateInfo` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretscertificateinfo) |
| `TomSecretsCertificateKeyType` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretscertificatekeytype) |
| `TomSecretsCharacterClass` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretscharacterclass) |
| `TomSecretsClientTokenRecord` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsclienttokenrecord) |
| `TomSecretsCommit` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretscommit) |
| `TomSecretsCommitReader` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretscommitreader) |
| `TomSecretsCompactionException` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretscompactionexception) |
| `TomSecretsCompactionResult` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretscompactionresult) |
| `TomSecretsCompactionSettings` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretscompactionsettings) |
| `TomSecretsConfig` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsconfig) |
| `TomSecretsConfigException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsconfigexception) |
| `TomSecretsCsvBrowser` | Import and Export | [→](api_summary_import_export.md#tomsecretscsvbrowser) |
| `TomSecretsDeviceContainer` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsdevicecontainer) |
| `TomSecretsDeviceKeyException` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsdevicekeyexception) |
| `TomSecretsDeviceKeyMode` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsdevicekeymode) |
| `TomSecretsDeviceKeys` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsdevicekeys) |
| `TomSecretsDeviceRecord` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsdevicerecord) |
| `TomSecretsDeviceRecords` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsdevicerecords) |
| `TomSecretsDeviceSettings` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsdevicesettings) |
| `TomSecretsDimension` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsdimension) |
| `TomSecretsEnpassExport` | Import and Export | [→](api_summary_import_export.md#tomsecretsenpassexport) |
| `TomSecretsEntryConflict` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsentryconflict) |
| `TomSecretsEntryFields` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsentryfields) |
| `TomSecretsEntryType` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsentrytype) |
| `TomSecretsExplainedCandidate` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsexplainedcandidate) |
| `TomSecretsExplainOutcome` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsexplainoutcome) |
| `TomSecretsExplanation` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsexplanation) |
| `TomSecretsExport` | Import and Export | [→](api_summary_import_export.md#tomsecretsexport) |
| `TomSecretsFieldValue` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsfieldvalue) |
| `TomSecretsFileLocator` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsfilelocator) |
| `TomSecretsFirstRun` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsfirstrun) |
| `TomSecretsFirstRunException` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsfirstrunexception) |
| `TomSecretsFirstRunProblem` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsfirstrunproblem) |
| `TomSecretsFirstRunResult` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsfirstrunresult) |
| `TomSecretsFirstRunSetup` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsfirstrunsetup) |
| `TomSecretsGeneratedCertificate` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsgeneratedcertificate) |
| `TomSecretsGeneratedPgpKey` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsgeneratedpgpkey) |
| `TomSecretsGeneratedSshKey` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsgeneratedsshkey) |
| `TomSecretsGitCommitReader` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsgitcommitreader) |
| `TomSecretsGitHubCommitReader` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsgithubcommitreader) |
| `TomSecretsGitHubLocation` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsgithublocation) |
| `TomSecretsGitHubLocator` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsgithublocator) |
| `TomSecretsGitHubRelay` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsgithubrelay) |
| `TomSecretsGitHubRepositoryCheck` | First Run and Device Settings | [→](api_summary_device.md#tomsecretsgithubrepositorycheck) |
| `TomSecretsGitLocator` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsgitlocator) |
| `TomSecretsGrantsGroup` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsgrantsgroup) |
| `TomSecretsHealthEntry` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretshealthentry) |
| `TomSecretsHealthFinding` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretshealthfinding) |
| `TomSecretsHealthIssue` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretshealthissue) |
| `TomSecretsHealthPolicy` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretshealthpolicy) |
| `TomSecretsHealthReport` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretshealthreport) |
| `TomSecretsHistoryRewritten` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretshistoryrewritten) |
| `TomSecretsImportAttachment` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportattachment) |
| `TomSecretsImportAttachmentSize` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportattachmentsize) |
| `TomSecretsImportField` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportfield) |
| `TomSecretsImportFormatException` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportformatexception) |
| `TomSecretsImportItem` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportitem) |
| `TomSecretsImportKind` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportkind) |
| `TomSecretsImportLine` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportline) |
| `TomSecretsImportNotice` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportnotice) |
| `TomSecretsImportOldPassword` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportoldpassword) |
| `TomSecretsImportOutcome` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportoutcome) |
| `TomSecretsImportReport` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportreport) |
| `TomSecretsImportSource` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportsource) |
| `TomSecretsImportTarget` | Import and Export | [→](api_summary_import_export.md#tomsecretsimporttarget) |
| `TomSecretsImportVault` | Import and Export | [→](api_summary_import_export.md#tomsecretsimportvault) |
| `TomSecretsIndexedEntry` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsindexedentry) |
| `TomSecretsKdbxImportResult` | Import and Export | [→](api_summary_import_export.md#tomsecretskdbximportresult) |
| `TomSecretsKeeAgentSettings` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretskeeagentsettings) |
| `TomSecretsKeyFile` | Key Files and Outer Encryption | [→](api_summary_protection.md#tomsecretskeyfile) |
| `TomSecretsKeyFileException` | Key Files and Outer Encryption | [→](api_summary_protection.md#tomsecretskeyfileexception) |
| `TomSecretsKeyStrength` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretskeystrength) |
| `TomSecretsLinkCipher` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkcipher) |
| `TomSecretsLinkException` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkexception) |
| `TomSecretsLinkFrameReader` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkframereader) |
| `TomSecretsLinkInitiator` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkinitiator) |
| `TomSecretsLinkKey` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkkey) |
| `TomSecretsLinkKeys` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkkeys) |
| `TomSecretsLinkPublicKey` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkpublickey) |
| `TomSecretsLinkRandom` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkrandom) |
| `TomSecretsLinkResponder` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinkresponder) |
| `TomSecretsLinkSession` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretslinksession) |
| `TomSecretsLocalLocation` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretslocallocation) |
| `TomSecretsLocatorException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretslocatorexception) |
| `TomSecretsLockMode` | First Run and Device Settings | [→](api_summary_device.md#tomsecretslockmode) |
| `TomSecretsLockPolicy` | First Run and Device Settings | [→](api_summary_device.md#tomsecretslockpolicy) |
| `TomSecretsLoginMatch` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsloginmatch) |
| `TomSecretsMachine` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsmachine) |
| `TomSecretsMailboxEntry` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsmailboxentry) |
| `TomSecretsMailboxItem` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsmailboxitem) |
| `TomSecretsMember` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsmember) |
| `TomSecretsMemberFields` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsmemberfields) |
| `TomSecretsMemberKey` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsmemberkey) |
| `TomSecretsMemberKeyException` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsmemberkeyexception) |
| `TomSecretsMemberKeyFailure` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsmemberkeyfailure) |
| `TomSecretsMergeResult` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsmergeresult) |
| `TomSecretsMetadata` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsmetadata) |
| `TomSecretsMetadataException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsmetadataexception) |
| `TomSecretsMetadataFields` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsmetadatafields) |
| `TomSecretsOfflineCache` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsofflinecache) |
| `TomSecretsOuterCipher` | Key Files and Outer Encryption | [→](api_summary_protection.md#tomsecretsoutercipher) |
| `TomSecretsOuterCodec` | Key Files and Outer Encryption | [→](api_summary_protection.md#tomsecretsoutercodec) |
| `TomSecretsOuterException` | Key Files and Outer Encryption | [→](api_summary_protection.md#tomsecretsouterexception) |
| `TomSecretsPairingBundle` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingbundle) |
| `TomSecretsPairingChannel` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingchannel) |
| `TomSecretsPairingCode` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingcode) |
| `TomSecretsPairingException` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingexception) |
| `TomSecretsPairingFailure` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingfailure) |
| `TomSecretsPairingGiven` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairinggiven) |
| `TomSecretsPairingPeerKeys` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingpeerkeys) |
| `TomSecretsPairingReceipt` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingreceipt) |
| `TomSecretsPairingReceived` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingreceived) |
| `TomSecretsPairingRefusal` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingrefusal) |
| `TomSecretsPairingToken` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingtoken) |
| `TomSecretsPairingVault` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingvault) |
| `TomSecretsPairingWindow` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretspairingwindow) |
| `TomSecretsPasskey` | Import and Export | [→](api_summary_import_export.md#tomsecretspasskey) |
| `TomSecretsPasskeyException` | Import and Export | [→](api_summary_import_export.md#tomsecretspasskeyexception) |
| `TomSecretsPasskeyFields` | Import and Export | [→](api_summary_import_export.md#tomsecretspasskeyfields) |
| `TomSecretsPasswordGenerator` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretspasswordgenerator) |
| `TomSecretsPasswordPolicy` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretspasswordpolicy) |
| `TomSecretsPasswordStrength` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretspasswordstrength) |
| `TomSecretsPgpKeyAlgorithm` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretspgpkeyalgorithm) |
| `TomSecretsPgpKeyException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretspgpkeyexception) |
| `TomSecretsPgpKeyInfo` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretspgpkeyinfo) |
| `TomSecretsPlainCodec` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsplaincodec) |
| `TomSecretsPrimaryNextKeys` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsprimarynextkeys) |
| `TomSecretsPrimaryVaults` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsprimaryvaults) |
| `TomSecretsRankedCandidate` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsrankedcandidate) |
| `TomSecretsReceivedMemberKey` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsreceivedmemberkey) |
| `TomSecretsRecordedApprover` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrecordedapprover) |
| `TomSecretsRecordedHost` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrecordedhost) |
| `TomSecretsRelay` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrelay) |
| `TomSecretsRelayException` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrelayexception) |
| `TomSecretsRelayFileExists` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrelayfileexists) |
| `TomSecretsRelayFolder` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrelayfolder) |
| `TomSecretsRelayId` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrelayid) |
| `TomSecretsRelayKind` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrelaykind) |
| `TomSecretsRelayService` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrelayservice) |
| `TomSecretsRepositoryKey` | Key Files and Outer Encryption | [→](api_summary_protection.md#tomsecretsrepositorykey) |
| `TomSecretsResolution` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsresolution) |
| `TomSecretsResolveException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsresolveexception) |
| `TomSecretsResolver` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsresolver) |
| `TomSecretsRotation` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrotation) |
| `TomSecretsRotationException` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrotationexception) |
| `TomSecretsRotationKind` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrotationkind) |
| `TomSecretsRotations` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsrotations) |
| `TomSecretsShare` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsshare) |
| `TomSecretsSharedAttachment` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharedattachment) |
| `TomSecretsSharedEntry` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharedentry) |
| `TomSecretsSharedField` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharedfield) |
| `TomSecretsSharedVaultException` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharedvaultexception) |
| `TomSecretsSharedVaultFailure` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharedvaultfailure) |
| `TomSecretsSharedVaultKeys` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharedvaultkeys) |
| `TomSecretsSharedVaultMember` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharedvaultmember) |
| `TomSecretsShareException` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsshareexception) |
| `TomSecretsShareFailure` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharefailure) |
| `TomSecretsShareSender` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssharesender) |
| `TomSecretsSignedKind` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssignedkind) |
| `TomSecretsSignedLabels` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssignedlabels) |
| `TomSecretsSiteUrl` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssiteurl) |
| `TomSecretsSocketChannel` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssocketchannel) |
| `TomSecretsSpake2` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsspake2) |
| `TomSecretsSpake2Keys` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsspake2keys) |
| `TomSecretsSshAgentConnection` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshagentconnection) |
| `TomSecretsSshAgentIdentity` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshagentconnection) |
| `TomSecretsSshAgentMessage` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshagentmessage) |
| `TomSecretsSshAgentServing` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshagentserving) |
| `TomSecretsSshGrantSecret` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshgrantsecret) |
| `TomSecretsSshKeyAlgorithm` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshkeyalgorithm) |
| `TomSecretsSshKeyException` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshkeyexception) |
| `TomSecretsSshKeyFormat` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshkeyformat) |
| `TomSecretsSshKeyInfo` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshkeyinfo) |
| `TomSecretsSshPrivateKey` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretssshprivatekey) |
| `TomSecretsStorageRelayFolder` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretsstoragerelayfolder) |
| `TomSecretsStore` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsstore) |
| `TomSecretsStoreLocation` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsstorelocation) |
| `TomSecretsStoreSpec` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsstorespec) |
| `TomSecretsSystemLinkRandom` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretssystemlinkrandom) |
| `TomSecretsTokenMatch` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretstokenmatch) |
| `TomSecretsTotp` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretstotp) |
| `TomSecretsTotpAlgorithm` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretstotpalgorithm) |
| `TomSecretsTotpFields` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretstotpfields) |
| `TomSecretsTrust` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#tomsecretstrust) |
| `TomSecretsUrlMatchLevel` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsurlmatchlevel) |
| `TomSecretsUrlMatchRule` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsurlmatchrule) |
| `TomSecretsVaultCodec` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsvaultcodec) |
| `TomSecretsVaultConflict` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsvaultconflict) |
| `TomSecretsVaultFields` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsvaultfields) |
| `TomSecretsVaultKeys` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsvaultkeys) |
| `TomSecretsVaultKind` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsvaultkind) |
| `TomSecretsVaultLocator` | Vaults and Resolution | [→](api_summary_vaults.md#tomsecretsvaultlocator) |
| `TomSecretsVaultSource` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsvaultsource) |
| `TomSecretsVaultUnit` | Sync, Merge and Compaction | [→](api_summary_sync.md#tomsecretsvaultunit) |

---

## Alphabetical Function Index

| Name | Module | Link |
| --- | --- | --- |
| `tomSecretsAcceptedBy` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAcceptKeyChange` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAddMember` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAddMemberKey` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeArmor` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeClassicalSecret` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeDearmor` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeDecrypt` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeEncrypt` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeEncryptPassphrase` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAgeIsPassphrase` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsApprovalCode` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsApproverKeyId` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsAsciiHost` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeCandidates` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeEnabled` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeSequenceFor` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeValues` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsAutoTypeWindowMatches` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsBase32` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsBase32Decode` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsBase32Encode` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsBase64Url` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsBech32Data` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsBitwardenDecrypt` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsBitwardenExportKeys` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsBitwardenNeedsPassword` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsBlobId` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsBreachCheckExcluded` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsBrowserOfCsv` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsCertificateOf` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsCheckSharedVaultMembers` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsClassifyMove` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsClientTokenHash` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsClientTokenId` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsCodeToken` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsCompact` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsCompactionFiles` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsCompactionMessage` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsCompactionSettingsOf` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsCompositeKey` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsConflictsOf` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsCopyEntry` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsDecodeBase64` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsDecodeStored` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsDefaultHost` | First Run and Device Settings | [→](api_summary_device.md#functions) |
| `tomSecretsDeviceCommitter` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsEncodeStored` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsEntryUrls` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsExportBitwardenJson` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportCsv` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportEnpassJson` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportEntries` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsExportKdbx` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsGenerateCertificate` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsGeneratePgpKey` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsGenerateSshKey` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsGitHubRemote` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsGitHubTokenExpiryHandle` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsGitHubTokenHandle` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsGivePairing` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsHealthReport` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsHkdf` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsImport` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportCategoryField` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportedAtField` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportGroupName` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportKdbxAsGroup` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportKdbxMerged` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsImportShare` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsImportVersionField` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsInboxDate` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsInboxExpired` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsInboxPath` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsAgeArmor` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsInboxMember` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsInboxName` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsPairingAddress` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsIsPasskeyField` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsIsPkcs12` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsIsReservedName` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsIsToken` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsJoinOuterKeys` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsKeyFileHandle` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsKeyId` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsKeysDue` | First Run and Device Settings | [→](api_summary_device.md#functions) |
| `tomSecretsLinkFrame` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsLinkRekey` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsLooksLikeShare` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsLp` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsLpList` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsLps` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsMarkMemberChecked` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsMatchLogins` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsMatchSiteUrl` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsMemberKeyEntries` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyFile` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyFileName` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyOf` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsMemberKeyRecipientOf` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsMembers` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsMergeVaults` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsMetadataEntry` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsMigrateSshKeys` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsNewInboxName` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsNewSharedVault` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsNewVault` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsNoiseHkdf` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsNormalizeCode` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsOuterCipherOf` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterCodecFor` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterDecrypt` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterEncrypt` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterKeyIds` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsOuterKeyList` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsOverlayBinding` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsPairingAddresses` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsPairingSetupProblem` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsParseAutoType` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsParseCsv` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsParseFileBinding` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsParsePairingAddress` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsParseTokenExpiration` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsPasskeyPem` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsPasswordChanged` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsPasswordHash` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsPasswordOf` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsPasswordStrength` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsPgpKeyOf` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsPgpPublicOf` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsPinText` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsRead1PasswordCsv` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsRead1Pux` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadBitwardenJson` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadBrowserCsv` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadEnpassCsv` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadEnpassJson` | Import and Export | [→](api_summary_import_export.md#functions) |
| `tomSecretsReadMemberKeys` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsReadRecipientsFile` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsReadShare` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsReceivePairing` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsReceivePairingAt` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsReceivePairingForSetup` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsReceivePairingVia` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsRecipientsFileName` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsRedeemToken` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsRegistrableDomain` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsRepositoryKeyHandle` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsRequestDigest` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsSameText` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsSetBreachCheckExcluded` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsSettleConflicts` | Sync, Merge and Compaction | [→](api_summary_sync.md#functions) |
| `tomSecretsShareFitsQr` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsShareOf` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsSharingGroupOf` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsSignedBytes` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsSshKeyCandidates` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsSshKeyOf` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsTakeNextKeys` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsTypedFileField` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsUuidFromHex` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsUuidHex` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsVaultCredentials` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsVaultKeyIds` | Key Files and Outer Encryption | [→](api_summary_protection.md#functions) |
| `tomSecretsVerifiedBy` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsWriteCertificate` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsWritePgpKey` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |
| `tomSecretsWriteRecipientsFile` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsWriteShare` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#functions) |
| `tomSecretsWriteSshKey` | Vaults and Resolution | [→](api_summary_vaults.md#functions) |

---

## Alphabetical Constant Index

| Name | Module | Link |
| --- | --- | --- |
| `tomSecretsAgeDefaultWorkFactor` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsAgeMaxWorkFactor` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsAmbiguousCharacters` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsBitwardenCardFields` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsBitwardenIdentityFields` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsBitwardenLosses` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsBitwardenSource` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsBreachCheckField` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsBrowserCsvLosses` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsBuiltInDimensions` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsCardsCategory` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsCertificateAttachment` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsCertificateKeyAttachment` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsCompactedFromTrailer` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsCompactionConfigPath` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsCompactionScriptPath` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsCompactionWorkflowPath` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsConflictKey` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsCsvExportColumns` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsDecisions` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsDefaultArgon2` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsDefaultAutoTypeSequence` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsDefaultValue` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsDeviceGroup` | First Run and Device Settings | [→](api_summary_device.md#constants) |
| `tomSecretsDeviceNamespace` | First Run and Device Settings | [→](api_summary_device.md#constants) |
| `tomSecretsDevicesGroup` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsEnpassCategories` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsEnpassCsvLosses` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsEnpassJsonLosses` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsEnpassSource` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsFavoriteTag` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsFormatKey` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsFormatVersion` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsGrantsGroup` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsIdentitiesCategory` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsInboxExpiry` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsInboxFolder` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsLinkKeyMigration` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsLinkMaxFrame` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsLinkProtocolName` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsMetadataFormat` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsMetadataTitle` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsNextKeysGroup` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsOnePasswordCategories` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsOnePasswordCsvLosses` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsOnePasswordSource` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsOnePuxLosses` | Import and Export | [→](api_summary_import_export.md#constants) |
| `tomSecretsOuterSuffix` | Key Files and Outer Encryption | [→](api_summary_protection.md#constants) |
| `tomSecretsOuterVersion` | Key Files and Outer Encryption | [→](api_summary_protection.md#constants) |
| `tomSecretsOverlayPrefix` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsPairingAad` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsPairingVersion` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsPairingWindow` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsPairingWords` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsPgpPrivateAttachment` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsPgpPublicAttachment` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsPkcs12Attachment` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsPlatforms` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsPrimaryKeyMonths` | First Run and Device Settings | [→](api_summary_device.md#constants) |
| `tomSecretsProductGroup` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsQrCapacity` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsRecipientsSuffix` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsRelayPairFolder` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsRelayStaleAfter` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsRetentionTrailer` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsRotationPeriod` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsRotationsGroup` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsSharedVaultKeysFormat` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsShareExtension` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsShareFormat` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsShareVersion` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsSharingGroup` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsSignedFields` | Trust, Approvals and Pairing | [→](api_summary_sharing.md#constants) |
| `tomSecretsSshAgentKeyTypes` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsSshAgentMaxBindings` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsSshAgentMaxMessage` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsStrengthMaxLength` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |
| `tomSecretsTokenExpirationHeader` | Sync, Merge and Compaction | [→](api_summary_sync.md#constants) |
| `tomSecretsTrustGroup` | First Run and Device Settings | [→](api_summary_device.md#constants) |
| `tomSecretsVaultsGroup` | Vaults and Resolution | [→](api_summary_vaults.md#constants) |