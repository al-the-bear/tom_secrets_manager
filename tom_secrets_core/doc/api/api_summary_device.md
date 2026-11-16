# Tom Secrets Core API Reference: First Run and Device Settings Module

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Types](#types)
  - [TomSecretsFirstRunProblem](#tomsecretsfirstrunproblem)
  - [TomSecretsFirstRunException](#tomsecretsfirstrunexception)
  - [TomSecretsGitHubRepositoryCheck](#tomsecretsgithubrepositorycheck)
  - [TomSecretsFirstRunSetup](#tomsecretsfirstrunsetup)
  - [TomSecretsFirstRunResult](#tomsecretsfirstrunresult)
  - [TomSecretsFirstRun](#tomsecretsfirstrun)
  - [TomSecretsDeviceKeyMode](#tomsecretsdevicekeymode)
  - [TomSecretsLockMode](#tomsecretslockmode)
  - [TomSecretsLockPolicy](#tomsecretslockpolicy)
  - [TomSecretsDeviceKeyException](#tomsecretsdevicekeyexception)
  - [TomSecretsDeviceSettings](#tomsecretsdevicesettings)
  - [TomSecretsDeviceKeys](#tomsecretsdevicekeys)
  - [TomSecretsDeviceContainer](#tomsecretsdevicecontainer)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The device module sets a machine up and keeps its local settings: the first run (the primary vault created or opened, its protection layers, the machine's settings, the keys in the device keychain, or everything taken from a pairing bundle) and the device settings container with its lock policies and the place its key is kept (OS keychain, primary vault or key file).

Source files: `lib/src/first_run.dart`, `lib/src/device_settings.dart`.

---

## Class Hierarchy

```text
Object
├── TomSecretsFirstRunProblem (enum)
├── TomSecretsFirstRunException
├── TomSecretsGitHubRepositoryCheck
├── TomSecretsFirstRunSetup
├── TomSecretsFirstRunResult
├── TomSecretsFirstRun
├── TomSecretsDeviceKeyMode (enum)
├── TomSecretsLockMode (enum)
├── TomSecretsLockPolicy
├── TomSecretsDeviceKeyException
├── TomSecretsDeviceSettings
├── TomSecretsDeviceKeys
└── TomSecretsDeviceContainer
```

---

## Types

### TomSecretsFirstRunProblem

Why the first run cannot go on.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `tokenRefused` | GitHub refused the token (401, or 403 without a rate limit). |
| `repositoryNotFound` | The repository does not exist, or the token cannot see it. |
| `repositoryEmpty` | The repository has no commit yet: GitHub cannot take a file into it through the REST API. Create it with a README. |
| `unreachable` | GitHub (or the disk) could not be reached. |
| `primaryExists` | A new primary would replace a file that is already there. |
| `primaryNotFound` | The primary to open is not there. |
| `wrongPassword` | The master password (with the key file) does not open the primary. |
| `repositoryKeyNeeded` | The primary is outer encrypted and no repository key was given. |
| `repositoryKeyWrong` | The repository key given has no slot in the primary, or the file is damaged. |
| `notAVault` | The file is not a vault this product reads. |
| `inconsistent` | The locator, the protection layers and the file name do not agree (a `.tsmx` name without a repository key, or the other way round). |
| `keychainNeeded` | Keys are to be kept and there is no keychain. |
| `alreadySetUp` | The machine is set up already: `bootstrap.yaml` is there. |

---

### TomSecretsFirstRunException

The first run cannot go on, for `problem`.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsFirstRunException(problem, message)` | — | A `problem` described by `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `problem` | `TomSecretsFirstRunProblem` | What is wrong. |
| `message` | `String` | What it means, for the user. |

---

### TomSecretsGitHubRepositoryCheck

A GitHub repository as a token sees it.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsGitHubRepositoryCheck({defaultBranch, expires})` | const | The repository's `defaultBranch`; the token `expires` then (null: no expiry reported). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `defaultBranch` | `String` | The repository's default branch. |
| `expires` | `DateTime?` | When the token expires, as GitHub reports it, or null. |

---

### TomSecretsFirstRunSetup

What the first run sets up.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsFirstRunSetup({primary, create, masterPassword, keyFile, repositoryKey, cipher, githubToken, githubTokenExpires, settings, deviceKey, host})` | — | A setup of the primary at `primary`, `create`d or opened, with `masterPassword` and the optional layers; `settings` and `deviceKey` for this machine. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `primary` | `TomSecretsVaultLocator` | Where the primary is. |
| `create` | `bool` | Whether a new primary is created (else an existing one is opened). |
| `masterPassword` | `String` | The master password. |
| `keyFile` | `Uint8List?` | The key file's bytes (a new one from `TomSecretsKeyFile.toBytes`, or one chosen), or null for none. |
| `repositoryKey` | `TomSecretsRepositoryKey?` | The repository's outer key, or null for none. |
| `cipher` | `TomSecretsOuterCipher` | The outer cipher of a new primary (an existing one keeps its own). |
| `githubToken` | `String?` | The GitHub token for the primary's repository (a `github:` primary). |
| `githubTokenExpires` | `DateTime?` | The token's expiry as entered, or null (then GitHub's report is kept). |
| `settings` | `TomSecretsDeviceSettings` | The machine's settings: its default environment, the files it serves, the lock modes. |
| `deviceKey` | `TomSecretsDeviceKeyMode` | Where the device settings container's key is kept. |
| `host` | `String?` | The host name, when it is to differ from `tomSecretsDefaultHost`. |

---

### TomSecretsFirstRunResult

What the first run did.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsFirstRunResult({bootstrapPath, created, deviceKey, keysDue, githubTokenExpires})` | const | The result. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `bootstrapPath` | `String` | The `bootstrap.yaml` written. |
| `created` | `bool` | Whether a new primary was written. |
| `deviceKey` | `TomSecretsDeviceKeyMode` | Where the device settings container's key went (`auto` decided). |
| `keysDue` | `DateTime?` | The primary's `tsm.keys-due`, when one was set. |
| `githubTokenExpires` | `DateTime?` | The GitHub token's expiry kept, or null. |

---

### TomSecretsFirstRun

The first run of a machine, writing into `dataDirectory` and `keychain`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsFirstRun({dataDirectory, keychain, httpClient, githubBaseUrl, argon2, clock})` | — | A first run for the data directory `dataDirectory` (where `bootstrap.yaml` goes), keeping keys in `keychain` (null: none on this machine), reaching GitHub at `githubBaseUrl` through `httpClient`; new vaults keyed with `argon2`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `dataDirectory` | `String` | The data directory. |
| `keychain` | `TomSecretStore?` | The device keychain, or null. |
| `githubBaseUrl` | `String` | GitHub's API. |
| `argon2` | `KdbxArgon2` | The key derivation of a new vault. |
| `bootstrapPath` | `String` | The bootstrap file the first run writes. |
| `deviceContainerPath` | `String` | The device settings container's file (the bootstrap's default). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `checkGitHub({owner, repository, token})` | `Future<TomSecretsGitHubRepositoryCheck>` | Checks that `token` sees `owner`/`repository`: answers its default branch and the token's expiry GitHub reports. Throws `TomSecretsFirstRunException` (`tokenRefused`, `repositoryNotFound`, `unreachable`). |
| `run(setup)` | `Future<TomSecretsFirstRunResult>` | Sets the machine up as `setup` says; see the library comment for the order. Throws `TomSecretsFirstRunException`; nothing is written to the keychain, the container or the bootstrap before the primary opened (or was written), and the bootstrap only when everything else succeeded. |
| `runPaired(receipt, {masterPassword, settings, deviceKey})` | `Future<TomSecretsFirstRunResult>` | Sets the machine up from a pairing `receipt`: the bundle's primary opened with `masterPassword` and its keys and token from the bundle, `settings` and `deviceKey` as for `run`; then the keys of every further vault of the bundle and its tokens kept in the keychain, and this machine's trust material written into the device settings container with the giving device recorded: it approves for this machine, and this machine approves for it (its link key and address, the approval-token key the pairing derived). |

---

### TomSecretsDeviceKeyMode

Where the device settings container's key is kept.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `auto` | The keychain where one is available, else `vault` (the default). |
| `keychain` | The OS keychain; the service refuses to start without an unlocked one. |
| `vault` | The primary vault, overlay entry `@host:<host>/.tom-secrets/device`. |
| `keyfile` | A key file (mode 0600; on Windows an ACL of the user) beside the container. |

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `parse(name)` | `TomSecretsDeviceKeyMode` | The mode named `name`. |

---

### TomSecretsLockMode

How a lock policy relocks.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `never` | (a) Automatic locking is off. |
| `idle` | (b) Relock after an idle period; unlock again with the master password. |

---

### TomSecretsLockPolicy

A lock policy.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsLockPolicy({mode, idle, maxUnlocked, lockOnSleep})` | const | A policy of `mode` relocking after `idle` input idle time; `maxUnlocked` caps the unlocked time whatever the input (null: off); `lockOnSleep` asks the app to lock the service on system sleep. |
| `TomSecretsLockPolicy.fromJson(json)` | factory | From the stored JSON. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `mode` | `TomSecretsLockMode` | The mode. |
| `idle` | `Duration` | The idle period of mode (b). |
| `maxUnlocked` | `Duration?` | The longest unlocked time, or null. |
| `lockOnSleep` | `bool` | Whether the app locks the service on system sleep. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The JSON kept in the device settings. |
| `shouldLock({idle, unlockedFor})` | `bool` | Whether to lock now, the input having been idle `idle` (null: cannot be measured, headless) and the service unlocked for `unlockedFor`. |

---

### TomSecretsDeviceKeyException

The device settings container's key could not be had.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsDeviceKeyException(message)` | — | A problem described by `message`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What is wrong. |

---

### TomSecretsDeviceSettings

What the device settings hold. The keys of later parts (approver and approval-link keys, the audit-log key) are added by their parts.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsDeviceSettings({serviceLock, appLock, defaultEnvironment, servedStores, refreshMinutes, offlineCache, keyExpiryWarningDays, approvalTimeout, codeTimeout, startAtLogin, approvalLink, otherKeyWarningDays, keyPairAgeMonths, primaryKeyAgeMonths, vaultKeyAgeMonths})` | const | Settings with the defaults for every value not given. |
| `TomSecretsDeviceSettings.fromJson(json)` | factory | From the stored JSON; a value missing takes its default. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `serviceLock` | `TomSecretsLockPolicy` | The service's lock mode. |
| `appLock` | `TomSecretsLockPolicy` | The app's lock mode, kept here for the app. |
| `defaultEnvironment` | `String?` | The machine's default environment (`env`), or null. |
| `servedStores` | `List<String>?` | The stores this machine serves, or null for every one. |
| `refreshMinutes` | `int` | The refresh interval in minutes; 0 switches it off. |
| `offlineCache` | `bool` | Whether the offline cache is kept. |
| `keyExpiryWarningDays` | `int` | How many days before a key expires the reminders start. |
| `approvalTimeout` | `Duration` | How long a request waits for an unlock or an approval. |
| `codeTimeout` | `Duration` | How long an approval code is valid. |
| `approvalLink` | `String?` | Where this host's approval link listens (`address:port`, its VPN or LAN address, never all interfaces); null: no link. |
| `startAtLogin` | `bool` | Whether the app starts at login (phase B). |
| `otherKeyWarningDays` | `int` | How many days before its due date the reminders of a key other than the GitHub token start (Reminders, default 30). |
| `keyPairAgeMonths` | `int` | The rotation age of the approver and approval-link key pairs, in months (default 24). |
| `primaryKeyAgeMonths` | `int` | The rotation age a new key file or repository key of the primary vault gets, in months (default 24; rotating them means pairing again). |
| `vaultKeyAgeMonths` | `int` | The rotation age a new key file or repository key of every other vault gets, in months (default 12). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The JSON kept in the container. |

---

### TomSecretsDeviceKeys

The container's key, by the mode `bootstrap.yaml` names.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsDeviceKeys({mode, host, containerPath, keychain})` | — | Keys for the container at `containerPath` of `host`; `keychain` the OS keychain, null where none is available. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `mode` | `TomSecretsDeviceKeyMode` | The configured mode. |
| `host` | `String` | This machine's host name. |
| `containerPath` | `String` | The container's file. |
| `keychain` | `TomSecretStore?` | The OS keychain, or null. |
| `keychainHandle` | `String` | The keychain handle of this machine's container key. |
| `keyFilePath` | `String` | The key file beside the container. |
| `vaultPath` | `List<String>` | The overlay path of the vault entry holding the key. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `keychainAvailable()` | `Future<bool>` | Whether a keychain answers (a read that fails means none is available, or it is locked). |
| `effectiveMode()` | `Future<TomSecretsDeviceKeyMode>` | The mode in effect: `mode`, with `auto` decided (keychain where one is available, else vault). Throws `TomSecretsDeviceKeyException` for `keychain` without an available keychain: the service refuses to start. |
| `keyFor({primary, savePrimary})` | `Future<String>` | The container's key, minted on first use. `primary` is the unlocked primary vault; with the `vault` mode a new key is written into it and `savePrimary` saves it. |

---

### TomSecretsDeviceContainer

The device settings container, opened with its key.

**Kind:** `final class`

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `open(path, key)` | `Future<TomSecretsDeviceContainer>` | Opens (or creates in memory) the container at `path` with `key`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `settings` | `TomSecretsDeviceSettings` | The settings as read (defaults for what is not stored). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `trust(device, {now})` | `Future<TomSecretsTrust>` | The device's trust material (its keys, the approvers and hosts it recorded), created for `device` (its key pairs dated `now`) and committed when the container holds none yet. |
| `writeTrust(value)` | `Future<void>` | Replaces the trust material and commits the container. |
| `write(value)` | `Future<void>` | Replaces the settings and commits the container. |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsPrimaryKeyMonths` | `int` | How long a new primary's key file and repository key are good for before they are due for rotation. |
| `tomSecretsDeviceNamespace` | `String` | The settings namespace of the product. |
| `tomSecretsDeviceGroup` | `String` | The settings group the device settings are kept in, as one fragment. |
| `tomSecretsTrustGroup` | `String` | The container's group of the device's trust material (keys, recorded approvers and hosts). |

### Functions

| Function | Signature | Description |
| --- | --- | --- |
| `tomSecretsDefaultHost` | `String tomSecretsDefaultHost()` | The host name the service goes by when `bootstrap.yaml` names none: the machine's name up to its first dot, in lower case. |
| `tomSecretsKeysDue` | `DateTime tomSecretsKeysDue(DateTime created, {int months = 24})` | The due date of keys created at `created`: `months` later, the day kept (the last of the month where that month is shorter). |
