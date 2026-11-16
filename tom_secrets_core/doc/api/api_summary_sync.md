# Tom Secrets Core API Reference: Sync, Merge and Compaction Module

## Table of Contents

- [Overview](#overview)
- [Class Hierarchy](#class-hierarchy)
- [Types](#types)
  - [TomSecretsVaultCodec](#tomsecretsvaultcodec)
  - [TomSecretsPlainCodec](#tomsecretsplaincodec)
  - [TomSecretsVaultConflict](#tomsecretsvaultconflict)
  - [TomSecretsVaultSource](#tomsecretsvaultsource)
  - [TomSecretsHistoryRewritten](#tomsecretshistoryrewritten)
  - [TomSecretsVaultUnit](#tomsecretsvaultunit)
  - [TomSecretsEntryConflict](#tomsecretsentryconflict)
  - [TomSecretsMergeResult](#tomsecretsmergeresult)
  - [TomSecretsCachedVault](#tomsecretscachedvault)
  - [TomSecretsOfflineCache](#tomsecretsofflinecache)
  - [TomSecretsCommit](#tomsecretscommit)
  - [TomSecretsCommitReader](#tomsecretscommitreader)
  - [TomSecretsGitHubCommitReader](#tomsecretsgithubcommitreader)
  - [TomSecretsGitCommitReader](#tomsecretsgitcommitreader)
  - [TomSecretsBranchMove](#tomsecretsbranchmove)
  - [TomSecretsBranchAhead](#tomsecretsbranchahead)
  - [TomSecretsBranchCompacted](#tomsecretsbranchcompacted)
  - [TomSecretsBranchRewritten](#tomsecretsbranchrewritten)
  - [TomSecretsCompactionException](#tomsecretscompactionexception)
  - [TomSecretsCompactionSettings](#tomsecretscompactionsettings)
  - [TomSecretsCompactionResult](#tomsecretscompactionresult)
- [Global Functions and Constants](#global-functions-and-constants)

---

## Overview

The sync module is the GitHub cycle of a vault: a `tom_core_sync` sync unit over a `tom_core_storage` backend (the GitHub REST API, no clone), the three-way merge of two copies of a vault keyed by UUID with its conflict records, the offline cache a vault opens from when the remote cannot be reached, telling a history compaction from a force push, the compaction itself with the files each vault repository carries, and the expiry GitHub reports for a token.

Source files: `lib/src/vault_sync.dart`, `lib/src/vault_merge.dart`, `lib/src/offline_cache.dart`, `lib/src/history.dart`, `lib/src/compaction.dart`, `lib/src/github_token.dart`.

---

## Class Hierarchy

```text
Object
├── TomSecretsVaultCodec
│   └── TomSecretsPlainCodec (implements)
├── TomSecretsVaultConflict
├── TomSecretsVaultSource (enum)
├── TomSecretsHistoryRewritten
├── TomSecretsVaultUnit
├── TomSecretsEntryConflict
├── TomSecretsMergeResult
├── TomSecretsCachedVault
├── TomSecretsOfflineCache
├── TomSecretsCommit
├── TomSecretsCommitReader
│   ├── TomSecretsGitHubCommitReader (implements)
│   └── TomSecretsGitCommitReader (implements)
├── TomSecretsBranchMove
│   ├── TomSecretsBranchAhead
│   ├── TomSecretsBranchCompacted
│   └── TomSecretsBranchRewritten
├── TomSecretsCompactionException
├── TomSecretsCompactionSettings
└── TomSecretsCompactionResult
```

---

## Types

### TomSecretsVaultCodec

Turns a vault file's stored bytes into KDBX bytes and back: the outer encryption layer plugs in here; the identity when a repository has none.

**Kind:** `abstract interface class`

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `decode(bytes)` | `Future<Uint8List>` | The KDBX bytes of the stored `bytes`. |
| `encode(bytes)` | `Future<Uint8List>` | The stored bytes of the KDBX `bytes`. |

---

### TomSecretsPlainCodec

No outer layer.

**Kind:** `final class` · **Implements:** `TomSecretsVaultCodec`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsPlainCodec()` | const | The identity. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `decode(bytes)` | `Future<Uint8List>` | The KDBX bytes of the stored `bytes`. |
| `encode(bytes)` | `Future<Uint8List>` | The stored bytes of the KDBX `bytes`. |

---

### TomSecretsVaultConflict

The merge conflicts of one entry, as the sync engine queues them.

**Kind:** `final class` · **Implements:** `TomSyncConflict`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsVaultConflict(locator, conflict)` | const | A conflict of `conflict`'s entry in the vault at `locator`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `locator` | `String` | The vault. |
| `conflict` | `TomSecretsEntryConflict` | The entry's conflict record. |
| `anchor` | `String` | The record the conflict is about. |

---

### TomSecretsVaultSource

Where an open vault's file came from.

**Kind:** `enum`

#### Values

| Value | Description |
| --- | --- |
| `remote` | Read from (or written to) the remote. |
| `cache` | The offline cache: the remote could not be reached or refused the token. |

---

### TomSecretsHistoryRewritten

The remote's history was rewritten without a compaction (a force push): nothing was merged; the user chooses `TomSecretsVaultUnit.takeRemote` or `TomSecretsVaultUnit.mergeOverRemote`.

**Kind:** `final class` · **Implements:** `TomSyncConflict`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsHistoryRewritten(locator, remoteHead, reason)` | const | The vault at `locator`, its branch rewritten to the commit `remoteHead`, for `reason`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `locator` | `String` | The vault. |
| `remoteHead` | `String` | The rewritten branch's head commit. |
| `reason` | `String` | Why the move counts as rewritten. |
| `anchor` | `String` | The record the conflict is about. |

---

### TomSecretsVaultUnit

One vault kept converged with its remote.

**Kind:** `final class` · **Implements:** `TomSyncUnit`

#### Static Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `isOfflineFailure(error)` | `bool` | Whether `error` is a failure the offline cache may stand in for: no answer, or the token refused or missing (GitHub's 401 and 403 for the token). |
| `open({locator, storage, credentials, device, codec, maxPushAttempts, cache, history, clock})` | `Future<TomSecretsVaultUnit>` | Opens the vault at `locator` on `storage` with `credentials`: reads the head and the file at it; the head and the file as read are the base. `device` names this device in commit messages. |
| `create({locator, storage, file, device, codec, maxPushAttempts, cache, history, clock})` | `Future<TomSecretsVaultUnit>` | Creates the vault `file` at `locator` (which must not exist yet) and opens it. `file` is a new vault from `tomSecretsNewVault`; a file whose key is not derived through Argon2id is refused with `ArgumentError`. |
| `commitMessageFor(fileName, device)` | `String` | The commit message of a save: the vault and the device, never an entry title or a value. |
| `readAtHead(storage, locator, {attempts})` | `Future<(Uint8List, String)>` | The file at `locator` with the head it was read at: the head is read before and after the file, and again until both agree, so a branch that moved in between never pairs one head with another head's file. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `locator` | `String` | The vault's locator. |
| `storage` | `TomStorage` | The storage backend the vault is read from and written to. |
| `credentials` | `Credentials` | The vault's credentials (new ones after a `rekey`). |
| `device` | `String` | This device's name. |
| `codec` | `TomSecretsVaultCodec` | The outer layer (a new one after a `rekey`). |
| `maxPushAttempts` | `int` | How many commits a save attempts before its work waits in the journal. |
| `head` | `String?` | The head the open copy was read at. |
| `cache` | `TomSecretsOfflineCache?` | The offline cache, or null (mobile, or a vault never stored on this device): the base then lives in memory only while the vault is open. |
| `history` | `TomSecretsCommitReader?` | Reads the remote branch's commits, or null: without it a moved head is merged as usual, compaction or not. Used for `github:` vaults, whose path in the repository the locator names. |
| `source` | `TomSecretsVaultSource` | Where the open file came from: the remote, or the offline cache. |
| `fetchedAt` | `DateTime?` | When the base was last retrieved from (or written to) the remote. |
| `offlineReason` | `Object?` | Why the vault opened from the cache (the remote's failure), or null. |
| `rewrittenHead` | `String?` | The head commit of a rewritten remote history awaiting the user's choice (`takeRemote` or `mergeOverRemote`), or null. |
| `lastMove` | `TomSecretsBranchMove?` | How the remote moved the last time a new head was merged in, or null (no commit reader, or no move yet). |
| `working` | `KdbxFile` | The open copy the app edits; after an edit call `markEdited`. |
| `baseBytes` | `Uint8List` | The file as last read or written (the merge's base), as stored. |
| `merges` | `List<TomSecretsMergeResult>` | What every merge of this unit reported, oldest first. |
| `commitMessage` | `String` | The commit message of this vault's saves. |
| `edits` | `Stream<void>` | The local edits since the base. |
| `hasLocalChanges` | `bool` | Whether the open copy holds changes not yet pushed. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `markEdited()` | `void` | Records that the working copy changed, so the engine pushes it. |
| `replaceWorking(file, {stored})` | `void` | Makes `file` the working copy (a whole edited file, e.g. the one the app saved through the service) and marks it edited: the next `push` commits it over the base, merging with the remote when it moved. |
| `pull(remoteHead)` | `Future<List<TomSyncConflict>>` | Reads the remote file at `remoteHead` and merges it into the open copy. |
| `push()` | `Future<List<TomSyncConflict>>` | Commits the open copy on top of the base and moves the branch. |
| `rekey(file, {stored, codec})` | `Future<void>` | Commits `file` re-keyed: `stored` is `file` as the store keeps it under its new keys (`file`'s credentials, and `codec`'s outer layer), written as it is in one commit on top of the base's head. |
| `takeRemote()` | `Future<void>` | Takes the remote as it is, dropping local work: the answer to a force-pushed branch the user chose to follow. |
| `mergeOverRemote()` | `Future<List<TomSyncConflict>>` | Pushes the local copy over a rewritten remote: merges it three-way against an empty base with the remote's file (nothing is taken as deleted), then commits on top of the remote's head. The other answer to a force-pushed branch. |
| `followCompaction(result)` | `Future<void>` | Follows a compaction this device made (`result` of `tomSecretsCompact`) without a read: the base's head moves to the rewritten head, whose file is the same. |
| `dispose()` | `Future<void>` | Releases the open copy. |

---

### TomSecretsEntryConflict

One open conflict of an entry: both sides changed `fields` differently; the merged entry holds the newer values, and the loser is the entry's history version whose modification time is `loserModified`.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsEntryConflict({entryUuid, fields, loserModified, at})` | const | A conflict record. |
| `TomSecretsEntryConflict.fromJson(json)` | factory | From the JSON kept in `tsm.conflict`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `entryUuid` | `String` | The entry's UUID (KDBX base64 form). |
| `fields` | `List<String>` | The attributes both sides changed (`field:Password`, `tags`, ...). |
| `loserModified` | `DateTime` | The modification time of the losing version, kept in the history. |
| `at` | `DateTime` | When the merge met the conflict. |
| `record` | `TomConflictRecord<String>` | The `TomConflictRecord` of `tom_core_sync`: the entry's key and the locator of the retained loser (its modification time). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toJson()` | `Map<String, Object?>` | The JSON kept in `tsm.conflict`. |

---

### TomSecretsMergeResult

What a merge did.

**Kind:** `final class`

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `conflicts` | `List<TomSecretsEntryConflict>` | The real conflicts it met, one per entry (also recorded in the vault). |
| `editsAgainstDeletion` | `List<String>` | Entries one side deleted and the other edited: the edit stands. |
| `keptGroups` | `List<String>` | Groups one side deleted that still hold something after the merge, and were kept. |
| `isClean` | `bool` | Whether the merge met nothing to report. |

---

### TomSecretsCachedVault

One cached vault file with its record.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsCachedVault({locator, bytes, head, fetchedAt, blobId})` | — | The file `bytes` of `locator` as read at commit `head` at `fetchedAt`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `locator` | `String` | The vault. |
| `bytes` | `Uint8List` | The file as stored on the remote. |
| `head` | `String` | The head the storage read the file at (`TomStorage.headOf`; for `TomGitHubStorage` the file's blob id), which a save expects. |
| `blobId` | `String` | The file's git blob id. |
| `fetchedAt` | `DateTime` | When it was retrieved (UTC). |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `ageAt(now)` | `Duration` | How old the copy is at `now`. |
| `isStaleAt(now, {staleAfter})` | `bool` | Whether the notice "offline copy" turns into a warning at `now`: older than `staleAfter` (default `TomSecretsOfflineCache.defaultStaleAfter`). Never a reason to stop serving it: there is no age limit. |

---

### TomSecretsOfflineCache

The cache directory: `<root>/<repository>/<path>` per vault, beside it `<path>.tsm-cache.json` with the locator, the head it was read at, the blob id and the time it was fetched. No commit id is kept: the cycle finds its base in the remote's history by the blob id.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsOfflineCache(root)` | — | The cache under `root` (the app's or service's data directory, `cache/`). |

#### Static Properties

| Property | Type | Description |
| --- | --- | --- |
| `defaultStaleAfter` | `Duration` | The age after which an offline copy is shown as a warning. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `root` | `Directory` | The cache directory. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `fileFor(locator)` | `File` | The file `locator` is cached in: `<owner>/<repository>/<path>` for a `github:` vault, the locator's name made safe otherwise. |
| `put(vault)` | `Future<void>` | Keeps `vault`, replacing what was cached for its locator. The file is written first and the record last, each through a temporary file and a rename, so a record never names a file that is not there. |
| `get(locator)` | `Future<TomSecretsCachedVault?>` | What is cached for `locator`, or null: nothing cached, a record of another locator, or a file that is not the one its record names (a write that did not finish). |
| `remove(locator)` | `Future<bool>` | Deletes what is cached for `locator` (a vault removed from the device, or the device revoked); answers whether anything was there. |

---

### TomSecretsCommit

One commit as the cycle and the compaction read it.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsCommit({id, tree, parents, message, author, committer})` | const | Commit `id` of `tree` on `parents` with `message`, written by `author` and made by `committer` (when known). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `id` | `String` | The commit id. |
| `tree` | `String` | Its root tree. |
| `parents` | `List<String>` | Its parents (none for a root commit). |
| `message` | `String` | Its message. |
| `author` | `GitPerson?` | Who wrote it, when known. |
| `committer` | `GitPerson?` | Who made it, and when, when known. |
| `committedAt` | `DateTime?` | When it was committed, when known. |
| `compactedFrom` | `String?` | The head a compaction made this root commit from, or null when it is not a compaction's root. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `trailer(key)` | `String?` | The value of the trailer `key` in the message's last paragraph, or null. |

---

### TomSecretsCommitReader

Reads the commits of one branch of a repository.

**Kind:** `abstract interface class`

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `branchHead()` | `Future<String?>` | The branch's head commit, or null when the branch does not exist. |
| `readCommit(id)` | `Future<TomSecretsCommit>` | The commit `id`. |
| `blobAt(commit, path)` | `Future<String?>` | The blob id of the file at `path` in `commit`'s tree, or null when the tree holds no file there. |

---

### TomSecretsGitHubCommitReader

Commits read through the GitHub REST API (`GET git/commits/{sha}`), one request each.

**Kind:** `final class` · **Implements:** `TomSecretsCommitReader`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsGitHubCommitReader(client, owner, repository, {branch})` | — | Commits of `branch` (default: the repository's default branch) of `owner`/`repository` through `client`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `client` | `GitHubApiClient` | The API client. |
| `owner` | `String` | The repository's owner. |
| `repository` | `String` | The repository. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `branchHead()` | `Future<String?>` | The branch's head commit, or null when the branch does not exist. |
| `blobAt(commit, path)` | `Future<String?>` | One request: the commit's tree read recursively (a vault repository is small; a truncated listing is answered as no file). |
| `readCommit(id)` | `Future<TomSecretsCommit>` | The commit `id`. |

---

### TomSecretsGitCommitReader

Commits read from a `tom_git` repository (a `git:` vault's clone, or a repository a compaction fetched into).

**Kind:** `final class` · **Implements:** `TomSecretsCommitReader`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsGitCommitReader(repository, {branch, ref})` | — | Commits of `branch` of `repository`; `ref` names the branch's ref (default `refs/heads/<branch>`, e.g. a remote-tracking ref instead). |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `repository` | `GitRepository` | The repository. |
| `branch` | `String` | The branch. |
| `ref` | `String` | The ref its head is read from. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `branchHead()` | `Future<String?>` | The branch's head commit, or null when the branch does not exist. |
| `blobAt(commit, path)` | `Future<String?>` | The blob id of the file at `path` in `commit`'s tree, or null when the tree holds no file there. |
| `readCommit(id)` | `Future<TomSecretsCommit>` | The commit `id`. |

---

### TomSecretsBranchMove

How a branch moved from a base to a new head.

**Kind:** `sealed class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsBranchMove()` | const | Creates the base of the subtypes. |

---

### TomSecretsBranchAhead

The new head descends from the base: merge as usual.

**Kind:** `final class` · **Extends:** `TomSecretsBranchMove`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsBranchAhead(commits)` | const | Ahead by `commits` commits. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `commits` | `int` | How many commits the new head is ahead. |

---

### TomSecretsBranchCompacted

The history was compacted: the base left it, and the new history starts at a root commit carrying `Tsm-Compacted-From`. Its files continue the base's line, so the cycle merges against its base as usual.

**Kind:** `final class` · **Extends:** `TomSecretsBranchMove`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsBranchCompacted({root, from})` | const | Compacted by the root `root` from the old head `from`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `root` | `String` | The new root commit. |
| `from` | `String` | The head the compaction replaced. |

---

### TomSecretsBranchRewritten

The history was rewritten without a compaction's trailer (a force push), or could not be followed within the walk's limit: the user decides.

**Kind:** `final class` · **Extends:** `TomSecretsBranchMove`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsBranchRewritten(reason)` | const | Rewritten, for `reason`. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `reason` | `String` | Why the move counts as rewritten. |

---

### TomSecretsCompactionException

A compaction that could not be pushed.

**Kind:** `final class` · **Implements:** `Exception`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsCompactionException(message, {race})` | — | A failure described by `message`; `race` when saves kept landing between the read and the push. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `message` | `String` | What went wrong. |
| `race` | `bool` | Whether every attempt lost a race against a save. |

---

### TomSecretsCompactionSettings

A repository's compaction configuration (`.tsm/compaction.yaml`).

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsCompactionSettings({retentionDays, intervalDays})` | const | Revisions kept for `retentionDays` (0: only the current state); a compaction due every `intervalDays`. |
| `TomSecretsCompactionSettings.parse(yaml)` | factory | The configuration in `yaml`; a missing key keeps its default. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `retentionDays` | `int` | How far back revisions are kept, in days. |
| `intervalDays` | `int` | How often a compaction is due, in days. |

#### Methods

| Method | Return Type | Description |
| --- | --- | --- |
| `toYaml()` | `String` | The configuration file's text. |

---

### TomSecretsCompactionResult

What a compaction did.

**Kind:** `final class`

#### Constructors

| Constructor | Kind | Description |
| --- | --- | --- |
| `TomSecretsCompactionResult({oldHead, newHead, root, kept, compacted})` | const | Rewrote `oldHead` to `newHead`, starting at `root`, keeping `kept` commits above the root; `compacted` false when there was nothing to cut. |

#### Properties

| Property | Type | Description |
| --- | --- | --- |
| `oldHead` | `String` | The head before. |
| `newHead` | `String` | The head after (the old head when nothing was cut). |
| `root` | `String` | The new root commit (the old root when nothing was cut). |
| `kept` | `int` | The commits re-created above the root. |
| `compacted` | `bool` | Whether the branch was rewritten. |

---

## Global Functions and Constants

### Constants

| Constant | Type | Description |
| --- | --- | --- |
| `tomSecretsConflictKey` | `String` | The custom-data key of an entry's open conflicts. |
| `tomSecretsFormatKey` | `String` | The database custom-data key of the product's format version. |
| `tomSecretsFormatVersion` | `String` | The product format version this library writes (`major.minor`). |
| `tomSecretsCompactedFromTrailer` | `String` | The trailer naming the head a compaction replaced. |
| `tomSecretsRetentionTrailer` | `String` | The trailer naming the retention, in days, a compaction kept. |
| `tomSecretsCompactionWorkflowPath` | `String` | The workflow file's path in a vault repository. |
| `tomSecretsCompactionScriptPath` | `String` | The script's path in a vault repository. |
| `tomSecretsCompactionConfigPath` | `String` | The configuration's path in a vault repository. |
| `tomSecretsTokenExpirationHeader` | `String` | The header GitHub answers a token with an expiry with. |

### Functions

| Function | Signature | Description |
| --- | --- | --- |
| `tomSecretsDeviceCommitter` | `GitHubGitIdentity tomSecretsDeviceCommitter(String device)` | The committer and author of the cycle's commits for `device`: the device name with a placeholder address, `<device>@tsm.invalid` (`.invalid` never resolves, RFC 2606). The composition root passes it as `TomGitHubStorage(committer: ...)`. |
| `tomSecretsConflictsOf` | `List<TomSecretsEntryConflict> tomSecretsConflictsOf(KdbxEntry entry)` | The open conflicts recorded on `entry`. |
| `tomSecretsSettleConflicts` | `void tomSecretsSettleConflicts(KdbxEntry entry)` | Settles `entry`'s conflicts: the record goes; the history keeps the loser. |
| `tomSecretsMergeVaults` | `TomSecretsMergeResult tomSecretsMergeVaults({required KdbxFile? base, required KdbxFile ours, required KdbxFile theirs, DateTime? now, String? location})` | Merges `theirs` into `ours` against their common `base` (null: an empty base, the force-pushed case, where everything present counts as added). `ours` becomes the merged copy; `base` and `theirs` are only read. |
| `tomSecretsBlobId` | `String tomSecretsBlobId(List<int> bytes)` | The git blob id of `bytes`: SHA-1 over `blob <length>\0` and the bytes, the id the remote's tree names the file by. |
| `tomSecretsClassifyMove` | `Future<TomSecretsBranchMove> tomSecretsClassifyMove(TomSecretsCommitReader reader, {required String path, required String baseBlob, required String head, int maxCommits = 100})` | How the branch moved from the base to `head`: the history behind `head` is walked (newest first, every parent) until a commit whose file at `path` is `baseBlob` is found, or every path ends at a root commit, or `maxCommits` commits were read. |
| `tomSecretsCompactionMessage` | `String tomSecretsCompactionMessage({required String compactedBy, required String oldHead, required int retentionDays})` | The root commit's message: a subject naming who compacted, then the trailers. |
| `tomSecretsCompact` | `Future<TomSecretsCompactionResult> tomSecretsCompact({required GitHttpRemote remote, required TomSecretsCommitReader reader, required String branch, required String device, int retentionDays = 0, DateTime? now, int maxAttempts = 3})` | Compacts `branch` of `remote` for `device`: a new root commit holding the files as they were `retentionDays` days before `now` (0: as they are now), every later commit of the first-parent line re-created on it with the same tree, message, author and committer, the older ones dropped. |
| `tomSecretsGitHubRemote` | `GitHttpRemote tomSecretsGitHubRemote(TomSecretsGitHubLocator locator, {required Future<String?> Function() token, http.Client? client})` | The git remote of a `github:` vault's repository for `tomSecretsCompact`: `https://github.com/<owner>/<repository>.git` over smart HTTP, the vault token sent as `x-access-token` (the GitHub token the cycle uses; a compaction needs contents write, no more). |
| `tomSecretsCompactionFiles` | `Map<String, String> tomSecretsCompactionFiles([TomSecretsCompactionSettings settings = const TomSecretsCompactionSettings()])` | The files the app places in a vault repository: the workflow, its script and the configuration `settings`, by path. The workflow file needs the `workflows` permission the vault tokens do not have, so the app shows it and the user commits it; the script and the configuration the app commits itself. |
| `tomSecretsCompactionSettingsOf` | `TomSecretsCompactionSettings tomSecretsCompactionSettingsOf(String? text)` | `settings` read from the configuration file's `text`, or the defaults when there is none. |
| `tomSecretsParseTokenExpiration` | `DateTime? tomSecretsParseTokenExpiration(String value)` | The time in a `GitHub-Authentication-Token-Expiration` header (`2026-12-01 10:00:00 UTC`, or with a numeric offset), in UTC; null when it cannot be read. |
