# Tom Secrets Manager — core and service

The core of the Tom Secrets Manager: the pure-Dart library the service and the
apps share, and the secrets service that holds the unlocked secrets and answers
local clients. No Flutter here, so the service, the desktop app and the mobile
app take the same code.

In the workspace this repository is the submodule `tom_ai/secrets_manager`
(repository id `TSM`, GitHub `al-the-bear/tom_secrets_manager`, private).

## Packages

| Package | What it holds |
| --- | --- |
| `tom_secrets_core` | vaults and locators, the GitHub cycle, the offline cache, the entry-level merge, key files and the outer encryption with key slots, dimensions and resolution, the KDBX mapping, the importers, the hybrid pairing and signature crypto |
| `tom_secrets_service` | the secrets service executable: the client and admin endpoints, approval, grants, the audit log, lock modes |

`tom_secrets_core` holds the model and resolution so far
([README](tom_secrets_core/README.md)); the rest of it and the service are
created by the quest's phase-A todos.

## Licence and boundaries

Every package here is BSD-3 (`LICENSE`). Only `tom_secrets_core` reaches KDBX,
and only through `tom_kdbx_store`'s own KDBX types; no package's dependency
closure may hold a GPL-licensed package.

## Design

The design is the idea document of the tom_core quest,
`_ai/quests/tom_core/ideas/tom_secrets_manager/tom_secrets_manager.md`
(section `part-repositories`); the work is tracked in the
`tom_secrets_manager` quest.
