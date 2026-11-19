# Tom Secrets Manager — core and service

The vaults, the resolution of secret references and the secrets service of
the Tom Secrets Manager, in pure Dart.

> Part of the **Tom Secrets Manager** by al-the-bear.
> © 2026 Peter Nicolai Alexis Kyaw — BSD-3-Clause, see [LICENSE](LICENSE).

This document is the map of the repository `tom_secrets_manager`; each
package has its own README. The Tom Secrets Manager keeps secrets in KDBX
vaults (local files or GitHub repositories) and hands them to the programs of
one OS user through a local service that measures who asks and asks an
approver before a program gets a value the first time. No Flutter here, so the
service, the desktop app and the mobile app share the same code.

**New here?** Start with the
[install and first-run guide](https://github.com/al-the-bear/tom_app_secrets_manager#readme)
of the apps; to read secrets from a program, go to the
[clients repository](https://github.com/al-the-bear/tom_secrets_clients#readme).

## What you can do with it

- Keep secrets in KDBX vaults, one primary vault per user and further vaults
  it lists, local or in a GitHub repository with an offline cache.
- Name a secret by a reference (`[env:prod]db.main`) that resolves per host,
  platform and environment through overlays and dimensions.
- Run a per-user service that answers local programs, decides by signed
  grants which program may read what, and asks the app or a paired device for
  the rest.
- Pair machines, so a desktop approves the requests of a headless server.

## The product's repositories

| Repository | What it holds |
| --- | --- |
| `al-the-bear/tom_secrets_manager` (this one) | the core library and the secrets service |
| [`al-the-bear/tom_secrets_clients`](https://github.com/al-the-bear/tom_secrets_clients) | the protocol document, the conformance suite, the client libraries and the command line `tsm` |
| [`al-the-bear/tom_app_secrets_manager`](https://github.com/al-the-bear/tom_app_secrets_manager) | the desktop and mobile apps, the build, the install and first-run guide |

## Packages

| Package | What it is | Binary |
| --- | --- | --- |
| [`tom_secrets_core`](tom_secrets_core/README.md) | vaults and locators, the GitHub cycle, the offline cache, the entry-level merge, key files and the outer encryption with key slots, dimensions and resolution, the KDBX mapping, the importers, the pairing and signature crypto | — |
| [`tom_secrets_service`](tom_secrets_service/README.md) | the secrets service: the client and admin endpoints, peer identity, approvals and grants, the approval link, the audit log, lock modes, the device settings | `tom_secrets_service` |

Both are on pub.dev. The service takes the core by path inside this
repository; every other dependency comes from pub.dev.

## Getting started

The service is a `dart build cli` bundle, its executable in `bin/` and the
native library of `tom_pqc` in `lib/` beside it:

```sh
cd tom_secrets_service
dart build cli --target bin/tom_secrets_service.dart -o build/service
```

It is started by the manager app or by `tsm start`, never by hand (it reads a
handover line on its standard input). The release build of
`tom_app_secrets_manager` builds it with `tsm` into the app's distribution.

Each package's suite runs with `testkit :test` from its folder.

## Documentation

| Topic | Document |
| --- | --- |
| Stores, overlays, resolution, the GitHub cycle, outer encryption, importers | [`tom_secrets_core` README](tom_secrets_core/README.md) |
| Running and configuring the service, what it does, its limits | [`tom_secrets_service` README](tom_secrets_service/README.md) |
| The wire format between the service and its clients | [protocol document](https://github.com/al-the-bear/tom_secrets_clients/blob/main/protocol/protocol.md) |
| Installing the apps, the first run | [`tom_app_secrets_manager` README](https://github.com/al-the-bear/tom_app_secrets_manager#readme) |

The design decisions the code and documents cite (`DP-`, `BP-`, `TD-` and
`IDEA-` ids, the `part-…` sections) are recorded in the product's design
document, which is not published with the source. The published contract
between the service and its clients is the protocol document.

## Repository layout

```text
tom_secrets_manager/
  tom_secrets_core/        the core library: stores, resolution, vault cycle, crypto
    lib/src/               one file per concern (store, resolution, vault_sync, pairing, ...)
    example/               a resolution example
    test/                  the core's suite (one live GitHub test, skipped by default)
  tom_secrets_service/     the secrets service executable and library
    bin/                   the executable: hardening, handover, launch
    lib/src/               endpoints, approvals, links, audit, vaults, identity, log
    test/                  the service's suite, in-process and as a compiled process
  _agent_guidelines/     development notes for contributors
  LICENSE                  BSD-3-Clause
```

## Licence and boundaries

Every package here is BSD-3-Clause ([LICENSE](LICENSE)). Only
`tom_secrets_core` reaches KDBX, and only through `tom_kdbx_store`'s own KDBX
types; no package's dependency closure holds a GPL-licensed package.
