# Tom Secrets Manager — core and service

The core of the Tom Secrets Manager: the pure-Dart library the service and the
apps share, and the secrets service that holds the unlocked secrets and answers
local clients. No Flutter here, so the service, the desktop app and the mobile
app take the same code.

GitHub: `al-the-bear/tom_secrets_manager`. The product's other two
repositories are `al-the-bear/tom_secrets_clients` (the protocol, the client
libraries and `tsm`) and `al-the-bear/tom_app_secrets_manager` (the apps, the
manual CI and the release build, with the install and first-run guide in its
README).

## Building

The service is a `dart build cli` bundle (its native library, `tom_pqc`'s,
in `lib/` beside `bin/`):

```text
cd tom_secrets_service
dart build cli --target bin/tom_secrets_service.dart -o build/service
```

The release build of `tom_app_secrets_manager` (`tom_secrets_build/ci.sh
:release`) builds it with `tsm` into the app's distribution. Every dependency comes from
pub.dev; the service takes the core by path inside this repository. Both
packages are on pub.dev: `tom_secrets_core` and `tom_secrets_service`.

## Packages

| Package | What it holds |
| --- | --- |
| `tom_secrets_core` | vaults and locators, the GitHub cycle, the offline cache, the entry-level merge, key files and the outer encryption with key slots, dimensions and resolution, the KDBX mapping, the importers, the hybrid pairing and signature crypto |
| `tom_secrets_service` | the secrets service executable: the client and admin endpoints, approval, grants, the audit log, lock modes |

What each holds today is in its own README: `tom_secrets_core`
([README](tom_secrets_core/README.md)) has everything in its row but the
pairing and signature crypto; `tom_secrets_service`
([README](tom_secrets_service/README.md)) has the runtime directory, both
endpoints, the admin channel with its challenge and claim, unlock and lock,
the lock modes and the device settings, and refuses every value until the
allow list and approvals are in place.

## Licence and boundaries

Every package here is BSD-3 (`LICENSE`). Only `tom_secrets_core` reaches KDBX,
and only through `tom_kdbx_store`'s own KDBX types; no package's dependency
closure may hold a GPL-licensed package.

## Design

The design decisions the code and documents cite (`DP-`, `BP-`, `TD-` and
`IDEA-` ids, the `part-…` sections) are recorded in the product's design
document, which is not published with the source. The published contract
between the service and its clients is the protocol document of
`al-the-bear/tom_secrets_clients` (`protocol/protocol.md`).
