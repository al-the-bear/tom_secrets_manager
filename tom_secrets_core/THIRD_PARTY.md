# Third-party material

`tom_secrets_core` is licensed under the BSD 3-Clause License
([`LICENSE`](LICENSE)). It carries one work of others as data:

| Material | Licence | Where | Used for |
| --- | --- | --- | --- |
| [The Public Suffix List](https://publicsuffix.org/) | Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/) | `lib/src/public_suffix_list.g.dart`: the list's rules as published, unmodified but for non-ASCII labels written as punycode; the file keeps the list's licence notice | the registrable domain in URL matching (`tomSecretsRegistrableDomain`) |

The list is regenerated with `tool/update_public_suffix_list.py`, which
fetches it from publicsuffix.org, the one place its maintainers ask it to be
pulled from. The MPL applies to that file only (it is file-level copyleft):
the rest of the package stays under the BSD 3-Clause License, and a change to
the list's data would have to be published under the MPL.

Of the packages it depends on, two came with the typed certificates and PGP
keys (phase C): `basic_utils` (MIT) generates and reads X.509 certificates,
requests and their keys, and `dart_pg` (BSD 3-Clause) generates and reads
OpenPGP keys; `dart_pg` brings `pinenacl` (MIT), `sign_dart` (BSD 3-Clause)
and `sha3` (MIT). None is copyleft (the repository's licence-boundary check
holds every closure to that).
