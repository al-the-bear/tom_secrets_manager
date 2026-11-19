# Tom Secrets Manager core — development guidelines

Guidelines for the packages of this repository (`tom_secrets_core`,
`tom_secrets_service`).

## Boundaries

- Only `tom_secrets_core` reaches KDBX, and only through `tom_kdbx_store`'s
  own KDBX types; it imports no KDBX library itself. What the core needs and
  the store lacks is added to `tom_kdbx_store` and released there.
- The service takes the protocol codec (frames, messages, the reference
  grammar) from `tom_secrets_client`, never a second copy.
- `tom_pqc` is taken by version from pub.dev, once published.

## Rules for every package

- **BSD-3.** Every package carries the BSD-3 licence and copyright notice of
  the repository's `LICENSE`; no package's dependency closure may hold a
  GPL-licensed or other copyleft package.
- **Quality per change:** `dart analyze` clean (no Problems pane issue), tests
  run with `testkit` (or `dart test`) from the package root, and the manual
  CI `tom_secrets_build/ci.sh :all` of `tom_app_secrets_manager`, which
  covers this repository too.
- **CLI tools** are built on `tom_build_base`.
- **Locks:** a library keeps its `pubspec.lock` ignored; an application
  package (a tracked `bin/*.dart`, or a Flutter app) tracks it with an
  anchored `!/pubspec.lock` in its own `.gitignore`.
- **No CI on GitHub.** Actions is switched off for this repository; builds,
  tests and checks are started by a person from the clone.
- **Real secrets never enter the repository or a test.** Tests and corpora use
  demo data under demo keys.
- **New packages** are listed in this repository's README (and in the
  project register of the maintainers' workspace).
- **Standalone.** Nothing shipped names the maintainers' workspace: no path
  dependency into another repository, no `pubspec_overrides.yaml`, no
  workspace path in code or documents (`tom_secrets_build/ci.sh :standalone`).

The maintainers' workspace-wide guidelines apply as well. The design
document the code cites is not published with the source.

## Documents

| Document | Purpose |
| -------- | ------- |
| [index.md](index.md) | This index: the repository's rules and its guideline documents |
