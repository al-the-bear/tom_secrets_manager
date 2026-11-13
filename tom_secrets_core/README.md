# Tom Secrets Core

The core of the Tom Secrets Manager: the pure-Dart library the service and the
apps share. It reads KDBX files only through `tom_kdbx_store`, and takes the
reference grammar from `tom_secrets_client`, so the clients, the core and the
service parse references with one implementation.

## What it holds

- **Stores** (`TomSecretsStore`): one KDBX file under its store name (the
  machine's configuration, else the metadata's `tsm.store`, else the file
  name), indexed for resolution. Each entry gets its logical path (the groups
  below the root without the overlay groups, then the title), its bindings
  (the file binding and its overlay groups) and its flat key (`tsm.key`). The
  recycle bin, the metadata entry and the `tsm.grants` group are never
  reached; an overlay that binds a dimension twice, an overlay group between
  ordinary groups and a `tsm.key` that is not a key are skipped and named in
  `warnings`.
- **Overlays**: a group `@<dimension>:<value>` binds every entry below it,
  at the file's root (`@host:bomber/Telegram/Bot`) or inside the entry's own
  group (`Telegram/@host:bomber/Bot`), nestable.
- **The metadata entry** `.tom-secrets` (`TomSecretsMetadata`): `tsm.format`,
  `tsm.store`, `tsm.kind`, `tsm.purpose`, `tsm.dimensions` (the file binding)
  and, in the primary vault, `tsm.config`.
- **The shared configuration** `tsm.config` (`TomSecretsConfig`): the
  dimensions in priority order with an optional configured `default` and
  `fallback_to_default` (off unless set), and the stores per environment
  (a local path or a GitHub repository and path). Built-in dimensions the
  list leaves out (`host`, `platform`, `env`) come first, in that order.
- **Resolution** (`TomSecretsResolver`): the request's value per dimension (a
  binding in the brackets, else beside the reference, else the machine's
  value, else the configured default, else `default`); candidates (a path, a
  `~uuid` with the overlays of its path, or a key with the overlays at each
  keyed entry's path); the strict match with the per-dimension fallback; the
  rank vectors (2 bound to the value, 1 kept by the fallback, 0 unbound);
  ambiguity; the field (a string field, `attachment:<name>`, the virtual
  `totp`; passkey fields are `denied`). Failures are
  `TomSecretsResolveException`s with the protocol's kinds and details.
- **The KDBX mapping** (`TomSecretsEntryFields`, `TomSecretsEntryType`) and
  **TOTP** (`TomSecretsTotp`, RFC 6238): the three conventions `otp`,
  `OTPAuth` and `TimeOtp-*`, read in that order and written together.

```dart
final resolver = TomSecretsResolver(
  stores: [TomSecretsStore.fromFile(file, name: 'fleet')],
  config: TomSecretsConfig.builtIn(),
  machine: TomSecretsMachine.current(values: {'env': 'prod'}),
);
final resolution = resolver.resolve('[env:prod]db.main#UserName');
print(resolution.entry.pathText);
resolution.value.dispose();
```

The design is part-structure of the idea document
(`_ai/quests/tom_core/ideas/tom_secrets_manager/tom_secrets_manager.md`); its
worked examples are `test/worked_examples_test.dart`, row by row.

## Licence

BSD-3-Clause (`LICENSE`).
