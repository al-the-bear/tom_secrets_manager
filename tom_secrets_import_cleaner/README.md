# tom_secrets_import_cleaner

> Part of the Tom Secrets Manager by Peter Nicolai Alexis Kyaw,
> BSD-3-Clause.

`tsm_import_cleaner` cleans a password manager's export so it can be
handed to someone for testing the Tom Secrets Manager's import. Every
secret and every personal value is replaced; the structure the import
reads is kept, so the cleaned file imports with the same items, fields and
attachment sizes.

## Overview

| What | Becomes |
| --- | --- |
| passwords, notes, custom field values, one-time code secrets, password history | `X` for every character; whitespace and line breaks kept, so lengths stay |
| titles | `Item 1`, `Item 2`, ... (the same title, the same stand-in) |
| e-mail addresses | `user1@example.com`, ... |
| URLs and passkey relying parties | `https://site1.example.com/xxxx`: the host replaced, the path masked |
| attachments | the same number of bytes, all zero |
| private keys (passkeys, SSH keys) | emptied: the import names the key as missing |
| numbers inside a field's value (a card's expiry) | the same number of digits, `1000…` |
| ids, references, types, categories, field labels, timestamps, flags | kept |

Stand-ins stay unique, so importers that match items by title, URL and
user name (the CSV formats) still see distinct items.

The formats:

- Enpass JSON and Enpass CSV;
- Bitwarden JSON (unencrypted; an encrypted export is refused, its values
  are encrypted already);
- 1Password 1PUX (`export.data` cleaned, `files/` zeroed);
- the CSV exports with a header: 1Password, Bitwarden, Chrome, Edge,
  Firefox, Safari.

A KDBX file is refused: it opens only with its keys.

## Installation

The workspace's binaries build compiles it into each platform's binaries
folder (`buildkit.yaml`), so it is on `PATH` after the next build. To build
it by hand:

```text
dart compile exe bin/tsm_import_cleaner.dart -o tsm_import_cleaner
```

## Usage

```text
tsm_import_cleaner <export> [<cleaned>] [--force]
```

`<cleaned>` defaults to the export's name with `.cleaned` before its
extension. An existing file is not overwritten without `--force`.

```text
$ tsm_import_cleaner enpass_export.json
Enpass JSON: 1890 values masked, 3344 replaced by stand-ins, 5 attachments zeroed (2000 KiB), 12568 kept
wrote enpass_export.cleaned.json (4692 KiB)
```

Exit codes: 0 cleaned, 2 usage, 3 a file that cannot be read or written,
4 an export the cleaner does not know.

**Look at the cleaned file before you hand it on.** Field labels, folder
structure, categories and timestamps are kept on purpose; a label that
itself says something private stays.

## Testing

```text
testkit :test
```

The tests clean the core's synthetic fixtures of every format and read
the result with the core's own importers: the same items, field counts
and attachment sizes, and none of the original values left.

## Licence

BSD-3-Clause, see [LICENSE](LICENSE).
