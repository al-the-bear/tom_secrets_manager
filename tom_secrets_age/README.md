# Tom Secrets Age

The `age` v1 file format and the member keys of the Tom Secrets Manager, in
pure Dart over `tom_pqc`, without any vault format. `tom_secrets_core`
re-exports it; the relay server (`tom_secrets_relay`) uses it alone to
answer a mailbox's recipient proof.

## What it holds

| Part | API |
| --- | --- |
| `age` v1 files to hybrid recipients (`mlkem768x25519`, HPKE with X-Wing), classical ones (`X25519`) or under a passphrase (`scrypt`), never hybrid and classical in one file; the armour | `tomSecretsAgeEncrypt`, `tomSecretsAgeEncryptPassphrase`, `tomSecretsAgeDecrypt`, `tomSecretsAgeArmor`, `tomSecretsAgeDearmor`, `TomSecretsAgeIdentity` |
| Member keys: hybrid `age` v1.3 identities (`AGE-SECRET-KEY-PQ-1…`) and their recipients (`age1pq1…`, X25519 + ML-KEM-768), other people's classical `age1…` recipients, the fingerprint (base32 SHA-256 of the recipient), the published key file | `TomSecretsMemberKey`, `TomSecretsAgeRecipient`, `tomSecretsMemberKeyFile`, `tomSecretsReadMemberKeys` |
| HKDF-SHA-256 (RFC 5869) | `tomSecretsHkdf` |

The reader passes the age testkit's hybrid and scrypt vectors
([C2SP/CCTV](https://github.com/C2SP/CCTV), in `test/fixtures/`), and files
go both ways with `filippo.io/age` v1.3.2.

## Installation

```yaml
dependencies:
  tom_secrets_age: ^0.1.0
```

`tom_pqc` compiles vendored C with the platform's C compiler when the
application is built.

## Usage

```dart
import 'package:tom_secrets_age/tom_secrets_age.dart';

final key = await TomSecretsMemberKey.generate();
final file = await tomSecretsAgeEncrypt(bytes, [key.recipient]);
final text = tomSecretsAgeArmor(file); // paste into a message
final back = await tomSecretsAgeDecrypt(file, [
  TomSecretsAgeHybridIdentity(key),
]);
key.dispose();
```

`example/tom_secrets_age_example.dart` runs it with a demo key.

## Limits

- No plugin recipients and no SSH recipients; a classical identity is read,
  never made.
- A passphrase file's work factor is at most 22 (as `age`); scrypt runs in
  another isolate.

## More

The API reference is [doc/api/api_summary_age.md](doc/api/api_summary_age.md);
the member keys' role in sharing is in `tom_secrets_core`'s README.

## Licence

BSD 3-Clause ([LICENSE](LICENSE)).
