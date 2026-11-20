# GnuPG-made demo keys

Demo keys made with GnuPG 2.5.24 for the typed PGP key tests
(`typed_keys_test.dart`). They protect nothing; the secret key's passphrase
is `demo-gpg-pass`.

| File | Key | What it tests |
| --- | --- | --- |
| `gpg_ed25519.pub.asc`, `gpg_ed25519.priv.asc` | Ed25519 with a Curve25519 subkey, expiring after one year | its user id self-signature has an `r` of 248 bits (a leading zero byte), which `dart_pg` 2.1's verifying reader refuses |
| `gpg_rsa1024.pub.asc`, `gpg_rsa1024.priv.asc` | RSA 1024 with an RSA 1024 subkey and two user ids, the older one set primary, expiring after one year | a key `dart_pg` 2.1's decoder refuses, read by `pgp_raw.dart`: GnuPG's fingerprint, the primary user id first, the expiry, flagged short; the public key derived from the secret key equals GnuPG's export |
| `gpg_rsa3072.pub.asc` | RSA 3072 with an RSA subkey and two user ids, none flagged primary, expiring after two years | the expiry from the latest user id self-signature, counted from the key's creation; the user ids in GnuPG's order |

The values the tests expect are those `gpg --list-keys --with-colons`
printed for them.
