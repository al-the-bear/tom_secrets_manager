# Changelog

## 0.1.0

- The `age` v1 format (hybrid `mlkem768x25519`, classical `X25519`,
  passphrase `scrypt`, the armour), the member keys and HKDF-SHA-256, taken
  out of `tom_secrets_core` so a program can use them without the vault
  format (the relay server's recipient proof).
