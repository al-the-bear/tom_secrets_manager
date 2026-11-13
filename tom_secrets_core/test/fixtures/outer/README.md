# `.tsmx` fixtures

Two files written by `tomSecretsOuterEncrypt` in format version 1, one per
cipher: the content `fixed content` (UTF-8), the path
`vaults/fixed.kdbx.tsmx`, one slot under the demo repository key of the 32
bytes 0, 1, ..., 31, and the deterministic generator of
`test/protection_test.dart` (byte i = (37 i + 11) mod 256) for the file key and
the nonces. `protection_test.dart` reads them, so every later version keeps
opening phase-A files, and pins their SHA-256, so the writer cannot drift. They
were also decrypted by a separate Go reader written from the layout in
`lib/src/outer.dart` alone (Go's AES-GCM, `golang.org/x/crypto`'s
XChaCha20-Poly1305) before they were committed. Demo data under a demo key.
