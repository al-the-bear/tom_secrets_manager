# Enpass fixtures (synthetic)

Demo data only: no item, password or key here is real. The layout follows
Enpass 6's JSON and CSV exports (part-password-manager, DP-36, DP-120); a real
export is checked against it before the user's own import, and the shape of
an Enpass passkey in particular is an assumption until then.

- `json/export.json`, written by `generate_json.py`: three folders (`Work`,
  `Work/Servers`, `Personal`) and fifteen items: a login in two folders with
  a second e-mail, a second password, two URLs, a TOTP, a PIN, a section, a
  deleted and an empty field, password history and the favourite flag; a
  password; a note; a computer; a credit card; an identity; an archived and a
  trashed login; a login with an attachment; and six logins with passkeys.
  Five carry a private key, in a different shape each: PKCS#8 base64 DER, a
  P-256 JWK, a SEC1 PEM, a raw base64 P-256 scalar (with no relying party, so
  it is taken from the URL), and an Ed25519 JWK. The sixth has no private key.
- `json/passkey_public_keys.json`: the public points of the four P-256 keys,
  so the tests check that each converted key signs what its public key
  verifies.
- `csv/export.csv`: a header row, a login with label and value pairs and a
  quoted multi-line note, a note-only row, and a login with an e-mail.

The passkey keys are derived from public seeds (`tsm demo passkey N`), so
`python3 generate_json.py` writes the same files again. Each new format
version Enpass writes gets a fixture of its own here.
