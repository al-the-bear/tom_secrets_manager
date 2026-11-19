# Bitwarden fixtures (synthetic)

Demo data only: no item, password or key here is real. The layout follows
Bitwarden's JSON export (part-password-manager).

- `export.json`: the unencrypted export, two folders (`Work`,
  `Work/Servers`) and seven items: a login with two URIs, a TOTP, text,
  hidden, boolean and linked custom fields, password history and the
  favourite flag; a secure note; a card; an identity; an SSH key (the
  demo key `demo_ssh_ed25519`, made for these tests); a trashed login; and a
  login with a passkey.
- `export_encrypted.json`: the same export, password-protected
  (`demo-export-password`, PBKDF2-SHA256 with 5000 iterations).

`python3 generate.py` writes both again, the same bytes each time. It
encrypts with an implementation of its own (Python's `hashlib` and `hmac`,
the `openssl` command for AES-256-CBC), so the Dart reader is checked
against a second writer. The Argon2id case is written by the Dart test
itself.
