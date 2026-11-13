# 1Password fixtures (synthetic)

Demo data only: no item, password, token or key here is real. The layout
follows 1Password 8's export formats (part-password-manager, DP-36); a real
export is checked against it before the user's own import.

- `1pux_v3/` is a 1PUX export (`export.attributes` version 3) unpacked:
  `export.data` (accounts, then vaults, then items), `export.attributes`, and
  `files/<documentId>__<file name>`. The tests zip it in memory, as 1Password
  writes it. Its two vaults, `Personal` and `@Shared`, hold one item of every
  case the importer handles: a login with extra form fields, sections, a TOTP,
  password history and two URLs; a password with a bare TOTP secret; a secure
  note; an API credential; a server; a credit card; an identity; an SSH key; a
  document; a login with a file field; an archived login; a login with a
  passkey; and two logins with the same title.
- `csv/export.csv` is a CSV export with a quoted multi-line note, a row
  without login data and an archived row.

Each new format version 1Password writes gets a folder of its own here.
