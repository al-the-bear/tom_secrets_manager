# Changelog

## 0.1.0

- Stores over KDBX files with their index (logical paths, bindings, keys),
  overlays in both placements, the metadata entry and `tsm.config`, dimensions
  with priority, configured defaults and `fallback_to_default`, resolution
  with its rank vectors, ambiguity and fields (string fields, attachments,
  `totp`, refused passkey fields), the KDBX mapping and TOTP (RFC 6238, the
  three conventions).
