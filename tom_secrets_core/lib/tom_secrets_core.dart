// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The core of the Tom Secrets Manager: stores over KDBX files, the metadata
/// entry and the shared configuration, dimensions, overlays and resolution
/// (part-structure). The reference grammar is `tom_secrets_client`'s.
library;

export 'src/approval_code.dart';
export 'src/approval_link.dart';
export 'src/bcrypt_pbkdf.dart';
export 'src/compaction.dart';
export 'src/config.dart';
export 'src/device_records.dart';
export 'src/device_settings.dart';
export 'src/export_enpass.dart';
export 'src/first_run.dart';
export 'src/github_token.dart';
export 'src/grants.dart';
export 'src/history.dart';
export 'src/import.dart';
export 'src/import_1password.dart';
export 'src/import_enpass.dart';
export 'src/key_file.dart';
export 'src/locator.dart';
export 'src/mapping.dart';
export 'src/metadata.dart';
export 'src/new_vault.dart';
export 'src/offline_cache.dart';
export 'src/outer.dart';
export 'src/pairing.dart';
export 'src/pairing_setup.dart';
export 'src/pairing_words.dart';
export 'src/passkey.dart';
export 'src/password_generator.dart';
export 'src/primary.dart';
export 'src/resolution.dart';
export 'src/signed_objects.dart';
export 'src/ssh_agent.dart';
export 'src/ssh_key.dart';
export 'src/ssh_private_key.dart';
export 'src/store.dart';
export 'src/stored_vault.dart';
export 'src/totp.dart';
export 'src/trust.dart';
export 'src/url_match.dart';
export 'src/vault_merge.dart';
export 'src/vault_sync.dart';

// The KDBX types the product's other packages handle (credentials, protected
// values, an opened file), re-exported: only this package declares
// tom_kdbx_store (DP-29), so the service and the apps reach KDBX through it.
export 'package:tom_kdbx_store/tom_kdbx_store.dart'
    show
        Credentials,
        KdbxEntry,
        KdbxFile,
        KdbxFormat,
        KdbxFormatException,
        KdbxGroup,
        KdbxInvalidKeyException,
        KdbxKey,
        KdbxKeyCommon,
        KdbxUuid,
        PlainValue,
        ProtectedValue,
        StringValue;
