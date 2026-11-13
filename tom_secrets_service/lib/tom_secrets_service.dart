// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The Tom Secrets Manager's secrets service (part-service, part-protocol):
/// the runtime directory, the client and admin endpoints, the admin
/// challenge and claim, the vaults while unlocked, the device settings
/// container with its key modes, the lock policy; and for its starters the
/// handover, the start and the admin client.
library;

export 'src/access.dart';
export 'src/admin_auth.dart';
export 'src/admin_client.dart';
export 'src/bootstrap.dart';
export 'src/connection.dart';
export 'src/lock_policy.dart';
export 'src/runtime.dart';
export 'src/service.dart';
export 'src/starter.dart';
export 'src/vault_set.dart';

// The device settings and lock types the service's API hands out; they live
// in tom_secrets_core, which alone reaches KDBX (DP-29).
export 'package:tom_secrets_core/tom_secrets_core.dart'
    show
        TomSecretsDeviceContainer,
        TomSecretsDeviceKeyException,
        TomSecretsDeviceKeyMode,
        TomSecretsDeviceKeys,
        TomSecretsDeviceSettings,
        TomSecretsLockMode,
        TomSecretsLockPolicy;
