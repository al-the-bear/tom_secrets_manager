// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Where the service keeps the secret half of its identity key
/// (protocol.md 6.1), per platform, without an administrator:
///
/// - **macOS:** a generic-password item of the login keychain, made by the
///   service process itself (`SecItemAdd`), so its access list trusts the
///   service's code signature alone: another program asking for it gets the
///   system's prompt. An ad-hoc signed build changes its signature with
///   every build, so an update asks once.
/// - **Windows:** DPAPI (`CryptProtectData`, the user's scope): the file
///   holds the protected blob, which only this user's logon opens. It is per
///   user, not per process.
/// - **Linux:** none: the file itself (0600 in a 0700 folder). A system
///   install (`tsm install --system`) keeps it in a directory only the
///   installed service reaches (system_mode.dart).
///
/// A store that cannot take the key now (a locked keychain in an SSH
/// session, a logon without the user's credentials) leaves it in the file;
/// the service moves it at a later start.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:ffi/ffi.dart';
import 'package:tom_secrets_client/admin.dart' show tomSecretsKeychainService;
import 'package:tom_secrets_core/tom_secrets_core.dart';

/// The identity key's store of this platform, or null where the file is
/// the store (Linux).
TomSecretsIdentitySecretStore? tomSecretsPlatformIdentityStore() {
  if (Platform.isMacOS) return TomSecretsKeychainIdentityStore();
  if (Platform.isWindows) return const TomSecretsDpapiIdentityStore();
  return null;
}

/// The keychain account of the identity key in [file]: one per key file,
/// so services with other data directories keep their own.
String tomSecretsIdentityKeychainAccount(File file) =>
    'tsm.service-identity.'
    '${crypto.sha256.convert(utf8.encode(file.absolute.path)).toString().substring(0, 16)}';

// ---------------------------------------------------------------- macOS

const int _errSecItemNotFound = -25300;
const int _errSecInteractionNotAllowed = -25308;
const int _errSecUserCanceled = -128;
const int _errSecAuthFailed = -25293;
const int _kCFStringEncodingUTF8 = 0x08000100;

/// The macOS keychain: a generic-password item the service makes itself,
/// so its access list trusts the service's code signature alone.
final class TomSecretsKeychainIdentityStore
    implements TomSecretsIdentitySecretStore {
  /// The store; [keychainPath] is a keychain file other than the login
  /// keychain (tests use a scratch keychain).
  TomSecretsKeychainIdentityStore({this.keychainPath});

  /// A keychain file to keep the item in, or null: the default keychain.
  final String? keychainPath;

  @override
  String get name => 'keychain';

  @override
  Future<Map<String, Object?>> seal(Uint8List secret, File file) async {
    final account = tomSecretsIdentityKeychainAccount(file);
    final mac = _Mac.instance;
    // One item per key file: a rotated key replaces it.
    mac.delete(account, keychainPath);
    final status = mac.add(account, secret, keychainPath);
    if (status != 0) {
      throw TomSecretsIdentityKeyUnavailable(
        'the keychain did not take the identity key (OSStatus $status)',
      );
    }
    return {'service': tomSecretsKeychainService, 'account': account};
  }

  @override
  Future<Uint8List> open(Map<String, Object?> sealed, File file) async {
    final account = sealed['account'];
    if (account is! String) {
      throw const TomSecretsIdentityKeyUnavailable(
        'the identity key file names no keychain item',
      );
    }
    final (status, bytes) = _Mac.instance.read(account, keychainPath);
    if (status == 0 && bytes != null) return bytes;
    throw TomSecretsIdentityKeyUnavailable(switch (status) {
      _errSecItemNotFound =>
        'the keychain item of the identity key is gone ($account)',
      _errSecInteractionNotAllowed =>
        'the keychain is locked, or asks for an approval this session '
            'cannot show (an SSH login): start the service once from the '
            'desktop session, or unlock the keychain',
      _errSecUserCanceled || _errSecAuthFailed =>
        'access to the identity key was refused at the keychain prompt',
      _ => 'the keychain did not give the identity key (OSStatus $status)',
    });
  }

  @override
  Future<void> forget(Map<String, Object?> sealed, File file) async {
    final account = sealed['account'];
    if (account is String) _Mac.instance.delete(account, keychainPath);
  }
}

typedef _CFStringCreateN =
    Pointer<Void> Function(Pointer<Void>, Pointer<Utf8>, Uint32);
typedef _CFStringCreateD =
    Pointer<Void> Function(Pointer<Void>, Pointer<Utf8>, int);
typedef _CFDataCreateN =
    Pointer<Void> Function(Pointer<Void>, Pointer<Uint8>, Long);
typedef _CFDataCreateD =
    Pointer<Void> Function(Pointer<Void>, Pointer<Uint8>, int);
typedef _CFDictionaryCreateN =
    Pointer<Void> Function(
      Pointer<Void>,
      Pointer<Pointer<Void>>,
      Pointer<Pointer<Void>>,
      Long,
      Pointer<Void>,
      Pointer<Void>,
    );
typedef _CFDictionaryCreateD =
    Pointer<Void> Function(
      Pointer<Void>,
      Pointer<Pointer<Void>>,
      Pointer<Pointer<Void>>,
      int,
      Pointer<Void>,
      Pointer<Void>,
    );
typedef _CFArrayCreateN =
    Pointer<Void> Function(
      Pointer<Void>,
      Pointer<Pointer<Void>>,
      Long,
      Pointer<Void>,
    );
typedef _CFArrayCreateD =
    Pointer<Void> Function(
      Pointer<Void>,
      Pointer<Pointer<Void>>,
      int,
      Pointer<Void>,
    );
typedef _SecQueryN = Int32 Function(Pointer<Void>, Pointer<Pointer<Void>>);
typedef _SecQueryD = int Function(Pointer<Void>, Pointer<Pointer<Void>>);
typedef _SecDeleteN = Int32 Function(Pointer<Void>);
typedef _SecDeleteD = int Function(Pointer<Void>);
typedef _SecKeychainOpenN =
    Int32 Function(Pointer<Utf8>, Pointer<Pointer<Void>>);
typedef _SecKeychainOpenD = int Function(Pointer<Utf8>, Pointer<Pointer<Void>>);

/// The few CoreFoundation and Security calls the keychain store makes.
final class _Mac {
  _Mac._()
    : _cf = DynamicLibrary.open(
        '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation',
      ),
      _sec = DynamicLibrary.open(
        '/System/Library/Frameworks/Security.framework/Security',
      );

  static final _Mac instance = _Mac._();

  final DynamicLibrary _cf;
  final DynamicLibrary _sec;

  late final _stringCreate = _cf
      .lookupFunction<_CFStringCreateN, _CFStringCreateD>(
        'CFStringCreateWithCString',
      );
  late final _dataCreate = _cf.lookupFunction<_CFDataCreateN, _CFDataCreateD>(
    'CFDataCreate',
  );
  late final _dictionaryCreate = _cf
      .lookupFunction<_CFDictionaryCreateN, _CFDictionaryCreateD>(
        'CFDictionaryCreate',
      );
  late final _arrayCreate = _cf
      .lookupFunction<_CFArrayCreateN, _CFArrayCreateD>('CFArrayCreate');
  late final _release = _cf
      .lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('CFRelease');
  late final _dataLength = _cf
      .lookupFunction<
        Long Function(Pointer<Void>),
        int Function(Pointer<Void>)
      >('CFDataGetLength');
  late final _dataBytes = _cf
      .lookupFunction<
        Pointer<Uint8> Function(Pointer<Void>),
        Pointer<Uint8> Function(Pointer<Void>)
      >('CFDataGetBytePtr');
  late final _itemAdd = _sec.lookupFunction<_SecQueryN, _SecQueryD>(
    'SecItemAdd',
  );
  late final _itemCopyMatching = _sec.lookupFunction<_SecQueryN, _SecQueryD>(
    'SecItemCopyMatching',
  );
  late final _itemDelete = _sec.lookupFunction<_SecDeleteN, _SecDeleteD>(
    'SecItemDelete',
  );
  late final _keychainOpen = _sec
      .lookupFunction<_SecKeychainOpenN, _SecKeychainOpenD>('SecKeychainOpen');

  Pointer<Void> _constant(DynamicLibrary lib, String name) =>
      lib.lookup<Pointer<Void>>(name).value;

  Pointer<Void> _string(String text, List<Pointer<Void>> owned) {
    final c = text.toNativeUtf8();
    try {
      final s = _stringCreate(nullptr, c, _kCFStringEncodingUTF8);
      owned.add(s);
      return s;
    } finally {
      calloc.free(c);
    }
  }

  /// A query for the item of [account], with [extra] entries; every object
  /// it made is in [owned], released by the caller.
  Pointer<Void> _query(
    String account,
    String? keychainPath,
    List<Pointer<Void>> owned, {
    Map<Pointer<Void>, Pointer<Void>> extra = const {},
    bool forAdd = false,
  }) {
    final entries = <Pointer<Void>, Pointer<Void>>{
      _constant(_sec, 'kSecClass'): _constant(_sec, 'kSecClassGenericPassword'),
      _constant(_sec, 'kSecAttrService'): _string(
        tomSecretsKeychainService,
        owned,
      ),
      _constant(_sec, 'kSecAttrAccount'): _string(account, owned),
      ...extra,
    };
    if (keychainPath != null) {
      final ref = calloc<Pointer<Void>>();
      final path = keychainPath.toNativeUtf8();
      try {
        if (_keychainOpen(path, ref) == 0) {
          owned.add(ref.value);
          if (forAdd) {
            entries[_constant(_sec, 'kSecUseKeychain')] = ref.value;
          } else {
            final list = calloc<Pointer<Void>>()..value = ref.value;
            final array = _arrayCreate(
              nullptr,
              list,
              1,
              _cf.lookup<Void>('kCFTypeArrayCallBacks'),
            );
            calloc.free(list);
            owned.add(array);
            entries[_constant(_sec, 'kSecMatchSearchList')] = array;
          }
        }
      } finally {
        calloc
          ..free(ref)
          ..free(path);
      }
    }
    final keys = calloc<Pointer<Void>>(entries.length);
    final values = calloc<Pointer<Void>>(entries.length);
    try {
      var i = 0;
      for (final MapEntry(:key, :value) in entries.entries) {
        keys[i] = key;
        values[i] = value;
        i++;
      }
      final dictionary = _dictionaryCreate(
        nullptr,
        keys,
        values,
        entries.length,
        _cf.lookup<Void>('kCFTypeDictionaryKeyCallBacks'),
        _cf.lookup<Void>('kCFTypeDictionaryValueCallBacks'),
      );
      owned.add(dictionary);
      return dictionary;
    } finally {
      calloc
        ..free(keys)
        ..free(values);
    }
  }

  void _releaseAll(List<Pointer<Void>> owned) {
    for (final o in owned.reversed) {
      if (o != nullptr) _release(o);
    }
  }

  int add(String account, Uint8List secret, String? keychainPath) {
    final owned = <Pointer<Void>>[];
    final bytes = calloc<Uint8>(secret.length);
    try {
      bytes.asTypedList(secret.length).setAll(0, secret);
      final data = _dataCreate(nullptr, bytes, secret.length);
      owned.add(data);
      final label = _string('Tom Secrets Manager service identity', owned);
      final query = _query(
        account,
        keychainPath,
        owned,
        forAdd: true,
        extra: {
          _constant(_sec, 'kSecValueData'): data,
          _constant(_sec, 'kSecAttrLabel'): label,
        },
      );
      return _itemAdd(query, nullptr);
    } finally {
      bytes.asTypedList(secret.length).fillRange(0, secret.length, 0);
      calloc.free(bytes);
      _releaseAll(owned);
    }
  }

  (int, Uint8List?) read(String account, String? keychainPath) {
    final owned = <Pointer<Void>>[];
    final result = calloc<Pointer<Void>>();
    try {
      final query = _query(
        account,
        keychainPath,
        owned,
        extra: {
          _constant(_sec, 'kSecReturnData'): _constant(_cf, 'kCFBooleanTrue'),
          _constant(_sec, 'kSecMatchLimit'): _constant(
            _sec,
            'kSecMatchLimitOne',
          ),
        },
      );
      final status = _itemCopyMatching(query, result);
      if (status != 0 || result.value == nullptr) return (status, null);
      final data = result.value;
      owned.add(data);
      final length = _dataLength(data);
      return (0, Uint8List.fromList(_dataBytes(data).asTypedList(length)));
    } finally {
      calloc.free(result);
      _releaseAll(owned);
    }
  }

  int delete(String account, String? keychainPath) {
    final owned = <Pointer<Void>>[];
    try {
      return _itemDelete(_query(account, keychainPath, owned));
    } finally {
      _releaseAll(owned);
    }
  }
}

// ---------------------------------------------------------------- Windows

const int _cryptProtectUiForbidden = 0x1;

/// The identity's DPAPI entropy: a blob made for anything else does not
/// open as an identity key.
final Uint8List _dpapiEntropy = Uint8List.fromList(
  utf8.encode('tsm-service-identity-v1'),
);

/// DPAPI's data blob.
final class _Blob extends Struct {
  @Uint32()
  external int cbData;

  external Pointer<Uint8> pbData;
}

typedef _ProtectN =
    Int32 Function(
      Pointer<_Blob>,
      Pointer<Utf16>,
      Pointer<_Blob>,
      Pointer<Void>,
      Pointer<Void>,
      Uint32,
      Pointer<_Blob>,
    );
typedef _ProtectD =
    int Function(
      Pointer<_Blob>,
      Pointer<Utf16>,
      Pointer<_Blob>,
      Pointer<Void>,
      Pointer<Void>,
      int,
      Pointer<_Blob>,
    );
typedef _UnprotectN =
    Int32 Function(
      Pointer<_Blob>,
      Pointer<Pointer<Utf16>>,
      Pointer<_Blob>,
      Pointer<Void>,
      Pointer<Void>,
      Uint32,
      Pointer<_Blob>,
    );
typedef _UnprotectD =
    int Function(
      Pointer<_Blob>,
      Pointer<Pointer<Utf16>>,
      Pointer<_Blob>,
      Pointer<Void>,
      Pointer<Void>,
      int,
      Pointer<_Blob>,
    );

/// Windows' DPAPI in the user's scope: the file holds the protected blob.
final class TomSecretsDpapiIdentityStore
    implements TomSecretsIdentitySecretStore {
  /// The store.
  const TomSecretsDpapiIdentityStore();

  @override
  String get name => 'dpapi';

  static DynamicLibrary get _crypt32 => DynamicLibrary.open('crypt32.dll');

  static Pointer<Void> Function(Pointer<Void>) get _localFree =>
      DynamicLibrary.open('kernel32.dll').lookupFunction<
        Pointer<Void> Function(Pointer<Void>),
        Pointer<Void> Function(Pointer<Void>)
      >('LocalFree');

  /// [bytes] through DPAPI: protected with [protect], else opened. Null
  /// when DPAPI refuses.
  static Uint8List? _run(Uint8List bytes, {required bool protect}) {
    final input = calloc<_Blob>();
    final entropy = calloc<_Blob>();
    final output = calloc<_Blob>();
    final data = calloc<Uint8>(bytes.length);
    final salt = calloc<Uint8>(_dpapiEntropy.length);
    try {
      data.asTypedList(bytes.length).setAll(0, bytes);
      salt.asTypedList(_dpapiEntropy.length).setAll(0, _dpapiEntropy);
      input.ref
        ..cbData = bytes.length
        ..pbData = data;
      entropy.ref
        ..cbData = _dpapiEntropy.length
        ..pbData = salt;
      final ok = protect
          ? _crypt32.lookupFunction<_ProtectN, _ProtectD>('CryptProtectData')(
              input,
              nullptr,
              entropy,
              nullptr,
              nullptr,
              _cryptProtectUiForbidden,
              output,
            )
          : _crypt32.lookupFunction<_UnprotectN, _UnprotectD>(
              'CryptUnprotectData',
            )(
              input,
              nullptr,
              entropy,
              nullptr,
              nullptr,
              _cryptProtectUiForbidden,
              output,
            );
      if (ok == 0 || output.ref.pbData == nullptr) return null;
      final result = Uint8List.fromList(
        output.ref.pbData.asTypedList(output.ref.cbData),
      );
      output.ref.pbData
          .asTypedList(output.ref.cbData)
          .fillRange(0, output.ref.cbData, 0);
      _localFree(output.ref.pbData.cast());
      return result;
    } finally {
      data.asTypedList(bytes.length).fillRange(0, bytes.length, 0);
      calloc
        ..free(input)
        ..free(entropy)
        ..free(output)
        ..free(data)
        ..free(salt);
    }
  }

  @override
  Future<Map<String, Object?>> seal(Uint8List secret, File file) async {
    final blob = _run(secret, protect: true);
    if (blob == null) {
      throw const TomSecretsIdentityKeyUnavailable(
        'DPAPI did not protect the identity key (a logon without the '
        'user\'s credentials, such as a key-based SSH session)',
      );
    }
    return {'blob': base64.encode(blob)};
  }

  @override
  Future<Uint8List> open(Map<String, Object?> sealed, File file) async {
    final blob = sealed['blob'];
    final secret = blob is String
        ? _run(base64.decode(blob), protect: false)
        : null;
    if (secret == null) {
      throw const TomSecretsIdentityKeyUnavailable(
        'DPAPI did not open the identity key: another user\'s, or a logon '
        'without the user\'s credentials (a key-based SSH session)',
      );
    }
    return secret;
  }

  @override
  Future<void> forget(Map<String, Object?> sealed, File file) async {}
}
