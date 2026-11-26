// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The quick unlock (part-app, Unlocking; protocol.md 6.4): after an unlock
/// with the master password the primary's keys are kept sealed in this
/// process's memory, so a PIN or the platform's biometric undoes a later
/// idle or screen lock without the master password.
///
/// - **What seals them:** AES-256-GCM, under a key from Argon2id over the
///   PIN with a 32-byte random secret as the salt (the PIN slot), or under a
///   key from HKDF over a 32-byte random token the app keeps behind the
///   biometric (the token slot). The secret exists only in this object: a
///   copy of the disk holds nothing to guess the PIN from.
/// - **What ends them:** 5 wrong PINs, "Lock completely", a re-keyed
///   primary (the keys sealed no longer match the ones held), the age limit
///   (7 days after the last unlock with the master password), and the end of
///   the process.
/// - **What it is not:** a way in after a restart. The keys are never
///   written anywhere; only the switch "quick unlock with a PIN is on" is in
///   the device settings.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

/// The fewest characters a PIN has (letters allowed).
const int tomSecretsPinMinLength = 6;

/// The wrong PINs after which the sealed keys are wiped.
const int tomSecretsPinAttempts = 5;

/// How long after the last unlock with the master password the quick
/// unlock lasts.
const Duration tomSecretsQuickUnlockAge = Duration(days: 7);

/// Why a quick unlock did not open the keys.
enum TomSecretsQuickRefusal {
  /// Nothing is sealed for that way (none set, or ended).
  none('no_quick_unlock'),

  /// The age limit passed: the keys were wiped.
  expired('quick_expired'),

  /// A wrong PIN; attempts are left.
  badPin('bad_pin'),

  /// The last attempt was wrong: the keys were wiped.
  wiped('pin_wiped'),

  /// The token does not open its slot.
  badToken('bad_token');

  const TomSecretsQuickRefusal(this.reason);

  /// The `details.reason` of the `denied` answer.
  final String reason;
}

/// A quick unlock that did not open the keys.
final class TomSecretsQuickUnlockException implements Exception {
  /// A refusal for [refusal], with [attemptsLeft] PINs left.
  const TomSecretsQuickUnlockException(this.refusal, {this.attemptsLeft});

  /// Why.
  final TomSecretsQuickRefusal refusal;

  /// The wrong PINs still allowed (a wrong PIN), or null.
  final int? attemptsLeft;

  @override
  String toString() => 'TomSecretsQuickUnlockException(${refusal.reason})';
}

/// The Argon2id parameters of the PIN slot (tests take smaller ones).
final class TomSecretsPinKdf {
  /// [memoryKiB] of memory, [iterations] passes, [parallelism] lanes.
  const TomSecretsPinKdf({
    this.memoryKiB = 64 * 1024,
    this.iterations = 2,
    this.parallelism = 1,
  });

  /// Memory in KiB.
  final int memoryKiB;

  /// Passes.
  final int iterations;

  /// Lanes.
  final int parallelism;
}

final class _Slot {
  _Slot(this.nonce, this.sealed);

  final List<int> nonce;
  final List<int> sealed;
}

/// The sealed keys of the primary in memory, opened by a PIN or a token.
final class TomSecretsQuickUnlock {
  /// A quick unlock with [kdf] for the PIN, [now] as the clock and [age]
  /// as the limit after the last master-password unlock.
  TomSecretsQuickUnlock({
    this.kdf = const TomSecretsPinKdf(),
    DateTime Function()? now,
    this.age = tomSecretsQuickUnlockAge,
    Random? random,
  }) : _now = now ?? DateTime.now,
       _random = random ?? Random.secure() {
    _secret = _bytes(32);
  }

  /// The PIN slot's key derivation.
  final TomSecretsPinKdf kdf;

  /// The limit after the last master-password unlock.
  final Duration age;

  final DateTime Function() _now;
  final Random _random;
  late final Uint8List _secret;
  final AesGcm _aes = AesGcm.with256bits();

  _Slot? _pin;
  _Slot? _token;
  int _attemptsLeft = tomSecretsPinAttempts;
  DateTime? _passwordUnlockAt;
  List<int>? _keysHash;

  Uint8List _bytes(int n) =>
      Uint8List.fromList(List<int>.generate(n, (_) => _random.nextInt(256)));

  /// Whether a PIN opens the keys now.
  bool get pinArmed {
    _expireIfDue();
    return _pin != null;
  }

  /// Whether a token opens the keys now.
  bool get tokenArmed {
    _expireIfDue();
    return _token != null;
  }

  /// The wrong PINs still allowed.
  int get attemptsLeft => _attemptsLeft;

  /// When the quick unlock ends (the age limit), or null with nothing
  /// sealed.
  DateTime? get until {
    _expireIfDue();
    final at = _passwordUnlockAt;
    if (at == null || (_pin == null && _token == null)) return null;
    return at.add(age);
  }

  /// When the service was last unlocked with the master password, or null.
  DateTime? get passwordUnlockAt => _passwordUnlockAt;

  void _expireIfDue() {
    final at = _passwordUnlockAt;
    if (at == null || (_pin == null && _token == null)) return;
    if (!_now().isBefore(at.add(age))) wipe();
  }

  /// The service was unlocked with the master password (or the saved one,
  /// "Remember the master password") and holds [keys] (the primary's keys,
  /// encoded): the age limit counts from now. Sealed keys that no longer
  /// match (the vault was re-keyed) are wiped.
  void passwordUnlocked(List<int> keys) {
    _passwordUnlockAt = _now();
    _expired = false;
    if (!matches(keys)) wipe();
  }

  /// Whether the keys sealed are [keys] (nothing sealed: true).
  bool matches(List<int> keys) {
    final hash = _keysHash;
    if (hash == null) return true;
    final now = crypto.sha256.convert([..._secret, ...keys]).bytes;
    var same = hash.length == now.length;
    for (var i = 0; i < now.length && same; i++) {
      same = hash[i] == now[i];
    }
    return same;
  }

  /// Seals [keys] under [pin] (replacing a PIN set before); the token slot,
  /// when there is one, keeps the same keys. Throws [ArgumentError] for a
  /// PIN of fewer than [tomSecretsPinMinLength] characters and [StateError]
  /// before a master-password unlock.
  Future<void> setPin(String pin, List<int> keys) async {
    if (pin.runes.length < tomSecretsPinMinLength) {
      throw ArgumentError(
        'a PIN has at least $tomSecretsPinMinLength characters',
      );
    }
    _requirePasswordUnlock();
    _rebase(keys);
    _pin = await _seal(await _pinKey(pin), keys);
    _attemptsLeft = tomSecretsPinAttempts;
  }

  /// Seals [keys] under a new random token and answers the token (the app
  /// keeps it behind the biometric; the caller wipes it).
  Future<Uint8List> newToken(List<int> keys) async {
    _requirePasswordUnlock();
    _rebase(keys);
    final token = _bytes(32);
    _token = await _seal(await _tokenKey(token), keys);
    return token;
  }

  void _requirePasswordUnlock() {
    if (_passwordUnlockAt == null) {
      throw StateError('no unlock with the master password yet');
    }
    _expireIfDue();
    if (!_now().isBefore(_passwordUnlockAt!.add(age))) {
      throw StateError('the last unlock with the master password is too old');
    }
  }

  /// Other keys than the ones sealed: the old slots go.
  void _rebase(List<int> keys) {
    if (!matches(keys)) {
      _pin = null;
      _token = null;
    }
    _keysHash = crypto.sha256.convert([..._secret, ...keys]).bytes;
  }

  /// The keys [pin] opens (the caller wipes them). A wrong PIN counts; the
  /// last allowed one wipes everything sealed.
  Future<Uint8List> openWithPin(String pin) async {
    _expireIfDue();
    final slot = _pin;
    if (slot == null) throw _refusal();
    final keys = await _open(await _pinKey(pin), slot);
    if (keys != null) {
      _attemptsLeft = tomSecretsPinAttempts;
      return keys;
    }
    _attemptsLeft--;
    if (_attemptsLeft <= 0) {
      wipe();
      throw const TomSecretsQuickUnlockException(
        TomSecretsQuickRefusal.wiped,
        attemptsLeft: 0,
      );
    }
    throw TomSecretsQuickUnlockException(
      TomSecretsQuickRefusal.badPin,
      attemptsLeft: _attemptsLeft,
    );
  }

  /// The keys [token] opens (the caller wipes them).
  Future<Uint8List> openWithToken(List<int> token) async {
    _expireIfDue();
    final slot = _token;
    if (slot == null) throw _refusal();
    final keys = await _open(await _tokenKey(token), slot);
    if (keys == null) {
      throw const TomSecretsQuickUnlockException(
        TomSecretsQuickRefusal.badToken,
      );
    }
    return keys;
  }

  TomSecretsQuickUnlockException _refusal() => TomSecretsQuickUnlockException(
    _expired ? TomSecretsQuickRefusal.expired : TomSecretsQuickRefusal.none,
  );

  bool _expired = false;

  /// Forgets the PIN slot (the PIN removed); the token slot stays.
  void removePin() {
    _pin = null;
    _attemptsLeft = tomSecretsPinAttempts;
    _forgetHashIfEmpty();
  }

  /// Forgets the token slot (the biometric turned off).
  void removeToken() {
    _token = null;
    _forgetHashIfEmpty();
  }

  void _forgetHashIfEmpty() {
    if (_pin == null && _token == null) _keysHash = null;
  }

  /// Wipes everything sealed ("Lock completely", 5 wrong PINs, the age
  /// limit, a re-keyed primary).
  void wipe() {
    _expired =
        _passwordUnlockAt != null &&
        !_now().isBefore(_passwordUnlockAt!.add(age));
    _pin = null;
    _token = null;
    _keysHash = null;
    _attemptsLeft = tomSecretsPinAttempts;
  }

  /// The state for `status` (protocol.md 6.4): never a key or a PIN.
  Map<String, Object?> toStatus({required bool pinOn}) => {
    'pin': pinOn,
    'pinArmed': pinArmed,
    'token': tokenArmed,
    'attemptsLeft': _attemptsLeft,
    'until': ?until?.toUtc().toIso8601String(),
  };

  Future<SecretKey> _pinKey(String pin) => Argon2id(
    parallelism: kdf.parallelism,
    memory: kdf.memoryKiB,
    iterations: kdf.iterations,
    hashLength: 32,
  ).deriveKey(secretKey: SecretKey(utf8.encode(pin)), nonce: _secret);

  Future<SecretKey> _tokenKey(List<int> token) =>
      Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: SecretKey(token),
        nonce: _secret,
        info: utf8.encode('tsm-quick-token-v1'),
      );

  Future<_Slot> _seal(SecretKey key, List<int> keys) async {
    final nonce = _bytes(12);
    final box = await _aes.encrypt(keys, secretKey: key, nonce: nonce);
    return _Slot(nonce, [...box.cipherText, ...box.mac.bytes]);
  }

  Future<Uint8List?> _open(SecretKey key, _Slot slot) async {
    const tag = 16;
    try {
      final plain = await _aes.decrypt(
        SecretBox(
          slot.sealed.sublist(0, slot.sealed.length - tag),
          nonce: slot.nonce,
          mac: Mac(slot.sealed.sublist(slot.sealed.length - tag)),
        ),
        secretKey: key,
      );
      return Uint8List.fromList(plain);
    } on SecretBoxAuthenticationError {
      return null;
    }
  }
}
