// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The password generator of the entry editor (part-app): random passwords
/// from chosen character classes, drawn with a cryptographically secure
/// random source.
library;

import 'dart:math';

/// The character classes a generated password draws from.
enum TomSecretsCharacterClass {
  /// `a`–`z`.
  lower('abcdefghijklmnopqrstuvwxyz'),

  /// `A`–`Z`.
  upper('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),

  /// `0`–`9`.
  digits('0123456789'),

  /// The printable ASCII symbols.
  symbols(
    r'!"#$%&'
    "'"
    r'()*+,-./:;<=>?@[\]^_`{|}~',
  );

  const TomSecretsCharacterClass(this.characters);

  /// Its characters.
  final String characters;
}

/// The characters [TomSecretsPasswordPolicy.excludeAmbiguous] leaves out,
/// because they are easily confused when read or typed.
const String tomSecretsAmbiguousCharacters = 'Il1O0|`\'"';

/// What a generated password is made of.
final class TomSecretsPasswordPolicy {
  /// A password of [length] characters from [classes], each class present at
  /// least once; [excludeAmbiguous] leaves out
  /// [tomSecretsAmbiguousCharacters]. Throws [ArgumentError] for no class or
  /// a length shorter than the number of classes or longer than 1024.
  TomSecretsPasswordPolicy({
    this.length = 20,
    Set<TomSecretsCharacterClass> classes = const {
      TomSecretsCharacterClass.lower,
      TomSecretsCharacterClass.upper,
      TomSecretsCharacterClass.digits,
      TomSecretsCharacterClass.symbols,
    },
    this.excludeAmbiguous = false,
  }) : classes = Set.unmodifiable(classes) {
    if (classes.isEmpty) {
      throw ArgumentError.value(classes, 'classes', 'name at least one class');
    }
    if (length < classes.length || length > 1024) {
      throw ArgumentError.value(
        length,
        'length',
        'between ${classes.length} and 1024',
      );
    }
  }

  /// The number of characters.
  final int length;

  /// The classes drawn from, each at least once.
  final Set<TomSecretsCharacterClass> classes;

  /// Whether [tomSecretsAmbiguousCharacters] are left out.
  final bool excludeAmbiguous;

  /// The characters of [cls] under this policy.
  String charactersOf(TomSecretsCharacterClass cls) => excludeAmbiguous
      ? cls.characters
            .split('')
            .where((c) => !tomSecretsAmbiguousCharacters.contains(c))
            .join()
      : cls.characters;

  /// Every character a password may hold, in class order.
  String get alphabet => [
    for (final cls in TomSecretsCharacterClass.values)
      if (classes.contains(cls)) charactersOf(cls),
  ].join();

  /// The password's strength in bits, as if every character were drawn from
  /// [alphabet] alone (the guarantee of one per class takes off a fraction of
  /// a bit, which this leaves out).
  double get entropyBits => length * log(alphabet.length) / ln2;

  /// The policy with the given parts changed.
  TomSecretsPasswordPolicy copyWith({
    int? length,
    Set<TomSecretsCharacterClass>? classes,
    bool? excludeAmbiguous,
  }) => TomSecretsPasswordPolicy(
    length: length ?? this.length,
    classes: classes ?? this.classes,
    excludeAmbiguous: excludeAmbiguous ?? this.excludeAmbiguous,
  );
}

/// Generates passwords under a [TomSecretsPasswordPolicy].
final class TomSecretsPasswordGenerator {
  /// A generator drawing from [random], by default [Random.secure] (a test
  /// passes a seeded one).
  TomSecretsPasswordGenerator({Random? random})
    : _random = random ?? Random.secure();

  final Random _random;

  /// A new password: one character of every class of [policy], the rest from
  /// its whole alphabet, the order shuffled.
  String generate([TomSecretsPasswordPolicy? policy]) {
    final p = policy ?? TomSecretsPasswordPolicy();
    final alphabet = p.alphabet;
    final chars = <String>[
      for (final cls in TomSecretsCharacterClass.values)
        if (p.classes.contains(cls)) _pick(p.charactersOf(cls)),
    ];
    while (chars.length < p.length) {
      chars.add(_pick(alphabet));
    }
    // Fisher-Yates, so the guaranteed characters sit anywhere.
    for (var i = chars.length - 1; i > 0; i--) {
      final j = _random.nextInt(i + 1);
      final t = chars[i];
      chars[i] = chars[j];
      chars[j] = t;
    }
    return chars.join();
  }

  String _pick(String from) => from[_random.nextInt(from.length)];
}
