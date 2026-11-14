// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The entry editor's password generator (part-app): the length and classes
/// a policy names, every class present, ambiguous characters left out on
/// request, the strength in bits, and its refusals.
library;

import 'dart:math';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

void main() {
  final generator = TomSecretsPasswordGenerator(random: Random(42));

  test('the default: 20 characters of all four classes, each present', () {
    for (var i = 0; i < 200; i++) {
      final password = generator.generate();
      expect(password, hasLength(20));
      for (final cls in TomSecretsCharacterClass.values) {
        expect(
          password.split('').any(cls.characters.contains),
          isTrue,
          reason: '$cls in $password',
        );
      }
    }
  });

  test('only the classes named, at the length named', () {
    final policy = TomSecretsPasswordPolicy(
      length: 32,
      classes: {TomSecretsCharacterClass.digits},
    );
    final password = generator.generate(policy);
    expect(password, matches(RegExp(r'^[0-9]{32}$')));
    expect(policy.alphabet, '0123456789');
  });

  test('ambiguous characters are left out on request', () {
    final policy = TomSecretsPasswordPolicy(
      length: 512,
      excludeAmbiguous: true,
    );
    final password = generator.generate(policy);
    for (final c in tomSecretsAmbiguousCharacters.split('')) {
      expect(password, isNot(contains(c)));
      expect(policy.alphabet, isNot(contains(c)));
    }
  });

  test('every character of the alphabet is drawn, none outside it', () {
    final policy = TomSecretsPasswordPolicy(length: 1024);
    final seen = <String>{};
    for (var i = 0; i < 20; i++) {
      seen.addAll(generator.generate(policy).split(''));
    }
    expect(seen, policy.alphabet.split('').toSet());
  });

  test('the strength in bits', () {
    final policy = TomSecretsPasswordPolicy();
    expect(policy.alphabet, hasLength(26 + 26 + 10 + 32));
    expect(policy.entropyBits, closeTo(20 * log(94) / ln2, 1e-9));
    expect(
      policy.copyWith(length: 40).entropyBits,
      closeTo(2 * policy.entropyBits, 1e-9),
    );
  });

  test('no class, too short for its classes, or too long: refused', () {
    expect(() => TomSecretsPasswordPolicy(classes: {}), throwsArgumentError);
    expect(() => TomSecretsPasswordPolicy(length: 3), throwsArgumentError);
    expect(() => TomSecretsPasswordPolicy(length: 1025), throwsArgumentError);
  });

  test('two generators without a seed differ (Random.secure)', () {
    expect(
      TomSecretsPasswordGenerator().generate(),
      isNot(TomSecretsPasswordGenerator().generate()),
    );
  });
}
