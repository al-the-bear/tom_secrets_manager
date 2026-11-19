// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Auto-type's OS-independent half (part-password-manager, DP-41): KeePass's
/// sequence syntax parsed into actions, window title patterns, which sequence
/// an entry types where, which entries fit a window, and the auto-type
/// settings carried by the merge and by a copied entry. Demo data only.
library;

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const _shift = TomSecretsAutoTypeModifier.shift;
const _control = TomSecretsAutoTypeModifier.control;
const _alt = TomSecretsAutoTypeModifier.alt;

TomSecretsAutoTypeKeyPress _key(
  TomSecretsAutoTypeKey key, [
  Set<TomSecretsAutoTypeModifier> modifiers = const {},
]) => TomSecretsAutoTypeKeyPress(key: key, modifiers: modifiers);

TomSecretsAutoTypeKeyPress _char(
  String c, [
  Set<TomSecretsAutoTypeModifier> modifiers = const {},
]) => TomSecretsAutoTypeKeyPress(character: c, modifiers: modifiers);

List<TomSecretsAutoTypeAction> _parse(String sequence) =>
    tomSecretsParseAutoType(
      sequence,
      values: (name) => switch (name.toUpperCase()) {
        'USERNAME' => 'demo-user',
        'PASSWORD' => 'p+w^d{}',
        'S:PIN' => '0000',
        _ => null,
      },
    );

void main() {
  group('the sequence syntax', () {
    test('the default: user name, Tab, password (its + ^ { } typed as '
        'text), Enter', () {
      expect(_parse(tomSecretsDefaultAutoTypeSequence), [
        const TomSecretsAutoTypeText('demo-user'),
        _key(TomSecretsAutoTypeKey.tab),
        const TomSecretsAutoTypeText('p+w^d{}'),
        _key(TomSecretsAutoTypeKey.enter),
      ]);
    });

    test('literal text, repeat counts, function keys, ~ and escaped '
        'characters', () {
      expect(_parse('ab{TAB 2}{F5}~{+}{{}{}}{S:pin}'), [
        const TomSecretsAutoTypeText('ab'),
        _key(TomSecretsAutoTypeKey.tab),
        _key(TomSecretsAutoTypeKey.tab),
        const TomSecretsAutoTypeKeyPress(
          key: TomSecretsAutoTypeKey.function,
          function: 5,
        ),
        _key(TomSecretsAutoTypeKey.enter),
        const TomSecretsAutoTypeText('+{}0000'),
      ]);
    });

    test('modifiers on a character, a key and a group', () {
      expect(_parse('^v+{TAB}%(ab)^+x'), [
        _char('v', {_control}),
        _key(TomSecretsAutoTypeKey.tab, {_shift}),
        _char('a', {_alt}),
        _char('b', {_alt}),
        _char('x', {_control, _shift}),
      ]);
    });

    test('delays: a pause, and the pause between keys', () {
      expect(_parse('{DELAY 250}x{DELAY=40}'), [
        const TomSecretsAutoTypeDelay(Duration(milliseconds: 250)),
        const TomSecretsAutoTypeText('x'),
        const TomSecretsAutoTypeKeyDelay(Duration(milliseconds: 40)),
      ]);
    });

    test('an unknown placeholder and an unclosed brace are refused, '
        'naming no value', () {
      expect(
        () => _parse('{NOPE}'),
        throwsA(
          isA<TomSecretsAutoTypeException>().having(
            (e) => e.message,
            'message',
            'unknown placeholder {NOPE}',
          ),
        ),
      );
      expect(() => _parse('{TAB'), throwsA(isA<TomSecretsAutoTypeException>()));
    });

    test('an entry\'s values, the TOTP code included', () {
      final vault = DemoVault();
      final e = vault.add(
        'Mail',
        password: 'demo-pw',
        fields: {
          'UserName': 'demo-user',
          'URL': 'https://mail.example.com',
          'otp': 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP',
          'Region': 'eu',
        },
      );
      final values = tomSecretsAutoTypeValues(
        e,
        now: DateTime.utc(2026, 11, 19),
      );
      expect(values('USERNAME'), 'demo-user');
      expect(values('password'), 'demo-pw');
      expect(values('TITLE'), 'Mail');
      expect(values('URL'), 'https://mail.example.com');
      expect(values('S:Region'), 'eu');
      expect(values('S:missing'), isNull);
      expect(values('TOTP'), hasLength(6));
      expect(values('OTHER'), isNull);
    });
  });

  group('window titles', () {
    test('wildcards over the whole title, any case; //regex// anywhere', () {
      expect(
        tomSecretsAutoTypeWindowMatches(
          'Demo Login - *',
          'demo login - Firefox',
        ),
        isTrue,
      );
      expect(
        tomSecretsAutoTypeWindowMatches('Demo Login', 'Demo Login - Firefox'),
        isFalse,
      );
      expect(
        tomSecretsAutoTypeWindowMatches(
          '*Remote?Desktop*',
          'My Remote Desktop 1',
        ),
        isTrue,
      );
      expect(
        tomSecretsAutoTypeWindowMatches('//^ssh .*@db//', 'ssh demo@db01'),
        isTrue,
      );
      expect(tomSecretsAutoTypeWindowMatches('//[//', 'anything'), isFalse);
      expect(tomSecretsAutoTypeWindowMatches('', 'anything'), isFalse);
    });
  });

  group('which sequence, which entries', () {
    test('an association\'s sequence, else the entry\'s, else the group\'s, '
        'else the default; off types nothing', () {
      final vault = DemoVault();
      final e = vault.add('Work/Db', password: 'x');
      expect(
        tomSecretsAutoTypeSequenceFor(e),
        tomSecretsDefaultAutoTypeSequence,
      );
      e.parent!.defaultAutoTypeSequence.set('{PASSWORD}{ENTER}');
      expect(tomSecretsAutoTypeSequenceFor(e), '{PASSWORD}{ENTER}');
      e.autoType = const KdbxAutoTypeSettings(
        defaultSequence: '{USERNAME}{ENTER}',
        associations: [
          KdbxAutoTypeAssociation('psql*', '{PASSWORD}{ENTER}'),
          KdbxAutoTypeAssociation('Db console', ''),
        ],
      );
      expect(tomSecretsAutoTypeSequenceFor(e), '{USERNAME}{ENTER}');
      expect(
        tomSecretsAutoTypeSequenceFor(e, windowTitle: 'psql - demo'),
        '{PASSWORD}{ENTER}',
      );
      expect(
        tomSecretsAutoTypeSequenceFor(e, windowTitle: 'Db console'),
        '{USERNAME}{ENTER}',
      );
      e.parent!.autoTypeEnabled.set(false);
      expect(tomSecretsAutoTypeSequenceFor(e), isNull);
    });

    test('candidates: associations first, then titles the window holds; '
        'notes and entries with auto-type off left out', () {
      final vault = DemoVault();
      final db = vault.add('Db', password: 'x');
      db.autoType = const KdbxAutoTypeSettings(
        associations: [KdbxAutoTypeAssociation('*Terminal*', '')],
      );
      vault.add('Terminal', password: 'y');
      vault.add('Terminal note', fields: {'tsm.type': 'note'});
      final off = vault.add('Terminal off', password: 'z');
      off.autoType = const KdbxAutoTypeSettings(enabled: false);
      final found = tomSecretsAutoTypeCandidates([
        for (final e in vault.file.body.rootGroup.getAllEntries()) ('v', e),
      ], 'Terminal — demo@host');
      expect(found.map((c) => c.entry.label), ['Db', 'Terminal']);
      expect(found.first.byAssociation, isTrue);
      expect(found.last.byAssociation, isFalse);
      expect(found.first.sequence, tomSecretsDefaultAutoTypeSequence);
    });
  });

  group('carried along', () {
    test('a merge keeps the auto-type settings the other side changed, a '
        'copied entry keeps them', () async {
      final vault = DemoVault();
      final e = vault.add('Db', password: 'x');
      final copy = await KdbxFormat().read(
        await vault.file.save(),
        demoCredentials,
      );
      const settings = KdbxAutoTypeSettings(
        defaultSequence: '{PASSWORD}{ENTER}',
        associations: [KdbxAutoTypeAssociation('psql*', '')],
      );
      final theirs = copy.body.rootGroup.getAllEntries().single;
      theirs.autoType = settings;
      tomSecretsMergeVaults(
        base: await KdbxFormat().read(await vault.file.save(), demoCredentials),
        ours: vault.file,
        theirs: copy,
      );
      expect(e.autoType, settings);

      final other = newTestVault(demoCredentials, 'other');
      final copied = tomSecretsCopyEntry(other, other.body.rootGroup, e);
      expect(copied.autoType, settings);
    });
  });
}
