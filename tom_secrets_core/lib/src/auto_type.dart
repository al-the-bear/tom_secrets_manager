// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Auto-type (part-password-manager, DP-41): typing an entry's user name and
/// password into another application's window. This library holds what is
/// the same on every OS; the app types the actions with the OS's own events
/// (never the service).
///
/// - **Sequences** in KeePass's syntax ([tomSecretsParseAutoType]): the
///   default `{USERNAME}{TAB}{PASSWORD}{ENTER}`; placeholders (`{USERNAME}`,
///   `{PASSWORD}`, `{TITLE}`, `{URL}`, `{NOTES}`, `{TOTP}`, `{S:<field>}`)
///   typed as text; special keys (`{TAB}`, `{ENTER}`, `{UP}`, `{F5}`, … with
///   a repeat count `{TAB 2}`); modifiers `+` Shift, `^` Ctrl, `%` Alt, `@`
///   the Windows or Command key on the next key or on a group `^(ac)`; `~`
///   Enter; `{DELAY n}` waits n ms; `{DELAY=n}` sets the pause between keys;
///   `{+}`, `{^}`, `{%}`, `{@}`, `{~}`, `{{}`, `{}}`, `{(}`, `{)}` type the
///   character itself.
/// - **Which sequence** ([tomSecretsAutoTypeSequenceFor]): the window
///   association whose title pattern matches the active window, else the
///   entry's default, else its groups', else the default above. A pattern is
///   KeePass's: `*` and `?` wildcards, case-insensitive, or `//regex//`.
/// - **Which entries** for a window ([tomSecretsAutoTypeCandidates]): those
///   with a matching association, or whose title the window's title holds.
library;

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';
import 'totp.dart';

/// The sequence typed when neither the entry nor its groups name one.
const String tomSecretsDefaultAutoTypeSequence =
    '{USERNAME}{TAB}{PASSWORD}{ENTER}';

/// A key auto-type presses that is no character.
enum TomSecretsAutoTypeKey {
  /// Tab.
  tab,

  /// Enter (Return).
  enter,

  /// Space.
  space,

  /// Backspace.
  backspace,

  /// Delete (forward).
  delete,

  /// Escape.
  escape,

  /// Arrow up.
  up,

  /// Arrow down.
  down,

  /// Arrow left.
  left,

  /// Arrow right.
  right,

  /// Home.
  home,

  /// End.
  end,

  /// Page up.
  pageUp,

  /// Page down.
  pageDown,

  /// Insert.
  insert,

  /// F1 … F16 ([TomSecretsAutoTypeKeyPress.function] names which).
  function,
}

/// A modifier held while a key is pressed.
enum TomSecretsAutoTypeModifier {
  /// Shift (`+`).
  shift,

  /// Control (`^`).
  control,

  /// Alt or Option (`%`).
  alt,

  /// The Windows key, or Command on macOS (`@`).
  meta,
}

/// One step of a parsed sequence.
sealed class TomSecretsAutoTypeAction {
  const TomSecretsAutoTypeAction();
}

/// Text typed as characters (a placeholder's value or literal text), each
/// as Unicode where the OS allows.
final class TomSecretsAutoTypeText extends TomSecretsAutoTypeAction {
  /// Types [text].
  const TomSecretsAutoTypeText(this.text);

  /// The characters.
  final String text;

  @override
  bool operator ==(Object other) =>
      other is TomSecretsAutoTypeText && other.text == text;

  @override
  int get hashCode => text.hashCode;

  @override
  String toString() => 'text(${text.length})';
}

/// A key pressed with [modifiers]: a special [key] or a [character].
final class TomSecretsAutoTypeKeyPress extends TomSecretsAutoTypeAction {
  /// Presses [key] (for [TomSecretsAutoTypeKey.function], [function] says
  /// which) or [character].
  const TomSecretsAutoTypeKeyPress({
    this.key,
    this.character,
    this.function = 0,
    this.modifiers = const {},
  }) : assert((key == null) != (character == null));

  /// The special key, or null for a character.
  final TomSecretsAutoTypeKey? key;

  /// The character, or null for a special key.
  final String? character;

  /// For a function key, its number (1–16).
  final int function;

  /// The modifiers held.
  final Set<TomSecretsAutoTypeModifier> modifiers;

  @override
  bool operator ==(Object other) =>
      other is TomSecretsAutoTypeKeyPress &&
      other.key == key &&
      other.character == character &&
      other.function == function &&
      other.modifiers.length == modifiers.length &&
      other.modifiers.containsAll(modifiers);

  @override
  int get hashCode =>
      Object.hash(key, character, function, Object.hashAllUnordered(modifiers));

  @override
  String toString() =>
      'key(${[for (final m in modifiers) m.name, key?.name ?? character, if (function > 0) 'F$function'].join('+')})';
}

/// A pause.
final class TomSecretsAutoTypeDelay extends TomSecretsAutoTypeAction {
  /// Waits [duration].
  const TomSecretsAutoTypeDelay(this.duration);

  /// How long.
  final Duration duration;

  @override
  bool operator ==(Object other) =>
      other is TomSecretsAutoTypeDelay && other.duration == duration;

  @override
  int get hashCode => duration.hashCode;
}

/// Sets the pause between keys from here on.
final class TomSecretsAutoTypeKeyDelay extends TomSecretsAutoTypeAction {
  /// Pauses [duration] between keys.
  const TomSecretsAutoTypeKeyDelay(this.duration);

  /// How long.
  final Duration duration;

  @override
  bool operator ==(Object other) =>
      other is TomSecretsAutoTypeKeyDelay && other.duration == duration;

  @override
  int get hashCode => duration.hashCode;
}

/// A sequence that cannot be typed.
final class TomSecretsAutoTypeException implements Exception {
  /// Refused for [message].
  const TomSecretsAutoTypeException(this.message);

  /// What is wrong (never a value).
  final String message;

  @override
  String toString() => 'Auto-type: $message';
}

const Map<String, TomSecretsAutoTypeKey> _keys = {
  'TAB': TomSecretsAutoTypeKey.tab,
  'ENTER': TomSecretsAutoTypeKey.enter,
  'SPACE': TomSecretsAutoTypeKey.space,
  'BACKSPACE': TomSecretsAutoTypeKey.backspace,
  'BS': TomSecretsAutoTypeKey.backspace,
  'BKSP': TomSecretsAutoTypeKey.backspace,
  'DEL': TomSecretsAutoTypeKey.delete,
  'DELETE': TomSecretsAutoTypeKey.delete,
  'ESC': TomSecretsAutoTypeKey.escape,
  'UP': TomSecretsAutoTypeKey.up,
  'DOWN': TomSecretsAutoTypeKey.down,
  'LEFT': TomSecretsAutoTypeKey.left,
  'RIGHT': TomSecretsAutoTypeKey.right,
  'HOME': TomSecretsAutoTypeKey.home,
  'END': TomSecretsAutoTypeKey.end,
  'PGUP': TomSecretsAutoTypeKey.pageUp,
  'PGDN': TomSecretsAutoTypeKey.pageDown,
  'INSERT': TomSecretsAutoTypeKey.insert,
  'INS': TomSecretsAutoTypeKey.insert,
};

const Map<String, TomSecretsAutoTypeModifier> _modifiers = {
  '+': TomSecretsAutoTypeModifier.shift,
  '^': TomSecretsAutoTypeModifier.control,
  '%': TomSecretsAutoTypeModifier.alt,
  '@': TomSecretsAutoTypeModifier.meta,
};

/// The values of an entry's placeholders, for [tomSecretsParseAutoType]:
/// `{USERNAME}`, `{PASSWORD}`, `{TITLE}`, `{URL}`, `{NOTES}`, `{TOTP}` (the
/// current code at [now]) and `{S:<field>}`; null for any other name.
String? Function(String name) tomSecretsAutoTypeValues(
  KdbxEntry entry, {
  DateTime? now,
}) => (name) {
  String text(String field) => entry.getString(KdbxKey(field))?.getText() ?? '';
  final upper = name.toUpperCase();
  if (upper.startsWith('S:')) {
    final field = name.substring(2);
    return entry.getString(KdbxKey(field)) == null ? null : text(field);
  }
  return switch (upper) {
    'USERNAME' => text('UserName'),
    'PASSWORD' => text('Password'),
    'TITLE' => text('Title'),
    'URL' => text('URL'),
    'NOTES' => text('Notes'),
    'TOTP' => TomSecretsTotp.fromEntry(entry)?.code(now ?? DateTime.now()),
    _ => null,
  };
};

/// Parses [sequence] (KeePass's syntax) into actions; a placeholder's value
/// comes from [values] and is typed as text. Throws
/// [TomSecretsAutoTypeException] for an unknown placeholder or an unclosed
/// brace.
List<TomSecretsAutoTypeAction> tomSecretsParseAutoType(
  String sequence, {
  required String? Function(String name) values,
}) {
  final actions = <TomSecretsAutoTypeAction>[];
  final text = StringBuffer();
  void flush() {
    if (text.isEmpty) return;
    actions.add(TomSecretsAutoTypeText(text.toString()));
    text.clear();
  }

  var i = 0;
  final held = <TomSecretsAutoTypeModifier>{};

  // A key with the modifiers held, which are then released.
  void press(TomSecretsAutoTypeKeyPress plain) {
    flush();
    actions.add(
      TomSecretsAutoTypeKeyPress(
        key: plain.key,
        character: plain.character,
        function: plain.function,
        modifiers: {...held},
      ),
    );
  }

  void character(String c) {
    if (held.isEmpty) {
      text.write(c);
    } else {
      press(TomSecretsAutoTypeKeyPress(character: c));
    }
  }

  // One braced token at i ('{'); answers the index after it.
  int braced(int at) {
    // `{}}` and `{{}` are the braces themselves.
    if (sequence.startsWith('{}}', at)) {
      character('}');
      return at + 3;
    }
    final close = sequence.indexOf('}', at + 1);
    if (close < 0) {
      throw const TomSecretsAutoTypeException('a "{" is not closed');
    }
    final body = sequence.substring(at + 1, close);
    final after = close + 1;
    if (body.length == 1 && '+^%@~{}()[]'.contains(body)) {
      character(body);
      return after;
    }
    final upper = body.toUpperCase();
    final delay = RegExp(r'^DELAY\s*(=)?\s*(\d+)$').firstMatch(upper);
    if (delay != null) {
      flush();
      final ms = Duration(milliseconds: int.parse(delay.group(2)!));
      actions.add(
        delay.group(1) == null
            ? TomSecretsAutoTypeDelay(ms)
            : TomSecretsAutoTypeKeyDelay(ms),
      );
      return after;
    }
    final keyed = RegExp(r'^([A-Z]+[0-9]*)(?:\s+(\d+))?$').firstMatch(upper);
    if (keyed != null) {
      final name = keyed.group(1)!;
      final times = int.parse(keyed.group(2) ?? '1');
      final f = RegExp(r'^F(\d{1,2})$').firstMatch(name);
      TomSecretsAutoTypeKeyPress? key;
      if (_keys[name] case final k?) {
        key = TomSecretsAutoTypeKeyPress(key: k);
      } else if (f != null &&
          int.parse(f.group(1)!) >= 1 &&
          int.parse(f.group(1)!) <= 16) {
        key = TomSecretsAutoTypeKeyPress(
          key: TomSecretsAutoTypeKey.function,
          function: int.parse(f.group(1)!),
        );
      }
      if (key != null) {
        for (var n = 0; n < times; n++) {
          press(key);
        }
        return after;
      }
    }
    final value = values(body);
    if (value == null) {
      throw TomSecretsAutoTypeException('unknown placeholder {$body}');
    }
    if (held.isEmpty) {
      text.write(value);
    } else {
      for (final rune in value.runes) {
        press(TomSecretsAutoTypeKeyPress(character: String.fromCharCode(rune)));
      }
    }
    return after;
  }

  while (i < sequence.length) {
    final c = sequence[i];
    final modifier = _modifiers[c];
    if (modifier != null) {
      // Modifiers before a key or a group: held for it.
      final mods = <TomSecretsAutoTypeModifier>{modifier};
      var j = i + 1;
      while (j < sequence.length && _modifiers.containsKey(sequence[j])) {
        mods.add(_modifiers[sequence[j]]!);
        j++;
      }
      if (j >= sequence.length) break;
      held.addAll(mods);
      if (sequence[j] == '(') {
        final close = sequence.indexOf(')', j + 1);
        if (close < 0) {
          throw const TomSecretsAutoTypeException('a "(" is not closed');
        }
        var k = j + 1;
        while (k < close) {
          if (sequence[k] == '{') {
            k = braced(k);
          } else {
            character(sequence[k]);
            k++;
          }
        }
        i = close + 1;
      } else if (sequence[j] == '{') {
        i = braced(j);
      } else if (sequence[j] == '~') {
        press(
          const TomSecretsAutoTypeKeyPress(key: TomSecretsAutoTypeKey.enter),
        );
        i = j + 1;
      } else {
        final rune = sequence.runes.elementAt(
          sequence.substring(0, j).runes.length,
        );
        final ch = String.fromCharCode(rune);
        press(TomSecretsAutoTypeKeyPress(character: ch));
        i = j + ch.length;
      }
      held.clear();
      continue;
    }
    if (c == '~') {
      press(const TomSecretsAutoTypeKeyPress(key: TomSecretsAutoTypeKey.enter));
      i++;
      continue;
    }
    if (c == '{') {
      i = braced(i);
      continue;
    }
    text.write(c);
    i++;
  }
  flush();
  return actions;
}

/// Whether the window title [title] matches the association pattern
/// [pattern]: `//regex//` as a regular expression found anywhere, any case;
/// else the whole title against `*` (any run) and `?` (one character), any
/// case. An empty pattern matches nothing.
bool tomSecretsAutoTypeWindowMatches(String pattern, String title) {
  final p = pattern.trim();
  if (p.isEmpty) return false;
  if (p.length > 4 && p.startsWith('//') && p.endsWith('//')) {
    try {
      return RegExp(
        p.substring(2, p.length - 2),
        caseSensitive: false,
      ).hasMatch(title);
    } on FormatException {
      return false;
    }
  }
  final buffer = StringBuffer('^');
  for (final rune in p.runes) {
    final ch = String.fromCharCode(rune);
    buffer.write(switch (ch) {
      '*' => '.*',
      '?' => '.',
      _ => RegExp.escape(ch),
    });
  }
  buffer.write(r'$');
  return RegExp(
    buffer.toString(),
    caseSensitive: false,
    dotAll: true,
  ).hasMatch(title.trim());
}

/// Whether auto-type is on for [entry]: its own setting and the nearest
/// group that sets one.
bool tomSecretsAutoTypeEnabled(KdbxEntry entry) {
  if (!entry.autoType.enabled) return false;
  for (var g = entry.parent; g != null; g = g.parent) {
    final enabled = g.autoTypeEnabled.get();
    if (enabled != null) return enabled;
  }
  return true;
}

/// The sequence typed for [entry] into the window titled [windowTitle]
/// (null: the entry's default): the first association matching the title
/// (its own sequence, else the entry's default), else the entry's default
/// sequence, else the nearest group's, else
/// [tomSecretsDefaultAutoTypeSequence]. Null when auto-type is off for it.
String? tomSecretsAutoTypeSequenceFor(KdbxEntry entry, {String? windowTitle}) {
  if (!tomSecretsAutoTypeEnabled(entry)) return null;
  final settings = entry.autoType;
  String inherited() {
    final own = settings.defaultSequence;
    if (own != null && own.trim().isNotEmpty) return own;
    for (var g = entry.parent; g != null; g = g.parent) {
      final sequence = g.defaultAutoTypeSequence.get();
      if (sequence != null && sequence.trim().isNotEmpty) return sequence;
    }
    return tomSecretsDefaultAutoTypeSequence;
  }

  if (windowTitle != null) {
    for (final a in settings.associations) {
      if (tomSecretsAutoTypeWindowMatches(a.window, windowTitle)) {
        return a.sequence.trim().isEmpty ? inherited() : a.sequence;
      }
    }
  }
  return inherited();
}

/// An entry auto-type may type into a window, and why.
final class TomSecretsAutoTypeCandidate {
  /// [entry] of [store], matched [byAssociation] or by its title.
  const TomSecretsAutoTypeCandidate(
    this.store,
    this.entry, {
    required this.byAssociation,
    required this.sequence,
  });

  /// The entry's store.
  final String store;

  /// The entry.
  final KdbxEntry entry;

  /// Whether a window association matched (else the entry's title).
  final bool byAssociation;

  /// The sequence it types there.
  final String sequence;
}

/// The entries of [entries] (store and entry) whose auto-type fits the
/// window titled [windowTitle]: a window association matching it, or (when
/// none does) a title of 3 characters or more the window's title contains.
/// Entries with auto-type off and those outside the login and API-token
/// types are left out. Association matches come first.
List<TomSecretsAutoTypeCandidate> tomSecretsAutoTypeCandidates(
  Iterable<(String, KdbxEntry)> entries,
  String windowTitle,
) {
  final byAssociation = <TomSecretsAutoTypeCandidate>[];
  final byTitle = <TomSecretsAutoTypeCandidate>[];
  final lowerTitle = windowTitle.toLowerCase();
  for (final (store, entry) in entries) {
    final type = TomSecretsEntryType.of(
      entry.getString(TomSecretsEntryFields.type)?.getText(),
    );
    if (type != TomSecretsEntryType.login &&
        type != TomSecretsEntryType.apiToken) {
      continue;
    }
    if (!tomSecretsAutoTypeEnabled(entry)) continue;
    final associated = entry.autoType.associations.any(
      (a) => tomSecretsAutoTypeWindowMatches(a.window, windowTitle),
    );
    final label = (entry.label ?? '').trim().toLowerCase();
    if (!associated && (label.length < 3 || !lowerTitle.contains(label))) {
      continue;
    }
    final candidate = TomSecretsAutoTypeCandidate(
      store,
      entry,
      byAssociation: associated,
      sequence: tomSecretsAutoTypeSequenceFor(entry, windowTitle: windowTitle)!,
    );
    (associated ? byAssociation : byTitle).add(candidate);
  }
  return [...byAssociation, ...byTitle];
}
