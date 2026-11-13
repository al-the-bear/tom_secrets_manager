// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The three-way merge of two copies of a vault (part-stores, DP-7).
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_core_sync/tom_core_sync.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const user = KdbxKey('UserName');
const notes = KdbxKey('Notes');

/// Base, ours and theirs: three independent copies of one file.
Future<(KdbxFile, KdbxFile, KdbxFile)> copies(KdbxFile original) async {
  final bytes = await original.save();
  Future<KdbxFile> open() => KdbxFormat().read(bytes, demoCredentials);
  return (await open(), await open(), await open());
}

KdbxEntry byTitle(KdbxFile file, String title) =>
    file.body.rootGroup.getAllEntries().firstWhere((e) => e.label == title);

KdbxEntry? maybe(KdbxFile file, String title) => file.body.rootGroup
    .getAllEntries()
    .where((e) => e.label == title)
    .firstOrNull;

String? text(KdbxEntry e, KdbxKey key) => e.getString(key)?.getText();

DateTime at(int minute) => DateTime.utc(2026, 11, 13, 10, minute);

/// Edits [entry] with [change] and stamps it at [minute].
void edit(KdbxEntry entry, int minute, void Function(KdbxEntry e) change) {
  change(entry);
  entry.times.lastModificationTime.set(at(minute));
}

Future<KdbxFile> roundTrip(KdbxFile file) async =>
    KdbxFormat().read(await file.save(), demoCredentials);

void main() {
  late KdbxFile original;
  setUp(() {
    final v = DemoVault();
    v.add(
      'Mail/Box',
      password: 'pw0',
      key: 'mail.box',
      fields: {'UserName': 'alice', 'Notes': 'n0'},
    );
    v.add('Db/Main', password: 'db0', key: 'db.main');
    original = v.file;
    for (final e in original.body.rootGroup.getAllEntries()) {
      e.times.lastModificationTime.set(at(0));
    }
  });

  test(
    'different fields of one entry on each side: both, no conflict (DP-7)',
    () async {
      final (base, ours, theirs) = await copies(original);
      edit(byTitle(ours, 'Box'), 5, (e) {
        e.setString(
          KdbxKeyCommon.PASSWORD,
          ProtectedValue.fromString('pw-ours'),
        );
      });
      edit(
        byTitle(theirs, 'Box'),
        6,
        (e) => e.setString(notes, PlainValue('n-theirs')),
      );
      final result = tomSecretsMergeVaults(
        base: base,
        ours: ours,
        theirs: theirs,
      );
      expect(result.isClean, isTrue);
      final box = byTitle(await roundTrip(ours), 'Box');
      expect(text(box, KdbxKeyCommon.PASSWORD), 'pw-ours');
      expect(box.getString(KdbxKeyCommon.PASSWORD), isA<ProtectedValue>());
      expect(text(box, notes), 'n-theirs');
      expect(text(box, user), 'alice');
      expect(tomSecretsConflictsOf(box), isEmpty);
    },
  );

  test('the same field changed differently: the newer wins, the loser is in '
      'the history, a conflict record names it', () async {
    final (base, ours, theirs) = await copies(original);
    edit(byTitle(ours, 'Box'), 5, (e) {
      e.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('pw-ours'));
    });
    edit(byTitle(theirs, 'Box'), 9, (e) {
      e.setString(
        KdbxKeyCommon.PASSWORD,
        ProtectedValue.fromString('pw-theirs'),
      );
      e.setString(notes, PlainValue('n-theirs'));
    });
    final result = tomSecretsMergeVaults(
      base: base,
      ours: ours,
      theirs: theirs,
      now: at(10),
    );
    expect(result.conflicts.single.fields, ['field:Password']);
    expect(result.conflicts.single.loserModified, at(5));
    final merged = await roundTrip(ours);
    final box = byTitle(merged, 'Box');
    expect(text(box, KdbxKeyCommon.PASSWORD), 'pw-theirs');
    expect(text(box, notes), 'n-theirs');
    final conflict = tomSecretsConflictsOf(box).single;
    expect(conflict.fields, ['field:Password']);
    expect(conflict.record.retained, at(5).toIso8601String());
    final loser = box.history.firstWhere(
      (h) => h.times.lastModificationTime.get() == at(5),
    );
    expect(text(loser, KdbxKeyCommon.PASSWORD), 'pw-ours');
    tomSecretsSettleConflicts(box);
    expect(tomSecretsConflictsOf(box), isEmpty);
  });

  test('a conflict stays recorded through a later clean merge', () async {
    final (base, ours, theirs) = await copies(original);
    edit(byTitle(ours, 'Box'), 5, (e) => e.setString(notes, PlainValue('a')));
    edit(byTitle(theirs, 'Box'), 6, (e) => e.setString(notes, PlainValue('b')));
    tomSecretsMergeVaults(base: base, ours: ours, theirs: theirs);
    final (base2, ours2, theirs2) = await copies(ours);
    edit(byTitle(theirs2, 'Main'), 7, (e) {
      e.setString(user, PlainValue('dbuser'));
    });
    tomSecretsMergeVaults(base: base2, ours: ours2, theirs: theirs2);
    expect(tomSecretsConflictsOf(byTitle(ours2, 'Box')), hasLength(1));
    expect(text(byTitle(ours2, 'Main'), user), 'dbuser');
  });

  test('a deletion on one side and no change on the other: deleted, and the '
      'deletion carried over', () async {
    final (base, ours, theirs) = await copies(original);
    final gone = byTitle(theirs, 'Main');
    theirs.deletePermanently(gone);
    final result = tomSecretsMergeVaults(
      base: base,
      ours: ours,
      theirs: theirs,
    );
    expect(result.isClean, isTrue);
    expect(maybe(ours, 'Main'), isNull);
    expect(ours.isDeleted(gone.uuid), isTrue);
  });

  test('an edit against a deletion: the edit stands and is reported', () async {
    final (base, ours, theirs) = await copies(original);
    edit(
      byTitle(ours, 'Main'),
      5,
      (e) => e.setString(user, PlainValue('kept')),
    );
    theirs.deletePermanently(byTitle(theirs, 'Main'));
    final result = tomSecretsMergeVaults(
      base: base,
      ours: ours,
      theirs: theirs,
    );
    expect(result.editsAgainstDeletion, hasLength(1));
    final main = byTitle(ours, 'Main');
    expect(text(main, user), 'kept');
    expect(ours.isDeleted(main.uuid), isFalse);
  });

  test(
    'entries and groups added on each side: all of them, with their UUIDs',
    () async {
      final (base, ours, theirs) = await copies(original);
      final group = theirs.createGroup(
        parent: theirs.body.rootGroup,
        name: 'New',
      );
      final added = KdbxEntry.create(theirs, group);
      group.addEntry(added);
      added
        ..label = 'Fresh'
        ..setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('f'));
      added.createBinary(
        isProtected: true,
        name: 'key.bin',
        bytes: Uint8List.fromList([1, 2, 3]),
      );
      final mine = KdbxEntry.create(ours, ours.body.rootGroup);
      ours.body.rootGroup.addEntry(mine);
      mine.label = 'Mine';
      tomSecretsMergeVaults(base: base, ours: ours, theirs: theirs);
      final merged = await roundTrip(ours);
      final fresh = byTitle(merged, 'Fresh');
      expect(fresh.uuid, added.uuid);
      expect(fresh.parent!.uuid, group.uuid);
      expect(fresh.parent!.name.get(), 'New');
      expect(fresh.getBinary(const KdbxKey('key.bin'))!.value, [1, 2, 3]);
      expect(maybe(merged, 'Mine'), isNotNull);
    },
  );

  test('a move into an overlay group on one side and an edit on the other: '
      'both (a move is an attribute)', () async {
    final (base, ours, theirs) = await copies(original);
    final overlay = theirs.createGroup(
      parent: theirs.body.rootGroup,
      name: '@host:bomber',
    );
    final db = theirs.createGroup(parent: overlay, name: 'Db');
    theirs.move(byTitle(theirs, 'Main'), db);
    byTitle(theirs, 'Main').times.lastModificationTime.set(at(5));
    edit(byTitle(ours, 'Main'), 6, (e) => e.setString(user, PlainValue('u')));
    final result = tomSecretsMergeVaults(
      base: base,
      ours: ours,
      theirs: theirs,
    );
    expect(result.isClean, isTrue);
    final store = TomSecretsStore.fromFile(
      await roundTrip(ours),
      name: 'fleet',
    );
    final main = store.entries.firstWhere((e) => e.entry.label == 'Main');
    expect(main.bindings, {'host': 'bomber'});
    expect(text(main.entry, user), 'u');
  });

  test(
    'an entry recycled on the other side goes to this copy\'s recycle bin',
    () async {
      final (base, ours, theirs) = await copies(original);
      theirs.deleteEntry(byTitle(theirs, 'Main'));
      expect(ours.recycleBin, isNull);
      tomSecretsMergeVaults(base: base, ours: ours, theirs: theirs);
      final merged = await roundTrip(ours);
      expect(byTitle(merged, 'Main').parent!.uuid, merged.recycleBin!.uuid);
      final store = TomSecretsStore.fromFile(merged, name: 'fleet');
      expect(store.entries.map((e) => e.entry.label), isNot(contains('Main')));
    },
  );

  test('history: the union of both sides, pruned to the limit, a conflict\'s '
      'loser kept', () async {
    original.body.meta.historyMaxItems.set(3);
    final (base, ours, theirs) = await copies(original);
    // Theirs edits the notes four times (four saves: four history versions).
    var side = theirs;
    for (var i = 1; i <= 4; i++) {
      edit(
        byTitle(side, 'Box'),
        10 + i,
        (e) => e.setString(notes, PlainValue('t$i')),
      );
      side = await roundTrip(side);
    }
    edit(byTitle(ours, 'Box'), 5, (e) {
      e.setString(notes, PlainValue('ours'));
    });
    final result = tomSecretsMergeVaults(base: base, ours: ours, theirs: side);
    expect(result.conflicts, hasLength(1));
    final box = byTitle(await roundTrip(ours), 'Box');
    expect(text(box, notes), 't4');
    final stamps = box.history
        .map((h) => h.times.lastModificationTime.get())
        .toList();
    expect(stamps, contains(at(5)), reason: 'the loser is protected');
    expect(stamps.length, lessThanOrEqualTo(4));
    expect(stamps, isNot(contains(at(14))), reason: 'the live version');
  });

  test(
    'meta custom data merges per key; another format major is refused',
    () async {
      final (base, ours, theirs) = await copies(original);
      ours.body.meta.customData['app.a'] = '1';
      theirs.body.meta.customData['app.b'] = '2';
      tomSecretsMergeVaults(base: base, ours: ours, theirs: theirs);
      expect(ours.body.meta.customData['app.a'], '1');
      expect(ours.body.meta.customData['app.b'], '2');

      final (base2, ours2, theirs2) = await copies(original);
      theirs2.body.meta.customData[tomSecretsFormatKey] = '2.0';
      expect(
        () => tomSecretsMergeVaults(base: base2, ours: ours2, theirs: theirs2),
        throwsA(isA<TomMergeRefusedException>()),
      );
      expect(maybe(ours2, 'Box'), isNotNull, reason: 'nothing changed');
    },
  );

  test('copies of different vaults are refused', () async {
    final other = DemoVault().file;
    expect(
      () => tomSecretsMergeVaults(base: null, ours: original, theirs: other),
      throwsA(isA<TomMergeRefusedException>()),
    );
  });

  test('an empty base (a force-pushed branch): everything is kept, a '
      'differing entry is a conflict', () async {
    final (_, ours, theirs) = await copies(original);
    edit(byTitle(ours, 'Box'), 5, (e) => e.setString(notes, PlainValue('a')));
    edit(byTitle(theirs, 'Box'), 6, (e) => e.setString(notes, PlainValue('b')));
    final result = tomSecretsMergeVaults(
      base: null,
      ours: ours,
      theirs: theirs,
    );
    expect(result.conflicts.single.fields, contains('field:Notes'));
    expect(text(byTitle(ours, 'Box'), notes), 'b');
    expect(maybe(ours, 'Main'), isNotNull);
  });

  test('the merged copy resolves, after a save', () async {
    final (base, ours, theirs) = await copies(original);
    edit(byTitle(theirs, 'Main'), 5, (e) {
      e.setString(KdbxKeyCommon.PASSWORD, ProtectedValue.fromString('db1'));
    });
    tomSecretsMergeVaults(base: base, ours: ours, theirs: theirs);
    final store = TomSecretsStore.fromFile(
      await roundTrip(ours),
      name: 'fleet',
    );
    expect(resolver([store], host: 'mbp').resolve('db.main').value.text, 'db1');
  });
}
