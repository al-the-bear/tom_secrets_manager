// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The age v1 file format (part-sharing, DP-63, DP-177): the reader against
// every hybrid vector of the age testkit (fixtures/age, C2SP CCTV at the
// commit SOURCE.json names, each file's SHA-256 pinned), the writer by
// round trips (empty, one chunk, exactly one chunk, several, armoured,
// several recipients) and its refusals. The files filippo.io/age v1.3.2
// reads and writes are checked by hand once per change (README, Status).

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

const _dir = 'test/fixtures/age';

/// One testkit vector: its header fields and the file.
final class _Vector {
  _Vector(this.fields, this.file);

  factory _Vector.read(File path) {
    final bytes = path.readAsBytesSync();
    final fields = <String, List<String>>{};
    var pos = 0;
    while (true) {
      final end = bytes.indexOf(0x0a, pos);
      final line = ascii.decode(bytes.sublist(pos, end));
      pos = end + 1;
      if (line.isEmpty) break;
      final colon = line.indexOf(': ');
      (fields[line.substring(0, colon)] ??= []).add(line.substring(colon + 2));
    }
    var file = Uint8List.sublistView(bytes, pos);
    if (fields['compressed']?.single == 'zlib') {
      file = Uint8List.fromList(zlib.decode(file));
    }
    return _Vector(fields, file);
  }

  final Map<String, List<String>> fields;
  final Uint8List file;

  String get expect => fields['expect']!.single;
  List<String> get identities => fields['identity'] ?? const [];
  String? get payloadHash => fields['payload']?.single;
}

Matcher _failure(TomSecretsAgeFailure reason) => throwsA(
  isA<TomSecretsAgeException>().having((e) => e.reason, 'reason', reason),
);

void main() {
  group('the age testkit (hybrid vectors)', () {
    final source =
        jsonDecode(File('$_dir/SOURCE.json').readAsStringSync())
            as Map<String, dynamic>;
    final digests = (source['sha256'] as Map).cast<String, String>();
    final files = [
      for (final f in Directory(_dir).listSync().whereType<File>())
        if (!f.path.endsWith('SOURCE.json')) f,
    ]..sort((a, b) => a.path.compareTo(b.path));

    test('the vectors are the pinned files', () {
      expect(files, hasLength(19));
      for (final f in files) {
        final name = f.uri.pathSegments.last;
        expect(sha256.convert(f.readAsBytesSync()).toString(), digests[name]);
      }
    });

    const outcomes = {
      'no match': TomSecretsAgeFailure.noMatch,
      'header failure': TomSecretsAgeFailure.header,
      'payload failure': TomSecretsAgeFailure.payload,
      'armor failure': TomSecretsAgeFailure.armor,
    };

    for (final f in files) {
      final vector = _Vector.read(f);
      test('${f.uri.pathSegments.last}: ${vector.expect}', () async {
        final identities = <TomSecretsAgeIdentity>[];
        final keys = <TomSecretsMemberKey>[];
        final classical = <TomSecretsAgeX25519Identity>[];
        for (final i in vector.identities) {
          if (i.toUpperCase().startsWith('AGE-SECRET-KEY-PQ-1')) {
            final k = await TomSecretsMemberKey.parse(i);
            keys.add(k);
            identities.add(TomSecretsAgeHybridIdentity(k));
          } else {
            final c = TomSecretsAgeX25519Identity.parse(i);
            classical.add(c);
            identities.add(c);
          }
        }
        addTearDown(() {
          for (final k in keys) {
            k.dispose();
          }
          for (final c in classical) {
            c.dispose();
          }
        });
        final run = tomSecretsAgeDecrypt(vector.file, identities);
        if (vector.expect == 'success') {
          final plain = await run;
          expect(sha256.convert(plain).toString(), vector.payloadHash);
        } else {
          await expectLater(run, _failure(outcomes[vector.expect]!));
        }
      });
    }
  });

  group('the writer', () {
    late TomSecretsMemberKey alice;
    late TomSecretsMemberKey bob;
    late TomSecretsMemberKey carol;
    setUpAll(() async {
      alice = await TomSecretsMemberKey.generate();
      bob = await TomSecretsMemberKey.generate();
      carol = await TomSecretsMemberKey.generate();
    });
    tearDownAll(() {
      alice.dispose();
      bob.dispose();
      carol.dispose();
    });

    for (final size in [0, 1, 1000, 65536, 65537, 200000]) {
      test('$size bytes to two hybrid recipients, read by each', () async {
        final plain = Uint8List.fromList([
          for (var i = 0; i < size; i++) (i * 7) % 256,
        ]);
        final file = await tomSecretsAgeEncrypt(plain, [
          alice.recipient,
          bob.recipient,
        ]);
        expect(ascii.decode(file.sublist(0, 22)), 'age-encryption.org/v1\n');
        expect('-> mlkem768x25519 '.allMatches(latin1.decode(file)).length, 2);
        for (final k in [alice, bob]) {
          expect(
            await tomSecretsAgeDecrypt(file, [TomSecretsAgeHybridIdentity(k)]),
            plain,
          );
        }
        await expectLater(
          tomSecretsAgeDecrypt(file, [TomSecretsAgeHybridIdentity(carol)]),
          _failure(TomSecretsAgeFailure.noMatch),
        );
      });
    }

    test('armoured: written, recognised and read; a broken armour', () async {
      final file = await tomSecretsAgeEncrypt(utf8.encode('demo'), [
        alice.recipient,
      ]);
      final armored = tomSecretsAgeArmor(file);
      expect(armored, startsWith('-----BEGIN AGE ENCRYPTED FILE-----\n'));
      expect(armored, endsWith('-----END AGE ENCRYPTED FILE-----\n'));
      for (final l in armored.split('\n')) {
        expect(l.length, lessThanOrEqualTo(64));
      }
      final pasted = utf8.encode('\n  ${armored.replaceAll('\n', '\r\n')}  ');
      expect(tomSecretsIsAgeArmor(pasted), isTrue);
      expect(tomSecretsAgeDearmor(pasted), file);
      expect(
        utf8.decode(
          await tomSecretsAgeDecrypt(Uint8List.fromList(pasted), [
            TomSecretsAgeHybridIdentity(alice),
          ]),
        ),
        'demo',
      );
      final lines = armored.trim().split('\n');
      final short = [
        lines.first,
        lines[1].substring(1),
        ...lines.skip(2),
      ].join('\n');
      expect(
        () => tomSecretsAgeDearmor(utf8.encode(short)),
        throwsA(isA<TomSecretsAgeException>()),
      );
    });

    test('a changed byte: header or payload failure', () async {
      final file = await tomSecretsAgeEncrypt(utf8.encode('demo value'), [
        alice.recipient,
      ]);
      final payload = Uint8List.fromList(file)..[file.length - 1] ^= 1;
      await expectLater(
        tomSecretsAgeDecrypt(payload, [TomSecretsAgeHybridIdentity(alice)]),
        _failure(TomSecretsAgeFailure.payload),
      );
      final mac = latin1.decode(file).indexOf('--- ') + 5;
      final header = Uint8List.fromList(file)
        ..[mac] = file[mac] == 0x41 ? 0x42 : 0x41;
      await expectLater(
        tomSecretsAgeDecrypt(header, [TomSecretsAgeHybridIdentity(alice)]),
        _failure(TomSecretsAgeFailure.header),
      );
      final cut = Uint8List.sublistView(file, 0, file.length - 20);
      await expectLater(
        tomSecretsAgeDecrypt(cut, [TomSecretsAgeHybridIdentity(alice)]),
        _failure(TomSecretsAgeFailure.payload),
      );
    });

    test(
      'classical recipients alone; never mixed with hybrid ones, never none',
      () async {
        // A classical identity and recipient filippo.io/age v1.3.2 made (demo).
        final identity = TomSecretsAgeX25519Identity.parse(
          'AGE-SECRET-KEY-1CYJJCCQEGXMJWST3YH0Q40FSAN9253TSGS566S9LXJFAWSRMF3AST60U4U',
        );
        addTearDown(identity.dispose);
        final classical = TomSecretsAgeRecipient.parse(
          'age1vg68yht8qxg2p0tedkg4pp9f6tqu4zpm55n52zca7mzy0rw7lvwq73k9ju',
        );
        final file = await tomSecretsAgeEncrypt(utf8.encode('for carol'), [
          classical,
        ]);
        expect(latin1.decode(file), contains('-> X25519 '));
        expect(
          utf8.decode(await tomSecretsAgeDecrypt(file, [identity])),
          'for carol',
        );
        await expectLater(
          tomSecretsAgeEncrypt(utf8.encode('x'), [alice.recipient, classical]),
          _failure(TomSecretsAgeFailure.recipients),
        );
        await expectLater(
          tomSecretsAgeEncrypt(utf8.encode('x'), const []),
          _failure(TomSecretsAgeFailure.recipients),
        );
      },
    );

    test('not an age file', () async {
      await expectLater(
        tomSecretsAgeDecrypt(Uint8List.fromList(utf8.encode('hello\n')), [
          TomSecretsAgeHybridIdentity(alice),
        ]),
        _failure(TomSecretsAgeFailure.header),
      );
    });
  });
}
