// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The Enpass import and export (part-password-manager, DP-36, DP-40,
/// DP-120) on the synthetic fixtures in test/fixtures/enpass: JSON and CSV,
/// folders, categories, archived and trashed items, passkeys into
/// KeePassXC's `KPEX_PASSKEY_*` fields (each converted key signs a challenge
/// that its public key verifies), re-import without duplicates, and the
/// Enpass JSON export read back by the importer.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cr;
import 'package:pointycastle/asn1.dart' as asn1;
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const fixtures = 'test/fixtures/enpass';
const keepassxcApp = '/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli';
const vault = ['Enpass', 'Vault'];

String exportJson() => File('$fixtures/json/export.json').readAsStringSync();

KdbxGroup? groupAt(KdbxFile file, List<String> path) {
  KdbxGroup? group = file.body.rootGroup;
  for (final name in path) {
    group = group?.groups.where((g) => g.name.get() == name).firstOrNull;
  }
  return group;
}

KdbxEntry entryAt(KdbxFile file, List<String> path, String title) =>
    groupAt(file, path)!.entries.firstWhere((e) => e.label == title);

KdbxEntry find(KdbxFile file, String title) =>
    file.body.rootGroup.getAllEntries().firstWhere((e) => e.label == title);

String? text(KdbxEntry e, String field) =>
    e.getString(KdbxKey(field))?.getText();

Future<KdbxFile> reopen(KdbxFile file) async =>
    KdbxFormat().read(await file.save(), demoCredentials);

/// The DER elements inside a PEM's base64.
Uint8List pemDer(String pem) => base64.decode(
  pem.split('\n').where((l) => !l.startsWith('-----') && l.isNotEmpty).join(),
);

BigInt big(List<int> bytes) =>
    bytes.fold(BigInt.zero, (v, b) => (v << 8) | BigInt.from(b));

void main() {
  final now = DateTime.utc(2026, 11, 13, 12);

  group('reading the exports', () {
    test(
      'JSON: items, kinds, folders, trash, archive and the passkey notice',
      () {
        final source = tomSecretsReadEnpassJson(
          exportJson(),
          vaultName: 'Vault',
        );
        expect(source.source, 'enpass');
        expect(source.format, 'json');
        final items = {for (final i in source.vaults.single.items) i.title: i};
        expect(items, hasLength(15));
        final mail = items['Demo Enpass Mail']!;
        expect(mail.folders, ['Work', 'Servers']);
        expect(mail.tags, ['Personal'], reason: 'the other folders as tags');
        expect(mail.kind, TomSecretsImportKind.login);
        expect(items['Demo Enpass Note']!.kind, TomSecretsImportKind.note);
        expect(items['Demo Enpass Server']!.kind, TomSecretsImportKind.login);
        expect(items['Demo Enpass Card']!.category, 'Credit Cards');
        expect(items['Demo Enpass Trashed']!.trashed, isTrue);
        expect(items['Demo Enpass Archived']!.archived, isTrue);
        expect(source.notImported.single.title, 'Demo Passkey Without Key');
        expect(
          () => tomSecretsReadEnpassJson('{"folders": []}'),
          throwsA(isA<TomSecretsImportFormatException>()),
        );
      },
    );
  });

  group('a JSON import into a new vault', () {
    late KdbxFile file;
    late TomSecretsImportReport report;

    setUp(() async {
      final fresh = newTestVault(demoCredentials, 'v');
      report = tomSecretsImport(
        tomSecretsReadEnpassJson(exportJson()),
        file: fresh,
        now: now,
      );
      file = await reopen(fresh);
    });

    test('a login: folders nested, fields mapped, sections, deleted and empty '
        'fields dropped, history, times', () {
      final e = entryAt(file, [
        ...vault,
        'Work',
        'Servers',
      ], 'Demo Enpass Mail');
      expect(text(e, 'UserName'), 'demo.user');
      expect(
        text(e, 'E-mail'),
        'demo@example.com',
        reason: 'a second user name or e-mail is a custom field',
      );
      expect(text(e, 'Password'), 'demo-enpass-pw');
      expect(
        e.getString(const KdbxKey('Second password')),
        isA<ProtectedValue>(),
      );
      expect(text(e, 'URL'), 'https://mail.example.com');
      expect(text(e, 'KP2A_URL_1'), 'https://webmail.example.com');
      expect(TomSecretsTotp.fromEntry(e)!.issuer, 'Demo Enpass Mail');
      expect(e.getString(const KdbxKey('PIN')), isA<ProtectedValue>());
      expect(text(e, 'Recovery · Hint'), 'demo hint');
      expect(text(e, 'Recovery · Codes'), 'code-1\ncode-2');
      expect(
        e.getString(const KdbxKey('Recovery · Codes')),
        isA<ProtectedValue>(),
      );
      expect(text(e, 'Recovery · Removed'), isNull);
      expect(text(e, 'Recovery · Empty'), isNull);
      expect(
        text(e, 'Recovery · KPEX_PASSKEY_FAKE'),
        'not a passkey',
        reason: 'only the importer writes passkey fields',
      );
      expect(text(e, 'Notes'), 'Demo enpass note');
      expect(
        e.tags.get()!.split(';'),
        unorderedEquals(['Personal', 'favorite']),
      );
      expect(e.history.map((h) => text(h, 'Password')), [
        'demo-enpass-old-1',
        'demo-enpass-old-2',
      ]);
      expect(
        text(e, 'tsm.import.enpass.id'),
        'e0000000-0000-4000-8000-000000000001',
      );
      expect(
        e.times.lastModificationTime.get(),
        DateTime.utc(2023, 11, 15, 22, 13, 20),
      );
    });

    test('types and category subgroups; archived and trashed left out', () {
      expect(text(find(file, 'Demo Enpass Note'), 'tsm.type'), 'note');
      final server = entryAt(file, [
        ...vault,
        'Work',
        'Servers',
      ], 'Demo Enpass Server');
      expect(text(server, 'tsm.type'), 'login');
      expect(text(server, 'Hostname'), 'server.example.com');
      expect(text(server, 'Port'), '2222');
      final card = entryAt(file, [
        ...vault,
        'Credit Cards',
      ], 'Demo Enpass Card');
      expect(card.getString(const KdbxKey('Number')), isA<ProtectedValue>());
      expect(text(card, 'Expiry'), '07/28');
      expect(
        entryAt(file, [...vault, 'Identities'], 'Demo Enpass Identity'),
        isNotNull,
      );
      expect(
        report
            .withOutcome(TomSecretsImportOutcome.leftOut)
            .map((l) => l.reason),
        unorderedEquals(['archived', 'trashed']),
      );
      expect(
        utf8.decode(
          find(
            file,
            'Demo Enpass Attachment',
          ).getBinary(const KdbxKey('demo.txt'))!.value,
        ),
        'demo attachment, no secret\n',
      );
    });

    test('trashed items stay out even with archived ones included', () {
      final fresh = newTestVault(demoCredentials, 'v');
      final r = tomSecretsImport(
        tomSecretsReadEnpassJson(exportJson()),
        file: fresh,
        includeArchived: true,
        now: now,
      );
      expect(
        entryAt(fresh, [...vault, 'Archive'], 'Demo Enpass Archived'),
        isNotNull,
      );
      expect(
        r.withOutcome(TomSecretsImportOutcome.leftOut).single.reason,
        'trashed',
      );
    });

    test('passkeys into KPEX_PASSKEY_*: every key shape converted to PKCS#8 '
        'PEM, the report says kept but not yet usable', () async {
      final publics =
          jsonDecode(
                File(
                  '$fixtures/json/passkey_public_keys.json',
                ).readAsStringSync(),
              )
              as Map<String, dynamic>;
      final kept = report.withOutcome(TomSecretsImportOutcome.passkeyKept);
      expect(
        kept.map((l) => l.title),
        unorderedEquals([
          'Demo Passkey One',
          'Demo Passkey Two',
          'Demo Passkey Three',
          'Demo Passkey Four',
          'Demo Passkey Five',
        ]),
      );
      expect(kept.first.reason, 'passkey kept, not yet usable');
      expect(
        report.withOutcome(TomSecretsImportOutcome.notImported).single.title,
        'Demo Passkey Without Key',
      );

      final one = TomSecretsPasskey.fromEntry(find(file, 'Demo Passkey One'))!;
      expect(one.relyingParty, 'one.passkey.example');
      expect(
        one.credentialId,
        tomSecretsBase64Url(base64.encode(utf8.encode('demo-credential-1'))),
      );
      expect(one.credentialId, isNot(contains('=')));
      expect(one.userHandle, 'ZGVtby11c2VyLTE');
      expect(one.userName, 'pk-one');
      expect(
        find(
          file,
          'Demo Passkey One',
        ).getString(TomSecretsPasskeyFields.privateKeyPem),
        isA<ProtectedValue>(),
      );
      expect(
        TomSecretsPasskey.fromEntry(find(file, 'Demo Passkey Two'))!.userHandle,
        'ZGVtby11c2VyLTI',
      );
      expect(
        text(find(file, 'Demo Passkey Two'), 'Password'),
        'pk-two-pw',
        reason: 'beside the password',
      );
      expect(
        TomSecretsPasskey.fromEntry(
          find(file, 'Demo Passkey Four'),
        )!.relyingParty,
        'four.passkey.example',
        reason: 'from the URL when the export names no relying party',
      );

      // Each P-256 key signs a challenge its fixture public key verifies.
      final params = pc.ECDomainParameters('prime256v1');
      final random = pc.FortunaRandom()
        ..seed(pc.KeyParameter(Uint8List.fromList(List.filled(32, 7))));
      final challenge = Uint8List.fromList(utf8.encode('demo challenge'));
      for (final title in [
        'Demo Passkey One',
        'Demo Passkey Two',
        'Demo Passkey Three',
        'Demo Passkey Four',
      ]) {
        final pem = TomSecretsPasskey.fromEntry(
          find(file, title),
        )!.privateKeyPem;
        expect(pem, startsWith('-----BEGIN PRIVATE KEY-----\n'));
        final pkcs8 =
            asn1.ASN1Parser(pemDer(pem)).nextObject() as asn1.ASN1Sequence;
        final inner =
            asn1.ASN1Parser(
                  (pkcs8.elements![2] as asn1.ASN1OctetString).valueBytes,
                ).nextObject()
                as asn1.ASN1Sequence;
        final d = big((inner.elements![1] as asn1.ASN1OctetString).valueBytes!);
        final xy = publics[title] as Map<String, dynamic>;
        final q = params.curve.createPoint(
          big(tomSecretsDecodeBase64(xy['x'] as String)),
          big(tomSecretsDecodeBase64(xy['y'] as String)),
        );
        expect(params.G * d, q, reason: '$title: the key\'s public point');
        final signer = pc.Signer('SHA-256/ECDSA')
          ..init(
            true,
            pc.ParametersWithRandom(
              pc.PrivateKeyParameter(pc.ECPrivateKey(d, params)),
              random,
            ),
          );
        final signature = signer.generateSignature(challenge);
        final verifier = pc.Signer('SHA-256/ECDSA')
          ..init(false, pc.PublicKeyParameter(pc.ECPublicKey(q, params)));
        expect(
          verifier.verifySignature(challenge, signature),
          isTrue,
          reason: title,
        );
      }

      // The Ed25519 key signs and verifies too.
      final edPem = TomSecretsPasskey.fromEntry(
        find(file, 'Demo Passkey Five'),
      )!.privateKeyPem;
      final seed = pemDer(edPem).sublist(pemDer(edPem).length - 32);
      final ed = cr.Ed25519();
      final pair = await ed.newKeyPairFromSeed(seed);
      final sig = await ed.sign(challenge, keyPair: pair);
      expect(await ed.verify(challenge, signature: sig), isTrue);
    });

    test(
      'KeePassXC counts the imported passkeys',
      () async {
        final dir = Directory(
          '${Directory.current.path}/testlog/scratch_enpass_kxc',
        )..createSync(recursive: true);
        addTearDown(() => dir.deleteSync(recursive: true));
        final path = '${dir.path}/vault.kdbx';
        File(path).writeAsBytesSync(await file.save());
        final process = await Process.start(keepassxcApp, [
          'db-info',
          '-q',
          path,
        ]);
        process.stdin.writeln('demo-key');
        await process.stdin.close();
        final out = await process.stdout.transform(utf8.decoder).join();
        final err = await process.stderr.transform(utf8.decoder).join();
        expect(await process.exitCode, 0, reason: err);
        expect(out, contains('Number of passkeys: 5'));
      },
      skip: File(keepassxcApp).existsSync()
          ? null
          : 'keepassxc-cli is not on this machine',
    );

    test('the client endpoint never serves the passkey fields', () {
      for (final f in [
        TomSecretsPasskeyFields.privateKeyPem,
        TomSecretsPasskeyFields.credentialId,
        TomSecretsPasskeyFields.relyingParty,
        TomSecretsPasskeyFields.userHandle,
        TomSecretsPasskeyFields.userName,
      ]) {
        expect(tomSecretsIsPasskeyField(f.key), isTrue);
      }
    });
  });

  group('re-import', () {
    test('the same export: nothing added; a newer item updated', () async {
      final fresh = newTestVault(demoCredentials, 'v');
      tomSecretsImport(
        tomSecretsReadEnpassJson(exportJson()),
        file: fresh,
        now: now,
      );
      final file = await reopen(fresh);
      final again = tomSecretsImport(
        tomSecretsReadEnpassJson(exportJson()),
        file: file,
        now: now,
      );
      expect(again.count(TomSecretsImportOutcome.added), 0);
      expect(again.count(TomSecretsImportOutcome.unchanged), 13);

      final data = jsonDecode(exportJson()) as Map<String, dynamic>;
      final mail = (data['items'] as List).first as Map<String, dynamic>;
      mail['updated_at'] = (mail['updated_at'] as int) + 3600;
      ((mail['fields'] as List)[2] as Map)['value'] = 'demo-enpass-newer';
      final newer = tomSecretsImport(
        tomSecretsReadEnpassJson(jsonEncode(data)),
        file: file,
        now: now,
      );
      expect(
        newer.withOutcome(TomSecretsImportOutcome.updated).single.title,
        'Demo Enpass Mail',
      );
      final e = find(file, 'Demo Enpass Mail');
      expect(text(e, 'Password'), 'demo-enpass-newer');
      expect(text(e.history.last, 'Password'), 'demo-enpass-pw');
    });
  });

  group('CSV', () {
    TomSecretsImportSource csv([String Function(String)? edit]) {
      final t = File('$fixtures/csv/export.csv').readAsStringSync();
      return tomSecretsReadEnpassCsv(edit == null ? t : edit(t));
    }

    test(
      'title, label and value pairs, the note; the header row skipped',
      () async {
        final fresh = newTestVault(demoCredentials, 'v');
        final report = tomSecretsImport(csv(), file: fresh, now: now);
        final file = await reopen(fresh);
        expect(report.count(TomSecretsImportOutcome.added), 3);
        final mail = find(file, 'Demo Enpass CSV Mail');
        expect(text(mail, 'UserName'), 'csv.user');
        expect(text(mail, 'Password'), 'csv-enpass-pw');
        expect(text(mail, 'URL'), 'https://mail.example.com');
        expect(TomSecretsTotp.fromEntry(mail), isNotNull);
        expect(mail.getString(const KdbxKey('PIN')), isA<ProtectedValue>());
        expect(text(mail, 'Hint'), 'demo hint');
        expect(text(mail, 'Notes'), 'Line one\nline two, with "quotes"');
        expect(text(find(file, 'Demo Enpass CSV Note'), 'tsm.type'), 'note');
        expect(
          text(find(file, 'Demo Enpass CSV Note'), 'Notes'),
          'Just a note',
        );
        expect(
          text(find(file, 'Demo Enpass CSV Login'), 'UserName'),
          'login@example.com',
        );
        expect(report.lost, contains('passkeys'));

        final again = tomSecretsImport(csv(), file: file, now: now);
        expect(again.count(TomSecretsImportOutcome.unchanged), 3);
        final changed = tomSecretsImport(
          csv((t) => t.replaceFirst('login-pw', 'login-pw-2')),
          file: file,
          now: now,
        );
        expect(
          changed.withOutcome(TomSecretsImportOutcome.updated).single.title,
          'Demo Enpass CSV Login',
        );
      },
    );
  });

  group('the Enpass JSON export (DP-40)', () {
    test('a vault written as Enpass JSON and read back by the importer keeps '
        'folders, fields, sections, history, TOTP, attachments', () async {
      final source = newTestVault(demoCredentials, 'source');
      tomSecretsImport(
        tomSecretsReadEnpassJson(exportJson()),
        file: source,
        now: now,
      );
      // A product group stays behind.
      final product = source.createGroup(
        parent: source.body.rootGroup,
        name: '.tom-secrets',
      );
      product.addEntry(
        KdbxEntry.create(source, product)
          ..setString(KdbxKeyCommon.TITLE, PlainValue('metadata')),
      );
      final exported = tomSecretsExportEnpassJson(
        source,
        group: groupAt(source, vault),
        now: now,
      );
      final json = jsonDecode(exported.json) as Map<String, dynamic>;
      expect(json.keys, ['folders', 'items']);
      expect(exported.items, 13);
      expect(
        (json['folders'] as List).map((f) => (f as Map)['title']),
        containsAll(['Work', 'Servers', 'Credit Cards']),
      );
      final firstItem = (json['items'] as List).first as Map<String, dynamic>;
      expect(
        firstItem.keys,
        containsAll([
          'uuid',
          'title',
          'category',
          'fields',
          'folders',
          'note',
          'favorite',
          'archived',
          'trashed',
          'createdAt',
          'updated_at',
          'template_type',
        ]),
      );
      expect(exported.lost.join('\n'), contains('passkeys of:'));
      expect(exported.json, isNot(contains('metadata')));
      expect(exported.json, isNot(contains('tsm.import')));
      expect(exported.json, isNot(contains('KPEX_PASSKEY_PRIVATE')));

      final back = newTestVault(demoCredentials, 'back');
      tomSecretsImport(
        tomSecretsReadEnpassJson(exported.json, vaultName: 'Again'),
        file: back,
        now: now,
      );
      final e = entryAt(back, [
        'Enpass',
        'Again',
        'Work',
        'Servers',
      ], 'Demo Enpass Mail');
      expect(text(e, 'UserName'), 'demo.user');
      expect(text(e, 'Password'), 'demo-enpass-pw');
      expect(text(e, 'URL'), 'https://mail.example.com');
      expect(text(e, 'KP2A_URL_1'), 'https://webmail.example.com');
      expect(text(e, 'Recovery · Hint'), 'demo hint');
      expect(
        e.getString(const KdbxKey('Recovery · Codes')),
        isA<ProtectedValue>(),
      );
      expect(text(e, 'E-mail'), 'demo@example.com');
      expect(
        TomSecretsTotp.fromEntry(e)!.toUri(),
        TomSecretsTotp.fromEntry(find(source, 'Demo Enpass Mail'))!.toUri(),
      );
      expect(text(e, 'Notes'), 'Demo enpass note');
      expect(e.tags.get(), contains('favorite'));
      expect(
        e.history.map((h) => text(h, 'Password')),
        containsAll(['demo-enpass-old-1', 'demo-enpass-old-2']),
      );
      expect(text(find(back, 'Demo Enpass Note'), 'tsm.type'), 'note');
      expect(
        utf8.decode(
          find(
            back,
            'Demo Enpass Attachment',
          ).getBinary(const KdbxKey('demo.txt'))!.value,
        ),
        'demo attachment, no secret\n',
      );
    });
  });

  group('passkey keys', () {
    test('PKCS#8 passes through; SEC1, raw and JWK become PKCS#8; others are '
        'refused', () {
      final d = Uint8List.fromList(List.generate(32, (i) => i + 1));
      final fromRaw = tomSecretsPasskeyPem(base64.encode(d));
      expect(tomSecretsPasskeyPem(fromRaw), fromRaw);
      expect(tomSecretsPasskeyPem(d), fromRaw);
      expect(
        tomSecretsPasskeyPem({
          'kty': 'EC',
          'crv': 'P-256',
          'd': base64Url.encode(d).replaceAll('=', ''),
        }),
        fromRaw,
      );
      expect(
        () => tomSecretsPasskeyPem({'kty': 'RSA', 'd': 'AAAA'}),
        throwsA(isA<TomSecretsPasskeyException>()),
      );
      expect(
        () => tomSecretsPasskeyPem(Uint8List(32)),
        throwsA(isA<TomSecretsPasskeyException>()),
        reason: 'zero is no key',
      );
      expect(
        () => tomSecretsPasskeyPem('not a key!'),
        throwsA(isA<TomSecretsPasskeyException>()),
      );
      expect(tomSecretsBase64Url('a+b/cw=='), 'a-b_cw');
    });
  });
}
