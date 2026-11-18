// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The typed SSH key (part-structure, DP-5, DP-179): reading a key file's
/// type, public key and fingerprint (checked against `ssh-keygen` where it
/// is installed), generating Ed25519 and RSA keys OpenSSH reads, the
/// `KeeAgent.settings` attachment as KeePassXC writes it, the migration of
/// phase A's notes, and the 1Password import of a key. Demo keys only.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

/// `ssh-keygen`, or null when this machine has none.
final String? _sshKeygen = () {
  for (final dir in [
    '/usr/bin',
    '/usr/local/bin',
    '/opt/homebrew/bin',
    r'C:\Windows\System32\OpenSSH',
  ]) {
    for (final name in ['ssh-keygen', 'ssh-keygen.exe']) {
      final path = '$dir${Platform.pathSeparator}$name';
      if (File(path).existsSync()) return path;
    }
  }
  return null;
}();

/// Runs `ssh-keygen` with [args]; its standard output.
String _keygen(List<String> args) {
  final r = Process.runSync(_sshKeygen!, args);
  if (r.exitCode != 0) fail('ssh-keygen ${args.join(' ')}: ${r.stderr}');
  return '${r.stdout}';
}

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('tsm-ssh'));
  tearDown(() => dir.deleteSync(recursive: true));

  group('generated keys (DP-179)', () {
    test('Ed25519 by default: OpenSSH reads it and derives the same public '
        'key and fingerprint', () async {
      final key = await tomSecretsGenerateSshKey(comment: 'demo@example');
      final text = utf8.decode(key.privateKey);
      expect(text, startsWith('-----BEGIN OPENSSH PRIVATE KEY-----\n'));
      final info = key.info;
      expect(info.format, TomSecretsSshKeyFormat.openssh);
      expect(info.keyType, 'ssh-ed25519');
      expect(info.encrypted, isFalse);
      expect(info.bits, 256);
      expect(info.comment, 'demo@example');
      expect(info.publicKey, startsWith('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5'));
      expect(info.publicKey, endsWith(' demo@example'));
      expect(info.fingerprint, startsWith('SHA256:'));
      if (_sshKeygen == null) return;
      final file = File('${dir.path}/id_demo')
        ..writeAsBytesSync(key.privateKey);
      if (!Platform.isWindows) Process.runSync('chmod', ['600', file.path]);
      expect(_keygen(['-y', '-f', file.path]).trim(), info.publicKey);
      expect(
        _keygen(['-l', '-E', 'sha256', '-f', file.path]),
        contains(info.fingerprint!),
      );
    });

    test('RSA where a tool needs it: OpenSSH reads it', () async {
      final key = await tomSecretsGenerateSshKey(
        algorithm: TomSecretsSshKeyAlgorithm.rsa,
        rsaBits: 2048, // 4096 in the product; shorter here for speed
        comment: 'rsa-demo',
      );
      expect(key.info.keyType, 'ssh-rsa');
      expect(key.info.bits, 2048);
      if (_sshKeygen == null) return;
      final file = File('${dir.path}/id_rsa_demo')
        ..writeAsBytesSync(key.privateKey);
      if (!Platform.isWindows) Process.runSync('chmod', ['600', file.path]);
      expect(_keygen(['-y', '-f', file.path]).trim(), key.info.publicKey);
    });

    test('the product generates RSA 4096 by default', () async {
      final key = await tomSecretsGenerateSshKey(
        algorithm: TomSecretsSshKeyAlgorithm.rsa,
      );
      expect(key.info.bits, 4096);
    }, timeout: const Timeout(Duration(minutes: 3)));
  });

  group('reading key files', () {
    test('OpenSSH, encrypted or not: type and public key without the '
        'passphrase; PEM RSA (PKCS#1), EC (SEC1) and PKCS#8', () {
      if (_sshKeygen == null) {
        markTestSkipped('no ssh-keygen on this machine');
        return;
      }
      String make(String name, List<String> args) {
        final path = '${dir.path}/$name';
        _keygen([...args, '-q', '-C', 'demo', '-f', path]);
        return path;
      }

      TomSecretsSshKeyInfo read(String path) =>
          TomSecretsSshKeyInfo.parse(File(path).readAsBytesSync())!;
      String pub(String path) => File(
        '$path.pub',
      ).readAsStringSync().trim().split(' ').take(2).join(' ');
      String bare(String? line) => line!.split(' ').take(2).join(' ');

      final enc = make('enc', ['-t', 'ed25519', '-N', 'demo-passphrase']);
      final encrypted = read(enc);
      expect(encrypted.encrypted, isTrue);
      expect(encrypted.keyType, 'ssh-ed25519');
      expect(bare(encrypted.publicKey), pub(enc));
      expect(encrypted.comment, isNull, reason: 'inside the encrypted part');

      final ecdsa = make('ecdsa', ['-t', 'ecdsa', '-b', '384', '-N', '']);
      expect(read(ecdsa).keyType, 'ecdsa-sha2-nistp384');
      expect(bare(read(ecdsa).publicKey), pub(ecdsa));

      final pkcs1 = make('pkcs1', [
        '-t',
        'rsa',
        '-b',
        '2048',
        '-m',
        'PEM',
        '-N',
        '',
      ]);
      expect(read(pkcs1).format, TomSecretsSshKeyFormat.pkcs1);
      expect(bare(read(pkcs1).publicKey), pub(pkcs1));
      expect(read(pkcs1).bits, 2048);

      final sec1 = make('sec1', [
        '-t',
        'ecdsa',
        '-b',
        '256',
        '-m',
        'PEM',
        '-N',
        '',
      ]);
      expect(read(sec1).format, TomSecretsSshKeyFormat.sec1);
      expect(bare(read(sec1).publicKey), pub(sec1));

      final pkcs8 = make('pkcs8', [
        '-t',
        'rsa',
        '-b',
        '2048',
        '-m',
        'PKCS8',
        '-N',
        '',
      ]);
      expect(read(pkcs8).format, TomSecretsSshKeyFormat.pkcs8);
      expect(bare(read(pkcs8).publicKey), pub(pkcs8));
      expect(read(pkcs8).fingerprint, isNotNull);
    });

    test('anything else is no key', () {
      for (final bytes in [
        utf8.encode('just a note'),
        utf8.encode(
          '-----BEGIN OPENSSH PRIVATE KEY-----\nDEMO-NOT-A-REAL-KEY\n'
          '-----END OPENSSH PRIVATE KEY-----\n',
        ),
        utf8.encode(
          '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n',
        ),
        [0xff, 0xfe, 0x00],
      ]) {
        expect(TomSecretsSshKeyInfo.parse(bytes), isNull);
      }
    });
  });

  group('KeeAgent.settings', () {
    test('written as UTF-16 with a byte order mark, as KeePassXC writes it; '
        'read from UTF-16 and UTF-8', () {
      const settings = TomSecretsKeeAgentSettings(
        attachmentName: 'id_ed25519',
        useConfirmConstraintWhenAdding: true,
      );
      final bytes = settings.toBytes();
      expect(bytes.sublist(0, 2), [0xff, 0xfe]);
      final back = TomSecretsKeeAgentSettings.parse(bytes)!;
      expect(back.attachmentName, 'id_ed25519');
      expect(back.useConfirmConstraintWhenAdding, isTrue);
      expect(back.addAtDatabaseOpen, isTrue);
      expect(back.selectedType, 'attachment');
      final utf8Settings = TomSecretsKeeAgentSettings.parse(
        utf8.encode(settings.toXml()),
      )!;
      expect(utf8Settings.attachmentName, 'id_ed25519');
      expect(TomSecretsKeeAgentSettings.parse(utf8.encode('<x/>')), isNull);
    });
  });

  group('entries', () {
    late KdbxFile file;
    late Uint8List key;

    KdbxEntry add(String title, {String? type, Map<String, List<int>>? files}) {
      final root = file.body.rootGroup;
      final entry = KdbxEntry.create(file, root)
        ..setString(KdbxKeyCommon.TITLE, PlainValue(title));
      if (type != null) {
        entry.setString(TomSecretsEntryFields.type, PlainValue(type));
      }
      for (final MapEntry(:key, :value) in (files ?? {}).entries) {
        entry.createBinary(
          isProtected: true,
          name: key,
          bytes: Uint8List.fromList(value),
        );
      }
      root.addEntry(entry);
      return entry;
    }

    setUp(() async {
      file = newTestVault(demoCredentials, 'personal');
      key = (await tomSecretsGenerateSshKey(comment: 'demo')).privateKey;
    });

    test('a new key entry: typed, the key protected, KeeAgent.settings '
        'naming it', () {
      final entry = add('Deploy key');
      tomSecretsWriteSshKey(
        entry,
        attachmentName: 'id_ed25519',
        privateKey: key,
      );
      expect(entry.getString(TomSecretsEntryFields.type)?.getText(), 'ssh-key');
      final found = tomSecretsSshKeyOf(entry)!;
      expect(found.name, 'id_ed25519');
      expect(found.info.keyType, 'ssh-ed25519');
      expect(entry.getBinary(const KdbxKey('id_ed25519'))!.isProtected, isTrue);
      final settings = TomSecretsKeeAgentSettings.parse(
        entry.getBinary(const KdbxKey(tomSecretsKeeAgentSettingsName))!.value,
      )!;
      expect(settings.attachmentName, 'id_ed25519');
    });

    test('the migration retypes phase A notes and KeePassXC entries that '
        'hold a key, keeps the old state in the history, and leaves the '
        'rest', () async {
      var note = add('Server key', type: 'note', files: {'private_key': key});
      var keepass = add(
        'KeePassXC key',
        files: {
          'id': key,
          tomSecretsKeeAgentSettingsName: const TomSecretsKeeAgentSettings(
            attachmentName: 'id',
            useConfirmConstraintWhenAdding: true,
          ).toBytes(),
        },
      );
      var plainNote = add(
        'Recovery',
        type: 'note',
        files: {'codes.txt': utf8.encode('demo codes')},
      );
      var login = add('Login with a key file', files: {'key': key});
      final already = add('Typed', files: {'k': key});
      tomSecretsWriteSshKey(already, attachmentName: 'k', privateKey: key);
      // As the app meets them: a vault read from its file.
      file = await KdbxFormat().read(await file.save(), demoCredentials);
      KdbxEntry named(String title) => file.body.rootGroup
          .getAllEntries()
          .firstWhere((e) => e.label == title);
      note = named('Server key');
      keepass = named('KeePassXC key');
      plainNote = named('Recovery');
      login = named('Login with a key file');

      expect(tomSecretsSshKeyCandidates(file), [note, keepass]);
      final before = note.history.length;
      final migrated = tomSecretsMigrateSshKeys(file);
      expect(migrated, [note, keepass]);
      for (final e in migrated) {
        expect(e.getString(TomSecretsEntryFields.type)?.getText(), 'ssh-key');
      }
      expect(note.history.length, before + 1);
      expect(
        note.history.last.getString(TomSecretsEntryFields.type)?.getText(),
        'note',
      );
      expect(tomSecretsSshKeyOf(note)!.name, 'private_key');
      // KeePassXC's own settings stay, the attachment named again.
      final kept = TomSecretsKeeAgentSettings.parse(
        keepass.getBinary(const KdbxKey(tomSecretsKeeAgentSettingsName))!.value,
      )!;
      expect(kept.useConfirmConstraintWhenAdding, isTrue);
      expect(kept.attachmentName, 'id');
      expect(
        plainNote.getString(TomSecretsEntryFields.type)?.getText(),
        'note',
      );
      expect(login.getString(TomSecretsEntryFields.type), isNull);
      expect(tomSecretsSshKeyCandidates(file), isEmpty, reason: 'once');
    });

    test('the 1Password import types an SSH key whose key it carries', () {
      final source = TomSecretsImportSource(
        source: tomSecretsOnePasswordSource,
        displayName: '1Password',
        format: '1pux',
        vaults: [
          TomSecretsImportVault(
            id: 'v1',
            name: 'Personal',
            items: [
              TomSecretsImportItem(
                sourceId: 'demo-ssh-real',
                version: '1',
                title: 'Real SSH Key',
                kind: TomSecretsImportKind.sshKey,
                attachments: [TomSecretsImportAttachment('private_key', key)],
              ),
            ],
          ),
        ],
      );
      tomSecretsImport(source, file: file);
      final entry = file.body.rootGroup.getAllEntries().firstWhere(
        (e) => e.label == 'Real SSH Key',
      );
      expect(entry.getString(TomSecretsEntryFields.type)?.getText(), 'ssh-key');
      expect(tomSecretsSshKeyOf(entry)!.name, 'private_key');
      expect(
        entry.getBinary(const KdbxKey(tomSecretsKeeAgentSettingsName)),
        isNotNull,
      );
    });
  });
}
