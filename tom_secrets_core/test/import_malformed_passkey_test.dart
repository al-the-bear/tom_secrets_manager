/// A passkey whose key cannot be read never aborts an import: in every
/// format, the export's other items are all read and imported, the item
/// itself comes without the passkey, and the passkey is named in
/// `notImported`.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const _enpass = 'test/fixtures/enpass/json/export.json';
const _onePux = 'test/fixtures/1password/1pux_v3';
const _bitwarden = 'test/fixtures/bitwarden/export.json';
const _demoPasskey = 'Demo Passkey One';

/// Keys in the shapes an export may hold, none of them readable.
const _malformedKeys = <String, Object>{
  'bad base64': 'not*base64*at*all',
  'a JWK without d': {'kty': 'EC', 'crv': 'P-256', 'x': 'AAAA', 'y': 'AAAA'},
  'a JWK with d that is not base64': {'kty': 'EC', 'crv': 'P-256', 'd': '*'},
  'a PEM that is not a key':
      '-----BEGIN CERTIFICATE-----\nAAECAwQFBgcICQ==\n-----END CERTIFICATE-----',
  'a PEM with bad base64':
      '-----BEGIN PRIVATE KEY-----\n***\n-----END PRIVATE KEY-----',
  'DER that is not a key': 'MAMCAQU=',
};

Map<String, dynamic> _enpassWith(
  void Function(Map<String, dynamic> passkey) edit,
) {
  final data = jsonDecode(File(_enpass).readAsStringSync()) as Map;
  final items = (data['items'] as List).cast<Map<String, dynamic>>();
  final item = items.firstWhere((i) => i['title'] == _demoPasskey);
  final field = (item['fields'] as List)
      .cast<Map<String, dynamic>>()
      .firstWhere((f) => f['type'] == 'passkey');
  final passkey = jsonDecode(field['value'] as String) as Map<String, dynamic>;
  edit(passkey);
  field['value'] = jsonEncode(passkey);
  return data.cast<String, dynamic>();
}

int _itemsIn(TomSecretsImportSource source) =>
    source.vaults.fold(0, (n, v) => n + v.items.length);

Uint8List _onePuxWith(void Function(Map<String, dynamic> item) edit) {
  final data =
      jsonDecode(File('$_onePux/export.data').readAsStringSync())
          as Map<String, dynamic>;
  final vault = ((data['accounts'] as List).first as Map)['vaults'] as List;
  edit((vault.first['items'] as List).first as Map<String, dynamic>);
  final archive = Archive()
    ..add(ArchiveFile.bytes('export.data', utf8.encode(jsonEncode(data))))
    ..add(
      ArchiveFile.bytes(
        'export.attributes',
        File('$_onePux/export.attributes').readAsBytesSync(),
      ),
    );
  for (final f in Directory('$_onePux/files').listSync().whereType<File>()) {
    archive.add(
      ArchiveFile.bytes(
        'files/${f.uri.pathSegments.last}',
        f.readAsBytesSync(),
      ),
    );
  }
  return Uint8List.fromList(ZipEncoder().encodeBytes(archive));
}

void main() {
  final now = DateTime.utc(2026, 11, 25, 12);

  group('Enpass JSON', () {
    final whole = tomSecretsReadEnpassJson(File(_enpass).readAsStringSync());

    for (final MapEntry(key: shape, value: key) in _malformedKeys.entries) {
      test('a passkey key that is $shape: every item imported, the passkey '
          'named', () {
        final source = tomSecretsReadEnpassJson(
          jsonEncode(_enpassWith((p) => p['privateKey'] = key)),
        );
        expect(_itemsIn(source), _itemsIn(whole));
        final item = source.vaults.single.items.firstWhere(
          (i) => i.title == _demoPasskey,
        );
        expect(item.passkey, isNull);
        expect(item.userName, 'pk-one', reason: 'the rest of the item kept');
        final notice = source.notImported.singleWhere(
          (n) => n.title == _demoPasskey,
        );
        expect(notice.what, startsWith('passkey that could not be read ('));
        final secret = key is Map ? key['d'] : key;
        if (secret is String) {
          expect(notice.what, isNot(contains(secret)), reason: 'not quoted');
        }

        final vault = DemoVault();
        final report = tomSecretsImport(source, file: vault.file, now: now);
        expect(report.count(TomSecretsImportOutcome.passkeyKept), 4);
      });
    }

    test('a credential id that is not base64 and a passkey value that is not '
        'JSON: both named, the import goes on', () {
      final data = _enpassWith((p) => p['credentialId'] = '***');
      final items = (data['items'] as List).cast<Map<String, dynamic>>();
      final two = items.firstWhere((i) => i['title'] == 'Demo Passkey Two');
      two['passkey'] = '{"rpId": ';
      final source = tomSecretsReadEnpassJson(jsonEncode(data));
      expect(_itemsIn(source), _itemsIn(whole));
      expect([
        for (final n in source.notImported)
          if (n.what.startsWith('passkey that could not be read')) n.title,
      ], unorderedEquals([_demoPasskey, 'Demo Passkey Two']));
    });
  });

  group('1Password 1PUX', () {
    test('a passkey with a malformed key: every item imported, the passkey '
        'named', () {
      final whole = tomSecretsRead1Pux(_onePuxWith((_) {}));
      late String title;
      final source = tomSecretsRead1Pux(
        _onePuxWith((item) {
          title = '${(item['overview'] as Map)['title']}';
          (item['details'] as Map)['passkey'] = {
            'credentialId': '***',
            'rpId': 'demo.example',
            'privateKey': 'not*base64',
          };
        }),
      );
      expect(_itemsIn(source), _itemsIn(whole));
      expect(
        source.notImported.where((n) => n.title == title).single.what,
        startsWith('passkey'),
      );
      final report = tomSecretsImport(source, file: DemoVault().file, now: now);
      expect(report.lines, isNotEmpty);
    });
  });

  group('Bitwarden JSON', () {
    test('a passkey with a malformed key: every item imported, the passkey '
        'named', () async {
      final text = File(_bitwarden).readAsStringSync();
      final whole = await tomSecretsReadBitwardenJson(text);
      final data = jsonDecode(text) as Map<String, dynamic>;
      final item = (data['items'] as List)
          .cast<Map<String, dynamic>>()
          .firstWhere((i) => i['login'] is Map && i['deletedDate'] == null);
      (item['login'] as Map)['fido2Credentials'] = [
        {
          'credentialId': '***',
          'keyType': 'public-key',
          'keyAlgorithm': 'ECDSA',
          'keyCurve': 'P-256',
          'keyValue': 'not*base64',
          'rpId': 'demo.example',
        },
      ];
      final source = await tomSecretsReadBitwardenJson(jsonEncode(data));
      expect(_itemsIn(source), _itemsIn(whole));
      expect(
        source.notImported.map((n) => n.title),
        contains('${item['name']}'),
      );
      final report = tomSecretsImport(source, file: DemoVault().file, now: now);
      expect(report.lines, isNotEmpty);
    });
  });
}
