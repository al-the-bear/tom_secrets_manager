// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Typed certificates and PGP keys through the service (part-sharing,
/// part-protocol, BP-33): `getFile` of the entry without a field serves its
/// private key (a certificate's `private-key.pem`, a PGP key's secret key),
/// a named attachment as before; their expiry (a certificate's notAfter in
/// Expires) is a key reminder (`keys`, `status.expiring`) from 30 days
/// before. Demo keys only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

void main() {
  late Demo demo;
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  setUp(() async => demo = await Demo.create());

  test(
    'getFile of a certificate and a PGP key; their expiry reminded',
    () async {
      final now = DateTime.now().toUtc();
      final certificate = tomSecretsGenerateCertificate(
        commonName: 'web.example',
        days: 20,
        now: now,
      );
      final pgp = tomSecretsGeneratePgpKey(
        userId: 'Demo <demo@example.com>',
        expiresAfter: const Duration(days: 300),
        now: now,
      );
      // The team vault with a certificate expiring in 20 days and a PGP key
      // in 300.
      final credentials = Credentials(ProtectedValue.fromString(teamPassword));
      final team = await KdbxFormat().read(
        File(demo.teamPath).readAsBytesSync(),
        credentials,
      );
      KdbxEntry add(String title) {
        final e = KdbxEntry.create(team, team.body.rootGroup)
          ..setString(KdbxKeyCommon.TITLE, PlainValue(title));
        team.body.rootGroup.addEntry(e);
        return e;
      }

      tomSecretsWriteCertificate(
        add('Web'),
        certificatePem: certificate.certificatePem,
        privateKeyPem: certificate.privateKeyPem,
      );
      tomSecretsWritePgpKey(
        add('Signing'),
        privateArmored: pgp.privateArmored,
        passphrase: pgp.passphrase,
      );
      File(demo.teamPath).writeAsBytesSync(await team.save());

      final service = await demo.start(transport: transport);
      final admin = await TomSecretsAdminClient.connect(
        demo.runtime(transport),
        demo.adminKey,
      );
      addTearDown(admin.close);
      await admin.unlock(primaryPassword);

      final client = await TomSecretsClient.connect(
        clientName: 'demo-tool',
        environment: demo.clientEnvironment(),
      );
      addTearDown(client.close);
      final key = await client.getFile('team/Web');
      expect(key.name, tomSecretsCertificateKeyAttachment);
      expect(utf8.decode(key.bytes), certificate.privateKeyPem);
      final cert = await client.getFile(
        'team/Web',
        field: 'attachment:$tomSecretsCertificateAttachment',
      );
      expect(utf8.decode(cert.bytes), certificate.certificatePem);
      // A field the reference writes wins over the typed default.
    final named = await client.getFile('team/Web#Title');
    expect(named.name, 'Title');
    expect(utf8.decode(named.bytes), 'Web');
    final secret = await client.getFile('team/Signing');
      expect(secret.name, tomSecretsPgpPrivateAttachment);
      expect(utf8.decode(secret.bytes), pgp.privateArmored);
      // A plain get still answers the Password: the PGP key's passphrase.
      expect((await client.get('team/Signing')).text, pgp.passphrase);

      // The reminders: the certificate within 30 days, the PGP key listed but
      // not due yet.
      final keys = {for (final k in service.keys) k.key: k};
      final web = keys['certificate:team/Web']!;
      expect(web.kind, 'certificate');
      expect(web.vault, 'team');
      expect(web.expiresAt, certificate.info.notAfter);
      expect(keys['pgp-key:team/Signing']!.kind, 'pgp_key');
      final expiring = service.expiring.map((k) => k.key).toList();
      expect(expiring, contains('certificate:team/Web'));
      expect(expiring, isNot(contains('pgp-key:team/Signing')));
      final status = await admin.request('status');
      expect(
        (status['expiring']! as List).map((e) => (e as Map)['kind']),
        contains('certificate'),
      );
    },
  );
}
