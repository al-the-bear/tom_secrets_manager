// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** Passkeys for the browser host (protocol.md 5.8, DP-120):
/// `passkeys` lists a page's passkeys by name and credential id (never a
/// key, never a system vault's, the browser prompt when no grant covers
/// them), `passkeyGet` answers a signature that verifies with the
/// passkey's public key and only for a passkey of the page, `passkeyCreate`
/// asks the app, makes the key pair and keeps the passkey in the site's
/// login on disk before answering; excluded credentials, unsupported
/// algorithms, a relying party the page may not use and any other client
/// are refused. This test process plays the browser host. Demo keys only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;
import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/raw_client.dart';
import 'support/setup.dart';

String _b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List _unb64(String text) => tomSecretsDecodeBase64(text);

/// The client data hash of a sign-in with [challenge].
Uint8List _hash(String challenge) => Uint8List.fromList(
  crypto.sha256
      .convert(
        utf8.encode(
          jsonEncode({
            'type': 'webauthn.get',
            'challenge': challenge,
            'origin': 'https://mail.example.com',
          }),
        ),
      )
      .bytes,
);

void main() {
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;
  final self = {tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!).exe};
  late Demo demo;
  late TomSecretsAdminClient admin;
  late TomSecretsPasskeyRegistration mailKey;

  setUp(() async {
    demo = await Demo.create();
    // team: the Mail login with an Ed25519 passkey of mail.example.com, a
    // login of shop.example.org without one; primary: a system vault with
    // a passkey of the same site (never offered to the browser).
    final team = await KdbxFormat().read(
      File(demo.teamPath).readAsBytesSync(),
      tomSecretsVaultCredentials(password: teamPassword),
    );
    final root = team.body.rootGroup;
    root.addEntry(
      KdbxEntry.create(team, root)
        ..setString(KdbxKeyCommon.TITLE, PlainValue('Mail'))
        ..setString(KdbxKeyCommon.URL, PlainValue('https://mail.example.com'))
        ..setString(KdbxKeyCommon.USER_NAME, PlainValue('demo-user')),
    );
    root.addEntry(
      KdbxEntry.create(team, root)
        ..setString(KdbxKeyCommon.TITLE, PlainValue('Shop'))
        ..setString(KdbxKeyCommon.URL, PlainValue('https://shop.example.org'))
        ..setString(KdbxKeyCommon.USER_NAME, PlainValue('demo-shopper')),
    );
    mailKey = await tomSecretsCreatePasskey(
      rpId: 'mail.example.com',
      userHandle: Uint8List.fromList(utf8.encode('demo-user-handle')),
      userName: 'demo-user',
      algorithms: const [-8],
    );
    tomSecretsKeepPasskey(team, mailKey.passkey);
    File(demo.teamPath).writeAsBytesSync(await team.save());
    final primary = await KdbxFormat().read(
      File(demo.primaryPath).readAsBytesSync(),
      tomSecretsVaultCredentials(password: primaryPassword),
    );
    TomSecretsMetadata(kind: TomSecretsVaultKind.system).writeTo(primary);
    tomSecretsKeepPasskey(
      primary,
      (await tomSecretsCreatePasskey(
        rpId: 'mail.example.com',
        userHandle: Uint8List.fromList(utf8.encode('fleet')),
        userName: 'fleet-user',
      )).passkey,
    );
    File(demo.primaryPath).writeAsBytesSync(await primary.save());
  });

  Future<TomSecretsService> start({
    Set<String>? browserHosts,
    Set<String> passkeyPlugins = const {},
    TomSecretsAccessPolicy? policy = const AllowAllPolicy(),
  }) async {
    final service = await demo.start(
      transport: transport,
      policy: policy,
      browserHostExecutables: browserHosts ?? self,
      helperExecutables: const {},
      passkeyPluginExecutables: passkeyPlugins,
    );
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    await admin.request('subscribe');
    return service;
  }

  /// The answer of [request], progress frames skipped.
  Future<Map<String, Object?>> answer(
    RawClient raw,
    Map<String, Object?> request,
  ) async {
    raw.send(request);
    while (true) {
      final m = await raw.next();
      if (m['op'] != 'progress') return m;
    }
  }

  Future<RawClient> host(TomSecretsService service) async {
    final raw = await RawClient.open(demo, transport);
    await raw.hello(service, features: const ['passkey']);
    return raw;
  }

  test('passkeys lists the page\'s passkeys by name, never a key or a system '
      'vault\'s; passkeyGet signs for the one picked and the signature '
      'verifies with its public key', () async {
    final service = await start();
    final raw = await host(service);
    final listed = await answer(raw, {
      'op': 'passkeys',
      'id': 1,
      'url': 'https://mail.example.com/login',
      'rpId': 'mail.example.com',
    });
    expect(listed['op'], 'passkeyCandidates');
    final candidates = (listed['candidates']! as List).cast<Map>();
    expect(candidates, hasLength(1));
    expect(candidates.single['title'], 'Mail');
    expect(candidates.single['userName'], 'demo-user');
    expect(candidates.single['credentialId'], _b64(mailKey.credentialId));
    expect(jsonEncode(listed), isNot(contains('PRIVATE KEY')));
    expect(candidates.single['entryId'], startsWith('team/~'));

    // Another site's passkeys, and an id the site does not allow: none.
    final other = await answer(raw, {
      'op': 'passkeys',
      'id': 2,
      'url': 'https://mail.example.com/',
      'rpId': 'mail.example.com',
      'allowCredentials': ['bm90LWhlbGQ'],
    });
    expect(other['candidates'], isEmpty);

    final hash = _hash('ZGVtby1jaGFsbGVuZ2U');
    final signed = await answer(raw, {
      'op': 'passkeyGet',
      'id': 3,
      'url': 'https://mail.example.com/login',
      'rpId': 'mail.example.com',
      'entryId': candidates.single['entryId'],
      'clientDataHash': _b64(hash),
    });
    expect(signed['op'], 'passkeyAssertion');
    final data = _unb64(signed['authenticatorData']! as String);
    expect(data.sublist(0, 32), tomSecretsRpIdHash('mail.example.com'));
    expect(data[32], tomSecretsPasskeyFlags);
    expect(signed['userHandle'], _b64(utf8.encode('demo-user-handle')));
    final spki = mailKey.publicKeySpki;
    final ok = await cg.Ed25519().verify(
      [...data, ...hash],
      signature: cg.Signature(
        _unb64(signed['signature']! as String),
        publicKey: cg.SimplePublicKey(
          spki.sublist(spki.length - 32),
          type: cg.KeyPairType.ed25519,
        ),
      ),
    );
    expect(ok, isTrue);

    // A malformed hash, an entry that is no passkey of the page.
    final short = await answer(raw, {
      'op': 'passkeyGet',
      'id': 4,
      'url': 'https://mail.example.com/',
      'rpId': 'mail.example.com',
      'entryId': candidates.single['entryId'],
      'clientDataHash': 'AAAA',
    });
    expect((short['details']! as Map)['reason'], 'client_data');
    final foreign = await answer(raw, {
      'op': 'passkeyGet',
      'id': 5,
      'url': 'https://shop.example.org/',
      'rpId': 'shop.example.org',
      'entryId': candidates.single['entryId'],
      'clientDataHash': _b64(hash),
    });
    expect((foreign['details']! as Map)['reason'], 'not_matched');
  });

  test('a relying party the page may not use, and any other client, are '
      'refused', () async {
    final service = await start();
    final raw = await host(service);
    for (final (url, rpId) in [
      ('https://evil.example.net/', 'mail.example.com'),
      ('http://mail.example.com/', 'mail.example.com'),
      ('https://mail.example.com/', 'example.com.'),
      ('https://a.github.io/', 'github.io'),
    ]) {
      final refused = await answer(raw, {
        'op': 'passkeys',
        'id': 1,
        'url': url,
        'rpId': rpId,
      });
      expect(refused['kind'], 'denied', reason: '$url $rpId');
      expect((refused['details']! as Map)['reason'], 'rp_id');
    }
    await service.stop();

    final second = await start(browserHosts: const {});
    final other = await host(second);
    for (final op in ['passkeys', 'passkeyGet', 'passkeyCreate']) {
      final denied = await answer(other, {
        'op': op,
        'id': 1,
        'url': 'https://mail.example.com/',
        'rpId': 'mail.example.com',
      });
      expect((denied['details']! as Map)['reason'], 'not_allowed_op');
    }
  });

  test('without a grant the browser prompt asks for the passkeys (passkey '
      'true); never lists none', () async {
    final service = await start(policy: null);
    final raw = await host(service);
    final needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final listed = answer(raw, {
      'op': 'passkeys',
      'id': 1,
      'url': 'https://mail.example.com/',
      'rpId': 'mail.example.com',
    });
    final event = await needed;
    expect(event['browser'], isTrue);
    expect(event['passkey'], isTrue);
    expect(
      [for (final r in (event['resolved']! as List).cast<Map>()) r['path']],
      ['Mail'],
    );
    await admin.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    expect((await listed)['candidates'], hasLength(1));
    await service.stop();

    final again = await start(policy: null);
    final second = await host(again);
    final asked = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final refused = answer(second, {
      'op': 'passkeys',
      'id': 1,
      'url': 'https://mail.example.com/',
      'rpId': 'mail.example.com',
    });
    await admin.request('approve', {
      'approvalId': (await asked)['approvalId'],
      'decision': 'never',
      'secret': 'ref',
    });
    expect((await refused)['candidates'], isEmpty);
  });

  test('passkeyCreate asks the app; confirmed, the passkey is made with the '
      'site\'s algorithm, kept in the site\'s login on disk and answered; '
      'listed and signing afterwards', () async {
    final service = await start(policy: null);
    final raw = await host(service);
    final needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final created = answer(raw, {
      'op': 'passkeyCreate',
      'id': 1,
      'url': 'https://shop.example.org/signup',
      'rpId': 'shop.example.org',
      'userId': _b64(utf8.encode('shopper-handle')),
      'userName': 'demo-shopper',
      'algorithms': [-257, -8, -7],
    });
    final event = await needed;
    expect(event['confirmOnly'], isTrue);
    expect(event['passkeyCreate'], {
      'rpId': 'shop.example.org',
      'userName': 'demo-shopper',
      'url': 'https://shop.example.org/signup',
    });
    expect(event['refs'], isEmpty);
    await expectLater(
      admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'always',
        'secret': 'ref',
      }),
      throwsA(isA<TomSecretsAdminException>()),
    );
    await admin.request('approve', {
      'approvalId': event['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    final made = await created;
    expect(made['op'], 'passkeyCreated', reason: '$made');
    expect(made['publicKeyAlgorithm'], -8);
    final attestation = _unb64(made['attestationObject']! as String);
    expect(attestation.first, 0xA3);
    final spki = _unb64(made['publicKey']! as String);
    expect((await admin.request('grants.list'))['grants'], isEmpty);

    // On disk: in the Shop login of the team vault.
    final onDisk = await KdbxFormat().read(
      File(demo.teamPath).readAsBytesSync(),
      tomSecretsVaultCredentials(password: teamPassword),
    );
    final kept = tomSecretsPasskeysIn(
      onDisk,
    ).where((p) => p.passkey.relyingParty == 'shop.example.org').single;
    expect(kept.entry.label, 'Shop');
    expect(kept.passkey.userName, 'demo-shopper');
    expect(
      tomSecretsBase64Url(kept.passkey.credentialId),
      made['credentialId'],
    );

    // No grant covers it yet: the browser prompt, answered once.
    final prompt = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final listing = answer(raw, {
      'op': 'passkeys',
      'id': 2,
      'url': 'https://shop.example.org/login',
      'rpId': 'shop.example.org',
    });
    await admin.request('approve', {
      'approvalId': (await prompt)['approvalId'],
      'decision': 'once',
      'secret': 'ref',
    });
    final listed = await listing;
    final entryId = ((listed['candidates']! as List).single as Map)['entryId'];
    final hash = _hash('c2hvcA');
    final signed = await answer(raw, {
      'op': 'passkeyGet',
      'id': 3,
      'url': 'https://shop.example.org/login',
      'rpId': 'shop.example.org',
      'entryId': entryId,
      'clientDataHash': _b64(hash),
    });
    final data = _unb64(signed['authenticatorData']! as String);
    expect(
      await cg.Ed25519().verify(
        [...data, ...hash],
        signature: cg.Signature(
          _unb64(signed['signature']! as String),
          publicKey: cg.SimplePublicKey(
            spki.sublist(spki.length - 32),
            type: cg.KeyPairType.ed25519,
          ),
        ),
      ),
      isTrue,
    );
  });

  test('passkeyCreate: an excluded credential, an algorithm not made here, '
      'a refusal and no approver are refused; nothing is written', () async {
    final service = await start(policy: null);
    final raw = await host(service);
    final before = File(demo.teamPath).readAsBytesSync();
    Map<String, Object?> create(
      int id, {
      List<Object?>? exclude,
      List<int> algorithms = const [-7],
    }) => {
      'op': 'passkeyCreate',
      'id': id,
      'url': 'https://mail.example.com/',
      'rpId': 'mail.example.com',
      'userId': _b64(utf8.encode('demo-user-handle')),
      'userName': 'demo-user',
      'algorithms': algorithms,
      'excludeCredentials': ?exclude,
    };
    final excluded = await answer(
      raw,
      create(1, exclude: [_b64(mailKey.credentialId)]),
    );
    expect((excluded['details']! as Map)['reason'], 'excluded');
    final rsa = await answer(raw, create(2, algorithms: const [-257]));
    expect(rsa['kind'], 'unsupported');
    expect((rsa['details']! as Map)['reason'], 'algorithm');

    final needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
    final refused = answer(raw, create(3));
    await admin.request('approve', {
      'approvalId': (await needed)['approvalId'],
      'decision': 'never',
      'secret': 'ref',
    });
    expect(((await refused)['details']! as Map)['reason'], 'refused');

    // No app attached: nobody can confirm it. The service notices the
    // closed connection on its own time; a busy machine may take a moment.
    await admin.close();
    for (var i = 0; service.hasLocalApprover && i < 200; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    expect(service.hasLocalApprover, isFalse);
    final alone = await answer(raw, create(4));
    expect((alone['details']! as Map)['reason'], 'no_approver');
    expect(File(demo.teamPath).readAsBytesSync(), before);
  });

  test('the Windows passkey plugin is a passkey client: it lists and signs '
      'as the browser host does, and reads no value', () async {
    final service = await start(browserHosts: const {}, passkeyPlugins: self);
    final raw = await host(service);
    final listed = await answer(raw, {
      'op': 'passkeys',
      'id': 1,
      'url': 'https://mail.example.com/',
      'rpId': 'mail.example.com',
    });
    final entryId = ((listed['candidates']! as List).single as Map)['entryId'];
    final signed = await answer(raw, {
      'op': 'passkeyGet',
      'id': 2,
      'url': 'https://mail.example.com/',
      'rpId': 'mail.example.com',
      'entryId': entryId,
      'clientDataHash': _b64(_hash('d2luZG93cw')),
    });
    expect(signed['op'], 'passkeyAssertion');
    final read = await answer(raw, {
      'op': 'get',
      'id': 3,
      'ref': '$entryId',
      'field': 'UserName',
    });
    expect((read['details']! as Map)['reason'], 'not_allowed_op');
    final matched = await answer(raw, {
      'op': 'match',
      'id': 4,
      'url': 'https://mail.example.com/',
    });
    expect((matched['details']! as Map)['reason'], 'not_allowed_op');
  });

  test('the plugin is found beside the service by its file name', () {
    final dir = Directory.systemTemp.createTempSync('tsm_lookup');
    addTearDown(() => dir.deleteSync(recursive: true));
    final ext = Platform.isWindows ? '.exe' : '';
    for (final name in ['tom_secrets_service', tomSecretsPasskeyPluginName]) {
      File('${dir.path}/$name$ext').writeAsStringSync('');
    }
    final lookup = tomSecretsLookupExecutables(
      '${dir.path}/tom_secrets_service$ext',
    );
    expect(lookup.passkeyPlugins.single, endsWith('tsm-passkey-plugin$ext'));
  });
}
