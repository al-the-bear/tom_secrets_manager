// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

// The service's identity key with the real primitives (protocol.md 6.1,
// 6.2): made once and read back, the signed exchange checked by an admin,
// a claim sealed to the one-time key and opened only by its holder, a
// rotation's statement followed from a pinned key, the helper mode's
// answers, and the key in device records and pairing keys. Demo keys only.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

const _crypto = TomSecretsPqcIdentityCrypto();

void main() {
  test('made at the first start, the user\'s alone, and the same at every '
      'later one; a file that cannot be read is never replaced', () async {
    final dir = scratch('identity');
    final first = await TomSecretsServiceIdentityKey.loadOrCreate(dir.path);
    addTearDown(first.dispose);
    expect(first.publicKey, hasLength(tomSecretsIdentityKeyLength));
    final file = File('${dir.path}/$tomSecretsServiceIdentityFile');
    expect(file.existsSync(), isTrue);
    if (!Platform.isWindows) {
      expect(file.statSync().mode & 0x1FF, 0x180, reason: '0600');
    }
    final again = await TomSecretsServiceIdentityKey.loadOrCreate(dir.path);
    addTearDown(again.dispose);
    expect(again.publicKey, first.publicKey);
    expect(again.created, first.created);
    expect(again.words, first.words);
    expect(again.words.split('-'), hasLength(8));

    final before = file.readAsStringSync();
    file.writeAsStringSync('{"version":1,"secretKey":"AAAA"}');
    await expectLater(
      TomSecretsServiceIdentityKey.loadOrCreate(dir.path),
      throwsA(isA<FileSystemException>()),
    );
    expect(file.readAsStringSync(), isNot(before), reason: 'left as it is');
    expect(file.readAsStringSync(), contains('AAAA'));
  });

  test('the exchange: the signature over both nonces, the start and the '
      'one-time key verifies under the key; not for another nonce, start, '
      'one-time key or key', () async {
    final key = await TomSecretsServiceIdentityKey.generate();
    addTearDown(key.dispose);
    final oneTime = await TomSecretsOneTimeKey.generate();
    addTearDown(oneTime.dispose);
    expect(oneTime.publicKey, hasLength(tomSecretsOneTimeKeyLength));
    final clientNonce = List.generate(32, (i) => i);
    final serviceNonce = List.generate(32, (i) => 100 + i);
    final answer = await key.present(
      clientNonce: clientNonce,
      serviceNonce: serviceNonce,
      serviceStart: 1700000000000,
      oneTimeKey: oneTime,
    );
    final publicKey = base64.decode(answer['publicKey']! as String);
    final signature = base64.decode(answer['signature']! as String);
    expect(publicKey, key.publicKey);
    Future<bool> valid({
      List<int>? nonce,
      int start = 1700000000000,
      Uint8List? otk,
      Uint8List? under,
    }) => _crypto.verify(
      publicKey: under ?? publicKey,
      message: tomSecretsIdentityMessage(
        clientNonce: nonce ?? clientNonce,
        serviceNonce: serviceNonce,
        serviceStart: start,
        oneTimeKey: otk ?? oneTime.publicKey,
      ),
      signature: signature,
      context: tomSecretsIdentityContext,
    );
    expect(await valid(), isTrue);
    expect(await valid(nonce: [...clientNonce]..[0] ^= 1), isFalse);
    expect(await valid(start: 1700000000001), isFalse);
    final other = await TomSecretsOneTimeKey.generate();
    addTearDown(other.dispose);
    expect(await valid(otk: other.publicKey), isFalse);
    final impostor = await TomSecretsServiceIdentityKey.generate();
    addTearDown(impostor.dispose);
    expect(await valid(under: impostor.publicKey), isFalse);
    // Not a signature of another kind of statement either.
    expect(
      await _crypto.verify(
        publicKey: publicKey,
        message: tomSecretsIdentityMessage(
          clientNonce: clientNonce,
          serviceNonce: serviceNonce,
          serviceStart: 1700000000000,
          oneTimeKey: oneTime.publicKey,
        ),
        signature: signature,
        context: tomSecretsIdentityChangeContext,
      ),
      isFalse,
    );
  });

  test('a claim sealed to the one-time key: its holder opens it; another '
      'one-time key, with every frame in hand, does not', () async {
    final oneTime = await TomSecretsOneTimeKey.generate();
    addTearDown(oneTime.dispose);
    final transcript = List.generate(200, (i) => i % 251);
    final sealedTo = await _crypto.encapsulate(oneTime.publicKey);
    final sealed = await tomSecretsSealClaim(
      sharedSecret: sealedTo.sharedSecret,
      kemCiphertext: sealedTo.ciphertext,
      transcript: transcript,
      password: 'demo-master-password',
      keyFile: [9, 8, 7],
    );
    expect(jsonEncode(sealed), isNot(contains('demo-master-password')));
    final opened = await tomSecretsOpenClaim(
      sharedSecret: await oneTime.decapsulate(
        base64.decode(sealed['kem']! as String),
      ),
      transcript: transcript,
      sealed: sealed,
    );
    expect(opened.password, 'demo-master-password');
    expect(opened.keyFile, [9, 8, 7]);

    // Whoever relays the exchange holds the frames and its own keys only.
    final relay = await TomSecretsOneTimeKey.generate();
    addTearDown(relay.dispose);
    await expectLater(
      () async => tomSecretsOpenClaim(
        sharedSecret: await relay.decapsulate(
          base64.decode(sealed['kem']! as String),
        ),
        transcript: transcript,
        sealed: sealed,
      ),
      throwsFormatException,
    );
  });

  test('a rotation: the old key signs the new one, the file holds the new '
      'key and the statements, and an admin that pinned any earlier key '
      'follows them; a pin of an unrelated key does not', () async {
    final dir = scratch('identity');
    var key = await TomSecretsServiceIdentityKey.loadOrCreate(dir.path);
    final first = Uint8List.fromList(key.publicKey);
    key = await key.rotate();
    final second = Uint8List.fromList(key.publicKey);
    key = await key.rotate();
    addTearDown(key.dispose);
    expect(key.publicKey, isNot(first));
    expect(key.changes, hasLength(2));
    final read = await TomSecretsServiceIdentityKey.loadOrCreate(dir.path);
    addTearDown(read.dispose);
    expect(read.publicKey, key.publicKey);
    expect(read.changes, hasLength(2));

    TomSecretsServicePin pin(Uint8List k) => TomSecretsServicePin(
      host: 'demo-host',
      runtime: '/run/demo',
      key: k,
      source: TomSecretsPinSource.start,
      at: DateTime.utc(2026),
    );
    Future<TomSecretsPinVerdict> judge(Uint8List pinned) =>
        tomSecretsJudgeIdentity(
          pinned: [pin(pinned)],
          presented: read.publicKey,
          changes: read.changes,
          crypto: _crypto,
        );
    expect(await judge(read.publicKey), TomSecretsPinVerdict.pinned);
    expect(await judge(second), TomSecretsPinVerdict.rotated);
    expect(await judge(first), TomSecretsPinVerdict.rotated);
    final stranger = await TomSecretsServiceIdentityKey.generate();
    addTearDown(stranger.dispose);
    expect(await judge(stranger.publicKey), TomSecretsPinVerdict.changed);
    // A statement whose signature is another key's leads nowhere.
    final forged = [
      TomSecretsIdentityChange(
        from: first,
        to: stranger.publicKey,
        signature: await stranger.sign(
          stranger.publicKey,
          tomSecretsIdentityChangeContext,
        ),
      ),
    ];
    expect(
      await tomSecretsJudgeIdentity(
        pinned: [pin(first)],
        presented: stranger.publicKey,
        changes: forged,
        crypto: _crypto,
      ),
      TomSecretsPinVerdict.changed,
    );
    expect(
      await tomSecretsJudgeIdentity(
        pinned: const [],
        presented: read.publicKey,
        changes: read.changes,
        crypto: _crypto,
      ),
      TomSecretsPinVerdict.unpinned,
    );
  });

  test('the helper mode\'s answers (what tsm asks the service executable '
      'for): verify and encapsulate, as the primitives in process', () async {
    final key = await TomSecretsServiceIdentityKey.generate();
    addTearDown(key.dispose);
    final message = Uint8List.fromList(List.generate(64, (i) => i));
    final signature = await key.sign(message, tomSecretsIdentityContext);
    Map<String, Object?> request(Uint8List m) => {
      'op': 'verify',
      'publicKey': base64.encode(key.publicKey),
      'message': base64.encode(m),
      'signature': base64.encode(signature),
      'context': base64.encode(tomSecretsIdentityContext),
    };
    expect(await tomSecretsIdentityHelperAnswer(request(message)), {
      'valid': true,
    });
    expect(
      await tomSecretsIdentityHelperAnswer(
        request(Uint8List.fromList([...message]..[1] ^= 1)),
      ),
      {'valid': false},
    );
    final oneTime = await TomSecretsOneTimeKey.generate();
    addTearDown(oneTime.dispose);
    final sealed = await tomSecretsIdentityHelperAnswer({
      'op': 'encapsulate',
      'publicKey': base64.encode(oneTime.publicKey),
    });
    expect(
      await oneTime.decapsulate(base64.decode(sealed['ciphertext']! as String)),
      base64.decode(sealed['sharedSecret']! as String),
    );
    expect(await tomSecretsIdentityHelperAnswer({'op': 'x'}), {
      'error': 'unsupported',
    });
    expect((await tomSecretsIdentityHelperAnswer('x'))['error'], 'malformed');
    expect(
      (await tomSecretsIdentityHelperAnswer({'op': 'verify'}))['error'],
      isNotNull,
    );
  });

  test(
    'the device record and the pairing keys carry the service\'s key',
    () async {
      final key = await TomSecretsServiceIdentityKey.generate();
      addTearDown(key.dispose);
      final text = base64.encode(key.publicKey);
      final file = newTestVault(demoCredentials, 'primary');
      final records = TomSecretsDeviceRecords(file);
      final at = DateTime.utc(2026, 11, 25);
      records.put(
        TomSecretsDeviceRecord(
          device: 'bigbeast',
          paired: at,
          serviceKey: text,
        ),
      );
      records.put(TomSecretsDeviceRecord(device: 'phone', paired: at));
      expect(records.byDevice('bigbeast')!.serviceKey, text);
      expect(records.byDevice('bigbeast')!.toJson()['serviceKey'], text);
      expect(records.byDevice('phone')!.serviceKey, isNull);
      // It stays through the changes that rewrite a record.
      records
        ..takeKeyIds('bigbeast', ['k1'], now: at)
        ..revoke('bigbeast', at);
      expect(records.byDevice('bigbeast')!.serviceKey, text);
      expect(
        records.byDevice('bigbeast')!.withGitHub(null, null).serviceKey,
        text,
      );
      expect(records.byDevice('phone')!.withServiceKey(text).serviceKey, text);

      final trust = TomSecretsTrust.create('bigbeast', now: at);
      final keys = TomSecretsPairingPeerKeys(
        linkKey: (await trust.linkKey()).publicKey,
        serviceKey: text,
      );
      final read = TomSecretsPairingPeerKeys.fromJson(
        (jsonDecode(jsonEncode(keys.toJson())) as Map).cast(),
      );
      expect(read.serviceKey, text);
      // An older peer names none; something that is no key is none.
      final older = (jsonDecode(jsonEncode(keys.toJson())) as Map)
        ..remove('serviceKey');
      expect(
        TomSecretsPairingPeerKeys.fromJson(older.cast()).serviceKey,
        isNull,
      );
      older['serviceKey'] = 'AAAA';
      expect(
        TomSecretsPairingPeerKeys.fromJson(older.cast()).serviceKey,
        isNull,
      );
    },
  );
}
