// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A vault file as its store keeps it (protocol.md 6.4): a plain `.kdbx` and
/// a `.tsmx` under the outer key, opened with a password and a key file and
/// written back the same way. Demo data under demo keys.
library;

import 'package:test/test.dart';
import 'package:tom_core_storage/tom_core_storage.dart'
    show TomKeyRequiredException;
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

void main() {
  final keyFile = TomSecretsKeyFile.generate();
  final credentials = tomSecretsVaultCredentials(
    password: 'demo-password',
    keyFile: keyFile.toBytes(),
  );

  test('a plain .kdbx: read, edited and written back', () async {
    final vault = newTestVault(credentials, 'demo');
    final stored = await vault.save();
    const locator = 'file:/demo/vaults/demo.kdbx';
    final file = await tomSecretsDecodeStored(locator, stored, credentials);
    file.body.rootGroup.addEntry(
      KdbxEntry.create(file, file.body.rootGroup)..label = 'Added',
    );
    final again = await tomSecretsEncodeStored(locator, file);
    final reread = await tomSecretsDecodeStored(locator, again, credentials);
    expect(
      reread.body.rootGroup.getAllEntries().map((e) => e.label),
      contains('Added'),
    );
  });

  test('a .tsmx under the outer key; without the key or with the wrong '
      'password it does not open', () async {
    final outerKey = TomSecretsRepositoryKey.generate().toBase64();
    const locator = 'github:al-the-bear/demo-vault/demo.kdbx.tsmx';
    final vault = newTestVault(credentials, 'demo');
    final stored = await tomSecretsEncodeStored(
      locator,
      vault,
      outerKey: outerKey,
    );
    expect(stored.sublist(0, 4), isNot(equals(await vault.save())));
    final file = await tomSecretsDecodeStored(
      locator,
      stored,
      credentials,
      outerKey: outerKey,
    );
    expect(file.body.rootGroup.name.get(), 'demo');
    await expectLater(
      tomSecretsDecodeStored(locator, stored, credentials),
      throwsA(isA<TomKeyRequiredException>()),
    );
    await expectLater(
      tomSecretsDecodeStored(
        locator,
        stored,
        tomSecretsVaultCredentials(password: 'wrong'),
        outerKey: outerKey,
      ),
      throwsA(isA<KdbxInvalidKeyException>()),
    );
  });

  test('a rewrite keeps the repository\'s cipher: AES-256-GCM written, '
      'read and written again stays AES-256-GCM', () async {
    final outerKey = TomSecretsRepositoryKey.generate().toBase64();
    const locator = 'file:/demo/vaults/demo.kdbx.tsmx';
    final vault = newTestVault(credentials, 'demo');
    final aes = await tomSecretsEncodeStored(
      locator,
      vault,
      outerKey: outerKey,
      cipher: TomSecretsOuterCipher.aes256Gcm,
    );
    expect(tomSecretsOuterCipherOf(aes), TomSecretsOuterCipher.aes256Gcm);
    final again = await tomSecretsEncodeStored(
      locator,
      vault,
      outerKey: outerKey,
      like: aes,
    );
    expect(tomSecretsOuterCipherOf(again), TomSecretsOuterCipher.aes256Gcm);
    final codec = tomSecretsOuterCodecFor('demo.kdbx.tsmx', outerKey)!;
    expect(codec.written, TomSecretsOuterCipher.xchacha20Poly1305);
    await codec.decode(aes);
    expect(codec.written, TomSecretsOuterCipher.aes256Gcm);
    expect(
      tomSecretsOuterCipherOf(await codec.encode(await vault.save())),
      TomSecretsOuterCipher.aes256Gcm,
    );
  });

  test('the outer codec only for a .tsmx file', () {
    expect(tomSecretsOuterCodecFor('a.kdbx', null), isNull);
    expect(tomSecretsOuterCodecFor('a.kdbx.tsmx', null), isNotNull);
  });

  test('the composite key (the OS unlock\'s, DP-72) opens a .tsmx made with '
      'the password and the key file, and a rewrite under it still opens '
      'with them', () async {
    final outerKey = TomSecretsRepositoryKey.generate().toBase64();
    const locator = 'github:al-the-bear/demo-vault/demo.kdbx.tsmx';
    final stored = await tomSecretsEncodeStored(
      locator,
      newTestVault(credentials, 'demo'),
      outerKey: outerKey,
    );
    final composite = tomSecretsCompositeKey(
      password: 'demo-password',
      keyFile: keyFile.toBytes(),
    );
    expect(composite, hasLength(32));
    expect(composite, credentials.getHash());
    final viaComposite = tomSecretsVaultCredentials(compositeKey: composite);
    final file = await tomSecretsDecodeStored(
      locator,
      stored,
      viaComposite,
      outerKey: outerKey,
    );
    final rewritten = await tomSecretsEncodeStored(
      locator,
      file,
      outerKey: outerKey,
    );
    final again = await tomSecretsDecodeStored(
      locator,
      rewritten,
      credentials,
      outerKey: outerKey,
    );
    expect(again.body.rootGroup.name.get(), 'demo');
    expect(tomSecretsCompositeKey(password: 'demo-password'), isNot(composite));
  });
}
