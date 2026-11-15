// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// A device rotating its own key pairs (part-key-rotation): the approver
/// key with its key-change statement (signed by the old and the new pair,
/// four signatures, accepted against the old key), and the approval-link
/// key with its migration period (the previous key used for the hosts the
/// new one has not reached, dropped once all have it or the period is
/// over), kept across the stored JSON. Demo data only.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

void main() {
  final t0 = DateTime.utc(2026, 11, 15, 12);

  TomSecretsTrust trust() =>
      TomSecretsTrust.create('mbp', now: t0)
        ..hosts.addAll([
          for (final h in ['bigbeast', 'legiondary01'])
            TomSecretsRecordedHost(
              host: h,
              linkKey: TomSecretsLinkPublicKey(
                Uint8List(32)..[0] = 1,
                Uint8List(1184)..[0] = 1,
              ),
              tokenKey: Uint8List(32),
            ),
        ]);

  test('the approver key: a new pair, the statement signed four times, '
      'accepted against the old key only', () async {
    final t = trust();
    final old = (await t.approverKey()).publicKey;
    final at = t0.add(const Duration(days: 700));
    final statement = await t.rotateApproverKey(now: at);
    final fresh = (await t.approverKey()).publicKey;
    expect(fresh.keyId, isNot(old.keyId));
    expect(t.approverKeySince, at);
    expect(statement['device'], 'mbp');
    expect(statement['oldKeyId'], old.keyId);
    expect(statement['newKeyId'], fresh.keyId);
    expect(statement['time'], at.toIso8601String());
    final signatures = (statement['signatures']! as List).cast<Map>();
    expect(signatures, hasLength(4));
    expect(
      {for (final s in signatures) '${s['keyId']}/${s['alg']}'},
      {
        '${old.keyId}/ed25519',
        '${old.keyId}/ml-dsa-65',
        '${fresh.keyId}/ed25519',
        '${fresh.keyId}/ml-dsa-65',
      },
    );
    final accepted = await tomSecretsAcceptKeyChange(statement, old);
    expect(accepted?.keyId, fresh.keyId);
    expect(await tomSecretsAcceptKeyChange(statement, fresh), isNull);
    final forged = {...statement, 'time': t0.toIso8601String()};
    expect(await tomSecretsAcceptKeyChange(forged, old), isNull);
  });

  test('the link key: the previous one for the hosts not reached, during '
      'the migration period; dropped once all have it', () async {
    final t = trust();
    final old = (await t.linkKey()).publicKey;
    t.rotateLinkKey(now: t0);
    final fresh = (await t.linkKey()).publicKey;
    expect(base64.encode(fresh.x25519), isNot(base64.encode(old.x25519)));
    expect(t.linkKeySince, t0);
    expect(t.previousLinkUntil, t0.add(tomSecretsLinkKeyMigration));
    expect(t.linkKeyPending.map((h) => h.host), ['bigbeast', 'legiondary01']);
    Future<String> keyFor(String host, DateTime at) async =>
        base64.encode((await t.linkKeyFor(host, now: at)).publicKey.x25519);
    final soon = t0.add(const Duration(days: 1));
    expect(await keyFor('bigbeast', soon), base64.encode(old.x25519));

    t.markLinkKeyDelivered('bigbeast');
    expect(await keyFor('bigbeast', soon), base64.encode(fresh.x25519));
    expect(await keyFor('legiondary01', soon), base64.encode(old.x25519));

    // Kept across the stored JSON.
    final again = TomSecretsTrust.fromJson(
      (jsonDecode(jsonEncode(t.toJson())) as Map).cast(),
    );
    expect(again.linkKeyPending.map((h) => h.host), ['legiondary01']);
    expect(
      base64.encode(
        (await again.linkKeyFor('legiondary01', now: soon)).publicKey.x25519,
      ),
      base64.encode(old.x25519),
    );

    t.markLinkKeyDelivered('legiondary01');
    expect(t.linkKeyPending, isEmpty);
    expect(t.previousLinkUntil, isNull, reason: 'dropped once all have it');
    expect(t.toJson().containsKey('previousLinkSeeds'), isFalse);
    expect(await t.previousLinkKey(now: soon), isNull);
  });

  test('with an approver recorded the previous key stays to the end of the '
      'period: it answers that approver as a host', () async {
    final t = trust()
      ..approvers.add(
        TomSecretsRecordedApprover(
          device: 'bomber',
          approverKey: (await TomSecretsTrust.create(
            'bomber',
          ).approverKey()).publicKey,
          tokenKey: Uint8List(32),
        ),
      );
    final old = base64.encode((await t.linkKey()).publicKey.x25519);
    t
      ..rotateLinkKey(now: t0)
      ..markLinkKeyDelivered('bigbeast')
      ..markLinkKeyDelivered('legiondary01');
    final soon = t0.add(const Duration(days: 3));
    expect(
      base64.encode((await t.previousLinkKey(now: soon))!.publicKey.x25519),
      old,
    );
    expect(t.expirePreviousLinkKey(soon), isFalse);
    expect(t.expirePreviousLinkKey(t0.add(tomSecretsLinkKeyMigration)), isTrue);
    expect(await t.previousLinkKey(now: soon), isNull);
  });

  test('the migration period over: the current key for every host, the '
      'previous one dropped', () async {
    final t = trust()..rotateLinkKey(now: t0);
    final fresh = base64.encode((await t.linkKey()).publicKey.x25519);
    final after = t0.add(tomSecretsLinkKeyMigration);
    expect(
      base64.encode(
        (await t.linkKeyFor('bigbeast', now: after)).publicKey.x25519,
      ),
      fresh,
    );
    expect(t.expirePreviousLinkKey(after), isTrue);
    expect(t.linkKeyPending, isEmpty);
    expect(t.expirePreviousLinkKey(after), isFalse);
  });
}
