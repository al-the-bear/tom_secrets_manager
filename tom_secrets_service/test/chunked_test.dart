// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Chunked members on the admin endpoint (protocol.md 2.7): a vault far over
/// the frame limits is saved and read back through an admin that agreed on
/// them; an admin that did not is refused the large file (`too_large`) and
/// closed when it sends chunks; and nobody is read in chunks before the
/// authentication. Demo data only.
@TestOn('vm')
@Timeout(Duration(minutes: 3))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:tom_secrets_client/admin.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// A raw admin connection: frames in and out, nothing chunked unless told.
final class _Raw {
  _Raw._(this.socket);

  final Socket socket;
  final _reader = TomSecretsFrameReader(maxPayload: tomSecretsMaxAnswerPayload)
    ..binaryAllowed = true;
  final _messages = StreamController<Map<String, Object?>>();
  late final StreamIterator<Map<String, Object?>> _next = StreamIterator(
    _messages.stream,
  );
  bool closed = false;

  static Future<_Raw> open(TomSecretsRuntime runtime) async {
    final socket = Platform.isWindows
        ? await Socket.connect(
            InternetAddress.loopbackIPv4,
            readTomSecretsPortFile(
                  await File(runtime.adminPortFile).readAsString(),
                ) ??
                0,
          )
        : await Socket.connect(
            InternetAddress(
              runtime.adminSocket,
              type: InternetAddressType.unix,
            ),
            0,
          );
    final raw = _Raw._(socket);
    socket.listen(
      (bytes) {
        for (final f in raw._reader.add(bytes)) {
          if (f.type == tomSecretsFrameJson) {
            raw._messages.add(tomSecretsDecodePayload(f.payload));
          }
        }
      },
      onDone: () {
        raw.closed = true;
        unawaited(raw._messages.close());
      },
      onError: (Object _) {},
    );
    return raw;
  }

  Future<Map<String, Object?>?> next() async =>
      await _next.moveNext() ? _next.current : null;

  /// Authenticates with [adminKey], offering [features].
  Future<void> auth(Uint8List adminKey, List<String> features) async {
    final challenge = (await next())!;
    expect(challenge['features'], contains(tomSecretsChunkedFeature));
    final adminNonce = tomSecretsRandomBytes();
    socket.add(
      tomSecretsJsonFrame({
        'op': 'auth',
        'adminNonce': base64.encode(adminNonce),
        'mac': base64.encode(
          tomSecretsChallengeMac(
            adminKey,
            tomSecretsAdminLabel,
            base64.decode(challenge['serviceNonce']! as String),
            adminNonce,
            challenge['serviceStart']! as int,
          ),
        ),
        'client': {'name': 'tsm'},
        'features': features,
      }),
    );
    expect((await next())!['op'], 'authed');
  }

  Future<void> close() => socket.close();
}

/// The team vault at [path] with [count] more entries, notes of
/// [noteBytes] each.
Future<Uint8List> _bigTeam(String path, int count, int noteBytes) async {
  final file = await KdbxFormat().read(
    await File(path).readAsBytes(),
    Credentials(ProtectedValue.fromString(teamPassword)),
  );
  final group = file.body.rootGroup;
  final random = Random(count);
  for (var i = 0; i < count; i++) {
    group.addEntry(
      KdbxEntry.create(file, group)
        ..setString(KdbxKeyCommon.TITLE, PlainValue('Demo $i'))
        ..setString(KdbxKeyCommon.USER_NAME, PlainValue('user$i'))
        ..setString(
          KdbxKeyCommon.PASSWORD,
          ProtectedValue.fromString('demo-password-$i'),
        )
        ..setString(
          KdbxKeyCommon.NOTES,
          // Random letters: the file's compression keeps them large.
          PlainValue(
            String.fromCharCodes(
              List.generate(noteBytes, (_) => 0x41 + random.nextInt(26)),
            ),
          ),
        ),
    );
  }
  return file.save();
}

void main() {
  late Demo demo;
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;

  setUp(() async {
    demo = await Demo.create();
    await demo.start(transport: transport);
  });

  test('1,000 entries, over 1 MiB, saved and read back in chunks', () async {
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    expect(admin.sendsChunked, isTrue);
    await admin.unlock(primaryPassword);

    final first = await admin.request('vaultFile', {'store': 'team'});
    final big = await _bigTeam(demo.teamPath, 1000, 2000);
    // Over both frame limits, as base64 too.
    expect(big.length, greaterThan(tomSecretsMaxAnswerPayload));
    await admin.request('save', {
      'store': 'team',
      'bytes': base64.encode(big),
      'baseRevision': first['revision'],
    });
    final read = await admin.request('vaultFile', {'store': 'team'});
    final opened = await KdbxFormat().read(
      base64.decode(read['bytes']! as String),
      Credentials(ProtectedValue.fromString(teamPassword)),
    );
    expect(opened.body.rootGroup.getAllEntries().length, greaterThan(1000));

    // The connection goes on after both.
    expect((await admin.request('status'))['op'], 'statusReport');
    final client = await TomSecretsClient.connect(
      clientName: 'demo-client',
      environment: demo.clientEnvironment(),
    );
    addTearDown(client.close);
    expect((await client.get('team/Api/Token')).text, 'demo-api-token');
  });

  test('an admin without the feature: the large file refused, chunks '
      'closed', () async {
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    final first = await admin.request('vaultFile', {'store': 'team'});
    await admin.request('save', {
      'store': 'team',
      'bytes': base64.encode(await _bigTeam(demo.teamPath, 1000, 2000)),
      'baseRevision': first['revision'],
    });

    final raw = await _Raw.open(demo.runtime(transport));
    addTearDown(raw.close);
    await raw.auth(demo.adminKey, const []);
    raw.socket.add(
      tomSecretsJsonFrame({'op': 'vaultFile', 'id': 1, 'store': 'team'}),
    );
    var refused = (await raw.next())!;
    while (refused['id'] != 1) {
      refused = (await raw.next())!; // events
    }
    expect(refused['kind'], 'unsupported');
    expect((refused['details']! as Map)['reason'], 'too_large');

    raw.socket.add(
      tomSecretsJsonFrame({
        'op': 'status',
        'id': 2,
        'chunked': [
          {'name': 'x', 'size': 4, 'sha256': '0' * 64},
        ],
      }),
    );
    var error = (await raw.next())!;
    while (error['op'] != 'error') {
      error = (await raw.next())!;
    }
    expect((error['details']! as Map)['reason'], 'frame');
    expect(await raw.next(), isNull);
    expect(raw.closed, isTrue);
  });

  test('before the authentication nothing is read in chunks', () async {
    final raw = await _Raw.open(demo.runtime(transport));
    addTearDown(raw.close);
    await raw.next(); // the challenge
    raw.socket.add(
      tomSecretsJsonFrame({
        'op': 'auth',
        'chunked': [
          {'name': 'mac', 'size': 4, 'sha256': '0' * 64},
        ],
      }),
    );
    await raw.next(); // the error
    expect(await raw.next(), isNull);
    expect(raw.closed, isTrue);
  });
}
