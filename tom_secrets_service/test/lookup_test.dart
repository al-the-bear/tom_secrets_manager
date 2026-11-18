// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The phase-B client messages (protocol.md 5.5, section 8): the features
/// the service offers in `welcome`, `getFile` over binary frames, `match`
/// (the browser host and the helpers; only the entries their grants cover;
/// no system vault for the browser host; audited) and `propose` (the
/// browser host with a grant; passed to the attached app). This test
/// process plays the browser host or a helper by its own executable. Demo
/// data only.
@TestOn('vm')
@Timeout(Duration(minutes: 2))
library;

import 'dart:async';
import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tom_secrets_client/tom_secrets_client.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/setup.dart';

/// A client connection that speaks frames by hand: `hello` without
/// features, `match` and `propose`, which the client library leaves to the
/// browser host and the helpers.
final class _Raw {
  _Raw._(this.socket) {
    socket.listen((bytes) {
      for (final f in reader.add(bytes)) {
        final m = tomSecretsDecodePayload(f.payload);
        if (waiting.isNotEmpty) {
          waiting.removeFirst().complete(m);
        } else {
          queue.add(m);
        }
      }
    });
  }

  static Future<_Raw> open(Demo demo, TomSecretsTransport transport) async {
    final runtime = demo.runtime(transport);
    final socket = transport == TomSecretsTransport.unix
        ? await Socket.connect(
            InternetAddress(
              runtime.clientSocket,
              type: InternetAddressType.unix,
            ),
            0,
          )
        : await Socket.connect(
            InternetAddress.loopbackIPv4,
            readTomSecretsPortFile(
              File(runtime.clientPortFile).readAsStringSync(),
            )!,
          );
    addTearDown(socket.destroy);
    return _Raw._(socket);
  }

  final Socket socket;
  final TomSecretsFrameReader reader = TomSecretsFrameReader(
    maxPayload: tomSecretsMaxAnswerPayload,
  );
  final Queue<Map<String, Object?>> queue = Queue();
  final Queue<Completer<Map<String, Object?>>> waiting = Queue();

  void send(Map<String, Object?> m) => socket.add(tomSecretsJsonFrame(m));

  Future<Map<String, Object?>> next() {
    if (queue.isNotEmpty) return Future.value(queue.removeFirst());
    final c = Completer<Map<String, Object?>>();
    waiting.add(c);
    return c.future.timeout(const Duration(seconds: 10));
  }

  /// Says hello (with [features]) and returns the welcome.
  Future<Map<String, Object?>> hello(
    TomSecretsService service, {
    List<String>? features,
  }) {
    send({
      'op': 'hello',
      'protocol': 1,
      'client': {'name': 'demo-host-extension', 'version': '1'},
      if (Platform.isWindows) 'token': service.clientToken,
      'features': ?features,
    });
    return next();
  }

  /// Sends [request] and returns its answer.
  Future<Map<String, Object?>> ask(Map<String, Object?> request) {
    send(request);
    return next();
  }
}

/// Adds a login [title] at [url] to [file], last used at [used].
KdbxEntry _login(KdbxFile file, String title, String url, {DateTime? used}) {
  final root = file.body.rootGroup;
  final entry = KdbxEntry.create(file, root)
    ..setString(KdbxKeyCommon.TITLE, PlainValue(title))
    ..setString(KdbxKeyCommon.USER_NAME, PlainValue('$title-user'))
    ..setString(KdbxKeyCommon.URL, PlainValue(url))
    ..setString(
      KdbxKeyCommon.PASSWORD,
      ProtectedValue.fromString('$title-demo-pw'),
    );
  if (used != null) entry.times.lastAccessTime.set(used);
  root.addEntry(entry);
  return entry;
}

void main() {
  final transport = Platform.isWindows
      ? TomSecretsTransport.tcp
      : TomSecretsTransport.unix;
  // This process, as the service measures it: the browser host or a helper
  // when the test names its executable so.
  final self = {tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!).exe};
  late Demo demo;
  late TomSecretsAdminClient admin;
  late Uint8List attachment;

  setUp(() async {
    demo = await Demo.create();
    // team: two logins and a key file attachment; primary: a system vault
    // with a login of the same site.
    final team = await KdbxFormat().read(
      File(demo.teamPath).readAsBytesSync(),
      tomSecretsVaultCredentials(password: teamPassword),
    );
    _login(team, 'Mail', 'https://mail.example.com');
    _login(team, 'Shop', 'https://shop.example.org');
    attachment = Uint8List.fromList(
      List.generate(300 * 1024 + 7, (i) => i % 251),
    );
    _login(
      team,
      'Deploy',
      'https://deploy.example.com',
      used: DateTime.utc(2026, 1, 1),
    ).createBinary(
      isProtected: true,
      name: 'id_ed25519',
      bytes: Uint8List.fromList(attachment),
    );
    File(demo.teamPath).writeAsBytesSync(await team.save());
    final primary = await KdbxFormat().read(
      File(demo.primaryPath).readAsBytesSync(),
      tomSecretsVaultCredentials(password: primaryPassword),
    );
    TomSecretsMetadata(kind: TomSecretsVaultKind.system).writeTo(primary);
    _login(
      primary,
      'Fleet',
      'https://example.com',
      used: DateTime.utc(2026, 6, 1),
    );
    File(demo.primaryPath).writeAsBytesSync(await primary.save());
  });

  Future<TomSecretsService> start({
    Set<String>? browserHosts,
    Set<String>? helpers,
    TomSecretsAccessPolicy? policy = const AllowAllPolicy(),
    bool subscribe = true,
  }) async {
    final service = await demo.start(
      transport: transport,
      policy: policy,
      browserHostExecutables: browserHosts ?? const {},
      helperExecutables: helpers ?? const {},
    );
    admin = await TomSecretsAdminClient.connect(
      demo.runtime(transport),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    if (subscribe) await admin.request('subscribe');
    return service;
  }

  test('welcome offers binary, getFile, match and propose; getFile streams '
      'an attachment in chunks with its name, size and sha256', () async {
    final service = await start();
    final raw = await _Raw.open(demo, transport);
    final welcome = await raw.hello(service);
    expect(welcome['features'], ['binary', 'getFile', 'match', 'propose']);

    final client = await TomSecretsClient.connect(
      clientName: 'demo-agent',
      environment: demo.clientEnvironment(),
    );
    addTearDown(client.close);
    final file = await client.getFile(
      'team/Deploy',
      field: 'attachment:id_ed25519',
    );
    expect(file.name, 'id_ed25519');
    expect(file.bytes, attachment);
    // More than one chunk: 300 KiB over 256 KiB chunks.
    expect(attachment.length, greaterThan(tomSecretsFileChunkSize));
  });

  test('getFile without the features binary and getFile in hello is '
      'unsupported; an unknown entry is not_found', () async {
    final service = await start();
    final raw = await _Raw.open(demo, transport);
    await raw.hello(service, features: ['getFile']);
    final refused = await raw.ask({
      'op': 'getFile',
      'id': 1,
      'ref': 'team/Deploy',
      'field': 'attachment:id_ed25519',
    });
    expect(refused['kind'], 'unsupported');
    expect((refused['details']! as Map)['features'], ['binary']);

    final client = await TomSecretsClient.connect(
      clientName: 'demo-agent',
      environment: demo.clientEnvironment(),
    );
    addTearDown(client.close);
    await expectLater(
      client.getFile('team/Nothing', field: 'attachment:x'),
      throwsA(
        isA<TomSecretsClientException>().having(
          (e) => e.kind,
          'kind',
          TomSecretsErrorKind.notFound,
        ),
      ),
    );
  });

  test('match for a helper: the logins of the site, system vaults '
      'included, never a value; audited', () async {
    final service = await start(helpers: self);
    final raw = await _Raw.open(demo, transport);
    await raw.hello(service);
    final answer = await raw.ask({
      'op': 'match',
      'id': 1,
      'url': 'https://mail.example.com/inbox',
    });
    expect(answer['op'], 'matches');
    final candidates = (answer['candidates']! as List).cast<Map>();
    expect(
      [for (final c in candidates) c['title']],
      ['Mail', 'Fleet', 'Deploy'],
    );
    final mail = candidates.first;
    expect(mail['userName'], 'Mail-user');
    expect(mail['matchedUrl'], 'https://mail.example.com');
    expect(mail['hasTotp'], isFalse);
    expect(mail['entryId'], matches(RegExp(r'^team/~[0-9a-f]{32}$')));
    expect(mail.containsKey('value'), isFalse);
    expect(mail.containsKey('password'), isFalse);
    // The entry id reads the entry (the fill's get).
    final client = await TomSecretsClient.connect(
      clientName: 'demo-helper',
      environment: demo.clientEnvironment(),
    );
    addTearDown(client.close);
    expect(
      (await client.get(mail['entryId']! as String, field: 'UserName')).text,
      'Mail-user',
    );
    final now = DateTime.now().toUtc();
    final audit = await admin.request('audit.query', {
      'from': now.subtract(const Duration(hours: 1)).toIso8601String(),
      'to': now.add(const Duration(hours: 1)).toIso8601String(),
    });
    final records = (audit['records']! as List).cast<Map>();
    final lookup = records.firstWhere(
      (r) => (r['refs']! as List).first == 'match mail.example.com',
    );
    expect(lookup['outcome'], 'matched');
    expect((lookup['entries']! as List), hasLength(3));
  });

  test('match for the browser host leaves system vaults out; any other '
      'client is denied (not_allowed_op); a frame of another site matches '
      'nothing', () async {
    final service = await start(browserHosts: self);
    final raw = await _Raw.open(demo, transport);
    await raw.hello(service);
    final answer = await raw.ask({
      'op': 'match',
      'id': 1,
      'url': 'https://mail.example.com/inbox',
    });
    expect(
      [for (final c in answer['candidates']! as List) c['title']],
      ['Mail', 'Deploy'],
    );
    final framed = await raw.ask({
      'op': 'match',
      'id': 2,
      'url': 'https://mail.example.com/',
      'frameUrl': 'https://evil.example.net/login',
    });
    expect(framed['candidates'], isEmpty);
    final bad = await raw.ask({'op': 'match', 'id': 3});
    expect(bad['kind'], 'malformed');
    await service.stop();

    // The new service's hello (on Windows its client token).
    final second = await start();
    final other = await _Raw.open(demo, transport);
    await other.hello(second);
    final denied = await other.ask({
      'op': 'match',
      'id': 1,
      'url': 'https://mail.example.com/',
    });
    expect(denied['kind'], 'denied');
    expect((denied['details']! as Map)['reason'], 'not_allowed_op');
  });

  test('match lists only what the grants cover: a store grant, a never '
      'grant for one entry', () async {
    final me = tomSecretsIdentityOf(tomSecretsProcessInfo(pid)!);
    final subject = me.kind == 'script'
        ? 'script ${me.interpreter} ${me.script}'
        : 'exe ${me.exe}';
    final service = await start(helpers: self, policy: null);
    final team = service.vaults.resolver!.stores.firstWhere(
      (s) => s.name == 'team',
    );
    final shop = team.entries.firstWhere((e) => e.entry.label == 'Deploy');
    for (final grant in [
      {'secret': 'store team', 'decision': 'allow'},
      {'secret': 'team/~${shop.uuid}#Password', 'decision': 'never'},
    ]) {
      await admin.request('grants.add', {
        'grant': {
          'host': 'demo-host',
          'subject': subject,
          'pin': 'off',
          ...grant,
        },
      });
    }
    final raw = await _Raw.open(demo, transport);
    await raw.hello(service);
    final answer = await raw.ask({
      'op': 'match',
      'id': 1,
      'url': 'https://mail.example.com/',
    });
    expect(
      [for (final c in answer['candidates']! as List) c['title']],
      ['Mail'],
    );
  });

  test('propose: the browser host with a grant reaches the attached app as '
      'proposal; with no app attached unavailable (no_app); a helper is '
      'denied', () async {
    final service = await start(browserHosts: self);
    final proposal = admin.events.firstWhere((e) => e['op'] == 'proposal');
    final raw = await _Raw.open(demo, transport);
    await raw.hello(service);
    final accepted = await raw.ask({
      'op': 'propose',
      'id': 1,
      'url': 'https://new.example.com/signup',
      'title': 'New site',
      'userName': 'demo-new-user',
      'password': 'demo-new-pw',
    });
    expect(accepted, {'op': 'accepted', 'id': 1});
    final event = await proposal;
    expect(event['url'], 'https://new.example.com/signup');
    expect(event['title'], 'New site');
    expect(event['userName'], 'demo-new-user');
    expect(event['password'], 'demo-new-pw');
    await service.stop();

    final quiet = await start(browserHosts: self, subscribe: false);
    final again = await _Raw.open(demo, transport);
    await again.hello(quiet);
    final dropped = await again.ask({
      'op': 'propose',
      'id': 1,
      'url': 'https://new.example.com/',
      'userName': 'u',
      'password': 'p',
    });
    expect(dropped['kind'], 'unavailable');
    expect((dropped['details']! as Map)['reason'], 'no_app');
    await quiet.stop();

    final helper = await start(helpers: self);
    final raw3 = await _Raw.open(demo, transport);
    await raw3.hello(helper);
    final denied = await raw3.ask({
      'op': 'propose',
      'id': 1,
      'url': 'https://new.example.com/',
      'userName': 'u',
      'password': 'p',
    });
    expect((denied['details']! as Map)['reason'], 'not_allowed_op');
  });

  test('propose needs an allow grant of the browser host', () async {
    final service = await start(browserHosts: self, policy: null);
    final raw = await _Raw.open(demo, transport);
    await raw.hello(service);
    final denied = await raw.ask({
      'op': 'propose',
      'id': 1,
      'url': 'https://new.example.com/',
      'userName': 'u',
      'password': 'p',
    });
    expect((denied['details']! as Map)['reason'], 'not_allowed_op');
  });
}
