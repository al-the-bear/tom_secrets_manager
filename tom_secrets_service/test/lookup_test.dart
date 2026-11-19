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

  test(
    'propose: the browser host with a grant reaches the attached app as '
    'proposal; with no app attached unavailable (no_app); a helper '
    "(git's store, DP-52): a known credential ignored, a new one proposed",
    () async {
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
      var proposed = 0;
      final sub = admin.events.listen((e) {
        if (e['op'] == 'proposal') proposed++;
      });
      final raw3 = await _Raw.open(demo, transport);
      await raw3.hello(helper);
      final known = await raw3.ask({
        'op': 'propose',
        'id': 1,
        'url': 'https://mail.example.com/',
        'userName': 'Mail-user',
        'password': 'Mail-demo-pw',
      });
      expect(known, {'op': 'accepted', 'id': 1, 'known': true});
      final changed = await raw3.ask({
        'op': 'propose',
        'id': 2,
        'url': 'https://mail.example.com/',
        'userName': 'Mail-user',
        'password': 'demo-new-pw',
      });
      expect(changed, {'op': 'accepted', 'id': 2});
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await sub.cancel();
      expect(proposed, 1);
    },
  );

  group('match with pick (a helper, part-os-integration)', () {
    /// Adds a second login of mail.example.com to the team vault.
    Future<String> secondMailLogin() async {
      final team = await KdbxFormat().read(
        File(demo.teamPath).readAsBytesSync(),
        tomSecretsVaultCredentials(password: teamPassword),
      );
      // Used long ago: the candidates are ordered by last use (5.7), so it
      // comes after Mail whether or not both were made in the same second.
      final work = _login(
        team,
        'Mail work',
        'https://mail.example.com/work',
        used: DateTime.utc(2020),
      );
      File(demo.teamPath).writeAsBytesSync(await team.save());
      return 'team/~${tomSecretsUuidHex(work.uuid)}';
    }

    /// The answer of [request], progress frames skipped.
    Future<Map<String, Object?>> answer(
      _Raw raw,
      Map<String, Object?> request,
    ) async {
      raw.send(request);
      while (true) {
        final m = await raw.next();
        if (m['op'] != 'progress') return m;
      }
    }

    test('no grant: the logins of the site at a pick prompt; always writes '
        'a grant for the pick, the next match answers it without asking, '
        'get reads it', () async {
      final work = await secondMailLogin();
      final service = await start(helpers: self, policy: null);
      final raw = await _Raw.open(demo, transport);
      await raw.hello(service);
      final needed = admin.events.firstWhere(
        (e) => e['op'] == 'approval_needed',
      );
      final matched = answer(raw, {
        'op': 'match',
        'id': 1,
        'url': 'https://mail.example.com/',
        'pick': true,
      });
      final event = await needed;
      expect(event['url'], 'https://mail.example.com/');
      final pick = (event['pick']! as List).cast<Map>();
      // The host rule: only mail.example.com's logins, not example.com's.
      expect([for (final p in pick) p['title']], ['Mail', 'Mail work']);
      expect(pick.last['entryId'], work);
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'always',
        'secret': 'ref',
        'pick': work,
      });
      final first = await matched;
      expect(
        [for (final c in first['candidates']! as List) c['entryId']],
        [work],
      );
      final grants = (await admin.request('grants.list'))['grants']! as List;
      expect(grants.map((g) => (g as Map)['secret']), contains(work));

      var prompted = false;
      final sub = admin.events.listen((e) {
        if (e['op'] == 'approval_needed') prompted = true;
      });
      final again = await answer(raw, {
        'op': 'match',
        'id': 2,
        'url': 'https://mail.example.com/',
        'pick': true,
      });
      expect(
        [for (final c in again['candidates']! as List) c['title']],
        ['Mail work'],
      );
      final value = await answer(raw, {'op': 'get', 'id': 3, 'ref': work});
      expect(value['op'], 'value');
      await sub.cancel();
      expect(prompted, isFalse);
    });

    test('once: this connection reads the pick once, a second get asks; '
        'userName narrows the logins; never answers none; no approver: '
        'none at once', () async {
      final work = await secondMailLogin();
      final service = await start(helpers: self, policy: null);
      final raw = await _Raw.open(demo, transport);
      await raw.hello(service);
      var needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
      final matched = answer(raw, {
        'op': 'match',
        'id': 1,
        'url': 'https://mail.example.com/',
        'userName': 'Mail work-user',
        'pick': true,
      });
      final event = await needed;
      expect((event['pick']! as List), hasLength(1));
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'once',
        'secret': 'ref',
        'pick': work,
      });
      expect(((await matched)['candidates']! as List), hasLength(1));
      final first = await answer(raw, {'op': 'get', 'id': 2, 'ref': work});
      expect(first['op'], 'value');
      needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
      final second = answer(raw, {'op': 'get', 'id': 3, 'ref': work});
      final ask = await needed;
      expect(ask['pick'], isNull, reason: 'a value prompt');
      await admin.request('approve', {
        'approvalId': ask['approvalId'],
        'decision': 'once',
        'secret': 'ref',
      });
      expect((await second)['op'], 'value');

      needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
      final refused = answer(raw, {
        'op': 'match',
        'id': 4,
        'url': 'https://mail.example.com/',
        'pick': true,
      });
      final ask2 = await needed;
      await admin.request('approve', {
        'approvalId': ask2['approvalId'],
        'decision': 'never',
        'secret': 'ref',
      });
      expect((await refused)['candidates'], isEmpty);
      // A never at a pick prompt writes nothing.
      expect((await admin.request('grants.list'))['grants'], isEmpty);
      await service.stop();

      final alone = await start(helpers: self, policy: null, subscribe: false);
      final raw2 = await _Raw.open(demo, transport);
      await raw2.hello(alone);
      final none = await answer(raw2, {
        'op': 'match',
        'id': 1,
        'url': 'https://mail.example.com/',
        'pick': true,
      });
      expect(none['candidates'], isEmpty);
    });

    test('pick is for the helpers: the browser host is denied', () async {
      final service = await start(browserHosts: self);
      final raw = await _Raw.open(demo, transport);
      await raw.hello(service);
      final denied = await answer(raw, {
        'op': 'match',
        'id': 1,
        'url': 'https://mail.example.com/',
        'pick': true,
      });
      expect((denied['details']! as Map)['reason'], 'not_allowed_op');
    });

    test('a helper call: a lasting grant names the tool that started it', () {
      final helper = TomSecretsIdentity.fromJson({
        'kind': 'exe',
        'exe': '/opt/tsm/bin/tsm',
        'args': ['get'],
        'cwd': '/home/demo/work',
        'parent': {'exe': '/usr/bin/git'},
      });
      expect(tomSecretsIsHelperCall(helper), isTrue);
      expect(
        tomSecretsGrantSubject(
          helper,
          const TomSecretsApprovalAnswer(
            decision: 'always',
            secret: 'ref',
            approver: 'demo',
          ),
        ),
        'exe-from /usr/bin/git => /opt/tsm/bin/tsm',
      );
      final shell = TomSecretsIdentity.fromJson({
        'kind': 'exe',
        'exe': '/opt/tsm/bin/tsm',
        'args': ['get', 'telegram.bot_token'],
        'cwd': '/home/demo/work',
        'parent': {'exe': '/bin/zsh'},
      });
      expect(tomSecretsIsHelperCall(shell), isFalse);
    });
  });

  group('match for the browser host without a grant (DP-44)', () {
    /// The answer of [request], progress frames skipped.
    Future<Map<String, Object?>> answer(
      _Raw raw,
      Map<String, Object?> request,
    ) async {
      raw.send(request);
      while (true) {
        final m = await raw.next();
        if (m['op'] != 'progress') return m;
      }
    }

    /// The reference of the system vault's login Fleet.
    String fleetOf(TomSecretsService service) {
      final system = service.vaults.resolver!.stores.firstWhere(
        (s) => s.metadata.kind == TomSecretsVaultKind.system,
      );
      final fleet = system.entries.firstWhere((e) => e.entry.label == 'Fleet');
      return '${system.name}/~${fleet.uuid}';
    }

    test('the first match asks for the page\'s personal and shared logins; '
        'always writes one grant for the host as started by its browser, '
        'the next match and get ask nothing; a system vault\'s value is '
        'refused whatever the grant says', () async {
      final service = await start(browserHosts: self, policy: null);
      final raw = await _Raw.open(demo, transport);
      await raw.hello(service);
      final needed = admin.events.firstWhere(
        (e) => e['op'] == 'approval_needed',
      );
      final matched = answer(raw, {
        'op': 'match',
        'id': 1,
        'url': 'https://mail.example.com/inbox',
      });
      final event = await needed;
      expect(event['browser'], isTrue);
      expect(event['url'], 'https://mail.example.com/inbox');
      expect(event['pick'], isNull);
      // The site's logins of the team vault; the system vault's Fleet is
      // never put to the user for the browser.
      expect([
        for (final r in (event['resolved']! as List).cast<Map>()) r['path'],
      ], unorderedEquals(['Mail', 'Deploy']));
      expect(
        (event['refs']! as List).every((r) => '$r'.startsWith('team/~')),
        isTrue,
      );
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'always',
        'secret': 'all',
        'pin': 'off',
      });
      final first = await matched;
      expect(
        [for (final c in first['candidates']! as List) c['title']],
        ['Mail', 'Deploy'],
      );
      final identity = TomSecretsIdentity.fromJson(
        (event['identity']! as Map).cast<String, Object?>(),
      );
      final grants = ((await admin.request('grants.list'))['grants']! as List)
          .cast<Map>();
      expect(grants, hasLength(1));
      expect(grants.single['secret'], 'all');
      expect(
        grants.single['subject'],
        tomSecretsGrantSubject(
          identity,
          const TomSecretsApprovalAnswer(
            decision: 'always',
            secret: 'all',
            approver: 'demo',
          ),
          browser: true,
        ),
      );

      var prompted = false;
      final sub = admin.events.listen((e) {
        if (e['op'] == 'approval_needed') prompted = true;
      });
      final again = await answer(raw, {
        'op': 'match',
        'id': 2,
        'url': 'https://mail.example.com/',
      });
      expect((again['candidates']! as List), hasLength(2));
      final mail = (again['candidates']! as List).cast<Map>().first['entryId'];
      final values = await answer(raw, {
        'op': 'getMany',
        'id': 3,
        'refs': [
          {'ref': mail, 'field': 'Password'},
          {'ref': fleetOf(service), 'field': 'Password'},
        ],
      });
      final results = (values['results']! as List).cast<Map>();
      expect(results.first['op'], 'value');
      expect(results.last['kind'], 'denied');
      expect((results.last['details']! as Map)['reason'], 'system_vault');
      final single = await answer(raw, {
        'op': 'get',
        'id': 4,
        'ref': fleetOf(service),
      });
      expect((single['details']! as Map)['reason'], 'system_vault');
      await sub.cancel();
      expect(prompted, isFalse);
    });

    test('once: the logins are listed and each read once, also by another '
        'host process of the same browser (the fill), nothing written; a '
        'second read asks again', () async {
      final service = await start(browserHosts: self, policy: null);
      final raw = await _Raw.open(demo, transport);
      await raw.hello(service);
      var needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
      final matched = answer(raw, {
        'op': 'match',
        'id': 1,
        'url': 'https://mail.example.com/',
      });
      final event = await needed;
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'once',
        'secret': 'ref',
      });
      final mail = ((await matched)['candidates']! as List)
          .cast<Map>()
          .firstWhere((c) => c['title'] == 'Mail')['entryId'];
      expect((await admin.request('grants.list'))['grants'], isEmpty);

      // The fill: a new host process, a new connection.
      final fill = await _Raw.open(demo, transport);
      await fill.hello(service);
      var prompted = false;
      final sub = admin.events.listen((e) {
        if (e['op'] == 'approval_needed') prompted = true;
      });
      final listed = await answer(fill, {
        'op': 'match',
        'id': 1,
        'url': 'https://mail.example.com/',
      });
      expect((listed['candidates']! as List), hasLength(2));
      final values = await answer(fill, {
        'op': 'getMany',
        'id': 2,
        'refs': [
          {'ref': mail, 'field': 'UserName'},
          {'ref': mail, 'field': 'Password'},
        ],
      });
      expect(
        [for (final r in (values['results']! as List).cast<Map>()) r['op']],
        ['value', 'value'],
      );
      await sub.cancel();
      expect(prompted, isFalse);

      needed = admin.events.firstWhere((e) => e['op'] == 'approval_needed');
      final second = answer(fill, {
        'op': 'get',
        'id': 3,
        'ref': mail,
        'field': 'Password',
      });
      final ask = await needed;
      expect(ask['browser'], isNull, reason: 'a value prompt');
      await admin.request('approve', {
        'approvalId': ask['approvalId'],
        'decision': 'never',
        'secret': 'ref',
      });
      expect((await second)['kind'], 'denied');
    });

    test('never lists none and asks no more; a folder answer is refused; '
        'no approver connected: none at once', () async {
      final service = await start(browserHosts: self, policy: null);
      final raw = await _Raw.open(demo, transport);
      await raw.hello(service);
      final needed = admin.events.firstWhere(
        (e) => e['op'] == 'approval_needed',
      );
      final matched = answer(raw, {
        'op': 'match',
        'id': 1,
        'url': 'https://mail.example.com/',
      });
      final event = await needed;
      await expectLater(
        admin.request('approve', {
          'approvalId': event['approvalId'],
          'decision': 'folder',
          'secret': 'all',
          'folder': '/opt',
        }),
        throwsA(
          isA<TomSecretsAdminException>().having(
            (e) => e.kind,
            'kind',
            'malformed',
          ),
        ),
      );
      await admin.request('approve', {
        'approvalId': event['approvalId'],
        'decision': 'never',
        'secret': 'all',
      });
      expect((await matched)['candidates'], isEmpty);
      final grants = ((await admin.request('grants.list'))['grants']! as List)
          .cast<Map>();
      expect(grants.single['decision'], 'never');

      var prompted = false;
      final sub = admin.events.listen((e) {
        if (e['op'] == 'approval_needed') prompted = true;
      });
      final again = await answer(raw, {
        'op': 'match',
        'id': 2,
        'url': 'https://mail.example.com/',
      });
      expect(again['candidates'], isEmpty);
      await sub.cancel();
      expect(prompted, isFalse);
      await service.stop();

      final alone = await start(
        browserHosts: self,
        policy: null,
        subscribe: false,
      );
      final raw2 = await _Raw.open(demo, transport);
      await raw2.hello(alone);
      final none = await answer(raw2, {
        'op': 'match',
        'id': 1,
        'url': 'https://shop.example.org/',
      });
      expect(none['candidates'], isEmpty);
    });

    test('the browser host\'s lasting grants name its browser', () {
      const always = TomSecretsApprovalAnswer(
        decision: 'always',
        secret: 'all',
        approver: 'demo',
      );
      final host = TomSecretsIdentity.fromJson({
        'kind': 'exe',
        'exe': '/opt/tsm/bin/tsm-browser-host',
        'args': ['chrome-extension://lcejninmlbnhfnpedlgjjfeelhbgmach/'],
        'cwd': '/',
        'parent': {'exe': '/opt/google/chrome/chrome'},
      });
      expect(
        tomSecretsGrantSubject(host, always, browser: true),
        'exe-from /opt/google/chrome/chrome => /opt/tsm/bin/tsm-browser-host',
      );
      expect(
        tomSecretsGrantSubject(host, always),
        'exe /opt/tsm/bin/tsm-browser-host',
      );
      final unmeasured = TomSecretsIdentity.fromJson({
        'kind': 'exe',
        'exe': '/opt/tsm/bin/tsm-browser-host',
        'args': const <String>[],
        'cwd': '/',
      });
      expect(
        tomSecretsGrantSubject(unmeasured, always, browser: true),
        'exe /opt/tsm/bin/tsm-browser-host',
      );
    });

    test('on Windows a browser starts the host through cmd: the browser is '
        'the launcher', () {
      TomSecretsProcessInfo info(int pid, String exe, int? parent) =>
          TomSecretsProcessInfo(
            pid: pid,
            exe: exe,
            args: const [],
            cwd: r'C:\',
            startTime: pid,
            parentPid: parent,
            uid: 'S-1-5-21-demo',
          );
      final chrome = info(10, r'C:\Program Files\Google\Chrome\chrome.exe', 1);
      final cmd = info(11, r'C:\Windows\System32\cmd.exe', 10);
      final host = info(12, r'C:\tsm\bin\tsm-browser-host.exe', 11);
      final processes = {10: chrome, 11: cmd};
      expect(tomSecretsLauncherOf(host, cmd, (p) => processes[p]), chrome);
      // Its shell's parent unreadable: the shell.
      expect(tomSecretsLauncherOf(host, cmd, (_) => null), cmd);
      // Started directly (Firefox), or another program under cmd: the parent.
      expect(tomSecretsLauncherOf(host, chrome, (p) => processes[p]), chrome);
      final tsm = info(13, r'C:\tsm\bin\tsm.exe', 11);
      expect(tomSecretsLauncherOf(tsm, cmd, (p) => processes[p]), cmd);
      expect(tomSecretsLauncherOf(host, null, (p) => processes[p]), isNull);
    });
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
