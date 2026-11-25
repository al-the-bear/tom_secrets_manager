// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The transcripts of the operator's guide (`doc/user_guide.md`): each block
/// marked `<!-- transcript <name> -->` shows what a demo service leaves for
/// its operator to read (the runtime and data directories, `service.json`,
/// the operational log, a `status` report), and this test checks the guide
/// still shows it. `TSM_UPDATE_TRANSCRIPTS=1 dart test
/// test/guide_transcripts_test.dart` writes them into the guide instead.
///
/// The demo's scratch paths are written as a user's would read (`/home/demo
/// /…`), and what changes from run to run (process ids, times, version
/// numbers that follow the release) as fixed values, so a transcript
/// changes only when what the service writes does. Demo data only.
@TestOn('mac-os || linux')
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

import 'support/raw_client.dart';
import 'support/setup.dart';

/// The guide the transcripts are in.
const guide = 'doc/user_guide.md';

/// [text] with the fenced block after `<!-- transcript [name] -->` replaced
/// by [body]; throws when the marker or its block is missing.
String replaceTranscript(String text, String name, String body) {
  final marker = '<!-- transcript $name -->';
  final at = text.indexOf(marker);
  if (at < 0) throw StateError('$guide has no $marker');
  final open = text.indexOf('```text\n', at);
  final close = open < 0 ? -1 : text.indexOf('\n```', open + 7);
  if (open < 0 ||
      close < 0 ||
      text.substring(at + marker.length, open).trim().isNotEmpty) {
    throw StateError('$marker is not followed by a ```text block');
  }
  return '${text.substring(0, open + 8)}$body${text.substring(close)}';
}

/// [text] with the scratch [paths] (longest first) replaced by the paths
/// they stand for, and the values that change from run to run fixed: a
/// time as `2026-11-24T09:00:00.000Z` (an epoch in milliseconds as its
/// value), a process id as 4242, the service's version as `<version>`
/// (in JSON and in a log line), the platform as `linux` like the paths.
String normalize(String text, Map<String, String> paths) {
  var out = text;
  for (final p
      in paths.keys.toList()..sort((a, b) => b.length.compareTo(a.length))) {
    out = out.replaceAll(p, paths[p]!);
  }
  return out
      .replaceAll(
        RegExp(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z'),
        '2026-11-24T09:00:00.000Z',
      )
      .replaceAll(RegExp(r'"start": \d+'), '"start": 1795510800000')
      .replaceAll(RegExp(r'"pid": \d+'), '"pid": 4242')
      // The identity key is made anew for every demo installation.
      .replaceAll(
        RegExp(r'"fingerprint": "[0-9a-f]{64}"'),
        '"fingerprint": "${'5c1e' * 16}"',
      )
      .replaceAll(
        RegExp(r'"words": "[a-z-]+"'),
        '"words": "harbor-violet-cedar-lantern-maple-orbit-pebble-quill"',
      )
      .replaceAll(RegExp(r'"version": "[0-9.]+"'), '"version": "<version>"')
      .replaceAll(RegExp(r'\bversion=[0-9.]+'), 'version=<version>')
      .replaceAll(RegExp(r'\bpid=\d+'), 'pid=4242')
      // The paths shown are Linux's; so is the platform.
      .replaceAll(RegExp(r'\bplatform=\w+'), 'platform=linux');
}

/// The entries of [dir] as `ls -l` shows their kind and mode, and their
/// names, sorted; folders end in `/`.
String listing(String dir) {
  final entries = Directory(dir).listSync()
    ..sort((a, b) => a.path.compareTo(b.path));
  return [
    for (final e in entries)
      '${_kind(e)}${e.statSync().modeString()}  '
          '${e.uri.pathSegments.lastWhere((s) => s.isNotEmpty)}'
          '${e is Directory ? '/' : ''}',
  ].join('\n');
}

String _kind(FileSystemEntity e) =>
    switch (FileSystemEntity.typeSync(e.path, followLinks: false)) {
      FileSystemEntityType.directory => 'd',
      FileSystemEntityType.unixDomainSock => 's',
      _ => '-',
    };

void main() {
  test('the guide shows what the service leaves for its operator', () async {
    // The binary hardens its process before it starts (umask 077 among it,
    // so its files are 0600); this test process does the same, so the
    // listings show the modes an operator sees.
    tomSecretsHardenProcess();
    final demo = await Demo.create();
    final service = await demo.start();
    final admin = await TomSecretsAdminClient.connect(
      demo.runtime(),
      demo.adminKey,
    );
    addTearDown(admin.close);
    await admin.unlock(primaryPassword);
    final client = await RawClient.open(demo, TomSecretsTransport.unix);
    await client.hello(service);
    expect(
      await client.ask({'op': 'get', 'id': 1, 'ref': 'team/Api/Token'}),
      containsPair('op', 'value'),
    );
    final status = await admin.request('status');
    await admin.request('lock');

    final run = '${demo.dir}/run';
    final data = '${demo.dir}/data';
    final paths = {
      run: '/run/user/1000/tsm',
      data: '/home/demo/.local/share/tom-secrets-manager',
      demo.dir: '/home/demo/vaults',
    };
    final log = File('$data/service.log').readAsLinesSync();
    final sessions = <String, String>{
      'runtime-directory': '\$ ls -l /run/user/1000/tsm\n${listing(run)}',
      'service-json':
          '\$ cat /run/user/1000/tsm/service.json\n'
          '${const JsonEncoder.withIndent('  ').convert(jsonDecode(File('$run/service.json').readAsStringSync()))}',
      'data-directory':
          '\$ ls -l /home/demo/.local/share/tom-secrets-manager\n'
          '${listing(data)}',
      'service-log':
          '\$ cat /home/demo/.local/share/tom-secrets-manager/service.log\n'
          '${log.join('\n')}',
      'status':
          '\$ tsm status --json\n${const JsonEncoder.withIndent('  ').convert({for (final e in status.entries)
            // The hardening of a service launched inside a test is empty;
            // the guide describes a real one's.
            if (e.key != 'id' && e.key != 'hardening') e.key: e.value})}',
    };

    final file = File(guide);
    var text = file.readAsStringSync();
    final update = Platform.environment['TSM_UPDATE_TRANSCRIPTS'] == '1';
    for (final MapEntry(key: name, value: body) in sessions.entries) {
      final updated = replaceTranscript(text, name, normalize(body, paths));
      if (!update) {
        expect(
          updated,
          text,
          reason:
              'the transcript $name changed: run TSM_UPDATE_TRANSCRIPTS=1 '
              'dart test test/guide_transcripts_test.dart',
        );
      }
      text = updated;
    }
    if (update) file.writeAsStringSync(text);
  });

  test('times, process ids, versions and paths are normalized', () {
    expect(
      normalize(
        '/tmp/x/run 2027-01-02T03:04:05.678Z "pid": 99 "start": 17 '
        '"version": "0.25.6" version=0.25.6 pid=12 platform=macos',
        {'/tmp/x': '/home/demo/vaults', '/tmp/x/run': '/run/user/1000/tsm'},
      ),
      '/run/user/1000/tsm 2026-11-24T09:00:00.000Z "pid": 4242 '
      '"start": 1795510800000 "version": "<version>" version=<version> '
      'pid=4242 platform=linux',
    );
  });
}
