// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// URL matching (part-browser): normalising, the registrable domain after
/// the Public Suffix List, the four `tsm.urlMatch` rules, and the login
/// entries of a page in their order. Demo data only.
library;

import 'package:test/test.dart';
import 'package:tom_secrets_core/tom_secrets_core.dart';

import 'support/vaults.dart';

TomSecretsSiteUrl _url(String text) => TomSecretsSiteUrl.parse(text)!;

void main() {
  group('hosts', () {
    test('non-ASCII labels as punycode (RFC 3492), lower-case, no trailing '
        'dot', () {
      expect(tomSecretsAsciiHost('München.de'), 'xn--mnchen-3ya.de');
      expect(tomSecretsAsciiHost('bücher.example.'), 'xn--bcher-kva.example');
      expect(tomSecretsAsciiHost('例え.テスト'), 'xn--r8jz45g.xn--zckzah');
      expect(tomSecretsAsciiHost('[fd00::1]'), 'fd00::1');
    });

    test('the registrable domain after the Public Suffix List', () {
      expect(tomSecretsRegistrableDomain('login.example.com'), 'example.com');
      expect(tomSecretsRegistrableDomain('example.com'), 'example.com');
      expect(tomSecretsRegistrableDomain('a.b.example.co.uk'), 'example.co.uk');
      expect(tomSecretsRegistrableDomain('co.uk'), isNull);
      expect(tomSecretsRegistrableDomain('com'), isNull);
      // The private section: every github.io name is a site of its own.
      expect(
        tomSecretsRegistrableDomain('a.example.github.io'),
        'example.github.io',
      );
      // A wildcard rule (`*.ck`) and its exception (`!www.ck`).
      expect(tomSecretsRegistrableDomain('foo.bar.ck'), 'foo.bar.ck');
      expect(tomSecretsRegistrableDomain('www.ck'), 'www.ck');
      // No rule: the implicit `*`.
      expect(tomSecretsRegistrableDomain('host.unlisted'), 'host.unlisted');
      expect(tomSecretsPublicSuffixListVersion, isNotEmpty);
    });
  });

  group('URLs', () {
    test('normalised: https without a scheme, default ports dropped, `/` at '
        'least; not web URLs are none', () {
      final a = _url('Example.COM/login');
      expect(
        (a.scheme, a.host, a.port, a.path),
        ('https', 'example.com', null, '/login'),
      );
      expect(_url('https://example.com:443').port, isNull);
      expect(_url('http://example.com:80/').port, isNull);
      expect(_url('https://example.com:8443').port, 8443);
      expect(_url('https://bücher.de/').host, 'xn--bcher-kva.de');
      expect(_url('localhost:3000').port, 3000);
      for (final none in [
        'androidapp://com.example.app',
        'mailto:demo@example.com',
        'ftp://example.com',
        '',
        'https://',
      ]) {
        expect(TomSecretsSiteUrl.parse(none), isNull, reason: none);
      }
    });

    test('the rules: domain (same site), host, exact (path prefix), never; '
        'https not offered on http; addresses by host and port', () {
      TomSecretsUrlMatchLevel? m(
        String entry,
        String page, [
        TomSecretsUrlMatchRule rule = TomSecretsUrlMatchRule.domain,
      ]) => tomSecretsMatchSiteUrl(_url(entry), _url(page), rule: rule);

      expect(
        m('https://example.com', 'https://example.com/a'),
        TomSecretsUrlMatchLevel.exactHost,
      );
      expect(
        m('https://example.com', 'https://login.example.com'),
        TomSecretsUrlMatchLevel.domain,
      );
      expect(m('https://example.github.io', 'https://other.github.io'), isNull);
      expect(m('https://example.co.uk', 'https://other.co.uk'), isNull);
      expect(m('https://example.com', 'http://example.com'), isNull);
      expect(
        m('http://example.com', 'https://example.com'),
        TomSecretsUrlMatchLevel.exactHost,
      );

      const host = TomSecretsUrlMatchRule.host;
      expect(
        m('https://example.com', 'https://example.com/x', host),
        TomSecretsUrlMatchLevel.exactHost,
      );
      expect(
        m('https://example.com', 'https://login.example.com', host),
        isNull,
      );

      const exact = TomSecretsUrlMatchRule.exact;
      expect(
        m('https://example.com/app', 'https://example.com/app/x', exact),
        TomSecretsUrlMatchLevel.exactHost,
      );
      expect(
        m('https://example.com/app', 'https://example.com/apple', exact),
        isNull,
      );
      expect(
        m('https://example.com:8443/', 'https://example.com/', exact),
        isNull,
      );

      expect(
        m(
          'https://example.com',
          'https://example.com',
          TomSecretsUrlMatchRule.never,
        ),
        isNull,
      );
      expect(
        m('http://192.168.1.20:8080', 'http://192.168.1.20:8080/x'),
        TomSecretsUrlMatchLevel.exactHost,
      );
      expect(m('http://192.168.1.20:8080', 'http://192.168.1.20:9090'), isNull);
      expect(m('http://localhost:3000', 'http://localhost:4000'), isNull);
      expect(TomSecretsUrlMatchRule.of(' HOST '), TomSecretsUrlMatchRule.host);
      expect(
        TomSecretsUrlMatchRule.of('nonsense'),
        TomSecretsUrlMatchRule.domain,
      );
    });
  });

  group('the logins of a page', () {
    late TomSecretsStore store;

    KdbxEntry add(
      KdbxFile file,
      String title, {
      String? url,
      Map<String, String> fields = const {},
      DateTime? used,
    }) {
      final root = file.body.rootGroup;
      final entry = KdbxEntry.create(file, root)
        ..setString(KdbxKeyCommon.TITLE, PlainValue(title))
        ..setString(KdbxKeyCommon.USER_NAME, PlainValue('$title-user'))
        ..setString(
          KdbxKeyCommon.PASSWORD,
          ProtectedValue.fromString('$title-demo-pw'),
        );
      if (url != null) entry.setString(KdbxKeyCommon.URL, PlainValue(url));
      for (final MapEntry(:key, :value) in fields.entries) {
        entry.setString(KdbxKey(key), PlainValue(value));
      }
      if (used != null) entry.times.lastAccessTime.set(used);
      root.addEntry(entry);
      return entry;
    }

    setUp(() {
      final file = tomSecretsNewVault(
        tomSecretsVaultCredentials(password: 'demo-pw'),
        'personal',
        argon2: testArgon2,
      );
      add(
        file,
        'Domain old',
        url: 'https://example.com',
        used: DateTime.utc(2026, 1, 1),
      );
      add(
        file,
        'Domain new',
        url: 'example.com/',
        used: DateTime.utc(2026, 6, 1),
      );
      add(
        file,
        'Exact host',
        url: 'https://login.example.com/',
        used: DateTime.utc(2026, 3, 1),
      );
      add(
        file,
        'Extra url',
        used: DateTime.utc(2026, 2, 1),
        fields: {
          'KP2A_URL_1': 'androidapp://com.example',
          'KP2A_URL_2': 'https://login.example.com/sso',
        },
      );
      add(
        file,
        'Never',
        url: 'https://example.com',
        fields: {'tsm.urlMatch': 'never'},
      );
      add(
        file,
        'A note',
        url: 'https://example.com',
        fields: {'tsm.type': 'note'},
      );
      add(file, 'Elsewhere', url: 'https://example.org');
      add(
        file,
        'With totp',
        url: 'https://other.example.com',
        used: DateTime.utc(2026, 7, 1),
        fields: {'otp': 'otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP'},
      );
      store = TomSecretsStore.fromFile(file, name: 'personal');
    });

    test('exact host first, then the last used, then by title; notes, '
        '`never` and other sites left out; hasTotp', () {
      final found = tomSecretsMatchLogins(
        store.entries,
        'https://login.example.com/signin',
      );
      expect(
        [for (final m in found) m.title],
        ['Exact host', 'Extra url', 'With totp', 'Domain new', 'Domain old'],
      );
      expect(found[1].matchedUrl, 'https://login.example.com/sso');
      expect(found[0].level, TomSecretsUrlMatchLevel.exactHost);
      expect(found[2].level, TomSecretsUrlMatchLevel.domain);
      expect(found[2].hasTotp, isTrue);
      expect(found[0].userName, 'Exact host-user');
      expect(found.first.hasTotp, isFalse);
    });

    test('a frame is matched when it is the same site as the page; a frame '
        'of another site matches nothing', () {
      final inFrame = tomSecretsMatchLogins(
        store.entries,
        'https://www.example.com/',
        frameUrl: 'https://login.example.com/frame',
      );
      expect(inFrame.first.title, 'Exact host');
      expect(
        tomSecretsMatchLogins(
          store.entries,
          'https://www.example.com/',
          frameUrl: 'https://evil.example.org/frame',
        ),
        isEmpty,
      );
      expect(tomSecretsMatchLogins(store.entries, 'not a url:'), isEmpty);
    });
  });
}
