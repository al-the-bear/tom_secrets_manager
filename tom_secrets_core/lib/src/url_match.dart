// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// Which login entries belong to a web page (part-browser, URL matching;
/// protocol.md 5.5 `match`): an entry's URLs (`URL` and every `KP2A_URL*`
/// field) normalised and compared with the page's by the entry's
/// `tsm.urlMatch` rule, by default the same site: the registrable domain
/// after the Public Suffix List. The browser host, the git and Docker
/// helpers (through the service's `match`) and the OS autofill read the same
/// rules.
library;

import 'dart:io' show InternetAddress;

import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';
import 'public_suffix_list.g.dart';
import 'store.dart';
import 'totp.dart';

export 'public_suffix_list.g.dart' show tomSecretsPublicSuffixListVersion;

/// How an entry's URLs match a page: the entry field `tsm.urlMatch`.
enum TomSecretsUrlMatchRule {
  /// The registrable domain (the default): `login.example.com` matches an
  /// entry for `example.com`.
  domain,

  /// The exact host, any path.
  host,

  /// Scheme, host, port and a path prefix.
  exact,

  /// Never offered.
  never;

  /// The rule a `tsm.urlMatch` value names; absent or unknown is [domain].
  static TomSecretsUrlMatchRule of(String? value) =>
      values.where((r) => r.name == value?.trim().toLowerCase()).firstOrNull ??
      domain;
}

/// How closely an entry matches: the exact host before the domain.
enum TomSecretsUrlMatchLevel {
  /// The same host (or, for [TomSecretsUrlMatchRule.exact], scheme, host,
  /// port and path prefix).
  exactHost,

  /// The same registrable domain.
  domain,
}

/// A web URL as matching reads it: `http` or `https`, the host lower-case
/// with every non-ASCII label as punycode, the port (null when it is the
/// scheme's default) and the path (`/` at least). A text without a scheme
/// is read as `https`.
final class TomSecretsSiteUrl {
  const TomSecretsSiteUrl._(this.scheme, this.host, this.port, this.path);

  /// [text] normalised, or null when it is not a web URL (`androidapp://`,
  /// `mailto:`, a URL without a host).
  static TomSecretsSiteUrl? parse(String text) {
    var t = text.trim();
    if (t.isEmpty) return null;
    final schemeEnd = t.indexOf('://');
    if (schemeEnd < 0) {
      // `example.com/login`, but not `mailto:x` or `javascript:...`.
      if (RegExp(r'^[A-Za-z][A-Za-z0-9+.-]*:(?!\d)').hasMatch(t)) return null;
      t = 'https://$t';
    }
    final Uri uri;
    try {
      uri = Uri.parse(t);
    } on FormatException {
      return null;
    }
    final scheme = uri.scheme.toLowerCase();
    if (scheme != 'http' && scheme != 'https') return null;
    if (uri.host.isEmpty) return null;
    final String host;
    try {
      host = tomSecretsAsciiHost(Uri.decodeComponent(uri.host));
    } on FormatException {
      return null;
    }
    final port = !uri.hasPort || uri.port == (scheme == 'https' ? 443 : 80)
        ? null
        : uri.port;
    return TomSecretsSiteUrl._(
      scheme,
      host,
      port,
      uri.path.isEmpty ? '/' : uri.path,
    );
  }

  /// `http` or `https`.
  final String scheme;

  /// The host: lower-case, punycode labels, an IPv6 address without
  /// brackets.
  final String host;

  /// The port, or null for the scheme's default.
  final int? port;

  /// The path, `/` at least.
  final String path;

  /// Whether the host is an IP address or `localhost`: such a URL matches
  /// by host and port exactly.
  bool get isAddressOrLocalhost =>
      host == 'localhost' ||
      host.endsWith('.localhost') ||
      InternetAddress.tryParse(host) != null;

  /// The registrable domain (the public suffix and one label before it),
  /// or null for an address, `localhost`, or a host that is itself a
  /// public suffix.
  String? get registrableDomain =>
      isAddressOrLocalhost ? null : tomSecretsRegistrableDomain(host);

  @override
  String toString() => '$scheme://$host${port == null ? '' : ':$port'}$path';
}

/// The level at which an entry URL [entry] matches the page [page] under
/// [rule], or null when it does not. An entry saved for `https` is not
/// offered on an `http` page. An address or `localhost` matches by host
/// and port exactly, whatever the rule.
TomSecretsUrlMatchLevel? tomSecretsMatchSiteUrl(
  TomSecretsSiteUrl entry,
  TomSecretsSiteUrl page, {
  TomSecretsUrlMatchRule rule = TomSecretsUrlMatchRule.domain,
}) {
  if (rule == TomSecretsUrlMatchRule.never) return null;
  if (entry.scheme == 'https' && page.scheme == 'http') return null;
  final sameHost = entry.host == page.host;
  if (entry.isAddressOrLocalhost || page.isAddressOrLocalhost) {
    return sameHost && entry.port == page.port
        ? TomSecretsUrlMatchLevel.exactHost
        : null;
  }
  switch (rule) {
    case TomSecretsUrlMatchRule.exact:
      final prefix = entry.path.endsWith('/') ? entry.path : '${entry.path}/';
      return entry.scheme == page.scheme &&
              sameHost &&
              entry.port == page.port &&
              (page.path == entry.path || page.path.startsWith(prefix))
          ? TomSecretsUrlMatchLevel.exactHost
          : null;
    case TomSecretsUrlMatchRule.host:
      return sameHost ? TomSecretsUrlMatchLevel.exactHost : null;
    case TomSecretsUrlMatchRule.domain:
      if (sameHost) return TomSecretsUrlMatchLevel.exactHost;
      final domain = page.registrableDomain;
      return domain != null && entry.registrableDomain == domain
          ? TomSecretsUrlMatchLevel.domain
          : null;
    case TomSecretsUrlMatchRule.never:
      return null;
  }
}

/// The URLs of [entry] that matching reads: `URL`, then every field whose
/// name begins with `KP2A_URL` (in name order); empty ones left out.
List<String> tomSecretsEntryUrls(KdbxEntry entry) {
  final out = <String>[];
  final url = entry.getString(KdbxKeyCommon.URL)?.getText()?.trim();
  if (url != null && url.isNotEmpty) out.add(url);
  final extra = [
    for (final e in entry.stringEntries)
      if (e.key.key.startsWith(TomSecretsEntryFields.extraUrlPrefix)) e.key,
  ]..sort((a, b) => a.key.compareTo(b.key));
  for (final key in extra) {
    final text = entry.getString(key)?.getText()?.trim();
    if (text != null && text.isNotEmpty) out.add(text);
  }
  return out;
}

/// A login entry matching a page.
final class TomSecretsLoginMatch {
  /// [entry] matched through its URL [matchedUrl] at [level].
  const TomSecretsLoginMatch({
    required this.entry,
    required this.matchedUrl,
    required this.level,
  });

  /// The entry.
  final TomSecretsIndexedEntry entry;

  /// The entry's URL that matched, as written in the entry.
  final String matchedUrl;

  /// How closely.
  final TomSecretsUrlMatchLevel level;

  /// The entry's title.
  String get title => entry.entry.label ?? '';

  /// The entry's user name, or empty.
  String get userName =>
      entry.entry.getString(KdbxKeyCommon.USER_NAME)?.getText() ?? '';

  /// Whether the entry carries a TOTP secret.
  bool get hasTotp => TomSecretsTotp.fromEntry(entry.entry) != null;

  /// When it was last used: its last access, else its last change.
  DateTime? get lastUsed =>
      entry.entry.times.lastAccessTime.get() ??
      entry.entry.times.lastModificationTime.get();
}

/// The login entries of [entries] that belong to the page [url]: entries of
/// type `login`, no overlays, whose URLs match by their `tsm.urlMatch` rule
/// (the best of an entry's URLs counts). With [frameUrl] (a login form in a
/// frame) the frame is matched instead, and only when it is the same site as
/// the page; otherwise nothing. Ordered: the exact host before the domain,
/// then the last used first, then by title. A [url] that is not a web URL
/// matches nothing.
List<TomSecretsLoginMatch> tomSecretsMatchLogins(
  Iterable<TomSecretsIndexedEntry> entries,
  String url, {
  String? frameUrl,
}) {
  final top = TomSecretsSiteUrl.parse(url);
  if (top == null) return const [];
  var page = top;
  if (frameUrl != null && frameUrl.trim().isNotEmpty) {
    final frame = TomSecretsSiteUrl.parse(frameUrl);
    if (frame == null) return const [];
    final sameSite =
        frame.host == top.host ||
        (frame.registrableDomain != null &&
            frame.registrableDomain == top.registrableDomain);
    if (!sameSite) return const [];
    page = frame;
  }
  final out = <TomSecretsLoginMatch>[];
  for (final indexed in entries) {
    if (indexed.isOverlay) continue;
    final entry = indexed.entry;
    final type = TomSecretsEntryType.of(
      entry.getString(TomSecretsEntryFields.type)?.getText(),
    );
    if (type != TomSecretsEntryType.login) continue;
    final rule = TomSecretsUrlMatchRule.of(
      entry.getString(TomSecretsEntryFields.urlMatch)?.getText(),
    );
    if (rule == TomSecretsUrlMatchRule.never) continue;
    TomSecretsLoginMatch? best;
    for (final text in tomSecretsEntryUrls(entry)) {
      final site = TomSecretsSiteUrl.parse(text);
      if (site == null) continue;
      final level = tomSecretsMatchSiteUrl(site, page, rule: rule);
      if (level == null) continue;
      if (best == null || level.index < best.level.index) {
        best = TomSecretsLoginMatch(
          entry: indexed,
          matchedUrl: text,
          level: level,
        );
      }
    }
    if (best != null) out.add(best);
  }
  out.sort((a, b) {
    final byLevel = a.level.index.compareTo(b.level.index);
    if (byLevel != 0) return byLevel;
    final at = a.lastUsed;
    final bt = b.lastUsed;
    if (at != bt) {
      if (at == null) return 1;
      if (bt == null) return -1;
      return bt.compareTo(at);
    }
    return a.title.toLowerCase().compareTo(b.title.toLowerCase());
  });
  return out;
}

// ── Hosts ────────────────────────────────────────────────────────────────

/// [host] as matching compares it: lower-case, a trailing dot dropped,
/// every non-ASCII label as punycode (`xn--...`, RFC 3492), an IPv6 address
/// without its brackets. Throws [FormatException] for a label punycode
/// cannot hold.
String tomSecretsAsciiHost(String host) {
  var h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) {
    return h.substring(1, h.length - 1);
  }
  if (h.endsWith('.')) h = h.substring(0, h.length - 1);
  return h
      .split('.')
      .map(
        (label) => label.runes.every((r) => r < 0x80)
            ? label
            : 'xn--${_punycode(label)}',
      )
      .join('.');
}

/// The registrable domain of the ASCII host [host] after the Public Suffix
/// List (both its sections): the longest matching rule, an exception rule
/// (`!`) taking one label off it, a wildcard (`*`) standing for any label,
/// and `*` when no rule matches; the domain is the public suffix with one
/// more label. Null when the host is itself a public suffix.
String? tomSecretsRegistrableDomain(String host) {
  final labels = host.split('.');
  if (labels.any((l) => l.isEmpty)) return null;
  final rules = _PublicSuffixRules.instance;
  var suffixLength = 1; // the implicit rule `*`
  for (var i = 0; i < labels.length; i++) {
    final candidate = labels.sublist(i).join('.');
    final count = labels.length - i;
    if (rules.exceptions.contains(candidate)) {
      // An exception rule wins: its suffix is the rule less its first label.
      suffixLength = count - 1;
      break;
    }
    final wildcard = i + 1 < labels.length
        ? '*.${labels.sublist(i + 1).join('.')}'
        : null;
    if (rules.rules.contains(candidate) ||
        (wildcard != null && rules.rules.contains(wildcard))) {
      if (count > suffixLength) suffixLength = count;
    }
  }
  if (labels.length <= suffixLength) return null;
  return labels.sublist(labels.length - suffixLength - 1).join('.');
}

final class _PublicSuffixRules {
  _PublicSuffixRules._() {
    for (final line in tomSecretsPublicSuffixRules.split('\n')) {
      if (line.isEmpty) continue;
      if (line.startsWith('!')) {
        exceptions.add(line.substring(1));
      } else {
        rules.add(line);
      }
    }
  }

  static final _PublicSuffixRules instance = _PublicSuffixRules._();

  final Set<String> rules = {};
  final Set<String> exceptions = {};
}

/// The punycode of [label] (RFC 3492, without the `xn--` prefix).
String _punycode(String label) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const initialBias = 72, initialN = 128;
  final input = label.runes.toList();
  final out = StringBuffer();
  for (final c in input) {
    if (c < 0x80) out.writeCharCode(c);
  }
  final basic = out.length;
  var handled = basic;
  if (basic > 0) out.write('-');
  int digit(int d) => d + 22 + (d < 26 ? 75 : 0);
  int adapt(int delta, int points, bool first) {
    var d = first ? delta ~/ damp : delta ~/ 2;
    d += d ~/ points;
    var k = 0;
    while (d > ((base - tMin) * tMax) ~/ 2) {
      d ~/= base - tMin;
      k += base;
    }
    return k + (base - tMin + 1) * d ~/ (d + skew);
  }

  var n = initialN;
  var delta = 0;
  var bias = initialBias;
  while (handled < input.length) {
    final m = input.where((c) => c >= n).reduce((a, b) => a < b ? a : b);
    delta += (m - n) * (handled + 1);
    n = m;
    for (final c in input) {
      if (c < n) delta++;
      if (c == n) {
        var q = delta;
        for (var k = base; ; k += base) {
          final t = k <= bias
              ? tMin
              : k >= bias + tMax
              ? tMax
              : k - bias;
          if (q < t) break;
          out.writeCharCode(digit(t + (q - t) % (base - t)));
          q = (q - t) ~/ (base - t);
        }
        out.writeCharCode(digit(q));
        bias = adapt(delta, handled + 1, handled == basic);
        delta = 0;
        handled++;
      }
    }
    delta++;
    n++;
  }
  return out.toString();
}
