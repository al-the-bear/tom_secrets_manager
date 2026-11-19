// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The health report (part-password-manager, DP-39, DP-179): what the app's
/// Health screen lists per open vault, computed in the app's memory.
///
/// - **weak** passwords, by a zxcvbn estimator (dictionaries, patterns,
///   keyboard walks, the entry's own title, user name and site), not by
///   length alone;
/// - **reused** passwords: equal values across every vault given;
/// - **old** passwords: unchanged for longer than [TomSecretsHealthPolicy.
///   oldAfter] (one year), read from the entry's history;
/// - **expiring** entries: Expires within [TomSecretsHealthPolicy.
///   expiringWithin] (30 days) or past;
/// - **short keys** (DP-179): RSA below 3072 bits, elliptic curves below
///   256 bits, DSA; flagged, never refused;
/// - **breached** passwords: from the breach check ([TomSecretsBreachCheck]),
///   whose counts the caller passes in.
///
/// Passwords are those of login entries; API tokens, notes and keys are
/// checked for expiry (and keys for their length) only.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';
import 'package:zxcvbn/zxcvbn.dart';

import 'mapping.dart';
import 'ssh_key.dart';

/// What the report flags.
enum TomSecretsHealthIssue {
  /// A password an attacker guesses quickly.
  weak('Weak'),

  /// A password two or more entries share.
  reused('Reused'),

  /// A password unchanged for longer than the policy's age.
  old('Old'),

  /// An entry that expires soon, or has expired.
  expiring('Expiring'),

  /// A key shorter than today's guidance (DP-179).
  shortKey('Short keys'),

  /// A password found in known breaches.
  breached('Breached');

  const TomSecretsHealthIssue(this.label);

  /// The heading the Health screen shows.
  final String label;
}

/// The report's thresholds.
final class TomSecretsHealthPolicy {
  /// Passwords count as old after [oldAfter]; entries as expiring within
  /// [expiringWithin] of their Expires time.
  const TomSecretsHealthPolicy({
    this.oldAfter = const Duration(days: 365),
    this.expiringWithin = const Duration(days: 30),
  });

  /// The age after which a password counts as old (default one year).
  final Duration oldAfter;

  /// How long before its Expires time an entry counts as expiring (30 days).
  final Duration expiringWithin;
}

/// How guessable a password is (zxcvbn).
final class TomSecretsPasswordStrength {
  const TomSecretsPasswordStrength._({
    required this.score,
    required this.guessesLog10,
    this.warning,
  });

  /// zxcvbn's score, 0 (guessed at once) to 4 (very unguessable).
  final int score;

  /// The estimated guesses, as a power of ten.
  final double guessesLog10;

  /// What makes it guessable, when zxcvbn names it.
  final String? warning;

  /// Whether the report flags it: a score below 3 (zxcvbn's "safely
  /// unguessable" starts at 3, about 10^8 guesses).
  bool get weak => score < 3;
}

/// The longest prefix of a password the estimator reads: its matching grows
/// with the square of the length, and a password this long is strong unless
/// its start is already guessable.
const int tomSecretsStrengthMaxLength = 100;

/// The strength of [password]; [userInputs] are words the password should
/// not be built from (the entry's title, user name, site).
TomSecretsPasswordStrength tomSecretsPasswordStrength(
  String password, {
  List<String> userInputs = const [],
}) {
  if (password.isEmpty) {
    return const TomSecretsPasswordStrength._(score: 0, guessesLog10: 0);
  }
  final text = password.length > tomSecretsStrengthMaxLength
      ? password.substring(0, tomSecretsStrengthMaxLength)
      : password;
  final result = Zxcvbn().evaluate(
    text,
    userInputs: [
      for (final input in userInputs)
        if (input.trim().length >= 3) input.trim(),
    ],
  );
  final warning = result.feedback.warning;
  return TomSecretsPasswordStrength._(
    score: (result.score ?? 0).round(),
    guessesLog10: result.guesses_log10,
    warning: warning == null || warning.isEmpty ? null : warning,
  );
}

/// Today's minimum key lengths (DP-179, NIST SP 800-57, BSI TR-02102).
abstract final class TomSecretsKeyStrength {
  /// RSA below this many bits is flagged (128-bit strength).
  static const rsaMinimumBits = 3072;

  /// An elliptic curve below this many bits is flagged.
  static const ecMinimumBits = 256;

  /// Why a key of [keyType] (an SSH key type) and [bits] is short, or null
  /// when it passes or its length cannot be read (an encrypted key that does
  /// not say it).
  static String? shortness(String? keyType, int? bits) {
    if (keyType == null) return null;
    if (keyType == 'ssh-dss') {
      return 'DSA: no longer accepted by OpenSSH';
    }
    if (bits == null) return null;
    if (keyType == 'ssh-rsa' && bits < rsaMinimumBits) {
      return 'RSA $bits bits: below $rsaMinimumBits';
    }
    if (keyType.startsWith('ecdsa-') && bits < ecMinimumBits) {
      return 'ECDSA $bits bits: below $ecMinimumBits';
    }
    return null;
  }
}

/// The field that keeps an entry out of the breach check (`off`).
const KdbxKey tomSecretsBreachCheckField = KdbxKey('tsm.breachCheck');

/// Whether [entry] is kept out of the breach check.
bool tomSecretsBreachCheckExcluded(KdbxEntry entry) =>
    entry.getString(tomSecretsBreachCheckField)?.getText() == 'off';

/// Keeps [entry] out of the breach check, or ([excluded] false) lets it in
/// again; the entry as it was goes to its history.
void tomSecretsSetBreachCheckExcluded(KdbxEntry entry, bool excluded) {
  if (tomSecretsBreachCheckExcluded(entry) == excluded) return;
  entry.modify(() {
    if (excluded) {
      entry.setString(tomSecretsBreachCheckField, PlainValue('off'));
    } else {
      entry.removeString(tomSecretsBreachCheckField);
    }
  });
}

/// The password of [entry], or null when it has none.
String? tomSecretsPasswordOf(KdbxEntry entry) {
  final password = entry.getString(KdbxKeyCommon.PASSWORD)?.getText();
  return password == null || password.isEmpty ? null : password;
}

/// When [entry]'s current password was set: the save time of the oldest
/// version, back from the current one, that still holds it (its history
/// as far as it is kept). Null when the entry carries no times.
DateTime? tomSecretsPasswordChanged(KdbxEntry entry) {
  final password = tomSecretsPasswordOf(entry) ?? '';
  var changed = entry.times.lastModificationTime.get();
  for (final version in entry.history.reversed) {
    final old = tomSecretsPasswordOf(version) ?? '';
    if (old != password) break;
    changed = version.times.lastModificationTime.get() ?? changed;
  }
  return changed;
}

/// The SHA-1 of [password] in upper-case hex, as the breach check's range
/// API compares it. Never written anywhere: the check keeps it in memory.
String tomSecretsPasswordHash(String password) =>
    crypto.sha1.convert(utf8.encode(password)).toString().toUpperCase();

/// An entry the report reads.
final class TomSecretsHealthEntry {
  /// [entry] of the vault [store].
  const TomSecretsHealthEntry(this.store, this.entry);

  /// The store.
  final String store;

  /// The entry.
  final KdbxEntry entry;

  /// Its type.
  TomSecretsEntryType get type => TomSecretsEntryType.of(
    entry.getString(TomSecretsEntryFields.type)?.getText(),
  );

  /// Its password when it is a login with one (the report's password
  /// checks), else null.
  String? get password =>
      type == TomSecretsEntryType.login ? tomSecretsPasswordOf(entry) : null;
}

/// One flag of the report.
final class TomSecretsHealthFinding {
  const TomSecretsHealthFinding._({
    required this.issue,
    required this.store,
    required this.entry,
    required this.detail,
  });

  /// What is flagged.
  final TomSecretsHealthIssue issue;

  /// The entry's store.
  final String store;

  /// The entry.
  final KdbxEntry entry;

  /// Why, for the user; never a value.
  final String detail;
}

/// The report: its findings in the order of [TomSecretsHealthIssue], then
/// by store and title.
final class TomSecretsHealthReport {
  const TomSecretsHealthReport._(this.findings, this.checkedPasswords);

  /// The empty report.
  static const empty = TomSecretsHealthReport._([], 0);

  /// Every finding.
  final List<TomSecretsHealthFinding> findings;

  /// How many login passwords were checked.
  final int checkedPasswords;

  /// The findings of [issue].
  List<TomSecretsHealthFinding> of(TomSecretsHealthIssue issue) =>
      findings.where((f) => f.issue == issue).toList();

  /// Whether nothing is flagged.
  bool get healthy => findings.isEmpty;
}

/// The health report of [entries] at [now]: [breachCount] answers how often
/// a password was seen in breaches (null: not checked); an entry kept out of
/// the breach check ([tomSecretsBreachCheckExcluded]) is never listed as
/// breached.
TomSecretsHealthReport tomSecretsHealthReport(
  Iterable<TomSecretsHealthEntry> entries, {
  required DateTime now,
  TomSecretsHealthPolicy policy = const TomSecretsHealthPolicy(),
  int? Function(TomSecretsHealthEntry entry, String password)? breachCount,
}) {
  final findings = <TomSecretsHealthFinding>[];
  void add(TomSecretsHealthIssue issue, TomSecretsHealthEntry e, String why) =>
      findings.add(
        TomSecretsHealthFinding._(
          issue: issue,
          store: e.store,
          entry: e.entry,
          detail: why,
        ),
      );

  final byPassword = <String, List<TomSecretsHealthEntry>>{};
  final strengths = <String, TomSecretsPasswordStrength>{};
  var checked = 0;
  for (final e in entries) {
    final entry = e.entry;
    final password = e.password;
    if (password != null) {
      checked++;
      final userInputs = [
        entry.label ?? '',
        entry.getString(KdbxKeyCommon.USER_NAME)?.getText() ?? '',
        Uri.tryParse(
              entry.getString(KdbxKeyCommon.URL)?.getText() ?? '',
            )?.host ??
            '',
      ];
      // The same password with the same words scores the same.
      final strength = strengths.putIfAbsent(
        '${userInputs.join('\u0000')}\u0000$password',
        () => tomSecretsPasswordStrength(password, userInputs: userInputs),
      );
      if (strength.weak) {
        add(
          TomSecretsHealthIssue.weak,
          e,
          strength.warning ?? 'Easy to guess (strength ${strength.score} of 4)',
        );
      }
      byPassword.putIfAbsent(password, () => []).add(e);
      final changed = tomSecretsPasswordChanged(entry);
      if (changed != null && now.difference(changed) > policy.oldAfter) {
        add(TomSecretsHealthIssue.old, e, 'Unchanged since ${_date(changed)}');
      }
      final count = breachCount?.call(e, password);
      if (count != null && count > 0 && !tomSecretsBreachCheckExcluded(entry)) {
        add(
          TomSecretsHealthIssue.breached,
          e,
          'Seen ${count == 1 ? 'once' : '$count times'} in known breaches',
        );
      }
    }
    if (entry.times.expires.get() == true) {
      final expiry = entry.times.expiryTime.get();
      if (expiry != null && expiry.difference(now) <= policy.expiringWithin) {
        add(
          TomSecretsHealthIssue.expiring,
          e,
          expiry.isAfter(now)
              ? 'Expires on ${_date(expiry)}'
              : 'Expired on ${_date(expiry)}',
        );
      }
    }
    if (e.type == TomSecretsEntryType.sshKey) {
      final info = tomSecretsSshKeyOf(entry)?.info;
      final why = TomSecretsKeyStrength.shortness(info?.keyType, info?.bits);
      if (why != null) add(TomSecretsHealthIssue.shortKey, e, why);
    }
  }
  for (final shared in byPassword.values) {
    if (shared.length < 2) continue;
    for (final e in shared) {
      add(
        TomSecretsHealthIssue.reused,
        e,
        'Shared with ${shared.length - 1} other '
        '${shared.length == 2 ? 'entry' : 'entries'}',
      );
    }
  }
  findings.sort((a, b) {
    final byIssue = a.issue.index.compareTo(b.issue.index);
    if (byIssue != 0) return byIssue;
    final byStore = a.store.compareTo(b.store);
    if (byStore != 0) return byStore;
    return (a.entry.label ?? '').toLowerCase().compareTo(
      (b.entry.label ?? '').toLowerCase(),
    );
  });
  return TomSecretsHealthReport._(List.unmodifiable(findings), checked);
}

String _date(DateTime t) => t.toIso8601String().substring(0, 10);

/// The breach check (part-password-manager, DP-39) over the Have I Been
/// Pwned range API: only the first five hex characters of a password's
/// SHA-1 leave the device, with `Add-Padding: true` so the answer's size
/// reveals nothing; the returned suffixes are compared here. Counts are
/// kept per hash in memory (never written), so a password is asked about
/// once per run of the app.
final class TomSecretsBreachCheck {
  /// A check over [client] (default a new one) against [endpoint]; at most
  /// [parallel] requests at a time.
  TomSecretsBreachCheck({
    http.Client? client,
    Uri? endpoint,
    this.parallel = 4,
    this.userAgent = 'tom-secrets-manager',
  }) : _client = client ?? http.Client(),
       _ownsClient = client == null,
       endpoint = endpoint ?? defaultEndpoint;

  /// The range API.
  static final Uri defaultEndpoint = Uri.parse(
    'https://api.pwnedpasswords.com/range/',
  );

  /// Where the prefixes are sent (`<endpoint><prefix>`).
  final Uri endpoint;

  /// How many requests run at once.
  final int parallel;

  /// The `User-Agent` the API asks for.
  final String userAgent;

  final http.Client _client;
  final bool _ownsClient;
  final Map<String, int> _counts = {};

  /// How often [password] was seen in breaches, when this check has asked
  /// already; else null.
  int? cached(String password) => _counts[tomSecretsPasswordHash(password)];

  /// How often [password] was seen in breaches.
  Future<int> count(String password) async =>
      (await countAll([password]))[password]!;

  /// How often each of [passwords] was seen, one request per hash prefix
  /// not asked about before. A failed request throws
  /// [TomSecretsBreachCheckException]; what was answered stays cached.
  Future<Map<String, int>> countAll(Iterable<String> passwords) async {
    final hashes = {for (final p in passwords) p: tomSecretsPasswordHash(p)};
    final prefixes = {
      for (final h in hashes.values)
        if (!_counts.containsKey(h)) h.substring(0, 5),
    }.toList();
    var next = 0;
    Future<void> worker() async {
      while (next < prefixes.length) {
        final prefix = prefixes[next++];
        final suffixes = await _range(prefix);
        for (final h in hashes.values) {
          if (h.startsWith(prefix)) _counts[h] = suffixes[h.substring(5)] ?? 0;
        }
      }
    }

    await Future.wait([
      for (var i = 0; i < parallel && i < prefixes.length; i++) worker(),
    ]);
    return {
      for (final MapEntry(:key, :value) in hashes.entries) key: _counts[value]!,
    };
  }

  Future<Map<String, int>> _range(String prefix) async {
    final http.Response response;
    try {
      response = await _client.get(
        endpoint.resolve(prefix),
        headers: {'Add-Padding': 'true', 'User-Agent': userAgent},
      );
    } on Object catch (e) {
      throw TomSecretsBreachCheckException('$e');
    }
    if (response.statusCode != 200) {
      throw TomSecretsBreachCheckException(
        'the breach check answered ${response.statusCode}',
      );
    }
    return parseRange(response.body);
  }

  /// The suffixes of a range answer with their counts; the padding lines
  /// (count 0) are left out.
  static Map<String, int> parseRange(String body) {
    final counts = <String, int>{};
    for (final line in const LineSplitter().convert(body)) {
      final colon = line.indexOf(':');
      if (colon < 0) continue;
      final count = int.tryParse(line.substring(colon + 1).trim()) ?? 0;
      if (count > 0) {
        counts[line.substring(0, colon).trim().toUpperCase()] = count;
      }
    }
    return counts;
  }

  /// Closes the client it made.
  void close() {
    if (_ownsClient) _client.close();
  }
}

/// The breach check could not ask.
final class TomSecretsBreachCheckException implements Exception {
  /// Fails with [message].
  const TomSecretsBreachCheckException(this.message);

  /// What went wrong.
  final String message;

  @override
  String toString() => 'Breach check: $message';
}
