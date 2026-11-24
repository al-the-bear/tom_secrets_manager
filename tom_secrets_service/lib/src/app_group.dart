// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The client socket in the macOS app's App Group container
/// (part-browser, Safari; protocol.md 3.1): the Safari Web Extension's
/// handler runs sandboxed and cannot reach the runtime directory in
/// `$TMPDIR`, but it may reach its App Group's container. When the service
/// runs from the app's tools folder (`<App>.app/Contents/Resources/tsm/bin`)
/// and the app names its App Group (`TSMAppGroup` in its `Info.plist`, from
/// the team-signed build's `TSM_TEAM_ID`), the service offers its client
/// endpoint there too: `~/Library/Group Containers/<group>/tsm/client.sock`.
/// It is the same endpoint: the same protocol, the same measurement of the
/// peer and the same grants.
library;

import 'dart:io';

/// The `Info.plist` key naming the app's App Group.
const String tomSecretsAppGroupKey = 'TSMAppGroup';

/// The App Group the app bundle around [serviceExecutable] names, or null:
/// the service is not in an app bundle's tools folder, the bundle names no
/// group, or the group has no team (an ad-hoc build, where it is
/// `.tom.secrets`).
String? tomSecretsAppGroupOf(String serviceExecutable) {
  final parts = serviceExecutable.split('/');
  // <App>.app/Contents/Resources/tsm/bin/<service>
  if (parts.length < 6) return null;
  final n = parts.length;
  if (parts[n - 2] != 'bin' ||
      parts[n - 3] != 'tsm' ||
      parts[n - 4] != 'Resources' ||
      parts[n - 5] != 'Contents' ||
      !parts[n - 6].endsWith('.app')) {
    return null;
  }
  final plist = File([...parts.sublist(0, n - 4), 'Info.plist'].join('/'));
  if (!plist.existsSync()) return null;
  final String text;
  try {
    text = plist.readAsStringSync();
  } on FileSystemException {
    return null; // a binary plist: the build writes XML
  }
  final match = RegExp(
    '<key>${RegExp.escape(tomSecretsAppGroupKey)}</key>\\s*<string>([^<]*)</string>',
  ).firstMatch(text);
  final group = match?[1]?.trim() ?? '';
  // A group without its team prefix is the ad-hoc build's: none.
  if (group.isEmpty || group.startsWith('.') || group.contains(r'$(')) {
    return null;
  }
  return group;
}

/// The client socket in [group]'s container under [home].
String tomSecretsAppGroupClientSocket(String group, String home) =>
    '$home/Library/Group Containers/$group/tsm/client.sock';

/// The client socket in the App Group container of the app around
/// [serviceExecutable] (macOS), or null.
String? tomSecretsAppGroupClientSocketFor(
  String serviceExecutable, {
  Map<String, String>? environment,
  String? operatingSystem,
}) {
  if ((operatingSystem ?? Platform.operatingSystem) != 'macos') return null;
  final home = (environment ?? Platform.environment)['HOME'];
  if (home == null || home.isEmpty) return null;
  final group = tomSecretsAppGroupOf(serviceExecutable);
  return group == null ? null : tomSecretsAppGroupClientSocket(group, home);
}
