// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

import 'dart:io';

import 'package:test/test.dart';
import 'package:tom_secrets_service/tom_secrets_service.dart';

void main() {
  test('the version in the welcome and status is the pubspec version', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    final version = RegExp(
      r'^version: (\S+)$',
      multiLine: true,
    ).firstMatch(pubspec)!.group(1);
    expect(tomSecretsServiceVersion, version);
  });
}
