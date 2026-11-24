// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// `tsm_import_cleaner` on the command line, a `tom_build_base` tool:
/// `tsm_import_cleaner <export> [<cleaned>]`.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:tom_build_base/tom_build_base_v2.dart';

import 'cleaner.dart';

/// The tool's version.
const String tomSecretsImportCleanerVersion = '0.1.0';

/// The tool definition.
final ToolDefinition tomSecretsImportCleanerTool = ToolDefinition(
  name: 'tsm_import_cleaner',
  description:
      "Cleans a password manager's export for testing the Tom Secrets "
      'Manager import: passwords, notes and every other value masked (X), '
      'titles, e-mail addresses and URLs replaced by unique stand-ins, '
      'attachments zeroed; the structure, ids and field labels kept. Reads '
      'Enpass JSON and CSV, Bitwarden JSON (unencrypted), 1Password 1PUX and '
      'the CSV exports with a header (1Password, Bitwarden, the browsers).',
  version: tomSecretsImportCleanerVersion,
  prefixlessCommands: true,
  defaultCommand: 'clean',
  features: NavigationFeatures.minimal,
  helpFooter:
      'Exit codes: 0 cleaned, 2 usage, 3 a file that cannot be read or '
      'written, 4 an export the cleaner does not know.\n'
      'Check the cleaned file before you hand it on: the cleaner keeps field '
      'labels, folder structure, types and timestamps.',
  commands: [
    CommandDefinition(
      name: 'clean',
      description:
          'Clean <export> into <cleaned> (default: <export> with '
          '".cleaned" before its extension).',
      requiresTraversal: false,
      supportsProjectTraversal: false,
      options: const [
        OptionDefinition.flag(
          name: 'force',
          description: 'Overwrite <cleaned> when it exists.',
        ),
      ],
      examples: const [
        'tsm_import_cleaner enpass_export.json',
        'tsm_import_cleaner enpass_export.json cleaned.json --force',
        'tsm_import_cleaner 1PasswordExport.1pux',
      ],
    ),
  ],
);

/// The default output path of [input]: `.cleaned` before the extension.
String tomSecretsCleanedPathOf(String input) {
  final slash = input.lastIndexOf(RegExp(r'[/\\]'));
  final dot = input.lastIndexOf('.');
  if (dot <= slash + 1) return '$input.cleaned';
  return '${input.substring(0, dot)}.cleaned${input.substring(dot)}';
}

/// Runs the tool on [arguments]; answers the exit code.
Future<int> tomSecretsImportCleanerMain(List<String> arguments) async {
  var code = 0;
  final runner = ToolRunner(
    tool: tomSecretsImportCleanerTool,
    executors: {
      'clean': CallbackExecutor(
        onExecute: (_, _) async =>
            const ItemResult.success(path: '.', name: 'clean'),
        onExecuteWithoutTraversal: (args) async {
          code = _clean(
            args.positionalArgs,
            force: args.commandArgs['clean']?.options['force'] == true,
          );
          return const ToolResult.success();
        },
      ),
    },
  );
  final result = await runner.run(arguments);
  return result.success ? code : (code == 0 ? 2 : code);
}

int _clean(List<String> positional, {required bool force}) {
  if (positional.isEmpty || positional.length > 2) {
    stderr.writeln('usage: tsm_import_cleaner <export> [<cleaned>] [--force]');
    return 2;
  }
  final input = positional.first;
  final output = positional.length == 2
      ? positional[1]
      : tomSecretsCleanedPathOf(input);
  final Uint8List bytes;
  try {
    bytes = File(input).readAsBytesSync();
  } on FileSystemException catch (e) {
    stderr.writeln('tsm_import_cleaner: cannot read $input: ${e.message}');
    return 3;
  }
  if (File(output).existsSync() && !force) {
    stderr.writeln(
      'tsm_import_cleaner: $output exists; name another file or pass --force',
    );
    return 3;
  }
  final ({Uint8List bytes, TomSecretsCleanReport report}) cleaned;
  try {
    cleaned = tomSecretsCleanExport(bytes);
  } on TomSecretsCleanerException catch (e) {
    stderr.writeln('tsm_import_cleaner: $input: $e');
    return 4;
  }
  try {
    File(output).writeAsBytesSync(cleaned.bytes);
  } on FileSystemException catch (e) {
    stderr.writeln('tsm_import_cleaner: cannot write $output: ${e.message}');
    return 3;
  }
  stdout.writeln('${cleaned.report}');
  stdout.writeln('wrote $output (${(cleaned.bytes.length / 1024).ceil()} KiB)');
  return 0;
}
