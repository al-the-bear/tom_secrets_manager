// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The typed SSH key (part-structure, DP-5; phase B): an entry of type
/// `ssh-key` holding the private key as an attachment and a
/// `KeeAgent.settings` attachment naming it, as KeePassXC's SSH agent reads
/// it, with the passphrase (when the key has one) in `Password`. Reading a
/// key's type, public key and fingerprint; generating one by DP-179
/// (Ed25519, or RSA 4096 where a tool needs RSA); and retyping phase A's
/// `note` entries that hold a key.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;
import 'package:pointycastle/export.dart' as pc;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';
import 'ssh_wire.dart';

/// The attachment KeePassXC's SSH agent (and KeeAgent) reads an entry's SSH
/// settings from.
const String tomSecretsKeeAgentSettingsName = 'KeeAgent.settings';

/// How a private key file is written.
enum TomSecretsSshKeyFormat {
  /// OpenSSH's own format (`-----BEGIN OPENSSH PRIVATE KEY-----`,
  /// `openssh-key-v1`).
  openssh,

  /// PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`).
  pkcs1,

  /// SEC1 (`-----BEGIN EC PRIVATE KEY-----`).
  sec1,

  /// PKCS#8 (`-----BEGIN PRIVATE KEY-----`).
  pkcs8,

  /// Encrypted PKCS#8 (`-----BEGIN ENCRYPTED PRIVATE KEY-----`).
  pkcs8Encrypted,

  /// DSA (`-----BEGIN DSA PRIVATE KEY-----`), legacy.
  dsa,
}

/// What a private key file says about its key, read without its
/// passphrase: the type, and for an OpenSSH key (whose public key is not
/// encrypted) or an unencrypted PEM key of RSA or ECDSA the public key and
/// its fingerprint.
final class TomSecretsSshKeyInfo {
  const TomSecretsSshKeyInfo._({
    required this.format,
    required this.encrypted,
    this.keyType,
    this.publicKeyBlob,
    this.bits,
    this.comment,
  });

  /// The key in [bytes] (a private key file), or null when they hold none.
  static TomSecretsSshKeyInfo? parse(List<int> bytes) {
    final String text;
    try {
      text = utf8.decode(bytes);
    } on FormatException {
      return null;
    }
    final SshPem? pem;
    try {
      pem = SshPem.find(text);
    } on FormatException {
      return null;
    }
    if (pem == null) return null;
    try {
      return switch (pem.label) {
        'OPENSSH PRIVATE KEY' => _openssh(pem.body),
        'RSA PRIVATE KEY' =>
          pem.encrypted
              ? const TomSecretsSshKeyInfo._(
                  format: TomSecretsSshKeyFormat.pkcs1,
                  encrypted: true,
                  keyType: 'ssh-rsa',
                )
              : _rsa(SshDer(pem.body).sequence(), TomSecretsSshKeyFormat.pkcs1),
        'EC PRIVATE KEY' =>
          pem.encrypted
              ? const TomSecretsSshKeyInfo._(
                  format: TomSecretsSshKeyFormat.sec1,
                  encrypted: true,
                )
              : _ec(
                  SshDer(pem.body).sequence(),
                  null,
                  TomSecretsSshKeyFormat.sec1,
                ),
        'PRIVATE KEY' => _pkcs8(pem.body),
        'ENCRYPTED PRIVATE KEY' => const TomSecretsSshKeyInfo._(
          format: TomSecretsSshKeyFormat.pkcs8Encrypted,
          encrypted: true,
        ),
        'DSA PRIVATE KEY' => TomSecretsSshKeyInfo._(
          format: TomSecretsSshKeyFormat.dsa,
          encrypted: pem.encrypted,
          keyType: 'ssh-dss',
        ),
        _ => null,
      };
    } on FormatException {
      return null;
    } on RangeError {
      return null;
    }
  }

  /// How the file is written.
  final TomSecretsSshKeyFormat format;

  /// Whether the private key is encrypted under a passphrase (kept in the
  /// entry's `Password`).
  final bool encrypted;

  /// The SSH key type (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, ...),
  /// or null when the file does not say it without its passphrase.
  final String? keyType;

  /// The public key in SSH's wire form, or null when it cannot be read
  /// without the passphrase.
  final Uint8List? publicKeyBlob;

  /// The key size in bits (RSA's modulus, the curve's), or null.
  final int? bits;

  /// The key's comment, when the file carries it unencrypted.
  final String? comment;

  /// The public key as `authorized_keys` writes it (the type, the base64
  /// of the key, the comment), or null.
  String? get publicKey {
    final blob = publicKeyBlob;
    if (blob == null || keyType == null) return null;
    final c = comment;
    return '$keyType ${base64.encode(blob)}${c == null || c.isEmpty ? '' : ' $c'}';
  }

  /// The fingerprint as `ssh-keygen -l` prints it (`SHA256:<base64>`), or
  /// null.
  String? get fingerprint {
    final blob = publicKeyBlob;
    if (blob == null) return null;
    final digest = crypto.sha256.convert(blob).bytes;
    return 'SHA256:${base64.encode(digest).replaceAll('=', '')}';
  }

  static TomSecretsSshKeyInfo _openssh(Uint8List body) {
    const magic = 'openssh-key-v1\u0000';
    final head = ascii.decode(body.sublist(0, magic.length));
    if (head != magic) throw const FormatException('not openssh-key-v1');
    final r = SshWire(body, magic.length);
    final cipher = r.text();
    r.string(); // kdfname
    r.string(); // kdfoptions
    if (r.uint32() < 1) throw const FormatException('no key');
    final blob = r.string();
    final keyType = SshWire(blob).text();
    final encrypted = cipher != 'none';
    String? comment;
    if (!encrypted) {
      final p = SshWire(r.string());
      final check1 = p.uint32();
      final check2 = p.uint32();
      if (check1 != check2) throw const FormatException('check ints differ');
      p.text(); // key type
      _skipPrivate(p, keyType);
      comment = p.text();
    }
    return TomSecretsSshKeyInfo._(
      format: TomSecretsSshKeyFormat.openssh,
      encrypted: encrypted,
      keyType: keyType,
      publicKeyBlob: blob,
      bits: _bitsOf(blob),
      comment: comment,
    );
  }

  static void _skipPrivate(SshWire p, String keyType) {
    final fields = switch (keyType) {
      'ssh-ed25519' => 2,
      'ssh-rsa' => 6,
      'ssh-dss' => 5,
      final t when t.startsWith('ecdsa-sha2-') => 3,
      final t when t.startsWith('sk-') => 4,
      _ => throw const FormatException('unknown key type'),
    };
    for (var i = 0; i < fields; i++) {
      p.string();
    }
  }

  static int? _bitsOf(Uint8List blob) {
    final r = SshWire(blob);
    final type = r.text();
    if (type == 'ssh-ed25519') return 256;
    if (type == 'ssh-rsa') {
      r.string(); // e
      return _bitLength(r.string());
    }
    if (type.startsWith('ecdsa-sha2-nistp')) {
      return int.tryParse(type.substring('ecdsa-sha2-nistp'.length));
    }
    return null;
  }

  static int _bitLength(Uint8List mpint) {
    var i = 0;
    while (i < mpint.length && mpint[i] == 0) {
      i++;
    }
    if (i == mpint.length) return 0;
    return (mpint.length - i - 1) * 8 + mpint[i].bitLength;
  }

  /// A PKCS#1 RSAPrivateKey: version, n, e, ...
  static TomSecretsSshKeyInfo _rsa(
    List<SshDerItem> items,
    TomSecretsSshKeyFormat format,
  ) {
    final n = items[1].content;
    final e = items[2].content;
    final blob =
        (SshWireWriter()
              ..text('ssh-rsa')
              ..mpintBytes(e)
              ..mpintBytes(n))
            .bytes;
    return TomSecretsSshKeyInfo._(
      format: format,
      encrypted: false,
      keyType: 'ssh-rsa',
      publicKeyBlob: blob,
      bits: _bitLength(n),
    );
  }

  static const Map<String, String> _curves = {
    '1.2.840.10045.3.1.7': 'nistp256',
    '1.3.132.0.34': 'nistp384',
    '1.3.132.0.35': 'nistp521',
  };

  /// A SEC1 ECPrivateKey: version, the private key, [0] the curve, [1] the
  /// public key.
  static TomSecretsSshKeyInfo _ec(
    List<SshDerItem> items,
    String? curveOid,
    TomSecretsSshKeyFormat format,
  ) {
    String? oid = curveOid;
    Uint8List? point;
    for (final item in items.skip(2)) {
      if (item.tag == 0xa0) {
        final param = SshDer(item.content).read();
        // A named curve; explicit parameters (LibreSSL writes them) are
        // known by the point's length below.
        if (param.tag == 0x06) oid = param.oid;
      }
      if (item.tag == 0xa1) {
        final bits = SshDer(item.content).read();
        point = bits.content.sublist(1); // the unused-bits byte
      }
    }
    final curve = oid != null
        ? _curves[oid]
        : switch (point?.length) {
            65 => 'nistp256',
            97 => 'nistp384',
            133 => 'nistp521',
            _ => null,
          };
    final keyType = curve == null ? null : 'ecdsa-sha2-$curve';
    return TomSecretsSshKeyInfo._(
      format: format,
      encrypted: false,
      keyType: keyType,
      publicKeyBlob: keyType == null || point == null
          ? null
          : (SshWireWriter()
                  ..text(keyType)
                  ..text(curve!)
                  ..bytes_(point))
                .bytes,
      bits: curve == null ? null : int.parse(curve.substring(5)),
    );
  }

  static TomSecretsSshKeyInfo _pkcs8(Uint8List body) {
    final items = SshDer(body).sequence();
    final algorithm = SshDer(items[1].content);
    final oid = algorithm.read().oid;
    final key = items[2].content;
    switch (oid) {
      case '1.2.840.113549.1.1.1':
        return _rsa(SshDer(key).sequence(), TomSecretsSshKeyFormat.pkcs8);
      case '1.2.840.10045.2.1':
        // A named curve, or explicit parameters (LibreSSL), known by the
        // point's length.
        final params = algorithm.read();
        return _ec(
          SshDer(key).sequence(),
          params.tag == 0x06 ? params.oid : null,
          TomSecretsSshKeyFormat.pkcs8,
        );
      case '1.3.101.112':
        // The public key is not in the file; it needs Ed25519's
        // derivation, which the agent makes when it loads the key.
        return const TomSecretsSshKeyInfo._(
          format: TomSecretsSshKeyFormat.pkcs8,
          encrypted: false,
          keyType: 'ssh-ed25519',
          bits: 256,
        );
      default:
        throw const FormatException('unknown PKCS#8 algorithm');
    }
  }
}

/// The algorithm of a generated SSH key (DP-179).
enum TomSecretsSshKeyAlgorithm {
  /// Ed25519 (the default).
  ed25519,

  /// RSA 4096, for a tool that needs RSA.
  rsa,
}

/// A generated SSH key: the private key file (OpenSSH format, not
/// encrypted: the vault protects it) and what it says.
final class TomSecretsGeneratedSshKey {
  const TomSecretsGeneratedSshKey._(this.privateKey, this.info);

  /// The private key file, `-----BEGIN OPENSSH PRIVATE KEY-----`.
  final Uint8List privateKey;

  /// Its type, public key and fingerprint.
  final TomSecretsSshKeyInfo info;
}

/// A new SSH key (DP-179): Ed25519, or RSA of [rsaBits] (4096; less only for
/// tests) with [algorithm] `rsa`, carrying [comment]. The private key is
/// written in OpenSSH's format without a passphrase: the vault protects it,
/// and the entry's `Password` stays empty.
Future<TomSecretsGeneratedSshKey> tomSecretsGenerateSshKey({
  TomSecretsSshKeyAlgorithm algorithm = TomSecretsSshKeyAlgorithm.ed25519,
  String comment = '',
  int rsaBits = 4096,
  Random? random,
}) async {
  final rng = random ?? Random.secure();
  final Uint8List publicBlob;
  final Uint8List privateFields;
  final String keyType;
  switch (algorithm) {
    case TomSecretsSshKeyAlgorithm.ed25519:
      keyType = 'ssh-ed25519';
      final seed = Uint8List.fromList(
        List.generate(32, (_) => rng.nextInt(256)),
      );
      final pair = await cg.Ed25519().newKeyPairFromSeed(seed);
      final public = Uint8List.fromList((await pair.extractPublicKey()).bytes);
      publicBlob =
          (SshWireWriter()
                ..text(keyType)
                ..bytes_(public))
              .bytes;
      privateFields =
          (SshWireWriter()
                ..bytes_(public)
                ..bytes_(Uint8List.fromList([...seed, ...public])))
              .bytes;
      seed.fillRange(0, seed.length, 0);
    case TomSecretsSshKeyAlgorithm.rsa:
      keyType = 'ssh-rsa';
      final secure = pc.FortunaRandom()
        ..seed(
          pc.KeyParameter(
            Uint8List.fromList(List.generate(32, (_) => rng.nextInt(256))),
          ),
        );
      final generator = pc.RSAKeyGenerator()
        ..init(
          pc.ParametersWithRandom(
            pc.RSAKeyGeneratorParameters(BigInt.from(65537), rsaBits, 64),
            secure,
          ),
        );
      final pair = generator.generateKeyPair();
      final private = pair.privateKey;
      final n = private.modulus!;
      final e = private.publicExponent!;
      final p = private.p!;
      final q = private.q!;
      final iqmp = q.modInverse(p);
      publicBlob =
          (SshWireWriter()
                ..text(keyType)
                ..mpint(e)
                ..mpint(n))
              .bytes;
      privateFields =
          (SshWireWriter()
                ..mpint(n)
                ..mpint(e)
                ..mpint(private.privateExponent!)
                ..mpint(iqmp)
                ..mpint(p)
                ..mpint(q))
              .bytes;
  }
  final check = rng.nextInt(1 << 32);
  final section = SshWireWriter()
    ..uint32(check)
    ..uint32(check)
    ..text(keyType)
    ..raw(privateFields)
    ..text(comment);
  for (var pad = 1; section.length % 8 != 0; pad++) {
    section.raw([pad]);
  }
  final body = SshWireWriter()
    ..raw(ascii.encode('openssh-key-v1\u0000'))
    ..text('none')
    ..text('none')
    ..text('')
    ..uint32(1)
    ..bytes_(publicBlob)
    ..bytes_(section.bytes);
  privateFields.fillRange(0, privateFields.length, 0);
  final file = Uint8List.fromList(
    utf8.encode(SshPem.write('OPENSSH PRIVATE KEY', body.bytes)),
  );
  return TomSecretsGeneratedSshKey._(file, TomSecretsSshKeyInfo.parse(file)!);
}

/// KeePassXC's (and KeeAgent's) per-entry SSH agent settings, the
/// `KeeAgent.settings` attachment: where the key is and how the agent
/// adds it. Read from UTF-8 or UTF-16; written as UTF-16 with a byte order
/// mark, as KeeAgent reads it.
final class TomSecretsKeeAgentSettings {
  /// Settings for the key in the attachment [attachmentName].
  const TomSecretsKeeAgentSettings({
    this.allowUseOfSshKey = true,
    this.addAtDatabaseOpen = true,
    this.removeAtDatabaseClose = true,
    this.useConfirmConstraintWhenAdding = false,
    this.useLifetimeConstraintWhenAdding = false,
    this.lifetimeConstraintDuration = 600,
    this.selectedType = 'attachment',
    this.attachmentName,
    this.saveAttachmentToTempFile = false,
    this.fileName,
  });

  /// The settings in [bytes], or null when they are not KeeAgent settings.
  static TomSecretsKeeAgentSettings? parse(List<int> bytes) {
    final text = _decodeText(bytes);
    if (text == null || !text.contains('<EntrySettings')) return null;
    String? tag(String name) {
      final m = RegExp(
        '<$name(?:\\s[^>]*)?>([^<]*)</$name>|<$name\\s*/>',
      ).firstMatch(text);
      if (m == null) return null;
      return _unescape(m.group(1) ?? '');
    }

    bool flag(String name, bool fallback) => switch (tag(name)?.trim()) {
      'true' => true,
      'false' => false,
      _ => fallback,
    };
    String? blank(String? v) => v == null || v.isEmpty ? null : v;
    return TomSecretsKeeAgentSettings(
      allowUseOfSshKey: flag('AllowUseOfSshKey', true),
      addAtDatabaseOpen: flag('AddAtDatabaseOpen', true),
      removeAtDatabaseClose: flag('RemoveAtDatabaseClose', true),
      useConfirmConstraintWhenAdding: flag(
        'UseConfirmConstraintWhenAdding',
        false,
      ),
      useLifetimeConstraintWhenAdding: flag(
        'UseLifetimeConstraintWhenAdding',
        false,
      ),
      lifetimeConstraintDuration:
          int.tryParse(tag('LifetimeConstraintDuration') ?? '') ?? 600,
      selectedType: tag('SelectedType')?.trim() ?? 'attachment',
      attachmentName: blank(tag('AttachmentName')),
      saveAttachmentToTempFile: flag('SaveAttachmentToTempFile', false),
      fileName: blank(tag('FileName')),
    );
  }

  /// Whether the agent may use the key.
  final bool allowUseOfSshKey;

  /// Whether the key is added when the vault opens.
  final bool addAtDatabaseOpen;

  /// Whether the key is removed when the vault closes.
  final bool removeAtDatabaseClose;

  /// Whether each use asks for confirmation.
  final bool useConfirmConstraintWhenAdding;

  /// Whether the key is added for a limited time.
  final bool useLifetimeConstraintWhenAdding;

  /// That time, in seconds.
  final int lifetimeConstraintDuration;

  /// `attachment` (the key is an attachment of the entry) or `file`.
  final String selectedType;

  /// The attachment holding the key.
  final String? attachmentName;

  /// Whether KeePassXC writes the key to a temporary file.
  final bool saveAttachmentToTempFile;

  /// The key file outside the vault, for `selectedType` `file`.
  final String? fileName;

  /// These settings with the members given replaced.
  TomSecretsKeeAgentSettings copyWith({
    bool? allowUseOfSshKey,
    bool? addAtDatabaseOpen,
    bool? useConfirmConstraintWhenAdding,
  }) => TomSecretsKeeAgentSettings(
    allowUseOfSshKey: allowUseOfSshKey ?? this.allowUseOfSshKey,
    addAtDatabaseOpen: addAtDatabaseOpen ?? this.addAtDatabaseOpen,
    removeAtDatabaseClose: removeAtDatabaseClose,
    useConfirmConstraintWhenAdding:
        useConfirmConstraintWhenAdding ?? this.useConfirmConstraintWhenAdding,
    useLifetimeConstraintWhenAdding: useLifetimeConstraintWhenAdding,
    lifetimeConstraintDuration: lifetimeConstraintDuration,
    selectedType: selectedType,
    attachmentName: attachmentName,
    saveAttachmentToTempFile: saveAttachmentToTempFile,
    fileName: fileName,
  );

  /// The XML as KeePassXC writes it.
  String toXml() {
    String e(String v) => v
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;');
    String item(String name, String? value) => value == null || value.isEmpty
        ? '<$name />'
        : '<$name>${e(value)}</$name>';
    return '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
        '  <AllowUseOfSshKey>$allowUseOfSshKey</AllowUseOfSshKey>\n'
        '  <AddAtDatabaseOpen>$addAtDatabaseOpen</AddAtDatabaseOpen>\n'
        '  <RemoveAtDatabaseClose>$removeAtDatabaseClose</RemoveAtDatabaseClose>\n'
        '  <UseConfirmConstraintWhenAdding>$useConfirmConstraintWhenAdding</UseConfirmConstraintWhenAdding>\n'
        '  <UseLifetimeConstraintWhenAdding>$useLifetimeConstraintWhenAdding</UseLifetimeConstraintWhenAdding>\n'
        '  <LifetimeConstraintDuration>$lifetimeConstraintDuration</LifetimeConstraintDuration>\n'
        '  <Location>\n'
        '    <SelectedType>$selectedType</SelectedType>\n'
        '    ${item('AttachmentName', attachmentName)}\n'
        '    <SaveAttachmentToTempFile>$saveAttachmentToTempFile</SaveAttachmentToTempFile>\n'
        '    ${item('FileName', fileName)}\n'
        '  </Location>\n'
        '</EntrySettings>\n';
  }

  /// The attachment's bytes: [toXml] as UTF-16 little-endian with a byte
  /// order mark.
  Uint8List toBytes() {
    final units = toXml().codeUnits;
    final out = ByteData(2 + units.length * 2)
      ..setUint16(0, 0xfeff, Endian.little);
    for (var i = 0; i < units.length; i++) {
      out.setUint16(2 + i * 2, units[i], Endian.little);
    }
    return out.buffer.asUint8List();
  }

  static String? _decodeText(List<int> bytes) {
    if (bytes.length >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe) {
      return _utf16(bytes.sublist(2), Endian.little);
    }
    if (bytes.length >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff) {
      return _utf16(bytes.sublist(2), Endian.big);
    }
    if (bytes.length >= 2 && bytes[1] == 0 && bytes[0] == 0x3c) {
      return _utf16(bytes, Endian.little);
    }
    try {
      final t = utf8.decode(bytes);
      return t.startsWith('﻿') ? t.substring(1) : t;
    } on FormatException {
      return null;
    }
  }

  static String _utf16(List<int> bytes, Endian endian) {
    final data = ByteData.sublistView(Uint8List.fromList(bytes));
    return String.fromCharCodes([
      for (var i = 0; i + 1 < bytes.length; i += 2) data.getUint16(i, endian),
    ]);
  }

  static String _unescape(String v) => v
      .replaceAll('&lt;', '<')
      .replaceAll('&gt;', '>')
      .replaceAll('&quot;', '"')
      .replaceAll('&apos;', "'")
      .replaceAll('&amp;', '&');
}

// ── Entries ──────────────────────────────────────────────────────────────

/// The SSH key of [entry]: the attachment its `KeeAgent.settings` names, else
/// the first attachment holding a private key; null when it has none.
({String name, Uint8List bytes, TomSecretsSshKeyInfo info})? tomSecretsSshKeyOf(
  KdbxEntry entry,
) {
  final named = _settingsOf(entry)?.attachmentName;
  if (named != null) {
    final binary = entry.getBinary(KdbxKey(named));
    final info = binary == null
        ? null
        : TomSecretsSshKeyInfo.parse(binary.value);
    if (binary != null && info != null) {
      return (name: named, bytes: binary.value, info: info);
    }
  }
  for (final MapEntry(:key, :value) in entry.binaryEntries) {
    if (key.key == tomSecretsKeeAgentSettingsName) continue;
    final info = TomSecretsSshKeyInfo.parse(value.value);
    if (info != null) return (name: key.key, bytes: value.value, info: info);
  }
  return null;
}

/// The `KeeAgent.settings` of [entry], or null when it has none.
TomSecretsKeeAgentSettings? tomSecretsKeeAgentSettingsOf(KdbxEntry entry) =>
    _settingsOf(entry);

/// Writes [settings] as [entry]'s `KeeAgent.settings` (replacing the one it
/// has); the entry as it was goes to its history.
void tomSecretsWriteKeeAgentSettings(
  KdbxEntry entry,
  TomSecretsKeeAgentSettings settings,
) {
  entry.modify(() {
    entry.removeBinary(const KdbxKey(tomSecretsKeeAgentSettingsName));
    entry.createBinary(
      isProtected: false,
      name: tomSecretsKeeAgentSettingsName,
      bytes: settings.toBytes(),
    );
  });
}

TomSecretsKeeAgentSettings? _settingsOf(KdbxEntry entry) {
  final binary = entry.getBinary(const KdbxKey(tomSecretsKeeAgentSettingsName));
  return binary == null ? null : TomSecretsKeeAgentSettings.parse(binary.value);
}

/// Makes [entry] an SSH key entry: `tsm.type` `ssh-key`, the private key
/// [privateKey] as the attachment [attachmentName] (protected, replacing one
/// of that name), and `KeeAgent.settings` naming it (an existing one keeps
/// its other settings). [passphrase], when given, goes to `Password`.
void tomSecretsWriteSshKey(
  KdbxEntry entry, {
  required String attachmentName,
  required Uint8List privateKey,
  String? passphrase,
}) {
  entry.modify(() {
    entry.setString(
      TomSecretsEntryFields.type,
      PlainValue(TomSecretsEntryType.sshKey.wireName),
    );
    entry.removeBinary(KdbxKey(attachmentName));
    entry.createBinary(
      isProtected: true,
      name: attachmentName,
      bytes: privateKey,
    );
    _writeSettings(entry, attachmentName);
    if (passphrase != null) {
      entry.setString(
        KdbxKeyCommon.PASSWORD,
        ProtectedValue.fromString(passphrase),
      );
    }
  });
}

void _writeSettings(KdbxEntry entry, String attachmentName) {
  final old = _settingsOf(entry) ?? const TomSecretsKeeAgentSettings();
  final settings = TomSecretsKeeAgentSettings(
    allowUseOfSshKey: old.allowUseOfSshKey,
    addAtDatabaseOpen: old.addAtDatabaseOpen,
    removeAtDatabaseClose: old.removeAtDatabaseClose,
    useConfirmConstraintWhenAdding: old.useConfirmConstraintWhenAdding,
    useLifetimeConstraintWhenAdding: old.useLifetimeConstraintWhenAdding,
    lifetimeConstraintDuration: old.lifetimeConstraintDuration,
    attachmentName: attachmentName,
    saveAttachmentToTempFile: old.saveAttachmentToTempFile,
  );
  entry.removeBinary(const KdbxKey(tomSecretsKeeAgentSettingsName));
  entry.createBinary(
    isProtected: false,
    name: tomSecretsKeeAgentSettingsName,
    bytes: settings.toBytes(),
  );
}

/// The entries of [file] that hold an SSH private key as an attachment but
/// are not typed `ssh-key` (part-structure, DP-5): phase A's `note` entries
/// (the 1Password import's SSH keys, hand-made secure notes with a key)
/// and entries KeePassXC made (a `KeeAgent.settings` attachment). Entries in
/// the recycle bin and history versions are left out.
List<KdbxEntry> tomSecretsSshKeyCandidates(KdbxFile file) {
  final bin = file.recycleBin;
  final out = <KdbxEntry>[];
  void walk(KdbxGroup group) {
    if (bin != null && group.uuid == bin.uuid) return;
    for (final entry in group.entries) {
      final type = TomSecretsEntryType.of(
        entry.getString(TomSecretsEntryFields.type)?.getText(),
      );
      if (type == TomSecretsEntryType.sshKey) continue;
      final hasSettings =
          entry.getBinary(const KdbxKey(tomSecretsKeeAgentSettingsName)) !=
          null;
      if (type != TomSecretsEntryType.note && !hasSettings) continue;
      if (tomSecretsSshKeyOf(entry) != null) out.add(entry);
    }
    group.groups.forEach(walk);
  }

  walk(file.body.rootGroup);
  return out;
}

/// Retypes [tomSecretsSshKeyCandidates] of [file] as SSH key entries: each
/// gets `tsm.type` `ssh-key` and a `KeeAgent.settings` naming its key's
/// attachment (an existing one keeps its other settings). The entry as it
/// was goes to its history. Answers the entries retyped; nothing else
/// changes.
List<KdbxEntry> tomSecretsMigrateSshKeys(KdbxFile file) {
  final migrated = tomSecretsSshKeyCandidates(file);
  for (final entry in migrated) {
    final key = tomSecretsSshKeyOf(entry)!;
    entry.modify(() {
      entry.setString(
        TomSecretsEntryFields.type,
        PlainValue(TomSecretsEntryType.sshKey.wireName),
      );
      _writeSettings(entry, key.name);
    });
  }
  return migrated;
}

/// Whether the agent serves an entry's SSH key (part-os-integration).
enum TomSecretsSshAgentServing {
  /// The agent offers the key.
  served,

  /// The entry is not an `ssh-key` entry.
  notSshKey,

  /// The entry holds no key the agent reads.
  noKey,

  /// `KeeAgent.settings` does not allow the agent to use the key.
  notAllowed,

  /// `KeeAgent.settings` does not add the key when the vault opens.
  notAdded,

  /// `KeeAgent.settings` names a key file outside the vault.
  keyFileOutside,

  /// The key type is one the agent does not sign with (DSA, security keys).
  unsupported,

  /// The key is encrypted and the entry's `Password` is empty.
  passphraseMissing,
}

/// The key types the agent signs with.
const Set<String> tomSecretsSshAgentKeyTypes = {
  'ssh-ed25519',
  'ssh-rsa',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
};

/// Whether and how the agent serves [entry]'s SSH key: the state, the key
/// (when there is one), and whether each use is confirmed (KeeAgent's
/// "require confirmation", `UseConfirmConstraintWhenAdding`).
({
  TomSecretsSshAgentServing state,
  ({String name, Uint8List bytes, TomSecretsSshKeyInfo info})? key,
  bool confirm,
})
tomSecretsSshAgentStateOf(KdbxEntry entry) {
  final type = TomSecretsEntryType.of(
    entry.getString(TomSecretsEntryFields.type)?.getText(),
  );
  final settings = _settingsOf(entry);
  final confirm = settings?.useConfirmConstraintWhenAdding ?? false;
  if (type != TomSecretsEntryType.sshKey) {
    return (
      state: TomSecretsSshAgentServing.notSshKey,
      key: null,
      confirm: confirm,
    );
  }
  if (settings != null && !settings.allowUseOfSshKey) {
    return (
      state: TomSecretsSshAgentServing.notAllowed,
      key: null,
      confirm: confirm,
    );
  }
  if (settings != null && settings.selectedType == 'file') {
    return (
      state: TomSecretsSshAgentServing.keyFileOutside,
      key: null,
      confirm: confirm,
    );
  }
  final key = tomSecretsSshKeyOf(entry);
  if (key == null) {
    return (
      state: TomSecretsSshAgentServing.noKey,
      key: null,
      confirm: confirm,
    );
  }
  final keyType = key.info.keyType;
  if (key.info.format == TomSecretsSshKeyFormat.dsa ||
      (keyType != null && !tomSecretsSshAgentKeyTypes.contains(keyType))) {
    return (
      state: TomSecretsSshAgentServing.unsupported,
      key: key,
      confirm: confirm,
    );
  }
  if (settings != null && !settings.addAtDatabaseOpen) {
    return (
      state: TomSecretsSshAgentServing.notAdded,
      key: key,
      confirm: confirm,
    );
  }
  if (key.info.encrypted &&
      (entry.getString(KdbxKeyCommon.PASSWORD)?.getText() ?? '').isEmpty) {
    return (
      state: TomSecretsSshAgentServing.passphraseMissing,
      key: key,
      confirm: confirm,
    );
  }
  return (state: TomSecretsSshAgentServing.served, key: key, confirm: confirm);
}
