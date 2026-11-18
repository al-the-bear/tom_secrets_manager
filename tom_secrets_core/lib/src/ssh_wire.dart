// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// The encodings SSH keys are written in, shared by the key files
/// (`ssh_key.dart`) and the agent (`ssh_agent.dart`): PEM blocks, SSH's wire
/// strings (RFC 4251 section 5), and the DER of PKCS#1, SEC1 and PKCS#8.
/// Internal to the package (not exported).
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// A PEM block: its label, its decoded body, and its RFC 1421 headers
/// (`Proc-Type`, `DEK-Info`).
final class SshPem {
  /// A block.
  const SshPem(this.label, this.body, this.headers);

  /// `OPENSSH PRIVATE KEY`, `RSA PRIVATE KEY`, ...
  final String label;

  /// The base64-decoded body.
  final Uint8List body;

  /// The headers, by name.
  final Map<String, String> headers;

  /// Whether `Proc-Type` says the body is encrypted.
  bool get encrypted => headers['Proc-Type']?.contains('ENCRYPTED') ?? false;

  static final RegExp _block = RegExp(
    r'-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]*?)-----END \1-----',
  );

  /// The first block of [text], or null. Throws [FormatException] for a body
  /// that is not base64.
  static SshPem? find(String text) {
    final m = _block.firstMatch(text);
    if (m == null) return null;
    final lines = m.group(2)!.split(RegExp(r'\r?\n'));
    final headers = <String, String>{};
    final data = StringBuffer();
    for (final line in lines) {
      final t = line.trim();
      if (t.isEmpty) continue;
      final colon = t.indexOf(':');
      if (colon > 0) {
        headers[t.substring(0, colon).trim()] = t.substring(colon + 1).trim();
        continue;
      }
      data.write(t);
    }
    return SshPem(m.group(1)!, base64.decode(data.toString()), headers);
  }

  /// [body] as a PEM block labelled [label], 70 characters a line.
  static String write(String label, List<int> body) {
    final text = base64.encode(body);
    final out = StringBuffer('-----BEGIN $label-----\n');
    for (var i = 0; i < text.length; i += 70) {
      out.writeln(text.substring(i, min(i + 70, text.length)));
    }
    out.writeln('-----END $label-----');
    return out.toString();
  }
}

/// Reads SSH's wire encoding. Every read throws [FormatException] past the
/// end.
final class SshWire {
  /// A reader of [data] from [at].
  SshWire(this.data, [this.at = 0]);

  /// The bytes read.
  final Uint8List data;

  /// The read position.
  int at;

  /// Whether everything is read.
  bool get done => at >= data.length;

  void _need(int n) {
    if (n < 0 || at + n > data.length) throw const FormatException('short');
  }

  /// A byte.
  int byte() {
    _need(1);
    return data[at++];
  }

  /// A boolean (a byte, non-zero true).
  bool boolean() => byte() != 0;

  /// A big-endian uint32.
  int uint32() {
    _need(4);
    final v = ByteData.sublistView(data, at, at + 4).getUint32(0);
    at += 4;
    return v;
  }

  /// A length-prefixed string, as a view of [data].
  Uint8List string() {
    final length = uint32();
    _need(length);
    final v = Uint8List.sublistView(data, at, at + length);
    at += length;
    return v;
  }

  /// A string as UTF-8 text.
  String text() => utf8.decode(string());

  /// An mpint as a non-negative integer (a negative one is refused).
  BigInt mpint() {
    final b = string();
    if (b.isNotEmpty && b[0] & 0x80 != 0) {
      throw const FormatException('negative mpint');
    }
    return sshBigIntOf(b);
  }

  /// The [n] next bytes.
  Uint8List raw(int n) {
    _need(n);
    final v = Uint8List.sublistView(data, at, at + n);
    at += n;
    return v;
  }

  /// What is left.
  Uint8List rest() => raw(data.length - at);
}

/// Writes SSH's wire encoding.
final class SshWireWriter {
  final BytesBuilder _out = BytesBuilder();

  /// The bytes written so far.
  int get length => _out.length;

  /// The bytes written.
  Uint8List get bytes => _out.toBytes();

  /// [b] as they are.
  void raw(List<int> b) => _out.add(b);

  /// A byte.
  void byte(int v) => _out.addByte(v);

  /// A big-endian uint32.
  void uint32(int v) =>
      _out.add((ByteData(4)..setUint32(0, v)).buffer.asUint8List());

  /// [b] as a length-prefixed string.
  // ignore: non_constant_identifier_names
  void bytes_(List<int> b) {
    uint32(b.length);
    _out.add(b);
  }

  /// [s] as a UTF-8 string.
  void text(String s) => bytes_(utf8.encode(s));

  /// An mpint of the unsigned magnitude [magnitude] (big-endian), a zero
  /// byte added when its high bit is set.
  void mpintBytes(List<int> magnitude) {
    var i = 0;
    while (i < magnitude.length - 1 && magnitude[i] == 0) {
      i++;
    }
    final m = magnitude.sublist(i);
    if (m.isEmpty || (m.length == 1 && m[0] == 0)) {
      bytes_(const []);
    } else if (m[0] & 0x80 != 0) {
      bytes_([0, ...m]);
    } else {
      bytes_(m);
    }
  }

  /// An mpint of [v] (non-negative).
  void mpint(BigInt v) => mpintBytes(sshBytesOf(v));
}

/// The non-negative integer of the big-endian [bytes].
BigInt sshBigIntOf(List<int> bytes) {
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  return v;
}

/// [v] (non-negative) big-endian, at least one byte; left-padded with zeros
/// to [length] when given.
Uint8List sshBytesOf(BigInt v, [int? length]) {
  final hex = v.toRadixString(16);
  final padded = hex.length.isOdd ? '0$hex' : hex;
  final raw = [
    for (var i = 0; i < padded.length; i += 2)
      int.parse(padded.substring(i, i + 2), radix: 16),
  ];
  if (length == null || raw.length >= length) return Uint8List.fromList(raw);
  return Uint8List(length)..setRange(length - raw.length, length, raw);
}

/// One DER item: its tag and content.
final class SshDerItem {
  /// An item.
  const SshDerItem(this.tag, this.content);

  /// The tag byte.
  final int tag;

  /// The content.
  final Uint8List content;

  /// The dotted object identifier of an OID. Throws [FormatException] for
  /// another tag.
  String get oid {
    if (tag != 0x06) throw const FormatException('not an OID');
    final parts = <int>[content[0] ~/ 40, content[0] % 40];
    var v = 0;
    for (final b in content.skip(1)) {
      v = (v << 7) | (b & 0x7f);
      if (b & 0x80 == 0) {
        parts.add(v);
        v = 0;
      }
    }
    return parts.join('.');
  }

  /// The items of a constructed item (a SEQUENCE, a context tag).
  List<SshDerItem> get children => SshDer(content).all();

  /// An INTEGER as a non-negative integer.
  BigInt get integer => sshBigIntOf(content);
}

/// Reads DER.
final class SshDer {
  /// A reader of [data].
  SshDer(this.data);

  /// The bytes read.
  final Uint8List data;
  int _at = 0;

  /// The next item. Throws [RangeError] past the end.
  SshDerItem read() {
    final tag = data[_at++];
    var length = data[_at++];
    if (length & 0x80 != 0) {
      final count = length & 0x7f;
      length = 0;
      for (var i = 0; i < count; i++) {
        length = (length << 8) | data[_at++];
      }
    }
    if (_at + length > data.length) throw RangeError('short DER');
    final content = Uint8List.sublistView(data, _at, _at + length);
    _at += length;
    return SshDerItem(tag, content);
  }

  /// Every item to the end.
  List<SshDerItem> all() {
    final items = <SshDerItem>[];
    while (_at < data.length) {
      items.add(read());
    }
    return items;
  }

  /// The items of the SEQUENCE this data is. Throws [FormatException] for
  /// another item.
  List<SshDerItem> sequence() {
    final outer = read();
    if (outer.tag != 0x30) throw const FormatException('not a SEQUENCE');
    return outer.children;
  }
}
