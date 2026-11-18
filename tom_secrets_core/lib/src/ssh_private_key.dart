// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// SSH private keys as the agent uses them (part-os-integration): a key file
/// decoded, with its passphrase when it is encrypted, and signatures made
/// and checked as SSH writes them.
///
/// - Key files: OpenSSH's `openssh-key-v1` (unencrypted, or encrypted under
///   `bcrypt_pbkdf` with AES in CTR, CBC or GCM mode), PEM PKCS#1 and SEC1
///   (also encrypted with `DEK-Info` AES-CBC or DES-EDE3-CBC), and PKCS#8
///   (also encrypted with PBES2: PBKDF2 and AES-CBC).
/// - Key types: Ed25519, ECDSA P-256 / P-384 / P-521 and RSA.
/// - Signatures: Ed25519; ECDSA with the curve's SHA-2 and deterministic
///   nonces (RFC 6979); RSA with SHA-256 or SHA-512 only (`rsa-sha2-256`,
///   `rsa-sha2-512`, RFC 8332): the SHA-1 `ssh-rsa` signature is refused.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cg;
import 'package:pointycastle/export.dart' as pc;

import 'bcrypt_pbkdf.dart';
import 'ssh_wire.dart';

/// Why a key file cannot be used.
enum TomSecretsSshKeyProblem {
  /// The file holds no private key the agent reads.
  malformed,

  /// The key is encrypted and no passphrase was given.
  passphraseNeeded,

  /// The passphrase does not decrypt the key.
  wrongPassphrase,

  /// The key type, cipher or key derivation is one the agent does not
  /// support (DSA, security keys, `chacha20-poly1305`, scrypt, ...).
  unsupported,
}

/// A key file that cannot be used, for [problem]; [detail] names what (never
/// key material).
final class TomSecretsSshKeyException implements Exception {
  /// An exception for [problem].
  const TomSecretsSshKeyException(this.problem, [this.detail]);

  /// What is wrong.
  final TomSecretsSshKeyProblem problem;

  /// Which type, cipher or field, when known.
  final String? detail;

  @override
  String toString() =>
      'TomSecretsSshKeyException: ${problem.name}'
      '${detail == null ? '' : ' ($detail)'}';
}

/// The RSA signature flags of a `SIGN_REQUEST` (draft-miller-ssh-agent).
abstract final class TomSecretsSshSignFlags {
  /// `SSH_AGENT_RSA_SHA2_256`.
  static const int rsaSha256 = 2;

  /// `SSH_AGENT_RSA_SHA2_512`.
  static const int rsaSha512 = 4;
}

/// A decoded SSH private key. Its material stays in this object until
/// [dispose].
final class TomSecretsSshPrivateKey {
  TomSecretsSshPrivateKey._(
    this.keyType,
    this.publicKeyBlob,
    this.comment,
    this._material,
  );

  /// The key in the private key file [file], decrypted with [passphrase]
  /// when it is encrypted. Throws [TomSecretsSshKeyException].
  static Future<TomSecretsSshPrivateKey> decode(
    List<int> file, {
    String? passphrase,
  }) async {
    final SshPem? pem;
    try {
      pem = SshPem.find(utf8.decode(file, allowMalformed: true));
    } on FormatException {
      throw const TomSecretsSshKeyException(TomSecretsSshKeyProblem.malformed);
    }
    if (pem == null) {
      throw const TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.malformed,
        'no PEM block',
      );
    }
    try {
      return switch (pem.label) {
        'OPENSSH PRIVATE KEY' => await _openssh(pem.body, passphrase),
        'RSA PRIVATE KEY' => _rsa(
          SshDer(_pemBody(pem, passphrase)).sequence(),
          null,
        ),
        'EC PRIVATE KEY' => _ec(
          SshDer(_pemBody(pem, passphrase)).sequence(),
          null,
        ),
        'PRIVATE KEY' => await _pkcs8(pem.body),
        'ENCRYPTED PRIVATE KEY' => await _pkcs8(
          _pbes2(pem.body, _needPassphrase(passphrase)),
          encrypted: true,
        ),
        'DSA PRIVATE KEY' => throw const TomSecretsSshKeyException(
          TomSecretsSshKeyProblem.unsupported,
          'ssh-dss',
        ),
        final other => throw TomSecretsSshKeyException(
          TomSecretsSshKeyProblem.malformed,
          other,
        ),
      };
    } on TomSecretsSshKeyException {
      rethrow;
    } on FormatException {
      throw const TomSecretsSshKeyException(TomSecretsSshKeyProblem.malformed);
    } on RangeError {
      throw const TomSecretsSshKeyException(TomSecretsSshKeyProblem.malformed);
    } on ArgumentError {
      throw const TomSecretsSshKeyException(TomSecretsSshKeyProblem.malformed);
    }
  }

  /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, ...
  final String keyType;

  /// The public key in SSH's wire form.
  final Uint8List publicKeyBlob;

  /// The comment the file carries, or empty.
  final String comment;

  final _KeyMaterial _material;
  bool _disposed = false;

  /// Signs [data] as SSH signs: the signature blob (`string algorithm,
  /// string signature`). An RSA key needs [flags] naming SHA-256 or SHA-512
  /// ([TomSecretsSshSignFlags]); SHA-1 is refused with [StateError]. Throws
  /// [StateError] after [dispose].
  Future<Uint8List> sign(List<int> data, {int flags = 0}) async {
    if (_disposed) throw StateError('disposed');
    final message = Uint8List.fromList(data);
    final w = SshWireWriter();
    switch (_material) {
      case _Ed25519(:final seed):
        final pair = await cg.Ed25519().newKeyPairFromSeed(seed);
        final sig = await cg.Ed25519().sign(message, keyPair: pair);
        w
          ..text('ssh-ed25519')
          ..bytes_(sig.bytes);
      case _Ecdsa(:final curve, :final d):
        final signer = pc.ECDSASigner(_digestOf(curve), _hmacOf(curve))
          ..init(
            true,
            pc.PrivateKeyParameter<pc.ECPrivateKey>(
              pc.ECPrivateKey(d, pc.ECDomainParameters(_pcCurve(curve))),
            ),
          );
        final sig = signer.generateSignature(message) as pc.ECSignature;
        final inner = SshWireWriter()
          ..mpint(sig.r)
          ..mpint(sig.s);
        w
          ..text('ecdsa-sha2-$curve')
          ..bytes_(inner.bytes);
      case _Rsa(:final n, :final d, :final p, :final q):
        final String algorithm;
        final pc.RSASigner signer;
        if (flags & TomSecretsSshSignFlags.rsaSha512 != 0) {
          algorithm = 'rsa-sha2-512';
          signer = pc.RSASigner(pc.SHA512Digest(), '0609608648016503040203');
        } else if (flags & TomSecretsSshSignFlags.rsaSha256 != 0) {
          algorithm = 'rsa-sha2-256';
          signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201');
        } else {
          throw StateError('RSA signs with SHA-2 only');
        }
        signer.init(
          true,
          pc.PrivateKeyParameter<pc.RSAPrivateKey>(
            pc.RSAPrivateKey(n, d, p, q),
          ),
        );
        final sig = signer.generateSignature(message);
        w
          ..text(algorithm)
          ..bytes_(sshBytesOf(sshBigIntOf(sig.bytes), (n.bitLength + 7) ~/ 8));
    }
    return w.bytes;
  }

  /// Forgets the key material (the integers cannot be wiped in place; the
  /// Ed25519 seed is zeroed).
  void dispose() {
    _disposed = true;
    if (_material case _Ed25519(:final seed)) {
      seed.fillRange(0, seed.length, 0);
    }
  }

  // ── openssh-key-v1 ──────────────────────────────────────────────────────

  static Future<TomSecretsSshPrivateKey> _openssh(
    Uint8List body,
    String? passphrase,
  ) async {
    const magic = 'openssh-key-v1\u0000';
    if (body.length < magic.length ||
        ascii.decode(body.sublist(0, magic.length), allowInvalid: true) !=
            magic) {
      throw const FormatException('not openssh-key-v1');
    }
    final r = SshWire(body, magic.length);
    final cipher = r.text();
    final kdf = r.text();
    final kdfOptions = r.string();
    if (r.uint32() != 1) {
      throw const TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.unsupported,
        'several keys in one file',
      );
    }
    r.string(); // the public key
    var private = r.string();
    if (cipher != 'none') {
      final spec = _cipherSpecs[cipher];
      if (spec == null || kdf != 'bcrypt') {
        throw TomSecretsSshKeyException(
          TomSecretsSshKeyProblem.unsupported,
          spec == null ? cipher : kdf,
        );
      }
      final pass = _needPassphrase(passphrase);
      final o = SshWire(kdfOptions);
      final salt = o.string();
      final rounds = o.uint32();
      final derived = tomSecretsBcryptPbkdf(
        utf8.encode(pass),
        salt,
        spec.keyLength + spec.ivLength,
        rounds,
      );
      final key = derived.sublist(0, spec.keyLength);
      final iv = derived.sublist(spec.keyLength);
      final tag = spec.gcm ? r.raw(16) : null;
      try {
        private = spec.decrypt(key, iv, private, tag);
      } on Object {
        throw const TomSecretsSshKeyException(
          TomSecretsSshKeyProblem.wrongPassphrase,
        );
      }
    }
    final p = SshWire(private);
    if (p.uint32() != p.uint32()) {
      throw cipher == 'none'
          ? const FormatException('check ints differ')
          : const TomSecretsSshKeyException(
              TomSecretsSshKeyProblem.wrongPassphrase,
            );
    }
    final type = p.text();
    final _KeyMaterial material;
    final Uint8List blob;
    switch (type) {
      case 'ssh-ed25519':
        final public = p.string();
        final secret = p.string();
        if (public.length != 32 || secret.length != 64) {
          throw const FormatException('ed25519 lengths');
        }
        material = _Ed25519(Uint8List.fromList(secret.sublist(0, 32)));
        blob =
            (SshWireWriter()
                  ..text(type)
                  ..bytes_(public))
                .bytes;
      case 'ssh-rsa':
        final n = p.mpint();
        final e = p.mpint();
        final d = p.mpint();
        p.mpint(); // iqmp
        final pp = p.mpint();
        final q = p.mpint();
        material = _Rsa(n, e, d, pp, q);
        blob = _rsaBlob(n, e);
      case final t when t.startsWith('ecdsa-sha2-'):
        final curve = p.text();
        final point = p.string();
        final d = p.mpint();
        if (!_curves.containsValue(curve) || t != 'ecdsa-sha2-$curve') {
          throw TomSecretsSshKeyException(
            TomSecretsSshKeyProblem.unsupported,
            t,
          );
        }
        material = _Ecdsa(curve, d);
        blob = _ecBlob(curve, point);
      default:
        throw TomSecretsSshKeyException(
          TomSecretsSshKeyProblem.unsupported,
          type,
        );
    }
    final comment = p.text();
    return TomSecretsSshPrivateKey._(type, blob, comment, material);
  }

  static const Map<String, _CipherSpec> _cipherSpecs = {
    'aes128-ctr': _CipherSpec(16, 16, _CipherMode.ctr),
    'aes192-ctr': _CipherSpec(24, 16, _CipherMode.ctr),
    'aes256-ctr': _CipherSpec(32, 16, _CipherMode.ctr),
    'aes128-cbc': _CipherSpec(16, 16, _CipherMode.cbc),
    'aes192-cbc': _CipherSpec(24, 16, _CipherMode.cbc),
    'aes256-cbc': _CipherSpec(32, 16, _CipherMode.cbc),
    'aes128-gcm@openssh.com': _CipherSpec(16, 12, _CipherMode.gcm),
    'aes256-gcm@openssh.com': _CipherSpec(32, 12, _CipherMode.gcm),
  };

  // ── PEM, PKCS#1, SEC1, PKCS#8 ───────────────────────────────────────────

  static String _needPassphrase(String? passphrase) {
    if (passphrase == null || passphrase.isEmpty) {
      throw const TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.passphraseNeeded,
      );
    }
    return passphrase;
  }

  /// The DER of [pem], decrypted after its `DEK-Info` when it is encrypted
  /// (OpenSSL's `EVP_BytesToKey` with MD5 and one iteration).
  static Uint8List _pemBody(SshPem pem, String? passphrase) {
    if (!pem.encrypted) return pem.body;
    final info = pem.headers['DEK-Info'];
    final comma = info?.indexOf(',') ?? -1;
    if (info == null || comma < 0) {
      throw const FormatException('no DEK-Info');
    }
    final name = info.substring(0, comma).toUpperCase();
    final iv = _hex(info.substring(comma + 1));
    final (keyLength, des) = switch (name) {
      'AES-128-CBC' => (16, false),
      'AES-192-CBC' => (24, false),
      'AES-256-CBC' => (32, false),
      'DES-EDE3-CBC' => (24, true),
      _ => throw TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.unsupported,
        name,
      ),
    };
    final pass = utf8.encode(_needPassphrase(passphrase));
    final key = <int>[];
    var previous = <int>[];
    while (key.length < keyLength) {
      previous = pc.MD5Digest().process(
        Uint8List.fromList([...previous, ...pass, ...iv.sublist(0, 8)]),
      );
      key.addAll(previous);
    }
    final engine = des ? pc.DESedeEngine() : pc.AESEngine();
    final clear = _cbcDecrypt(
      engine,
      Uint8List.fromList(key.sublist(0, keyLength)),
      iv,
      pem.body,
    );
    // A wrong passphrase shows as bad padding or DER that does not read.
    try {
      SshDer(clear).sequence();
    } on Object {
      throw const TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.wrongPassphrase,
      );
    }
    return clear;
  }

  /// PKCS#8's EncryptedPrivateKeyInfo under PBES2 (PBKDF2 with HMAC-SHA1,
  /// -SHA224, -SHA256, -SHA384 or -SHA512; AES-CBC).
  static Uint8List _pbes2(Uint8List body, String passphrase) {
    final top = SshDer(body).sequence();
    final algorithm = top[0].children;
    if (algorithm[0].oid != '1.2.840.113549.1.5.13') {
      throw TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.unsupported,
        algorithm[0].oid,
      );
    }
    final params = algorithm[1].children;
    final kdf = params[0].children;
    final scheme = params[1].children;
    if (kdf[0].oid != '1.2.840.113549.1.5.12') {
      throw TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.unsupported,
        kdf[0].oid,
      );
    }
    final kdfParams = kdf[1].children;
    final salt = kdfParams[0].content;
    final iterations = kdfParams[1].integer.toInt();
    var prf = '1.2.840.113549.2.7';
    for (final item in kdfParams.skip(2)) {
      if (item.tag == 0x30) prf = item.children[0].oid;
    }
    final digest = switch (prf) {
      '1.2.840.113549.2.7' => pc.SHA1Digest(),
      '1.2.840.113549.2.8' => pc.SHA224Digest(),
      '1.2.840.113549.2.9' => pc.SHA256Digest(),
      '1.2.840.113549.2.10' => pc.SHA384Digest(),
      '1.2.840.113549.2.11' => pc.SHA512Digest(),
      _ => throw TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.unsupported,
        prf,
      ),
    };
    final keyLength = switch (scheme[0].oid) {
      '2.16.840.1.101.3.4.1.2' => 16,
      '2.16.840.1.101.3.4.1.22' => 24,
      '2.16.840.1.101.3.4.1.42' => 32,
      _ => throw TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.unsupported,
        scheme[0].oid,
      ),
    };
    final iv = scheme[1].content;
    final derivator = pc.PBKDF2KeyDerivator(pc.HMac(digest, digest.byteLength))
      ..init(pc.Pbkdf2Parameters(salt, iterations, keyLength));
    final key = derivator.process(Uint8List.fromList(utf8.encode(passphrase)));
    final Uint8List clear;
    try {
      clear = _cbcDecrypt(pc.AESEngine(), key, iv, top[1].content);
      SshDer(clear).sequence();
    } on Object {
      throw const TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.wrongPassphrase,
      );
    }
    return clear;
  }

  static Uint8List _cbcDecrypt(
    pc.BlockCipher engine,
    Uint8List key,
    Uint8List iv,
    Uint8List data,
  ) {
    final cipher =
        pc.PaddedBlockCipherImpl(pc.PKCS7Padding(), pc.CBCBlockCipher(engine))
          ..init(
            false,
            pc.PaddedBlockCipherParameters(
              pc.ParametersWithIV(pc.KeyParameter(key), iv),
              null,
            ),
          );
    return cipher.process(data);
  }

  /// A PKCS#1 RSAPrivateKey: version, n, e, d, p, q, ...
  static TomSecretsSshPrivateKey _rsa(List<SshDerItem> items, String? _) {
    final n = items[1].integer;
    final e = items[2].integer;
    return TomSecretsSshPrivateKey._(
      'ssh-rsa',
      _rsaBlob(n, e),
      '',
      _Rsa(n, e, items[3].integer, items[4].integer, items[5].integer),
    );
  }

  static const Map<String, String> _curves = {
    '1.2.840.10045.3.1.7': 'nistp256',
    '1.3.132.0.34': 'nistp384',
    '1.3.132.0.35': 'nistp521',
  };

  /// A SEC1 ECPrivateKey: version, the private key, [0] the curve, [1] the
  /// public key; [curveOid] from PKCS#8 when the key does not name it.
  static TomSecretsSshPrivateKey _ec(List<SshDerItem> items, String? curveOid) {
    final d = sshBigIntOf(items[1].content);
    var oid = curveOid;
    Uint8List? point;
    for (final item in items.skip(2)) {
      if (item.tag == 0xa0) {
        final param = SshDer(item.content).read();
        if (param.tag == 0x06) oid = param.oid;
      }
      if (item.tag == 0xa1) {
        point = SshDer(item.content).read().content.sublist(1);
      }
    }
    // Explicit parameters (LibreSSL): the curve by the private key's or the
    // point's size.
    final curve = oid != null
        ? _curves[oid]
        : switch (point?.length ?? items[1].content.length) {
            65 || 32 => 'nistp256',
            97 || 48 => 'nistp384',
            133 || 66 => 'nistp521',
            _ => null,
          };
    if (curve == null) {
      throw TomSecretsSshKeyException(
        TomSecretsSshKeyProblem.unsupported,
        oid ?? 'curve',
      );
    }
    final q =
        point ??
        (pc.ECDomainParameters(_pcCurve(curve)).G * d)!.getEncoded(false);
    return TomSecretsSshPrivateKey._(
      'ecdsa-sha2-$curve',
      _ecBlob(curve, q),
      '',
      _Ecdsa(curve, d),
    );
  }

  static Future<TomSecretsSshPrivateKey> _pkcs8(
    Uint8List body, {
    bool encrypted = false,
  }) async {
    final items = SshDer(body).sequence();
    final algorithm = items[1].children;
    final key = items[2].content;
    switch (algorithm[0].oid) {
      case '1.2.840.113549.1.1.1':
        return _rsa(SshDer(key).sequence(), null);
      case '1.2.840.10045.2.1':
        // A named curve, or explicit parameters (LibreSSL), known by size.
        final params = algorithm.length > 1 ? algorithm[1] : null;
        return _ec(
          SshDer(key).sequence(),
          params?.tag == 0x06 ? params!.oid : null,
        );
      case '1.3.101.112':
        final seed = SshDer(key).read().content;
        if (seed.length != 32) throw const FormatException('ed25519 seed');
        final pair = await cg.Ed25519().newKeyPairFromSeed(seed);
        final public = (await pair.extractPublicKey()).bytes;
        return TomSecretsSshPrivateKey._(
          'ssh-ed25519',
          (SshWireWriter()
                ..text('ssh-ed25519')
                ..bytes_(public))
              .bytes,
          '',
          _Ed25519(Uint8List.fromList(seed)),
        );
      default:
        throw TomSecretsSshKeyException(
          TomSecretsSshKeyProblem.unsupported,
          algorithm[0].oid,
        );
    }
  }
}

/// Whether [signature] (SSH's signature blob) is a valid signature of
/// [data] by the public key [publicKeyBlob] (SSH's wire form): Ed25519,
/// ECDSA P-256 / P-384 / P-521, or RSA with `rsa-sha2-256` /
/// `rsa-sha2-512`. Anything it cannot read, or another algorithm, is not.
Future<bool> tomSecretsSshVerify(
  List<int> publicKeyBlob,
  List<int> signature,
  List<int> data,
) async {
  try {
    final key = SshWire(Uint8List.fromList(publicKeyBlob));
    final sig = SshWire(Uint8List.fromList(signature));
    final keyType = key.text();
    final algorithm = sig.text();
    final sigBytes = sig.string();
    final message = Uint8List.fromList(data);
    switch (keyType) {
      case 'ssh-ed25519':
        if (algorithm != keyType) return false;
        return await cg.Ed25519().verify(
          message,
          signature: cg.Signature(
            sigBytes,
            publicKey: cg.SimplePublicKey(
              key.string(),
              type: cg.KeyPairType.ed25519,
            ),
          ),
        );
      case 'ssh-rsa':
        final e = key.mpint();
        final n = key.mpint();
        final signer = switch (algorithm) {
          'rsa-sha2-256' => pc.RSASigner(
            pc.SHA256Digest(),
            '0609608648016503040201',
          ),
          'rsa-sha2-512' => pc.RSASigner(
            pc.SHA512Digest(),
            '0609608648016503040203',
          ),
          _ => null,
        };
        if (signer == null) return false;
        signer.init(
          false,
          pc.PublicKeyParameter<pc.RSAPublicKey>(pc.RSAPublicKey(n, e)),
        );
        return signer.verifySignature(message, pc.RSASignature(sigBytes));
      case final t when t.startsWith('ecdsa-sha2-'):
        if (algorithm != keyType) return false;
        final curve = key.text();
        if (!TomSecretsSshPrivateKey._curves.containsValue(curve)) {
          return false;
        }
        final params = pc.ECDomainParameters(_pcCurve(curve));
        final point = params.curve.decodePoint(key.string());
        final rs = SshWire(sigBytes);
        final signer = pc.ECDSASigner(_digestOf(curve))
          ..init(
            false,
            pc.PublicKeyParameter<pc.ECPublicKey>(
              pc.ECPublicKey(point, params),
            ),
          );
        return signer.verifySignature(
          message,
          pc.ECSignature(rs.mpint(), rs.mpint()),
        );
      default:
        return false;
    }
  } on Object {
    return false;
  }
}

Uint8List _rsaBlob(BigInt n, BigInt e) =>
    (SshWireWriter()
          ..text('ssh-rsa')
          ..mpint(e)
          ..mpint(n))
        .bytes;

Uint8List _ecBlob(String curve, List<int> point) =>
    (SshWireWriter()
          ..text('ecdsa-sha2-$curve')
          ..text(curve)
          ..bytes_(point))
        .bytes;

String _pcCurve(String curve) => switch (curve) {
  'nistp256' => 'secp256r1',
  'nistp384' => 'secp384r1',
  _ => 'secp521r1',
};

pc.Digest _digestOf(String curve) => switch (curve) {
  'nistp256' => pc.SHA256Digest(),
  'nistp384' => pc.SHA384Digest(),
  _ => pc.SHA512Digest(),
};

pc.Mac _hmacOf(String curve) => switch (curve) {
  'nistp256' => pc.HMac(pc.SHA256Digest(), 64),
  'nistp384' => pc.HMac(pc.SHA384Digest(), 128),
  _ => pc.HMac(pc.SHA512Digest(), 128),
};

Uint8List _hex(String text) {
  final t = text.trim();
  return Uint8List.fromList([
    for (var i = 0; i + 1 < t.length; i += 2)
      int.parse(t.substring(i, i + 2), radix: 16),
  ]);
}

sealed class _KeyMaterial {
  const _KeyMaterial();
}

final class _Ed25519 extends _KeyMaterial {
  const _Ed25519(this.seed);
  final Uint8List seed;
}

final class _Ecdsa extends _KeyMaterial {
  const _Ecdsa(this.curve, this.d);
  final String curve;
  final BigInt d;
}

final class _Rsa extends _KeyMaterial {
  const _Rsa(this.n, this.e, this.d, this.p, this.q);
  final BigInt n;
  final BigInt e;
  final BigInt d;
  final BigInt p;
  final BigInt q;
}

enum _CipherMode { ctr, cbc, gcm }

final class _CipherSpec {
  const _CipherSpec(this.keyLength, this.ivLength, this.mode);

  final int keyLength;
  final int ivLength;
  final _CipherMode mode;

  bool get gcm => mode == _CipherMode.gcm;

  Uint8List decrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List data,
    Uint8List? tag,
  ) {
    switch (mode) {
      case _CipherMode.ctr:
        final c = pc.CTRStreamCipher(pc.AESEngine())
          ..init(false, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        return c.process(data);
      case _CipherMode.cbc:
        final c = pc.CBCBlockCipher(pc.AESEngine())
          ..init(false, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        final out = Uint8List(data.length);
        for (var at = 0; at < data.length; at += 16) {
          c.processBlock(data, at, out, at);
        }
        return out;
      case _CipherMode.gcm:
        final c = pc.GCMBlockCipher(pc.AESEngine())
          ..init(
            false,
            pc.AEADParameters(pc.KeyParameter(key), 128, iv, Uint8List(0)),
          );
        return c.process(Uint8List.fromList([...data, ...tag!]));
    }
  }
}
