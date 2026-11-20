// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

/// **[C]** The typed `certificate` entry (part-structure, part-sharing,
/// BP-33, DP-179): an X.509 certificate with its private key.
///
/// - **The entry:** the certificate (with its chain) as the attachment
///   `certificate.pem`, its private key as `private-key.pem`; a PKCS#12
///   bundle as `certificate.p12`, its passphrase in `Password`. Expires is
///   the certificate's `notAfter`, so the reminders and the health report
///   see it coming.
/// - **Generated** (DP-179): a key on ECDSA P-384 (192-bit strength), or RSA
///   4096 where a tool needs RSA, with a self-signed certificate and a
///   certificate signing request for a CA (SHA-384).
/// - **Read:** subject, issuer, validity, the key's algorithm and length,
///   the SHA-256 fingerprint; an imported short key (RSA below 3072 bits, a
///   curve below 256) is kept and flagged by the health report, never
///   refused.
/// - **Served:** `getFile` of the entry without a field answers its private
///   key (or the PKCS#12 bundle), for `tsm run --file`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart' as bu;
import 'package:tom_kdbx_store/tom_kdbx_store.dart';

import 'mapping.dart';

/// The attachment holding a certificate entry's certificate (and chain).
const String tomSecretsCertificateAttachment = 'certificate.pem';

/// The attachment holding a certificate entry's private key.
const String tomSecretsCertificateKeyAttachment = 'private-key.pem';

/// The attachment holding a certificate entry's PKCS#12 bundle.
const String tomSecretsPkcs12Attachment = 'certificate.p12';

/// A certificate's key algorithm as the product names it.
enum TomSecretsCertificateKeyType {
  /// An elliptic curve key (ECDSA).
  ec,

  /// RSA.
  rsa,

  /// Another algorithm (Ed25519, DSA, ...).
  other,
}

/// A certificate refused as unreadable.
final class TomSecretsCertificateException implements Exception {
  /// A refusal told by [message].
  const TomSecretsCertificateException(this.message);

  /// For people.
  final String message;

  @override
  String toString() => 'TomSecretsCertificateException: $message';
}

/// What a certificate says.
final class TomSecretsCertificateInfo {
  const TomSecretsCertificateInfo._({
    required this.subject,
    required this.issuer,
    required this.serialNumber,
    required this.notBefore,
    required this.notAfter,
    required this.keyType,
    required this.keyBits,
    required this.curve,
    required this.sha256Fingerprint,
    required this.subjectAlternativeNames,
    required this.hasPrivateKey,
    required this.chainLength,
  });

  /// Its subject's common name (else the whole subject), e.g. `demo.example`.
  final String subject;

  /// Its issuer's common name (else the whole issuer).
  final String issuer;

  /// The serial number, in hex.
  final String serialNumber;

  /// Valid from.
  final DateTime notBefore;

  /// Valid until: the entry's Expires.
  final DateTime notAfter;

  /// The key's algorithm.
  final TomSecretsCertificateKeyType keyType;

  /// The key's length in bits (the curve's for EC), or null when unknown.
  final int? keyBits;

  /// The curve's name of an EC key (`secp384r1`), or null.
  final String? curve;

  /// The SHA-256 fingerprint of the certificate, upper-case hex with colons.
  final String sha256Fingerprint;

  /// The subject alternative names (DNS names, addresses).
  final List<String> subjectAlternativeNames;

  /// Whether the PEM it was read from holds a private key too.
  final bool hasPrivateKey;

  /// How many certificates the PEM holds (the certificate and its chain).
  final int chainLength;

  /// Whether it is its own issuer.
  bool get selfSigned => subject == issuer;

  /// The key in words, e.g. `ECDSA P-384` or `RSA 4096`.
  String get keyDescription => switch (keyType) {
    TomSecretsCertificateKeyType.ec => 'ECDSA ${_curveName(curve, keyBits)}',
    TomSecretsCertificateKeyType.rsa => 'RSA ${keyBits ?? '?'}',
    TomSecretsCertificateKeyType.other => 'another algorithm',
  };

  /// Why its key is shorter than today's guidance (DP-179: RSA below 3072
  /// bits, a curve below 256), or null when it passes or is not known.
  String? get shortness {
    final bits = keyBits;
    if (bits == null) return null;
    if (keyType == TomSecretsCertificateKeyType.rsa && bits < 3072) {
      return 'RSA $bits bits: below 3072';
    }
    if (keyType == TomSecretsCertificateKeyType.ec && bits < 256) {
      return 'ECDSA $bits bits: below 256';
    }
    return null;
  }

  /// The information of the PEM [pem] (its first certificate; a private key
  /// block beside it is noted, never read). Throws
  /// [TomSecretsCertificateException] for one that holds no readable
  /// certificate.
  factory TomSecretsCertificateInfo.parse(String pem) {
    final blocks = _certificateBlocks(pem);
    if (blocks.isEmpty) {
      throw const TomSecretsCertificateException('no certificate in it');
    }
    final bu.X509CertificateData data;
    try {
      data = bu.X509Utils.x509CertificateFromPem(blocks.first);
    } on Object catch (e) {
      throw TomSecretsCertificateException('an unreadable certificate ($e)');
    }
    final tbs = data.tbsCertificate!;
    final key = tbs.subjectPublicKeyInfo;
    final algorithm = key.algorithmReadableName ?? key.algorithm ?? '';
    final type = algorithm.contains('rsa') || algorithm.contains('RSA')
        ? TomSecretsCertificateKeyType.rsa
        : algorithm.contains('ec') || algorithm.contains('EC')
        ? TomSecretsCertificateKeyType.ec
        : TomSecretsCertificateKeyType.other;
    final curve = key.parameterReadableName ?? key.parameter;
    String name(Map<String, String?> dn) =>
        dn['2.5.4.3'] ??
        [
          for (final MapEntry(:key, :value) in dn.entries)
            if (value != null) '${_dnLabel(key)}=$value',
        ].join(', ');
    final fingerprint = data.sha256Thumbprint ?? '';
    return TomSecretsCertificateInfo._(
      subject: name(tbs.subject),
      issuer: name(tbs.issuer),
      serialNumber: tbs.serialNumber.toRadixString(16),
      notBefore: tbs.validity.notBefore.toUtc(),
      notAfter: tbs.validity.notAfter.toUtc(),
      keyType: type,
      keyBits: type == TomSecretsCertificateKeyType.ec
          ? (_curveBits(curve) ?? key.length)
          : key.length,
      curve: type == TomSecretsCertificateKeyType.ec ? curve : null,
      sha256Fingerprint: [
        for (var i = 0; i + 2 <= fingerprint.length; i += 2)
          fingerprint.substring(i, i + 2).toUpperCase(),
      ].join(':'),
      subjectAlternativeNames:
          tbs.extensions?.subjectAlternativNames ?? const [],
      hasPrivateKey: RegExp(
        '-----BEGIN (?:ENCRYPTED |EC |RSA )?PRIVATE KEY-----',
      ).hasMatch(pem),
      chainLength: blocks.length,
    );
  }

  static String _curveName(String? curve, int? bits) => switch (curve) {
    'secp384r1' || 'prime384v1' => 'P-384',
    'prime256v1' || 'secp256r1' => 'P-256',
    'secp521r1' => 'P-521',
    final c? => c,
    null => '${bits ?? '?'} bits',
  };

  static int? _curveBits(String? curve) => switch (curve) {
    'secp384r1' || 'prime384v1' => 384,
    'prime256v1' || 'secp256r1' => 256,
    'secp521r1' => 521,
    'secp224r1' => 224,
    'secp192r1' || 'prime192v1' => 192,
    _ => null,
  };

  static String _dnLabel(String oid) => switch (oid) {
    '2.5.4.3' => 'CN',
    '2.5.4.10' => 'O',
    '2.5.4.11' => 'OU',
    '2.5.4.6' => 'C',
    '2.5.4.7' => 'L',
    '2.5.4.8' => 'ST',
    _ => oid,
  };
}

final _certificate = RegExp(
  '-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----',
);

List<String> _certificateBlocks(String pem) => [
  for (final m in _certificate.allMatches(pem)) m.group(0)!,
];

/// Whether [bytes] look like a PKCS#12 bundle (DER, not PEM text).
bool tomSecretsIsPkcs12(List<int> bytes) =>
    bytes.length > 4 && bytes[0] == 0x30 && !_isText(bytes);

bool _isText(List<int> bytes) {
  try {
    final text = utf8.decode(bytes.take(64).toList());
    return text.contains('-----BEGIN');
  } on FormatException {
    return false;
  }
}

/// The key a certificate is generated with (DP-179).
enum TomSecretsCertificateAlgorithm {
  /// ECDSA on P-384 (the default).
  ecdsaP384,

  /// RSA 4096, for a tool that needs RSA.
  rsa,
}

/// A generated certificate: the certificate, its private key and a request
/// to have a CA sign the same key, all PEM.
final class TomSecretsGeneratedCertificate {
  const TomSecretsGeneratedCertificate._({
    required this.certificatePem,
    required this.privateKeyPem,
    required this.csrPem,
    required this.info,
  });

  /// The self-signed certificate.
  final String certificatePem;

  /// The private key (PKCS#8 for RSA, SEC 1 for EC), unencrypted: the vault
  /// protects it.
  final String privateKeyPem;

  /// The certificate signing request (PKCS#10) for a CA.
  final String csrPem;

  /// What the certificate says.
  final TomSecretsCertificateInfo info;
}

/// A new certificate for [commonName] (and [subjectAlternativeNames]),
/// valid for [days] (DP-179): its key on ECDSA P-384, or RSA of [rsaBits]
/// (4096; less only for tests) with [algorithm] `rsa`; self-signed with
/// SHA-384 (SHA-256 for RSA), with a CSR beside it.
TomSecretsGeneratedCertificate tomSecretsGenerateCertificate({
  required String commonName,
  List<String> subjectAlternativeNames = const [],
  int days = 365,
  TomSecretsCertificateAlgorithm algorithm =
      TomSecretsCertificateAlgorithm.ecdsaP384,
  int rsaBits = 4096,
  DateTime? now,
}) {
  final subject = {'CN': commonName};
  final sans = subjectAlternativeNames.isEmpty
      ? [commonName]
      : subjectAlternativeNames;
  final String csr;
  final String keyPem;
  final bu.PrivateKey private;
  switch (algorithm) {
    case TomSecretsCertificateAlgorithm.ecdsaP384:
      final pair = bu.CryptoUtils.generateEcKeyPair(curve: 'secp384r1');
      private = pair.privateKey as bu.ECPrivateKey;
      csr = bu.X509Utils.generateEccCsrPem(
        subject,
        private as bu.ECPrivateKey,
        pair.publicKey as bu.ECPublicKey,
        san: sans,
        signingAlgorithm: 'SHA-384',
      );
      keyPem = bu.CryptoUtils.encodeEcPrivateKeyToPem(private);
    case TomSecretsCertificateAlgorithm.rsa:
      final pair = bu.CryptoUtils.generateRSAKeyPair(keySize: rsaBits);
      private = pair.privateKey as bu.RSAPrivateKey;
      csr = bu.X509Utils.generateRsaCsrPem(
        subject,
        private as bu.RSAPrivateKey,
        pair.publicKey as bu.RSAPublicKey,
        san: sans,
        signingAlgorithm: 'SHA-256',
      );
      keyPem = bu.CryptoUtils.encodeRSAPrivateKeyToPem(private);
  }
  final at = (now ?? DateTime.now()).toUtc();
  final certificate = bu.X509Utils.generateSelfSignedCertificate(
    private,
    csr,
    days,
    sans: sans,
    serialNumber: '${at.millisecondsSinceEpoch}',
    notBefore: at,
  );
  return TomSecretsGeneratedCertificate._(
    certificatePem: certificate,
    privateKeyPem: keyPem,
    csrPem: csr,
    info: TomSecretsCertificateInfo.parse('$certificate\n$keyPem'),
  );
}

/// Makes [entry] a `certificate` entry holding [certificatePem] (with its
/// chain) and [privateKeyPem] as attachments, or a [pkcs12] bundle, with
/// [passphrase] (of an encrypted key or the bundle) in `Password`; Expires
/// is set from the certificate's `notAfter` when it can be read (a PKCS#12
/// bundle's is not: set it by hand). The entry as it was goes to its
/// history. Answers what the certificate says, or null for a bundle.
TomSecretsCertificateInfo? tomSecretsWriteCertificate(
  KdbxEntry entry, {
  String? certificatePem,
  String? privateKeyPem,
  Uint8List? pkcs12,
  String? passphrase,
}) {
  if ((certificatePem == null) == (pkcs12 == null)) {
    throw ArgumentError('a certificate PEM or a PKCS#12 bundle');
  }
  final info = certificatePem == null
      ? null
      : TomSecretsCertificateInfo.parse(
          [certificatePem, ?privateKeyPem].join('\n'),
        );
  entry.modify(() {
    entry.setString(
      TomSecretsEntryFields.type,
      PlainValue(TomSecretsEntryType.certificate.wireName),
    );
    for (final name in const [
      tomSecretsCertificateAttachment,
      tomSecretsCertificateKeyAttachment,
      tomSecretsPkcs12Attachment,
    ]) {
      entry.removeBinary(KdbxKey(name));
    }
    if (certificatePem != null) {
      entry.createBinary(
        isProtected: false,
        name: tomSecretsCertificateAttachment,
        bytes: Uint8List.fromList(utf8.encode(certificatePem)),
      );
    }
    if (privateKeyPem != null) {
      entry.createBinary(
        isProtected: true,
        name: tomSecretsCertificateKeyAttachment,
        bytes: Uint8List.fromList(utf8.encode(privateKeyPem)),
      );
    }
    if (pkcs12 != null) {
      entry.createBinary(
        isProtected: true,
        name: tomSecretsPkcs12Attachment,
        bytes: pkcs12,
      );
    }
    if (passphrase != null) {
      entry.setString(
        KdbxKeyCommon.PASSWORD,
        ProtectedValue.fromString(passphrase),
      );
    }
    if (info != null) {
      entry.times.expires.set(true);
      entry.times.expiryTime.set(info.notAfter);
    }
  });
  return info;
}

/// What the certificate of the `certificate` entry [entry] says, or null
/// when it holds none that reads (a PKCS#12 bundle, a broken PEM).
TomSecretsCertificateInfo? tomSecretsCertificateOf(KdbxEntry entry) {
  final cert = entry.getBinary(const KdbxKey(tomSecretsCertificateAttachment));
  if (cert == null) return null;
  final key = entry.getBinary(
    const KdbxKey(tomSecretsCertificateKeyAttachment),
  );
  try {
    // The private key is never decoded into a string here: only that it is
    // there counts.
    return TomSecretsCertificateInfo.parse(
      [
        utf8.decode(cert.value),
        if (key != null) '-----BEGIN PRIVATE KEY-----',
      ].join('\n'),
    );
  } on Object {
    return null;
  }
}
