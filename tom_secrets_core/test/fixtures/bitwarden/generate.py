#!/usr/bin/env python3
# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""Writes the synthetic Bitwarden fixtures (demo data only).

- export.json: an unencrypted JSON export in Bitwarden's layout.
- export_encrypted.json: the same export, password-protected the way
  Bitwarden writes it (PBKDF2-SHA256 over the salt, HKDF-Expand into an
  encryption and a MAC key, type-2 cipher strings: AES-256-CBC with PKCS#7
  and HMAC-SHA256 over IV and data). The password is
  `demo-export-password`; the iteration count is lowered to 5000 so the
  test runs fast (Bitwarden writes 600000; the reader takes any).

This is an implementation of its own (Python's hashlib and hmac, the
openssl command for AES), so the Dart reader is checked against a second
writer. The IVs and salt come from fixed seeds: running it again writes the
same files.

    python3 generate.py
"""

import base64
import hashlib
import hmac
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
PASSWORD = 'demo-export-password'
SALT = 'ZGVtby1zYWx0LWZvci10ZXN0cw=='
ITERATIONS = 5000

with open(os.path.join(HERE, 'demo_ssh_ed25519')) as f:
    SSH_KEY = f.read()

EXPORT = {
    'encrypted': False,
    'folders': [
        {'id': 'f0000000-0000-4000-8000-000000000001', 'name': 'Work'},
        {'id': 'f0000000-0000-4000-8000-000000000002',
         'name': 'Work/Servers'},
    ],
    'items': [
        {
            'passwordHistory': [
                {'lastUsedDate': '2025-03-01T10:00:00.000Z',
                 'password': 'demo-old-pw-1'},
            ],
            'revisionDate': '2026-01-02T03:04:05.000Z',
            'creationDate': '2024-01-01T00:00:00.000Z',
            'deletedDate': None,
            'id': '10000000-0000-4000-8000-000000000001',
            'organizationId': None,
            'folderId': 'f0000000-0000-4000-8000-000000000002',
            'type': 1,
            'reprompt': 0,
            'name': 'Demo Server',
            'notes': 'Demo note\nsecond line',
            'favorite': True,
            'fields': [
                {'name': 'Region', 'value': 'eu-demo', 'type': 0,
                 'linkedId': None},
                {'name': 'PIN', 'value': '0000', 'type': 1,
                 'linkedId': None},
                {'name': 'Admin', 'value': 'true', 'type': 2,
                 'linkedId': None},
                {'name': 'Linked', 'value': None, 'type': 3,
                 'linkedId': 100},
            ],
            'login': {
                'fido2Credentials': [],
                'uris': [
                    {'match': None, 'uri': 'https://demo.example.com'},
                    {'match': 1, 'uri': 'https://admin.demo.example.com'},
                ],
                'username': 'demo-user',
                'password': 'demo-server-pw',
                'totp': 'otpauth://totp/Demo:demo-user?secret='
                        'JBSWY3DPEHPK3PXP&issuer=Demo',
            },
            'collectionIds': None,
        },
        {
            'id': '10000000-0000-4000-8000-000000000002',
            'folderId': None,
            'type': 2,
            'name': 'Demo Note',
            'notes': 'A demo secure note',
            'favorite': False,
            'secureNote': {'type': 0},
            'revisionDate': '2026-01-02T03:04:05.000Z',
            'creationDate': '2026-01-01T00:00:00.000Z',
            'deletedDate': None,
        },
        {
            'id': '10000000-0000-4000-8000-000000000003',
            'folderId': 'f0000000-0000-4000-8000-000000000001',
            'type': 3,
            'name': 'Demo Card',
            'notes': None,
            'favorite': False,
            'card': {
                'cardholderName': 'Demo Person',
                'brand': 'Visa',
                'number': '4111111111111111',
                'expMonth': '12',
                'expYear': '2030',
                'code': '123',
            },
            'revisionDate': '2026-01-02T03:04:05.000Z',
            'creationDate': '2026-01-01T00:00:00.000Z',
            'deletedDate': None,
        },
        {
            'id': '10000000-0000-4000-8000-000000000004',
            'folderId': None,
            'type': 4,
            'name': 'Demo Identity',
            'notes': None,
            'favorite': False,
            'identity': {
                'title': 'Dr',
                'firstName': 'Demo',
                'middleName': None,
                'lastName': 'Person',
                'email': 'demo@example.com',
                'passportNumber': 'X0000000',
            },
            'revisionDate': '2026-01-02T03:04:05.000Z',
            'creationDate': '2026-01-01T00:00:00.000Z',
            'deletedDate': None,
        },
        {
            'id': '10000000-0000-4000-8000-000000000005',
            'folderId': 'f0000000-0000-4000-8000-000000000002',
            'type': 5,
            'name': 'Demo SSH key',
            'notes': None,
            'favorite': False,
            'sshKey': {
                'privateKey': SSH_KEY,
                'publicKey': 'ssh-ed25519 AAAA-demo demo@example',
                'keyFingerprint': 'SHA256:demo',
            },
            'revisionDate': '2026-01-02T03:04:05.000Z',
            'creationDate': '2026-01-01T00:00:00.000Z',
            'deletedDate': None,
        },
        {
            'id': '10000000-0000-4000-8000-000000000006',
            'folderId': None,
            'type': 1,
            'name': 'Demo Trashed',
            'login': {'username': 'gone', 'password': 'demo-gone-pw',
                      'uris': []},
            'revisionDate': '2026-01-02T03:04:05.000Z',
            'creationDate': '2026-01-01T00:00:00.000Z',
            'deletedDate': '2026-01-03T00:00:00.000Z',
        },
        {
            'id': '10000000-0000-4000-8000-000000000007',
            'folderId': None,
            'type': 1,
            'name': 'Demo Passkey Site',
            'login': {
                'username': 'demo-pk',
                'password': None,
                'uris': [{'match': None, 'uri': 'https://pk.example.com'}],
                'fido2Credentials': [
                    {'credentialId': '00000000-0000-4000-8000-0000000000aa',
                     'keyType': 'public-key', 'keyAlgorithm': 'ECDSA',
                     'keyCurve': 'P-256', 'keyValue': 'demo',
                     'rpId': 'pk.example.com', 'userName': 'demo-pk'},
                ],
            },
            'revisionDate': '2026-01-02T03:04:05.000Z',
            'creationDate': '2026-01-01T00:00:00.000Z',
            'deletedDate': None,
        },
    ],
}


def expand(key, info):
    # HKDF-Expand (RFC 5869) to one SHA-256 block.
    return hmac.new(key, info.encode() + b'\x01', hashlib.sha256).digest()


def cipher_string(plain, enc_key, mac_key, seed):
    iv = hashlib.sha256(seed.encode()).digest()[:16]
    data = subprocess.run(
        ['openssl', 'enc', '-aes-256-cbc', '-K', enc_key.hex(),
         '-iv', iv.hex()],
        input=plain, capture_output=True, check=True).stdout
    mac = hmac.new(mac_key, iv + data, hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()
    return f'2.{b64(iv)}|{b64(data)}|{b64(mac)}'


def main():
    plain = json.dumps(EXPORT, indent=2)
    with open(os.path.join(HERE, 'export.json'), 'w') as f:
        f.write(plain + '\n')
    master = hashlib.pbkdf2_hmac(
        'sha256', PASSWORD.encode(), SALT.encode(), ITERATIONS, 32)
    enc, mac = expand(master, 'enc'), expand(master, 'mac')
    encrypted = {
        'encrypted': True,
        'passwordProtected': True,
        'salt': SALT,
        'kdfType': 0,
        'kdfIterations': ITERATIONS,
        'kdfMemory': None,
        'kdfParallelism': None,
        'encKeyValidation_DO_NOT_EDIT': cipher_string(
            b'00000000-0000-4000-8000-0000000000ff', enc, mac, 'validation'),
        'data': cipher_string(plain.encode(), enc, mac, 'data'),
    }
    with open(os.path.join(HERE, 'export_encrypted.json'), 'w') as f:
        f.write(json.dumps(encrypted, indent=2) + '\n')


if __name__ == '__main__':
    main()
