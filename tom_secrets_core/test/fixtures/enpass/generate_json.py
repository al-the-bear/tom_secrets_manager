"""Writes the synthetic Enpass JSON fixture (json/export.json) and the public
keys of its demo passkeys (json/passkey_public_keys.json). Demo data only:
every passkey key is derived from a public seed ("tsm demo passkey N"), so it
is no secret and the fixture is reproducible. Run from anywhere:

    python3 test/fixtures/enpass/generate_json.py
"""
import hashlib, base64, json, os
OUT = os.path.dirname(os.path.abspath(__file__))
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
a = p - 3
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        l = (3 * P[0] * P[0] + a) * pow(2 * P[1], p - 2, p) % p
    else:
        l = (Q[1] - P[1]) * pow(Q[0] - P[0], p - 2, p) % p
    x = (l * l - P[0] - Q[0]) % p
    return (x, (l * (P[0] - x) - P[1]) % p)


def mul(k, P):
    R = None
    while k:
        if k % 2 == 1:
            R = add(R, P)
        P = add(P, P)
        k //= 2
    return R


def tlv(tag, c):
    m = len(c)
    if m < 0x80:
        l = bytes([m])
    elif m < 0x100:
        l = bytes([0x81, m])
    else:
        l = bytes([0x82, m // 256, m % 256])
    return bytes([tag]) + l + c


def seq(*ps):
    return tlv(0x30, b''.join(ps))


EC = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
P256 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])


def key(seed):
    d = int.from_bytes(hashlib.sha256(seed.encode()).digest(), 'big') % (n - 1) + 1
    Q = mul(d, G)
    db = d.to_bytes(32, 'big')
    pub = b'\x04' + Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big')
    return db, pub, Q


def b64(x):
    return base64.b64encode(x).decode()


def b64u(x):
    return base64.urlsafe_b64encode(x).decode().rstrip('=')


def xy(Q):
    return {'x': b64u(Q[0].to_bytes(32, 'big')), 'y': b64u(Q[1].to_bytes(32, 'big'))}


keys = {}
db, pub, Q = key('tsm demo passkey 1')
pkcs8 = seq(tlv(2, b'\x00'), seq(tlv(6, EC), tlv(6, P256)),
            tlv(4, seq(tlv(2, b'\x01'), tlv(4, db), tlv(0xA1, tlv(3, b'\x00' + pub)))))
keys['Demo Passkey One'] = xy(Q)
pk1 = b64(pkcs8)
db, pub, Q = key('tsm demo passkey 2')
jwk = dict(kty='EC', crv='P-256', d=b64u(db), **xy(Q))
keys['Demo Passkey Two'] = xy(Q)
db, pub, Q = key('tsm demo passkey 3')
sec1 = seq(tlv(2, b'\x01'), tlv(4, db), tlv(0xA0, tlv(6, P256)), tlv(0xA1, tlv(3, b'\x00' + pub)))
sec1pem = '-----BEGIN EC PRIVATE KEY-----\n' + b64(sec1) + '\n-----END EC PRIVATE KEY-----\n'
keys['Demo Passkey Three'] = xy(Q)
db, pub, Q = key('tsm demo passkey 4')
raw = b64(db)
keys['Demo Passkey Four'] = xy(Q)
seed5 = hashlib.sha256(b'tsm demo passkey 5').digest()
ed = {'kty': 'OKP', 'crv': 'Ed25519', 'd': b64u(seed5)}

T = 1700000000


def f(type_, label, value, sensitive=0, deleted=0, **kw):
    d = {'deleted': deleted, 'label': label, 'order': 0, 'sensitive': sensitive, 'type': type_,
         'uid': 0, 'updated_at': T, 'value': value, 'value_updated_at': T}
    d.update(kw)
    return d


def item(uuid, title, category, fields, folders=(), **kw):
    it = {'archived': 0, 'auto_submit': 1, 'category': category, 'createdAt': T, 'favorite': 0,
          'fields': fields, 'folders': list(folders),
          'icon': {'fav': '', 'image': {'file': 'misc/login'}, 'type': 1, 'uuid': ''},
          'note': '', 'subtitle': '', 'template_type': category + '.default', 'title': title,
          'trashed': 0, 'updated_at': T + 86400, 'uuid': uuid}
    it.update(kw)
    return it


def passkeyfield(obj):
    return f('passkey', 'Passkey', json.dumps(obj), sensitive=1)


F1 = 'f0000000-0000-4000-8000-000000000001'
F2 = 'f0000000-0000-4000-8000-000000000002'
F3 = 'f0000000-0000-4000-8000-000000000003'


def u(i):
    return 'e0000000-0000-4000-8000-%012d' % i


items = [
    item(u(1), 'Demo Enpass Mail', 'login', [
        f('username', 'Username', 'demo.user'),
        f('email', 'E-mail', 'demo@example.com'),
        f('password', 'Password', 'demo-enpass-pw', 1,
          history=[{'value': 'demo-enpass-old-1', 'updated_at': T - 200000},
                   {'value': 'demo-enpass-old-2', 'updated_at': T - 100000}]),
        f('password', 'Second password', 'demo-second-pw', 1),
        f('url', 'Website', 'https://mail.example.com'),
        f('url', 'Webmail', 'https://webmail.example.com'),
        f('totp', 'One-time code', 'JBSWY3DPEHPK3PXP', 1),
        f('pin', 'PIN', '4321', 1),
        f('section', 'Recovery', ''),
        f('text', 'Hint', 'demo hint'),
        f('multiline', 'Codes', 'code-1\ncode-2', 1),
        f('text', 'Removed', 'gone', deleted=1),
        f('text', 'Empty', ''),
        f('text', 'KPEX_PASSKEY_FAKE', 'not a passkey'),
    ], folders=[F2, F3], favorite=1, note='Demo enpass note', subtitle='demo.user'),
    item(u(2), 'Demo Enpass Password', 'password', [f('password', 'Password', 'demo-only-enpass', 1)]),
    item(u(3), 'Demo Enpass Note', 'note', [], note='A demo note.'),
    item(u(4), 'Demo Enpass Server', 'computer', [
        f('text', 'Hostname', 'server.example.com'), f('username', 'Username', 'admin'),
        f('password', 'Password', 'demo-server-enpass', 1), f('text', 'Port', '2222')], folders=[F2]),
    item(u(5), 'Demo Enpass Card', 'creditcard', [
        f('text', 'Cardholder', 'Demo Holder'), f('ccNumber', 'Number', '4111111111111111', 1),
        f('ccCvc', 'CVC', '123', 1), f('ccExpiry', 'Expiry', '07/28')]),
    item(u(6), 'Demo Enpass Identity', 'identity', [f('text', 'First name', 'Demo'), f('date', 'Birthday', '2000-01-01')]),
    item(u(7), 'Demo Enpass Archived', 'login', [f('username', 'Username', 'old'), f('password', 'Password', 'old-pw', 1)], archived=1),
    item(u(8), 'Demo Enpass Trashed', 'login', [f('username', 'Username', 'bin'), f('password', 'Password', 'bin-pw', 1)], trashed=1),
    item(u(9), 'Demo Enpass Attachment', 'login', [f('username', 'Username', 'attach')],
         attachments=[{'data': b64(b'demo attachment, no secret\n'), 'kind': 'text/plain', 'name': 'demo.txt', 'order': 1, 'updated_at': T}]),
    item(u(10), 'Demo Passkey One', 'login', [
        f('username', 'Username', 'pk-one'), f('url', 'Website', 'https://one.passkey.example'),
        passkeyfield({'rpId': 'one.passkey.example', 'credentialId': b64(b'demo-credential-1'),
                      'userHandle': b64u(b'demo-user-1'), 'userName': 'pk-one', 'privateKey': pk1})]),
    item(u(11), 'Demo Passkey Two', 'login', [
        f('username', 'Username', 'pk-two'), f('password', 'Password', 'pk-two-pw', 1)],
         passkey={'relyingParty': 'two.passkey.example', 'credential_id': b64u(b'demo-credential-2'),
                  'user_handle': b64(b'demo-user-2'), 'privateKey': jwk}),
    item(u(12), 'Demo Passkey Three', 'login', [
        f('username', 'Username', 'pk-three'),
        passkeyfield({'rpId': 'three.passkey.example', 'credentialId': b64u(b'demo-credential-3'), 'privateKey': sec1pem})]),
    item(u(13), 'Demo Passkey Four', 'login', [
        f('username', 'Username', 'pk-four'), f('url', 'Website', 'https://four.passkey.example/login'),
        passkeyfield({'credentialId': b64u(b'demo-credential-4'), 'privateKey': raw})]),
    item(u(14), 'Demo Passkey Five', 'login', [
        f('username', 'Username', 'pk-five'),
        passkeyfield({'rpId': 'five.passkey.example', 'credentialId': b64u(b'demo-credential-5'), 'privateKey': ed})]),
    item(u(15), 'Demo Passkey Without Key', 'login', [
        f('username', 'Username', 'pk-none'),
        passkeyfield({'rpId': 'none.passkey.example', 'credentialId': b64u(b'demo-credential-6')})]),
]
for it in items:
    for i, fl in enumerate(it['fields']):
        fl['order'] = i + 1
        fl['uid'] = 10 + i
folders = [
    {'icon': '1008', 'parent_uuid': '', 'title': 'Work', 'updated_at': T, 'uuid': F1},
    {'icon': '1008', 'parent_uuid': F1, 'title': 'Servers', 'updated_at': T, 'uuid': F2},
    {'icon': '1008', 'parent_uuid': '', 'title': 'Personal', 'updated_at': T, 'uuid': F3},
]
open(OUT + '/json/export.json', 'w').write(json.dumps({'folders': folders, 'items': items}, indent=4) + '\n')
open(OUT + '/json/passkey_public_keys.json', 'w').write(json.dumps(keys, indent=2) + '\n')
