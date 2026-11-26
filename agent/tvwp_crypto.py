"""Криптография TVWP/2: ML-KEM-1024 + общий ключ (гибрид), HKDF-SHA256, ChaCha20-Poly1305.

ML-KEM выполняет OpenSSL ≥ 3.5 (командой `openssl`), AEAD — пакет `cryptography`.
Используется и агентом, и тестовыми клиентами.
"""
import base64
import hashlib
import hmac
import os
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

VERSION = 2
MAGIC = b"TW"
HDR = struct.Struct(">2sBBBBII")          # magic, ver, type, flags, rsv, seq, len
FLAG_ENC = 0x02
KEM_ALG = "ML-KEM-1024"
KEM_PUB_LEN = 1568
KEM_CT_LEN = 1568
PREAUTH_MAX = 4096                         # кадры до входа (рукопожатие)
FRAME_MAX = 8 * 1024 * 1024                # кадры после входа
AEAD_TAG = 16
OPENSSL = os.environ.get("TVWP_OPENSSL", "openssl")
TMP = "/run" if os.access("/run", os.W_OK) else None   # в RAM, без записи на флешку

L_CLIENT = b"TVWP2-client"
L_SERVER = b"TVWP2-server"
L_C2S = b"TVWP2 c2s"
L_S2C = b"TVWP2 s2c"


def b64(b):
    return base64.b64encode(b).decode()


def unb64(s, maxlen=8192):
    if not isinstance(s, str) or len(s) > maxlen:
        raise ValueError("bad base64")
    return base64.b64decode(s, validate=True)


def mac(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def sha(b):
    return hashlib.sha256(b).digest()


def hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def session_keys(psk, kem_ss, ns, nc, kem_pub, ct):
    """Гибрид: ключи зависят и от общего ключа, и от секрета ML-KEM, и от всей переписки рукопожатия."""
    salt = sha(ns + nc + sha(kem_pub) + sha(ct))
    ikm = psk + kem_ss
    return hkdf(ikm, salt, L_C2S), hkdf(ikm, salt, L_S2C)


def client_mac(psk, ns, nc, kem_pub):
    return mac(psk, L_CLIENT, ns, nc, sha(kem_pub))


def server_proof(psk, ns, nc, kem_pub, ct):
    return mac(psk, L_SERVER, nc, ns, sha(kem_pub), sha(ct))


# ---------------------------------------------------------------- ML-KEM через OpenSSL
_SPKI_PREFIX = None


def _run(*args, inp=None):
    r = subprocess.run([OPENSSL, *args], input=inp, capture_output=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"openssl {args[0]}: {r.stderr.decode(errors='replace').strip()[:200]}")
    return r.stdout


def spki_prefix():
    """DER-префикс SubjectPublicKeyInfo для ML-KEM-1024 (берём у самого OpenSSL)."""
    global _SPKI_PREFIX
    if _SPKI_PREFIX is None:
        priv = _run("genpkey", "-algorithm", KEM_ALG, "-outform", "DER")
        der = _run("pkey", "-inform", "DER", "-pubout", "-outform", "DER", inp=priv)
        _SPKI_PREFIX = der[:-KEM_PUB_LEN]
    return _SPKI_PREFIX


def kem_encapsulate(pub_raw):
    """Сервер: (ciphertext, shared_secret) для открытого ключа клиента."""
    if len(pub_raw) != KEM_PUB_LEN:
        raise ValueError("bad ML-KEM public key length")
    with tempfile.TemporaryDirectory(dir=TMP) as d:
        p, ct, ss = (os.path.join(d, n) for n in ("pub.der", "ct", "ss"))
        with open(p, "wb") as f:
            f.write(spki_prefix() + pub_raw)
        _run("pkeyutl", "-encap", "-pubin", "-keyform", "DER", "-inkey", p, "-out", ct, "-secret", ss)
        ct_b, ss_b = open(ct, "rb").read(), open(ss, "rb").read()
    if len(ct_b) != KEM_CT_LEN or len(ss_b) != 32:
        raise RuntimeError("bad encapsulation output")
    return ct_b, ss_b


class KemClient:
    """Клиент (для тестов на Python): одноразовая пара ключей ML-KEM-1024."""

    def __init__(self):
        self.priv = _run("genpkey", "-algorithm", KEM_ALG, "-outform", "DER")
        self.pub = _run("pkey", "-inform", "DER", "-pubout", "-outform", "DER", inp=self.priv)[-KEM_PUB_LEN:]

    def decapsulate(self, ct):
        with tempfile.TemporaryDirectory(dir=TMP) as d:
            k, c, s = (os.path.join(d, n) for n in ("k.der", "ct", "ss"))
            with open(k, "wb") as f:
                f.write(self.priv)
            with open(c, "wb") as f:
                f.write(ct)
            _run("pkeyutl", "-decap", "-keyform", "DER", "-inkey", k, "-in", c, "-secret", s)
            return open(s, "rb").read()


# ---------------------------------------------------------------- кадры
class Channel:
    """Шифрование кадров после рукопожатия. Nonce = 4 нуля + номер кадра (у каждого направления свой ключ)."""

    def __init__(self, k_send, k_recv):
        self.tx, self.rx = ChaCha20Poly1305(k_send), ChaCha20Poly1305(k_recv)

    @staticmethod
    def nonce(seq):
        return b"\0\0\0\0" + struct.pack(">Q", seq)

    def seal(self, mtype, seq, plain):
        ln = len(plain) + AEAD_TAG
        hdr = HDR.pack(MAGIC, VERSION, mtype, FLAG_ENC, 0, seq, ln)
        return hdr + self.tx.encrypt(self.nonce(seq), plain, hdr)

    def open(self, hdr, seq, body):
        return self.rx.decrypt(self.nonce(seq), body, hdr)   # InvalidTag при подделке


def plain_frame(mtype, seq, payload):
    return HDR.pack(MAGIC, VERSION, mtype, 0, 0, seq, len(payload)) + payload
