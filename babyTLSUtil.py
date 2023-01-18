from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Cipher import AES
from math import ceil
import hmac
import hashlib
import struct

# AES-GCM handler
# ref: https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#gcm-mode

class AES_GCM:
    def encrypt_and_digest(pt, header, key, iv):
        cipher = AES.new(bytes.fromhex(key), AES.MODE_GCM, nonce = bytes.fromhex(iv))
        cipher.update(bytes.fromhex(header))
        ct, tag = cipher.encrypt_and_digest(pt)
        return ct, tag

    def decrypt_and_verify(ct, header, key, iv, tag):
        cipher = AES.new(bytes.fromhex(key), AES.MODE_GCM, nonce = bytes.fromhex(iv))
        cipher.update(bytes.fromhex(header))
        pt = cipher.decrypt_and_verify(bytes.fromhex(ct), bytes.fromhex(tag))
        return pt
    
# ChaCha20-Poly1305 handler
# ref: https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20_poly1305.html    

class CHACHA20_POLY1305:
    def encrypt_and_digest(pt, header, key, iv):
        cipher = ChaCha20_Poly1305.new(key = bytes.fromhex(key), nonce = bytes.fromhex(iv))
        cipher.update(bytes.fromhex(header))
        ct, tag = cipher.encrypt_and_digest(pt)
        return ct, tag

    def decrypt_and_verify(ct, header, key, iv, tag):
        cipher = ChaCha20_Poly1305.new(key = bytes.fromhex(key), nonce = bytes.fromhex(iv))
        cipher.update(bytes.fromhex(header))
        pt = cipher.decrypt_and_verify(bytes.fromhex(ct), bytes.fromhex(tag))
        return pt
    
# HKDF handler
# ref: https://github.com/casebeer/python-hkdf/blob/master/hkdf.py + CryptoHack

def tls_HMAC(k, b, algorithm): # HKDF-Extract
    return bytearray(hmac.new(k, b, algorithm).digest())


def HKDF_expand(prk, info, length, algorithm):
    hash_len = algorithm().digest_size
    t = bytearray()
    okm = bytearray()
    for i in range(1, ceil(length / hash_len)+2):
        t = tls_HMAC(prk, t + info + bytearray([i]), algorithm)
        okm += t
    return okm[:length]


def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    hkdfLabel = bytearray()
    hkdfLabel += struct.pack('>H', length)
    seq = bytearray(b"tls13 ") + label
    hkdfLabel += bytearray([len(seq)]) + seq
    seq = hashValue
    hkdfLabel += bytearray([len(seq)]) + seq

    return HKDF_expand(secret, hkdfLabel, length, algorithm)


def verify_data(finished_key, transcript_hash, hash_alg):
    my = hash_alg(concatenated).digest()
    return tls_HMAC(finished_key, my, hash_alg)

# Data verification

def hello_verify(messages, shared_secret, HASH_ALG, HASH_LEN):
    # print(messages)
    hello_hash = HASH_ALG(''.join(messages).encode()).digest()
    
    # early_secret = HKDF-Extract(salt: 00, key: 00...)
    early_secret = tls_HMAC(bytearray((0,) * HASH_LEN), bytearray((0,) * HASH_LEN), HASH_ALG)
    # empty_hash = SHA384("")
    empty_hash = HASH_ALG(b"").digest()
    # derived_secret = HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
    derived_secret = HKDF_expand_label(early_secret, b"derived", empty_hash, 48, HASH_ALG)
    # handshake_secret = HKDF-Extract(salt: derived_secret, key: shared_secret)
    handshake_secret = tls_HMAC(derived_secret, long_to_bytes(shared_secret), HASH_ALG)
    # client_secret = HKDF-Expand-Label(key: handshake_secret, label: "c hs traffic", ctx: hello_hash, len: 48)
    client_secret = HKDF_expand_label(handshake_secret, b"c hs traffic", hello_hash, 48, HASH_ALG)
    # server_secret = HKDF-Expand-Label(key: handshake_secret, label: "s hs traffic", ctx: hello_hash, len: 48)
    server_secret = HKDF_expand_label(handshake_secret, b"s hs traffic", hello_hash, 48, HASH_ALG)
    # client_handshake_key = HKDF-Expand-Label(key: client_secret, label: "key", ctx: "", len: 32)
    client_handshake_key = HKDF_expand_label(client_secret, b"key", b"", 32, HASH_ALG)
    # server_handshake_key = HKDF-Expand-Label(key: server_secret, label: "key", ctx: "", len: 32)
    server_handshake_key = HKDF_expand_label(server_secret, b"key", b"", 32, HASH_ALG)
    # client_handshake_iv = HKDF-Expand-Label(key: client_secret, label: "iv", ctx: "", len: 12)
    client_handshake_iv = HKDF_expand_label(client_secret, b"iv", b"", 12, HASH_ALG)
    # server_handshake_iv = HKDF-Expand-Label(key: server_secret, label: "iv", ctx: "", len: 12)
    server_handshake_iv = HKDF_expand_label(server_secret, b"iv", b"", 12, HASH_ALG)
    
    result = {
        "server_secret": server_secret.hex(),
        "client_secret": client_secret.hex(),
        "handshake_secret": handshake_secret.hex(),
        "server_handshake_traffic_secret": server_secret.hex(),
        "client_handshake_traffic_secret": client_secret.hex(),
        "server_handshake_key": server_handshake_key.hex(),
        "server_handshake_iv": server_handshake_iv.hex(),
        "client_handshake_key": client_handshake_key.hex(),
        "client_handshake_iv": client_handshake_iv.hex()
    }
    return result 

def handshake_verify(handshake_hash, handshake_secret, HASH_ALG, HASH_LEN):
    # handshake_secret : result["handshake_secret"]
    
    # empty_hash = SHA384("")
    empty_hash = HASH_ALG(b"").digest()
    # derived_secret = HKDF-Expand-Label(key: handshake_secret, label: "derived", ctx: empty_hash, len: 48)
    derived_secret = HKDF_expand_label(handshake_secret, b"derived", empty_hash, 48, HASH_ALG)
    # master_secret = HKDF-Extract(salt: derived_secret, key: 00...)
    master_secret = tls_HMAC(derived_secret, bytearray((0,) * HASH_LEN), HASH_ALG)
    # client_secret = HKDF-Expand-Label(key: master_secret, label: "c ap traffic", ctx: handshake_hash, len: 48)
    client_secret = HKDF_expand_label(master_secret, b"c ap traffic", handshake_hash, 48, HASH_ALG)
    # server_secret = HKDF-Expand-Label(key: master_secret, label: "s ap traffic", ctx: handshake_hash, len: 48)
    server_secret = HKDF_expand_label(master_secret, b"s ap traffic", handshake_hash, 48, HASH_ALG)
    # client_application_key = HKDF-Expand-Label(key: client_secret, label: "key", ctx: "", len: 32)
    client_application_key = HKDF_expand_label(client_secret, b"key", b"", 32, HASH_ALG)
    # server_application_key = HKDF-Expand-Label(key: server_secret, label: "key", ctx: "", len: 32)
    server_application_key = HKDF_expand_label(server_secret, b"key", b"", 32, HASH_ALG)
    # client_application_iv = HKDF-Expand-Label(key: client_secret, label: "iv", ctx: "", len: 12)
    client_application_iv = HKDF_expand_label(client_secret, b"iv", b"", 12, HASH_ALG)
    # server_application_iv = HKDF-Expand-Label(key: server_secret, label: "iv", ctx: "", len: 12)
    server_application_iv = HKDF_expand_label(server_secret, b"iv", b"", 12, HASH_ALG)
    
    result = {
        "server_application_key": server_application_key.hex(),
        "server_application_iv": server_application_iv.hex(),
        "client_application_key": client_application_key.hex(),
        "client_application_iv": client_application_iv.hex()
    }
    return result 