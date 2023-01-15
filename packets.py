from key_exchange import *
from babyTLSUtil import *
from os import urandom
import json

# Signature handler (different hash of handshake hash)
# ref: https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_pss.html
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def node_hello(KEP_alg, KEP_struct):
    '''
        KEP_alg: Key exchange protocol algorithm (DHKE of ECDHKE)
        KEP_struct: Group of curve used for the KEP
    '''
    KEP = KEY_EXCHANGE(KEP_alg, KEP_struct)
    node_public_key = KEP.generate_public_key()
    node_hello = {
        "Random": urandom(16).hex(),
        "Key_Share": node_public_key
    }
    return json.dumps(node_hello), KEP

def extract_node_hello(node_hello):
    node_hello = json.loads(node_hello)
    node_public_key = node_hello["Key_Share"]
    return json.dumps(node_hello), node_public_key

def TLS_packet(pt, header, key, iv): # assuming AEAD like AES-GCM encryption for now
    '''
        Encrypt a packet
    '''
    encrypted, auth_tag = encrypt_and_digest(pt, header, key, iv)
    payload = {
        "Record_Header": header,
        "Encrypted_Data": encrypted.hex(),
        "Auth_Tag": auth_tag.hex()
    }
    return json.dumps(payload)

def handshake_signature(messages, HASH_ALG): # assuming RSA-PSS signature for now
    ''' 
        Sign handshake messages for Server Certificate Verify
    '''
    handshake_hash = HASH_ALG(''.join(messages).encode()).digest()
    priv = open("certs/priv.key", "rb").read() # read RSA private key
    private_key = RSA.import_key(priv)
    h = SHA256.new(handshake_hash)
    signature = pss.new(private_key).sign(h)
    return signature