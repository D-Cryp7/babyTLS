from babyTLSUtil import *
from params import *
from packets import *
import hashlib

CIPHER_SUITES = {
    # TLS_AES_256_GCM_SHA384 with RSA-PSS-SHA256 as certificate signature and ECDHE as key exchange
    "TLS_ECDHE_RSA_PSS_SHA256_AES_256_GCM_SHA384": {
        "KEY_EXCHANGE": ECDHE_SUPPORTED_CURVES,
        "AUTHENTICATED_CIPHER": (AES_GCM.encrypt_and_digest, AES_GCM.decrypt_and_verify),
        "SIGNATURE_ALGORITHM": handshake_verify,
        "HANDSHAKE_AUTHENTICATION": (hashlib.sha384, hashlib.sha384().digest_size)
    },
    # TLS_AES_256_GCM_SHA384 with RSA-PSS-SHA256 as certificate signature and DHE as key exchange
    "TLS_DHE_RSA_PSS_SHA256_AES_256_GCM_SHA384": {
        "KEY_EXCHANGE": DHE_SUPPORTED_GROUPS,
        "AUTHENTICATED_CIPHER": (AES_GCM.encrypt_and_digest, AES_GCM.decrypt_and_verify),
        "SIGNATURE_ALGORITHM": handshake_verify,
        "HANDSHAKE_AUTHENTICATION": (hashlib.sha384, hashlib.sha384().digest_size)
    },
    # TLS_CHACHA20_POLY1305_SHA256 with RSA-PSS-SHA256 as certificate signature and ECDHE as key exchange
    "TLS_ECDHE_RSA_PSS_SHA256_CHACHA20_POLY1305_SHA256": {
        "KEY_EXCHANGE": ECDHE_SUPPORTED_CURVES,
        "AUTHENTICATED_CIPHER": (CHACHA20_POLY1305.encrypt_and_digest, CHACHA20_POLY1305.decrypt_and_verify),
        "SIGNATURE_ALGORITHM": handshake_verify,
        "HANDSHAKE_AUTHENTICATION": (hashlib.sha256, hashlib.sha256().digest_size)
    },
    # TLS_CHACHA20_POLY1305_SHA256 with RSA-PSS-SHA256 as certificate signature and DHE as key exchange
    "TLS_DHE_RSA_PSS_SHA256_CHACHA20_POLY1305_SHA256": {
        "KEY_EXCHANGE": DHE_SUPPORTED_GROUPS,
        "AUTHENTICATED_CIPHER": (CHACHA20_POLY1305.encrypt_and_digest, CHACHA20_POLY1305.decrypt_and_verify),
        "SIGNATURE_ALGORITHM": handshake_verify,
        "HANDSHAKE_AUTHENTICATION": (hashlib.sha256, hashlib.sha256().digest_size)
    }
}