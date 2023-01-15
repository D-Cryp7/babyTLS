# ref: https://www.rfc-editor.org/rfc/rfc7919#appendix-A.1
# ref: https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3.2
# ref: https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20180125_TLSv1.3_Andy_Brodie.pdf
# ref: https://www.amongbytes.com/post/201810-baby-steps-to-pq-https-server/
# ref: https://crypto.stackexchange.com/questions/60690/what-is-the-most-popular-cipher-suite-used-in-tls-1-2-for-https
# ref: https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
# ref: https://media.cert.europa.eu/static/WhitePapers/CERT-EU-SWP_16-002_Weaknesses%20in%20Diffie-Hellman%20Key%20v1_0.pdf
# ref: https://weakdh.org/imperfect-forward-secrecy.pdf
# ref: https://www.cs.miami.edu/home/burt/learning/Csc609.142/ecdsa-cert.pdf#page=28
# ref: https://crypto.stackexchange.com/questions/89870/is-there-a-complete-summarized-list-of-attacks-on-diffie-hellman
# ref: https://mailarchive.ietf.org/arch/msg/tls/CzjJB1g0uFypY8UDdr6P9SCQBqA/
# ref: https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
# ref: https://tls13.xargs.org/#wrapped-record-9/annotated
# ref: https://8gwifi.org/PemParserFunctions.jsp
# ref: https://cryptoctf.org/2022/09/11/writeup-of-flag-submission-forgery-by-si/

DHKE_SUPPORTED_GROUPS = {
    "ffdhe2048": {
        "g": 0x02,
        "p": 0xffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff
    },
    "ffdhe3072": {
        "g": 0x02,
        "p": 0xffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff
    }
}

ECDHKE_SUPPORTED_CURVES = {
    "secp256r1": {
        "G": (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
        "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        "type": "W"
    },
    "secp384r1": {
        "G": (0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),
        "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        "a": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
        "b": 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        "n": 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        "type": "W"
    },
    "X25519": {
        "G": (0x09, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9),
        "p": 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
        "a": 0x76d06,
        "b": 0x01,
        "n": 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
        "type": "M"
    }
}