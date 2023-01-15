# babyTLS
"Tiny" implementation of Transport Layer Security (TLS) 1.3 for educational purposes.

babyTLS should not be used for securing systems. Instead, openSSL, Disco or other libraries that are meant for commercial/academic purposes are prefered. This implementation is for educational purposes, in order to understand the protocol in a more simplier way.

For now, babyTLS have the following structure:
* `certs` folder: contains the digital certificate data as an example.
* `babyTLSUtil.py`: Encryption, decryption and verification functions.
* `ecc.py`: Elliptic Curve Cryptography handler.
* `key_exchange.py`: Key exchange methods for Client Hello and Server Hello part.
* `packets.py`: Construct TLS packets for Client Hello, Server Hello, Encrypted Packet and Certificate Signature.
* `params.py`: Parameters for different key exchange methods.
* `server.ipynb`: Server handler using TCP sockets.
* `client.ipynb`: Client handler using TCP sockets.

### About the cipher suites
babyTLS only supports (for now) `TLS_AES_256_GCM_SHA256`, with `ECDHE` and `DHE` as key exchange methods and `RSA-PSS` as the certificate signature algorithm.

### To Do
* Cipher suite negotiation
* Add more modularization
* Encrypt data for application flow

### References
* TLS in practice: https://cryptohack.org
* Curve and Group parameters for key exchange methods: https://www.rfc-editor.org/rfc/rfc7919#appendix-A.1
* TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446, https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20180125_TLSv1.3_Andy_Brodie.pdf
* Adding Post-Quantum Cryptography: https://www.amongbytes.com/post/201810-baby-steps-to-pq-https-server/
* Searching for most popular cipher suite: https://crypto.stackexchange.com/questions/60690/what-is-the-most-popular-cipher-suite-used-in-tls-1-2-for-https
* TLS cipher suites supported for your browser: https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html
* Some vulnerabilities of `DHE`: https://media.cert.europa.eu/static/WhitePapers/CERT-EU-SWP_16-002_Weaknesses%20in%20Diffie-Hellman%20Key%20v1_0.pdf, https://weakdh.org/imperfect-forward-secrecy.pdf, https://crypto.stackexchange.com/questions/89870/is-there-a-complete-summarized-list-of-attacks-on-diffie-hellman
* Security considerations of ECDSA: https://www.cs.miami.edu/home/burt/learning/Csc609.142/ecdsa-cert.pdf#page=28
* Industry concerns about TLS 1.3: https://mailarchive.ietf.org/arch/msg/tls/CzjJB1g0uFypY8UDdr6P9SCQBqA/
* Key Log format for decrypting TLS 1.3: https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
* The Illustrated TLS 1.3 Connection: https://tls13.xargs.org
* PEM Parser: https://8gwifi.org/PemParserFunctions.jsp
* David Wong - Real-World Cryptography: https://www.manning.com/books/real-world-cryptography

