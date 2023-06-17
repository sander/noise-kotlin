# Module Noise for Kotlin

A library for implementing [Noise](https://noiseprotocol.org) protocols based on Diffie-Hellman key agreement.

To get started, implement the cryptography dependencies and initialize a Noise handshake. 

# Package nl.sanderdijkhuis.noise

Provides Noise Protocol Framework implementation.

# Package nl.sanderdijkhuis.noise.data

Provides management of generic bounded binary data and state.

All data is handled as immutable.

No particular masking, encryption, or zeroization of sensitive data is implemented. The module assumes that the runtime environment’s volatile memory is sufficiently protected and that only trusted roles can access heap dump data.

# Package nl.sanderdijkhuis.noise.cryptography

Provides means to implement and apply cryptographic function dependencies.

The module depends on the following cryptographic functions:

- ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) from [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
- SHA-256 hashing from [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- X25519 Diffie-Hellman exchange from [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)

These can be implemented using for example Java SE 11 or [Bouncy Castle](https://www.bouncycastle.org/java.html).

Note that in some cases we speak of “no-op encryption”. This is to meet the `EncryptWithAd` and `DecryptWithAd` [Noise specification](https://noiseprotocol.org/noise.html#the-cipherstate-object) which provide the identity function when no cipher key is set.
