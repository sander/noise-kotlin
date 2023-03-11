package nl.sanderdijkhuis.noise

interface Cryptography {

    /** X25519 from [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) */
    fun agree(privateKey: PrivateKey, publicKey: PublicKey): SharedSecret

    /** ChaCha20-Poly1305 encryption from [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) */
    fun encrypt(key: CipherKey, nonce: Nonce, associatedData: Data, plaintext: Plaintext): Ciphertext

    /** ChaCha20-Poly1305 decryption from [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) */
    fun decrypt(key: CipherKey, nonce: Nonce, associatedData: Data, ciphertext: Ciphertext): Plaintext?

    /** SHA-256 from [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) */
    fun hash(data: Data): Digest
}
