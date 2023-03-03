package nl.sanderdijkhuis.noise

interface Cryptography {

    fun agree(privateKey: PrivateKey, publicKey: PublicKey): SharedSecret

    fun encrypt(key: CipherKey, nonce: Nonce, associatedData: Data, plaintext: Plaintext): Ciphertext

    fun decrypt(key: CipherKey, nonce: Nonce, associatedData: Data, ciphertext: Ciphertext): Plaintext?

    fun hash(data: Data): Digest
}