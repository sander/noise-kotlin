package nl.sanderdijkhuis.noise

interface Cryptography {

    fun agree(privateKey: PrivateKey, publicKey: PublicKey): SharedSecret

    fun encrypt(key: CipherKey, nonce: Nonce, associatedData: AssociatedData, plaintext: Plaintext): Ciphertext

    fun decrypt(key: CipherKey, nonce: Nonce, associatedData: AssociatedData, ciphertext: Ciphertext): Plaintext?

    fun hash(data: Data): Digest
}