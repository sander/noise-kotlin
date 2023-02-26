package nl.sanderdijkhuis.noise

data class Payload(val data: Data) {

    val plainText get() = Plaintext(data.value)
}