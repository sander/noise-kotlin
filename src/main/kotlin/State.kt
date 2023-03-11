package nl.sanderdijkhuis.noise

data class State<S, A>(val value: S, val result: A) {

    fun <B>map(f: (A) -> B) = State(value, f(result))
}
