package nl.sanderdijkhuis.noise

data class State<S, A>(val state: S, val value: A) {

    fun <B>map(f: (A) -> B) = State(state, f(value))
}
