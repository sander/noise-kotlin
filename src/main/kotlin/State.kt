package nl.sanderdijkhuis.noise

data class State<S, A>(val current: S, val result: A) {

    fun <B>map(f: (A) -> B) = State(current, f(result))
}
