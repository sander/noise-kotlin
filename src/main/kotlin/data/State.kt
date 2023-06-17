package nl.sanderdijkhuis.noise.data

/** Provides a functional approach to handling protocol state. */
data class State<S, A>(val value: S, val result: A) {

    fun <B>map(f: (A) -> B) = State(value, f(result))

    @Suppress("UNCHECKED_CAST")
    fun <T>state(): T? = value as? T
}
