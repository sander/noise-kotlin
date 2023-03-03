package nl.sanderdijkhuis.noise

@JvmInline
value class AssociatedData(val data: Data) {

    companion object {

        val empty get() = AssociatedData(Data.empty)
    }
}
