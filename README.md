# Noise for Kotlin

**Noise for Kotlin** contains example code for implementing [Noise](https://noiseprotocol.org) protocols based on Diffie-Hellman key agreement. It may evolve into a usable library. [Contact me](mailto:mail@sanderdijkhuis.nl) if you are interested in helping out to realize this.

> **Warning**: Some reasons why you **may not** use any of this code in production yet:
>
> - It has not yet been reviewed for secure engineering practices.
> - It leaves your secrets on the heap, up for grabs.

## How to build

Run the tests. On POSIX:

    ./gradlew test

On Windows:

    gradlew test

See [HandshakeTest](src/test/kotlin/HandshakeTest.kt) for some example handshakes.

Instead of `test`, use `jar` to create a JAR in `build/distributions`.

## How to use in a prototype

Assuming you build your prototype using [Gradle](https://gradle.org), add to `settings.gradle.kts`:

```kotlin
sourceControl {
    gitRepository(uri("https://github.com/sander/noise-kotlin.git")) {
        producesModule("nl.sanderdijkhuis:noise-kotlin")
    }
}
```

Then, pick any [release](https://github.com/sander/noise-kotlin/releases) you like, such as `v0.1.0`, and add to `build.gradle.kts`:

```kotlin
dependencies {

    // -%<- other dependencies -%<-

    implementation("nl.sanderdijkhuis:noise-kotlin:v0.1.0")
}
```

Then, implement [`Cryptography`](src/main/kotlin/Cryptography.kt) for your platform and `initialize` a [`HandshakeState`](src/main/kotlin/HandshakeState.kt).

## Design decisions

- Provide pure functions only, never a callback, leaving effect handling to the user.
    - Consequence: users must provide any generated keys upfront. Not yet sure if this will work for all situations.
- Support only Curve25519, ChaCha20-Poly1305, and SHA-256 to reduce the need to choose and since these are available on most platforms.
    - Consequence: it should be easy to use with [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html).
- Use only Kotlin types and functions, and nothing directly from Java SE or libraries.
    - Consequence: all dangerous cryptography implementation is behind an interface, which users need to implement using native platform functions.

## Test vectors

[Test vectors](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors) are used from:

- [snow.txt](src/test/resources/vectors/snow.txt) from [mcginty/snow](https://github.com/mcginty/snow/blob/375ba067b54f09ecaaa4211f9dd48fdc7f43fa50/tests/vectors/snow.txt)

## Related resources

- [License](LICENSE.md)
- [Security policy](SECURITY.md)
