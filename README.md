# Noise for Kotlin

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/nl.sanderdijkhuis/noise-kotlin/badge.svg?style=flat-square&gav=true)](https://central.sonatype.com/artifact/nl.sanderdijkhuis/noise-kotlin/)

**Noise for Kotlin** enables implementation of [Noise](https://noiseprotocol.org) protocols based on Diffie-Hellman key agreement.

## API documentation

See the [API docs](https://sander.github.io/noise-kotlin/api/) about the latest release or use the Gradle `dokkaHtml` task for a local copy about any version.

## How to build

Run the tests. On POSIX:

    ./gradlew test

On Windows:

    gradlew test

See [HandshakeTest](src/test/kotlin/HandshakeTest.kt) for some example handshakes.

Instead of `test`, use `jar` to create a JAR in `build/distributions`.

## How to use in an application

Add the [`noise-kotlin` dependency](https://central.sonatype.com/artifact/nl.sanderdijkhuis/noise-kotlin) to your project.

Then, implement [`Cryptography`](src/main/kotlin/cryptography/Cryptography.kt) for your platform and `initialize` a [`Handshake`](src/main/kotlin/Handshake.kt).

## Design decisions

- Provide pure functions only, never a callback, leaving effect handling to the user.
    - Consequence: users must provide any generated keys upfront. Not yet sure if this will work for all situations.
- Support only Curve25519, ChaCha20-Poly1305, and SHA-256 to reduce the need to choose and since these are available on most platforms.
    - Consequence: it should be easy to use with [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html).
- Use only Kotlin types and functions, and nothing directly from Java SE or libraries.
    - Consequence: all cryptographic function dependency implementation is behind an interface, which users need to implement using native platform functions.
- Do not include particular masking, encryption, or zeroization functionality for sensitive data, to avoid disproportional complexity.
    - Consequence: run with sufficiently protected volatile memory and protect heap dump data from unauthorized access.

## Test vectors

[Test vectors](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors) are used from:

- [snow.txt](src/test/resources/vectors/snow.txt) from [mcginty/snow](https://github.com/mcginty/snow/blob/375ba067b54f09ecaaa4211f9dd48fdc7f43fa50/tests/vectors/snow.txt)

## Related resources

- [License](LICENSE.md)
- [Security policy](SECURITY.md)
