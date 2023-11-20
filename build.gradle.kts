import java.net.URL
import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.9.10"
    id("org.jetbrains.kotlinx.kover") version "0.7.4"
    kotlin("plugin.serialization") version "1.9.10"
    `maven-publish`
    signing
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    id("org.jetbrains.dokka") version "1.9.10"
}

group = "nl.sanderdijkhuis"
version = "1.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.1")
    testImplementation("org.bouncycastle:bcprov-jdk15on:1.70")
    testImplementation("org.bouncycastle:bcpkix-jdk15on:1.70")
}

java {
    withJavadocJar()
    withSourcesJar()

    toolchain {
        languageVersion.set(JavaLanguageVersion.of(8))
        vendor.set(JvmVendorSpec.AZUL)
        implementation.set(JvmImplementation.VENDOR_SPECIFIC)
    }
}

kotlin {
    jvmToolchain(8)
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<DokkaTask> {
    dokkaSourceSets {
        named("main") {
            moduleName.set("Noise for Kotlin")
            includes.from("src/main/README.md")
            skipDeprecated.set(true)
            sourceLink {
                localDirectory.set(file("src/main/kotlin"))
                remoteUrl.set(URL("https://github.com/sander/noise-kotlin/tree/main/src/main/kotlin"))
                remoteLineSuffix.set("#L")
            }
        }
    }
}

tasks.withType<KotlinCompile> {
    kotlinOptions.allWarningsAsErrors = true
    kotlinOptions.jvmTarget = "1.8"
}

koverReport {
    defaults {
        verify {
            onCheck = true
            rule {
                bound {
                    metric = kotlinx.kover.gradle.plugin.dsl.MetricType.BRANCH
                    minValue = 55
                }
            }
        }
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "noise-kotlin"
            from(components["java"])
            pom {
                name.set("Noise for Kotlin")
                description.set("Noise protocols based on Diffie-Hellman key agreement")
                url.set("https://github.com/sander/noise-kotlin")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://github.com/sander/noise-kotlin/blob/main/LICENSE.md")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/sander/noise-kotlin.git")
                    developerConnection.set("scm:git:ssh://github.com/sander/noise-kotlin.git")
                    url.set("https://github.com/sander/noise-kotlin")
                }
                developers {
                    developer {
                        id.set("sander")
                        name.set("Sander Dijkhuis")
                        email.set("mail@sanderdijkhuis.nl")
                    }
                }
            }
        }
    }
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}

signing {
    sign(publishing.publications["maven"])
}
