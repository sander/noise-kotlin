import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.8.21"
    id("org.jetbrains.kotlinx.kover") version "0.7.1"
    kotlin("plugin.serialization") version "1.8.21"
    `maven-publish`
    signing
}

group = "nl.sanderdijkhuis"
version = "0.7.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.5.1")
}

java {
    withJavadocJar()
    withSourcesJar()
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.allWarningsAsErrors = true
    kotlinOptions.jvmTarget = "1.8"
}

koverReport {
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
    repositories {
        maven {
            val releasesRepoUrl = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            val snapshotsRepoUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
            credentials(PasswordCredentials::class.java)
        }
    }
}

signing {
    sign(publishing.publications["maven"])
}
