import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.8.10"
    id("org.jetbrains.kotlinx.kover") version "0.7.0-Alpha"
    kotlin("plugin.serialization") version "1.8.10"
}

group = "nl.sanderdijkhuis"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.5.0")
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
