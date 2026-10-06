// Root build script. AGP + Kotlin + the maven-publish plugin are
// declared here so subprojects can apply them by id; per-module
// configuration lives in each subproject's build.gradle.kts.

plugins {
    id("com.android.application") version "8.7.0" apply false
    id("com.android.library") version "8.7.0" apply false
    kotlin("android") version "2.0.21" apply false
    // Kotlin 2.0+ requires the Compose Compiler Gradle plugin to be
    // applied explicitly alongside the Compose Multiplatform plugin.
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
    // Compose Multiplatform plugin — applied only by the `:demo`
    // app module, declared at the root so the version is pinned
    // centrally.
    id("org.jetbrains.compose") version "1.7.0" apply false
    id("com.vanniktech.maven.publish") version "0.30.0" apply false
}
