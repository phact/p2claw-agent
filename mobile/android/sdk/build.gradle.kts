// Android Library module for the p2claw mobile SDK.
//
// Carries the UniFFI-generated Kotlin bindings + native `.so` files
// (built by `../build-rust.sh`) into a single AAR. Maven Central
// publish is wired via the vanniktech plugin but never invoked from
// local Gradle — the only path to a real publish is the
// `.github/workflows/mobile-release.yml` job on a `mobile-v*` tag push.

plugins {
    id("com.android.library")
    kotlin("android")
    id("com.vanniktech.maven.publish")
}

group = "com.p2claw"
version = project.findProperty("VERSION_NAME") as String? ?: "0.0.0-SNAPSHOT"

android {
    namespace = "com.p2claw.sdk"
    // Track the latest platform we have local SDK metadata for. CI
    // bumps in lock-step with the workflow's `sdkmanager "platforms;..."`
    // line; bump together.
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            // UniFFI bindgen writes the generated Kotlin to
            // `crates/p2claw-mobile/generated/kotlin/`. Pull it onto
            // the source path so AGP compiles it alongside our
            // hand-written code in `src/main/kotlin/`. The CI
            // workflow regenerates this dir on every push;
            // checked-in copies stay in `crates/p2claw-mobile/` so
            // both Android and iOS consume from one source.
            java.srcDirs(
                "src/main/java",
                "src/main/kotlin",
                "${rootDir}/../../crates/p2claw-mobile/generated/kotlin",
            )
            jniLibs.srcDir("src/main/jniLibs")
        }
    }
}

dependencies {
    // JNA powers the UniFFI runtime's Java ↔ native calls. Pinned
    // major version; future bumps roll forward as upstream UniFFI
    // tracks them.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    // Kotlin coroutines for the foreign-implemented `SignalingTransport`
    // / `WsTransport` traits — the platform impl runs its async work
    // on a Dispatchers.IO coroutine; the SDK surfaces UniFFI's async
    // bindings as suspending functions.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // LiveKit's maintained prebuilt fork of the abandoned Google
    // `org.webrtc:google-webrtc` AAR. Same `org.webrtc.*` package
    // namespace, so `PeerConnectionFactory` / `PeerConnection` /
    // `DataChannel` imports are unchanged.
    implementation("io.github.webrtc-sdk:android:125.6422.07")

    // HTTPS POST + signaling WebSocket. The platform-side
    // `SignalingTransport` / `WsTransport` implementations route
    // through this single shared OkHttpClient.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // JSON for the connect-request body and ICE-server descriptors
    // returned from coord. Same library WebRTC's RTCConfiguration
    // parser already understands.
    implementation("org.json:json:20240303")
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()
    coordinates("com.p2claw", "sdk-android", version.toString())

    pom {
        name.set("p2claw Mobile SDK for Android")
        description.set("Native peer-to-peer client for the p2claw network")
        inceptionYear.set("2026")
        url.set("https://github.com/phact/p2claw-agent")
        licenses {
            license {
                name.set("MIT")
                url.set("https://opensource.org/licenses/MIT")
            }
        }
        developers {
            developer {
                id.set("p2claw")
                name.set("p2claw maintainers")
                url.set("https://p2claw.com/")
            }
        }
        scm {
            url.set("https://github.com/phact/p2claw-agent")
            connection.set("scm:git:git://github.com/phact/p2claw-agent.git")
            developerConnection.set("scm:git:ssh://git@github.com/phact/p2claw-agent.git")
        }
    }
}

// Cross-compile the Rust cdylib via `../build-rust.sh` before AGP
// assembles the AAR. The script populates
// `src/main/jniLibs/<abi>/libp2claw_mobile.so`; AGP picks them up
// from there during `assembleRelease` and lays them into the AAR's
// `lib/<abi>/` tree.
//
// CI skips this task (the `android-rust` matrix already produced the
// .so files and downloaded them as artifacts into the same dir).
// `-PskipRustBuild=true` short-circuits.
val skipRustBuild: Boolean = (project.findProperty("skipRustBuild") as String?)?.toBoolean() ?: false

val cargoNdk = tasks.register<Exec>("cargoNdkBuild") {
    workingDir = rootProject.projectDir
    commandLine("./build-rust.sh")
    onlyIf { !skipRustBuild }
}

tasks.named("preBuild") {
    dependsOn(cargoNdk)
}
