// Gradle settings for the mobile Android side of the workspace.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "p2claw-mobile-android"

include(":sdk")
project(":sdk").projectDir = file("sdk")

include(":demo")
project(":demo").projectDir = file("demo")
