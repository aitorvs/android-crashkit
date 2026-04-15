plugins {
    id("com.android.library")
    id("com.vanniktech.maven.publish") version "0.34.0"
    kotlin("android")
}
val libVersion = providers.gradleProperty("VERSION_NAME").orElse("0.0.1-SNAPSHOT").get()

mavenPublishing {
    publishToMavenCentral()

    signAllPublications()

    coordinates(
        groupId = "com.duckduckgo.crashkit",
        artifactId = "android-crashkit",
        version = libVersion // or call a function e.g. getVersionName()
    )

    pom {
        name.set("DDG Crashkit")
        description.set("DuckDuckGo Android crash reporting library wrapping Google Crashpad.")
        inceptionYear.set("2025")
        url.set("https://github.com/duckduckgo/android-crashkit")

        licenses {
            license {
                name.set("Apache License Version 2.0")
                url.set("https://github.com/duckduckgo/android-crashkit/blob/main/LICENSE")
                distribution.set("https://github.com/duckduckgo/android-crashkit/blob/main/LICENSE")
            }
        }
        developers {
            developer {
                id.set("duckduckgo")
                name.set("DuckDuckGo")
                url.set("https://github.com/duckduckgo/")
            }
        }
        scm {
            url.set("https://github.com/duckduckgo/android-crashkit")
            connection.set("scm:git:git://github.com/duckduckgo/android-crashkit.git")
            developerConnection.set("scm:git:ssh://git@github.com:duckduckgo/android-crashkit.git")
        }
    }
}


android {
    namespace = "com.duckduckgo.android_crashkit"
    compileSdk = 35
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 23
        ndk {
            // Ship the ABIs you actually provide in jniLibs/
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64") // add others if you included them
        }
    }

    sourceSets["main"].jniLibs.srcDirs("src/main/cpp/crashpad/lib")
    packagingOptions.jniLibs.useLegacyPackaging = true

    externalNativeBuild {
        cmake { version = "3.18.1" }
    }

    buildTypes {
        release {
            isMinifyEnabled = false // AAR code shrink is optional; native symbols unaffected
        }
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.13")
    testImplementation("androidx.test:core:1.6.1")
}

android.externalNativeBuild.cmake.apply {
    setPath(file("src/main/cpp/CMakeLists.txt"))
}