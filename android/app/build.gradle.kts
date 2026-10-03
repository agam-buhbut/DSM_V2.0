plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.dsm.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.dsm.android"
        minSdk = 26 // StrongBox (28+) is gated at runtime.
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Ship only the ABIs we cross-compile the native core for.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    kotlinOptions {
        jvmTarget = "21"
    }

    // The native libs cross-compiled by cargo-ndk live in the default jniLibs
    // source dir (src/main/jniLibs/<abi>/libtuncore.so); the generated UniFFI
    // bindings live in src/main/java/uniffi/tuncore/tuncore.kt.

    testOptions {
        unitTests {
            isReturnDefaultValues = true
        }
    }

    lint {
        // The UniFFI-generated bindings (uniffi/tuncore/tuncore.kt) call
        // java.lang.ref.Cleaner behind a runtime Class.forName guard with a JNA
        // fallback for API < 33; lint cannot see through the reflection so it
        // flags NewApi false positives. The baseline records those known,
        // runtime-safe findings while still failing on any NEW issue.
        baseline = file("lint-baseline.xml")
    }
}

dependencies {
    // UniFFI Kotlin bindings depend on the JNA runtime; the @aar variant bundles
    // the JNA native dispatcher for Android ABIs.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("androidx.annotation:annotation:1.8.2")

    testImplementation("junit:junit:4.13.2")
    // TEST-ONLY: BouncyCastle mints the synthetic CA + server certs (custom
    // critical noiseStaticBinding extension) used to exercise the verifier
    // off-device. The production verifier uses ONLY java.security — BC is never
    // on the `implementation` classpath and ships in no APK.
    testImplementation("org.bouncycastle:bcpkix-jdk18on:1.77")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
