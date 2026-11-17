// Step 14 phase 3: timing ShezGuard.evaluate on an emulator (docs/BENCHMARK.md). Instrumented tests only;
// nothing here ships. androidx.benchmark is used in this module only, without its Gradle plugin.
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.shezguard.benchmark"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.benchmark.junit4.AndroidBenchmarkRunner"
    }

    // The test APK is built from the release build type: not debuggable (a debuggable process runs
    // ART with fewer JIT optimisations), not minified. It depends on :shezguard-core's release variant.
    testBuildType = "release"

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    testOptions {
        targetSdk = 35
    }
}

dependencies {
    androidTestImplementation(project(":shezguard-core"))
    androidTestImplementation(libs.androidx.benchmark.junit4)
    androidTestImplementation(libs.androidx.junit)
}
