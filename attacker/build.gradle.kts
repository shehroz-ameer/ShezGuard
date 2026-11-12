// Step 11: the attacker app used by scripts/attacks (emulator only; attacker/README.md).
// No dependencies beyond the Android SDK (the Kotlin standard library comes with the Kotlin plugin).
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.shezguard.attacker"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.shezguard.attacker"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0-attacker"
    }

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
}
