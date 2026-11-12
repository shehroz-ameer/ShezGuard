plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.shezguard.router"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.shezguard.router"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Step 11: a deliberately vulnerable demo for emulators only (app/README.md). Both flavors have
    // the same applicationId, so every attack targets the same package; install one at a time.
    // The only flavor-specific source is the EntryGuard shim (src/<flavor>/.../guard/EntryGuard.kt);
    // everything else, including every vulnerable sink, is shared in src/main.
    flavorDimensions += "variant"
    productFlavors {
        create("vulnerable") {
            dimension = "variant"
            versionNameSuffix = "-vulnerable"
        }
        create("protected") {
            dimension = "variant"
            versionNameSuffix = "-protected"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
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

dependencies {

    implementation(project(":shezguard-core"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}