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

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        // AUDIT_LOGCAT: the protected flavor's policy installs ShezGuard's redacted LogcatAuditSink when true
        // (step 12), so the attack scripts can record violation codes. Unused by the vulnerable flavor.
        debug {
            buildConfigField("boolean", "AUDIT_LOGCAT", "true")
        }
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            buildConfigField("boolean", "AUDIT_LOGCAT", "false")
        }
        // TEST-ONLY BUILD TYPE (step 12, author condition 6). NEVER SHIP IT. It exists only to check that
        // R8 keeps @GuardedEntryPoint (docs/LIMITATIONS.md L36) and that every attack and benign script
        // gives the same result as the unminified build. It is a release build minified with R8, signed
        // with the debug key, with audit logging to logcat switched on, and marked testOnly in its
        // manifest (src/minified/AndroidManifest.xml), so it installs only with `adb install -t`.
        create("minified") {
            initWith(getByName("release"))
            isMinifyEnabled = true
            signingConfig = signingConfigs.getByName("debug")
            matchingFallbacks += "release"
            buildConfigField("boolean", "AUDIT_LOGCAT", "true")
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
        // Step 12: the protected flavor's DemoPolicyTest builds the policy (ComponentName, IntentSanitizer)
        // under Robolectric, which needs the merged manifest and resources.
        unitTests.isIncludeAndroidResources = true
    }
}

dependencies {

    implementation(project(":shezguard-core"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    // Step 12: test-only, same catalog version as :shezguard-core (no version change).
    testImplementation(libs.robolectric)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}