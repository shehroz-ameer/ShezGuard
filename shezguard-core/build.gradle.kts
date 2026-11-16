plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.shezguard.core"
    compileSdk = 35

    defaultConfig {
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
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
    testOptions {
        // Robolectric needs merged Android resources/manifest on the unit-test classpath.
        unitTests.isIncludeAndroidResources = true
    }
}

kotlin {
    // Every declaration must be deliberately `public` or `internal` (CLAUDE.md hard rule).
    explicitApi()
}

dependencies {
    // The only allowed runtime dependency: androidx.core (for IntentSanitizer).
    // `api`, not `implementation`: the public constructor NestedIntentSanitizer(IntentSanitizer)
    // exposes androidx.core.content.IntentSanitizer to apps.
    api(libs.androidx.core)

    // Step 13: the build-time coverage check (Lint rule) ships inside this library's AAR as lint.jar.
    // lintPublish is not a runtime or compile dependency: it adds nothing to the runtime classpath or
    // the published POM (checked in step 13 by diffing releaseRuntimeClasspath; docs/SPEC.md section 9).
    // Non-transitive: lintPublish takes exactly one jar, and Lint supplies the Kotlin stdlib itself.
    lintPublish(project(":shezguard-lint")) { isTransitive = false }

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
