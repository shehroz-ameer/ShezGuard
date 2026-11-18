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
        // Step 14: the instrumented test APK targets 35, so that targetSdk-gated platform behaviour
        // (package visibility from 30, hidden-API lists) is the behaviour a current app gets.
        // Test APK only; the library itself declares no targetSdk.
        targetSdk = 35
    }

    // Step 14: classes in src/sharedTest run twice: on the JVM (Robolectric, via AndroidJUnit4's
    // delegation, keeping each class's @Config(sdk = ...)) and as instrumented tests on an emulator.
    sourceSets {
        getByName("test").java.srcDir("src/sharedTest/java")
        getByName("androidTest").java.srcDir("src/sharedTest/java")
    }
}

kotlin {
    // Every declaration must be deliberately `public` or `internal` (CLAUDE.md hard rule).
    explicitApi()
}

// Step 15: adversarial hardening tests (docs/HARDENING.md). Several of them fail on purpose: each
// failing test demonstrates a finding. They live in src/hardeningTest and are compiled into the debug
// unit-test classes ONLY when `hardeningTest` is on the command line, so `test` and `check` never
// compile or run them. The normal unit-test tasks also exclude the package, as a second guard.
// Run: ./gradlew :shezguard-core:hardeningTest
val hardeningRequested = gradle.startParameter.taskNames.any { it.substringAfterLast(':') == "hardeningTest" }
if (hardeningRequested) {
    android.sourceSets.getByName("test").java.srcDir("src/hardeningTest/java")
}
val hardeningPackage = "com.shezguard.core.hardening.*"
tasks.withType<Test>().configureEach {
    if (name != "hardeningTest") {
        filter.excludeTestsMatching(hardeningPackage)
    }
}
tasks.register<Test>("hardeningTest") {
    group = "verification"
    description = "Step 15 adversarial hardening tests (expected to contain failing tests). Not part of test/check."
    val unit = tasks.named<Test>("testDebugUnitTest").get()
    testClassesDirs = unit.testClassesDirs
    classpath = unit.classpath
    filter.includeTestsMatching(hardeningPackage)
    maxHeapSize = "2g"
    systemProperty("shezguard.hardening.out", layout.buildDirectory.dir("hardening").get().asFile.absolutePath)
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.SHORT
    }
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
    // Step 14: AndroidJUnit4 runner for src/sharedTest; on the JVM it delegates to Robolectric.
    testImplementation(libs.androidx.junit)
    // Step 14: @Config(sdk = ...) on shared classes must compile for androidTest. Compile-only: the
    // annotation is absent from the test APK, and ART ignores an annotation whose class is missing.
    androidTestCompileOnly(libs.robolectric.annotations)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
