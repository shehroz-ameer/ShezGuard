// Step 13: build-time coverage check (docs/SPEC.md section 9). A custom Android Lint rule, shipped to
// consumers inside the :shezguard-core AAR via `lintPublish`. Not a runtime dependency of anything.
plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

dependencies {
    // Lint provides its own API (and the Kotlin stdlib) at run time; never bundled.
    compileOnly(libs.lint.api)
    testImplementation(libs.lint.api)
    testImplementation(libs.lint.tests)
    testImplementation(libs.lint.checks)
    testImplementation(libs.lint.cli)
    testImplementation(libs.junit)
}

tasks.jar {
    manifest {
        // Lint also finds the registry through META-INF/services; this attribute is the older mechanism.
        attributes("Lint-Registry-v2" to "com.shezguard.lint.ShezGuardIssueRegistry")
    }
}

tasks.test {
    // lint-tests needs an Android SDK (android.jar) to resolve android.app.Activity.
    val sdkDir = rootProject.file("local.properties").takeIf { it.exists() }
        ?.readLines()?.firstOrNull { it.startsWith("sdk.dir=") }?.substringAfter("=")
        ?: System.getenv("ANDROID_HOME")
    if (sdkDir != null) environment("ANDROID_HOME", sdkDir)
}
