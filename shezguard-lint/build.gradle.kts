import java.time.Duration

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

// Step 15: adversarial hardening tests for the Lint rule (docs/HARDENING.md). A separate source set and task,
// not wired into `test` or `check`; some tests fail on purpose to demonstrate a finding.
// Run: ./gradlew :shezguard-lint:hardeningTest
val hardeningTestSourceSet: SourceSet = sourceSets.create("hardeningTest") {
    compileClasspath += sourceSets.main.get().output + sourceSets.test.get().output
    runtimeClasspath += sourceSets.main.get().output + sourceSets.test.get().output
}
configurations[hardeningTestSourceSet.implementationConfigurationName].extendsFrom(configurations.testImplementation.get())
configurations[hardeningTestSourceSet.runtimeOnlyConfigurationName].extendsFrom(configurations.testRuntimeOnly.get())
tasks.register<Test>("hardeningTest") {
    group = "verification"
    description = "Step 15 adversarial hardening tests for the Lint rule. Not part of test/check."
    testClassesDirs = hardeningTestSourceSet.output.classesDirs
    classpath = hardeningTestSourceSet.runtimeClasspath
    val sdkDir = rootProject.file("local.properties").takeIf { it.exists() }
        ?.readLines()?.firstOrNull { it.startsWith("sdk.dir=") }?.substringAfter("=")
        ?: System.getenv("ANDROID_HOME")
    if (sdkDir != null) environment("ANDROID_HOME", sdkDir)
    testLogging {
        events("passed", "failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.SHORT
    }
}

// Step 16 safety net: no test task may hang a build.
tasks.withType<Test>().configureEach { timeout.set(Duration.ofMinutes(20)) }
