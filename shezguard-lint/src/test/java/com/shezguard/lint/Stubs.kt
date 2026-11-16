package com.shezguard.lint

import com.android.tools.lint.checks.infrastructure.LintDetectorTest.java
import com.android.tools.lint.checks.infrastructure.LintDetectorTest.kotlin
import com.android.tools.lint.checks.infrastructure.TestFile
import com.android.tools.lint.checks.infrastructure.TestFiles.manifest

/**
 * Minimal stand-ins for the :shezguard-core API the rule recognises. Only names and signatures matter:
 * the detectors match on fully qualified names, never on behaviour.
 */
object Stubs {
    val checkResult: TestFile = java(
        """
        package androidx.annotation;
        import java.lang.annotation.*;
        @Retention(RetentionPolicy.CLASS)
        @Target({ElementType.METHOD})
        public @interface CheckResult { String suggest() default ""; }
        """
    ).indented()

    val core: TestFile = kotlin(
        """
        package com.shezguard.core

        import android.app.Activity
        import android.content.Intent
        import androidx.annotation.CheckResult

        @Retention(AnnotationRetention.RUNTIME)
        @Target(AnnotationTarget.CLASS)
        annotation class GuardedEntryPoint(val name: String = "", val exempt: Boolean = false)

        class CheckedIntent(val intent: Intent)

        class ActivityGuard(private val policy: Any?) {
            @CheckResult
            fun onCreate(activity: Activity): CheckedIntent? = null
            @CheckResult
            fun onNewIntent(activity: Activity, intent: Intent): CheckedIntent? = null
        }
        """
    ).indented()

    val policy: TestFile = kotlin(
        """
        package com.shezguard.core.policy

        class IntentPolicy
        class EntryPointBuilder
        class IntentPolicyBuilder {
            fun entryPoint(name: String, block: EntryPointBuilder.() -> Unit) {}
        }
        fun intentPolicy(block: IntentPolicyBuilder.() -> Unit): IntentPolicy = IntentPolicy()
        """
    ).indented()

    val all: Array<TestFile> = arrayOf(checkResult, core, policy)

    /** An app manifest with the given `<application>` body. */
    fun appManifest(body: String, targetSdk: Int = 35): TestFile = manifest(
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            xmlns:tools="http://schemas.android.com/tools" package="test.app">
            <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="$targetSdk"/>
            <application>
        $body
            </application>
        </manifest>
        """
    ).indented()

    /** An activity source in package `test.app`, with an optional annotation line. */
    fun activity(name: String, annotation: String = "", body: String = ""): TestFile = kotlin(
        """
        package test.app

        import android.app.Activity
        import com.shezguard.core.GuardedEntryPoint

        $annotation
        class $name : Activity() {
        $body
        }
        """
    ).indented()

    /** A policy file in package `test.app` declaring the given entry points (literal names). */
    fun policyFor(vararg names: String): TestFile = kotlin(
        """
        package test.app

        import com.shezguard.core.policy.intentPolicy

        object AppPolicy {
            val policy = intentPolicy {
        ${names.joinToString("\n") { "        entryPoint(\"$it\") {}" }}
            }
        }
        """
    ).indented()
}
