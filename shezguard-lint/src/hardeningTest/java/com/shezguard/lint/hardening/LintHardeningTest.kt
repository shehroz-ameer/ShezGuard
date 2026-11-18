package com.shezguard.lint.hardening

import com.android.tools.lint.checks.infrastructure.LintDetectorTest.kotlin
import com.android.tools.lint.checks.infrastructure.TestFile
import com.android.tools.lint.checks.infrastructure.TestLintResult
import com.android.tools.lint.checks.infrastructure.TestLintTask.lint
import com.shezguard.lint.ShezGuardDetector
import com.shezguard.lint.Stubs
import com.shezguard.lint.Stubs.activity
import com.shezguard.lint.Stubs.appManifest
import com.shezguard.lint.Stubs.policyFor
import org.junit.Test

/**
 * Step 15, area 7: ways to write an unguarded entry point that the Lint rule accepts (docs/HARDENING.md).
 * `flags...` tests assert what the rule should report (a failure is a finding); `observes...` tests record
 * known blind spots (docs/LIMITATIONS.md L4, L41) and pass; `holds...` tests are negative results.
 */
class LintHardeningTest {

    private fun run(vararg files: TestFile): TestLintResult = lint()
        .issues(
            ShezGuardDetector.UNGUARDED_ENTRY_POINT,
            ShezGuardDetector.UNKNOWN_ENTRY_POINT_NAME,
            ShezGuardDetector.ENTRY_POINT_NAME_UNVERIFIABLE,
            ShezGuardDetector.INVALID_ANNOTATION,
            ShezGuardDetector.GUARD_CALL_ORDER,
            ShezGuardDetector.UNCHECKED_GUARD_RESULT,
            ShezGuardDetector.DEPENDENCY_ENTRY_POINT,
            ShezGuardDetector.UNCOVERED_COMPONENT,
        )
        .files(*Stubs.all, *files)
        .run()

    private val browsable = """
                <intent-filter>
                    <action android:name="android.intent.action.VIEW"/>
                    <category android:name="android.intent.category.DEFAULT"/>
                    <category android:name="android.intent.category.BROWSABLE"/>
                    <data android:scheme="https" android:host="example.com"/>
                </intent-filter>"""

    /**
     * H7, by design (docs/LIMITATIONS.md L41, step 16): `exempt = true` is the explicit opt-out and is accepted even on
     * an exported BROWSABLE activity that reads `intent.data`. A warning for that case is future work.
     */
    @Test
    fun observesExemptBrowsableActivityThatReadsIntentDataIsAccepted() {
        run(
            appManifest("""<activity android:name=".LinkActivity" android:exported="true">$browsable</activity>"""),
            activity(
                "LinkActivity", "@GuardedEntryPoint(exempt = true)",
                """
                override fun onCreate(savedInstanceState: android.os.Bundle?) {
                    super.onCreate(savedInstanceState)
                    val target = intent.data?.getQueryParameter("next")
                }
                """,
            ),
        ).expectClean()
    }

    /** L4 instance: guarded in onCreate, raw intent consumed in onNewIntent (singleTop / singleTask). */
    @Test
    fun observesOnNewIntentThatSkipsTheGuardIsAccepted() {
        run(
            appManifest("""<activity android:name=".LinkActivity" android:exported="true" android:launchMode="singleTop">$browsable</activity>"""),
            policyFor("link"),
            activity(
                "LinkActivity", "@GuardedEntryPoint(\"link\")",
                """
                private val guard = com.shezguard.core.ActivityGuard(null)
                override fun onCreate(savedInstanceState: android.os.Bundle?) {
                    val checked = guard.onCreate(this)
                    super.onCreate(checked?.let { savedInstanceState })
                    if (checked == null) return
                }
                override fun onNewIntent(intent: android.content.Intent) {
                    super.onNewIntent(intent)
                    val next = intent.data?.getQueryParameter("next") // never evaluated
                }
                """,
            ),
        ).expectClean()
    }

    /** Outside v1 scope: an exported receiver registered at run time never appears in the manifest. */
    @Test
    fun observesDynamicallyRegisteredExportedReceiverIsInvisible() {
        run(
            appManifest("""<activity android:name=".MainActivity" android:exported="false"/>"""),
            activity(
                "MainActivity", "",
                """
                override fun onCreate(savedInstanceState: android.os.Bundle?) {
                    super.onCreate(savedInstanceState)
                    registerReceiver(object : android.content.BroadcastReceiver() {
                        override fun onReceive(c: android.content.Context, i: android.content.Intent) { }
                    }, android.content.IntentFilter("test.app.OPEN"), android.content.Context.RECEIVER_EXPORTED)
                }
                """,
            ),
        ).expectClean()
    }

    /** Negative results: unresolvable or unusual `android:exported` values are treated as exported. */
    @Test
    fun holdsPlaceholderAndResourceExportedValuesAreTreatedAsExported() {
        run(
            appManifest(
                """
                <activity android:name=".AActivity" android:exported="${'$'}{exportA}"/>
                <activity android:name=".BActivity" android:exported="@bool/export_b"/>
                <activity android:name=".CActivity" android:exported="TRUE"/>"""
            ),
            activity("AActivity"),
            activity("BActivity"),
            activity("CActivity"),
        ).expectErrorCount(3)
    }

    /** Negative result: an alias whose target is unannotated is flagged, whatever the alias is called. */
    @Test
    fun holdsAliasToUnannotatedTargetIsFlagged() {
        run(
            appManifest(
                """
                <activity android:name=".TargetActivity" android:exported="false"/>
                <activity-alias android:name=".GuardedLooking" android:targetActivity=".TargetActivity" android:exported="true">$browsable</activity-alias>"""
            ),
            activity("TargetActivity"),
            kotlin(
                """
                package test.app
                import android.app.Activity
                import com.shezguard.core.GuardedEntryPoint
                @GuardedEntryPoint("guarded")
                class GuardedLooking : Activity()
                """
            ).indented(),
            policyFor("guarded"),
        ).expectErrorCount(1)
    }
}
