package com.shezguard.lint

import com.android.tools.lint.checks.CheckResultDetector
import com.android.tools.lint.checks.infrastructure.LintDetectorTest.java
import com.android.tools.lint.checks.infrastructure.LintDetectorTest.kotlin
import com.android.tools.lint.checks.infrastructure.TestFile
import com.android.tools.lint.checks.infrastructure.TestLintResult
import com.android.tools.lint.checks.infrastructure.TestLintTask.lint
import org.junit.Test

/**
 * Issues 3 (guard call in an exempt activity), 4 (call order) and 5 (unchecked result), and the
 * built-in CheckResult check this rule relies on for a completely ignored result. Attack category:
 * the unchecked intent reaching app code, a base class or a library before (or despite) the guard.
 * All are intra-method checks of DIRECT calls to `ActivityGuard`; a wrapper (like the demo's
 * EntryGuard shim) hides the call from them (docs/LIMITATIONS.md).
 */
class GuardCallDetectorTest {

    private fun run(source: String): TestLintResult = lint()
        .files(*Stubs.all, guarded(source))
        .issues(
            ShezGuardDetector.GUARD_CALL_ORDER,
            ShezGuardDetector.UNCHECKED_GUARD_RESULT,
            ShezGuardDetector.INVALID_ANNOTATION,
        )
        .run()

    private fun guarded(body: String, annotation: String = "@GuardedEntryPoint(\"p\")"): TestFile = kotlin(
        """
        package test.app

        import android.app.Activity
        import android.content.Intent
        import android.os.Bundle
        import com.shezguard.core.ActivityGuard
        import com.shezguard.core.GuardedEntryPoint

        $annotation
        class GuardedActivity : Activity() {
            private val guard = ActivityGuard(null)
        $body
        }
        """
    ).indented()

    // ---- Issue 4: ShezGuardGuardCallOrder ------------------------------------------------------

    @Test
    fun flagsGuardAfterSuperOnCreate() {
        run(
            """
            override fun onCreate(savedInstanceState: Bundle?) {
                super.onCreate(savedInstanceState)
                val checked = guard.onCreate(this) ?: return
            }
            """
        ).expectErrorCount(1)
            .expectContains("ActivityGuard.onCreate runs after super.onCreate")
            .expectContains("[ShezGuardGuardCallOrder]")
    }

    @Test
    fun flagsGuardAfterGetIntentRead() {
        run(
            """
            override fun onCreate(savedInstanceState: Bundle?) {
                val raw = intent.data
                val checked = guard.onCreate(this)
                super.onCreate(checked?.let { savedInstanceState })
                if (checked == null) return
            }
            """
        ).expectErrorCount(1)
            .expectContains("ActivityGuard.onCreate runs after a read of getIntent()")
    }

    @Test
    fun flagsGuardAfterBareIntentPropertyRead() {
        run(
            """
            override fun onCreate(savedInstanceState: Bundle?) {
                remember(intent)
                val checked = guard.onCreate(this) ?: return
                super.onCreate(savedInstanceState)
            }
            private fun remember(i: Intent?) {}
            """
        ).expectErrorCount(1)
            .expectContains("ActivityGuard.onCreate runs after a read of getIntent()")
    }

    @Test
    fun flagsGuardAfterGetIntentCallInJava() {
        lint().files(
            *Stubs.all,
            java(
                """
                package test.app;

                import android.app.Activity;
                import android.os.Bundle;
                import com.shezguard.core.ActivityGuard;
                import com.shezguard.core.CheckedIntent;
                import com.shezguard.core.GuardedEntryPoint;

                @GuardedEntryPoint("p")
                public class JavaGuardedActivity extends Activity {
                    private final ActivityGuard guard = new ActivityGuard(null);

                    @Override
                    protected void onCreate(Bundle savedInstanceState) {
                        Object raw = getIntent().getData();
                        CheckedIntent checked = guard.onCreate(this);
                        if (checked == null) return;
                        super.onCreate(savedInstanceState);
                    }
                }
                """
            ).indented(),
        ).issues(ShezGuardDetector.GUARD_CALL_ORDER, ShezGuardDetector.UNCHECKED_GUARD_RESULT).run()
            .expectErrorCount(1)
            .expectContains("ActivityGuard.onCreate runs after a read of getIntent()")
    }

    @Test
    fun flagsGuardAfterSuperOnNewIntent() {
        run(
            """
            override fun onNewIntent(intent: Intent) {
                super.onNewIntent(intent)
                val checked = guard.onNewIntent(this, intent) ?: return
            }
            """
        ).expectErrorCount(1)
            .expectContains("ActivityGuard.onNewIntent runs after super.onNewIntent")
    }

    @Test
    fun acceptsGuardFirstInOnCreateAndOnNewIntent() {
        run(
            """
            override fun onCreate(savedInstanceState: Bundle?) {
                val checked = guard.onCreate(this)
                super.onCreate(checked?.let { savedInstanceState })
                if (checked == null) return
                checked.intent.data
                intent.data
            }

            override fun onNewIntent(intent: Intent) {
                val checked = guard.onNewIntent(this, intent) ?: return
                super.onNewIntent(checked.intent)
            }
            """
        ).expectClean()
    }

    // ---- Issue 5: ShezGuardUncheckedGuardResult ------------------------------------------------

    @Test
    fun flagsStoredGuardResultNeverNullChecked() {
        run(
            """
            override fun onCreate(savedInstanceState: Bundle?) {
                val checked = guard.onCreate(this)
                super.onCreate(savedInstanceState)
                show(checked)
            }
            private fun show(c: Any?) {}
            """
        ).expectErrorCount(0)
            .expectWarningCount(1)
            .expectContains("The result of ActivityGuard.onCreate is stored in checked but never checked for null")
            .expectContains("[ShezGuardUncheckedGuardResult]")
    }

    @Test
    fun flagsNotNullAssertedGuardResult() {
        run(
            """
            override fun onNewIntent(intent: Intent) {
                val checked = guard.onNewIntent(this, intent)!!
                super.onNewIntent(checked.intent)
            }
            """
        ).expectWarningCount(1).expectContains("[ShezGuardUncheckedGuardResult]")
    }

    @Test
    fun acceptsElvisReturnSafeCallAndIfNullReturn() {
        run(
            """
            // One pattern per helper method, so the call-order rule (onCreate only) is not involved.
            fun elvis() { val a = guard.onCreate(this) ?: return }
            fun safeCall() { guard.onCreate(this)?.let { it.intent } }
            fun ifNullReturn() {
                val b = guard.onCreate(this)
                if (b == null) return
            }
            fun storedThenSafeCall() {
                val c = guard.onCreate(this)
                c?.intent
            }
            """
        ).expectClean()
    }

    // ---- Issue 3 (call part): guard called inside an exempt activity ---------------------------

    @Test
    fun flagsGuardCallInsideExemptActivity() {
        lint().files(
            *Stubs.all,
            guarded(
                """
                override fun onCreate(savedInstanceState: Bundle?) {
                    val checked = guard.onCreate(this) ?: return
                    super.onCreate(savedInstanceState)
                }
                """,
                annotation = "@GuardedEntryPoint(exempt = true)",
            ),
        ).issues(ShezGuardDetector.INVALID_ANNOTATION).run()
            .expectErrorCount(1)
            .expectContains("is called in an activity marked @GuardedEntryPoint(exempt = true)")
    }

    // ---- Built-in CheckResult covers a completely ignored result (not duplicated) --------------

    @Test
    fun builtInCheckResultFlagsIgnoredGuardResultInKotlin() {
        lint().files(
            *Stubs.all,
            guarded(
                """
                override fun onCreate(savedInstanceState: Bundle?) {
                    guard.onCreate(this)
                    super.onCreate(savedInstanceState)
                }
                """
            ),
        ).issues(CheckResultDetector.CHECK_RESULT, ShezGuardDetector.UNCHECKED_GUARD_RESULT).run()
            .expectWarningCount(1)
            .expectContains("[CheckResult]")
    }
}
