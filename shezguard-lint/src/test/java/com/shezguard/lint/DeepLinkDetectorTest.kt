package com.shezguard.lint

import com.android.tools.lint.checks.AppLinksValidDetector
import com.android.tools.lint.checks.infrastructure.TestLintResult
import com.android.tools.lint.checks.infrastructure.TestLintTask.lint
import com.shezguard.lint.Stubs.appManifest
import org.junit.Test

/**
 * Issue 6, the build-time half of threat 4 (deep link hijacking). Advice only: Lint cannot know
 * whether the domain verifies or whether the link carries a secret. The https case with a MISSING
 * autoVerify is left to the built-in AppLinkWarning (not part of ShezGuard); the last test shows it.
 */
class DeepLinkDetectorTest {

    private fun filter(data: String, autoVerify: String = "", browsable: Boolean = true): String = """
        <activity android:name=".LinkActivity" android:exported="true">
            <intent-filter$autoVerify>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                ${if (browsable) "<category android:name=\"android.intent.category.BROWSABLE\"/>" else ""}
                $data
            </intent-filter>
        </activity>"""

    private fun run(body: String): TestLintResult =
        lint().files(appManifest(body)).issues(DeepLinkDetector.UNVERIFIABLE_DEEP_LINK).run()

    @Test
    fun flagsHijackableCustomSchemeLink() {
        run(filter("""<data android:scheme="shezdemo" android:host="login"/>"""))
            .expectWarningCount(1)
            .expectContains("Custom scheme shezdemo in a BROWSABLE intent filter")
            .expectContains("[ShezGuardUnverifiableDeepLink]")
    }

    @Test
    fun flagsHttpsLinkWithAutoVerifyFalse() {
        run(filter("""<data android:scheme="https" android:host="example.com"/>""", """ android:autoVerify="false""""))
            .expectWarningCount(1)
            .expectContains("android:autoVerify=\"false\"")
    }

    @Test
    fun acceptsVerifiedHttpsLink() {
        run(filter("""<data android:scheme="https" android:host="example.com"/>""", """ android:autoVerify="true""""))
            .expectClean()
    }

    @Test
    fun leavesHttpsLinkWithoutAutoVerifyToBuiltInAppLinkWarning() {
        run(filter("""<data android:scheme="https" android:host="example.com"/>""")).expectClean()
        lint().files(appManifest(filter("""<data android:scheme="https" android:host="example.com"/>""")))
            .issues(AppLinksValidDetector.APP_LINK_WARNING, DeepLinkDetector.UNVERIFIABLE_DEEP_LINK)
            .run()
            .expectWarningCount(1)
            .expectContains("[AppLinkWarning]")
    }

    @Test
    fun ignoresCustomSchemeWithoutBrowsable() {
        run(filter("""<data android:scheme="shezdemo" android:host="login"/>""", browsable = false)).expectClean()
    }

    @Test
    fun flagsEachCustomSchemeOnceInMixedFilter() {
        run(
            filter(
                """<data android:scheme="https" android:host="example.com"/>
                <data android:scheme="myapp"/>""",
                """ android:autoVerify="true"""",
            )
        ).expectWarningCount(1).expectContains("Custom scheme myapp")
    }
}
