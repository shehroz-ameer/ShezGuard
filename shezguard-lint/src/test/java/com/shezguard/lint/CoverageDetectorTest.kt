package com.shezguard.lint

import com.android.tools.lint.checks.infrastructure.LintDetectorTest.java
import com.android.tools.lint.checks.infrastructure.LintDetectorTest.kotlin
import com.android.tools.lint.checks.infrastructure.ProjectDescription
import com.android.tools.lint.checks.infrastructure.TestFile
import com.android.tools.lint.checks.infrastructure.TestFiles.manifest
import com.android.tools.lint.checks.infrastructure.TestLintResult
import com.android.tools.lint.checks.infrastructure.TestLintTask
import com.android.tools.lint.checks.infrastructure.TestLintTask.lint
import com.shezguard.lint.Stubs.activity
import com.shezguard.lint.Stubs.appManifest
import com.shezguard.lint.Stubs.policyFor
import org.junit.Test

/**
 * Issues 1, 2, 2b and 3 (annotation part), plus the dependency and non-activity reports
 * (docs/SPEC.md section 9, step 13). Attack category: an entry point reachable from other apps or
 * from a browser that no ShezGuard policy covers.
 */
class CoverageDetectorTest {

    private val coverageIssues = arrayOf(
        ShezGuardDetector.UNGUARDED_ENTRY_POINT,
        ShezGuardDetector.UNKNOWN_ENTRY_POINT_NAME,
        ShezGuardDetector.ENTRY_POINT_NAME_UNVERIFIABLE,
        ShezGuardDetector.INVALID_ANNOTATION,
        ShezGuardDetector.DEPENDENCY_ENTRY_POINT,
        ShezGuardDetector.UNCOVERED_COMPONENT,
    )

    private fun task(): TestLintTask = lint().issues(*coverageIssues)

    private fun run(vararg files: TestFile): TestLintResult = task().files(*Stubs.all, *files).run()

    private val browsableFilter = """
                <intent-filter>
                    <action android:name="android.intent.action.VIEW"/>
                    <category android:name="android.intent.category.DEFAULT"/>
                    <category android:name="android.intent.category.BROWSABLE"/>
                    <data android:scheme="https" android:host="example.com"/>
                </intent-filter>"""

    private val plainFilter = """
                <intent-filter>
                    <action android:name="test.app.ACTION_OPEN"/>
                    <category android:name="android.intent.category.DEFAULT"/>
                </intent-filter>"""

    // ---- Issue 1: ShezGuardUnguardedEntryPoint -------------------------------------------------

    @Test
    fun flagsExplicitlyExportedActivityWithoutAnnotation() {
        run(
            appManifest("""<activity android:name=".OpenActivity" android:exported="true"/>"""),
            activity("OpenActivity"),
        ).expectErrorCount(1)
            .expectContains("OpenActivity is exported (android:exported=\"true\") but has no @GuardedEntryPoint")
            .expectContains("[ShezGuardUnguardedEntryPoint]")
    }

    @Test
    fun flagsImplicitlyExportedActivityBelowApi31() {
        run(
            appManifest("""<activity android:name=".OpenActivity">$plainFilter</activity>""", targetSdk = 30),
            activity("OpenActivity"),
        ).expectErrorCount(1)
            .expectContains("exported implicitly (it has an intent filter and targetSdkVersion 30 < 31)")
    }

    @Test
    fun noImplicitExportFromApi31() {
        run(
            appManifest("""<activity android:name=".OpenActivity">$plainFilter</activity>""", targetSdk = 31),
            activity("OpenActivity"),
        ).expectClean()
    }

    @Test
    fun flagsBrowsableActivityEvenWhenNotExported() {
        run(
            appManifest("""<activity android:name=".LinkActivity" android:exported="false">$browsableFilter</activity>"""),
            activity("LinkActivity"),
        ).expectErrorCount(1)
            .expectContains("LinkActivity has a BROWSABLE intent filter but has no @GuardedEntryPoint")
    }

    @Test
    fun flagsExportedBrowsableActivityOnce() {
        run(
            appManifest("""<activity android:name=".LinkActivity" android:exported="true">$browsableFilter</activity>"""),
            activity("LinkActivity"),
        ).expectErrorCount(1)
            .expectContains("is exported (android:exported=\"true\") and has a BROWSABLE intent filter")
    }

    @Test
    fun acceptsExemptLauncherActivity() {
        run(
            appManifest(
                """
                <activity android:name=".MainActivity" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN"/>
                        <category android:name="android.intent.category.LAUNCHER"/>
                    </intent-filter>
                </activity>"""
            ),
            activity("MainActivity", "@GuardedEntryPoint(exempt = true)"),
        ).expectClean()
    }

    @Test
    fun ignoresNonExportedActivityWithoutBrowsableFilter() {
        run(
            appManifest("""<activity android:name=".InternalActivity" android:exported="false">$plainFilter</activity>"""),
            activity("InternalActivity"),
        ).expectClean()
    }

    @Test
    fun ignoresActivityWithoutFiltersOrExportedAttribute() {
        run(
            appManifest("""<activity android:name=".InternalActivity"/>""", targetSdk = 30),
            activity("InternalActivity"),
        ).expectClean()
    }

    @Test
    fun acceptsAnnotatedActivityWhosePolicyDeclaresTheName() {
        run(
            appManifest("""<activity android:name=".SearchActivity" android:exported="true">$browsableFilter</activity>"""),
            activity("SearchActivity", "@GuardedEntryPoint(\"search\")"),
            policyFor("search"),
        ).expectClean()
    }

    @Test
    fun acceptsAnnotatedJavaActivity() {
        run(
            appManifest("""<activity android:name=".JavaActivity" android:exported="true"/>"""),
            java(
                """
                package test.app;
                import com.shezguard.core.GuardedEntryPoint;
                @GuardedEntryPoint(name = "java")
                public class JavaActivity extends android.app.Activity {}
                """
            ).indented(),
            policyFor("java"),
        ).expectClean()
    }

    @Test
    fun flagsUnannotatedJavaActivity() {
        run(
            appManifest("""<activity android:name=".JavaActivity" android:exported="true"/>"""),
            java(
                """
                package test.app;
                public class JavaActivity extends android.app.Activity {}
                """
            ).indented(),
        ).expectErrorCount(1).expectContains("JavaActivity is exported")
    }

    @Test
    fun matchesNestedActivityClassNames() {
        run(
            appManifest("""<activity android:name=".Outer${'$'}Inner" android:exported="true"/>"""),
            kotlin(
                """
                package test.app
                import com.shezguard.core.GuardedEntryPoint
                class Outer {
                    @GuardedEntryPoint("inner")
                    class Inner : android.app.Activity()
                }
                """
            ).indented(),
            policyFor("inner"),
        ).expectClean()
    }

    @Test
    fun flagsExportedAliasOfUnannotatedActivity() {
        run(
            appManifest(
                """
                <activity android:name=".TargetActivity" android:exported="false"/>
                <activity-alias android:name=".AliasActivity" android:targetActivity=".TargetActivity" android:exported="true"/>"""
            ),
            activity("TargetActivity"),
        ).expectErrorCount(1)
            .expectContains("AliasActivity (alias of TargetActivity) is exported")
    }

    @Test
    fun acceptsExportedAliasOfAnnotatedActivity() {
        run(
            appManifest(
                """
                <activity android:name=".TargetActivity" android:exported="false"/>
                <activity-alias android:name=".AliasActivity" android:targetActivity=".TargetActivity" android:exported="true"/>"""
            ),
            activity("TargetActivity", "@GuardedEntryPoint(\"target\")"),
            policyFor("target"),
        ).expectClean()
    }

    // ---- Dependencies and non-activity components ----------------------------------------------

    @Test
    fun activityFromDependencyIsReportedOnlyAsDependencyEntryPoint() {
        // The library has a manifest but no sources: like an AAR, its class is not part of the analysed code.
        val lib = ProjectDescription(
            manifest(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.lib">
                    <application>
                        <activity android:name="test.lib.LibActivity" android:exported="true"/>
                    </application>
                </manifest>
                """
            ).indented()
        ).type(ProjectDescription.Type.LIBRARY).name("lib")
        val app = ProjectDescription(
            *Stubs.all,
            appManifest("""<activity android:name=".MainActivity" android:exported="true"/>"""),
            activity("MainActivity", "@GuardedEntryPoint(exempt = true)"),
        ).name("app").dependsOn(lib)
        task().projects(app, lib).run()
            .expectErrorCount(0)
            .expectWarningCount(1)
            .expectContains("test.lib.LibActivity comes from a dependency's manifest and is exported")
            .expectContains("[ShezGuardDependencyEntryPoint]")
    }

    @Test
    fun exportedServiceWithoutPermissionIsInformationalOnly() {
        run(
            appManifest(
                """
                <service android:name=".SyncService" android:exported="true"/>
                <receiver android:name=".GuardedReceiver" android:exported="true" android:permission="test.app.PRIVATE"/>
                <provider android:name=".DataProvider" android:authorities="test.app.data" android:exported="false"/>"""
            ),
        ).expectErrorCount(0)
            .expectWarningCount(0)
            .expectContains("Exported service test.app.SyncService is not covered by ShezGuard v1")
            .expectContains("[ShezGuardUncoveredComponent]")
            .expectContains("0 errors, 0 warnings, 1 hint") // Informational is printed as "Hint"
    }

    // ---- Issue 2 / 2b: names against the policy ------------------------------------------------

    @Test
    fun flagsAnnotatedNameMissingFromPolicy() {
        run(
            appManifest("""<activity android:name=".SearchActivity" android:exported="true"/>"""),
            activity("SearchActivity", "@GuardedEntryPoint(\"serach\")"),
            policyFor("search"),
        ).expectErrorCount(1)
            .expectContains("@GuardedEntryPoint(\"serach\") names an entry point that no entryPoint(\"serach\")")
            .expectContains("[ShezGuardUnknownEntryPointName]")
    }

    @Test
    fun matchesConstValNamesOnBothSides() {
        run(
            appManifest("""<activity android:name=".SearchActivity" android:exported="true"/>"""),
            kotlin(
                """
                package test.app
                object Names { const val SEARCH = "search" }
                """
            ).indented(),
            activity("SearchActivity", "@GuardedEntryPoint(Names.SEARCH)"),
            kotlin(
                """
                package test.app
                import com.shezguard.core.policy.intentPolicy
                val policy = intentPolicy { entryPoint(Names.SEARCH) {} }
                """
            ).indented(),
        ).expectClean()
    }

    @Test
    fun nonConstantEntryPointNameMakesMissingNameUnverifiable() {
        run(
            appManifest("""<activity android:name=".SearchActivity" android:exported="true"/>"""),
            activity("SearchActivity", "@GuardedEntryPoint(\"search\")"),
            kotlin(
                """
                package test.app
                import com.shezguard.core.policy.intentPolicy
                fun build(names: List<String>) = intentPolicy { names.forEach { entryPoint(it) {} } }
                """
            ).indented(),
        ).expectErrorCount(0)
            .expectWarningCount(1)
            .expectContains("Cannot prove that entry point \"search\" is declared: an entryPoint(...) call has a non-constant name")
            .expectContains("[ShezGuardEntryPointNameUnverifiable]")
    }

    @Test
    fun noPolicyFoundWithoutCheckDependenciesIsUnverifiable() {
        task().files(
            *Stubs.all,
            appManifest("""<activity android:name=".SearchActivity" android:exported="true"/>"""),
            activity("SearchActivity", "@GuardedEntryPoint(\"search\")"),
        ).configureOptions { it.isCheckDependencies = false }
            .run()
            .expectErrorCount(0)
            .expectWarningCount(1)
            .expectContains("no entryPoint(...) call was found in the analysed modules")
    }

    @Test
    fun noPolicyFoundWithCheckDependenciesIsAnError() {
        task().files(
            *Stubs.all,
            appManifest("""<activity android:name=".SearchActivity" android:exported="true"/>"""),
            activity("SearchActivity", "@GuardedEntryPoint(\"search\")"),
        ).configureOptions { it.isCheckDependencies = true }
            .run()
            .expectErrorCount(1)
            .expectContains("[ShezGuardUnknownEntryPointName]")
    }

    @Test
    fun nameDeclaredInLibraryModuleIsFoundWithCheckDependencies() {
        val lib = ProjectDescription(
            *Stubs.all,
            policyFor("search"),
            manifest("""<manifest package="test.lib"/>""").indented(),
        ).type(ProjectDescription.Type.LIBRARY).name("lib")
        val app = ProjectDescription(
            appManifest("""<activity android:name=".SearchActivity" android:exported="true"/>"""),
            activity("SearchActivity", "@GuardedEntryPoint(\"search\")"),
        ).name("app").dependsOn(lib)
        task().projects(app, lib).configureOptions { it.isCheckDependencies = true }.run().expectClean()
    }

    // ---- Issue 3: invalid annotations (the guard always blocks these) --------------------------

    @Test
    fun flagsExemptAnnotationThatAlsoNamesAnEntryPoint() {
        run(
            appManifest("""<activity android:name=".MixedActivity" android:exported="true"/>"""),
            activity("MixedActivity", "@GuardedEntryPoint(name = \"mixed\", exempt = true)"),
            policyFor("mixed"),
        ).expectErrorCount(1)
            .expectContains("sets both a name and exempt = true")
            .expectContains("[ShezGuardInvalidAnnotation]")
    }

    @Test
    fun flagsEmptyNameWithoutExemption() {
        run(
            appManifest("""<activity android:name=".EmptyActivity" android:exported="true"/>"""),
            activity("EmptyActivity", "@GuardedEntryPoint"),
            policyFor("other"),
        ).expectErrorCount(1)
            .expectContains("has an empty name and is not exempt")
            .expectContains("[ShezGuardInvalidAnnotation]")
    }

    @Test
    fun flagsEntryPointNameTheDslRejects() {
        run(
            appManifest("""<activity android:name=".BadActivity" android:exported="true"/>"""),
            activity("BadActivity", "@GuardedEntryPoint(\"bad name\")"),
            policyFor("other"),
        ).expectErrorCount(1)
            .expectContains("Entry point name \"bad name\" is invalid")
    }
}
