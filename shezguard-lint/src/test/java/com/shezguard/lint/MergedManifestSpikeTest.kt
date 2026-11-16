package com.shezguard.lint

import com.android.tools.lint.checks.infrastructure.TestFiles.manifest
import com.android.tools.lint.checks.infrastructure.TestLintTask.lint
import com.android.tools.lint.checks.infrastructure.TestMode
import com.android.tools.lint.checks.infrastructure.ProjectDescription
import com.android.tools.lint.detector.api.Category
import com.android.tools.lint.detector.api.Context
import com.android.tools.lint.detector.api.Detector
import com.android.tools.lint.detector.api.Implementation
import com.android.tools.lint.detector.api.Issue
import com.android.tools.lint.detector.api.PartialResult
import com.android.tools.lint.detector.api.Scope
import com.android.tools.lint.detector.api.Severity
import com.android.tools.lint.detector.api.XmlScanner
import org.junit.Test

/**
 * Step 13 spike (author condition 4): is the app's MERGED manifest available to a detector in both
 * global analysis (TestMode.DEFAULT) and partial analysis (TestMode.PARTIAL, AGP's default)?
 * The spike detector reports, from the merged manifest, every activity and which project declared it.
 */
class MergedManifestSpikeTest {

    class SpikeDetector : Detector(), XmlScanner {
        override fun afterCheckRootProject(context: Context) {
            if (context.isGlobalAnalysis()) report(context, "global")
            else context.getPartialResults(ISSUE).map().put("seen", true)
        }

        override fun checkPartialResults(context: Context, partialResults: PartialResult) {
            report(context, "partial")
        }

        private fun report(context: Context, mode: String) {
            val project = context.mainProject
            if (project.isLibrary) return
            val merged = project.mergedManifest
            if (merged == null) {
                context.report(ISSUE, com.android.tools.lint.detector.api.Location.create(project.dir), "mergedManifest=null")
                return
            }
            val acts = merged.getElementsByTagName("activity")
            for (i in 0 until acts.length) {
                val el = acts.item(i) as org.w3c.dom.Element
                val name = el.getAttributeNS("http://schemas.android.com/apk/res/android", "name")
                val src = context.client.findManifestSourceNode(el)?.first
                context.report(
                    ISSUE,
                    context.client.findManifestSourceLocation(el) ?: com.android.tools.lint.detector.api.Location.create(project.dir),
                    "merged: $name",
                )
            }
        }

        companion object {
            val ISSUE = Issue.create(
                "MergedManifestSpike", "spike", "spike", Category.CORRECTNESS, 1, Severity.WARNING,
                Implementation(SpikeDetector::class.java, Scope.MANIFEST_SCOPE),
            )
        }
    }

    private val appManifest = manifest(
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.app">
          <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
          <application>
            <activity android:name=".AppActivity" android:exported="true"/>
          </application>
        </manifest>
        """
    ).indented()

    private val libManifest = manifest(
        """
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.lib">
          <application>
            <activity android:name="test.lib.LibActivity" android:exported="true"/>
          </application>
        </manifest>
        """
    ).indented()

    @Test
    fun mergedManifestIsAvailableInGlobalAndPartialAnalysis() {
        val lib = ProjectDescription(libManifest).type(ProjectDescription.Type.LIBRARY).name("lib")
        val app = ProjectDescription(appManifest).name("app").dependsOn(lib)
        val result = lint()
            .projects(app, lib)
            .issues(SpikeDetector.ISSUE)
            .testModes(TestMode.DEFAULT, TestMode.PARTIAL)
            .allowMissingSdk()
            .run()
        // Same output in both modes (lint-tests also asserts that); each activity is located in the
        // manifest of the project that declared it, which is how dependency components are told apart.
        result.expect(
            """
            ../lib/AndroidManifest.xml:3: Warning: merged: test.lib.LibActivity [MergedManifestSpike]
                <activity android:name="test.lib.LibActivity" android:exported="true"/>
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            AndroidManifest.xml:4: Warning: merged: test.app.AppActivity [MergedManifestSpike]
                <activity android:name=".AppActivity" android:exported="true"/>
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            0 errors, 2 warnings
            """
        )
    }
}
