package com.shezguard.lint

import com.android.tools.lint.detector.api.CURRENT_API
import com.android.tools.lint.detector.api.Severity
import org.junit.Assert.assertEquals
import org.junit.Test

/** Pins the shipped issue IDs and the severities agreed for step 13 (author condition 2). */
class ShezGuardIssueRegistryTest {

    @Test
    fun registersEveryIssueWithTheAgreedSeverity() {
        val registry = ShezGuardIssueRegistry()
        assertEquals(
            mapOf(
                "ShezGuardUnguardedEntryPoint" to Severity.ERROR,
                "ShezGuardUnknownEntryPointName" to Severity.ERROR,
                "ShezGuardEntryPointNameUnverifiable" to Severity.WARNING,
                "ShezGuardInvalidAnnotation" to Severity.ERROR,
                "ShezGuardGuardCallOrder" to Severity.ERROR,
                "ShezGuardUncheckedGuardResult" to Severity.WARNING,
                "ShezGuardUnverifiableDeepLink" to Severity.WARNING,
                "ShezGuardDependencyEntryPoint" to Severity.WARNING,
                "ShezGuardUncoveredComponent" to Severity.INFORMATIONAL,
            ),
            registry.issues.associate { it.id to it.defaultSeverity },
        )
        assertEquals(CURRENT_API, registry.api)
        assertEquals(CURRENT_API, registry.minApi)
        assertEquals("ShezGuard", registry.vendor.vendorName)
    }
}
