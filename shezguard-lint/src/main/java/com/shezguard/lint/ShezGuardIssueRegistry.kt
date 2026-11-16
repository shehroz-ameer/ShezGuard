package com.shezguard.lint

import com.android.tools.lint.client.api.IssueRegistry
import com.android.tools.lint.client.api.Vendor
import com.android.tools.lint.detector.api.CURRENT_API
import com.android.tools.lint.detector.api.Issue

/**
 * Registers ShezGuard's build-time coverage check (docs/SPEC.md section 9, step 13).
 *
 * Compiled against Lint 31.10.1 (AGP 8.10.1). [minApi] equals [api]: a host Lint older than this
 * skips the whole registry and only reports `ObsoleteLintCustomCheck` (docs/LIMITATIONS.md).
 */
public class ShezGuardIssueRegistry : IssueRegistry() {
    override val issues: List<Issue> = listOf(
        Issues.UNGUARDED_ENTRY_POINT,
        Issues.UNKNOWN_ENTRY_POINT_NAME,
        Issues.ENTRY_POINT_NAME_UNVERIFIABLE,
        Issues.INVALID_ANNOTATION,
        Issues.GUARD_CALL_ORDER,
        Issues.UNCHECKED_GUARD_RESULT,
        Issues.UNVERIFIABLE_DEEP_LINK,
        Issues.DEPENDENCY_ENTRY_POINT,
        Issues.UNCOVERED_COMPONENT,
    )
    override val api: Int = CURRENT_API
    override val minApi: Int = CURRENT_API
    override val vendor: Vendor = Vendor(
        vendorName = "ShezGuard",
        identifier = "com.shezguard:shezguard-lint",
    )
}
