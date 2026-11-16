package com.shezguard.lint

import com.android.tools.lint.detector.api.Category
import com.android.tools.lint.detector.api.Implementation
import com.android.tools.lint.detector.api.Issue
import com.android.tools.lint.detector.api.Scope
import com.android.tools.lint.detector.api.Severity
import java.util.EnumSet

/**
 * The issues of ShezGuard's build-time coverage check (docs/SPEC.md section 9, step 13).
 * Confidence per issue is stated in README.md ("Build-time coverage check").
 */
internal object Issues {
    private const val DOCS = "docs/SPEC.md section 9; docs/LIMITATIONS.md L4"

    /**
     * Source plus merged manifest; runs when either a source file or the manifest is analysed. Lint
     * requires every issue of one detector to share one scope, so the source-only call checks use it too.
     */
    private val COVERAGE = Implementation(
        ShezGuardDetector::class.java,
        EnumSet.of(Scope.JAVA_FILE, Scope.MANIFEST),
        Scope.JAVA_FILE_SCOPE,
        Scope.MANIFEST_SCOPE,
    )

    val UNGUARDED_ENTRY_POINT: Issue = Issue.create(
        id = "ShezGuardUnguardedEntryPoint",
        briefDescription = "Exported or BROWSABLE activity without a ShezGuard entry point",
        explanation = """
            Every activity that other apps or a browser can start must name its ShezGuard entry point \
            with `@GuardedEntryPoint("name")`, or be marked `@GuardedEntryPoint(exempt = true)` if it \
            reads no intent data (for example a launcher). An activity is reachable when it is exported \
            (`android:exported="true"`, or, below targetSdkVersion 31, implicitly when it has an intent \
            filter and no `android:exported`), or when it has a `BROWSABLE` intent filter.

            This check reads the app's merged manifest. It proves that a name is declared, not that the \
            activity calls the guard ($DOCS).
            """,
        category = Category.SECURITY,
        priority = 8,
        severity = Severity.ERROR,
        implementation = COVERAGE,
    )

    val UNKNOWN_ENTRY_POINT_NAME: Issue = Issue.create(
        id = "ShezGuardUnknownEntryPointName",
        briefDescription = "@GuardedEntryPoint names an entry point the policy does not declare",
        explanation = """
            The name in `@GuardedEntryPoint` must match an `entryPoint("name")` call in an \
            `intentPolicy {}` block; otherwise the guard blocks every launch (`ENTRY_POINT_UNKNOWN`). \
            Reported as an error only when the analysed code proves the name is missing: every \
            `entryPoint(...)` argument is a constant, and either at least one `entryPoint(...)` call \
            was found or `checkDependencies` is on. Otherwise see `ShezGuardEntryPointNameUnverifiable`.
            """,
        category = Category.SECURITY,
        priority = 8,
        severity = Severity.ERROR,
        implementation = COVERAGE,
    )

    val ENTRY_POINT_NAME_UNVERIFIABLE: Issue = Issue.create(
        id = "ShezGuardEntryPointNameUnverifiable",
        briefDescription = "Cannot prove that a @GuardedEntryPoint name is declared",
        explanation = """
            The name was not found, but the policy may still declare it: an `entryPoint(...)` call has \
            a non-constant name, or no `entryPoint(...)` call was found and the policy may live in a \
            module this Lint run did not analyse. Enable `lint { checkDependencies = true }` in the \
            app module, or use constant names, to turn this into a proof.
            """,
        category = Category.SECURITY,
        priority = 5,
        severity = Severity.WARNING,
        implementation = COVERAGE,
    )

    val INVALID_ANNOTATION: Issue = Issue.create(
        id = "ShezGuardInvalidAnnotation",
        briefDescription = "@GuardedEntryPoint that the guard always blocks",
        explanation = """
            `ActivityGuard` blocks an activity whose annotation is empty, exempt, or names an invalid \
            entry point. This reports: a name together with `exempt = true`; an empty name without \
            `exempt = true`; a name that is not 1 to 64 characters from `A-Z a-z 0-9 _ . -`; and a \
            direct `ActivityGuard` call inside an activity marked `exempt = true`.
            """,
        category = Category.SECURITY,
        priority = 7,
        severity = Severity.ERROR,
        implementation = COVERAGE,
    )

    val GUARD_CALL_ORDER: Issue = Issue.create(
        id = "ShezGuardGuardCallOrder",
        briefDescription = "ActivityGuard called after the intent was already used",
        explanation = """
            `ActivityGuard.onCreate` must run before `super.onCreate` and before any read of \
            `getIntent()`; `ActivityGuard.onNewIntent` must run before `super.onNewIntent`. Otherwise \
            base classes, fragments or deep link libraries see the unchecked intent \
            (docs/LIMITATIONS.md L34, L35). Intra-method and source-order based: only direct \
            `ActivityGuard` calls in the same method are checked.
            """,
        category = Category.SECURITY,
        priority = 7,
        severity = Severity.ERROR,
        implementation = COVERAGE,
    )

    val UNCHECKED_GUARD_RESULT: Issue = Issue.create(
        id = "ShezGuardUncheckedGuardResult",
        briefDescription = "ActivityGuard result stored but never checked for null",
        explanation = """
            `null` from `ActivityGuard.onCreate` / `onNewIntent` means Block: the method must stop \
            before using the intent. This heuristic reports a result stored in a variable that the \
            same method never compares with `null` or uses with `?.` or `?:`; `!!` does not count. \
            A result that is ignored completely is reported by the built-in `CheckResult` check.
            """,
        category = Category.SECURITY,
        priority = 5,
        severity = Severity.WARNING,
        implementation = COVERAGE,
    )

    val DEPENDENCY_ENTRY_POINT: Issue = Issue.create(
        id = "ShezGuardDependencyEntryPoint",
        briefDescription = "Exported or BROWSABLE activity from a dependency",
        explanation = """
            An activity declared in a dependency's manifest is reachable from other apps, but the app \
            cannot annotate the dependency's class, so ShezGuard does not cover it. If the app does not \
            use it, override it in the app manifest with `android:exported="false"` and \
            `tools:replace="android:exported"`; otherwise review the library.
            """,
        category = Category.SECURITY,
        priority = 4,
        severity = Severity.WARNING,
        implementation = COVERAGE,
    )

    val UNCOVERED_COMPONENT: Issue = Issue.create(
        id = "ShezGuardUncoveredComponent",
        briefDescription = "Exported service, receiver or provider not covered by ShezGuard v1",
        explanation = """
            ShezGuard v1 covers activities only. This lists the app's own exported services, receivers \
            and providers that no `android:permission` protects, so they can be reviewed by hand. It \
            never fails a build.
            """,
        category = Category.SECURITY,
        priority = 2,
        severity = Severity.INFORMATIONAL,
        implementation = COVERAGE,
    )

    val UNVERIFIABLE_DEEP_LINK: Issue = Issue.create(
        id = "ShezGuardUnverifiableDeepLink",
        briefDescription = "Deep link that another app can also claim",
        explanation = """
            Threat 4 (deep link hijacking) is decided by the OS before the app runs, so the runtime \
            guard cannot prevent it. A custom scheme in a `BROWSABLE` filter can be declared by any app, \
            and an `https` filter with `android:autoVerify="false"` is not verified. Do not put secrets \
            or one-time tokens in such links. An `https` filter WITHOUT `autoVerify` is reported by the \
            built-in `AppLinkWarning` check. Even `autoVerify="true"` does not prove the domain \
            verifies: that needs a valid Digital Asset Links file.
            """,
        category = Category.SECURITY,
        priority = 5,
        severity = Severity.WARNING,
        implementation = Implementation(DeepLinkDetector::class.java, Scope.MANIFEST_SCOPE),
    )
}
