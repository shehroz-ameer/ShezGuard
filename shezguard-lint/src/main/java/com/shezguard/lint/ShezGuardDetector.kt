package com.shezguard.lint

import com.android.SdkConstants.ANDROID_URI
import com.android.tools.lint.detector.api.ConstantEvaluator
import com.android.tools.lint.detector.api.Context
import com.android.tools.lint.detector.api.Detector
import com.android.tools.lint.detector.api.Issue
import com.android.tools.lint.detector.api.JavaContext
import com.android.tools.lint.detector.api.LintMap
import com.android.tools.lint.detector.api.Location
import com.android.tools.lint.detector.api.PartialResult
import com.android.tools.lint.detector.api.Project
import com.android.tools.lint.detector.api.SourceCodeScanner
import com.android.tools.lint.detector.api.XmlScanner
import com.intellij.psi.PsiMethod
import org.jetbrains.uast.UCallExpression
import org.jetbrains.uast.UClass
import org.jetbrains.uast.UElement
import org.jetbrains.uast.UMethod
import org.jetbrains.uast.getParentOfType
import org.w3c.dom.Element
import java.io.File

/**
 * ShezGuard's build-time coverage check (docs/SPEC.md section 9, step 13).
 *
 * Two phases, so it works under Lint's partial (per-module) analysis, AGP's default:
 * 1. **Analysis, per module (source):** every Activity subclass is recorded, with its
 *    `@GuardedEntryPoint` values, and every constant `entryPoint("...")` name of the policy DSL.
 *    Annotation errors (issue 3) and direct `ActivityGuard` call problems (issues 3, 4, 5) are
 *    reported here, because they need only the current file.
 * 2. **Reporting, app module ([checkPartialResults]):** the recorded data of every analysed module
 *    is compared with the app's MERGED manifest (issue 1, dependency and non-activity reports) and
 *    with the declared names (issue 2 / 2b).
 *
 * What it proves and what it does not: docs/LIMITATIONS.md L4 and L41.
 */
public class ShezGuardDetector : Detector(), SourceCodeScanner, XmlScanner {
    // XmlScanner only because Lint requires every detector in MANIFEST scope to be one. The manifest is
    // read in the reporting phase (merged manifest), so no element is visited here.


    // ---- Phase 1: analysis --------------------------------------------------------------------

    override fun applicableSuperClasses(): List<String> = listOf(ACTIVITY)

    override fun visitClass(context: JavaContext, declaration: UClass) {
        val fqn = declaration.qualifiedName ?: return
        val data = moduleData(context)
        data.child(KEY_CLASSES).put(fqn, true)

        val annotation = declaration.findAnnotation(GUARDED_ENTRY_POINT) ?: return
        val name = annotation.findAttributeValue("name")?.let { ConstantEvaluator.evaluate(null, it) } as? String ?: ""
        val exempt = annotation.findAttributeValue("exempt")?.let { ConstantEvaluator.evaluate(null, it) } as? Boolean ?: false
        val location = context.getLocation(annotation as UElement)
        val problem = annotationProblem(name, exempt)
        if (problem != null) context.report(INVALID_ANNOTATION, annotation, location, problem)

        data.child(KEY_ANNOTATIONS).put(
            fqn,
            LintMap().put(A_NAME, name).put(A_EXEMPT, exempt).put(A_VALID, problem == null).put(A_LOCATION, location),
        )
    }

    override fun getApplicableMethodNames(): List<String> = listOf("entryPoint", "onCreate", "onNewIntent")

    override fun visitMethodCall(context: JavaContext, node: UCallExpression, method: PsiMethod) {
        when (method.containingClass?.qualifiedName) {
            POLICY_BUILDER -> if (method.name == "entryPoint") recordEntryPoint(context, node, method)
            ACTIVITY_GUARD -> GuardCallChecks.check(context, node, method)
        }
    }

    private fun recordEntryPoint(context: JavaContext, node: UCallExpression, method: PsiMethod) {
        val argument = context.evaluator.computeArgumentMapping(node, method)
            .entries.firstOrNull { it.value.name == "name" }?.key
            ?: node.valueArguments.firstOrNull()
        val name = argument?.let { ConstantEvaluator.evaluate(null, it) } as? String
        val data = moduleData(context)
        if (name != null) {
            data.child(KEY_NAMES).put(name, true)
        } else {
            val nonConstant = data.child(KEY_NON_CONSTANT)
            nonConstant.put(nonConstant.size.toString(), context.getLocation(node))
        }
    }

    override fun afterCheckEachProject(context: Context) {
        // Marks the module as analysed even when it records nothing else.
        moduleData(context).put(KEY_ANALYSED, true)
    }

    override fun afterCheckRootProject(context: Context) {
        if (context.isGlobalAnalysis()) checkPartialResults(context, context.getPartialResults(UNGUARDED_ENTRY_POINT))
    }

    // ---- Phase 2: reporting -------------------------------------------------------------------

    override fun checkPartialResults(context: Context, partialResults: PartialResult) {
        val seen = Seen.from(partialResults)
        checkNames(context, seen)
        val project = context.mainProject
        if (project.isLibrary) return // the final manifest exists only for the app
        val manifest = project.mergedManifest?.documentElement ?: return
        ManifestCoverage(context, seen, manifest, partialResults.projects()).check()
    }

    /** Issue 2 / 2b. Error only when the analysed code proves the name is missing. */
    private fun checkNames(context: Context, seen: Seen) {
        val checkDependencies = context.driver.checkDependencies
        for ((_, annotation) in seen.annotations) {
            if (annotation.getBoolean(A_VALID) != true || annotation.getBoolean(A_EXEMPT) == true) continue
            val name = annotation.getString(A_NAME) ?: continue
            if (name in seen.names) continue
            val location = annotation.getLocation(A_LOCATION) ?: continue
            when {
                seen.nonConstant.isNotEmpty() -> context.report(
                    ENTRY_POINT_NAME_UNVERIFIABLE, location,
                    "Cannot prove that entry point \"$name\" is declared: an `entryPoint(...)` call has a " +
                        "non-constant name. Use constant names so the check can match them.",
                )
                seen.names.isEmpty() && !checkDependencies -> context.report(
                    ENTRY_POINT_NAME_UNVERIFIABLE, location,
                    "Cannot prove that entry point \"$name\" is declared: no `entryPoint(...)` call was found " +
                        "in the analysed modules. If the policy is in another module, enable " +
                        "`lint { checkDependencies = true }` in the app module.",
                )
                else -> context.report(
                    UNKNOWN_ENTRY_POINT_NAME, location,
                    "`@GuardedEntryPoint(\"$name\")` names an entry point that no `entryPoint(\"$name\")` in an " +
                        "`intentPolicy {}` declares; the guard blocks every launch (`ENTRY_POINT_UNKNOWN`).",
                )
            }
        }
    }

    /** Everything recorded by the analysed modules, flattened. */
    internal class Seen(
        val classes: Set<String>,
        val annotations: Map<String, LintMap>,
        val names: Set<String>,
        val nonConstant: List<Location>,
    ) {
        companion object {
            fun from(results: PartialResult): Seen {
                val classes = mutableSetOf<String>()
                val annotations = mutableMapOf<String, LintMap>()
                val names = mutableSetOf<String>()
                val nonConstant = mutableListOf<Location>()
                for (map in results.maps()) {
                    map.getMap(KEY_CLASSES)?.let { classes += it.keys() }
                    map.getMap(KEY_ANNOTATIONS)?.let { m -> m.keys().forEach { k -> m.getMap(k)?.let { annotations[k] = it } } }
                    map.getMap(KEY_NAMES)?.let { names += it.keys() }
                    map.getMap(KEY_NON_CONSTANT)?.let { m -> m.keys().forEach { k -> m.getLocation(k)?.let { nonConstant += it } } }
                }
                return Seen(classes, annotations, names, nonConstant)
            }
        }
    }

    /** Issue 1 and the dependency / non-activity reports, from the merged manifest. */
    private class ManifestCoverage(
        private val context: Context,
        private val seen: Seen,
        private val manifest: Element,
        private val projects: Collection<Project>,
    ) {
        private val pkg = manifest.getAttribute("package")
        private val targetSdk = context.mainProject.targetSdk
        private val ownDirs: List<File> = (projects + context.mainProject).map { it.dir.canonicalFile }

        fun check() {
            for (application in children(manifest, "application")) {
                for (component in children(application)) {
                    when (component.tagName) {
                        "activity" -> checkActivity(component, classOf(component.androidAttr("name")), alias = null)
                        "activity-alias" -> checkActivity(
                            component, classOf(component.androidAttr("targetActivity")), alias = classOf(component.androidAttr("name")),
                        )
                        "service", "receiver", "provider" -> checkOther(component)
                    }
                }
            }
        }

        private fun checkActivity(element: Element, target: String, alias: String?) {
            val reach = reachability(element) ?: return
            val subject = if (alias != null) "${simple(alias)} (alias of ${simple(target)})" else simple(target)
            if (target !in seen.classes) {
                context.report(
                    DEPENDENCY_ENTRY_POINT, location(element),
                    "`${alias ?: target}` comes from a dependency's manifest and $reach; it cannot carry " +
                        "`@GuardedEntryPoint`, so ShezGuard does not cover it. If the app does not use it, set " +
                        "`android:exported=\"false\"` with `tools:replace=\"android:exported\"` in the app manifest.",
                )
                return
            }
            val annotation = seen.annotations[target]
            if (annotation == null) {
                context.report(
                    UNGUARDED_ENTRY_POINT, location(element),
                    "`$subject` $reach but has no `@GuardedEntryPoint`. Annotate it with " +
                        "`@GuardedEntryPoint(\"name\")` and declare `entryPoint(\"name\")` in your `intentPolicy {}`, " +
                        "or with `@GuardedEntryPoint(exempt = true)` if it reads no intent data.",
                )
            }
            // An invalid annotation was already reported at the annotation (ShezGuardInvalidAnnotation);
            // a valid name is checked against the policy by checkNames.
        }

        /** "is exported (...)", "has a BROWSABLE intent filter", both, or null when not reachable. */
        private fun reachability(element: Element): String? {
            val filters = children(element, "intent-filter")
            val exported = element.getAttributeNodeNS(ANDROID_URI, "exported")?.value
            val parts = mutableListOf<String>()
            when {
                exported != null && exported != "false" -> parts += "is exported (`android:exported=\"$exported\"`)"
                exported == null && filters.isNotEmpty() && targetSdk < 31 ->
                    parts += "is exported implicitly (it has an intent filter and targetSdkVersion $targetSdk < 31)"
            }
            val browsable = filters.any { f -> children(f, "category").any { it.androidAttr("name") == BROWSABLE } }
            if (browsable) parts += "has a BROWSABLE intent filter"
            return parts.takeIf { it.isNotEmpty() }?.joinToString(" and ")
        }

        /** Exported services, receivers and providers of the app's own modules: informational only. */
        private fun checkOther(element: Element) {
            if (!isOwn(element)) return
            val exported = element.getAttributeNodeNS(ANDROID_URI, "exported")?.value
            val implicitLimit = if (element.tagName == "provider") 17 else 31
            val implicit = exported == null &&
                (element.tagName == "provider" || children(element, "intent-filter").isNotEmpty()) &&
                targetSdk < implicitLimit
            if (!(exported != null && exported != "false") && !implicit) return
            val permission = element.androidAttr("permission").isNotEmpty() ||
                (element.androidAttr("readPermission").isNotEmpty() && element.androidAttr("writePermission").isNotEmpty())
            if (permission) return
            context.report(
                UNCOVERED_COMPONENT, location(element),
                "Exported ${element.tagName} ${classOf(element.androidAttr("name"))} is not covered by ShezGuard v1 " +
                    "(activities only), and no `android:permission` protects it. Review it by hand.",
            )
        }

        private fun isOwn(element: Element): Boolean {
            val file = context.client.findManifestSourceNode(element)?.first?.canonicalFile
                ?: return findInSourceManifests(element) != null
            return ownDirs.any { file.startsWith(it) }
        }

        /**
         * Where to point the developer. Lint maps merged elements back to their source in lint-tests, but in
         * a real Gradle build (AGP 8.10.1) it returned null (step 13), so the element is also looked up by
         * tag and class name in the analysed modules' own manifests.
         */
        private fun location(element: Element): Location =
            context.client.findManifestSourceLocation(element)
                ?: findInSourceManifests(element)?.let { (file, source) -> context.client.xmlParser.getLocation(file, source) }
                ?: Location.create(context.mainProject.dir)

        private val sourceManifests: List<Pair<File, Element>> by lazy {
            (listOf(context.mainProject) + projects).distinct().flatMap { it.manifestFiles }.distinct().mapNotNull { file ->
                runCatching { context.client.xmlParser.parseXml(file)?.documentElement }.getOrNull()?.let { file to it }
            }
        }

        private fun findInSourceManifests(element: Element): Pair<File, Element>? {
            val wanted = classOf(element.androidAttr("name"))
            for ((file, root) in sourceManifests) {
                val sourcePkg = root.getAttribute("package").ifEmpty { pkg }
                val nodes = root.getElementsByTagName(element.tagName)
                for (i in 0 until nodes.length) {
                    val candidate = nodes.item(i) as? Element ?: continue
                    if (classOf(candidate.androidAttr("name"), sourcePkg) == wanted) return file to candidate
                }
            }
            return null
        }

        private fun classOf(name: String, base: String = pkg): String {
            val full = when {
                name.startsWith(".") -> base + name
                !name.contains('.') -> "$base.$name"
                else -> name
            }
            return full.replace('$', '.')
        }

        private fun simple(fqn: String): String = fqn.substringAfterLast('.')
    }

    public companion object {
        @JvmField public val UNGUARDED_ENTRY_POINT: Issue = Issues.UNGUARDED_ENTRY_POINT
        @JvmField public val UNKNOWN_ENTRY_POINT_NAME: Issue = Issues.UNKNOWN_ENTRY_POINT_NAME
        @JvmField public val ENTRY_POINT_NAME_UNVERIFIABLE: Issue = Issues.ENTRY_POINT_NAME_UNVERIFIABLE
        @JvmField public val INVALID_ANNOTATION: Issue = Issues.INVALID_ANNOTATION
        @JvmField public val GUARD_CALL_ORDER: Issue = Issues.GUARD_CALL_ORDER
        @JvmField public val UNCHECKED_GUARD_RESULT: Issue = Issues.UNCHECKED_GUARD_RESULT
        @JvmField public val DEPENDENCY_ENTRY_POINT: Issue = Issues.DEPENDENCY_ENTRY_POINT
        @JvmField public val UNCOVERED_COMPONENT: Issue = Issues.UNCOVERED_COMPONENT

        internal const val ACTIVITY = "android.app.Activity"
        internal const val GUARDED_ENTRY_POINT = "com.shezguard.core.GuardedEntryPoint"
        internal const val ACTIVITY_GUARD = "com.shezguard.core.ActivityGuard"
        internal const val POLICY_BUILDER = "com.shezguard.core.policy.IntentPolicyBuilder"
        private const val BROWSABLE = "android.intent.category.BROWSABLE"

        /** The DSL's rule for entry point names (PolicyDsl.kt, `entryPoint`). */
        private val NAME = Regex("[A-Za-z0-9_.-]{1,64}")

        private const val KEY_ANALYSED = "analysed"
        private const val KEY_CLASSES = "activityClasses"
        private const val KEY_ANNOTATIONS = "annotations"
        private const val KEY_NAMES = "entryPointNames"
        private const val KEY_NON_CONSTANT = "nonConstantEntryPoints"
        private const val A_NAME = "name"
        private const val A_EXEMPT = "exempt"
        private const val A_VALID = "valid"
        private const val A_LOCATION = "location"

        /** Issue 3, annotation part. `null` when the annotation is usable by the guard or the exemption. */
        internal fun annotationProblem(name: String, exempt: Boolean): String? = when {
            exempt && name.isNotEmpty() ->
                "`@GuardedEntryPoint` sets both a name and `exempt = true`; the guard blocks exempt activities " +
                    "and the coverage check ignores the name. Keep one of them."
            exempt -> null
            name.isEmpty() ->
                "`@GuardedEntryPoint` has an empty name and is not exempt, so the guard blocks every launch. " +
                    "Name the entry point, or set `exempt = true` if the activity reads no intent data."
            !NAME.matches(name) ->
                "Entry point name \"$name\" is invalid: use 1 to 64 characters from `A-Z a-z 0-9 _ . -`."
            else -> null
        }

        private fun moduleData(context: Context): LintMap = context.getPartialResults(UNGUARDED_ENTRY_POINT).map()

        private fun LintMap.child(key: String): LintMap = getMap(key) ?: LintMap().also { put(key, it) }

        private fun Element.androidAttr(name: String): String = getAttributeNS(ANDROID_URI, name)

        private fun children(parent: Element, tag: String? = null): List<Element> {
            val out = mutableListOf<Element>()
            var node = parent.firstChild
            while (node != null) {
                if (node is Element && (tag == null || node.tagName == tag)) out += node
                node = node.nextSibling
            }
            return out
        }
    }
}

/** Issues 3 (call part), 4 and 5: direct `ActivityGuard` calls, checked inside one method. */
internal object GuardCallChecks {
    fun check(context: JavaContext, call: UCallExpression, method: PsiMethod) {
        val guardMethod = method.name
        if (guardMethod != "onCreate" && guardMethod != "onNewIntent") return
        val cls = call.getParentOfType(UClass::class.java) ?: return

        val annotation = cls.findAnnotation(ShezGuardDetector.GUARDED_ENTRY_POINT)
        val exempt = annotation?.findAttributeValue("exempt")?.let { ConstantEvaluator.evaluate(null, it) } as? Boolean ?: false
        if (exempt) {
            context.report(
                ShezGuardDetector.INVALID_ANNOTATION, call, context.getLocation(call),
                "`ActivityGuard.$guardMethod` is called in an activity marked `@GuardedEntryPoint(exempt = true)`; " +
                    "the guard blocks every launch of an exempt activity. Name its entry point instead, or remove the call.",
            )
        }

        val enclosing = call.getParentOfType(UMethod::class.java) ?: return
        if (enclosing.name == guardMethod && context.evaluator.extendsClass(cls.javaPsi, ShezGuardDetector.ACTIVITY, false)) {
            CallOrder.check(context, call, enclosing, guardMethod)
        }
        ResultUse.check(context, call, enclosing, guardMethod)
    }

    internal fun startOf(element: UElement): Int? = element.sourcePsi?.textRange?.startOffset
}
