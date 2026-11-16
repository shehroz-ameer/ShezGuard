package com.shezguard.lint

import com.android.SdkConstants.ANDROID_URI
import com.android.tools.lint.detector.api.Detector
import com.android.tools.lint.detector.api.Issue
import com.android.tools.lint.detector.api.XmlContext
import com.android.tools.lint.detector.api.XmlScanner
import org.w3c.dom.Element

/**
 * Issue 6, the build-time half of threat 4 (deep link hijacking; docs/SPEC.md section 2). Advice:
 * Lint cannot know whether the domain verifies or whether a link carries a secret.
 *
 * Reports a `BROWSABLE` intent filter with a custom (non-http(s)) scheme, once per scheme, and an
 * http(s) one with `android:autoVerify="false"`. An http(s) filter with NO `autoVerify` is left to
 * the built-in `AppLinkWarning` check, which is part of Android Lint, not of ShezGuard.
 * Reads each module's own manifest, like the built-in check.
 */
public class DeepLinkDetector : Detector(), XmlScanner {

    override fun getApplicableElements(): Collection<String> = listOf("intent-filter")

    override fun visitElement(context: XmlContext, element: Element) {
        val categories = children(element, "category").map { it.getAttributeNS(ANDROID_URI, "name") }
        if (BROWSABLE !in categories) return
        val schemes = children(element, "data").map { it.getAttributeNS(ANDROID_URI, "scheme") }.filter { it.isNotEmpty() }
        val web = schemes.filter { it == "http" || it == "https" }
        for (scheme in schemes.filter { it !in web }.distinct()) {
            context.report(
                UNVERIFIABLE_DEEP_LINK, element, context.getElementLocation(element),
                "Custom scheme `$scheme` in a BROWSABLE intent filter: any app can declare the same scheme and " +
                    "receive these links. Do not put secrets or one-time tokens in them; prefer a verified https App Link.",
            )
        }
        val autoVerify = element.getAttributeNodeNS(ANDROID_URI, "autoVerify")?.value
        if (web.isNotEmpty() && autoVerify != null && autoVerify != "true") {
            context.report(
                UNVERIFIABLE_DEEP_LINK, element, context.getElementLocation(element),
                "BROWSABLE ${web.distinct().joinToString("/")} filter with `android:autoVerify=\"$autoVerify\"`: the " +
                    "domain is not verified, so other apps can claim these links. Use `android:autoVerify=\"true\"` " +
                    "with a Digital Asset Links file.",
            )
        }
    }

    private fun children(parent: Element, tag: String): List<Element> {
        val out = mutableListOf<Element>()
        var node = parent.firstChild
        while (node != null) {
            if (node is Element && node.tagName == tag) out += node
            node = node.nextSibling
        }
        return out
    }

    public companion object {
        private const val BROWSABLE = "android.intent.category.BROWSABLE"

        @JvmField public val UNVERIFIABLE_DEEP_LINK: Issue = Issues.UNVERIFIABLE_DEEP_LINK
    }
}
