package com.shezguard.core.android

import android.net.Uri
import com.shezguard.core.eval.UriView

/**
 * [UriView] over a real `android.net.Uri`: each function calls the getter of the same name.
 * Values are read lazily, so an accessor that throws does so inside the evaluator's
 * fail-closed boundary.
 */
internal class AndroidUriView(private val uri: Uri) : UriView {
    override fun isHierarchical(): Boolean = uri.isHierarchical
    override fun scheme(): String? = uri.scheme
    override fun host(): String? = uri.host
    override fun port(): Int = uri.port
    override fun userInfo(): String? = uri.userInfo
    override fun pathSegments(): List<String> = uri.pathSegments
    override fun path(): String? = uri.path
    override fun encodedPath(): String? = uri.encodedPath
    override fun authority(): String? = uri.authority
    override fun encodedAuthority(): String? = uri.encodedAuthority
    override fun query(): String? = uri.query
    override fun encodedQuery(): String? = uri.encodedQuery
    override fun fragment(): String? = uri.fragment
    override fun encodedFragment(): String? = uri.encodedFragment
    override fun queryParameterNames(): Set<String> = uri.queryParameterNames
    override fun queryParameter(name: String): String? = uri.getQueryParameter(name)
    override fun decode(encoded: String): String = Uri.decode(encoded)
}
