package com.shezguard.core.hardening

import android.os.Parcel
import android.os.Parcelable

/** Leaf of a nested-List extra (H1): its CREATOR records the stack at the deepest point of the platform's read. */
class DepthProbe : Parcelable {
    override fun describeContents(): Int = 0
    override fun writeToParcel(dest: Parcel, flags: Int) = Unit

    companion object {
        @Volatile
        var lastTrace: Array<StackTraceElement>? = null

        @JvmField
        val CREATOR: Parcelable.Creator<DepthProbe> = object : Parcelable.Creator<DepthProbe> {
            override fun createFromParcel(source: Parcel): DepthProbe {
                lastTrace = Thread.currentThread().stackTrace
                return DepthProbe()
            }

            override fun newArray(size: Int): Array<DepthProbe?> = arrayOfNulls(size)
        }

        /** The recursing (framework) cycle and the ShezGuard frames below it, innermost first. */
        fun describe(trace: Array<StackTraceElement>): String {
            fun n(e: StackTraceElement) = "${e.className.substringAfterLast('.')}.${e.methodName}"
            val names = trace.map(::n)
            val firstShez = trace.indexOfFirst { it.className.startsWith("com.shezguard") && !it.className.contains("hardening") && !it.className.contains("device") }
            val recursion = names.subList(0, if (firstShez < 0) names.size else firstShez)
                .filterNot { it.startsWith("Thread.") || it.startsWith("DepthProbe") }
            val counts = recursion.groupingBy { it }.eachCount().filterValues { it > 5 }
            val shez = if (firstShez < 0) emptyList() else trace.drop(firstShez).filter { it.className.startsWith("com.shezguard") }.map(::n).distinct()
            return "recursing frames (x count): ${counts.entries.joinToString(", ") { "${it.key} x${it.value}" }}; " +
                "first non-framework frames below them (innermost first): ${shez.take(6).joinToString(" < ")}"
        }
    }
}
