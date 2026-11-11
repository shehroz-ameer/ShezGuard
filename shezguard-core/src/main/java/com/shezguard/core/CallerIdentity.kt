package com.shezguard.core

/**
 * Which source a decision used for the caller's identity (SPEC section 8). Recorded in
 * `Decision.callerIdentitySource`; the package name itself is never exposed.
 */
public enum class IdentitySource {
    /**
     * `Activity.getCallingPackage()`: set by the OS, but only when the caller used
     * `startActivityForResult`. Reliable as **the app that will receive the result**: with
     * `Intent.FLAG_ACTIVITY_FORWARD_RESULT` an intermediate activity can forward an earlier
     * caller's result slot, so this can name that earlier app rather than the immediate launcher.
     */
    CALLING_PACKAGE,

    /**
     * `Activity.getLaunchedFromPackage()` (API 34+): set by the OS, available only if the
     * launcher called `ActivityOptions.setShareIdentityEnabled(true)` or shares this app's uid.
     * Reliable when present.
     */
    LAUNCHED_FROM_PACKAGE,

    /** `Intent.EXTRA_REFERRER` or `EXTRA_REFERRER_NAME`: set by the caller. Advisory only. */
    REFERRER_EXTRA,

    /**
     * The system referrer (`Activity.getReferrer()` when the intent has no extras): the
     * launcher's own package string, checked against its uid only from API 30. Advisory only.
     */
    REFERRER_SYSTEM,

    /** No source was available. */
    NONE,
}

/**
 * How the intent reached the activity. Caller identity is only available for [LAUNCH]: on API
 * 24–34 the OS keeps the identity of the launch that created the activity, so for an intent
 * delivered to `onNewIntent` (`singleTop`, `singleTask`, ...) `getCallingPackage()`,
 * `getLaunchedFromPackage()` and the system referrer can describe an earlier caller
 * (`docs/PAPER_NOTES.md` N12).
 */
public enum class Delivery {
    /** The intent that created the activity (`onCreate`). */
    LAUNCH,

    /** An intent delivered to `onNewIntent`. No reliable caller identity is reported. */
    NEW_INTENT,
}
