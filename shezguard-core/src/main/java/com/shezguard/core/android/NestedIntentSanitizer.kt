package com.shezguard.core.android

import androidx.core.content.IntentSanitizer

/**
 * Wraps an `androidx.core.content.IntentSanitizer` for nested-intent handling.
 *
 * ShezGuard does not reimplement `IntentSanitizer`. This wrapper keeps the policy model
 * free of the androidx type; the evaluator calls the sanitizer through its
 * `sanitize(intent, penalty)` overload so rejections become violations rather than
 * exceptions.
 *
 * @param sanitizer the configured sanitizer to apply to each nested Intent.
 */
public class NestedIntentSanitizer(internal val sanitizer: IntentSanitizer)
