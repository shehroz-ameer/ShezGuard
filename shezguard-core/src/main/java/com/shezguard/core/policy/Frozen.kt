package com.shezguard.core.policy

import java.util.Collections

// Step 16 (docs/HARDENING.md H6): policy objects keep unmodifiable copies of the collections they are given, so a
// built policy cannot be changed through a cast or through the caller's own collection afterwards.

internal fun <T> Set<T>.frozen(): Set<T> = Collections.unmodifiableSet(LinkedHashSet(this))

internal fun <T> List<T>.frozen(): List<T> = Collections.unmodifiableList(ArrayList(this))

internal fun <K, V> Map<K, V>.frozen(): Map<K, V> = Collections.unmodifiableMap(LinkedHashMap(this))
