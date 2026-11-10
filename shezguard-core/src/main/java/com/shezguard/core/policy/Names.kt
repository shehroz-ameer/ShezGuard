package com.shezguard.core.policy

// Shared syntax rules for names in a policy. The model classes and the policy DSL both use
// these, so the DSL can report a precise message and the model can never disagree with it.

/** Entry point names: 1 to 64 characters from `A-Z a-z 0-9 _ . -`. */
internal val ENTRY_POINT_NAME: Regex = Regex("^[A-Za-z0-9_.-]{1,64}$")

/** Query parameter names: the same set, checked raw by the canonicaliser (`docs/LIMITATIONS.md` L16). */
internal val PARAM_NAME: Regex = Regex("^[A-Za-z0-9_.-]{1,64}$")

/** Lowercase RFC 3986 schemes. */
internal val SCHEME: Regex = Regex("^[a-z][a-z0-9+.-]*$")

/** Android package names, e.g. `com.example.app`. */
internal val PACKAGE_NAME: Regex = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")
