# Canonicaliser test list (step 3)

**Status: Implemented in step 3; all tests pass.** Approved by the author on 2026-11-09, with
additions merged in. Tests 111 and 112 and the change to test 99 were decided by the author
on 2026-11-10.

Test numbers are stable identifiers. Tests 1–103 keep the numbers they had in the first
list. Approved additions are numbered 104 and up and placed in the section they belong to,
marked *(added)*.

## Shape under test

```kotlin
internal object UriCanonicalizer {
    fun canonicalize(raw: String, limits: Limits): CanonResult
}
// CanonResult.Ok(CanonicalUri, findings)  // findings may hold only the soft URI_NON_CANONICAL
// CanonResult.Rejected(findings)          // every hard finding, not just the first
// CanonicalUri: scheme, host, port?, pathSegments (decoded), query: List<Pair> (decoded,
//               order and duplicates kept), fragment?
```

- Findings use the `ViolationCode`s from step 2. `URI_NON_CANONICAL` is the only soft one.
- Out of scope here, and tested in step 4: scheme/host/port/fragment allow-lists,
  repeated parameters, and checks on parameter values.

## Input contract: which `Uri` accessor feeds `canonicalize()`

`canonicalize()` takes a `String`. The evaluator (step 4b) will pass
**`intent.getDataString()`**, which is `intent.getData().toString()`. It is `null` when the
intent has no data, and the evaluator handles that through the `Data` rule without calling
the canonicaliser.

Whether that string is Android's original encoded form depends on how the `Uri` was made:
- **`Uri.parse(s)` (a `StringUri`)**: `toString()` returns `s` exactly as given, with no
  decoding or normalisation. Browsers, `adb shell am start -d`, and `Intent.parseUri`
  produce this kind. For these deep links the canonicaliser sees the original string.
  Tests 104 and 105 confirm this.
- **`Uri.Builder` or `Uri.fromParts` (a `HierarchicalUri` or `OpaqueUri`)**: there is no
  single original string. `toString()` is rebuilt from the components' encoded forms.
  Whatever the sender passed to the builder in decoded form gets encoded by Android. The
  canonicaliser then sees Android's encoded form, which is what the receiving app's
  accessors decode. Test 106 confirms this.

**Open risk, deferred to step 4b:** a `HierarchicalUri` sent over IPC carries its
components in a parcelled form that can hold both an encoded and a decoded representation.
If a crafted parcel can make them disagree, `toString()`, which uses the encoded form, and
accessors such as `getPathSegments()`, which use the decoded form, would show different
values. The canonicaliser alone cannot detect this. The runtime parser-mismatch check in
step 4b, which compares the canonical result with the received `Uri`'s own accessors and
emits `URI_PARSER_MISMATCH`, is the intended defence. It must include a test that crafts
such a parcel if Robolectric allows it. Whether this is exploitable on current Android
versions is **not verified**.

---

## A. `UriCanonicalizerTest` (plain JVM)

### 1. Mixed case
1. `lowercasesSchemeAndHost`: `HTTPS://EXAMPLE.COM/p` gives `https`, `example.com`
2. `preservesPathAndQueryCase`: `/Product?Id=A` is unchanged
3. `lowercasesPunycodePrefix`: `XN--80AK6AA92E.COM` gives `xn--80ak6aa92e.com`
4. `treatsUpperAndLowerHexEscapesAlike`: `%2f` and `%2F`, `%2e` and `%2E`
5. `doesNotFlagSchemeOrHostCaseAsNonCanonical`: no `URI_NON_CANONICAL`

### 2. Single percent-encoding
6. `decodesEachComponentOnce`: `/a%20b?q=x%26y` gives segment `a b` and value `x&y`
7. `decodesQueryOnlyAfterSplitting`: `?a=1%26b%3D2` gives one parameter, `a` = `1&b=2`
8. `blocksEncodedSlashInPathSegment`: `/a%2Fb` gives `URI_PATH_ENCODED_SEPARATOR`
9. `blocksEncodedBackslashInPathSegment`: `/a%5Cb` gives `URI_BACKSLASH`
10. `flagsNeedlesslyEncodedUnreservedCharAsNonCanonical`: `/%41` gives `A` plus `URI_NON_CANONICAL`
11. `blocksMalformedPercentEscapes`: `%`, `%2`, `%G1`, `%u002e` give `URI_PERCENT_MALFORMED`
12. `blocksInvalidUtf8AfterDecoding`: `%FF` and a lone `%C3` give `URI_INVALID_UTF8`
13. `blocksOverlongUtf8Encoding`: `%C0%AE` and `%E0%80%AE` give `URI_INVALID_UTF8`
14. `blocksEncodedSurrogateCodePoints`: `%ED%A0%80` gives `URI_INVALID_UTF8`
15. `decodesValidMultibyteUtf8InPath`: `/caf%C3%A9` gives `café`
107. *(added)* `decodesEncodedQuestionMarkIntoPathSegmentWithoutSplitting`: `/a%3Fb` gives
     the single segment `a?b`, with no query component
108. *(added)* `decodesEncodedHashIntoPathSegmentWithoutSplitting`: `/a%23b` gives the
     single segment `a#b`, with no fragment
109. *(added)* `blocksRawUnpairedSurrogate`: a lone high surrogate (`\uD800`), a lone low
     surrogate (`\uDC00`), and a reversed pair (`\uDC00\uD800`), raw in the path, query and
     fragment, give `URI_INVALID_UTF8`. A raw unpaired surrogate has no UTF-8 form, so it
     uses the same code as encoded surrogates (test 14). At implementation time the code's
     KDoc must say it also covers invalid UTF-16 in the input.

### 3. `+` versus `%20`
16. `decodesPlusAsSpaceInQueryValue`: `?q=a+b` gives `a b`
17. `decodesPlusAsSpaceInQueryName`: `?a+b=1` gives the name `a b`
18. `keepsPlusLiteralInPath`: `/a+b` gives the segment `a+b`
19. `decodesEncodedPlusAsLiteralPlusInQuery`: `?q=a%2Bb` gives `a+b`
20. `treatsPlusAndPercent20AsEquivalentInQuery`: `?q=a+b` and `?q=a%20b` give the same value

### 4. Double encoding
21. `blocksDoubleEncodedPathTraversal`: `/%252e%252e/etc`
22. `blocksDoubleEncodedSlash`: `/a%252Fb`
23. `blocksTripleEncoding`: `/%25252e`
24. `blocksDoubleEncodingInQueryValue`: `?next=%2568ttp`
25. `blocksDoubleEncodingInFragment`: `#%2541`
26. `blocksDoubleEncodedLiteralPercentAsKnownFalsePositive`: `?q=%2541`, documenting L2
27. `acceptsEncodedPercentNotFollowedByHex`: `?q=100%25` gives `100%`

### 5. `.` and `..` segments, raw and encoded
All give `URI_PATH_TRAVERSAL` or `URI_PATH_DOT_SEGMENT`.

28. `blocksRawDotDotSegment`: `/a/../b`, `/..`, `/a/..`
29. `blocksEncodedDotDotSegment`: `%2e%2e`, `%2E%2E`, `.%2e`, `%2e.`
30. `blocksEncodedDotDotWithEncodedSeparator`: `/%2e%2e%2fetc`
31. `blocksRawSingleDotSegment`: `/./a`, `/a/.`
32. `blocksEncodedSingleDotSegment`: `/%2e/a`
33. `blocksFullwidthDotTraversal`: `/%EF%BC%8E%EF%BC%8E/` (U+FF0E) gives `URI_PATH_UNICODE_SEPARATOR`
34. `blocksUnicodeSlashLookalikesInPath`: U+2215, U+2044, U+FF0F
35. `allowsDotsInsideSegmentNames`: `/file..txt`, `/v1.2/`, `/.well-known/x`
36. `leavesDotDotInQueryValueToParameterRules`: `?f=../x` is accepted here

### 6. Null bytes and control characters
37. `blocksRawNullByte`
38. `blocksEncodedNullByteInEveryComponent`: `%00` in the path, query name, query value and fragment
39. `blocksCrLfInjection`: raw `\r\n`, and encoded `%0D%0A`
40. `blocksTabAndNewlineInsideScheme`: `jav\tascript:`
41. `blocksDelCharacter`: `%7F`
42. `blocksC1ControlCharacters`: `%C2%85` (NEL), `%C2%80`, `%C2%9F`

### 7. Unicode format characters (Cf), rejected everywhere after decoding
All give `URI_FORMAT_CHAR`.

43. `blocksBidiOverrideInPath`: `/%E2%80%AE`
44. `blocksBidiOverrideInQueryValue`: `?name=%E2%80%AEtxt.exe`
45. `blocksZeroWidthSpaceInQueryValue`: U+200B
46. `blocksZeroWidthJoinerInQueryValueAsKnownFalsePositive`: an emoji ZWJ sequence, documenting L8
47. `blocksSoftHyphenAndByteOrderMark`: U+00AD, U+FEFF
48. `blocksFormatCharInFragment`
49. `blocksRawFormatCharWithoutEncoding`: a raw U+202E in the input

### 8. Whitespace
50. `blocksLeadingOrTrailingWhitespace`
51. `blocksRawSpaceInsideUri`
112. *(added 2026-11-10)* `blocksNonAsciiWhitespace`: U+00A0, U+3000, U+2028 and U+2029, raw
     and encoded, in the path, query and fragment, give `URI_WHITESPACE` (Unicode categories
     Zs, Zl, Zp other than U+0020; see `docs/LIMITATIONS.md` L15). `%20` stays allowed.

### 9. Backslashes
52. `blocksRawBackslashInPath`: `/a\b`
53. `blocksBackslashAuthorityTrick`: `https:\\evil.com`, `https:/\evil.com`
54. `blocksBackslashBeforeAt`: `https://example.com\@evil.com`
55. `allowsBackslashInQueryValueForParameterRules`: `?q=a\b` is accepted here

### 10. Userinfo tricks
All give `URI_USERINFO`, except where noted.

56. `blocksUserInfoWithPassword`: `https://user:pass@example.com`
57. `blocksHostLookingUserInfo`: `https://example.com@evil.com`
58. `blocksPortLookingUserInfo`: `https://example.com:443@evil.com`
59. `blocksEmptyUserInfo`: `https://@example.com`
60. `blocksPercentEncodedAtInHost`: `https://example.com%40evil.com` gives `URI_HOST_PERCENT_ENCODED`
61. `parsesAtAfterHashAsFragmentNotUserInfo`: `https://evil.com#@example.com` gives host `evil.com`
62. `parsesAtAfterQuestionMarkAsQueryNotUserInfo`: `https://evil.com?@example.com` gives host `evil.com`

### 11. Overlong input
The default limits are 2048 characters for the URI and 256 per parameter.

63. `acceptsUriAtExactly2048Chars`
64. `blocksUriAt2049Chars`
65. `measuresUriLimitOnRawNotDecodedForm`
66. `acceptsParamValueAtExactly256DecodedChars`
67. `blocksParamValueAt257DecodedChars`
68. `blocksParamNameOverLimit`
69. `honoursCustomLimits`
70. `blocksEmptyInput`: gives `URI_EMPTY`

### 12. Unicode lookalike hosts
71. `blocksCyrillicLookalikeHost`: `еxample.com` (U+0435) gives `URI_HOST_NON_ASCII`
72. `blocksFullwidthHost`: `ｅｘａｍｐｌｅ.com`
73. `blocksIdeographicFullStopInHost`: `example。com` (U+3002)
74. `blocksPercentEncodedNonAsciiHost`: `%D0%B5xample.com` gives `URI_HOST_PERCENT_ENCODED`
75. `blocksZeroWidthCharInHost`
76. `passesPunycodeHostThroughUnchanged`: `xn--80ak6aa92e.com` is accepted, and step 4's exact
    host matching rejects it

### 13. Host, port and structure
77. `blocksEmptyHost`: `https:///path`, `https://:443/`
78. `blocksTrailingDotHost`: `example.com.` gives `URI_HOST_TRAILING_DOT`
79. `blocksEmptyHostLabel`: `a..b.com`
80. `blocksInvalidHostCharacters`: `exa!mple.com`
81. `blocksIpv6Literal`: `[::1]` (see `docs/LIMITATIONS.md`, L9)
82. `blocksInvalidPort`: `:abc`, `:99999`, `:0`, an empty `:`
83. `flagsExplicitDefaultPortAsNonCanonical`: `https://example.com:443/`
84. `keepsNonDefaultPortForPolicyStage`: `:8443`
85. `blocksOpaqueUri`: `myapp:product`, `mailto:x`, `intent:#Intent;end`,
    `javascript:alert(1)`, `https:evil.com`, `http:example.com`. All give `URI_OPAQUE`
    (see `docs/LIMITATIONS.md`, L10). The last two catch a well-known scheme followed
    directly by a host-looking string with no `//`. A lenient parser can read that as a
    host, while `android.net.Uri` treats it as opaque.
86. `blocksInvalidSchemeSyntax`: `1http://x`, `ht tp://x`, `://x`
87. `acceptsCustomHierarchicalScheme`: `myapp://product/1`

### 14. Paths, queries and fragments
88. `collapsesDuplicateSlashesAndFlagsNonCanonical`: `/a//b` gives `/a/b` plus `URI_NON_CANONICAL`
89. `preservesTrailingSlash`
90. `preservesQueryOrderAndDuplicates`: duplicates are passed through for step 4 to block
91. `treatsSemicolonAsLiteralNotSeparator`: `?a=1;b=2` gives one parameter
92. `parsesParamWithoutEqualsAsEmptyValue`: `?flag`
93. `blocksEmptyParamName`: `?=x` gives `PARAM_NAME_INVALID`
94. `keepsFragmentForPolicyStage`

### 15. Pipeline properties
95. `reportsAllFindingsNotJustFirst`: a control character, a backslash and double encoding
    together give all three codes
96. `isDeterministicForSameInput`
97. `neverThrowsOnArbitraryInput`: a fixed-seed fuzz loop of 10,000 random strings,
    including unpaired surrogates
98. `findingsNeverContainRawValues`: findings carry only codes and components

---

## B. `UriCanonicalizerDifferentialTest` (Robolectric, SDK 34, the real AOSP `android.net.Uri` code)

### Agreement on accepted input
99. `agreesWithAndroidUriOnAcceptedInputs`
    - Runs over a corpus of accepted URIs, including the inputs of tests 107 and 108
      (`%3F` and `%23` in a path).
    - Compares scheme, host, port, decoded path segments, query names
      (`getQueryParameterNames`), the first value of each name through `getQueryParameter`
      (singular), and the fragment.
    - *(changed 2026-11-10)* `getQueryParameters` (plural) is not used, because it does not
      decode `+`, and the corpus has no `+` in parameter names (`docs/LIMITATIONS.md` L11).
110. *(added)* `encodedQuestionMarkAndHashInPathMatchAndroid`: for `/a%3Fb` and `/a%23b`,
     `getPathSegments()` returns one segment, `getQuery()` and `getFragment()` are `null`,
     and the canonicaliser agrees.

### The `+` rule
100. `plusInQueryDecodesToSpaceLikeAndroid`: `?q=a+b`
101. `plusInPathStaysLiteralLikeAndroid`: `/a+b` against `getPathSegments()`
102. `encodedPlusDecodesToLiteralPlusLikeAndroid`: `?q=a%2Bb`

If Android disagrees with our parser, tests 100–102 fail with a message naming both
results. The `+` rule then goes back to the author rather than being silently adjusted.

### Input contract (see "Input contract" above)
104. *(added)* `parsedUriToStringIsOriginalString`: for a corpus of tricky but parseable
     strings (mixed-case hex, `%2e`, `+`, `%2B`, `//`, `%3F` in path, a trailing `?` or `#`),
     `Uri.parse(s).toString() == s` and `Intent(ACTION_VIEW, Uri.parse(s)).dataString == s`.
105. *(added)* `dataStringSurvivesParcelRoundTrip`: the same corpus, with the `Intent`
     written to a `Parcel` and read back, as happens when it crosses processes. `dataString`
     is unchanged.
106. *(added)* `builderMadeUriToStringIsAndroidsEncodedForm`: a `Uri` built with
     `Uri.Builder` from decoded parts (`appendPath("a b")`, `appendQueryParameter("q", "a+b")`)
     has a `toString()` in encoded form (`a%20b`, `q=a%2Bb`). Canonicalising that string
     gives the same decoded values as `getPathSegments()` and `getQueryParameter("q")`.

### Characterisation (records Android's behaviour, asserts nothing about agreement)
103. `characterisesAndroidParsingOfRejectedTricks`
     - Records how `android.net.Uri` itself parses the backslash, userinfo, `#@`,
       `https:evil.com` and `http:example.com` inputs, to show why we reject them.
     - Prints Android's result so it can be cited.
111. *(added 2026-11-10)* `characterisesAndroidQueryAccessorInconsistency`
     - Records `getQueryParameter` vs `getQueryParameters` for `?q=a+b`,
       `getQueryParameterNames` for `?a+b=1`, and `getQueryParameter("id")` returning `null`
       for `?%69d=5`, next to ShezGuard's result.
     - Prints the result; the recorded output is in `docs/PAPER_NOTES.md`.

---

## Notes on scope
- **`URI_PARSER_MISMATCH` comes later.** The canonicaliser is pure Kotlin, so it can't call
  `android.net.Uri` itself. Emitting that code at runtime belongs to the evaluator
  (step 4b), together with the parcel-mismatch risk described under "Input contract".
- **Robolectric isn't a real device.** It runs the AOSP code for SDK 34 on the JVM. Section B
  must also run as an instrumented test on a device or emulator. That run is listed in
  step 14 of `docs/PROMPTS.md`.

## Summary
- 112 tests: 102 in section A (JVM), 10 in section B (Robolectric).
- Additions approved on 2026-11-09: 104–110. Added on 2026-11-10: 111, 112.
