# ShezGuard: known limitations

This file lists what ShezGuard does **not** protect against, or protects against only
partially. Each entry says what the limitation is, why it exists, and what ShezGuard does
about it. New limitations are appended as soon as they are found.

## L1. Catching unparcelling exceptions does not prevent unsafe deserialisation
- **What:** to check an extra, the Bundle has to be unparcelled. Before API 33, reading any
  extra (or even `keySet()`) deserialises the whole Bundle. From API 33, values are
  deserialised lazily, but the value being read still is. Any side effects of a malicious
  `Parcelable` or `Serializable` (deserialisation gadgets) can therefore run **before**
  ShezGuard sees the result.
- **What ShezGuard does:** uses typed getters, catches the exception, records
  `EXTRAS_UNPARCEL_FAILED` and never crashes. This stops the crash (denial of service). It
  does not stop gadget side effects that happen during unparcelling.
- **Source:** orientation item 25; SPEC sections 2 (threat 5) and 5.

## L2. Double-encoding detection has false positives
- **What:** after decoding each URI component once, any remaining `%XX` sequence is treated
  as double encoding and blocked. A legitimate value that really contains an encoded percent
  sign followed by two hex digits is also blocked. For example, a search for the literal
  text `%41` arrives as `%2541`, decodes to `%41` and is blocked.
- **Why:** the design fails closed. Telling real double encoding apart from intended
  literal text is not reliable.
- **Workaround:** none in v1. Apps that need to accept such values must encode them in
  a different way (e.g. base64url in a bounded-string parameter).
- **Source:** orientation item 13; SPEC section 6.

## L3. Caller identity is only as reliable as its source, which depends on the component
ShezGuard treats caller information as a risk signal, not proof, unless the source is
reliable or a signature-level permission protects the component.

| Component / API | Source | Reliability |
|---|---|---|
| Activity | `getCallingPackage()` / `getCallingActivity()` | Set only when started with `startActivityForResult`. `null` for plain `startActivity`, so absence proves nothing. |
| Activity | `getReferrer()` (API 22+) | Can be set by the caller (`Intent.EXTRA_REFERRER`). Advisory only. |
| Activity | `getLaunchedFromUid()` / `getLaunchedFromPackage()` (API 34+) | Reliable when present, but only present if the caller opted in to sharing its identity (`ActivityOptions.setShareIdentityEnabled`). Unavailable on API 24–33. |
| Bound Service | `Binder.getCallingUid()` during a binder call | Reliable. (Services are out of v1; listed for completeness.) |
| BroadcastReceiver | `getSentFromUid()` / `getSentFromPackage()` (API 34+) | Reliable when present, but only if the sender opted in to sharing its identity. Unavailable on API 24–33. (Receivers are out of v1.) |
| Any | Signature-level `android:permission` on the component | Enforced by the OS. The strongest guarantee, and outside ShezGuard. |

- **Consequence:** on most Activity launches the caller cannot be reliably identified.
  `AllowedPackages` is therefore a soft (scored) signal by default and becomes a hard rule
  only when a reliable source is available. The decision records which source was used.
- **Related:** `requireVerifiedDomain` checks whether the app's own domain is verified
  (`DomainVerificationManager`, API 31+; unknown below). It cannot tell whether a
  particular intent came through a verified App Link: any app can send an explicit intent
  with `https` data.
- **Step 8 update:** `getLaunchedFromUid()` / `getLaunchedFromPackage()` are public only from
  API 34; on 31–33 they are `@hide` and not used. On API 34 they also require the launcher's
  opt-in. All of this is from the AOSP source; unconfirmed on device (L30).
- **Source:** orientation items 22 and 23; SPEC section 8.

## L4. The build-time check proves a policy is declared, not that it is enforced
- **What:** the Lint rule checks that every exported or `BROWSABLE` component carries a
  `@GuardedEntryPoint` annotation (or an explicit exemption), and a test helper checks that
  the annotated name exists in the policy. Neither proves that the component actually calls
  `ShezGuard.evaluate()` (or the Activity helper), nor that the app acts on the returned
  decision instead of reading `getIntent()` directly.
- **Why:** proving that a call happens on every path is a data-flow problem that Lint does
  not solve reliably.
- **Source:** orientation item 28; SPEC section 9.

## L5. `subdomainsOf` cannot detect public suffixes
- **What:** `HostPattern.SubdomainsOf` rejects a single-label domain such as `com`, but it
  cannot tell that `co.uk` or `github.io` are public suffixes. `subdomainsOf("co.uk")` would
  accept every site registered under `.co.uk`.
- **Why:** detecting public suffixes needs the Public Suffix List, a large external data set
  that changes over time. Bundling it conflicts with the no-third-party-dependency rule.
- **What ShezGuard does:** documents the risk in KDoc and recommends exact hosts. Subdomain
  matching is an explicit opt-in.
- **Source:** step 2 (policy model); SPEC section 4.

## L6. Parcelable, Serializable and Bundle extras cannot be allow-listed
- **What:** `ExtraType` covers only primitives, `String` and primitive or `String` arrays.
  An entry point that genuinely needs a `Parcelable`, `Serializable` or nested `Bundle`
  extra cannot validate it with ShezGuard. It can only reject it as not allowed.
- **Why:** reading these types runs deserialisation code chosen by the sender (see L1), so
  ShezGuard cannot inspect them safely.
- **Source:** step 2 (policy model); SPEC section 4.

## L7. Non-ASCII (internationalised) hosts cannot be allowed in v1
- **What:** `HostPattern` accepts only lowercase ASCII hosts, and the canonicaliser rejects
  non-ASCII hosts (`URI_HOST_NON_ASCII`). An app whose deep links use an internationalised
  domain such as `bücher.example` cannot allow it by its Unicode spelling, and ShezGuard
  does not convert between Unicode and punycode (`xn--`).
- **Why:** lookalike hosts are an in-scope threat (threat 6). Supporting them safely needs
  IDNA conversion plus confusable-character checks, which v1 leaves out to keep host
  matching exact and easy to reason about.
- **Workaround:** none in v1. Allowing the punycode form as an exact ASCII host is possible,
  but then the canonicaliser must receive that same form.
- **Source:** step 2 decision (choice 7); SPEC sections 4 and 6.

## L8. Unicode format characters are rejected everywhere, including legitimate text
- **What:** after decoding, any character in Unicode general category Cf (bidi controls
  such as U+202E, zero-width characters such as U+200B and U+200D, soft hyphen U+00AD,
  and others) blocks the intent (`URI_FORMAT_CHAR`). This includes query values. Some
  legitimate text uses these characters: zero-width joiners inside emoji sequences, and
  bidi marks in mixed Arabic/Hebrew and Latin text. Such values are blocked.
- **Why:** these characters make a value display differently from what it contains
  (Trojan Source-style spoofing, hidden content in hosts and paths). Rejecting the whole
  category is simpler and more predictable than an allow-list of "safe" ones.
- **Workaround:** none in v1. Apps that need such text should accept it through a channel
  other than a deep link parameter.
- **Source:** step 3 decision; SPEC section 6.

## L9. IPv6 literal hosts are unsupported
- **What:** a URI whose host is an IPv6 literal, such as `https://[::1]/` or
  `https://[2001:db8::1]:8443/`, is rejected (`URI_HOST_INVALID`). An entry point cannot
  allow one, because `HostPattern` accepts only ASCII host names.
- **Why:** bracketed IPv6 parsing (zone IDs, embedded IPv4, compressed forms, and several
  equivalent spellings of one address) would roughly double the canonicaliser's parsing
  surface. Deep links to IPv6 literals are rare.
- **Workaround:** none in v1. IPv4 literals are syntactically host names and can be allowed
  as exact hosts, but their alternative spellings (`0x7f.1`, `2130706433`) are not
  normalised; exact matching rejects them.
- **Source:** step 3 test list (test 81); SPEC section 6.

## L10. Opaque (non-hierarchical) URIs are unsupported
- **What:** only hierarchical URIs (`scheme://authority/path?query#fragment`) are accepted.
  Opaque URIs, where the scheme is not followed by `//`, are rejected (`URI_OPAQUE`). This
  includes `mailto:x`, `tel:123`, `sms:...`, `geo:...`, `intent:#Intent;...end`,
  `myapp:product`, and malformed forms such as `https:evil.com` and `http:example.com`.
  An entry point that legitimately handles `mailto:`, `tel:` or `geo:` cannot be protected
  by ShezGuard's URI checks.
- **Why:** opaque URIs have no host, path or query structure for the policy to check. Their
  scheme-specific part would need its own parser per scheme. Malformed `https:host` forms
  are a known parser-differential trick, and rejecting all opaque URIs removes that whole
  class.
- **Workaround:** none in v1. Such entry points can still use ShezGuard's extras, nested
  intent and caller checks with `data(Data.Forbidden)` if the URI is not needed, or handle
  the URI without ShezGuard.
- **Source:** step 3 test list (test 85); SPEC section 6.

## L11. Android's own query accessors disagree about `+`; read parameters from the Decision
- **Rule for apps:** read query parameters from the ShezGuard `Decision`, which holds the
  canonical values ShezGuard validated. If an app must read the `Uri` directly, it must use
  `Uri.getQueryParameter(name)`, the accessor whose `+` handling ShezGuard matches.
  `getQueryParameters(name)` and `getQueryParameterNames()` behave differently and must not
  be used to read validated data.
- **What Android does** (Robolectric, SDK 34, test 111; not yet verified on a device):
  - `?q=a+b`: `getQueryParameter("q")` returns `a b`; `getQueryParameters("q")` returns
    `[a+b]`. The plural accessor does not decode `+` in values.
  - `?a+b=1`: `getQueryParameterNames()` returns `[a+b]` (no `+` decoding in names).
    `getQueryParameter` finds the parameter under neither `a+b` nor `a b`.
    `getQueryParameters("a b")` returns `[1]`, `getQueryParameters("a+b")` returns `[]`.
- **What ShezGuard does:** decodes `+` to a space in values (SPEC section 6), so it agrees
  with `getQueryParameter`. The differential test 99 compares values through
  `getQueryParameter` only (author decision, step 3). **Names:** since step 4 a raw name
  must match `[A-Za-z0-9_.-]{1,64}`, so a `+` in a name is `PARAM_NAME_INVALID` (test 17)
  and the name half of this limitation no longer applies. For names in that set all three
  accessors agree (test 116). The value half remains. The step 5b parser-mismatch
  check reads values with `getQueryParameter` only (author decision, 2026-11-10; L19).
- **Source:** step 3, differential tests 99 and 111.

## L12. `getQueryParameter` does not find percent-encoded parameter names
- **Rule for apps:** as in L11, read parameters from the `Decision` (or, failing that, via
  `getQueryParameter`). Do not combine `getQueryParameterNames()` with `getQueryParameter`.
- **What Android does** (Robolectric, SDK 34, test 111): for `?%69d=5`,
  `getQueryParameterNames()` returns `[id]`, but `getQueryParameter("id")` returns `null`
  and `getQueryParameters("id")` returns `[]`. The lookup compares the requested name with
  the raw, still-encoded query text.
- **Consequence (before step 4):** ShezGuard decoded the name and saw `id = 5`, which the
  app's own `getQueryParameter("id")` does not see.
- **What ShezGuard does now:** since step 4 this case is blocked. A raw name containing `%`
  is `PARAM_NAME_INVALID` (test 113), so ShezGuard and the accessors can no longer disagree
  about which name a parameter has. The cost is L16.
- **Source:** step 3, differential tests 99 and 111; resolved by the step 4 name rule.

## L13. Deep links with empty query pieces, including a trailing `&`, are blocked
- **What:** the query is split on `&`, and every piece, including an empty one, becomes a
  parameter. `?a=1&&b=2` and `?a=1&` therefore contain a parameter with an empty name and
  are blocked with `PARAM_NAME_INVALID`. Some link generators and hand-written links add a
  trailing `&`, and `android.net.Uri` silently skips it, so such links work without
  ShezGuard and are blocked with it.
- **Why:** fails closed and keeps the parser simple: there is no "silently ignored" part
  of the query that the policy did not see.
- **Workaround:** none in v1. Senders must not emit empty query pieces.
- **Source:** step 3 decision (author accepted, 2026-11-10); test 93.

## L14. Unicode lookalikes of `/` and `.` outside a small set are accepted
- **What:** the canonicaliser rejects only four path lookalikes (`URI_PATH_UNICODE_SEPARATOR`:
  U+2215, U+2044, U+FF0F, U+FF0E). Others, such as U+2024 ONE DOT LEADER, U+FE52 SMALL
  FULL STOP, U+29F8 BIG SOLIDUS, and backslash lookalikes U+FF3C and U+2216, pass. They
  then reach the policy stage, where `anyPath()` accepts any canonical path, and a loosely
  defined string parameter (`CharClass.TEXT`) accepts Unicode punctuation and symbols.
- **Why:** any fixed list of lookalikes is incomplete. The reliable defence is to restrict
  the allowed characters, not to list the bad ones.
- **What ShezGuard does:** exact or prefix path patterns, `ALPHANUMERIC`, `SLUG` and
  `PRINTABLE_ASCII` are ASCII-only, so they reject these characters. The default character
  class for string parameters must be ASCII-restricted (step 4 note in `docs/PROMPTS.md`).
  Entry points that use `anyPath()` or `CharClass.TEXT` accept the lookalikes and must not
  pass such values to a file system or another path-sensitive sink.
- **Source:** step 3 decision (author, 2026-11-10).

## L15. Non-ASCII whitespace is rejected everywhere, including legitimate text
- **What:** Unicode whitespace other than U+0020 (categories Zs, Zl, Zp, e.g. U+00A0
  NO-BREAK SPACE, U+3000 IDEOGRAPHIC SPACE, U+2028, U+2029) blocks the intent
  (`URI_WHITESPACE`), raw or encoded, in every component. Legitimate text sometimes contains
  these, e.g. a no-break space in French typography or text pasted from a word processor.
- **Why:** these characters look like a normal space or a line break but compare
  differently, which enables spoofing and inconsistent handling downstream. As with L8,
  rejecting the whole categories is simpler and more predictable than an allow-list.
- **Workaround:** none in v1. An encoded U+0020 (`%20`, or `+` in a query) is still accepted.
- **Source:** step 3 decision (author, 2026-11-10); test 112.

## L16. Query parameter names are restricted to `[A-Za-z0-9_.-]{1,64}` (not configurable)
- **What:** every query parameter name, declared or not, must be 1 to 64 characters from
  `A-Z a-z 0-9 _ . -` in the raw URI, before decoding. Anything else is
  `PARAM_NAME_INVALID` (hard), under every `Unknown` mode, including `Drop`. Legitimate
  links that are blocked as a result:
  - PHP- and Rails-style array names: `ids[]=1`, `filter[type]=x`.
  - Names containing `~`, `*`, `!`, `'`, `(`, `)`, `@`, `:` or non-ASCII letters (`café=1`).
  - Names that a sender percent-encodes although it does not need to (`%69d=5` for `id`),
    and names containing `+` (`a+b=1`).
  - Names longer than 64 characters. This is a fixed limit; `Limits.maxParamLength`
    (default 256) applies to values only.
- **Why:** Android's query accessors disagree about names outside this set
  (`docs/PAPER_NOTES.md` N1, N3; tests 111 and 117). Inside it, the raw and decoded name are
  identical and all three accessors agree (test 116). ShezGuard therefore never depends on
  how an accessor decodes a name.
- **Configurability:** none in v1. The set and the 64-character limit cannot be changed
  per policy, and `ParamRule.name` uses the same set, so a policy cannot declare a name
  outside it.
- **Source:** step 4 decision (author, 2026-11-10); tests 17, 68, 113–117.

## L17. URL-typed parameters cannot carry percent-escapes or explicit non-default ports
- **What:** a `ParamType.Url` value is decoded once by the outer canonicaliser, then
  canonicalised again as a URL. Any `%XX` left after that first decoding is reported as
  double encoding (`URI_DOUBLE_ENCODING`, L2) before the Url rule runs. A redirect target
  that needs its own escapes is therefore blocked. Examples: a path with a space
  (`?next=https://example.com/a%2520b`) or a nested query value containing `&`
  (`%2526`). A nested URL may still contain a query whose separators are encoded once
  (`?next=https://example.com/p%3Fa%3D1%26b%3D2`). Separately, a URL with an explicit
  non-default port (`https://example.com:8443/`) is rejected, because `Url` has no port
  allow-list.
- **Why:** both follow from failing closed: double-encoding detection cannot tell a
  nested URL's escapes from an evasion attempt, and an unlisted port is an unlisted origin.
- **Workaround:** none in v1. Redirect targets should be plain paths on the allowed host,
  or an app-side identifier (e.g. `OneOf` of known destinations) rather than a URL.
- **Source:** step 4; tests `nestedUrlCannotCarryPercentEscapesKnownLimitation`,
  `blocksRedirectWithExplicitNonDefaultPort`.

## L18. Declared parameters cannot be empty, so value-less flags cannot be declared
- **What:** every `ParamType` rejects an empty value, so `?debug` or `?id=` is
  `PARAM_INVALID_FORMAT` for a declared parameter. There is no flag or boolean type, so a
  link that uses a parameter's presence alone as a switch cannot declare it.
- **Why:** a typed parameter that is present but empty has no valid value, and an empty
  string reaching a sink that expects an identifier is a common source of bugs.
- **Workaround:** declare the parameter as `OneOf(setOf("1"))` (or similar) and send
  `?debug=1`.
- **Source:** step 4 decision; test `blocksEmptyValueForEveryType`.

## L19. The parser-mismatch check compares a fixed list of `Uri` accessors
- **What:** `URI_PARSER_MISMATCH` compares the canonical URI with `isHierarchical`,
  `getScheme`, `getHost`, `getPort`, `getUserInfo`, `getPathSegments`, `getPath` (trailing
  slash), `getFragment`, `getQueryParameterNames` and `getQueryParameter`, and checks that
  `getAuthority`, `getPath`, `getQuery` and `getFragment` equal `Uri.decode` of their encoded
  forms. Other accessors, such as `getQueryParameters` (plural, L11),
  `getBooleanQueryParameter`, `getSchemeSpecificPart` and `normalizeScheme()`, are not
  compared. An app that reads one of them can still see different data from what ShezGuard
  checked.
- **Why:** Android's own accessors disagree with each other (N1), so "agree with every
  accessor" is not achievable. ShezGuard picks one accessor per component.
- **What ShezGuard does:** exposes the checked values in `Decision.data` (`GuardedUri`), which
  apps must use instead of the `Uri`.
- **Verification status:** the crafted-parcel case (API 24–29, `docs/PAPER_NOTES.md` N4) was
  shown under Robolectric SDK 29 and by reading AOSP source; not yet on a device.
- **Source:** step 5b.

## L20. Undeclared parameters kept under `Unknown.Ignore` stay in the original intent
- **What:** under `Unknown.Ignore` the decision is Allow, and `Decision.Allow.intent` is the
  unmodified original, so the undeclared parameters are still in its data URI. `GuardedUri`
  does not expose them (author decision 3), but an app that reads `getIntent().getData()`
  still sees them.
- **Why:** Sanitize may only be triggered by REMOVABLE violations, and `Ignore` is defined as
  "leave in place and signal".
- **Workaround:** use `Unknown.Drop` to have them removed from a sanitized copy, or read data
  only from the `Decision`.
- **Source:** step 5b, author decision 3.

## L21. Copying the intent touches a private flag of the caller's extras on API 33+
- **What:** Sanitize copies the intent with `Intent(Intent)`. From API 33 that constructor sets
  the private `mOwnsLazyValues` flag of the **source** extras Bundle to `false` when the Bundle
  is already unparcelled (`docs/PAPER_NOTES.md` N5). No value, key or public property of the
  caller's intent changes, and ShezGuard's "input is never modified" tests check public state
  only.
- **Why:** it is the platform's copy constructor; copying an intent without it would mean
  reimplementing `Intent` copying.
- **Source:** step 5b, AOSP source read of `BaseBundle(BaseBundle, boolean)`.

## L22. `EVALUATION_FAILED` discards the other violations
- **What:** if a `RuntimeException` is thrown during evaluation (e.g. by a `Uri` accessor on
  a crafted object), the decision is Block with only `EVALUATION_FAILED`, and its `Field` is
  `entryPoint`. Violations found before the failure are not reported, and no exception message
  or class name is recorded, so the decision explains less than usual.
- **Why:** a partial evaluation cannot be trusted to be complete, and exception messages from
  platform code can contain raw input.
- **Source:** step 5b, author decision 1. The fuzz test asserts the code never occurs on its
  corpus, so it does not hide library bugs there.

## L23. A failed unparcel leaves the Bundle silently truncated (platform behaviour)
- **What:** on API 24–34, when unparcelling a Bundle throws, the platform keeps the entries
  read so far and discards the rest of the parcel. Every later read of **that** Bundle
  succeeds silently with only some keys (`docs/PAPER_NOTES.md` N6).
- **What ShezGuard does:** reads extras only from `intent.getExtras()`, a copy whose parcelled
  bytes are duplicated, so a failure truncates ShezGuard's copy, never the caller's Bundle. The
  first failure is final: it records `EXTRAS_UNPARCEL_FAILED` (HARD) and never re-reads that
  Bundle.
- **What it does not do:** protect an app that reads the same intent's extras itself, catches
  the exception and carries on. Such an app sees a truncated Bundle. Apps must treat a Block
  as final and not read the intent.
- **Source:** step 6, AOSP source read (N6). Not run on a device.

## L24. `IntentSanitizer` rejections are counted, not explained
- **What:** `IntentSanitizer.sanitize(intent, penalty)` reports each rejection as a message
  that contains raw values from the nested intent (extra values, data URI, ClipData text;
  `docs/PAPER_NOTES.md` N9). ShezGuard must not log or keep raw intent data, so its penalty
  consumer discards every message unread. A `NESTED_INTENT_SANITIZED` or
  `NESTED_INTENT_DENIED` violation therefore names the extra key that held the nested intent,
  but not which part of the nested intent was removed.
- **Why:** parsing the message text to recover the category would depend on an undocumented
  message format and still carry attacker-controlled text.
- **Source:** step 6, androidx.core 1.16.0 source read.

## L25. A nested intent whose component `IntentSanitizer` rejects cannot be sanitized
- **What:** `IntentSanitizer` does not remove a rejected component; it **replaces** it with
  `android/java.lang.Void`. SPEC 4.1 allows Sanitize only to remove, so ShezGuard treats a
  changed component as `NESTED_INTENT_DENIED` (HARD) and blocks. This includes implicit nested
  intents (no component) unless the sanitizer was built with `allowAnyComponent()`.
- **Consequence:** an entry point that forwards implicit nested intents must use
  `allowAnyComponent()`, which also allows any explicit component. There is no "implicit only"
  setting in `IntentSanitizer`.
- **Source:** step 6, androidx.core 1.16.0 source read (N9).

## L26. Not covered in v1: nested intents outside extras, opaque objects, and grant flags
ShezGuard's nested-intent check looks only at extras values that are, or contain, an `Intent`,
`PendingIntent` or `IntentSender` inside framework containers (arrays, `List`, `Map`,
`SparseArray`, nested `Bundle`). Not covered in v1:
- **Custom `Parcelable` or `Serializable` objects that hold an Intent.** Their fields are
  opaque; ShezGuard sees the object, not what it contains. (They are never an allowed
  `ExtraType`, so they are removed under an unknown key, but an Intent inside one is not
  reported as a nested intent.)
- **`ClipData`** of the incoming intent, including `ClipData.Item` intents and URIs.
  (`IntentSanitizer` does check the ClipData of a *nested* intent under `AllowSanitized`.)
- **The selector** of the incoming intent (`Intent.getSelector()`).
- **URI-permission grant flags** (`FLAG_GRANT_READ_URI_PERMISSION`,
  `FLAG_GRANT_WRITE_URI_PERMISSION`, `FLAG_GRANT_PERSISTABLE_URI_PERMISSION`,
  `FLAG_GRANT_PREFIX_URI_PERMISSION`) on the incoming intent. On a nested intent under
  `AllowSanitized` they are kept only if the developer's `IntentSanitizer` allows them.
- **Source:** step 6 (author condition 3). Listed as "not covered" in `docs/ATTACK_MATRIX.md`.

## L27. Inspecting extras adds deserialisation the app might not have done
- **What:** to find nested intents anywhere in the extras, ShezGuard reads every value with
  `Bundle.get(key)`. On API 24–32 the first read of any extra deserialises every value anyway.
  On API 33–34 values of Parcelable, Serializable, List, Map, SparseArray and object-array
  types are lazy (`docs/PAPER_NOTES.md` N7), and ShezGuard deserialises all of them, including
  ones the app would never read. ShezGuard also does this for intents it then blocks, which the
  app would not have read at all. Any side effect of a hostile `CREATOR` or Serializable gadget
  therefore runs in more cases with ShezGuard than without it (see also L1).
- **Why the extras stage always runs** (author decision, step 6): skipping it after a URI
  violation gives no protection against an attacker who controls both the URI and the extras,
  because a valid URI is trivial to produce. It would only save work on non-adversarial
  malformed traffic, at the cost of an incomplete violation list.
- **Evaluated, not adopted:** a restrictive class loader on ShezGuard's copy of the extras
  would make app-defined Parcelable classes fail before their `CREATOR` runs, as the platform
  already does for nested-intent extras (N8). It is not adopted in v1 because the production
  configuration cannot be tested under Robolectric. Revisit in step 14.
- **Source:** step 6 proposal (d) and (a).

## L28. What the extras stage protects, and what it does not (step 6 summary)
Every "protected" item below is shown by the named test under Robolectric SDK 24, 29 and 34
(Robolectric-only, device check pending, step 14). Nothing else is claimed.

**Shown by tests:**
- An `Intent`, `PendingIntent` or `IntentSender` in an extra, explicit or implicit, directly,
  in a `Parcelable[]`, `ArrayList`, `Map` value, `SparseArray`, nested `Bundle`, or inside another
  nested Intent, blocks with `NESTED_INTENT_DENIED` (`NestedIntentTest.blocks*`; PendingIntent and
  IntentSender in-process only, not after a Parcel round trip).
- Wrong types, oversized strings, arrays and array elements under allowed keys, and more than 16
  keys, block (`ExtrasEvaluateTest`, `ExtrasValidatorTest`).
- Unknown keys, including a `null` key and custom Parcelables, are removed from a sanitized copy
  that holds only checked values (`sanitizesUnknownExtraKeyByRemovingIt`,
  `nullKeyIsReportedAsUndeclaredAndRemoved`, `customParcelableUnderUnknownKeyIsRemoved`).
- More than four nested containers block with `EXTRAS_TOO_DEEP` (`blocksExtrasNestedBeyondDepthLimit`).
- A Parcelable whose `CREATOR` throws, or that has no `CREATOR`, gives `EXTRAS_UNPARCEL_FAILED`
  and never a crash, also when nested in a Bundle, and the URI violations are kept
  (`ExtrasUnparcelTest`). The caller's Bundle stays parcelled (`callerBundleStaysParcelledAfterUnparcelFailure`).
- Under `Nested.AllowSanitized`, the forwarded nested intent is `IntentSanitizer`'s output, not
  the original object (`forwardedNestedIntentIsTheSanitizerOutputNotTheOriginal`); a rewritten
  component, a sanitizer exception and an Intent left in the output all block.
- The input intent's extras, including a nested intent's extras and categories, are unchanged
  after evaluation (`inputIntentAndItsExtrasAreNeverModified`); no decision output contains extra
  keys or values (`noDecisionOutputContainsExtraKeysOrValues`,
  `intentSanitizerMessagesNeverReachDecisionOutput`).
- On a 4000-case fixed-seed fuzz corpus with random extras, `EVALUATION_FAILED` never occurs and
  every extras code is reached (`EvaluateInvariantsTest.evaluateNeverThrowsOnFuzzedIntents`).

**Not protected or not shown:**
- **Deserialisation side effects** of a hostile `Parcelable` or `Serializable` run before ShezGuard
  sees the result (L1, L27). ShezGuard stops the crash, not the side effect.
- **`Error`s are not caught.** A parcel that makes unparcelling throw `StackOverflowError` (deeply
  nested lists, which the platform reads recursively and eagerly) or `OutOfMemoryError` crashes the
  app as it would without ShezGuard. Not tested.
- **String content of extras is not validated**: only type and length. A `STRING` extra may hold
  control characters, bidi overrides or a URL; apply the app's own validation before using it.
- **A `null` value under an allowed key is accepted** as absent (author decision 5): `hasExtra` is
  true for it, but every typed getter returns `null` or the default.
- **The size limits are approximations** (key count, `String.length`, element count), not a
  measured Parcel size. A large `Bundle` or byte array under an unknown key is read before it is
  removed.
- **Shapes not searched** (L26): custom objects holding an Intent, `ClipData`, the selector, grant flags.
- **A nested intent's own contents under `AllowSanitized` are only as safe as the developer's
  `IntentSanitizer` configuration**; ShezGuard adds only the component, exception and
  "no further nested intent" checks.
- **Device behaviour.** Robolectric runs the AOSP Java code of `Bundle`, `Parcel` and `Intent` with
  an emulated native `Parcel`. OEM builds and real IPC through `system_server` were not tested.
- **Source:** step 6.

## L29. The risk score is a small, hand-tuned part of the design
- **What it is:** ShezGuard's risk score is a transparent, additive tally of a few advisory signals, compared
  with a fixed threshold. It is not learned, adaptive or statistical, and it does not detect
  attacks: every attack-specific check is a HARD rule that blocks regardless of the score. In v1
  there are six soft signals, mostly about caller identity and domain verification, which cannot
  be established reliably (L3). The score exists so that several individually inconclusive
  signals can combine into a Block in a way a developer can read and tune. With the default
  weights, no single signal blocks, and only two strong (HIGH) signals together reach the default
  threshold. Before caller signals are implemented (step 8), the score cannot change any outcome
  under default settings.
- **Default weights are design choices, not empirically derived.** They were set so that the
  stated rule holds (no single signal blocks; one HIGH plus every compatible LOW stays below 70;
  two HIGH block), checked over every emittable subset of the six soft codes
  (`WeightedScorerTest.defaultWeightsOverAllEmittableSubsetsOfSoftSignals`). They were not
  measured against real traffic, and no false-positive or false-negative rate is claimed.
- **The default rule depends on two exclusive pairs** (`CALLER_UNIDENTIFIED` /
  `CALLER_NOT_ALLOWED`, `DOMAIN_NOT_VERIFIED` / `DOMAIN_VERIFICATION_UNAVAILABLE`) never being
  emitted together. Since step 8 the evaluator emits them, at most one per pair, from single
  `when` expressions; `CallerValidatorTest.neverEmitsBothSignalsOfAnExclusivePair` (20 000
  fixed-seed cases with fakes) and `CallerAndroidTest.neverEmitsBothSignalsOfAnExclusivePairEndToEnd`
  (Robolectric) check it. If both of a pair were emitted, one HIGH signal plus all LOW ones would
  reach 70.
- **Counting each code once** means volume is not evidence: 1 and 50 ignored parameters weigh
  the same. That is deliberate (benign links carry many tracking parameters), but it also
  means the score cannot express "unusually many" of anything.
- **Developer overrides can weaken the soft layer** (weight 0 everywhere) but never the hard
  one: no weight can unblock a HARD violation or turn a REMOVABLE one into Allow
  (`noCombinationOfWeightsTurnsHardIntoAllowOrSanitize`, `scoreCanOnlyAddBlock`).
- **Source:** step 7 (author approval 2026-11-11).

## L30. Caller signals: what is and is not established (step 8)
Everything below the "shown by tests" list is from the AOSP source (`docs/PAPER_NOTES.md`
N11–N13) and **unconfirmed on device**; the device check is step 14.

**Shown by tests** (Robolectric SDK 24, 29, 31, 34, unless noted; Robolectric-only, device check
pending (step 14)):
- A reliable caller (`getCallingPackage()`, faked by Robolectric's `ShadowActivity`) that is not
  listed, is signed by an unlisted key, has any unlisted signer (multi-signer), cannot be read,
  or (SDK 29, 31, 34) is signed by a current key while only a rotated-out key is listed, is
  blocked (`CallerAndroidTest`).
- A referrer extra naming an allowed package gives `CALLER_UNIDENTIFIED`; naming an unlisted one
  gives `CALLER_NOT_ALLOWED`; a web referrer names no package.
- The system referrer is read only when neither intent has extras; with extras, `getReferrer()`
  is not called and the caller's Bundle stays parcelled
  (`systemReferrerIsNotReadWhenItWouldUnparcelTheCallersExtras`).
- `Delivery.NEW_INTENT` reports no reliable identity and ignores the system referrer.
- `requireReliableIdentity = true` blocks a launch without a reliable identity.
- The exclusive pairs never co-occur: a 20 000-case fixed-seed property test with fakes, and an
  end-to-end grid under Robolectric.
- No package name or digest appears in any decision output.

**Not shown, or not protected:**
- **`getLaunchedFromPackage()` (API 34)** is tested with fakes only; Robolectric has no shadow.
- **Domain verification** VERIFIED / NOT_VERIFIED is tested with fakes only; under Robolectric
  `DomainVerificationManager` is unavailable, so only the UNAVAILABLE path runs for real.
- **Package visibility** (Android 11+) is not enforced by Robolectric. The claim that no
  `<queries>` entry is needed for a reliable caller rests on the source only (N13).
- **Forward-result caveat:** `getCallingPackage()` names the app that receives the result. An
  activity started for result by an allowed app can forward that result slot
  (`FLAG_ACTIVITY_FORWARD_RESULT`) when it launches this one, so the allowed app is reported
  although another app launched. ShezGuard cannot detect this from `getCallingPackage()` alone;
  on API 34 a shared launcher identity is also checked when present.
- **Key rotation:** only current signers are accepted. When an allowed caller rotates its signing
  key, it is blocked until the new key is added to the allow-list.
- **Most launches are unidentified.** Plain `startActivity` and browser deep links carry no
  reliable identity, so a default (advisory) allow-list only scores them. Enforcing mode blocks
  them all.
- **The referrer is worth little:** a caller can set it to any value. It catches only callers
  that do not bother to spoof it.
- **`onNewIntent` deliveries** get no reliable identity at all, even if the new sender used
  `startActivityForResult`.
- **Signature-level permissions** on the component are not detected at runtime.
- **Source:** step 8 (author approval 2026-11-11).

## L31. `Activity.getReferrer()` unparcels the caller's extras (platform behaviour)
- **What:** `getReferrer()` reads `EXTRA_REFERRER` with `getParcelableExtra` on `getIntent()`, the
  caller's own intent, on API 24–34 (N11). That unparcels the caller's Bundle (on API 24–32, every
  value), runs any hostile `CREATOR` in it, and catches only `BadParcelableException`; any other
  exception propagates, and a failure leaves the Bundle truncated (N6).
- **What ShezGuard does:** never calls it when either intent has extras (`getExtras() == null` is
  the test, which never unparcels); reads the referrer extras from its own copy instead.
- **Cost:** with extras present and no referrer extra, the system referrer is not read, so the
  only advisory source is lost for that delivery.
- **What it does not do:** stop an app from calling `getReferrer()` itself.
- **Source:** step 8; shown under Robolectric (SDK 24, 29, 31, 34) by the mutation check of
  `systemReferrerIsNotReadWhenItWouldUnparcelTheCallersExtras`.

## L32. `requireVerifiedDomain` needs exact hosts
- **What:** ShezGuard looks up the canonical host exactly in the app's verification state. Wildcard
  hosts declared in the manifest (`*.example.com`) are not expanded, so `subdomainsOf(...)` is
  rejected with `requireVerifiedDomain()` at build time. `DOMAIN_STATE_SELECTED` (the user chose
  the app) counts as not verified.
- **Source:** step 8, author condition 4.

## L33. Audit events: what is and is not protected (step 9)
**Shown by tests** (Robolectric SDK 34):
- A fixed-seed corpus of 600 evaluations puts the canary `zqxcanary` in every attacker-controlled
  position: scheme, host, userinfo, path, parameter names and values (raw and percent-encoded),
  fragment, extras keys and values, nested intents (component, data, extras), deep Bundles,
  referrer extras, the calling package, the message of an exception thrown by a caller source,
  and the message of an exception thrown by a sink. It covers every outcome, including Sanitize
  decisions whose rebuilt URI and extras still contain the canary. The canary appears in no
  `AuditEvent` (fields and `toString`) and in no logcat line, and no throwable is logged
  (`AuditCanaryTest`).
- Mutation checks: the test catches raw undeclared names in the event, an unvalidated entry point
  name, a logged sink exception, a logged evaluation exception, a debug log of the data URI, and a
  caller package placed in a declared field.
- Exactly one event per call on every path; a throwing sink, or one that tries to modify the
  event, does not change the decision; `Error`s from a sink propagate (`AuditWiringTest`).

**Not protected:**
- **A slow sink delays the app.** The sink runs synchronously on the calling thread, usually the
  main thread; a blocking sink can cause an ANR. It cannot change the decision.
- **A sink that throws is silent.** Its exceptions are swallowed on purpose, so a broken sink goes
  unnoticed unless it reports its own failures.
- **Raw names are no longer public** (author decision, step 9 follow-up). `Field.Param` and
  `Field.Extra` keep the raw name internally (`internal` and `@JvmSynthetic`, because Kotlin
  `internal` members compile to public JVM methods). The only public form is `declaredName`,
  which is non-null only for names from the policy. This also covers
  `RiskScore.contributions[].violation.field`. `RawNameExposureTest` walks every public,
  non-synthetic, zero-argument method of `Field`, `Violation`, `ScoreContribution`, `RiskScore` and
  `Decision` (all outcomes) and finds no undeclared name; mutation checks (name public again, key
  public again, `internal` without `@JvmSynthetic`, `declaredName` ignoring `declared`) are all caught.
  - It is not a security boundary: code inside the app can still read the field by reflection.
  - The walk does not descend into Android objects: `Decision.Allow.intent` and
    `Decision.Sanitize.sanitizedIntent` are the app's intents and still contain the raw URI and
    extras by design.
- **A failure while building the Sanitize copy** is caught by ShezGuard's outer catch, gives
  `EVALUATION_FAILED`, emits one event, and leaks nothing into the event, the decision or logcat,
  even with the canary in the exception message (`SanitizeCopyFailureTest`, using an internal
  failure hook that is a no-op in production).
- **The entry point name** is assumed to come from app code. A valid but app-chosen name is
  logged as given.
- **`LogcatAuditSink` in a release build** advertises validation decisions to anyone with `adb`
  access or a bug report. It is meant for debug builds only.
- **Source:** step 9.
