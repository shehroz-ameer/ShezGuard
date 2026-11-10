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
- **What ShezGuard does:** decodes `+` to a space in names and values (SPEC section 6), so
  it agrees with `getQueryParameter`. The differential test 99 compares values through
  `getQueryParameter` only, and its corpus has no `+` in parameter names (author decision,
  step 3). How the step 4b parser-mismatch check handles this is still to be decided.
- **Source:** step 3, differential tests 99 and 111.

## L12. `getQueryParameter` does not find percent-encoded parameter names
- **Rule for apps:** as in L11, read parameters from the `Decision` (or, failing that, via
  `getQueryParameter`). Do not combine `getQueryParameterNames()` with `getQueryParameter`.
- **What Android does** (Robolectric, SDK 34, test 111): for `?%69d=5`,
  `getQueryParameterNames()` returns `[id]`, but `getQueryParameter("id")` returns `null`
  and `getQueryParameters("id")` returns `[]`. The lookup compares the requested name with
  the raw, still-encoded query text. ShezGuard decodes the name and sees `id = 5`.
- **Consequence:** a policy rule for `id` sees a parameter the app's own
  `getQueryParameter("id")` does not. ShezGuard sees at least as much as the app, so the
  check fails safe. But an app reading the `Uri` directly may act on different data than
  was validated.
- **Source:** step 3, differential tests 99 and 111.

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
