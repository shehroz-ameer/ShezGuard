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
