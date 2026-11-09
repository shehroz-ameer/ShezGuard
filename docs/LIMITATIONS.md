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
