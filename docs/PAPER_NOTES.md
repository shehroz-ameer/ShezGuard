# Paper notes: findings worth citing

Findings from the implementation that the article can cite. Each entry says what was
observed, what it means, and where the evidence lives. Unless noted, observations come from
Robolectric running the AOSP `android.net.Uri` code for SDK 34 on the JVM. They are **not yet
confirmed on a device or emulator**. That run is step 14 of `docs/PROMPTS.md`.

Recorded output is copied verbatim from the test logs (`<testcase>` `system-out` in
`shezguard-core/build/test-results/testDebugUnitTest/TEST-com.shezguard.core.canon.UriCanonicalizerDifferentialTest.xml`),
captured on 2026-11-10. Re-run `./gradlew :shezguard-core:test` to reproduce.

## N1. `android.net.Uri`'s query accessors disagree with each other

**Observation.** The query accessors on the same `Uri` object give different answers:
- `getQueryParameter` (singular) decodes `+` to a space. `getQueryParameters` (plural) does
  not.
- `getQueryParameterNames` does not decode `+` in names.
- A parameter whose name is percent-encoded (`%69d`) is listed as `id`, but cannot be
  read with `getQueryParameter("id")`.

**Why it matters.** A validator and the code that later reads the value can see different
data if they use different accessors. This is a parser differential *inside* one platform
API, not only between two parsers. It supports the design rule that apps read validated
values from the `Decision` rather than from `getIntent()` (SPEC section 6).

**Evidence.**
- Test 111 `characterisesAndroidQueryAccessorInconsistency`, in
  `shezguard-core/src/test/java/com/shezguard/core/canon/UriCanonicalizerDifferentialTest.kt`.
- Test 99 originally failed on this disagreement (step 3). It now compares values through
  `getQueryParameter` only (author decision).
- `docs/LIMITATIONS.md` L11, L12.

**Recorded output (test 111), re-recorded 2026-11-10 after the step 4 name rule.** The
Android columns are unchanged from step 3. In step 3 ShezGuard returned `[(a b, 1)]` and
`[(id, 5)]` for the last two inputs; both are now rejected.
```
[111] <https://example.com/?q=a+b> android: getQueryParameterNames()=[q] getQueryParameter("q")=<a b> getQueryParameters("q")=[a+b] | shezguard: [(q, a b)]
[111] <https://example.com/?a+b=1> android: getQueryParameterNames()=[a+b] getQueryParameter("a+b")=<null> getQueryParameters("a+b")=[] getQueryParameter("a b")=<null> getQueryParameters("a b")=[1] | shezguard: Rejected
[111] <https://example.com/?%69d=5> android: getQueryParameterNames()=[id] getQueryParameter("id")=<null> getQueryParameters("id")=[] | shezguard: Rejected
```

**How this finding shaped the design (step 4).** In step 3 the differential test 99
failed on the `+` disagreement. That showed ShezGuard could not "match Android" for names,
because Android does not agree with itself. Instead of choosing one accessor, the name rule
removes the dependency. A raw name must match `[A-Za-z0-9_.-]{1,64}`, so it is identical
before and after decoding, and every accessor sees the same name (test 116, N3). Names
containing `+` or `%` are now `PARAM_NAME_INVALID` (tests 17, 113). Values keep the
`getQueryParameter` rule (`+` is a space). Cost: `docs/LIMITATIONS.md` L16.

Note the second line: the `+` name is listed as `a+b`. `getQueryParameters` finds it only
as `a b`, and `getQueryParameter` finds it under neither spelling.

## N2. Android ends the authority at a backslash; a lenient reading treats it as userinfo

**Observation.** For `https://example.com\@evil.com`, `android.net.Uri` stops the authority
at `\`. The result is host `example.com` and path `\@evil.com`. An RFC 3986 reading, where
`\` is not a delimiter, takes the authority as `example.com\@evil.com`. That gives userinfo
`example.com\` and host `evil.com`. WHATWG URL parsers treat `\` as `/` for special schemes.
Two parsers can therefore disagree about the host of the same string. ShezGuard rejects any
backslash in the authority or path (`URI_BACKSLASH`, plus `URI_USERINFO` here), so the
disagreement cannot reach the policy stage.

Other results from the same test:
- `https:\\evil.com`, `https:evil.com` and `http:example.com` are opaque to Android, with
  no host.
- `https:/\evil.com` is hierarchical with no authority and the path `/\evil.com`.
- For the userinfo tricks, Android reports the host after the last `@` (`evil.com`).

**Evidence.**
- Test 103 `characterisesAndroidParsingOfRejectedTricks`, same file as N1.
- `docs/LIMITATIONS.md` L10 (opaque URIs).

**Recorded output (test 103):**
```
[103] <https:\\evil.com> android: opaque=true scheme=https authority=null userInfo=null host=null port=-1 path=null fragment=null | shezguard: Rejected [URI_OPAQUE, URI_BACKSLASH]
[103] <https:/\evil.com> android: opaque=false scheme=https authority=null userInfo=null host=null port=-1 path=/\evil.com fragment=null | shezguard: Rejected [URI_HOST_EMPTY, URI_BACKSLASH]
[103] <https://example.com\@evil.com> android: opaque=false scheme=https authority=example.com userInfo=null host=example.com port=-1 path=\@evil.com fragment=null | shezguard: Rejected [URI_BACKSLASH, URI_USERINFO]
[103] <https://user:pass@example.com/> android: opaque=false scheme=https authority=user:pass@example.com userInfo=user:pass host=example.com port=-1 path=/ fragment=null | shezguard: Rejected [URI_USERINFO]
[103] <https://example.com@evil.com/> android: opaque=false scheme=https authority=example.com@evil.com userInfo=example.com host=evil.com port=-1 path=/ fragment=null | shezguard: Rejected [URI_USERINFO]
[103] <https://example.com:443@evil.com/> android: opaque=false scheme=https authority=example.com:443@evil.com userInfo=example.com:443 host=evil.com port=-1 path=/ fragment=null | shezguard: Rejected [URI_USERINFO]
[103] <https://evil.com#@example.com> android: opaque=false scheme=https authority=evil.com userInfo=null host=evil.com port=-1 path= fragment=@example.com | shezguard: Ok(host=evil.com) []
[103] <https:evil.com> android: opaque=true scheme=https authority=null userInfo=null host=null port=-1 path=null fragment=null | shezguard: Rejected [URI_OPAQUE]
[103] <http:example.com> android: opaque=true scheme=http authority=null userInfo=null host=null port=-1 path=null fragment=null | shezguard: Rejected [URI_OPAQUE]
```

## N3. Which parameter-name characters all three query accessors agree on

**Observation.** Two tests:
- Inside `[A-Za-z0-9_.-]`, `getQueryParameterNames`, `getQueryParameter` and
  `getQueryParameters` agree with each other and with ShezGuard. Test 116 checks this for
  9 fixed names and 300 random names, from 1 to 64 characters, with a fixed seed.
- Test 117 adds one character at a time. Results by character:
  - `*`: all three accessors agree.
  - `@`, `[`, `]`: the name is listed, but neither lookup finds it.
  - `!`, `'`, `(`, `)`, `~`: the name is listed and `getQueryParameter` finds it, but
    `getQueryParameters` returns `[]`.

**Interpretation (not verified against the AOSP source).** The singular lookup behaves as
if it compared `Uri.encode(name)` with the raw query: `Uri.encode` leaves `! ' ( ) * ~`
unencoded and encodes `@ [ ]`. The plural lookup's results fit a form-style encoding of the
name: it finds `a b` for raw `a+b` (N1), and fails for `! ' ( ) ~` but not for `*`.
`java.net.URLEncoder` behaves this way. This explanation is consistent with every observed
row, but it has not been checked against the AOSP source.

**Design consequence.** The conservative set is justified by observation for every listed
character except `*`, where the accessors agree. `*` is still excluded, to keep one small,
explainable set shared by `ParamRule.name`, entry point names and the canonicaliser. That is
a design choice, not an Android inconsistency.

**Evidence.**
- Tests 116 and 117 in
  `shezguard-core/src/test/java/com/shezguard/core/canon/UriCanonicalizerDifferentialTest.kt`.
- `docs/LIMITATIONS.md` L16.

**Recorded output (test 117, 2026-11-10):**
```
[117] <https://example.com/?a@b=1> android: getQueryParameterNames()=[a@b] getQueryParameter("a@b")=<null> getQueryParameters("a@b")=[] Uri.encode("a@b")=a%40b | shezguard: Rejected [PARAM_NAME_INVALID]
[117] <https://example.com/?a!b=1> android: getQueryParameterNames()=[a!b] getQueryParameter("a!b")=<1> getQueryParameters("a!b")=[] Uri.encode("a!b")=a!b | shezguard: Rejected [PARAM_NAME_INVALID]
[117] <https://example.com/?a'b=1> android: getQueryParameterNames()=[a'b] getQueryParameter("a'b")=<1> getQueryParameters("a'b")=[] Uri.encode("a'b")=a'b | shezguard: Rejected [PARAM_NAME_INVALID]
[117] <https://example.com/?a(b=1> android: getQueryParameterNames()=[a(b] getQueryParameter("a(b")=<1> getQueryParameters("a(b")=[] Uri.encode("a(b")=a(b | shezguard: Rejected [PARAM_NAME_INVALID]
[117] <https://example.com/?a)b=1> android: getQueryParameterNames()=[a)b] getQueryParameter("a)b")=<1> getQueryParameters("a)b")=[] Uri.encode("a)b")=a)b | shezguard: Rejected [PARAM_NAME_INVALID]
[117] <https://example.com/?a*b=1> android: getQueryParameterNames()=[a*b] getQueryParameter("a*b")=<1> getQueryParameters("a*b")=[1] Uri.encode("a*b")=a*b | shezguard: Rejected [PARAM_NAME_INVALID]
[117] <https://example.com/?a~b=1> android: getQueryParameterNames()=[a~b] getQueryParameter("a~b")=<1> getQueryParameters("a~b")=[] Uri.encode("a~b")=a~b | shezguard: Rejected [PARAM_NAME_INVALID]
[117] <https://example.com/?a[b=1> android: getQueryParameterNames()=[a[b] getQueryParameter("a[b")=<null> getQueryParameters("a[b")=[] Uri.encode("a[b")=a%5Bb | shezguard: Rejected [PARAM_NAME_INVALID]
[117] <https://example.com/?a]b=1> android: getQueryParameterNames()=[a]b] getQueryParameter("a]b")=<null> getQueryParameters("a]b")=[] Uri.encode("a]b")=a%5Db | shezguard: Rejected [PARAM_NAME_INVALID]
```

## N4. Up to API 29, a parcelled `Uri` can carry a decoded form that contradicts its string form

**Observation (AOSP source).** `android.net.Uri.HierarchicalUri.readFrom(Parcel)` per API
level, read from `platform/frameworks/base` at the first release tag and the latest release
or security tag of each branch (fetched 2026-11-10):

| API | Tags read | Part format in the parcel | Can encoded and decoded disagree? |
|---|---|---|---|
| 24, 25 | `android-7.0.0_r1`, `_r36`; `android-7.1.0_r1`, `7.1.2_r39` | `Part.readFrom` / `PathPart.readFrom` accept `Representation.BOTH` (0): encoded then decoded string, no check | Yes |
| 26, 27 | `android-8.0.0_r1`, `android-security-8.0.0_r54`; `android-8.1.0_r1`, `android-security-8.1.0_r93` | same | Yes |
| 28 | `android-9.0.0_r1`, `android-security-9.0.0_r76` | same | Yes |
| 29 | `android-10.0.0_r1`, `android-security-10.0.0_r75` | same | Yes |
| 30, 31, 32 | `android-11.0.0_r1`, `android-security-11.0.0_r76`; `android-12.0.0_r1`, `android-security-12.0.0_r69`; `android-12.1.0_r1`, `android-security-12.1.0_r7` | one representation per part (`ENCODED` or `DECODED`); the other form is derived | No (by construction) |
| 33 | `android-13.0.0_r1`, `android-security-13.0.0_r33` | as API 30, plus RFC 3986 path handling | No (by construction) |
| 34 | `android-14.0.0_r1`, `android-security-14.0.0_r31` | the whole URI is one string, re-parsed with `StringUri` | No |

On API 24–29, `toString()` (and so `Intent.getDataString()`) and `getHost()` /
`getPathSegments()` / `getQueryParameter()` are computed from the **encoded** form, while
`getAuthority()`, `getPath()`, `getQuery()` and `getFragment()` return the **decoded** form
stored in the parcel. A sender can therefore make `getPath()` return a different path from
the one any string-based validator sees.

**Demonstrated (Robolectric, SDK 29).** A hand-written parcel with encoded path `/product/1`
and decoded path `/admin/../../secret`:
```
[N4] sdk=29 toString=<https://example.com/product/1?id=1> getPath=</admin/../../secret> getEncodedPath=</product/1> getPathSegments=[product, 1]
```
Only `getPath()` disagrees; `getPathSegments()` agrees with the string. A check that compared
only the canonical result with `getPathSegments()` (check (c)1) would have missed it. The
self-consistency check (c)2 (`getPath() == Uri.decode(getEncodedPath())`) blocks it with
`URI_PARSER_MISMATCH` on `uri.path`.

**Why it matters.** It is a validator/consumer differential inside one `Uri` object, reachable
over IPC on API 24–29 (still within minSdk 24). It supports the rule that apps read data from
the `Decision`, and shows why a runtime parser-agreement check must also compare the platform
parser with itself.

**Not verified.** No device or emulator run yet (step 14). Robolectric's SDK 29 `Parcel` is a
JVM emulation. OEM builds and devices without the listed security patches were not examined.
The AOSP commit that removed `BOTH` was not identified (the history pages need sign-in), so no
CVE or bug number is claimed. Whether `Intent` delivery through `system_server` preserves a
crafted `Uri` parcel unchanged on API 24–29 was not tested; the
`Uri.CREATOR`-level demonstration is what is shown.

**Evidence.** `CraftedUriParcelTest` (SDK 29); `ParserMismatchTest` rows for (c)2;
`docs/LIMITATIONS.md` L19.

## N5. `Intent(Intent)` copies extras without unparcelling them (API 24–34)

**Observation (AOSP source, same tags as N4).** On every listed tag, `new Intent(Intent o)`
copies extras with `new Bundle(o.mExtras)`, i.e. `BaseBundle(BaseBundle, deep = false)`. When
the source Bundle is still parcelled, the copy duplicates the raw bytes (`Parcel.appendFrom`)
and never unparcels them. `setDataAndType(Uri, String)` only assigns `mData` and `mType` on
every listed tag.

**Demonstrated (Robolectric, SDK 29 and 34).** An intent received through
`Intent.CREATOR` has parcelled extras. After a Sanitize decision, both the original and the
sanitized copy still report `BaseBundle.isParcelled() == true` (`IntentCopyParcelTest`).

**Caveat.** From API 33 the copy constructor sets the internal flag `mOwnsLazyValues = false`
on the **source** Bundle when its map is already unparcelled. That is a change to private
state of the caller's intent that no public API reports. It is not a change to any value
(`docs/LIMITATIONS.md` L21).

## Source index for step 6 (AOSP and androidx claims)

Every AOSP claim in N6–N9 was read in `platform/frameworks/base` on
`android.googlesource.com`, fetched 2026-11-11 with
`https://android.googlesource.com/platform/frameworks/base/+/refs/tags/<tag>/<path>?format=TEXT`.
One tag per API level (the latest release or security tag of each branch, as in N4):

| API | Tag |
|---|---|
| 24 | `android-7.0.0_r36` |
| 25 | `android-7.1.2_r39` |
| 26 | `android-security-8.0.0_r54` |
| 27 | `android-security-8.1.0_r93` |
| 28 | `android-security-9.0.0_r76` |
| 29 | `android-security-10.0.0_r75` |
| 30 | `android-security-11.0.0_r76` |
| 31 | `android-security-12.0.0_r69` |
| 32 | `android-security-12.1.0_r7` |
| 33 | `android-security-13.0.0_r33` |
| 34 | `android-security-14.0.0_r31` |

Files: `core/java/android/os/BaseBundle.java`, `core/java/android/os/Bundle.java`,
`core/java/android/os/Parcel.java`, `core/java/android/content/Intent.java`.
Line numbers below are for those tags. Other tags of the same branch, OEM builds and devices
without these patches were **not** read.

Marking convention: a claim that has also been exercised by a test is marked with the test
name. Tests run under Robolectric (AOSP Java code, JVM-emulated native `Parcel`), so every such
claim is **Robolectric-only, device check pending (step 14)** unless stated otherwise.

## N6. A failed unparcel leaves a Bundle silently truncated (API 24–34)

**Observation (AOSP source).** The method that unparcels a Bundle catches
`BadParcelableException` only to rethrow it (unless the process-wide `sShouldDefuse` flag is
set, which only `system_server` does), and in its `finally` block installs the map it was
filling and drops the parcel. The map is filled entry by entry, so after an exception it holds
every entry read before the failing one. A second call on the same Bundle sees
`mParcelledData == null`, returns at once, and every accessor then answers from the partial map
without any error. A `RuntimeException` that is not a `BadParcelableException` (for example,
thrown by a hostile `CREATOR`) is not caught there at all, but the same `finally` block runs.

| API | Method (file `BaseBundle.java` unless noted) | `finally { mMap = map; ... mParcelledData = null; }` at line | Entry-by-entry fill |
|---|---|---|---|
| 24 | `unparcel()` | 278 | `Parcel.readArrayMapInternal(ArrayMap, int, ClassLoader)`, `Parcel.java` 2714–2733 (`outVal.append(key, value)` per entry) |
| 25 | `unparcel()` | 278 | same method |
| 26 | `unparcel()` | 266 | same method |
| 27 | `initializeFromParcelLocked(Parcel, boolean, boolean)` | 282 | same method (or `readArrayMapSafelyInternal`) |
| 28–32 | `initializeFromParcelLocked(Parcel, boolean, boolean)` | 298 (28), 302 (29–32) | same |
| 33 | `initializeFromParcelLocked(Parcel, boolean, boolean)` | 459 | `Parcel.readArrayMap(ArrayMap, int, boolean, boolean, ClassLoader, int[])` |
| 34 | `initializeFromParcelLocked(Parcel, boolean, boolean)` | 497 | same, `Parcel.java` 5352–5370 (`map.append` / `map.put` per entry) |

**Why it matters.** An app (or a validator) that catches the exception from its first extras
read and carries on gets a Bundle that silently lacks some keys, with no further error. A
validator that unparcels the **caller's** Bundle and fails would leave the app with that
truncated Bundle. ShezGuard therefore (1) reads only a copy (N7, `getExtras()`), and (2) treats
the first failure as final and never re-reads the same Bundle. See `docs/LIMITATIONS.md` L23.

**Demonstrated (Robolectric SDK 24 and 29; Robolectric-only, device check pending (step 14)).**
`ExtrasUnparcelTest.characterisesPartialMapAfterFailedUnparcel` writes a Bundle holding `"a"`
(a String) and `"zzzz"` (a Parcelable whose `CREATOR` throws), reads it back, and calls
`keySet()` twice. Recorded output (2026-11-11):
```
[N6] sdk=24 first keySet() threw IllegalStateException; second keySet()=[a]
[N6] sdk=29 first keySet() threw IllegalStateException; second keySet()=[a]
```
The behaviour does not occur on SDK 34: the hostile value is lazy there (N7), so `keySet()`
succeeds. The test is **skipped** on SDK 34 by `assumeTrue(!lazyValues)` and JUnit reports it as
skipped. (Until 2026-11-12 it returned early instead, and was reported as passed on SDK 34 while
checking nothing; the earlier text here called that "skipped", which was wrong.)
ShezGuard's mitigation is shown by `callerBundleStaysParcelledAfterUnparcelFailure` and
`repeatedEvaluationGivesTheSameDecision` (SDK 24, 29, 34; Robolectric-only, device check
pending (step 14)).

**Not verified.** Not run on a device. From API 33, lazy values (N7) make a failure in
`initializeFromParcelLocked` rarer, because most attacker-chosen types are no longer
deserialised there; it is still possible for eagerly read types. The partial map on API 33–34
was read in the source but not demonstrated.

## N7. What triggers deserialisation, per API level

**Observation (AOSP source).**
1. `Intent.getExtras()` returns `new Bundle(mExtras)` on every level (`Intent.java`, method
   `getExtras()`, lines 6532 (24), 6564 (25), 7368 (26), 7460 (27), 7770 (28), 8227 (29),
   8575 (30), 8834 (31), 8850 (32), 9267 (33), 9520 (34)). The copy constructor
   `BaseBundle(BaseBundle)` (`BaseBundle.java` line 158 on 24–26, 164 (27), 170 (28),
   173 (29–32); on 33–34 it delegates to `BaseBundle(BaseBundle, boolean deep = false)`, lines
   200 / 206) copies the parcelled bytes with `Parcel.appendFrom` without unparcelling, and
   copies `mClassLoader`. So reading the copy never unparcels the caller's Bundle, and setting
   a class loader on the copy does not change the caller's.
2. `keySet()`, `size()`, `isEmpty()`, `get(String)` and every typed getter call `unparcel()`
   first (all levels).
3. **API 24–32:** unparcelling reads every value with `Parcel.readValue`, so every Parcelable
   `CREATOR` and every Serializable runs at the first `keySet()`.
4. **API 33–34:** unparcelling reads values with `Parcel.readLazyValue`. Types for which
   `Parcel.isLengthPrefixed(int)` returns true become `LazyValue`s and are not deserialised:
   `VAL_MAP`, `VAL_PARCELABLE`, `VAL_LIST`, `VAL_SPARSEARRAY`, `VAL_PARCELABLEARRAY`,
   `VAL_OBJECTARRAY`, `VAL_SERIALIZABLE` (`Parcel.java` line 4695 (33), 4783 (34)). Primitives,
   `String`, primitive arrays, `String[]` and `Bundle` are read eagerly.
5. **API 33–34:** `get(String)` calls `BaseBundle.getValueAt(int, Class, Class...)` (line 390
   (33), 397 (34)), which applies the `LazyValue` and stores the result with `mMap.setValueAt`
   only after it succeeded. A failure is therefore per key: the entry stays lazy and the other
   keys are unaffected.
6. Typed getters (`getString`, `getInt`, ...) catch `ClassCastException` and return `null` or
   the default (e.g. `BaseBundle.getString(String)`, line 991 on 24), so they cannot tell a
   wrong type from an absent key. The typed `get(String, Class)` of API 33+ also catches
   `BadTypeParcelableException` (`BaseBundle.java` 33, line 698).

**Tested (Robolectric-only, device check pending (step 14)).** Points 3 and 5:
`ExtrasUnparcelTest.blocksBundleWhoseParcelableThrowsOnRead` and
`blocksBundleWithParcelableMissingItsCreator` assert a whole-Bundle failure (`Field.Extras`)
on SDK 24 and 29 and a per-key failure (`Field.Extra("evil")`, other key read normally) on
SDK 34. Point 1: `callerBundleStaysParcelledAfterUnparcelFailure` (SDK 24, 29, 34) and
`IntentCopyParcelTest` (SDK 29, 34). Points 2, 4 (beyond the failure behaviour) and 6 were read
in the source only.

**Design consequence.** ShezGuard reads `intent.getExtras()` once, then `keySet()` once, then
`get(key)` for every key (the only accessor that reveals the real type, and the only one that
can find an Intent inside a mixed List or Map). On API 33–34 this deserialises every lazy value,
which the app itself might never have done (`docs/LIMITATIONS.md` L27).

## N8. A nested Intent's extras are resolved with the framework class loader

**Observation (AOSP source).** `Intent.readFromParcel(Parcel)` reads extras with
`mExtras = in.readBundle()` (`Intent.java` line 8704 (24), 8736 (25), 9529 (26), 9644 (27),
10010 (28), 10545 (29), 10905 (30), 11156 (31), 11172 (32), 11601 (33), 11861 (34)), i.e.
`Parcel.readBundle(null)`, which calls `setClassLoader` only for a non-null loader
(`Parcel.readBundle(ClassLoader)`, `Parcel.java` line 1879 (24), 1880 (25), 2150 (26),
2223 (27), 2158 (28), 2278 (29), 2599 (30), 2673 (31, 32), 3321 (33), 3373 (34)). The Bundle is built with
`BaseBundle(Parcel, int)`, which never assigns `mClassLoader` (the only assignments are in
`BaseBundle(ClassLoader, int)`, the copy constructor and `setClassLoader`). With a null loader,
`Parcel.readParcelableCreator` falls back to `getClass().getClassLoader()`, the loader of
`Parcel` itself (`Parcel.readParcelableCreator(ClassLoader)` on 24–32, `readParcelableCreatorInternal` on
33–34; `Parcel.java` line 2512 (24), 2513 (25), 2824 (26), 2894 (27), 2808 (28), 3012 (29),
3336 (30), 3410 (31, 32), 4888 (33), 4996 (34)). On a device
that is the framework (boot) class loader, so app-defined Parcelables inside a nested Intent's
extras fail to resolve. A nested `Bundle` read with `readBundle(loader)` inherits the parent's
loader.

**Why it matters.** The platform already resolves nested-Intent extras with a framework-only
loader. A restrictive loader on ShezGuard's top-level copy would mirror that (evaluated in
step 6, not adopted: it cannot be tested under Robolectric, where one sandbox loader loads both
framework and test classes; revisit in step 14).

**Tested:** nothing in this note. Under Robolectric one sandbox class loader loads both
framework and test classes, so the framework-only behaviour cannot be observed there.

**Not verified.** That the class loader of `Parcel` on ART is the boot class loader; what
`ObjectInputStream.resolveClass` does with a null loader on ART (Serializables); whether
`ActivityThread` sets the app's class loader on the extras of a delivered intent
(`ActivityThread.java` was not read).

## N9. `IntentSanitizer.sanitize(Intent, Consumer<String>)`: messages, component rewrite, versions

**Observation (androidx source).** `androidx/core/content/IntentSanitizer.java` in
`androidx.core:core:1.16.0` (`core-1.16.0-sources.jar` from Google Maven), method
`sanitize(Intent in, Consumer<String> penalty)`:
1. Penalty messages embed raw values from the nested intent, e.g. `"Extra is not allowed. Key: "
   + key + ". Value: " + value`, `"Data is not allowed: " + data`, ClipData text and URIs.
2. A component that is not allowed is **replaced**:
   `intent.setComponent(new ComponentName("android", "java.lang.Void"))`. A `null` component
   (an implicit intent) is treated the same way unless the sanitizer was built with
   `allowAnyComponent()`.
3. Extras are read with `in.getExtras()`, `keySet()` and the deprecated `Bundle.get(key)`; an
   allowed extra is copied as the same object. A nested Intent allowed by an `allowExtra`
   predicate is copied without being sanitized itself.
4. Flags are reduced to `allowedFlags & in.getFlags()`; action, data, type, categories,
   package, ClipData items, identifier (API 29+), selector and source bounds are dropped when
   not allowed.

**Versions.** `IntentSanitizer` is absent from `androidx.core:core:1.8.0` and present from
`1.9.0` with the same `sanitize(Intent, androidx.core.util.Consumer<String>)` signature
(checked with `javap` on both `classes.jar`). Between 1.9.0 and 1.16.0 the method bodies are
the same except that 1.16.0 drops the API 15/16 guards (`Api15Impl`, `Api16Impl`), which are
dead code under minSdk 24 (`diff` of the two source jars, 2026-11-11). AAR metadata
(`META-INF/com/android/build/gradle/aar-metadata.properties`): 1.16.0 requires
`minCompileSdk=35`, `minAndroidGradlePluginVersion=8.6.0`; 1.9.0 requires `minCompileSdk=33`.

**Tested (Robolectric-only, device check pending (step 14)), SDK 24, 29, 34, first against
androidx.core 1.16.0 (step 6) and again against 1.9.0 (2026-11-11, after the switch), with the
same results (574 tests per variant, 0 failures).** Point 2: `NestedIntentTest.blocksNestedIntentWhoseComponentIntentSanitizerRewrites`,
`blocksImplicitNestedIntentWithoutAllowAnyComponent`,
`sanitizesImplicitNestedIntentWithAllowAnyComponent`. Point 3: `blocksDoublyNestedIntentLeftBySanitizer`.
Point 4 (extra, category and grant-flag removal): `sanitizesNestedIntentThroughIntentSanitizer`.
Point 1 is shown indirectly: `intentSanitizerMessagesNeverReachDecisionOutput` checks that no
raw value reaches the decision; the message text itself was read in the source only.

**Dependency (author decision, 2026-11-11).** `:shezguard-core` depends on androidx.core
**1.9.0**, declared `api` because the public constructor `NestedIntentSanitizer(IntentSanitizer)`
exposes the androidx type. This is a minimum: Gradle resolves the highest requested version, so
in the demo `:app` (which uses `core-ktx` 1.16.0) the runtime version is 1.16.0. ShezGuard's own
tests run against 1.9.0; an app's actual version depends on its other dependencies.

**Design consequence.** ShezGuard's penalty consumer discards every message unread (`docs/LIMITATIONS.md` L24). A replaced component is a rewrite, not a removal (SPEC 4.1),
so it is `NESTED_INTENT_DENIED`, not `NESTED_INTENT_SANITIZED` (L25).

## N10. The risk score: what to claim and what not to

**Wording approved by the author for the paper (step 7):**
> ShezGuard's risk score is a transparent, additive tally of a few advisory signals, compared
> with a fixed threshold. It is not learned, adaptive or statistical, and it does not detect
> attacks: every attack-specific check is a HARD rule that blocks regardless of the score. In v1
> there are six soft signals, mostly about caller identity and domain verification, which cannot
> be established reliably (L3). The score exists so that several individually inconclusive
> signals can combine into a Block in a way a developer can read and tune. With the default
> weights, no single signal blocks, and only two strong (HIGH) signals together reach the default
> threshold. Before caller signals are implemented (step 8), the score cannot change any outcome
> under default settings.

**Facts behind it.**
- Score = sum over distinct SOFT codes of their weights, capped at 100; blocked when
  `score >= threshold` (default 70). Each code counts once; the explanation records how often it
  occurred (`ScoreContribution.occurrences`).
- Default weights (design choices, not empirically derived): 5 for the four LOW soft codes,
  50 for the two HIGH ones (`CALLER_NOT_ALLOWED`, `DOMAIN_NOT_VERIFIED`).
- Exhaustive check: of the 64 subsets of the six soft codes, 28 contain an exclusive pair and
  cannot be emitted; over the other 36, no single signal blocks, every set with at most one HIGH
  signal stays below 70 (the largest such sets score 65), and every set with two HIGH signals
  blocks (`WeightedScorerTest.defaultWeightsOverAllEmittableSubsetsOfSoftSignals`).
- The score can only add a Block; a fixed-seed property test over 5000 random weight maps,
  thresholds and violation lists shows no weights unblock a HARD violation
  (`noCombinationOfWeightsTurnsHardIntoAllowOrSanitize`).
- Before step 8 only `URI_NON_CANONICAL` and `PARAM_UNKNOWN_IGNORED` are ever emitted, so the
  default maximum is 10 and the score cannot change any outcome under default settings
  (`ScoringEvaluateTest.defaultWeightsCannotChangeAnOutcomeBeforeStep8`).

**Do not claim:** that the score detects attacks, adapts, is calibrated, or reduces false
positives. None of that has been measured.

## Source index for step 8 (caller identity)

Same repository and tags as the step 6 index above (fetched 2026-11-11). Additional files:
`core/java/android/app/Activity.java`, `ActivityOptions.java`, `ActivityThread.java`,
`Instrumentation.java`; `core/java/android/content/pm/PackageManager.java`, `SigningInfo.java`,
`verify/domain/DomainVerificationManager.java`, `verify/domain/DomainVerificationUserState.java`;
server side under `services/core/java/com/android/server/`: `am/ActivityManagerService.java`,
`am/ActivityStarter.java`, `am/ActivityRecord.java`, `am/ActivityStackSupervisor.java` (24–28),
`wm/ActivityTaskManagerService.java` (29–30), `wm/ActivityClientController.java` (31–34),
`wm/ActivityStarter.java`, `wm/ActivityRecord.java`, `wm/ActivityTaskSupervisor.java` (29–34),
`pm/AppsFilter.java` (30–31), `pm/AppsFilterImpl.java` / `pm/AppsFilterBase.java` (33–34).
Not every file was read at every level; each claim names the levels read.

**Every claim in N11–N13 is source-read or Robolectric-only and unconfirmed on device** (step 14).

## N11. `Activity.getReferrer()` reads, and unparcels, the caller's extras

**Observation (AOSP source, API 24–34).** `Activity.getReferrer()` (`Activity.java` line 5008 (24),
5028 (25), 5303 (26), 5318 (27), 5425 (28), 6042 (29), 6193 (30), 6276 (31), 6279 (32), 6481 (33),
6741 (34)) first calls `getIntent().getParcelableExtra(Intent.EXTRA_REFERRER)`, then
`getStringExtra(Intent.EXTRA_REFERRER_NAME)`, and only if both are absent returns the system
referrer `mReferrer` as `android-app://<package>`. It catches only `BadParcelableException`.

**Why it matters.** Reading the referrer, an identity API, unparcels the caller's own Bundle: on
API 24–32 every value is deserialised (N7), any other exception from a hostile `CREATOR` escapes,
and a failure leaves the Bundle truncated (N6). The referrer also prefers caller-set extras over the
system value.

**Demonstrated (Robolectric SDK 24, 29, 31, 34; Robolectric-only, device check pending (step 14)).**
With the guard removed from `ActivityCallerSource`, the test
`systemReferrerIsNotReadWhenItWouldUnparcelTheCallersExtras` fails on all four SDKs because the
activity's parcelled Bundle is unparcelled; with the guard it passes.

**Design consequence.** ShezGuard calls `getReferrer()` only when the delivered intent and
`activity.intent` both have `getExtras() == null` (a null check that never unparcels), and reads
the referrer extras from its own copy (`docs/LIMITATIONS.md` L31).

## N12. Caller identity describes the launch, not a later `onNewIntent` delivery

**Observation (AOSP source).**
- `getCallingPackage()` returns `resultTo.info.packageName` of the activity's record
  (`getCallingRecordLocked` / `getCallingRecord`: `am/ActivityManagerService.java` 6989 (24),
  8296 (28); `wm/ActivityTaskManagerService.java` 2290 (29), 2443 (30);
  `wm/ActivityClientController.java` 565 (31), 688 (34)).
- `getLaunchedFromUid/Package()` return the record's `launchedFromUid` / `launchedFromPackage`
  (`wm/ActivityClientController.java` 571 (31), 694 and 707 (34)).
- In `ActivityRecord`, `resultTo`, `launchedFromUid` and `launchedFromPackage` are assigned in the
  constructor only (`am/ActivityRecord.java` 607/617 (24); `wm/ActivityRecord.java` 951/960 (29),
  1633/1642 (31), 2012/2021 (33), 2099/2108 (34)); later assignments only clear `resultTo` or
  restore state. `deliverNewIntentLocked` (34, line 4905) passes the new launcher only as the
  referrer string.
- On the client, `ActivityThread.deliverNewIntents` (2776 (24) ... 3954 (34)) calls
  `Instrumentation.callActivityOnNewIntent(Activity, ReferrerIntent)` (1229 (24), 1314 (26),
  1372 (28), 1406 (29), 1416 (30), 1436 (31), 1491 (33), 1563 (34)), which sets `mReferrer` to the
  new intent's referrer **only for the duration of `onNewIntent`** and restores the old value in
  `finally`. `getReferrer()` still checks `getIntent()` (the old intent, unless the app called
  `setIntent`) first.

**Consequence.** For an intent delivered to `onNewIntent`, all three sources can describe the
earlier launch. ShezGuard takes the intent and a `Delivery` explicitly and reports no reliable
identity, and no system referrer, for `Delivery.NEW_INTENT`.

**Tested (Robolectric-only, device check pending (step 14)).**
`newIntentDeliveryHasNoReliableIdentity`, `newIntentDeliveryIgnoresTheSystemReferrer`,
`newIntentDeliveryStillReadsReferrerExtrasOfTheNewIntent` (SDK 24, 29, 31, 34). Robolectric does not
run the server; the staleness itself is source-read only.

## N13. Reliable sources, package visibility and signing certificates

**Observation (AOSP source).**
- **Shared identity (API 34).** `Activity.getLaunchedFromUid()` / `getLaunchedFromPackage()` are
  `@hide` on 31–33 (`Activity.java` 6355/6364 (31), 6562/6571 (33)) and public on 34 (6846/6879).
  `ActivityClientController.canGetLaunchedFromLocked` (742, 34) returns the identity only if
  `r.mShareIdentity` (set from `ActivityOptions.isShareIdentityEnabled()`, `ActivityRecord.java`
  2089) or the same uid, under compat change `ACCESS_SHARED_IDENTITY` (line 147), which has no
  `@EnabledSince`; platform-signed, system and installer callers are exempt
  (`isInternalCallerGetLaunchedFrom`).
- **Forward result.** `ActivityStarter` (274 (24), 624 (28), 663 (29), 988 (34)) transfers
  `sourceRecord.resultTo` to the new activity for `FLAG_ACTIVITY_FORWARD_RESULT`, so
  `getCallingPackage()` names the original requester.
- **System referrer.** `launchedFromPackage` is passed as the referrer
  (`am/ActivityStackSupervisor.java` 1298 (24); `wm/ActivityTaskSupervisor.java` 929 (34), through
  `ActivityRecord.getFilteredReferrer`, present on 33 and 34 but not 31, which nulls it when the
  receiver cannot see the launcher). The caller-supplied `callingPackage` is checked against the
  caller's uid by `assertPackageMatchesCallingUid` from API 30 (`ActivityTaskManagerService.java`
  1057 (30); absent at 29).
- **Visibility.** `ActivityStarter` calls `PackageManagerInternal.grantImplicitAccess` with the
  started app as recipient and the result recipient as visible (1690 (30), 1768 (31), 1884 (33),
  1793 (34)), and on 34 also the launcher when `mShareIdentity` (1799). `AppsFilter` keeps these in
  `mImplicitlyQueryable` (30: line 468; 34: `AppsFilterBase.isImplicitlyQueryable` 217). No
  `AppsFilter` exists at API 29 (no visibility filtering before 30).
- **Certificates.** `PackageManager.hasSigningCertificate` (34, line 10339) matches certificates
  the package "was or is signed by", i.e. the lineage too. `SigningInfo.getApkContentsSigners()`
  (34, line 115) returns the current signers only; `getSigningCertificateHistory()` (92) returns the
  lineage. `GET_SIGNING_CERTIFICATES` exists from 28 (line 504 (28), 1166 (34)); `GET_SIGNATURES`
  (249 (24)) is deprecated from 28. `SigningInfo` does not exist before 28 (HTTP 404 at 24–27).
- **Domain verification.** `DomainVerificationManager` and `DomainVerificationUserState` exist from
  31 (HTTP 404 at 24–30). `getDomainVerificationUserState(packageName)` (330 (31, 34)) returns
  `null` if the app declares no web domains; `DOMAIN_STATE_SELECTED` means chosen by the user, not
  verified; `isLinkHandlingAllowed()` (229) and `getHostToStateMap()` (237) are public.

**Tested** (Robolectric-only, device check pending (step 14)): current-signer matching, multi-signer
and rotated-key rejection through Robolectric's `ShadowSigningInfo`. **Not tested at all**:
visibility grants (Robolectric does not enforce visibility), the API 34 shared-identity path and
real domain verification state (fakes only).

**Not read:** server-side code for 25, 27 and 32; OEM changes.

## Source index for step 10 (Activity integration)

Same repository and tags as the step 6 and step 8 indexes (fetched 2026-11-12). Files and levels
read for this step:
- `core/java/android/app/Activity.java` and `core/java/android/app/ActivityThread.java`: 24, 28, 29,
  31, 34.
- `core/java/android/app/Application.java`: 24, 34.
- Server side: `am/ActivityRecord.java` and `am/ActivityStackSupervisor.java` (24);
  `wm/ActivityRecord.java` and `wm/ActivityTaskSupervisor.java` (31, 34);
  `wm/ActivityClientController.java` (34).
- Robolectric 4.14.1 `ActivityController.java` and `ComponentController.java`
  (`shadows-framework-4.14.1-sources.jar`), to know what the tests can and cannot show.

**Not read:** API 25–27, 30, 32 and 33 at all; the server side at 28 and 29; the restart path
through `attachApplication` line by line; any androidx source (`ComponentActivity`,
`FragmentActivity`, `SavedStateRegistry`, Navigation, Hilt); OEM changes.

## N14. Where an Activity helper can run, and what recreation re-delivers

Every claim is source-read or Robolectric-only, and **unconfirmed on device** (step 14).

**1. Lifecycle callbacks cannot guard an Activity (source).**
- `ActivityLifecycleCallbacks.onActivityCreated` is dispatched from the **base**
  `Activity.onCreate`, after fragment state has been restored (`mFragments.restoreAllState`,
  `Activity.java` 957 (24), 1716 (34)): dispatch at line 961 (24), 1048 (28), 1475 (29), 1607 (31),
  1720 (34). It therefore runs when the app calls `super.onCreate`, after restored fragments were
  created, and before whatever the app does after `super.onCreate`. `finish()` there does not stop
  that code.
- `onActivityPreCreated` (API 29+) is dispatched from `performCreate` before `onCreate`
  (`Activity.java` 7796 (29), 8040 (31), 8587 (34)); it does not exist at 24–28
  (`Application.java` 57–64 (24) lists only `onActivityCreated` … `onActivityDestroyed`).
  `onActivityPostCreated` runs after `onCreate` returns (7811 (29), 8061 (31), 8611 (34)).
- `Application.ActivityLifecycleCallbacks` has no `onNewIntent` method at 24 or 34
  (`Application.java` 57 (24), 70–214 (34)).

**2. An activity finished in `onCreate` skips start and restore (source).**
- API 24: `performLaunchActivity` calls `performStart`, `callActivityOnRestoreInstanceState` and
  `onPostCreate` only `if (!r.activity.mFinished)` (`ActivityThread.java` 2608–2622).
- API 28–34: `handleStartActivity` returns early when `r.activity.mFinished`
  (`ActivityThread.java` 2931 (28), 3288 (29), 3649 (31), 3796 (34)), before
  `performStart` and before `callActivityOnRestoreInstanceState` / `callActivityOnPostCreate`
  (2949 / 2961 (28); 3819 / 3832 (34)).
- Robolectric's `ActivityController.setup(Bundle)` and `recreate()` call `start()` and
  `restoreInstanceState()` unconditionally, so this cannot be shown under Robolectric.

**3. The base `onCreate` restores framework fragments only from the Bundle it is given (source and
test).** `Activity.onCreate` reads `FRAGMENTS_TAG` from `savedInstanceState` only when it is
non-null (`Activity.java` 955–958 (24), 1712–1717 (34)). Passing `null` to `super.onCreate` on Block
therefore prevents the restore. `performCreate` still passes the original Bundle to two
framework-internal readers, `restoreHasCurrentPermissionRequest` and
`mActivityTransitionState.readState` (`Activity.java` 8595, 8605 (34)); no app code runs there.
Shown (SDK 24, 29, 31, 34) by `blockedRecreationDoesNotRestoreFrameworkFragments`, with an allowed
recreation as control. androidx base classes were not read (see the index).

**4. Rotation keeps the current intent; process death re-delivers the original one (source).**
- **Relaunch in the same process** (configuration change): `handleRelaunchActivityInner` saves
  `r.activity.mIntent` as `customIntent` ("Preserve last used intent, it may be set from
  Activity#setIntent()", `ActivityThread.java` 5913–5914 (34); `handleRelaunchActivity` 4427 (24)),
  and `performLaunchActivity` puts it back (`activity.mIntent = customIntent`, 2586 (24), 3740 (34)).
  After a Sanitize, the new instance's `getIntent()` is the sanitized copy.
- **New process** (after process death): the launch transaction carries `new Intent(r.intent)`
  (`ActivityStackSupervisor.realStartActivityLocked`, 1296 (24);
  `ActivityTaskSupervisor.realStartActivityLocked`, 845 (31), 923 (34)), and `ActivityRecord.intent`
  is `final`, "the original intent that generated us" (`ActivityRecord.java` 116 (24), 445 (31),
  484 (34)). `getIntent()` is the **raw launch intent** again: a Sanitize replacement and any
  `setIntent` from `onNewIntent` are lost.
- **Identity across both:** `resultTo`, `launchedFromUid`/`launchedFromPackage` (N12) and, on 34,
  `mShareIdentity` (`ActivityRecord.java` 2089) live on the server-side record, which outlives the
  app process. `getCallingPackage()` reads `r.resultTo` (`ActivityClientController.java` 688–690
  (34)); `getLaunchedFromPackage()` checks `r.mShareIdentity` (744 (34)). The launch transaction
  passes `launchedFromPackage` as the referrer (1298 (24), 851 (31); filtered on 34, 929). So the
  identity seen at recreation is the identity of the original launch.

**5. A task restored after reboot loses reliable identity (source).** `ActivityRecord.restoreFromXml`
(1423 (24), 8412 (31), 10066 (34)) restores `launchedFromUid` and `launchedFromPackage`; on 34 the
record is built with no result-to activity and no `ActivityOptions` (builder chain, 10115–10126), so
`resultTo` is null and `mShareIdentity` is false. `getCallingPackage()` and
`getLaunchedFromPackage()` then report nothing, and an enforcing allow-list
(`requireReliableIdentity = true`) blocks a legitimate recreation. When the OS persists a task
across reboot was **not** checked.

**6. Consequences for the helper (design, tests).**
- The guard runs before `super.onCreate` and evaluates on every creation; re-evaluation after process
  death is required by point 4. `processDeathRedeliversTheRawIntentAndItIsSanitizedAgain` uses
  Robolectric's `recreate()`, which re-attaches the controller's original intent (process-death
  behaviour); rotation is simulated by building the new instance with the old instance's
  `getIntent()` (`rotationReevaluatesSanitizedIntentAsAllowWithIdenticalCanonicalData`: the sanitized
  intent re-evaluates to Allow with equal `GuardedUri`).
- **Identity attribution after `onNewIntent` plus rotation.** After an allowed `onNewIntent`,
  `getIntent()` is the new intent; rotation keeps it (point 4); the guard re-evaluates it as
  `LAUNCH`, and the record's original identity is attributed to it
  (`rotationAfterNewIntentAttributesLauncherIdentityToTheLatestIntent`, simulated: Robolectric's
  calling package is set on the new instance by hand).
- **Enforcing caller rules ignore every `onNewIntent`**, because `NEW_INTENT` has no reliable source
  (N12; `requireReliableIdentityIgnoresEveryNewIntent`).
- **Skipping `super.onNewIntent`** on `android.app.Activity` does not throw and leaves the activity
  usable (`skippingSuperOnNewIntentDoesNotThrowAndActivityStaysUsable`); `setResult`, `setIntent`
  and `finish()` before `super.onCreate` do not throw
  (`finishSetResultAndSetIntentBeforeSuperOnCreateDoNotThrow`). Both SDK 24, 29, 31, 34, Robolectric
  only.

**Not verified.** API 25–27, 30, 32, 33 (not read); server-side behaviour at 28 and 29; when the OS
persists a task across reboot; whether extras survive `Intent.restoreFromXml`; the restart path
through `attachApplication`; androidx `ComponentActivity` / `FragmentActivity` / `SavedStateRegistry`
behaviour with a `null` `savedInstanceState`, and whether `ComponentActivity.onNewIntent` dispatches
to `addOnNewIntentListener` listeners (`docs/LIMITATIONS.md` L35); Hilt's injection point; anything
on a device or emulator.
