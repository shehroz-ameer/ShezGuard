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
