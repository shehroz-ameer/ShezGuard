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

**Recorded output (test 111):**
```
[111] <https://example.com/?q=a+b> android: getQueryParameterNames()=[q] getQueryParameter("q")=<a b> getQueryParameters("q")=[a+b] | shezguard: [(q, a b)]
[111] <https://example.com/?a+b=1> android: getQueryParameterNames()=[a+b] getQueryParameter("a+b")=<null> getQueryParameters("a+b")=[] getQueryParameter("a b")=<null> getQueryParameters("a b")=[1] | shezguard: [(a b, 1)]
[111] <https://example.com/?%69d=5> android: getQueryParameterNames()=[id] getQueryParameter("id")=<null> getQueryParameters("id")=[] | shezguard: [(id, 5)]
```

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
