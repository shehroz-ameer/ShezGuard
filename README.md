# ShezGuard

Work in progress. The full README (usage, threat model, limitations, comparison with
`IntentSanitizer`) is written in step 16 of `docs/PROMPTS.md`.

## Reading deep link data

Read URI data from the `Decision`, never from `getIntent().getData()`:

```kotlin
when (val d = ShezGuard.evaluate(intent, policy, "product")) {
    is Decision.Allow    -> show(d.data?.param("id"))
    is Decision.Sanitize -> show(d.data?.param("id"))   // forward d.sanitizedIntent if needed
    is Decision.Block    -> finish()
}
```

`GuardedUri` exposes only the parameters your policy **declares**. Parameters kept under
`Unknown.Ignore` are not readable through it, but they **remain in the original intent**
(`Decision.Allow.intent`), so code that reads `getIntent()` directly still sees them
(`docs/LIMITATIONS.md` L20). Use `Unknown.Drop` to have them removed from a sanitized copy.

See `docs/SPEC.md` and `docs/LIMITATIONS.md`.
