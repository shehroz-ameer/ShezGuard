# Attack matrix

The full matrix (attack, vulnerable result, protected result, test name, notes) is built in
step 12 of `docs/PROMPTS.md`, once the demo app and the attack scripts exist. Until then this
file only records what is known **not** to be covered, so it cannot be forgotten.

## Not covered in v1

| Attack surface | Threat (SPEC section 2) | Why not covered | Limitation |
|---|---|---|---|
| An Intent held inside a custom `Parcelable` or `Serializable` extra | 1 (intent redirection) | Object fields are opaque to ShezGuard; only framework containers are searched | `docs/LIMITATIONS.md` L26 |
| `ClipData` of the incoming intent (including `ClipData.Item` intents and URIs) | 1 | Only extras are inspected; ClipData is checked only on nested intents, by `IntentSanitizer` | L26 |
| The selector of the incoming intent (`Intent.getSelector()`) | 1 | Not inspected | L26 |
| URI-permission grant flags (`FLAG_GRANT_*_URI_PERMISSION`) on the incoming intent | 1 | Flags are not inspected; on nested intents they depend on the developer's `IntentSanitizer` | L26 |
