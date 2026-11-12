# `:attacker`: attacker app for the demo (emulator only)

> **Warning.** For emulators only. Never install it on a phone you use and never publish it. It is
> marked `android:testOnly="true"` and has no INTERNET permission. It only targets
> `com.shezguard.router`, the deliberately vulnerable demo app in `:app`.

It sends what `adb` cannot express, and declares the intent filters an attacker app would.

| Component | Used by | What it does |
|---|---|---|
| `AttackActivity` (`-e attack nested`) | `t1` | starts `ForwardActivity` with an Intent extra `next` targeting the non-exported `InternalAdminActivity` |
| `AttackActivity` (`-e attack serializable_unknown`) | `t5` | sends `ProfileActivity` a Serializable of a class the demo app does not have |
| `AttackActivity` (`-e attack gadget`) | `t5 gadget` | sends `ProfileActivity` a `com.shezguard.router.demo.LegacyProfile` (same name and `serialVersionUID` as the demo's class) |
| `HijackActivity` | `t4` | declares `shezdemo://login` and `https://shezguard.example/login`; logs any token it receives |
| `LandingActivity` | `t3` | declares `https://attacker.invalid`; logs `CANARY-REDIRECT-LANDED` |

Logs use the tag `ShezAttacker`. No dependencies beyond the Android SDK (and the Kotlin standard
library). Step 14 will add caller-identity modes (`startActivityForResult`,
`FLAG_ACTIVITY_FORWARD_RESULT`, `setShareIdentityEnabled`, referrer variants).

```sh
./gradlew :attacker:installDebug
adb shell am start -n com.shezguard.attacker/.AttackActivity -e attack nested
```
