# Prover — Architecture & Security Design

A zero-knowledge TOTP authenticator sync backend, in Go.

This document is the design you're building against. Read it top to bottom once,
then use it as a reference while you implement. Every "why" here is a question an
interviewer will ask you about this project.

---

## 1. What you are building (and what you are NOT)

There are two completely different systems people call "2FA backend". Be precise
about which one you're writing, because the crypto is different.

| | **Relying party** (what a website runs) | **Authenticator sync backend** (this project) |
|---|---|---|
| Role | Verifies your 6-digit code at login | Stores your TOTP secrets so you can back them up / move devices |
| Holds | The secret it issued to *you* | Secrets issued by *other* services (Google, GitHub, your bank…) |
| Must be able to | Compute the current code | **Never** compute the code |
| Analogy | The lock | The keyring |

You are building the keyring. This is the Authy / 1Password / Bitwarden model.

That distinction drives the single most important architectural decision:

> **The server must be able to store the user's TOTP secrets without ever being
> able to read them.**

This is called **zero-knowledge** or **end-to-end encrypted (E2EE)** storage.
Everything else in this document follows from it.

Note the one exception: Prover has its *own* login, and you may later want to
protect that login with TOTP. There, Prover *is* the relying party and does hold
the secret. Keep those two code paths mentally and physically separate — they
live in different packages for exactly this reason.

---

## 2. Threat model — decide who the enemy is before you write code

Security design is meaningless without naming the attacker. Write this down and
revisit it whenever you add a feature.

### T1 — Database dump (the one that actually happens)
Attacker gets a full copy of MongoDB: every document, every field.
**Requirement:** the dump contains no usable TOTP secrets and no usable passwords.
**Defense:** client-side encryption + Argon2id password hashing.

### T2 — Server compromise (attacker has RAM, code execution, TLS terminated)
Attacker reads live requests and process memory.
**Requirement:** they still cannot read vault contents, because plaintext secrets
never enter the server process at all.
**Defense:** the E2EE boundary is the device, not the TLS connection.

### T3 — Network attacker
MITM, replay, downgrade.
**Defense:** TLS 1.3, HSTS, certificate pinning in the mobile client later.

### T4 — Credential stuffing / brute force
Attacker has a leaked password list and hammers `/login`.
**Defense:** per-account + per-IP rate limits, lockout with jitter, Argon2id cost.

### T5 — Malicious or curious *insider* (you, in prod)
You have DB access and could look.
**Defense:** same as T1. Zero-knowledge means you *cannot* look, which is also
your best legal and marketing position.

### T6 — Stolen session token
Attacker steals an access or refresh token off a device.
**Defense:** short-lived access tokens, refresh-token rotation with reuse
detection, device revocation.

### Explicitly OUT of scope (be honest about this)
- **Malicious client build.** If you ship an app update that uploads plaintext,
  E2EE is over. Mitigated only by open-sourcing the client / reproducible builds.
- **Weak user passwords.** Argon2id makes offline cracking expensive, not
  impossible. `password123` still dies.
- **Metadata.** The server learns: how many secrets you have, when you add/change
  them, your IP, your device model, your login times. That is a genuine leak.
  Bitwarden and Authy have it too. Don't claim otherwise.
- **Compromised endpoint device.** Malware on the phone reads the decrypted vault.

---

## 3. The key hierarchy — the heart of the design

This is the part to understand deeply. Everything else is plumbing.

The problem: the server needs to (a) check you know your password, and (b) store
data you can decrypt — without (c) being able to decrypt it. Those look
contradictory. They aren't, because you derive *two independent keys* from the
password and only ever give the server one of them.

```
   password  +  client_kdf_salt (32 random bytes, per-user, stored server-side)
        │
        │   Argon2id   m=64 MiB, t=3, p=4, len=32     ← slow ON PURPOSE
        ▼
   ┌──────────────────────────────────────────┐
   │  MASTER KEY (MK, 32 bytes)               │   never leaves the device.
   │  never transmitted, never stored anywhere│   not even in device storage.
   └──────────────┬───────────────────────────┘
                  │
        HKDF-SHA256(MK, info=...)      ← cheap, one-way, domain-separated
                  │
      ┌───────────┴────────────┐
      ▼                        ▼
 AUTH KEY (AK)            KEK (key-encryption key)
 info="prover|auth|v1"    info="prover|enc|v1"
      │                        │
      │ sent to server         │ NEVER sent. Wraps the Vault Key.
      │ over TLS at login      │
      ▼                        ▼
 server stores            server stores
 Argon2id(AK, server_salt)  Enc(KEK, VaultKey) ── an opaque blob to the server
```

And a second layer of indirection for the data itself:

```
 VAULT KEY (VK) = 32 bytes from crypto/rand, generated ONCE at signup on-device
        │
        ├── stored on server as WrappedVK = AEAD(KEK, VK, aad="vk|"+userID)
        ├── stored on server as RecoveryWrappedVK = AEAD(RecoveryKey, VK, ...)
        │
        └── encrypts every vault item:
              blob = AEAD(VK, json{issuer,account,secret,digits,period,algo},
                          aad = userID || itemID || version)
```

### Why split MK into AK and KEK instead of just sending the password hash?

Because HKDF is a pseudorandom function: knowing `AK` tells you *nothing* about
`KEK`, even though both come from `MK`. So the server can hold `AK` forever and
still be unable to derive the key that opens the vault. If you skipped this and
sent `MK` itself, a compromised server could decrypt everything on the spot —
zero-knowledge would be a lie.

The `info` strings matter. They're **domain separation**: they guarantee the two
outputs are unrelated. Version them (`v1`) so you can rotate the scheme later.

### Why does the server hash AK again with Argon2id?

`AK` arrives over the wire and gets stored. If you stored it raw, a DB dump would
hand the attacker a working login credential for every user. Hashing it means the
dump is useless for login. It's cheaper than hashing the raw password server-side
(the client already did the expensive work), so you can afford a real cost here.

### Why the Vault Key indirection? Why not encrypt items with KEK directly?

Three concrete wins, all of which you'd otherwise have to hack in later:

1. **Password change is O(1).** New password → new MK → new KEK → re-wrap 32
   bytes. Without VK, changing your password means downloading, decrypting, and
   re-encrypting every item — slow, and catastrophic if it fails halfway.
2. **Recovery is possible.** Wrap the same VK a second time with a Recovery Key
   printed at signup. Lose the password, keep the vault.
3. **Multi-device is trivial.** A new device pulls `WrappedVK`, unwraps it with
   the KEK it derived locally, and it's in sync. No key transport protocol.

This pattern — a random data key wrapped by a derived key — is called
**envelope encryption**. You'll see it again in AWS KMS, in disk encryption
(LUKS), everywhere.

### Where does the KDF salt come from?

The client needs `client_kdf_salt` *before* it can log in, so there's an endpoint
`POST /auth/prelogin {email}` that returns it plus the KDF parameters.

That's a **user enumeration oracle**: unknown email → 404 tells an attacker who
has an account. Fix: for unknown emails return a *deterministic fake* salt,
`HMAC-SHA256(server_secret, lowercase(email))`, with default KDF params. Same
shape, same timing, no signal. This kind of thing is what separates a project
that "has auth" from one that was designed.

### Better option you should know exists: OPAQUE / SRP

An **augmented PAKE** (Password-Authenticated Key Exchange) lets the client prove
knowledge of the password without ever sending anything password-derived, and
removes the enumeration oracle entirely. OPAQUE (RFC 9807) is the modern one; SRP
is the older one Apple and 1Password use.

It is strictly better than the scheme above. It is also significantly harder to
implement correctly and easy to get subtly wrong. **Build the Argon2 + HKDF split
first** (Bitwarden ships this in production), get it working, then read the
OPAQUE RFC and treat migrating to it as your stretch goal. Mentioning in your
README that you know the difference and why you chose the simpler one is worth
more than a broken PAKE.

---

## 4. Cryptographic primitives — what to use and why

Rule zero: **use `crypto/*` and `golang.org/x/crypto/*`. Never implement a
primitive yourself.** Your job is to compose primitives correctly. That's where
real systems break anyway.

### Password hashing / KDF → **Argon2id**
`golang.org/x/crypto/argon2`, `argon2.IDKey()`.

- **Argon2id**, not `i` or `d`. `id` is the hybrid: side-channel resistance from
  `i` plus GPU resistance from `d`. It's the OWASP default recommendation.
- **Not** bcrypt (max 72 bytes, no memory hardness), **not** PBKDF2 (cheap on
  GPUs), **not** SHA-256 (fast is the *opposite* of what you want here).
- Parameters: `m=64 MiB, t=3, p=4, keyLen=32`. Memory hardness is the point — an
  attacker's GPU has thousands of cores but not thousands × 64 MiB of RAM.
- **Store the parameters in the user document.** In two years you'll want to
  raise the cost. If parameters are hardcoded, you can't upgrade existing users
  without breaking them. Re-derive and upgrade on next successful login.

### Key derivation from a key → **HKDF-SHA256**
`crypto/hkdf` (Go 1.24+) or `golang.org/x/crypto/hkdf`.

Use HKDF when you already have a *high-entropy* key and want several from it.
Use Argon2 when the input is a *low-entropy* password. Confusing these is a
classic mistake: HKDF on a password is nearly free to brute-force.

### Symmetric encryption → **XChaCha20-Poly1305**
`golang.org/x/crypto/chacha20poly1305`, `chacha20poly1305.NewX()`.

- It's an **AEAD**: encryption *and* authentication in one. Never use raw
  ChaCha20 or AES-CTR/CBC. Unauthenticated ciphertext is malleable — an attacker
  who can flip bits in your DB can corrupt or manipulate plaintext, and padding
  oracles are a whole genre of exploit.
- **Why XChaCha20 over AES-256-GCM:** the nonce is 24 bytes instead of 12. With
  12 bytes you cannot safely pick nonces at random at scale (birthday collision
  around 2³² messages), so you need a counter, which means state, which means
  bugs. With 24 bytes, `crypto/rand` is safe essentially forever. **Nonce reuse
  in GCM is catastrophic** — it leaks the authentication key, not just the
  plaintext. XChaCha20 removes the footgun.
- Secondary reason: ChaCha20 is fast and constant-time in *software*. AES is only
  fast and constant-time with AES-NI hardware. Your clients are phones.
- **Always set the AAD.** Additional Authenticated Data is authenticated but not
  encrypted. Bind each ciphertext to `userID || itemID || version`. Without it, a
  malicious server can (a) move Alice's blob into Bob's row, or (b) roll an item
  back to an older ciphertext. Both decrypt fine and both are attacks. With AAD,
  they fail authentication.

### Randomness → **`crypto/rand`, always**
`math/rand` is a PRNG for simulations. Using it for keys, nonces, salts, tokens,
or recovery codes is an instant, total break. There is no exception.

### Comparing secrets → **`crypto/subtle.ConstantTimeCompare`**
`==` and `bytes.Equal` return early on the first differing byte. That timing
difference leaks how much of a token you got right, which is enough to recover it
byte by byte over many requests. Use `subtle` for TOTP codes, tokens, MACs,
anything secret.

### Hashing opaque high-entropy tokens → **SHA-256**
Refresh tokens are 32 random bytes — no entropy problem, so you don't need a slow
hash. Store `SHA-256(token)`. Argon2 here would just be a self-inflicted DoS.

### Signing → **Ed25519 (EdDSA)** for JWTs
Not HS256. Asymmetric signing means services can *verify* without holding the
key that can *mint*, and it structurally avoids the `alg` confusion attack class
(HMAC-vs-RSA key confusion, `alg: none`). **Pin the algorithm on verification.**
Never trust the `alg` header from the token.

---

## 5. TOTP itself (RFC 6238)

Even though your server doesn't compute user codes, implement this — you need it
to validate parsing, to write tests, and for your own login's 2FA.

```
K  = shared secret (Base32-encoded in the otpauth:// URI, RFC 4648, no padding)
T0 = 0, X = 30 (seconds)
T  = floor((unixTime - T0) / X)                 → 8-byte big-endian counter

H  = HMAC-SHA1(K, T)                            → 20 bytes
o  = H[19] & 0x0F                               → dynamic truncation offset
bin= (H[o]&0x7F)<<24 | H[o+1]<<16 | H[o+2]<<8 | H[o+3]
code = bin mod 10^digits                        → zero-padded to `digits`
```

Notes that matter:

- **TOTP is just HOTP (RFC 4226) with a time-derived counter.** Implement HOTP,
  then TOTP is three lines on top. Your code should reflect that.
- **Why SHA-1 in 2026?** SHA-1 is broken for *collision resistance*. HMAC-SHA1
  does not depend on collision resistance, so it is not affected — HMAC-SHA1 is
  still considered secure. RFC 6238 permits SHA-256/512, but essentially every
  issuer in the wild emits SHA-1. You use SHA-1 for **interoperability**, not
  because you think it's better. Support the others via the `algorithm` param.
- **Why the `0x7F` mask?** Clears the top bit so the value is unambiguously
  positive across languages with signed integers.
- **Why dynamic truncation at all?** Rather than fixing which 4 bytes to take, it
  selects them based on the hash output itself, avoiding any fixed-position bias.
- **Verification window:** accept `T-1, T, T+1` for clock skew. Wider windows
  multiply an attacker's guessing odds — a 6-digit code is only ~20 bits.
- **Replay protection:** if the server ever verifies a code, record the last
  accepted counter per user and reject anything `<=` it. Without this, a code
  sniffed once is valid for the rest of its 30-second window.
- The `otpauth://` URI is **untrusted input** — it comes from a QR code a user
  scanned from who-knows-where. Bound `digits` (6–8), `period` (>0), enforce a
  max URI length, and reject unknown `algorithm` values instead of defaulting.

---

## 6. System design — the layers, and why

```
                    ┌─────────────────────────────────────┐
   HTTP request ───▶│  cmd/server        wiring, shutdown │
                    └───────────────┬─────────────────────┘
                                    ▼
                    ┌─────────────────────────────────────┐
                    │  internal/httpapi                   │  TRANSPORT
                    │   router, middleware, handlers      │  decode → validate
                    │   DTOs (never expose domain structs)│  → call → encode
                    └───────────────┬─────────────────────┘
                                    ▼
                    ┌─────────────────────────────────────┐
                    │  internal/auth   internal/vault     │  BUSINESS LOGIC
                    │   services: rules, orchestration    │  knows nothing about
                    │   depend on STORE INTERFACES only   │  HTTP or Mongo
                    └───────────────┬─────────────────────┘
                                    ▼
                    ┌─────────────────────────────────────┐
                    │  internal/store  (+ store/mongo)    │  PERSISTENCE
                    │   interfaces here, Mongo impl below │
                    └─────────────────────────────────────┘

   ┌──────────────────────┐        ┌──────────────────────┐
   │ internal/domain      │        │ internal/crypto      │
   │  structs + errors    │        │  pure functions      │
   │  imported by all     │        │  NO I/O, NO imports  │
   │  imports nothing     │        │  from other layers   │
   └──────────────────────┘        └──────────────────────┘
```

**Dependencies point one direction only: down.** `httpapi` → `auth` → `store`.
Never the reverse. `domain` and `crypto` are leaves that everyone may import and
that import nothing of yours.

### Why this shape, specifically

- **`crypto` has zero dependencies and does no I/O.** That means (a) it's
  unit-testable against RFC 4226/6238 published vectors with no mocks, and (b)
  your entire security-critical surface is one small package a reviewer can read
  in an afternoon. If crypto code is smeared across HTTP handlers, nobody can
  audit it, including you.
- **Services depend on interfaces, not `*mongo.Collection`.** You can test the
  whole login flow against a 40-line in-memory store — no Docker, no DB, tests in
  milliseconds. This is the single change that most improves whether you actually
  write tests.
- **Handlers contain no business logic.** Decode, validate, call, encode. That
  gives you exactly one place to audit for input validation, and it means your
  business rules aren't accidentally coupled to Gin.
- **Separate DTOs from domain structs.** If you `c.JSON(200, user)` you will leak
  `auth_hash` the day someone adds a field. Explicit response structs make
  leaking a deliberate act, not an accident.
- **`internal/`** is enforced by the Go compiler — nothing outside this module
  can import it. Free encapsulation.

### On your current layout
`Log/`, `URLParser/`, `Test/`, `models/` at the repo root with capitalised
directory names isn't idiomatic Go and will confuse reviewers. Go convention is
lowercase, single-word package names, code under `internal/`, binaries under
`cmd/`. See §10 for the specific migration.

---

## 7. Data model (MongoDB)

Field names are the wire/DB names. Note what is and isn't readable by the server.

### `users`
```jsonc
{
  "_id":            "ObjectId",
  "email":          "lowercase, unique index",
  "email_verified": false,

  // --- server-side auth ---
  "auth_hash":      "base64",          // Argon2id(AuthKey, auth_salt) — NOT the password
  "auth_salt":      "base64, 16B",     // server-generated
  "server_kdf":     { "m": 65536, "t": 3, "p": 4, "v": 19 },

  // --- client-side KDF (public-ish, served by /prelogin) ---
  "client_kdf_salt":"base64, 32B",
  "client_kdf":     { "alg": "argon2id", "m": 65536, "t": 3, "p": 4 },

  // --- opaque to the server ---
  "wrapped_vault_key":          { "ct": "b64", "nonce": "b64", "alg": "xchacha20poly1305" },
  "recovery_wrapped_vault_key": { "ct": "b64", "nonce": "b64", "alg": "..." },

  "security_stamp": "uuid",   // bump ⇒ every outstanding access token dies
  "revision":       142,      // monotonic per-user sync cursor
  "failed_logins":  0,
  "locked_until":   null,
  "status":         "active|locked|deleted",
  "created_at": "...", "updated_at": "..."
}
```

### `vault_items` — the server sees only ciphertext
```jsonc
{
  "_id":       "ObjectId",
  "user_id":   "ObjectId",       // index: {user_id: 1, revision: 1}
  "ct":        "base64",         // AEAD(VK, item JSON)
  "nonce":     "base64, 24B",
  "alg":       "xchacha20poly1305",
  "aad_ver":   1,
  "version":   7,                // optimistic-concurrency token
  "revision":  142,              // server-assigned, for sync
  "deleted":   false,            // TOMBSTONE, not a hard delete
  "created_at": "...", "updated_at": "..."   // SERVER clock only
}
```
The decrypted plaintext (which only the device ever sees) is:
`{issuer, account, secret, digits, period, algorithm, type, counter, notes}` —
i.e. exactly your existing `ParsedURI`.

### `sessions` (refresh tokens)
```jsonc
{
  "_id": "...", "user_id": "...", "device_id": "...",
  "token_hash":  "SHA-256 of the refresh token — never the token",
  "family_id":   "uuid",     // rotation lineage, for reuse detection
  "used":        false,
  "expires_at":  "...", "created_at": "...",
  "ip_hash": "...", "user_agent": "...", "revoked": false
}
```

### `audit_log`
```jsonc
{ "user_id": "...", "event": "login_success|login_fail|item_create|...",
  "ip": "...", "ua": "...", "ts": "...", "meta": {} }   // NEVER secrets
```

---

## 8. API surface

```
POST   /v1/auth/register           email, client_kdf_salt, kdf params,
                                   auth_key, wrapped_vault_key,
                                   recovery_wrapped_vault_key
POST   /v1/auth/prelogin           {email} → kdf params + salt (enumeration-safe)
POST   /v1/auth/login              {email, auth_key} → access + refresh + wrapped VK
POST   /v1/auth/refresh            rotate; reuse ⇒ kill the whole family
POST   /v1/auth/logout             revoke this session
POST   /v1/auth/verify-email

GET    /v1/vault/items?since=<rev> changed items + tombstones since revision
POST   /v1/vault/items             create (client supplies ciphertext)
PUT    /v1/vault/items/:id         If-Match: <version> → 409 on conflict
DELETE /v1/vault/items/:id         tombstone
GET    /v1/vault/key               wrapped vault key

POST   /v1/account/password        {new auth_key, new salt, re-wrapped VK} — atomic
POST   /v1/account/recovery/rotate

GET    /v1/devices                 list
DELETE /v1/devices/:id             revoke

GET    /healthz  /readyz           unauthenticated, no detail leakage
```

### Sync design
- **Server-assigned monotonic `revision` per user.** Never sync on client
  timestamps — client clocks are wrong, skewed, or lied about deliberately.
- **Pull is a delta:** `?since=<rev>` returns everything with a higher revision,
  including tombstones, so deletions propagate to other devices.
- **Push is optimistic-concurrency:** client sends the `version` it last saw. If
  it doesn't match, return `409` and let the client resolve. Last-write-wins
  silently destroys data on two devices edited offline.
- **Tombstones, not hard deletes.** Garbage-collect after ~30 days.

### Session design
- **Access token:** JWT, Ed25519, **15 minutes**. Claims: `sub, sid, jti, iat,
  exp, sstamp`. Short lifetime is what makes a stateless token acceptable —
  you can't revoke a JWT, so it must expire fast.
- **`sstamp` = the user's `security_stamp`.** Password change or "log out
  everywhere" bumps it, and every outstanding access token fails validation
  instantly with no blocklist to maintain.
- **Refresh token:** 32 bytes from `crypto/rand`, opaque, stored as SHA-256,
  **rotated on every use**. If a token is presented twice, that means someone
  cloned it → revoke the entire `family_id`. This is how you detect theft rather
  than just hoping it doesn't happen.
- Bearer tokens only, no cookies → **CSRF does not apply**. Say that explicitly
  in your README so a reviewer knows it was a decision, not an omission.

---

## 9. Security features checklist

Transport & headers
- [ ] TLS 1.3, HSTS, redirect 80→443
- [ ] `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout` on
      `http.Server` — the defaults are unlimited, which is Slowloris-by-default
- [ ] `MaxHeaderBytes`, `MaxBytesReader` on every body
- [ ] Locked-down CORS allowlist (not `*`), strict `Content-Type` checking

Auth
- [ ] Argon2id with stored, upgradeable parameters
- [ ] Generic errors: `"invalid credentials"` for both bad email and bad password
- [ ] Enumeration-safe `/prelogin` (deterministic fake salt)
- [ ] Per-IP **and** per-account rate limits; lockout with exponential backoff + jitter
- [ ] Argon2id is itself a DoS vector — always behind the rate limiter
- [ ] `subtle.ConstantTimeCompare` for every secret comparison
- [ ] Pin the JWT algorithm on verify; reject `none`

Data
- [ ] Vault contents encrypted client-side; server stores opaque blobs
- [ ] AAD binds ciphertext to user + item + version (anti-swap, anti-rollback)
- [ ] Server-side envelope encryption of *metadata* (email, device name) as
      defense-in-depth, key from env/KMS
- [ ] Per-user item count and per-blob size caps
- [ ] Tombstones + retention policy

Operational
- [ ] **Never log secrets.** Give domain types a `Redact()`/`MarshalLogObject`.
      *Your current `parser.go` logs the full parsed URI including the TOTP
      secret — fix this first.*
- [ ] Structured logs with request IDs; panic-recovery middleware
- [ ] Audit log for auth events; alert on anomalies
- [ ] Secrets from env/KMS; **`.env` and `main.exe` must be gitignored** (they
      are currently not — add a `.gitignore` before your next commit)
- [ ] `govulncheck`, `go vet`, `staticcheck` in CI
- [ ] Graceful shutdown; least-privilege Mongo user; non-root container

---

## 10. Fixes to your existing code

Real findings, in priority order. Each one is a lesson.

1. **`parser.go` logs the secret.**
   `log.Log.Info("parsed uri", zap.Any("parsed", parsed))` writes the TOTP secret
   to disk in plaintext, forever, outside all your encryption. Logs get shipped
   to third parties, backed up, and read by ops. This one line defeats the whole
   design. Redact it.

2. **`log.Log.Fatal` on bad input.** `zap`'s `Fatal` calls `os.Exit(1)`. A
   malformed URI from any user takes down your entire server — a one-request DoS.
   Library code returns `error`; only `main` decides to exit.

3. **`URIParser` returns nothing.** It should be
   `func Parse(uri string) (*domain.OTPAuth, error)`. Right now the result is
   unreachable.

4. **`strconv.ParseInt(s, 10, 8)`** — bitSize 8 caps at 127. A HOTP counter
   legitimately exceeds that. Use `64`. Also, the current code overwrites the
   defaults with `0` before checking `err`, so `digits` silently becomes 0 when
   the parameter is absent. Parse into a temp and only assign on success.

5. **Unvalidated `parts[0]`** — `strings.SplitN(label, ":", 2)` on a label with
   no colon gives `len(parts) == 1`, and the code reads `parts[1]`. It's guarded
   today, but the guard `Fatal`s (see #2). Also handle URL-encoded labels.

6. **Module path has a `.git` suffix** — `github.com/spryzz3n/2Factor-Auth.git`.
   Drop the `.git`; it breaks `go get` for consumers.

7. **`go.mod` marks everything `// indirect`** including Gin, which you import
   directly. Run `go mod tidy`.

8. **No `.gitignore`; `.env` and `main.exe` are in the tree.** Add one now.

9. **Layout & naming.** `loagENV.go` is a typo of `loadENV.go`. Suggested
   migration (do it in one commit, before there's more code):

   ```
   main.go            → cmd/server/main.go
   config/            → internal/config/
   Log/               → internal/logger/
   models/            → internal/domain/
   URLParser/         → internal/otpauth/
   router/            → internal/httpapi/
   Test/              → delete; use *_test.go next to the code it tests
   ```

10. **Global `log.Log`.** Package-level mutable globals are convenient and then
    become the reason nothing is testable. Pass the logger into constructors.

---

## 11. Build order

Don't build breadth-first. Each phase should end with something you can run.

| Phase | Deliverable | Done when |
|---|---|---|
| 0 | `internal/crypto`: HOTP, TOTP, Argon2id, HKDF, AEAD | RFC 4226 & 6238 vectors pass |
| 1 | `internal/otpauth`: parser returning errors, fuzz-tested | `go test -fuzz` finds no panics |
| 2 | Config, logger with redaction, `/healthz`, graceful shutdown | server starts and stops cleanly |
| 3 | `domain` + `store` interfaces + in-memory store | services testable without Mongo |
| 4 | Register / prelogin / login, Argon2id, Ed25519 JWTs | full auth flow via curl |
| 5 | Refresh rotation + reuse detection, devices, logout | replayed refresh kills the family |
| 6 | Vault CRUD + delta sync + optimistic concurrency | two clients converge; conflict → 409 |
| 7 | Password change, recovery key | password change doesn't touch item blobs |
| 8 | Rate limiting, audit log, hardening checklist | §9 all ticked |
| 9 | Mongo implementation behind the interfaces | integration tests green |
| 10 | CI: `go vet`, `staticcheck`, `govulncheck`, coverage | pipeline green |

**Phase 0 first, always.** Everything else depends on the crypto being right, and
it's the only part with published test vectors to check yourself against.

---

## 12. Running what's here now

```bash
cd Prover
go mod tidy                       # fixes the // indirect markers
go test ./internal/crypto/...     # RFC 4226 + 6238 vectors, AEAD, key separation
go test ./internal/otpauth/...
go test -fuzz=FuzzParse -fuzztime=30s ./internal/otpauth
go vet ./...
go run ./cmd/server               # will nil-panic until you wire it up — expected
```

`internal/crypto` and `internal/otpauth` are complete and tested. Everything else
is a skeleton whose method bodies `panic("TODO")`, with each TODO naming the
security property that implementation must satisfy. Start at Phase 0 above and
work down.

Your original files (`main.go`, `Log/`, `URLParser/`, `models/`, `router/`,
`config/`, `Test/`) are untouched — migrate and delete them when you're ready
(§10.9). The module currently builds both; that's temporary.

---

## 13. Reading list

- RFC 4226 — HOTP
- RFC 6238 — TOTP
- RFC 5869 — HKDF (read §3.1 on the `info` parameter)
- RFC 9106 — Argon2
- RFC 9807 — OPAQUE (for phase 2 of your life)
- Google Authenticator `otpauth://` Key URI Format (the de-facto spec)
- OWASP Password Storage Cheat Sheet
- OWASP API Security Top 10
- Bitwarden Security Whitepaper — the closest published design to this one
