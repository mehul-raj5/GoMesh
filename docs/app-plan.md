# GoMesh app plan: macOS + iOS first

Approved revision 3 · 2026-10-15 · Phases 0–7 built (Phases 4–7 uncommitted); Phase 7's EC2 run is yours

## What we are building

A Signal/WhatsApp-style chat app for macOS and iOS, built from one SwiftUI codebase on top of
the existing Go crypto and protocol. The Go code is compiled into an XCFramework with gomobile.

- **First priority: username + password accounts.** These need TLS and a server that persists
  data, so all three ship together.
- **One account, one device.** Signing in somewhere new *moves* the account there:
  - you stay in all your groups
  - every conversation keeps its ID
  - the old device is signed out and its keys are wiped
- **Chat history stays on the device** that received it. Like WhatsApp, a later account on the
  same device can still read it, but can't send in those chats.
- **Themes:** the 22 themes (the 20 from the reference picker, plus Telegram Light and Dark, which are the defaults) plus *Auto*, with a GoMesh house theme in
  place of "Texora".
- **Colorful:** every contact gets an avatar color and a sender-name color from the active
  theme's palette. Outgoing bubbles use the theme's accent color.
- **The terminal client stays.** It becomes a thin shell over the same engine and remains our
  second test client. I read "signal/wp/terminal" as Signal/WhatsApp-style. If "terminal" meant
  Telegram, the design target is the same.

No code changes until this plan is approved.

---

## Decisions (defaults, change any before approving)

| Decision | Default | Alternative and what would flip it |
| :--- | :--- | :--- |
| UI stack | **SwiftUI multiplatform app** (one codebase for macOS and iOS) + Go engine via `gomobile bind` | **Flutter + Go via `dart:ffi`**: one UI that also covers Windows. The costs are Dart, a hand-written C bridge, installing Flutter, and a less native feel on Apple. Pick it if shipping Windows soon matters more than Apple polish. |
| Signing in on a new device | **The account moves.** Same user ID, same conversations, same group memberships and roles (via a signed `rekey` entry). Peers see "safety number changed". The old device is signed out and its keys are wiped. | none. One account = one device is a product rule. |
| Who can change a member's keys in a group | **The member's new device, signing with its new key.** See *The trade-off* below. | Require the old device or an admin to co-sign, at the cost of people losing groups when the old device is gone |
| An earlier account's history on a device | **Stays, read-only** (WhatsApp-like). The sign-out dialog offers to delete it. | Lock each account's history behind its own password |
| Where keys and chats live | **Keychain, wrapped by the Secure Enclave,** for the keys. **Sealed files with opaque names** for per-chat crypto state and history. See *Storage on the device*. | Whole-database encryption (SQLCipher) to hide even message counts, if the Phase 0 SQLite spike shows a cgo build works on iOS |
| The offline queue when a device is replaced | **Deleted for good.** The new device starts with an empty queue, and the old device is sent a fire-and-forget "replaced" notice. | none |
| Password transport | **TLS 1.3** on the existing TCP port. Dev uses a self-signed cert whose fingerprint the client pins | OPAQUE (the server never sees the password). Possible later; much more complex |
| Password hashing | **argon2id** (`golang.org/x/crypto/argon2`, already in the dependency tree) | none |
| Server storage | **SQLite** via `modernc.org/sqlite` (pure Go, no cgo), one file | Supabase Postgres (you already have a project), at the cost of a network dependency for every login |
| Minimum OS | macOS 14, iOS 17 (needed for `@Observable`) | none |
| House theme | **GoMesh Light / GoMesh Dark** | none |

---

## One account, one device

- An **account** is a username, a password and a user ID. The server issues the user ID once,
  and it never changes.
- A **device** holds the crypto: identity key, signing key, prekeys, ratchet sessions and sender
  keys. It can be replaced.
- An account is signed in on exactly one device at a time. A data directory counts as one
  device. So during testing, the TUI and the app on the same Mac need separate accounts, or
  each signs the other out.

### Moving to a new device (Mac → iPhone)

| Who | What they see |
| :--- | :--- |
| You, on the iPhone | All your groups, with no history. Each direct chat appears as new when you or the other person next writes. |
| People you DM | The same conversation with history intact, a "safety number changed" line, then the chat carries on |
| Your groups | You are still a member with the same role, history is intact for everyone else, and there's a "*name* changed devices" notice |
| Your Mac | Signed out. Its crypto keys are wiped, and its chat history stays readable. |

You were right that conversation IDs survive the move. `handleDirectInit` builds a direct
chat's ID as `HashIDs(userA, userB)`, and user IDs belong to the account, not the device.

**1. The server, when the iPhone signs in with the password and new keys.** Your user ID stays
the same, so every conversation ID does too. Steps 1–5 below happen under one lock (one
transaction once the server persists), so nothing can slip into the wrong queue between them:

1. **Replace the keys** in the directory and create a new device record. **The offline queue
   belongs to the device, not the account,** so the new device starts with a new, empty queue.
2. **Permanently delete the old device's queue.** Everything in it was encrypted for the Mac
   and is unreadable on the iPhone. Once queues are in SQLite (Phase 3), `secure_delete` is on
   so the rows are overwritten, not just unlinked. Any group changes in the old queue aren't
   lost, because `CtrlMyGroups` and the log fetch in step 2 cover them.
3. **Revoke the Mac's token,** recording the reason "replaced". The revocation record is kept,
   so a Mac that was offline learns why on its next connect: resume returns `DeviceReplaced`,
   not a generic `SessionRevoked`, and the Mac wipes its keys then.
4. **Send `DeviceReplaced` to the Mac, fire-and-forget.**
   - The old client is marked replaced, and the notice goes in as its last packet through a
     non-blocking `enqueue`.
   - Its `writeLoop` writes the notice, then closes the connection. The notice can't be written
     directly from the login goroutine, because `writeLoop` is the connection's only writer and
     two writers would interleave packets on the wire.
   - If the send buffer is full, or the Mac is offline, the notice is simply dropped. It's
     never queued offline, and nothing waits for an acknowledgement. Step 3 is the backstop.
5. **Close the Mac's connection and discard its unsent backlog.** Three paths push packets
   back into the offline queue today:
   - `writeLoop` defers `spill`
   - a failed `writePacket` requeues its packet
   - `sendPacket` falls back to the queue when `enqueue` fails

   Any of them would put old-device packets into the new device's queue. With queues keyed by
   device, one rule covers all three: **`queueOffline` for a device record that no longer
   exists drops the packet, and never creates a queue.**
6. Only then does the server:
   - start delivering to the iPhone
   - send `CtrlKeyChange [UserID 16][PreKeyBundle 164]` to everyone who shares a conversation
     with you, queued for anyone offline ahead of anything sent later
   - send the iPhone `CtrlMyGroups`, the IDs and names of every group you belong to

**2. The iPhone, for each group:**

1. Fetches the membership log and verifies it from the create.
2. Finds itself listed with the old keys.
3. Submits a signed `rekey` entry.

It retries on every connect until each entry is accepted.

**3. The `rekey` entry** is a new `ActionRekey = 7` in `common.Membership`. The server and the
clients share that state machine, so they enforce the same rule.

- It names you as both actor and target, and carries your new identity and signing keys.
- **It is the only action whose signature is checked against keys carried in the entry itself.**
  Every other action is checked against the actor's key as the log records it.
- It is valid only if:
  - the actor and target are the same person
  - that person is already a member
  - the keys differ from the current ones
  - the role stays the same
- Anything else is refused. There is a test for each refusal case:
  - a rekey for someone else
  - a role change smuggled in
  - keys identical to the current ones
  - a non-member
- The server also checks that the submitter is you and that the keys match its directory. It
  already checks the second point for every entry.
- **What every member does on receiving it:**
  - forgets your old sender keys
  - marks its own sender key for replacement, through the existing `PeerKeysChanged` path,
    exactly as for a removal plus an add
  - on its next send, gives the new key to your iPhone over a fresh 1:1 session, opened from
    the bundle hint that travels with the entry

  The Mac can therefore read nothing new, even if it was stolen.
- **Admins stay admins,** so nobody has to re-add anyone and a group's only admin can move
  devices too.

**4. Which keys a peer trusts for you.** Today two checks would fight here:
`newResponderState` drops a handshake whose key differs from the directory, and `group.go:916`
refuses a session whose key differs from the group log. The new rule:

- **Direct chats follow the server's directory,** as they do today. On `CtrlKeyChange` a peer
  closes its session with you and keeps the new bundle. Its next message starts a fresh
  handshake that your iPhone builds the session from.
- **A handshake whose key doesn't match is held, not dropped,** and the roster is fetched again.
  If the server confirms the new key, the session is replaced and the chat shows "safety number
  changed".
- **Groups accept your new keys only from the signed `rekey`,** never from the server's notice.
- **Sender keys go to your iPhone once both have happened.** The check in `group.go` stays as
  it is, and is satisfied once the rekey is applied.

**5. What is lost.** Messages already on their way to you at the moment you switch were
encrypted for the Mac, so the iPhone can't read them. One backstop handles this: when the iPhone
receives a message it can't read and has no session for, it sends the sender a rate-limited
`CtrlSessionReset`. The sender's client restarts the session and shows "*name* may not have
received your last message". This also fixes the README limitation where a device that lost its
state had to tell its user to run `/dm`.

### The trade-off

Today the server can't change group membership at all. After this change it still can't add or
remove anyone. But a `rekey` is signed only by the *new* key, because the old device may be
lost. So **a malicious server could rekey a member to keys it controls**, take over that
member's seat, and receive everyone's new sender keys.

- That is the same trust Signal places in its server when someone re-registers. It is also the
  same as direct chats today until safety numbers are compared.
- What makes it visible:
  - every member sees "*name* changed devices"
  - safety numbers still detect a substituted key
- Hardening for later:
  1. If you've verified someone's safety number, your client asks before accepting their new
     keys.
  2. When the old device is still available, it co-signs the move, so no warning is needed.
- The README's security summary is updated in the same phase.

### Signing out and switching accounts

- **Signing out,** whether you chose it or were replaced (`DeviceReplaced`, `SessionRevoked`),
  deletes:
  - the account key (see *Storage on the device*)
  - the identity key and prekeys
  - ratchet sessions and sender keys
  - the session token

  Every crypto record was sealed with that account key, so any bytes left behind in flash or
  in SQLite's free pages can no longer be decrypted. The server revokes the token. The
  account's chat history and its history key stay.
- **A token presented with different device keys is refused, and the password is required.**
  iOS keeps Keychain items when an app is reinstalled but wipes its files, so a stale token can
  come back with fresh keys.
- **Messages sent to you while you're signed out are lost,** because they're encrypted to keys
  that no longer exist. Optionally, the server could withdraw your bundle at sign-out, so new
  chats fail visibly ("*name* is signed out") instead of disappearing.

### Chat history shared on a device (WhatsApp-like)

- **One history store per device** (per app install). Each account's rows are sealed with that
  account's own history key.
  - It is kept apart from the crypto state, because `StateStore` wipes itself whenever the
    identity key changes.
- **Rows are tagged per account.** If accounts A and B chatted with each other on this device,
  both sides of that chat have the same conversation ID, so a tag can't be the conversation
  ID alone.
- **When signed in as B:**
  - A's chats appear in a "Previous account: A" section and are read-only.
  - Instead of a composer, they show "This chat belongs to A".
- **If A signs in on this device again,** A's chats become writable again with history intact.
  New sessions start, so peers see "safety number changed".
- **The sign-out dialog** offers "Also delete A's chat history from this device", off by
  default. Choosing it deletes A's history key as well as the rows, so the delete holds even
  where the storage doesn't really erase.
- **Privacy:** anyone who signs in on this device can read earlier accounts' history. That is
  the behavior you described. Locking each account's history with its password is the
  alternative, if you want it.

### Storage on the device

The Secure Enclave can only hold P-256 keys, not our Curve25519/Ed25519 ones. So the Enclave
**wraps** the small keys we keep in the Keychain, and those keys seal everything on disk.
Nothing that changes on every message goes into the Keychain.

```
Secure Enclave            P-256 wrapping key: never leaves the chip, needs no Face ID
│                         (so background reconnect works)
└─ wraps everything in ↓

Keychain                  this device only, never synced to iCloud, readable after first unlock
├─ account key            random per signed-in account. Deleted at sign-out or replacement.
├─ identity keys          identity X25519 + Ed25519 seed + signed prekeys, sealed with the account key
├─ history key (per acct) random. Deleted only by "delete this account's history".
└─ session token

App folder                Application Support/GoMesh, readable after first unlock
├─ state/7c1e…            one sealed record per conversation (ratchet, sender keys). Never backed up.
├─ history.db             chats: only opaque tags and sequence numbers are in clear
└─ media/a93f…            downloaded files, encrypted, with random names
```

**Per-conversation crypto state (`state/`).** Today the files are `session-<convIDhex>.gob` and
`group-<id>.gob`, in plaintext.

- **Each file name becomes an HMAC of the conversation's record name, under the account key.**
  Naming files by the conversation ID itself would not hide anything:
  - the server knows every conversation ID
  - a DM's ID is a hash of two user IDs, which anyone holding both IDs can compute
- **The real record name is stored inside the sealed record and bound to it as associated
  data.** A file copied over another conversation's file then fails to open, instead of
  loading the wrong session.
- **There's no separate index.** A record's file name is a deterministic HMAC of its record
  name, so `Load` and `Save` find it directly. Only `List`, used today at `ratchet.go:460` and
  `group.go:348` with filename prefixes, has to enumerate. It opens each file and reads the
  record name sealed inside, which is cheap for a few hundred records. Each record therefore
  stays one atomically written file: an index would be a second file to keep in step, and a
  crash between the two writes could lose a session.
- **Records are sealed with XChaCha20-Poly1305 under the account key.**
- **The folder is excluded from backups. This is mandatory, not optional.** Restoring an older
  ratchet, even onto the same phone, would reuse message keys that were already spent.

**Chats (`history.db`).**

- `conversations(tag, sealed)` and `messages(tag, seq, sealed)`.
- The tag is an HMAC of the account ID and conversation ID, under that account's history key.
- Everything else is inside `sealed`: names, members, sender, timestamp, text, status.
- The associated data is `tag ‖ seq`, so rows can't be swapped or reordered.
- `PRAGMA secure_delete = ON`.
- History is excluded from backups too. Its key never leaves the device, so a backup restored
  anywhere else would be unreadable anyway.

**What someone browsing the folder still sees:** how many chats there are, how many messages
each holds and roughly how big they are, and when files change. They do not see who the chats
are with, the names, the times, or any text. Whole-database encryption (SQLCipher) would hide
the counts too. It needs a cgo build that works on iOS, so it depends on the Phase 0 SQLite
spike and isn't promised.

**Media.** Today downloads are saved as plaintext in `downloads/`. In the app they stay
encrypted under random names.

- They are sealed with the account's **history key**, not the account key. Otherwise a previous
  account's read-only chats would show broken attachments, and "delete history" wouldn't
  remove them.
- They are decrypted into a temporary folder for viewing, which is cleared afterwards.
- They are saved in the clear only when you choose *Save* or *Share*.

**Apple specifics:**

- **Keychain items survive an uninstall on iOS.** On first launch, a missing marker file means
  a fresh install, so leftover GoMesh Keychain items are deleted. The marker lives in the
  backup-excluded folder, so a restore from backup also looks like a fresh install and runs
  the same wipe.
- **The simulator has no Secure Enclave.** There, the keys go into the Keychain unwrapped. This
  is an explicit, tested code path, logged as a warning.
- **On the Mac, the data-protection Keychain and the Secure Enclave both need signing
  entitlements** (a keychain access group). Phase 0 checks they work with your signing setup.
- **Face ID app lock (Phase 7) only gates the UI.** If the keys needed Face ID, the app
  couldn't reconnect in the background.
- **Recent macOS versions also ask you before another app reads a sandboxed app's container.**

**How the Go engine reaches the Keychain.** Through a small `Vault` interface (`Get`, `Put`,
`Delete` for named secrets) that the host app implements:

- **The Apple app** implements it in Swift, with the Keychain and the Secure Enclave. The Go
  code never touches Apple APIs.
- **The TUI** implements it with 0600 files. It's a test client, so it gets no real protection.
- **Windows** will implement it later with DPAPI.

---

## Phase 0: foundations and spike (no visible change)

- **Commit the tests.** `.gitignore` contains `*_test.go`, so none of the 189 tests are tracked.
  Remove that line and commit them before anything else, because later phases change tested
  crypto code.
- Whitelist the new top-level dirs in `.gitignore` (`core/`, `bridge/`, `apps/`, `design/`,
  `docs/`, `Makefile`).
- Add a `Makefile` with these targets: `test`, `server`, `tui`, `dev-cert`, `xcframework`, `app`.
- **Spike:**
  1. Install gomobile.
  2. Bind a tiny Go package into `GoMeshCore.xcframework` (`-target=ios,iossimulator,macos`).
  3. Load it from a hello-world SwiftUI app on the Mac and the iOS 18.6 simulator.
  4. Check that gomobile works with our `go.work` workspace. If it doesn't, `bridge/` gets its
     own module with `replace` directives.
  5. Open a `modernc.org/sqlite` database from the bound package and confirm it runs on the
     simulator. Its supported platforms list darwin, not ios, so this is not a given. The
     fallbacks are `mattn/go-sqlite3` (gomobile already builds with cgo), or keeping history in
     a gob store of its own. Also check whether a SQLCipher build is practical.
  6. Store a Secure Enclave–wrapped secret in the data-protection Keychain on the Mac, using
     your signing setup, and read it back. Confirm the simulator takes the fallback path.

**Done when:** a string from Go, a row read back from SQLite, and a Keychain secret all
round-trip in the app on the Mac and in the iPhone simulator.

**Result (2026-10-15): done.**

- **gomobile works with `go.work`.** `bridge/` is a workspace module, and `make xcframework`
  builds iOS, simulator and macOS slices in about 40 s.
- **`modernc.org/sqlite` builds and runs on `ios/arm64`.** SQLite 3.53.4 round-trips a row on
  both the Mac and the simulator.
- **The Secure Enclave works on the Mac even unsigned,** and also in the simulator on Apple
  silicon. So the no-Enclave fallback is not exercised here, and it will need a forced-path
  test.
- **The data-protection Keychain on the Mac fails with `-34018`** (missing entitlement). The
  Mac has no code-signing identity. An unsigned Debug build falls back to the legacy login
  keychain, and a Release build never does. **To fix:** add your Apple ID in Xcode → Settings →
  Accounts (a free Personal Team is enough), then set `DEVELOPMENT_TEAM` in
  `apps/apple/project.yml`. The simulator uses the data-protection Keychain already.
- **`mutecomm/go-sqlcipher/v4` compiles for iOS** with its bundled crypto. It hasn't been run,
  so whole-database encryption stays possible later.
- **Minor:** some of the framework's cgo objects still report macOS 27 as their minimum,
  despite `MACOSX_DEPLOYMENT_TARGET=14.0`. The linker only warns. This needs fixing before the
  app runs on macOS older than the build machine.

## Phase 1: accounts, username + password (first priority)

### Server (`server/`)

- **`store.go`:** SQLite, WAL mode.
  - `users(id, username UNIQUE, password_hash, identity_key, signing_key, bundle, created_at)`
  - `devices(token_hash, user_id, device_name, created_at, last_seen)`
  - Only the token's SHA-256 is stored. Nothing needs migrating, because today nothing survives
    a restart.
- **`auth.go`:**
  - argon2id with a per-user salt, stored as a PHC string. Parameters are tuned to about 250 ms
    per hash. Hashes are compared in constant time.
  - **Attempts are throttled per username and per IP *before* hashing.** A semaphore caps
    concurrent hashes at about 4. At roughly 64 MB per hash, unthrottled logins would be a
    memory DoS.
  - Usernames are 3–32 characters from `[a-z0-9_.]`, unique regardless of case.
  - Passwords were 8–128 characters and checked against a small embedded list of common
    passwords. For the testing phase that is relaxed to anything non-empty up to 512 bytes
    (`common.CheckPassword`); bring the rules back before real use.
- **TLS:**
  - The listener is wrapped in `crypto/tls` (TLS 1.3 only), configured with the `TLS_CERT` and
    `TLS_KEY` environment variables.
  - `make dev-cert` generates a self-signed pair.
  - The server logs the cert's SHA-256 fingerprint at startup.
  - Nothing at the OS level forces TLS on a raw Go socket (Apple's ATS only covers its URL
    APIs), so we enforce it ourselves.
- **Login order:**
  1. Verify the password.
  2. Run the existing signing-key challenge, which proves the device holds its key.
  3. If the keys are new, this is a device change. Run steps 1–5 of *Moving to a new device*:
     - new device record and empty queue
     - old queue deleted
     - old token revoked as "replaced"
     - fire-and-forget `DeviceReplaced`, as the old client's last packet through its own
       `writeLoop`
     - old connection closed, with its backlog dropped by the `queueOffline` rule

     Phase 2 adds what the rest of the network does about it.
  4. Issue a token.

### Protocol (`common/protocol.go`)

| Packet | Body |
| :--- | :--- |
| `CtrlRegister` (new, 0x26) | `[ULen 1][Username][PLen 2][Password][PreKeyBundle 164][DLen 1][DeviceName]`. `PLen` is 2 bytes because 128 characters of UTF-8 can exceed 255 bytes. |
| `CtrlLogin` (changed) | same layout as `CtrlRegister` |
| `CtrlLoginChallenge` / `CtrlLoginProof` | unchanged; the proof's domain string becomes `GoMesh-login-v2` |
| `CtrlLoginAck` (changed) | `[UserID 16][SessionToken 32]` |
| `CtrlResume` (new, 0x27) | `[SessionToken 32][PreKeyBundle 164]`, then the same challenge and proof. A stolen token is useless without the device key, and a token presented with different keys is refused. |
| `CtrlLogout` (new, 0x28) | empty; revokes the token |
| `CtrlError` (gains a body) | `[Code 1][MsgLen 2][Msg]`. Codes: `BadCredentials`, `UsernameTaken`, `InvalidUsername`, `WeakPassword`, `RateLimited`, `SessionRevoked`, `DeviceReplaced`, `PasswordRequired`, `Internal` |

We won't claim the login errors hide which usernames exist, because user lookup already
reveals that.

### TUI

- On start the TUI asks for:
  - the server address
  - register or log in
  - username
  - password, entered without echo (`golang.org/x/term`), and confirmed when registering
- It saves the session token (mode 0600) so later starts skip the password.
- It pins the server's cert fingerprint: the user confirms it on first connect, or sets
  `GOMESH_SERVER_FP`.
- On `DeviceReplaced` or `SessionRevoked` it wipes its crypto state and exits with a clear
  message.

### Tests

New tests cover:

- register, then log in
- wrong password, username taken, weak password, invalid username
- rate limiting
- resume with a token, a revoked token, and a token presented with different keys
- a second device replacing the first and disconnecting it
- the replace, in detail:
  - the old device gets `DeviceReplaced` if it's online
  - an offline old device gets `DeviceReplaced` when it next tries to resume
  - nothing from the old queue, or from the old connection's unsent backlog, ever reaches the
    new device
- plaintext connections being refused
- an account surviving a server restart

The e2e tests move to the new login flow.

**Done when:** an account created in the TUI survives a server restart, password login works
over TLS, and every test passes.

**Result (2026-10-15): done.**

- **Server.** Accounts and devices are stored in SQLite (`server/store.go`). Login, register,
  resume and the device move live in `server/accounts.go`; argon2id hashing and the throttles
  in `server/auth.go`. TLS 1.3 is the only transport, and `make dev-cert` creates a
  certificate.
- **Device scoping.** Offline queues belong to the device, and `queueOffline` drops anything
  for a device that no longer exists. A retired connection sends `DeviceReplaced` through its
  own write loop before its backlog, and its reads are dropped. Each of these three races has
  a test that fails when its safeguard is removed.
- **TUI.** It pins the server's certificate on first use, asks before you type a password, and
  hides the password as you type. It resumes with a saved token, and deletes its keys on
  `DeviceReplaced`, `SessionRevoked` or `/logout`. Tests run with `dataDir` in a temporary
  folder, so a wipe can't reach a real `identity.key`.
- **Tests:** 234 tests plus 14 fuzz targets. Every test passes, including under `-race`.
- **Checked with the real binaries:** register, then restart the server, then resume without
  the password. A second client signing in with the password moved the account, and the first
  client deleted its keys on its next start.
- **Still missing until Phase 2:** peers and groups don't yet follow a move. The README lists
  this as a known limitation.

## Phase 2: device change

Phase 2 ships right after Phase 1. Until it lands, a device change leaves groups unable to reach
the member.

- **`common/`:**
  - `ActionRekey`, with its encoding and the `Membership` rules described above
  - `CtrlKeyChange`, `CtrlMyGroups` and `CtrlSessionReset`, with their codecs
- **`server/`:**
  - broadcast the key change and send `CtrlMyGroups` at sign-in (step 6). The queue handling
    in steps 1–5 already landed in Phase 1.
  - accept a `rekey` only from its own member, with keys matching the directory
  - relay each accepted rekey with the mover's new bundle as a hint. Today hints only travel
    with entries that introduce a member, and without one, members couldn't open the fresh
    1:1 session.
- **`client/`:**
  - submit a rekey for each group after a device change, retrying until accepted
  - on a peer's key change, close that session and record the new bundle
  - **group effects during a move come only from the applied rekey.** Today, replacing a
    direct session calls `PeerKeysChanged` (through `OnReplaced`, at `client.go:331` and
    `groupflow.go:667`). That rotates our sender key and marks the mover as lacking it, which
    would stall every shared group until the rekey lands, and indefinitely if iOS suspends the
    new device first. A replacement caused by a key-change notice must therefore skip that
    step.
  - hold a mismatched handshake and fetch the roster again, instead of dropping it
  - give sender keys to a rekeyed member once both the signed rekey and the directory agree
  - the `CtrlSessionReset` backstop, rate-limited per conversation
  - "changed devices" and "safety number changed" notices
- **README:** the security summary and the known-limitations list are updated.

### Tests

- Every `rekey` refusal case, in `common` and on the server.
- An end-to-end move with two TUI data directories on the same account:
  - DMs carry on, whichever side writes first
  - groups carry on, with every member's sender key rotated
  - the old device reads nothing sent after the move
  - an admin who moves stays an admin
  - other members' group messages keep flowing between the key-change notice and the rekey
- Concurrent rekey and admin changes. These are reworked by the existing reject-and-retry
  logic.

**Done when:** you move an account between two TUI clients, then chat and post in groups with
no manual steps.

**Result (2026-10-15): done.**

- **`common`:**
  - Added `ActionRekey`. It is signed by the new key, names only the actor, requires two new
    keys, and leaves the role unchanged.
  - Added the codecs for `CtrlKeyChange`, `CtrlMyGroups` and `CtrlSessionReset`.
  - Clients now apply changes without pins, and only the server pins.
- **`server`:**
  - Moves broadcast `CtrlKeyChange`, and `CtrlMyGroups` goes out at every login.
  - A rekey must match the directory, and its fan-out carries the mover's new bundle.
  - Session resets are relayed over 1:1 chats only.
- **`client`:**
  - `NoteDirectoryKey` is the one entry point for "the directory says X has keys K". It is
    called from the notice, the roster and the chat-open reply, and it marks X as moving and
    rotates our key.
  - Group code never opens or replaces a session to keys the log doesn't name.
  - A held sender key records which session it came over.
  - A handshake under unknown keys is held while the roster is fetched.
  - The rekey intent waits for the client to catch up and doesn't give up on stale refusals.
  - The session-reset backstop is rate-limited at both ends.
- **Tests:**
  - in-process: moving with the only admin, sends during the move, the old device reading
    nothing after the notice, the roster-only path, held keys, and unsettled members
  - against the real server: rekey through `CtrlMyGroups`, a handshake read with the notice
    lost, the reset round trip, the reset rate limit, and a rekey that loses a race with
    another admin's change and is resubmitted
  - mutation checks on the moving skip, the settled install, the held handshake, and the
    replay before reset
- **Not covered by a test:** a full move between two interactive TUIs. The TUI needs a
  terminal, so the end-to-end tests drive the same client code directly.

## Phase 3: durable server

- Persist conversations and their members, group change logs, and offline queues in the same
  SQLite file, and load them at boot.
- **Don't replay a stored log through `Apply` with directory pins.** A log that rekeys
  someone holds their older keys, and a pin is the current key, so the replay would refuse
  it. Either store the membership state alongside the log, or replay with `nil` pins.
- Queues are keyed by device, and `PRAGMA secure_delete = ON` is set, so a replaced device's
  queue is overwritten when deleted.
- Revisit the 512-packet offline cap: phones are offline far more often than terminals.

**Done when:** restarting the server mid-conversation loses nothing.

**Result (2026-10-15): done.**

- **What's stored.** SQLite now holds:
  - conversations and the members of two-party ones
  - each group's log
  - each device's queue, row by row
- **Groups at startup.** Logs are replayed with `nil` pins. A change is applied to a copy,
  stored, then made current.
- **Queue delivery is at least once.** A row is deleted only after its packet is written,
  and only that row. Anything taken but unwritten goes back with its rows.
- **Shutdown.** `Close` waits for every write loop to spill, and the server shuts down that
  way on SIGINT and SIGTERM.
- **Write speed.** `synchronous=NORMAL`, so there's no fsync under the global lock.
- **Queue limits.** The cap is now 5,000 packets and 64 MiB per device.
- **Tests:**
  - against an in-process server: conversations and a group whose log includes a rekey
    surviving a restart, with work carrying on from there; a pairwise chat outliving its
    group; queued packets surviving a restart and arriving once; a clean shutdown keeping
    a connected client's unsent packets; put-back adding no rows; exact-row deletes; the
    byte cap; nothing old delivered after a move and a restart
  - against the real server binary: SIGTERM, a restart, and the group chat, a DM and a
    membership change carrying on
  - in the client: a whole inbox delivered twice changes nothing and warns nobody
  - mutation checks on the shutdown wait, the put-back, and the replay without pins
- **Remaining gap:** a crash or `kill -9` still loses what was in send buffers, because
  there are no acknowledgements. The README says so.

## Phase 4: client engine as a library (`core/`)

- **New module `core/`.** Everything in `client/` except `ui.go` and `main()` moves here.
  - The globals (`mgr`, `idMgr`, `stateStore`, `sessionMgr`, `conn`, `connLock`, `pending`,
    `program`) become fields of `core.Client`.
  - `tuiPrint` and `program.Send` are replaced by an event sink.
  - This happens in two steps, with the full test suite run after each:
    1. Make the package importable, globals intact.
    2. Encapsulate the globals into the struct.
- **Config fields:**
  - `DataDir`, which today is the working directory
  - `ServerAddr`
  - `ServerFingerprint`
  - `Vault`, the host's secret store: the Keychain plus Secure Enclave in the app, 0600 files
    in the TUI
  - `DeviceName`
- **Connection manager.** Today `readLoop` calls `os.Exit(1)` on disconnect, so iOS sending the
  app to the background would kill it. That becomes reconnect with backoff, resuming with the
  token. The engine reports its state as offline, connecting, or online.
- **History store,** separate from `StateStore`, exactly as in *Storage on the device*:
  - opaque tags, sealed rows bound to `tag ‖ seq`, one history key per account
  - `secure_delete` on
  - paged reads, and a read-only mode for earlier accounts' chats
- **Encryption at rest.**
  - The identity keys move from `identity.key` into the vault, sealed with the account key.
  - `StateStore` records get opaque HMAC names and sealing under the account key. `List`
    decrypts and scans instead of matching filename prefixes, with no index file.
  - This closes the README's "ratchet state stored unencrypted" limitation.
  - Existing plaintext files are read once, rewritten sealed, then deleted.
- **Media** is kept encrypted under random names, as in *Storage on the device*.
- **Sign-out** deletes the account key, the identity keys, the crypto state and the token. It
  keeps the history and its key, unless "delete history" was chosen.
- **`client/` becomes a thin TUI over `core`,** with no behavior change.

**Done when:**

- the TUI works as before through `core`
- history survives sign-out and switching accounts
- no file in the data folder names a conversation or contains readable text
- every test passes

**Result (2026-10-15): done, uncommitted.**

- **The engine moved to the `core` module.** An AST rewrite (type-checked, not regex) turned
  the 22 per-client globals into a `Client` struct and 76 functions into methods. Tests
  use a fresh client per `startClient`.
  - Core never prints, never exits, and imports nothing from the UI. Everything goes out as
    an `Event`, and sign-out emits one instead of quitting.
  - The ANSI thumbnail drawing moved to the terminal client.
- **Vault.** A failed read is never taken for "not found". It holds:
  - a random account key, deleted first at sign-out
  - the identity keys, sealed with that key
  - the session token
  - one history key per account
- **State.** Records live in `state/`, sealed, with HMAC file names, bound to their file,
  and listed by decrypt-and-scan.
  - Unreadable records are left in place, never deleted.
  - Plaintext `identity.key`, `session.json` and `gomesh-state/` migrate crash-safely, and
    the sealed copy wins. Checked on a real data folder from the earlier build: it migrated
    and resumed.
- **History.** It lives in `history.db`, one key per account, with opaque tags and rows
  bound to their tag and position.
  - It survives sign-out and stays readable for an earlier account.
  - Deleting it removes the rows, the files and the key.
  - Media is kept sealed under random names and leaves only through `ExportMedia`.
- **Reconnect.** Backoff runs 1–30 s with jitter, using the pinned certificate only. Sends
  are refused while offline before anything is encrypted.
  - A replaced device signs out.
  - When the password is needed, the host gets an event.
  - `Close` stops the loop.
- **The readable-text check is automated.** `TestNothingAtRestIsReadable` runs after a DM,
  a group, a key change and a file. It covers what core manages: `state/`, `history.db*`
  and `media/`. The vault stands in for the Keychain and is out of scope, as are the
  terminal client's log and its `downloads/` copies.
- **Mutation checks:**
  - unsealed state, and names in the clear (the at-rest test)
  - the offline send refusal
  - the redelivery warning, re-checked through the event sink
- **Terminal client.** It now uses `/chat` from history, plus `/history`, `/logout
  [--delete-history]`, and a `Reconnecting…` status.

## Phase 5: bridge, Apple app shell, themes

**Carried over from Phase 4:**

- **Map a missing Keychain item correctly.** The Swift vault from the Phase 0 spike returns
  empty data for a missing item. The bridge adapter must turn exactly that into
  `ErrNotInVault`, and pass every other Keychain error through as an error. That includes
  `errSecInteractionNotAllowed`, which is what a read before first unlock returns.
- **A `Client` is finished once it emits `EventSignedOut`.** The host creates a new one for
  the next sign-in.
- **Commands are refused while offline.** `OpenChat`, the group actions, `SendText` and
  `SendFile` return `ErrOffline`, and the app should show that, not queue silently.

### `bridge/` (the app-facing Go API)

gomobile can't export slices of structs, so the API takes and returns JSON strings and delivers
everything else through one event callback. The same surface becomes a C ABI DLL for Windows
later.

```go
type EventHandler interface { OnEvent(kind string, payload string) }

type Vault interface {                                      // implemented in Swift
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Delete(name string) error
}

func Start(configJSON string, h EventHandler, v Vault) error
func Register(username, password string) error
func Login(username, password string) error
func Resume() error
func Logout(deleteHistory bool) error
func Conversations() (string, error)                        // JSON, includes earlier accounts' read-only chats
func Messages(convID, before string, limit int) (string, error)
func SendText(convID, text string) error
func OpenDirect(username string) (string, error)
func CreateGroup(name, membersJSON string) (string, error)
func GroupAction(convID, action, username string) error     // add/remove/promote/demote/leave
func SendFile(convID, path string) error
func SafetyNumber(convID string) (string, error)
func SetForeground(active bool)
```

### `apps/apple/GoMesh.xcodeproj` (SwiftUI, one shared codebase, macOS and iOS targets)

- **`Engine/`:** a Swift wrapper over the bridge.
  - `AppState` is an `@Observable` that turns events into models.
  - `Vault.swift` implements `Vault` with the Keychain (this device only, after first unlock)
    and Secure Enclave wrapping, with the simulator fallback and the first-launch wipe. The
    password is never stored.
  - The app folder is created with *after first unlock* file protection and excluded from
    backups.
- **`Theme/`:**
  - `design/themes.json` is decoded into a `Theme` struct and injected through the SwiftUI
    environment.
  - `ThemeStore` saves the choice.
  - *Auto* follows the system, using a light theme and a dark theme you choose.
- **`Auth/`:**
  - Screens: Welcome, Create account, Sign in.
  - The server address and fingerprint sit under *Advanced*.
  - Error codes map to inline messages.
  - Signing in on a new device first warns: "This will sign out *name* on your other device."
  - On launch the app resumes silently.
- **Settings → Appearance:** the picker from your screenshots.
  - The first row is *Auto, Follows your Mac* (or *iPhone*).
  - Then a LIGHT section and a DARK section.
  - Each row shows a mini swatch (background, panel, text line, accent line), and the selected
    row gets a checkmark.

**Done when:** you can sign up and sign in from the Mac app and the iOS simulator against the
local server, and all 20 themes switch live.

**Result (2026-10-15): done, uncommitted.**

- **The bridge is an `Engine` per data directory**, not package functions, so the app can
  close one and open the next.
  - **JSON shapes.** Account, saved session, server check, conversations, history
    accounts, history chats and messages, and events.
  - **Errors.** A single `wrap` maps every error to a stable code in a `*bridge.Error`,
    whose text is that JSON. There are 21 codes, all tested.
  - **Events.** A queue delivers them in order, on its own goroutine.
  - **Trust and sign-in.**
    - Server trust is two calls (`CheckServer`, then `TrustServer` with the fingerprint
      shown); `ForgetServer` is for a replaced certificate.
    - `Register` and `Login` refuse an engine that already has an account (`already_signed_in`);
      this was found when a test reused an engine.
  - **Lifecycle.**
    - `SetForeground(true)` cuts the reconnect delay short.
    - Opening a directory closes the engine that had it.
    - A signed-out engine refuses further calls with `signed_out`.
- **Core gained what the app needed:**
  - **Offline resume.** `Resume` starts offline when the server is unreachable instead of
    failing; only the server, or an untrusted certificate, ends a resume.
  - **New calls.** `ServerFingerprint`, `TrustServer`, `ForgetServer`, `ReconnectNow` and
    `SignedIn`.
  - **Close and dialing.**
    - `Close` waits for the read and reconnect loops (5 s backstop).
    - Dials are cancellable, through `tls.Dialer.DialContext` on the stop channel.
    - A certificate mismatch while reconnecting is reported once and retried, since it may
      be a captive portal.
- **The vault in Swift:**
  - **Writes** update in place, or add when the item is missing, so a secret is never in
    neither place.
  - **Fresh-install wipe.** It runs only when the app folder certainly does not exist; any
    error checking for it is not a fresh install.
  - **Unsigned Mac Debug builds** use 0600 files in the container, still sealed by the
    Secure Enclave. This replaced the legacy-keychain fallback, which ties items to an
    ad-hoc signature that changes every build. A Release build refuses to run without the
    Keychain.
  - **The simulator on Apple silicon has a Secure Enclave**, so its items are sealed too.
- **Themes.**
  - `design/themes.json` was generated from the published palette files, fetched, never
    typed:
    - Catppuccin `palette.json`
    - Gruvbox `gruvbox.vim`
    - Solarized's README table
    - Tokyo Night `night.lua` over `storm.lua`
    - Dracula `dracula.vim`
    - Nord `nord.css`
    - `@rose-pine/palette` 4.0.1
    - `@primer/primitives` 11.10.0
    - Atom One `colors.less`
  - Each theme names its source. Every derived or contrast-adjusted color is listed in its
    `notes`, for example Dracula's comment color as muted text, and Solarized's red as
    danger.
  - The test in `bridge/themes_test.go` covers:
    - text, muted text, the accent label and both bubbles at 4.5:1 or better
    - warning and success at 3:1
    - the order of the 8 light and 12 dark themes
    - every token present
  - A mutation (Dracula's original comment color) fails it.
- **The app:** Welcome, Create account and Sign in, with:
  - inline errors per field that clear as you type
  - Return to submit
  - the server under Advanced
  - a trust sheet that shows the whole fingerprint
  - "Forget this server's certificate…" when the pinned certificate no longer matches,
    which confirms, forgets, and shows the new fingerprint to compare
  - a general new-device warning (see below)

  The rest of the app:
  - the signed-in shell, with a connection pill and the chat list
  - Settings with Appearance, Sign out (with "also delete chats") and the vault's kind
  - the Mac's Settings window
- **Verified:**
  - **Mac (scripted `-autotest`, Debug only).**
    - Sign-up, then silent resume on the next launch.
    - Sign-out, then signing in as another account.
    - After being replaced, the next launch lands on Sign in.
    - All 20 themes rendered to PNG and checked by eye.
  - **iOS simulator, by hand.**
    - Inline validation, and sign-up with the trust sheet.
    - Silent resume, and a wrong password shown under the password field.
    - Replacement by the Mac, showing the reason with the username filled in, then signing
      back in on a new address with its own trust sheet.
    - Sign-out from Settings.
    - A replaced server certificate:
      - The mismatch shows under the server field.
      - Forget, then the new fingerprint, then trust, then sign-in reaches the new server.
    - The reinstall wipe. Signed in, uninstalled, reinstalled: the app opened on Welcome with
      no resume attempt, though the session had been in the Keychain.
    - All 20 themes switched live one by one, and Auto followed the system's light and dark
      mode with the settings sheet open.
  - **Not seen.** The Mac app's screens (auth, home, settings sheet, Settings window) were
    built but never looked at. The self-test drives the same `AppState` calls they make, and
    renders the welcome screen and the theme gallery.
  - **Go.** Every suite passes under `-race`, with mutation checks on:
    - offline resume
    - `ReconnectNow`
    - the vault adapter
    - the theme contrast test
- **Bugs found by looking, and fixed:**
  - **The trust sheet truncated the fingerprint.** A fingerprint that can't be compared in
    full is useless.
  - **Sheets stuck on the last forced color scheme under Auto.** A presentation given
    `preferredColorScheme(nil)` keeps its old override. Sheets now take the resolved theme
    from their presenter and always force a concrete scheme; only the main window uses nil.
  - **The source folder `Vault/` was ignored by git.** The `vault/` data-folder rule matches
    it on macOS's case-insensitive git; the folder is now re-included.
  - **A pin mismatch was a dead end.** The message said to forget the server, but nothing
    could; the control above does.
  - **iOS covered the sign-up password fields with an "Automatic Strong Password".** The
    simulator did this even without an associated domain, and with no domain a self-hosted
    server's generated password might never be saved where the person could find it. The
    fields now use `.password` rather than `.newPassword`. The simulator still draws its
    strong-password cover over the two fields, leaving them empty so validation stops the
    submit; nothing is sent with a password the person never saw. Check this on a device.
- **The macOS-27 linker warning is gone.** The cgo objects came from Go's build cache, which
  does not key on `MACOSX_DEPLOYMENT_TARGET`; `make xcframework` now passes `-a`.
- **Departures from the spec:**
  - The new-device warning is general ("signing in here signs this account out on any other
    device") rather than naming the device: telling an unauthenticated caller which device
    holds an account would leak it.
  - There is no `Auth/` folder; the screens are in `Views/`.

**Carried over to Phase 6:**

- **A first message from someone new is named by ID until the roster arrives.**
  `senderName` is the first 8 hex characters, and the chat is "Private Chat: 1a2b3c4d" for a
  moment. The chat list should resolve names when the roster lands (it refreshes on every
  event already), and the message view should show the current name, not the one stored
  with the message.
- **Conversation names come from core with a "Private Chat: " prefix.** The Swift
  `Conversation.title` strips it; better to have core return the peer's name.
- **Signing.** With a development team set (Xcode shows the free team FD8PSGCKR8), the Mac
  build would use the data-protection Keychain instead of files. Creating the signing
  certificate is the person's call; nothing here does it.
- **Palette colors are not contrast-checked as text** (avatar letters, sender names). Check
  them against the incoming bubble once names are drawn there.
- **A signed-in device that meets a changed certificate can only sign out.** It keeps retrying
  and says why, but forgetting the pin happens on the sign-in screen. Offer it from the
  connection banner.
- **Look at the Mac screens.** They have never been seen; set them beside the iOS ones.
- **The sign-up form could not be driven on the simulator** after the first account. Its
  strong-password cover blocks typing; try it on a device.
- **`design/gen_themes.py` regenerates `themes.json`** from the published palettes; its header
  has the fetch commands.

## Phase 6: chat experience

- **Chat list:**
  - colored avatar initials, with a palette color picked from a hash of the user ID
  - last-message preview, time, and unread badge
  - search
  - a banner while offline or connecting
  - a read-only "Previous account" section
- **Conversation view:**
  - accent-colored outgoing bubbles and surface-colored incoming ones
  - colored sender names in groups
  - day separators, with consecutive messages grouped
  - send status (sending, sent, failed)
  - inline system lines: "safety number changed", "*name* changed devices", member changes
  - copy, jump-to-bottom, and older history loading on scroll
- **Composer:**
  - multi-line
  - on macOS, Return sends and Shift+Return adds a newline
  - attachments by button, drag-and-drop on the Mac, or the photo picker on iOS
  - upload progress, inline image thumbnails, and Quick Look
  - in a previous account's chat, a "This chat belongs to *name*" bar instead
- **Other screens:**
  - **New chat:** username lookup.
  - **New group:** multi-select.
  - **Group info:** members, admin badges, add/remove/promote/demote, leave.
  - **Contact info:** includes the safety number.
- **Sign-out dialog:** includes "Also delete this account's chat history from this device".
- **Notifications:** local notifications when a message arrives while the window isn't focused.
- **Layout:**
  - macOS: `NavigationSplitView` with an info inspector, plus shortcuts: ⌘N new chat, ⌘K
    search, ⌘, settings.
  - iOS: a `NavigationStack` with *Chats* and *Settings* tabs.

**Done when:** the Mac app, the iOS simulator and the TUI can DM each other, group chat, and
send files, and moving an account from the Mac app to the simulator behaves as described above.

**How Phase 6 is built (locked 2026-10-16):**

- **Decided:** files stay on Supabase Storage. For testing, a local stand-in answers the
  signed-URL calls `server/supabase.go` makes. It exists twice: an `httptest` version for a
  core end-to-end test, and a scratch tool for driving the app by hand. Real Supabase stays
  unverified until its credentials are set on EC2.
- **Four slices, each verified before the next:**
  1. Private chat text between the Mac, the simulator and a scratch TUI: the chat list,
     the conversation and the composer.
  2. Groups: create, info, member actions, and system lines.
  3. Files.
  4. Local notifications, Mac shortcuts, and iOS tabs.
- **Engine and bridge:**
  - **Names.** Return the peer's plain name, live and from history, and resolve again when
    a stored sender name is the 8-hex fallback.
  - **Opening a chat.** Return the conversation ID, or a coded error such as user not
    found. Never reset an existing chat from New chat: navigate to it instead. Resetting
    a session is a deliberate action in Contact info.
  - **System lines.** Give the conversation-scoped notices a conversation ID and record them
    in history as system rows, worded without slash commands. Test that rows written before
    the change still decode.
  - **Unread and previews** go in the sealed conversation record.
    - Keep the read marker on append, in the same transaction.
    - Sending marks the chat read.
    - Decide whether system lines count as unread, and test it.
    - Extend `TestNothingAtRestIsReadable` to cover previews.
  - **Send status.**
    - A group message held in the outbox shows as queued, not sent.
    - `sendMedia` must not record a file as sent when `sendPacket` fails.
  - **Files.** Progress and file events carry the conversation ID and a transfer ID. The UI
    caps file size, since `sendMedia` reads the whole file into memory.
  - **Group members.** A member list with name, admin and "this is me" flags.
- **At rest:**
  - Notifications show the sender's name, or "New message"; message previews are opt-in.
  - Viewing a file decrypts it into the app's temporary folder for Quick Look, and the copy
    is deleted when the preview closes.
  - Nothing from chats goes in UserDefaults, and the message cache is in memory only.
  - Files picked on the Mac are copied out of their security-scoped location before
    sending, and the copy is deleted afterwards.
- **Performance.** Chat-list refreshes run off the main thread and are coalesced. Messages
  page in: the latest 50 first, older ones as you scroll.
- **Themes.** Add contrast checks for sender names on the incoming bubble, and for avatar
  letters on their 22% wash.
- **Verification:**
  - Accounts are created with scratch TUIs run from scratchpad folders, never from `client/`.
  - The Mac self-test is extended to send and receive.
  - The Mac screens are looked at, with permission, before being called verified.

**Result (2026-10-16): done, uncommitted.** Built in the four slices above, each verified
before the next.

- **Engine.**
  - **Names.** Chats carry the person's plain name, and a stored ID-prefix name is
    resolved again when the roster has named the sender.
  - **`OpenChat`** returns the chat's ID, or `ErrUserNotFound` / `ErrChatWithSelf`. It never
    resets a chat that exists; `RestartChat` does that, from Contact info or the terminal
    client's `/dm` on an existing chat.
  - **`CreateGroup`** returns the group's ID once the server has taken it, and refuses an
    unknown member before creating anything. `GroupMembers` lists the members.
  - **System lines** are kept in the history, worded without slash commands:
    - key and device changes
    - session resets
    - member, admin and rekey changes
    - leaving
    - a received file that failed
  - **The chat list** comes from the sealed conversation records: last message, file
    flag, mine or theirs, unread count. Sending reads the chat; system lines count neither
    as unread nor as the preview. A group left stays listed, read-only.
  - **Queued messages.** A group message held for sessions is kept as queued, then marked
    sent or failed when the outbox flushes (an event says so). A full outbox refuses.
  - **Files.**
    - `sendMedia` no longer records a file as sent when announcing it failed.
    - Every transfer has an ID, and its progress events carry the chat. A failure is
      reported as -1.
    - `SendFile` refuses over 50 MB.
    - Thumbnails are 320 px with area-averaging; the terminal client shrinks them to 30.
- **Theme tokens.** `paletteText` was added: the palette fitted to 4.5:1 on the incoming
  bubble and 3:1 for an avatar's letter on its 22% wash, for every theme. It is generated
  by `design/gen_themes.py` and checked by the theme test.
- **The app.**
  - **Chat list:** search, unread badges, and an "Earlier on this device" read-only section.
  - **Conversation:**
    - day separators and grouped runs
    - sender names in colour
    - system lines
    - sent, queued and failed ticks
    - "Sending" bubbles with Retry and Delete
    - paged history, and a jump-to-latest button (iOS 18 and macOS 15)
  - **Composer:** Return sends on the Mac; there's an attach menu, and dropping a file on a
    chat on the Mac sends it.
  - **New chat, New group, Group info** (admin menu, add, leave) and **Contact info**
    (safety number, restart).
  - **Files:**
    - Picked files are copied into the app's temporary folder and deleted when the transfer
      ends.
    - Opening a file decrypts it into a temporary folder for Quick Look and deletes it when
      the preview closes.
    - Photos from the picker lose their GPS before sending.
  - **Local notifications:** "New message" unless previews are turned on. A tap opens the
    chat, and the badge counts unread.
  - **Mac:** ⌘N, ⌘⇧N, ⌘K, and info in an inspector.
  - **iPhone:** Chats and Settings tabs.
- **Verified.** Every Go suite passes under `-race`.
  - **New end-to-end tests:**
    - `OpenChat`
    - system lines
    - groups through the API
    - files through an `httptest` Supabase stand-in, with a failed upload too
    - old history rows still opening
    - queued and failed statuses
    - the bridge's group and chat-list calls
  - **Mutation checks:** unread counting, and `OpenChat` reuse.
  - **By hand, on the iPhone simulator, against a local server and storage stand-in:**
    - chats with an echo bot on the engine, the Mac app and the terminal client (driven in
      tmux), both ways
    - a group created, posted in and administered
    - photos sent, received on the Mac and opened in Quick Look, with the temporary copies
      gone afterwards
    - the photo the Mac received carries no location
    - a notification shown, and tapping it opened the chat
  - **Mac:** through its scripted self-test: chats, a group, a received photo, and replies.
- **Bugs found by looking, and fixed:**
  - A chat read on screen still counted as unread, because the list had not caught up.
  - The jump button showed at the bottom; it needed the scroll geometry, so it is iOS 18
    and macOS 15 only.
  - A chat opened one message short of the end.
  - Picked photos carried their location.
  - Thumbnails were 30 px, sized for the terminal client.

**Fixed after the advisor's review (2026-10-16):**

- **Kept private chats.** After signing back in they are no longer read-only; the first
  send reopens the session (`ensureDirect`). Only a group the account left is read-only.
  Tested in `TestPrivateChatsComeBackWritable`.
- **Open-chat cache keys.** They are now the account and the chat, so two accounts on one
  device that share a chat ID don't mix.
- **Notifications** and the badge are cleared on sign-out.
- **A transfer that finished** before `sendFile` returned no longer leaves a stuck row.

**The account move with the new screens (2026-10-16), which completes Phase 6:**

- **To the Mac:** bob moved from the phone to the Mac through the self-test. The phone went
  to Sign in, saying its keys were deleted.
- **Trio survived the rekey:** the Mac posted, and carol's echo came back.
- **Back to the phone:** bob signed in on the phone again. His old private chat with carol
  was writable and got its echo, and so did Trio.
- **One bug found:** a device catching up on a group's log announced the group's whole
  history again: "created", admin changes (one with a raw ID), and "now holds your keys"
  once per move.
  - **Fix:** it now announces only changes from the time it holds the account's current
    keys.
  - **Tested** in `TestAMovedDeviceIsNotToldOldGroupNews`, which fails without the fix.
- **Also found:** the phone had been running a build from before the review fixes. The
  fixed build was installed and checked. Kept private chats show no lock, and they send.

**Carried over to Phase 7:**

- **Look at the Mac screens.** Computer use was not available in this session, so nobody has
  seen them. That includes the inspector, the shortcuts and drag-and-drop.
- **Real Supabase** is unverified; set its three variables on EC2 and send a file.
- **Queued group messages** are lost if the app quits before they go (they stay "queued").
- **Read markers are per device**; with one device per account that is enough.
- **The sign-up form on the simulator** is still covered by iOS's strong-password view after
  the first account.
- **Unsent drafts** are not kept when switching chats.

## Phase 7: iOS realities and polish

- **Background:** iOS drops the socket when the app goes to the background. On returning, the
  app resumes and drains the offline queue.
- **No push notifications** (decided 2026-10-16). Messages wait in the server's per-device
  queue and arrive when the app next connects; local notifications cover a running app.
- **Deployment: the server runs on AWS EC2** (decided 2026-10-16).
  - A systemd unit, with `DB_PATH` on the instance's EBS volume. SIGTERM already shuts the
    server down cleanly.
  - TLS: either the self-signed certificate, pinned by fingerprint as today, or a real one
    for a domain. The clients pin either way.
  - The security group opens only the server's port.
  - The app's default server address becomes the EC2 host instead of `localhost:8080`.
- **Physical iPhone:**
  - A free Apple ID can sign the app, but it must be re-signed every 7 days.
  - With the server on EC2, the phone reaches it over the internet like the Mac does.
- **Polish:**
  - App lock with Face ID or Touch ID
  - App icon and haptics
  - Dynamic Type and VoiceOver support
  - A contrast test over every theme

### How Phase 7 is built

Order: delivery first (it decides whether backgrounding loses messages), then the iPhone's
lifecycle, deployment, polish, and the carry-overs.

1. **Delivery acks** (protocol, server and engine). Today the server counts a packet as delivered
   once it is written to the socket. A phone that iOS suspends, or that changes networks,
   loses whatever was written but not yet read.
   - **The ack:** a new `CtrlDelivered` (client → server). Its body is the number of packets
     the client has handled on this connection since signing in. It is cumulative, so the
     packet header does not change.
   - **When the client acks:** the read loop handles one packet at a time, so the count
     follows `deliver`. The client acks after a quiet 250 ms, after every 64 packets, and
     before it closes.
   - **Server side:**
     - It keeps the written, unacked packets of each connection in order. An ack drops the
       ones it covers.
     - **Packets from the offline queue** are deleted from the store only once acked, not
       once written.
     - **When a connection ends,** its unacked packets go back on the device's queue ahead
       of anything spilled from the send channel. Live packets are written to the queue;
       queued ones already have their rows.
     - **A cap:** a connection with more than 4,096 unacked packets is closed, and its
       packets requeued.
   - **Duplicates** are already harmless, as tested in `TestRedeliveredPacketsChangeNothing`.
   - **Not covered:** packets parked for a missing key are still held in memory only, as
     before.
   - **Tests:**
     - A raw connection that reads without acking and then drops gets the same packets on its
       next connection, for both live and queued packets.
     - An acked packet is not sent again.
     - The cap.
2. **The iPhone in the background.** `Client.Pause()` acks, closes the connection, and stops
   reconnecting until `ReconnectNow`.
   - **On iOS,** the app pauses when it goes to the background (inside a background task) and
     reconnects at once when it comes back.
   - **The Mac stays connected,** since its notifications depend on that.
   - **Exposed to the app** through `bridge.Engine.SetForeground`, which pauses only when told
     to.
3. **Deployment on EC2.**
   - **Files:** a `deploy/` folder with a hardened systemd unit (`gomesh.service`: its own
     user, `StateDirectory`, `ProtectSystem=strict`), an example environment file, and
     `docs/deploy-ec2.md`. The guide covers the instance, the security group, an Elastic IP,
     the certificate and its fingerprint, Supabase, updates, backups (`sqlite3 .backup` and
     EBS snapshots), and logs.
   - **Build:** `make server-linux` cross-compiles for linux/arm64 and amd64. The SQLite
     driver is pure Go, so this works.
   - **The app's default server** comes from a build setting, `GOMESH_DEFAULT_SERVER`, in an
     untracked `Config/Local.xcconfig`. That file also holds `DEVELOPMENT_TEAM` for a real
     iPhone, so neither is committed.
   - **The terminal client** takes `GOMESH_SERVER` as its default.
4. **Polish.**
   - **App lock:** off by default, with a Settings toggle. It uses LocalAuthentication
     (`.deviceOwnerAuthentication`, so the passcode works as a fallback). The app locks at
     launch and after a set time in the background (immediately, 1 minute or 15 minutes). The
     app switcher is covered while the app is inactive. Adds `NSFaceIDUsageDescription`.
   - **App icon:** drawn by a script in `design/` from the logo, giving the iOS 1024 px icon
     and the macOS sizes, in an asset catalog.
   - **Haptics:** `sensoryFeedback` on send, on a failed send, and on the app unlocking.
   - **Dynamic Type:** fixed font sizes become text styles or `@ScaledMetric`.
   - **VoiceOver:**
     - each bubble reads as one element: sender, text, time and status
     - icon-only buttons and avatars get labels
     - system lines read as such
   - **Contrast:** the theme test gains every pair the screens actually use. Those include
     accent text on `bg` and `surface` (links and buttons), and the timestamp on each bubble.
5. **Carry-overs.**
   - **Group messages still queued** when the app quit turn into "failed" (not sent) at the
     next start, instead of saying "waiting to send" for ever.
   - **Drafts** are kept per chat for as long as the app runs.
   - **Group lines on a device catching up.** A device that signs in is told only of group
     changes from the time it holds the account's keys. This was found in the account-move
     test and is already done, in `TestAMovedDeviceIsNotToldOldGroupNews`.

**Done when:**

- Every suite passes under `-race`, with the new tests.
- On the simulator, a message sent while the app is in the background arrives when it
  returns, and a chat survives a dropped connection.
- The app lock works on the Mac, and on the simulator through its enrolled Face ID.
- The deploy guide is complete: someone can follow it on a fresh EC2 instance.
  - The unit and build are checked locally with `systemd-analyze verify` where possible, or
    by reading them.
- **Left to you:**
  - running it on EC2, and real Supabase
  - a real iPhone, which needs your team ID
  - a look at the Mac screens

**Result (2026-10-16).**

1. **Delivery acks.**
   - **Built:** `CtrlDelivered`, `IsReply`, server-side tracking with a 1,024-packet window
     and a one-minute timeout, in-order requeueing, and a new connection waiting for the
     old one (`lastConn`).
   - **The client** acknowledges from its read loop.
   - **A new `ErrAlreadyRead`** covers a message read before, so repeats are dropped
     quietly. It also covers a handshake for a session already replaced.
   - **Server tests:**
     - `TestUnacknowledgedPacketsAreSentAgain` (live and queued)
     - `TestAnUnacknowledgedReplyIsNotSentAgain`
     - `TestAReconnectGetsWhatTheDeadConnectionHeld`
     - `TestTheServerWaitsForAcknowledgements`
     - `TestABadAcknowledgementChangesNothing`
   - **Engine tests:**
     - `TestADroppedConnectionLosesNothingAndDuplicatesNothing` fails with the requeue
       switched off.
     - `TestAPausedDeviceGetsEverythingWhenItComesBack`.
   - **Tests updated:** four older server tests and the core test parties now acknowledge
     what they read, or skip repeats, as a real client does.
   - **Found while building:**
     - A packet in hand when the window timed out was queued ahead of older ones. It now
       goes back after them.
     - The scratch bot predated the new `CreateGroup` and had to be rebuilt.
2. **The iPhone in the background:** `Client.Pause`, exposed as `bridge.Engine.Pause`.
   - **When it runs:** on `.background` only, inside a background task.
   - **Checked on the simulator:**
     - a message was sent, then Home was pressed
     - carol's echo, 8 s later, waited in the server's queue for bob's device
     - on return it arrived, and the queue emptied once acknowledged
3. **Deployment.**
   - **Files:** `deploy/gomesh.service` and `deploy/gomesh.env.example`, plus
     `docs/deploy-ec2.md`, with every claim checked against the code (the cert generator,
     the settings, the forget control).
   - **Build:** `make server-linux` builds static arm64 and amd64 binaries.
   - **Unit:** checked by reading only, since there was no Linux here. It avoids filters
     that would kill the Go runtime.
   - **Build settings:** `Config/Base.xcconfig` with an optional `Local.xcconfig`, which git
     ignores; an override was checked with `-showBuildSettings`. `Config/Info.plist` carries
     `GoMeshDefaultServer`, merged with the generated keys.
   - **The terminal client** takes `GOMESH_SERVER`.
4. **Polish.**
   - **App Lock**, checked on the simulator with enrolled Face ID:
     - it locks at launch and when the app comes back
     - a wrong face keeps it locked; a match unlocks
     - Cancel leaves the lock screen up
     - the Face ID prompt making the app inactive does not lock it again
   - **App Lock on the Mac:** checked through the self-test's `lock` mode, with a stand-in
     for Touch ID: not locked after 30 s away, locked after 61 s, and the lock screen
     rendered.
   - **Icon:** `design/gen_icon.swift` draws the iOS icon and the macOS sizes.
   - **Haptics** on sending, on a failed send, and on unlocking.
   - **Dynamic Type:** the fixed sizes became text styles or `@ScaledMetric`.
   - **VoiceOver:** each bubble is one element ("You, …, 7:21 PM, sent"), with an Open action
     for a kept file.
   - **Contrast:** the theme test now covers every pair the screens draw. The old colours
     failed 22 checks.
     - **The fixes:**
       - `textMuted` is fitted on `surfaceRaised`, and `danger` on `surface`.
       - A new `accentText` token is used for text and tints.
       - Bubble timestamps, ticks and "Sending" are drawn at full strength, since 75% fell
         to 2.9:1.
     - **How they were applied:** by the generator's own fit, to the existing
       `themes.json`, so nothing had to be downloaded again.
5. **Carry-overs.**
   - **Queued group messages** left at a restart are marked failed
     (`TestMessagesQueuedWhenTheAppStoppedAreMarkedNotSent`, which fails without the call).
   - **Drafts** are kept on the chat's model, and checked on the simulator.

**Bugs found by using it:**
- **The lock prompt came straight back after Cancel.** The automatic prompt now asks once
  per lock.
- **A late acknowledgement could crash the server.** Found in the final review: an
  acknowledgement arriving after the write loop had put its packets back indexed an empty
  list and panicked. It is now ignored. `TestAnAcknowledgementAfterTheRequeueIsIgnored`
  panics without the fix.
- **The simulator drops quick taps on a switch.** That is the test tool, not the app; a
  longer press works.

**Still open:**
- **On EC2:** the run itself, and real Supabase.
- **On a real iPhone:** a real device, and real Face ID.
- **On the Mac:** a real Touch ID or password prompt, and a look at its screens.
- **A reply sent while a device was away is dropped.** For example, a DirectAck for an
  `OpenChat` that was in flight when the app paused. The request fails and can be made
  again.
- **System lines move a chat to the top** without changing its preview (Phase 6 design).

---

## Receipts and the Telegram look (approved 2026-10-17)

An outgoing message shows a clock, then one tick (the server took it), two (every recipient's
device has it) and two coloured ticks (every recipient has read it). README's *Receipts*
section is the reference for how it works; this is what was decided.

| Decision | Choice | Alternative |
| :--- | :--- | :--- |
| Where "read" lives | End-to-end encrypted `MsgReadReceipt`, sent by the reader to the sender alone. The server cannot see which message. | A plaintext read packet the server stores: simpler and recoverable, but the server would learn what each person read, and when. |
| Taken and delivered | Recorded by the server in `msg_receipts` for 14 days, reported to the sender. | none |
| Read receipts switch | Settings, on by default. Off means you send none and what you read meanwhile is never reported. | Always on |

Built in `common/receipts.go`, `server/receipts.go`, `core/receipts.go`, and the bridge's
message and event fields (`delivery`, `deliveredCount`, `readCount`, `total`).

**Carried over.** "Delivered" is the device handling the packet, not showing it. Receipts for a
message sent before this change are never reported (it keeps one tick).

---

## Theme system

`design/themes.json` is the single source of truth. Each theme has an `id`, a `name`, an
`appearance` (light or dark) and these tokens:

| Token | Used for |
| :--- | :--- |
| `bg`, `surface`, `surfaceRaised`, `border` | window, sidebar and panels, popovers, dividers |
| `text`, `textMuted` | body text, timestamps and previews |
| `accent`, `onAccent` | buttons, selection, links, outgoing bubbles |
| `bubbleOut`, `onBubbleOut`, `bubbleIn`, `onBubbleIn` | message bubbles |
| `danger`, `warning`, `success` | errors, the safety-number warning, connection state |
| `palette[8]` | red, orange, yellow, green, teal, blue, purple, pink: avatars and sender names |
| `chatBg`, `chatPattern` | the chat's background and its dots. Optional: `bg` and `textMuted` when left out |
| `selectedRow`, `onSelectedRow` | the selected row in the chat list and the text on it. Optional: `accent` and `onAccent` |
| `metaOut`, `metaIn`, `tickRead` | timestamps and plain ticks on an outgoing and an incoming bubble, and the colour of read ticks. Optional: the bubble's text colour when left out |

Colors come from each theme's published palette. A unit test requires a contrast ratio of at
least 4.5:1 for text on `bg` and for bubble text on its bubble in every theme.

| Light | Dark |
| :--- | :--- |
| Telegram Light (default), GoMesh Light, Paper, Catppuccin Latte, One Light, Gruvbox Light, Solarized Light, Rosé Pine Dawn, GitHub Light | Telegram Dark (default), GoMesh Dark, Catppuccin Mocha, Catppuccin Macchiato, One Dark, Gruvbox Dark, Dracula, Nord, Tokyo Night, Solarized Dark, Rosé Pine, Rosé Pine Moon, GitHub Dark |

Optional: the TUI reads the same file for a `/theme` command.

---

## Repository layout afterwards

```
common/       protocol + crypto, shared by everything
core/         client engine library (moved out of client/)
client/       terminal UI over core
bridge/       app-facing API: gomobile now, C ABI for Windows later
server/       + store.go (SQLite), auth.go, TLS
apps/apple/   SwiftUI app for macOS and iOS
design/       themes.json
docs/         this plan
Makefile
```

## Later (not in this plan)

- **Windows:** the same `bridge/` built as a DLL. We choose its UI then (WinUI 3 or Flutter),
  reusing `themes.json`.
- **Rekey hardening:**
  - verified contacts need your approval before their keys change
  - the old device co-signs a move when it is still available
- Encrypted backups, typing indicators, reactions, edit and delete, voice and video.

## Risks

| Risk | Mitigation |
| :--- | :--- |
| A malicious server could rekey a member and take over their place in groups | Visible "changed devices" notices, safety numbers, and the hardening above. Accepted knowingly; see *The trade-off*. |
| Restructuring tested crypto code | Tests committed first, moved in two steps, suite green after each |
| The direct-chat and group key checks conflicting during a move | One rule (above), covered by the end-to-end move tests |
| gomobile and `go.work` may not cooperate | Phase 0 spike, with a fallback to a separate module |
| `modernc.org/sqlite` may not build for `GOOS=ios` | Phase 0 spike, with fallback to `mattn/go-sqlite3` (cgo) or a gob store |
| argon2 memory exhaustion | Throttle before hashing, plus a semaphore on concurrent hashes |
| Messages in flight during a move, or sent while signed out, are lost | `CtrlSessionReset` tells the sender. A real fix needs backups, which are out of scope. |
| A backup restoring an old ratchet, which would reuse spent message keys | Crypto state is excluded from backups, and its keys are this-device-only |
| Deleted keys or history lingering in flash or in SQLite free pages | Crypto-shredding: delete the key that sealed them. `secure_delete` too. |
| The old device's backlog leaking into the new device's queue | Queues are per device, and `queueOffline` drops packets for a deleted device. Tested. |
| No Secure Enclave in the simulator, and Keychain entitlements on the Mac | Explicit, tested fallback, plus the Phase 0 spike |
| A self-signed cert on a physical phone | Fingerprint pinning instead of system trust |
| App size from the Go runtime (~10–15 MB) | Acceptable for a messenger |
