# GoMesh: Comprehensive Project Documentation

`GoMesh` is a secure messaging application supporting end-to-end encrypted (E2EE) private
chats, end-to-end encrypted group chats, and file transfers over a custom protocol on TLS 1.3.

This document describes every mechanism, byte pattern, and component as they exist in the
code today.

---

## Implementation status

Private chats use a Signal-inspired design: a signed-prekey handshake followed by a
directional ratchet with ephemeral-key rotation. Group chats use per-member sender keys
delivered over those direct sessions, with a signed membership log that every client
verifies. Both are implemented, tested, and working end to end.

| Area | Status | Notes |
| :--- | :--- | :--- |
| Direct chats | **Working** | Signed-prekey handshake, then a directional ratchet with ephemeral-key rotation. The recipient is never notified in advance and builds its session from the first ciphertext. |
| Forward secrecy and self-healing (direct) | **Working** | A fresh ephemeral key is mixed in every 50 sent messages, or as soon as the peer publishes a newer one. Old keys are deleted. |
| Session persistence | **Working** | Ratchet state is saved atomically before each message is released, and restored on start. |
| Accounts | **Working** | Username and password. The server stores an argon2id hash in SQLite. Logins are throttled before any hashing. |
| Client engine | **Working** | The client is a library, `core`, with one `Client` per signed-in account and events for the host. The terminal client and the Apple apps are thin screens over it. |
| Apple apps (macOS, iOS) | **Working** | One SwiftUI app for the Mac and the iPhone, on the engine through `bridge/` (gomobile). Accounts and server trust; a chat list with previews, unread counts and search; private chats and groups (create, members, admins, leave); files with thumbnails, opened in Quick Look; local notifications; App Lock with Face ID, Touch ID or the passcode; VoiceOver labels and Dynamic Type; 22 themes plus Auto (Telegram Light and Dark by default), every pair of colours the screens use checked for contrast. On the iPhone the connection pauses in the background and catches up on return. The Mac's screens have not been looked at yet; the iPhone's have. |
| Encryption at rest | **Working** | Keys live in a vault (the Keychain on Apple devices). Ratchet and group state are sealed files with HMAC names; history is sealed row by row with a per-account key; received files are sealed under random names. Sign-out deletes the key everything is sealed under. |
| Chat history | **Working** | Kept on the device across sign-out. A later account on the same device can read an earlier one's chats, not write to them; sign-out can delete them. |
| Reconnect | **Working** | The client reconnects on its own with backoff, resuming the session over the pinned certificate; sends are refused while offline. A device whose server is down at launch still starts, with its chats, and comes online when the server does. |
| Delivery | **Working** | The client acknowledges what it has handled, and the server keeps every packet until it is acknowledged: one written to a connection that then dropped, or to an iPhone that iOS suspended, is delivered again on the next connection, and the client ignores the copy. |
| Message ticks | **Working** | An outgoing message shows a clock until the server takes it, one tick once it has, two when every recipient's device has it, and two coloured ticks when every recipient has read it. In a group, "every recipient" means everyone in the chat now who was in it when the message went. *Taken* and *delivered* come from the server, which records them for 14 days so a sender that was away can ask again. *Read* is end-to-end encrypted, sent by the reader's device to the sender alone, and can be turned off in Settings. See *Receipts* below. |
| Deployment | **Ready, not yet run** | A hardened systemd unit and a step-by-step guide for AWS EC2 in [`docs/deploy-ec2.md`](docs/deploy-ec2.md); `make server-linux` cross-compiles. |
| Server restarts | **Working** | Accounts, conversations, group logs and offline queues live in SQLite, so a restart loses nothing queued. SIGINT or SIGTERM shuts down cleanly, saving what connected clients had not yet been sent. |
| Login | **Working** | Password (or a saved session token), then a signed challenge proving the device holds the keys it presents. Over TLS 1.3 only; clients pin the server's certificate. |
| Moving to a new device | **Working** | Signing in with the password on new keys moves the account. The old device is told and wipes its keys, and its queued messages are deleted. Contacts are told the new keys, direct chats restart on them, and the new device rekeys every group it is in with a change it signs, keeping its role. |
| Key verification (safety numbers) | **Working** | `/safety` shows a number to compare out of band. |
| Group chats | **Working** | Each member owns a sender key per group (a ratcheting chain plus an Ed25519 signing key) and hands it to every other member inside their direct session. One encryption and one signature per message; the server fans out the same ciphertext. |
| Group forward secrecy and healing | **Working** | The chain only moves forward and old keys are deleted. A sender key is replaced every 100 messages, every 7 days, and whenever a member leaves or is removed. |
| Group sender authentication | **Working** | Every message is signed by its sender's key, so members who all hold each other's chain keys still cannot forge one another. |
| Membership changes | **Working** | Admin-signed, hash-chained, and verified by every client. The server only orders them. |
| Out-of-order messages | **Working** | Direct chats and groups: skipped-key tracking, up to 1000 ahead, kept 7 days. |
| Deferred delivery | **Working, with a gap** | A direct message whose epoch has not arrived yet is held and replayed, not dropped. Losing *every* message of an epoch sticks that direction until someone runs `/dm`; see *Known limitations*. |
| Media transfer | **Working** | Unchanged by the rewrite. Encrypted blobs go directly to Supabase; only a metadata envelope is relayed. |
| Group admin controls | **Working** | Enforced by the server *and* re-checked by every client from the signed log. Admin is a membership role and has no part in key distribution. |

### Tests

319 tests across the four modules (common, server, core, bridge), plus 15 fuzz targets and end-to-end tests that
run the real server binary and drive the real client code over a socket.

```bash
cd common && go test ./...      # protocol codecs, ID ordering, the membership state machine
cd core && go test ./...        # the client engine: ratchet, handshake, sealed state, history, sender keys, membership, reconnect, end-to-end
cd server && go test ./...      # routing, signed membership log, concurrent changes
cd bridge && go test ./...      # the apps' API against a real server, its error codes, the vault adapter, and every theme's contrast

# Fuzz the decoders that parse untrusted bytes
cd common && go test -run '^$' -fuzz='^FuzzDecodeConvInfo$' -fuzztime=60s
```

### Known limitations

These are deliberate, not oversights.

- **Group keys wait on 1:1 sessions.** A sender key goes to each member inside their direct
  session, which needs their prekey bundle to open. The server sends bundles alongside the
  membership changes that introduce a member, and a send that cannot yet reach everyone is
  held and retried rather than sent, so nobody misses messages that went out before they
  could be keyed. A member whose bundle never arrives blocks sends to that group.
- **A removal costs about one direct message per pair of members**, spread over each
  member's next send. That is fine for a few hundred members; larger groups would need a
  different design (MLS).
- **Group history is not backfilled.** A new member reads nothing sent before they joined,
  by design, and a message sent while a member's key is still on its way is held for up to
  7 days in memory only. A client restarted inside that time loses what it was holding.
- **Last-admin leave is two signed changes.** The leaving client promotes the first other
  member, then leaves. If another admin's change lands in between, the pair is re-worked
  against the new log, up to four times, and then reported as failed.
- **Group names and the directory hints are not signed.** The server supplies display names
  and prekey bundles. A bundle that does not match the keys the signed log names is
  ignored, but the name is shown as given.
- **One account, one device.** Signing in somewhere new moves the account there; there is
  no multi-device. The new device starts with no history, and messages already on their way
  to the old device when the account moved are lost.
- **A rekey is signed by the new key, so the server could swap a member's keys.** The old
  device may be gone, so nothing older can vouch for the move. A malicious server could rekey
  a member to keys it holds and take their place in a group. It still cannot add or remove
  anyone, and every member is shown "*name* is on a new device"; safety numbers detect the
  substitution. This is the same trust Signal places in its server when someone
  re-registers.
- **A group a known peer appears to create is no longer refused for contradicting their
  keys.** Clients stopped checking membership changes against keys learned elsewhere,
  because a log that rekeys someone legitimately holds older keys. Such a group can show up
  in the list, but nobody whose 1:1 session disagrees with the log gets anyone's sender key,
  and the client warns about them.
- **A server crash can lose live packets.** A packet is kept until the device acknowledges
  it, and a dropped connection or a clean shutdown puts what was not acknowledged back on
  the device's queue. But packets sent to a connected device are held in memory, not on
  disk, until then, so a crash or `kill -9` of the server loses the ones not yet
  acknowledged. Offline queues are on disk; with `synchronous=NORMAL`, only a power cut can
  lose their last few writes.
- **Packets are delivered at least once.** A queued row is deleted only once its packet is
  acknowledged, and anything unacknowledged is sent again, so a device can be sent the same
  packet twice. Clients ignore what they have already read; tests deliver a whole inbox
  twice, and drop a connection between reading and acknowledging, to check it.
- **The server sees passwords at login.** TLS protects them in transit and the server keeps
  only an argon2id hash, but a malicious server could log them as they arrive. A PAKE such
  as OPAQUE would remove that, at considerable cost.
- **The first connection trusts the certificate it is shown.** The client pins the
  fingerprint the user confirms, so compare it with the one the server printed.
- **Some losses still stick a chat.** Offline queues are capped at 5,000 packets or 64 MiB
  per device and drop the oldest first, and a server crash loses what connected devices had
  not acknowledged. Out-of-order delivery is handled. *Loss* is not, in one case. Losing a single message is harmless, since every
  message in an epoch carries what is needed to open it. But if **every** message of an
  epoch is lost, that direction is stuck for good: each later root key chains through the
  lost epoch's ratchet key, which only its messages carry, and the sender rotating again
  does not help. In a back-and-forth chat nearly every message opens a new epoch, so one
  lost message can be enough. Nothing detects this automatically. The way out is to type
  `/dm <name>` on **either** side, which abandons the session and starts a fresh one; see
  *Starting over*. Messages in flight on the old session when you do this may not arrive.
- **A device that loses its state cannot read an established peer until the peer starts
  over.** The peer's messages carry no handshake fields any more, so no session can be built
  from them. The client discards what it held and sends the peer a session reset, at most
  once a minute per chat; what was in flight is lost.
- **A handshake that arrives late is treated as a restart.** Once a session has heard from a
  peer, a message carrying different handshake fields replaces it. That needs the server to
  reorder packets, which it does not do.
- **The temporary session kept after a simultaneous handshake is not saved to disk.** A
  client restarted inside its few minutes cannot read what the other side sent before it
  switched.
- **Signed prekeys are not rotated on a schedule yet.** Rotation and 30-day retention of the
  old key exist; nothing calls them.
- **The server is trusted for key distribution until safety numbers are compared.** It hands
  out bundles, so a malicious server can substitute its own. `/safety` is the check.
- **The first membership change is trusted on first use.** Every later change is checked
  against the signed log, so a malicious server cannot add a silent member. But the log
  starts with a create the creator signed with a key the server vouched for, so a server
  that substitutes keys *before* a group exists is the same attack as for a direct chat, and
  `/safety` is the same check.
- **The terminal client's vault is plain files.** On Apple devices the vault is the Keychain,
  sealed again by the Secure Enclave; the terminal client, a development tool, keeps the
  account key, identity, session token and history keys as 0600 files in `vault/`, which
  protects nothing beyond the file permissions. Its `downloads/` copies and `client.log`
  are plaintext conveniences too.
- **An unsigned Mac build keeps its vault in files.** The data-protection Keychain on the Mac
  needs a development team's signature. Until `DEVELOPMENT_TEAM` is set, a Debug build keeps
  the vault as 0600 files in the app's container, still sealed by the Secure Enclave, and
  Settings says so; a Release build refuses to run without the Keychain. The iPhone and the
  simulator use the Keychain.
- **No push notifications.** A message waits in the server's queue until the app connects;
  the app notifies only while it is running. On an iPhone the app disconnects as it goes to
  the background, so nothing arrives until it is opened again.
- **A group message held for sessions lives in memory.** It is kept in the history as queued
  and sent once the group's sessions are ready; if the app quits first it is not sent, and
  the next start marks it "not sent".
- **App Lock covers the app, not the data.** The chats are already encrypted at rest; App
  Lock only stops someone holding the unlocked device from reading them in GoMesh. It needs
  a device passcode (or a Mac password). Quick Look closes when the app locks.
- **Files are read whole and capped at 50 MB**, and go through Supabase Storage, which the
  server needs `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` and `SUPABASE_BUCKET` for.
- **The sign-in screen cannot name the device it will sign out.** Asking the server which
  device holds an account before the password is checked would tell anyone, so the warning
  is general.

---

## How to run

The repository is a Go workspace. From the root:

```bash
go work init                             # only if go.work is missing
go work use ./bridge ./client ./common ./core ./server
```

The quickest path is the Makefile: `make dev-cert` once, then `make server` and `make tui` in
separate terminals. `make help` lists the rest, including the Apple app targets.

To run the server for real, on AWS EC2, follow [`docs/deploy-ec2.md`](docs/deploy-ec2.md):
`make server-linux` builds it, `deploy/` holds the systemd unit and an example settings
file, and `apps/apple/Config/Local.xcconfig` (copied from the `.example` next to it) points
the apps at your server and holds your team ID for a real iPhone. The terminal client takes
its default server from `GOMESH_SERVER`.

Every connection is TLS 1.3. For development, create a self-signed certificate once:

```bash
make dev-cert        # writes server/dev-certs/{cert,key}.pem and prints the fingerprint
# To reach the server from a phone on your network, add its LAN address:
cd server && go run . -gen-dev-cert dev-certs 192.168.1.20
```

Then run the server and one or more clients in separate terminals:

```bash
# Optional: where the server keeps everything, accounts, conversations, group logs
# and offline queues (default gomesh.db in the working directory), and a
# certificate other than dev-certs/. Stop the server with Ctrl-C or SIGTERM: it
# saves what it had not yet sent before it exits.
export DB_PATH="gomesh.db"
export TLS_CERT="dev-certs/cert.pem" TLS_KEY="dev-certs/key.pem"

# Media send/receive uploads encrypted blobs to a Supabase Storage bucket, so the
# server needs these three variables to mint signed upload/download URLs.
# (Create a private bucket in your Supabase project and copy the service_role key.)
export SUPABASE_URL="https://<your-project>.supabase.co"
export SUPABASE_SERVICE_KEY="<service_role secret key>"
export SUPABASE_BUCKET="gomesh-media"

export LISTEN_ADDR=":8080"   # optional, this is the default

cd server && go run .
```

> If the Supabase variables are unset the server still runs, but logs `Media storage
> DISABLED` and `/file` sends are rejected. Text messaging is unaffected.

```bash
cd client && go run .
```

The client asks for the server address, shows the server's certificate fingerprint the
first time, then asks you to log in or register. It saves a session token, so later starts
skip the password. Set `GOMESH_SERVER_FP` to pin a fingerprint without the prompt.

**Files the client creates** in its working directory. Each directory is one device, so run
each client from its own directory if you want more than one account on a machine. Two
directories signed in to the *same* account are two devices, and the second sign-in signs
the first out.

| Path | Contents |
| :--- | :--- |
| `vault/` | The terminal client's stand-in for the Keychain, one 0600 file per secret: `account-key` (the random key this sign-in's state is sealed under), `identity` (the identity keys, sealed with it), `session` (server, username and token), and a `history.<account>` key per account with history here. Sign-out deletes the first three, account key first. |
| `state/` | Signed prekeys and one ratchet session or group state per chat, each a sealed file named by an HMAC. Deleted on sign-out. |
| `history.db` | Chat history, every row sealed with its account's history key. Kept across sign-out; another account's is read-only. |
| `media/` | Received and sent files, sealed, under random names. |
| `servers.json` | The certificate fingerprint pinned for each server. |
| `client.log` | Debug log. |
| `downloads/` | Plaintext copies of received files, written by the terminal client. |

A folder from an earlier version (`identity.key`, `session.json`, `gomesh-state/`) is moved
into this layout on first start, sealed, and the plaintext files are deleted.

### The Mac and iPhone app

```bash
make tools          # once: gomobile and xcodegen
make app-mac        # builds the engine framework, generates the Xcode project, builds and opens the Mac app
make app-sim        # the same for the iOS simulator (SIM="iPhone 16 Pro" by default)
```

`make xcframework` rebuilds only the engine (`apps/apple/Frameworks/GoMeshCore.xcframework`)
and `make xcodeproj` only the project; neither is committed. The server address is under
**Advanced** on the sign-in screen and defaults to `localhost:8080`, which the simulator
reaches on the Mac it runs on. The first time, the app shows the server's fingerprint to
compare with the one the server printed, and pins it. If the server's certificate later
changes (a new `make dev-cert`, say), signing in says so under the server field and offers
**Forget this server's certificate…**, after which the new fingerprint is shown to compare.
A device that is signed in and meets a changed certificate keeps retrying; sign out first.

The app keeps its device in `Application Support/GoMesh/device/`, the same layout as the
table above with the vault in the Keychain, and excludes the folder from backups. Deleting
the app and installing it again starts clean: Keychain items outlive an iOS app, so the
first launch, which finds no folder, deletes them before anything else.

Chats, groups and files work as in the terminal client. On the Mac, ⌘N starts a chat,
⌘⇧N a group and ⌘K searches; contact and group info open beside the chat; files can be
dropped onto a chat. On the iPhone, photos come from the photo picker, with their location
removed before they are sent. Notifications say only "New message" unless the sender and
text are turned on in Settings, because the system keeps notification text outside
GoMesh's encryption.

A Debug build of the Mac app can test itself from a script: launched with `-autotest` and
the `GOMESH_AUTOTEST_*` variables described in `apps/apple/GoMesh/Debug/AutoTest.swift`,
it signs up or in, or opens a chat or group, sends to it and waits for a reply, renders
every theme to PNG files in its container's `tmp/autotest/`, writes `result.json` there,
and quits.

### Signing in on another device

Signing in with the password from a directory that holds different keys moves the account
there. The user ID stays the same, so every conversation keeps its ID.

- **The old device.** The server deletes whatever was queued for it, revokes its token, and
  sends it a "replaced" notice without waiting to see if it arrives. A running client that
  gets the notice deletes its keys and exits; one that was offline finds out when it next
  starts, and does the same.
- **Contacts** are each sent a key-change notice with the new bundle. Their direct chat with
  the account restarts on the new keys, with history intact on their side and a "safety
  number changed" warning. In every group they share, they stop giving the account their
  sender key and replace their own, since the old device held it.
- **Groups.** The new device is sent the list of groups the account is in. It fetches each
  log and signs a **rekey**: a change that puts its new keys in the log in place of the old
  ones. The account stays a member, with the same role, so even a group's only admin can
  move. Every member then drops the old device's sender key, replaces its own, and gives the
  new one only to the new device. The new device sends nothing to a group until its rekey is
  in.
- **If a contact writes before hearing of the move,** on the old session, the new device
  cannot read it. It sends them a session reset, and their next message starts a fresh
  session.

### Starting over (`/dm` on an existing chat)

`/dm <name>` normally opens a chat. If a session with that person already exists it throws
that session away and performs a new handshake from scratch: a new ephemeral key, new
roots, new chains, nothing carried over. This is how a conversation that has stopped
decrypting is repaired, whichever side notices it.

- **Either side can do it.** The other side sees a handshake it does not recognise on an
  established session and treats it as a restart, replacing its own.
- **What else starts over.** The server's `CtrlDirectAck` resets a chat only when it answers
  a `/dm` the user just ran, so an unsolicited ack cannot reset a working session. Two other
  things do restart one without the user asking: a key-change notice for the peer, when the
  session is on the old keys, and a session reset from the peer, which is honoured at most
  once a minute per chat and ignored while this side's own fresh handshake is still pending.
- **Old handshakes stay dead.** The replaced session's handshake keys are remembered, so a
  captured first message from it cannot be replayed to swap the fresh session back out.
- **What is lost.** Messages either side had in flight on the old session, and anything the
  client was holding for it, which is discarded when the session is replaced.
- **Safety numbers.** If the peer's identity key differs from the one the old session was
  built on, a warning says so. Compare safety numbers before trusting the new session.

### Client commands

| Command | Effect |
| :--- | :--- |
| `/dm <username>` | Open a private chat. On a chat that already exists, start a fresh secure session in its place (see *Starting over* above) |
| `/group <name> <user1,user2>` | Create a group |
| `/chat <number>` | Switch the active conversation |
| `/list` | List conversations |
| `/add`, `/remove` `<username>` | Add or remove a group member (admin). Each is a change the admin signs. |
| `/admin`, `/remove_admin` `<username>` | Grant or revoke admin |
| `/leave` | Leave the current group |
| `/safety` | Show the safety number of the current private chat |
| `/file <path>` | Send a file |
| `/history` | Show the chats this device kept for other accounts, read-only |
| `/logout [--delete-history]` | Sign out: the token is revoked and this device's keys are deleted, and with the flag this account's history too |

---

## 1. Cryptography Architecture & E2EE Model (`common/crypto_utils.go`)

The governing principle is that **the server must never be able to read message contents
or file data**. Everything sensitive is encrypted on the sender's device and decrypted
only on the recipients'.

### 1.1 Core Algorithms

- **X25519 (ECDH)**: Elliptic-curve Diffie-Hellman over Curve25519. Used for the session
  handshake (identity key, signed prekey and a fresh ephemeral key) and again at every
  ratchet rotation.
- **Ed25519**: Signs each signed prekey, and signs the server's login challenge.
- **XChaCha20-Poly1305 (AEAD)**: Authenticated encryption with a 24-byte extended nonce.
  Encrypts every message body, and separately encrypts media blobs with a fresh random
  32-byte key per file before upload.
- **HMAC-SHA256**: Drives the symmetric ratchet that produces per-message keys.
- **SHA-256**: The conversation ID for a direct chat is derived from the two user IDs, and
  media integrity is verified by hashing the plaintext.
- **HKDF-SHA256**: Derives the handshake secret, the per-direction roots, and each new root
  and chain key at a rotation (`KDFRootKey`).

### 1.2 Key Types

- **Identity keys**: A long-term X25519 pair and an Ed25519 signing key, generated on the
  client (`identity.go`) and kept in the vault, sealed with the account key (private X25519,
  public X25519, signing seed). The private halves never leave the device. The public halves are
  registered with the server at login.
- **Signed prekey**: A medium-term X25519 pair whose public half the server hands out so
  that people can start a chat while its owner is offline. It is signed by the signing key,
  so a recipient can check the server did not swap it. The private half is kept for 30 days
  after it is replaced.
- **Ratchet keys (direct)**: Each party has one current ratchet pair. It is both the
  ephemeral key for that party's own next rotation and the key the peer mixes in when it
  rotates. Its public half is in every message header.
- **Root and chain keys (direct)**: Each *direction* has its own root key, advanced only by
  that direction's sender. A chain key derives one message key per message.
- **Sender keys (group)**: Each member holds, per group, one *sender key*: a chain key that
  ratchets once per message and an Ed25519 signing key pair, both replaced together. They
  hold one receiving copy per other member (the current key and, for 24 hours after a
  rotation, the previous one). There is no shared group key, so members rotating at the
  same moment never conflict.
- **Identity signing key (group)**: The Ed25519 key that signs membership changes.

### 1.3 Mechanisms

**Key clamping.** The X25519 private key is clamped per RFC 7748 in `generateKeyPair()`
(`private[0] &= 248`, `private[31] &= 127`, `private[31] |= 64`) to mitigate
small-subgroup attacks.

**Ratchet step.** `HMAC(ChainKey, 0x01)` produces the message key for the current payload;
`HMAC(ChainKey, 0x02)` produces the next chain key. One-way, so a stolen chain key reveals
nothing about earlier messages.

**Session handshake.** The initiator fetches the peer's bundle, verifies the prekey
signature, generates an ephemeral key `EK`, and computes
`HKDF(DH(IK_a, SPK_b) ‖ DH(EK_a, IK_b) ‖ DH(EK_a, SPK_b))`. The responder computes the
mirror image from the handshake fields in the first message. That secret is split into two
roots, one per direction.

**One root per direction.** `LowerID` assigns the lower user ID the `low->high` direction
and the higher ID `high->low`. Only the owner of a direction ever advances its root, in one
well-defined order, so two people rotating at the same moment cannot disagree about it.

**Rotation.** Every 50 messages *sent*, or on the next send after the peer publishes a
newer key, the sender generates a fresh ephemeral pair, computes a DH against the newest
peer key it has seen, and mixes the result into its root with HKDF. The new public key goes
in the next header and the receiver repeats the DH. No server round trip is involved. After
20 unacknowledged epochs the sender stops rotating and keeps only the symmetric ratchet.

**Key deletion.** A message key is erased as soon as it is used. Chain and root keys are
overwritten at each step. A private ratchet key is deleted once the peer has built a chain
against a newer one, since the peer only moves forward.

**Simultaneous handshakes.** If both sides open a chat at once, the session started by the
lower user ID stands. The loser adopts it and deletes its own; the winner keeps the loser's
session receive-only for a few minutes so nothing sent before the switch is lost.

**Conversation IDs.** `HashIDs(a, b)` sorts the two user IDs and returns the first 16 bytes
of `SHA-256(lower ‖ higher)`, so both peers compute the same ID independently. It is a
hash, so the peer cannot be recovered from it — sessions store `PeerID` explicitly.

### 1.4 Parameters

| Constant | Value | Meaning |
| :--- | :--- | :--- |
| `RotateEvery` | 50 | Messages a party sends in an epoch before rotating its ephemeral key. |
| `MaxSkipDirect` | 1000 | How far ahead of the expected index a direct message may claim to be. |
| `MaxUnackedEpochs` | 20 | Epochs the peer may leave unanswered before DH rotation stops. |
| `SkippedKeyTTL` | 7 days | How long a key for a message that never arrived is kept. |
| `SPKGrace` | 30 days | How long a retired signed prekey's private half is kept. |
| `GroupRotateEvery` | 100 | Messages this member sends under one sender key before replacing it. |
| `GroupRotateMaxAge` | 7 days | How old a sender key may get before it is replaced. |
| `OldKeyGrace` | 24 hours | How long a peer's previous sender key stays readable after they rotate. |
| `MaxSkipGroup` | 1000 | How far ahead of a sender key's chain a message may claim to be. |
| `GroupPendingTTL` | 7 days | How long a group message waits for the key or membership it needs. |
| `MaxGroupMembers` | 256 | Members in one group. |
| `auxIdle` / `auxMaxMessages` | 5 min / 100 | How long the losing session of a simultaneous handshake stays readable. |
| `maxRetiredInits` | 16 | Superseded handshakes remembered per conversation. |
| `loginTimeout` | 30 s | How long a connection has to finish logging in, TLS handshake included. |
| argon2id | t=2, 64 MiB, p=2 | Password hash cost (`defaultArgon`). |
| `IPAttempts` / `IPWindow` | 30 / 1 min | Password logins and registrations allowed from one IP. Resumes, which never hash, get ten times that. |
| `UserFailures` / `UserWindow` | 10 / 15 min | Wrong passwords allowed for one username before it is locked out for the rest of the window. |
| `HashSlots` / `HashWait` | 4 / 10 s | Password hashes that may run at once, and how long an attempt waits for a slot. |
| `MaxPreAuthBody` | 1 KiB | Largest packet the server reads before a login completes. |
| `maxOfflineQueue` / `maxQueueBytes` | 5,000 / 64 MiB | A device's offline queue; the oldest are dropped first. |

---

## 2. Network Protocol & Byte Patterns (`common/protocol.go`)

### 2.1 Fixed Header

Every packet starts with a 55-byte header, big-endian. The server uses it exclusively for
routing and is oblivious to the payload.

| Field | Size | Description |
| :--- | :--- | :--- |
| **MessageID** | 16 | Unique ID for the message. |
| **ConversationID** | 16 | The group or private chat this belongs to. |
| **SenderID** | 16 | The sender's user ID. **Stamped by the server**, so a client cannot spoof it. |
| **MsgType** | 1 | Packet type. |
| **Flags** | 2 | Bitmask. Only `FlagEncrypted (1 << 0)` is defined. |
| **BodyLen** | 4 | uint32 size of the payload that follows. |

The whole header is fed to the AEAD as associated data, so tampering with any field — the
sender ID included — fails the tag check rather than taking effect. For a direct message
the ratchet header below is appended to it, byte for byte as received.

### 2.2 Message Bodies

**Direct message** (`MsgText`, `MsgMediaMeta` and `CtrlSenderKey` in a 1-to-1 conversation):

```
[Ratchet header (50 or 118)] [Nonce (24)] [Ciphertext + Poly1305 tag]
```

The ratchet header:

| Field | Size | Meaning |
| :--- | :--- | :--- |
| Version | 1 | Always 1. Any other value is refused. |
| Flags | 1 | Bit 0: handshake fields follow. Other bits must be zero. |
| SenderEpoch | 4 | Epoch of the sender's current ratchet key. Never 0. |
| UsedPeerEpoch | 4 | Which of the receiver's keys this epoch's chain was built against. 0 means the receiver's signed prekey. |
| N | 4 | Index of this message within the epoch. |
| PrevLen | 4 | How many messages the sender's previous epoch held, so the receiver can set aside keys for the ones that are late. |
| RatchetPub | 32 | The sender's ratchet public key for `SenderEpoch`. |
| *Handshake fields* | 68 | Only while the initiator has heard nothing back: `[IdentityKey 32] [HandshakeEphemeral 32] [SPKID 4]`. |

The initiator's ephemeral key is carried explicitly in the handshake fields. `RatchetPub`
moves on at every rotation, and a later message that repeats the handshake still needs the
original.

**Group message** (`MsgText`, `MsgMediaMeta` in a group conversation):

```
[Header (46)] [Signature (64)] [Nonce (24)] [Ciphertext + Poly1305 tag]
```

| Header field | Size | Meaning |
| :--- | :--- | :--- |
| Version | 1 | Always 1. |
| GroupID | 16 | The group; must equal the packet's `ConversationID`. |
| SenderID | 16 | The sender; must equal the packet's server-stamped `SenderID`. |
| KeyID | 4 | Which of the sender's sender keys sealed this. Starts at 1 and rises on every rotation. |
| N | 4 | The message's position in that key's chain. |
| MembershipVersion | 4 | The newest membership version the sender had verified. |
| MsgType | 1 | Text or media. The packet header sits outside the signature, so the type is repeated here to stop a relay presenting one as the other. |

The header is the AEAD's associated data. The signature is Ed25519 by the sender key's
signing key over the header and the ciphertext. Receivers check it **before** doing any
chain work, so a forged message cannot move a chain.

A receiver derives message key *n* by stepping the sender's chain from where it stands,
setting aside the keys it steps over for messages that arrive late. Nothing is written back
until the signature and the ciphertext both verify, so forged packets cannot push a chain
past where the real messages are.

**Sender key distribution** (`CtrlSenderKey`, always inside a 1:1 ratchet session):

```
[Version 1 = 2] [GroupID 16] [KeyID 4] [ChainKey 32] [N 4] [SignPub 32] [MembershipVersion 4]
```

The key's owner is the **session's peer**, never a field of the payload. The chain key is
the chain at position `N`, so the recipient reads that message and everything after it, and
nothing before.

### 2.3 Operations

#### Accounts and login

Every connection is TLS 1.3, and the first packet must be one of three:

| Type | Body |
| :--- | :--- |
| `0x26 CtrlRegister` | `[ULen 1] [Username] [PLen 2] [Password] [PreKeyBundle 164] [DLen 1] [DeviceName]` |
| `0x10 CtrlLogin` | Same layout as `CtrlRegister` |
| `0x27 CtrlResume` | `[SessionToken 32] [PreKeyBundle 164]` |

`PreKeyBundle` is `[IdentityKey 32] [SigningKey 32] [SPKID 4] [SPK 32] [SPKSig 64]`. `PLen`
is two bytes because 128 characters of UTF-8 can exceed 255 bytes. Every one is then
followed by the same challenge:

- **Challenge** (`0x17 CtrlLoginChallenge`): `[Nonce 32]`, random per connection.
- **Proof** (`0x18 CtrlLoginProof`): `[Signature 64]` over
  `"GoMesh-login-v2" ‖ nonce ‖ IdentityKey ‖ username`, made with the signing key, where
  the username is in its canonical lower-case form.
- **Reply** (`0x11 CtrlLoginAck`): `[UserID 16] [SessionToken 32]`.

A refusal is a `0xFF CtrlError` with body `[Code 1] [MsgLen 2] [Msg]`. The codes are bad
request, wrong username or password, username taken, invalid username, weak password, rate
limited, session revoked, device replaced, password required, and server error.

- **Register** checks the username (3–32 characters of `a-z 0-9 _ .`, unique regardless of
  case) and the password (while GoMesh is being tested, anything non-empty up to 512 bytes),
  then stores an argon2id hash.
- **Login** checks the password. If the bundle carries the account's current keys, it is the
  same device: it gets a new token, and may present a newer signed prekey, which is how it
  rotates one. If the keys are new, the account moves to them; see *Signing in on another
  device*.
- **Resume** looks the token up. It works only with the keys it was issued to: new keys get
  "password required", and a token revoked by a move gets "device replaced", so an old
  device learns why.

Proving the signing key is still what stops someone who knows a public bundle, which the
server hands to anyone, from logging in as its owner: the password authenticates the
account, and the proof shows the device holds the keys it presents. `CtrlLogout` (`0x28`)
revokes the connection's token. Everything before the reply is read with a 1 KiB limit and
one deadline.

#### Private chat initialization (`0x15 CtrlDirectInit` → `0x16 CtrlDirectAck`)

- **Request** (client → server only): `[TargetUsername]`
- **Reply to initiator**: `[ConvID 16] [PeerID 16] [PrekeyBundle 164] [PeerUsername]`

**The target is not notified.** The server mints the conversation ID, registers it, and
answers the initiator alone. The initiator verifies the bundle's signature, builds its
session and can send straight away, even if the target is offline.

Every message the initiator sends before hearing back repeats the handshake fields in its
ratchet header, so the target can build its session from *any one* of them. It learns of
the conversation when the first message arrives, registers it under a placeholder name,
and asks the server for the roster, which supplies the name and an independent check of
the identity key the message claimed. See §4.4.

#### Conversation lookup (`0x1E CtrlConvInfoRq` → `0x1F CtrlConvInfoAck`)

- **Request**: `[ConvID 16]`
- **Reply**: `[ConvID 16] [IsGroup 1] [NameLen 2] [Name] [MemberCount 2]` then per member
  `[UserID 16] [PubKey 32] [SigningKey 32] [NameLen 2] [Name]`

This is the only route by which a client obtains another user's public key. The server
**refuses unless the requester is a member** of that conversation, and answers a
non-member with silence rather than an error, so it cannot be used to probe which
conversation IDs exist.

A single reply tells the client whether the conversation is a group and supplies every
member's identity and signing keys. For a direct chat that confirms the key the first
message claimed, and provides what the safety number needs.

#### Membership is a signed log

The server decides who receives a group's traffic, so on its own it could quietly add
itself. Every change to a group is therefore signed by the member who made it, chained to
the one before by hash, and verified by every client. The server assigns the order and
refuses what is invalid, but clients do not take its word for either.

```
GroupChange = [Version 1] [GroupID 16] [ChangeVersion 4] [PrevHash 32] [Action 1]
              [Actor 16] [Timestamp 8] [TargetCount 2] { [ID 16] [IdentityKey 32] [SigningKey 32] }
SignedChange = GroupChange ‖ Ed25519(actor's identity signing key)
PrevHash     = SHA-256("GoMesh-GroupChangeHash-v1" ‖ SignedChange of the previous change)
```

| Action | Who may sign it | Rule |
| :--- | :--- | :--- |
| `create` | the creator | Version 1. Lists every initial member, the creator included. The creator is the first admin. |
| `add` | an admin | Targets must not already be members. |
| `remove` | an admin | Targets must be members, and not the actor (an admin leaves with `leave`). |
| `leave` | the member leaving | Names only themselves. **The last admin may not leave a group that has other members**; they promote someone first. |
| `promote` | an admin | Targets must be non-admin members. |
| `demote` | an admin | Must leave at least one admin. |
| `rekey` | the member being rekeyed, **with the new key** | Names only themselves, with a new identity key and a new signing key. Role unchanged. |

A change that introduces someone carries their identity and signing keys, signed by the
admin who vouches for them, so the log is self-contained: later signatures verify against
keys the log itself established. Clients apply changes strictly in version order and buffer
any that arrive early. A change that is unsigned, wrongly signed, from a non-member, from a
non-admin, or not built on the current head is refused and changes nothing.

Of two admins who submit at the same version, the server accepts the first; the second is
sent a reject naming the head and works its request out again on top, as the client does
automatically.

| Type | Direction | Body |
| :--- | :--- | :--- |
| `0x12 CtrlGroupCreate` | client → server | `[NameLen 2] [Name] [SignedChange] [HintCount 2]…`; the first change of a new group. |
| `0x13 CtrlGroupChange` | both | Same body. Client → server submits a change; server → members is an accepted one, with hints for whoever it introduced. A removed member is sent the removal too. |
| `0x14 CtrlGroupChangeReject` | server → submitter | `[GroupID 16] [ChangeHash 32] [HeadVersion 4] [ReasonLen 2] [Reason]` |
| `0x1B CtrlGroupLogRq` | client → server | `[GroupID 16] [FromVersion 4]`. Members only. Answered with every later change, then a `CtrlGroupHints`. |
| `0x1C CtrlGroupHints` | server → client | `[GroupID 16] [HintCount 2]` then per member `[ID 16] [NameLen 2] [Name] [PrekeyBundle 164]`. |
| `0x24 CtrlUserLookupRq` / `0x25 CtrlUserLookupAck` | | A username in; `[ID 16] [PrekeyBundle 164] [Name]` out, or empty if there is no such user. Needed to name a person in a change. |
| `0x29 CtrlKeyChange` | server → client | `[ID 16] [PrekeyBundle 164] [Name]`: a contact moved to new keys. Sent to everyone who shares a conversation with them. |
| `0x2A CtrlMyGroups` | server → client | `[Count 2]` then per group `[GroupID 16] [NameLen 2] [Name]`, at every login. |
| `0x2B CtrlSessionReset` | client → server → peer | Empty, over a 1:1 conversation only: "I cannot read you; start a new session." |
| `0x2C CtrlDelivered` | client → server | `[Count 8]`: how many packets the client has handled on this connection since signing in. See *3.2 Delivery*. |
| `0x05 MsgReadReceipt` | client → server → peer | `[ID 16]…`, one to 256 message IDs the sender of this packet has read. Encrypted over the 1:1 conversation (the pair's own, for a group message), so the server relays it without knowing which messages. Never fanned out to a group. See *Receipts*. |
| `0x2D CtrlMsgAccepted` | server → sender | `[At 8]`: the server took the message named in the header's `MessageID`. A reply: dropped, not requeued, if its connection never acknowledged it. |
| `0x2E CtrlMsgDelivered` | server → sender | `[Recipient 16] [At 8]`: that recipient's device has handled the message. Durable: queued for an offline sender. |
| `0x2F CtrlReceiptsRq` | client → server | `[Since 8]`: unix milliseconds. Answered with the sender's `CtrlMsgAccepted` and `CtrlMsgDelivered` packets for messages taken since then, at most 2,000 messages and at most 14 days back. |

**Who is settled.** Clients do not check changes against keys learned outside the log,
because a log that rekeys someone holds their older keys too. They check where keys are
used instead. A member is *settled* when the client's 1:1 session with them is on the keys
the log names. Only settled members are given this client's sender key. A sender key is
installed only if the session it arrived over was on the keys the log names for its owner;
otherwise it is held until the log catches up. A member the directory says has new keys
the log lacks is *moving*: they are left out, without holding anyone else up, until their
rekey arrives. A member who is unsettled with no move to explain it gets a warning.

**Hints** are directory data (a name and a prekey bundle) so that direct sessions can be
opened without a round trip. They are not signed; a client keeps one only if its bundle
verifies and matches the identity and signing keys the signed log names for that member.

The server also registers the **pairwise conversations** between all members when a group
is created or grown, so sender keys have somewhere to be relayed. It refuses to fan a
`CtrlSenderKey` out to a group.

#### Receipts

An outgoing message is kept with what it has been told, as sets of user IDs: who it was for
when it went out, which of them the server says have it, and which say they read it. Its
ticks are computed from those sets and from who is in the chat now, so a member who has left
stops holding the ticks back.

- **Taken.** After the membership checks, `handleData` records the message in the
  `msg_receipts` table (one row per recipient, keyed by the message ID the header carries,
  which encryption leaves alone) and sends the sender a `CtrlMsgAccepted`. Only
  `MsgText` and `MsgMediaMeta` get receipts; a receipt never causes another.
- **Delivered.** When a recipient's device acknowledges the packet (`CtrlDelivered`), the
  server looks the message up in `msg_receipts`, not in the packet it handed over, marks that
  recipient, and tells the sender, once: a packet delivered again after a dropped connection is
  not reported twice. "Delivered" means the device's client handled the packet. It is
  acknowledged in batches, so the second tick can lag a moment, and a packet parked for a
  missing sender key or dropped as unreadable is acknowledged too.
- **Read.** The server cannot know. When a person reads a chat, the reader's engine sends
  each sender a `MsgReadReceipt` over the channel the two share, encrypted like a message. The
  receiver takes it as coming from whoever sent the packet, and only if that person was a
  recipient. A read while offline is kept (`ReadWanted` against `ReadSent` in the chat's
  record) and sent on the next connection. With the Settings switch off, nothing is sent and
  what was read in the meantime is never reported.
- **What the server learns.** It already saw who messaged whom, and when. It now keeps that for
  14 days in `msg_receipts` (and prunes it), and can see that a read receipt was sent and when,
  but not which message it names.
- **Missed receipts.** On every connection the engine asks for what it missed since the newest
  time the server gave it. An `accepted` reply lost with a dropped connection is recovered
  that way, and a stalled reader is never disconnected for the server's replies to it.
- **Lookup.** History rows are sealed, so a message is found by a keyed hash of its ID kept in
  a `mid` column. A receipt that beats the message into the history waits, bounded and for at
  most two minutes, and is applied when the message is kept.

#### Sending, receiving and rotating

- **Sending** (`EncryptGroupPacket`, one choke point for text and media). Replace the sender
  key first if it is due, or a member has left, or there is none. Then give the *current*
  chain position to every member who lacks it, over their direct session. Then advance the
  chain, encrypt once, sign, and **save before anything is returned**. Distribution is
  lazy: a rotation or an add costs nothing until this member next speaks, and members who
  never speak never distribute. If any member cannot be reached yet, nothing is consumed
  and the message waits.
- **Removal.** Every remaining member marks its key for replacement and forgets the removed
  member's. The new key goes only to people the verified log names, so the removed member
  never receives it and cannot read anything sent after they left. What they already
  received stays readable to them, which no scheme can prevent.
- **Add.** Nothing rotates. The newcomer is not in anyone's delivered set, so each member's
  next send gives them the *current* chain position, which only moves forward.
- **A peer's device starting over** is treated as a removal and an add.

#### Media transfers (`0x04 MsgMediaMeta`)

Heavy bytes never travel through the chat server. The encrypted blob goes directly to
Supabase Storage and only a small metadata envelope is relayed.

1. **Signed-URL exchange** (plaintext control packets):
   - `0x20 CtrlUploadRq` → `0x21 CtrlUploadAck` `[objectPath] [signed upload URL]`
   - `0x22 CtrlDownloadRq` `[objectPath]` → `0x23 CtrlDownloadAck` `[signed download URL]`

   The server holds the Supabase `service_role` key, scopes the object path to the
   conversation (`<convIDhex>/<random>`), and mints time-limited URLs. It verifies the
   requester is a **member of that conversation** first.

2. **Blob transfer** (client ⇄ Supabase, direct HTTP): the sender generates a random
   32-byte key, encrypts the file, and PUTs the ciphertext. The recipient GETs it from a
   signed download URL.

3. **The envelope**, fully E2E encrypted and relayed like any text message:
   `[NameLen 2] [FileName] [TypeLen 2] [FileType] [FileSize 8] [PathLen 2] [ObjectPath]
   [DecryptKey 32] [FileHash SHA-256 32] [ThumbLen 4] [Thumbnail JPEG]`

The recipient recomputes SHA-256 over the decrypted bytes and drops the file if it does
not match. The server sees neither the file bytes nor the decryption key.

---

## 3. Server Architecture (`server/server.go`)

A TLS broker handling concurrent connections, state, and routing. Its state lives in SQLite (`store.go`) and is loaded at start; what is in memory mirrors it.

### 3.1 State

- **Users** (`users`, `usernames`): user records, each with its password hash, its prekey
  bundle (identity key, signing key and signed prekey, all public) and its current
  **device**. The offline queue belongs to the device, not the account, so a move to new
  keys drops the old queue with the old device. Users and devices are loaded from SQLite at
  start.
- **Connections** (`clients`, `conns`): active sockets, guarded by `sync.RWMutex`.
- **Conversations** (`convs`): both 1-to-1 and group, each with a member list used to
  authorize routing. A group also holds its signed change log and the membership it
  defines. A two-party conversation is stored with its members, whether a `/dm` or a group
  made it; a group is stored as its log, which is replayed at start **without** directory
  pins, since a log that rekeyed someone holds older keys than the directory's. A group
  change is applied to a copy, stored, and only then made current.

### 3.2 Delivery

Each connection has exactly one writer goroutine (`writeLoop`), so packets are framed in
order without a write lock. Producers hand packets over via `enqueue`, which never blocks:
a recipient more than `sendBufferSize` (128) packets behind is treated as stalled and
disconnected, and its backlog spills to its device's offline queue. The offline queue is
capped at 5,000 packets and 64 MiB per device and **drops the oldest first**. A packet
spilled or requeued for a device the account no longer uses is dropped, and a connection
retired by a move writes its "replaced" notice before anything else and then closes.

**Acknowledgements.** Writing a packet to a socket does not deliver it: an iPhone can be
suspended, or change networks, with it unread. So each connection keeps the packets it has
written, in order, until the client acknowledges them with `CtrlDelivered`. The count only
grows, so the header carries no sequence numbers.

- **When the client acknowledges:** it counts every packet its read loop handles, and
  acknowledges after a quiet 250 ms, every 64 packets, and before it disconnects on purpose.
- **When a connection ends,** whatever it wrote but had not had acknowledged goes back on
  the device's queue, ahead of what it had not written yet.
- **Replies are the exception:** answers to a request (a `CtrlDirectAck`, `CtrlUploadAck`
  and the like) meant something only to the connection that asked, so they are dropped.
- **Backpressure:** at 1,024 unacknowledged packets the server stops writing to that
  connection until an acknowledgement comes, and closes it if none comes within a minute.
- **A device that reconnects before its old connection is noticed gone:** the new
  connection waits for the old one to put its packets back before draining the queue, so
  none are stranded.

The offline queue is stored row by row. When a device connects, its queue is written to it
and each row is deleted once its packet has been acknowledged: exactly that row, never a
range, because a dying connection can put older packets back after a newer one was written.
Whatever is taken but not acknowledged, however the drain ends, goes back on the queue with
the rows it already has. `Close` waits for every write loop, and each spills its unsent
packets to the store first, and for every read loop, which may be routing a last packet
into an offline queue. A shutdown that arrives before the listener is up stops the server
all the same.

### 3.3 Processing

1. **`handleConnection`** — runs the login (`authenticate` in `accounts.go`: register,
   password login or resume, then `proveKeyPossession`), binds the socket, flushes the
   device's offline queue, and reads in a loop. Every inbound packet has its `SenderID`
   overwritten with the authenticated user ID; a retired connection's packets are dropped.
2. **`handleData`** — looks the conversation up, verifies the sender is a member, and fans
   out to everyone else. A **blind relay**: with `FlagEncrypted` set it never inspects the
   body. Carries `MsgText`, `MsgMediaMeta`, and `CtrlSenderKey` (two-party conversations only).
3. **`handleDirectInit`** — answers a `/dm` with the target's prekey bundle and registers the
   conversation, without notifying the target. **`handleConvInfoRq`** — the
   membership-gated roster lookup described in §2.3.
4. **`handleUploadRq` / `handleDownloadRq`** (`supabase.go`) — the only endpoints that talk
   to Supabase. They validate membership and mint short-lived signed URLs.
5. **Membership log** (`groups.go`) — `handleGroupCreate` and `handleGroupChange` run each
   submitted change through the same `common.Membership` state machine the clients use,
   under a per-group lock so check, apply and append are one step. They also confirm that
   every key a change names matches the directory. `handleGroupLogRq` replays the log to a
   member and `handleUserLookup` resolves a username. Nothing here promotes anyone: an
   admin is whoever a signed change says.

---

## 4. Client Internals

The engine is the `core` module: one `Client` per signed-in account, with no globals, no
printing and no knowledge of screens. Everything for the user leaves as an `Event`
(`events.go`); the terminal client in `client/` and the Apple apps are hosts that
show them. `api.go` is the surface hosts call.

### 4.1 Keys at rest: the vault, `IdentityManager` (`core/identity.go`) and `StateStore` (`core/store.go`)

The **vault** holds small secrets: the Keychain on Apple devices, 0600 files in the
terminal client. It holds the **account key**, a random key made when this device first
signs in, which everything else is sealed under; the identity keys, sealed with it; and the
session token. A vault read that fails for any reason other than "not found" is an error
to retry, never taken for an empty vault, since new keys made over old ones would orphan
every session. Sign-out deletes the account key first, so whatever else is left behind can
never be opened.

The identity keys are the X25519 private and public keys and the Ed25519 signing seed. A
plaintext `identity.key` from an earlier version is moved into the vault on first open,
including one from before signing keys existed, which keeps the X25519 pair peers know and
gains a signing key.

The manager also owns the **signed prekeys**: it creates the first on first run, advertises
the current one in the login bundle, and keeps the private half of a retired one for 30
days so someone who fetched the old bundle just before a rotation can still reach it.

`StateStore` keeps one gob-encoded record per file in `state/`, sealed with
XChaCha20-Poly1305 under a key derived from the account key. Each file is named by an HMAC
of the record's name, the seal is bound to that file name, and the record's real name is
inside it: a listing says nothing about which chat a file is for, a file copied over
another does not open, and `List` finds records by opening them. Each write goes to a
temporary file that is synced and renamed into place, then the directory is synced, so a
crash leaves the old record or the new one and never a torn mixture. A record that cannot
be opened or decoded is an error, never treated as absent, and is left in place. Plaintext
records from an earlier version are sealed and deleted on first open; if a crash left both,
the sealed copy wins.

**History** (`core/history.go`) is one SQLite file per device. Each account's rows are
sealed with its own history key, which sign-out keeps, so an earlier account's chats stay
readable, read-only. Only a tag per conversation (an HMAC of the account and the
conversation) and a sequence number per message are in the clear, and each row is bound to
both. A received message is recorded before the host hears of it. Files are kept in
`media/`, sealed with the history key, under random names, and leave only through
`ExportMedia`. Deleting an account's history deletes its rows, its files and its key.

### 4.2 `SessionManager` (`core/session.go`)

**Direct sessions** (`core/ratchet.go`). `OpenDirectSession` builds the initiator's side
from a verified bundle and sends nothing. The responder's side is built by `DecryptPacket`
when a message with handshake fields matches no session it holds.

- **State** is one plain struct per conversation: both roots and chains, the ratchet keys
  still held, skipped message keys, and the handshake keys. It is copied, saved and
  restored whole.
- **Receiving** works on a copy of that state and keeps it only if the authentication tag
  verifies, so a forged index or a replay cannot move the real chain.
- **Sending** saves the new state to disk before the ciphertext is released. If the save
  fails nothing is sent, so a restart cannot reissue a key that has already gone out.
- **Epoch gaps.** A message from an epoch whose predecessor has not arrived cannot be read,
  because its root depends on the missing epoch's DH. `ErrEpochGap` marks it recoverable;
  it is held and released when the predecessor lands.
- **Pending.** A session the local side opened is *pending* until it has received something
  on it. Until then every message repeats the handshake fields, and the session loses a
  simultaneous-handshake tie-break to one opened by the lower user ID.
- **Restart.** Once a session is established, a new handshake from the peer replaces it,
  and the replaced handshake's key is remembered so a captured first message cannot be
  replayed to roll the session back.
- **Starting over.** `OpenDirectSession(..., force=true)` discards an existing session and
  opens a fresh one. The client passes `force` only for the ack to a `/dm` the user typed
  (`noteDMRequest` / `takeDMRequest`). The replaced session's retired handshakes carry
  over, and its receive-only copy is dropped.
- **Replacement hook.** `OnReplaced` fires, with no lock held, whenever a session is
  replaced, whether by a forced `/dm` or by the peer's restart. The client uses it to
  discard packets held for the old session, which could never be read.

**Group state** (`core/group.go`). A `groupState` per group is saved atomically and holds
the verified `Membership`, this member's own sender key (`ownSenderKey`), each peer's
current and previous sender key (`peerKeys`), sender keys held while membership catches up,
and the directory hints. `GroupSession` and the per-sender epoch scheme are gone.

- `ApplyGroupChange` verifies and applies a membership change, buffers one that arrives
  ahead of the log, and acts on its effects: a removal marks our key for replacement and
  deletes the removed member's keys; being removed clears the group and leaves a tombstone
  so a later sender key for it is refused rather than held.
- `ReceiveSenderKey` installs a key from a 1:1 session. It refuses one from a non-member,
  ignores a stale `KeyID`, retires the key it replaces for `OldKeyGrace`, and **holds** one
  whose `MembershipVersion` is ahead of ours: the 1:1 message it came in is consumed and
  cannot be fetched again, so rejecting it would lose the key until its owner next rotates.
- `DecryptGroupPacket` checks the header against the packet, the sender against the
  verified membership, then the signature, and only then steps the chain on a copy.
- `PeerKeysChanged` handles a peer whose session was restarted on the same keys: it forgets
  their keys and that they hold ours, and marks ours for replacement.
- `NoteDirectoryKey` takes the directory's word that a user has new keys: in every group
  whose log names other keys for them it marks them as moving, drops their old bundle, and
  marks ours for replacement. Applying their signed rekey ends it.

**Shared ratchet handling.** `advanceChain` derives the message key for a sequence number
and returns a *prospective* chain state. Nothing is written back until the ciphertext
authenticates. Committing first would let a forged sequence number push the chain past
where real messages can reach it — permanently rejecting everything that follows — and let
a replay consume a stored skipped key that a genuine late message still needed.

**Recoverable failures.** `ErrNoSession`, `ErrNoGroupSession`, `ErrNoSenderKey`,
`ErrMembershipBehind` and `ErrEpochGap` mean
"not yet" rather than "never". `Recoverable(err)` distinguishes them from a genuine reject
(bad tag, duplicate, retired epoch), which is what decides whether a packet is held or
dropped.

### 4.3 `pendingQueue` (`core/pending.go`)

Holds packets whose key has not arrived and replays them when it does — released by
conversation when a roster lands, or by conversation *and sender* when a sender key lands,
since that unblocks nothing else.

Bounded three ways, because anything held is memory that arrived unsolicited: 64 packets
per conversation, 512 overall, and a 30-second TTL. The per-conversation cap keeps the
*newest*, since whatever is blocking a conversation is likelier to resolve for recent
traffic than for a long backlog. Global eviction charges the conversation holding the most.
The TTL sweep runs on insertion, so there is no background goroutine to manage.

### 4.4 Flow (`core/client.go`, `core/connection.go`)

`readLoop` decodes from the socket and hands each packet to `deliver`, which decrypts and
dispatches — or, if the key has not arrived, holds it:

```
readLoop  →  deliver  →  dispatch
                 ↓
           park + request roster
                 ↓
        (key arrives)  →  replay  →  deliver
```

Replayed packets re-enter through `deliver`, so they take exactly the same path as fresh
ones. `requestConvInfo` is throttled to one lookup per conversation per 5 seconds, since
the server answers non-members with silence.

**Restoring state.** On start, `restoreSessions` reloads the saved direct sessions and
re-registers each conversation, so a restart picks every ratchet up where it stopped.

**Receiving a first message from an unknown peer**, end to end:

1. Ciphertext arrives for a conversation the client has never seen. Its ratchet header
   carries the initiator's handshake fields.
2. `DecryptPacket` builds the session from them and decrypts at once. If the directory
   already knows the sender's key it must match; otherwise the session is marked
   *unverified*. Nothing is parked.
3. `learnDirectPeer` registers the conversation under a placeholder name and sends
   `CtrlConvInfoRq`.
4. The roster reply gives the peer's name and signing key. `applyConvInfo` renames the
   conversation and `NotePeerKeys` confirms the identity key the message claimed. If the
   server names a different key, the session is closed.

A message with no handshake fields for a conversation with no session is parked and the
roster requested, as before. Once any direct message reads successfully, packets held for
that conversation are replayed, which is how a message waiting on an earlier epoch is
released.

A handshake under keys the client's directory does not give for the sender is held too,
and the roster requested, rather than dropped: the sender may have moved. If the roster
names the new keys, the old session is closed with a "safety number changed" warning and
the held handshake builds the new one.

If the roster arrives and there is still no session, nothing held can ever be read: the
peer has an established session and no longer sends handshake fields, and a roster carries
no prekey bundle to open one with. This is what a lost state directory, or a move the peer
has not heard of, looks like from the receiving end. The held packets are discarded and the
peer is sent a session reset.

An unknown *group* message initially takes the direct branch, because `IsGroup` returns
false for anything unregistered. That resolves itself: the roster reply says which it
really is, and the replayed packet takes the correct branch on the second pass.

**Commands become intents.** A change is only valid on one version of the log, so `/add`,
`/remove`, `/promote`-style commands record what the user asked for (`groupIntent`) and
work out the signed change against the current log (`nextChange`). If the server refuses it
because another admin's change landed first, the intent is worked out again once the
client has caught up. `/leave` by the last admin becomes `promote`, then `leave`.

**Group traffic waits for its inputs.** A group message from a membership version we have
not verified, or from a sender whose key has not arrived, is held for up to
`GroupPendingTTL` and replayed when the log advances or the key lands. A send that cannot
yet reach every member is queued and retried when their bundles arrive.

**Reconnecting.** When the connection drops, the client reports `connecting` and resumes
with the saved session over the pinned certificate, backing off from 1 s to 30 s with
jitter. It never asks a question from the background: a server whose certificate is not
pinned is not connected to, and a session that needs the password is handed to the host as
an event. A device that turns out to have been replaced, or whose session ended, signs out.
While offline, a send is refused before anything is encrypted, so no message key is burned.

### 4.5 `ClientManager` (`core/manager.go`)

Tracks conversations, usernames, and cached public keys for display and early command
checks. For groups its member and admin sets are copied from the verified membership;
nothing cryptographic reads them.

**Media** (`media.go`, `thumbnail.go`): on `/file`, `sendMedia` detects the MIME type,
hashes and encrypts the file, requests a signed upload URL, PUTs the ciphertext, and sends
the envelope. On receipt the item appears inline immediately (with an ANSI half-block
thumbnail for images) while a background download fetches, decrypts, verifies the hash,
and keeps the file sealed in `media/`; the terminal client then exports a copy to
`downloads/`.

### 4.6 TUI (`client/`)

A Bubble Tea split-screen: conversation sidebar with unread counts, message viewport, and
a system log. Slash commands with tab completion and parameter hints (including `/safety`,
which shows the safety number for the current private chat), plus a progress bar for
transfers. It is a thin host over `core`: it asks for the server and the password, turns
engine events into screen messages, shows `Reconnecting…` while the engine reconnects, and
loads a chat's history from the device when you switch to it.

### 4.7 The bridge and the Apple apps (`bridge/`, `apps/apple/`)

`bridge` is what gomobile binds: an `Engine` per data directory whose methods take and
return strings, numbers and bools, with anything richer as JSON and every ID as hex.

- **Events** reach the app through one `EventHandler.OnEvent(kind, payload)`, from a
  goroutine of the bridge's own, in order, so a slow screen never holds up the engine. The
  app's handler only queues each event onto the main thread.
- **Errors** are all `*bridge.Error`, whose text is `{"code","message"}`. The code is the
  one thing the app branches on: `bad_credentials` goes under the password field,
  `username_taken` under the username, `unreachable` and `pin_mismatch` under the server;
  `offline` means nothing was encrypted or sent. One function decides every code, and a test
  covers each.
- **The vault** is implemented in Swift. Empty data from `Get` means the item is not there,
  the one case in which the engine may make new keys; any error, a locked device
  included, stays an error, so an unreadable Keychain is never taken for an empty one. The
  adapter refuses to store an empty item for the same reason.
- **Lifecycle.** Opening a directory closes whichever engine had it, and `Close` waits for
  the read and reconnect loops, cancelling a dial in progress. An engine that signs out is
  spent; the app opens a new one on the same folder. `Register` and `Login` refuse on an
  engine that already has an account started.
- **Trust** takes two calls: `CheckServer` returns the fingerprint and whether it is pinned,
  and `TrustServer` pins exactly the one the app showed. Sign-in refuses a server that is
  not pinned.

The Swift side (`apps/apple/GoMesh/`) is one SwiftUI target for macOS and iOS. `Engine/`
wraps the bridge and runs every call that touches the network on a background task;
`App/AppState.swift` holds the screen, account and connection on the main actor;
`Vault/Vault.swift` keeps each item in the data-protection Keychain, this device only and
readable after first unlock, updated in place, and sealed again to a Secure Enclave P-256
key with ECIES and AES-GCM bound to the item's name.

**Themes** are defined once, in `design/themes.json`: 8 light, 12 dark, each with a
background, two surfaces, a border, text and muted text, an accent and the text on it, the
two bubble colours and their text, danger, warning and success, and an 8-colour palette
for avatars and names. Every published palette's colours are taken from its source, which
the file names and `design/gen_themes.py` reads to produce the file; anything adjusted for contrast is listed in that theme's `notes`, and the
canonical accent is kept wherever only the bubble needed darkening. A test in `bridge`
checks all twenty: every pairing of text and ground at 4.5:1 or better, and warning and
success at 3:1. Auto follows the system with a light and a dark theme of the person's
choosing.

---

## 5. Security Summary

**What holds:**

- **Server blindness.** Message and file contents are opaque to the server. It sees
  routing headers, control payloads, and packet sizes — nothing more.
- **Per-message keys.** Every message uses a distinct key derived by one-way HMAC ratchet,
  so compromising one message key reveals neither earlier keys nor other messages.
- **Authenticated metadata.** The header and the plaintext counters are covered by the
  AEAD tag, so a forged sender ID, conversation ID, counter or epoch fails verification
  rather than taking effect.
- **Verify-before-commit.** Ratchet state advances only after a ciphertext authenticates,
  so forged packets cannot desynchronize a chain or destroy a stored key.
- **Group removal is meaningful.** Every remaining member replaces their sender key before
  they next send, and gives the new one only to members the verified log names, so a
  removed member cannot read anything sent after they left.
- **Group senders cannot be forged.** Members hold each other's chain keys, so the
  per-message Ed25519 signature is what proves who wrote something.
- **The server cannot add or remove members.** Changes are signed by an admin, chained by
  hash, and checked by every client, so a server that adds itself, reorders, or invents a
  change is refused. It can still withhold changes, which shows as a group that stops
  growing. The one thing it could do is swap a member's keys with a forged rekey, which every
  member is shown; see *Known limitations*.
- **Authorization is checked twice.** The server refuses invalid changes, and every client
  re-checks from the signed log. Public keys are only released to conversation members.
- **Bounded resources.** Skipped keys are capped at 1000 ahead in a direct chat and in a
  group (4000 held in total per chain), held packets at 64 per conversation and 512 total,
  held sender keys at 64 per group, verified groups at 256 (plus at most 32 placeholders for
  groups only heard of through a sender key, which expire after 7 days, and 512 records of
  groups left), buffered membership changes at 64,
  retained private ratchet keys at 20 unanswered epochs, offline queues at 5,000 packets and
  64 MiB per device.

**Also holds, for direct chats and groups:**

- **Forward secrecy.** Message keys are erased on use and ratchet keys once the peer has
  moved past them, so a stolen device or key file cannot decrypt messages already read.
  Stealing long-term keys later no longer recomputes a conversation, because the handshake
  includes an ephemeral key.
- **Self-healing.** After a compromise, the next rotation mixes in a key generated
  afterwards plus the peer's contribution, so a copied state stops reading new messages
  once the two sides have exchanged one round.
- **Login is authenticated.** A password (or a token issued to these exact keys) proves the
  account, and a signature over a fresh challenge proves the device holds its keys.
- **Passwords are hashed and guessing is throttled.** argon2id with a per-account salt;
  attempts are limited per IP and per username before any hash runs, and only a few hashes
  run at once.
- **The transport is encrypted.** TLS 1.3 only, and clients accept only the certificate they
  pinned.
- **Crash safety.** State is saved before a message leaves, so a restart does not reuse a
  message key.

**What does not hold** — see *Known limitations* at the top for detail:

- **Group healing is periodic.** A stolen sender key reads that member's future messages
  until their next rotation, at most 100 messages or 7 days away, or a removal. Rotation
  heals because the new key travels over 1:1 sessions, which heal on their own.
- **A group message is readable by whoever holds a member's chain key**, which is every
  member, so a member can prove nothing to a third party about what another said beyond the
  signature itself.
- **Group metadata is visible to the server:** group IDs, members, sizes, timing, and who
  sends. It never sees chain keys, signing seeds or plaintext.
- No protection against a malicious server substituting keys, *unless* the two people
  compare safety numbers (`/safety`).
- A direction is stuck if every message of one epoch is lost. A single lost message is
  harmless, and `/dm <name>` on either side recovers a stuck chat at the cost of what was
  in flight.
- The terminal client's vault is plain files; see *Known limitations*.
