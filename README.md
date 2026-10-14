# GoMesh: Comprehensive Project Documentation

`GoMesh` is a secure messaging application supporting end-to-end encrypted (E2EE) private
chats, end-to-end encrypted group chats, and file transfers over a custom TCP protocol.

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
| Login | **Working** | The client proves it holds the account's signing key by signing a server challenge. |
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

189 tests across the three modules, plus 11 fuzz targets and end-to-end tests that
run the real server binary and drive the real client code over a socket.

```bash
cd common && go test ./...      # protocol codecs, ID ordering, the membership state machine
cd client && go test ./...      # ratchet, handshake, persistence, sender keys, membership, pending queue, end-to-end
cd server && go test ./...      # routing, signed membership log, concurrent changes

# Fuzz the decoders that parse untrusted bytes
cd common && go test -run '^$' -fuzz='^FuzzDecodeConvInfo$' -fuzztime=60s
```

> **Note:** `.gitignore` currently contains `*_test.go`, so none of the test files are
> tracked by git. Remove that line if you want them committed.

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
- **One device per user.** Each device would need to be its own member with its own sender
  keys; that is not implemented.- **Delivery is trusted to be lossless.** The server has no per-direction sequence numbers
  and no resend, and offline queues are capped at 512 packets. Out-of-order delivery is
  handled. *Loss* is not, in one case. Losing a single message is harmless, since every
  message in an epoch carries what is needed to open it. But if **every** message of an
  epoch is lost, that direction is stuck for good: each later root key chains through the
  lost epoch's ratchet key, which only its messages carry, and the sender rotating again
  does not help. In a back-and-forth chat nearly every message opens a new epoch, so one
  lost message can be enough. Nothing detects this automatically. The way out is to type
  `/dm <name>` on **either** side, which abandons the session and starts a fresh one; see
  *Starting over*. Messages in flight on the old session when you do this may not arrive.
- **A device that loses its state cannot read an established peer.** The peer's messages
  carry no handshake fields any more, so no session can be built from them. The client
  discards what it held, says so, and tells the user to run `/dm <name>`.
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
- **Ratchet and group sender-key state is stored unencrypted on disk**, in `gomesh-state/`
  next to `identity.key`, with owner-only permissions, as the identity key already is.

---

## How to run

The repository is a Go workspace. From the root:

```bash
go work init                             # only if go.work is missing
go work use ./client ./common ./server
```

Then run the server and one or more clients in separate terminals:

```bash
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

**Files the client creates** in its working directory, so run each client from its own
directory if you want more than one identity on a machine:

| Path | Contents |
| :--- | :--- |
| `identity.key` | Long-term X25519 key pair and Ed25519 signing seed. Never share it. Mode 0600. |
| `gomesh-state/` | Signed prekeys and one saved ratchet session per private chat. Mode 0700. Deleting it makes every chat start over. |
| `client.log` | Debug log. |
| `downloads/` | Received files. |

### Starting over (`/dm` on an existing chat)

`/dm <name>` normally opens a chat. If a session with that person already exists it throws
that session away and performs a new handshake from scratch: a new ephemeral key, new
roots, new chains, nothing carried over. This is how a conversation that has stopped
decrypting is repaired, whichever side notices it.

- **Either side can do it.** The other side sees a handshake it does not recognise on an
  established session and treats it as a restart, replacing its own.
- **Only a typed `/dm` counts.** The server's `CtrlDirectAck` resets a chat only when it
  answers a `/dm` the user just ran, so an unsolicited ack cannot reset a working session.
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
  client (`identity.go`) and stored in `identity.key` (private X25519, public X25519,
  signing seed). The private halves never leave the device. The public halves are
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
| `loginProofTimeout` | 10 s | How long the server waits for a login proof. |

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

#### Login (`0x10 CtrlLogin` → `0x17 CtrlLoginChallenge` → `0x18 CtrlLoginProof` → `0x11 CtrlLoginAck`)

- **Request**: a prekey bundle, then the username.
  `[IdentityKey 32] [SigningKey 32] [SPKID 4] [SPK 32] [SPKSig 64] [Username]`
- **Challenge**: `[Nonce 32]`, random per connection.
- **Proof**: `[Signature 64]` over `"GoMesh-login-v1" ‖ nonce ‖ IdentityKey ‖ username`,
  made with the signing key.
- **Reply**: `[Assigned UserID 16]`

The server refuses a bundle whose prekey signature does not verify before issuing a
challenge. The identity key and signing key are pinned to the username on first use; a
returning user must present both unchanged and sign the challenge. Only the signed prekey
may change between logins, which is how it is rotated. A public bundle, which the server
hands to anyone, is therefore not enough to log in as its owner. The server then binds the
socket and flushes any offline queue.

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

**Hints** are directory data (a name and a prekey bundle) so that direct sessions can be
opened without a round trip. They are not signed; a client keeps one only if its bundle
verifies and matches the identity and signing keys the signed log names for that member.

The server also registers the **pairwise conversations** between all members when a group
is created or grown, so sender keys have somewhere to be relayed. It refuses to fan a
`CtrlSenderKey` out to a group.

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

A TCP broker handling concurrent connections, state, and routing.

### 3.1 State

- **Users** (`users`, `usernames`): user records, each with its prekey bundle (identity key,
  signing key and signed prekey, all public) and a per-user offline queue.
- **Connections** (`clients`, `conns`): active sockets, guarded by `sync.RWMutex`.
- **Conversations** (`convs`): both 1-to-1 and group, each with a member list used to
  authorize routing. A group also holds its signed change log and the membership it
  defines.

### 3.2 Delivery

Each connection has exactly one writer goroutine (`writeLoop`), so packets are framed in
order without a write lock. Producers hand packets over via `enqueue`, which never blocks:
a recipient more than `sendBufferSize` (128) packets behind is treated as stalled and
disconnected, and its backlog spills to the offline queue. The offline queue is capped at
512 packets per user and **drops the oldest first**.

### 3.3 Processing

1. **`handleConnection`** — forces a login packet, checks the prekey bundle, issues the login
   challenge and verifies the signed reply (`proveKeyPossession`), then pins the keys
   (`authenticateUser`), binds the socket, flushes the offline queue, and reads in a loop.
   Every inbound packet has its `SenderID` overwritten with the authenticated user ID.
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

### 4.1 `IdentityManager` (`client/identity.go`) and `StateStore` (`client/store.go`)

`identity.key` holds the X25519 private and public keys and the Ed25519 signing seed. A
file from before signing keys existed holds only the first two and is upgraded in place,
keeping the identity key peers already know. The public key is re-derived from the private
key at runtime. The file is written atomically with owner-only permissions.

The manager also owns the **signed prekeys**: it creates the first on first run, advertises
the current one in the login bundle, and keeps the private half of a retired one for 30
days so someone who fetched the old bundle just before a rotation can still reach it.

`StateStore` keeps one gob-encoded record per file in `gomesh-state/`. Each write goes to a
temporary file that is synced and renamed into place, then the directory is synced, so a
crash leaves the old record or the new one and never a torn mixture. The directory is
bound to one identity key; if `identity.key` is replaced, the old records are discarded.
A record that cannot be decoded is an error, never treated as absent.

### 4.2 `SessionManager` (`client/session.go`)

**Direct sessions** (`client/ratchet.go`). `OpenDirectSession` builds the initiator's side
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

**Group state** (`client/group.go`). A `groupState` per group is saved atomically and holds
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
- `PeerKeysChanged` handles a peer whose session was replaced: it forgets their keys and
  that they hold ours, and marks ours for replacement.

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

### 4.3 `pendingQueue` (`client/pending.go`)

Holds packets whose key has not arrived and replays them when it does — released by
conversation when a roster lands, or by conversation *and sender* when a sender key lands,
since that unblocks nothing else.

Bounded three ways, because anything held is memory that arrived unsolicited: 64 packets
per conversation, 512 overall, and a 30-second TTL. The per-conversation cap keeps the
*newest*, since whatever is blocking a conversation is likelier to resolve for recent
traffic than for a long backlog. Global eviction charges the conversation holding the most.
The TTL sweep runs on insertion, so there is no background goroutine to manage.

### 4.4 Flow (`client/client.go`)

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

If the roster arrives and there is still no session, nothing held can ever be read: the
peer has an established session and no longer sends handshake fields, and a roster carries
no prekey bundle to open one with. This is what a lost state directory looks like from the
receiving end. The held packets are discarded, and the user is told to run `/dm <name>`.

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

### 4.5 `ClientManager` (`client/manager.go`)

Tracks conversations, usernames, and cached public keys for display and early command
checks. For groups its member and admin sets are copied from the verified membership;
nothing cryptographic reads them.

**Media** (`media.go`, `thumbnail.go`): on `/file`, `sendMedia` detects the MIME type,
hashes and encrypts the file, requests a signed upload URL, PUTs the ciphertext, and sends
the envelope. On receipt the item appears inline immediately (with an ANSI half-block
thumbnail for images) while a background download fetches, decrypts, verifies the hash,
and saves to `downloads/`.

### 4.6 TUI (`client/ui.go`)

A Bubble Tea split-screen: conversation sidebar with unread counts, message viewport, and
a system log. Slash commands with tab completion and parameter hints (including `/safety`,
which shows the safety number for the current private chat), plus a progress bar for
transfers.

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
- **The server cannot edit membership.** Changes are signed by an admin, chained by hash,
  and checked by every client, so a server that adds itself, reorders, or invents a change
  is refused. It can still withhold changes, which shows as a group that stops growing.
- **Authorization is checked twice.** The server refuses invalid changes, and every client
  re-checks from the signed log. Public keys are only released to conversation members.
- **Bounded resources.** Skipped keys are capped at 1000 ahead in a direct chat and in a
  group (4000 held in total per chain), held packets at 64 per conversation and 512 total,
  held sender keys at 64 per group, verified groups at 256 (plus at most 32 placeholders for
  groups only heard of through a sender key, which expire after 7 days, and 512 records of
  groups left), buffered membership changes at 64,
  retained private ratchet keys at 20 unanswered epochs, offline queues at 512 per user.

**Also holds, for direct chats and groups:**

- **Forward secrecy.** Message keys are erased on use and ratchet keys once the peer has
  moved past them, so a stolen device or key file cannot decrypt messages already read.
  Stealing long-term keys later no longer recomputes a conversation, because the handshake
  includes an ephemeral key.
- **Self-healing.** After a compromise, the next rotation mixes in a key generated
  afterwards plus the peer's contribution, so a copied state stops reading new messages
  once the two sides have exchanged one round.
- **Login is authenticated.** The signing key is pinned and proven at every login.
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
- Ratchet state on disk is not encrypted.
