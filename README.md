# GoMesh: Comprehensive Project Documentation

This document provides an exhaustive, self-explanatory guide to every mechanism, byte pattern, cryptographic algorithm, and component within the `GoMesh` project. `GoMesh` is a secure messaging application supporting End-to-End Encrypted (E2EE) private chats, group messaging, and file transfers over a custom TCP protocol.

---

## How to run

To set up the workspace and link the local modules together properly, run the following commands from the root directory:

```bash
cd /Users/mehulraj/Desktop/PROJECTS\ /MSR\(GO\)
go work init
go work use ./client ./common ./server
```

Once the workspace is initialized, you can run the server and client(s) in separate terminal windows:

```bash
# Start the server first
cd server
go run .
```

```bash
# Start a client in a new terminal
cd client
go run .
```

---

## 1. Cryptography Architecture & E2EE Model (`common/crypto_utils.go`)

The security of GoMesh relies on several state-of-the-art cryptographic primitives. The fundamental philosophy of the project is that **the backend server must never be able to read message contents or file data**. All sensitive data is encrypted on the sender's device and decrypted only on the recipients' devices.

### 1.1 Core Algorithms
- **X25519 (ECDH)**: Elliptic-Curve Diffie-Hellman over Curve25519. Used for establishing shared secrets during the initial handshake phases of a 1-to-1 secure session.
- **XChaCha20-Poly1305 (AEAD)**: An Authenticated Encryption with Associated Data (AEAD) cipher. Combines the ChaCha20 stream cipher with Poly1305 MAC, using a 24-byte extended nonce. Used to encrypt all message bodies and file chunks end-to-end.
- **HKDF (SHA-256)**: HMAC-based Extract-and-Expand Key Derivation Function. Used to derive robust session keys securely from ECDH shared secrets.
- **HMAC (SHA-256)**: Hash-based Message Authentication Code used specifically in the Ratchet chain to derive message keys and next chain keys.

### 1.2 Key Types
- **Identity Keys**: Long-term X25519 key pairs generated on the client side (`identity.go`). The private key is strictly kept local, while the public key is shared with the server and peers.
- **Ephemeral Keys**: Short-lived X25519 key pairs used during the initial Direct Chat handshake to guarantee Perfect Forward Secrecy (PFS) in private conversations.
- **Session Keys (Group)**: 32-byte symmetric keys derived to encrypt group messages. These are rotated periodically by the group admin and securely distributed to members using their individual 1-to-1 E2EE private channels.
- **Ratchet Chain/Message Keys (Private)**: Derived via `RatchetStep()` in `crypto_utils.go` using HMAC-SHA256 for the Double Ratchet implementation in private chats, ensuring forward secrecy for every individual message.

### 1.3 Mechanisms
- **Key Clamping**: The private X25519 key undergoes bitwise clamping (RFC 7748) in `generateKeyPair()` to mitigate small-subgroup attacks (`private[0] &= 248`, `private[31] &= 127`, `private[31] |= 64`).
- **Ratchet Step**: Steps the chain forward. `KDF(ChainKey, 0x01)` produces the `MessageKey` for the current payload, and `KDF(ChainKey, 0x02)` produces the `NextChainKey` for future use.

---

## 2. Network Protocol & Byte Patterns (`common/protocol.go`)

### 2.1 Fixed Header
Every packet transmitted over TCP starts with a 55-byte fixed-size header. It uses Big-Endian byte order for integers. The server uses this header exclusively for routing, oblivious to the encrypted payload that follows.

| Field | Size (Bytes) | Description |
| :--- | :--- | :--- |
| **MessageID** | 16 | Unique UUID for the message. |
| **ConversationID**| 16 | The ID of the Group or Private Chat. |
| **SenderID** | 16 | The UUID of the user sending the packet. |
| **MsgType** | 1 | Enum representing the packet type. |
| **Flags** | 2 | Bitmask for states (e.g., `0x01` Encrypted, `0x02` Handshake). |
| **BodyLen** | 4 | uint32 indicating the exact size of the payload following the header. |

### 2.2 Packet Flags (Bitmask)
- `FlagEncrypted (1 << 0)`: Indicates the payload is E2E encrypted: `[Nonce(24 bytes)] + [Ciphertext]`. The backend forwards these blindly.
- `FlagHandshake (1 << 1)`: Used during `CtrlDirectInit` setups to trigger the asynchronous Diffie-Hellman key exchange.
- `FlagAck (1 << 2)`: Standard acknowledgment flag.
- `FlagInit (1 << 3)`: Auto-initialization flag.

### 2.3 Operations, Messages & E2EE Enforcement

#### Handshake (MsgType `0x10` Login | `0x11` Ack)
- **Login Body**: `[PublicKey 32 bytes] + [Username string (variable)]`
- **Ack Body**: `[Assigned UserID 16 bytes]`
- **Backend Role**: The server registers the user, maps their TCP socket, and stores their public key to facilitate future peer-to-peer handshakes.

#### Private Chat Initialization (MsgType `0x15` Init | `0x16` Ack)
- **Target Notification Body**: `[ConvID 16] + [SenderPubKey 32] + [SenderUsername string]`
- **Ack to Initiator**: `[ConvID 16] + [TargetPubKey 32]`
- **E2EE Aspect**: This performs an ECDH exchange involving both identity and ephemeral keys. The server merely routes the public keys between the two clients. Once the exchange completes, the Double Ratchet session begins, making all subsequent traffic mathematically opaque to the server.

#### Creating a Group (MsgType `0x12`)
- **Client -> Server Body**: `[NameLen 1] + [GroupName] + [MemberCount 1] + ([UserLen 1] + [Username])...`
- **Server -> Client Broadcast**: `[ConvID 16] + [NameLen 1] + [GroupName] + [MemberCount 1] + ([UserID 16] + [NameLen 1] + [UserName])...`
- **Backend Role**: The server creates a logical grouping of users in memory, tracking membership and administrative roles to enforce protocol-level access control.

#### Text Messages (MsgType `0x01`)
- **Unencrypted**: `[Payload String]` (Available structurally, but overridden by E2EE for standard chats).
- **Private E2EE Payload**: `[SeqNum uint32 (4 bytes)] + [XChaCha20 Nonce (24 bytes)] + [Ciphertext]`
- **Group Encrypted Payload**: `[KeyVersion uint32 (4 bytes)] + [XChaCha20 Nonce (24 bytes)] + [Ciphertext]`
- **Backend Role**: The server examines the `ConversationID`, looks up the associated TCP sockets, and multiplexes the bytes. It cannot read the text.

#### File Transfers (MsgTypes `0x02` Meta | `0x03` Chunk)
- **MsgFileMeta**: `[NameLen uint16(2)] + [FileName] + [TypeLen uint16(2)] + [FileType] + [FileSize uint64(8)] + [TotalChunks uint32(4)]` (Fully E2E encrypted).
- **MsgFileChunk**: `[ChunkNo uint32(4)] + [ChunkData (max 32KB)]` (Fully E2E encrypted).
- **Backend Role**: The server routes chunk packets seamlessly. High-volume data never touches server-side disk storage; it remains completely ephemeral and securely encrypted in-transit.

#### Group Administration Control Types
- `0x13 CtrlGroupAdd`: Add members.
- `0x14 CtrlGroupRemove`: Remove members from group or self-leave.
- `0x1B CtrlGroupMakeAdmin`: Elevate member to admin.
- `0x1C CtrlGroupRemoveAdmin`: Revoke admin privileges.
- `0x17 CtrlGroupKeyUpdate`: Propagates the new Symmetric Group Key whenever membership changes or after 5 messages. This payload `[GroupID 16] + [Version 4] + [GroupKey 32]` is **encrypted via 1-to-1 secure private sessions** with each member before sending over the network, guaranteeing that the backend can never intercept the group chat's master symmetric key.

---

## 3. Server Architecture (`server/server.go`)

The central backend broker is specifically designed to handle high-concurrency TCP connections, state management, and real-time routing securely securely and efficiently.

### 3.1 State Management Structure
- **Users Cache (`users`, `usernames`)**: Maps UUIDs/Usernames to User Objects. Crucially, it tracks user offline queues and their public identity keys.
- **Client Connections (`clients`, `conns`)**: Maps active `net.Conn` sockets to connected users. Protected heavily by `sync.RWMutex` to prevent race conditions during high message velocity.
- **Conversations (`convs`)**: Maintains state for both 1-to-1 chats and Groups. Stores a `Members` hash set, and an `Admins` hash set. The backend relies on these in-memory data structures to securely verify transmission authorizations.

### 3.2 Backend Processing Loop
1. **`handleConnection`**: Blocks on standard `net.Accept()`. Forces an immediate `handshake/login` packet from the connecting client. Once authenticated, binds a struct instance to the TCP socket and triggers the off-line queue flush to deliver any E2EE messages missed while the user was disconnected.
2. **`handleData`**: Any standard message or file payload simply gets mapped via `ConversationID` and distributed to all other users in that subset. The server acts entirely as a **blind relay**. Because the `FlagEncrypted` bit is set, the server ignores the body and pushes raw encrypted bytes directly into the outgoing TCP buffers of the intended recipients.
3. **Explicit Admin Verification**: Network handlers like `handleGroupAdd`, `handleGroupRemove`, `handleGroupMakeAdmin`, explicitly look up the sender's privileges in the `conv.Admins[sender.UserID]` map to reject unauthorized network messages before they propagate. The backend enforces structure without ever looking at the contents.

---

## 4. Client Internal Workings

The client is highly decoupled into session tracking, cryptography application, Bubble Tea TUI rendering, and distinct network loops.

### 4.1 `IdentityManager` (`client/identity.go`)
Loads or generates the root `identity.key` file holding 64 bytes (`[Private X25519 32][Public X25519 32]`). It programmatically derives the public key from the private key at runtime to bypass corrupted key files.

### 4.2 `SessionManager` (`client/session.go`)
The core nexus for managing End-to-End Encryption algorithms on the client-side.

- **Private Chat (Symmetric Ratchet)**:
  - Implements out-of-order execution (up to 2000 messages) by saving derived message keys into a HashMap `SkippedKeys`. If a message arrives out of order due to network latency, the client can securely decrypt it using the skipped key memory.
  - On `EncryptPacket`, it prepends the `SeqNum` in raw text, generates a Message Key via `RatchetStep()`, encrypts the body via XChaCha20, and attaches it.
  - On `DecryptPacket`, it parses the 4-byte `SeqNum`, ratchets the Recv Chain forward efficiently, decrypts via XChaCha20-Poly1305, and clears the flag.
- **Group Encryption**:
  - Employs a shared `CurrentKey` + `CurrentVersion` model.
  - Prepends `CurrentVersion` in plain text. Prevents the client from attempting to decrypt messages if the Group Key has rotated but they missed the network update.
  - **Key Rotation**: Group admins track the `MessageCounter`. Once it hits 5, or if a member joins/leaves, they proactively invoke `rotateGroupKey()`. They generate a random 32-byte key, individually encrypt this new key using the 1-to-1 private chat sessions established with every group member, and distribute `CtrlGroupKeyUpdate` packets asynchronously.

### 4.3 `ClientManager` (`client/manager.go`)
- **File Assembly Engine**: Intercepts `MsgFileMeta` messages to reserve `FileSize` bytes dynamically inside the `PendingFiles` map. Streams `MsgFileChunk` bytes into appropriate memory offsets depending on the `ChunkNo * 32768`. Since chunks are individually E2E encrypted, they are decrypted upon receipt and written to physical disks immediately after verification.
- **Conversation Tracking**: Handles localized metadata, admin tracking, member caches, and caching public keys retrieved from the server (with a 5-second timeout on requests).

### 4.4 Flow Loop & TUI (`client/client.go` & `client/ui.go`)
- **`main()`**: Reaches out to the server via TCP dial and instantiates the managers. Invokes the Bubble Tea framework for the display.
- **Terminal User Interface (`ui.go`)**: Renders a sophisticated split-screen view with state-driven updates. Features command parsing (e.g. `/admin`, `/remove_admin`, `/leave`, `/file`) and intelligent status indicators.
- **`readLoop()`**: Runs on an infinite `goroutine`. Detects `FlagEncrypted` header bits, decrypts on the fly, and multiplexes payloads synchronously to the Bubble Tea application via `msg` channels, triggering screen re-renders seamlessly without blocking the network buffer.

---

## 5. Security Summary
- **Backend Blindness**: Messages and files generated in Private Chats or Groups are entirely opaque to the Server. It processes only explicit headers and control payloads necessary for routing.
- **Perfect Forward Secrecy**: The Double Ratchet chain used in 1-to-1 chats guarantees that even if a future key is compromised, past messages remain mathematically secure.
- **Secure Group Rotation**: Group messages are secure against server eavesdropping. Forward secrecy within groups is actively simulated via forced key rotations enforced by the client admins every 5 messages or upon roster changes.
- **Authoritative Backend Constraints**: The protocol prevents bad actors from spoofing administrative operations entirely via Server-side checks on `CtrlGroupAdd`, `CtrlGroupRemove`, `CtrlGroupMakeAdmin`, and `CtrlGroupRemoveAdmin`. The backend ensures trust without violating encryption boundaries.
