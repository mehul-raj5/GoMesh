# GoMesh: Comprehensive Project Documentation

This document provides an exhaustive, self-explanatory guide to every mechanism, byte pattern, cryptographic algorithm, and component within the `GoMesh` project. `GoMesh` is a secure messaging application supporting End-to-End Encrypted (E2EE) private chats, group messaging, and file transfers over a custom TCP protocol.

---

## 1. Cryptography Architecture (`Common/crypto_utils.go`)
The security of GoMesh relies on several state-of-the-art cryptographic primitives.

### 1.1 Core Algorithms
- **X25519 (ECDH)**: Elliptic-Curve Diffie-Hellman over Curve25519. Used for establishing shared secrets during handshakes.
- **XChaCha20-Poly1305 (AEAD)**: An Authenticated Encryption with Associated Data (AEAD) cipher. Combines the ChaCha20 stream cipher with Poly1305 MAC, using a 24-byte extended nonce. Used to encrypt all message bodies.
- **HKDF (SHA-256)**: HMAC-based Extract-and-Expand Key Derivation Function. Used to derive session keys securely from ECDH shared secrets.
- **HMAC (SHA-256)**: Hash-based Message Authentication Code used specifically in the Ratchet chain to derive message keys and next chain keys.

### 1.2 Key Types
- **Identity Keys**: Long-term X25519 key pairs generated on the client side (`identity.go`). The private key is strictly kept local, while the public key is shared with the server and peers.
- **Ephemeral Keys**: Short-lived X25519 key pairs used during the initial Direct Chat handshake to guarantee Perfect Forward Secrecy (PFS).
- **Session Keys**: 32-byte keys derived to encrypt group messages.
- **Ratchet Chain/Message Keys**: Derived via `RatchetStep()` in `crypto_utils.go` using HMAC-SHA256 for the Double Ratchet implementation in private chats.

### 1.3 Mechanisms
- **Key Clamping**: The private X25519 key undergoes bitwise clamping (RFC 7748) in `generateKeyPair()` to mitigate small-subgroup attacks (`private[0] &= 248`, `private[31] &= 127`, `private[31] |= 64`).
- **Ratchet Step**: Steps the chain forward. `KDF(ChainKey, 0x01)` produces the `MessageKey`, and `KDF(ChainKey, 0x02)` produces the `NextChainKey`.

---

## 2. Network Protocol & Byte Patterns (`Common/protocol.go`)

### 2.1 Fixed Header
Every packet transmitted over TCP starts with a 55-byte fixed-size header. It uses Big-Endian byte order for integers.

| Field | Size (Bytes) | Description |
| :--- | :--- | :--- |
| **MessageID** | 16 | Unique UUID for the message. |
| **ConversationID**| 16 | The ID of the Group or Private Chat. |
| **SenderID** | 16 | The UUID of the user sending the packet. |
| **MsgType** | 1 | Enum representing the packet type. |
| **Flags** | 2 | Bitmask for states (e.g., `0x01` Encrypted, `0x02` Handshake). |
| **BodyLen** | 4 | uint32 indicating the exact size of the payload following the header. |

### 2.2 Packet Flags (Bitmask)
- `FlagEncrypted (1 << 0)`: Indicates the payload is encrypted `[Nonce(24 bytes)] + [Ciphertext]`.
- `FlagHandshake (1 << 1)`: Used during `CtrlDirectInit` setups.
- `FlagAck (1 << 2)`: Standard acknowledgment flag.
- `FlagInit (1 << 3)`: Auto-initialization flag.

### 2.3 Operations & Extrapolated Message Bodies

#### Handshake (MsgType `0x10` Login | `0x11` Ack)
- **Login Body**: `[PublicKey 32 bytes] + [Username string (variable)]`
- **Ack Body**: `[Assigned UserID 16 bytes]`

#### Creating a Group (MsgType `0x12`)
- **Client -> Server Body**: `[NameLen 1] + [GroupName] + [MemberCount 1] + ([UserLen 1] + [Username])...`
- **Server -> Client Broadcast**: `[ConvID 16] + [NameLen 1] + [GroupName] + [MemberCount 1] + ([UserID 16] + [NameLen 1] + [UserName])...`

#### Private Chat Initialization (MsgType `0x15` Init | `0x16` Ack)
- **Target Notification Body**: `[ConvID 16] + [SenderPubKey 32] + [SenderUsername string]`
- **Ack to Initiator**: `[ConvID 16] + [TargetPubKey 32]`

#### Text Messages (MsgType `0x01`)
- **Unencrypted**: `[Payload String]`
- **Private E2EE Payload**: `[SeqNum uint32 (4 bytes)] + [XChaCha20 Nonce (24 bytes)] + [Ciphertext]`
- **Group Encrypted Payload**: `[KeyVersion uint32 (4 bytes)] + [XChaCha20 Nonce (24 bytes)] + [Ciphertext]`

#### File Transfers (MsgTypes `0x02` Meta | `0x03` Chunk)
- **MsgFileMeta**: `[NameLen uint16(2)] + [FileName] + [TypeLen uint16(2)] + [FileType] + [FileSize uint64(8)] + [TotalChunks uint32(4)]`
- **MsgFileChunk**: `[ChunkNo uint32(4)] + [ChunkData (max 32KB)]`

#### Group Administration Control Types
- `0x13 CtrlGroupAdd`: Add members.
- `0x14 CtrlGroupRemove`: Remove members from group.
- `0x1B CtrlGroupMakeAdmin`: Elevate member to admin.
- `0x1C CtrlGroupRemoveAdmin`: Revoke admin privileges.
- `0x17 CtrlGroupKeyUpdate`: Propagates the new Symmetric Group Key whenever membership changes or after 5 messages. This payload `[GroupID 16] + [Version 4] + [GroupKey 32]` is encrypted via 1-to-1 secure private sessions with each member.

---

## 3. Server Architecture (`Server/server.go`)

The central broker handles connections, state management, and real-time routing.

### 3.1 State Management Structure
- **Users Cache (`users`, `usernames`)**: Maps UUIDs/Usernames to User Objects (Holds offline queues and identity keys).
- **Client Connections (`clients`, `conns`)**: Maps active `net.Conn` sockets to users. Protected by `sync.RWMutex`.
- **Conversations (`convs`)**: Maintains state for both 1-to-1 chats and Groups. Stores a `Members` hash set, and an `Admins` hash set (crucial for verifying permissions).

### 3.2 Processing Loop
1. **`handleConnection`**: Blocks on standard `net.Accept()`. Forces an immediate `handshake/login` packet. Binds a struct instance to the TCP socket and triggers the off-line queue flush to deliver missed messages.
2. **`handleData`**: Any standard message/file payload simply gets distributed to all other users in the `ConversationID` member set. The server acts as a blind relay (it cannot decrypt AES/XChaCha20 data).
3. **Admin Verification**: `handleGroupAdd`, `handleGroupRemove`, etc., explicitly look up `conv.Admins[sender.UserID]` to reject unauthorized network messages.

---

## 4. Client Internal Workings

The client is highly decoupled into session tracking, cryptography application, UI rendering, and network looping.

### 4.1 `IdentityManager` (`Clients/identity.go`)
Loads or generates the root `identity.key` file holding 64 bytes (`[Private X25519 32][Public X25519 32]`). It programmatically derives the public key from the private key at runtime to bypass corrupted key files.

### 4.2 `SessionManager` (`Clients/session.go`)
The core nexus for managing End-to-End Encryption algorithms.

- **Private Chat (Symmetric Ratchet)**:
  - Implements out-of-order execution (up to 2000 messages) by saving derived message keys into a HashMap `SkippedKeys`.
  - On `EncryptPacket`, it prepends the `SeqNum` in raw text, generates a Message Key via `RatchetStep()`, encrypts the body, and attaches it.
  - On `DecryptPacket`, it parses the 4-byte `SeqNum`, ratchets the Recv Chain forward efficiently, decrypts via XChaCha20-Poly1305, and clears the flag.
- **Group Encryption**:
  - Employs a shared `CurrentKey` + `CurrentVersion` model.
  - Prepends `CurrentVersion` in plain text. Prevents reading key mismatches.
  - **Key Rotation**: Group admins track `MessageCounter`. Once it hits 5, or if a member joins/leaves, they invoke `rotateGroupKey()`, generate a random 32-byte key, encrypt it using the 1-to-1 private chat sessions, and distribute `CtrlGroupKeyUpdate` packets to active members.

### 4.3 `ClientManager` (`Clients/manager.go`)
- **File Assembly Engine**: Intercepts `MsgFileMeta` messages to reserve `FileSize` bytes dynamically inside the `PendingFiles` map. Streams `MsgFileChunk` bytes into appropriate memory offsets depending on the `ChunkNo * 32768`. Writes to physical disks immediately after completion.
- **Conversation Tracking**: Handles localized metadata, admin tracking, member caches, and caching public keys retrieved from the server (with a 5-second timeout on requests).

### 4.4 Flow Loop (`Clients/client.go`)
- **`main()`**: Reaches out to the server via Dial and instantiates the managers.
- **`readLoop()`**: Runs on an infinite `goroutine`. Detects `FlagEncrypted` header bits, decrypts on the fly, and multiplexes payloads via a massive `switch` statement updating the UI with formats like `[Group] Username: Hello`.
- **`inputLoop()`**: Continuously scans `os.Stdin` in the main thread rendering the "Menu" system to fire off file transfers, direct messages, and administration protocols.

---

## 5. Security Summary
- Messages generated in Private Chats are entirely opaque to the Server (Forward Secrecy maintained by rotating chain keys).
- Group messages are secure against server eavesdropping but do not feature forward secrecy inherently (except through arbitrary key rotations enforced by the client).
- The protocol prevents bad actors from spoofing administrative operations entirely via Server-side checks on `CtrlGroupAdd`, `CtrlGroupRemove`, `CtrlGroupMakeAdmin`, and `CtrlGroupRemoveAdmin`.
