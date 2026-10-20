# GoMesh

An end-to-end encrypted messenger I built to understand how secure messaging really works. The engine, server and protocol are written in Go, and there is a native SwiftUI app for the Mac and iPhone on top.

> **Demo (about 60 seconds):** [watch the video](VIDEO_LINK_HERE)

It is a learning project, not a product. I followed the published designs behind Signal (signed-prekey handshake, ratcheting keys, sender keys for groups), wrote my own implementation, and then tried to break it with tests. It has **not** been audited. Please don't trust it with anything that matters.

## What it does

- Private chats and group chats, end-to-end encrypted. The server only ever sees ciphertext.
- Accounts with a username and password, then a signed proof that your device holds its keys.
- Files and photos, encrypted before upload.
- Delivery and read ticks, with the "read" part encrypted too (and optional).
- Signing in on a new device moves your account: the old device is signed out and wipes its keys, your contacts are told, and your groups are re-keyed.
- Safety numbers to compare with a friend, so you can spot a swapped key.
- A Mac and iPhone app with 22 themes, each checked for readable contrast.

## How it works, briefly

Think of it in four layers.

1. **Transport.** Everything runs over TLS 1.3. The app pins the server's certificate fingerprint the first time you trust it.
2. **Login.** You send your username and password plus your public key bundle. The server answers with a random challenge and you sign it with a private key that never leaves the device. A password alone isn't enough, and neither is a public bundle.
3. **Private chats.** A Signal-style handshake mixes three Diffie-Hellman results into a starting secret. After that, every message gets its own key from a ratchet. Keys rotate every 50 messages, and old ones are deleted, so a stolen key can't read the past.
4. **Group chats.** Each member keeps a sender key per group and gives it to every other member inside their private chat. A message is encrypted once and signed by its sender, then the server fans out the same bytes. Who is in the group is a hash-chained, signed log that every client checks for itself, so the server can order changes but can't quietly add anyone.

The full walk-through, packet by packet, is in [`docs/technical-reference.md`](docs/technical-reference.md).

### The keys, and how long they live

| Key | What it's for | Lifetime |
| :--- | :--- | :--- |
| Account key | Seals every other secret and file on the device | Until sign-out or device replacement. Never sent anywhere. |
| Identity key pair | Proves who you are in each new private chat | Same. Only the public half goes to the server. |
| Signing key pair | Signs your login proof, prekeys and group changes | Same |
| Signed prekey | Lets people start a chat with you while you're offline | Replaced over time. The old private half is kept 30 days. |
| Session token | Reconnect without the password | Until logout or replacement. The server stores only its hash. |
| Ratchet and message keys | One key per message | A message key is used once, then wiped |
| Group sender key | Encrypts and signs your group messages | Replaced every 100 messages, every 7 days, or when someone leaves |

## Where the code is

| Folder | What's in it |
| :--- | :--- |
| `common/` | The wire protocol, crypto helpers, the signed membership log |
| `core/` | The client engine: handshake, ratchet, groups, sealed storage, history, reconnect |
| `server/` | The relay: accounts, offline queues, group log ordering, SQLite storage |
| `bridge/` | Go bindings for the Apple app (via gomobile) |
| `client/` | A small terminal client that uses the same engine |
| `apps/apple/` | The SwiftUI app for macOS and iOS |
| `design/` | The theme definitions and the script that builds them |

## Testing

I put most of the effort here, because crypto code that merely "seems to work" isn't worth much.

- Over 300 tests across the four Go modules, plus 15 fuzz targets on the decoders that parse untrusted bytes.
- End-to-end tests that run the real server and drive the real client code over a socket.
- Tests for the awkward cases: lost and out-of-order messages, two people starting a chat at once, a server that drops connections mid-delivery, a device that moves while its contacts are online.
- A check that every theme keeps its text readable.

```bash
make test
```

## Run it

You need Go. For the Mac app you also need Xcode.

```bash
make dev-cert      # a self-signed certificate for local use
make server        # start the server
make tui           # the terminal client
make app-mac       # build the Mac app
```

On the Mac, download `GoMesh-mac.zip` from the latest release, move `GoMesh.app` to Applications, and run this once because the app isn't signed for distribution:

```bash
xattr -cr /Applications/GoMesh.app
```

For the iPhone, open the project in Xcode, sign it with your own Apple ID, turn on Developer Mode on the phone, and run it from Xcode.

## Architecture and spec

If you'd rather read about how it works than run it, there are two documents in [`docs/`](docs/):

- **[Architecture diagram (PDF, one page)](docs/gomesh-architecture.pdf):** the whole system on one landscape page. It shows the client engine's modules, every stage of the relay server from sign-in to delivery, the SQLite tables, the five main flows, key lifetimes and packet sizes. There's also a [PNG version](docs/gomesh-architecture.png).
- **[Technical spec (HTML)](docs/gomesh-tech-spec.html):** three architecture diagrams, sequence diagrams for sign-in, private messages and groups, and the byte layout of every packet type. GitHub shows HTML as source, so download it and open it in a browser, or [view it rendered here](https://htmlpreview.github.io/?https://github.com/mehul-raj5/GoMesh/blob/main/docs/gomesh-tech-spec.html).

The long-form write-up, with every mechanism and known limitation, is in [`docs/technical-reference.md`](docs/technical-reference.md).

## What it doesn't do (yet)

I'd rather you hear this from me.

- **No audit.** Treat it as a study of the ideas, not a replacement for Signal.
- **One account, one device.** Signing in somewhere new moves the account. There is no multi-device sync.
- **You have to trust the server's directory until you compare safety numbers.** A malicious server could hand out its own keys. That is the same trust Signal asks for, and the safety number is how you check it.
- **A new device could be swapped in by a malicious server.** The rekey is signed by the new key, because the old device may be gone. Members are shown "signed in on a new device", but you'd have to notice.
- **The server sees your password at login.** It stores only an argon2id hash and uses TLS, but a malicious server could log it. A scheme like OPAQUE would fix that and is on my list.
- **Large groups are expensive.** Removing someone costs about one direct message per pair of members. Fine for a few hundred people; beyond that, MLS is the right design.
- **A chat can get stuck** if every message of one ratchet epoch is lost. Starting a new session with `/dm <name>` fixes it, but nothing detects it automatically.
- **Signed prekey rotation isn't scheduled yet.** The rotation code exists and is tested, but nothing calls it on a timer.

The complete list, with the reasons behind each, is in [`docs/technical-reference.md`](docs/technical-reference.md).

## What I learned

- Most of the difficulty isn't the cryptography. It's the state: saving the ratchet before a message leaves, surviving a crash, and handling a message that arrives early.
- "End-to-end encrypted" says nothing about metadata. The server still knows who talks to whom, and when.
- A good protocol is mostly a list of attacks you decided to deal with, and the tests are where you find the ones you forgot.

## Credit

The designs come from the Signal protocol documentation (X3DH and the Double Ratchet) and the sender-key approach used for groups. Any mistakes in the implementation are mine.
