# Running the GoMesh server on AWS EC2

The server is one static binary with one SQLite database. It needs one open TCP port and,
for files and photos, a Supabase Storage bucket. There are no push notifications: messages
wait in the server's per-device queue until the app next connects.

```
  iPhone / Mac / terminal ──TLS, port 8080──▶ EC2: gomesh-server ──▶ /var/lib/gomesh/gomesh.db
          │                                         │
          └──── signed URLs, HTTPS ───▶ Supabase Storage ◀──┘ (signs the URLs)
```

Commands marked **(Mac)** run in this repository on your Mac. Commands marked **(EC2)** run
on the instance, over SSH or Session Manager.

## 1. Launch the instance

| Setting | Value |
| :--- | :--- |
| Image | Amazon Linux 2023 (arm64), or Ubuntu 24.04 LTS (arm64) |
| Type | `t4g.small` (2 GB). `t4g.micro` (1 GB) is enough for a handful of people. |
| Storage | 8–20 GB gp3. The database is small: messages are deleted once delivered. |
| Key pair | yours, for SSH. Or none, and use Session Manager. |

Allocate an **Elastic IP** and associate it with the instance, so the address the apps use
never changes. A DNS name pointing at it (Route 53 or any provider) is optional; the apps
take either.

The password check (argon2id) uses 64 MiB per sign-in, at most 4 at a time, so 256 MiB at
worst.

## 2. Security group

| Direction | Port | Source | Why |
| :--- | :--- | :--- | :--- |
| Inbound | TCP 8080 | `0.0.0.0/0` and `::/0` | the apps |
| Inbound | TCP 22 | **your IP only** | SSH. Skip it if you use Session Manager. |
| Outbound | all | anywhere | Supabase (HTTPS) and OS updates |

Nothing else. The server speaks TLS itself; there is no web server in front of it.

## 3. Build and copy the server **(Mac)**

```bash
make server-linux
scp dist/gomesh-server-linux-arm64 deploy/gomesh.service deploy/gomesh.env.example ec2-user@YOUR-ELASTIC-IP:~
```

Use `dist/gomesh-server-linux-amd64` on an x86 instance. On Ubuntu the user is `ubuntu`, not
`ec2-user`.

## 4. Install it **(EC2)**

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gomesh
sudo install -m 0755 gomesh-server-linux-arm64 /usr/local/bin/gomesh-server
sudo install -d -m 0750 -o root -g gomesh /etc/gomesh /etc/gomesh/tls
sudo install -m 0640 -o root -g gomesh gomesh.env.example /etc/gomesh/gomesh.env
sudo install -m 0644 gomesh.service /etc/systemd/system/gomesh.service
```

## 5. The certificate **(EC2)**

The apps pin the server's certificate by its fingerprint the first time they connect, so a
self-signed certificate is the right kind.

- **Use the server's own generator,** with the Elastic IP and any DNS name. Its validity
  dates don't matter, because the apps check only the pin.
- **Don't use a Let's Encrypt certificate.** Every renewal would change the fingerprint and
  lock every device out.

```bash
sudo /usr/local/bin/gomesh-server -gen-dev-cert /etc/gomesh/tls YOUR-ELASTIC-IP your.dns.name
sudo chown root:gomesh /etc/gomesh/tls/cert.pem /etc/gomesh/tls/key.pem
sudo chmod 0640 /etc/gomesh/tls/key.pem
```

It prints the fingerprint. **Write it down.** Each device shows it when it first connects,
and you compare the two before tapping Trust.

Keep `/etc/gomesh/tls` safe and backed up. A new certificate means every device has to
forget the old one and trust the server again.

## 6. Supabase Storage

Files and photos are encrypted on the device, then uploaded straight to Supabase through a
short-lived signed URL. The server never sees their contents.

1. In your Supabase project, go to **Storage**, then **New bucket**. Name it `gomesh-media`.
   Make it **private** (not public), and set a 50 MB file size limit.
2. Go to **Project Settings**, then **API**, and copy the **Project URL** and the
   **service_role** key. The service_role key is a secret: it goes only in
   `/etc/gomesh/gomesh.env`, never into an app.
3. On the instance, edit the settings and fill in the three `SUPABASE_*` lines:

   ```bash
   sudo nano /etc/gomesh/gomesh.env
   ```

Leaving them empty turns sending files off. Everything else still works.

## 7. Start it **(EC2)**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gomesh
systemctl status gomesh
journalctl -u gomesh -n 20
```

The log should show these lines:

- `TLS certificate fingerprint: …`, the same fingerprint as in step 5
- `Media storage enabled (bucket "gomesh-media" at https://…)`
- `Server listening on :8080 (TLS)`

## 8. Point the clients at it **(Mac)**

- **The apps:**
  1. `cp apps/apple/Config/Local.xcconfig.example apps/apple/Config/Local.xcconfig`
  2. Set `GOMESH_DEFAULT_SERVER = YOUR-ELASTIC-IP:8080`.
  3. Run `make app-mac` or `make app-sim`.
  4. The sign-in screen suggests that server. You can still change it under **Advanced**.
  5. Git ignores `Local.xcconfig`.
- **The terminal client:** `GOMESH_SERVER=YOUR-ELASTIC-IP:8080 make tui`.

The first connection shows the fingerprint. Compare it with step 5, then trust it.

## 9. A real iPhone

1. In Xcode, go to **Settings**, then **Accounts**, and add your Apple ID. A free one works.
   Copy the **Team ID** it shows.
2. Put the Team ID in `apps/apple/Config/Local.xcconfig`, as the example file does. The
   `[sdk=iphoneos*]` there signs only the iPhone build, so the Mac and simulator builds
   still need no certificate.
3. Run `make xcodeproj` and open `apps/apple/GoMesh.xcodeproj`.
4. Pick your iPhone as the destination and press Run.
5. On the phone, go to **Settings**, then **General**, then **VPN & Device Management**, and
   trust the developer.
6. With a free Apple ID, the app stops opening after 7 days. Run it from Xcode again; your
   chats stay.

The phone reaches the server over the internet, as the Mac does.

## Updating the server

1. **(Mac)** Run `make server-linux`, then copy the binary up as in step 3.
2. **(EC2)** Install and restart:

   ```bash
   sudo install -m 0755 gomesh-server-linux-arm64 /usr/local/bin/gomesh-server
   sudo systemctl restart gomesh
   ```

A restart is safe:

- **Stopping:** the server puts everything it had not delivered into the database first.
- **Clients:** they reconnect on their own.
- **Messages:** a message a device read but had not yet acknowledged is delivered again,
  and the device ignores the copy.

## Backups

The database holds accounts, password hashes, public keys, group membership logs and
undelivered messages, which are encrypted. It never holds message contents in the clear.

- **EBS snapshots:** turn on daily snapshots of the volume with Amazon Data Lifecycle
  Manager.
- **Or copy the database while the server runs** (`sudo dnf install sqlite` first, or
  `apt install sqlite3` on Ubuntu):

  ```bash
  sudo sqlite3 /var/lib/gomesh/gomesh.db ".backup /var/lib/gomesh/backup-$(date +%F).db"
  ```

- **Back up `/etc/gomesh` too.** The certificate and key are what the devices pinned.

## Logs and troubleshooting

| Symptom | Look at |
| :--- | :--- |
| Apps say "Can't reach the server" | `systemctl status gomesh`. Check that the security group allows 8080, and that the address is the Elastic IP. |
| Apps say the certificate is not trusted | The certificate changed. Restore `/etc/gomesh/tls` from a backup, or have each device forget the server (Sign in, then **Advanced**) and trust the new one. |
| Sending a file fails | Check `journalctl -u gomesh \| grep -i supabase`, the bucket name, and the service_role key. |
| `journalctl` shows `acknowledged nothing for 1m0s` | A device stopped reading, usually a suspended app. Its messages wait for it. |

Logs never contain message contents.
