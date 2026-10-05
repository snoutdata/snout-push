# snout-push

Push notifications for Postgres-backed apps: iPhone, Android and the web from one API, with the
device registry, the queue and the delivery log kept as tables in **your own Postgres**, and your
**row-level security policies deciding who may notify whom**. One static binary, written in Rust.
One runs beside each project's database, in that project's own pod on SnoutData Cloud, so
everything about a project's push, its keys included, stays with the project.

- **One API, three transports.** Apple's APNs for native apps on iPhone, iPad, Mac and Watch;
  Firebase Cloud Messaging for Android (and for apps built on the Firebase SDKs); Web Push
  (RFC 8030, 8291, 8292) for browsers, including web apps on an iPhone's Home Screen.
- **Web push with no Firebase project.** Browsers are reached directly with a VAPID key pair
  generated for your project. (Android still needs your own Firebase project: Google delivers only
  through FCM, with credentials from the project the app is built against.)
- **Send from SQL.** `select push.send('{"title": "Order shipped"}', user_ids => array[...])` in a
  trigger, a function or a migration; or `POST /push/v1/send` from a server.
- **Your policies decide.** A send is an insert into `push.messages`, run as the caller, so an
  ordinary Postgres policy is the whole of the access control. With no policy, only the service
  role sends.
- **A log you can query.** Every delivery is a row: accepted by the provider, failed with the
  provider's own reason, or the device's token gone. "Received" and "opened" are recorded only
  when the app reports them, never inferred from a provider's acceptance.
- **Your keys stay in your database.** The APNs key, the Firebase service account and the VAPID
  keys are rows in `push.credentials`, readable by the server's own role and by nothing else (not
  your service role either). They are set through the API, proven before they are stored (an
  APNs key must sign, a service account must get a real token from Google), and reloaded by the
  running server when they change. The VAPID keys are made by the server on first start.

## The schema

`migrations/tenant/` creates the `push` schema in each project's database:

| Table | What it holds |
| --- | --- |
| `push.devices` | one row per installation: the user, the transport, the token or subscription |
| `push.topics`, `push.topic_members` | named audiences users (or anonymous devices) join |
| `push.messages` | the queue: target, notification, `send_at`, ttl, priority, status |
| `push.deliveries` | one row per device per message: what the provider said, and receipts |
| `push.settings` | log retention, device staleness, shared and anonymous devices |
| `push.credentials` | the APNs, FCM and VAPID keys; `push.credential_summaries()` shows what is set |

A policy that lets a user notify the members of a chat they belong to:

```sql
create policy "notify my chats" on push.messages for insert to authenticated
	with check (target_topic in (select 'chat:' || chat_id from chat_members where user_id = push.uid()));
```

`push.uid()` is the caller's `sub`, so the schema works whether or not an auth server is in use.

## The HTTP API

Every call carries the caller's HS256 token (`Authorization: Bearer ...`), signed with the
project's JWT secret.

| Call | Who | What |
| --- | --- | --- |
| `GET /push/v1/vapid-public-key` | anyone | the key a browser subscribes with: `{"id", "key"}` |
| `POST /push/v1/devices` | a user | registers this installation: `{"transport": "apns" \| "fcm" \| "web", "token", "p256dh", "auth", "environment", "app", "locale"}` |
| `DELETE /push/v1/devices/{id}` | its user | removes it |
| `PUT` / `DELETE /push/v1/topics/{name}/members` | a user | joins or leaves a topic |
| `POST /push/v1/send` | the service role, or a user a policy allows | queues a notification: `{"notification", "user_ids" \| "topic" \| "device_ids", "send_at", "ttl", "priority", "collapse_key"}` |
| `GET /push/v1/messages/{id}` | its sender | its status |
| `POST /push/v1/receipts` | the device's user | `{"delivery_id", "event": "received" \| "opened"}` |
| `PUT /push/v1/credentials/apns` | the service role | `{"topic", "keys": [{"p8", "key_id", "team_id", "environment"}]}`, proven, then stored |
| `PUT /push/v1/credentials/fcm` | the service role | `{"service_account": "<the JSON file>"}`, proven, then stored |
| `GET /push/v1/credentials`, `DELETE /push/v1/credentials/{apns\|fcm}` | the service role | what is set (never the keys), or remove one |

A notification is `{"title", "body", "data", "badge", "sound", "thread", "image", "url",
"background"}`, plus `apns`, `fcm` and `web` objects merged over what the server builds for
anything this shape does not name. Unknown fields are refused, not ignored. Every payload carries
`snout_push_delivery`, the id the app sends back with a receipt.


## Configuration

| Variable | Default | Secret | |
| --- | --- | --- | --- |
| `PUSH_DATABASE_URL` | none, required | yes | the project's database, as the server's own role |
| `PUSH_JWT_SECRET` | none, required | yes | the project's JWT secret, 32+ characters, that callers' tokens are verified with |
| `PUSH_VAPID_SUBJECT` | none, required | no | the operator's contact, `mailto:` or `https:`, named in every Web Push request |
| `PUSH_PUBLIC_ADDR` | `0.0.0.0:5200` | no | the `/push/v1` API |
| `PUSH_POD_MEMORY_MB` | `512` | no | concurrency toward the providers follows it (1 per 32 MB, 4 to 64) |
| `PUSH_SCHEDULING` | `false` | no | whether a future `send_at` and long retries are allowed |
| `PUSH_ANON_ROLE`, `PUSH_AUTHENTICATED_ROLE`, `PUSH_SERVICE_ROLE` | `anon`, `authenticated`, `service_role` | no | the roles calls run as |
| `PUSH_INSTALL_ROLES` | `false` | no | create those roles when missing (self-hosting, tests) |
| `PUSH_LOG`, `PUSH_LOG_FORMAT` | `info`, text | no | log filter; `json` for structured logs |

There are no demo secrets: without the three required settings the server refuses to start.

## Security

- **What it holds:** one project's APNs key, FCM service account and VAPID keys, loaded from that
  project's own database. A compromise lets an attacker send notifications to that project's
  users, and no other project's.
- **Every outbound address is checked before connecting.** Private, loopback, link-local,
  carrier-grade NAT, reserved and documentation ranges are refused in IPv4 and IPv6 (IPv4 inside
  IPv6 judged as the IPv4), the connection goes to the address that was checked, redirects are not
  followed and responses are capped. A Web Push endpoint must be a known browser push service.
- **A service-account file's own `token_uri` is ignored:** assertions go to Google's token
  endpoint only.
- **Tokens:** HS256 verified in constant time; the role claim is limited to the three API roles.
- `#![forbid(unsafe_code)]`, fuzzed parsers (libFuzzer targets over each parser of untrusted input), `cargo-deny` and gitleaks.
  Reports: [SECURITY.md](./SECURITY.md).

## Operations

`GET /health` answers `ok`. The runner logs `draining` when it connects, a `pass` line when it did
something, `credentials reloaded` when a key changed, and `pruned` hourly; a database that is not
up yet is retried every ten seconds without a warning. Upgrading is replacing the binary: the
schema migrates itself on first connection, under an advisory lock, refusing to run over a
migration that changed after it ran.

## Running it

```sh
docker build -f Containerfile -t snout-push .
docker run -e PUSH_DATABASE_URL=postgres://snout_push_admin:...@db:5432/app \
	-e PUSH_JWT_SECRET=... -e PUSH_VAPID_SUBJECT=mailto:you@example.com -p 5200:5200 snout-push
```

Tests: `bash scripts/test.sh` for the unit tests, `bash tests/schema.sh` for the schema's policies
on a real Postgres, `bash tests/db.sh` for everything, database tests included (both need docker).

Licensed under the [Apache License 2.0](./LICENSE).
