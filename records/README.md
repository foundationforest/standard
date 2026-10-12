# records

Part of Forest's standard: [the top README](../README.md). The record shapes: [schemas/](schemas/).

## What it is

How a Forest profile says things, and how anyone reads them. Everything a profile says (its card,
the record that gives its name and photo; its offers; its reviews of others) is a record: a small
signed JSON value at a path in the profile's folder. Hosts keep folders and serve them to anyone.
Any app, index (a service that reads records and scores profiles) or AI reads them and checks
every signature itself, so a host can withhold a record but never forge one. Beside each
folder a host keeps the profile's inbox, where anyone may leave an encrypted message, and the photos
and videos its records name.

This README is the standard. The library in `src/` does every MUST in it, and `test/` checks it;
MUST, SHOULD and MAY are as in RFC 2119. The directory also holds a reference host, the three
record shapes as JSON Schemas, and test vectors.

## How it works

### Folders

A profile is one main key, mixed from the person's seed (24 words every key comes from) and a
label such as `tutoring/seller`
([keys/](../keys/README.md)). Its name is its address: the main key's public key in base58, which
is also its Solana address. Its inbox key, mixed from the main key, opens what is encrypted to it.
Nothing else is needed: no account, no sign-up, no directory.

Its folder is everything signed for it, one current record per path:

| Path | What it holds |
|---|---|
| `hosts` | where the folder lives |
| `permissions` | the access keys the profile hands out: keys that act for it within limits |
| `profile` | the card: name, photo, inbox, proofs |
| `offer/<id>` | an offer, or a request for one |
| `review/<id>` | a review this profile wrote of another |

- `hosts` and `permissions` are the control paths: only the main key writes them. Every other path
  is content. Readers MAY ignore a first segment they do not know.
- A path is 1 to 4 segments separated by `/`, each `[a-z0-9][a-z0-9._-]{0,63}`, at most 256
  bytes. A prefix covers a path segment by segment: `offer` covers `offer` and `offer/x`, not
  `offerx`.
- `profile`, `offer/<id>` and `review/<id>` are shaped by the JSON Schemas in `schemas/`; a market
  (the trade a label names, such as `tutoring`) adds fields, never a shape. A review sits in the
  folder of the profile that wrote it: the one it is about cannot erase it; the one who wrote it
  can. It names its subject by address, and its deal, if it wants, by `dealId`: the escrow receipt's
  address (the account the escrow leaves on chain when a deal ends) when the deal went through the
  [escrow](../escrow/README.md), else 32 random bytes chosen when the deal began.

**The hosts record** is `{ "urls": [origin, …] }`: 1 to 8 distinct origins, `https://host[:port]`,
lower case, no path (`http` only on loopback, for tests). Each host it names holds the whole
folder. An app posts every record to every host it names, the hosts and permissions records
first. To move, it posts a hosts record naming the new hosts to old and new, then its copies; to
leave a host, post a hosts record that no longer names it, to every host, the one you are leaving
included, so a reader that still asks that host is pointed on. The old host may keep its copies;
readers follow the hosts record.

### Records

```
{ "v": 1, "profile": <address>, "path": <path>, "time": <ms since 1970>,
  "body": <object> | null, "by"?: <address>, "sig": <base64url> }
```

- `v` is 1. No other field is allowed.
- `time` is whole milliseconds, 0 to 2^53 − 1. A `null` body deletes the path.
- `by` is there only when an access key signed (Permissions). It differs from `profile`, and is
  never at a control path.
- `sig` is Ed25519 (RFC 8032) by `by` if present, else by `profile`, over the signing input
  `0xff` ‖ UTF-8(`forest/v1/record\n`) ‖ UTF-8(canonical text of the record without `sig`), in
  base64url without padding. Verification is strict: S < L, canonical encodings, R and the key in
  the prime-order subgroup, the key not of small order, then the cofactorless equation.
- The id is lowercase hex of SHA-256(signing input).

**Canonical text.** A record travels as exactly its canonical text: RFC 8785 (JCS) over a narrowed
JSON. Strings have no lone surrogates; numbers are whole, within ±(2^53 − 1), so money and
coordinates are decimal text (`"30"`, `"38.72"`); arrays have no holes; object keys match
`^[a-z][a-zA-Z0-9]{0,63}$`; nesting is at most 16 deep. A reader MUST re-serialize what it parsed
and refuse the record unless the result equals the bytes it received.

**Keys by address.** An address has one spelling: decoding and encoding again MUST give the same
text. A key named by its address anywhere, in a record, a message, a pull (a signed request to
fetch an inbox's messages) or a grant (the private
body that hands an access key to whoever it is for), MUST be a canonical point in the prime-order
subgroup and not of small order; anything else is refused.

**One key, four kinds of signature.** A main key signs Solana transactions, records, messages and
pulls. The signed bytes of the last three begin with `0xff`, which no Solana message begins with,
then each with its own text (`forest/v1/record\n`, `forest/v1/message\n`, `forest/v1/pull\n`), so
no signature is ever two of them, and none is a payment's. Access keys sign the same bytes.

**Which record counts.** A reader's view of a profile is a pure function of the records it holds
and its clock `now`:

1. Records dated after `now + 600,000` are held back.
2. Record A is newer than B if `A.time > B.time`, or the times are equal and `A.id > B.id`.
3. At `hosts` and at `permissions`, the newest record is current.
4. At a content path, if the main key (the owner) has any record there, the owner's newest is
   current. Otherwise the newest record of an access key the current permissions record allows,
   by the access rule (Permissions). A key not on the list counts for nothing.
5. A current record with a `null` body means the path is deleted.

Beyond step 1, readers check no date: when an access key's record arrived is the host's check
(Hosts). An app sets `time = max(now, newest known at that path + 1)` (`nextTime`), so a slow clock
never makes an edit lose to what it replaces.

### Permissions

A person hands out access keys, never a main key. The owner's app makes an access key at random,
lists its public half in the permissions record with one scope, and hands its private half to
whoever it is for in a grant (Grants).

```
{ "access": [{ "key": <key>, "scope": <scope>, "paths"?: [prefix, …] }, …],
  "notes"?: <base64url of an age file> }
```

The scope names the kind of key: a write key signs records, a message key signs messages and pulls
the inbox, and a read key opens private records and messages.

| Scope | What its holder can do |
|---|---|
| `write` | sign records into the folder, by the access rule below |
| `message` | sign messages for the main key, and pull its inbox (Inbox) |
| `read` | open the private records and messages encrypted to it (Private records) |

- `key` is the key's address, or, for a read key, its age recipient (`age1pq1…`). A key listed
  twice makes the record invalid.
- `was`, in place of `scope`, marks a past key: a write or message key the owner removed, and the
  scope it had (Removing a key).
- `paths`: at most 16 content-path prefixes, on a write or read key, never on a message key; a
  past key keeps the paths it had. With `paths`, the key works only under them: where a write key
  writes, and which private records the owner's devices encrypt to a read key. Without, it works at
  every content path but those `profile` covers.
- In the hosts and the permissions record, a field not named here, at any level, makes the record
  invalid, so a later limit is never ignored.

**The access rule.** A write key adds records while it is listed with scope `write`; what it wrote
counts while it is listed, past or not.

- Hosts take an access key's record only if its key is listed with scope `write`, its paths
  covering the record's path.
- Readers count it if its key is listed with scope `write`, or `was` `write`, its paths covering
  the record's path. No date is checked.
- The owner's record wins over an access key's at the same path, so the owner can always delete
  an access key's record.

**Removing a key.** To remove a write or message key, the owner replaces its `scope` with `was`,
the scope it had, and keeps its entry and its paths: it can no longer act. Readers count a past
write key's records, at its paths, only because the permissions record, signed by the main key,
still lists it, so a host cannot slip in a key never allowed. A past message key never counts for
writing. Deleting the entry instead disowns what the key wrote: none of it counts any more. To
keep one of a past key's records as the owner's own, the owner publishes it again with the main
key. A read key is removed by deleting its entry: nothing it did needs to count.

**Notes.** `notes` holds the owner's notes on its keys (who holds each, until when, why), as one
envelope, an encrypted body that only the keys it is encrypted to can open (Private records). It
is encrypted to the owner's own inbox key alone, and holds `{ "notes": [<note>, …] }`. Each note
has a grant's shape (Grants), but its `key` is the key's public half, as `access` lists it, not its
private half: a note says who holds a key, and that needs no secret. Hosts and readers ignore
`notes`; only the owner's apps open it. The public part stays `key`, `scope` and `paths`: no
names, dates or reasons.

### Private records

A private record's body is `{ "private": <base64url of an age file> }` and nothing else. The age
file is the envelope: the canonical text of an object under a random key made for that record,
and that key encrypted once to each reader.

- The readers are read keys the owner's app makes at random, one for each reader, and hands over
  in a grant. The permissions record lists each read key's public half, so the owner's other
  devices can encrypt to it too. The owner usually adds its own inbox key, to open its copy; the
  profile record's `inboxKey` is its public half.
- Each key an envelope is encrypted to is an age post-quantum hybrid recipient (`age1pq1…`, stanza
  `mlkem768x25519`); an app MUST NOT encrypt an envelope to any other kind, since one classic key
  among them would let a quantum computer open it for all. Each adds about 2 KB.
- A host checks a private record like any other and cannot open it. Anyone can see that it
  exists, its path, time and size, and how many keys it is encrypted to.
- To remove a reader, the owner writes a new version for the rest; a reader keeps what it already
  opened.

### Inbox

A message is an encrypted note anyone delivers to a profile's hosts, and only its main key or its
message keys pull. It is not a record: it has no path and no versions, and it is in no one's
folder.

**Declaring it.** The profile record's optional `inbox` field:

```
"inbox": { "senders": "anyone" | { "issuer": <issuer key> }, "once"?: true,
           "maxBytes"?: <integer>, "readers"?: [<age1pq1…>, …] }
```

- No `inbox` field means no inbox: hosts refuse deliveries. A profile with an inbox gives
  `inboxKey`, since senders encrypt to it.
- `senders` is `"anyone"`, or `{ "issuer" }`: the sender's key must hold a registry row (the public
  statement that a key holds a note an issuer, anyone who checks people, signed) from that issuer,
  under any label ([registry/](../registry/README.md)). The issuer is named by its key as a row
  holds it: x then y of its point on Baby Jubjub, each 32 bytes big-endian, as 128 characters of
  lowercase hex.
- `once`: one message from each sender, ever.
- `maxBytes`: the largest message it takes, as canonical text in bytes.
- `readers`: read keys' public halves. Senders encrypt every message to them too, so a reader that
  also holds a message key pulls, opens and answers while the person's devices are off.
- A host refuses deliveries to an inbox it cannot read: a field, a rule or a value it does not
  know. So a new rule can be added later without an old host taking what it should refuse. A
  sender's app does not deliver to one either: a field it does not know could name more keys to
  encrypt to.

**Messages.**

```
{ "v": 1, "to": <address>, "from": <address>, "time": <ms since 1970>,
  "body": { "private": <base64url of an age file> }, "key"?: <address>, "host"?: <origin>,
  "sig": <base64url> }
```

- `v` is 1. No other field is allowed, in the message or in its body.
- `to` is the recipient profile. `from` is the sender's key: a main key, or any other ed25519 key.
- `body` is one envelope encrypted to `to`'s inbox key and its inbox's readers, or, when it holds a
  grant, to the inbox key alone (Grants).
- `key` and `host` come together, when a message key signs for `from`, a main key: `key` is the
  message key's address, other than `from`, and `host` is one of `from`'s hosts, an origin as its
  hosts record writes it. So the recipient sees that a message key sent it.
- `sig` is Ed25519 by `key` if present, else by `from`, strict as a record's, over `0xff` ‖
  UTF-8(`forest/v1/message\n`) ‖ UTF-8(canonical text of the message without `sig`), in
  base64url without padding.
- The id is lowercase hex of SHA-256(signing input), as a record's.

**Deliver.** The sender reads the recipient's profile record for its `inbox` and `inboxKey`, and
its hosts record. It encrypts the body, signs, and posts the message to each host the hosts record
names (`POST /v1/inbox`). Anyone may deliver, with no login; each host checks the message on its
own (Hosts).

**Send with a message key.** The main key lists the message key with scope `message`; the message
names it as `key`, and one of the main key's hosts as `host`. No permissions record travels in the
message: the receiving host reads `from`'s current hosts and permissions records from `host`, so a
message key the owner makes past stops being taken once a host reads them again. The inbox's rule
and `once` apply to `from`, as for any message.

**Pull.** The recipient asks each of its hosts for what arrived after a cursor, the number a host
gives the last message on a page, so the next ask starts after it (`POST /v1/inbox/pull`):

```
{ "v": 1, "profile": <address>, "after": <cursor>, "time": <ms since 1970>, "key"?: <address>,
  "sig": <base64url> }
```

- `sig` is Ed25519 by the profile's main key, or by `key`, one of its message keys, over `0xff` ‖
  UTF-8(`forest/v1/pull\n`) ‖ UTF-8(canonical text without `sig`). A message key pulls only while
  the profile's permissions record on that host lists it with scope `message`. No other access
  key pulls.
- `after` is the `forest-cursor` of the last page; 0 for everything.
- `time` is within 600,000 ms of the host's clock, either way.
- It is signed because each body is encrypted but `from`, `to` and the time are not: unsigned,
  anyone could list who wrote to whom. It is a POST and not a GET because hosting platforms log
  URLs, and a signed URL would be a log of pulls.

**Requests.** A message body may be `{ "request": <kind>, … }`: something the sender was not
allowed to do itself, for the recipient's app to do with its main key. `request` names one of the
kinds below, which are the actions the
[mcp folder in services](https://github.com/foundationforest/services/tree/main/mcp) accepts as
requests today, and the other fields are that kind's parameters:
`{ "request": "post-offer", "offer": { … } }`, `{ "request": "send", "to": <address>, "text": … }`.

| Kind | Parameters |
|---|---|
| `post-offer` | `offer`, an offer record's body; and `id`, the `<id>` in `offer/<id>`, if wanted |
| `update-offer` | `id`, the `<id>` of the offer; `offer`, its new body |
| `remove-offer` | `id`, the `<id>` of the offer |
| `post-review` | `review`, a review record's body; and `id`, the `<id>` in `review/<id>`, if wanted |
| `send` | `to`, the recipient's address; and `text`, or `body`, an object in its place, one of the two |
| `private` | `path`, if wanted: only the private records under this path |
| `inbox` | `after`, if wanted: the cursors a pull returned, by host, for newer messages only |
| `pay` | `offer`, `units` and `note`, as below |

For `pay` they are `offer`, the offer as `<profile address>/offer/<id>`, and if wanted `units`, a
whole number of hours or days for an offer priced per hour or per day, and `note`, text for the
person: `{ "request": "pay", "offer": <profile address>/offer/<id>, "units": 2, "note": … }`. The
app reads the offer and opens the escrow from it
([escrow](../escrow/README.md#two-ways-to-open-it)).

An app acts on a request only when it was sent to the profile's own inbox by the profile's main
key or by a message key its permissions record lists, and shows any other `request` body as a
plain message. It shows the request, and does it only if the person agrees. So whoever holds only
a message key can send messages as the profile and ask for anything else; it can write no record
and move no money.

### Grants

A grant is how an access key reaches whoever it is for: its private half, and what it is for.

```
{ "key": <private half>, "folder": <address>, "scope": "write" | "message" | "read",
  "paths"?: [prefix, …], "from": <address>, "since": <ms since 1970>, "note"?: <text> }
```

- `key` is a read key's age identity (`AGE-SECRET-KEY-PQ-1…`), or any other key's 32 private
  bytes in base64url without padding.
- `folder` is the profile whose permissions record lists the key, and `paths` are as it lists
  them. `from` is who handed it over, `since` when, and `note` whatever its holder wants to
  remember. A grant is private, so it can hold the names and reasons the permissions record never
  does.
- No other field is allowed.
- Handed over by message, a grant is the body `{ "grant": <grant> }`, encrypted to the recipient's
  inbox key alone, never to its inbox's readers: a reader acts on the inbox, and a grant is a key.
  The library's `message` encrypts it so.
- A person keeps the grants they received in their vault, a private folder of their own that a new
  device restores from (The vault). The app's local copy is the working copy; the vault on the
  hosts is why losing the phone loses nothing.

### The vault

The vault holds what a new device needs and the seed alone cannot give back: the labels of the
person's profiles and where each lives, the grants they received, their issuers' notes (the signed
word each issuer gave them that it checked them), and apps' settings. It lives on hosts in a folder
of its own, whose main key is the vault key, mixed from the seed
([keys](../keys/README.md#the-vault-key)), so a new device finds it with the seed alone.

```
{ "profiles": [{ "label": <label>, "hosts": [<origin>, …] }, …],
  "grants": [<grant>, …],
  "issuerNotes": [{ "issuer": <issuer name>, "note": <signed note> }, …],
  "settings": { … } }
```

- The folder holds its hosts record and one private record at `vault`, its body the object above,
  encrypted to the vault's own inbox key alone. It has no card, no inbox and no access keys.
- Every field may be missing. An app keeps every field it does not know, at the top and inside
  `settings`, so two apps share one vault.
- `profiles`: each label once, with the hosts its folder lived on when written; the signed hosts
  record there is the truth.
- `grants`: grants as above. A grant still reaches the person in a profile's inbox: the app pulls
  it, opens it, adds it here and writes the vault again.
- `issuerNotes`: the issuer's name, exactly as keys/'s recipe takes it, and the note it signed, as
  registry/'s JSON ([registry](../registry/README.md#the-note-and-the-person-proof)).
- `settings`: apps' settings, such as the hosts, issuers and indexes the person chose. Each field
  is an app's own.
- To change it, an app reads the current vault, changes it, and writes it, at a time past the
  current one's, to every host the vault's hosts record names.

**Restoring.** A new device mixes the vault key from the seed, and its inbox key from that. It asks
the hosts it knows for the vault key's folder, or a host the person names; the folder's hosts
record names the rest. It opens `vault`, then mixes each profile's main key from its label and
reads that folder from its hosts. Issuer secrets come from the seed and each note's issuer name.

### Proofs

The profile record's optional `proofs` field carries up to four proofs, each named by its
`circuit` and checked by that circuit's verifier ([schemas/profile.json](schemas/profile.json)).
A proof counts for one main key: a reader checks it against the main key of the profile that
carries it, so a proof copied to another profile fails. A reader ignores a proof whose circuit it
does not know, so a newer kind never makes a profile invalid for an older app. An app puts a
proof in the profile record only when the person chooses to show it there:
[reputation/](../reputation/README.md#limits) says what one can reveal.

- **`reputation`** shows the score of the profiles the person holds in an index's tree, without
  saying which. It carries the index's key, the root and time the index signed and its signature,
  the score, the stamp of this profile's registry row (the number the row is kept at), the label
  when the proof shows one market, and the proof's 256 bytes. A reader checks it with
  reputation/client's `verifyReputation`: it holds only when the row at that stamp names this main
  key, and the proof shows that stamp comes from the same secret as the profiles it counts, so
  nobody can lend their score to someone else. Each reader decides which indexes and issuers it
  trusts and how old a time it accepts. How it is made is [reputation/](../reputation/README.md)'s.
- **`person`** shows the profile's tier, a number in the note whose meaning is the issuer's: that
  an issuer signed the person a note at that tier
  ([registry/](../registry/README.md)). It carries the issuer's key, the label and the stamp as
  the profile's registry row holds them, the tier in decimal (a tier can be a number far past
  2^53 − 1, where a record's numbers stop), and the proof's 256 bytes, in the reputation proof's
  order. A reader checks it with registry/client's `verifyTier`: it holds only when the row at
  that stamp names this main key, this issuer and this label, and the proof holds for them and the
  tier. Each reader decides which issuers it trusts.

### Blobs

A blob is bytes a record names by SHA-256: a profile's `photo`, or the `media` of an offer or a
review. Each name gives the hash, the type (`mimeType`) and the size. An app posts the record
first, then the bytes, to each host (`PUT /v1/blobs/<sha256>`): a host takes bytes only while a
current record on it names them, so it is never a free file store for anyone. Readers fetch a
blob from the record's hosts, and check its SHA-256 themselves.

### Hosts

A host is an address that answers seven requests, the host socket, however many machines stand
behind it. It has no keys, no accounts and no login: a record's signature is all it asks for,
and a pull's is the recipient's main key's or message key's. It is open: it takes signed records
for any profile and serves them to anyone; it takes messages for any profile whose profile record
on it declares an inbox, and serves them only to that profile's main key and message keys; it
takes the bytes a current record names, and serves them to anyone. A host never talks to an
index; to take a message a message key signed, it reads the sender's records from the sender's
host.

| Request | Body | Answer |
|---|---|---|
| `POST /v1/records` | NDJSON, one canonical record a line | NDJSON, one `{i, id?, ok, error?, message?}` a line (Taking a record in) |
| `GET /v1/records?profile=&after=` | none | NDJSON of stored records in the order taken, after the cursor `after`, one profile's if asked |
| `POST /v1/records/read` | `{ "profile"?: <address>, "after"?: <cursor> }` | the same |
| `POST /v1/inbox` | NDJSON, one canonical message a line | as for records (Taking a message in) |
| `POST /v1/inbox/pull` | a pull's canonical text | NDJSON of the messages to that profile that arrived after the cursor, in arrival order |
| `PUT /v1/blobs/<sha256>` | the raw bytes, `content-type` their type | `{ok, error?, message?}` (Taking a blob in) |
| `GET /v1/blobs/<sha256>` | none | the bytes, with the type a record named when they came in, or 404 |

- A page's header `forest-cursor` is the last sequence number on it: the next page is after it.
  A page always holds at least one line.
- `POST /v1/records/read` gives the same answer as `GET /v1/records`, with the profile and the
  cursor in the body instead of the URL. Front doors, the proxies and hosting platforms that stand
  in front of a host, log URLs, so a person who reads their own profiles by GET leaves a trail. The
  GET stays for public readers.
- A refused pull is answered 400 with `{ok, error, message}`: [`stale`] when its time is more than
  600,000 ms from the host's clock, [`signature`] when neither the profile's main key nor the
  `key` it names signed it, [`permission`] when the profile's permissions record on this host does
  not list that `key` with scope `message`, or a shape code.
- A request with more lines than the host takes gets one [`batch`] result, and one with more bytes
  gets 413.

**Taking a record in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Records and the control records
   [`canonical`, `shape`, `path`, `key`, `version`, `time`, `body`, `control`, `hosts`,
   `permissions`, `signature`], and `time ≤ now + 600,000` [`future`].
2. Within a request, hosts and permissions records first, then the rest in the order sent.
3. It MUST become the current record at its path by Which record counts, over what the host
   stores plus it [`older`, `permission`].
4. An access key's record: its key MUST be listed with scope `write`, its paths covering the
   record's path [`permission`]. A reader also counts a past write key's records; a host takes
   none.
5. A host MAY refuse a content record by its own choice [`refused`]. It MUST NOT refuse a hosts or
   permissions record by its own choice but for its size, so a person can always move and always
   remove an access key: a record that only removes one is never larger than the one before.

**Taking a message in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Messages [`canonical`, `shape`,
   `version`, `key`, `time`, `body`], and `time ≤ now + 600,000` [`future`].
2. No message with the same id is here already [`duplicate`].
3. The current profile record of `to` on this host declares an inbox [`no_inbox`].
4. The signature: by `key` if the message names one, else by `from` [`signature`].
5. A message key: the host reads `from`'s records from `host`, as a reader does
   (`GET /v1/records`), or uses what it read before, kept for a time it chooses. `host` MUST be
   one the current hosts record names, and the current permissions record MUST list `key` with
   scope `message` [`permission`]. A read that fails is [`lookup`]: the sender may try again. A
   host that reads no sender's records refuses every message a message key signed
   [`rule_unsupported`].
6. The rule, on `from`. `"anyone"` passes. `{ issuer }` needs a row for `from` from that issuer,
   under any label [`sender`]: a registry lookup, over an RPC the host chooses; a host without one
   accepts only `"anyone"` [`rule_unsupported`]. A lookup that fails is [`lookup`]: the sender may
   try again. An inbox the host cannot read is [`rule_unsupported`] too.
7. `once`: a second message from this `from` to this `to` is refused, ever, whichever key signed
   it [`once`]. The host keeps each pair it takes while the inbox says `once`, for as long as it
   keeps the profile.
8. `maxBytes`: the canonical text is at most that many bytes [`too_big`].
9. A host MAY refuse a message by its own choice [`refused`].

A message whose `from` is its `to` skips steps 6 to 8: an inbox's rules are for others.

**Taking a blob in**, in this order:

1. The bytes' SHA-256 is the name in the path [`hash`].
2. A current record on this host names that hash, with the `content-type` sent as its type
   [`unnamed`]. So the record comes first.
3. The host's own choice allows them, by their size, their type or the folders whose current
   records name them [`refused`].

A host SHOULD verify in native code with these same strict rules: OpenSSL's defaults accept a
small-order signature this protocol refuses.

### What a host chooses

Nothing here is a rule: each host chooses, and says its numbers where it describes itself, as the
reference host does (Run it).

- **Sizes.** The largest record, message and blob it takes; how many records or messages a
  request may carry; how many lines and bytes a page holds. A client handles any size: it sends a
  refused request again in halves, and follows the cursor page by page. A reader MAY ignore a
  record, a message or a blob it finds too big.
- **Keeping.** A record that stops being current is kept for a number of days the host chooses,
  by its own clock, then deleted. A message is kept for a number of days from when it arrived; a
  pull does not delete it. Bytes no current record names any more may go after the host's keep
  days. A host that drops a current record withholds it.

### Indexes

An index reads records from hosts and weighs them as it chooses. It MAY answer one request,
`POST /v1/hosts`: the body is a profile's hosts record as canonical text, and the answer is the
HTTP status and nothing else. The index checks the signature, and that the profile holds a
registry row from an issuer it trusts, then crawls the hosts the record names, reading each host
itself, page by page (`GET /v1/records`). Sending the record again asks it to look now. An app
sends the hosts record to the indexes the person chose. Which hosts an index crawls or refuses is
its own choice.

### Run it

`@forest/records` has four import paths, each built to `dist/` with types, and the shapes:

- `@forest/records`: keys as addresses (`keyFromPrivate`, `publicKeyFromAddress`); canonical
  text; signing, checking and encoding records; the view (`viewProfile`, `liveContent`, `allows`,
  `covers`); writing (`ownerRecord`, `accessRecord`, `hostsRecord`, `permissionsRecord`,
  `nextTime`); messages and pulls (`signMessage`, `decodeMessage`, `messageId`, `pullRequest`,
  `checkPull`, `inboxOf`, `sealedTo`); grants and notes (`checkGrant`, `checkNote`); talking to
  hosts (`publish`, `readPage`, `readAll`, `readProfile`, `deliver`, `pull`, `putBlob`,
  `getBlob`). A read asks by POST with `post: true`. A read, a publish, a
  delivery and a pull go through the caller's own `fetch` if given, and refuse a host that
  redirects with `redirect: 'error'`. No server, database or encryption library is in it.
- `@forest/records/private`: `makePrivate`, `openPrivate`, `readerCount`; `message` (encrypt to a
  card's inbox key and readers, a grant to the inbox key alone, and sign) and `openMessage`;
  `makeNotes` and `openNotes`; the vault (`vaultRecord`, `openVault`, `readVault`, `checkVault`,
  `VAULT_PATH`). The inbox key itself is keys/'s `inboxKey`, and the vault's keys/'s `vaultKey`.
- `@forest/records/host`: `Host`, the reference host (below).
- `@forest/records/public`: `publicFetch`, a fetch that reaches only public addresses and follows
  no redirect, for a host or an app that goes to a host a stranger named: it refuses loopback,
  private, link-local, carrier-grade NAT, NAT64, 6to4, multicast and every other range not
  globally reachable, written in the URL or behind a name. `isPublic` checks one address. Node
  only, like the host.
- `@forest/records/schemas/<kind>.json`: the three shapes, as JSON Schemas.

Publish a profile with one offer, read it back, then let another app write offers:

```ts
import { randomBytes } from 'node:crypto'
import { mainKey } from '@forest/keys' // keys/
import { accessRecord, hostsRecord, keyFromPrivate, ownerRecord, permissionsRecord, publish,
  readProfile } from '@forest/records'

const me = await mainKey(seed, 'tutoring/seller') // seed: the 32 bytes the 24 words encode
const now = Date.now()
const maths = { direction: 'offer', description: 'One hour of maths, online.',
  createdAt: new Date(now).toISOString() }
await publish([host], [hostsRecord(me, [host], now), ownerRecord(me, 'offer/maths', maths, now)])
// Your own profile: by POST, so its address is in the body, not the URL.
const view = await readProfile([host], me.address, Date.now(), { post: true })
view.current.get('offer/maths')?.record.body

const helper = keyFromPrivate(randomBytes(32)) // the other app's own access key
const access = [{ key: helper.address, scope: 'write' as const, paths: ['offer'] }]
await publish(view.hosts, [permissionsRecord(me, access, now)])
const physics = { direction: 'offer', description: 'Physics, one hour.',
  createdAt: new Date(now).toISOString() }
await publish(view.hosts, [accessRecord(helper, me.address, 'offer/physics', physics, now)])
```

Write to that profile's inbox from another profile, then pull it on the owner's device:

```ts
import { mainKey, inboxKey } from '@forest/keys'
import { deliver, pull, pullRequest, readProfile } from '@forest/records'
import { message, openMessage } from '@forest/records/private'

const buyer = await mainKey(otherSeed, 'tutoring/buyer')
const seller = await readProfile([host], me.address, Date.now()) // its card declares an inbox
const card = seller.current.get('profile')!.record.body!
const ask = await message(buyer, me.address, { text: 'Is Tuesday at six free?' }, Date.now(), card)
await deliver(seller.hosts, [ask])

const page = await pull(host, pullRequest(me, 0, Date.now())) // the main key signs each pull
const { identity } = await inboxKey(me.privateKey) // the inbox key
for (const m of page.messages) (await openMessage(m.message, identity)).body
```

Let a helper answer while the owner is away. It holds `messageKey`, listed with scope `message`,
and `readKey`, listed as a reader of the inbox, both handed over in grants:

```ts
import { readAll } from '@forest/records'
import { Host } from '@forest/records/host'

// A host takes a message a message key signed only if it reads the sender's records.
const buyersHost = new Host({
  readSender: async (url, profile) => (await readAll(url, { profile })).records,
})

const mine = await pull(host, pullRequest({ key: messageKey, profile: me.address }, 0, Date.now()))
for (const m of mine.messages) (await openMessage(m.message, readKey.identity)).body
const buyerView = await readProfile([host], buyer.address, Date.now())
const buyerCard = buyerView.current.get('profile')!.record.body!
const from = { key: messageKey, from: me.address, host }
const answer = await message(from, buyer.address, { text: 'Tuesday at six, yes.' }, Date.now(),
  buyerCard)
await deliver(buyerView.hosts, [answer])
```

```
(cd keys && npm ci)    # the tests take their keys from keys/
cd records
npm ci                 # also builds dist/
npm run check          # type-check
npm test               # everything, on loopback
npm run bench          # speed on this machine
node test/vectors.ts   # print the test vectors
```

Node 22.18 or later. Built from existing pieces, unchanged: `@noble/curves`, `@noble/hashes`,
`@scure/base` and `canonicalize` for the core; `age-encryption` for private records and messages;
Node's built-in `node:sqlite` for the host; `undici` for the public fetch.

**The reference host.** One process, listening on `127.0.0.1` unless told otherwise; TLS is the
operator's. What it chooses, unless told otherwise: records and messages of up to 65,536 bytes, and
100 a request; pages of at most 1,000 lines and 4,194,304 bytes; a replaced record, a message, and
bytes no current record names any more, kept for 30 days; png, jpeg and mp4 blobs of up to
50,000,000 bytes. Give it `rowLookup` to take messages for inboxes with an issuer's rule, and
`readSender` to take messages a message key signed: it reads the sender's records again for each
request.

It keeps everything in its data directory, `dir` (a temporary one, removed on close, when none is
given), through one module, `src/storage.ts`:

- `folders/<address>.sqlite`: one file per folder, with its records, the messages to its inbox and
  its once pairs. With the host stopped, deleting a folder's file removes that folder.
- `host.sqlite`: the log, which numbers every folder's records in the order taken, and which
  folders name which blobs. It holds nothing that exists only there: `rebuild(dir)` makes it
  again. A new number, a record's or a message's, is the larger of the last one plus 1 and the
  clock in microseconds, so a rebuilt `host.sqlite`, or a folder's file made again, never reuses
  one, unless the clock is set back.
- The blobs: in `blobs/`, or with `blobs: { kind: 's3', … }` in a bucket of any S3-compatible
  service.

Today, one machine with one file per folder; when one machine is not enough, the options are more
machines, a managed per-folder store, or Postgres, and the storage is one module.

### Test vectors

`test/vectors.json`: a hosts, profile, offer, permissions, access key's offer and delete record,
each with its wire text, signing input and id, for keys/'s `tutoring/seller` profile from its test
seed `00 01 … 1f`; the profile record's `inboxKey` is that profile's inbox key. The seed, the main
key and the inbox key are pinned in `keys/test/vectors.json`, and checked there. The access key's
private key is 32 bytes of `0x2a`, listed with scope `write`; the message key's is 32 bytes of
`0x2b`, listed with scope `message`. It also holds a message from keys/'s `tutoring/buyer` profile
to `tutoring/seller`, and a message from `tutoring/seller` signed by its message key, naming
`https://host-a.example`, to `tutoring/buyer`, each with its wire text, signing input and id; a
pull request by `tutoring/seller`, and the same pull signed by its message key; and `past`, a
later permissions record in which the access key is past and the message key still listed, with
notes on both encrypted to `tutoring/seller`'s inbox key. Each message's body is encrypted to its
recipient's inbox key; age's encryption is random, so the encrypted bodies and the notes are
pinned as they were made. `test/vectors.test.ts` recomputes the records, the messages and the
pulls, checks each with node:crypto (Ed25519, SHA-256), and opens each message, and the notes,
with the pinned inbox key they were encrypted to. The profile is
`EofQN9U3MiKVmAo3Pyvuw19WjyYbpddfN52E1Q1uBwhu`; every signing input begins
`ff 66 6f 72 65 73 74 2f` (`0xff`, then `forest/`).

## Promises

- **A record checks the same wherever it comes from.** One canonical spelling and strict Ed25519.
  A host cannot forge or change a record; it can only withhold it.
- **Every reader computes the same view from the same records.** Where they came from and in what
  order does not matter. The reader's clock matters only to hold back records dated more than ten
  minutes ahead.
- **The owner wins.** An access key never replaces or deletes what the main key wrote, and never
  writes the hosts or permissions record.
- **Nobody writes for a profile unless its permissions record says so.** Removing an access key
  ends what it can add at any host that follows the standard, never what it already wrote.
- **A person can always move.** A profile's name is its key, not a host's address. A host never
  refuses a newer hosts or permissions record by its own choice but for its size, and one that
  only removes an access key is never larger than the one before.
- **A host holds nothing secret of the people it serves.** No keys, no accounts, no login, and it
  cannot open a private record.
- **Only a profile's main key, or a message key its permissions record lists, can pull its inbox.**

## Limits

- **The reference host is a reference.** One process on one machine, a SQLite file per folder. It
  checks each record against everything it stores for that profile, which is slow for a busy one.
- **Checking signatures is slow here.** Pure JavaScript checks about 150 a second on one core of
  the machine these tests ran on, against about 7,800 for OpenSSL. A busy host or index should
  verify in native code with the same strict rules (Hosts).
- **A host keeps only the newest record at each path,** and what it replaced for its keep days.
  Older history is in the app's copies, or nowhere.
- **A past write key can still write to a careless host.** Honest hosts refuse its records, but
  readers count every record it signed at its paths, since no date is checked: a host that skips
  the check could take a new one, and readers of that host would count it. The owner deletes it by
  writing at that path.
- **A past message key can still send until a host reads the sender's permissions again.** A host
  keeps what it read for a time it chooses, and until then takes what the past key signs. One of
  the sender's own hosts that withholds the newer permissions record lets it send through that
  host for as long as it withholds.
- **A host sees who wrote to whom.** It holds each message's `from`, `to`, time and size, and the
  message key when one signed, though not what it says. To take a message key's message, it asks
  the sender's host for the sender's records, which tells that host where the sender wrote.
  Filtering by an inbox's rule needs the sender, so there is no anonymous mode.
- **A blob is only as true as its hash.** The record says what it is, and the bytes say what they
  are. A host checks the hash, never that the bytes are the type or size the record gives.
- **No forward secrecy.** An inbox key or a read key that leaks opens every message and private
  record encrypted to it, from any host or copy that still holds them, and a reader removed keeps
  what it already opened.
- **An envelope holds about 30 keys on the reference host.** Each key adds about 2 KB, and the
  reference host takes records and messages of up to 64 KB; another host chooses its own. Each
  reader an inbox lists makes every message to it about 2 KB larger, and anyone sees how many
  readers it lists.
- **Two profiles of one person can be linked by how they are written.** One access key listed by
  both names itself in both, and a host that logs addresses links them; whether it logs is its own
  choice. Give each folder its own access keys.
- **Two devices writing the vault at once lose one change.** The newer record counts. An app that
  reads before it writes, and writes again when the vault changed under it, loses nothing.
- **The vault is one record.** A host's largest record bounds it: 64 KB on the reference host, a
  few hundred grants.
- **A vault has no registry row.** A host that chooses to take only registered folders will not keep
  it.
- **Not here: a pay scope.** A key that moves money is the person's own; a delegate's allowance is
  the chain's, not this standard's.

## Who decides what

- **The standard:** the record and the message, and what makes each valid (the ten-minute
  window); the seven requests and their codes; the control records and the scopes of access keys;
  envelopes; the three shapes; the inbox, its rules and the request body; the grant; the vault;
  the proofs field.
- **A host chooses:** its keep days; the largest record, message and blob it takes;
  batch and page sizes; which blob types it takes; which inbox rules it supports; whether it reads
  senders' records to take a message key's message, and how long it keeps what it read; rate
  limits; logging; storage.
- **An app, with the person:** the copies it keeps; which hosts, the vault's among them; which
  private records it encrypts to a read key; how a grant reaches its holder; whether to forward a
  message to email or a notification; dropping a message that arrives twice; what it finds too
  big to read; and what asks for the person's face. The profile can change or delete anything it
  wrote, at will. What others wrote about it, and payments, stay.
- **An index chooses:** which hosts, issuers and markets count, which hosts it crawls,
  how much each review weighs, and which proofs it accepts.

## FAQ

**Why does the permissions record carry no dates or names?**
It is public. A date would tell anyone when you met someone or began using an app, and a name
would say who. Who a key is for, and since when, is in its grant, which only you and its holder
can open, and in your notes, which only you can. A key ends when you rewrite the record, so
readers check no clock, and agree whatever theirs say.

**Why does a past key have `was` in place of `scope`?**
So nothing that checks a key's scope lets a removed key act, and removing a key never makes the
permissions record larger: `"was":"write"` is shorter than `"scope":"write"`.

**Why does the owner win?**
An access key lives somewhere less safe than the main key: on a server, or with another app. If
it could replace what you wrote yourself, losing it would let someone rewrite your card or your
offers. Because the owner wins, the worst a lost access key can do is add records where you never
wrote, and you can always overwrite or delete those by writing at the same path.

**Why does the owner make the readers' keys?**
So a reader needs no profile and no key of its own: the owner's app makes a read key for it and
hands it over. A read key that leaks opens only what one owner encrypted to it, never everything
ever encrypted to the reader's own inbox key. And one relationship can be ended without the reader
rotating its own key.

**Why is a message not a record in the sender's folder?**
Anyone reads a folder. A message there would need a field naming its recipient so hosts could
route it, and that field would make every inquiry a public fact: who asked whom, and when. A
message goes to the recipient's hosts instead, encrypted, and only the recipient pulls it.

**How do I hear that a message arrived?**
By default the app checks your inboxes itself, pulling from your hosts. A push service would see
which inboxes one device watches, and so which profiles are one person's.

**Why is there no deposit rule?**
A rule that asks senders to pay would have every host check payments. An inbox's `senders` is a
field with kinds, and a host refuses deliveries under a kind it does not know, so a kind can be
added later without breaking anything.

**Why do offers and reviews name no market?**
A profile names one market and role, from its label. An offer's market and side are its author's;
a review's market is that of the profile it is about. A registry row counts for a profile under
its own label, so neither needs more.

**Does a review need proof of a deal?**
No. A review needs only its subject. Evidence weighs, it never rejects: what is missing weighs
less, and nothing is refused. An index decides how much each review weighs.

**Why is the vault a folder of its own?**
A new device has only the seed. A record inside a profile's folder could be found only by first
knowing that profile's label, and the labels are what the vault keeps. A folder named by a key from
the seed is found with nothing else; it can live on hosts apart from the profiles; and no profile's
key opens it.

**Why is a proof's `proof` 256 bytes, and not snarkjs's JSON?**
A record's object keys cannot spell snarkjs's `pi_a`, `pi_b` and `pi_c`: they allow no `_`. The
256 bytes are the proof's three points, not compressed, in the order Ethereum's and Solana's BN254
precompiles read them, so a reader gets snarkjs's form back by reading eight 32-byte numbers.
Compressed, the points would take 128 bytes fewer, but every reader would have to take square
roots to rebuild them.

**Why not AT Protocol, Nostr or Pubky as the base?**
AT Protocol has one server per profile and a central directory. Nostr's keys cannot be Solana keys,
and it has no access key that can be removed. Pubky's servers can forge records.
