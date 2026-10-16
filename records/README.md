# records

Part of Forest's standard: [the top README](../README.md). The profile record's shape:
[schemas/](schemas/).

## What it is

How a Forest profile says things, and how anyone reads them. Everything a profile says (its profile
record, which shows it; its offers; its reviews of others) is a record: a small signed JSON value at
a path in the profile's folder. A profile record shows the profile's market and role, and may carry
its payment address, its inbox and its proofs. Hosts keep folders and serve them to anyone. Any
app, index (a service that reads records and scores profiles) or AI reads them and checks every
signature itself, so a host can withhold a record but never forge one. Beside each folder a host
keeps the profile's inbox, where anyone may leave a sealed message, and its blobs: photos and
videos the folder's keys put there.

This README is the standard. The library in `src/` does every MUST in it, and `test/` checks it;
MUST, SHOULD and MAY are as in RFC 2119. The directory also holds a reference host, the profile
record's shape as a JSON Schema, and test vectors.

## How it works

### Folders

A profile is one main key, mixed from the person's seed (32 bytes every key comes from) and a label,
`<market>/<role>`, such as `tutoring/seller` ([keys/](../keys/README.md)). The main key is a key on
Baby Jubjub, the curve the proofs work on, and its address is its name on the network: the public
key packed into 32 bytes, in base58. Its inbox key, mixed from the profile's secret, opens what is
sealed to it, and its payment key, an ed25519 key of its own, is its Solana address. Nothing else
is needed: no account, no sign-up, no directory.

Its folder is everything signed for it, one current record per path:

| Path | What it holds |
|---|---|
| `hosts` | where the folder lives |
| `permissions` | the access keys the profile hands out: keys that act for it within limits |
| `profile` | the profile record: market, role, payment address, inbox, proofs |
| `offer/<id>` | an offer |
| `review/<id>` | a review this profile wrote of another |

- `hosts` and `permissions` are the control paths: only the main key writes them. Every other path
  is content. Readers MAY ignore a first segment they do not know.
- A path is 1 to 4 segments separated by `/`, each `[a-z0-9][a-z0-9._-]{0,63}`, at most 256
  bytes. A prefix covers a path segment by segment: `offer` covers `offer` and `offer/x`, not
  `offerx`.
- `profile` is shaped by the JSON Schema in `schemas/`: its fields are the standard's, and its
  market (the trade a label names, such as `tutoring`) adds fields beside them. An offer's and a
  review's body is defined by the market the profile lives in, in
  [foundationforest/markets](https://github.com/foundationforest/markets): the standard names none
  of their fields. A blob a record points at is the folder's (Blobs). Neither names a market: its
  profile's label does.
- A review sits in the folder of the profile that wrote it: the one it is about cannot erase it;
  the one who wrote it can.

**The hosts record** is `{ "urls": [origin, …] }`: 1 to 8 distinct origins, `https://host[:port]`,
lower case, no path (`http` only on loopback, for tests). Each host it names holds the whole
folder. An app posts every record to every host it names, the hosts and permissions records
first. Moving is copying the folder to the new host: its hosts record, naming the new host, its
permissions record, then every record. To leave a host, post a hosts record that no longer names
it, to every host, the one you are leaving included, so a reader that still asks that host is
pointed on. The old host may keep its copies; readers follow the hosts record.

### Records

```
{ "v": 1, "profile": <address>, "path": <path>, "time": <ms since 1970>,
  "body": <object> | null, "by"?: <address>, "sig": <base64url> }
```

- `v` is 1. No other field is allowed.
- `time` is whole milliseconds, 0 to 2^53 − 1. A `null` body deletes the path.
- `by` is there only when an access key signed (Permissions). It differs from `profile`, and is
  never at a control path.
- `sig` is EdDSA-Poseidon on Baby Jubjub ([keys](../keys/README.md#signatures)) by `by` if present,
  else by `profile`, over the signing input `0xff` ‖ UTF-8(`forest/v1/record\n`) ‖ UTF-8(canonical
  text of the record without `sig`): the 64 bytes, R8 packed then S, in base64url without padding.
  The signed number is SHA-256 of the signing input, shifted right one byte. Verification is
  strict: R8 a point on the curve in its one spelling, S below `l`, the key a point of the
  prime-order subgroup, then `S · Base8 = R8 + 8 · hm · A`.
- The id is lowercase hex of SHA-256(signing input).

**Canonical text.** A record travels as exactly its canonical text: RFC 8785 (JCS) over a narrowed
JSON. Strings have no lone surrogates; numbers are whole, within ±(2^53 − 1), so money and
coordinates are decimal text (`"30"`, `"38.72"`); arrays have no holes; object keys match
`^[a-z][a-zA-Z0-9]{0,63}$`; nesting is at most 16 deep. A reader MUST re-serialize what it parsed
and refuse the record unless the result equals the bytes it received.

**Keys by address.** An address has one spelling: decoding and encoding again MUST give the same
text, 32 bytes, a point packed as keys/ packs it. A key named by its address anywhere, in a
record, a message, a pull (a signed request to fetch an inbox's messages) or the permissions
record, MUST be a point of the prime-order subgroup other than the identity; anything else is
refused.

**One key, four kinds of signature.** A main key or an access key signs records, messages, pulls
and blob requests. The signed bytes of each begin with `0xff`, then each with its own text
(`forest/v1/record\n`, `forest/v1/message\n`, `forest/v1/pull\n`, `forest/v1/blob\n`), so no
signature is ever two of them, nor an index's (`forest/v1/reputation\n`,
[proofs/reputation](../proofs/reputation/README.md)). Payments are the payment key's, on Solana.

**Which record counts.** A reader's view of a profile is a pure function of the records it holds
and its clock `now`:

1. Records dated after `now + 600,000` are held back.
2. Record A is newer than B if `A.time > B.time`, or the times are equal and `A.id > B.id`.
3. At `hosts` and at `permissions`, the newest record is current.
4. At a content path, if the main key (the owner) has any record there, the owner's newest is
   current. Otherwise the newest record of an access key the current permissions record allows,
   by the access rule (Permissions). A key not on the list counts for nothing.
5. A current record with a `null` body means the path is deleted.

Beyond step 1, readers check no clock: the access rule compares a record's time with its key's
`until`, both signed. An app sets `time = max(now, newest known at that path + 1)`
(`nextTime`), so a slow clock never makes an edit lose to what it replaces.

### Permissions

A person hands out access keys, never a main key. The owner's app makes an access key from 32
random bytes ([keys](../keys/README.md#access-keys)), lists it in the permissions record with one
scope, and hands its 32 bytes to whoever it is for.

```
{ "access": [{ "key": <address>, "sealTo"?: <age1pq1…>, "scope": "write" | "read",
               "paths"?: [prefix, …] }, …] }
```

| Scope | What its holder can do |
|---|---|
| `write` | sign records into the folder, by the access rule below; messages for the main key, when its paths cover `inbox` (Inbox); and blob requests, whatever its paths (Blobs) |
| `read` | pull the inbox, when its paths cover `inbox` (Inbox); and open what is sealed to it (Private records) |

- `key` is the access key's address: the key that signs its records, messages, pulls or blob
  requests.
- `sealTo`, on a read key and only there, is what others seal to for it, an age post-quantum
  hybrid key (`age1pq1…`). A key or a `sealTo` listed twice makes the record invalid.
- `was`, in place of `scope`, marks a past key: `"was": "write"`, a write key the owner removed
  (Removing a key). `until`, on a past key and only there, is the time of the permissions record
  that made it past.
- `paths`: at most 16 content-path prefixes; a past key keeps the paths it had. With `paths`, the
  key works only under them: where a write key writes, which private records the owner's devices
  seal to a read key, and, when one covers `inbox`, the inbox. Without, it works at every
  content path but those `profile` covers, and the inbox.
- In the hosts and the permissions record, a field not named here, at any level, makes the record
  invalid, so a limit added to the standard is never ignored.

**The access rule**, one rule for hosts and readers: a host takes an access key's record, and a
reader counts it, only if the current permissions record allows it.

- A key listed with scope `write`, its paths covering the record's path, is allowed.
- A past key, listed with `was` `write`, its paths covering the record's path, is allowed only for
  a record dated before its `until`.
- A read key writes nothing.
- The owner's record wins over an access key's at the same path, so the owner can always delete
  an access key's record.

**Removing a key.** To remove a write key, the owner replaces its `scope` with `was`, the scope it
had, adds `until`, the time of the permissions record that does it, and keeps its entry and its
paths: it can no longer send, pull, or put or delete blobs, and a record of its counts only if
dated before `until`. Every later permissions record keeps that entry as it is, so adding another
key later never lets the past key add more. What it wrote counts, at its paths, only because the
permissions record, signed by the main key, still lists it, so a host cannot slip in a key never
allowed. Deleting the entry instead disowns what the key wrote: none of it counts any more. If the
owner deletes a key's entry and wants to keep one of its records, the owner publishes that record
again with the main key. A read key is removed by deleting its entry: nothing it did needs to
count.

### Private records

A private record's body is `{ "private": <base64url of an age file> }` and nothing else. The age
file is the envelope: the canonical text of an object under a random key made for that record,
and that key sealed once to each reader.

- The readers are read keys the owner's app makes, one for each reader, and hands over. The
  permissions record lists each read key with its `sealTo`, so the owner's other devices seal to it
  too. The owner usually adds its own inbox key, to open its copy; the profile record's
  `inboxKey` is its public half.
- Each key an envelope is sealed to is an age post-quantum hybrid key (`age1pq1…`, stanza
  `mlkem768x25519`); an app MUST NOT seal an envelope to any other kind, since one classic key
  among them would let a quantum computer open it for all. Each adds about 2 KB.
- A host checks a private record like any other and cannot open it. Anyone can see that it
  exists, its path, time and size, and how many keys it is sealed to.
- To remove a reader, the owner writes a new version for the rest; a reader keeps what it already
  opened.

### Inbox

A message is a sealed envelope anyone delivers to a profile's hosts, and only its main key or its
read keys pull. It is not a record: it has no path and no versions, and it is in no one's folder.

**Declaring it.** The profile record's optional `inbox` field:

```
"inbox": { "senders": "anyone" | { "issuer": <issuer address> }, "once"?: true,
           "maxBytes"?: <integer>, "readers"?: [<age1pq1…>, …] }
```

- No `inbox` field means no inbox: hosts refuse deliveries. A profile with an inbox gives
  `inboxKey`, since senders seal to it.
- `senders` is `"anyone"`, or `{ "issuer" }`: the sender's profile record carries a note proof from
  that issuer (Proofs) that holds for the sender's key, under any label. The issuer is named by its
  key's address, as the proof shows it.
- `once`: one message from each sender, ever.
- `maxBytes`: the largest message it takes, as canonical text in bytes.
- `readers`: what read keys are sealed to, their `sealTo`. Senders seal every message to them too,
  so a helper holding a read key the permissions record lists for the inbox pulls and opens while
  the person's devices are off, and, with a write key, answers.
- A host refuses deliveries to an inbox it cannot read: a field, a rule or a value it does not
  know. So a new rule can be added without an old host taking what it should refuse. A
  sender's app does not deliver to one either: a field it does not know could name more keys to
  seal to.

**Messages.**

```
{ "v": 1, "to": <address>, "from": <address>, "time": <ms since 1970>,
  "body": { "private": <base64url of an age file> }, "key"?: <address>, "host"?: <origin>,
  "sig": <base64url> }
```

- `v` is 1. No other field is allowed, in the message or in its body.
- `to` is the profile it is to. `from` is the sender's key: a main key, or any other key on Baby
  Jubjub.
- `body` is one envelope sealed to `to`'s inbox key and its inbox's readers.
- `key` is there when a write key signs for `from`, a main key: the write key's address, other
  than `from`. So the profile it is to sees that a write key sent it.
- `host` is one of `from`'s hosts, an origin as its hosts record writes it: where a receiving host
  reads `from`'s records. It MUST be there with `key`, and with an inbox with an issuer's rule;
  otherwise it MAY be.
- `sig` is EdDSA-Poseidon by `key` if present, else by `from`, strict as a record's, over `0xff` ‖
  UTF-8(`forest/v1/message\n`) ‖ UTF-8(canonical text of the message without `sig`).
- The id is lowercase hex of SHA-256(signing input), as a record's.

**Deliver.** The sender reads the profile record of the profile it writes to, for its `inbox` and
`inboxKey`, and its hosts record. It seals the body, signs, and posts the message to each host the
hosts record names (`POST /v1/inbox`). Anyone may deliver, with no login; each host checks the
message on its own (Hosts).

**Send with a write key.** The main key lists the write key with scope `write`, its paths covering
`inbox`; the message names it as `key`, and one of the main key's hosts as `host`. No permissions
record travels in the message: the receiving host reads `from`'s current hosts and permissions
records from `host`, so a write key the owner makes past stops being taken once a host reads them
again. The inbox's rule and `once` apply to `from`, as for any message.

**Pull.** A profile asks each of its hosts for what arrived after a cursor, the number a host
gives the last message on a page, so the next ask starts after it (`POST /v1/inbox/pull`):

```
{ "v": 1, "profile": <address>, "after": <cursor>, "time": <ms since 1970>, "key"?: <address>,
  "sig": <base64url> }
```

- `sig` is EdDSA-Poseidon by the profile's main key, or by `key`, one of its read keys, over
  `0xff` ‖ UTF-8(`forest/v1/pull\n`) ‖ UTF-8(canonical text without `sig`). A read key pulls only
  while the profile's permissions record on that host lists it with scope `read`, its paths
  covering `inbox`. No other access key pulls.
- `after` is the `forest-cursor` of the last page; 0 for everything.
- `time` is within 600,000 ms of the host's clock, either way.
- It is signed because each body is sealed but `from`, `to` and the time are not: unsigned,
  anyone could list who wrote to whom. It is a POST and not a GET because hosting platforms log
  URLs, and a signed URL would be a log of pulls.

**Requests.** A message body may be `{ "request": <kind>, … }`: something the sender was not
allowed to do itself, for the receiving profile's app to do with its main key. `request` names one
of the kinds below, and the other fields are that kind's parameters:
`{ "request": "post-offer", "offer": { … } }`, `{ "request": "send", "to": <address>, "text": … }`.

| Kind | Parameters |
|---|---|
| `post-offer` | `offer`, an offer record's body; and `id`, the `<id>` in `offer/<id>`, if wanted |
| `update-offer` | `id`, the `<id>` of the offer; `offer`, its new body |
| `remove-offer` | `id`, the `<id>` of the offer |
| `post-review` | `review`, a review record's body; and `id`, the `<id>` in `review/<id>`, if wanted |
| `send` | `to`, the address of the profile to send to; and `text`, or `body`, an object in its place, one of the two |
| `private` | `path`, if wanted: only the private records under this path |
| `inbox` | `after`, if wanted: the cursors a pull returned, by host, for newer messages only |
| `pay` | `offer`, `amount`, `mint` and `note`, as below |

For `pay` they are `offer`, the offer as `<profile address>/offer/<id>`; `amount`, decimal text in
whole units of the mint, such as `"25"` or `"12.50"`; `mint`, the money's mint address on Solana;
and, if wanted, `note`, text for the person: `{ "request": "pay", "offer": <profile
address>/offer/<id>, "amount": "25", "mint": <mint address>, "note": … }`. The app reads the offer
and opens the escrow from it ([solana](../escrows/solana/README.md#two-ways-to-open-it)).

An app acts on a request only when it was sent to the profile's own inbox by the profile's main
key or by a write key its permissions record lists for the inbox, and shows any other `request`
body as a plain message. It shows the request, and does it only if the person agrees. So whoever
holds a write key for `inbox` alone can send messages as the profile and ask for anything else; it
writes records only under `inbox`, and moves no money.

### The vault

The vault is one folder on a host, sealed to the vault's own inbox key, holding what the seed
cannot recompute: which profiles exist and where each lives, their issuers' notes (the note each
issuer signed to the seed), and settings. Its main key is the vault key, mixed from the seed
([keys](../keys/README.md#the-vault-key)), so a new device finds it with the seed and one host's
address; like any folder, its hosts record may name more than one host.

```
{ "profiles": [{ "label": <label>, "hosts": [<origin>, …] }, …],
  "issuerNotes": [{ "issuer": <issuer name>, "note": <signed note> }, …],
  "settings": { … } }
```

- The folder holds its hosts record and one private record at `vault`, its body the object above,
  sealed to the vault's own inbox key alone. It has no profile record, no inbox and no access keys.
- Every field may be missing. An app keeps every field it does not know, at the top and inside
  `settings`, so two apps share one vault.
- `profiles`: each label once, with the hosts its folder lived on when written; the signed hosts
  record there is the truth.
- `issuerNotes`: the issuer's name, exactly as keys/'s recipe takes it, and the note it signed, as
  proofs/note/'s JSON ([note](../proofs/note/README.md#the-note-and-the-note-proof)).
- `settings`: apps' settings, such as the hosts, issuers and indexes the person chose. Each field
  is an app's own.
- To change it, an app reads the current vault, changes it, and writes it, at a time past the
  current one's, to every host the vault's hosts record names.

**Restoring.** A new device mixes the vault key from the seed, and its inbox key from the vault's
secret. It needs one host's address: it asks a host it knows, or one the person names, for the vault
key's folder; the folder's hosts record names the rest. It finds no vault only when every host it
asked answered: if one failed, the read fails too, since the vault may be there. It opens `vault`,
then mixes each profile's main key from its label and reads that folder from its hosts. Issuer
secrets come from the seed and each note's issuer name.

### Proofs

The profile record's optional `proofs` field carries up to four proofs, each named by its
`circuit` and checked by that circuit's verifier ([schemas/profile.json](schemas/profile.json)).
A proof counts for one main key: a reader checks it against the address of the profile that
carries it, so a proof copied to another profile fails. A reader ignores a proof whose circuit it
does not know, so a newer kind never makes a profile invalid for an older app. An app puts a
proof in the profile record only when the person chooses to show it there:
[proofs/reputation/](../proofs/reputation/README.md#limits) says what one can reveal. Records
checks no proof itself: `noteCheck` and `reputationCheck` turn a proof on a profile record into
what its verifier takes, for the profile that carries it.

- **`note`** shows that an issuer signed a note to the seed that gives this profile's key for its
  label ([proofs/note/](../proofs/note/README.md)). It carries the issuer's key, as its address, and
  its name, the label, the profile's stamp at that issuer, and the proof's 256 bytes, in the
  reputation proof's order. A reader checks it with proofs/note/client's `verifyNote`, which works
  the name hash and the scope out of the name and the label itself. Each reader decides which
  issuers it trusts.
- **`reputation`** shows the score of profiles the person holds in an index's tree, without
  saying which. It carries the index's key, the root and time the index signed and its signature,
  the score, the label when the proof shows one market, and the proof's 256 bytes. A reader checks
  it with proofs/reputation/client's `verifyReputation`: the proof derives this profile's key from
  the same seed as the profiles it counts, so nobody can lend their score to someone else. Each
  reader decides which indexes it trusts and how old a time it accepts. How it is made is
  [proofs/reputation/](../proofs/reputation/README.md)'s.

### Blobs

A blob is bytes a folder holds, such as a photo or a video. It is the folder's, not a record's: no
record needs to name it, and none keeps it on a host. Where a record points at a blob, and under
what field, is the market's.

```
{ "v": 1, "action": "put", "profile": <address>, "sha256": <hex>, "mimeType": <type>,
  "size": <bytes>, "time": <ms since 1970>, "key"?: <address>, "sig": <base64url> }
```

- **Its name** is what a stranger needs to fetch it and check it: `sha256`, the SHA-256 of the
  bytes in lowercase hex; `mimeType`, their media type, `type/subtype` in lower case, at most 255
  characters; and `size`, how many bytes.
- **Put.** The folder's main key, or a write key its permissions record lists, whatever the key's
  paths, signs a put, above, and sends it with the bytes to each of the folder's hosts
  (`PUT /v1/blobs/<sha256>`). The main key putting bytes a write key put makes them its own.
- **Delete.** `{ "v": 1, "action": "delete", "profile", "sha256", "time", "key"?, "sig" }`, to each
  host (`DELETE /v1/blobs/<sha256>`). A key deletes only blobs it put; the owner deletes any.
- `key` is there when a write key signed. `sig` is EdDSA-Poseidon by `key` if present, else by
  `profile`, strict as a record's, over `0xff` ‖ UTF-8(`forest/v1/blob\n`) ‖ UTF-8(canonical text
  without `sig`). The request travels in the header `forest-blob`, as its canonical text, and its
  `time` is within 600,000 ms of the host's clock, either way, as a pull's.
- **Kept** until a key that may deletes it, or by the host's own retention rule, which each host
  chooses and says where it describes itself, as Forest's host does in
  [How we run it](https://github.com/foundationforest/services/tree/main/host#how-we-run-it). The
  reference host keeps blobs until they are deleted. Bytes two folders hold stay until the last of
  them deletes them.
- **Fetch.** Anyone fetches a blob from the folder's hosts (`GET /v1/blobs/<sha256>`), with no
  request to sign, and checks its SHA-256 itself: a host that serves other bytes is skipped.

### Hosts

A host is an address that answers eight requests, the host socket, however many machines stand
behind it. It has no keys, no accounts and no login: a record's signature is all it asks for, a
pull's is the main key's or a read key's of the profile it pulls for, and a blob request's the
folder's main key's or a write key's. It is open: it takes signed records for any profile and serves
them to anyone; it takes messages for any profile whose profile record on it declares an inbox, and
serves them only to that profile's main key and read keys; it takes the bytes a folder's keys put,
and serves them to anyone. It reads no offer's or review's body. A host never talks to an index; to
take a message a write key signed, or one to an inbox with an issuer's rule, it reads the sender's
records from the sender's host.

| Request | Body | Answer |
|---|---|---|
| `POST /v1/records` | NDJSON, one canonical record a line | NDJSON, one `{i, id?, ok, error?, message?}` a line (Taking a record in) |
| `GET /v1/records?profile=&after=` | none | NDJSON of stored records in the order taken, after the cursor `after`, one profile's if asked |
| `POST /v1/records/read` | `{ "profile"?: <address>, "after"?: <cursor> }` | the same |
| `POST /v1/inbox` | NDJSON, one canonical message a line | as for records (Taking a message in) |
| `POST /v1/inbox/pull` | a pull's canonical text | NDJSON of the messages to that profile that arrived after the cursor, in arrival order |
| `PUT /v1/blobs/<sha256>` | the raw bytes, `content-type` their type; the signed put in the header `forest-blob` | `{ok, error?, message?}` (Taking a blob in) |
| `GET /v1/blobs/<sha256>` | none | the bytes, with the type they came in with, or 404 |
| `DELETE /v1/blobs/<sha256>` | none; the signed delete in the header `forest-blob` | `{ok, error?, message?}` (Deleting a blob) |

- A page's header `forest-cursor` is the last sequence number on it: the next page is after it.
  A page always holds at least one line.
- `POST /v1/records/read` gives the same answer as `GET /v1/records`, with the profile and the
  cursor in the body instead of the URL. Front doors, the proxies and hosting platforms that stand
  in front of a host, log URLs, so a person who reads their own profiles by GET leaves a trail. The
  GET stays for public readers.
- A refused pull is answered 400 with `{ok, error, message}`: [`stale`] when its time is more than
  600,000 ms from the host's clock, [`signature`] when neither the profile's main key nor the
  `key` it names signed it, [`permission`] when the profile's permissions record on this host does
  not list that `key` with scope `read`, its paths covering `inbox`, or a shape code.
- A request with more lines than the host takes gets one [`batch`] result, and one with more bytes
  gets 413.

**Taking a record in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Records and the control records
   [`canonical`, `shape`, `path`, `key`, `version`, `time`, `body`, `control`, `hosts`,
   `permissions`, `signature`], and `time ≤ now + 600,000` [`future`].
2. Within a request, hosts and permissions records first, then the rest in the order sent.
3. It MUST become the current record at its path by Which record counts, over what the host
   stores plus it [`older`, `permission`].
4. An access key's record: the current permissions record MUST allow it, by the access rule
   (Permissions) [`permission`]. The host checks it again just before it stores the record.
5. A host MAY refuse a content record by its own choice [`refused`]. It MUST NOT refuse a hosts or
   permissions record by its own choice but for its size, so a person can always move and always
   remove an access key: a record that only deletes a key's entry is never larger than the one
   before.

**Taking a message in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Messages [`canonical`, `shape`,
   `version`, `key`, `time`, `body`], and `time ≤ now + 600,000` [`future`].
2. No message with the same id is here already [`duplicate`].
3. The current profile record of `to` on this host declares an inbox [`no_inbox`].
4. The signature: by `key` if the message names one, else by `from` [`signature`].
5. A write key: the host reads `from`'s records from `host`, as a reader does
   (`GET /v1/records`), or uses what it read before, kept for a time it chooses. `host` MUST be
   one the current hosts record names, and the current permissions record MUST list `key` with
   scope `write`, its paths covering `inbox` [`permission`]. A read that fails is [`lookup`]: the
   sender may try again. A host that reads no sender's records refuses every message a write key
   signed [`rule_unsupported`].
6. The rule, on `from`. An inbox the host cannot read is [`rule_unsupported`]. `"anyone"` passes.
   `{ issuer }`: a host that checks no note proof accepts only `"anyone"`
   [`rule_unsupported`]. The message MUST name `host` [`sender`]; the host reads `from`'s records
   from it as in step 5 [`rule_unsupported`, `lookup`, `permission`], and `from`'s current profile
   record there MUST carry a note proof from that issuer that holds for `from`, under any label:
   proofs/note/client's `verifyNote`, given the proof as `noteCheck` makes it [`sender`]. A
   check that fails to run is [`lookup`]: the sender may try again.
7. `once`: a second message from this `from` to this `to` is refused, ever, whichever key signed
   it [`once`]. The host keeps each pair it takes while the inbox says `once`, for as long as it
   keeps the profile.
8. `maxBytes`: the canonical text is at most that many bytes [`too_big`].
9. A host MAY refuse a message by its own choice [`refused`].

A message whose `from` is its `to` skips steps 6 to 8: an inbox's rules are for others.

**Taking a blob in**, in this order, error code in brackets:

1. The signed put (Blobs): no larger than the host takes, then its canonical text and shape
   [`size`, `canonical`, `shape`, `version`, `key`, `time`], a put for the name in the path
   [`shape`], its time within 600,000 ms of the host's clock [`stale`], and its signature, by `key`
   if it names one, else by the profile's main key [`signature`].
2. A write key: the current permissions record on this host lists `key` with scope `write`
   [`permission`]. The host checks it again just before the folder holds the bytes.
3. The bytes are the type (`content-type`) and the size the put names [`shape`], and their SHA-256
   is the name in the path [`hash`].
4. Bytes the folder holds already are `already here`.
5. The host's own choice allows them, by their size, their type, or what the folder holds there
   already [`refused`]. A declared size larger than the host takes is answered 413, unread.

**Deleting a blob**, in this order:

1. The signed delete, as step 1 and step 2 of taking a blob in.
2. Bytes the folder does not hold are `not here`.
3. A write key deletes only bytes it put; the main key deletes any [`permission`]. Whether the write
   key is still listed, and who put them, are read in the same step that deletes them.
4. Once no folder holds the bytes, the host deletes them.

A busy host SHOULD verify in native code, with these same strict rules: another library may skip
one (zk-kit's `verifySignature` does not check that the key is in the prime-order subgroup).

### What a host chooses

Nothing here is a rule: each host chooses, and says its numbers where it describes itself, as the
reference host does (Run it).

- **Sizes.** The largest record, message and blob it takes; how many records or messages a
  request may carry; how many lines and bytes a page holds. A client handles any size: it sends a
  refused request again in halves, and follows the cursor page by page. A reader MAY ignore a
  record, a message or a blob it finds too big.
- **Keeping.** A record that stops being current is kept for a number of days the host chooses,
  by its own clock, then deleted. A message is kept for a number of days from when it arrived; a
  pull does not delete it. A blob stays until the folder deletes it, unless the host has a
  retention rule of its own, which it says. A host that drops a current record withholds it.

### Indexes

An index reads the hosts it lists in full, page by page (`GET /v1/records`), verifies the note
proofs on each profile, and interprets records by the market files it reads
([foundationforest/markets](https://github.com/foundationforest/markets)). Each index chooses which
hosts it reads. It MAY answer one request, `POST /v1/hosts`: the body is a profile's hosts record
as canonical text, and the answer is the HTTP status and nothing else. The index checks the
signature, then reads the hosts the record names, if it chooses to; sending the record again asks
it to look now. An app sends the hosts record to the indexes the person chose.

### Run it

`@foundationforest/records` has four import paths, each built to `dist/` with types, and the shapes:

- `@foundationforest/records`: keys as addresses (`publicKeyFromAddress`, `keyFromScalar`);
  canonical text; signing, checking and encoding records; the view (`viewProfile`, `liveContent`,
  `allows`, `allowsInbox`, `covers`); writing (`ownerRecord`, `accessRecord`, `hostsRecord`,
  `permissionsRecord`, `nextTime`); messages and pulls (`signMessage`, `decodeMessage`, `messageId`,
  `pullRequest`, `checkPull`, `inboxOf`, `sealedTo`); blob requests (`blobNameOf`, `blobRequest`,
  `checkBlobRequest`); a profile record's proofs as their verifiers take them (`proofsOf`,
  `noteCheck`, `reputationCheck`); talking to hosts (`publish`, `readPage`, `readAll`,
  `readProfile`, `deliver`, `pull`, `putBlob`, `getBlob`, `deleteBlob`). A host that fails does not
  stop `readProfile`: it reads the others and lists that host, with the error, in `failed`. A read
  ends with an error on a cursor that is not a whole number or does not move forward, and its
  `timeout` bounds the whole read. A publish reads a host's status first, and sends a batch the host
  answers 413 again in halves. A read asks by POST with `post: true`. A read, a publish, a delivery
  and a pull go through the caller's own `fetch` if given, and refuse a host that redirects with
  `redirect: 'error'`. No server, database or encryption library is in it. The keys themselves,
  `mainKey`, `accessKey` and `readKey` among them, are keys/'s.
- `@foundationforest/records/private`: `makePrivate`, `openPrivate`, `readerCount`; `message` (seal
  to a profile record's inbox key and readers, and sign) and `openMessage`; the vault
  (`vaultRecord`, `openVault`, `readVault`, `checkVault`, `VAULT_PATH`). The inbox key itself is
  keys/'s `inboxKey`, and the vault's keys/'s `vaultKey`.
- `@foundationforest/records/host`: `Host`, the reference host (below).
- `@foundationforest/records/public`: `publicFetch`, a fetch that reaches only public addresses and
  follows no redirect, for a host or an app that goes to a host a stranger named: it refuses
  loopback, private, link-local, carrier-grade NAT, NAT64, 6to4, multicast and every other range not
  globally reachable, written in the URL or behind a name. `isPublic` checks one address. Node only,
  like the host.
- `@foundationforest/records/schemas/profile.json`: the profile record's shape, as a JSON Schema.

Publish a profile with one offer, read it back, put a photo in the folder, then let another app
write offers:

```ts
import { randomBytes } from 'node:crypto'
import { accessKey, mainKey } from '@foundationforest/keys' // keys/
import { accessRecord, blobNameOf, blobRequest, hostsRecord, ownerRecord, permissionsRecord,
  publish, putBlob, readProfile } from '@foundationforest/records'

const me = await mainKey(seed, 'tutoring/seller') // seed: its 32 bytes
const now = Date.now()
const maths = { ...fields } // an offer's fields are its market's (foundationforest/markets)
await publish([host], [hostsRecord(me, [host], now), ownerRecord(me, 'offer/maths', maths, now)])
// Your own profile: by POST, so its address is in the body, not the URL.
const view = await readProfile([host], me.address, Date.now(), { post: true })
view.current.get('offer/maths')?.record.body
const photo = blobNameOf(jpeg, 'image/jpeg') // jpeg: the photo's bytes
await putBlob(view.hosts, blobRequest(me, { action: 'put', ...photo }, Date.now()), jpeg)

const helper = accessKey(randomBytes(32)) // the other app's write key: these 32 bytes go to it
const access = [{ key: helper.address, scope: 'write' as const, paths: ['offer'] }]
await publish(view.hosts, [permissionsRecord(me, access, now)])
const physics = { ...otherFields }
await publish(view.hosts, [accessRecord(helper, me.address, 'offer/physics', physics, now)])
```

Write to that profile's inbox from another profile, then pull it on the owner's device:

```ts
import { inboxKey, mainKey } from '@foundationforest/keys'
import { deliver, pull, pullRequest, readProfile } from '@foundationforest/records'
import { message, openMessage } from '@foundationforest/records/private'

const buyer = await mainKey(otherSeed, 'tutoring/buyer')
const seller = await readProfile([host], me.address, Date.now()) // it declares an inbox
const sellerProfile = seller.current.get('profile')!.record.body!
const ask = await message(buyer, me.address, { text: 'Is Tuesday at six free?' }, Date.now(),
  sellerProfile)
await deliver(seller.hosts, [ask])

const page = await pull(host, pullRequest(me, 0, Date.now())) // the main key signs each pull
const { identity } = await inboxKey(me.secret) // the inbox key
for (const m of page.messages) (await openMessage(m.message, identity)).body
```

Let a helper answer while the owner is away. It holds `reader`, a read key listed with scope
`read` for `inbox` and named among the inbox's readers, and `writer`, a write key listed for
`inbox`:

```ts
import { readAll } from '@foundationforest/records'
import { Host } from '@foundationforest/records/host'
import { verifyNote } from '@foundationforest/note' // proofs/note/client

// A host takes a message a write key signed only if it reads the sender's records; given
// verifyNote too, it takes messages to inboxes with an issuer's rule.
const buyersHost = new Host({
  readSender: async (url, profile) => (await readAll(url, { profile })).records,
  verifyNote,
})

const mine = await pull(host, pullRequest({ key: reader, profile: me.address }, 0, Date.now()))
for (const m of mine.messages) (await openMessage(m.message, reader.identity)).body
const buyerView = await readProfile([host], buyer.address, Date.now())
const buyerProfile = buyerView.current.get('profile')!.record.body!
const from = { key: writer, from: me.address, host }
const answer = await message(from, buyer.address, { text: 'Tuesday at six, yes.' }, Date.now(),
  buyerProfile)
await deliver(buyerView.hosts, [answer])
// The main key names one of its hosts for an inbox with an issuer's rule: { from: me, host }.
```

```
# The tests take their keys from keys/, and check the example profile record's proofs with the
# proofs' clients.
npm ci && npm run build   # at the root: every package; keys/, both clients and records to dist/
cd records
npm run check          # type-check
npm test               # everything, on loopback
npm run bench          # speed on this machine
node test/vectors.ts   # print the test vectors
node scripts/example-profile.ts   # make the example profile record's proofs again, after
                                  # npm run fetch in proofs/reputation/circuit
```

Node 22.18 or later. Built from existing pieces, unchanged: `@noble/curves`, `@noble/hashes`,
`@scure/base`, `poseidon-lite` and `canonicalize` for the core, with keys/'s Baby Jubjub;
`age-encryption` for private records and messages; Node's built-in `node:sqlite` for the host;
`undici` for the public fetch.

**The reference host.** One process, listening on `127.0.0.1` unless told otherwise; TLS is the
operator's. What it chooses, unless told otherwise: records and messages of up to 65,536 bytes, and
100 a request; pages of at most 1,000 lines and 4,194,304 bytes; a replaced record and a message,
kept for 30 days; png, jpeg and mp4 blobs of up to 50,000,000 bytes, kept until their folder
deletes them. Give it `readSender` to take messages a write key signed, and `verifyNote` with
it to take messages for inboxes with an issuer's rule: it reads the sender's records again for each
request.

It keeps everything in its data directory, `dir` (a temporary one, removed on close, when none is
given), through one module, `src/storage.ts`:

- `folders/<address>.sqlite`: one file per folder, with its records, the messages to its inbox, its
  once pairs and the blobs it holds. With the host stopped, deleting a folder's file removes that
  folder, and the next prune deletes the bytes no other folder holds.
- `host.sqlite`: the log, which numbers every folder's records in the order taken, and which
  folders hold which blobs. It holds nothing that exists only there: `rebuild(dir)` makes it
  again. A new number, a record's or a message's, is the larger of the last one plus 1 and the
  clock in microseconds, so a rebuilt `host.sqlite`, or a folder's file made again, never reuses
  one, unless the clock is set back.
- The blobs: in `blobs/`, or with `blobs: { kind: 's3', … }` in a bucket of any S3-compatible
  service.

One machine, one file per folder; when it grows, more machines, a managed per-folder store, or
Postgres: the storage is one module.

### Test vectors

`test/vectors.json`: a hosts, profile, offer, permissions, write key's offer and delete record,
each with its wire text, signing input and id, for keys/'s `tutoring/seller` profile from its test
seed `00 01 … 1f`; the profile record's `inboxKey` is that profile's inbox key. The write key is
keys/'s from 32 bytes of `0x2a`, listed for `offer` and `inbox`; the read key keys/'s from 32 bytes
of `0x2b`, listed with its `sealTo` for `inbox`. The seed, the main key, the inbox key and both
access keys are pinned in `keys/test/vectors.json`, and checked there. It also holds a message from
keys/'s `tutoring/buyer` profile to `tutoring/seller`, and a message from `tutoring/seller` signed
by its write key, naming `https://host-a.example`, to `tutoring/buyer`, each with its wire text,
signing input and id; a pull request by `tutoring/seller`, and the same pull signed by its read
key; `past`, a later permissions record in which the write key is past, until that record's time,
and the read key still listed; and two blob requests, each with its wire text and signing input:
`blobPut`, the main key
putting the 26 letters `a` to `z` as `text/plain`, and `blobDelete`, the write key deleting them.
Each message's body is sealed to the inbox key of the profile it is to; age's sealing is random, so
the sealed bodies are pinned as they were made. `test/vectors.test.ts` recomputes the records, the
messages, the pulls and the blob requests, checks each with a second SHA-256 (node:crypto) and a
second EdDSA-Poseidon (zk-kit's, from the address and the 64 bytes on its own), and opens each
message with the pinned inbox key it was sealed to. The profile is
`9bpPbLYCPwNWq9BZqnJr3EqRNqymFZ4g58Zk9K86azDC`; every signing input begins `ff 66 6f 72 65 73 74 2f`
(`0xff`, then `forest/`).

The example profile record, [schemas/examples/profile.json](schemas/examples/profile.json), is that
profile's, with a note proof from an example issuer and a reputation proof from an example index's
tree, made with the circuits' setups by `scripts/example-profile.ts`; `test/schemas.test.ts`
checks both with their verifiers.

## Promises

- **A record checks the same wherever it comes from.** One canonical spelling and strict
  EdDSA-Poseidon on Baby Jubjub. A host cannot forge or change a record; it can only withhold it.
- **Every reader computes the same view from the same records.** Where they came from and in what
  order does not matter. The reader's clock matters only to hold back records dated more than ten
  minutes ahead.
- **The owner wins.** An access key never replaces or deletes what the main key wrote, and never
  writes the hosts or permissions record.
- **Nobody writes for a profile unless its permissions record says so.** Removing an access key
  ends what it can add dated after its removal, at any host that follows the standard; what it
  wrote before still counts.
- **A person can always move.** A profile's name is its key, not a host's address. A host never
  refuses a newer hosts or permissions record by its own choice but for its size, and one that
  only deletes an access key's entry is never larger than the one before.
- **A host holds nothing secret of the people it serves.** No keys, no accounts, no login, and it
  cannot open a private record.
- **Only a profile's main key, or a read key its permissions record lists for the inbox, can pull
  its inbox.**

## Limits

- **The reference host is a reference.** One process on one machine, a SQLite file per folder. It
  checks each record against everything it stores for that profile, which is slow for a busy one.
- **Checking signatures is slow here.** Pure JavaScript checks about 300 a second on one core of
  the machine these tests ran on, and the reference host takes about 190 records a second
  (`npm run bench`). A busy host or index should verify in native code with the same strict rules
  (Hosts).
- **A host keeps only the newest record at each path,** and what it replaced for its keep days.
  Older history is in the app's copies, or nowhere.
- **A removed key can still write a record dated before its removal time.** A newer record at that
  path wins, and you can delete it.
- **A message a write key sent proves only that the key signed it.** The host that took it checked
  the key was allowed at the time; the message itself does not carry that.
- **A host sees who wrote to whom.** It holds each message's `from`, `to`, time and size, and the
  write key when one signed, though not what it says. To take a write key's message, or one to an
  inbox with an issuer's rule, it asks the sender's host for the sender's records, which tells that
  host where the sender wrote. Filtering by an inbox's rule needs the sender, so there is no
  anonymous mode.
- **A blob is only as true as its hash.** A host checks the hash and the size, never that the
  bytes are the type their put names; a record that points at them says what it means them to be.
- **A delete is a request.** What was public may already have been copied: whoever fetched the
  bytes has them.
- **No forward secrecy.** An inbox key or a read key that leaks opens every message and private
  record sealed to it, from any host or copy that still holds them, and a reader removed keeps
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
- **The vault is one record.** A host's largest record bounds it: 64 KB on the reference host.
- **Not here: a pay scope.** A key that moves money is the person's own; a delegate's allowance is
  the chain's, not this standard's.

## Who decides what

- **The standard:** the record and the message, and what makes each valid (the ten-minute
  window); the eight requests and their codes; the control records and the scopes of access keys;
  envelopes; the profile record's fields; a blob's name, its put and its delete; the inbox, its
  rules and the request body; the vault; the proofs field.
- **A market chooses:** its roles, the bodies of its offers and reviews, and where a record points
  at a blob ([foundationforest/markets](https://github.com/foundationforest/markets)).
- **A host chooses:** its keep days, and any retention rule for blobs; the largest record, message
  and blob it takes; batch and page sizes; which blob types it takes; which inbox rules it supports;
  whether it reads senders' records to take a write key's message, and how long it keeps what it
  read; rate limits; logging; storage.
- **An app, with the person:** the copies it keeps; which hosts, the vault's among them; which
  private records it seals to a read key; how an access key reaches its holder; whether to
  forward a message to email or a notification; dropping a message that arrives twice; what it finds
  too big to read; and what asks for the person's device unlock. The profile can change or delete
  anything it wrote, at will. What others wrote about it, and payments, stay.
- **An index chooses:** which hosts it reads, which issuers and markets count, how much each
  review weighs, and which proofs it accepts.

## FAQ

**Why does the permissions record carry no names, and no date but a past key's `until`?**
It is public. A date would tell anyone when you met someone or began using an app, and a name
would say who. Who a key is for, and since when, is the app's to remember, on the person's devices
or in the vault, which only the person opens. A past key's `until` is the one date it keeps: the
time of the permissions record that removed the key, which anyone could read while that record was
current. It stays so that a later permissions record never reopens what the key can add, and so
anyone can read when each past key was removed. Readers still check no clock, and agree whatever
theirs say.

**Why does a past key have `was` in place of `scope`?**
So nothing that checks a key's scope lets a removed key act.

**Why does the owner win?**
An access key lives somewhere less safe than the main key: on a server, or with another app. If
it could replace what you wrote yourself, losing it would let someone rewrite your profile record
or your offers. Because the owner wins, the worst a lost access key can do is add records where
you never wrote, and you can always overwrite or delete those by writing at the same path.

**Why does the owner make the readers' keys?**
So a reader needs no profile and no key of its own: the owner's app makes a read key for it and
hands over its 32 bytes. A read key that leaks opens only what one owner sealed to it, never
everything ever sealed to the reader's own inbox key. And one relationship can be ended without
the reader rotating its own key.

**Why is the inbox one of a key's paths, and not a scope of its own?**
A key's paths already say where it acts, and its scope what it does there: a write key sends to
the inbox as it writes elsewhere, and a read key pulls it as it reads elsewhere. So two scopes
cover the inbox with no third. `inbox` is not kept from records: a write key for `inbox` may write
records under it too, which no shape names and readers may ignore.

**Why is a blob the folder's, and not the record's that points at it?**
A host that kept bytes only while a record named them had to read every record's body for the
fields that name them, and where a record points at a blob is each market's to say. So the folder's
own keys put and delete its blobs, and a host reads no offer's or review's body. A blob sits at no
path, so a write key puts one whatever its paths; how much a folder may put is the host's choice.

**Why is a message not a record in the sender's folder?**
Anyone reads a folder. A message there would need a field naming who it is to so hosts could
route it, and that field would make every inquiry a public fact: who asked whom, and when. A
message goes to the hosts of the profile it is to instead, sealed, and only that profile pulls it.

**How do I hear that a message arrived?**
By default the app checks your inboxes itself, pulling from your hosts. A push service would see
which inboxes one device watches, and so which profiles are one person's.

**Why is there no deposit rule?**
A rule that asks senders to pay would have every host check payments. An inbox's `senders` is a
field with kinds, and a host refuses deliveries under a kind it does not know, so a new kind can be
added without breaking anything.

**Why is the vault a folder of its own?**
A new device has only the seed and a host's address. A record inside a profile's folder could be
found only by first knowing that profile's label, and the labels are what the vault keeps. A folder
named by a key from the seed is found with nothing more; it can live on hosts apart from the
profiles; and no profile's key opens it.

**Why is a proof's `proof` 256 bytes, and not snarkjs's JSON?**
A record's object keys cannot spell snarkjs's `pi_a`, `pi_b` and `pi_c`: they allow no `_`. The
256 bytes are the proof's three points, not compressed, in the order Ethereum's and Solana's BN254
precompiles read them, so a reader gets snarkjs's form back by reading eight 32-byte numbers.
Compressed, the points would take 128 bytes fewer, but every reader would have to take square
roots to rebuild them.

**Why not AT Protocol, Nostr or Pubky as the base?**
AT Protocol has one server per profile and a central directory. Nostr's keys are on secp256k1,
which a proof cannot derive from a seed cheaply, and it has no access key that can be removed.
Pubky's servers can forge records.
