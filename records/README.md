# records

Part of Forest's standard: [the top README](../README.md). The profile record's shape:
[schemas/](schemas/).

## What it is

How a Forest profile says things, and how anyone reads them. Everything a profile says (its profile
record, which shows it; its offers; its reviews of others) is a record: a small signed JSON value at
a path in the profile's folder. A profile record shows the profile's market and role, and may carry
its pay addresses, its inbox and its proofs. Hosts keep folders and serve them to anyone. Any
app, index (a service that reads records and scores profiles) or AI reads them and checks every
signature itself, so a host can withhold a record but never forge one. Beside each folder a host
keeps the profile's inbox, where anyone may leave an encrypted message, and its blobs: photos and
videos the folder's main key puts there.

This README is the standard. The library in `src/` does every MUST in it, and `test/` checks it;
MUST, SHOULD and MAY are as in RFC 2119. The directory also holds a reference host, the profile
record's shape as a JSON Schema, and test vectors.

## How it works

### Folders

A profile is one main key, mixed from the person's seed (32 bytes every key comes from) and a label,
`<market>/<role>`, such as `tutoring/seller` ([keys/](../keys/README.md)). The main key is a key on
Baby Jubjub, the curve the proofs work on, and its address is its name on the network: the public
key packed into 32 bytes, in base58. Its inbox key, mixed from the profile's secret, opens what is
encrypted to it, and its pay keys, one for each address type, give its Solana and EVM addresses.
Nothing else is needed: no sign-up, no directory.

Its folder is everything signed for it, one current record per path:

| Path | What it holds |
|---|---|
| `hosts` | where the folder lives |
| `profile` | the profile record: market, role, pay addresses, inbox, proofs |

- Every record in it is signed by the profile's main key, and by no other key.
- `hosts` is the control path, the one record every host reads. Every other path is content.
  Beside `profile`, content paths and their bodies are the market's, the one the profile's label
  names: [foundationforest/markets](https://github.com/foundationforest/markets) keeps
  `offer/<id>` and `review/<id>` as the two kinds a market defines. Readers MAY ignore a first
  segment they do not know.
- A path is 1 to 4 segments separated by `/`, each `[a-z0-9][a-z0-9._-]{0,63}`, at most 256
  bytes.
- `profile` is shaped by the JSON Schema in `schemas/`: its fields are the standard's, and its
  market (the trade a label names, such as `tutoring`) adds fields beside them. A blob a record
  points at is the folder's (Blobs).
- A record sits in the folder of the profile that wrote it, so the profile a review is about
  cannot erase it; the one who wrote it can.

**The hosts record** is `{ "urls": [origin, …] }`: 1 to 8 distinct origins, `https://host[:port]`,
lower case, no path (`http` only on loopback, for tests). Each host it names holds the whole folder.
An app posts every record to every host it names, the hosts record first. Moving is copying the
folder to the new host: its hosts record, naming the new host, then every record. To leave a host,
post a hosts record that no longer names it, to every host, the one you are leaving included, so a
reader that still asks that host is pointed on. The old host may keep its copies; readers follow the
hosts record.

### Records

```
{ "v": 1, "profile": <address>, "path": <path>, "time": <ms since 1970>,
  "body": <object> | null, "sig": <base64url> }
```

- `v` is 1. No other field is allowed.
- `time` is whole milliseconds, 0 to 2^53 − 1. A `null` body deletes the path.
- `sig` is EdDSA-Poseidon on Baby Jubjub ([keys](../keys/README.md#signatures)) by `profile`, the
  main key, over the signing input `0xff` ‖ UTF-8(`forest/v1/record\n`) ‖ UTF-8(canonical
  text of the record without `sig`): the 64 bytes, R8 packed then S, in base64url without padding.
  The signed number is SHA-256 of the signing input, shifted right one byte. The check is
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
record, a message or a pull (a signed request to fetch an inbox's messages), MUST be a point of the
prime-order subgroup other than the identity; anything else is refused.

**One key, four kinds of signature.** A profile's main key signs its records, messages, pulls and
blob requests: no other key signs for it. Someone acting for the person asks one of the person's
signers, the devices that hold the seed, which signs with the main key
([keys](../keys/README.md#signers)). The signed bytes of each begin with `0xff`, then each with its
own text (`forest/v1/record\n`, `forest/v1/message\n`, `forest/v1/pull\n`, `forest/v1/blob\n`), so
no signature is ever two of them, nor an index's (`forest/v1/reputation\n`,
[proofs/reputation](../proofs/reputation/README.md)). Payments are the pay keys', on their
chains.

**Which record counts.** A reader's view of a profile is a pure function of the records it holds
and its clock `now`:

1. Records dated after `now + 600,000` are held back.
2. Record A is newer than B if `A.time > B.time`, or the times are equal and `A.id > B.id`.
3. At each path, the newest record is current.
4. A current record with a `null` body means the path is deleted.

Beyond step 1, readers check no clock. An app sets `time = max(now, newest known at that path + 1)`
(`nextTime`), so a slow clock never makes an edit lose to what it replaces.

### Private records

A private record's body is `{ "private": <base64url of an age file> }` and nothing else. The age
file is the envelope: the canonical text of an object under a random key made for that record,
and that key encrypted once to each reader.

- The owner encrypts it to its own inbox key, to open its copy; the profile record's `inboxKey` is
  its public half.
- It may be encrypted to other people's inbox keys besides the owner's, each the `inboxKey` of a
  profile of theirs: that is how a person lets someone read. A signer does it by the person's
  permissions (The vault, Permissions).
- Each key an envelope is encrypted to is an age post-quantum hybrid key (`age1pq1…`, stanza
  `mlkem768x25519`); an app MUST NOT encrypt an envelope to any other kind, since one classic key
  among them would let a quantum computer open it for all. Each adds about 2 KB.
- A host checks a private record like any other and cannot open it. Anyone can see that it
  exists, its path, time and size, and how many keys it is encrypted to, never which: each key's
  stanza holds only its encapsulation, and no piece of a reader's key is in the file.
- Removing someone stops new versions only: the owner writes the next version for the rest, and
  they keep what they already opened (Limits).

### Inbox

A message is an encrypted envelope anyone delivers to a profile's hosts, and only its main key
pulls. It is not a record: it has no path and no versions, and it is in no one's folder.

**Declaring it.** The profile record's optional `inbox` field:

```
"inbox": { "senders": "anyone" | { "verifier": <verifier address> }, "once"?: true,
           "maxBytes"?: <integer> }
```

- No `inbox` field means no inbox: hosts refuse deliveries. A profile with an inbox gives
  `inboxKey`, since senders encrypt to it.
- `senders` is `"anyone"`, or `{ "verifier" }`: the sender's profile record carries a stamp proof
  from that verifier (Proofs) that holds for the sender's key, under any label. The verifier is
  named by its key's address, as the proof shows it. Today the only requirement is a stamp from a
  named verifier; a second kind would be a second proof the host checks, under a new `senders` kind.
- `once`: one message from each sender, ever.
- `maxBytes`: the largest message it takes, as canonical text in bytes.
- A host refuses deliveries to an inbox it cannot read: a field, a rule or a value it does not
  know. So a new rule can be added without an old host taking what it should refuse. A
  sender's app does not deliver to one either: a field it does not know could name more keys to
  encrypt to.

**Messages.**

```
{ "v": 1, "to": <address>, "from": <address>, "time": <ms since 1970>,
  "body": { "private": <base64url of an age file> }, "host"?: <origin>, "sig": <base64url> }
```

- `v` is 1. No other field is allowed, in the message or in its body.
- `to` is the profile it is to. `from` is the sender's key: a main key, or any other key on Baby
  Jubjub.
- `body` is one envelope encrypted to `to`'s inbox key. The object encrypted in it is any JSON
  object the two apps agree on; the request kinds our MCP server sends and reads are its own, in
  [foundationforest/services](https://github.com/foundationforest/services/tree/main/mcp).
- `host` is one of `from`'s hosts, an origin as its hosts record writes it: where a receiving host
  reads `from`'s records. It MUST be there for an inbox with a verifier's rule; otherwise it MAY be.
- `sig` is EdDSA-Poseidon by `from`, strict as a record's, over `0xff` ‖
  UTF-8(`forest/v1/message\n`) ‖ UTF-8(canonical text of the message without `sig`).
- The id is lowercase hex of SHA-256(signing input), as a record's.

**Deliver.** The sender reads the profile record of the profile it writes to, for its `inbox` and
`inboxKey`, and its hosts record. It encrypts the body, signs, and posts the message to each host
the hosts record names (`POST /v1/inbox`). Anyone may deliver, with no login; each host checks the
message on its own (Hosts).

**Pull.** A profile asks each of its hosts for what arrived after a cursor, the number a host
gives the last message on a page, so the next ask starts after it (`POST /v1/inbox/pull`):

```
{ "v": 1, "profile": <address>, "after": <cursor>, "time": <ms since 1970>, "sig": <base64url> }
```

- `sig` is EdDSA-Poseidon by the profile's main key, over `0xff` ‖ UTF-8(`forest/v1/pull\n`) ‖
  UTF-8(canonical text without `sig`).
- `after` is the `forest-cursor` of the last page; 0 for everything.
- `time` is within 600,000 ms of the host's clock, either way.
- It is signed because each body is encrypted but `from`, `to` and the time are not: unsigned,
  anyone could list who wrote to whom. It is a POST and not a GET because hosting platforms log
  URLs, and a signed URL would be a log of pulls.

### The vault

The vault is one folder on a host, encrypted to the vault's own inbox key, holding what the seed
cannot recompute: which profiles exist and where each lives, their verifiers' stamps (the stamp each
verifier signed to the seed), the person's permissions, and settings. Its main key is the vault key,
mixed from the seed ([keys](../keys/README.md#the-vault-key)), so a new device finds it with the
seed and one host's address; like any folder, its hosts record may name more than one host.

```
{ "profiles": [{ "label": <label>, "hosts": [<origin>, …] }, …],
  "stamps": [{ "verifier": <verifier name>, "stamp": <signed stamp> }, …],
  "permissions": [<permission>, …],
  "settings": { … } }
```

- The folder holds its hosts record and one private record at `vault`, its body the object above,
  encrypted to the vault's own inbox key alone. It has no profile record and no inbox.
- Every field may be missing. An app keeps every field it does not know, at the top and inside
  `settings`, so two apps share one vault.
- `profiles`: each label once, with the hosts its folder lived on when written; the signed hosts
  record there is the truth.
- `stamps`: the verifier's name, exactly as keys/'s recipe takes it, and the stamp it signed, as
  proofs/stamp/'s JSON ([stamp](../proofs/stamp/README.md#the-stamp-and-the-stamp-proof)).
- `permissions`: who may ask the person's signers to act, and for what (Permissions, below).
- `settings`: apps' settings, such as the hosts, verifiers and indexes the person chose. Each field
  is an app's own.
- To change it, an app reads the current vault, changes it, and writes it, at a time past the
  current one's, to every host the vault's hosts record names.

**Restoring.** A new device mixes the vault key from the seed, and its inbox key from the vault's
secret. It needs one host's address: it asks a host it knows, or one the person names, for the vault
key's folder; the folder's hosts record names the rest. It finds no vault only when every host it
asked answered: if one failed, the read fails too, since the vault may be there. It opens `vault`,
then mixes each profile's main key from its label and reads that folder from its hosts. Verifier
secrets come from the seed and each stamp's verifier name.

#### Permissions

The person's permissions say who may ask their signers, the devices that hold the seed, to act for
them, and for what ([keys](../keys/README.md#signers)). Only the signers read them, and only they
act on them: no host or reader checks them, since everything a host takes is signed by a
profile's main key.

```
"permissions": [{ "who": { "connector": <origin>, "connection": <id>, "name"?: <text> }
                       | { "profile": <address> },
                  "profiles": "all" | [<label>, …], "can": [<action>, …],
                  "limits"?: [{ "amount": <decimal text>, "currency": "USD",
                                "per": "day" | "week" | "month", "profile"?: <label> }, …],
                  "until"?: <ms since 1970> }, …]
```

- `who` is a connection or a profile, each listed once:
  - a connection is how an AI app reaches a signer: named by the address of the connector it comes
    through, an origin as a hosts record writes it, and `connection`, the id the signer gave it,
    so connections through two connectors never collide. `name` is what the person calls it.
  - a profile is a person or a business, by the address of a profile of their own: it asks by
    messages to the person's inbox, signed by that profile's main key (Inbox).
- `profiles`: the person's profiles the entry covers, by label, or `"all"`.
- `can`: what the who may ask for. The standard's actions are `post` (write any record, whatever its
  kind), `message` (send messages), `read` (open private records and messages) and `pay`, and
  nothing more; markets decide the kinds of record
  ([foundationforest/markets](https://github.com/foundationforest/markets)).
- `post` never covers a profile's profile record, its hosts record or the vault: a signer always
  asks the person for those. The vault holds the permissions, so an AI allowed to post there could
  raise its own limits; the profile record holds the pay addresses, which no reader can check
  against the seed; and the hosts record says where the folder lives. An AI could change any of them
  after reading an offer written to trick it.
- `limits`: how much the who may pay, each limit in one currency in any one period: a day is any
  24 hours, a week any 7 days, a month any 30 days. `amount` is decimal text, a whole number and up
  to six places (`"25"`, `"0.5"`). A limit with `profile` holds on that profile, which the entry
  must cover; without it, across all the profiles the entry covers, so "$25 a day on this profile,
  $100 a day across all" is two limits. An entry with no limit sets no money cap; which limits an
  app suggests is the app's.
- `until`: when the entry ends, if it does.
- `read` and sharing: for a profile, the signer encrypts the private records the entry covers to
  that profile's inbox key, from their next version on (Private records), and removing the entry
  stops new versions only. For a connection, the signer opens records when it asks.
- An app keeps every field and value it does not know, and a signer acts on no entry it does not
  know whole, a field at any level, an action, a currency or a period among them: it asks the
  person, since what it skipped could be a limit (`knowsPermission`).
- Limits belong to the who: each counts what that who asks for, on the profiles its entry covers.
  Counting what was spent is the app's.
- A signer never acts on a request no entry covers without the person's yes; how it asks, a prompt
  or a message waiting in the inbox, is the app's.

### Proofs

The profile record's optional `proofs` field carries up to four proofs, each named by its
`circuit` and checked by that circuit's proof check ([schemas/profile.json](schemas/profile.json)).
A proof counts for one main key: a reader checks it against the address of the profile that
carries it, so a proof copied to another profile fails. A reader ignores a proof whose circuit it
does not know, so a newer kind never makes a profile invalid for an older app. `stamp` and
`reputation`, below, are ours: the field takes any circuit's name, and anyone can add one. An app
puts a proof in the profile record only when the person chooses to show it there:
[proofs/reputation/](../proofs/reputation/README.md#limits) says what one can reveal. Records
checks no proof itself: `stampCheck` and `reputationCheck` turn a proof on a profile record into
what its proof check takes, for the profile that carries it.

- **`stamp`** shows that a verifier signed a stamp to the seed that gives this profile's key for its
  label ([proofs/stamp/](../proofs/stamp/README.md)). It carries the verifier's key, as its address,
  and its name, the label, the profile's tag at that verifier, and the proof's 256 bytes, in the
  reputation proof's order. A reader checks it with proofs/stamp/client's `checkStamp`, which works
  the name hash and the scope out of the name and the label itself. Each reader decides which
  verifiers it trusts.
- **`reputation`** shows the score of profiles the person holds in an index's tree, without
  saying which. It carries the index's key, the root and time the index signed and its signature,
  the score, the label when the proof shows one market, and the proof's 256 bytes. A reader checks
  it with proofs/reputation/client's `checkReputation`: the proof derives this profile's key from
  the same seed as the profiles it counts, so nobody can lend their score to someone else. Each
  reader decides which indexes it trusts and how old a time it accepts. How it is made is
  [proofs/reputation/](../proofs/reputation/README.md)'s.

### Blobs

A blob is bytes a folder holds, such as a photo or a video. It is the folder's, not a record's: no
record needs to name it, and none keeps it on a host. Where a record points at a blob, and under
what field, is the market's.

```
{ "v": 1, "action": "put", "profile": <address>, "sha256": <hex>, "mimeType": <type>,
  "size": <bytes>, "time": <ms since 1970>, "sig": <base64url> }
```

- **Its name** is what a stranger needs to fetch it and check it: `sha256`, the SHA-256 of the
  bytes in lowercase hex; `mimeType`, their media type, `type/subtype` in lower case, at most 255
  characters; and `size`, how many bytes.
- **Put.** The folder's main key signs a put, above, and sends it with the bytes to each of the
  folder's hosts (`PUT /v1/blobs/<sha256>`).
- **Delete.** `{ "v": 1, "action": "delete", "profile", "sha256", "time", "sig" }`, to each host
  (`DELETE /v1/blobs/<sha256>`).
- `sig` is EdDSA-Poseidon by `profile`, the main key, strict as a record's, over `0xff` ‖
  UTF-8(`forest/v1/blob\n`) ‖ UTF-8(canonical text without `sig`). The request travels in the header
  `forest-blob`, as its canonical text, and its `time` is within 600,000 ms of the host's clock,
  either way, as a pull's.
- **Kept** until the folder's main key deletes it, or by the host's own retention rule, which each
  host chooses and says where it describes itself, as Forest's host does in
  [How we run it](https://github.com/foundationforest/services/tree/main/host#how-we-run-it). The
  reference host keeps blobs until they are deleted. Bytes two folders hold stay until the last of
  them deletes them.
- **Fetch.** Anyone fetches a blob from the folder's hosts (`GET /v1/blobs/<sha256>`), with no
  request to sign, and checks its SHA-256 itself: a host that serves other bytes is skipped.

### Hosts

A host is an address that answers eight requests, the host socket, however many machines stand
behind it. It has no keys, no sign-up and no login: a record's signature is all it asks for, and
a pull's and a blob request's are the main key's of the profile they are for. It is open: it takes
signed records for any profile and serves them to anyone; it takes messages for any profile whose
profile record on it declares an inbox, and serves them only to that profile's main key; it takes
the bytes a folder's main key puts, and serves them to anyone. It reads no body but the hosts and
profile records'. A host never talks to an index; to take a message to an inbox with a verifier's
rule, it reads the sender's records from the sender's host.

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
  600,000 ms from the host's clock, [`signature`] when the profile's main key did not sign it, or a
  shape code.
- A request with more lines than the host takes gets one [`batch`] result, and one with more bytes
  gets 413.

**Taking a record in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Records and the hosts record
   [`canonical`, `shape`, `path`, `key`, `version`, `time`, `body`, `hosts`, `signature`], and
   `time ≤ now + 600,000` [`future`].
2. It MUST become the current record at its path by Which record counts, over what the host
   stores plus it [`older`].
3. A host MAY refuse a content record by its own choice [`refused`]. It MUST NOT refuse a hosts
   record by its own choice but for its size, so a person can always move.

**Taking a message in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Messages [`canonical`, `shape`,
   `version`, `key`, `time`, `body`], and `time ≤ now + 600,000` [`future`].
2. No message with the same id is here already [`duplicate`].
3. The current profile record of `to` on this host declares an inbox [`no_inbox`].
4. The signature, by `from` [`signature`].
5. The rule, on `from`. An inbox the host cannot read is [`rule_unsupported`]. `"anyone"` passes.
   `{ verifier }`: a host that reads no sender's records, or checks no stamp proof, accepts only
   `"anyone"` [`rule_unsupported`]. The message MUST name `host` [`sender`]. The host reads
   `from`'s records from it, as a reader does (`GET /v1/records`), or uses what it read before,
   kept for a time it chooses; a read that fails is [`lookup`]: the sender may try again. `host`
   MUST be one `from`'s current hosts record names, and `from`'s current profile record there MUST
   carry a stamp proof from that verifier that holds for `from`, under any label:
   proofs/stamp/client's `checkStamp`, given the proof as `stampCheck` makes it [`sender`]. A check
   that fails to run is [`lookup`]: the sender may try again.
6. `once`: a second message from this `from` to this `to` is refused, ever [`once`]. The host
   keeps each pair it takes while the inbox says `once`, for as long as it keeps the profile.
7. `maxBytes`: the canonical text is at most that many bytes [`too_big`].
8. A host MAY refuse a message by its own choice [`refused`].

A message whose `from` is its `to` skips steps 5 to 7: an inbox's rules are for others.

**Taking a blob in**, in this order, error code in brackets:

1. The signed put (Blobs): no larger than the host takes, then its canonical text and shape
   [`size`, `canonical`, `shape`, `version`, `key`, `time`], a put for the name in the path
   [`shape`], its time within 600,000 ms of the host's clock [`stale`], and its signature, by the
   profile's main key [`signature`].
2. The bytes are the type (`content-type`) and the size the put names [`shape`], and their SHA-256
   is the name in the path [`hash`].
3. Bytes the folder holds already are `already here`.
4. The host's own choice allows them, by their size, their type, or what the folder holds there
   already [`refused`]. A declared size larger than the host takes is answered 413, unread.

**Deleting a blob**, in this order:

1. The signed delete, as step 1 of taking a blob in.
2. Bytes the folder does not hold are `not here`.
3. Once no folder holds the bytes, the host deletes them.

A busy host SHOULD check signatures in native code, with these same strict rules: another library
may skip one (zk-kit's `verifySignature` does not check that the key is in the prime-order
subgroup).

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

An index reads the hosts it lists in full, page by page (`GET /v1/records`), checks the stamp
proofs on each profile, and interprets records by the market files it reads
([foundationforest/markets](https://github.com/foundationforest/markets)). Each index chooses which
hosts it reads. It MAY answer one request, `POST /v1/hosts`: the body is a profile's hosts record
as canonical text, and the answer is the HTTP status and nothing else. The index checks the
signature, then reads the hosts the record names, if it chooses to; sending the record again asks
it to look now. An app sends the hosts record to the indexes the person chose.

### Run it

`@foundationforest/records` has four import paths, each built to `dist/` with types, and the shapes:

- `@foundationforest/records`: keys as addresses (`publicKeyFromAddress`, `keyFromScalar`);
  canonical text; signing, checking and encoding records; the view (`viewProfile`, `liveContent`);
  writing (`ownerRecord`, `hostsRecord`, `nextTime`); messages and pulls (`signMessage`,
  `decodeMessage`, `messageId`, `pullRequest`, `checkPull`, `inboxOf`, `inboxKeyOf`); blob requests
  (`blobNameOf`, `blobRequest`, `checkBlobRequest`); a profile record's proofs as their proof checks
  take them (`proofsOf`, `stampCheck`, `reputationCheck`); talking to hosts (`publish`, `readPage`,
  `readAll`, `readProfile`, `deliver`, `pull`, `putBlob`, `getBlob`, `deleteBlob`). A host that
  fails does not stop `readProfile`: it reads the others and lists that host, with the error, in
  `failed`. A read ends with an error on a cursor that is not a whole number or does not move
  forward, and its `timeout` bounds the whole read. A publish reads a host's status first, and sends
  a batch the host answers 413 again in halves. A read asks by POST with `post: true`. A read, a
  publish, a delivery and a pull go through the caller's own `fetch` if given, and refuse a host
  that redirects with `redirect: 'error'`. No server, database or encryption library is in it. The
  keys themselves, `mainKey` among them, are keys/'s.
- `@foundationforest/records/private`: `makePrivate`, `openPrivate`, `readerCount`; `message`
  (encrypt to a profile record's inbox key, and sign) and `openMessage`; the vault (`vaultRecord`,
  `openVault`, `readVault`, `checkVault`, `VAULT_PATH`) and its permissions' words (`ACTIONS`,
  `CURRENCIES`, `PERIODS`, `knowsPermission`). The inbox key itself is keys/'s `inboxKey`, and the
  vault's keys/'s `vaultKey`.
- `@foundationforest/records/host`: `Host`, the reference host (below).
- `@foundationforest/records/public`: `publicFetch`, a fetch that reaches only public addresses and
  follows no redirect, for a host or an app that goes to a host a stranger named: it refuses
  loopback, private, link-local, carrier-grade NAT, NAT64, 6to4, multicast and every other range not
  globally reachable, written in the URL or behind a name. `isPublic` checks one address. Node only,
  like the host.
- `@foundationforest/records/schemas/profile.json`: the profile record's shape, as a JSON Schema.

Publish a profile with one offer, read it back, and put a photo in the folder:

```ts
import { mainKey } from '@foundationforest/keys' // keys/
import { blobNameOf, blobRequest, hostsRecord, ownerRecord, publish, putBlob, readProfile }
  from '@foundationforest/records'

const me = await mainKey(seed, 'tutoring/seller') // seed: its 32 bytes
const now = Date.now()
const maths = { ...fields } // an offer's fields are its market's (foundationforest/markets)
await publish([host], [hostsRecord(me, [host], now), ownerRecord(me, 'offer/maths', maths, now)])
// Your own profile: by POST, so its address is in the body, not the URL.
const view = await readProfile([host], me.address, Date.now(), { post: true })
view.current.get('offer/maths')?.record.body
const photo = blobNameOf(jpeg, 'image/jpeg') // jpeg: the photo's bytes
await putBlob(view.hosts, blobRequest(me, { action: 'put', ...photo }, Date.now()), jpeg)
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

Run a host that takes messages to inboxes with a verifier's rule, and write to one, naming one of
the sender's hosts:

```ts
import { readAll } from '@foundationforest/records'
import { Host } from '@foundationforest/records/host'
import { checkStamp } from '@foundationforest/stamp' // proofs/stamp/client

// A host takes a message to an inbox with a verifier's rule only if it reads the sender's records
// and checks stamp proofs.
const buyersHost = new Host({
  readSender: async (url, profile) => (await readAll(url, { profile })).records,
  checkStamp,
})

const buyerView = await readProfile([host], buyer.address, Date.now())
const buyerProfile = buyerView.current.get('profile')!.record.body!
const answer = await message({ from: me, host }, buyer.address, { text: 'Tuesday at six, yes.' },
  Date.now(), buyerProfile)
await deliver(buyerView.hosts, [answer])
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
deletes them. Give it `readSender` and `checkStamp` to take messages for inboxes with a verifier's
rule: it reads the sender's records again for each request.

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

`test/vectors.json`: a hosts, profile, offer and delete record, each with its wire text, signing
input and id, for keys/'s `tutoring/seller` profile from its test seed `00 01 … 1f`; the profile
record's `inboxKey` is that profile's inbox key. The seed, the main key and the inbox key are pinned
in `keys/test/vectors.json`, and checked there. It also holds a message from keys/'s
`tutoring/buyer` profile to `tutoring/seller`, with its wire text, signing input and id; a pull
request by `tutoring/seller`; and two blob requests, each with its wire text and signing input:
`blobPut`, the main key putting the 26 letters `a` to `z` as `text/plain`, and `blobDelete`, the
main key deleting them. The message's body is encrypted to the inbox key of the profile it is to;
age's encryption is random, so the encrypted body is pinned as it was made. `test/vectors.test.ts`
recomputes the records, the message, the pull and the blob requests, checks each with a second
SHA-256 (node:crypto) and a second EdDSA-Poseidon (zk-kit's, from the address and the 64 bytes on
its own), and opens the message with the pinned inbox key it was encrypted to. The profile is
`9bpPbLYCPwNWq9BZqnJr3EqRNqymFZ4g58Zk9K86azDC`; every signing input begins `ff 66 6f 72 65 73 74 2f`
(`0xff`, then `forest/`).

The example profile record, [schemas/examples/profile.json](schemas/examples/profile.json), is that
profile's, with a stamp proof from an example verifier and a reputation proof from an example
index's tree, made with the circuits' setups by `scripts/example-profile.ts`; `test/schemas.test.ts`
checks both with their proof checks.

## Promises

- **A record checks the same wherever it comes from.** One canonical spelling and strict
  EdDSA-Poseidon on Baby Jubjub. A host cannot forge or change a record; it can only withhold it.
- **Every reader computes the same view from the same records.** Where they came from and in what
  order does not matter. The reader's clock matters only to hold back records dated more than ten
  minutes ahead.
- **Only a profile's main key writes for it.** A host takes, and a reader counts, a record, a
  message, a pull or a blob request for a profile only when its main key signed it.
- **A person can always move.** A profile's name is its key, not a host's address. A host never
  refuses a newer hosts record by its own choice but for its size.
- **A host holds nothing secret of the people it serves.** No keys, no sign-up, no login, and it
  cannot open a private record.
- **Only a profile's main key can pull its inbox.**

## Limits

- **The reference host is a reference.** One process on one machine, a SQLite file per folder. It
  checks each record against everything it stores for that profile, which is slow for a busy one.
- **Checking signatures is slow here.** Pure JavaScript checks about 300 a second on one core of the
  machine these tests ran on, and the reference host takes about 190 records a second (`npm run
  bench`). A busy host or index should check signatures in native code with the same strict rules
  (Hosts).
- **A host keeps only the newest record at each path,** and what it replaced for its keep days.
  Older history is in the app's copies, or nowhere.
- **A host sees who wrote to whom.** It holds each message's `from`, `to`, time and size, though not
  what it says. To take a message to an inbox with a verifier's rule, it asks the sender's host for
  the sender's records, which tells that host where the sender wrote. Filtering by an inbox's rule
  needs the sender, so there is no anonymous mode.
- **A blob is only as true as its hash.** A host checks the hash and the size, never that the
  bytes are the type their put names; a record that points at them says what it means them to be.
- **A delete is a request.** What was public may already have been copied: whoever fetched the
  bytes has them.
- **No forward secrecy.** An inbox key that leaks opens every message and private record encrypted
  to it, from any host or copy that still holds them.
- **Sharing reaches forward only.** Removing someone stops the versions written after; what they
  already opened, and an older version a host or a copy still holds, they can still open.
- **An envelope holds about 30 keys on the reference host.** Each key adds about 2 KB, and the
  reference host takes records and messages of up to 64 KB; another host chooses its own.
- **Two profiles of one person can be linked by how they are written.** Written in the same moment,
  they sit side by side in a host's listing, and a host that logs network addresses links them;
  whether it logs is its own choice.
- **Two devices writing the vault at once lose one change.** The newer record counts. An app that
  reads before it writes, and writes again when the vault changed under it, loses nothing.
- **The vault is one record.** A host's largest record bounds it: 64 KB on the reference host.

## Who decides what

- **The standard:** the record and the message, and what makes each valid (the ten-minute window);
  the eight requests and their codes; the hosts record; envelopes; the profile record's fields; a
  blob's name, its put and its delete; the inbox and its rules; the vault; the proofs field.
- **A market chooses:** its roles, its content paths and their bodies, and where a record points
  at a blob ([foundationforest/markets](https://github.com/foundationforest/markets)).
- **A host chooses:** its keep days, and any retention rule for blobs; the largest record, message
  and blob it takes; batch and page sizes; which blob types it takes; which inbox rules it supports;
  whether it reads senders' records for an inbox with a verifier's rule, and how long it keeps what
  it read; rate limits; logging; storage.
- **An app, with the person:** the copies it keeps; which hosts, the vault's among them; the
  person's permissions, counting what each who spent against its limits, and how a signer asks the
  person about a request no entry covers; whether to forward a message to email or a notification;
  dropping a message that arrives twice; what it finds too big to read; and what asks for the
  person's device unlock. The profile can change or delete anything it wrote, at will. What others
  wrote about it, and payments, stay.
- **An index chooses:** which hosts it reads, which verifiers and markets count, how much each
  review weighs, and which proofs it accepts.

## FAQ

**Why does only the main key sign, with no key to hand out?**
A key handed out lives somewhere less safe than the person's own devices: on a server, or with
another app. Each one had to be listed, scoped and removed, every host and reader had to check what
it was allowed, and one that leaked kept writing what it was allowed until the person noticed. With
one key per profile, a host or a reader checks one signature, and what an app, an AI or another
person may do is the person's to decide on their own devices: a signer, a device that holds the
seed, acts for them by the permissions in their vault, or asks them
([keys](../keys/README.md#signers)). Nothing outside a signer holds a key, so a permission removed
ends at once, and nothing is left behind that can still sign.

**Why is a blob the folder's, and not the record's that points at it?**
A host that kept bytes only while a record named them had to read every record's body for the
fields that name them, and where a record points at a blob is each market's to say. So the folder's
main key puts and deletes its blobs, and a host reads no record's body to find them. How much a
folder may put is the host's choice.

**Why is a message not a record in the sender's folder?**
Anyone reads a folder. A message there would need a field naming who it is to so hosts could route
it, and that field would make every inquiry a public fact: who asked whom, and when. A message goes
to the hosts of the profile it is to instead, encrypted, and only that profile pulls it.

**How do I hear that a message arrived?**
By default the app checks your inboxes itself, pulling from your hosts. A push service would see
which inboxes one device watches, and so which profiles are one person's.

**Why is there no deposit rule?**
A rule that asks senders to pay would have every host check payments. An inbox's `senders` is a
field with kinds, and a host refuses deliveries under a kind it does not know, so a new kind can be
added without breaking anything.

**Why are the permissions in the vault, not a public record?**
A public list would tell anyone which apps and which people act for a person, and since when, and
one connection or one person listed under two profiles would link them. Nobody but the person's
signers needs to read it: they alone act on it, and every host and reader checks only the main key's
signature. In the vault it is encrypted to the vault's own inbox key, which only the seed gives, and
a new device gets it back with the rest.

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
which a proof cannot derive from a seed cheaply. Pubky's servers can forge records.
