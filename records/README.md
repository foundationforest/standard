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
MUST, SHOULD and MAY are as in RFC 2119. The directory also holds the host check, which any host
runs against its own address to show it fits the plug (Hosts), the profile record's shape as a JSON
Schema, and test vectors.

## How it works

### Folders

A profile is one main key, mixed from the person's seed (32 bytes every key comes from) and a label,
`<market>/<role>`, such as `tutoring/seller` ([keys/](../keys/README.md)). The main key is a key on
Baby Jubjub, the curve the proofs work on, and its address is its name on the network: the public
key packed into 32 bytes, in base58 (the Bitcoin alphabet). Its inbox key, mixed from the profile's
secret, opens what is encrypted to it, and its pay keys, one for each address type, give its Solana
and EVM addresses. Nothing else is needed: no sign-up, no directory.

Its folder is everything signed for it, one current record per path:

| Path | What it holds |
|---|---|
| `hosts` | where the folder lives |
| `profile` | the profile record: market, role, pay addresses, inbox, proofs |
| `permission/<id>` | one of the profile's permissions, a private record ([signers](../signers/README.md#permissions)) |

- Every record in it is signed by the profile's main key, and by no other key.
- `hosts` is the control path, the one record every host reads. Every other path is content.
  Beside `profile` and `permission/<id>`, content paths and their bodies are the market's, the one
  the profile's label names: [foundationforest/markets](https://github.com/foundationforest/markets)
  keeps `offer/<id>` and `review/<id>` as the two kinds a market defines. Readers MAY ignore a first
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
hosts record. A host may refuse the first hosts record of a folder it does not hold yet, so joining
can cost; a hosts record for a folder it holds it never refuses by its own choice but for its size
(Taking a record in).

**Pay addresses.** A profile record's `pay` lists any of the profile's pay addresses, by address
type, `solana` or `evm`. A profile record that carries `pay` MUST carry `paySig`, a signature for
each address it lists, each by that type's pay key over `0xff` ‖ UTF-8(`forest/v1/pay\n`) ‖ UTF-8(the
profile's address), in base64url without padding: `solana`, an Ed25519 signature, 64 bytes; `evm`,
a secp256k1 signature over keccak256 of the bytes, 65 bytes, r ‖ s ‖ the recovery id, checked by
recovering the key and comparing its EIP-55 address ([keys](../keys/README.md#pay-keys)). A reader
checks each and counts an address only when its signature holds (`checkPay`), so a profile cannot
list an address that is not its own; a host MAY check them.

**Finding profiles.** A profile's label is its name to the person, and an app keeps the labels it
made. With only the seed and a host's address, an app finds a person's profiles by trying the labels
in the markets directory
([foundationforest/markets](https://github.com/foundationforest/markets)): the seed and a label
give the main key, and the host answers whether that folder exists. A label outside the directory is
found only by whoever remembers it.

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
([signers](../signers/README.md)). The signed bytes of each begin with `0xff`, then each with its
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

A private record's body is `{ "private": <base64url of an age file> }` and nothing else, age being a
widely used encryption format. The age file is the envelope: the canonical text of an object under a
random key made for that record, and that key encrypted once to each reader.

- The owner encrypts it to its own inbox key, to open its copy; the profile record's `inboxKey` is
  its public half.
- It may be encrypted to other people's inbox keys besides the owner's, each the `inboxKey` of a
  profile of theirs: that is how a person lets someone read.
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
"inbox": { "maxBytes"?: <integer> }
```

- No `inbox` field means no inbox: hosts refuse deliveries. With one, anyone may deliver. A profile
  with an inbox gives `inboxKey`, since senders encrypt to it.
- `maxBytes`: the largest message it takes, as canonical text in bytes.
- A host refuses deliveries to an inbox it cannot read: a field or a value it does not know. So a
  new field, a rule for who may send among them, can be added without an old host taking what it
  should refuse. A sender's app does not deliver to one either: a field it does not know could name
  more keys to encrypt to.

**Messages.**

```
{ "v": 1, "to": <address>, "from": <address>, "time": <ms since 1970>,
  "body": { "private": <base64url of an age file> }, "host"?: <origin>, "sig": <base64url> }
```

- `v` is 1. No other field is allowed, in the message or in its body.
- `to` is the profile it is to. `from` is the sender's key: a main key, or any other key on Baby
  Jubjub.
- `body` is one envelope encrypted to `to`'s inbox key. What the object encrypted in it says is the
  two apps' to agree; the main way, for a plain message, is `{ "text": <text> }`.
- `host`, which a message MAY carry, is one of `from`'s hosts, an origin as its hosts record writes
  it: it tells the recipient's app where the sender's folder is.
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

### Proofs

The profile record's optional `proofs` field carries up to four proofs, each named by its
`circuit` and checked by that circuit's proof check ([schemas/profile.json](schemas/profile.json)).
A proof counts for one main key: a reader checks it against the address of the profile that
carries it, so a proof copied to another profile fails. A reader ignores a proof whose circuit it
does not know, so a newer kind never makes a profile invalid for an older app. `verification` and
`reputation`, below, are ours: the field takes any circuit's name, and anyone can add one. An app
puts a proof in the profile record only when the person chooses to show it there:
[proofs/reputation/](../proofs/reputation/README.md#limits) says what one can reveal. Records
checks no proof itself: `verificationCheck` and `reputationCheck` turn a proof on a profile record
into what its proof check takes, for the profile that carries it.

- **`verification`** shows that a verifier signed a stamp to the seed that gives this profile's key
  for its label ([proofs/verification/](../proofs/verification/README.md)). It carries the
  verifier's key, as its address, and its name, the label, and the proof's 256 bytes, in the
  reputation proof's order. A reader checks it with proofs/verification/client's
  `checkVerification`, which works the name hash and the scope, the numbers the proof takes for the
  name and the label, out of them itself. Each reader decides which verifiers it trusts.
- **`reputation`** shows the average score of profiles the person holds in an index's tree,
  without saying which. It carries the index's key, the root and time the index signed and its
  signature, the score, and the proof's 256 bytes. A reader checks
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
  host chooses and says where it describes itself. Bytes two folders hold stay until the last of
  them deletes them.
- **Fetch.** Anyone fetches a blob from the folder's hosts (`GET /v1/blobs/<sha256>`), with no
  request to sign, and checks its SHA-256 itself: a host that serves other bytes is skipped.

### Hosts

A host is an address that answers eight requests, the plug, however many machines stand behind
it. It has no keys, no sign-up and no login: a record's signature is all it asks for, and
a pull's and a blob request's are the main key's of the profile they are for. It is open: it takes
signed records for any profile and serves them to anyone; it takes messages for any profile whose
profile record on it declares an inbox, and serves them only to that profile's main key; it takes
the bytes a folder's main key puts, and serves them to anyone. It reads no body but the hosts and
profile records', and needs nothing from an index or from another host.

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

- A page's header `forest-cursor` is the last sequence number on it, or, on an empty page, the
  cursor asked with: the next page is after it. A page holds at least one line while there is one
  to give, however large; an empty page is the end.
- `POST /v1/records/read` gives the same answer as `GET /v1/records`, with the profile and the
  cursor in the body instead of the URL. Front doors, the proxies and hosting platforms that stand
  in front of a host, log URLs, so a person who reads their own profiles by GET leaves a trail. The
  GET stays for public readers.
- A refused pull is answered 400 with `{ok, error, message}`: [`stale`] when its time is more than
  600,000 ms from the host's clock, [`signature`] when the profile's main key did not sign it, or a
  shape code; one larger than the host takes, 413 [`size`].
- A request with more lines than the host takes gets one [`batch`] result, and one with more bytes
  gets 413.

**Taking a record in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Records and the hosts record
   [`canonical`, `shape`, `path`, `key`, `version`, `time`, `body`, `hosts`, `signature`], and
   `time ≤ now + 600,000` [`future`].
2. It MUST become the current record at its path by Which record counts, over what the host
   stores plus it [`older`].
3. A host MAY refuse a content record by its own choice [`refused`], and the first hosts record of
   a folder it does not hold yet [`refused`], so joining can cost. It MUST NOT refuse a hosts record
   for a folder it already holds by its own choice but for its size, so a person can always leave
   or update.

**Taking a message in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Messages [`canonical`, `shape`,
   `version`, `key`, `time`, `body`], and `time ≤ now + 600,000` [`future`].
2. No message with the same id is here already [`duplicate`].
3. The current profile record of `to` on this host declares an inbox the host can read
   [`no_inbox`].
4. The signature, by `from` [`signature`].
5. `maxBytes`: the canonical text is at most that many bytes [`too_big`].
6. A host MAY refuse a message by its own choice [`refused`].

A message whose `from` is its `to` skips step 5: an inbox's limit is for others.

**Taking a blob in**, in this order, error code in brackets; before all of it, a declared size
larger than the host takes is answered 413, unread:

1. The signed put (Blobs): no larger than the host takes, then its canonical text and shape
   [`size`, `canonical`, `shape`, `version`, `key`, `time`], its time within 600,000 ms of the
   host's clock [`stale`], its signature, by the profile's main key [`signature`], and a put for the
   name in the path [`shape`].
2. The bytes are the type (`content-type`) and the size the put names [`shape`], and their SHA-256
   is the name in the path [`hash`].
3. Bytes the folder holds already are `already here`.
4. The host's own choice allows them, by their size, their type, or what the folder holds there
   already [`refused`].

**Deleting a blob**, in this order:

1. The signed delete, as step 1 of taking a blob in.
2. Bytes the folder does not hold are `not here`.
3. Once no folder holds the bytes, the host deletes them.

A busy host SHOULD check signatures in native code, with these same strict rules: another library
may skip one (zk-kit's `verifySignature` does not check that the key is in the prime-order
subgroup).

**The host check.** Any host runs `checkHost` (`@foundationforest/records/check`) against its own
address to show it fits the plug: `npm run check-host -- <address>`. It writes from two profiles of
one seed, under the labels `check/a` and `check/b`, sends each request above, and checks each
answer: records taken, and served by GET and by POST in the order taken; each refusal with its
code; the newest kept at each path; a newer hosts record always taken; reading after a cursor;
messages refused in the order above, and pulled only by the main key; blobs put, served, refused
and deleted. A refusal the plug lets a host make by its own choice, such as a folder's first hosts
record or a size it does not take, is no failure: what it stops is reported unchecked, and given a
seed whose folders the host holds already, the check runs it all. Records' own tests run it against
a minimal host in `test/host.ts`, which holds everything in memory and chooses nothing of its own.

### What a host chooses

Nothing here is the standard's: each host chooses, and says its numbers where it describes itself.

- **Sizes.** The largest record, message and blob it takes; how many records or messages a
  request may carry; how many lines and bytes a page holds. A client handles any size: it sends a
  refused request again in halves, and follows the cursor page by page. A reader MAY ignore a
  record, a message or a blob it finds too big.
- **Joining.** Whether it takes the first hosts record of a folder it does not hold yet, so joining
  can cost. A hosts record for a folder it holds it never refuses by its own choice but for its size
  (Taking a record in).
- **Keeping.** A record that stops being current is kept for a number of days the host chooses,
  by its own clock, then deleted. A message is kept for a number of days from when it arrived; a
  pull does not delete it. A blob stays until the folder deletes it, unless the host has a
  retention rule of its own, which it says. A host that drops a current record withholds it.

### Run it

`@foundationforest/records` has four import paths, each built to `dist/` with types, and the shapes:

- `@foundationforest/records`: keys as addresses (`publicKeyFromAddress`, `keyFromScalar`);
  canonical text; signing, checking and encoding records; the view (`viewProfile`, `liveContent`);
  writing (`ownerRecord`, `hostsRecord`, `nextTime`); messages and pulls (`signMessage`,
  `decodeMessage`, `messageId`, `pullRequest`, `checkPull`, `inboxOf`, `inboxKeyOf`); blob requests
  (`blobNameOf`, `blobRequest`, `checkBlobRequest`); a profile record's proofs as their proof checks
  take them (`proofsOf`, `verificationCheck`, `reputationCheck`), and its pay addresses whose
  signature holds (`checkPay`); talking to hosts (`publish`, `readPage`, `readAll`, `readProfile`,
  `deliver`, `pull`, `putBlob`, `getBlob`, `deleteBlob`). A host that fails does not stop `readProfile`: it
  reads the others and lists that host, with the error, in `failed`. A read ends with an error on a
  cursor that is not a whole number or does not move forward, and its `timeout` bounds the whole
  read. A publish reads each answer's HTTP status before its body, and sends a batch again in
  halves when the host answers 413 or one [`batch`] result. A read asks by POST with `post: true`.
  A read, a publish, a delivery and a pull go through the caller's own `fetch` if given, and, given
  `redirect: 'error'`, refuse a host that redirects. No server, database or encryption library is in
  it. The keys themselves, `mainKey` among them, are keys/'s.
- `@foundationforest/records/private`: `makePrivate`, `openPrivate`, `readerCount`; `message`
  (encrypt to a profile record's inbox key, and sign) and `openMessage`. The inbox key itself is
  keys/'s `inboxKey`.
- `@foundationforest/records/check`: `checkHost(url, { seed?, mimeType? })`, the host check, and
  `CHECK_LABELS`, the labels of the profiles it writes from (Hosts).
- `@foundationforest/records/public`: `publicFetch`, a fetch that reaches only public addresses and
  follows no redirect, for a service that goes to a host a stranger named: it refuses loopback,
  private, link-local, carrier-grade NAT, NAT64, 6to4, multicast and every other range IANA's
  special-purpose registries mark not globally reachable, written in the URL or behind a name.
  `isPublic` checks one address. Node only.
- `@foundationforest/records/schemas/profile.json`: the profile record's shape, as a JSON Schema.

Publish a profile with one offer, read it back, and put a photo in the folder:

```ts
import { mainKey } from '@foundationforest/keys' // keys/
import { type SignedBlobRequest, blobNameOf, blobRequest, hostsRecord, ownerRecord, publish,
  putBlob, readProfile } from '@foundationforest/records'

const me = await mainKey(seed, 'tutoring/seller') // seed: its 32 bytes
const now = Date.now()
const maths = { ...fields } // an offer's fields are its market's (foundationforest/markets)
await publish([host], [hostsRecord(me, [host], now), ownerRecord(me, 'offer/maths', maths, now)])
// Your own profile: by POST, so its address is in the body, not the URL.
const view = await readProfile([host], me.address, Date.now(), { post: true })
view.current.get('offer/maths')?.record.body
const photo = blobNameOf(jpeg, 'image/jpeg') // jpeg: the photo's bytes
// blobRequest gives a put or a delete; putBlob takes only a put.
const put = blobRequest(me, { action: 'put', ...photo }, Date.now())
await putBlob(view.hosts, put as SignedBlobRequest & { action: 'put' }, jpeg)
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

```
# The tests take their keys from keys/, and check the example profile record's proofs with the
# proofs' clients.
npm ci && npm run build   # at the root: every package; keys/, both clients and records to dist/
cd records
npm run check          # type-check
npm test               # everything, on loopback
npm run check-host -- https://host.example   # the host check, against a host
node test/vectors.ts   # print the test vectors
node scripts/example-profile.ts   # make the example profile record's proofs again
```

Node 22.18 or later. Built from existing pieces, unchanged: `@noble/curves`, `@noble/hashes`,
`@scure/base`, `poseidon-lite` and `canonicalize` for the core, with keys/'s Baby Jubjub;
`age-encryption` for private records and messages; `undici` for the public fetch.

### Test vectors

`test/vectors.json`: a hosts, profile, offer and delete record, each with its wire text, signing
input and id, for keys/'s `tutoring/seller` profile from its test seed `00 01 … 1f`; the profile
record's `inboxKey` is that profile's inbox key, its `pay` its pay addresses and its `paySig` their
signatures. The seed, the main key, the inbox key, the pay addresses and their signatures are pinned
in `keys/test/vectors.json`, and checked there. It also holds a message from
keys/'s `tutoring/buyer` profile to `tutoring/seller`, with its wire text, signing input and id; a
pull request by `tutoring/seller`; two blob requests, each with its wire text and signing input:
`blobPut`, the main key putting the 26 letters `a` to `z` as `text/plain`, and `blobDelete`, the
main key deleting them. The message's body is encrypted to the inbox key of the profile it is to;
age's encryption is random, so it is pinned as it was made. `test/vectors.test.ts` recomputes the
records, the message, the pull and the blob requests, checks each with a second SHA-256
(node:crypto) and a second EdDSA-Poseidon (zk-kit's, from the address and the 64 bytes on its own),
opens the message with the pinned inbox key it was encrypted to, and checks the profile record's pay
signatures. The profile
is `9bpPbLYCPwNWq9BZqnJr3EqRNqymFZ4g58Zk9K86azDC`; every signing input begins
`ff 66 6f 72 65 73 74 2f` (`0xff`, then `forest/`).

The example profile record, [schemas/examples/profile.json](schemas/examples/profile.json), is that
profile's, with its pay addresses each signed by its pay key, a verification from an example
verifier and a reputation proof from an example index's tree, made with the circuits' setups by
`scripts/example-profile.ts`; `test/schemas.test.ts` checks both proofs with their proof checks and
the pay signatures with `checkPay`.

## Promises

- **A record checks the same wherever it comes from.** One canonical spelling and strict
  EdDSA-Poseidon on Baby Jubjub. A host cannot forge or change a record; it can only withhold it.
- **Every reader computes the same view from the same records.** Where they came from and in what
  order does not matter. The reader's clock matters only to hold back records dated more than ten
  minutes ahead.
- **Only a profile's main key writes for it.** A host takes, and a reader counts, a record, a pull
  or a blob request for a profile only when its main key signed it, and a message only when its
  sender's key signed it.
- **A person can always move.** A profile's name is its key, not a host's address. A host never
  refuses a hosts record for a folder it holds by its own choice but for its size, though it may
  refuse a folder's first, so joining a host can cost.
- **A host holds nothing secret of the people it serves.** No keys, no sign-up, no login, and it
  cannot open a private record, though it sees who wrote to whom (Limits).
- **Only a profile's main key can pull its inbox.**

## Limits

- **Checking signatures in JavaScript is slow.** A busy host or index checks them in native code,
  with the same strict rules (Hosts).
- **A host keeps only the newest record at each path,** and what it replaced for its keep days.
  Older history is in the app's copies, or nowhere.
- **A host sees who wrote to whom.** It holds each message's `from`, `to`, time and size, though not
  what it says.
- **A blob is only as true as its hash.** A host checks the hash and the size, never that the
  bytes are the type their put names; a record that points at them says what it means them to be.
- **A delete is a request.** What was public may already have been copied: whoever fetched the
  bytes has them.
- **No forward secrecy.** An inbox key that leaks opens every message and private record encrypted
  to it, from any host or copy that still holds them.
- **Sharing reaches forward only.** Removing someone stops the versions written after; what they
  already opened, and an older version a host or a copy still holds, they can still open.
- **A host's size bounds an envelope.** Each key it is encrypted to adds about 2 KB, and each host
  chooses the largest record and message it takes.

## Who decides what

- **The standard:** the record and the message, and what makes each valid (the ten-minute window);
  the eight requests and their codes; the hosts record; envelopes; the profile record's fields and
  the pay signature; a blob's name, its put and its delete; the inbox; the proofs field.
- **A market chooses:** its roles, its content paths and their bodies, and where a record points
  at a blob ([foundationforest/markets](https://github.com/foundationforest/markets)).
- **A host chooses:** whether it takes a folder it does not hold yet, and at what price; its keep
  days, and any retention rule for blobs; the largest record, message and blob it takes; batch and
  page sizes; which blob types it takes; spam limits and rate limits; logging; storage.
- **An app, with the person:** the copies it keeps; which hosts; filtering messages, by the sender's
  verifications or anything else; whether to forward a message to email or a notification; dropping
  a message that arrives twice; what it finds too big to read; and what asks for the person's
  device unlock. The profile can
  change or delete anything it wrote, at will. What others wrote about it, and payments, stay.
- **An index chooses:** which hosts it reads and how it learns of new ones, which verifiers and
  markets count, how much each review weighs, and which proofs it accepts.

## FAQ

**Why does only the main key sign, with no key to hand out?**
A key handed out lives somewhere less safe than the person's own devices: on a server, or with
another app. Each one had to be listed, scoped and removed, every host and reader had to check what
it was allowed, and one that leaked kept writing what it was allowed until the person noticed. With
one key per profile, a host or a reader checks one signature, and what an app, an AI or another
person may do is the person's to decide on their own devices: a signer, a device that holds the
seed, acts for them by the profile's permissions, or asks them ([signers](../signers/README.md)).
Nothing outside a signer holds a key, so a permission removed ends with the next ask, and nothing is
left behind that can still sign.

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
Your app pulls each inbox from its hosts (`pull`); nothing in the standard pushes.

**Why does an inbox not say who may write to it?**
A rule for senders had each host that holds the inbox read the sender's records from the sender's
host, which told that host where the sender wrote, and check the sender's proofs; each new kind, a
verification or a deposit, was more for every host to run. So anyone may write to an inbox: limiting
spam is each host's choice, and filtering messages, by the sender's verifications or anything else,
is the recipient's app's, once it opens them. A host refuses an `inbox` field it does not know, so a
rule for senders can come back as a new field without an old host taking what it should refuse.

**Why is a proof's `proof` 256 bytes, and not snarkjs's JSON?**
A record's object keys cannot spell snarkjs's `pi_a`, `pi_b` and `pi_c`: they allow no `_`. The
256 bytes are the proof's three points, not compressed, in the order Ethereum's and Solana's BN254
precompiles read them, so a reader gets snarkjs's form back by reading eight 32-byte numbers.
Compressed, the points would take 128 bytes fewer, but every reader would have to take square
roots to rebuild them.

**Why not AT Protocol, Nostr or Pubky as the base?**
AT Protocol has one server per profile and a central directory. Nostr's keys are on secp256k1,
which a proof cannot derive from a seed cheaply. Pubky's servers can forge records.
