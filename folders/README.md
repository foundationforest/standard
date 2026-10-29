# folders

Part of Forest's standard: [the top README](../README.md). The profile entry's shape:
[schemas/](schemas/).

## What it is

How a Forest profile says things, and how anyone reads them. Each profile has one folder on one or
more hosts. It holds three things:

- **the profile entry**, which shows the profile;
- **its entries**, of any shape the writer chooses, public or locked, photos included;
- **its inbox**, the entries others leave it, always locked.

An entry is a small signed JSON value at a path. Hosts keep folders and serve them to anyone. Any
app, index (a service that reads entries and scores profiles) or AI reads them and checks every
signature itself, so a host can withhold an entry but never forge one.

Who enforces what:

- **Writing: hosts and readers.** An entry counts only when the profile's main key signed it, or
  an access key the folder's profile entry lists with `write`. A host takes, and a reader counts,
  nothing else.
- **Reading: envelopes.** A locked entry opens only for the keys it was locked to. Nobody else
  checks anything.
- **Messages: the recipient's app.** It checks each message's signature and its sender's profile
  entry, and decides what to show.

This README is the standard. The library in `src/` does every MUST in it, and `test/` checks it;
MUST, SHOULD and MAY are as in RFC 2119. The directory also holds the host check, which any host
runs against its own address to show it fits the plug (Hosts), the profile entry's shape as a JSON
Schema, and test vectors.

## How it works

### Folders

A profile is one main key, mixed from the person's seed (32 bytes every key comes from) and a label,
`<market>/<role>`, such as `tutoring/seller` ([keys/](../keys/README.md)). Every key is a pair: a
signing half, whose address names it, and an opening half, whose open key envelopes are locked to.
The main key's address is the profile's name on the network: a key on Baby Jubjub, the curve the
proofs work on, packed into 32 bytes, in base58 (the Bitcoin alphabet). Nothing else is needed: no
sign-up, no directory.

Its folder is every entry signed for it, one current entry per path:

| Path | What it holds |
|---|---|
| `profile` | the profile entry: hosts, market and role, open key, pay addresses, proofs, access keys |
| `key/<id>` | a note for the person about one access key, at a random id (Access keys) |
| any other | anything the writer chooses: a market's offers and reviews, an app's own entries, a photo |

- A path is 1 to 4 segments separated by `/`, each `[a-z0-9][a-z0-9._-]{0,63}`, at most 256
  bytes. `profile` is a single path: `profile/<anything>` is refused.
- Beside `profile`, paths and their bodies are the writer's. The main way is the market's, the one
  the profile's label names: [foundationforest/markets](https://github.com/foundationforest/markets)
  keeps `post/<id>` and `review/<id>` among the kinds a market defines. Readers MAY ignore a first
  segment they do not know.
- An entry sits in the folder of the profile that wrote it, so the profile a review is about
  cannot erase it; the one who wrote it can.

### Entries

```
{ "v": 1, "profile": <address>, "path": <path>, "time": <ms since 1970>,
  "body": <object> | null, "key"?: <address>, "sig": <base64url> }
```

- `v` is 1. No other field is allowed.
- `time` is whole milliseconds, 0 to 2^53 − 1. A `null` body deletes the path.
- `key` is the address of the access key that signed; it is absent when the main key signed, and
  never the main key's own address.
- `sig` is EdDSA-Poseidon on Baby Jubjub ([keys](../keys/README.md#signatures)) by `key` when
  there is one, else by `profile`, the main key, over the signing input, UTF-8 of the canonical text
  of the entry without `sig` and nothing else: the 64 bytes, R8 packed then S, in base64url without
  padding. The signed number is SHA-256 of the signing input, shifted right one byte. The check is
  strict: R8 a point on the curve in its one spelling, S below `l`, the key a point of the
  prime-order subgroup, then `S · Base8 = R8 + 8 · hm · A`.
- The id is lowercase hex of SHA-256(signing input).

**Canonical text.** An entry travels as exactly its canonical text: RFC 8785 (JCS) over a narrowed
JSON. Strings have no lone surrogates; numbers are whole, within ±(2^53 − 1), so money and
coordinates are decimal text (`"30"`, `"38.72"`); arrays have no holes; object keys match
`^[a-z][a-zA-Z0-9]{0,63}$`; nesting is at most 16 deep. A reader MUST re-serialize what it parsed
and refuse the entry unless the result equals the bytes it received.

**Keys by address.** An address has one spelling: decoding and encoding again MUST give the same
text, 32 bytes, a point packed as keys/ packs it. A key named by its address anywhere, in an entry
or a message, MUST be a point of the prime-order subgroup other than the identity; anything else is
refused.

**Signed values.** A signature carries no words: an entry and a message are each signed as their
own canonical text without `sig`, and an index's root as the canonical text of `{ root, time }`
([proofs](../proofs/README.md#the-tree-an-index-publishes)). Each says what it is by its own fields,
an entry by `profile` and `path`, a message by `from` and `to`, so no signature is ever two of
them. Payments are the pay keys', on their chains.

**Which entry counts.** A reader's view of a folder is a pure function of the entries it holds and
its clock `now`:

1. Entries dated after `now + 600,000` are held back.
2. The current profile entry is the newest at `profile`, signed by the main key.
3. An entry counts when the main key signed it, or a key the current profile entry lists with
   `write`. Any other is ignored as unlisted.
4. Entry A is newer than B if `A.time > B.time`, or the times are equal and `A.id > B.id`. At each
   path, the newest entry that counts is current.
5. A current entry with a `null` body means the path is deleted.

Beyond step 1, readers check no clock. An app sets `time = max(now, newest known at that path + 1)`
(`nextTime`), so a slow clock never makes an edit lose to what it replaces.

### The profile entry

The entry at `profile`, written by the main key only, shows the profile, and it is the one body
every host reads. It is shaped by the JSON Schema in `schemas/`: its fields are the standard's,
and its market (the trade a label names, such as `tutoring`) adds fields beside them.

```
{ "market"?: <text>, "role"?: <text>, "hosts": [<origin>, …], "openKey"?: <open key>,
  "pay"?: { … }, "proofs"?: [ … ],
  "keys"?: [ { "key": <address>, "open"?: <open key>, "can": [ … ] }, … ], "files"?: [ … ] }
```

- **`market` and `role`** are both present for a market profile, the two halves of its label.
- **`hosts`** is 1 to 8 distinct origins, `https://host[:port]`, lower case, no path (`http` only
  on loopback, for tests). Each host it names holds the whole folder. An app writes every entry to
  every host it names, the profile entry first. Moving is copying the folder to the new host: its
  profile entry, naming the new host, then every entry. To leave a host, write a profile entry that
  no longer names it, to every host, the one you are leaving included, so a reader that still asks
  that host is pointed on. The old host may keep its copies; readers follow the profile entry.
- **`openKey`** is the main key's opening half, as its open key, `age1pq1…`
  ([keys](../keys/README.md#opening-halves)). Locked entries and inbox entries are locked to it. A
  folder whose profile entry has one takes inbox entries.
- **`pay`** lists any of the profile's pay addresses, by chain, `solana` or `evm`, each the one
  keys/'s `payAddresses` gives ([keys](../keys/README.md#pay-keys)). They are unsigned: the main key
  signed the profile entry, so they are where the profile says it is paid.
- **`proofs`** carries up to four proofs (Proofs).
- **`keys`** lists the access keys the profile hands out (Access keys).
- **`files`**, as in any entry (Files), names a photo of the profile, say.

A host checks the fields it acts on, `hosts`, `openKey` and `keys`, and refuses a profile entry
where one is not as above [`profile`]; the rest is a reader's to check.

### Access keys

An access key is a key the profile hands out: to an AI app, a service or another person. It is
made from random bytes, not from the seed ([keys](../keys/README.md#access-keys)). The profile entry
lists each one, `{ key, open?, can }`: its address, its open key, and what it can do. `can` holds
any of:

| `can` | The key |
|---|---|
| `read` | opens the folder's locked entries: every one written after the profile entry listed it is locked to it |
| `read-inbox` | opens the folder's inbox entries |
| `write` | writes any entry in the folder but `profile`: an entry it signs, naming itself in `key`, counts |
| `message` | signs messages as the profile, which the recipient's app shows as the profile's |

- `open`, the key's opening half as its open key, is present whenever it can `read` or
  `read-inbox`.
- A key is listed once. A listing has no end date: the person removes a key by writing a profile
  entry that no longer lists it.
- **No access key writes `profile`**, so none can list itself, add a host or widen what it can do:
  an entry at `profile` that names a `key` is refused [`unlisted`].
- **A key removed stops counting, and its entries with it,** for every host and reader at once:
  what counts is decided by the folder's current profile entry, never by when an entry was written.
  At each path the key had written, the newest entry that still counts is current again. The app
  writes again, signed by the main key, what it keeps of what the key wrote.
- A `can` this code does not know grants nothing, and a listed key with a field this code does not
  know counts for nothing (FAQ).
- **Notes.** Each access key may have a note for the person: who holds it, since when, whatever
  the app keeps. It is a locked entry at `key/<id>`, the id random, so the path names no key,
  locked to the main key's open key alone, so no access key reads it. Its locked body names the
  access key it is about, `{ "key": <address>, … }`; the app lists the folder's `key/` entries and
  opens each to find it.

### Locked entries

A locked entry's body is `{ "private": <base64url of an age file> }` and nothing else, age being a
widely used encryption format. The age file is the envelope: the canonical text of an object under
a random key made for that body, and that key locked once to each open key.

- **A locked entry is locked to the main key's open key, and to each listed key that can `read`**
  (`lockKeysOf`). Whoever writes it, the main key or an access key that can write, MUST lock it to
  all of them. Nobody can check: an envelope names no key.
- Each key an envelope is locked to is an age post-quantum hybrid key (`age1pq1…`, stanza
  `mlkem768x25519`); an app MUST NOT lock an envelope to any other kind, since one classic key among
  them would let a quantum computer open it for all. Each adds about 2 KB.
- A host checks a locked entry like any other and cannot open it. Anyone can see that it exists,
  its path, time and size, and how many keys it is locked to, never which: each key's stanza holds
  only its encapsulation, and no piece of a key is in the file.
- A key removed reads no new version: the next one is locked to the rest. What it already opened,
  it keeps (Limits).
- A locked entry carries no files (FAQ).

### Files

Any entry's body that is not locked MAY carry `files`, the files it names:

```
"files": [ { "sha256": <hex>, "type": <media type>, "size": <bytes> }, … ]
```

- **A file's name** is what a stranger needs to fetch it and check it: `sha256`, the SHA-256 of the
  bytes in lowercase hex; `type`, their media type, `type/subtype` in lower case, at most 255
  characters; and `size`, how many bytes. Each item is exactly these three; any other is refused
  [`files`].
- **A photo is an entry whose body is its file**: `{ "files": [ <its name> ] }`, at a path the
  market or the app chooses.
- **Upload.** The app writes the entry first, then uploads the bytes to each of the folder's hosts
  by their hash (`PUT /v1/files/<sha256>`). A host takes them only while a current entry it holds
  names them, with that type and size.
- **Kept** while a current entry names them; once none does, for the host's keep days.
- **Fetch.** Anyone fetches a file from the folder's hosts (`GET /v1/files/<sha256>`), with nothing
  to sign, and checks its SHA-256 itself: a host that serves other bytes is skipped.

### The inbox

An inbox entry is what anyone leaves in a folder whose profile entry has `openKey`. It is not
signed outside, and it names only the folder it is to:

```
{ "v": 1, "to": <address>, "private": <base64url of an age file> }
```

- `v` is 1. No other field is allowed.
- Its id is lowercase hex of SHA-256 of its canonical text. Each host keeps it for its keep days.
- Its envelope is locked to `to`'s open key and to every key `to`'s profile entry lists with
  `read-inbox` (`inboxLockKeysOf`). The sender locks it so; nobody can check.

Locked inside it is one message:

```
{ "from": <address>, "to": <address>, "key"?: <address>, "host"?: <origin>,
  "time": <ms since 1970>, "body": <object>, "sig": <base64url> }
```

- `from` is the sender's profile, and `to` the folder it is left in. `key`, when there is one, is
  the access key that signed, which `from`'s profile entry lists with `message`; else `from`'s main
  key signed.
- `host`, which a message MAY carry, is one of `from`'s hosts, an origin as a profile entry writes
  it: it tells the recipient's app where the sender's folder is.
- `body` is what the message says: the two apps' to agree. The main way, for a plain message, is
  `{ "text": <text> }`.
- `sig` is EdDSA-Poseidon, strict as an entry's, by `key` or `from`, over UTF-8 of the canonical
  text of the message without `sig`. `to` is among the fields it signs, so nobody can move a message
  to another inbox as its sender's.
- **The recipient's app checks** that `to` is the folder it was left in, and the signature
  (`openInbox`), then the sender's profile entry, from the sender's hosts: that it lists `key` with
  `message`, if a key signed (`senderCounts`), and anything else it wants, such as a verification, a
  market and a role. Then it decides what to show.

**Leave.** The sender reads the profile entry of the folder it writes to, for its hosts and the
open keys to lock to; it signs the message, locks it, and leaves the inbox entry with each host
the profile entry names (`POST /v1/inbox`). Anyone may leave one, with no login; each host checks
it on its own (Hosts).

**List.** Anyone lists a folder's inbox after a cursor, the number a host gives the last line on a
page, so the next ask starts after it (`POST /v1/inbox/read`, with `{ "to", "after"? }`). Only the
envelopes protect it.

How many inbox entries a host takes, and from whom, is each host's spam limit (What a host
chooses).

### The Profiles folder

The person's Profiles folder lists every profile they made and every stamp they hold, so a new
device needs only the seed. It is a folder like any other, the empty label's, signed by its main
key, which the seed alone gives ([keys](../keys/README.md#the-profiles-folder)).

- **Its profile entry holds only `hosts`**: no market, no role, no `openKey`, so it takes no inbox
  entries, and no access keys.
- **Every entry in it is locked to its own opening half**, which only the person's devices mix
  from the seed:
  - one for each profile the person made, at `label/<id>`: `{ "label": <label>, "time": <ms since
    1970> }`, its label and when it was made;
  - one for each stamp the person holds, at `stamp/<id>`: `{ "stamp": <text> }`, the stamp's JSON
    ([proofs](../proofs/README.md#the-stamp-and-the-verification)) as text, so any field a verifier
    adds fits, whatever the narrowed JSON of an entry can spell.
- Each id is random, so the paths name nothing.
- An app adds every new profile there, and every new stamp.
- **A new device:** the seed gives the Profiles folder's key; any host that holds the folder gives
  its entries, which the device lists and opens, each giving a label or a stamp; each label gives
  its main key and its folder. Anyone can also try the labels in the markets directory
  ([foundationforest/markets](https://github.com/foundationforest/markets)): the seed and a label
  give the main key, and a host answers whether that folder exists; a label outside the directory
  is found that way only by whoever remembers it.

### Proofs

The profile entry's optional `proofs` field carries up to four proofs, each named by its `circuit`
and checked by that circuit's proof check ([schemas/profile.json](schemas/profile.json)). A proof
counts for one main key: a reader checks it against the address of the profile that carries it, so
a proof copied to another profile fails. A reader ignores a proof whose circuit it does not know,
so a newer kind never makes a profile invalid for an older app. `verification` and `reputation`,
below, are ours: the field takes any circuit's name, and anyone can add one. An app puts a proof in
the profile entry only when the person chooses to show it there: [proofs/](../proofs/README.md#limits)
says what one can reveal. Folders checks no proof itself: `verificationCheck` and `reputationCheck`
turn a proof on a profile entry into what its proof check takes, for the profile that carries it.

- **`verification`** shows that a verifier signed a stamp to the seed that gives this profile's key
  for its label ([proofs/](../proofs/README.md#the-stamp-and-the-verification)). It carries the
  verifier's key, as its address, and its name, the label, and the proof's 256 bytes, in the
  reputation proof's order. A reader checks it with proofs/'s `checkVerification`, which works the
  name hash and the scope, the numbers the proof takes for the name and the label, out of them
  itself. Each reader decides which verifiers it trusts.
- **`reputation`** shows the average score of profiles the person holds in an index's tree,
  without saying which. It carries the index's key, the root and time the index signed and its
  signature, the score, and the proof's 256 bytes. A reader checks it with proofs/'s
  `checkReputation`: the proof derives this profile's key from the same seed as the profiles it
  counts, so nobody can lend their score to someone else. Each reader decides which indexes it
  trusts and how old a time it accepts. How it is made is
  [proofs/](../proofs/README.md#the-reputation-proof)'s.

### Hosts

A host is an address that answers seven requests, the plug, however many machines stand behind
it. It has no keys, no sign-up and no login: an entry's signature is all it asks for. It is open: it
takes signed entries for any folder and serves them to anyone; it takes inbox entries for any folder
whose profile entry on it has `openKey`, and lists them to anyone; it takes the bytes a current
entry names, and serves them to anyone. It reads no body but the profile entry's and each body's
`files`, and needs nothing from an index or from another host.

| Request | Body | Answer |
|---|---|---|
| `POST /v1/entries` | NDJSON, one canonical entry a line | NDJSON, one `{i, id?, ok, error?, message?}` a line (Taking an entry in) |
| `POST /v1/entries/read` | `{ "profile": <address>, "after"?: <cursor> }` | NDJSON of that folder's stored entries after the cursor, in the order taken |
| `GET /v1/entries?after=` | none | NDJSON of every stored entry after the cursor, in the order taken |
| `POST /v1/inbox` | NDJSON, one canonical inbox entry a line | as for entries (Taking an inbox entry in) |
| `POST /v1/inbox/read` | `{ "to": <address>, "after"?: <cursor> }` | NDJSON of the inbox entries left for that folder after the cursor, in arrival order |
| `PUT /v1/files/<sha256>` | the raw bytes, `content-type` their type | `{ok, error?, message?}` (Taking a file in) |
| `GET /v1/files/<sha256>` | none | the bytes, with the type they came in with, or 404 |

- A page's header `forest-cursor` is the last sequence number on it, or, on an empty page, the
  cursor asked with: the next page is after it. A page holds at least one line while there is one
  to give, however large; an empty page is the end.
- A folder is read by POST, its address in the body: front doors, the proxies and hosting platforms
  that stand in front of a host, log URLs, so a person who read their own folder by GET would leave
  a trail. A read with a field the host does not know, or no folder, is answered 400.
- A request with more lines than the host takes gets one [`batch`] result, and one with more bytes
  gets 413.

**Taking an entry in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Entries, of the profile entry's
   fields and of `files` [`canonical`, `shape`, `version`, `key`, `path`, `time`, `body`,
   `profile`, `files`, `unlisted`, `signature`], and `time ≤ now + 600,000` [`future`].
2. Signed by an access key: the current profile entry of its folder on this host lists the key
   with `write` [`unlisted`].
3. It MUST become the current entry at its path by Which entry counts, over what the host stores
   plus it [`older`].
4. A host MAY refuse an entry by its own choice [`refused`], and the first profile entry of a folder
   it does not hold yet [`refused`], so joining can cost. It MUST NOT refuse a profile entry for a
   folder it already holds by its own choice but for its size, so a person can always leave or
   update.

**Taking an inbox entry in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of The inbox [`canonical`, `shape`,
   `version`, `key`].
2. No inbox entry with the same id is here already [`duplicate`].
3. The current profile entry of `to` on this host has `openKey` [`no_inbox`].
4. A host MAY refuse an inbox entry by its own choice [`refused`]: its spam limits.

**Taking a file in**, in this order, error code in brackets; before all of it, a declared size
larger than the host takes is answered 413, unread:

1. `content-type` is a media type [`shape`].
2. A current entry in a folder this host holds names the hash in the path [`unnamed`], with this
   type and this size [`shape`].
3. The bytes' SHA-256 is the hash in the path [`hash`].
4. Bytes the host holds already are `already here`.
5. The host's own choice allows them, by their size, their type, or what the folder holds already
   [`refused`].

A busy host SHOULD check signatures in native code, with these same strict rules: another library
may skip one (zk-kit's `verifySignature` does not check that the key is in the prime-order
subgroup).

**The host check.** Any host runs `checkHost` (`@foundationforest/folders/check`) against its own
address to show it fits the plug: `npm run check-host -- <address>`. It writes from two profiles of
one seed, under the labels `check/a` and `check/b`, and an access key it makes, sends each request
above, and checks each answer: entries taken, and served, one folder's and everyone's, in the order
taken; each refusal with its code; the newest kept at each path; a newer profile entry always taken;
an access key's entry taken while listed with `write`, refused otherwise, and no longer counting
once removed; reading after a cursor; inbox entries refused in the order above, and listed to
anyone in arrival order; files taken only while named, served, and refused when they do not
match. A refusal the plug lets a host make by its own choice, such as
a folder's first profile entry or a size it does not take, is no failure: what it stops is
reported unchecked, and given a seed whose folders the host holds already, the check runs it all.
Folders' own tests run it against a minimal host in `test/host.ts`, which holds everything in
memory and chooses nothing of its own.

### What a host chooses

Nothing here is the standard's: each host chooses, and says its numbers where it describes itself.

- **Sizes.** The largest entry, inbox entry and file it takes; how many lines a request may carry;
  how many lines and bytes a page holds. A client handles any size: it sends a refused request
  again in halves, and follows the cursor page by page. A reader MAY ignore an entry, an inbox entry
  or a file it finds too big.
- **Joining.** Whether it takes the first profile entry of a folder it does not hold yet, so joining
  can cost. A profile entry for a folder it holds it never refuses by its own choice but for its
  size (Taking an entry in).
- **Keeping.** An entry that stops being current, or stops counting, is kept for a number of days
  the host chooses, by its own clock, then deleted. An inbox entry is kept for a number of days from
  when it arrived, then it leaves. A file is kept while a current entry names it, then for the
  host's keep days. A host that drops a current entry withholds it.
- **Spam.** How many inbox entries it takes, for which folders, and from where.

### Use it

`@foundationforest/folders` has three import paths, each built to `dist/` with types, and the shapes:

- `@foundationforest/folders`: keys as addresses (`publicKeyFromAddress`, `keyFromScalar`);
  canonical text; entries (`entry`, the `Writer` that signs one, a main key or `{ profile, key }`,
  `nextTime`, `signEntry`, `checkEntry`, `encodeEntry`, `decodeEntry`, `entryId`); the profile entry
  (`checkProfileBody`, `hostsOf`, `openKeyOf`, `keysOf`, `canDo`, `lockKeysOf`, `inboxLockKeysOf`,
  `CAN`); the view (`viewFolder`, `liveContent`); files (`fileOf`, `filesOf`); the inbox
  (`decodeInbox`, `inboxId`, `signMessage`, `checkMessage`, `senderCounts`); a profile entry's proofs
  as their proof checks take them (`proofsOf`, `verificationCheck`, `reputationCheck`); talking to
  hosts (`write`, `readPage`, `readAll`, `readFolder`, `leave`, `readInbox`, `upload`, `fetchFile`). A host that fails does
  not stop `readFolder`: it reads the others and lists that host, with the error, in `failed`. A
  read ends with an error on a cursor that is not a whole number or does not move forward, and its
  `timeout` bounds the whole read. A write reads each answer's HTTP status before its body, and
  sends a batch again in halves when the host answers 413 or one [`batch`] result. Every request
  goes through the caller's own `fetch` if given, and, given `redirect: 'error'`, refuses a host
  that redirects. No server, database or encryption library is in it. The keys themselves,
  `mainKey`, `openingHalf` and `newAccessKey` among them, are keys/'s.
- `@foundationforest/folders/locked`: `lock`, `openLocked`, `lockCount`, `isLocked`; `inboxEntry`
  (sign a message, and lock it to the open keys a profile entry gives for its inbox) and
  `openInbox` (open one, and check that its message is to that folder and its signature).
- `@foundationforest/folders/check`: `checkHost(url, { seed?, type? })`, the host check, and
  `CHECK_LABELS`, the labels of the profiles it writes from (Hosts).
- `@foundationforest/folders/schemas/profile.json`: the profile entry's shape, as a JSON Schema.

Write a profile with one post, hand out an access key that can write and read the inbox, and put
a photo in the folder:

```ts
import { mainKey, newAccessKey, openingHalf } from '@foundationforest/keys' // keys/
import { entry, fileOf, readFolder, upload, write } from '@foundationforest/folders'

const me = await mainKey(seed, 'tutoring/seller') // seed: its 32 bytes
const ai = await newAccessKey() // its 64 bytes, ai.secret, go to whoever it is for
const profile = {
  market: 'tutoring', role: 'seller', hosts: [host],
  openKey: (await openingHalf(me.secret)).openKey,
  keys: [{ key: ai.address, open: ai.openKey, can: ['write', 'read-inbox'] }],
}
const maths = { ...fields } // a post's fields are its market's (foundationforest/markets)
await write([host], [entry(me, 'profile', profile, Date.now()), entry(me, 'post/maths', maths, Date.now())])
// Whoever holds the access key writes for the profile, naming the folder it writes in:
const photo = fileOf(jpeg, 'image/jpeg') // jpeg: the photo's bytes
await write([host], [entry({ profile: me.address, key: ai }, 'photo/1', { files: [photo] }, Date.now())])
await upload([host], jpeg, 'image/jpeg')
const folder = await readFolder([host], me.address, Date.now())
folder.current.get('photo/1')?.entry.body
```

Leave a message in that folder from another profile, then list and open it:

```ts
import { mainKey } from '@foundationforest/keys'
import { leave, readFolder, readInbox } from '@foundationforest/folders'
import { inboxEntry, openInbox } from '@foundationforest/folders/locked'

const buyer = await mainKey(otherSeed, 'tutoring/buyer')
const seller = await readFolder([host], me.address, Date.now()) // its profile entry has openKey
const sellerProfile = seller.current.get('profile')!.entry.body!
await leave(seller.hosts, [await inboxEntry(buyer, me.address, { text: 'Is Tuesday at six free?' }, Date.now(), sellerProfile)])

const page = await readInbox(host, me.address) // anyone lists it; only the keys it was locked to open it
for (const e of page.entries) {
  const { message } = await openInbox(e.entry, ai.identity) // or the main key's opening half
  // Then the sender's profile entry, from its hosts: senderCounts(message, theirProfile), and anything else.
}
```

```
# The tests take their keys from keys/, and check the example profile entry's proofs with the
# proofs' clients.
npm ci && npm run build   # at the root: every package; keys/, proofs/ and folders to dist/
cd folders
npm run check          # type-check
npm test               # everything, on loopback
npm run check-host -- https://host.example   # the host check, against a host
node test/vectors.ts   # print the test vectors
node scripts/example-profile.ts   # make the example profile entry's proofs again
```

Node 22.18 or later. Built from existing pieces, unchanged: `@noble/curves`, `@noble/hashes`,
`@scure/base`, `poseidon-lite` and `canonicalize` for the core, with keys/'s Baby Jubjub;
`age-encryption` for locking.

### Test vectors

`test/vectors.json`, for keys/'s `tutoring/seller` profile from its test seed `00 01 … 1f`: its
profile entry, whose `openKey` is that profile's main key's opening half, `pay` its pay addresses,
and `keys` keys/'s access key, from 32 bytes of `0x2b` then 32 of `0x2c`, with `read-inbox` and
`write`; an offer by the main key, an offer by the access key, a photo (the 26 letters `a` to `z`,
as `text/plain`) and a delete, each with its wire text, signing input and id; an inbox entry from
keys/'s `tutoring/buyer`, with its id and its message's wire text and signing input; the main key's
note about the access key, at a random path; and the seed's Profiles folder, its profile entry, its
entry for `tutoring/seller`, and its entry for one stamp, the example verifier's, held as text with
a fraction the verifier added. The seed and every key are pinned in `keys/test/vectors.json`, and
checked there. The locked bodies are pinned as made, in `test/envelopes.json`, and the random ids in
`test/vectors.ts`, since age's encryption and the ids are random. `test/vectors.test.ts` recomputes
every entry and the inbox entry, checks each with a second SHA-256 (node:crypto) and a second
EdDSA-Poseidon (zk-kit's, from the address and the 64 bytes on its own), and opens each locked body
with the pinned keys it was locked to and no other. The profile is
`6VQ37dtNvGa5HuC56g9gfhqXXPjxPmktdKaEMaL3rnZL`; every signing input is the canonical text of what it
signs, without `sig`.

The example profile entry, [schemas/examples/profile.json](schemas/examples/profile.json), is that
profile's, with its pay addresses, keys/'s access key listed with `read` and `write`, a verification
from an example verifier and a reputation proof from an example index's tree, made with the
circuits' setups by `scripts/example-profile.ts`; `test/schemas.test.ts` checks both proofs with
their proof checks.

## Promises

- **An entry checks the same wherever it comes from.** One canonical spelling and strict
  EdDSA-Poseidon on Baby Jubjub. A host cannot forge or change an entry; it can only withhold it.
- **Every reader computes the same view from the same entries.** Where they came from and in what
  order does not matter. The reader's clock matters only to hold back entries dated more than ten
  minutes ahead.
- **Only a profile's main key, and the access keys its profile entry lists with `write`, write for
  it.** A host takes, and a reader counts, an entry only when one of them signed it, and only the
  main key writes the profile entry.
- **A person can always move.** A profile's name is its key, not a host's address. A host never
  refuses a profile entry for a folder it holds by its own choice but for its size, though it may
  refuse a folder's first, so joining a host can cost.
- **A host holds nothing secret of the people it serves.** No keys, no sign-up, no login, and it
  cannot open a locked entry or an inbox entry, though it sees whom an inbox entry is for (Limits).
- **Only the keys an inbox entry was locked to open it,** and a sender locks it to the folder's main
  key and the keys its profile entry lists with `read-inbox`.

## Limits

- **Checking signatures in JavaScript is slow.** A busy host or index checks them in native code,
  with the same strict rules (Hosts).
- **A host keeps only the newest entry at each path,** and what it replaced for its keep days.
  Older history is in the app's copies, or nowhere.
- **A host sees whom an inbox entry is for,** when it came and its size, though not who wrote it or
  what it says.
- **Nobody checks what an envelope was locked to.** A writer that leaves out a key, the main key's
  among them, shuts that key out of what it wrote.
- **A key that can write can write any path but `profile`** until it is removed; removing it
  takes back every entry it wrote, at once.
- **What a key opened, it keeps.** Removing a key, or writing the next version for the rest, stops
  the versions written after; what it already opened, and an older version a host or a copy still
  holds, it can still open.
- **A file is only as true as its hash.** A host checks the hash and the size, never that the bytes
  are the type their entry names; the entry says what it means them to be.
- **A delete is a request.** What was public may already have been copied: whoever fetched it has
  it.
- **No forward secrecy.** An opening half that leaks opens every envelope locked to it, from any
  host or copy that still holds them.
- **A host's size bounds an envelope.** Each key it is locked to adds about 2 KB, and each host
  chooses the largest entry and inbox entry it takes.

## Who decides what

- **The standard:** the entry, the inbox entry and the message, and what makes each valid (the
  ten-minute window); the seven requests and their codes; the profile entry's fields, the access
  keys and what each `can` lets one do; locking; a file's name; the Profiles folder's paths; the
  proofs field.
- **A market chooses:** its roles, its content paths and their bodies, and where an entry names
  files ([foundationforest/markets](https://github.com/foundationforest/markets)).
- **A host chooses:** whether it takes a folder it does not hold yet, and at what price; its keep
  days; the largest entry, inbox entry and file it takes; batch and page sizes; which file types it
  takes; spam limits and rate limits; logging; storage.
- **An app, with the person:** which access keys it makes, what each can do, whom it hands them to
  and when to remove them; the copies it keeps; which hosts; which messages to show, by the
  sender's verifications or anything else; whether to forward a message to email or a
  notification; what it finds too big to read; and what asks for the person's device unlock. The
  profile can change or delete anything it wrote, at will. What others wrote about it, and
  payments, stay.
- **An index chooses:** which hosts it reads and how it learns of new ones, which verifiers and
  markets count, how much each review weighs, and which proofs it accepts.

## FAQ

**Why hand out keys, rather than have the person's app sign everything?**
So an AI app, a service or another person can act for a profile while none of the person's devices
is open, and every host and reader can check what each may do: it is in the profile entry, and an
entry by a key it does not list with `write` counts for nothing. The seed and the main keys never
leave the person's devices; a key handed out holds nothing of them.

**What if an access key leaks?**
Write a profile entry that no longer lists it. Every host and reader stops counting what it wrote,
at once, and the newest entry that still counts at each of its paths is current again; the app
writes again, with the main key, what it keeps. What the key could open stays opened, and it reads
nothing written after.

**Why does a listed key with a field this code does not know count for nothing?**
A field nobody defined yet could be a limit, such as an end date or a path the key may write. An
app or a host that skipped it would give the key more than the person meant. Refusing the whole
profile entry instead would stop the person updating it on an older host, and a person can always
update.

**Why is an inbox entry not signed outside?**
A signature outside would name its sender, and every host would see who wrote to whom. Inside the
envelope, only the keys it was locked to see the sender, and the signature, which names the folder,
lets the recipient's app check it.

**Why can anyone list an inbox?**
An inbox entry shows nothing but whom it is for, when it came and its size, which its host sees
anyway; what it says, and who wrote it, only the keys it was locked to open. A signed listing would
protect nothing more, and would need one more key for each reader.

**Why does an inbox not say who may write to it?**
A rule for senders had each host that holds the inbox read the sender's entries from the sender's
host, and check the sender's proofs; and since the sender is locked inside, a host cannot see who
the sender is. So anyone may leave an inbox entry: limiting spam is each host's choice, and
choosing what to show, by the sender's verifications or anything else, is the recipient's app's,
once it opens them.

**Why is a message not an entry in the sender's folder?**
Anyone reads a folder. A message there would need a field naming who it is to so hosts could route
it, and that field would make every inquiry a public fact: who asked whom, and when. A message goes
to the folder it is to instead, locked, sender and all.

**How do I hear that a message arrived?**
Your app lists each inbox from its hosts after its last cursor (`readInbox`); nothing in the
standard pushes.

**Why are a file's bytes kept only while an entry names them?**
So a file needs no request of its own to sign: the entry that names it is signed, by the main key or
by a key that can write, and a host takes and keeps the bytes it names. Which entry names a photo,
and under what path, is the market's or the app's; the field that names it, `files`, is the
standard's, so a host reads it in any body.

**Why can a locked entry carry no files?**
Anyone fetches a file's bytes by their hash. A locked entry that named a file would publish what it
was locked to keep, and locking the bytes themselves would need rules of its own: how they are
locked, and how a reader knows what they are. A photo shown to everyone is an entry like any other.

**Why is a proof's `proof` 256 bytes, and not snarkjs's JSON?**
An entry's object keys cannot spell snarkjs's `pi_a`, `pi_b` and `pi_c`: they allow no `_`. The
256 bytes are the proof's three points, not compressed, in the order Ethereum's and Solana's BN254
precompiles read them, so a reader gets snarkjs's form back by reading eight 32-byte numbers.
Compressed, the points would take 128 bytes fewer, but every reader would have to take square
roots to rebuild them.

**Why not AT Protocol, Nostr or Pubky as the base?**
AT Protocol has one server per profile and a central directory. Nostr's keys are on secp256k1,
which a proof cannot derive from a seed cheaply. Pubky's servers can forge entries.
