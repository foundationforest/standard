# folders

Part of [Forest's standard](../README.md). The profile entry's shape: [schemas/](schemas/).

## What it is

How a profile writes, locks and reads its entries; the inbox; files; the Profiles folder; and the
plug every host fits. Each profile has one folder on one or more hosts: its profile entry, which
shows it; its entries, of any shape, public or locked; and its inbox, the entries others leave it,
always locked. An entry is a small signed JSON value at a path. Hosts serve folders to anyone, and
every reader checks every signature itself, so a host can withhold an entry but never forge one.
This README is the standard: `src/` does every MUST in it (MUST, SHOULD and MAY as in RFC 2119),
`test/` checks it, and the host check shows that a host fits the plug.

## How it works

| What | Who enforces it | How |
|---|---|---|
| Writing | hosts and readers | an entry counts only when the profile's main key signed it, or an access key its profile entry lists with `write`; a host takes, and a reader counts, nothing else |
| Reading | envelopes | a locked entry opens only for the keys it was locked to; nobody else checks anything |
| Messages | the recipient's app | it checks each message's signature and its sender's profile entry, and decides what to show |

### Folders

A profile's name is its main key's address ([keys](../keys/README.md#main-keys)): no sign-up, no
directory. Its folder is every entry signed for it, one current entry per path:

| Path | What it holds |
|---|---|
| `profile` | the profile entry: hosts, market and role, open key, pay addresses, proofs, access keys |
| `key/<id>` | a note for the person about one access key, at a random id (Access keys) |
| any other | anything the writer chooses: a market's posts and reviews, an app's own entries, a photo |

- A path is 1 to 4 segments separated by `/`, each `[a-z0-9][a-z0-9._-]{0,63}`, at most 256 bytes.
  `profile` is a single path: `profile/<anything>` is refused.
- Beside `profile`, paths and bodies are the writer's. The main way is the market's the label names:
  [markets](https://github.com/foundationforest/markets) keeps `post/<id>` and `review/<id>` among
  them. Readers MAY ignore a first segment they do not know.
- An entry sits in the folder of the profile that wrote it, so the profile a review is about cannot
  erase it; the one who wrote it can.

### Entries

```
{ "v": 1, "profile": <address>, "path": <path>, "time": <ms since 1970>,
  "body": <object> | null, "key"?: <address>, "sig": <base64url> }
```

- `v` is 1, and no other field is allowed. `time` is whole milliseconds, 0 to 2^53 − 1. A `null`
  body deletes the path.
- `key` is the address of the access key that signed: absent when the main key signed, and never
  the main key's own address.
- `sig` is EdDSA-Poseidon by `key`, else by the main key, over the signing input, UTF-8 of the
  entry's canonical text without `sig`: the 64 bytes, R8 packed then S, in base64url without
  padding, checked strictly as [keys](../keys/README.md#signatures) sets out.
- The id is lowercase hex of SHA-256 of the signing input.

**Canonical text.** An entry travels as exactly its canonical text: RFC 8785 (JCS) over a narrowed
JSON. Strings have no lone surrogates; numbers are whole, within ±(2^53 − 1), so money and
coordinates are decimal text (`"30"`, `"38.72"`); arrays have no holes; object keys match
`^[a-z][a-zA-Z0-9]{0,63}$`; nesting is at most 16 deep. A reader MUST re-serialize what it parsed
and refuse the entry unless the result equals the bytes it received.

**Keys by address.** Decoding an address and encoding it again MUST give the same text: 32 bytes, a
point packed as keys/ packs it. A key named by its address, in an entry or a message, MUST be a
point of the prime-order subgroup other than the identity.

**Signed values.** An entry and a message are each signed as their own canonical text without
`sig`, and an index's root as the canonical text of `{ root, time }`
([proofs](../proofs/README.md#the-tree-an-index-publishes)). Each says what it is by its own fields,
an entry by `profile` and `path`, a message by `from` and `to`, so no signature is ever two of them.
Payments are the pay keys', on their chains.

**Which entry counts.** A reader's view of a folder is a pure function of the entries it holds and
its clock `now` (`viewFolder`):

1. Entries dated after `now + 600,000` are held back.
2. The current profile entry is the newest at `profile` signed by the main key.
3. An entry counts when the main key signed it, or a key the current profile entry lists with
   `write`; any other is ignored as unlisted.
4. A is newer than B if `A.time > B.time`, or the times are equal and `A.id > B.id`. At each path,
   the newest entry that counts is current.
5. A current entry with a `null` body means the path is deleted.

Beyond step 1, readers check no clock. An app sets `time = max(now, newest known at that path + 1)`
(`nextTime`), so a slow clock never makes an edit lose to what it replaces.

### The profile entry

The entry at `profile`, written by the main key only, shows the profile, and is the one body every
host reads. The JSON Schema in `schemas/` shapes it: its fields are the standard's, and its market
adds fields beside them.

```
{ "market"?: <text>, "role"?: <text>, "hosts": [<origin>, …], "openKey"?: <open key>,
  "pay"?: { … }, "proofs"?: [ … ],
  "keys"?: [ { "key": <address>, "open"?: <open key>, "can": [ … ] }, … ], "files"?: [ … ] }
```

- **`market` and `role`** are both present for a market profile: the two halves of its label.
- **`hosts`** is 1 to 8 distinct origins, `https://host[:port]`, lower case, no path (`http` only on
  loopback, for tests). Each holds the whole folder, and an app writes every entry to every one,
  the profile entry first. Moving is copying the folder to the new host: its profile entry, naming
  the new host, then every entry. To leave a host, write a profile entry that no longer names it to
  every host, that one included, so a reader that still asks it is pointed on; the old host may keep
  its copies, and readers follow the profile entry.
- **`openKey`** is the main key's open key, `age1pq1…` ([keys](../keys/README.md#opening-halves)).
  Locked entries and inbox entries are locked to it; a folder whose profile entry has one takes
  inbox entries.
- **`pay`** lists any of the profile's pay addresses by chain, `solana` or `evm`, as keys/'s
  `payAddresses` gives them ([keys](../keys/README.md#pay-keys)). They are unsigned: the main key
  signed the profile entry, so they are where the profile says it is paid.
- **`proofs`** carries up to four proofs (Proofs); **`keys`** lists the access keys the profile
  hands out (Access keys); **`files`**, as in any entry, names a photo of the profile, say (Files).

A host checks the fields it acts on, `hosts`, `openKey` and `keys`, and refuses a profile entry
where one is not as above [`profile`]; the rest is a reader's to check.

### Access keys

An access key is a key the profile hands out, to an AI app, a service or another person, made from
random bytes ([keys](../keys/README.md#access-keys)), so they can act for the profile while none of
the person's devices is open, and every host and reader can check what each may do. The profile
entry lists each one, `{ key, open?, can }`: its address, its open key, and what it can do:

| `can` | The key |
|---|---|
| `read` | opens the folder's locked entries: every one written after the profile entry listed it is locked to it |
| `read-inbox` | opens the folder's inbox entries |
| `write` | writes any entry in the folder but `profile`: an entry it signs, naming itself in `key`, counts |
| `message` | signs messages as the profile, which the recipient's app shows as the profile's |

- `open` is present whenever the key can `read` or `read-inbox`.
- A key is listed once, with no end date: the person removes it by writing a profile entry that no
  longer lists it.
- **No access key writes `profile`**, so none can list itself, add a host or widen what it can do:
  an entry at `profile` that names a `key` is refused [`unlisted`].
- **A key removed stops counting, and its entries with it,** for every host and reader at once:
  what counts is decided by the current profile entry, never by when an entry was written. At each
  path it wrote, the newest entry that still counts is current again; the app writes again, with
  the main key, what it keeps.
- A `can` this code does not know grants nothing, and a listed key with a field it does not know
  counts for nothing: the field could be a limit, such as an end date, and refusing the whole
  profile entry would stop the person updating it on an older host.
- **Notes.** An access key may have a note for the person, such as who holds it: a locked entry at
  `key/<id>`, the id random so the path names no key, locked to the main key's open key alone so no
  access key reads it. Its body names the key, `{ "key": <address>, … }`; the app lists the
  folder's `key/` entries and opens each.

### Locked entries

A locked entry's body is `{ "private": <base64url of an age file> }` and nothing else, age being a
widely used encryption format. The age file is the envelope: the canonical text of an object under
a random key made for it, and that key locked once to each open key (`lock`, `openLocked`).

- **It is locked to the main key's open key, and to each listed key that can `read`**
  (`lockKeysOf`). Whoever writes it MUST lock it to all of them. Nobody can check: an envelope
  names no key.
- Each key it is locked to is an age post-quantum hybrid key (`age1pq1…`, stanza
  `mlkem768x25519`); an app MUST NOT lock an envelope to any other kind, since one classic key among
  them would let a quantum computer open it for all. Each adds about 2 KB.
- A host checks it like any other entry and cannot open it. Anyone sees that it exists, its path,
  time and size, and how many keys it is locked to (`lockCount`), never which: each stanza holds
  only its encapsulation.
- A key removed reads no new version, which is locked to the rest; what it opened, it keeps.
- It carries no files: anyone fetches a file by its hash, so naming one would publish it.

### Files

Any body that is not locked MAY carry `files`, the files it names:

```
"files": [ { "sha256": <hex>, "type": <media type>, "size": <bytes> }, … ]
```

- **A file's name** is what a stranger needs to fetch and check it: `sha256` of the bytes, in
  lowercase hex; `type`, `type/subtype` in lower case, at most 255 characters; and `size`, in bytes.
  Each item is exactly these three; any other is refused [`files`] (`fileOf`, `filesOf`).
- **A photo is an entry whose body is its file,** `{ "files": [ <its name> ] }`, at a path the
  market or the app chooses.
- **Upload.** The app writes the entry first, then uploads the bytes to each of the folder's hosts
  (`PUT /v1/files/<sha256>`, `upload`). A host takes them only while a current entry it holds names
  them, with that type and size, so a file needs no signed request of its own.
- **Kept** while a current entry names them; once none does, for the host's keep days.
- **Fetch.** Anyone fetches a file from the folder's hosts (`GET /v1/files/<sha256>`, `fetchFile`),
  with nothing to sign, and checks its SHA-256: a host that serves other bytes is skipped.

### The inbox

An inbox entry is what anyone leaves in a folder whose profile entry has `openKey`:

```
{ "v": 1, "to": <address>, "private": <base64url of an age file> }
```

- `v` is 1, and no other field is allowed. Its id is lowercase hex of SHA-256 of its canonical
  text. Each host keeps it for its keep days.
- It is not signed outside, so no host sees who wrote to whom, and names only the folder it is to.
- Its envelope is locked to `to`'s open key and to every key `to`'s profile entry lists with
  `read-inbox` (`inboxLockKeysOf`). The sender locks it so; nobody can check.

Locked inside it is one message:

```
{ "from": <address>, "to": <address>, "key"?: <address>, "host"?: <origin>,
  "time": <ms since 1970>, "body": <object>, "sig": <base64url> }
```

- `from` is the sender's profile, and `to` the folder it is left in. `key`, when present, is the
  access key that signed, which `from`'s profile entry lists with `message`; else `from`'s main key
  signed.
- `host`, which a message MAY carry, is one of `from`'s hosts, an origin as a profile entry writes
  it: where the sender's folder is.
- `body` is the two apps' to agree; the main way, for a plain message, is `{ "text": <text> }`.
- `sig` is EdDSA-Poseidon, strict as an entry's, by `key` or `from`, over UTF-8 of the message's
  canonical text without `sig`. It signs `to`, so nobody can move a message to another inbox as its
  sender's.
- **The recipient's app checks** that `to` is the folder it was left in, and the signature
  (`openInbox`); then the sender's profile entry, from the sender's hosts: that it lists `key` with
  `message`, if a key signed (`senderCounts`), and anything else it wants, such as a verification, a
  market and a role. Then it decides what to show.

**Leave.** The sender reads the recipient's profile entry for its hosts and open keys, signs the
message, locks it, and leaves the inbox entry with each host (`POST /v1/inbox`; `inboxEntry`,
`leave`). Anyone may, with no login: a rule for senders would need each host to read the sender's
folder, and the sender is locked inside. Each host checks it on its own, and limits spam as it
chooses (Hosts).

**List.** Anyone lists a folder's inbox after a cursor (`POST /v1/inbox/read`, with `{ "to",
"after"? }`; `readInbox`), since a listing shows only what its host sees anyway. Nothing pushes: an
app lists each inbox after its last cursor.

### The Profiles folder

The person's Profiles folder lists every profile they made and every stamp they hold, so a new
device needs only the seed. It is a folder like any other, the empty label's
([keys](../keys/README.md#the-recipe)).

- **Its profile entry holds only `hosts`**: no market, no role, no `openKey`, so no inbox and no
  access keys.
- **Every entry in it is locked to its own opening half**, which only the person's devices mix, at
  a random id, so the paths name nothing:
  - one for each profile, at `label/<id>`: `{ "label": <label>, "time": <ms since 1970> }`, its
    label and when it was made;
  - one for each stamp, at `stamp/<id>`: `{ "stamp": <text> }`, the stamp's JSON
    ([proofs](../proofs/README.md#the-stamp-and-the-verification)) as text, so any field a verifier
    adds fits, whatever an entry's narrowed JSON can spell.
- An app adds every new profile there, and every new stamp.
- **A new device:** the seed gives the Profiles folder's key; any host that holds it gives its
  entries, which the device opens; each label gives its main key and its folder. Anyone can also try
  the labels in the markets directory ([markets](https://github.com/foundationforest/markets)) and
  ask a host whether that folder exists; a label outside the directory is found that way only by
  whoever remembers it.

### Proofs

The profile entry's `proofs` carries up to four proofs, each named by its `circuit`
([schemas/profile.json](schemas/profile.json)). A reader checks each against the address of the
profile that carries it, so a copied proof fails, and ignores a circuit it does not know, so a newer
kind never makes a profile invalid for an older app. An app shows a proof only when the person
chooses to ([proofs](../proofs/README.md#limits) says what one can reveal). Folders checks no proof
itself: `proofsOf`, `verificationCheck` and `reputationCheck` turn one into what its proof check
takes.

- **`verification`** ([proofs](../proofs/README.md#the-stamp-and-the-verification)) carries the
  verifier's key, as its address, its name, the label, and the proof's 256 bytes; proofs/'s
  `checkVerification` checks it. Each reader decides which verifiers it trusts.
- **`reputation`** ([proofs](../proofs/README.md#the-reputation-proof)) carries the index's key, the
  root and time the index signed, its signature, the score, and the proof's 256 bytes; proofs/'s
  `checkReputation` checks it. Each reader decides which indexes it trusts and how old a time it
  accepts.
- The 256 bytes are the proof's three points, not compressed, in the order Ethereum's and Solana's
  BN254 precompiles read them, since an entry's keys cannot spell snarkjs's `pi_a`; a reader gets
  snarkjs's form back as eight 32-byte numbers. Compressed would save 128 bytes and make every
  reader take square roots.

### Hosts

A host is an address that answers seven requests, the plug, however many machines stand behind it.
It has no keys, no sign-up and no login: a signature is all it asks for. It takes signed entries for
any folder, inbox entries for any folder whose profile entry on it has `openKey`, and the bytes a
current entry names, and serves each to anyone. It reads no body but the profile entry's and each
body's `files`, and needs nothing from an index or another host.

| Request | Body | Answer |
|---|---|---|
| `POST /v1/entries` | NDJSON, one canonical entry a line | NDJSON, one `{i, id?, ok, error?, message?}` a line |
| `POST /v1/entries/read` | `{ "profile": <address>, "after"?: <cursor> }` | NDJSON of that folder's stored entries after the cursor, in the order taken |
| `GET /v1/entries?after=` | none | NDJSON of every stored entry after the cursor, in the order taken |
| `POST /v1/inbox` | NDJSON, one canonical inbox entry a line | as for entries |
| `POST /v1/inbox/read` | `{ "to": <address>, "after"?: <cursor> }` | NDJSON of the inbox entries left for that folder after the cursor, in arrival order |
| `PUT /v1/files/<sha256>` | the raw bytes, `content-type` their type | `{ok, error?, message?}` |
| `GET /v1/files/<sha256>` | none | the bytes, with the type they came in with, or 404 |

- A page's header `forest-cursor` is the last sequence number on it, or, on an empty page, the
  cursor asked with; the next page is after it. A page holds at least one line while there is one,
  however large; an empty page is the end.
- A folder is read by POST, its address in the body, since the proxies and platforms in front of a
  host log URLs. A read with a field the host does not know, or no folder, is answered 400.
- A request with more lines than the host takes gets one [`batch`] result; with more bytes, 413.

**Taking an entry in**, in this order, error code in brackets:

1. No larger than the host takes [`size`]; then the checks of Entries, of the profile entry's
   fields and of `files` [`canonical`, `shape`, `version`, `key`, `path`, `time`, `body`,
   `profile`, `files`, `unlisted`, `signature`], and `time ≤ now + 600,000` [`future`].
2. Signed by an access key: the current profile entry of its folder on this host lists the key with
   `write` [`unlisted`].
3. It MUST become the current entry at its path by Which entry counts, over what the host stores
   plus it [`older`].
4. A host MAY refuse an entry by its own choice [`refused`], and the first profile entry of a folder
   it does not hold yet [`refused`], so joining can cost. It MUST NOT refuse a profile entry for a
   folder it already holds by its own choice but for its size, so a person can always leave or
   update.

**Taking an inbox entry in**, in this order:

1. No larger than the host takes [`size`]; then the checks of The inbox [`canonical`, `shape`,
   `version`, `key`].
2. No inbox entry with the same id is here already [`duplicate`].
3. The current profile entry of `to` on this host has `openKey` [`no_inbox`].
4. A host MAY refuse an inbox entry by its own choice [`refused`]: its spam limits.

**Taking a file in**, in this order, after answering 413, unread, to a declared size larger than it
takes:

1. `content-type` is a media type [`shape`].
2. A current entry in a folder this host holds names the hash in the path [`unnamed`], with this
   type and size [`shape`].
3. The bytes' SHA-256 is the hash in the path [`hash`].
4. Bytes the host holds already are `already here`.
5. The host's own choice allows them, by their size, their type, or what the folder holds already
   [`refused`].

A busy host SHOULD check signatures in native code, with these same strict rules: another library
may skip one (zk-kit's `verifySignature` does not check that the key is in the prime-order
subgroup).

**The host check.** Any host runs `checkHost` (`@foundationforest/folders/check`) against its own
address, `npm run check-host -- <address>`, to show it fits the plug. It writes from two profiles of
one seed, `check/a` and `check/b` (`CHECK_LABELS`), and an access key it makes, sends each request
above, and checks every answer and every refusal's code. A refusal the plug lets a host make by its
own choice, such as a folder's first profile entry or a size, is no failure: what it stops is
reported unchecked, and given a seed whose folders the host already holds, the check runs it all.

**What a host chooses**, and says where it describes itself:

- **Sizes:** the largest entry, inbox entry and file; how many lines a request may carry; how many
  lines and bytes a page holds. A client sends a refused request again in halves and follows the
  cursor; a reader MAY ignore anything it finds too big.
- **Joining:** whether it takes a folder's first profile entry, and at what price.
- **Keeping:** how many days, by its own clock, it keeps an entry that stopped being current or
  counting, and an inbox entry from when it arrived; a file while a current entry names it, then for
  those days. A host that drops a current entry withholds it.
- **Spam:** how many inbox entries it takes, for which folders, and from where.
- **The rest:** which file types it takes, rate limits, logging and storage.

## Use it

```ts
import { mainKey, newAccessKey, openingHalf } from '@foundationforest/keys'
import { entry, leave, readFolder, readInbox, write } from '@foundationforest/folders'
import { inboxEntry, openInbox } from '@foundationforest/folders/locked'

// A profile with one post, handing out an access key that can write and read the inbox.
const me = await mainKey(seed, 'tutoring/tutor')
const ai = await newAccessKey() // ai.secret goes to whoever it is for
const profile = {
  market: 'tutoring', role: 'tutor', hosts: [host],
  openKey: (await openingHalf(me.secret)).openKey,
  keys: [{ key: ai.address, open: ai.openKey, can: ['write', 'read-inbox'] }],
}
await write([host], [entry(me, 'profile', profile, Date.now()), entry(me, 'post/maths', post, Date.now())]) // a post's fields are its market's
await write([host], [entry({ profile: me.address, key: ai }, 'post/physics', post, Date.now())]) // by the access key

// Another profile leaves a message; anyone lists the inbox, and only the keys it was locked to open it.
const them = await mainKey(otherSeed, 'tutoring/student')
const folder = await readFolder([host], me.address, Date.now())
await leave(folder.hosts, [await inboxEntry(them, me.address, { text: 'Is Tuesday at six free?' }, Date.now(), folder.current.get('profile')!.entry.body)])
for (const e of (await readInbox(host, me.address)).entries) console.log((await openInbox(e.entry, ai.identity)).message.body)
```

The import paths are `@foundationforest/folders`, `/locked`, `/check` and `/schemas/profile.json`,
each built to `dist/` with types; the keys are keys/'s. `readFolder` reads every host and lists any
that failed in `failed`; a write sends a batch again in halves on 413 or a [`batch`] result; every
request goes through the caller's own `fetch` if given, and, given `redirect: 'error'`, refuses a
host that redirects.

## Run it

```
npm ci && npm run build                       # at the root: keys/, proofs/ and folders to dist/
cd folders
npm run check                                 # type-check
npm test                                      # everything, on loopback
npm run check-host -- https://host.example    # the host check, against a host
node test/vectors.ts                          # print the test vectors
node scripts/example-profile.ts               # make the example profile entry's proofs again
```

Node 22.18 or later. Built from existing pieces, unchanged: `@noble/curves`, `@noble/hashes`,
`@scure/base`, `poseidon-lite` and `canonicalize`, with keys/'s Baby Jubjub; `age-encryption` for
locking.

`test/` runs everything against a minimal in-memory host that chooses nothing of its own
(`test/host.ts`), the host check included, recomputes the vectors in `test/vectors.json` with a
second SHA-256 and a second EdDSA-Poseidon, and checks both proofs in
[schemas/examples/profile.json](schemas/examples/profile.json).

## Promises

- **An entry checks the same wherever it comes from.** One canonical spelling and strict
  EdDSA-Poseidon on Baby Jubjub: a host cannot forge or change an entry, only withhold it.
- **Every reader computes the same view from the same entries,** wherever they came from and in
  whatever order. Its clock matters only to hold back entries dated more than ten minutes ahead.
- **Only a profile's main key, and the access keys its profile entry lists with `write`, write for
  it.** A host takes, and a reader counts, an entry only when one of them signed it, and only the
  main key writes the profile entry.
- **A person can always move.** A profile's name is its key, not a host's address. A host never
  refuses a profile entry for a folder it holds by its own choice but for its size, though it may
  refuse a folder's first, so joining a host can cost.
- **A host holds nothing secret of the people it serves, and opens nothing locked.** It has no
  keys, no sign-up and no login, and cannot open a locked entry or an inbox entry, though it sees
  whom an inbox entry is for (Limits). Only the keys an inbox entry was locked to open it, and a
  sender locks it to the folder's main key and the keys its profile entry lists with `read-inbox`.

## Limits

- Checking signatures in JavaScript is slow; a busy host or index checks them in native code.
- A host keeps only the newest entry at each path, and what it replaced for its keep days; older
  history is in the app's copies, or nowhere.
- A host sees whom an inbox entry is for, when it came and its size, never who wrote it or what it
  says.
- Nobody checks what an envelope was locked to: a writer that leaves out a key, the main key's
  among them, shuts that key out.
- A key that can write can write any path but `profile` until it is removed; removing it takes back
  every entry it wrote, at once.
- What a key opened, it keeps, and it can still open an older version a host or a copy holds.
- A file is only as true as its hash: a host checks the hash and the size, never the type.
- A delete is a request: whoever fetched what was public has it.
- No forward secrecy: an opening half that leaks opens every envelope locked to it that a host or a
  copy still holds.
- A host's size bounds an envelope: each key it is locked to adds about 2 KB.

## FAQ

**Why is a message not an entry in the sender's folder?**
Anyone reads a folder. A message there would need a field naming whom it is to, so hosts could
route it, and that field would make every inquiry a public fact: who asked whom, and when. A
message goes to the folder it is to instead, locked, sender and all.

**Why not AT Protocol, Nostr or Pubky as the base?**
AT Protocol has one server per profile and a central directory. Nostr's keys are on secp256k1,
which a proof cannot derive from a seed cheaply. Pubky's servers can forge entries.
