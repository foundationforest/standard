# signers

Part of Forest's standard: [the top README](../README.md).

## What it is

How anyone asks a person's app to act for them. A signer is the person's app on a device that
holds their seed (the 32 bytes every key of theirs comes from, [keys](../keys/README.md)), such as
their phone or their laptop. The seed lives only on signers, and no key is ever handed out: not a
main key, not an inbox key, and no key made for someone else. An AI app, another person or a
business asks a signer, and the signer acts as one of the person's profiles, signing with its main
key, so a host or a reader checks one key per profile; or it asks the person first.

This README is the standard: the asks and their answers, how an AI app connects, and permissions,
the private records in each profile's folder that say who may ask for what. The library in `src/`
builds and checks each, `test/` checks it, and `test/vectors.json` pins a connection's signatures
and a permission. It runs no server and opens no socket: a connector, the service that carries an
AI app's asks to a signer and the answers back, is a program someone runs, and lives outside the
standard.

## How it works

### Who asks

- **An AI app,** through its connection: an id and a key the person's app made for it when the
  person connected it (Connecting an AI app). A connector carries its asks to a signer over the live
  link, and the answers back. Anyone can run a connector; the main way is the one in
  [services](https://github.com/foundationforest/services).
- **A person or a business,** by a message to one of the person's profiles, signed by the main key
  of a profile of their own (Asking by message).

The app decides by the permissions of the profile it is asked to act as (Permissions): it does what
one covers, refuses a few asks outright (Asks, Permissions), and asks the person about the rest.
Whatever it does, it signs with that profile's main key and publishes straight to the profile's
hosts.

### Asks

An ask is a JSON object, and `ask` says which of three it is. It names a profile by its label, such
as `tutoring/seller`, which is exactly one profile per seed ([keys](../keys/README.md#main-keys)),
never by its address.

```
{ "ask": "read", "label"?: <label>, "path"?: <path>, "inbox"?: true }
{ "ask": "write", "label": <label>, "path": <path>, "body": <object> | null }
{ "ask": "write", "label": <label>, "to": <address>, "body": <object> }
{ "ask": "pay", "label": <label>, "to": <address or a post's full address>,
  "amount": <decimal text>, "currency": <code> }
```

- **read,** with nothing named: each profile the asker holds a permission on, by label, and what it
  may do there. With a label and a path: the record at that path in the profile's folder, opened by
  the app if it is private and the read is allowed. With a label and `inbox`: the messages to that
  profile.
- **write,** a label, a path and a body: a record at that path in the profile's folder
  ([records](../records/README.md#records)); a null body deletes the path. A message is a write with
  `to`, another profile's address, instead of a path: the app encrypts the body to that profile's
  inbox key, signs it and delivers it ([records](../records/README.md#inbox)). A reply is a write to
  the sender's address.
- **A write of `profile`** always asks the person. Under a label with no profile yet, on a yes the
  app makes the profile: its hosts record, and its profile record with `market`, `role`,
  `inboxKey`, `pay` and `paySig`, and a verification in `proofs` when the app holds a stamp, made on
  the device ([proofs/verification](../proofs/verification/README.md)). For a profile that exists,
  on a yes the app keeps the fields it manages itself (`market`, `role`, `inboxKey`, `inbox`, `pay`,
  `paySig`, `proofs`) and takes only the market's own fields from the ask's body.
- **A write of `hosts` or of a permission** is refused: the person does those in their app.
- **pay,** as the profile with the label: `amount` of `currency` to `to`, an address or a post's
  full address, the address of the profile whose folder holds the post, `/`, then its path, such as
  `9bpP…azDC/offer/maths`. `amount` is decimal text, a whole number and up to six places (`"30"`,
  `"0.5"`); `currency` is a code, such as `USD`. Which pay address the app pays from and to, and on
  which chain, is the app's.
- An app refuses an ask with a field it does not know (`checkAsk`), so a later field never passes
  unread.

### Answers

```
{ "status": "done", …what the ask returns }
{ "status": "waiting", "link"?: <https address>, "why"?: <text> }
{ "status": "refused", "why": <text> }
```

- **done** returns, for a read with nothing named, `profiles`, each `{ label, can, limit?, until? }`
  from its permission; for a read of a path, `body`, null when nothing is there, and the record's
  `time` when there is one; for a read of the inbox, `messages`, each `{ from, time, body }`, its
  body opened; for a write or a pay, nothing more.
- **waiting:** the app asked the person. It may carry `link`, an https address the person opens on
  one of their devices, and `why`. The asker is not told when the person answers: it reads again
  later.
- **refused:** the app will not, and says why.
- An answer never carries an address of the person's own, a profile's or a pay address: the app
  leaves out each field that holds one (`leaveOut`), and a message from another of the person's
  own profiles shows that profile's label, as `fromLabel`, instead of `from`.
- A connector passes on only the fields above (`checkAnswer`), so an app cannot hand an AI app
  anything else by mistake.

### Connecting an AI app

An AI app connects once, through a connector; how it logs in to the connector is the connector's.
The connector sends the person's browser to the app's connect page:

```
<connect page>?connector=<origin>&request=<request>
```

- `connector` is the connector's origin, as a hosts record writes one.
- `request` is text the connector makes: base64url of a JSON object, a `.`, then whatever the
  connector adds, such as a code only it can check. The object holds `name`, the AI app's name, and
  `redirect`, the address the AI app is sent back to (`readRequest`); anything else in it is the
  connector's.
- The page shows `name`, the host of `redirect` and the connector's origin, and the person picks
  which of their profiles this AI app can see.

On a yes, the app makes the connection:

1. an Ed25519 key pair (`newConnection`): its public key, 32 bytes in base64url (43 characters), is
   the connection's id;
2. a permission in the folder of each profile picked, `who: { connector, connection, key, name }`
   with `can` empty, so the AI app sees those profiles and every ask needs the person's yes. `key`
   is the connection's private key, kept there, encrypted, so any of the person's signers can serve
   it, and `name` is the AI app's name;
3. the connection key's signature on `0xff` ‖ UTF-8(`forest/v1/login\n`) ‖ UTF-8(the request,
   exactly as received) (`signLogin`).

It sends the browser to
`<connector>/connected?request=<request>&connection=<id>&sig=<64 bytes in base64url>`; on a no, to
`<connector>/connected?request=<request>&error=access_denied`. The connector checks the signature,
with the connection's id as the key (`checkLogin`), before it lets the AI app ask as that
connection.

### The live link

A signer that is open keeps a WebSocket to each connector its permissions name, at the connector's
origin with `https` as `wss`, then `/signer` (`linkUrl`). Every frame is one JSON object as text,
with a `type` (`readFrame`):

| From | Frame |
|---|---|
| connector | `{ "type": "challenge", "challenge" }`: first, on every socket; 32 random bytes in base64url |
| signer | `{ "type": "register", "connection", "sig" }`: the connection key's signature on `0xff` ‖ UTF-8(`forest/v1/register\n`) ‖ UTF-8(the connector's origin, `\n`, the socket's challenge) (`signRegister`) |
| connector | `{ "type": "registered", "connection" }`, or `{ "type": "refused", "connection", "why" }` |
| connector | `{ "type": "ask", "id", "connection", …the ask }` (`askFrame`): `id` is text the connector picks |
| signer | `{ "type": "answer", "id", …the answer }` (`answerFrame`) |

- A signer registers each connection it serves, and may register another later on the same socket,
  signing the same challenge; the connector checks each (`checkRegister`).
- A connector sends an ask once, to one socket, and never again, so it never asks for a payment
  twice.
- An answer to no ask, or to one the connector gave up on, is dropped. A frame that is not JSON,
  not an object, or of no type above closes the socket.
- The two texts a connection key signs begin with `0xff` and their own text, as every signed text in
  the standard does, so no signature is ever two of them
  ([records](../records/README.md#records)).

### Asking by message

A person or a business asks with the same ask inside a message to one of the person's profiles,
from a profile a permission there names, `who: { profile }`: the object the message encrypts is the
ask itself ([records](../records/README.md#inbox)). It acts as the profile the message is to, and
an ask that names another label is refused. The app answers with a message back to the asker, the
answer as its body.

### Permissions

A profile's permissions say who may ask the person's signers to act as this profile, and for what.
Each is one private record at `permission/<id>` in the profile's folder, encrypted to the profile's
own inbox key only ([records](../records/README.md#private-records)): anyone can see that one
exists, never what it says or whom it is for. Only the person's signers read them: no host or
reader checks them, since everything a host takes is signed by the profile's main key.

```
{ "who": { "connector": <origin>, "connection": <id>, "key"?: <base64url>, "name"?: <text> }
       | { "profile": <address> },
  "can": [<action>, …],
  "limit"?: { "amount": <decimal text>, "currency": <code>, "per": "day" | "week" | "month" },
  "until"?: <ms since 1970> }
```

- `id` is the first 32 hex characters of HMAC-SHA256, keyed by the profile's permission key
  ([keys](../keys/README.md#the-recipe)), of the canonical text of `who` without `key` and `name`
  (`permissionId`). So one who has one permission per profile; and since only the person's signers
  hold the permission key, a path names no who, and one who's permissions on two profiles share no
  path.
- `who` is a connection (Connecting an AI app), or a profile, a person or a business asking by
  message (Asking by message).
- `can`: the asks the who may make without the person's yes, `read`, `write` and `pay`, and nothing
  more. It may be empty: the who sees that profile, and every ask needs the person's yes. A read
  with nothing named needs none.
- `write` never covers the profile record, the hosts record or a permission: a write of `profile`
  always asks the person, and one of `hosts` or of a permission is refused (Asks), since an AI
  allowed to write them could change what the profile shows, move the folder or raise its own
  limits after reading an offer written to trick it.
- `read` never covers a permission, whatever `can` says: the app refuses it, even with the person's
  yes, since a permission may hold a connection's private key (`refuses`).
- `limit`: how much the who may pay as this profile in any one period, in one currency: a day is any
  24 hours, a week any 7 days, a month any 30 days. `amount` is decimal text, a whole number and up
  to six places; `currency` is any currency code. A payment in another currency is outside it. No
  limit, no cap. Counting what was spent is the app's.
- `until`: when it ends, if it does.
- An app reads a profile's permissions before it acts on any ask for it (`readPermissions`), so one
  removed on one device stops on all within one ask, once a host the app reads serves the removal.
  It acts only on a permission it knows whole, every field, action and period, and a currency it
  pays in (`knowsPermission`); `allows` says whether one covers an ask.
- Removing a permission is a null body at its path. An app keeps every field and value it does not
  know.

### What an app that holds keys should know

The person decides what to do with their keys, and may expose or link them if they choose. This is
what an app that holds the seed, a signer, should know:

1. The seed stays on the person's own devices, behind each one's unlock. The main way is a passkey,
   the device's own unlock, so there is no password to keep; anyone can use an OS keychain or a
   hardware key instead. The recipe is the same whichever is used.
2. The signer asks for the person's device unlock whenever the person acts with the seed: to sign
   with a main key, or to make a proof. What others ask, it does only within the profile's
   permissions, and it asks the person about the rest.
3. No key ever leaves a signer, to an app, a server, an AI or another person. What leaves is
   signatures, proofs, and what the profile's permissions let others read.
4. An AI app asks through its connection, and a person or a business by a message signed by its own
   profile's main key; the signer acts on either only by the profile's permissions.
5. Neither the AI app nor the connector ever receives the person's own profiles' addresses, keys or
   folders, though what it posts is public, so it can find that one profile (hosts keep folders and
   indexes read addresses, by design). An AI names a profile by its label; the signer signs and
   publishes straight to the hosts; answers carry no addresses.
6. Proofs are made on the signer, never delegated.
7. The app keeps the verifier's stamp on the device, as JSON; a verifier that keeps what it signed
   can hand a lost one back by its stamp number, if it chooses.

### Use it

Everything is exported from `src/index.ts`, as `@foundationforest/signers`.

| Function | Gives |
|---|---|
| `checkAsk(value)`, `postAddressOf(text)` | An ask, checked, or a RecordError `ask`; a post's full address as its profile and path, or null |
| `checkAnswer(value, ask)`, `leaveOut(value, addresses)` | An answer to that ask with only its known fields, or a RecordError `answer`; a value with each field and item that holds one of the addresses left out |
| `newConnection()`, `connectionOf(key)`, `isConnection(id)` | A new connection, `{ connection, key }`; the one a private key gives; whether text is a connection's id |
| `signLogin(key, request)`, `checkLogin(connection, request, sig)`, `readRequest(request)` | A login's signature and its check; the `name` and `redirect` a connect page shows |
| `signRegister(key, connector, challenge)`, `checkRegister(connection, connector, challenge, sig)` | A registration's signature and its check |
| `linkUrl(connector)`, `readFrame(text)`, `askFrame(id, connection, ask)`, `answerFrame(id, answer)` | Where the live link opens; a frame, checked, or a RecordError `frame`; an ask and an answer as frames |
| `permissionRecord(mainKey, permission, time)`, `readPermissions(view, mainKey)`, `permissionId(mainKey, who)` | A permission's record, encrypted and signed; a profile's permissions from its view; a permission's id |
| `checkPermission(value)`, `knowsPermission(permission, currencies)`, `allows(permission, ask, { now, currencies, spent? })`, `refuses(ask)` | A permission's shape, or a RecordError `permission`; whether an app knows it whole; whether it covers an ask without the person's yes, `spent` what the who already paid in the limit's period; whether an app refuses an ask whatever a permission says, even with the person's yes |
| `ACTIONS`, `PERIODS`, `PERMISSION_PREFIX` | The actions, the periods in milliseconds, and `permission/` |

```
npm ci && npm run build   # at the root: every package; keys/, records and this one to dist/
cd signers
npm run check             # type-check
npm test                  # everything, with no network
node test/vectors.ts      # print the test vectors
```

Node 22.18 or later. Built from existing pieces, unchanged: keys/ and records/; `@noble/curves` for
Ed25519 and `@noble/hashes` for HMAC-SHA256.

### Test vectors

`test/vectors.json`: a connection, its key 32 bytes of `0x2b` and its id; its signature on a login
request and its registration on a socket, each with its signing input; and `permission`, one of
keys/'s `tutoring/seller` profile's permissions, for that connection, with its wire text, signing
input and id. Its path's id is keyed by the profile's permission key, and its body is encrypted to
the profile's own inbox key alone, pinned as made since age's encryption is random.
`test/vectors.test.ts` recomputes them, checks the connection's key and both signatures with Node's
own Ed25519 over the bytes written out by hand, opens the permission with the pinned inbox key,
recomputes its id with a second HMAC-SHA256 under the pinned permission key, and checks the main
key's signature with zk-kit's EdDSA-Poseidon.

## Limits

- **A connector can act as any connection it carries,** within that connection's permissions: it
  sees each ask and answer in plain text, and any token passed through it. That is why a permission
  has limits. Anyone can run their own.
- **Nothing acts while no signer is open.** An ask is answered only while one of the person's
  devices keeps the live link.
- **The asker is not told when the person says yes.** It reads again, or asks again.
- **What an AI writes is public.** Answers carry no address of the person's, but an index lists what
  a profile posts, so the AI can find that one profile; what is kept from it is the map of the
  person's profiles.

## Who decides what

- **The standard:** the asks and their answers, the connect step, the live link's frames and what
  each signs, and a permission's path, body and words.
- **An app, with the person:** how it asks the person (a notification, allow once, always,
  defaults); counting what each who spent against its limit; which currencies it pays in; and which
  pay address and chain a payment uses.
- **The person, through their app:** which AI apps connect, which of their profiles each sees, what
  each may do there, within which limits and until when; each yes; and removing a permission.
- **A connector:** how an AI app logs in to it, how long it waits for an answer, and which of a
  connection's sockets an ask goes to.

## FAQ

**Why are permissions private records?**
A public list would tell anyone which apps and which people act for a profile, and since when, and
one connection or one person listed under two profiles would link them. Nobody but the person's
signers needs to read them: they alone act on them, and every host and reader checks only the main
key's signature. As private records in the profile's own folder, each is encrypted to its inbox
key, which only the seed gives, so any of the person's devices reads them; and a permission's path
is keyed by the profile's permission key, so it names no who, and one who's permissions on two
profiles share no path.

**Why is a connection key Ed25519, and not Baby Jubjub as a main key is?**
A connection key is no profile's and no service's: it signs a login and a socket's challenge,
nothing a reader of records checks. Ed25519 is in every browser and in Node, so an app needs
nothing more to make one.
