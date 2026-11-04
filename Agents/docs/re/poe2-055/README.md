# LocalExile2 research archive — read this first

Everything reverse-engineered so far about running a **local server for the
Path of Exile 2 client, version 0.5.5.5** (standalone install), collected so
another engineer (human or AI) can pick the work up without redoing it.
The server itself lives in this repository (`src/`); this folder is the
research record behind it. `PORTING-POE2.md` at the repo root is the early
porting log — where it disagrees with these notes, **these notes win**.

## Conventions used in the notes

- Every claim is graded: **已实证 / proven** (script output, logs, math, or a
  live-device result that can be re-checked), **推断 / inferred** (basis
  stated), **待验假设 / hypothesis** (a work direction, not a conclusion).
- Client addresses are VAs in the pristine 0.5.5.5 executable
  (imagebase `0x140000000`; `.text` raw = VA − `0x140000C00`;
  `.rdata` raw = VA − `0x140001200`). Pristine exe SHA-256:
  `d46f4c27576122afc41a428eef96b3b4c75592a16827ed8c2204508ab06a455d`.
  The played client differs from pristine in ~700 bytes of `.rdata` only
  (the login key-material region, patched by the local patch server);
  **zero code bytes differ**, so all static findings apply to it.
- Ground rule for this project: **no PoE1 code or data** in the PoE2 work.
  Localization *methods* may be borrowed; implementations and data must
  come from the 0.5.5 client's own evidence (its binary and GGPK).

## Status (2026-11-04)

| Milestone | State |
|---|---|
| Local patch rig (self-signed CA + hosts redirect + patch stub/HTTPS) | ✅ live-proven |
| Login layer: account, character list/create/delete, enter-game ticket | ✅ live-proven (M1, 2026-11-04 06:50) |
| Instance crypto (Salsa streams, opening) | ✅ solved and live-proven |
| Area packet S→C `0x1e` accepted, client generates the area, replies C→S `0x9a` | ✅ live-proven |
| Player spawn (world `0x2f7` CreateObject) | ⚠️ delivered, decrypted, object created client-side — **blocked**: the world is never ticked/dispatched. Activation trigger identified (`0x23` → aggregate main vtable +0x1f0 → activation); the value-only test S1 is deployed and awaiting one live session (see open problem 1 and `CURRENT-STATUS.md`) |
| Instance `0x28` | ✅ **solved: it is a disconnect-with-reason (kick) message, not an identity message** (evening5). Never send it in the entry sequence |
| Character-select class display | ⚠️ open: wire format and all five numeric fields excluded by audit + live probe; the all-distinct fingerprint on the throwaway character `bbbbbb` is deployed and awaiting one look at the select screen (see open problem 2) |
| Item tables (gateway) | ⚠️ 32 tables re-exported from the 0.5.5 GGPK into staging (`ITEM-TABLES-REEXPORT.md`); deployment scheduled after the S2 readout |
| Reboot resilience | ✅ watchdog restores hosts entries and all listeners (negative-tested 2026-11-04) |
| Inventories / skill bar / gold in-area | not started (message ids in 0.5.5 not yet identified) |

## Proven protocol facts (digest; full evidence in INSTANCE-RE-NOTES.md)

- **Approach**: the client self-restores its pristine exe, so redirection
  goes through a *local patch server*: self-signed CA in the machine trust
  store, patch/login hostnames in `hosts` → 127.0.0.1, a patch stub
  (TCP 13060) + HTTPS capture (443) serving a patched exe whose only
  changes are the login key material and the login hostname
  (`local.pathofexile.com`, port 21260).
- **Instance opening is 29 bytes** (no realm byte): `u16 0x000F`, ticket
  u32 BE, `u16 0x000E`, 12-byte digest, addr u32, u32 0, u8 flag 1.
  The digest's last 4 bytes are a BE Unix timestamp; the real check value
  is the first 8 bytes = Hash(`8117a5fea309758d` ‖ Data8 ‖ timestamp) —
  it involves neither the ticket nor the key material.
- **S→C `0x11` StartEncryption is 3 bytes on the wire** (`00 11 00`): the
  client consumes one trailing byte before the encrypted stream. Getting
  this wrong desynchronizes *all* instance decryption by one byte.
- **Instance streams**: key = km[0:32], ivC2S = km[32:40], ivS2C = km[48:56]
  (Salsa20), km = the 64-byte key from login message `0x14`, verbatim.
- **HNC**: derive = instance key XOR the 64-byte mask at `0x142f10980`
  (SHA-256 `0e88f29a…7cbc31`) + six swaps; byte-verified against live
  captures. The state machine (`0x1421c55a0`) throws "HNC Protocol
  Violated" when fed garbage carrier bits.
- **id changes vs the old client build** (the fork's original assumptions):
  area = S→C **`0x1e`** (not `0x1d` — `0x1d` is now the latency **pong**,
  feeder reader R2, carrier rotation 9); tick = C→S **`0x1c`**
  (id + u32 + u8, feeder R1, rotation 14); area-generated = C→S **`0x9a`**
  (id + u8 + tile-hash u32 + doodad-hash u32, 11 bytes).
- **`0x1e` area message** (class vtable `0x1435079D8`, read `0x14211d340`):
  full field-by-field layout in the notes; the minimal form (flags 0,
  counts 0) is 47 bytes with id. Its WorldAreas key is the u16 at msg+0x1c
  (G1_1 "The Riverbank" = `0x0f14`).
- **World layer**: world message factory `0x142186c20` (method at +0x60 of
  the vtable starting `0x1435083e8`); 92 world ids catalogued. Common
  world header = 11 bytes (entity id u32 + stamp u32/u8/u16). CreateObject
  = **`0x2f7`** (read `0x141f6c5a0`): header + type-hash u32 BE +
  compact-int blob length + blob. Type hash = the fork's MurmurHash2
  variant (`ObjectTypeHash` in `InstanceEntities.cs`);
  `Metadata/Characters/Int/IntFour` → `0xa7000ea0` (computed, and the
  client accepted the value — no "unknown object type" throw).
  There is **no** SetLocalPlayer / EnterArea / wake-zone message in
  0.5.5; instance `0x21` is now a (key, flag) state sync, `0x22` a
  (key, flag) record sync, `0xc0` a one-byte message. Do not send the
  old-build spawn sequence: ids neither factory creates desync the
  encrypted stream.
- **Login layer**: S→C factory `0x14214fbe0`; `0x15` entry reader
  `0x142716700` (entry object 0x58 bytes); the six ids sharing vtable
  `0x143509F18` read u16+u32 (8 bytes with id), not u16 alone; C→S `0x0c`
  delete = wstring + u8 index + trailing u32.

## Open problems

1. **World never ticks (the current blocker).** Live-proven with the
   Frida probe: after `0x9a`, the server sends `0x2f7`; the client factory
   creates the message object and queues it — then world dispatch,
   activation (`0x14212fd90`), entity construction all fire **zero**
   times and the client sits on the loading screen. Statics (notes,
   "evening2" section): all dispatch is gated on `[world+0x84a]`, set
   only inside activation and inside the world update (`0x142130840`,
   vtable +0x448); the update lifts the gate unconditionally and would
   dispatch our stamp-0 message, so the update simply never runs for the
   instance world. The menu/background world *is* updated (7 calls
   before login in one capture); the function previously believed to
   drive updates (`0x14218bf90`) never fires at all. Missing piece: who
   registers/drives the instance world's update — candidates are an
   instance message received by a game-state listener (instance `0x23`,
   `0x28`, `0x29`, or a default-forwarded id). Investigation continues in
   the notes ("evening3" section when it lands).
2. **Class display.** Every character renders as Characters row 0
   (Marauder) on the select screen even though `0x15` carries class 1
   (verified on the wire). Mirroring the class into the entry's +0x40 u32
   (commit `5c87704`) was **tested and refuted**. Root cause not yet
   found; a from-scratch re-derivation of both the reader map and the UI's
   class source is in progress.
3. **Item layer tables** in the gateway are still older-generation
   exports; re-export from the 0.5.5 GGPK is pending (start-gear bounds
   guards are in place meanwhile).

## Contents

- `OPEN-PROBLEMS.md` — every problem currently open, what has been ruled out, and the follow-up plan for each (start there if you want to help).
- `INSTANCE-RE-NOTES.md` — the full RE log (login crypto, patch rig,
  instance protocol, HNC, world layer, activation hunt). The single most
  valuable file here.
- `frida/km_capture.js` — the Frida probe (v6): pair builder/process
  hooks, instance dispatcher, HNC feeders + throw helper, world factory /
  dispatch / activation / update hooks. `frida/run_km.py` — the poller
  that auto-attaches to `PathOfExile.exe` and logs to `km_capture.log`.
- `tools/` — the static RE toolkit (capstone disassembly, call/RIP-ref
  scanners, factory enumerators, a verified Python Salsa20 in
  `salsa_lib.py`). Scripts expect `PathOfExile.exe` (pristine 0.5.5.5)
  in the working directory.
- `data/` — derived datasets: instance dispatcher switch cases
  (`instance_switch_cases*.json`), factory read classification
  (`classify_out.txt`), the `0x15` entry reader disassembly
  (`entry_reader.txt`), a PoE2 command catalog extracted for the deck.
- `exiledeck2/` (in this folder) — ExileDeck2, the PoE2 companion app
  (Go + Fyne): talks to the gateway's command bridge on 127.0.0.1:7010,
  95 commands, item catalogs built **only** from the 0.5.5 GGPK
  (5,075 bases, 441 uniques with official TC names, 28,678 mods).

Deliberately **not** included: the game executable, GGPK data, key files
(`Tools/m1-keys.json` — the derivation is implemented in the server code
and documented in the notes), account databases, and session captures
with live key material.
