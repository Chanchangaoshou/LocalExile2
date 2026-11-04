# PoE2 0.5.5 instance protocol — RE notes (from the client binary itself)

Started 2026-11-04 after the user directed: no more adapting the PoE1 gateway; derive the
instance layer from the 0.5.5 client. All addresses are VAs in PathOfExile.exe (imagebase
0x140000000; .text VA 0x140001000, raw offset 0x400 — note: NOT 0x1000).

## Opening (live capture, 2026-11-04 08:16, gateway trace)

29 bytes: `000F <ticket u32 BE> 000E <digest 12B> <address u32> <u32 0> <flag u8=01>`
PoE1's opening was 30 bytes with a realm byte (0x40) before the flag; 0.5.5 has no realm byte.
Ticket echoes S→C login 0x14's U32_38 verbatim.

## Encryption switch (S→C 0x11)

- HNC key-pair builder: function 0x1421c52f0–0x1421c54c7; copies the 64 key bytes, XORs against
  the mask table at 0x142f10980 (bytes identical to PoE1's, SHA-256 verified), six swaps.
- Its only caller: 0x14212acc2, inside the small handler 0x14212ac80–0x14212ace5.
- That handler is called at 0x142122227 from the instance dispatcher (below), case for id 0x11.

## S→C instance dispatcher: 0x1421220f0–0x142125c78

- Message object in r8/r13; id = u16 at [obj+8].
- id == 0x12f → 0x14212428c; id > 0x12f → 0x1421242a1 (second chunk, ids 0x101..0x12f, unmapped);
  ids < 0x0d → default 0x142125628.
- Main switch (ids 0x0d..0x100): MSVC compressed tables, base = imagebase:
  byte-index table at 0x14212593c, u32 offset table at 0x1421258bc, target = base + u32[idx[id-0x0d]].
  Decoded map saved in instance_switch_cases.json.
- Dedicated cases: 0x0d→0x142123744, 0x11→0x1421221be (encryption), 0x18→0x1421236d8,
  0x19→0x142123759, 0x1a→0x14212379c, 0x1d→0x142122295 (AREA), 0x1e→0x14212269f, 0x1f→0x1421236a8,
  0x20→0x142123686, 0x21→0x142123bac, 0x22→0x142122f41, 0x23→0x14212306d, 0x24→0x142123014,
  0x25→0x142123e2f, 0x28→0x14212227f, 0x29→0x142122346, 0x5a→0x142123878, 0x6b→0x142123ebc,
  0x6d→0x142123e6f, 0xa5→0x142123a5e, 0xa6→0x142123a87, 0xb2→0x142123fa2, 0xb3→0x142124034,
  0xb4→0x142124079, 0xc6→0x14212409a, 0xc7→0x1421241a2, 0xca→0x142125665, 0xce→0x1421235a7,
  0xdc→0x1421234e5, 0xeb→0x142123959, 0x100→0x1421239d2. All other ids in range → 0x142125628
  (generic path, likely vtable-driven processing on the constructed message object).

## Dispatcher invocation

- No direct callers: the dispatcher is a vtable method. Its pointer sits at VA 0x1435078f0
  in a vtable whose neighbouring slots are 0x1421c5a50, 0x142170500, 0x14212ccb0, 0x14212cca0,
  0x14212cc90, 0x14212dd30, 0x14212dd20, 0x14212dd10, 0x14212dcd0 (the handler-group class).
- Case 0x1d starts with latency bookkeeping (u16 at [msg+0x18] vs connection fields
  +0x2250/+0x2260); the area logic is further into the case. The wire layout lives in the
  message class's read function (factory side), not in the handler.

## Opening fix (2026-11-04, commit f3ae22a)

- The fork's TryReadOpening was the PoE1 form (30 bytes, realm byte) — its regression test even
  used a 3.29.3b capture. Replaced with the 0.5.5 live capture (29 bytes, no realm); tests 11/11.
- Method from here: differential verification — the fork's formats (largely derived from the
  PoE2 client in Oct 2025 by Ehco) are the hypothesis, the 0.5.5 client is the judge; whatever
  fails gets re-derived from the 0.5.5 binary. The connection dispatcher's 0x1d case turned out
  to be only latency bookkeeping over [msg+0x18] = the seed (doc 03's field 4); the real area
  handling is the world-group handler/listener chain (doc 03).
- Doc 03 (Agents/docs/protocol/03-area-and-world.md) has the full 0x1d wire layout to verify
  against the client's reaction to the gateway's Encode() in the next live test.

## Live test 2026-11-04 09:32 — opening fixed, crypto mismatch found

- Opening parsed first try (ticket 0x091242ca); gateway sent 0x11 + 0x1d; client threw
  "Unable to deserialise packet with pid 32127. Last PID was 17" — it decrypted our 0x1d
  with a keystream starting c4bb (derived: C known, P known, P'[0:2]=7D7F).
- Ruled out by numeric probes against that keystream (all on the real secret/ticket):
  ticket-key with either IV, stream shifts 0..2048, HNC-transformed key, mask-only,
  swaps-only, SHA-512(Key64), ChaCha (3 nonce forms), Salsa ctr=1/u32/u64/ticket, /12, /8
  rounds, and a 105,600-candidate brute force of every naturally-packed struct window of
  the 0x14 fields around the key. The fork's own Salsa stream for the ticket
  (B9D9A626...) matches my reference implementation — server crypto is standard.
- Statically verified in the 0.5.5 binary: the 0x11 case (0x1421221be) builds the pair from
  [instance+0x2108]+0x38 with flag=1; pair builder 0x14219f500 IVs are km+32 (A) / km+48 (B),
  exactly the fork's arrangement; HNC builder 0x1421c52f0 = XOR mask @0x142f10980 + the six
  documented swaps; the info struct starts with the host string at +0x00 and has a mode
  byte at +0x84. The 0x14 read function (0x14214ee60) is field-for-field the server's encode.
  So the 64 bytes the client uses are NOT the 0x14 Key64 in any shifted/packed form.
- Working hypothesis: 0.5.5 keys the instance connection from the LOGIN connection's DH
  key material. Implemented (commit 38281c4): ServerHandshake exposes KeyMaterial; Auth
  stores it on the LoginLink + ticket; resolve returns it (base64); the Gateway uses it for
  the instance ciphers when Game_INSTANCE_KEYMODE=login (set in gateway-run.bat on the PC,
  backup gateway-run.bat.bak-keymode). Tests 420/420. Awaiting one live test.

## Next steps

1. Live test (KEYMODE=login): login → Play → Riverbank, or a new pid error (gateway log
   will show the "instance ciphers from LOGIN key material" line).
2. Whatever fails: find the 0.5.5 read function for that message (factory/RTTI route) and fix
   the layout from the binary, not from the old docs.
3. ~~Decode the second switch chunk~~ DONE 2026-11-04 09:33: ids 0x130..0x1f5 via byte table
   0x142125a7c / offset table 0x142125a30 (tables live in .text — the rdata mapping reads
   garbage); 18 dedicated cases + generic path; map in instance_switch_cases2.json. Special:
   id 0x24f → 0x142124f7a; ids 0x101..0x12f share a loop handler at 0x142124200 that walks a
   vector of sub-objects striding 0x210 and calls vtable+0x18 on each.
   The full 0.5.5 S→C instance dispatcher map is now decoded.
4. Then: C→S 0x7d area-generated → player entity (doc 04) → verify spawn.

## Characters table re-export (2026-11-04, deployed with 8d3815c)
- Gateway's data/tables/Characters.json was the PoE1 table (7 rows, PoE1 IntegerIds) — root cause of
  "class changes after selection": the 0x15 list sends the PoE2 ClassId (Witch 1), but the gateway fed
  the PoE1 enum into the PoE1 table and the player class byte (3) reads as Mercenary in 0.5.5.
- Replaced with an export of the 0.5.5 client's own Characters.datc64: 12 rows, IntegerId == row order
  0..11 (StrFour 0, IntFour 1, DexFour 2, StrDexFour 3, DexIntFour 4, StrIntFour 5, StrFourb 6,
  IntFourb 7, DexFourb 8, StrDexFourb 9, DexIntFourb 10, StrIntFourb 11). Validated fields: Id@0,
  Name@8, AOFile@16, ACTFile@24, BaseMaxLife@32 (16), BaseMaxMana@36 (30), WeaponSpeed@40 (606),
  MinDamage@44, MaxDamage@48, MaxAttackDistance@52 (8), IntegerId@64, Str/Dex/Int@68/72/76,
  StartingMeleeSkill@80 (array, elem 899), Description@96, StartSkillGem@104.
- SCHEMA DRIFT: repo schema sums to 612 bytes vs the dat's 640. After StartSkillGem the schema offsets
  are stale: empirically StartWeapons array header is at @168 (not @156), Gender@184, TraitDescription
  @192, and no valid StartSupportGem was found (PoE2 starts have none; exported null). Unread tail
  fields were exported best-effort with >=2^31 foreign keys nulled.
- ClassId now flows session -> TicketInfo -> ControlResponse -> Gateway RowOfClass(ClassId).
  The PoE1 enum no longer decides the gameplay class. Fallback ClassInfo = IntFour (1, 7/7/15, 16/30).
- Keystream probes live: Auth logs per-ticket "km probe" (ticket/login send+recv, 16B hex), Gateway
  logs the same per connection. With a failure pid, client keystream[0:2] = gateway Ks XOR P XOR pid.

## 2026-11-04 12:05 instance km hunt — state after full-material sweep
- Session 6 (t=0x1f504bb7, ujgfjjh): k and l captured raw via KmProbe (63970f4). pid 28931 -> Kc[0:2]=94F2 (BE) / E680 (LE). digest8=353A484E35EFC4EA, ts=0x6AEAAEDC.
- Sweeps (verified Salsa, self-checked vs gateway probes): ~45 materials from (k,l,t,secret) x all key/IV arrangements x counters 0/1 x rounds 20/12/8 x stream offsets 0..62 x BE/LE pid readings -> NO credible Kc hit. Digest: no hash/HMAC window, no keystream prefix. CONCLUSION: the instance km buffer is NOT k, l, or any plain hash combo of (k,l,t,secret). It is a fourth, client-derived value.
- Client statics verified today: pair builder 0x14219f500 = two Salsa ctors, key ptr = km base, IV ptr = km+((flag^1)+2)*16 (cipher A) / km+(flag+2)*16 (cipher B); flag=1 for client. Matches fork ConnectionCiphers exactly. Salsa ctor 0x1421a0320 -> SetKey 0x142ad7910 -> vtable 0x14350F400 slot+0x30 0x142ad7870 -> slot+0x70 UncheckedSetKey 0x142ae1ac0 (generic Crypto++ plumbing; login pair proves fork Salsa byte-matches client). Cipher is NOT the problem; the km BUFFER SOURCE is.
- km pointer = *([instance+0x2108] + 0x38); info struct X (string@+0x00, byte@+0x84 vs 7) filled by unknown code; factory chain 0x140efcead -> 0x14100b2a0 -> 0x141628d20 -> ctor 0x14211dd30. NEXT: xrefs to pair builder + instance vtable 0x1435078f0 connect method + 0x14 login handler (digest8 likely computed there or in connect/opening builder).
- Also fixed today: U16Message is u16+u32 (client class vtable 0x143509F18, read 0x14214e460 / write 0x14214e3e0) — commit 1e3ca9d; the u16-only model desynced the client after a successful character delete.

## 2026-11-04 12:10+ instance km hunt — TWO stacks; game stream is the new one
- Patch footprint diff (pristine vs played exe, done on PC): 7 ranges, ALL in .rdata 0x142f0c0d0..0x142f0c595 (login key material). ZERO code bytes differ -> RE on pristine == played client code.
- 0x14 read fn 0x14214ee60 re-read instruction by instruction: wire order Str,port,addr,hash,ticket,Key64(64B RAW read, no swap),Data8,U8 == fork encoder exactly. Client receives Key64 verbatim. X built by login handler 0x1420e9078 copies msg+0x3c..0x7c verbatim to X+0x38. Instance ctor chain moves THAT X into [instance+0x2108]; old dispatcher 0x1421220f0 (instance vtable 0x1435078f0 slot 0, verified via qword ref) 0x11 case keys pair from X+0x38 with NO transform (wrapper 0x14212ac10 -> pair builder direct).
- BUT the game connection's stream is a DIFFERENT, 0x16140-byte object: stream ctor 0x142141c30 <- wrapper W ctor F=0x1421415b0 <- instance creator 0x14100b2a0 (at 0x14100b90e). W (0xa8) is a coroutine task stored at login-session+0xf8; its ctor allocates the 15.7MB god object G (0xF000D8) and the stream; stream references G+0xF00068 (network subsystem / byte queue) at stream+0x12098.
- Stream ctor READS from that queue: u32 (ticket?) + u8 (flag) into W+0x30/+0x34, then setkey 0x142141140 reads a further blob and builds the pair (pair holder at stream+0x160c0) from the first 64 bytes of a buffer assembled from QUEUE READS. So the instance km is NOT read from X in this stack — it is DESERIALIZED from a byte queue inside G. Whoever serializes that queue (login-session play path) defines the km. NEXT: find all code referencing offset 0xF00068 and the queue-write helper (sibling of read helper 0x14021af60).
- Offline sweeps exhausted (all miss): raw/hash/HMAC/XOR/word-swap/Data8/host/X-serialization combos of (k,l,t,secret) x Salsa arrangements/counters/rounds/offsets, BE+LE pid readings. Session data: 4 sessions with (t,k,Kc), s6 also l. Scripts km_sweep3..7.py + salsa_lib.py in this dir.

## 2026-11-04 12:27 WAIT_AFTER_11 probe result (live, session t=0x7e99f69a)
- The probe finally ran for real (first deployment at 12:22 silently used a STALE exe: the probe
  code had 3 build errors — `pending` is a List<byte>, `.Length`/`.AsSpan` — and gw_build.ps1
  restarts the old binary anyway; fixed 716e26f, redeployed, VERIFIED via build output + exe mtime.
  LESSON in ~/AGENTS.md: always confirm 0 build errors AND the exe's LastWriteTime after a deploy.)
- Result: after the plaintext 0x11 the client sent NOTHING for the full 25 s hold; it simply
  waits for the area packet. => There is NO extra handshake step after 0x11 in either direction.
  The instance km is fully determined by data the client already holds at connect time.
- Session 7 also logged raw materials at the gateway: k=E49DF4CC..., l=3C86DFD3...;
  digest A2883FD54098E779 + ts 6AEAB327 (12:23 session); 12:27 digest8 = 3DBE3BE80FF7DEC2.
- More offline misses: km_sweep8 (k/l XOR login/ticket keystreams, half swaps) and km_digest4
  (plain SHA-256 / SHA3-256 / BLAKE2s / SHAKE / HMAC-SHA256 over the main concat blobs) — no hits.
- setkey (0x142141140) anatomy remains the lead: RNG object (0x14219c990) + material builder
  0x14219d1d0 (48-byte buffer) + transform 0x14219d2b0 (big frame, static-init guards, algorithm
  factory 0x1421a4f60, a vtable at 0x143606F60, sizes 1 and 0x180) feeding the G+0xF00068 queue
  and the pair builder. Agreement-shaped; resolving it needs dynamic instrumentation of the
  client during a join (break on 0x142141140 / the pair builder and read the km buffer), because
  the static call graph through the coroutine/queue machinery has resisted fragment reading.

## 2026-11-04 class display bug （野蛮人） — findings + candidate fix 5c87704
- TC Characters table verified from the client's own GGPK (EN/TC index-aligned, rowsize 640):
  row 0 StrFour = Marauder = 野蠻人， row 1 IntFour = Witch = 女巫. "Displays as barbarian" ==
  the client renders Characters row 0.
- Every 0x12 create all day sent S78="IntFourDefault", U50/U54/U58 = 0 (11 samples in auth log).
- The 0x15 entry WIRE was re-verified against the client's own entry reader (vector reader
  0x142716700, entry size 0x58): order name, league, +0x4d, +0x51, +0x4c, u32@+0x40, +0x4e,
  u16@+0x44, u16@+0x46, u16@+0x48 (level), u16@+0x4a (class), +0x4f, +0x50 — the fork's
  ListEntry15 matches exactly, and Auth sent Class=1 (Witch, correct) at 12:27.
- Yet the screen renders row 0 => the 0.5.5 character screen's class lookup evidently does NOT
  use +0x4a alone; the only unassigned id-shaped scalar left in the entry is the +0x40 u32
  (sent 0). Fix 5c87704 (deployed 12:41, Core 420/420): CharacterEntries mirrors the class row
  into U40 as well. UNVERIFIED until the user next opens the character screen.
- CharacterStartStateSet table (client GGPK): 15 sets; row 0 = "DefaultCharacters" — the
  league StartStateSet=0 we send is the correct standard set (hypothesis eliminated).
  CharacterStartStates: 109 rows, rowsize 222; @16 = Characters row; rows 0..11 = the twelve
  "...Default" states; @84=1 marks hidden/special states (rows 20/50), defaults are unflagged.
- Side observation: Play (0x0e) Index is treated by Auth as 1-based into the account list
  (Index=1 -> first character ujgfjjh at 12:27, although CharacterSelected had picked index 3
  and the Play tail carried 03) — if the client means the 0x10-selected character, Play
  resolution needs revisiting; unconfirmed either way.

## 2026-11-04 12:50 Frida capture ARMED (dynamic phase)
- Static elimination is complete for the old path: X delivery echoes (ticket/addr/Data8 fields),
  pair-builder flag = 1 (read in the 0x11 case at 0x1421221c5: byte [rbp+0x678] = 1), IV layout,
  Salsa identity (login interop). The digest is Hash(const8=0x8117a5fea309758d || Data8 ||
  timestamp u32) per the opening builder at 0x14211fb00 — it does NOT involve Key64/ticket
  (same design as PoE1 doc 010), so it was a red herring for the km.
- Frida 17.25.1 installed in D:\LocalExile\.venv on the PC. Runner
  C:\Users\<winuser>\AppData\Local\Temp\run_km.py (WMI-detached, polling) auto-attaches to
  PathOfExile.exe; script km_capture.js hooks pair_builder 0x14219f500 (caller-tagged:
  login 0x1420e8388 / instance 0x14212ac52 / setkey 0x14214126a / HNC 0x1421c53f9) and the
  instance wrapper 0x14212ac10, logging flag + 64 km bytes to km_capture.log.
- Gateway restored to TICKET keymode (KEYMODE line removed from gateway-run.bat) so the
  server's expected km = the 0x14 Key64 for the capture session.
- Next: when the user next logs in + Play, read km_capture.log: if the instance km == Key64,
  hook the cipher ProcessData/state next; if not, the captured bytes identify the true source.

## 2026-11-04 13:22 FRIDA CAPTURE #1 — KM VERIFIED CORRECT (breakthrough)
Session ticket=0x31eb0e36, client pid 32324, base 0x7ff6ff8c0000.
- LOGIN pair (caller 0x1420e838d): km = F7F9C619... == gateway l (byte-exact).
- SETKEY pair (caller 0x14214126f): km = D1AA99FD... + trailing zero bytes (local DRBG material, as predicted).
- INSTANCE pair via wrapper 0x14212ac10 (caller 0x14212ac57): km = F5C685CF... == gateway k
  (the 0x14 Key64) BYTE-EXACT. flag = 1 everywhere.
- HNC pair (caller 0x1421c53fe): km = 0111FAE6... (DeriveKey output, differs as expected).
=> Key delivery is PROVEN correct end-to-end. The divergence is inside cipher
   construction/installation/use (which cipher decrypts, IV assignment, counter/state).
- install_A (0x142198680): moves the pair into stream+0x1b8 and immediately runs the pair's
  vtable+0x10 process method over the stream's buffered bytes (ring at +0x258..+0x2a0).
- Still failed live (client exited ~13:23:26, usual pattern; no pid line flushed to Client.txt).
- Capture v2 armed 13:25 (km_capture.js): on the INSTANCE pair_builder return, dumps the pair
  object graph and extracts Salsa states (scan for 0x61707865); dynamically hooks the pair
  process method (vtable+0x10) and logs in/out bytes (XOR = the true keystream).
  Runner now re-reads the JS on every attach. ONE more user Play gives the decisive data.

## 2026-11-04 13:29-13:36 ROOT CAUSE FOUND + FIXED: 0x11 has ONE trailing byte in 0.5.5
Frida capture v3 (session ticket 0x08727e2d, k=853CCE80...):
- pair_process on the instance pair: client applied keystream Kc over a 38-byte buffer.
  Kc == gateway ticket-send keystream Salsa(k, k[48:56]) BYTE-EXACT (38/38, python-verified).
  => CRYPTO FULLY CORRECT (key, IV, counter, Salsa — all confirmed live).
- The decrypted buffer == wire[1:39] (python-verified): the client consumed ONE byte between
  the 0x11 and the encrypted stream, then decrypted the rest from keystream position 0.
  Garbage pid 0x6eeb follows exactly.
- Retro-proof: 12:04 session (login keymode, actual pid 0x7103): model (wire from l, client
  ks from k, 1-byte shift) predicts 0x7103 EXACTLY; no-shift model gives 0x653f. Root cause
  holds across sessions and keymodes. (All those months of keystream mismatch = this 1 byte:
  every earlier Kc derivation assumed decryption started at wire[0].)
- Bonus: the two INSTALL:p1 Salsa states confirm key=km[0:32], IVs km[32:40] (+ a second state
  differing in one IV word — moot now).
- FIX (commit 5e1c783): InstanceProtocol.StartEncryption() now emits 00 11 00 (trailing byte
  value 0; the 0x11 dispatcher case ignores the body). Test updated. Deployed 2026-11-04 13:35:
  Core 420/420, Gateway rebuilt (exe mtime 13:35:04 verified) + restarted, Auth rebuilt +
  restarted, all ports listening. Frida stays armed — the next Play's pair_process should show
  the 0x1d decrypting to 001D... as independent confirmation.

## 2026-11-04 13:40 session — "HNC Protocol Violated" after the 0x11 fix (analysis 13:45–14:05)

- Session (ticket 0x1559d7f1, bbbbbb): gateway sent ONLY 0x11 (3B) + 0x1d; read total stayed 29 B
  (opening only) for 44.9 s; client decrypted the 0x1d exactly (Frida pair_process n=6), showed the
  Riverbank loading screen, then threw the "HNC Protocol Violated" exception dialog (user screenshot).
  NO 0x1b received, NO 0x1c ever sent. Client sent nothing at all after the opening.
- HNC statics (0.5.5 binary, all verified by disassembly):
  - "HNC Protocol Violated" at VA 0x143513238 is the exception TYPE NAME; getter fn 0x1421c52e0;
    exception ctor 0x1421c5780 (vtable 0x143513250); throw helper 0x142c14380.
  - The ONLY throw sites are inside the HNC byte state machine **0x1421c55a0** (throws at
    0x1421c5724 bad type byte / 0x1421c574b zero length). Channel state: [ch+0]=pair,
    +0x54 bit count, +0x58 length, +0x59 type, +0x5c fed byte. It decrypts each fed byte with the
    pair's vtable+0x10 Process (len 1); idle byte must decrypt to 0, else 0xDA–0xDD + len + payload.
  - State machine callers = EXACTLY 8 sites in 4 message read functions (the "feeders"):
    * R1 0x141f48a50 (vtable 0x1434e5aa8): body u8@+0x1c, u32@+0x18 PURE carrier, feeds bits
      14..31 then 0..13 (rotation 14). Client SENDS this class as id **0x1c** from the instance
      session's latency method (~0x1421212xx): u32@+0x18 = counter, u8@+0x1c = clamped queue byte;
      write fn 0x141f48870 composes the u32 ENTIRELY from the HNC send-channel bit source.
    * R2 0x141f48de0 (vtable 0x14350af18): u16@+0x18, u16@+0x1a, u32@+0x1c carrier rotation 9 —
      the PoE1-style pong layout (the fork's Pong/NextIdleU32 matches THIS class, id unknown).
    * R3 0x141f49210 (vtable 0x1434e5498) / R4 0x141f49650 (vtable 0x1434e5398): item messages,
      u32@+0x18 data field with carrier bits 20..29 (R3) / 21..29 + mask 0xc01fffff (R4),
      + u32@+0x1c + 3 u8s (doc 13 family).
  - HNC pair builder 0x1421c52f0 sits right after the state machine; mask VA 0x142f10980,
    DeriveKey verified byte-exact vs the live Frida capture (13:40 session).
- Paradox: with zero carrier-bearing traffic, the state machine still threw during area loading.
  Leading hypothesis: the 0.5.5 **0x1d read function consumes a different byte count than the
  fork's PoE1-derived Encode (39 B)** — the stream desyncs inside/after the 0x1d, leftover bytes
  get parsed as a bogus message (possibly an R1/R3/R4 class) whose "carrier" bits feed garbage.
  This also explains why the client never sent a single byte after the opening (pump desynced).
  The 0x1d class does NOT match the common vtable shape (slot0 0x14015c940/0x1408a3250):
  a full-.rdata sweep found no read fn with a wstr call + many reads under that shape.
- Frida capture script upgraded to **v4** (PC km_capture.js, SHA-256 5c6134ab…, hash-verified):
  hooks the instance dispatcher (logs every dispatched id), all four feeder readers (entry caller
  + field values), the state machine (fed byte + state + feeding caller VA), the throw helper,
  and R1's write fn. Next client run will name the exact feeder and message.

## RESOLVED 2026-11-04 14:08–15:35 — HNC throw root cause + the real area message 0x1e

- The v4 capture of the 14:08 session (ticket 0x74e46fcc, character yyyyyy) is decisive:
  pair_process decrypted our 39-byte packet exactly, then `reader_in R2` fired on the instance
  stream, `hnc_feed n=1 byte=0 from 0x141f48ed7` (inside R2's read fn), then `throw_call from
  0x1421c574a`. Exactly one garbage feed from OUR OWN packet.
- Root cause: **in 0.5.5, S→C id 0x1d is the R2 latency pong class, not the area message.**
  Proven by decoding the S→C instance factory 0x142170500 (switch: eax = id − 0xd, cmp 0x35e,
  jump table 0x1421731dc, 317 unique targets; scripts factory_scan.py / classify_reads.py /
  field_map.py): case 0x1d → alloc 0x20, vtable 0x14350af18 (R2). The client parsed our "area"
  bytes as u16+u16+u32 carrier and fed the carrier bits into the HNC state machine.
- The real area message is **S→C 0x1e**: class vtable 0x1435079D8, ctor 0x142151850,
  read 0x14211d340, write 0x14211cb00, alloc 0x1a0; dispatcher handler 0x14212269f throws
  "Instance sent world area that does not exist" (string 0x143507f80) when the WorldAreas
  lookup of the u16 at +0x1c fails. 0x1e wire layout (body order): U8(+0x10), U32BE
  InstanceId(+0x18), U16BE AreaHash(+0x1c), WStr league(+0x38, via 0x141cfb540 = LoginWriter.WStr
  format), U32BE Seed(+0x20), U8(+0x2a dflt 3), U8(+0x2c dflt 0), U8(+0x2b dflt 2), U8(→+0x30
  dflt 0x23), 3 flag bytes(+0x2d..2f), U8 Level(+0x28), U8(+0x29), U8(→+0x34 dflt 0x39),
  U32BE(+0x24), then flag-gated/Counted vectors: [flags0&8: U16 second hash], vec16<u32>@+0x70,
  vec16<u8-as-u32>@+0x88, u8-counted bytes@+0x58 (achievement sets), vec16<u16>@+0xe8,
  unconditional block@+0x100 (helper 0x14212a9a0: u8 count × 8-byte elems), vec16<u16>@+0x118,
  [flags1&1: bytes@+0xa0], [flags1&2: u8s@+0xb8], [flags1&4: block@+0xd0 terrain, helper
  0x14212aa70], [flags0&0x80: pair-list objects @+0x130/+0x150 via 0x1423bacb0 + vec@+0x170 of
  0x20-byte objects], [flags1&8: block@+0x188]. Minimal packet (flags 0, counts 0) = 47 bytes
  with id. The 0x1e read fn contains NO HNC feeder calls.
- Id corrections for 0.5.5: C→S tick = **0x1c** (R1 class), S→C pong = **0x1d** (R2 class; the
  fork's Pong field layout already matched R2). S→C 0x29 = instance transfer (read 0x142152020,
  handler 0x142122346), not first area. Fork's AreaGeneratedId 0x7d is still UNVERIFIED for
  0.5.5 — identify the client's post-generation message from the next session's logs/Frida.
- Fix deployed 2026-11-04 14:31 (commits b883faa, 2e550f4, 6b51748; fork + PC at 6b51748):
  AreaInstanceId 0x1e with Encode rewritten to the layout above; TickId 0x1c; PongId 0x1d;
  PacketHistory.Kept now uses TickId; framing fixtures moved from 0x1b to 0x1c ticks.
  LeagueStats pair lists and the terrain block have no verified 0.5.5 encoding: Encode throws
  NotSupportedException for them instead of emitting the old format. Core 422/422, Data 34/34
  on the PC; Gateway.Tests has 386 pre-existing data-environment failures (parent commit
  5e1c783 fails the same classes; Program.Stats catalog key missing on this checkout) —
  unrelated to the protocol change.

## 2026-11-04 14:40 session — 0x1e ACCEPTED; next blocker = world/entity layer
- Live proof: gateway sent the new 47-byte 0x1e; Frida pair_process n=6 decrypted it exactly;
  NO R2 reader, NO hnc_feed, NO throw. The client generated the Riverbank (~2 s) and sent
  C->S **0x009a, 11 bytes: 009A 00 EA9763D7 FB86522D** (id + u8 + 2x u32 hashes = the 0.5.5
  "area generated" message; fork's AreaGeneratedId is still 0x7d/10 bytes — must remap to
  0x9a/11). Client then sent nothing more: it waits for the player sequence. Gateway logged
  the 0x9a as "unframed" (no KnownClientLength). User-visible result: stuck on loading screen.
- The fork's post-generation sequence (SendPlayer in Program.Player.cs) is all OLD ids:
  0x1f6, 0x22 SetLocalPlayer, 0x2b9 CreateObject, 0xc0 inventories, 0x3d, 0x21 EnterArea,
  0x1a9 wake zone, 0x2b9 objects, 0x1b3, then gold 0x2a9, cosmetics 0x1f3, skillbar 0x53,
  model 0x2ba... In 0.5.5 the instance factory (0x142170500) does NOT create the world ids
  (0x2f7/0x2ba/0x1f3/0x1a9/0x2a9 all hit its default case 0x1421731c0 = return input).
  Instance 0x22 is a different message now (U8 + U8 count + count x 0x28B elements + wstr
  helper; read 0x142157b50). Instance 0x21 read (0x14215aac0) = U8 + vec16<u16> + vec<u8>;
  its handler 0x142123bac merges the u16 list into session state (stride-0x406 array lookups).
- WORLD DISPATCHER FOUND: **0x1421343c0** (rcx = world object, flag at +0x84a; rdx = msg).
  Switch tree on id at [msg+8]: explicit cases incl. 0x1f3 -> 0x142134b32, 0x2ba -> 0x142134dbb
  (same ids as the old build's world group!), sub-switch ids 0x2f7..0x302 via jump table at
  0x1421363f0 (i32 offsets from imagebase). **CreateObject = id 0x2f7** (handler 0x142134ec7):
  msg +0x10 u32 = entity id, +0x20 u32 = object type hash -> registry lookup 0x141693840 via
  [world+0x4a8]+0x28 (null -> throw "Unknown object type serialized by server" @0x143508260,
  ref at 0x14213639d), +0x28..+0x30 = component blob span, entity ctor 0x141e705d0.
  Other sub-switch handlers: 0x2f8 -> 0x1421354e2, 0x2fc -> 0x142135953, 0x2ff -> 0x1421359e0,
  0x300 -> 0x142135c3f, 0x302 -> 0x142135c9e, rest -> default 0x142134d54.
- World messages are QUEUED on the world object (queue +0x6b8..0x6c8, entries {obj*, u32@+0x14,
  u8@+0x18, u16@+0x1a}) and drained per frame by 0x142130360 / 0x142130840 when the entry's
  fields match [world+0x678]/[+0x67c]/[+0x67e]. World dispatch callers: 0x14212fdf9 (in fn
  0x14212fbc0), 0x1421303c1, 0x1421308ab/b5c/bc3/c4c, 0x142137356/512.
- Instance session vtable actually starts at **0x1435078e8**: slot0 = factory 0x142170500,
  slot1 = dispatcher 0x1421220f0 (pointer refs prove it).
- OPEN: world factory location (creates 0x2f7 etc. before queueing); 0x2f7 read fn / wire
  layout; SetLocalPlayer equivalent in 0.5.5; wake-zone (old 0x1a9) equivalent; whether the
  world dispatcher switch kept old ids for the whole SendPlayer sequence (0x1f3/0x2ba suggest
  yes for world group); the 0x21 handler's exact expectations (does IT create/enter the player
  once objects exist?).

## 2026-11-04 晚 — 世界层逆向（world factory / dispatcher / 0x2f7 / spawn 序列提案）

目标：0x1e 之后客户端回 C→S 0x9a 并等 spawn 序列；fork 旧序列（0x22/0x2b9/0xc0/0x21/0x1a9/0x2a9…）在 0.5.5 全错。本节为纯静态逆向结论（反汇编实证，除非标注推断）。

### 1. WORLD FACTORY = 0x142186c20（已实证）

- 签名：`factory(rcx=world-ish ctx, rdx=&out, r8w=id, r9=stream)`。入口清零 out；公共尾 0x142188660：释放 out 旧对象 → 调新对象 vtable slot2(+0x10) = read fn 读线。未识别 id → out 保持 0（不读线）。
- 它是世界对象 vtable 的方法：指针在 **0x143508448**，vtable 起点 **0x1435083E8** 的 **+0x60** 槽（已回读验证）。同 vtable 已对位：+0x198=0x142136670（CreateObject handler 内被调）、+0x1B8=0x142133a30（handler 们经此取实体图 accessor）、+0x278=0x14212fd90（见 §2 激活函数）、+0x218=0x140b27b60（0x1f3 handler 末调）、+0x220=0x14010a080（通用空桩，0x1f2 handler 末调在此类上是 no-op）。无直接 caller（经 vtable 调用）。
- 结构三段：Chunk A（id≤0x181，仅 0x64/0x65/0xa3/0x181 有 case，其余返回 0）；Chunk B（0x181<id≤0x2ba，0x2ba 独立 case + MSVC 压缩 switch 覆盖 0x1ae..0x2a6，字节表 0x1421887A8/偏移表 0x142188694）；Chunk C（id>0x2ba：0x2e7..0x324 压缩 switch，字节表 0x1421888FC/偏移表 0x1421888A4）。
- **世界消息目录（92 个 id，逐 case 解析：alloc 大小/vtable/read fn 已抽样核对）**：
  0x64, 0x65, 0xa3, 0x181, 0x1af, 0x1b0, 0x1b1, 0x1b2, 0x1c5, 0x1c6, 0x1c7, 0x1c8, 0x1c9, 0x1ca, 0x1cb, 0x1cc, 0x1cd, 0x1ce, 0x1cf, 0x1d0, 0x1d1, 0x1d2, 0x1d3, 0x1d4, 0x1d5, 0x1d6, 0x1d7, 0x1d8, 0x1d9, 0x1da, 0x1db, 0x1dc, 0x1dd, 0x1de, 0x1df, 0x1e0, 0x1e1, 0x1e2, 0x1e3, 0x1e4, 0x1e5, 0x1e6, 0x1e7, 0x1e8, 0x1e9, 0x1ea, 0x1eb, 0x1ec, 0x1ed, 0x1ee, 0x1ef, 0x1f0, 0x1f1, 0x1f2, 0x1f3, 0x1f8, 0x1f9, 0x1fa, 0x1fb, 0x1fc, 0x1fd, 0x1fe, 0x222, 0x223, 0x26f, 0x270, 0x295, 0x296, 0x2a4, 0x2a5, 0x2a6, 0x2ba, 0x2ef, 0x2f4, 0x2f5, 0x2f7, 0x2f8, 0x2f9, 0x2fa, 0x2fb, 0x2fc, 0x2fd, 0x2fe, 0x2ff, 0x300, 0x302, 0x30e, 0x316, 0x318, 0x319, 0x31b, 0x324。
  **注意：0x1a9、0x2a9、0x2b9 不在此列**（双 factory 均不创建，见 §4）。
- 接收路径（架构已实证/细节推断）：会话泵先过 instance factory 0x142170500（其 default 把 stream 原样返回），世界组 id 落到世界对象 vtable+0x60 创建 → 对象进世界队列 **world+0x6b0..0x6b8（写指针）、+0x6c8（读指针）**（队列条目=裸 msg 指针；push 的确切指令未定位——推断）。游戏循环经 0x142130360 / 0x142130840 / 0x142137270 排空：仅当 msg 头 stamp 字段（+0x14 u32 / +0x18 u8 / +0x1a u16）分别等于 [world+0x678] / [world+0x67c] / [world+0x67e] 时才派发到 dispatcher 0x1421343c0（每帧按当前 area-object id [rbp+0x88] 查三张集合选队列）。dispatcher 入口有重入门 [world+0x120]，且 **[world+0x84a]==0 时直接返回什么都不做**。
- **世界激活函数 0x14212fd90**（world vtable +0x278）：置 [world+0x84a]=1 → 把队列全部消息依次过 dispatcher → 逐个释放 → 清队 → [world+0x84a]=0、[world+0x86a]=1 → 遍历 [world+0x5b8] 实体向量做注册收尾。唯一直接 caller = 0x1416820ac（在无直接 caller 的游戏状态回调 0x1416820a0 内，其后处理 UI/状态字段 [rbx+0x1270]/[+0xfc8]）。**结论：0.5.5 的世界激活由客户端自身游戏状态流触发（区域生成完成→进入 in-game 态），没有服务器 "enter area" 消息**（与 §4 的 0x21 结论互证）。

### 2. 通用世界头（每个世界消息的 read 都以此开头，已实证）

base read = **0x141f4b800**（类 vtable 0x14350C150，alloc 0x20 的公共类被 0x65/0x181/0x1b1/0x1c5/0x1c6/0x1c7/0x1ca/0x222/0x2fa 共用；写侧 0x141f4b740）：
U32BE→**+0x10 entityId**；U32BE→**+0x14（队列 stamp u32）**；U8→**+0x18（stamp u8）**；U16BE→**+0x1a（stamp u16）**。**共 11 字节**（旧版是 10 字节：旧版 +0x18 是 u16、无独立 u8——线格式已变）。stamp 三件套就是队列排空的匹配键；世界对象构造时为零初始化（推断）→ 服务器发 spawn 消息时 stamp 全填 0（推断，待实测）。

### 3. WORLD DISPATCHER 0x1421343c0 完整 case 图（已实证）

一级（id=[msg+8]）：
- **0x2ba → 0x142134dbb**：组件数据批量更新（见 §5.4）。
- **0x1f3 → 0x142134b32**：表项施加于实体列表（见 §5.3）。**不是 SetLocalPlayer**。
- **0x1f2 → 0x142134471**：网络对象描述符登记（见 §5.5）。
- **0x181 → 0x142134991**：[world+0x666]!=0 时清两组范围（重置味）；消息本体仅通用头。
- **0xa3 → 0x1421349ed**：读 msg 两字节 +0x20/+0x21 与 [world+0x5b0] 子对象 → 0x1421065a0(entity, …)。
- **0x1fd → 0x142134daa**：U8 [msg+0x20] → [world+0xc4]，随后落 generic。
- **0x1fe → 0x142134d14**：world vtable+0x200(world, [msg+0x20] u8, [msg+0x21] u8)；[world+0x5b0]!=0 时再调 0x14018a170。
- **0x2f7..0x302 → 跳表 0x1421363f0**（i32 相对偏移）：0x2f7→**0x142134ec7 CreateObject**；0x2f8→0x1421354e2（创建变体：按 [msg+0x20] 另一实体 + 两向量做对象构造/登记 +0x850 表）；0x2fc→0x142135953（实体组件向量操作）；0x2ff→0x1421359e0、0x300→0x142135c3f、0x302→0x142135c9e（均以 U16@[msg+0x20] 查 0x141e7e4c0/0x141e7e580/0x141e7e2e0 系 area-object 表）；0x2f9/0x2fa/0x2fb/0x2fd/0x2fe 落 generic（见下 B2）。
- 其余全部 → **generic 0x142134d54**：先按 [msg+0x10] 查实体图 world+0x6e0（0x141e721b0），查不到静默丢弃；查到后分发：
  - id==0x64/0x65 或 0x2e7 → 0x142134d92：0x14014e870(entity)→组件，0x1421497c0(组件, msg) 前转（下称 **FWD-A**）。
  - id==0x1ae → 0x1421360f1：0x14014fe20(entity) 后落共享尾 0x1421360d9（**FWD-B**）。
  - 0x1ae<id≤0x2a6 → 压缩子 switch B1（字节表 0x14213647c/偏移表 0x142136440）：0x1af,0x1b0,0x1b1,0x1b2,0x26f,0x270→FWD-B(0x1421360f1)；**0x1c5→0x142135d1b**（0x141e717a0(entity,0)，移除/消散味）；**0x1c6→0x142135d2a**（entity+0x8d|=4 并插入实体图——“实体登记/激活”）；**0x1c7→0x142135d45**（清 +0x8d 的 4 位并移出实体图）；0x1c8..0x1ce,0x1d8..0x1dc,0x1f9..0x1fc,0x222,0x223,0x295→FWD-A；0x1cf,0x1d0,0x1d1,0x296→0x142135d60（FWD-C：0x14014ef40→0x141d8ea60）；0x1d2,0x2a4,0x2a5,0x2a6→0x142135d90；0x1d3..0x1d7→0x142135da8；0x1dd..0x1ea（除 0x1e4）,0x2ef→0x1421362b0；0x1e4→0x142135dc0；0x1eb,0x1ec,0x1ed→0x142135d78；0x1ee,0x1ef,0x1f0→0x142135ed6；0x1f1→0x14213606c；0x1f8→0x1421360d1（同 FWD-B 尾）；其余 B1 区间（0x1b3..0x1c4、0x1f4..0x1f7、0x1ff..0x221、0x224..0x26e、0x271..0x294、0x297..0x2a3）→ 出口（查完实体后忽略）。
  - 0x2e7<id（0x2ef..0x324）→ 压缩子 switch B2（字节表 0x142136598/偏移表 0x142136574）：0x2f9→0x142136123（取 msg span @+0x20，首字节=组件下标 → 实体组件 vtable+0xb0(span)——通用组件 blob 更新）；0x2fa→0x142136219；0x2fb→0x142136293；0x2fd→0x142136166（按 [msg+0x20] 查另一实体）；0x2fe→0x1421361ee；0x30e,0x316,0x318,0x319,0x324→FWD-A；0x31b→0x1421362c1；其余 → 出口忽略。
  - id<0x1ae 且非 0x64/0x65 → 出口忽略。

### 4. 旧序列关键消息在 0.5.5 的下落（逐项已实证/证伪）

- **SetLocalPlayer（旧 S→C 0x22: u32 entity）— 不存在对应消息。** instance 0x22 是完全不同的消息（factory case 0x142171014，alloc 0x80；read 0x142157b50 = U8 + vec16<u16> + vec<u8> 的 0x28 字节记录向量；handler 0x142122f41 把记录与会话表 [session+0x48] 逐项匹配、写 +0x181/+0x39d4 状态字节——状态同步族，与 0x21 同味）。世界组里没有任何“裸 u32 指定本地玩家”的类；CreateObject handler 0x142134ec7 全程**不做** entityId 比对（旧版靠 0x22 存 world+0x980 再在 0x2b9 内比对，0.5.5 无此机制）。CreateObject 对每个对象都广播事件 **0xe794fcda**（0x1421f3090，载荷 {entity, 1}）。**推断**：本地玩家由客户端在激活/UI 绑定阶段（0x1416820a0 回调后段）按 Player 组件/自身角色身份自行认领，或经 CreateObject 阶段二传入的上下文对（world 数据字段 +0x1b8/+0x1c0，0x141e71010(entity, &pair) 消费）确立。**服务器侧无需也不能发 SetLocalPlayer**（待实测验证：只发 0x2f7 后玩家是否可控）。
- **EnterWakeZone（旧 0x1a9: u32 entity）— 不存在**（双 factory 均无 0x1a9；dispatcher 无）。且旧 0x21 handler 的“激活世界+取本地玩家 Player 组件”职责在 0.5.5 由客户端内部激活 0x14212fd90 接管。最接近的服务器可发消息是世界 **0x1c6**（通用头のみ：把已创建实体登记进实体图，见 §3）；CreateObject 本身在 blob 对象标志（entity +0x8d & 4）满足时已自动登记。spawn 时先不发，失败再试 0x1c6（见 §6）。
- **AddInventory（旧 0xc0）— 证伪。** 0.5.5 的 instance 0xc0：alloc **0x18**，ctor 0x1421621f0 只在 +0x10 放一个 0 字节，vtable 0x1434e5158，read 0x141f3d8d0（单字节级消息）；instance dispatcher 对 0xc0 走 generic 0x142125628。**绝不是背包消息**。0.5.5 真正的背包消息 id 尚未逆（不在本轮范围）；首测不要发任何 0xc0 冒充背包——会污染流。
- **Gold（旧 0x2a9: u32 amount）— 不存在**（双 factory 均无 0x2a9；dispatcher 无）。金币在 0.5.5 的承载消息未定（疑在背包/状态同步族内，需另轮逆向）。
- **instance 0x21（旧 EnterArea）— 已改作他用，不要发旧格式。** read 0x14215aac0（alloc 0x50）：U8→+0x10；U16BE count N（临时）；U16BE→+0x18；N×U16BE→向量 +0x20；同 N×U8→向量 +0x38。handler 0x142123bac：逐 i 以 vec16[i] 为下标查会话侧 **0x406 字节定长记录表**（对象经 0x14060e0e0 取 +0x28 表基址），flag=vec8[i]：非 0 → 0x141e75970（置位型操作）、0 → 0x141e75ed0（清位型操作），结果都追加进 [session+0x2348] 向量。**语义 = (key, flag) 状态对同步**（任务/遭遇状态旗推断），与进图激活无关：不调 0x14212fd90、不设会话状态 3（已读部分内）。fork 旧 `EnterArea` 最小形（0021+14 字节零）**禁止再发**。
- 顺带探针（instance factory 跳表）：0x1f6 仍有 case（0x142171cb1，藏宝图解锁族存续）；0x228 有 case（0x142171ed1，Delve 存续）；**0x3d、0x53、0x1b3、0x40 均为 default（不存在）**——旧序列的 atlas 预设(0x3d)/技能栏(0x53)/属性快照(0x1b3) 在 0.5.5 无对应 instance 消息。**凡双 factory 都不创建的 id 一律不要发：泵只消费了 id、body 无人读 = 加密流错位**。

### 5. 线格式（read fn 逐字段，已实证）

#### 5.1 世界 0x2f7 CreateObject —— 类：alloc 0x40，vtable 0x14350C4F0，read 0x141f6c5a0，write 0x141f6c540（写侧已对读侧互证）
1. u16 id = 0x02f7（泵读）
2. 通用头 11B：U32BE entityId→+0x10；U32BE stamp→+0x14；U8 stamp→+0x18；U16BE stamp→+0x1a
3. U32BE **typeHash→+0x20**
4. **compact-int blobLen**（0x1408719a0：<0x80 一字节；否则 0x80 标记 + 后续字节拼大端尾数）——**与旧 0x2b9 的 u16BE blob16 不同！**167 字节 blob 的前缀 = `80 A7`
5. blobLen 字节裸 blob → span +0x28..+0x30
handler 0x142134ec7：[world+0x4a8] 注册表按 typeHash 查（0x141693840(rec+0x28, &out, key)），查不到 → 抛 "Unknown object type serialized by server"（串 @0x143508260）；实体 ctor 0x141e705d0(obj, &typeInfo, entityId, &blobSpan, world)；组件标志决定登记实体图/组件回调；广播事件 0xe794fcda；阶段二用 {[world+0x1b8],[world+0x1c0]} 调 0x141e71010 做实体初始化，并查 +0x850 描述符表（0x1f2 登记的）补空间参数。

#### 5.2 世界 0x2f8（创建变体）——alloc 0x58，vtable 0x14350C350，read 0x141f6c7a0
通用头；U32BE→+0x20（关联实体 id，handler 以此查实体）；U8→+0x24；变长元素向量→+0x28..；compact-int + 第二向量→+0x40..。spawn 首测不需要。

#### 5.3 世界 0x1f3 —— alloc 0x40，vtable 0x14350C310，read 0x1421860a0
通用头；vec16<u32BE>（0x141f4d030）→+0x20 实体 id 列表；U16BE→+0x38 表下标；U8→+0x3c。handler：以 +0x38 下标查 0x3c 定长表（0x141635160），收集实体 → world vtable+0x218(world, &表项, &实体向量, 0, 1)。语义=“把表项 N 套到一批实体上”（旧版 fork 拿它发 cosmetics 0x1f3——结构巧合，0.5.5 语义未定，首测不发）。

#### 5.4 世界 0x2ba —— alloc 0x68，vtable 0x14350C290，read 0x141f4bc80（尾部向量段未逐指令读完，标注部分实证）
通用头；U8 **类型字节→+0x20** 决定载荷形：type1→compact-int→+0x24；type3→compact-int→+0x24 + U16BE→+0x28 + U8→+0x2a；type4→compact-int→+0x24 + U32BE→+0x28 + U16BE→+0x2c；type8/9→0x141cfc160 结构读→+0x24；之后共通：U32BE→+0x30；U8 位域字节驱动 +0x38 处 0x48 字节记录向量（条数由位域推导）；+0x50 处 0x10 字节 {u64, u32 entityId} 条目向量。handler 0x142134dbb：0x142132190(world, msg+0x20) 解析目标对象 → 按条目把记录配到各实体 → 0x141d7af90(对象, [msg+0x30], &配对向量)。语义=组件数据批量更新（旧版是单实体 Player 组件更新，0.5.5 已变批处理形）。spawn 首测不需要。

#### 5.5 世界 0x1f2 —— alloc 0x38，vtable 0x14350C4B0，read 0x142185e70（全长 27 字节）
通用头；U16BE→+0x20（表 A 下标）；U16BE→+0x22（表 B 下标）；U32BE→+0x24；U8→+0x28；U8(bool)→+0x2c；U32BE→+0x30。handler 0x142134471：以两下标查 0xbf/0x8f 定长表（[world+0x5b0] 系 getter），组装 0x30 字节记录插入 world+0x850 表（0x1421376a0），再调 world vtable+0x220。语义=为实体登记“网络对象描述符”（area 物件/传送点等由客户端本地表驱动外观）。玩家 spawn 不需要；CreateObject 阶段二查不到记录时跳过（已实证）。

#### 5.6 世界 0x181 —— 公共类，通用头のみ（13 字节总长）。0x64/0x65 同为公共类（头のみ）。

### 6. 提案：C→S 0x9a 之后的服务器发送序列（新角色 1 级，G1_1 河岸，area hash 0x0f14）

前置改造（网关侧）：AreaGeneratedId 0x7d→**0x9a**，KnownClientLength 10→**11**（0x9a 线形 = `009A` + U8 + 两个 u32 哈希，14:40 实测）。

只发一条（最小 spawn）：
```
S→C 世界 0x2f7 CreateObject(玩家):
  02 F7                                  id
  00 00 10 00                            entityId = 0x1000 (fork 既有 PlayerId)
  00 00 00 00  00  00 00                 stamp 三件套 = 0（推断：世界初值 0）
  A7 00 0E A0                            typeHash = MurmurHash2("Metadata/Characters/Int/IntFour") = 0xa7000ea0
                                         （推断：0.5.5 注册表键沿用旧 MurmurHash2-seed0；fork 的 ObjectTypeHash 算法与旧版一致且路径取自 0.5.5 Characters.dat 重导出的 IntFour 行。查不到键客户端会抛 "Unknown object type"——Frida throw 钩子可判）
  80 A7                                  compact-int blobLen = 167
  <167B 组件 blob>                        直接复用 fork 现有 player blob（PlayerForCreation/DevWitch 形）作为起点假设
                                         （未证：组件顺序/各 read fn 在 0.5.5 是否与旧版逐字相同——本轮未验实体 ctor 0x141e705d0 的组件读取环，是本提案最大风险点）
```
总长 = 2+11+4+2+167 = 186 字节（blob 长度随 fork 实际生成而变，前缀按 compact-int 规则重算）。

明确**不要发**（旧序列删除清单）：0x22（异物消息）、旧 0x21（已改作状态同步）、0xc0（单字节异物）、0x2a9（不存在）、0x1a9（不存在）、0x3d/0x53/0x1b3（无 factory case，发了错位）、0x1f6（存续但与 spawn 无关，押后）、传送点/waypoint/怪物等其他对象（同走 0x2f7，但等玩家本体先通）。

若只发 0x2f7 后玩家仍不可见/不可控，按序排查（均为推断阶梯）：
1. blob 对象标志字节：CreateObject 登记实体图要求 entity +0x8d & 4，该位由 blob 首字节标志经 ctor 映射——先试 fork blob 现状，再试置位变体；或补发世界 **0x1c6**（`01 C6` + 通用头 entityId=0x1000/stamp 0，共 13 字节）强制登记。
2. 激活未触发：Frida 钩 0x14212fd90 看 0x9a 后是否被调；若从未调，说明还差一个客户端状态前置（候选：0x1e 里某字段、或 instance 组某消息），需再逆 0x1416820a0 回调的触发条件。
3. typeHash 查不到（Frida 见 throw 0x142c14380 且串为 Unknown object type）：改以客户端注册表实测为准（钩 0x141693840 打印全部登记键或从数据表加载函数 0x141ec18c0 同族逆 Murmur 变体）。
4. blob 解析中途 Buffer Underflow/崩溃：逐组件比对 0.5.5 实体 ctor 0x141e705d0 的组件 read 环与旧版 doc 04 表，定位第一个改版组件。

判定标准（首测）：加载屏退出、角色站在河岸、可移动（C→S 移动消息开始流动）。背包/技能栏/金币/天赋等 UI 消息（instance 组新 id）是下一轮逆向，不作为本轮成败项。

### 7. 未决问题

- 世界队列 push 的确切位置与泵的双 factory 分派细节（架构已明，不影响发包）。
- stamp 三件套服务器应填值（现推断全 0）；若世界 stamp 在 0x1e 后被客户端推进（如 area-object id 关联），需从 drain 逻辑 [rbp+0x88] 语义再逆。
- 本地玩家认领机制的确切路径（事件 0xe794fcda 的监听者 / 0x1416820a0 回调后段 / 阶段二上下文对）——决定“只发 0x2f7 是否够”。
- player blob 组件格式在 0.5.5 的逐字有效性（实体 ctor 0x141e705d0 未逆）。
- typeHash 注册表键算法在 0.5.5 的连续性（0xa7000ea0 为推断值）。
- 背包（旧 0xc0 族）、金币（旧 0x2a9）、技能栏（旧 0x53）、天赋（旧 passives 消息）在 0.5.5 的 instance 组新 id——下一轮。
- G1_1 河岸的出生格坐标：fork AreaLayouts 现值未对 0.5.5 地形证（位置错位有空间索引野写风险，旧 doc 03 §6）。

## 2026-11-04 evening2 — activation trigger hunt（世界为何永不激活）

背景（真机实证，Frida v5）：服务器发 0x2f7 后，世界工厂 0x142186c20 确实创建了消息对象并入队，
但 dispatcher 0x1421343c0 / 激活 0x14212fd90 / 排空 0x142130360 / 实体 ctor 0x141e705d0 此后从未被调用，
客户端在加载界面停留至退出。本节为纯静态逆向，目标是定位缺失的触发。

### 1. 派发总闸 = [world+0x84a]，全二进制只有 4 个写点（已实证）

- dispatcher 0x1421343c0 入口：`cmp byte ptr [rcx+0x84a], 0; je 0x142136346`（直接返回）。
  **一切世界消息派发都过这道闸**——泵不存在能绕开它的「即时派发」分支（任务项 3 的答案：
  即便有代码直调 dispatcher，+0x84a=0 时也是 no-op；队列是唯一路径）。
- 全 .text 扫 [reg+0x84a] 写指令（C6/88 + disp32 0x84a），只有 4 处：
  0x14212fdd9 置 1 / 0x14212fe5e 清 0（激活函数 0x14212fd90 内）；
  0x142130862 置 1 / 0x142130d63 清 0（世界更新函数 0x142130840 内，进/出各一次）。
- [world+0x86a] 全二进制只有 1 个写点：激活内 0x14212fe65 置 1（一次性闩锁，无人清）。
- 世界更新 0x142130840（this=world, xmm1=dt）：入口**无条件**置 +0x84a=1；
  [world+0x661]==0 走「全量 flush」支（逐个 dispatcher 全部排队消息后释放清队）；
  !=0 走 stamp 支：先派发 stamp u32==0 的消息（esi 入口恒 0），再调 0x142137270 做 area-object 驱动的 stamp 推进，
  末尾把世界 stamp 置哨兵 0xFFFFFFFE/0/0 后收尾清 +0x84a。
  **推论（强推断）：15:10 会话里 dispatcher 从未被调 ⇒ 世界更新 0x142130840 在整个加载期一次都没跑**
  （任一模式都会直调 dispatcher 派发我们那条 stamp=0 的 0x2f7）。同理激活也没跑。
  问题因此收敛为：**谁负责周期调用世界更新 / 激活（虚表槽 +0x448 / +0x278），为什么没被调用**。

### 2. 激活回调 0x1416820a0 全解（已实证）

- 它是世界聚合对象（下 §3）某个 facet vtable 的 **+0x278 槽覆盖实现**：同槽在世界基 vtable
  0x1435083e8 是激活本体 0x14212fd90；在 facet vtable 0x1430e2598 与 0x14339d148（同一 vtable 组的两个 facet，
  以 +0x1b8 槽 = 0x142133a30 对位锚定）是 0x1416820a0。
- 回调本体：`mov rbx, rcx; call 0x14212fd90`——**第一条就无条件调激活，没有任何内部条件**；
  其后是收尾：[this+0x1270] 对象调 0x142ac16b0；若 [this+0xfc8]!=0 且 [this+0x98]（当前 area 描述符）
  的 +0x1b4==0x22 或其 +0x2a 的 area-hash ∈ {0x17e, 0x547a, 0x5bf0, 0x1a29}，且 [fc8obj+0x19]==0，
  则组装一个描述符调 0x142ab5f40 并置 [fc8obj+0x19]=1（城镇/教程类 area 的一次性 UI 弹出，推断）；
  最后尾调 0x141236e00（UI 状态刷新，推断）。
- 0x14212fd90 的 E8 调用方全二进制只有 0x1416820ac 一处（scan_calls 实证）；回调本身无 E8 调用方，
  只能经虚表 +0x278 被调用。**结论：门不在回调内部，在「谁调用 +0x278 / +0x448」这一层。**

### 3. 世界聚合对象与驱动链（已实证/部分推断）

- 世界不是单 vtable 对象：聚合对象 ctor = **0x14167d470**（先调世界基 ctor 0x14212ece0，
  再装 8+ 个 facet vtable：主 vtable 0x14339d1d0 @+0，其余 @+0x250/0x258/0x260/0x880/0x890/0x898/0x8a0…；
  全局自增计数 → [this+0x888] 对象 id）。facet 方法带 this 调整（如 A 组 +0x60 实现 0x140b45050 内
  `lea rbx, [rcx-0x3f0]`），这解释了 Frida v5 在工厂 rcx 上读 +0x84a 得到垃圾值——rcx 是 facet 指针而非对象基址。
- 聚合对象由实例创建链构造：creator 0x14100b2a0 内 0x14100b979 调 ctor，存入 [rsi+0x458]，
  随后 factory 0x141628d20 把它装进 instance（session+0x20f0 即此对象）。**即活会话里聚合对象/世界是存在的**（工厂能建消息、0x1e 能写它的 +0xb8/+0xbf.. 字段，均为实证）。
- 世界更新的虚表入口：基 vtable +0x448 = 0x14212ecd0（`movaps xmm1, xmm2; jmp 0x142130840` 的 dt 转发 thunk）。
- **InstMgr**（实例管理器，反射名串 "InstMgr" @0x14350c630，vtable 在 0x14350c520.. 区）持有 tick  registry：
  其 tick 方法 **0x14218bf90**（vtable 0x14350c5b8）遍历 [mgr+0x270..0x278] 的 shared-ptr 式条目，
  对每个条目调 **[obj_vtable+0x448](obj, &{xmm 对})**。另有 +0x148..0x150 的实例条目向量
  （0x14218bec0 遍历它做属性广播：[obj+0xf8]!=0 时以事件号 0x3911 调 obj 方法、回写 [obj+0xfc]）。
- 世界侧的 tick 适配：描述符表 0x14339f6a0 起 {0x14169c750(×2), **0x14169c740**, 0x14169c730, …}，
  其中 0x14169c740 = `xmm1=[rcx+0x10](float); rcx=[rcx+8](world); jmp 0x142130840`——
  一个 {+0x8: world, +0x10: float} 的持有者对象把 tick 转发给世界更新（反射类型描述符回调，推断）。
- **缺口（未定位）**：聚合对象/持有者被加入 InstMgr tick registry 的确切注册点未找到
  （vtable 起点无 qword/lea 引用——经反射描述符表间接登记的可能性大）。
  两种互斥假设待 Frida 验证：(a) 世界从未被登记进 tick registry；(b) InstMgr tick 本身在加载态不被主循环调用
  （游戏状态机未把当前状态切到 in-game，状态的 tick 列表不含本世界）。

### 4. 实例组 0x21 / 0x22 与激活无数据流关联（已实证其 handler 本体）

- 0x22 handler 0x142122f41：逐条记录（0x28B：wstring 名 + u8 值）按名匹配会话监听向量
  [session+0x48] 的条目（条目 +0x160 wstring / +0x170 长度），命中写 [条目+0x181]=值，
  并把值锁存到 [条目+0x1b0 对象 +0x39d4]（仅当为 0 时）。纯命名标志同步，不调世界/状态机函数。
- 0x21 handler 0x142123bac：以 (key u16, flag u8) 对查 0x14060e0e0 给出的 **0x406 字节定长记录表**
  （imul 0x406 索引），flag!=0 调 0x141e75970 置位 / ==0 调 0x141e75ed0 清位，结果追加 [session+0x2348]。
  表是数据驱动的（任务/遭遇/联盟类状态旗，推断）；键域即该数据表行数，无已知常量与进图相关。
  handler 本体不调 0x14212fd90、不调世界虚表、不写会话状态字段。
- **结论：0x21/0x22 不是缺失触发，给服务器的建议序列里不要为了「激活」而发它们**
  （旧 EnterArea 形 0x21 仍然禁止，理由见上一节）。

### 5. 实例组 0x23 / 0x24 复查（新，均为内容设置消息，非触发）

- **0x23**（factory: alloc 0x200, read 0x1421582b0；dispatcher case 0x14212306d）线格式（read 逐字段）：
  U8→+0x10；**compact-int→+0x1f8（u32 值）**；U8 flags 字节（bit0→+0x1fc, bit1→+0x1fd, bit2→+0x1fe）；
  U8 count → 0x70B 元素向量 @+0x18（每元素：两个 0x1421764b0 子结构、U8 计数 ×(u32BE,u32BE) 对向量、
  wstring @+0x48、3B @+0x68）；其后还有多段向量（classify seq 共 20 步，未逐字读完）。
  handler 对世界聚合对象调：vt+0x178（=0x14167e020：把值转发给 [world+0x5b0] 子管理器 0x142128810）、
  vt+0x200（=0x140b27ac0：`mov [facet+0x11c], edx`，存 bit0）、vt+0x60（facet 覆盖，存/查 bit2 字节）、
  vt+0x1f0（=0x142136960：查 [world+0x608/0x610] 映射的注册/查询），然后转发三组监听向量。
  语义 = 世界/玩法标志与数据下发（推断），handler 内无 +0x278/+0x448 调用。
- **0x24**（alloc 0x20, read 0x141f3ced0 = U8+U8+U32BE 级；case 0x142123014）：
  按 [msg+0x18] 字节值在 [session+0x48] 监听表找 [条目+0x181]==该值的条目，
  写 [条目+0x184]=[msg+0x1c] u32，并调 0x142133390(world, 值, 条目下标) 通知世界。命名通道赋值消息，非触发。

### 6. 世界 stamp 字段 +0x678/67c/67e 的真实写入点（任务项 5，已实证）

- 世界基 ctor 0x14212ece0 初始化：+0x678=0, +0x67c=0, +0x67e=0（连带 +0x661/+0x662 由参数字节、+0x670=1.0f）。
- 运行期唯一推进者 = **0x142137270**（area-object 迭代驱动）：以 area-object 记录 [rbp+0x88] 为当前 id（edi），
  先直调 dispatcher 派发队列中 stamp u32 < edi 的消息（派发时把该消息的 stamp u8/u16 拷入 +0x67c/+0x67e），
  然后 **[world+0x678] = edi**；再两轮调排空 0x142130360（先以 (edi,0,0)、后以 (edi,0xff,0) 为键）。
  世界更新（stamp 支）末尾把三件套复位为哨兵 (0xFFFFFFFE, 0, 0)。
- area-object 记录（+0x88=id, +0x8c 标志, +0x10/+0x18 子对象向量）挂在世界树 [world+0x6f0] 与另一棵 [rcx+0x10] 树上；
  其 id 来源（哪个消息/本地生成赋值 +0x88）本轮未逆。
- **对服务器的含义**：spawn 消息 stamp 填 0 与世界初值一致，排空键 (0,≤,≤) 在 area-object id 尚为 0 的语义下可通过；
  当前阻塞与 stamp 无关（更新根本没跑），不要先动 stamp。日后若出现「消息被派发但 CreateObject handler 前
  的 stamp 校验失败」类现象，再逆 area-object id 的赋值来源。
- 附带解明：[world+0x661] 是渲染质量/动态分辨率模式（会话 tick 0x142120f4f 按全局质量档与帧率阈值
  70/90 改写 0/1/2，+0x670=缩放 float 1.0）——更新函数按它分流是渲染管线差异，**与网络激活无关**（推断，依据充分）。

### 7. 结论与下一步建议

- **缺失触发最可能是什么（推断，证据链完整但注册点未静态定位）**：不是某条服务器消息的某个字段，
  而是客户端内部「世界未被纳入每帧 tick」：聚合世界对象已构造、消息已入队，但 InstMgr tick registry
  里没有它（或加载态下状态机没有把 tick 交给它），于是 +0x84a 永不抬起、队列永不排空、激活永不发生。
  真实服务器会话与我们的差异不在 0x2f7 本身，而在进图前后的**完整实例消息序列**：
  客户端的游戏状态/监听器（经 dispatcher default forwarder 0x142125628 按 [msg+0x10] 字节分发的
  [session+0x48]/[session+0x20]/[session+0x23e8] 三组监听者）很可能要先收到某些实例消息
  （候选：0x23 世界标志、0x28、0x29，或某个 default 转发 id）才把世界登记/切入 in-game 态。
- **下一步（按序）**：
  1. Frida v6 探针（一次会话即可判读）：钩 0x142130840（世界更新）、0x14218bf90（InstMgr tick，
     打印 registry 条目数与每个条目的 vtable）、0x1416820a0、0x14212fd90；
     若 tick 在跑而 registry 无世界 → (a) 成立，再钩 InstMgr vtable 的疑似登记方法
     （0x14218c9f0/0x14218ca00/0x142188cd0 一带）与 [mgr+0x270] 向量的 push 调用点（对 mgr+0x278 写断点）。
  2. 静态续查：dispatcher default forwarder 的三组监听者都是谁在何时注册的
     （[session+0x48] 的 push 点、0x142106bb0 的按字节匹配表），重点找聚合对象/状态对象注册为监听者的位置，
     以及它对哪些消息 id 作出「切状态」反应。
  3. 服务端实验（探针就位后）：在 0x1e 之后、0x9a 应答前/后补发 **0x23 最小形**
     （U8=0, compact-int=0, flags=0, count=0 … 需先把 read 0x1421582b0 后半段逐字读完再定字节），
     观察 tick/登记是否出现；无效再逐个试 0x28/0x29 的最小形。不要动 stamp、不要发 0x21/0x22 充数。

## 2026-11-04 evening3 — tick registration and listener hunt

前提修正（真机 Frida v6 实证，15:55 完整会话）：**InstMgr tick 0x14218bf90 整场从未被调用**
（钩子有效，同批 world_update 钩子有触发）；世界更新 0x142130840 在**登录完成前被调用 7 次**
（菜单/选角背景世界），**实例会话开始后零次**。故 evening2 的「InstMgr tick 驱动世界更新」模型不成立，
本节在此前提下重读全部静态结论。实例会话内其余事件与上轮一致（0x2f7 created=1，dispatch/activate/
facet 回调/entity ctor 全 0）。

### 1. tick registry 的确切结构（已实证，修正 evening2 §3）与注册点（未定位）

- tick 本体 0x14218bfc0（0x14218bf90 仅转发）：registry 不在 mgr 本体上，而是
  **X = 0x14014e870([mgr+0x140])**（对 mgr+0x140 处对象做关联对象查找）后取 **[X+0x270..0x278]**
  的裸指针向量（8B 步进）。条目 D：[D+0xf8]/[D+0x100] 是 shared_ptr → P；以 **[P+0x40] 为 id**
  在 mgr 的实例向量 **[mgr+0x148..0x150]**（16B shared_ptr 槽）中二分查找实例 E；
  0x14218c320 做 (D 的 pair, E 的 pair) 兼容检查；按 E 的 +0x188/+0x18c/+0x190 标志对 D 调
  vtable+0x2c8/+0x2d0 通知并维护 [D+0x144] bit3；最终调 **D.vtable+0x448(D, &E 的 shared_ptr 副本)**
  （无匹配实例时以全零 pair 调一次）。这与世界基 vtable +0x448=0x14212ecd0（更新 thunk）、
  facet vtable 0x14339d148 的 +0x2c8=0x141685f80/+0x2d0=0x141686050/+0x448=0x14167e580（事件投递形）
  均可对位，但**该 tick 在本会话根本不运行**，registry 里有没有世界已非主线问题。
- [mgr+0x148] 实例向量的填充路径（已实证）：**0x14218b130(mgr, stream, count)** 逐项调
  0x142188d50 构造实例对象；同 id（[obj+0x40]）已存在时先调 mgr.vtable+0x40 并移除旧条目；
  append 到 +0x148 后调 0x14218c750 与 mgr.vtable+0x38 通知。其调用方 **0x14218a9d0** 是流反序列化器：
  先取 0x14014efc0([mgr+0x140]) 关联对象，以其 +0x1d8 字段与常数 0x4ea4 调 mgr.vtable+0x18，
  再从流读 count 字节后调 0x14218b130。0x14218a9d0 与另一支 0x14218b780 由
  **0x142149510(obj, stream, full)** 分发（full!=0 → 0x14218a9d0(obj+0x9c0, stream)；
  full==0 且流内标志 bit3 → 0x14218b780；标志 bit4 → 0x1421428c0(obj+0xb90, stream) 等）。
- 0x142149510 所属类（facet vtable **0x143508B08**：slot+0x10 = read 0x142147300、+0x28 = 0x142149500）：
  对象内嵌 **InstMgr @+0x9c0**（恰 0x1d0 字节，与下一子对象相接）、流对象 @+0xb90、状态表 @+0x2c8，
  对象 ≥0xe00 字节。**该类不由实例工厂 0x142170500 创建**（factory_scan 全 case 无此 read），
  **也不由登录工厂 0x14214fbe0 创建**（全 case 最大 alloc 0x90）。其来源通道未定位；
  形态像客户端内部的「实例状态快照」对象（推断），是下一轮的开放线索（地址齐全，可直接续查）。
- **registry（[X+0x270]）的 append 调用点仍未静态定位**：disp 候选扫描无法从大量同偏移结构中分离出该类方法；
  会话 ctor/creator/factory 链（0x14100b2a0、0x141628d20、0x14211dd30）内均无对 +0x270 向量的 append。
- 真正的世界更新驱动（v6 后的候选集，已实证存在性）：全 .text 对 `call/jmp [reg+0x448]` 做字节扫描共
  21 处候选，剔除 tick 本体 2 处后与世界最相关的是：
  (a) **游戏状态机实现簇 0x14281xxxx**：0x142810b70（状态转移：查状态向量、置当前下标 [this+0x518]、
  依次调自身 vtable +0x448/+0x430/+0x428）、0x142812680（选定状态：置 [this+0x518]/[this+0x528] 后
  以所选状态对象为参数调自身 +0x448）；两函数均为 vtable 方法（引用点 0x14339e830/0x14339e9b0，
  与世界聚合对象 vtable 块 0x14339dxxx–0x14339exxx 同簇）；
  (b) **对象树遍历器 0x141917d60**：经子对象 vtable +0x70/+0x78 迭代并对节点调 +0x448（通用场景 tick）；
  (c) 其余为通用框架簇（0x1404cxxxx 等），未逐一归属。
- **菜单 vs 实例的差异（推断，证据链完整）**：菜单世界在程序启动时即存在于游戏状态机/对象树中，
  被 (a)/(b) 周期 tick（7 次实证）；实例世界由网络会话创建（[session+0x20f0]），**从未被挂入
  状态机/对象树**，故零 tick、零派发。挂入动作即 facet 虚表 +0x278 回调 0x1416820a0 的调用方层
  （状态机在某世界成为当前状态时调其 +0x278），与 evening2 §2「门在调用方层」互证。
  何种条件使状态机把实例世界选为当前状态仍未定位；候选触发源见 §4。

### 2. 三组监听者（已实证结构与 handler；注册点未定位）

- 分发模型修正：default forwarder 0x142125628 本体**只处理 [session+0x48]**（按 [entry+0x181]==[msg+0x10]
  匹配，命中调 0x142106bb0(entry, &msg)，未命中时以首条目调之）。三组完整扇出出现在专用 case 中
  （以 0x23 handler 0x14212306d 为样本）：先对世界聚合对象调内容槽 +0x178/+0x200/+0x60/+0x1f0，再依次：
  [session+0x20..0x28] 每条目调 **0x1420edc20(entry, msg)**；[session+0x48..0x50] 每条目调
  **0x14210c170(entry, msg)**；[session+0x23e8..0x23f0] 每条目调 **entry.vtable+0x50(entry, msg)**。
  0x23 handler 末尾还有：[session+0x48] 条目数 >1 时组装 0x60B 节点存入 [session+0x27d0]（延迟处理登记）。
- +0x48 组 = **命名状态通道对象**（小缓冲向量，内联缓冲 @session+0x60；条目 ≥0x8b88 字节）：
  名字 wstring @+0x160；0x22 按名匹配写 +0x181（字节通道号）；0x24 按 +0x181 匹配写 +0x184（u32 键）。
  0x14210c170 按 [entry+0x184] 在 0x23 第二向量（@msg+0x110，0x68B 元素）中找记录，命中后把元素字段
  写入 entry 的 +0x79fc/+0x79fd/+0x7980（经 0x14210c380）/+0x80a0/+0x80a2，清 +0x80a4 起 6B，
  再调 entry.vtable+0x70。default 路径的 0x142106bb0 是该组的全消息处理机（switch 覆盖 id 0x3a–0x132
  与 0x142；部分 case 经 0x1421386c0/0x142138af0 操作 entry 内部 +0x6cd0/+0x6e50/+0x7640 子结构，
  非世界聚合对象）。
- +0x20 组 = **通道组包装对象**（小缓冲向量，内联缓冲 @session+0x38）：其 [+0x8..+0x10] 是子通道对象向量；
  0x1420edc20 取首个子对象的 +0x184 键在 0x23 第二向量中找记录，命中后写入包装对象 +0x3fc0/+0x3eca…。
- +0x23e8 组 = **监听接口对象**（普通向量）：vtable +0x50（0x23 扇出）、+0x58（会话泵 0x142120220
  以 (rdx, r8) 广播）、+0x78（会话泵在 0x14211fff0 区逐个查询、返回值与 0x48 比较）、
  +0x90（分发器 0x14212558a 块中按 [entry+0x30] dword 键匹配后以 (ptr,len) 参数调用）。
- **注册点（未定位）**：会话 ctor 0x14211dd30 对三组只做向量头零初始化（+0x20 内联 @+0x38、
  +0x48 内联 @+0x60）；分发器/会话方法/creator 链内未找到对三组的 append 调用点。条目均为游戏侧大对象，
  推断由游戏系统在会话建立/进区域时按数据驱动的通道定义注册。**世界聚合对象不在三组之内**
  （单独存于 [session+0x20f0]），游戏状态机亦无注册为监听者的证据。
- 与激活的关系（已实证的否定面）：三组在 0x23 样本中的 handler 均为状态值应用，
  **不调用世界 +0x448/+0x278、不触碰 tick registry**；0x23 handler 对世界的调用仅为内容槽。

### 3. 0x23 与 0x28 完整线格式（已实证，逐字读完）

- **0x23**（factory case 块 0x142170ff4；alloc 0x200；read 0x1421582b0 全函数）：
  线（id 后）：U8→+0x10；**compact-int（0x1408719a0）→+0x1f8**；U8 flags（bit0→+0x1fc, bit1→+0x1fd,
  bit2→+0x1fe）；U8 countA → 向量 @+0x18（元素 0x70B）；U8 countB → 向量 @+0x110（元素 0x68B）。
  元素 A（0x70B）：sub 0x1421764b0 @+0x00；sub 0x1421764b0 @+0x18；U8 count → (U32BE, U32BE) 对向量
  @+0x30；wstring（0x141cfb540）@+0x48；3B 原样 @+0x68。
  元素 B（0x68B）：U32BE @+0x00；U8 甲（&0x3f→+0x04, bit6→+0x07, bit7→+0x06）；U8 乙（bit0→+0x08,
  bit1→+0x09, bit2→+0x0a）；U8 原样 @+0x05；3× sub 0x141f4d170 @+0x10/+0x20/+0x30；
  sub 0x142176540 @+0x40。
  **最小合法报文（7B）：`00 23 00 00 00 00 00`**（U8=0, compact=0, flags=0, countA=0, countB=0）。
  注：read 中途多次查流错误标志 [stream+0x252]，置位即中止后续读取——报文长度必须精确。
- **0x28**（factory case 块 0x1421707d5：alloc 0x40，base-init id=0x28，vtable **0x14350B058**：
  slot+0x8 = write 0x142151c30、+0x10 = read 0x142151cd0、+0x18 = copy-ctor 0x142151d40）：
  线（id 后）：**U8→+0x10；U16BE→+0x18；wstring（0x141cfb540）→+0x20**。
  **最小合法报文（7B）：`00 28 00 <key:u16BE> 00 00`**（空名 = wstring 计数 0）。
  handler 0x14212227f → **0x14211f920(session, key, name)**：[session+0x2208]=key、
  [session+0x2210]=name（移动语义）、**[session+0x2270]=1**；再对连接对象 [session+0x20f8]：
  [conn+0xc8]!=0 时调 0x142198110(conn, 0, 1)（连接流处理），经全局函数指针调一次 (…, 1)，
  清 [conn+0x250]。全程不调世界/状态机/registry（已实证）。
  附带发现（已实证）：分发器入口 0x142122135——泵以空消息调用分发器且 [session+0x2270]!=1 时，
  分发器**自行**以 (key=0xf, name=L"") 调 0x14211f920。即 0x28 承载「实例身份（键+名）」，
  客户端备有默认兜底（0xf/空名）；真实服务器预期会发 0x28（否则字段与兜底无存在意义——推断）。

### 4. 候选清单（0x1e 之后、0x9a 前后）——按证据强度排序

前提：v6 实证后「某条消息直接触发激活」的证据整体变弱；更强模型是 §1 的「实例世界未挂入状态机/对象树」。
下列是仍能由服务器侧影响该迁移的候选（均于 0x1e 之后、应答 0x9a 时一并发/先行发）：

1. **0x28 实例身份**（证据：中）：进图邻域唯一写会话级身份/状态字段
   （+0x2208/+0x2210/+0x2270=1）的消息，且客户端专设兜底默认值——若状态迁移以「会话身份已确立」
   为前置条件，只能由它满足。最小报文 `00 28 00 00 00 00 00`（key 可试 0，或与 0x1e 的 InstanceId 同值）。
2. **0x23 状态表最小形**（证据：中弱）：扇出最广（世界内容槽 + 三组监听者全量扇出）；
   若任一通道对象的状态值是迁移前置条件，只能由它携带。最小报文 `00 23 00 00 00 00 00`。
3. **0x29 实例转移**（证据：弱）：handler 0x142122346 以消息内字段组装实例描述（0x14212ad60）
   并通知 +0x48 组；属转移流程，本流程已用 0x1e 直进，误发有副作用风险，仅当前两者无效时考虑。
4. 0x21/0x22：已排除（evening2 §4），不要发。

未决/下一轮：状态 blob 类（read 0x142147300、vtable 0x143508B08）的来源通道；
状态机（0x142810b70/0x142812680）把实例世界选为当前状态的确切条件——动态侧钩这两个函数与
facet +0x278 的虚调用点（Frida v7）比继续静态扫更快。

## 2026-11-04 evening4 — 0x23 content value and the activation crash

背景：16:16 真机会话（0x28 先行、0x1e、最小 0x23 `00 23 00 00 00 00 00`）中 facet 回调与
世界激活首次触发、区域生成开始（Tile/Doodad hash 已打出）、随后进程崩溃且未及
[SCENE] Set Source。本节查清：handler 的四个世界虚调用到底落在哪、值去了哪、崩溃最可能死在哪。

### 0. 工具更正（影响一切虚表读数，先读）
- .rdata 的 raw = va − **0x140001200**（须按 PE 节表换算）；.text 的 raw = va − 0x140000C00。
  本轮早期曾拿 .text 偏移读 .rdata，产生过「相差 0x600 的孪生虚表」幻象，结论已全部作废重验。
- 锚点以正确换算复验无误：world 基虚表 0x1435083e8：+0x60=0x142186c20（工厂）、
  +0x278=0x14212fd90（激活）、+0x448=0x14212ecd0（update thunk）——evening2/3 的锚点成立。

### 1. handler 实际解引用的是「主虚表」，不是 facet 虚表（已实证）
- 世界聚合对象（ctor 0x14167d470）在两个簇里各有一对虚表：facet B / 主 B+0x88——
  (0x1430e2598, 0x1430e2620) 与 (0x14339d148, 0x14339d1d0)。
  聚合 ctor 把 **0x14339d1d0** 存进 [obj+0]，故聚合自身用 0x14339d1xx 簇。
- facet 虚表 0x14339d148：+0x178=0x14167e020、+0x1f0=0x142136960、+0x200=0x140b27ac0、+0x278=0x1416820a0。
- **主虚表 0x14339d1d0**：+0x60=0x140b27a70、**+0x178=0x140b27ac0**、**+0x1f0=0x1416820a0**、
  +0x200=0x14168ac70、+0x278=0x141686d70。
- 判别：handler 的实参形态与「0x23 派发内同步触发激活」这一真机事实只与主虚表自洽——
  只有主虚表 +0x1f0=0x1416820a0 以激活为首指令；facet 的 +0x1f0=0x142136960 是 (key, ptr)
  映射登记/查询，handler 根本不设它的实参、它也永不调激活。
- 对 evening2/3 的修正：那两节描述的是 **facet 接口**（同一回调在 facet 虚表上位于 +0x278；
  状态机等 facet 指针持有者走这条）。[session+0x20f0] 是聚合基址，0x23 handler 走**主接口**。
  facet 侧结论对 facet 持有者仍成立，但不适用于本 handler。

### 2. 四个世界虚调用的落点（主虚表，已实证）
1. **+0x178 → 0x140b27ac0**：`mov [rcx+0x11c], edx; ret`——**[agg+0x11c] = compact-int 值**。
   纯字段存，无管理器、无查表。
2. **+0x200 → 0x14168ac70(agg, bit0, bit1)**：sil = bit0 && bit1；[agg+0x1334] 与之不同才
   写存并走一段重型变更通知。flags=0 → sil=0，原值已 0 时为空转。
3. **+0x60 → 0x140b27a70(agg, bit2)**：[agg+0xc4] = bit2 ^ 1。flags=0 → [agg+0xc4]=1。
4. **+0x1f0 → 0x1416820a0(agg)**：首指令即 call **0x14212fd90（激活）**；随后
   [agg+0x1270] → 0x142ac16b0 子系统通知；特殊区域块：[agg+0x98] 区域对象的 +0x1b4==0x22 或
   HASH16(+0x2a) ∈ {0x17e, 0x547a, 0x5bf0, 0x1a29} 时对 [agg+0xfc8] 对象做额外登记
   （0x142cb75c0/0x142ab5f40，置 [obj+0x19]=1）——G1_1 的 0x0f14 不在集合内；
   尾：0x14118ece0 取全局对象 → [[rax]+8]+0x588 → jmp 0x141236e00。
⇒ **0x23 就是激活钥匙、且是直接调用链**：dispatcher case 0x23 → 主虚表 +0x1f0 →
   0x1416820a0 → 0x14212fd90。与 0x28 无关（其 handler 全程不碰世界，evening3 §3 已实证）。
   Frida 事件序（0x23 派发 → facet 回调 → 激活）与该链逐节吻合。
- handler 其余部分（与 evening3 步行一致，复核无误）：三组监听者扇出；
  [session+0x48] 计数 >1 时在 [session+0x27d0] 建 0x60B 节点串联各条目 [Y+0x4c0] 并调
  0x141eca920；**[session+0x2270]=3**（0x1421232b4；对照 0x28 置 1——状态语义：1=身份已立、3=0x23 已提交）；
  0x14013bbf0 对 session+0x270 加锁/通知；依次冲刷待决向量 +0x2768（0x20B 条目）、
  +0x2780（(u32,float) 对 → 0x140d24fc0 写入 session+0xc70 对象）、
  +0x2798（(u8,u32) 对 → 0x1404ad4c0 写入 session+0x15f0）、+0x27b0 计数（→ session+0x1ef0）；
  尾：[world+0x868]!=0 时进 0x14212346e 块遍历 session+0x970 树——**未解码（open）**。

### 3. [world+0x5b0] 与值的关系——原假设证伪（已实证）
- facet +0x178 的实现 0x14167e020：rcx=[facet+0x5b0]，为空即返回；否则调
  0x142128810(mgr, 0, rdx, (byte)r8, r9)。而 0x142128810 把第三参当**对象指针**解引用
  （[r8+8] 标志位、[r8+0xa] u16），包装成一个描述符对象（虚表 0x1434e5b68、字标签 0x301、
  含 dword 形参=0、描述符的 u16、标志字节），经 0x142bbaa10 分配后登记进管理器。
  ⇒ facet +0x178 是**描述符登记**操作，第三参是描述符对象指针、不是标量；
  属 evening3 §1 的描述符/状态机械，与 0x23 的标量值路径无关。
- 基址相对的 [world+0x5b0] 本身也是真字段：0x14212f9f0 遍历 [mgr+0x48..+0x50] 的对象指针
  向量，检查某个以 "Player" 为键（字符串 @0x1434D4BF4 一带）查得的对象是否已登记——
  是世界的**内容/对象注册表**。0x23 handler 从不碰它。
- **结论：0x23 的 compact-int 值不进 [world+0x5b0]、不作任何表的索引；值=0 不可能
  「在内容管理器查表致命」。父级假设（值扇出进 +0x5b0 查表）在 handler 的真实路径上不成立。**

### 4. 值 [agg+0x11c] 的真实消费者（已实证）
- 世界更新簇函数 0x142130440：样本环（[world+0x690/+0x698/+0x6a0/+0x6a8]）为空时
  candidate = **(float)[world+0x11c] / 1000.0**（xmm8 常量 = 1000.0f @0x14360d4c4，已按字节复核）；
  否则 candidate = 样本/1000.0。随后 [world+0x66c] = min([world+0x66c], candidate)
  （0x14213074a comiss）。+0x66c/+0x670/+0x674 即 evening2 §6 的动态分辨率/性能控制器字段。
  ⇒ 该值是**毫秒量纲的量**（与帧时间样本同单位）。**值=0 使 candidate 恒 0 →
  [world+0x66c] 被钳到 0 且经此路径永不能回升。**
- 会话函数 ~0x142121226（session+0x2230 队列处理）：以 [session+0x2260] + 2*值 作
  水位/容量界与 [session+0x2250] 比较——纯数值使用。
- 世界/会话/聚合代码区内 disp-0x11c 扫描无其他读者；两个 ctor 均不初始化 +0x11c（默认 0）。
- 语义名静态不可考（待验）：最可能是每实例的时间/标度参数（毫秒）；**不是**区域/内容 id
  （区域身份走 0x1e 的哈希与 0x28 的 key）。候选如区域哈希 0x0f14、WorldAreas 某列——均无证据，勿用。

### 5. 两个记录向量（结构已实证；语义推断）
- read 0x1421582b0 逐指令复核：U8→+0x10；compact-int→DWORD +0x1f8；flags 字节拆
  +0x1fc/+0x1fd/+0x1fe；U8 countA→向量 +0x18（元素 0x70B）；U8 countB→向量 +0x110
  （元素 0x68B）；全程查流错误标志，**报文长度必须精确**。
- 元素 A（0x70B）：sub 0x1421764b0 ×2（@+0x00/+0x18；各读一个 U16BE id 并经
  0x14217b0f0 解析为对象/记录引用）、U8 计数 + (U32BE,U32BE) 对向量 @+0x30、
  wstring @+0x48、3 原始字节 @+0x68。推断：**命名通道/组定义记录**（名 + 两个被引端点 + 数值对）。
- 元素 B（0x68B）：U32BE 键 @+0x00；位域 @+0x04..+0x0a；原始字节 @+0x05；
  sub 0x141f4d170 ×3（@+0x10/+0x20/+0x30；各读 1 字节标签并物化/保持一个对象引用——值对象读器）；
  sub 0x142176540 @+0x40（U16BE id 解析，与 A 的 sub 同族）。消费者（已实证，evening3）：
  [session+0x48] 条目经 0x14210c170、[session+0x20] 包装经 0x1420edc20，均以
  键 == [entry+0x184] 查元素，命中后把其字段写进条目（+0x79fc/+0x79fd 字节、
  +0x7980 经 0x14210c380、+0x80a0/+0x80a2 u16、+0x80a4 清 6B），再调条目虚表 +0x70。
  ⇒ 元素 B = **按通道键控的状态值记录**（通道的状态/属性块）。
- **「对 G1_1 合法」的 0x23 最少记录数 = 0**——已实证：16:16 真机会话中最小形被完整
  解析、派发、触发激活并置状态 3，无读/派发错误；handler 与消费者都不要求普通区域携带记录。
  记录只在会话里存在期待状态的通道条目时才有意义（新会话中 [session+0x48]/[+0x20]
  条目数静态未定——open）。

### 6. 崩溃机理（推断，按置信排序）
已立框架（已实证）：无 0x23 的会话能打出 [SCENE] Set Source [河岸] 并停在加载界面不崩；
有 0x23 时激活+生成都发生、Tile/Doodad hash 打出（生成函数在 0x14212f7xx 一带引用
"Tile hash: " @0x14339c2a0、"Doodad hash: " @0x14339c2d0；Set Source 由场景管理器
0x1411a39d2 一带打出），进程死在 Set Source 之前。故致命步在**已激活世界的生成后路径**，
不在 0x23 的解析/派发（已完成），也不在 +0x5b0 管理器（不在路径上）。
1. **（最可能）标度被钳到 0**：世界一旦被激活即被世界更新 tick；0x142130440 在样本环
   为空时以 (float)值/1000 = 0 算 candidate，把动态分辨率标度 [world+0x66c] 钳成 0。
   生成完成、场景开始呈现时，标度 0 → 渲染目标尺寸 0 / 以标度作除数 → 在 Set Source
   前后解引用/断言崩溃。与「只在已激活构型下崩」的时间线吻合。置信：中。
2. **flags 状态不对**：[agg+0xc4]=1（bit2 反相存）与 [agg+0x1334]=0 在聚合代码里有读者
   （+0xc4：0x1416753e1/0x1416766b9/0x14167e456/0x141684a44；+0x1334：0x14167e5c9/
   0x1416804d6，语义未解）。真实服务器对普通区域的 flags 未知；错误 flags 可能让场景
   搭建走未填充的分支。置信：低-中（open）。
3. **本地玩家未登记**：0x14212f9f0 与聚合侧孪生代码（~0x14167f7bb）都有「以 "Player" 键
   查注册表」的模式；若生成后场景绑定需要 [world+0x5b0] 注册表里的 Player 对象、而
   0x2f7 CreateObject 要等客户端发 0x9a 之后才有（16:16 会话中客户端是否在崩前发出
   0x9a 未核——需查网关日志），可能解空。但无激活会话同样没有 Player 却能到 Set Source，
   须已激活路径在此分叉才成立，未证。置信：低。
已排除：0x23 解析（已完成）、+0x5b0 值查表（不在路径）、0x28（不碰世界）、
stamp（evening2 已定案：服务器 0 == ctor 初值 0）。

### 7. 下一版 0x23——确切字节与发送时机
判别式设计：只改一个变量（值），取其唯一已知消费者的中性点：
- **值 = 1000** → (float)1000/1000.0 = 1.0，标度不变。若崩溃源于机理 1，此值即修复；
  若崩溃原样复现，值被洗清，嫌疑转 flags/记录。flags 保持 0、两向量保持空。
- compact-int 编码（已实证，源自 CreateObject blob 长度前缀 167→`80 A7`、1101→`84 4D`
  的方案）：1000 = 0x3E8 → 0x80|(1000>>8) = 0x83、低字节 0xE8 → **`83 E8`**。
- **字节（共 8）：`00 23 00 83 E8 00 00 00`**
  = id(2) + U8 0 + compact 值 1000 + flags 0 + countA 0 + countB 0。
- **时机：0x1e 之后、同一突发内、客户端 0x9a 之前**（与 16:16 实验一致，该顺序已实证
  可达激活；handler 的待决队列冲刷本就是为提交先行消息攒下的状态而设计，0x23 不得先于 0x1e）。
  0x28 仍在 0x1e 之前，不动。
- 明确还差的证据：(i) 值的语义名/单位只有 /1000.0 消费者这一条推断，无真实服务器抓包可定；
  (ii) 普通区域的正确 flags 无静态来源；(iii) handler 尾块 0x14212346e 未解码；
  (iv) 新会话中 [session+0x48]/[+0x20] 条目构成未定。
- 若值=1000 仍崩：下一探针 flags=0b111（`00 23 00 83 E8 07 00 00`，使 [agg+0xc4]→0、
  [agg+0x1334]→1）；动态侧钩 0x142130440 与 Set Source 调用点（0x1411a39d2 一带）
  在崩溃窗内定位比继续静态扫更快。

## 2026-11-04 evening5 — 0x28 encoding audit: NOT an identity message

**结论先行（已实证，代码级证据链完整）：0x28 不是「实例身份」，是服务器→客户端的
「带原因断开/踢出实例」消息。我们的编码逐字节正确——失败是纯语义误用：客户端忠实地
执行了一条合法的踢出消息。进图序列永不发 0x28。evening3 §3 的字段事实（线格式、
setter 存 +0x2208/+0x2210/+0x2270）无误，但其语义标注与 §4 候选 #1 的推断
（「兜底 ⇒ 真实服务器必发」）就此作废，见 §5 的反转解释。**

### 1. 逐字节审计：编码无错（已实证）

read 0x142151cd0 逐指令：
- read-bytes（0x142197e80）读 **1B → msg+0x10**（U8）；读 **2B → msg+0x18** 后
  `movzx ecx,[msg+0x18]; call [IAT ntohs]; [msg+0x18]=ax`——**U16BE** 确认；
- 尾跳字符串读 0x141cfb540（stream=rcx, dest=msg+0x20）。**字符串之后无任何尾随
  字段**；本 read 自身不查流错误标志，但字符串读内部在计数后与逐字后都查
  [stream+0x252]，置位即中止（0x141cfb949）。
- **U8（msg+0x10）是死字段**：handler 只取 [msg+0x18] 与 msg+0x20，setter 不读
  +0x10；write 侧从对象字段原样写出（ctor 默认 0）。我们发 0 无害，但它什么都不是。
- **key 的同一性**：read 存 msg+0x18（ntohs 后）→ handler `movzx edx,[r13+0x18]`
  → setter `movzx edi,dx; [rsi+0x2208]=di`。同一 u16，无二次变换。

write 0x142151c30 镜像：htons(id) 写 2B → [msg+0x10] 写 1B → htons([msg+0x18])
写 2B → wstring（长度取 [msg+0x30]）尾跳写助手 0x141cfb330。**与我们的
`Identity()` 编码（U16 id . U8 0 . U16BE key . WStr）逐字段同序同宽，diff 为零。**

字符串助手对（读 0x141cfb540 / 写 0x141cfb330）按 **[stream+0x254]** 分叉：
- ==0 → **compact**：计数 U16BE（ntohs/htons）；逐字 1B（<0x80）/ 标签 0x80+U16 /
  标签 0xC0+U32 码点（读侧含代理对合成/校验，写侧 0x141ce2970 预计算）——即
  LoginWriter.WStr 的格式；
- !=0 → 原始 UTF-16 单位（计数 U16BE + 每字 2B 原样）。
实例连接对象（0x1421975b0 初始化例程）把 +0x254 写 0，该类代码区内无非零写点；
且真机已实证 compact 模式在实例流上生效：16:50 会话中 9 字名被精确消费（其后
0x1e 完整派出、生成启动、type_lookup 序列正常），断线原因以干净的 "localtest"
打印——UTF-16 模式下两者都不可能。**名字格式无毒。**

### 2. setter = 带原因的会话拆除（已实证，与 leave 例程同尾）

setter 0x14211f920(session, code:u16, text:wstring)：
1. 单例对 0x142102b00/0x142102d20（会话管理器锁）；
2. [session+0x2208]=code、[session+0x2210]=text、**[session+0x2270]=1**；
3. conn=[session+0x20f8]：[conn+0xc8]!=0 时 0x142198110(conn,0,1)；
   经 IAT 单元 **0x142E89F88** 调 ([conn] 虚表, 1)；[conn+0x250]=0。

会话 leave 例程 0x14211f6c0（session, mode）：**入口先判 [session+0x2270]==1 则
直接返回**（已关勿重入）；做世界侧收尾、按 mode 组装并发送 C→S 0x1b（离场通知）
后，其尾段与 setter 第 1/3 步**逐指令相同**（同一对单例调用、同一条件强刷、
同一 IAT 单元 0x142E89F88、同一 [conn+0x250]=0、同一终局 [session+0x2270]=1）。
即 +0x2270 的真实状态机是：**1=已关闭（ctor 初值即 1，附默认记录 code=0x2cc/
空文本——会话生于"未连接"态）**、2=连接例程 0x14211fac0 已发起（组装 C→S
0x0f/0x0e 开场）、3=0x23 内容已提交。setter 是「以 (code, text) 为原因关闭会话」
的参数化拆除，与 leave 共用同一收尾——**0x28 的语义由此定死：踢出**。

handler 0x14212227f 本体只有取字段调 setter 一步，无其它动作。

### 3. 0x142198110 定性（对补充假说佐证点 (a) 的核查：不成立，但无关定案）

0x142198110(conn, mode, force) 是**发送队列冲刷**：若 [conn+0xc8]!=0（加密流对象
存在）且 force==0 → 直接返回（推迟）；否则把队列 [conn+0x258..0x260] 依次过两个
流对象（[conn+0x190] vtable+0x10、[conn+0x1b8] vtable+8，即加密变换）后以
send() 循环发尽（计数累加 [[conn+0x1b0]]），复位队列指针。**内无 closesocket/
shutdown，不是断开原语**；setter 以 force=1 调它只是「拆除前把队列强刷出去」。
[conn+0x250] 是队列侧状态字节，拆除尾段顺手清零。真正的关闭动作是 IAT 单元
0x142E89F88 的回调（(conn 虚表, 1)，leave 例程共用）与状态置 1。

### 4. 断线原因的显示链（已实证——名字为何被原样打印、空名为何是账号规则）

会话更新 0x142120cf0 在 state==1 时迭代 [session+0x1f0] 监听者列表，逐个以
**&[session+0x2208]（{u16 code; wstring text} 记录）**调 vtable+0x18——向监听者
通报关闭原因（推断：游戏状态对象据此退回登录/选角并弹断线框）；state>1 才泵消息、
state==3 才发 C→S tick，均与现象吻合（断开在生成早期、约一两帧内）。

日志侧（游戏会话管理器函数 0x141008280）：
- getter 0x141014950：自 [持有者+0x1a8] 取会话，拷出 { [会话+0x2208] code,
  [会话+0x2210] text }；code∈{0xf, 0x2cc}（两个通用码）且管理器自存 wstring
  [rsi+0x670] 非空时，以自存文本替换记录文本；
- 文本解析 0x141003ba0：**记录文本非空 → 原样使用**；为空 → code==0x2cc 用内嵌
  默认文案，其余 code 走 0x1425cb9c0 **按 code 查错误/本地化表**；
- 拼 `"Abnormal disconnect: " + 文本` 后以日志通道 **0x2d8e8554** 输出——正是
  Client.txt 里 `… 2d8e8554 [INFO Client …] Abnormal disconnect: …` 的那一行；
  随后按 code（0x4d/0x186/0xf…）分支做 UI 后续。

对号入座（全部已实证）：
- 我们发的 **text="localtest" → 非空 → 原样打印为 `Abnormal disconnect: localtest`**；
- 我们发的 **text="" → 按 code 查表**；而我们填的「key」是 InstanceId（1/2）——
  作为**原因码**，1/2 号表项恰是账号名校验类文案，故打印出
  `帳號長度必須大於三個字元且須由英文、數字與底線組成`。与「名字被校验」无关：
  被查表的是码，被显示的是表项。

### 5. evening3 两处推断的反转解释（已实证）

- **分发器兜底 (0xf, "")**：分发器以 NULL 消息被调用 = 泵报告连接已死/EOF；
  state!=1（尚无原因记录）时，客户端**自造默认原因记录**（通用码 0xf、空文本→
  查表显示）并走同一拆除，以便 UI 对「无原因的掉线」也有文案可报。它不是
  「真实服务器必发身份」的证据，恰恰相反：0x28 只在关闭路径上出现。
- **更新超时伪造记录**（0x142120ffb：[session+0x21a0] 期限过 → 直接写
  state=1、code=0x95、空文本）：连接实例超时时客户端自造「超时」原因记录关闭
  会话——同一记录槽的第三个写入者，三者（服务器 0x28 / EOF 兜底 / 超时）全是
  关闭语义，无一与「身份」相关。

### 6. 修正规范与建议

- **0x28 正确线格式**（若将来真要踢人）：`00 28 <u8 任意, 恒 0> <code:u16BE>
  <text: compact wstring>`；code 必须是客户端错误表中的有效原因码（表在数据侧，
  未逆向，不要发明码值），text 为要显示给玩家的原文（非空则原样显示）。
- **进图序列：永不发 0x28**（服务器代码现状已如此，保持）。fork 的
  `InstanceProtocol.IdentityId/Identity()` 命名是误名，建议改名
  DisconnectWithReason 并注明语义（本审计不改服务器代码，留待主线）。
- Frida 判别钩子（可选，一次性复核即可，本结论不依赖它）：钩 setter 0x14211f920
  入口读 (edx=code, r8=wstring) 并钩日志拼装点 0x14100844c 前的 [rsp+0x70] 文本，
  在任何真服/复现会话中应见 code/text 与日志行严格对应。


## 2026-11-04 evening6 — activation tail crash: [agg+0x1270]

背景：S1 真机会话（2026-11-04 17:29，网关在连接突发内 0x1e 后发 0x23 值 1000）：0x23 被
派发、聚合回调运行、激活首次触发、v11c=1000 落入聚合；随即访问违例 rip=0x142ac16b0、
返回地址 0x1416820bd、Frida dump（回调入口）[agg+0x1270]=0、fc8=0、area98≠0。进程死亡、
无 0x9a。16:16（值 0）崩溃签名相同 ⇒ **值假说就此证伪：值从来不是崩因**
（evening4 §6 机理 1 作废）。本节拆尾部链。

### 1. 崩点定位（已实证）

回调 0x1416820a0 全函数（0x1416820a0–0x14168219a）：

```
push rbx; sub rsp,0x90; mov rbx,rcx
0x1416820ac: call 0x14212fd90            ; 激活
0x1416820b1: mov rcx,[rbx+0x1270]
0x1416820b8: call 0x142ac16b0            ; ← 返回地址 0x1416820bd，与崩溃回溯首帧吻合
0x1416820bd: cmp qword [rbx+0xfc8],0     ; fc8/area98 的判空都在此后（崩了到不了）
...
```

- 对 [agg+0x1270] 的这次调用**无任何判空/分支**：激活返回即 reload 字段直调。与同函数
  后半对 fc8（cmp 0/je）、area98（test/je）的双重判空形成鲜明不对称——回调作者默认
  「激活合法触发时 +0x1270 必已装好」这一不变式，而该不变式在我们的时序下不成立（§3）。
- 回调入口（Frida dump）与该 call 之间只有激活 0x14212fd90 执行；激活全函数已复核：
  **不访问 +0x1270、不调用 §3 的任何写者**（其本体 = 抬闸 → 排空世界队列 → 释放 →
  清闸/置 +0x86a → 遍历 [world+0x5b8] 实体做注册收尾）。故 call 时点 [agg+0x1270]
  仍为入口 dump 的 0（证据链已实证；寄存器毒值异常见 §2 末）。

### 2. 0x142ac16b0 是什么（结构已实证；语义为推断）

函数本体（0x142ac16b0–0x142ac16f7，find_fn 确认起点即自身）：

```
mov r9,[rcx+8]        ; 外层 end
mov rdx,[rcx]         ; 外层 begin
cmp rdx,r9; je ret    ; 空即返回——但 rcx 本身不判空
外层循环（步长 0x950）:
  r8=[rec+0x938]（内层 end 指针）; rcx=[rec+0x930]（内层 begin 指针）
  内层循环（步长 0x940）: [elem+0x930] = [elem+0x934]   ; 待决值 → 已提交值
ret
```

- 入参 rcx 须指向 +0x1270 子系统对象：以 +0/+8 为 begin/end 的两级数组存储（外层记录
  0x950 B、内层元素 0x940 B，数值字段位于元素尾部 +0x930/+0x934）。0x142ac16b0 = 该
  存储的「提交待决值」遍（commit pass）。同簇函数 0x142ac0d10（以 agg 初始化对象）、
  0x142ac1970（登记/初始化）、0x142ac1700（按 [elem+0x900] 键查找）、0x142ac28f0
  （另一遍）构成该子系统的操作集——**推断：这是世界的一套 ECS 式组件数据存储**
  （具体子系统名静态不可考）。
- **崩溃机理**：rcx=0 时首指令 `mov r9,[rcx+8]` 即解引用近零地址 → 访问违例、rip 停在
  函数首址 0x142ac16b0、回溯首帧为回调 0x1416820bd——与真机三项特征逐一吻合。
- 毒值 0xffff800af4ca0000（异常上下文 rcx=rdx=r8）：**该常量在二进制中不存在**
  （qword/dword 全扫 0 命中）；§3 的全部写点只可能写入 0 或新分配地址；激活路径亦无
  写点。故它不可能由已识别路径写入 [agg+0x1270]。与「入口 dump=0 + 首指令解引用」
  定案并存的最合理解释是异常上下文在客户端自身首机会处理之后才被读到（上下文污染），
  属**未解异常**，不影响机理定案；判别法见 §4(c)（钩 0x1416820b1 直读 reload 值，
  或对字段下写监视，二选一即可钉死）。

### 3. [agg+0x1270] 的写点全表（已实证）

全 .text disp-0x1270 扫描（225 处，逐条以对象基址来源判别）后，基址确为世界聚合的
写点只有两处：

1. **ctor 0x14167d470 @0x14167d5ff**：`mov [rdi+0x1270], r12(=0)`——聚合构造时清零
   （连同 +0x1278..+0x12f8 一片标量）。字段生而为 0。
2. **ensure 方法 0x141681720 @0x1416817bc**：字段的唯一「装配者」：
   - 入口先判 [agg+0x1270]：非 0 → 跳过装配，直接对现存对象做 0x142ac1970 初始化 +
     [agg+0x508] 向量过滤 + 调 0x142ac16b0 + 0x142ac28f0；
   - 为 0 → 0x142bba600 分配 **0x1688 B** → 清头 6 个 qword → 子对象构造（+0x30 调
     0x14122be10；+0x590/+0xe08 调 0x14122bba0）→ 0x142ac0d10(obj, agg) → 交换写入
     [agg+0x1270]（旧对象存在则析构并以 0x1688 尺寸释放）→ 同上初始化/提交/通知。
   - ensure 内部在 0x141681889 调 0x142ac16b0 前同样**不判空**——靠「自己刚装好」
     保证非空，与回调同一不变式风格。
3. ensure 的直接调用方有且仅有一处：**0x14167b8ce，位于聚合方法 0x14167b3f0 内**。
   ensure 本身不在任何虚表里。
4. **提交方法 0x14167b3f0**（ensure 的主人）：聚合**主虚表 0x14339d1d0 的 +0x1e0 槽**
   （亦是 facet 虚表 0x14339d148 的 +0x268 槽，同一函数地址）。形态（已实证）：入参
   (agg, edx, r8d, r9, 栈上向量等) → 按 [agg+0x98] 区域描述符 +0x1b4 种类（0x20/0x21/
   0x23 为特殊类）设 [agg+0x663/0x664] → (edx,r8d,r9) 写 [agg+0x4b0] 参数块 → 栈传
   向量替换 [agg+0x508] 向量（即 ensure 里被过滤的那个 (ptr,float) 向量）→ 按区域种类
   选名 "world_map"/"client"（字符串 @0x14339c290/0x14339c2b8，与 "Tile hash: " 同簇）
   构串 → 暂存句柄对提交进 [agg+0x11f0]（旧值经虚表 +0x130 释放）→ **call ensure** →
   call 0x141680c70 → 以事件号 0x1f4d 作用 [agg+0x128] 成员、结果存 [agg+0x132c]。
   即这是一次「把当前区域的参数/状态正式提交进世界聚合」的重型方法，ensure 是其尾环。
5. 提交方法的到达路径（否定面已实证；肯定面为强推断）：
   - **没有任何服务器消息能到达它**：实例分发器 0x1421220f0 中对聚合的两处虚调用
     （0x1421245f3/0x142124660 的 [vtable+0x268] 及 +0x270）读的是**主虚表**——主虚表
     +0x268/+0x270 均为 `ret 0` 空桩 0x14010a080（已实证），与 facet 编号的同名槽不是
     一回事（本节最大的编号陷阱）；分发器其余聚合调用是字段存储小函数
     0x14211dc60/dc90/dca0/dcd0，亦不到达提交方法。会话/世界/状态机/实例创建诸簇内
     `call [vtable+0x1e0]` 的唯一命中（0x142806c1e）经核为另一类对象的属性通知器
     （基址对象只有 +0x16c/+0x177 小字段），同偏移噪声。
   - 提交方法另有一个**默认参数包装器 0x140b99180**（以全零/空参对象调 0x14167b3f0）；
     包装器的两个直接调用方 0x140b6d390/0x140b713f0 形态一致：先经 0x140b97c20
     取得/创建聚合 → 调包装器提交 → 把聚合存为当前（如 [rbx+0x310] 换装）。
     **推断（强）：提交由客户端自身的世界管理/游戏状态流驱动**——「取得聚合 → 提交 →
     设为当前世界」是引擎内部的世界装配流程，最自然的时机是区域生成完成、进入
     in-game 态前后。
   - 同偏移噪声备查：[session+0x1270] 是会话自身的另一字段（0x14211e129 写、
     0x142124218 读，基址 r15=session，与聚合无关）；扫描其余命中为栈槽与无关类。

### 4. 修复方向判读

(a) **S2 时序（0x9a 之后再发 0x23）避开本崩点的概率：高（推断，本节证据链支持的
最强一步）。** 依据：S1 的崩溃是纯时序问题——0x23 在连接突发内到达（0x1e 后约
0.5 s、区域尚在生成）时提交方法还没跑（字段入口 dump=0 为据）；提交是客户端本地
流程、与生成完成同簇（其构串用的 "world_map"/"client" 与生成日志字符串同址簇、
其读取的区域描述符与参数都以生成产物为前提）；0x9a 是客户端自报「区域已生成」的
信号，其后客户端本地装配最可能已完成。届时回调里 [agg+0x1270] 应非 0，
0x142ac16b0 对空数组直接返回（begin==end），尾部链安全通过。**残余风险**：若提交
实际由「进入 in-game 态」驱动、而 in-game 态又以世界被 tick 为前提（基线会话里
世界从未 tick、加载屏从未退出，提交是否在基线里跑过静态不可知），则 S2 仍会
在同一指令崩——该会话同时就是判别实验（见 (c)，一次定案）。
(b) **没有候选消息**：+0x1270 不由任何服务器消息填充（§3.5 否定面已实证）——不要
为它找消息、不要在 0x23 里加字段或改 0x1e。服务器侧唯一要改的是 0x23 的**时机**。
(c) 下一会话（即 S2 会话）顺带挂的判别钩子（Frida，一次定案）：
   1. 钩提交方法 0x14167b3f0 与 ensure 0x141681720 入口：记录 (agg, 时间戳)——看它们
      是否在 0x9a 前后、回调之前触发；
   2. 钩回调的 reload 点 0x1416820b1：直读 [rbx+0x1270] 的实际载入值（钉死毒值异常）；
   3. （可选）对回调 dump 给出的 agg 地址 +0x1270 下 MemoryAccessMonitor 写监视：
      抓任何写入者的指令地址。
   判读：提交在回调前触发且字段非 0 → S2 路线成立、本崩点关闭；提交整场不触发 →
   触发点在游戏状态迁移层（基线同样未达），下一步转查 0x140b6d390/0x140b713f0 两个
   「取得+提交+设为当前」函数的上层调用方与 [rbx+0x310] 持有者（世界管理器）的
   状态迁移条件；字段被写成非 0 怪值 → 以写监视的指令地址为准新开一线。
