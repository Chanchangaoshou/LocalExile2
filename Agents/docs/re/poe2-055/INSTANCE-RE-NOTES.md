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

## 2026-11-04 evening7 — player blob component audit

任务：S2 会话（17:44，bbbbbb，blob 1101 B）实体 ctor 首次运行即抛 Buffer
Underflow。把 ctor 的组件消费与 fork 的 `PlayerObject.Blob()` 逐项对齐，定
第一个分叉点。以下地址均为 0.5.5 原始 exe 静态反汇编（已实证 = 逐指令读出；
推断 / 待验假设逐条标注）。

### 0. 回溯五地址定点（已实证）

| 回溯地址 | 定点 |
|---|---|
| 0x141e70750 | ctor 0x141e705d0 内调用 blob 读取子程 fn C（0x141e712a0）的返回址——即 blob 消费在 ctor 的第二阶段（实例化之后）统一进行 |
| 0x141e7137b | fn C 组件循环内虚调用 `call [comp_vtable+0x98]` 的返回址——抛点位于「某个组件的 read fn」内 |
| 0x1421811a8 | read fn B（0x142181160）内、其第一 stat map 循环中读取 pair 的 **key** 后调用读助手 A 的返回址 |
| 0x1419973fe | A 内 `call 0x142c14380`（throw helper，位于 0x1419973f9）的返回址；该抛点 stub 的错误参数 r9d=1 且不设 r8（游标寄存器），是 A 的**首字节读**失败点 |
| 0x142134f4b / 0x14212fdfe | CreateObject handler / 激活排空（与 evening 世界层结论一致，不再展开） |

抛点形态定性（已实证）：A 在游标**恰好到达 blob 末尾（剩余 0 字节）**时读
下一个 key 的首字节（1 字节读）失败。即假 pair 循环把 blob 吃到最后一字节、
再多读一口才抛——不是「读到中段某定长字段不足」。

### 1. ctor 的 blob 消费结构（fn C = 0x141e712a0，已实证）

ctor 0x141e705d0 参数：rcx=entity（rsi）、rdx=&typeInfo、r8d=entityId（edi）、
r9=&blobSpan（rbp）、第 5 栈参 → [entity+0x78]=world。流程：基类 ctor
0x142601190 → 清零实体字段、装实体虚表 0x1434D55A8 / facet 0x1434D5568、
[entity+0x88]=entityId → 实例化子程 0x141e70790（按描述符表建组件实例）→
对组件向量逐个调 vtable+0x10（rcx-only，非 blob 读，像是 finalize）→
**fn C(entity, span) 读 blob** → 阶段二（[entity+0x78] vtable+0x1b8 →
0x141e72a00、0x141e70900）。

span 布局：{+0 begin, +8 end, +0x10 cursor}；每个读点先界检
（cursor+n > end → 错误构造 0x1421bffd0（r9d=所需字节数）+ throw helper
0x142c14380 + int3），异常类型对象在 rdata 0x1439FE7B0（"Buffer Underflow"）。

fn C 的读取顺序（逐指令读出）：
1. **1 字节 object flags**：bit0 → [entity+0x8d] |= 1；bit1 → [entity+0x8d] |= 4。
2. **base data**（子程 0x141e715a0）：u8 计数 N；每条 = u32 key + u8 kind +
   按 kind 的负载（0x141e7eb50）。N=0 时不读任何字节（fork 发 0 ✓ 安全）。
3. **组件循环**（esi = index 0,1,2,…）：上界 = **[[typeInfo+0x28]+0x78]**
   （描述符对象 D 上的 u64 组件个数；D 同时在 +0x298..+0x2a0 持有描述符
   向量）。逐个取实体组件向量 [entity+0x10] 的第 esi 个组件，**属主检查
   [comp+8]==entity** 不满足则跳过，满足则调 **[comp_vtable+0x98](comp, span)**
   —— 每个组件的 blob read fn。没有固定内联读，顺序完全由类型的组件表
   （.ot 数据驱动）决定。
4. **尾段 tasks**：u8 计数 M；M ×（u16 key + 按 key 注册的记录读程
   0x141e7dd60(entity+0x58, key, span)）。key 无注册读程时 0x141e7dd60 返回
   false、循环静默终止（不抛）。与旧版文档的 tasks 段同构。

注：0.5.5 的 read 槽是 vtable **+0x98**；旧版（fork 文档 04 §3）是 +0x88
（slot 17）——虚表布局已移位，旧版任何按槽位推的对应关系都不可直接搬。

### 2. 紧凑整数读助手与 fork 编码等价（已实证）

- **A = 0x141997220，无符号紧凑读**：b0<0x80 → 1 B；(b0&0xC0)==0x80 →
  ((b0&0x3F)<<8)|b1（2 B）；(b0&0xE0)==0xC0 → ((b0&0x1F)<<16)|…（3 B）；
  (b0&0xF0)==0xE0 → ((b0&0x1F)<<24)|…（4 B，读侧掩码 0x1F 是 fork 写侧
  28-bit 的超集，回读兼容）；b0≥0xF0 → 后 4 字节 BE（共 5 B，b0 纯标签）。
  **≡ fork `CompactUInt`，格式一致。**
- **0x141e25ed0，有符号紧凑读**（B 的 value 读）：1 B 形 b0&0x40 →
  value=b0−0x80（−0x40..0x3F），0x80 前缀形 ((b0&0x3F)<<8)|b1 带符号扩展，
  与 fork `CompactInt` 同族同构。**stat 对 (key, value) = (CompactUInt,
  CompactInt) 在 fork 与 0.5.5 间格式相同——pair 格式不是分叉点。**

### 3. read fn B 的完整线格式（已实证，逐指令）

B = 0x142181160（this=r13，span=rdi）：

1. **stat map → [this+0x1c8]**：count = A(span)；count ×（key = A(span)，
   value = 0x141e25ed0(span)，经 0x1426acb60 插入 map）。
2. **gate G = byte [[this+0x158]+0x20]**（+0x158 由基类构造 0x141dfc350 自
   类型定义对象设置；G 是定义侧标志，非 blob 内字段）。G≠0 时依次读：
   a. u8 → [this+0x168]；
   b. u8 长度 L；L>0 读 L 字节串（0x1423e57f0）→ 引用计数串 [this+0x170]；
      L=0 → 空串；
   c. **固定 3 个串槽** [this+0x180..0x1b0)（步长 0x10）：每槽 u8 tag；
      tag≠0 再读一串（长度参数 = tag−1，经 0x142504fc0；该「−1」语义为
      待验假设，疑 tag 本身即长度+1 编码）；
   d. u8 计数 N2（先按 [this+0x1e8] 向量元素 0x10 B 经 0x142119f30 预留
      容量）；N2 ×（u8 子键 → 0x142181e20 取/建子 stat map → 再读一个
      完整 stat map（A 计数 + A/S 对）入该子图）；
   e. 收尾 0x1421817a0(this)。
   G==0 时 a–e 全跳过（直达第 3 步）。
3. **公共尾**：u32 → [this+0x1b0]；u8 → [this+0x1b4]；u8 → [this+0x1b5]。

B 的身份（推断，强）：B 的地址在全 exe 只出现一次——rdata **0x14350bb08**，
恰为虚表 **0x14350ba70 的 +0x98 槽**；该虚表唯一的代码引用是组件构造
~0x142180c30（装 [this]=0x14350ba70、[this+0x18]=facet 0x14350BBA0、
[this+0x1b8]=0x14350BA68，并把 +0x1c8 的 stat map 放进一个引用计数子对象
（虚表 0x14350BBA8））。该类**无 MSVC RTTI**（0x143508000–0x14350bb10 内无
合法 COL；与 fork 文档「component classes have no RTTI」互证）。身份判定
依据：在 fork 旧版 schema 里，玩家 10 个组件中**只有 Stats
（ClientInternalStats，旧读 0x1421c2f40）以 stat map 开场**（Buffs 以 u16
计数开场、余者为定长/串开场），且旧 Stats 读的骨架 = 对流 + u32+u32+u8 尾
（空时共 10 B）与 B 的「对流 +（gate 段）+ u32+u8+u8」同构——差异 =
0.5.5 新增 gate 段、尾部 9 B 改 6 B。**B = 0.5.5 的 Stats 组件 read fn。**
gate 对 IntFour 的取值静态不可知（定义对象由 .ot 数据在运行时构建），
须动态读（见 §7）。

### 4. fork blob 逐节字节账（InstanceEntities.cs PlayerObject.Blob()，:898/:941）

写序（旧版组件序，Positioned 被旧版对象类型 ctor 提前到首位）：

| 节 | 内容 | 字节 |
|---|---|---|
| 头 | flags U8(0) | 1 |
| 头 | base data 计数 U8(0) | 1 |
| Positioned | I32 X + I32 Y + U32(0) + U16(0) + U8(0) + U8(0x02) + Shown 额外 U8(0)+U8(1) | 18 |
| Stats | CompactU 对数 + Σ(CompactU key + CompactI value) + U32(0)+U32(0)+U8(0) | 变长（空 = 10） |
| Buffs（原文 comp3） | U16(0) | 2 |
| Life | 3 × Pool(U32+U32+U16+U32+U32 = 18) + U8(0) | 55 |
| Animated | U8(1) + WStr32(AO 路径)（无路径时 U8(0)） | 1 + 4 + 2·len |
| Player（idx 6） | WStr32 名 + U8 职业 + U32 经验 + U32(0) + U16(0) + U16 头像 + FlagSet(任务旗) + FlagSet(联赛旗) + 9×0 + U16 藏身处 ×2 + U8 + 5×U8 + U32 + U8 | 变长 |
| Inventories（idx 8） | Σ VisibleItem + U8(0) | 变长 |
| Actor（idx 9） | WStr32("") + U16(0) + U8(0) + U32(0)×2 + 技能/灵魂段 | 变长 |
| 尾 | tasks U8(0) | 1 |
| 合计 | bbbbbb 本次会话（网关侧实测） | **1101** |

Pathfinding / PlayerClass 在旧版读 0 字节（ret 桩），fork 不写——若 0.5.5
仍是桩则无碍（待验）。

### 5. 第一个分叉点

**已实证**：
- 抛出点在 B 的第一 stat map 循环内（读 key 时、剩余 0 字节）。
- fork 的 blob 里格式完好的 stat map 只有 Stats 一节。若 B 起点 = fork 的
  Stats 节起点：count 与全部 pair 按 §2 的等价格式被精确消费（不可能在
  循环内 underflow）；即使 gate 为开，gate 段会把 fork 尾部 9 个 0 字节
  吃掉 6 个（u8/len/3×tag/子图计数全 0，合法），随后在公共尾的 u32 读
  （r9d=4）处抛——抛点形态与实测（pair 循环内、r9d=1）不符。**故 B 的
  起点不是 fork 的 Stats 节起点。**
- fork 各节首字节能给出的 count 上限：Positioned 首字节 = GridX 低字节
  0xC5（出生点 (197,261)，I32 LE = C5 00 00 00）→ A 解出 **327,680 对**
  （(0xC5&0x1F)<<16），需 ≥ 655,360 B 的 pair 流，blob 仅余 1,099 B →
  **必然在循环内耗尽**，且耗尽点恰在末尾（每对 ≥ 2 B、约第 ~500 对读
  key 时剩余归零）——与实测抛点逐项吻合。其余各节首字节（Buffs 0x00、
  Life 池值低字节、Animated 0x01、Player 名长低字节 0x06、Inventories
  物品数、Actor 0x00）给出的 count ≤ 31，循环在剩余字节内必能退出，
  产生不出本回溯。

**推断（强）：第一个分叉点 = 组件循环的 index 0（blob 偏移 2）。**
0.5.5 对 IntFour 的第一个组件 read 就是 Stats（B），fork 却在该位置写了
Positioned 的 18 B。即：**0.5.5 的组件序不再把 Positioned 提前**——
Character.ot 的原生序本就是 `Stats, Positioned, Pathfinding, Buffs, Life,
Animated, Player, PlayerClass, Inventories, Actor`（fork 文档 04 §3），
旧版靠对象类型 ctor 把 Positioned 提到首位；该提前行为在 0.5.5 的此路径
上不成立（或 .ot 继承链已变）。

**待验假设（备选几何，不可静态排除）**：B 仍在 index 1，但 0.5.5 的
Positioned read 消费 ≠ 18 B、落点恰在 fork Stats 对流中段某个 ≥0xC0 的
key 字节上。要落到该落点，Positioned 须比 fork 多吃数个字节（旧版 §4.0
的条件 f32×3 需 flags0&0x20，fork 写 0、不触发）。两几何由 §7 一次判别。

分叉的下游后果（已实证）：B 之后 fork 的全部 8 个数据节（Positioned /
Buffs / Life / Animated / Player / Inventories / Actor + tasks 尾）从未被
读到；1,101 B 中除头 2 B 外全被假 pair 循环吞掉。

### 6. 修正后的 blob 布局规范

帧（已与 0.5.5 对齐，fork 现状正确）：`U8 flags`（fork 发 0；bit1 置位会
给 [entity+0x8d] 加 4，与世界层笔记 §6 的实体图登记条件相关，保持 0、
待验）+ `base data: U8(0)` 空表 + 组件段 + `tasks: U8(0)` 空尾。

组件段（index 0 起）：
1. **Stats（read 0x142181160）**——按 0.5.5 重写：
   - CompactU 对数 + 对流（fork 现有 `Stats()` 数据**可直接复用**：快照
     属性表；格式已证等价）；
   - gate 段（**仅当 IntFour 的 gate≠0 时存在**，§7 定值后二选一）：
     全空安全形 = `U8(0)`（+0x168）+ `U8(0)`（空串）+ `U8(0)×3`（串槽
     tag）+ `U8(0)`（子图计数）= 6 个 0 字节——B 的读代码对每一项都显式
     处理空（len 0 → 空串、tag 0 → 跳过、计数 0 → 无子图），不猜；
   - 公共尾：`U32(0) + U8(0) + U8(0)`（6 B）——**删除旧尾 U32+U32+U8 的
     第二个 U32、多出的 3 B 必须去掉**。
2. **Positioned 及其后组件**：0.5.5 read fn 均未逐个静态定版（无 RTTI、
   顺序由 .ot 决定）。fork 的旧版格式（Positioned 18 B / Buffs 2 B /
   Life 55 B / Animated / Player / Inventories / Actor）只能作基线假设，
   须按 §7 的走序 trace 拿到每节的 (read fn, 实际消费) 后逐个静态对格式
   再定版——在此之前不要整包上线试。

### 7. 无数据来源清单与一次性判别方案

**fork 无数据来源、须写安全空形的字段**（全部在 Stats gate 段内）：
+0x168 的 u8、+0x170 的名字串、+0x180 起 3 个串槽、按 u8 子键的 stat map
群。空形写法以 B 的读代码为准（见 §6.1），均为 0/空、合法。其余组件
（Positioned 坐标、Stats 对流、Life 三池、Animated AO 路径、Player
名/职业/任务旗、Inventories 物品、Actor 技能）fork 均有数据来源，问题
在 0.5.5 格式未验，不在无源。base data 与 tasks 两段 fork 发空表（0）
本身就是 0.5.5 的合法空形（已实证）。

**判别方案（一次会话定三件事，不要求进图成功）**：
1. 钩 fn C 的虚调用点 0x141e71375：入口记 esi=index、[rcx]=组件虚表、
   span 游标偏移（[rdx+0x10]−[rdx]），返回再记游标 → 0.5.5 实际组件序、
   每节 read fn 与实际消费字节一次拿全（分叉几何、组件序、各节长度
   同时定案）。
2. 钩 B 入口 0x142181160：读 [[rcx+0x158]+0x20] 定 gate；并核对其
   index（与第 1 项互证 B 是否 index 0）。
3. 钩基类 ctor 0x142601190 返回后（或 0x142601300）：dump
   [entity+0x10..+0x18) 各组件的 [comp] 虚表序列 → 组件序全表；选角
   界面的预览实体若走同一构造，不开实例连接即可采集。

## 2026-11-04 evening8 — component order trace verdict

任务：判读 v11 走序 trace（idx0 虚表 VA ≈ 0x1434d24f8、消费 19 B；idx1 =
Stats；stats_gate = 1；comp_order dump 失败），给 index 0 定版、拆 fn C
循环框架、用 .ot 或修正 dump 点拿全序、更正 evening7 §5、产出下一版 blob
布局与 v12 钩子清单。地址均为 0.5.5 原始 exe 静态反汇编 + GGPK 实提取。

### 0. trace 结论复核（已实证）

- 基址差复核：Stats 运行时虚表 0x7ff64e86ba70 ↔ 镜像 VA 0x14350ba70，
  得模块基址后 idx0 运行时虚表 0x7ff64e8324f8 换算 = **0x1434d24f8**，
  与任务给定值逐位一致。
- idx0 的 +0x98 槽 = **0x141dd89a0**；Stats 的 +0x98 槽经同法复核 =
  0x142181160 = B ✓（虚表基址口径与 evening7 一致）。
- idx0 消费 19 B 的可信性：fn C 循环体内除虚调用外不读 span（见 §2），
  两次 comp_call 事件间游标差恰为 idx0 read fn 的消费，无夹带。

### 1. index 0 = Positioned（定版）

**类定位（已实证）**：虚表 0x1434d24f8 在全 exe 只有两处代码引用
（numpy 全对齐 RIP 扫描）：ctor 的虚表装配点 0x141dd8030 与析构
0x141dd8580（虚表槽 +0x00 本身，即 deleting dtor：对象大小 0x540）。
ctor 在 0x141dd8030 起写：[this] = 0x1434d24f8（主虚表）、
[this+0x18] = 0x1434D15B0（facet）、**[this+0x158] = rdx（类型定义
对象）**，并从定义侧播种 [this+0x1e0] = u16 [def+0x16]、
[this+0x1e2] = [def+0x1c]、[this+0x1e3] = [def+0x2d]。

**身份 = Positioned（推断，强）**：read fn 把两个 u32 存入 +0x444/
+0x448 并按世界区域网格钳制（经 world 虚表 +0x1a8 取区域对象，
+0x18/+0x20 为网格宽高，×0x17 = 23 世界单位/格换算，浮点支路同理）；
u16 存入 +0x1e0——与旧版文档 Positioned 的 team 字段偏移逐位相同，
且 ctor 正是从定义（.ot Positioned 块的 team 等）播种该字段；尾部
hidden/shown 可见性字节与旧版文档同构（旧：hidden→+0x1e7 bit0、
shown→+0x1e5 bit3；0.5.5：→+0x1e6 bit0、+0x1e4 bit3，位号相同、
偏移 −1）。无其他组件类有此字段谱。

**线格式（read fn 0x141dd89a0，已实证逐指令）**，按读序：

0. **Sector 前缀（定义门控）**：byte [def+0x29] ≠ 0 时先读 u32 A +
   u32 B；A 经名字查表（键串 "Sector" @0x1434D5E60，查 D+0x28 的
   map）写入同实体 Sector 组件的 +0x44。fork 旧文档独立记载过同一
   结构（"Positioned's 8-byte prefix belongs to types with a Sector
   component"）。**IntFour 无此段：[def+0x29] = 0（已实证——由
   §4 的 19 B 算术反推：含前缀则 ≥ 27 B，与实测矛盾）。**
1. u32 → +0x444（grid X）；u32 → +0x448（grid Y）；u32 → +0x44c；
   u16 → +0x1e0（team）。
2. **3 个标志字节**（read_exact(3) 进临时区，下称 flagsA/flagsB/flagsC）。
3. 条件段（按代码序；门控位即刚读的标志字节）：
   - flagsA&0x20：u32→+0x474、u32→+0x46c、u32→+0x470（12 B）
   - flagsB&0x04：u32×4 → +0x4b0/+0x4b4/+0x4b8/+0x4bc（16 B）
   - flagsA&0x04：u32→+0x440、u32→+0x48c（8 B）
   - flagsA&0x40：u32→+0x490、u32→+0x494（8 B；未置位时由 X/Y 浮点
     换算填 +0x490 的 double）
   - flagsA&0x02：**不读流**——按类型哈希 0x7700c879（回退
     0x31fb1f01）找同实体兄弟组件并拷其字段
   - flagsC&0x02：子读程 0x141ec9d20(span) → +0x208 子对象（以自身
     u8 标志开场，read_exact(1)；全格式待定）
   - flagsB&0x01：22 B 块 = u32×3（三元键，喂资源名构造）+
     read_exact(2) + u32 + u8×4，产物由 0x141de31a0 建子对象
     （语义待定）
   - flagsB&0x02：u8（hidden → +0x1e6 bit0）+ u8（shown → +0x1e4
     bit3），两者变更均调虚表 +0xc0 可见性回调（共 2 B）
   - flagsB&0x08：u8（→ +0x1e5 bit 0x40）+ u8 → +0x1e2（2 B）
   - flagsB&0x10：u32 → +0x450；flagsB&0x40：u8 → +0x478；
     flagsB&0x80：u8 → +0x47a
   - flagsC&0x01：子读程 0x141ed4200(span) → +0x1e8 内嵌子对象
     （自其 +0x10 起逐 u8 字段；全格式待定）
   - flagsA 的 0x01/0x08/0x10/0x80、flagsB 0x20、flagsC 0x04 只改
     内部标志位、不读流。

**19 B 构成与逐字节 diff（已实证，对 17:44/18:02 两次会话的真实
字节）**：fork 写 [X4][Y4][U32][U16][00][02][00][01] = 18 B。
0.5.5 读法：前 14 B 逐位相同（X=197、Y=261、U32=0、team=0）；随后
需要**三个**标志字节——fork 的 [00]→flagsA、[02]→flagsB、[00]→flagsC；
flagsB = 0x02 触发尾对：fork 的 [01] 被读作 hidden（bl），**再下一
字节是 fork Stats 节的首字节 0x80，被读作 shown（al）**。
即：**多出的 1 B 是 flagsB&0x02 的第二个尾字节；根源是 0.5.5 的
固定块比旧格式多一个 flagsC，hidden/shown 对整体后移一位，fork
的节恰好短 1 B。**（旁证：该会话中 Positioned 确实执行了
flagsB&0x02 块并把 hidden 置 1——错位机制自洽。）
- 最小形（全标志 0、无 Sector 前缀）= 17 B；
- 保持 fork 意图（hidden=0、shown=1）的正确写 = X,Y,U32,U16,
  flagsA=0, flagsB=0x02, flagsC=0, hidden=0, shown=1 = **19 B**。

### 2. fn C 循环框架（0x141e712a0，已实证逐指令；补正 evening7 §1）

- flags 字节（内联界检读）→ base data 子程 0x141e715a0 → 组件循环
  → tasks 尾，全程与 evening7 §1 一致。
- 循环体（0x141e71340–0x141e7137d）逐轮：typeInfo = [entity+0x8]，
  非空则 call 0x1421d7070(typeInfo)（不带 span，不可能读 blob）；
  D = [typeInfo+0x28]；上界 = **[D+0x78]**（u64，每轮重读）；
  comp = **[[entity+0x10] + esi×8]**（指针数组，步长 8）；
  属主检查 [comp+8] == entity，不满足则**跳过但索引照耗**；
  call [[comp]+0x98](comp, span)。
- **fn C 在循环内自身不读任何字节**——无 per-component 前缀/后缀；
  comp_call 游标差 = 组件消费本身（已实证）。
- 组件对象来源：实体 ctor 在 fn C 之前调实例化子程 **0x141e70790**，
  它遍历 D 的描述符向量（begin [D+0x298]、end [D+0x2a0]）按同序填
  [entity+0x10] 数组。
- **v11 comp_order dump 失败原因（已实证）**：钩子挂在基类 ctor
  0x142601190 返回点——此时 0x141e70790 尚未运行、[entity+0x10]
  未填充；且 [entity+0x18] 根本不是数组尾（循环只用 [entity+0x10]
  + D 的计数）。正确 dump 点 = fn C 入口（或 0x141e70790 返回点）。

### 3. 全序：.ot 集合（已实证）+ 序列化序（部分实证）

GGPK 实提取（提取前已确认游戏进程未运行；ggpk-extract 批量跑）：
- `metadata/characters/` 下**只有** character.ot、character_login.ot、
  character_mobile.ot 三个 .ot；**不存在** int/intfour.ot——职业对象
  类型由 Character.ot + Characters.dat 的 PlayerClass 注册
  （yamafutureclone_intfour.ot 实证同一模式：extends 基类 .ot +
  `PlayerClass { class = "IntFour" }`）。
- Character.ot（abstract，extends "nothing"）的服务端组件块声明序：
  **Stats, Positioned, Pathfinding, Buffs, Life, Animated, Player,
  PlayerClass, Inventories, Actor**（共 10；其后 client{} 块为客户端
  facet，不入服务端序）。
- 序列化序：[0] = Positioned、[1] = Stats（v11 trace 已实证）。
  其余为**推断**：Positioned 被提至首位、其余按 .ot 声明序 =
  Positioned, Stats, Pathfinding, Buffs, Life, Animated, Player,
  PlayerClass, Inventories, Actor。旁证（旧版真机 trace，fork
  PlayerObject 文档）：旧序为 Positioned, Stats, comp3(u16 计数 =
  Buffs), Life, Animated, Player@6, Inventories@8, Actor@9，
  Pathfinding 与 PlayerClass 读 0 B——与上列推断序逐位相容。
  **待验**：0.5.5 的组件总数是 10 还是旧版的 12（旧版 Actor 之后
  还有两个未验组件）——v12 dump 读 [D+0x78] 一次定案。

### 4. evening7 §5 正式更正（Stats 错位读的真实算术，已实证）

真实字节（网关日志，两次会话逐字节相同）：blob[20] = 0x80、
blob[21] = 0xBA、blob[22] = 0x81、blob[23] = 0x17、blob[24] = 0x02。
- fork Stats 节：count = CompactU[20..21] = ((0x80&0x3F)<<8)|0xBA
  = **186 对**；首对 key = [22..23] = 0x117 = 279、value = [24] 起，
  格式完好（若 B 从 20 起读本可精确消费）。
- Positioned（idx0）消费 [2..20] 共 19 B，其最后一个字节正是
  blob[20] = 0x80（被当作 shown 尾字节）。
- **B 从 blob[21] 起读：count = A(0xBA, 0x81) = ((0xBA&0x3F)<<8)|
  0x81 = 0x3A81 = 14,977 对**。每对 ≥ 2 B → 需 ≥ 29,954 B，余量
  仅 1,078 B → pair 循环必然把 blob 吃到最后一字节、在剩余 0 时
  读下一 key 的首字节抛错（A 的 r9d=1 stub）——与 17:44 回溯
  （B 第一 stat map 循环内、返回址 0x1421811a8）逐项吻合；B 至死
  未达 gate/尾段。
- **evening7 §5 的旧机制（B 自偏移 2 的 0xC5 解出 327,680 对）
  正式作废**：真实落点是偏移 21 的 0xBA → 14,977 对。失败形态
  相同、落点与数值不同。gate = 1 的结论不受影响（v11 在 B 入口
  自定义侧对象读得，与流位置无关）。

### 5. 下一版 blob 完整布局与确定程度

帧头与 tasks 尾维持 fork 现状（已与 0.5.5 对齐，已实证）。

| idx | 组件 | read fn（0.5.5） | 下一版写法 | 状态 |
|---|---|---|---|---|
| 0 | Positioned | 0x141dd89a0（vtbl 0x1434d24f8） | 19 B：I32 X、I32 Y、U32(0)、U16(team)、U8(0) flagsA、U8(0x02) flagsB、U8(0) flagsC、U8(0) hidden、U8(1) shown | **已定版**（格式已实证；hidden/shown 语义为强推断） |
| 1 | Stats | 0x142181160 = B（vtbl 0x14350ba70） | fork Stats() 对流原样 + **gate 段 6×0**（gate = 1 已实证）+ 尾 U32(0)+U8(0)+U8(0)（删旧尾第二个 U32） | **已定版** |
| 2 | Pathfinding | 待 v12 dump | 0 B（旧版为 ret 桩） | 待 trace |
| 3 | Buffs | 待 v12 dump | U16(0) 基线（旧：u16 计数条目） | 待 trace |
| 4 | Life | 待 v12 dump | fork 现 55 B 基线 | 待 trace |
| 5 | Animated | 待 v12 dump | fork 现写基线（U8 + 可选 WStr32 路径） | 待 trace |
| 6 | Player | 待 v12 dump | fork 现写基线 | 待 trace |
| 7 | PlayerClass | 待 v12 dump | 0 B（旧版读 0 B） | 待 trace |
| 8 | Inventories | 待 v12 dump | fork 现写基线 | 待 trace |
| 9 | Actor | 待 v12 dump | fork 现写基线 | 待 trace |
| 10/11? | （旧版 Actor 后另有 2 个未验组件） | 待 v12 计数 | 若 [D+0x78] = 12 则存在，按 dump 的 read fn 另行定版 | 待 trace |

确定程度小结：帧头 + idx0 + idx1 已逐字节定版；idx ≥ 2 仍为旧
格式基线假设。改完 idx0/idx1 后，Stats 将完整读完（186 对 + gate
+ 尾），循环推进到 idx2——同一会话里 v12 的 comp_call 游标差会把
idx ≥ 2 每个组件的真实消费一并测出（即使在某 idx 再抛错）。

### 6. 探针 v12 钩子清单（确切）

1. **fn C 入口 dump（新，替代失效的 comp_order）**：钩 0x141e712a0
   onEnter，rcx = entity：
   D = [[rcx+8]+0x28]；count = u64 [D+0x78]；arr = [rcx+0x10]；
   逐 i < count：comp = [arr+i×8]，发 {idx: i, vtbl: [comp],
   readfn: [[comp]+0x98], owner: [comp+8], def: [comp+0x158]}
   （def 字段非全组件都有，读失败记 null）。
   期望产出：组件总数（10 vs 12）+ 全序虚表 + 每个 read fn VA——
   与 §3 的 .ot 名单对照即得命名全序。
   同时 raw dump 描述符向量：begin = [D+0x298]、end = [D+0x2a0]，
   逐条发 8 B 原值，供离线对描述符布局。
2. **comp_call（沿用 v11）**：钩 0x141e71375 onEnter，发
   {idx: esi, vtbl: [rcx], cursor: [rdx+0x10]}（绝对游标即可，
   离线作差）。期望产出：idx ≥ 2 每个组件的实际消费字节数。
3. **stats_gate（沿用 v11）**：钩 B 入口 0x142181160，发
   {gate: [[rcx+0x158]+0x20]}。期望产出：复证 gate = 1。
4. 沿用 v11 的异常处理器、entity_ctor、world_* 钩子作回归上下文。
   删除 0x142601190 的 comp_order 钩（已证无效）。

## 2026-11-04 evening9 — downstream components

任务：判读 v12 真机 trace（组件总数 = 10；i2–i9 虚表/read fn 已给；
游标账：Positioned 19 ✓、Stats 605 完整读完 ✓、i2=0、i3=2、i4=125、
i5=1（错位位置的字节）、i6 起点错位 70 B 后在其 read 内 throw，
throw_call 自 0x1421c0555），逐个定版 i2–i9、拆 Life 的 125 B、
定点 Player 抛错、查 ctor 后段，并追加用户点名的「人物模型不显示」
三问。地址均为 0.5.5 原始 exe 静态反汇编；分级沿用前节。

### 0. trace 复核与换算（已实证）

- 运行时→VA 基址差由 i0/i1 双锚点复核，八个虚表的 +0x98 槽静态值
  与 trace 换算的 read fn VA **逐一相等**（i2/i7 同为 0x14010A080）。
- 共享空桩 **0x14010A080 = 字节 C2 00 00 = `ret 0`**（已实证）：它同
  时是 i2/i7 的 +0x98 槽与多个虚表的 +0x10/+0xa0 默认槽。
- 游标账闭合：626（Stats 末）+0（i2)+2（i3)+125（i4）+1（i5 错位
  字节）= 754 = comp_call 的 idx6 起点 ✓；fork 的 i6 起点在 684，
  差 70 = Life 一节的 125−55。

### 1. i2 = Pathfinding（read 恒 0 B）

- **read（已实证）**：+0x98 = 0x14010A080（ret 0 桩），消费恒 0 B，
  与 trace 的 i2=0 吻合。fork 写 0 B ✓ 无需改。
- **ctor 装配（已实证）**：装配点 0x141dcd216 起：[this] =
  0x1434D1E88、[this+0x18] = 0x1434D2420（facet）、[this+0xc0] =
  0x1434D19C8（内嵌子对象虚表）；对象 ≥ 0x578 B。
- **身份（推断，强）**：ctor 从定义侧播种一组浮点参数——[this+0x550]
  = (float)u16[def+0x5a]、[this+0x554] = −1.0f、[this+0x55c] = 1.0f、
  [this+0x574] = 9999.0f（0x461c4000），是移动/寻路族的量程参数；
  结合 .ot 序第 2 位与旧版同位组件读 0 B，命名 Pathfinding。

### 2. i3 = Buffs（vt 0x1434CF5E8，read 0x141DB5080）

**线格式（已实证，逐指令）**：
```
U16 count
count × 条目:
    U16 idA            ; 主读程内联读（0x141db50e0 循环头），随条目传给登记调用 0x141DB5AC0
    U8  flag           ; 同上传给 0x141DB5AC0 的 r9b
    记录子读程 0x141D72A90(span, &rec):
        U16 idB        ; → 内部按 id 查 BuffDefinitions 式定义（0x14260b9e0 一带）
        U16      → rec+0x00 附近（第二 id/句柄）
        U32      → rec+0x28
        U32      → rec+0x2c
        U16      → rec+0x38
        U32      → rec+0x34
        U16      → rec+0x3a
        U16      → rec+0x48
        U32      → rec+0x44
        U32      → rec+0x4c
        CompactU → rec+0x3c        ; 助手 A = 0x141997220
        U8       → rec+0xb8
        [定义侧门控：解析出的定义对象 +0xfe 字节 ≠ 0 时] U16 → rec+0x64
        U32 × K  → rec+0x10 向量   ; K = 该向量在定义解析期定下的长度（定义驱动，非流内计数）
```
- **空形 = U16(0) = 2 B**（已实证，与 trace 的 i3=2 吻合）；fork 现
  写 ✓ 直接可用。
- 非空条目的固定前缀 = 3 + 29 + CompactU +（门控 2）B，尾部 U32
  向量长度由定义数据决定——**条目总长为待验级**（fork 的玩家生成
  只写空表，不阻塞 v3；旧版「(u16, u8, 记录）」骨架与头部三件套
  巧合一致，记录内部已全然不同）。

### 3. i4 = Life（vt 0x1434C9FD0，read 0x141D8C260）——125 B 定版

**ctor 装配（已实证）**：装配点 0x141d86495（ctor 0x141d863e0，
1809 B)：[this] = 0x1434C9FD0、[this+0x18] = 0x1434C94A8（facet）、
[this+0x20] = 0x1433A4DD8、[this+0x50] = 0x1434C9D38；[this+0x190]
= 属主，[this+0x198]/[this+0x1a0] 由定义索引 [def+0xec]/[def+0xf0]
播种；各子对象在 ctor 内以不同 stat 常量组初始化（如 +0x1a8 组
{0x3335, 0x333c, 0xef, 0x584, 0x759, 0x2264, 0x37df}、+0x200 组
{0x6a92, 0xf0, 0x585, 0x1c9d}、+0x240 组含 {0xf1, 0x586, …}——
0xef/0xf0/0xf1 与 0x584/0x585/0x586 两组连续三元组是三池同族
stat 的指纹，推断）。

**read fn 骨架（已实证，逐指令）**：read fn 本身只做 9 次子读程
调用，全部流读都在子读程里：

| 序 | 目标 | 子读程 | 流读 |
|---|---|---|---|
| 1 | 子对象 +0x1a8 | A = 0x141D8BEC0 | 18 B |
| 2 | 子对象 +0x200 | B = 0x141D88E70 | 14 B |
| 3 | 子对象 +0x240 | A | 18 B |
| 4 | 子对象 +0x298 | B | 14 B |
| 5 | 子对象 +0x2e0 | A | 18 B |
| 6 | 子对象 +0x330 | A | 18 B |
| 7 | 向量 [this+0x380..+0x388)，元素步长 0x28 | 每元素 C = 0x141D8BA00 | 6 B/个 |
| 8 | 子对象 +0x398 | C | 6 B |
| 9 | Life 本体尾 | D = 0x141D8C1D0 | 1 B |

**子读程格式（已实证，逐指令）**：
- **C（0x141D8BA00）= 6 B**：U32 → [obj+0x18]；I16（movsx）→
  [obj+0x1c]。
- **B（0x141D88E70）= 14 B**：U32 → [obj+0x38]；内嵌 C（U32 →
  +0x18、I16 → +0x1c）；U32 → [obj+0x30]。
- **A（0x141D8BEC0）= 18 B**：先完整走 B 的 14 B，再 U32 →
  [obj+0x48]。
- **D（0x141D8C1D0）= 1 B**：U8 旗标——bit0 → [Life+0x3fa]、
  bit1 → [Life+0x3fc]、bit2 → [Life+0x3fb]；其后尾调
  0x14072B030(this+0x50， 名字常量）不带 span、不读流（推断为按名
  注册/收尾）。

**125 B 账目（已实证）**：4×18 + 2×14 = 100；向量元素数在构造期
由类型定义定死（read fn 内无计数读、A/B/C 的字段写不出 +0x380
范围），trace 总量反推 = 3 个 → 18；+ C 6 + D 1 = **125**，与
实测逐字节吻合。fork 的 55 B（3 池 × 18 + 1）自此作废。

**与 fork Pool 的关系（推断，强）**：A 记录的流序
(U32,U32,I16,U32,U32）与落点 (+0x38,+0x18,+0x1c,+0x30,+0x48）同
旧版 Pool 读（fork 注释 0x141e6be70：+0x30 current、+0x10
reserved、+0x14、+0x28、+0x40；写序同为 U32,U32,U16,U32,U32）
**五字段逐位 +8 对应**——A 即旧 Pool 在 0.5.5 的同构体，fork 的
`Pool()` 18 B 写法对单个 A 记录逐字节仍成立（current 落第一
U32、reserved 落第二 U32）。B = 缺尾 U32 的短池记录；C = 只剩
(reserved, percent）对的极简记录。
**值来源（待验）**：四个 A 按字段序对应哪四个池（Life/Mana/ES/
Spirit 为按 .ot/字段序的假设序）静态不可定，判别法：四 A 首
U32 分别写 101/202/303/404 进图读 HUD/面板。fork v3 应写：
A(Life,LifeReserved=0)、B(0)、A(Mana,ManaReserved)、B(0)、
A(ES,0)、A(0)、C×3(0)、C(0)、D flags U8(0)——除三池 current/
reserved 外全 0，总长恒 125。

### 4. i5 = Animated（vt 0x1434CE5C8，read 0x141DA66C0）

- **ctor（已实证）**：装配点 0x141da2740（[this] = 0x1434CE5C8、
  [this+0x18] = 0x1434CF3C8 facet、[this+0x168] = 定义对象——
  注意本类 def 在 +0x168 而非 +0x158，fnC_table 当时读 +0x158
  得 0 与此自洽）；对象 0x370 B（析构释放尺寸）；ctor 把
  [this+0x190] AO 引用对清零、两个路径串（+0x1d0/+0x200）置空
  ——**不预置任何默认 AO、不建实例**。
- **线格式（已实证主干，逐指令）**：
```
U8 flags
flags&1:  ; 有 AO
    flags&2: U32 索引 → 查类型定义表（[typeInfo+0x28]，行距 0x2C）取 AO 条目
             → [this+0x190] 引用对；随后按条目 +8 的 UTF-16 路径建模（见下）
    else:    U32 字符数 + UTF-16LE 路径串（内联读，越界尾 = 同名串读程一族）
    两路汇合：若路径 ≠ 组件现存路径（[this+0x350]），经 0x140BC8280 查资源、
             分配 0x308 B 的 AO 实例（ctor 0x141D2C750）、由 0x140BEB2D0 取
             模型描述、调 0x141DA37E0(this, …) 把模型挂上组件 —— 模型在
             read 内即时创建
flags&4:  子读程 0x141DA9FC0(this, span)：开场 U32×3 后按首值分支
          （模式 0 → 0x141DA8430(值对)；≠0 → 串构造支）——概要级，未定版
flags&8:  段：U32 + U32 + 其后至少 U32 + U32 与串处理
          （0x141D46D30/0x140152840 一带）——概要级，未定版
```
- **fork 对照**：现写 U8(1) + WStr32(路径）= flags 1 的串形，与真
  格式逐字节吻合 ✓；U8(0)(无路径）= 三段全关、合法但无模型（见
  §8)。bit2/bit3 段 fork 不写、玩家生成不需要，定版押后。

### 5. i6 = Player（vt 0x1433A7D20，read 0x141DCF4A0）——全格式与抛错定性

- **ctor（已实证）**：装配点 0x14171aab0（ctor 0x14171aa90，先调
  基类 0x141dcf110)：[this] = 0x1433A7D20、[this+0x18] =
  0x1433A7D18（facet = 主虚表 −8）、**[this+0x158] = 0x1433A86D0
  —— .rdata 里的静态定义对象**（与 trace 的 def 运行时值换算
  逐位一致）；对象 ≥ 0x438 B。
- **完整线格式（已实证，逐指令；this=rsi、span=rdi）**：
```
 1. 名串 → [this+0x1b0] 字符串对象   子读程 0x1421C04A0：U32 字符数 + UTF-16LE
 2. U8  职业字节                      与属主 facet 的 +0x158 字节同步（变更调 0x141DEFA60）
 3. U32 经验                          → 暂存 r13，尾段由 setter 0x141DD1360 落账
 4. U32 → [this+0x1d0]
 5. U32 → [this+0x1d4]
 6. U16 → [this+0x200]
 7. U16 → [this+0x202]
 8. FlagSet → [this+0x248]           子读程 0x141DEEBF0（格式见下）
 9. FlagSet → [this+0x260]           同上
10. 原始 5 字节 → [this+0x278]       read_exact(5) = 子读程 0x1421C0260(r8d=5)
11. U16 键一                         按 [typeInfo+0x28]+0x58 表解析 → 引用对 [this+0x280]/[this+0x288]
12. U16 键二                         同上 → [this+0x290]/[this+0x298]
13. U8  旗标                          bit0 → [this+0x206]；bit1 → [this+0x208]；bit2 → [this+0x20c]；
                                     bit3 → 尾段虚调用 +0x140 的参数。bit0 置位另有世界侧
                                     副作用（置世界对象 +0x2a1 位并以 8 字符名调 0x141E52C30——
                                     与 fork 旧注释「非 0 → WashedUp 态」同位）
14. U8 → [this+0x205]
15. U8 → [this+0x3e7]
16. CompactU 计数 N × U32            → 临时向量后经虚表 +0x1c8 交给组件（id 列表）
17. 尾表（子读程 0x141DEECB0 → 虚表 +0x1d0）：U8 计数 M × 条目
    （条目 = 子读 0x141DEF8A0 读 U32 键并按同一张 +0x58 表解析 + U32 → [条目+0x10]）
```
  FlagSet 格式（0x141DEEBF0，已实证）：U16 块数 → 0x141DF28E0
  按数预置 9 字节/块的数组；每块 = read_exact(1) 块号 + read_exact
  (8) 位图（均经 0x1421C0260）——**与 fork WriteFlagSet 逐字节
  一致** ✓。
- **抛错定点（已实证）**：0x1421C0534 是名串读程 0x1421C04A0 的
  越界尾巴（34 B 小函数：构造错误 0x1421BFFD0 + 调 throw helper
  0x142C14380，返回址 0x1421C0555 与 trace 的 throw_call 逐位
  一致）。名串读程在 0x1421C04DB 处界检失败即 `ja 0x1421C0534`
  ——读到的 u32 字符数来自错位 70 B 处的 fork Inventories/Actor
  字节，2×count 远超剩余 → 抛。**定性：本次抛错是纯错位后果**
  ——名串本身就是 Player 的第一个字段且与 fork 的 WStr32 逐字
  节同构（见下 diff 第 1 行），格式无差。
- **但格式本身另有真实差异（已实证，逐字段 diff）**：

| fork 现写 | 0.5.5 实证 | 判定 |
|---|---|---|
| WStr32 名 | U32 数 + UTF-16（0x1421C04A0) | ✓ 一致 |
| U8 职业 | U8 | ✓ |
| U32 经验 | U32 | ✓ |
| U32(0) | U32 → +0x1d0 | ✓（双 U32 的第一个） |
| U16(0) | **U32 → +0x1d4** | ✗ fork 少一个 U32（此处起短 4 B) |
| U16 头像 | U16 → +0x200 **且还有** U16 → +0x202 | ✗ 真格式是两个 U16 |
| FlagSet ×2 | 0x141DEEBF0 ×2 | ✓ 一致 |
| Zeros(9) | read_exact **5** B → +0x278 | ✗ 9 → 5（多 4 B) |
| U16 藏身处 ×2 | U16 键解析 ×2 | ✓ |
| U8(0)(+0x1b1) | U8 旗标（bit0..3) | ✓ 尺寸合，语义为旗标字节 |
| 5 × U8(0) | 仅 U8 → +0x205、U8 → +0x3e7 两个单字节 | ✗ fork 多写 3 B |
| U32(0)（计数＋列表） | **CompactU** 计数 × U32 | ✗ 计数宽度（空时 4 B → 1 B) |
| U8(0)（微交易计数） | 0x141DEECB0: U8 计数 ×（U32 键 + U32) | △ 空形同为 1 B，非空语义全异 |

- 空形总长（名 6 字符、无旗标集、无列表）= 16+1+4+4+4+2+2+2+
  2+5+2+2+1+1+1+1+1 = **51 B**（fork 同形 57 B）。

### 6. i7 = PlayerClass（read 恒 0 B）

- **read（已实证）**：+0x98 = 0x14010A080 ret 0 桩，恒 0 B；fork
  写 0 B ✓。
- **ctor 装配（已实证）**：装配点 0x141dd4b24:[this] =
  0x1434D15B8、[this+0x18] = 0x1434D26E0（facet）；尾段
  [this+0x158] = byte [rdi+0x10]、[this+0x160] = rdi——它持有一
  个**兄弟对象指针**并镜像其 +0x10 的一个字节（+0x158 在本类是
  字节字段、不是 def 指针；fnC_table 当时读 +0x158 得 0 与此
  自洽）。
- **身份（推断，强）**:.ot 序第 7 位 + 「引用职业定义对象 + 镜
  像其类别字节」的字段谱，与 PlayerClass（绑定 Characters 行）
  吻合，无其它候选。

### 7. i8 = Inventories（vt 0x1434C8C38）

- **ctor/身份（已实证装配、身份推断强）**：工厂 0x141D828F0 以
  0x138 分配：[this] = 0x1434C8C38、[this+0x18] = 0x1434C9210
  (facet)、[this+8] = 属主、+0xC8 处就地建哈希表；**对象只有
  0x138 B，根本不存在 +0x158**（fnC_table 的 def 读失败与此自
  洽），read 无任何 def 门控。read 路径处理「槽位 + 可见物品外
  观引用」并登记进该哈希表 → Inventories。
- **read 路径（已实证）**:+0x98 槽 0x1416E6D70 是跳板
  (`jmp [rax+0xB0]`)，本体 = 虚表 +0xB0 槽 **0x141D82BC0**。
  **fork 旧注「+0xa0 读 Inventories」在 0.5.5 不成立**(+0xa0 =
  ret 0 桩）。
- **线格式（已实证，逐指令）**：
```
U8 N
N × 条目:
    U8 slot
    子读程 0x1426C41A0:
        U8 type                   ; ==0 → 条目结束（空条目共 2 B）
        type≠0:
            A 0x1426C3D80 = U16 + U32 + U8     ; 7 B，外观引用一
            B 0x1426C3F50 = U16 + U32 + U8     ; 7 B，外观引用二（解析表不同）
            C 0x1426C4FD0 = U8                 ; 姿态（行距 0x11 查表）
            D 0x1426C4C50 = U16                ; VisualIdentity（HASH16 解析）
            U8 → 条目+0x80
            U8 → 条目+0x81        ; read_exact(0x1421C0260)
            U8 → 条目+0x82        ; read_exact(0x1421C0260)
U8 M
M × U32                           ; 第二段：技能重绑 id 表（推断语义；宽度已实证）
```
- **与 fork 的 diff（已实证）**：主计数/slot/空条目/引用一/引用
  二/Stance/VisualIdentity 全部一致；**每件非空物品尾字节 fork
  写 1 个、真格式 3 个（少 2 B/件）**；第二段 fork 空形同为单个
  0 ✓，但非空时宽度是 **U32 不是旧版 U16**。空形合计 2 B 与
  fork 现写一致 ✓；单件非空 = 22 B(fork 20 B)。

### 8. i9 = Actor（vt 0x1433A36A8）

- **ctor/身份（已实证装配、身份推断强）**：工厂 0x1416D7610 以
  0xCD0 分配、基类 ctor 0x142147160 后覆写虚表组：[this] =
  0x1433A36A8、[this+0x18] = 0x1433A4E70、**[this+0x158] =
  0x1433A34B0 是二级子对象虚表、不是 def**（基类先装一个 .rdata
  虚表、工厂再覆写；trace 的「def 非空」与此不矛盾但性质须纠
  正）；真正的描述符/上下文指针在 [this+0x9B8]。主读程独占
  「授予技能表 + 灵魂预算 + 冷却组」→ Actor。
- **read 路径（已实证）**:+0x98 的 0x1416D8210 是 wrapper（自
  身消费 0 B)，尾调主读程 **0x142147300**;+0xa0 是 ret 0 桩，
  **fork 旧注「标志字节由 +0xa0 子读程读」证伪**。
- **主读程线格式（已实证主干，逐指令）**：
```
段1 三槽（this+0x2C8 起、步长 0x28、共 3）：
    每槽 = U8 + U8 + WStr32        ; 空槽 6 B，段空形 18 B（槽语义未定）
段2 技能子系统 0x142149510(this, span, 模式=1 创建）：
    U8 F2nd                        ; 本段旗标
    [创建模式无条件] 技能表 0x14218A9D0（作用于 this+0x9C0):
        U8 n × 技能记录 0x142188D50
        U8 m × (U32 row, U32, U32）灵魂预算
        U8 k × U8 字节表           ; ← fork 缺此段
        U32 g × 冷却组（U32 key, U32 c, c × 16 B)
                                   ; 技能表空形 = 7 B，段2 空形 = 8 B
    F2nd&0x10: 子读程 0x1421428C0  ; U32+U32+U16 开场 + 记录表（概要）
    F2nd&0x02: U8 → [this+0x1C8]
    F2nd&0x20: U16（行号查表）
    F2nd&0x01/0x04：仅内部位，不读流
段3 read_exact(3) 旗标 F0,F1,F2；U16 → [this+0x2B2]；U8 → [this+0x2A3]（旗标字节）
段4 四条目（步长 0x1C)：每条 = U8 flags; bit0→U32; bit1→U32; bit2→U32（空形 4 B)
    其后 U32 → [this+0x4BC]（无门控）
段5 F0 门控（按位序）：
    &0x02: WStr32 → [this+0x218]
    &0x04: U8（姿态调用 0x141E52D10)
    &0x08: U32 → [this+0x230]
    [内部状态门控] 兄弟组件（描述符 +0xE0 索引）dword [+0x1E0] ≤ 0 时：
        U16 + U8 + U32 = 7 B       ; 与旧版「生命 <1 才读」同位（推断同一机制）；
                                   ; 满生命玩家应跳过（推断）
    &0x10: U32 → +0x3C4; U16 → +0x3D0
    &0x20: 仅置位；其内 &0x40: U16 → [this+0x3D8]
    [段3 的 +0x2A3 字节]&0x04: U32 → +0x3CC; U16 → +0x3D4
    &0x80: CompactU 对 × (CompactI, U32 位型 f32）向量
段6 F1 门控：&0x01 子读 0x14214C6A0(U8 对 × (U32,U16));&0x02 U32 世界查表；
    &0x04 U32 → 兄弟 +0x554;&0x08 U32 → +0x440;&0x10 U32 ×2 → +0x444/+0x448;
    &0x20 U32 键查技能向量、命中才子读 0x14196FFD0(;&0x40 再调 0x141DCD380);
    &0x80 子读 0x141E59D90（均概要级）
段7 F2 门控：&0x01/&0x02/&0x04 均为 U32（或 U16 对）键查技能向量、命中才变长子读；
    &0x08 U16 个数 × 记录 0x141998600（概要）；&0x10 U32 → [this+0x424]
    ——主读程至此结束，无其它尾段（已实证）
```
- **技能记录 0x142188D50（已实证主干）**：
```
U32 id                             ; ← fork 写 U16，少 2 B
U8 selector                        ; ← fork 无此字节，少 1 B
引用 0x142684090 = U8 + U32 row    ; GEPL（行距 0x74)
  + 嵌套引用 0x142683DB0 = U8 a; (a≠0 再 U8); U32 row   ; 属性集（行距 0xB9)
  + 附加集个数 × 嵌套引用          ; 个数由 GEPL 行数据决定、非流内计数
U8 flags                           ; bit0 → 紧跟 U32 + U32; bit1 无门控读（fork 写 0x02 不错位但无意义）
U8 supportCount × （引用 + U32)
U32 + U32 + U32                    ; 第三个对应 fork 的 CooldownMs 位
U8
属性表 CompactU 对 × (CompactU, CompactI)   ; 与 Stats 同格式
附加集个数 × 同形属性表
[GEPL 行 +0x10D 列表存在时] U8 count × 元素（内部查表 + 若干 Compact 属性表，概要/待验）
```
  零前缀、无附加集、无支持、尾段不存在时单条 = **31 B**；尾段
  存在则 32 B（**待验**，须按所选默认技能的 GEPL 行核对）。
- **与 fork 的 diff（已实证）**：fork 的 Actor 段（WStr32("") +
  U16 + U8 + U32×2 + f0/f1 + 技能表）与真格式**全面脱节**：
  开场串不存在（串只在段 1 三槽内）；旗标是 F2nd 1 B + F0/F1/F2
  3 B 而非 f0/f1 2 B;**技能表在创建模式下无条件必读、不被
  0x40 位门控**（fork 以 f0=0x40 触发技能表的写法人会误触发段
  5 的 U16 门控并整体错位）；技能表多一段 U8 字节表；条件段
  2 B → 7 B。**空形：fork 17 B → 真 40 B**（段1 18 + 段2 8 +
  段3 3 + U16 2 + U8 1 + 段4 4 + U32 4；条件段触发则 47 B）；
  带 1 条默认技能 = **71 B**（尾段存在则 72 B）。

### 9. ctor 后段（fn C 返回后，已实证）

实体 ctor 0x141E705D0 在 fn C 返回（0x141E70750）后只剩三步，
**都不带 span**：
1. `call [[entity+0x78]+0x1b8]`（世界侧工厂/服务对象）→
   0x141E72A00（该对象， entity)：以 [entity+0x88] 的实体 id 在
   世界对象的树/图中查找登记（开场即 id < 0x40000000 检查与树
   走位）——实体向世界的**登记/挂接**步；
2. 0x141E70900(entity)：先调基类 0x142601380，再遍历组件数组
   [entity+0x10..+0x18) 逐个做后读处理（虚调用，无 span）；
3. 返回实体。
**结论**：fn C 是 blob 的最后一个消费者；ctor 后段不可能再抛
Buffer Underflow。它们理论上可因世界状态抛其它异常（未见证
据），下一轮真机 trace 以「entity_ctor 是否返回」判读。

### 10. 「人物模型不显示」三问（用户 18:25 截图点名）

当轮事实：河岸场景已渲染、无任何人物模型；该轮实体死在 i6
构造中途，实体根本未建成——模型缺失在当轮可由死亡解释。但验
收标准是模型真正画出，以下三门逐个定版：

**(1) Animated 空形 = 无模型；写侧本就带 AO 路径（已实证）**
- read fn 的模型创建**只**发生在 flags bit0 分支内（查资源 →
  0x308 AO 实例 → 0x141DA37E0 挂接），flags=0 时三段全跳、什
  么都不建；ctor 不预置默认 AO（§4)。**客户端没有「回退到类
  型默认 AO」的路径**（ctor + read 两处已实证；组件 +0x10 收尾
  槽未单独验，列为残留待验但不改变结论方向）。
- fork 写侧**已经是真服形态**：PlayerForCreation 传
  AnimatedObject = Characters.dat 行的 AOFile（女巫 =
  `Metadata/Characters/Int/IntFour.ao`)，Blob() 写 U8(1) +
  WStr32(该路径）。18:25 trace 里 i5「消费 1 B」是在错位 70 B
  的位置读到的字节（该字节恰为 0)，**不是写侧为空的证据**。
  Life/Player 对齐后，Animated 将在正确位置以 flags=1 被读，
  read 内即建模。此门无需改写侧。

**(2) 可见性门（除 shown 外还有实体图登记，已实证机制）**
- Positioned 侧：hidden=0/shown=1（evening8 定版）→ [pos+0x1e6]
  bit0 清、[pos+0x1e4] bit3 置，变更走虚表 +0xc0 可见性回调。
  fork 写 ✓。
- **实体图登记门 [entity+0x8d] & 4**：fn C 把 blob 首字节 flags
  的 bit1 映射为 [entity+0x8d] |= 4(evening7 §1)；世界层笔记
  §3/§6 已实证：CreateObject 只在 +0x8d & 4 时把实体登记进世
  界实体图，世界 0x1C6 的 handler 0x142135D2A 做的正是
  `+0x8d |= 4` + 入图（0x1C7 反之）。**fork 现写 flags 字节 =
  0 → 实体不入图**——不入图的实体不被世界的逐帧派发/渲染走
  位（「不入图 ⇒ 不绘制」为推断，登记机制本身已实证）。
  → v3 二选一（待验哪种是真服形态）：blob flags 字节写 0x02，
  或 CreateObject 后补发世界 0x1C6（`01 C6` + 通用头 11 B =
  entityId 0x1000、stamp 全 0，共 13 B）。
- [entity+0x8d] bit0（flags bit0 → |1）的用途未定，不动。

**(3) 本地玩家认领：无服务器消息，客户端自认（机制缺失已实证、路径推断）**
- 世界组不存在 SetLocalPlayer 等价消息（世界层笔记 §3 已实
  证）；CreateObject handler 0x142134EC7 全程不做 entityId 比
  对，只对每个对象广播事件 0xE794FCDA{entity, 1}。
- 推断路径（世界层笔记 §3 原推断，仍成立）：客户端在激活/UI
  绑定阶段（0x1416820A0 回调后段）按 Player 组件/自身所选角
  色身份认领，或经 ctor 阶段二传入的上下文对（世界数据字段
  +0x1B8/+0x1C0，0x141E71010(entity, &pair）消费）确立。
- **服务器侧无需也不能发任何「认领」消息**（待实测：只发
  0x2F7 + 完成登记后，玩家是否可控、镜头是否跟随——下一轮
  真机判读）。
- 判读用探针钩子（确切清单，下一轮 v13 建议）：
  a. 钩 0x142134EC7 返回 / 0x141E72A00 入口：记录玩家实体
     (id 0x1000）的 [entity+0x8d] 值与登记结果；
  b. 钩 0x141DA37E0(Animated 挂接）：确认 AO 实例为玩家实体
     挂上（参数含组件属主 → [comp+8] = 实体）；
  c. 钩 0x1421F3090 且事件 id = 0xE794FCDA：看广播后的监听者
     调用链里是否出现本地玩家指针写入（[world+偏移] = entity);
  d. 钩 0x14212F9F0 与 0x1416820A0 返回后：dump 世界对象中
     「Player」键注册表（[world+0x5B0]）与疑似本地玩家字段，
     与玩家实体指针比对。

### 11. blob 终版布局 v3（全 10 组件定版）

帧：`U8 flags`（现写 0；登记门问题见 §10(2)，候选 0x02）+
`U8(0)` base data 空表 + 组件段 + `U8(0)` tasks 空尾。

| idx | 组件 | read fn | fork 应写（字节与值来源） | 状态 |
|---|---|---|---|---|
| 0 | Positioned | 0x141DD89A0 | 19 B:I32 X、I32 Y、U32(0)、U16 team、flagsA 0、flagsB 0x02、flagsC 0、hidden 0、shown 1（evening8) | 已定版 |
| 1 | Stats | 0x142181160 | fork Stats() 对流 + gate 段 6×0 + 尾 U32(0)+U8(0)+U8(0)（evening8) | 已定版 |
| 2 | Pathfinding | 0x14010A080（桩） | 0 B | 已定版 |
| 3 | Buffs | 0x141DB5080 | U16(0) 空表 = 2 B（条目格式见 §2，非空总长待验） | 空形已定版 |
| 4 | Life | 0x141D8C260 | A(Life current, reserved 0) + B(0) + A(Mana current, ManaReserved) + B(0) + A(ES current, 0) + A(0) + C(0)×3 + C(0) + U8(0) = **125 B**;A/B/C 形状见 §3（A=U32 cur + U32 res + I16 0 + U32 0 + U32 0;B = A 去尾 U32;C = U32 0 + I16 0） | 已定版（池↔A 槽对应为待验） |
| 5 | Animated | 0x141DA66C0 | U8(1) + WStr32(Characters.dat 的 AOFile，如 IntFour.ao) = 1+4+2·len | 已定版 |
| 6 | Player | 0x141DCF4A0 | 按 §5 序：WStr32 名、U8 职业、U32 经验、U32(0)、U32(0)、U16(0)、U16 头像、FlagSet 任务、FlagSet 联赛、5×0、U16 藏身处、U16 藏身处2、U8 旗标 0、U8(0)、U8(0)、CompactU(0) 空列表、U8(0) 空尾表 | 已定版（空形 51 B @ 名 6 字符） |
| 7 | PlayerClass | 0x14010A080（桩） | 0 B | 已定版 |
| 8 | Inventories | 0x141D82BC0（经 0x1416E6D70 跳板） | 空形 U8(0)+U8(0) = 2 B；非空：U8 N + 每件 (U8 slot + U8 type + 7 + 7 + 1 + 2 + 3 尾字节 = 22 B) + U8 M + M×U32 | 已定版 |
| 9 | Actor | 0x142147300（经 0x1416D8210 wrapper) | 空形 40 B：段1 3×(U8 0 + U8 0 + WStr32("")) + F2nd U8(0) + 技能表空形 7 B（U8 0 + U8 0 + U8 0 + U32 0) + F0/F1/F2 = 0,0,0 + U16(0) + U8(0) + 段4 4×U8(0) + U32(0)；带技能：技能表段换为 U8 n × 记录（31 B/条基线，见 §8) + 灵魂 + 字节表 U8(0) + 冷却组 U32(0) | 已定版（技能记录 GEPL 尾段 1 B 待验） |
| 尾 | tasks | fn C 尾段 | U8(0) | 已定版 |

空装备、无技能、名 6 字符时 v3 总长 = 2 + 19 + Stats（随快照，
bbbbbb 实测 605) + 0 + 2 + 125 + 75 + 51 + 2 + 40 + 1 = **922 B**
（Stats 与技能/物品按实际数据伸缩）。

**残留待验清单**（不阻塞 v3 落地）：
1. Life 四个 A 与 Life/Mana/ES/Spirit 的对应（HUD 判别法见 §3)。
2. Actor 条件段（兄弟 +0x1E0 ≤ 0 → 7 B）在玩家满生命时是否
   跳过——若误触发，空形 40 → 47 B，下一轮 trace 的 idx9 后游
   标（应落在 tasks 前 1 B）可判。
3. Actor 技能记录的 GEPL +0x10D 尾段（每条 ±1 B)，按所选默认
   技能行数据核对。
4. Buffs 非空条目的尾部 U32 向量长度（定义驱动）。
5. Animated bit2/bit3 段格式（玩家写 flags=1 不触发）。
6. blob flags 字节 bit1（登记）与 0x1C6 补发的二选一（§10(2)）。
7. 本地玩家认领的实测（§10(3) 钩子清单）。

## 2026-11-04 evening10 — Actor silent death（离线复现定案）

承 18:51 真机会话（bbbbbb，blob v3 1189 B）：前九个组件游标全对齐，idx9 Actor 读开始后无 throw、无异常事件、无 fnC 返回，客户端静默消失。本轮离线重构实际字节 + 模拟读程 + 0.5.5 datc64 原始数据定案。

### 10.1 会话输入重构（已实证：网关代码 + 存档 DB + 部署目录）

- bbbbbb 存档（PC saves.db 直读）：ClassId=1 女巫、Level=1、Standard 联盟、G1_1；世界存档 Inventories["11"] = 3 件药剂；StartWeapon Type 926725699（2 孔，Gem=null）；SkillBar/Passives/QuestFlags 均 null → **GemSkills 为空、Souls 为空（VaalSouls.Read() 对全 null 返回空）**。
- `PlayerForCreation`（Program.Player.cs:838）：Skills = PlayerDefaults(weaponStats) + GemSkills = **恰好 1 条** GrantedSkill：Id=0x0102（SkillCatalog.FirstSkillId）、GEPL=**4474**、GESSPL=**4430**、Stats=weaponStats、CooldownMs=0、VaalResourcesEnabled=false、Supports=[]、ExtraStatSets=[]。数据源是**部署目录的旧代表**（网关 18:21 启动日志 "23346 stat(s), 40355 mod(s)" 为旧代计数）：旧表里 GrantedEffects 468='PlayerMelee'、StatSet1=476、StatSet2=[] → GEPL(468,L1)=4474、GESSPL(476,L1)=4430，与网关无表回退常量 (4474,4430) 恰好同值。
- Stats 快照 186 对（CharacterPlayerStatsSnapshot：面板∪物品∪宝石）；weaponStats（记录内 Stats 表）= WeaponStats() 计算列表。

### 10.2 Actor 字节总账（已实证：写侧代码逐字节推算；与 trace 游标互证）

**先纠一处旧账：Actor+tasks 不是 140 B。** blob 1189（网关日志硬数）− Actor 起点 0x431=1073（trace 游标硬数）= **116 B**；组件和 19+605+0+2+125+73+213+0+34=1071，+2（flags+base）=1073 ✓。115 B Actor 本体 + 1 B tasks：

| 段 | 字节 | 内容 |
|---|---|---|
| seg1 三槽 | 18 | 每槽 U8(0)+U8(0)+WStr32("")=6 |
| F2nd | 1 | 0 |
| 技能表 | 82 | n=U8(1) + 记录 75 + m=U8(0) 灵魂 + k=U8(0) 字节表 + g=U32(0) 冷却组 |
| seg3 | 6 | F0,F1,F2=0 + U16(0) + U8(0) |
| seg4 | 8 | 4×U8(0) 旗标（无 U32 跟随）+ U32(0) |
| seg5 | 0 | F0=0 不读；内部生命门控关闭（§10.4） |
| seg6/seg7 | 0 | F1=F2=0 不读 |

记录 75 B = 定长 30（id U32 + selector U8 + 复合引用 5 + 嵌套引用 5 + flags U8 + supportCount U8 + U32×3 + U8）+ Stats 表 45（weaponStats 对流）。

### 10.3 引用解析器定版（已实证：0x142684090 / 0x142683DB0 全反汇编）

- 复合引用解析器 0x142684090：读 U8 tag + U32 row → 按 **0x74 步长**查 GEPL 表（越界→空指针不抛错）；再调嵌套解析器读主 GESSPL 引用；**然后按行数据驱动追加读 K 个嵌套引用**，K = 解析出的 GrantedEffects 行 **+0xB8 的数组长度**（AdditionalStatSets 列，schema foreignrow-array @文件偏移 0xB8，DatFile 约定 len=u32@[off]）。
- 嵌套解析器 0x142683DB0：U8 a（≠0 再读 U8 b）+ U32 row → 按 **0xB9 步长**查 GESSPL 表；无其他流读取。对我们的 (a=0, row=4430) 恰消费 5 B。
- 记录读程 0x142188D50 的全部越界出口（0x14218a790 族）都是「构造错误对象 + 0x142c14380 抛掷」——**真机会话里一个都没触发**，即读程从未越过 span。

### 10.4 段5 生命门控（已实证：0x142147300 反汇编 + 网关代码）

主读程 0x142147741–0x14214776e：rdx = 组件数组[ 描述符+0xE0 的索引 ]（兄弟组件，.ot 顺序下为 Life，强推断）；`cmp dword [rdx+0x1E0], 0; jg 跳过`——**兄弟 +0x1E0 ≤ 0 才多读 7 B（U16+U8+U32）**。Life 对象 +0x1E0 = 第一 A 子对象（+0x1a8）内 +0x38 处 = **A1 首个 U32 = 我们 Pool(Life).current = conn.PlayerLife = 31**（Program.LeagueModes.cs:78 初始化为满池；创建日志 "life 31"）。31 > 0 → **门关闭，我们的 seg5 零字节写法正确**，(b) 假设排除。

### 10.5 第一个不一致点（已实证：0.5.5 datc64 原始数据，本轮新抽取）

流格式层面整条记录**干净对齐**（K 实测=0：见下）——不一致在**行号语义**：网关按旧代编号发出的两个行号，在 0.5.5 客户端里指向完全不同的行：

| 引用 | 网关意图（旧表） | 0.5.5 实际 |
|---|---|---|
| GEPL 4474 | PlayerMelee L1 | GrantedEffect=**119**、Level=**12**；GE[119].Id = **'SupportMetaTotemSpellTotemPlayer'**（辅助/图腾系效果）；其 AdditionalStatSets len = **0**（故 K=0、无追加读） |
| GESSPL 4430 | PlayerMelee StatSet1(476) L1 | **StatSet=114、Level=40**（另一效果的 40 级属性集行） |

客户端据此构造技能：**效果=12 级图腾辅助、属性集=StatSet 114 的 40 级行**——跨代拼凑的弗兰肯技能。记录读程的流读取部分（id/selector/两引用/flags/0 辅助/U32×3/U8/主属性表）全部按我们的字节正常消费；附加集 K=0、尾段计数读到的字节是我们的 m=0，同样无事。

### 10.6 0.5.5 真值（已实证）

0.5.5 中**不存在 Id='PlayerMelee' 的效果**。默认攻击 = **GrantedEffects 第 0 行 'MeleePlayer'**（武器变体行 1–21），其 StatSet1=0、AdditionalStatSets len=0、**GEPL(MeleePlayer, L1) = 第 0 行、GESSPL(StatSet 0, L1) = 第 0 行**。正确行号是 (0, 0)。

### 10.7 跑飞机制（强推断；证据链如下）

- 排除项（已实证）：span 越界必抛掷（§10.3）而现场无 throw_call/异常；段5 门关闭（§10.4）；K=0 无追加引用（§10.5）；灵魂/字节表/冷却组计数全 0（§10.2）；前九组件全对齐。
- 读程内唯一尚未走完的数据相关工作 = 记录读程后半的**技能对象构造**（0x142189c80–0x14218a700 大量对象图调用与虚调用链，含辅助 0x14218ca30）：它只吃**解析出的行**、不吃流。毒行构造出的技能（meta 图腾辅助效果 × 无关 40 级属性集 × 12 级）使构造在效果授予图上进入循环/深递归（meta 辅助的效果授予链本就成环），栈耗尽或图遍历不终止——与现象吻合：无 C++ 抛掷、无可投递异常、fn C 永不返回、进程被用户/系统终结（网关 15 s 后才见 socket 断）。
- 待验点：具体打转的辅助函数（0x14218ca30 与记录尾虚调用链二选一）需探针 v14 在 0x142188D50/0x14218A9D0/0x142147300 返回点 + 游戏线程心跳上定位；本轮静态证据只能定到「构造阶段」粒度。

### 10.8 修正写法（字段级；布局不变，只换数据来源）

1. **Actor 段布局一字不改**（115 B 结构经模拟验证与读程一致）。
2. 默认攻击记录的两个行号改为 0.5.5 真值：**GEPL row U32 = 0、GESSPL row U32 = 0**（'MeleePlayer' L1）。记录其余字段（id 0x0102、selector 0、flags 0、无辅助、CooldownMs 0、weaponStats 表）保持——CooldownMs 真值未单独核读 GEPL[0] 的冷却列（默认攻击无冷却，推断 0 无风险）；id 0x0102 的编号空间语义待验（记录读程只把它存进记录对象、不查表，低风险）。
3. **系统性修复（根治）**：把已 staged 的 0.5.5 重导出表（GrantedEffects / GrantedEffectsPerLevel / GrantedEffectStatSetsPerLevel / GrantedEffectStatSets）部署进 `D:\LocalExile2\data\tables`，使 SkillCatalog.Find / WithExtraSets 对**全部**授予（默认攻击+宝石技能）算出 0.5.5 真行号；同时把 SkillCatalog 无表回退常量 (4474, 4430) 改为 (0, 0)——回退常量本身就是毒源。部署前注意 gateway 按什么键把客户端技能 id 映射到 GE 行（id↔行映射是实现侧唯一未定项，须在部署时核对）。
4. **Life 池↔槽**：本轮无新证据推翻 evening9 现状——A1=Life 由门控语义旁证（§10.4 比较的正是 A1 首 U32），fork 现写法（A1 Life / A2 Mana / A3 ES / A4 0）保持；A2–A4 的确切对应仍待 HUD 判别实验（101/202/303/404）定案，不在本轮修正范围。

### 10.9 残留未知

- 技能表读程 0x14218A9D0 的 n/m/k/g 逐字节格式未独立复核（本轮沿用 evening9 推导；尾部全零使多数误序无害，且记录构造先于表尾消费出事）。
- 跑飞点精确到函数级需探针 v14（见 §10.7）。
- GEPL[0] 冷却列、记录 id 编号空间：低风险待验（§10.8.2）。

## 2026-11-04 evening11 — row-zero underflow

承 19:21 真机会话（默认攻击已按 evening10 修正为 GEPL 0 / GESSPL 0，提交 d1dd23a；blob 仍 1189 B、仅记录内两个 U32 值变）：静默跑飞消失，客户端在加载界面弹真 **Buffer Underflow** 对话框。当轮探针已死、无 trace；本轮纯离线定案：记录读程/两解析器/技能表读程/Actor 主读程/fn C 尾段全反汇编 + 0.5.5 datc64 原始数据复核。

### 11.0 结论（先行）

- **越界点定性：流内**（已实证机制）。技能记录的真格式比 evening9 §8 多 **两处读**，fork 一处都没写：
1. **尾段计数（门控）**：主属性表 + 附加集属性表之后，若已解析 GE 对象 +0x10D 的 qword ≠ 0，读程再读 **U8 count × 元素**（每元素 = 内部查表 + 1 张属性表）；
2. **步 11 字节（无条件）**：尾段之后、记录返回之前，读程**总是**再读 **U8 flag**；flag ≠ 0 时再读 1 张属性表。
fork 的记录到主属性表（+附加集表）就结束 → 每条记录**至少少读 1 B**（步 11），尾门开时**少读 2 B**。
- (0,0) 全程模拟（§11.4）：错位后所有中间计数/旗标都恰好落在 fork 的 0 字节上、不触发任何额外循环，唯独**末端越过 span 终点**——与现象（加载界面弹 Underflow、无其它异常）严丝合缝。确切抛掷点取决于尾门对 GE 行 0 的开闭（§11.2 强推断为**开**）：
- 门开（+2 B 错位）：**Actor 主读程 seg4 收尾 U32** 的 read_exact 在游标 113 处需 4 B、只剩 3 B → 抛掷点 0x1421474df 的边界检查（错误桩 0x142148c70），仍在 fn C 组件循环内（idx9）；
- 门关（+1 B 错位）：Actor 恰好把 tasks 字节吃进 seg4 收尾 U32、正常返回 → **fn C 的 tasks 计数读**（0x141e71383，错误桩 0x141e7141c）在游标 == span 终点处抛掷。
- **行 0 与行 4474 在主流之后的消费差 = 0**（§11.5）：两行 K 均为 0、尾门字段在文件里同为 FEFE 图案、步 11 无条件——上一轮 (4474) 之所以没弹 Underflow，是构造跑飞发生在流读完之后、表尾/seg4 消费之前，先一步杀死了进程；本轮构造正常通过，末端越界才得以显形。
- **修正写法**（§11.7）：创建表记录在附加集属性表之后补写 `U8(0)`（尾段计数，门开时）+ `U8(0)`（步 11 flag）= **+2 B**；记录 75→77 B、技能表 82→84 B、Actor 115→117 B、blob 1189→**1191 B**。若 v14 实测尾门为关，则只补步 11 一字节（1190 B）——v14 钩子 #1 一次会话即可判别（§11.8）。

### 11.1 记录读程全图（已实证：0x142188D50 + 0x142684090 + 0x142683DB0 逐指令复核）

evening9 §8 的记录格式主干无误，但漏了两处读（其尾段本就标注「概要/待验」）。完整流读序列（span = fn C 的 blob span；定长读均为内联边界检查、越界走 0x142c14380 抛掷）：

```
U32 id
U8 selector
复合引用 0x142684090: U8 tag + U32 row(GEPL, 步长 0x74 查表, 越界→空不抛)
└ 嵌套引用 0x142683DB0: U8 a; (a≠0 再 U8); U32 row(GESSPL, 步长 0xB9)
└ K × 嵌套引用; K = [GE对象 +0xB8] qword（见下注）, 非流内计数
U8 flags; bit0 → U32 + U32
U8 supportCount × (复合引用 + U32)
U32 + U32 + U32
U8
主属性表: CompactU 对 × (CompactU, CompactI); 经 0x141997220/0x141e25ed0
K × 同形属性表; 同一 K 驱动（附加集属性表）
尾段（门控）: [GE对象 +0x10D] qword ≠ 0 时:
U8 count × 元素; 每元素 = 内部查表（0x141e8ca80 等, 不读流）+ 1 张属性表
步 11（无条件）: U8 flag; flag ≠ 0 → 再读 1 张属性表
（其后为纯构造/收尾, 无流读——已扫全函数: A/有符号紧凑读调用点仅 5 处:
主表 0x142189491、附加集表 0x1421895d6、尾元素两支 0x14218999c/0x142189b33、
步 11 表 0x142189e24; 内联定长读以 [span+0x10] 游标访问点穷举核对完毕）
```

注（evening10 §10.3 的归属修正）：复合解析器读 K 的原文是 `mov rax,[out]; mov rcx,[rax]; mov rsi,[rcx+0xB8]`——即先解 GEPL 行首 qword（加载器已解析的 **GE 对象指针**），K 取自 **GE 对象 +0xB8**，不是 GEPL 行内字段；记录读程 0x1421894ef 的 `[rdx+0xB8]` 中 rdx 同样是解引用后的 GE 对象（`mov rsi,[rbp+0x250]` 取 out 首槽 = GEPL 行指针 P，`mov rdx,[rsi]` = [P] = GE 对象）。两处读的是同一个 K，语义一致。元素循环里还以 GEPL 行 +0x10 的 **Level** 作查表键（0x142189866），与行 0 的 Level=1 / 行 4474 的 Level=12 的文件实读互证（§11.3）。

**步 11 的位置**：在尾段块之后的一段构造查表（0x142189c40–0x142189d31，按 selector 等键查技能定义）之后、函数收尾（0x14218a155）之前；三条到达路径（尾段循环自然退出 / count=0 / 尾门关 / GE 为空）全部汇入，无条件执行。字节语义（待验）：非零分支按 (selector&0x3F)|0x40 键查/建一张属性表再读一张流内属性表——形态像「变体属性表」开关；fork 写 0 即无此表。

**尾段元素的流消费**（已实证）：每元素恰读 **1 张属性表**（两条代码支路 i=0 特例 0x14218999c / i≥1 通路 0x142189b33，各一张，汇合于循环尾 0x142189bfb）；元素前的查表（0x141e8ca80 按 GE 的 kind 字段分发、读 [GE+0x9B] 等）不碰 span。故尾段总消费 = 1（count）+ Σ（每元素 1 张属性表）。

### 11.2 尾门 [GE+0x10D]（机制已实证；对 GE 行 0 的取值强推断为开）

- 机制（已实证，0x1421896d6–0x1421897b9）：rcx = [out] 解出的 GE 对象；`r9 = [GE+0x10D]`（qword）、`rcx2 = [GE+0x115]`（qword → 存 [rbp+0x88] 并按引用计数对象 inc/dec——一对 {数据, 伴随对象}）；`test r9, r9; je 跳过尾段`；非零才读流内 U8 count。+0x10D/+0x115 相差 8、成对被复制/计数，形态 = 该 GE 运行时对象内嵌的一个 Ref 对（数据指针 + 伴随对象指针），门 = 数据指针非空。
- 文件侧（已实证，grantedeffects.datc64 实读）：GE 行宽 0x129；行 0 与行 119 在 +0x10C..+0x11F **逐字节相同**：`00 | FE×16 | 00 00 00`——即 +0x10D 起 16 字节为全 0xFE 图案，qword@+0x10D = 0xFEFEFEFEFEFEFEFE ≠ 0。全表统计：8279/8349 行同为此图案；70 行该 16 B 为 [小首字节(5/8/…), 0…]；仅 5 行（39、7991–7994）qword@+0x10D = 0。
- **强推断：GE 行 0（MeleePlayer）尾门为开**。依据：(1) 行 0 的 +0x10D 字段非零且与行 119（4474 案）同图案，而 evening10 对 4474 的流模拟独立得出「尾段计数读到的字节是我们的 m=0」——即 4474 案里尾段计数**确实被读了**；两行同图案 ⇒ 同门状态。(2) 已证同偏移保值的先例：[GE+0xB8] 的文件值即内存中的 K 计数（文件侧 {0:8095 行, 1:168, 2:45, …} 的小整数分布与两处代码的计数用法严丝合缝；GEPL 表行距 0x74 文件/内存一致亦为同类证据）——加载器对 GE 行至少在 +0xB8 处同偏移保值，+0x10D 同理的可能性高。(3) 门若对 99.94% 的效果都开，尾段计数就是近乎通用的协议字节，与「真服记录都带此字节」的图景一致；行 0 不属于那 5 个零门例外。
- 残留不确定（待验）：[GE+0x115] 在文件里同为 FEFE 图案、却被代码按引用计数指针解引用——说明加载器对 +0x10D/+0x115 这一对字段做过变换（把文件字段建成运行时 Ref 对），变换的精确规则未逆出；若变换对行 0 恰好产出空数据指针，则门为关。v14 钩子 #1（0x14218971f 处直读 r9）可一次判别（§11.8）。**注意任务单里的提法需纠正：+0x10D 不是 GEPL 行的字段**——GEPL 行宽仅 0x74，+0x10D 位于 GE 对象上（经 GEPL 行首指针解引用到达）；GEPL 行 0 本身实读见 §11.3。

### 11.3 datc64 实读（已实证：ggx055 本地副本）

- GEPL（行宽 0x74，34300 行）行 0：GrantedEffect=0、+0x10 处 Level=1、+0x14=100、+0x6C 处 f32=1.0（攻速乘数形态）。行 4474：GrantedEffect=119、Level=12——与 evening10 §10.5 一致。
- GESSPL（行宽 0xB9，41557 行）行 0：StatSet=0、Level=1（+0x10)。行 4430：StatSet=114、Level=40——同 evening10。
- GE（行宽 0x129，8349 行）行 0 / 行 119：+0xB8 qword 均为 0（K=0，evening10 数据侧结论复核无误）；+0x10D 区域见 §11.2。
- **GESSPL 一侧无行驱动追加读**（任务 1b，已实证）：嵌套解析器 0x142683DB0 全程只读 a/[b]/row 三项流数据，行内容只用于查表得指针，从不以 GESSPL 行字段驱动任何流读；行 0 与行 4430 的流行为完全一致（a=0 时各 5 B）。复合解析器对 GEPL 行亦然（行驱动读只有经 GE 对象的 K 与尾门两处）。

### 11.4 (0,0）全程模拟（已实证：evening10 重构字节 + 本轮核完的全部读程）

基线复核（本轮新核，evening10 §10.9 的两个待验项就此关闭）：
- 技能表读程 0x14218A9D0 逐指令核完：n 经子读程 0x14218b130 循环调记录读程；m × (U32+U32+U32)=12 B（带 0x152 步长表查表，不读流外数据）；k 先按 k 值调整内部向量再 k × U8；g = U32，每组 U32 key + U32 c + c × 16 B（4×U32）。与 evening9 推导**完全一致**，空形 7 B 成立。
- seg2 子读程 0x142149510：F2nd 以 read_exact(1) 读入；mode=1（创建）时技能表**无条件**读；其余 F2nd 位（0x10/0x02/0x20） fork 写 0 均不触发。
- Actor 主读程 seg3（0x14214c660 读 3 B F0/F1/F2、0x141492120 读 U16、0x14214c680 读 U8→+0x2A3）、seg4（4 条目 × read_exact(1) 旗标 + 位门控 U32，收尾 U32 在 0x1421474df 带边界检查、错误桩 0x142148c70）逐指令核完，与 evening9 一致。seg5 的 Life 内部闸沿用 evening10 §10.4（A1 首 U32=31 > 0 → 关；该闸读的是已入对象的 Life 字段，与流错位无关，两分支下均关闭）。F0 与 +0x2A3 字节在两种错位下读到的都是 fork 的 0 字节，seg5/6/7 均不触发。
- fn C 尾段（0x141e71383）：组件循环后读 tasks U8 计数，边界检查失败走错误桩 0x141e7141c 抛掷（r9d=1 = 请求 1 B）；其后每 task 读 U16 键（桩 0x141e71446）。fork 写 tasks=U8(0)。

模拟（Actor 相对偏移；Actor 起于 blob 1073，总长 116 B 含 tasks；fork 字节布局同 evening10 §10.2，仅记录内 GEPL/GESSPL 两 U32 改 0）：

| 读程 | 应读位置（无错位） | 门开（+2）实际落点 | 门关（+1）实际落点 |
|---|---|---|---|
| 记录定长 30 + 主表 45 | 20..94 | 20..94 ✓ | 20..94 ✓ |
| 尾段 count | —（fork 未写） | 95 = fork 的 m(0) → 0 元素 | 不读 |
| 步 11 flag | —（fork 未写） | 96 = fork 的 k(0) → 无附加表 | 95 = fork 的 m(0) → 无附加表 |
| 技能表 m | 95 | 97 = g 的 byte0 (0) | 96 = fork 的 k(0) |
| 技能表 k | 96 | 98 = g 的 byte1 (0) | 97 = g 的 byte0 (0) |
| 技能表 g(U32) | 97..100 | 99..102 (0) | 98..101 (0) |
| seg3 (3+2+1) | 101..106 | 103..108（全 0，F0=0、+0x2A3=0) | 102..107（全 0) |
| seg4 旗标 ×4 | 107..110 | 109..112（全 0，无门控 U32) | 108..111（全 0) |
| seg4 收尾 U32 | 111..114 | **113..116 → 第 116 B 不存在，抛掷** | 112..115 ✓（吃掉 tasks 字节） |
| fn C tasks 计数 | 115 | 已抛掷 | **游标 116 == 终点，抛掷** |

**第一个越界点**：门开 → Actor seg4 收尾 U32（0x1421474df 检查、桩 0x142148c70）；门关 → fn C tasks 计数（0x141e71383、桩 0x141e7141c）。两处都在 fn C 的 span 消费链内（前者在 idx9 组件读内、后者在组件循环后），均为 0x142c14380 抛出的 Buffer Underflow 错误对象——与 19:21 的对话框一致（该轮 Client.txt 未记录异常回溯，2026-11-04 远程实查无果，不作证据）。

### 11.5 行 0 vs 行 4474 的消费差（任务 1c，已实证）

主属性表之后到记录结束之间，两行的流消费**逐字节相同**：K 同为 0（无附加集引用/属性表）；尾门字段同图案（§11.2）；步 11 无条件。差异只在流**之外**：4474 解析出的是图腾辅助效果 119 × StatSet 114/40 级的拼凑技能，构造阶段（0x142189c40 之后的对象图工作）跑飞、先于表尾消费杀死进程；行 0 是合法默认攻击，构造通过，错位才推进到末端显形。evening10 的「布局一字不改、只换行号」结论需补正：**布局差两字节（尾段计数 + 步 11），与行号无关、两行都缺**。

### 11.6 创建后路径排查（任务 3，已实证排除）

- **fn C 后读 0x141e70900**：入参只有实体、无 span（evening9 §9 已实证：基类调用 + 组件数组逐个虚调用）——不可能抛 span 的 Buffer Underflow。
- **激活回调 0x1416820a0 后段 / 本地玩家认领**：操作世界/实体对象、无 span 入参——排除。
- **技能构造对属性表的二次解析**：构造吃的是读程已建好的属性 map（0x1426acb60 产物），不回读 span——排除（4474 案的跑飞正是此阶段，但那是对象图问题、非 span 抛掷，两案性质不同、勿混淆）。
- **0x23 内容消息读程 0x1421582b0 / CreateObject 外层读 0x141f6c5a0 / 0x11·0x1e**:各自独立 span，本轮改动未触及（blob 长度未变、外层字段未变），且 0x23 在 17:44 会话已实证可正常处理——排除。

### 11.7 修正写法（字段级；只改创建表记录，布局其余不动）

在**创建表记录**（fork 的 `WriteActorSkillRecord`，InstanceEntities.cs:1043）的记录体末尾——即主属性表与附加集属性表（`WriteSkillRecordBody` 现有结尾，:1067–1068）之后——按读程顺序补两字节：

1. `U8(0)` —— **尾段计数 = 0**（该 GE 无尾段元素要声明；读程对 0 有显式退出支路 0x1421897e5，合法空形）。数据来源：无（空表）；门关时此字节不存在——**是否写此字节由 §11.2 的门状态决定，是本修正唯一待 v14 判别的点**（主案：写，依据 §11.2 强推断）。
2. `U8(0)` —— **步 11 flag = 0**（无变体属性表）。无条件写。

结果（主案）：单条记录 75→77 B；技能表 82→84 B；Actor 115→117 B；blob 1189→**1191 B**（0x2f7 的 compact 长度前缀随之 +2，属正常编码）。备选案（门关）：只补第 2 项，blob = 1190 B。
注意：**勿把这两字节加进共享的 `WriteSkillRecordBody`**而不加区分——旧式更新消息（U16 id 形，WriteSkillRecord）走的是尚未逆向的另一批读程，其记录尾是否同形未证；两字节应只出现在创建表路径（WriteActorSkillRecord）在 body 之后，或给 body 加路径开关。
残留风险（待验）：尾段计数与步 11 的**语义值**——若真服对 MeleePlayer 发的尾段计数非 0（即该效果的尾数据是记录必备项），写 0 虽能过流读、技能对象可能缺省某些属性表；验收（站出生点 + 能走动）不深入校验技能数值，M5 战斗阶段需再回看此点（连同元素表的构造来源 0x141e8ca80 的 kind 分发一并逆）。

### 11.8 探针 v14 钩子清单（一次会话同时判别门状态 + 抛掷点 + 验证修正）

在 v13 基础上增/改（偏移均为 VA；span 结构 [0]=数据、[+8]=终点、[+0x10]=游标）：

1. **0x14218971f 尾门读**（onEnter 读 rcx=[rbp+0x250] 解出的 GE 对象——实作时钩 0x142189704 后或直接在 0x14218971f 读 rcx）：log `[GE+0x10D]` qword 与 `[GE+0x115]` qword。**门判别一锤定音**（非 0 = 门开）。
2. **0x142188D50 记录读程 entry/leave**：log 入口游标、出口游标与首 U32 id；期望修正后单条 Δ=77（现行 75 应读点 Δ 对照：实测 Δ 若为 76/77 即分别对应门关/门开下读程的真实消费——注意现行构建读程会一路错位读到 seg4/tasks 才抛掷，本钩子的 leave 在抛掷时不触发，以 #5 的抛掷点为准）。
3. **0x14218A9D0 技能表 entry/leave**：log 游标 Δ（修正后应 = 84）。
4. **0x142147300 Actor 主读程 entry/leave**：log 游标 Δ（修正后应 = 117，且 leave 正常触发 = Actor 流内读完）。
5. **0x142c14380 抛掷点**：log 返回地址 + 线程回溯。判读表：返回点落在 0x142148c70 桩路径 = seg4 收尾 U32（门开签名）；落在 0x141e7141c 桩路径 = fn C tasks 计数（门关签名）；落在 0x14218a974 = 尾段计数读本身（说明错位比预估更深、需复查）；落在 0x14218a99d = 步 11 读。
6. **0x141e71383 fn C tasks 计数读**（onEnter）：log 游标与终点（游标 < 终点且其后 fn C 正常返回 = 全 blob 对齐的最终判据）。
7. **0x1421474df seg4 收尾 U32 读**（onEnter）：log 游标/终点（剩余 ≥4 = 安全）。
8. 保留 v13 的 comp_call 游标链、world_register（0x141e72a00）、ao_attach（0x141da37e0）——验收三条（不闪退 / 模型出现 / 能走动）与登记门判读照旧。

判读顺序：先看 #1 定门，再看 #5 定抛掷点，两者必须自洽（门开↔seg4 桩、门关↔tasks 桩）；修正部署后看 #4/#6 是否正常返回。

### 11.9 残留未知

- 尾门对 GE 行 0 的最终状态（§11.2，强推断开；v14 #1 判别）。
- 尾段元素的语义（按 GEPL Level 查表 + kind 分发 0x141e8ca80 + 每元素一张属性表——像「效果自带的逐级附加属性集」；真服计数来源未逆，M5 前需回看）。
- 步 11 字节的语义名（变体属性表开关为形态推断）。
- 旧式更新消息读程（U16 id 形记录）的尾部是否同形（§11.7 注意项；进图路径不经它们）。
- GE 运行时对象 +0x10D/+0x115 Ref 对的加载器变换规则（文件 16 B 字段 → 运行时 Ref 对）；与 [GE+0xB8]=K 的同偏移保值并存，规则未完全逆出——不阻塞本修正，v14 #1 可绕过它直接实测门值。

## 2026-11-04 evening12 — post-registration AV

承 20:25 真机会话（修复 83ca4ad +2 字节已部署、0.5.5 技能四表已换、探针 v14 全程在线）：blob 1191 B；游标账 Actor enter 1073 → leave 1189（Δ116，非 117）、技能表 Δ83（非 84）；**fnC 首次正常返回（fnC_done）、world_register 首次对玩家实体 0x1000 触发（f8d=12，含登记位）、随后立即 access violation**。尾门实测：GE 行 0 的门为**关**（读者只多读步 11 一字节；+2 写法多出 1 字节 slack、被 fnC 容忍、无严格尾检——此结论只针对行 0，门状态按效果行而异，+2 仍是通用安全写法，勿改）。本轮纯静态定案：AV 调用链逐函数反汇编 + 当轮 km 日志/Client.txt 复核。

### 12.0 结论（先行）

- **AV 子系统：世界 tick 的 drain 循环 → 0x23 处理器的激活后通知 walk → 统计/旗标聚合**（已实证：bt + 逐函数反汇编）。不是渲染、不是 AO 挂接、不是本地玩家认领——三者均不在链上。
- **致命机制：野指针解引用**（已实证）。聚合函数 0x1401506e0 在入口 `mov r8,[r14]`（0x1401506fe）读 FlagSet 的 {begin,end} 对时，r14 = [E+0x188]+0x248 所指地址不可读——即某客户端侧向量元素 E 的 +0x188 字段是一个野指针（0xffff80… 族，非空、非小偏移）。
- **归因（分级）**：
  - 1 字节 slack：**排除**（fnC/Actor/技能表均正常返回，slack 被当作 0 字节消费，AV 的野指针在堆对象字段里，与 span 无关）。
  - 缺某条后续服务器消息：**基本排除**（推断，弱）——崩溃的 walk 是客户端内部通知，0x23 自身的读已完成（[session+0x2270]=3 已置），其后协议上没有待发消息；92 世界消息目录里亦无「初始化统计」类候选。
  - **最强假设（推断，强）：我们的技能记录数据经技能构造留下了半建成对象**。同一会话里，技能表处理中途（rec_leave 之后、skilltab_leave 之前）已有一次同族野指针（0xffff800af4ca00xx）的 system 异常被内部捕获、执行继续，bt 经过实体 ctor 区 0x141e7489c；Client.txt 同轮有 `Could not find row for MeleeAttackActionClient skill MeleePlayer::1` WARN——MeleePlayer 技能的客户端动作行未解析到。半建成技能对象的野字段随后在 0x23 walk 里被解引用。E 的确切身份（技能对象？增益/监听对象？）静态未定，v15 一次会话判别（§12.6）。
  - ao_attach 未触发与 AV **无关**（链上无它）：模型创建路径在 Animated 读内或其后未完成，另有三类候选机制（§12.4），v15 钩子判别。

### 12.1 AV 调用链逐函数识别（已实证：bt 自内向外 + 逐函数反汇编）

bt（Frida exception 事件，内 → 外）：`0x140125e93 0x1416293fd 0x14013bc37 0x1421232cb 0x1421c5ad5 0x1421c5c54 0x14212113f 0x1421206cf 0x1410082c8 0x141008225 0x141631fc8 0x1415e84ef 0x1421c416b 0x141677c99 0x14011ce15 0x141050064`。0x140125e93 经 rip 引用扫描确证为直达 fault 函数的 call 返回址（`call 0x1401506e0` 结束于此）。

| 帧 | 函数 | 子系统 / 作用（已实证） |
|---|---|---|
| fault | **0x1401506e0** | **FlagSet 展开器**：入参 (rcx=FlagSet 对象， rdx=0x380 B  scratch)；先 memset 0x380 B，再读 [rcx]=begin、[rcx+8]=end，以 9 B 步长（FlagSet 块 = 1 B 块号 + 8 B 位图）遍历，块号 < 0x70(112）者把 8 B 拷入 scratch[块号×8]。fault 点 0x1401506fe `mov r8,[r14]`（r14=rcx）即 begin 读。0x380 = 112×8，与 0x70 钳制互证。 |
| 1 | **0x1401256d0** | **统计/旗标聚合 walk**：大函数，多阶段（向量拷贝、FlagSet 展开、0x380 块拷贝、map 擦除、引用计数释放、+0x10d/+0x10e 置位）。fault 路径为 r8（第 3 参）== 0 的 F 段（0x140125dfd 起）：迭代 [rdx+0x1a8]+0x48 向量（rdx = 第 2 参），每元素 E 取 rcx=[E+0x188]+0x248 调展开器。r8≠0 时走 A–E 段（另两组向量 + map 擦除），本轮未走。 |
| 2 | **0x1416292a0** | **引用计数清理/通知函数**：首参 rbx 对象，先处理 [rsp+0x38] 栈参对象的引用计数（`lock xadd [rdi+0xc]`，归 1 则调虚表 +8 析构）；再对 [rsi+0xe48]（rsi=[guard+0x50]）查 0x142828550，命中则置 [rsi+0xf29]=1 走另一路；否则迭代 rbx+0x1c0 的侵入链表，每节点调虚表 +0x18（= 0x1401256d0），传 rdx=首个 [rbx+0x340] 向量元素、r8=首个 [rbx+0x348] 向量元素（本轮 r8=0 → 上层 [rbx+0x348] 为空或空向量）。 |
| 3 | **0x14013bbf0** | **侵入链表迭代器**（通用）：rcx=链表锚点（[rcx]=?、[rcx+8]=头），头换栈槽后逐节点调虚表 +8（返回下一节点累加）与 +0x18（= 0x1416292a0）。 |
| 4 | **0x1421220f0 区（0x23 处理器尾段）** | **分发器/0x23 处理**：先跑消息 drain 循环（0x1421231f0 起，逐条擦 map、入队）；继而 `call 0x141eca920`、`mov [r15+0x2270],3`（session 状态机置 3 = 0x23 已应用，已实证）；最后 `lea rcx,[r15+0x270]; call 0x14013bbf0`——walk 会话 +0x270 链表（r15=session）。AV 即发生在此 walk 内。 |
| 5 | 0x1421c5a50 | drain 分发包装：按 dx 分支经虚表 slot 0 调 handler（本轮 `call [rax]`，返回址 0x1421c5ad5）。 |
| 6 | 0x1421c5b90 | drain 分发包装 2：调 0x142197e80、import 槽、`call [rax+8]`（返回址 0x1421c5c54）入 0x1421c5a50。 |
| 7 | **0x142120cf0** | **世界 drain/更新大函数**：查 [rcx+0x272a]、迭代 [rcx+0x2780..0x2788] 计时条目（浮点运算）；0x142121114 处 `[rdi+0x2270]>1` 才入 0x1421c5b90 循环（`test al,al;jne` 重试）。rdi=session（+0x20f8 = 世界聚合体 +8）。 |
| 8 | 0x142120650 | 世界 tick 入口：调 0x142120cf0（返回址 0x1421206cf）。 |
| 9–10 | 0x141008280 / 0x141007d20 | tick 上层：0x141008280 取 [rax+0x1a8]（世界聚合体）调 0x142120650；0x141007d20 调 0x141008280。 |
| 11–12 | 0x141631e00 / 0x1415e84ef | 观察者/事件派发：虚表 +8 调用、向量迭代（`add rbx,8; cmp`）。 |
| 13 | 0x1421c4040 | 定时回调分发器：imul 0x3e8(1000）/idiv 计时后 `call rdi`（回调）。 |
| 14–16 | 0x141677be0 / 0x14011ce00 / 0x14104ffb0 | 外层：0x141677be0 调 0x1421c4040；0x14011ce00 调 0x141677be0 后 `lea rcx,[rbx+0xe8]`；最外 0x14104ffb0 浮点运算（cvtsi2sd/mulsd）+ [rsi+0xb0] 对象虚调用——UI/面板更新侧（与 0x23 状态联动）。 |

**不在链上的子系统（已实证排除）**：AO/模型挂接（0x141DA37E0、0x141D2C750、0x140BC8280 全程无帧）、本地玩家认领（无独立帧，认领路径在激活回调内、已先于 drain 完成）、渲染（无渲染帧）、span 读程（无 0x142c14380/读程帧）。

### 12.2 致命机制（已实证）

1. 展开器读 [r14]（= [E+0x188]+0x248 处的 FlagSet begin）时 fault；r14 的值 0xffff80da7269e3c0（Frida 异常上下文 rcx）属内核空间地址族，用户态绝无合法映射——**野指针**，非空指针、非小偏移越界。
2. 调用点（0x140125e76–0x140125e8e）：`rdi=[rbx]`（向量元素 E）；`rcx=[rdi+0x188]`；`rcx+=0x248`；`rdx=[rbp+0x740]`（栈 scratch）；`call 0x1401506e0`。E 本身与 [E+0x188] 的读均成功（fault 在展开器内），故 **[E+0x188] 字段值本身即野指针**——该字段由客户端构造代码填充，blob 流内无指针字段，流数据只能经定义查表间接污染它（见 §12.3）。
3. 1 字节 slack 的精确账（v14 实测）：门关 → 记录实耗 76（非 77）、技能表 83（非 84）、Actor 116（非 117）；多写的一字节被后续读程当作全 0 字段消费，tasks 计数在 1189 正常读、fnC 正常返回、blob 末尾仅余 1 B 未读、无严格尾检。**slack 与 AV 无因果**。

### 12.3 技能构造中途的已捕获异常（关键旁证，已实证：km 日志 + Client.txt）

- 时序（20:25:53）：`rec_leave` → `throw_call from 0x142627445` → `exception type=system addr=rip=0x6812f408a`（某 DLL 内）→ `skilltab_leave`（Δ83 正常）→ seg4/actor/tasks 正常 → `fnC_done` → `world_register(0x1000, f8d=12)` → `agg_reload_1270` → AV。**被捕获的异常发生在技能表处理中途、记录流读完之后——即技能对象构造阶段**，执行继续，未杀死会话。
- 该异常的 bt：`0x142c14417 0x142627445 0x142626a93 0x1426264d7 0x141e7489c 0x140c071e3 0x1421d72bc 0x1421d6a60 0x14101c08f …`——0x142627440 处为 `call 0x142c14380`（throw helper，返回址 0x142627445）；0x141e7489c 位于函数 0x141e74740 内（实体 ctor 邻区：调 0x142626600、0x1421d7070 释放、0x142626440、0x1415d0f40，查 [rax+0xbc]）——**构造收尾/引用解析函数**。其上下文 rcx=0xffff800af4ca0000 与 AV 事件的 rdx/r8（0xffff800af4ca0010/0x70）**同属一个野指针地址族**（相距 0x70 内），指向同一批野数据/同一野对象。
- Client.txt 同秒 WARN：`Could not find row for MeleeAttackActionClient skill MeleePlayer::1`（+ TrapNormal2 资源 CRIT，区域 doodad 噪音，见下）。**动作行缺失是技能对象半建成的直接物证**：MeleePlayer::1 的客户端动作（MeleeAttackActionClient）未解析到——动作指针/动作引用极可能就是 [E+0x188]（或其上游）所持的野字段。
- 噪音排除：该 system 异常的 DLL 帧（0x6831cdda7/0x6840bee4c）与 20:25:44 登录期的 effect-graph WARN（FlipbookOld/VertexFlipBookOffset）同源的资源加载失败**不**等同——登录期 WARN 发生在实例连接前，与本次构造无关；TrapNormal2 CRIT（`Metadata/MiscellaneousObjects/TrapNormal2.ot is non-virtual and does not have a physical file`）是区域 doodad 资源缺失，与玩家实体无关。两者均不解释 [E+0x188] 的野值，列为噪音。

### 12.4 ao_attach 为何未触发（三种候选，待 v15 判别）

事实：Animated 读消费 73 B（flags=1 + 路径串，正确位置），但 0x141DA37E0 整轮零触发；ctor 已完整返回（fnC_done + world_register），故挂接缺失不在 ctor 之前。

- (a) **AO 资源加载中途抛错被捕**：Animated 读内 `0x140BC8280 查资源 → 分配 0x308 B AO 实例（ctor 0x141D2C750) → 0x140BEB2D0 取模型描述 → 0x141DA37E0`；若查资源/建图抛错被上层捕获，组件停留在无模型态。§12.3 的已捕获异常时间点与此路径相容（但其 bt 主干在技能构造区，AO 路径仅为相容、未证）。
- (b) **挂接延迟到首次渲染/更新派发**：模型创建在 post-read 虚调用或渲染可见性回调里；AV 在同一 tick 的 drain 内先发，渲染派发未及运行。
- (c) **路径相等跳过**：读内 `路径 == [this+0x350] 现存路径` 时跳过创建——ctor 已把路径串置空（evening9 §4），本应不等；除非某前置步骤已写入同一路径。可能性低。
- 判别钩子见 §12.6 #8。**ao_attach 与 AV 的关系：无**——AV 链上无 AO 帧，修 AO 不治 AV；两者是同一轮会话里两个独立症状（构造半建成 + 模型未挂接），勿并案。

### 12.5 排除链与归因定级

| 候选 | 结论 | 依据 |
|---|---|---|
| 1 字节 slack / 错位 | 排除（已实证） | §12.2(3)：游标账闭合、fnC 正常返回、野指针在堆字段 |
| 记录/技能表/Actor 流格式 | 排除（已实证） | 三者 entry/leave 全部正常、Δ 与门关模型一致 |
| 缺后续服务器消息 | 基本排除（推断，弱） | 0x23 读完成、状态机已置 3；walk 为客户端内部通知；92 世界消息无初始化类候选 |
| 实体登记/世界图 | 排除（已实证） | world_register 对 0x1000 触发、f8d=12 含登记位；登记在 AV 之前完成 |
| 技能构造半建成（动作行缺失） | **最强假设（推断，强）** | §12.3：同族野指针的已捕获异常 + 动作行 WARN + 构造区 bt |
| 增益/监听对象定义查表失败 | 备选（待验） | E 身份未定；Buffs 写空表，监听对象未必经技能路径 |
| 客户端既有期待未满足（区域/聚合体） | 待验（弱） | 区域数据为空（LeagueStats/地形未发）是已知缺口，但 AV 链的野指针在对象字段而非区域结构；需 v15 看 E 身份——若 E 来自区域对象集合则升级此项 |

### 12.6 探针 v15 钩子清单（一次会话定位 fault 前最后一次有意义状态变化）

在 v14 全部保留的基础上增（VA；span 结构 [0]=数据、[+8]=终点、[+0x10]=游标）：

1. **0x1401506e0 entry**：log rcx、[rcx]、[rcx+8]（begin/end）、返回址。**fault 前最后一道验证**：begin 野值当场现形；返回址计数第几次展开。
2. **0x140125e8e 调用点**（phase-F 循环内）：log rbx（E）、[E]（虚表 → 定 E 类型）、[E+0x188]、迭代序号（[rbp-0x40] 起点计次）。**E 身份一锤定音**。
3. **0x1401256d0 entry**：log rcx（N2）、rdx、r8（0=F 段）、[rdx+0x1a8]+0x48 向量长度。定相位与集合规模。
4. **0x1416292a0 entry**：log rcx（N1）、[rcx]（虚表）、[rcx+0x340]/[rcx+0x348] 空/非空。定 N1 身份与 r8=0 的来源。
5. **0x14013bbf0 entry**：log rcx（=session+0x270 锚点）、链表节点计数。定 walk 规模（是否仅玩家实体相关节点）。
6. **0x142627440 throw 点**（onEnter，读异常对象/类型字符串若可达）：定 §12.3 已捕获异常的异常类型与抛出函数入参——确认是否为技能构造抛错。
7. **0x141e74740 entry**：log rsi/rbx/[rbx+0x28]——构造收尾函数的上下文，关联 #6。
8. **ao_attach 判别组**：0x141DA66C0 entry（log flags 字节、路径串、[this+0x350] 现存路径）；0x140BC8280 entry/leave（log 路径、返回值空/非空）；0x141D2C750 entry（AO 实例 ctor）；保留 0x141DA37E0。**四钩子判 (a)/(b)/(c)**：查资源返回空 → (a)；查资源成功但 ctor/attach 不触发 → (b)；路径相等 → (c)。
9. **0x1421232cb 前（0x1421232bf 调用点）**：log [r15+0x270] 链表头——确认 walk 发生在 0x23 置状态后、drain 内。

判读顺序：#2 定 E（虚表 + [E+0x188]）→ #6/#7 定野指针是否构造期已产生 → #1 复核 fault 点 → #8 独立判 ao_attach。

### 12.7 修正写法 / 后续（均待 v15 数据，不先改代码）

- **不改**：+2 字节记录尾（§11.7 维持）、blob flags、0x2f7/0x23 序列——AV 与三者无关。
- **若 v15 证实 E=技能对象且 [E+0x188]=动作指针**：跟进静态任务——定位 `Could not find row for MeleeAttackActionClient` 的查表函数（字符串 xref），查它以何键（技能名::等级？GrantedEffect.ActiveSkill？记录 selector？）查何表；再看网关侧哪一字段可使该行命中（候选：记录 selector 字节现写 0、GE 行 0 的 ActiveSkill 列、技能等级/品质）。在查表机制定案前，不猜字段改法。
- **若 v15 证实 E 非技能对象**：按其虚表身份另立专项（增益容器/统计监听/区域对象），查其 +0x188 字段的填充来源（ctor/定义查表/某世界消息）。
- **ao_attach**：按 #8 结果分流——(a) 则查 AO 资源链（IntFour.ao 的 effect-graph 依赖是否在 0.5.5 客户端内可解）；(b) 则 AV 修好后模型自现（验收时复核）；(c) 则查路径预写来源。
- 残留：0xffff80… 野指针的生成机理（未初始化内存？32 位写坏高双字？NaN 位型？）——v15 抓到 E 与 [E+0x188] 的写入点（写 watchpoint 或 ctor/构造查表）后定；不阻塞 walk 定性。

## 2026-11-04 evening13 — model attach first

用户指令：先解决人物模型问题，模型挂接优先于 AV 链。本轮纯静态定案（未改服务器代码），承 20:37:54 真机会话（探针 v15 全程在线，客户端 pid 26576）+ 20:25 会话对照。

### 13.0 结论（先行）

- **Animated 读内模型未建的直接卡点（已实证：逐指令 + trace 时序）**：玩家 Animated 读程（0x141DA66C0）走了 flags=1 的**串形路径**，完整读出 `Metadata/Characters/Int/IntFour.ao`（73 B 游标账闭合），随后在**路径相等跳过**分支（0x141da69b5）直接返回——`[this+0x350]` 在读入时已非空且与流内路径逐字节相等，`0x140BC8280` 查资源、`0x308` AO 分配（ctor 0x141D2C750）、`0x140BEB2D0` 取模型描述、`0x141DA37E0` 挂接**四步全未执行**。读内无其它可提前返回的分支（见 §13.1）。
- **`[this+0x350]` 预置来源（待验，见 §13.2）**：Animated ctor（0x141da26d0）将 +0x350/+0x358/+0x360/+0x368 全部清零；工厂（0x141da1e60）只分配 + 调 ctor，不播种。预置必发生在 ctor 与 fnC 读之间，静态未定位写入点；最强候选是**定义播种**（Character.ot 的 Animated 默认 AO 路径被写进 +0x350 持有器），v16 一锤定音（§13.5 #1/#2）。
- **模型缺失与两次死亡的关系（推断，强，见 §13.3）**：模型创建极可能**晚于实体构造**——另有一条创建路径（虚表 +0x10，0x141da2c30：分配 AO + 取描述 + 在 +0x360 挂监听器）与挂接门控（attach 首检 `[owner+0x8c]&2`）都指向"注册/激活后才建模"。20:37 死于构造中途（ctor_throw，技能对象构造），20:25 死于注册后 walk（FlagSet AV），**两次都死在建模步骤之前**——ao_attach 未触发是两次死亡的下游症状，未必是独立的 Animated bug。修通技能构造（MeleeAttackActionClient 查行）+ AV 后，模型需复核是否自现；若仍不现，再按 §13.4 的 index 形跟进。
- **ctor_throw 定性（已实证，见 §13.4）**：0x142627440 是共享的"抛客户端错误"桩（栈上错误对象 + `.rdata` 描述符 → 调 MSVC 抛掷 helper 0x142c14380，异常码 `0xE06D7363`）——是**真 C++ 异常**，不是硬件 fault。两次会话的结局差异（20:25 被捕获继续、20:37 序列终止）最合理解释是**抛掷栈帧/异常上下文不同**：20:25 的抛掷发生在 exe 代码栈且被构造路径的外层 catch 吞掉（留半建成对象）；20:37 的 helper 调用返回址落在 exe 镜像外（`0x13fff544a`，外模块代码族），异常穿越了无 C++  unwind/handler 的外模块帧 → 未处理 → 序列终止。模块身份待 v16 枚举（§13.5 #4）。

### 13.1 Animated 读程 0x141DA66C0 全分支复核（已实证，逐指令）

签名：`this=rcx(rsi)`、`span=rdx(rdi)`；span 结构 `[+0]=数据、[+8]=终点、[+0x10]=游标`，流读经 `0x1421C0260(read_exact)`。

```
U8 flags = read_exact(1)
flags&1 == 0 → 跳 0x141da6aaa（仅处理 flags&4/&8 段后返回；无模型）
flags&1:
  flags&2:  U32 索引 → 0x1401d2270 解析类型定义表（[rbx+0x28] 向量，
            行距 0x2C，越界→空）→ 条目指针写入 [this+0x190]/[this+0x198]
            引用对（带 +0x3c 引用计数维护）；随后直入公共创建段
            （0x141da67fa），不做路径比较 —— index 形恒建模
  else:     U32 字符数 + UTF-16LE 路径串 → 栈上 wstring [rbp-0x29]
            （MSVC 布局：+0=_Bx、+0x10=size、+0x18=capacity）
            比较段（0x141da6963 起）：
              [this+0x350]==NULL → 建模段
              尺寸不等 → 建模段
              memcmp(0x142cb80a0)==0（相等）→ 跳 0x141da6aa1：
                  仅销毁栈串、处理 flags&4/&8、返回 —— 跳过建模
              不等 → 建模段
  建模段（0x141da69bb / 0x141da67fa 汇合）：
            [this+0x190]/[this+0x198] 引用对清零
            路径串 → 0x140BC8280 查资源（返回资源对象引用对）
            [owner+0x78]（[this+8] 属主的 +0x78 字段）取分配器 →
                分配 0x308 B，初始化 refcount 字 + 虚表 → AO ctor 0x141D2C750
            0x140BEB2D0 取模型描述 → 0x141DA37E0(this, 描述, AO, …) 挂接
flags&4: 子读程 0x141DA9FC0（未定版，与建模无关）
flags&8: U32×2 + 串处理段（0x141da6ac5 起，未定版，与建模无关）
```

- **20:37 时序铁证**：`comp_call idx5（游标 0x2f1）→ anim_read → comp_call idx6（游标 0x33a）`，其间**零** `res_lookup`/`ao_ctor`/`ao_attach` 事件；Δ=73 B = 1 + 4 + 34×2，串形路径完整读完。结合分支表，唯一自洽的出口是**路径相等跳过**（§13.0）。`flags&1==0` 不可能（游标账）；`flags&2` 不可能（index 形只读 5 B 且恒建模）；读内抛错不可能（无异常事件、执行继续到 idx6）。
- **fork 写侧对照**：现写 `U8(1) + WStr32(IntFour.ao)` 与真串形逐字节吻合 ✓，游标已证实对齐——写侧无错。问题在**客户端侧 `[this+0x350]` 的预置值**，不在流字节。
- **attach 0x141DA37E0 门控（已实证）**：首检 `[owner+0x8c]&2`（owner=[this+8]），清零则跳 0x141da397b（旁路块：读 `[this+0x350]`、调 0x141da3fb0 等，不建模）；置位才进字符串构建 + 挂接本体。attach 本身**只读不写** `[this+0x350]`（0x141da3aed/3b3d/3b9a/3bc1 四处读）。门控位语义（注册/激活标志？）待验——v16 在 +0x10 入口/anim_read 入口顺带读 `[owner+0x8c]`。

### 13.2 `[this+0x350]` 是什么、谁写它

- **字段语义（已实证）**：+0x350 持有"当前 AO 路径"的引用计数持有器（经 `[holder+8]+8` 到达 wstring：`+0x10`=size、`+0x18`=capacity、`+0`=缓冲指针；比较段与 attach/动画更新函数群（+0x10/+0x50/+0x68/+0x88/+0xB8 槽函数）一致地读写它）。对象 0x370 B，+0x350/+0x358/+0x360/+0x368 为末段字段组（+0x360 为 +0x10 刷新函数挂的监听器节点）。
- **ctor 清零（已实证）**：0x141da298d–0x141da29a2 四写 `mov [rdi+0x350/358/360/368],rsi(0)`；+0x190/+0x198 引用对与 +0x1d0/+0x200 路径串同样清零——**出生时无默认 AO、无现存路径**。
- **写入点排查（已实证排除一批）**：工厂 0x141da1e60（分配 + 尾调 ctor）无播种；实体 ctor 0x141e705d0–0x141e712a0 全段无 `+0x350` 写；attach 不写；+0xA0 槽函数 0x141DA6F60（0x60 B，调 0x1421c00f0/0x141da9e60）不写。**静态未找到 ctor→fnC 之间的写入点**。
- **候选（待验，分级）**：
  - H1（推断，强）：**定义播种**——实体装配时某"按定义初始化"虚调用（候选槽 +0x8/+0x10/+0x78）把 Character.ot 的 Animated 默认路径写进 +0x350。IntFour 的默认 AO 恰为流内同一路径时，读内跳过即被触发。区域实体的 def 默认路径与流内路径不同（或无），故不触发、正常建模——与"区域实体有模型、玩家无"一致。
  - H2（推断，弱）：组件对象池复用且复位不彻底，+0x350 残留上一实体的同路径。需同进程内先有 IntFour.ao 实体——本进程首个玩家创建前无此实体，弱。
  - 判别：v16 #1（anim_read 入口读 +0x350 持有器链 + 存串 + def 指针 `[this+0x168]`）+ #2（0x140189bc0 写点捕获——+0x10 刷新函数以 `&[this+0x350]` 调它，是已知唯一的 +0x350 地址传递点；若播种经此 helper，调用栈即定写入者）。

### 13.3 第二条建模路径：虚表 +0x10 刷新函数 0x141da2c30（已实证骨架）

- 流程：`0x141da2e50` 解析当前路径/资源引用（读 facet/def 的 `[rax+0x210]`）→ 非空则分配 0x308 + AO ctor + `0x140BEB2D0` 取描述 → `lea rcx,[rdi+0x350]; call 0x140189bc0`（+0x350 持有器参与）→ 读 `[rdi+0x350]` 经 `0x140bd3e70`/`0x141d516f0` 解析 → `0x14014f0c0` 取监听目标 → 在 `[rdi+0x360]` 挂监听器节点 → `[rdi+0x18d]` 置标志 → 尾调 `0x141da9480`。**全程不调 `0x141DA37E0`**（挂接由 0x141da9480 或监听触发，待验）。
- **本轮事实**：+0x10 在 20:25/20:37 两轮均未证实为玩家执行（ao_ctor 零触发；20:37 的 7 次 ao_ctor 全在玩家 fnC_table 之前、为区域实体）。它是否属于"构造后/激活后"步骤、是否被两次死亡抢先，待 v16 #3（入口钩子 + `[this+0x350]` 状态）。
- **推论（推断）**：若 +0x10 是激活后建模的正路，则模型问题与技能构造死亡同根——先修构造，模型复核后置；不要为绕过读内跳过而改 Animated 写侧（换路径/改 flags 会破坏与 def 的一致性，且 index 形需未知的表内行号）。

### 13.4 ctor_throw 0x142627440 定性与两次会话差异

- **桩的本质（已实证）**：0x142627430 起为某函数的错误尾段：`lea rdx,[.rdata 描述符 0x1439FBC68]`、`lea rcx,[rsp+0x110]`（栈上错误对象，其首 qword = 虚表 `0x142F745B8`）、`call 0x142c14380`。helper 0x142c14380：取异常对象虚表→RTTI 解析（`[rdx]&0x10` 门控分支）→ `mov ecx,0xE06D7363`（MSVC C++ 异常码）→ 调 import（RaiseException）。**确为真 C++ 异常抛掷**，抛掷点共享于全客户端的错误桩家族。
- **抛掷上下文（已实证，20:37 ctor_throw 寄存器）**：rcx=rax=栈错误对象（`[0]=0x142F745B8`，`[+0x188]=0x29338b57de0` 堆指针，非野）；rsi=0x292980801d8（`[0]=0xffffffffffffffff` 哨兵，`[+0x188]=0`）；r12 的 `[+0x188]=0x7ffb8c5b2e6d`（DLL 代码族地址，疑为回调/虚表槽）；r14=0x29325296110（ctor_tail 的 rcx 对象，其首 qword 指向 0x1434DC678 三函数表——0x141e74970/0x141e749d0 皆 ctor_tail 邻区函数，**不是实体虚表**，实体在 fnC_table 的 owner=0x2927e9a4580）；r13=代码区指针（`[0]=0x74006f` 指令流、`[+0x188]` ASCII 片段——误读代码为数据，忽略）。
- **调用链（已实证）**：`rec_leave → ctor_tail(0x141e74740) → res_lookup → ctor_throw → throw_call → 沉寂`。ctor_tail 0x141e74740 是**技能/效果对象构造收尾函数**：调 `0x142626280`，清零对象 +0x298..+0x2d4 并安装两张表，调 `0x141e763b0` 取某对象，建 10 元指针表（`lea rdx,[0x1434424B0]`，表元皆 .text/.rdata 地址，非字符串）经 `0x140152840` 后虚调用 `call rdi`（`rdi=[[r14]]`）。抛掷发生在其虚调用链内；Client.txt 同秒 `Could not find row for MeleeAttackActionClient skill MeleePlayer::1`——**动作行查表失败是构造死亡的直接物证**（与 evening12 §12.3 一致）。
- **`throw_call from` 差异（已实证数值，机理推断）**：20:25 为 `0x142627445`（桩内 call 的返回址——抛掷来自 exe 内）；20:37 为 `0x13fff544a`（低于 exe 镜像基址 `0x140000000` 的地址族——抛掷 helper 被**镜像外代码**调用）。结合"桩已入（ctor_throw 触发）而 helper 返回址在外"，最合理解释：helper 经尾跳/回调被外模块帧调用，或抛掷穿越了外模块帧。**外模块身份静态不可定**（候选：低位优先基址的捆绑 DLL、驱动/运行时回调、生成代码），v16 #4 枚举模块基址定性。
- **结局差异定性（推断，强）**：同一桩、同一异常对象族；20:25 的栈上有匹配的 catch（构造外层吞掉，留半建成对象 → 后续 AV），20:37 的异常穿越了无 C++ handler 的外模块帧（或异常类型/展开信息不匹配该帧）→ 未处理 → 玩家序列终止（其后网关 14 秒见断开，Client.txt 无崩溃文本——进程挂在未处理异常处理/WER 侧，与 20:25 的"继续跑"不同）。**ctor_throw 与模型未挂接之间是并行同因（都死于构造链），不是因果**：模型步骤在构造完成之后，两次死亡都抢在它前面。
- **噪音排除（已实证）**：20:37 窗口内**无** Frida exception 事件（与 20:25 的 system 异常不同——那次是 DLL 内硬件 fault 被捕）；km 日志尾部即 throw 后的两次 `res_lookup`（其一返回值 `0xe8575fd068` 为栈地址族——已是 unwind/清理期的垃圾值），此后无任何事件；Client.txt 止于 MeleePlayer WARN。TrapNormal2 CRIT 与 Targe/CrestShield CRIT 为既有噪音，与本次无关。

### 13.5 v16 钩子清单（模型优先，一次会话定写入点 + 晚期建模 + 外模块身份）

全部只盯玩家实体：以实体 id 0x1000（world_register 目标）与 `IntFour.ao` 路径串过滤；探针 runner 重读 JS，客户端须重开。

1. **anim_read 入口增强（0x141DA66C0）**：除 rcx 外，读 `[rcx+0x350]`（持有器链三级解引 + 存串 UTF-16 内容 + 长度）、`[rcx+0x168]`（def 指针）、`[rcx+0x190]`/`[rcx+0x198]`（AO 引用对）、`[rcx+8]` 属主及 `[owner+0x8c]`、span 游标处 flags 字节。**判定 +0x350 预置值与来源（def？）**。
2. **写点捕获（0x140189bc0 入口）**：log rcx（是否为某 Animated 的 +0x350 地址）、rdx（存入的串/描述）、返回址（定写入者：播种函数 vs +0x10）。**写入点一锤定音**。
3. **+0x10 刷新入口（0x141da2c30）**：log rcx、`[rcx+0x350]`、`0x141da2e50` 返回的路径引用空/非空、返回。**判定晚期建模路径是否为玩家执行**。
4. **模块枚举（attach 时一次）**：`Process.enumerateModules()` 记 base/size/name，**定 `0x13fff544a` 所属模块**；另在 throw helper（0x142c14380）入口记 `Thread.backtrace()` 前 8 帧——定外模块帧的调用链。
5. **attach 门控（0x141DA37E0 入口）**：log `[owner+0x8c]` 与 bit1，及 `[this+0x350]`——若某天 attach 触发，定门控位来源。
6. 保留 v15 全部钩子（E 身份、ctor throw、ao_attach 判别组）——AV 线并行，不丢。

判读顺序：#1 定 +0x350 预置值 → #2 定写入者 → #3 定晚期路径是否执行 → #4 定外模块 → 汇总入 §13.6。

### 13.6 修正写法（均待 v16 数据，不先改代码）

- **不改**：Animated 写侧（flags=1 + IntFour.ao 串形）维持——游标与格式已证实正确；blob flags bit1、+2 字节记录尾、0x2f7/0x23 序列维持。
- **若 v16 证实 H1（def 播种预置 +0x350）且 +0x10 晚期路径不执行**：跟进两路——(a) 查 +0x10 的触发条件（何者调用它：实体 ctor 后段？激活 walk？渲染首 tick？），看网关侧缺哪一步；(b) 候选 **flags&2 index 形**：index 路径恒建模、无相等检查，但行号需解析 `[typeInfo+0x28]` 表（行距 0x2C）中 IntFour.ao 的行号——另立静态任务，**不猜行号**。
- **若 v16 证实 +0x350 在读入时为 NULL**：§13.1 的分支推论被推翻，改查 res_lookup 内抛错被捕（hook 0x140BC8280 的异常出口）——本轮证据不支持此分支，列为备选。
- **根本 unblocker（与模型同根）**：MeleeAttackActionClient 查行失败——另立静态任务定位查表函数（字符串 xref `MeleeAttackActionClient`），查它以何键（技能名::等级？`GrantedEffect.ActiveSkill`？记录 selector？）查何表，再定网关字段改法。在查表机制定案前，不猜字段。

## 2026-11-04 evening14 — MeleeAttackActionClient lookup

本轮纯静态定案（未改服务器代码）：字符串 xref + 逐函数反汇编 + 0.5.5 GGPK 原始 datc64 实查（Melee.dat / ActiveSkills.dat / SkillArtVariations.dat 由 ggpk-extract 自 `E:\poe2-local\Content.ggpk` 提取，`ggx055b/`，游戏未运行时；解码器为重建的 export055.py，行宽硬校验全部通过）。承 evening13 §13.6：根本 unblocker = 让 `MeleePlayer::1` 的客户端动作行命中。

### 14.0 结论（先行）

- **查表函数（已实证）**：行应用 + WARN 函数 **0x14140ea70**（无行时记 `Could not find row for MeleeAttackActionClient skill <名>::<级>`，有行时把行字段写进动作对象）→ 查表函数 **0x14140e280**。两者均由动作客户端构造包装器（0x141471cc0/0x141471d10/0x141471d50 等，尾跳进各 Impl ctor）调用，属技能构造链（ctor_tail 0x141e74740 的虚调用下游）。
- **查哪张表（已实证）**：**`Data/Balance/Melee.dat`**（0x14140deb0 加载/取行索引缓存；内存哈希索引，查找经 0x14241c760）。WARN 串（VA 0x1431C9600）与 Melee.dat 路径串（VA 0x1431C9500）同处一串表区，各有唯一 lea xref，分别落在 0x14140eb3d 与 0x14140dec8。
- **键（已实证形态）**：`(u32 ebx, qword P)`——P 按指针值哈希（0x1402a3240 对 `[key+8]` 处 8 字节作 FNV-1a，空指针哈希 0），即**指针身份**比较，非字符串内容比较。P = 技能对象内 `[[skill]]+0x4f` 处 shared_ptr（`{ptr, control}`，control 带 +0x38/+0x3c 引用计数持有器形态）的 ptr；ebx = SAV 变体解析（0x14244ace0 的行号换算）+ 语境对象虚表 slot 0 映射的结果，初值 `0x153`。
- **行存在（已实证，数据）**：Melee.dat 共 213 行；`(ActiveSkill=661, __col1=1)` 恰有一行 = **行 17**。GE 行 0 `MeleePlayer` 的 `ActiveSkill=661`（ActiveSkills 行 661，Id=`player_melee`）；GEPL 行 0 = `(GrantedEffect 0, Level 1)`；GESS 行 0 的 Id=`MeleePlayer`。数据链完整，缺的只是运行时 key 的两个分量未被观测到。
- **网关字段改法：静态无法给出唯一修正（见 §14.6）**。记录已供给正确的 GEPL/GESSPL 行号；ebx 与 P 的运行时值、以及二者由哪一网关字段决定，均未被静态观测到——**不猜**，缺的一环与 v17 钩子见 §14.7。
- **ActiveSkill vs MeleeAttackActionClient（已实证，§14.4）**：不是同一概念的不同名。`ActiveSkill` 是 GrantedEffects 行指向 ActiveSkills 定义的外键（行 0 → `player_melee`）；`MeleeAttackActionClient` 是 C++ 动作客户端类名（ActionType 28 的 melee 动作实现），WARN 文本把它硬编码为类名。查表用 Melee.dat 行（ActiveSkill + 变体）把两者桥接。

### 14.1 字符串与函数识别（已实证）

UTF-16LE 串表区（.rdata，VA = raw + 0x140001200）：`Data/Balance/Melee.dat` @ 0x1431C9500、`Could not find row for MeleeAttackActionClient skill ` @ 0x1431C9600、`MeleeAttackActionClientImpl::ContactAttack on_hit_bone …` @ 0x1431C96D0/0x1431C9780。ASCII 形态三串在 exe 内零命中——日志串一律 UTF-16。

lea rip-relative xref（仅 48/49 8D 形扫描）：
| 串 | xref 点 |
|---|---|
| Melee.dat 路径 | 0x14140dec8（0x14140deb0 内） |
| WARN 格式串 | 0x14140eb3d（0x14140ea70 内） |
| ContactAttack 串 A | 0x141410a52、0x141572507 |
| ContactAttack 串 B | 0x141410b7f、0x141572635 |
| 裸 `MeleeAttackActionClient` 串 @ 0x1431C962E | 无 lea xref（疑经虚表/类型注册到达，非查表路径必需，未深究） |

函数：
- **0x14140deb0**：Melee.dat 行索引取用器（rcx=out holder；加载表 → `0x142195170`（串哈希，edx=0x2c）→ 16 桶散列定位 → `0x1401600c0` map 操作 → 返回 holder，`[holder]=行指针`）。姊妹函数 0x14140e0b0 为 SkillArtVariations.dat 取用器（edx=0x46，串长 0x23）。
- **0x14140ea70**：行应用函数。签名 `(rcx=A 语境, rdx=B 技能对象, r8=C 目标动作对象)`：`rdx_key = [[B]]+0x4f`，调 0x14140e280(out, rdx_key, A)；有行则把行字段写进 C：`+0x24/+0x34/+0x44/+0x54/+0x64/+0x74/+0x84`（步长 0x10，7 个字段，经 0x141ed8680）、`+0x14`（经 0x141ed6250）、`[+0x95]`（经 0x141ed8430）；无行则记 WARN（名取自 `[[B]]` 链的字符串 + `::` + 级，级取自 `[B]` 链 dword）。
- **0x14140e280**：查表函数。签名 `(rcx=out, rdx=r15 key 对象指针, r8=r14 语境)`，分两阶段（§14.2）。
- **0x14241c760**：哈希 map 查找。`(rcx=map, rdx=out, r8=key)`：`0x142413eb0(key)` 哈希 → Fibonacci 散列（乘 0x9e3779b97f4a7c15，桶位数 `[map+0x36]`) → 桶内 `[hash]` 比对 → 条目步长 0x20。未命中返回 map 尾（调用方判空行）。
- **0x142413eb0**：key 哈希。`rbx=key`；`rdx=key+8` 调 0x1402a3240（对 `[rdx]` 处 8 字节 FNV-1a）；再把 `[key+0..4)` 4 字节 FNV-1a 混入。**故 key = `{u32 @+0, qword @+8}`**，qword 按值哈希。
- **0x1402a3240**：8 字节值哈希（FNV-1a，basis 0xcbf29ce484222325，prime 0x100000001b3；`[rdx]==0` → 0）。不读字符串内容——证实 qword 分量是指针身份。
- **0x14244ace0**：指针→行号换算。`[rcx]==0 → 0x6a92`；否则 `(ptr - [table+0x28] 之首)/步长 + 1`（倒数乘法 0x4d4873ecade304d5，sar 5，inc）。即 SAV 行内某指针字段的 1-based 行号。

### 14.2 键的构造（已实证，0x14140e280 分阶段）

```
fn(out, r15=keyobj, r14=ctx):
  ebx = 0x153
  # 阶段 1：SkillArtVariations 查询（0x1423d86e0，key=r15）
  sav_range = query(SAV, r15)
  if sav_range 非空:
      cand = 0x1405cd450(sav_range)          # 首候选行对象
      if [cand] 且 [[cand]+0x10c] 非空:
          ebx = 0x14244ace0([cand]+0x10c)    # SAV 行内指针字段的行号
  ebx = [r14 vtable slot 0](r14, edx=ebx)    # 语境映射，0x14140e3c4–0x14140e3d2
  # 阶段 2：Melee.dat 查询（[r15] 非空时）
  melee = 0x14140deb0()
  key = { u32: ebx, qword: [r15], 持有器: [r15+8] }   # 栈上拼装，r8=&key
  row = 0x14241c760(melee_index, out, &key)
  out = (row == melee_end) ? {0,0} : {[row+0x18], melee_holder}
```

- **P 分量**：`[r15]` 与 `[r15+8]` 构成 shared_ptr（`[r15+8]` 对象带 +0x38/+0x3c 引用计数，与全客户端 holder 形态一致）。r15 = WARN 函数算出的 `[[B]]+0x4f`。P 的身份（应为 ActiveSkills 行 661 的内存行对象指针）**静态未证实**——只证实了它是指针身份比较。
- **ebx 分量**：初值 0x153（339；SAV 行 339 = `knockback_wave`，与 MeleePlayer 无可见关联——初值语义未定）；SAV 命中时被行号换算覆盖；再经语境虚调用映射。**最终 ebx 值静态未知**。Melee 行 17 的 `__col1=1`，故命中要求最终 ebx=1（若 ebx 即 __col1——键的 u32 分量与 __col1 的对应关系为强推断，见 §14.6）。
- **阶段 1 的 SAV 侧（已实证，数据）**：SAV 行 `default_ranged`（行 5）的 `ActiveSkill` 数组含 661——阶段 1 的查询以同一 key 对象命中它是数据自洽的；但该行 `Variants=[]`，其 `[+0x10c]` 指针字段内容与换算结果静态未读。

### 14.3 数据实查（已实证，0.5.5 datc64 解码，行宽校验通过）

| 表 | 行数 | 行宽 | 关键行 |
|---|---|---|---|
| Melee.dat | 213 | 205 B | 行 17：`ActiveSkill=661, __col1=1`，MeleeTrail3/4=213、Trail5=206、Trail6=218，其余 trail 空 |
| ActiveSkills.dat | 1147 | 338 B | 行 40：Id=`melee`；行 661：Id=`player_melee`，`DisplayedName=Default Attack`，ActionType=28，GrantedEffect="" |
| SkillArtVariations.dat | 737 | 284 B | 行 5 `default_ranged`：ActiveSkill 数组含 661；无 Id 含 `Melee` 的行 |
| GrantedEffects（staging） | 8349 | — | 行 0：Id=`MeleePlayer`，`ActiveSkill=661`，`StatSet=0`，AdditionalStatSets 空 |
| GrantedEffectsPerLevel（staging） | 34300 | — | 行 0：`GrantedEffect=0, Level=1, Cooldown=0` |
| GrantedEffectStatSets（staging） | 8283 | — | 行 0：Id=`MeleePlayer` |

- Melee.dat 的 `__col1` 分布：AS=40（`melee`）17 行（0–14、100、200）；AS=661（`player_melee`）仅 1 行（__col1=1）；其余多为单行。**`(661, 1)` 唯一**。
- Melee.dat validFor=2 schema 列序：`ActiveSkill(foreignrow) / __col1(i32) / MiscAnimated / MeleeTrail1–7 / bool / SurgeEffect_EPKFile / 2×string / MeleeTrail8–9`，列宽和 205 = 实际行宽 ✓。
- WARN 消息的 `::1` = 技能等级（GEPL 行 0 的 Level=1），与 key 的 u32 分量**不是同一字段**——消息只证明 GE 解析与等级解析成功，不证明 key 命中。

### 14.4 ActiveSkill 列与 MeleeAttackActionClient 的关系（任务项 4，已实证）

- GE 行 0 的 `ActiveSkill` 列 = 外键 661 → ActiveSkills 行 661，Id=`player_melee`。它是**技能定义**（Default Attack，ActionType 28）。
- `MeleeAttackActionClient` / `MeleeAttackActionClientImpl` 是**客户端 C++ 类名**（动作的客户端实现；ContactAttack 方法串为证）。WARN 文本把类名硬编码进格式串，技能名部分取 GE Id。
- 两者经 Melee.dat 桥接：`MeleeAttackActionClient` 的行应用函数按 `(ActiveSkill 定义, 变体)` 查 Melee.dat 行，再把行的 trail/字段写进动作对象。**网关侧不存在名为 MeleeAttackActionClient 的字段**；候选控制面只有记录字段（§14.6）。

### 14.5 selector 字节的角色（已实证部分，记录读程 0x142189c40 块）

记录读程（0x142188D50）在尾段/步 11 之后有一段定义解析块（0x142189c40–0x142189d31）：以 `"Actor"` 为键查某注册表得定义对象 r8，再按 r8 的字段取两 dword 写 `[rbp+0x20]/[rbp+0x24]`：
- 某标志 `[rax+0x20]==0` → 取 `[r8+0x2c8]/[r8+0x2cc]`；
- 否则看 selector（`[rbp+0x338]`，即流内 selector 字节）：`dl = selector & 0x3f`，`ecx = selector >> 6`；ecx==1 或 2 → 取 `[r8+0x2c8+40*dl]` 系；其余（含 selector=0）→ 取 `[r8+0x924]/[r8+0x928]`。
- **selector=0 与 selector=1 在此块行为相同**（同走 `[r8+0x924]` 支）——改 selector 0→1 不影响此块。`[rbp+0x20]/[rbp+0x24]` 的下游用途（是否进入技能对象、是否影响 Melee key）**静态未追踪到**，不作断言。

### 14.6 网关侧改法评估：无唯一修正，缺失证据（分级）

网关现发记录：`Id=0x0102、selector=0、GEPL 0、GESSPL 0、CooldownMs=0、weaponStats`。静态已排除/已证实：
- GEPL/GESSPL 行号正确（数据链 GE 0 → AS 661 → Melee 行 17 完整）——**行号不是缺口**。
- selector 0/1 在记录读程定义块内无差别——**selector 不是已证实的缺口**（其在动作构造中的其它用途未排除）。
- 缺失的一环（运行时观测，未静态可得）：
  1. **ebx 的终值**：SAV 换算与语境虚调用之后是多少？是否为 1？若不是，SAV 查询/虚调用的哪一步走偏？
  2. **P 的身份**：`[[skill]]+0x4f` 的 shared_ptr 是否指向 ActiveSkills 行 661 的内存对象？若不是，指向何对象（虚表定身份）？
  3. 二者与网关字段的因果：P 由技能对象的 ActiveSkill 引用填充——该引用由 GE 行解析（数据侧已正确）还是由某记录字段/后续步骤填充？静态未见填充点。
- 故**不给出字段改法**；一次 v17 会话同时观测 ebx 与 P 即可定案（§14.7）。在此之前不改服务器代码。

### 14.7 v17 探针钩子清单（一次会话，读数只读）

全部只盯玩家实体（id 0x1000 的 CreateObject 之后）；探针 runner 重读 JS，客户端须重开。保留 v16 全部钩子（模型线并行）。

1. **0x14140e280 entry**：log rdx（r15）、`[r15]`（P）、`[r15+8]`（control）、`[P]`（首 qword，虚表/行标记）、r8（r14）、`[r14]`（语境虚表）。
2. **0x14140e441（map-find 调用点，onEnter）**：log r8（key 指针）、`[r8]`（ebx，u32）、`[r8+8]`（P）；**0x14140e446（调用返回后）**：log rax 与 `[rax]`（命中行指针或 map 尾）。
3. **0x14140e3cf（虚调用点，onEnter）**：log edx（ebx 入）、`[r14]`；**0x14140e3d2**：log eax（ebx 出）——定虚调用是否改写 ebx。
4. **0x14244ace0 entry/leave**：log rcx、`[rcx]`、eax 返回值——定 SAV 换算的 ebx 候选。
5. **0x14140ea70 entry**：沿 arg2 链 log：`[rdx]`、`[[rdx]]`、名串（`[[[rdx]]]` 缓冲 + `[ [rdx]+0x10 ]` 长度域）、`[[rdx]]+0x4f` 处 shared_ptr（P + control + `[P]`）。
6. **0x1423d86e0 leave**：log 返回的 range 空/非空——定阶段 1 是否命中 SAV 行。

判读顺序：#2 定运行时 key（ebx，P）→ #1/#5 定 P 身份（是否为 AS 661 行对象）→ #3/#4 定 ebx 来源（SAV 换算 vs 虚调用 vs 初值 0x153）→ 若 ebx≠1，查虚调用 this 的类型与 slot 0 语义（另立静态任务）；若 P 不对，查技能对象 ActiveSkill 引用的填充点（记录读程定义块下游或构造后步骤）。

## 2026-11-05 evening15 — runtime key（运行时刻键重构）

会话：2026-11-05 05:48:42，探针 v17 + 洪水修复，日志干净；网关 blob 1191 B；Client.txt 止于 `Could not find row for MeleeAttackActionClient skill MeleePlayer::1` WARN；网关 05:48:56 见断开。fnC_done 全程零触发——死于构造中途，与 20:37/21:07 同型。完整过滤 trace：`trace-0548-v17.txt`；原始日志在 PC `Temp\km_capture.log`（多会话追加，查 05:48 段须按时间前缀过滤）。

本章纠正两处简报/前章的记录错误：(1) `sav_range` 钩子已在 02:17 洪水修复中移除，05:48 会话根本没有该钩子——其零触发不能证明 SAV range 为空；(2) 语境虚表 VA 曾按错误基址换算成 0x1427EEF38（读到 .text 代码），05:48 会话真实 exe 基址为 0x7ff607880000（throw_ctx 模块枚举），虚表 VA 应为 **0x14357EF38**，slot 0 = **0x1426aca90**。

### 15.1 查找函数 0x14140e280 全结构（已实证，反汇编）

```
ebx = 0x153                                    ; 0x14140e29a
SAV 查询 0x1423d86e0（无条件调用，range 出参 [rbp-0x39]）; 0x14140e2ff
if (begin != end):
    cand = 0x1405cd450(range)                  ; 0x14140e363
    if (cand && [[cand]+0x10c]):
        ebx = 0x14244ace0(&[cand]+0x10c)       ; 0x14140e3bd，见 §15.3
r14 = 语境对象；rcx=[r14]，r8=[rcx]（虚表 slot 0）
ebx = slot0(语境, ebx)                          ; call 0x14140e3cf，mov ebx,eax @0x14140e3d2
if ([r15] == 0): out = {0,0}，跳尾             ; [r15] = P（[[B]]+0x4f 解引）
key = { u32 ebx @+0, pad, qword P @+8, qword control @+0x10 }，位于 [rbp-0x51]
map-find 0x14241c760(map=[holder+0x28]+0x20, out=[rbp+0x7f], key) ; call @0x14140e441
rbx = [out]；与 map 尾哨兵比较；命中 → 行指针 = [rbx+0x18]；未命中 → 零值 + WARN 路径
```

### 15.2 映射函数 slot 0 = 0x1426aca90（已实证）

- 表位于 `[this+0xf8, this+0x100)`，元素 8 字节 `{u32 key, u32 value}`，按键升序；谓词 `0x1423ba4d0` = `[elem] < input`（setl）。
- 二分 lower_bound 后：`rsi != end 且 [rsi] == input` → 返回 `[rsi+4]`；否则走 fallback：`[this+0xe8]` 非空 → 尾调用其虚表 slot 0（同一输入）；`[this+0xe8]` 为空 → **返回 0**。
- 05:48 会话语境：`r14 = 0x37b89763390`，`[r14] = 0x7ff60adfef38` → VA 0x14357EF38（.rdata）；slot 0/1/2/3 = 0x1426aca90/0x1426ad100/0x1426ac880/0x1426ad284。

### 15.3 SAV 换算 0x14244ace0（已实证）

- 入参 rcx = 指向 `{ptr, control}` shared_ptr 的地址。`[rcx]==0` → 返回 **0x6a92 = 27282**（Stats 行数 27281 + 1，空指针哨兵）。
- 否则释放 control 后：`base = [[control+0x28]]`（首 qword），返回 `((ptr - base) / 106) + 1`——步长 106 由倒数乘法确证（magic `0x4d4873ecade304d5`，`imul` 后 `sar 5`，符号修正后 +1；2^69/magic = 106.0 精确）。
- 05:48:42 秒内成批触发 222 次：10 组三元组 ×22 次（区域生成实体，10 个实体级引用），另有一组 23 次（ret 0x3108）与一个单次离群（a0=0x37b8241ea18，ret **0x6054**）。玩家本次查表的换算调用（若 SAV 阶段运行）当在二者之一，但 a0 族与区域生成实体相同，归属无法确证（推断，弱）。
- 输入值三歧（待 v18 定）：SAV range 为空 → **0x153**；非空 → **0x3108** 或 **0x6054** 之一。三种输入下映射均返回 0（§15.5）。

### 15.4 键哈希 0x142413eb0 + FNV 0x1402a3240（已实证）

- `0x1402a3240(rdx=key+8)`：P==0 → 0；否则 FNV-1a（basis `0xcbf29ce484222325`，prime `0x100000001b3`）处理 P 值本身的 8 字节（小端序，逐字节 xor 后乘），得 hP 前缀；再对 `[control+0x28]` 的 8 字节做同样 FNV 得 hQ；返回 `(hP_prefix + hQ_prefix) * prime`（control 为空时只乘 hP 前缀）。**P 按指针值哈希，不读字符串内容**（evening14 结论维持）。
- `0x142413eb0`：`rdx = hP ^ 0x000811d69050c5d1f`（常量由指令字节 `48 b8 1f 5d 0c 05 69 1d 81 00` 确证）；ebx 混入是 **dword 移位式**（`ebx ^ basis`，乘 prime，异或 `ebx>>8`，乘，异或 `ebx>>16`，乘，异或 `ebx>>24`，乘）——不是逐字节 FNV（纠正初版验算）；终值 `((hP^C) * 0x1000193) ^ h_ebx`。
- 验算：Q 未知（trace 未记录 `[key+0x10]` 的 control 与 `[control+0x28]`），Q=null 时 ebx ∈ {0, 1, 0x153, 0x6a92} 的哈希（及 Fibonacci 乘积高 64 位）均 ≠ find_out 的 rdx `0x86212caf3fe8e602`。哈希项**未证实、不影响 miss 定案**（§15.5 的比较失败不依赖桶位置）。

### 15.5 运行时键重构与 miss 原因（已实证链）

**ebx = 0（已实证）**，链条每环均有反汇编为证：
1. 映射返回 `mov ebx, eax`（0x14140e3d2）后，至 map-find 调用之间无任何 ebx 写操作；key 构建只存 rbx。
2. 中间 release 调用 `0x1421d7070` 入口即存 rbx/rsi 于栈帧（标准保存，rbx 不变）。
3. map-find `0x14241c760` 两条返回路径均 `pop rbx`（早退路径 0x14241c780–787、主路径 0x14241c8c5–8c8），**rbx 全程保存**。
4. find_out（0x14140e446）入口 `rbx = 0x0` ⟹ 映射返回 0 ⟹ **输入不在语境 +0xf8 表内，且 fallback 链（[this+0xe8]）无结果或为空**。

**miss 双重决定（已实证）**：
- (a) 键比较失败：map-find 全键比较 `[rsi]==entry dword` 且 `[rsi+8]==entry qword`；ebx=0 ≠ 行 17 的 `__col1=1`，比较必败，与 P 无关。
- (b) 被查索引疑似空/未建：find_out 时 `[out]=0`（rsi=0x27f4dfd330，`[rsi]=0x0`），即 map-find 写入的尾哨兵 `[map+8]=0`；调用方随后 `rbx==尾哨兵` 走未命中分支（命中分支 0x14140e47f 首指令即 `[rbx+0x18]`，rbx=0 时必硬件 AV；实际死亡为 C++ 异常 + "Could not find row" WARN，与未命中分支一致）。**索引尾哨兵为 NULL 是强信号，map 本体状态（begin/buckets/count）待 v18 直接读数**。

**P 非空（已实证）**：`P = 0x37ba49b68ca`（`[rdx]`，rdx=`[[B]]+0x4f`）。`melee_rowapp` 的 `p4f=0` 与 name `ERR` 均为钩子读法错误（读了 `[B+0x4f]` 而非 `[[B]]+0x4f`），不是 shared_ptr 为空或名字缺失的证据。**P 的身份（是否为 ActiveSkills 行 661 的内存对象）仍未知**——miss 定案不需要它，但任何网关修正都需要它（§15.8）。

**find_in/find_out 悖论已解（探针 artifact，已实证地址）**：0x14140e441 确为 `call 0x14241c760` 指令（5 字节），0x14140e446 为返回点 `mov rbx,[rax]`。find_in 零触发而 find_out 触发一次，说明调用点钩子静默失效（attach 或回调失败且未落 hook_fail 行；同族先例：vcall_pre 在 attach 时报 hook_fail，地址在指令中间）。查表本身确已执行（find_out 触发、rdx 被哈希路径改写）。v18 改钩 map-find 函数入口（干净边界），见 §15.8。

WARN 文本的 `::1` = GEPL 行 0 的 Level，与 key 的 u32 分量不是同一字段（重申 evening14）。

### 15.6 0x13fff544a 定性（已实证排除 + 推断）

- **不是截断的 exe 返回地址（已实证）**：05:48 基址 0x7ff607880000（低 32 位 0x78800000），20:37 基址 0x7ff64b360000（低 32 位 0x4B360000）。同一低 32 位值 0x13FFF544A 要求两会话的偏移低 32 位分别为 0x9B7F544A（≈2.6 GB）与 0xC8C9544A（≈3.3 GB），均超出映像大小（~90 MB）——不可能。
- **不在任何已加载模块内（已实证）**：throw_ctx 模块枚举（05:48:55）显示 exe 基址 0x7ff607880000，无模块靠近 0x13fff544a（该值本身在 4 GB 以下，0x000000013FFF544A）。
- **system 异常地址族 0x6c4dd408a（05:48）/ 0x6812f408a（20:25）（已实证特征）**：均无模块归属、跨会话在高位变化（ASLR 族 0x6???????）、低字节同为 0x8a——符合 ASLR 堆/映射区的野指针，与"死亡螺旋二次 fault"一致，不是可逆向的代码位置。
- **定性（推断，强）**：0x13fff544a 最可能是不可靠栈回溯读出的 stale 32 位槽值（帧 2 起的回溯已确证为野指针串；确定性栈布局 + 确定性槽内容解释了跨 ASLR 值恒定）。手动映射/ JIT 可执行区的可能性未排除但无证据。**它在 throw 路径中无已证实角色**；帧 1（throw helper 调用方）才是有效信息。
- evening12/13 的"frameless 外层帧导致 20:25 与 20:37 结局不同"解释**撤回**，改为：主事件均为 C++ 异常（0xE06D7363，经 0x142c14380），20:25 被捕获后继续、20:37 序列终止的差异原因未定（死亡螺旋二次 fault 的落点不同所致，待 v18 的 throw 点上下文区分）。
- v18 决定性测试：throw helper 入口读 `this.returnAddress` 与 Rsp/Rbp、按模块边界做可靠 unwind、`Memory.readByteArray(ptr(0x13fff544a))` 判可读/可执行性与首字节、以及一次去掉 throw 钩子的对照会话（Frida artifact 检验）。

### 15.7 +0x350 再判（已实证机制 + 推断）

- 跳过分支语义确证（0x141da6983–0x141da69b5）：比较流内串长度与 +0x350 持有器串长度（`[rdx+0x10]` vs rbx），`call 0x142cb80a0` 串比较，相等 → `je 0x141da6aa1` 跳过建模；不等 → 0x141da69bb 起释放 `[rsi+0x190]/[rsi+0x198]` 旧 AO 引用并继续建模。流内路径为 IntFour.ao（字节精确，v12/v13 已证）⟹ +0x350 持有器在读时同样持有 IntFour.ao，跳过分支确已触发。
- **H1（定义播种）支持度高于 H2（对象池复用）（推断，强）**：实体为新 spawn、持有器链完整成形（两级解引成功）、持有内容恰为定义默认值。anim_entry 串内容读出乱码是钩子读了 wstring 对象字节而非缓冲区的 artifact，不反驳 H1。
- **结构性结论（已实证机制 + 推断）**：对默认 AO 路径，blob 的 Animated 读程按设计就是 no-op；**建模唯一路径是晚期 +0x10 刷新（0x141da2c30，分配 AO + 取描述符 + 挂 +0x360 监听）**，其触发在注册/激活之后、受 attach 门 `[owner+0x8c]&2` 控。全部死亡会话（20:25 注册后死于激活后 walk、20:37/21:07/05:48 死于构造中途）均未走到该步——**模型未现不需要独立的 Animated/blob 解释，当前最强解释就是"死在建模步骤之前"**。ctor 死因解决后若模型仍未现，再查刷新触发与 attach 门；+0x350 本身不是 bug，不改。
- p190=p198=0（anim_entry）与"跳过分支先于任何 AO 分配"一致。

### 15.8 网关侧修正：推不出——缺失环节与 v18 清单

**不给出字段改法（分级：缺失环节未闭合，猜测禁止）。** 网关只控制 blob 字节；(ebx, P) 由客户端自身状态派生：ebx 经 SAV 数据 + 语境 +0xf8 表 + fallback 链，P 为技能对象内 shared_ptr 的堆身份（指针值）。已证实 ebx=0，但以下环节缺失，无法从中推出任何记录字段（Id/selector/GEPL 行号/统计表/CooldownMs）的改法——行号与 selector 已在 evening10/14 排除为缺口，剩余字段与 ebx/P 之间**无已证实的因果链**：
1. 映射输入值（§15.3 三歧）与 +0xf8 表内容（运行时构建，静态不可见）——映射为何返回 0？
2. 被查 Melee 索引的本体状态（begin/buckets/count，尾哨兵 NULL 的含义）——索引是否根本未建？
3. P 的身份（`[P]` 首 qword/虚表）——是否为 AS 661 行对象？若不是，技能对象的 ActiveSkill 引用由何填充（记录读程定义块下游 0x142189c40 的 `[rbp+0x20]/[rbp+0x24]` 去向未追踪）？
4. SAV 查询的 holder（`[rbp+0x6f]`）来源——技能对象从哪一级获得变体语境？

**v18 钩子清单（只读，一次会话；客户端须重开；每钩 attach 成败在 arm 时显式落行）：**
1. **0x14241c760 入口（map-find 本体，替代调用点钩子）**：log rcx（map）、`[rcx]`/`[rcx+8]`/`[rcx+0x18]`/`[rcx+0x20]`/`[rcx+0x36]`（map 生命体征）、r8（key）、`[r8]`（ebx）、`[r8+8]`（P）、`[r8+0x10]`（control）；leave：log rax、`[rax]`、返回值是否为尾哨兵。
2. **0x1426aca90 入口/leave（映射函数）**：log edx（输入）、`[rcx+0xe8]`（fallback）、`[rcx+0xf8]`/`[rcx+0x100]`（表界）；leave：log eax（输出）。另 dump `[rcx+0xf8, rcx+0x100)` 全表（key/value 对，截断 64 项）。
3. **0x1423d86e0 leave（恢复 sav_range 钩子，须防洪水：仅玩家实体窗口内启用）**：log range begin/end（空/非空）。
4. **0x14140e3cf 入口 + 0x14140e3d2**：log edx（ebx 入）、`[r14]`（语境虚表）；0x14140e3d2：log eax（ebx 出）。（0x14140e3cf 在指令边界，已确认。）
5. **0x14140e441 改为 0x14241c760 入口（见 #1）；0x14140e446 保留**：log `[rax]`（命中行指针或尾哨兵）与 rbx。
6. **0x14140ea70 入口（修正读法）**：沿 `[[arg2]]+0x4f` 读 shared_ptr（P + control + `[P]`），名串读 `[[[arg2]]]` 缓冲（`[[arg2]+0x10]` 为长度域）；并 log `[[arg2]+0x4f]` 处 control 的 `[control+0x28]`（哈希第二分量 Q 的来源）。
7. **throw 点**：0x142c14380 入口 log `this.returnAddress`、Rsp/Rbp、模块枚举（`Process.findModuleByAddress` 判 0x13fff544a）、`Memory.readByteArray(ptr('0x13fff544a'), 16)` 试读（try/catch）；**对照会话**：去掉 throw 钩子，确认 0x13fff544a 是否消失。
8. 保留 v16 模型线钩子（anim_entry、+0x10 刷新入口、attach 门）；ctor 链钩子（ctor_tail/throw_ctx）保留。

判读顺序：#1 定索引状态与运行时 key → #2 定映射为何返 0（输入/表/fallback）→ #3 定 SAV 阶段是否运行 → #6 定 P 身份 → 四者闭合后才能判断网关侧是否存在控制面；若四者均指向客户端状态缺失（索引未建/语境为空），则网关无字段可改，转向技能对象构造链的上游（GEPL 统计表内容是否影响 SAV holder 的填充）。

### 15.9 evening14 §14.6 缺口 closure 状态

- 缺口 1（ebx 终值）：**已闭合——ebx=0**（§15.5）。
- 缺口 2（P 身份）：**未闭合**，v18 #6。
- 缺口 3（与网关字段的因果）：**未闭合**，v18 #1–#4 闭合后判定。
- evening14 §14.4 的"网关侧不存在 MeleeAttackActionClient 字段"维持；§14.5 selector 结论维持。

## 2026-11-05 evening16 — two death shapes（两种死亡形态）

会话：2026-11-05 06:48:54，探针 v18（哈希 5a2a4499…，v18b 表 dump 已修复部署、哈希 022588bb…，PC 回读验证一致）；网关 0x2f7 1210 B 与 05:48 同尺寸同秒发，断开 06:49:08（+14 s，与 05:48 的 +14 s 模式相同）。关键摘录：`trace-0648-v18.txt`；05:48 完整 trace：`trace-0548-v17.txt`。本轮纯静态 + 已采 trace 判读，未改服务器代码。

### 16.0 结论（先行，分级）

- **两种形态不是两个根因（推断，强）**：05:48 的"查表 miss + 构造抛错"与 06:48 的"melee 路径零触发 + 映射恒 0"共享同一个持续存在的客户端状态条件——语境对象的 +0xf8 表为空（或无键）且 fallback 链同样无结果，映射对一切输入返回 0。差别只在玩家序列走到了哪一步：05:48 走到了查表并死于 miss；06:48 在查表之前（或查表当时）就已死亡，且探针日志尾部随进程暴力死亡一起丢失，造成"WARN 存在但 rowapp 零触发"的表面矛盾。
- **"循环空转"不成立（已实证）**：0x14140e280 内无重试循环（单次执行、至多两次 map 查找，见 §16.2）；映射 7916 次与 sav_range 7854 次调用来自 37/16 个直接调用点分摊的背景流量（区域生成、记录读程、UI 等），不是 melee 路径的重试。映射函数是通用工具，不是 melee 专属。
- **mapfind 零触发不推翻 evening15（已实证）**：evening15 的链条针对 05:48 会话（find_out 在 0x14140e446 真实触发，指令确为 `call 0x14241c760` 的返回点）；06:48 会话根本未进入 melee 路径，map-find 零触发是预期结果，不是反证。但 evening15 有两处需纠正：其一，查找函数内含**第二次 ebx=0 的 fallback 查找**（此前未发现）；其二，sav_range 的返回值从未度量过 range 空/非空（§16.3/§16.5）。
- **WARN 发出者唯一（已实证）**：`Could not find row for MeleeAttackActionClient skill …` 全 .text 仅一处 lea 引用（0x14140eb3d，0x14140ea70 内），.rdata 无指针表引用，无中途入口。06:48 的 WARN（Client.txt，pid 48088，墙钟 06:48:54）必然由 0x14140ea70 发出；rowapp2 零触发只能是探针消息在进程死亡时丢失（日志止于 06:48:54、runner 存活、socket 晚 14 s 才断——尾部缺失实证），不是第二发出者。判定方法见 §16.6。
- **+0xf8 语义确证（已实证）**：`[this+0xf8]`=表首指针、`[this+0x100]`=表尾指针，8 字节元素 `{u32 key, u32 value}` 升序，二分查找；空表（首==尾）直接走 fallback；fallback 为 `[this+0xe8]` 对象的虚表 slot 0 尾调用，空则返回 0。v18b 的 dump 读法正确（指针读法），下次会话按 §16.4 指南解读。
- **0x6054 定性纠正（已实证部分 + 推断）**：sav_conv 的 a1（rdx）函数内**从未被读**，0x2e1 无意义；该换算函数有 50+ 个直接调用点，是通用工具——0x6054 不能归属玩家技能（evening15 §15.3 的归属推断撤回）。换算表为 106 字节步长、≥27023 行、空哨兵 27282，与 Stats.dat 行数（27281）精确吻合，**强推断为 Stats 内存行数组**，0x6054 = Stats 行 24660（具体 stat 需 base 指针，未采）。
- **网关修正写法：仍推不出**。缺失环节未变且新增一项：SAV range 在 melee 路径上是否为空从未被度量（§16.5 末）。v19 清单见 §16.6。

### 16.1 两种死亡形态的分野

**形态 A（05:48、20:37、21:07、02:11）**：玩家实体构造抵达 0x14140e280 → SAV 查询 + 语境映射（返 0）→ 两次 map 查找均 miss → 0x14140ea70 记 WARN → ctor 尾段 C++ 异常 → 序列死亡（20:25 例外：异常被捕获、留半建成对象、后续死于注册后 AV 链）。

**形态 B（06:48）**：melee 路径上全部钩子零触发——0x14140e280 入口（melee_lookup）、0x14140e3d2（ebx_out）、0x14140ea70（rowapp2）、0x14140e446（find_out）、ctor_throw、fnC_done、0x1000 注册。背景流量正常：映射 7916 次（同一 this=0x3f9356b47d0，fallback 指针非空 0x3f945ff0610，返回值恒 0）、sav_range 7854 次（返回值为 out 结构地址，两值交替、相差 0x40，见 §16.5）、区域生成实体正常注册（world_register id 3221225688..3221225723，f8d=0，ao_attach 多数触发）。探针日志止于 06:48:54（末行即 mapping_in/out 对），runner（pid 7768）存活至今；网关 06:49:08 才见断开。

**分野判定（推断，强）**：形态 B 不是"重试循环"，理由三：
1. 0x14140e280 全结构已逐指令复核（§16.2 调用清单）：无回跳/循环，单次执行，至多两次 map 查找；0x14140ea70 单次调用后即 WARN 返回。调用方级别的重试会表现为 melee_lookup 重复触发——形态 A 仅一次，形态 B 零次。
2. 映射函数直接调用点 37 处（scan_calls，含 0x142189eb5/0x14218a3d5 等**记录读程区**、0x142182xxx Stats 读程区、0x1406a3xxx/0x14213axxx/0x14214axxx 区），另经虚表 slot 0 间接调用；sav 查询 0x1423d86e0 直接调用点 16 处；换算 0x14244ace0 直接调用点 50+ 处。7916/7854 次是多调用点在区域生成 + blob 读程 + UI 期间的正常分摊量（约每秒数百次，非自旋循环的每秒百万级）。
3. 形态 B 的映射恒 0 与形态 A 的映射返 0 是同一条件在不同观测面上的表现：语境对象（05:48 this=0x37b89763390，虚表 0x14357EF38；06:48 this=0x3f9356b47d0，虚表未采——v19 须采 `[this]`）的 +0xf8 表 + fallback 链对一切输入无结果。该条件持续存在，不依赖 melee 路径。

**形态 B 的死亡点（待验）**：日志尾部缺失使"死于查表之前"与"死于查表当时、消息丢失"无法仅凭现有 trace 区分。v19 须捕获 stall 点（createobj_handler → fnC_table → comp_call（idx 顺序）→ 心跳），见 §16.6。用户侧现象（06:49:14 报"出错了"）与 14 s 间隔和 05:48 一致，不追加区分信息。

**映射恒 0 之后调用方如何继续（已实证，0x14140e280 内）**：映射返 0 不触发任何重试或短路——ebx=0 直接拼入 key，照常执行第一次 map 查找；miss 后**无条件执行第二次 ebx=0 的查找**（§16.2）；两次皆 miss 则 out={0,0}，返回调用方 0x14140ea70，后者记 WARN 并返回（不抛错、不重试）。抛错发生在上游 ctor 尾段的后续构造（evening13），不在本函数内。背景调用方（记录读程等）各自处理 0 值——多数路径下 0 是合法默认值，故不致死；唯 melee 路径要求 ebx=1（行 17 __col1），0 值即 miss。

### 16.2 mapfind 零触发：evening15 链条重锚定

**0x14140e280 内全部 call 目标（已实证，逐指令清点）**：
| 调用点 | 目标 | 作用 |
|---|---|---|
| 0x14140e2ac | 0x14140e0b0 | SAV holder 获取（SkillArtVariations.dat 取用器） |
| 0x14140e2d5/0x14140e429/0x14140e451 | 0x1421d7070 | shared_ptr release（3 处） |
| 0x14140e2ff | 0x1423d86e0 | SAV range 查询（无条件；out=[rbp-0x39]，key=r15，holder=[rbp+0x6f]） |
| 0x14140e38f | 0x1405cd450 | range 首候选行对象 |
| 0x14140e3bd | 0x14244ace0 | SAV 行内指针 → 行号换算（rcx=&[cand]+0x10c） |
| 0x14140e3cf | 间接 `call r8` | 语境虚表 slot 0（`[r14]`→虚表→`[vtable]`=0x1426aca90）；`mov ebx,eax` @0x14140e3d2 |
| 0x14140e3ea/0x14140e4ca | 0x14140deb0 | Melee.dat holder 获取（2 处） |
| **0x14140e441** | **0x14241c760** | **第一次 map 查找**：key=`{ebx=映射结果, P=[r15], control=[r15+8]}`（栈 [rbp-0x51]），map=`[[holder]+0x28]+0x20`，out=[rbp+0x7f]；返回点 0x14140e446 `mov rbx,[rax]` |
| 0x14140e521 | 0x14241c760 | **第二次 map 查找（此前未发现）**：key=`{ebx=0（edi 初值 0，全程未改）, P, control}`（同栈位），map 同上，out=[rbp+0x77]；返回点 0x14140e526 |
| 0x14140e5bd | 0x140141e10 | range 清理 |

**第二次查找的含义（已实证）**：第一次命中（`[rbp-0x69]!=0`）则跳过（0x14140e4c0 `jne 0x14140e590`）；miss 才执行第二次，ebx 强制为 0——即"指定变体无行时退回默认变体（__col1=0）"的 fallback。**当映射返回 0 时，两次查找的 key 完全相同**（纯重复）；仅当映射返回非零但无行时，第二次查找才有独立意义。05:48 会话：映射返 0 ⟹ 两次查找同 key (0, P) ⟹ 双 miss ⟹ WARN。evening15 §15.5 的"双重决定"表述修正为：(a) ebx=0 ≠ 1 必败（两次查找皆然）；(b) 索引尾哨兵 NULL（`[out]=0`，即 map 的 end 指针为 0，索引疑似零初始化/未建——v19 在 melee 路径上直接读 map 生命体征验证）。

**0x14140e280 的直接调用方仅两处（已实证）**：0x14140ea70（行应用，0x14140eaa7）与 **0x14140e5f0**（独立小函数，0x14140e65d——此前误作查找函数尾部，实为 int3 隔离后的另一函数：构造对象、取 `[rdi+0xf8]+0x58` 经 0x14010b570 得 key 对象后调查找；其调用方为 0x1414228c2、0x141422941（同一函数内两次，伴 0x142bba600 调用，疑技能/UI 解析循环）与 0x14156bf2f）。0x14140ea70 的直接调用点 19 处，包括 3 个动作客户端构造包装器（0x141471cc0/0x141471d10 直接 call、0x141471d00 尾跳 jmp，均经函数入口）与其余 16 处（0x1413cabd8、0x1413d81b8、0x14145939e、0x14145c6f8、0x1414896b8、0x14148a6e0、0x14156b2b0、0x141572e18、0x14157a0f7、0x14157c088、0x14157c508、0x14157d038、0x14157db7e、0x14157ee68、0x141597904）。

**结论**：evening15 的"映射返 0 → find_out rbx=0 → miss"链条在 05:48 会话上**每环均有指令为证，维持**；06:48 的 mapfind 零触发是因为该会话未进入查找函数的任一调用方（map-find 的 16 个直接调用点亦全程未运行），不是链条错误。v18 的 mapfind 钩子（函数入口干净边界）本身无问题——它在 06:48 正确地报告了"未调用"。

### 16.3 WARN 发出者：唯一性证明与矛盾消解

**唯一性（已实证，三重）**：
1. 全 .text 扫描：WARN 格式串 VA 0x1431C9600 的 rip-relative 引用**仅一处**——0x14140eb3d 的 `lea rdx,[rip+...]`（0x14140ea70 内，miss 分支 0x14140eb2e 之后）。Meleedat 路径串亦仅一处（0x14140dec8）。
2. .rdata 全区扫描：**无任何 8 字节指针槽**存放 0x1431C9600——格式串不经指针表到达，排除"另一函数经表取串"的可能。
3. 中途入口扫描：rel32 目标落在 (0x14140ea70, 0x14140ec80) 内的仅一处——0x142af13b4 → 0x14140eaa1，经核查为**假阳性**：0x142af13b1 处真实指令是 `mov rcx,[rbp-0x18]`（48 8B 4D E8），0x142af13b4 是其位移字节 0xE8，非 call 操作码。无任何函数中途跳入 WARN 块；全部 19 个调用点均经函数入口（Frida 入口钩子必触发）。

WARN 发出序列（0x14140eb2e 起，已实证）：`0x14013e3f0` 建串 → `0x14014d7a0` 格式化（格式串 + 技能名 + `::` + 级）→ `0x14019c930`/`0x140157890` 组装 → 日志调用 **0x14218eaf0**（ecx=0xdc46e4e5，即 Client.txt 行首哈希）。名取自 `[[B]]` 链字符串、级取自 `[B]` 链 dword——与 key 无关（重申 evening14/15）。

**矛盾消解（推断，强）**：06:48 WARN 真实发出（Client.txt：pid 48088，墙钟 06:48:54，毫秒计数 71632765，与前后会话的计数差精确对应墙钟间隔；三会话 pid 各异、无双进程迹象），而 rowapp2（hook_ok，06:48:29 arm，回调三段 try/catch + 无保护 send，PC 回读代码确认无未保护抛错点）零触发。唯一自洽的解释是**探针消息在进程暴力死亡时丢失**：日志末行止于 06:48:54（mapping 对），其后 14 s 再无任何事件而 runner 存活——尾部缺失是实证；Frida 消息异步投递，进程猝死时队列中未及发出的消息（melee 序列的 lookup/find/rowapp 事件恰在死亡同一秒）随 agent 一起丢。05:48 会话进程在 WARN 后又存活约 13 s（05:48:55 尚有 system exception 事件），消息得以发出——这正是两会话在"WARN 是否伴随 trace 事件"上的全部差异。次选解释（第二未探针进程）无证据支持，列为已排除弱项。

**判定方法（v19，见 §16.6）**：裸计数钩子（无读数、只 send 计数）+ runner 记录 Frida error/detach 消息 + 心跳（setInterval）+ 每事件带 pid——四者合一可区分"函数未运行"与"消息丢失"。

### 16.4 +0xf8 表语义（已实证，0x1426aca90 全函数）

```
rsi = [rcx+0xf8]              ; 表首指针
rbx = [rcx+0x100]             ; 表尾指针
count = (rbx - rsi) >> 3       ; 元素数（8 字节/项）
二分 lower_bound（谓词 0x1423ba4d0：[elem] < input）；
命中（rsi != end 且 [rsi] == input）→ 返回 [rsi+4]；
否则 fallback：[this+0xe8] 非空 → 尾调用其虚表 slot 0（同输入）；为空 → 返回 0。
```

- `[this+0xf8]` 与 `[this+0x100]` 是**首/尾指针**（非内联表、非长度域）：函数首两条 mov 即取指针作指针运算（`lea rbp,[rsi+rdi*8]`、`[rsi]` 解引）。count≤0 时 rsi 保持为首指针，随后 `cmp rsi,[r15+0x100]`（首==尾）直接走 fallback——空表判定即首尾相等。
- 元素：`{u32 key @+0, u32 value @+4}`，按键升序。谓词仅比较 key dword。
- fallback 链：`[this+0xe8]` 为另一语境对象指针；链深未知（06:48 仅知第一级非空且整链返 0）。v18b dump 读法（`[this+0xf8]`/`[this+0x100]` 作指针读、`(end-begin)/8` 计项、上限 64）**语义正确**；JS bug（`e.sub(b)` 在 Frida 返回 number，`.toNumber()` 抛错）已在 v18b 修复（哈希 022588bb…，PC 验证一致）。
- **下次会话 dump 解读指南**：n=0 ⟹ 表空，映射只能经 fallback 返回，须同时采 fallback 一级（`[this+0xe8]` 的虚表指针、`[fb+0xe8]`、`[fb+0xf8]`/`[fb+0x100]`）判定整链是否为空；n>0 ⟹ 逐项列出 key/value，核对输入（v19 采 edx）是否在表中；begin==0 ⟹ 表指针空（对象未初始化），dump 须 guard 空指针读。
- 表由谁填充、语境对象所属类（虚表 0x14357EF38）：静态未定。v19 采 `[this]`（虚表指针）确认两会话同类；填充源须另立静态任务（查该虚表类的构造/数据加载引用），不在本轮范围。

### 16.5 0x6054 单次离群与 SAV 换算再定

**0x14244ace0 全函数（已实证）**：
```
if ([rcx] == 0) return 0x6a92;                    ; 空 shared_ptr 哨兵
control = [rcx+8]; （release）
base = [[control+0x28]];                          ; [control+0x28] 为指向表首的指针槽
return (([rcx] - base) * 0x4d4873ecade304d5 >> 5，符号修正) + 1;   ; 即 (ptr-base)/106 + 1
```
- **rdx（hook 的 a1）函数内从未被读**：0x2e1 无意义，任何基于 a1 的归属推断作废。
- 步长 106 由 magic 确证（2^69/magic = 106.0 精确，sar 5）；+1 为 1-based 行号。
- **调用点 50+ 处**（scan_calls，遍布 0x1402xxxx–0x140d5xxxx）：通用工具。0x6054（及 0x3108 等循环值）**不能归属玩家/melee 路径**——evening15 §15.3 "玩家换算调用当在二者之一"撤回。a0 低位同为 …ea18（两会话）仅说明同一结构调用槽（栈/堆分配格局稳定），不定调用身份。
- **换算表身份（推断，强）**：观测返回值域 0x22e7–0x698f（8935–27023），空哨兵 0x6a92=27282 = 行数+1 ⟹ 表行数 27281，恰为 Stats.dat 行数（staging 报告）；步长 106 的数组唯此吻合。0x6054 = 该表行 24660（具体 stat 行身份需 base 指针 `[[control+0x28]]`，未采）。SAV 本身仅 737 行——0x6054 不可能是 SAV 行号，排除"变体行"解读。
- **SAV range 空/非空从未被度量（已实证缺失）**：v18 的 sav_range 钩子仅记 leave 返回值；0x1423d86e0 尾段 `mov rax,rbx; ret`——返回值恒为 out 结构地址（06:48 两交替值 0xfd9f3fd7b8/0xfd9f3fd778 为两调用点的栈上 out 槽，相差 0x40），**非空返回值与 range 非空无关**。range 本体在 out+0x10（begin）/out+0x28（end）（调用方 0x14140e353 比较 `[rbp-0x29]` 与 `[rbp-0x11]`，即 out+0x10/out+0x28；函数尾写 `[rbx+0x10]=[rsp+0x38]`、`[rbx+0x28]=[rsp+0x40]` 一致）。**这是当前最大未度量变量**：SAV range 为空 ⟹ ebx 保持初值 0x153；非空 ⟹ 换算值（0x3108/0x6054 候选）再经映射——映射恒 0 时两者皆 miss，但根因定位完全不同（SAV holder 未填充 vs 映射表空）。v19 第一项即度量它（§16.6）。

### 16.6 v19 钩子清单（只读、防洪水、区分两种死亡）

原则：背景高频钩子一律采样/过滤，melee 路径钩子全量；每事件带 `Process.id`；runner 记录 Frida error 与 detach 消息；agent 加 1 s 心跳（`setInterval` send `hb`，进程死亡即停——区分"agent 死"与"路径静默"）。客户端须重开；arm 时显式落行每钩成败（沿用 safeAttach + hook_ok）。

1. **SAV range 空/非空（最高优先级）**：0x1423d86e0 leave，读 out 结构 `[rcx_arg+0x10]`（begin）与 `[rcx_arg+0x28]`（end）（rcx 入参即 out 指针，函数内保存于 rbx；leave 时用 `this.context.rbx` 或闭包保存的 args[0]）。**按返回地址过滤**：仅当 `this.returnAddress` 落在 [0x14140e280, 0x14140e700)（查找函数 + 0x14140e5f0）内才 send——背景 16 调用点零流量。附带记 range 首候选 `[begin]`（若非空）供换算对照。
2. **映射输入 + 表 + fallback 一级**：0x1426aca90 entry：edx（输入）、`[rcx]`（虚表）、`[rcx+0xe8]`（fallback）、`[rcx+0xf8]`/`[rcx+0x100]`（表界）；leave：eax。表 dump（≤64 项）**仅当 this 与 05:48/06:48 语境不同或表非空时**发送全量，否则每会话首 3 次后采样（1/100）。fallback 一级：读 `[fb]`、`[fb+0xe8]`、`[fb+0xf8]`、`[fb+0x100]`（try/catch）。
3. **map 生命体征（melee 路径限定）**：0x14241c760 entry/leave，**按返回地址过滤**至 [0x14140e280, 0x14140e600)：rcx（map）、`[rcx]`/`[rcx+8]`（begin/end）、`[rcx+0x18]`/`[rcx+0x20]`/`[rcx+0x36]`、key（`[r8]`=ebx、`[r8+8]`=P、`[r8+0x10]`=control）；leave：rax、`[rax]`。区分"索引未建（end=0）"与"索引已建但无行"。
4. **ebx 出入（修正地址）**：0x14140e3d2（`mov ebx,eax`，干净边界）记 eax；0x14140e3cf 为**已知中指令地址**，不再挂钩（此前 hook_fail 已证实）。另在 0x14140e3c4（虚调用前）记 edx=ebx 入（同一基本块内，安全）。
5. **裸计数钩子（消息丢失判定）**：0x14140ea70 入口**仅 send `{ev:'rowapp_hit'}`**（零读数，排除回调抛错可能）；另 0x14140e280 入口裸计数 `lookup_hit`。若裸钩子触发而读数钩子无记录 ⟹ 回调问题；若裸钩子亦无而 Client.txt 有 WARN ⟹ 消息丢失/第二进程，二者由心跳 + pid 区分。
6. **rowapp 修正读法**：0x14140ea70 entry：`[[arg2]]+0x4f` 的 shared_ptr（P、control、`[P]`）、`[[[arg2]]]` 名串缓冲（`[[arg2]+0x10]` 为长度域，限读 48）、`[control+0x28]`（哈希 Q 分量来源）。仅在裸钩子（#5）确认路径运行后解读。
7. **stall 点捕获（区分"死于查表前"）**：createobj_handler（0x142134ec7，记实体 id）、fnC_table（fn C 入口，记 count）、comp_call（0x141e71375，记 idx 与绝对 cursor，**仅实体 id==0x1000 时** send——背景实体流量大，此过滤必需）、tasks_read（0x141e71383）。序列 `createobj(0x1000) → fnC_table → comp_call idx0..9 → fnC_done` 在哪一步中断，即 stall 点。
8. **throw 点对照**：保留 throw_probe（returnAddress/Rsp/Rbp + 0x13fff544a 试读）；**对照会话**：去掉 throw/throw_ctx 钩子跑一次，确认 0x13fff544a 是否消失（Frida artifact 检验，evening15 §15.6 遗留）。
9. **sav_conv 离群上下文（采样）**：0x14244ace0 leave：每 distinct 返回值记首次全量（a0、`[a0]`、control、`[[control+0x28]]` base、ret），其后仅计数。0x6054 再现时可定其表与行身份。
10. 保留 v16 模型线钩子（anim_entry、+0x10 刷新、attach 门）；保留 v15 AV 链钩子（flagset_expander 等）——形态 A 复现时 E 身份仍待定。

判读顺序：#7 定 stall 点 → #1 定 SAV 阶段 → #2/#4 定映射为何返 0 → #3 定索引状态 → #6 定 P 身份；#5/#8 全程判定探针可信度。五者闭合后才能判断网关侧是否存在控制面。

### 16.7 对 evening15 的纠正清单

1. §15.1/§15.5：查找函数含**第二次 ebx=0 查找**（0x14140e521），此前结构图遗漏；映射返 0 时两次查找同 key。miss 定案不受影响（双 miss），但"重试/ fallback 语义"描述以本章 §16.2 为准。
2. §15.3：0x6054/0x3108 归属玩家换算的推断**撤回**（换算函数 50+ 调用点）；a1=0x2e1 无意义（函数不读 rdx）。SAV 输入三歧（0x153/0x3108/0x6054）维持为"候选"，未定。
3. §15.5(b)："索引尾哨兵 NULL"的读法精确化为"map 的 end 指针为 0（`[out]=0` 且 `rbx==[inner+0x28]`）"，索引未建 vs 已建空表待 v19 #3 区分。
4. §15.6：0x13fff544a 的 stale 槽值定性维持；新增实证：06:48 throw_probe 试读该地址**不可读**（mem13=UNREADABLE），支持"非可执行映射"；v19 #8 对照会话为最终检验。
5. §15.8 清单第 3 项（sav_range leave 记空/非空）**作废重订**：原 v18 实现只记了无意义的返回值；v19 #1 改为读 out+0x10/out+0x28 并按返回地址过滤。
6. §15.2：映射函数表语义由"位于 [this+0xf8, this+0x100)"精确化为"首/尾指针"（本章 §16.4）；v18b dump 读法正确。

### 16.8 网关侧修正：推不出——缺失环节（更新）

不给出字段改法。缺失环节（四项未闭合 + 一项新增）：
1. SAV range 在 melee 路径上是否为空（v19 #1）——决定 ebx 的输入是初值 0x153 还是换算值；
2. +0xf8 表内容与 fallback 链深度（v19 #2）——决定映射为何恒 0；
3. Melee 索引本体状态（v19 #3）——决定 miss 是"索引未建"还是"索引已建无行"；
4. P 的身份（v19 #6）——是否为 AS 661 行对象；
5. （新增）形态 B 的 stall 点（v19 #7）——决定 06:48 的死亡是否与 melee 路径同一根因。
行号与 selector 已排除（evening10/14）；剩余记录字段与 ebx/P 之间无已证实因果链，猜测禁止。若五者均指向客户端状态缺失（SAV holder 空/索引未建/语境表空），则网关无字段可改，转向技能对象构造链上游（GEPL 统计表内容是否影响 SAV holder 填充）或客户端数据加载时序。

### 16.9 缺口 closure 状态（截至 evening16）

- 缺口 1（ebx 终值）：05:48 已闭合——ebx=0；06:48 映射恒 0  corroborate。ebx 输入值（0x153 vs 换算值）未闭合，v19 #1。
- 缺口 2（P 身份）：未闭合，v19 #6。
- 缺口 3（与网关字段的因果）：未闭合，v19 #1–#4、#7 闭合后判定。
- 缺口 4（新增，形态 B stall 点）：未闭合，v19 #7。
- 0x13fff544a：stale 槽值说获 06:48 不可读实证支持；最终检验 v19 #8。

## 2026-11-05 evening17 — stall between CreateObject and ctor

会话：2026-11-05 07:34:54，探针 v19（哈希 ebf4d7e1…）；网关 0x9a 07:34:54.417 → 0x2f7 1210 B + 0x23 07:34:54.421，断开 07:35:05.560（+14.3 s）。关键摘录：`trace-0734-v19.txt`。本轮纯静态 + 已采 trace 判读，未改服务器代码。

### 17.0 结论（先行，分级）

- **stall 点收窄至 [handler 入口，fn C 入口)（已实证）**：createobj_handler（0x142134ec7 入口）在 07:34:54 恰触发一次；其后 fnC_table（fn C 0x141e712a0 入口）、comp_call、fnC_done、0x1000 注册全部零触发；throw_probe 在 :54 零触发（仅登录阶段 :43 一次）；无 AV/系统异常事件记录。心跳止于 :53，mapping_out 持续到 :54（恒返 0），其后全静默。
- **链上各步已静态全映射（已实证，§17.1）**：注册表查找 → 分配器 → ctor 三阶段（0x142601190 基建 → 0x141e70790 描述符分支 → 0x142601300 组件物化 → +0x10 预初始化环）→ fn C。miss 分支必抛错（throw_probe 可见），故 :54 无 throw ⟹ **查找命中**（强推断，消息在 :54 仍流动）。
- **最可能静默死亡点（推断，中）**：ctor 的组件物化窗（0x142601300 的逐组件虚构造 + 0x141e70720 的 +0x10 环）内某组件工厂/回调深递归致栈耗尽——无异常记录的静默死亡在本工程已有先例（18:51，evening10）。备选：探针 .toNumber() bug 的干扰（§17.3，v19b 已消除，下次会话可判别）；跨线程竞态/死锁致挂起后被外部终结（挂与死在现有 trace 中无法区分，§17.3）。
- **两种形态最终分野（推断，强）：未证实同一根因**。形态 A 死于构造内（fn C 之后、查表 miss → ctor 尾抛错）；形态 B 死于构造前（fn C 之前）。共享上游嫌疑——客户端类型/描述符/索引状态未就绪（含 +0xf8 表空）——存在，但无已证实的共同机制把两者连成一因；形态 B 的 stall 先于一切映射表使用。判别式见 §17.4。
- **网关修正写法：推不出**。缺失环节：stall 的精确步骤（v20）+ 同会话内 +0xf8 表/SAV range 的健康状态（v19b 现可正确度量）。时序假说（0x2f7 距 0x9a 仅 4 ms，或撞上区域生成未完成）列为未证实的可试方向，**不得据此先改网关**（§17.7）。

### 17.1 CreateObject 分发 → 实体构造：完整调用链（已实证，反汇编）

分发：跳表 0x1421363f0，case 0x2f7 → 0x142134ec7。r15=world，rsi=message，r14=上下文（span 第三字段，见 §17.1 注）。

| 步 | 地址 | 动作 | 失败模式（可观测性） |
|---|---|---|---|
| 1 | 0x142134ec7–eee | 注册表查找 `0x141693840([world+0x4a8]+0x28, &out=[rbp+0x1d8], key=[msg+0x20]=typeHash)`：取锁 + 24 字节条目线性扫描，命中写 shared_ptr 到 out | miss → §17.1a；锁下挂起 → 挂（不可见）；表损坏 → 长循环/AV |
| 1a | 0x14213638c | miss 分支：组错误串 → **throw 0x142c14380** → `0x1401433c0`（terminate）→ int3 | 必经 throw_probe/throw_ctx；:54 零触发 ⟹ 未走此分支 |
| 2 | 0x142134f02–f1e | blob span 取自 [msg+0x28]/[msg+0x30]；`0x142bba600(0x280)` TLS 池分配 | null → rdi=r14（非实体替身，后续 AV；分配失败极不可能） |
| 3 | 0x142134f46 | `call 0x141e705d0(entity, &typeInfo, id=[msg+0x10], &span, world)` | 见 3a–3f |
| 3a | 0x141e705f2 | `0x142601190`：设实体虚表；[entity+8]=typeInfo（refcount +0x3c）；`0x142601480` 按 count=([D+0x18]−[D+0x10])/8 调整 [entity+0x10] 组件指针数组（D=`[typeInfo+0x28]`） | D 损坏 → AV（可见）；D 向量空 → 空数组（静默，传导至 3d） |
| 3b | 0x141e705fa–6fb | 字段清零：[entity+0x78]=world（[rsp+0x50]，第 5 栈参）、[entity+0x88]=id、[entity+0x8c]=0、[entity+0xc8]=0 | —（纯写） |
| 3c | 0x141e706fe | `0x141e70790`：D=[typeInfo+0x28]；若 [D+0x298]≠[D+0x2a0] → [entity+0x50]=&D+0x290；[entity+0xc8]==0（本路径恒成立）→ 3d；≠0（另一 ctor 的路径）→ 复用/创建环（0x1415d7710 + 虚 +0x10 谓词） | —（分支本身不死） |
| 3d | 0x142601300 | 逐 i∈[entity+0x10]：`0x1415d7710(D,i)` 取工厂 → 虚调用 slot +8（组件构造）→ 存回数组 | 工厂越界 → 组串抛错（可见；环界与 D 向量同一计数，不可达）；工厂返坏指针 → 虚调用 AV（可见）；**工厂深递归 → 栈耗尽静默死（§17.3）**；工厂锁挂 → 挂（不可见） |
| 3e | 0x141e70703–743 | 预初始化环：逐组件虚调用 slot +0x10 | 野虚表 → AV（可见）；回调递归 → 栈耗尽静默死 |
| 3f | 0x141e7074b | `call 0x141e712a0`（fn C，blob 读程） | **07:34 未抵达**（fnC_table 零触发） |
| 3g | 0x141e70750–76b | （fn C 之后）world 接口 +0x1b8 → `0x141e72a00` 登记 → `0x141e70900` 收尾 | 未抵达 |
| 4 | 0x142134f53 起 | handler 善后：`0x14014f040` 接口查询；[world+0x198] 虚调用；[entity+0x8d]&4 → `0x141e73d70` 入图；[entity+0x8c]&8 → +0x350 侧刷新（0x14014f0c0 + 虚 +0x10）；索引/向量记账；后续阶段二 `0x141e71010` | 未抵达 |

注：span 结构为 {base=[rbp−0x10], len=[rbp−8], cursor=[rbp]=r14}；fn C 首部（0x141e712cc–e8）以 [span+8]=len 作界、`[span+0x10]` 作游标。r14 在分发函数内由 [rbp−0x20]/某调用结果装入（0x142134c80/0x142134e07），即初始游标（0）；分配失败分支（rdi=r14）以其作实体替身，仅理论存在。

第二 ctor 0x141e709c0（经 0x141e702e0/0x141e70e40 等路径调用）共享 0x141e70790 + fn C + 登记 + 收尾，但置 [entity+0xc8]=typeInfo 从而走 3c 的复用/创建分支。**区域生成实体的 251 次成功登记不能证明 3d 分支健康**（推断，中）：它们未必走 0x2f7/0x141e705d0 路径；3d（[c8]==0 → 0x142601300）是本路径的特异分支。D 本身（同 typeHash → 同注册表项 → 同 D）则由区域实体的成功反证健康——stall 不在 D。

### 17.2 0x1415d7710 工厂取用（已实证，首段）

`0x1415d7710(D, i)`：i 与 [D+0x18]−[D+0x10] 计数比对；越界 → 组错误串（后续抛错路径，未追踪到底——环界保证不可达）；界内 → 0x1415d786f 起取第 i 个组件的工厂/描述符。调用方 0x142601300 与 0x141e70790 复用环共用此函数（索引语义一致：D 的 [0x10] 向量）。

### 17.3 静默死亡：三种可能与判别（分级）

1. **栈耗尽（推断，中，最可能）**：3d/3e 内某组件工厂或 +0x10 回调深递归/互递归，耗尽 guard 页后进程猝死，Frida 异常钩子无记录——与 18:51 会话的死亡签名相同（日志止于 idx9 comp_call，无 throw、无异常、无 fnC_done）。会话间差异（05:48 走完 fn C、07:34 死于 fn C 之前）的成因未定：候选为组件工厂 consult 的全局惰性状态（Stats 行数组/Melee 索引/变体语境）在不同会话的就绪时序不同，或另一线程的竞态。静态无法定哪一组件——v20 逐索引钩子（§17.6 #5）定位。
2. **探针 bug 干扰（已实证 bug，致死性未定）**：Frida 17.25.1 的 NativePointer/CpuContext 寄存器**没有 .toNumber()**；v18/v18b/v19 中所有 `.toNumber()` 读 ebx/edx/diff 的钩子（mapping onEnter、melee_find_in、ebx_out、mapfind 的 ebx 读、+0xf8 dump 的 `e.sub(b).toNumber()`）在 onEnter 抛 TypeError。mapping 钩子每调用必抛（07:34 计 2976 次 mapping_out、0 次 mapping_in）。Frida 截获器会捕获 JS 异常并继续目标执行，**按机制不应致死**，但 2976 次异常风暴是真实 confound；v19b 已全改为 `.toInt32()`（哈希 1bb5c1bc…，已部署验活）——下次会话若 stall 消失，则 bug 曾有贡献；若 stall 依旧，则排除。
3. **挂起后被终结（无法区分）**：锁死锁（注册表锁、工厂内锁）或无限循环（损坏的扫描向量）表现为挂而非死；用户侧"还有问题"后关闭进程时，网关所见断开（+14 s）与猝死无异。心跳（agent 内 1 s setInterval）在挂起时应**继续**、在猝死时停——07:34 心跳止于 :53 而 mapping_out 到 :54，粒度 1 s 不足定论；v20 以心跳 + 钩子末事件联合判别（§17.6 #10）。

### 17.4 两种形态：最终分野（推断，强：未证实同一根因）

- 形态 A（05:48/20:37/21:07）：fn C 已运行（comp_call 全组件、melee_lookup/find_out/rowapp 触发）→ 查表双 miss → WARN → ctor 尾段（0x141e74740 一带）C++ 异常 → 序列死亡。根因链：语境 +0xf8 表空 + fallback 空 → 映射返 0 → ebx=0 → miss（evening15/16）。
- 形态 B（06:48/07:34）：死于 fn C 之前（07:34 精确到 [handler, fn C)；06:48 的 stall 点未直接定位，但 melee 路径零触发 + 同型尾部缺失与之一致）。**形态 B 的死亡先于一切映射表/SAV/索引使用**——即使 +0xf8 表空是真，也无法经由 evening15 的链条杀死形态 B。
- 共享上游嫌疑（推断，弱）：客户端"类型/描述符/索引状态未就绪"——同一未就绪状态既可致 +0xf8 表空（形态 A 的 miss），也可致 3d/3e 工厂 consult 未建表而递归/挂起（形态 B）。但填充 +0xf8 表的来源与工厂 consult 的表是否为同一状态，**静态未证实**；两形态也可能全然独立（形态 B = 3d 分支缺陷或探针 bug，形态 A = 语境状态缺失）。**不得把两形态报为同一根因**。
- 判别式：v19b 会话（探针健康）+ v20（§17.6）同时采到 (a) stall 精确步骤、(b) 同会话 +0xf8 表/SAV range 状态：若 stall 在 3d 且某组件索引固定，同时 +0xf8 表空 → 共享上游说增强（同一数据加载时序问题）；若 stall 消失 → 探针 bug 曾有贡献；若 stall 在 3d 但 +0xf8 表健康 → 两形态独立。

### 17.5 对 evening15/16 的纠正清单

1. evening15 §15.5 "find_in 零触发 = 调用点钩子静默失效"**撤回，改为探针 bug**：melee_find_in 的 onEnter 首语句即 `.toNumber()`，每触发必抛 TypeError——钩子 attach 正常，是回调自毁。regs17（仅 toString）不受影响，**evening15 的"find_out rbx=0 ⟹ 映射返 0"维持**。
2. evening16 §16.0/§16.3 "06:48 rowapp 零触发 = 消息丢失"**弱化为未定**：rowapp/rowapp2 回调不用 .toNumber()，不受此 bug 影响；消息丢失说仍为最合理解释之一，但 07:34 的 cnt（lookup/rowapp）全程为 0（v19 裸计数钩子，无 .toNumber()）表明形态 B 会话中 melee 路径**确实未运行**——06:48 的 rowapp 零触发更可能同样是"路径未达"而非"消息丢失"。Client.txt 的 WARN 则仍由 0x14140ea70 发出（唯一性证明维持）——WARN 与 melee 路径的关系待 v20 的 stall 定位后重估（WARN 可能发自另一线程/另一实体序列，而非玩家构造序列）。
3. evening16 §16.4 的 +0xf8 dump 读法语义正确；此前 dump ERR 均为 .toNumber() bug 所致，非读法错误。v19b 的 dump 已可信，下次会话按 §16.4 指南解读。
4. evening16 §16.6 清单第 4 项（ebx 出入）修正：0x14140e3cf 永不再挂钩（中指令地址）；ebx 出（0x14140e3d2）改 .toInt32() 后可用；其 06:48 的零触发系 bug 所致，不作"路径未达"证据。

### 17.6 v20 钩子清单（只读、防洪水；全部读数只用 .toInt32()/toString()，禁用 .toNumber() 于 NativePointer/CpuContext）

部署前 grep 验证：除 `readU64().toNumber()`（line 369，已证实可用）外，全脚本零 `.toNumber()`。客户端须重开；arm 时显式落行每钩成败。

1. **ctor 括号**：0x141e705d0 entry（entity=rcx、typeInfo=[rdx]、id=r8d.toInt32、span base/len=[r9]/[r9+8]）+ leave（rax）。定 stall 是否在 ctor 内。
2. **0x142601190 entry/leave**：entry 记 rcx；leave 记 rax。定基建是否返回。
3. **0x141e70790 entry/leave**：entry 记 [rcx+8]、D、`[D+0x298]`/`[D+0x2a0]`；leave。定描述符分支是否返回。
4. **0x142601480 entry/leave**（向量调整）：entry 记 count（rdx.toInt32）；leave 记 [entity+0x10]/[entity+0x18]。定组件数组规模（0 = D 向量空；异常大 = D 损坏）。
5. **0x142601300 递归探测**：entry 记 rsp（toString）+ 嵌套计数（entry 计数器，leave 递减；>1 即重入）+ [rcx+0x10]/[rcx+0x18]；leave 记 rax。重入 + rsp 单调下降 = 栈耗尽进行中。
6. **工厂逐索引**：0x1415d7710 entry（edx.toInt32 = 组件索引）+ leave（rax = 工厂指针）。定死在哪一组件索引；索引恒定重复 = 该组件工厂递归。
7. **+0x10 环逐索引**：0x141e70720（环头，safeAttach）记 ebx.toInt32（索引）+ [rcx] 虚表。界内（≤组件数），全量。
8. **注册表 leave**：0x141693840 leave 记 [args[1]]（out shared_ptr，0 = miss）。罕见，全量。
9. **分配器 leave**：0x142bba600 leave 记 rax（0 = 分配失败）。罕见，全量。
10. **五环确认（v19b 已有，保留并验证）**：SAV range 按返回地址过滤读 out+0x10/+0x28、映射采样 dump + edx + fallback 级、mapfind 按返回地址过滤、裸计数 + 心跳、sav_conv distinct 节流——确认 .toInt32() 修复后首会话即采到 mapping_in 与 ebx_out（此前为 0 的读数复活与否，是探针可信度的第一检验）。
11. **throw 对照会话**（evening16 #8 遗留）：去掉 throw/throw_ctx 钩子跑一次，确认 0x13fff544a 是否消失。

判读顺序：#1/#2/#3 定 stall 在哪一段 → #5/#6 定是否递归/哪一组件 → #4 定 D 向量状态 → #10 定同会话五环状态 → #8 定 throw artifact。五者闭合后判定网关侧是否存在控制面。

### 17.7 网关修正写法：推不出——缺失环节与未证实假说

不给出字段改法。缺失环节：stall 精确步骤（v20 #1–#7）+ 同会话五环状态（v20 #10）。**时序假说（未证实，不得先行实施）**：网关在 0x9a 后 4 ms 即发 0x2f7；若区域生成的完成（描述符/索引表的填充）在另一线程异步进行，玩家构造可能撞上未就绪状态——形态差异（05:48 走完、07:34 早夭）与竞态的时序敏感性相符，但**无任何已采证据**表明 0x9a 处理是异步的（分发器 0x1421343c0 顺序处理消息是反证方向）。可试方向（仅在 v20 定位 stall 于 3d/3e 且与数据就绪相关后）：延迟 0x2f7 至客户端发出区域就绪信号之后（须先静态确认该信号的消息 id），或固定延迟对照。盲目延迟不解决数据缺口，只掩盖竞态——须先有 v20 证据。

### 17.8 缺口 closure 状态（截至 evening17）

- 缺口 1（ebx 终值）：05:48 已闭合 ebx=0；ebx 输入值（0x153 vs 换算值）未闭合，v19b/v20 #10。
- 缺口 2（P 身份）：未闭合，v20 #10（rowapp 修正读法）。
- 缺口 3（与网关字段的因果）：未闭合，v20 闭合后判定。
- 缺口 4（形态 B stall 点）：收窄至 [handler, fn C)，精确步骤未闭合，v20 #1–#7。
- 缺口 5（新增，探针 bug 致死性）：v19b 部署后首会话判别。
- 0x13fff544a：stale 槽值说维持（06:48/07:34 两次试读均不可读）；最终检验 v20 #11。

## 2026-11-05 evening18 — 0x2f7 dropped before dispatch（07:49 会话，静态判定）

证据来源：07:49 会话探针 v20 普查（parent 提供，见 trace-0749-v20.txt：entity_ctor / type_lookup /
createobj_handler 三者 07:49 全为 0；工厂 0x1415d7710 全程 54,459 次、末次 07:49:13；Client.txt 同秒
MeleePlayer WARN；进程静默死亡，无 exception/throw 事件）；本节静态验证全部在本机 PathOfExile.exe 上
新鲜复核（disasm_region.py / 字节扫描 / 快速 call 扫描），未改服务器代码。结论分级标注。

### §18.1 分发门模型：[world+0x84a] 是瞬态"排空中"标志，不是持久"世界已开"状态

**已实证——分发器入口门控。** 世界分发器 0x1421343c0 入口（rcx=world，rdx=消息对象）：

```
0x1421343f0: cmp byte ptr [rcx+0x84a], 0
0x1421343f7: je  0x142136346          ; 门关 → 直接跳 epilogue 返回
```

0x142136346 为 epilogue：先恢复 [rcx+0x120] 处的重入守卫字节（[rbp+0x29] 保存值），再
pop/ret。**门关时分发器不触碰消息**：不读消息 id、不调 handler、不消费、不释放、不记录。
调用方保留消息所有权。门控是"不执行"，不是"丢弃"。

**已实证——写点恰 4 处，无他处。** 全 .text 位移 0x84a 字节扫描 20 命中，逐一反汇编分类：
其余 14 个为假阳性（立即数 0x84a=2122，如 `mov edx,0x84a`；栈槽 `[rsp+0x84a]`；`[rbp+0x84a]`
局部）。真 [reg+0x84a] 访问恰 6 处：4 写 + 2 读，全部定位如下——

| 地址 | 方向 | 所在函数 | 语义 |
|---|---|---|---|
| 0x14212fdd9 | 写 1 | 激活 0x14212fd90 | 排空循环开始前置门 |
| 0x14212fe5e | 写 0 | 激活 0x14212fd90 | 释放循环后清门 |
| 0x142130862 | 写 1 | 世界更新 0x142130840 | 入口**无条件**置门 |
| 0x142130d63 | 写 0 | 世界更新 0x142130840 | 尾部清门 |
| 0x1421343f0 | 读 | 分发器 0x1421343c0 | 门关则 no-op（上） |
| 0x142130360 | 读 | 排空 0x142130360 | 门关则返回（下） |

**推论（已实证机制 + 直接推论）：门在 0x2f7 抵达时为 0 是正常态。** 门仅在激活或世界更
新正在排空的瞬时为 1，其余时间恒为 0。没有任何消息 handler、队列 push、工厂或提交路径置
门。**"门未开"本身不能解释 07:49 的未分发**；正确问题是：消息入队之后，是否有一次排空
（激活或世界更新）运行过。队列机制内不存在"门关丢弃"路径：未排空的消息留在队列里（见
§18.2 队头阻塞规则）。"dropped"一词对队列机制是错的——07:49 的 0x2f7 要么从未入队，要么
入队后从未排空，两者须由 v21 区分（§18.4 #1/#2/#4）。

**已实证——+0x86a 闩锁是死写。** 激活 0x14212fe65 写 [world+0x86a]=1；全 .text 位移 0x86a
扫描 12 命中，**无一处为真 [reg+0x86a] 读**（其余为立即数/栈槽）。激活不受它门控，可重复
运行；它不是"世界已激活"持久标志。勿以它作为门状态探针。

**已实证——排空 0x142130360 的三重 stamp 门（队头阻塞）。** 门开后，取队头消息，须同时满足：
msg u32 @+0x14 == [world+0x678]、u8 @+0x18 ≤ [world+0x67c]、u16 @+0x1a ≤ [world+0x67e]；
首个不匹配即返回，游标 [world+0x6c8] 不推进——**队头不匹配则整个队列停滞**，后续消息（含
0x2f7）全部被堵。仅两调用方，均在 0x142137270 内；0x142137270 仅一调用方（更新内
0x142130ada）。注：0x2f7 工厂 case（见下）把 stamp 三件套初始化为 0（[obj+0x10]=0、byte
+0x18=0、word +0x1a=0），与 fork 写侧的 stamp=0 一致；stamp 填 0 正确（evening2 结论维持）。

**已实证——激活 0x14212fd90 的排空不查 stamp。** 置门=1 → 无条件排空队列全部消息
（[world+0x6b0..0x6b8] 向量，逐条调分发器，不查 stamp）→ 逐条释放 → 清门=0 → 置 +0x86a=1 →
遍历 [world+0x5b8] 实体向量收尾。激活仅一直接调用方：回调内 0x1416820ac（回调首指令即
调激活，0x1416820ac 处 `call 0x14212fd90`，无前置条件）。

**已实证——世界更新 0x142130840。** 入口无条件置门=1；[world+0x661]==0 走全量 flush 支
（逐条分发器后释放），≠0 走 stamp 支（经 0x142137270）；尾部清门=0。零直接调用方，仅 2
处尾跳：0x14169c749（tick 适配 thunk）与 0x14212ecd3（WORLD vtable +0x448 thunk，
0x14212ecd0）。世界更新的 tick 驱动见 §18.3 末。

**纠正 evening2 §5（+0x178 槽归属）。** MAIN vtable 0x14339d1d0 新鲜读值：+0x60=0x140b27a70、
**+0x178=0x140b27ac0**（仅 `mov [rcx+0x11c],edx; ret`——把 0x23 的值存入 [agg+0x11c]，
与 evening4 §4 的 [agg+0x11c] 消费者一致；evening2 记的"转发至 [world+0x5b0] 子管理器
0x14167e020"作废）、+0x1b8=0x140b27b70、+0x1e0=提交 0x14167b3f0、**+0x1f0=回调
0x1416820a0**、+0x200=0x14168ac70、+0x278=0x141686d70、+0x448=0x14169bf80（小结构体拷贝，
非 tick thunk）。WORLD vtable 0x1435083e8：+0x60=世界工厂 0x142186c20、+0x178=空桩
0x14010a080、+0x1b8=0x142133a30、+0x1e0=0x14212f9f0、+0x1f0=0x142136960、+0x200=0x140b27ac0、
**+0x278=激活 0x14212fd90**、+0x448=thunk 0x14212ecd0。facet vtable 0x1430e2598 与
0x14339d148 的 +0x278 均为 0x1416820a0（确认）。evening4 的 +0x1f0=激活回调结论维持；
0x23 经 +0x1f0 确可触发激活（见 §18.2）。

### §18.2 0x23 与门的关系、07:49 未分发的决定因素、竞态判定

**已实证——0x23 handler 0x14212306d 依次调聚合体 vtable 四槽**（rcx=[session+0x20f0]，
[rcx] 须为 MAIN vtable 0x14339d1d0 才命中回调；evening4 已验 [session+0x20f0] 载 MAIN）：

```
+0x178  0x140b27ac0   存值 → [agg+0x11c]（edx=[msg+0x1f8]，即 0x23 的值 1000）
+0x200  0x14168ac70
+0x60   0x140b27a70
+0x1f0  0x1416820a0   激活回调 → 首指令 call 激活 0x14212fd90（无条件）
```

再转发三组监听向量。handler 同时置 [session+0x2270]=3。**0x23 是同步的排空触发器**：
0x23 走实例分发（不入世界队列），其 handler 同步调激活，激活置门并排空整个世界队列。
S2 机制的精确表述：0x2f7 入世界队列 → 0x23 被实例分发 → 激活排空队列 → 0x2f7 被分发。
该链成立须四条件同时满足：(i) 0x2f7 已入队（在 0x23 handler 运行之前）；(ii) [session+0x20f0]
所指聚合体载 MAIN vtable（+0x1f0 命中回调）；(iii) 回调执行（首指令即激活，无前置条件，
故 (ii) 成立则 (iii) 自动成立）；(iv) 激活的排空循环遍历到 0x2f7（队列向量包含它；激活
排空不查 stamp，故 stamp 不是障碍）。

**已实证——世界工厂有 0x2f7 case（排除"工厂无此 id"说）。** 工厂 0x142186c20（WORLD
vtable +0x60 槽，零直接调用方）内 0x1421881eb：alloc 0x40、[obj+8]=0x2f7、vtable
0x1435C4F0、stamp 三件套清零、经共享 epilogue 0x142186fde 返回对象。工厂按 id 分发建消息
对象（0x2ef/0x2f7/0x2f8 相邻 case），对象经 [rdx] 出参交调用方。队列 push 的确切指令未定
位（位移 0x6b8/0x6b0/0x6c8 扫描各有 1494/960/763 命中，0x14212–0x14214 区内为零；push 不在
排空代码附近）——**push 点未定位不影响本节结论**，v21 以工厂入口 + 分发器入口直接观测
"已建/已分发"，无需 push 地址。

**纠正任务前提——0x9a 在客户端没有 handler。** 0x9a 是 C→S 消息（客户端生成、发往网关），
客户端不存在 0x9a handler。客户端在区域生成完成时生成 0x9a；"0x9a handler 的处理序列"
应理解为：客户端区域生成完成侧的内部序列（区域组装 → 提交 → 0x9a 生成），其时序与内容未
完全静态定性。提交链已实证至此：提交 0x14167b3f0 仅一直接调用方——默认参数包装器
0x140b99180；ensure 0x141681720 仅一调用方（提交内 0x14167b8ce）；包装器仅两直接调用方
0x140b6d3f8 与 0x140b71503，所在两函数均分配 0x1fb8 字节对象、调 ctor 0x140b97c20、再调
包装器（commit）；构建函数 0x140b6d390 仅一 jmp 调用方 0x140bf1ee4。**提交驱动者的上游
身份尚未定（待续查）**——不得 claim 区域生成完成必然调提交；S1→S2 的 f1270 差异与提交时
序的关系仍为强推断（见 §18.2 末）。v21 #9 观测提交时序。

**决定因素判定（已实证 + 推断分级）。**

已实证（网关日志只读核查，本节）：全部五个会话（02:11 / 05:48 / 06:48 / 07:34 / 07:49）
的线序完全相同——0x9a 入后 3–15 ms 内网关回 0x2f7 + 0x23（07:49 为 3 ms，05:48 为 4 ms，
06:48 为 15 ms）；每会话实例内仅 4 个包（0x1e、0x9a、0x2f7、0x23），**0x9a 之后客户端再
无任何信号**（无 0x1c tick、无其他 C→S）。**相同线序、相同毫秒级时序，却有分发/未分发
两种结局——决定因素不在网关时序，而在客户端内部状态。** "0x9a→0x2f7 仅 4ms 撞异步区域
生成"的纯时序假说被证伪为唯一解释（05:48 同为 4ms 且走完全程；07:49 同为 3ms 却未抵
达分发）。时序仍可为促成因素，但不是决定因素。

推断（中）：07:49 的失败发生在 0x2f7 的"建对象→入队→排空"链上游，早于一切映射/SAV/
索引使用（形态 B 的前移，evening17 结论维持并前移一级）。三种互斥子情形，v21 之前无法
区分，列为待验假设：

- (A) 从未建对象/入队：pump 在 0x2f7 处停滞或丢弃（pump 线程模型未静态定性；工厂
  case 存在已排除 id 缺失）。v21 #1 判别（工厂入口 id 日志）。
- (B) 已入队、0x23 handler 未运行或未触发激活：实例分发未调 0x23 handler，或 [agg] 非
  MAIN vtable 致 +0x1f0 未命中回调，或激活未运行。v21 #3/#4 判别（0x23 入口读
  [session+0x20f0] 与 [agg] vtable；激活入口计数）。
- (C) 已入队、激活已运行但排空时队列快照不含 0x2f7：入队发生在激活排空之后（pump 与
  排空的线程/时序交错，线程模型未证实）。v21 #2/#4 判别（分发器入口队列指针快照 vs
  激活入口队列快照）。

**竞态说的精确地位（待验假设，不得据此改网关）。** 客户端内部存在两条时序线：① 区域组装/
提交线（客户端自身，时序未观测）；② 网关响应线（0x9a 后 3–15ms，固定）。S1 崩溃（回调时
[agg+0x1270]=0）与 S2 成功（f1270 非空）的差异，与"提交在回调前/后完成"的竞态说一致，
但 S1/S2 同时差了 0x2f7 有无，**不能单由此定提交时序为决定因素**。07:49 的新形态（连
分发都未抵达）说明竞态窗口比"提交时序"更宽：还包括入队与排空的相对时序。须 v21 观测
提交/工厂/激活三者的相对时刻后才能定哪条线是决定因素。

**网关确定性保证：静态证据为否定。** 0x9a 之后线上一无所有——网关没有任何可等待的客
户端信号。盲目延迟（等 N ms 再发 0x2f7）无静态依据，且同为毫秒级的不同结局已证伪纯时
序决定论。0x23 先发会更糟：激活排空空队列后 0x2f7 只能等下一次世界更新 tick，而 tick
是否到来、是否含世界条目均未证实（§18.3 末）——**禁止重排 burst（0x23 在 0x2f7 之前）**。
网关写法判定见 §18.5。

### §18.3 无分发时的 WARN 与工厂 churn：并发路径枚举

**已实证——工厂 0x1415d7710 是通用定义驱动工厂取用工具，146 个直接调用点。**
快速字节扫描（call rel32 + jmp rel32，.text 全域）：146 处（145 call + 1 jmp），遍布
0x1414–0x1428 区。采样反汇编的调用形态一致：先经 0x1401600c0 查 map/表、取 [entry+8]
索引（edx，-1 则跳过）、`call 0x1415d7710(D, index)`、用 [rax+0xe8]/[rax+0x50]。索引值
0x1/0x4/0x6/0x7/0xc 均为组件索引。**仅 3 处在实体 ctor 路径**：0x142601338/0x142601436
（0x142601300 内，3d 组件工厂环）与 0x141e70858（0x141e70790 复用环）。其余 143 处分属
各定义驱动构造系统（技能/效果/组件/UI 均可能；0x1428xxxx 区块约 90 处为一大定义驱动构
建系统，子系统归属未全部分类）。**07:49 的 54,459 次工厂调用为背景流量，不能证明存在并
发的玩家构造路径**——工厂调用数与玩家实体构造无关（evening17 的"工厂 churn"疑点解除为
背景流量，推断，强）。

**已实证——第二 ctor 0x141e709c0 不是并发路径。** 仅一直接调用方 0x1421356ae（0x2f8
handler 内）；07:49 未发 0x2f8（网关日志仅 4 包）。排除。0x14140e5f0（第二查表入口）的
调用方 0x1414228c2/0x141422941 与 0x14156bf2f 均分配 0x238 字节对象后调它，所属子系统
未分类；该路径调查表函数 0x14140e280 而**不调行应用 0x14140ea70**，故不发 WARN——与
07:49 的 WARN 无关。

**已实证——WARN 发出者唯一，无运行时拼接的第二发出者。** 格式串 `Could not find row for
MeleeAttackActionClient skill ` 在 exe 内 UTF-16LE 仅一处（0x1431c9600）；lea xref 仅一处
（0x14140eb3d，行应用 0x14140ea70 内）；.rdata 指针槽 0 个；`MeleeAttackActionClient`
（0x1431c962e）与 ` skill `（0x1431c965c）的命中均为同一格式串内的子串。**不存在第二
发出者（推断，强→已实证排除拼接说）。** 07:49 的 WARN 必经 0x14140ea70。

**行应用 0x14140ea70 的调用点：19 处已实证（18 call + 1 jmp，与 evening16 一致）**，含 3
个动作客户端构造包装器内址 0x141471cd8/d28/d68（包装器函数 0x141471cc0/d10/d50 本身零
直接调用点——经虚表/tail-jump 到达，静态枚举到此为止）与其余 16 处（含 0x14157xxxx 簇 8
处）。**WARN 的技能名来自技能对象自身的 GE 解析，与 0x2f7 blob 无关**——任何构造了
MeleePlayer 技能对象的路径（区域实体技能搭建、玩家技能预览/技能栏/UI 组装、或独立技能对
象构建）都可发出它。候选家族（推断，未证实）：区域生成期客户端本地搭建的区域实体技能
（07:49 :55 有 227 次 world_register，区域实体确在本地构造；怪物是否用默认攻击 GE 未
证实）、或与 0x2f7 无关的本地玩家技能对象搭建。**纠正 evening16/17：WARN 存在不再是
"玩家序列曾运行"的证据**——07:49 证明 WARN 可在零玩家分发时发出；06:48 的"探针消息丢
失"说进一步弱化为未定（07:34 裸计数为 0 已提示路径未达）。

**已实证——InstMgr tick 0x14218bf90 的 +0x448 调用是条件性的。** tick 迭代
[r13+0x270..0x278] 注册向量（8 字节步进，refcount 对象：lock xadd +0xc、vtable slot 0
释放、slot +8 销毁），对每条目经 [r15+0x148..0x150] 16 字节条目二分查找（比较
[entry+0xf8]+0x40）后，按 sil 标志走两分支，分别在 0x14218c218 / 0x14218c26d 调
[rax+0x448]（rdx=&{xmm 对} dt 结构）。**tick 是否调到世界条目取决于二分查找结果（时序/
优先级门），静态未定世界条目是否在注册向量内、以及门条件**——世界更新能否作为 0x2f7 的
后备排空路径，未证实。v21 #5/#6 观测。

**分发器/工厂虚表归属（已实证，补 evening18 调查）。** 实例分发器 0x1421220f0 零直接
调用方，位于 vtable（基址疑 0x1435078d8，槽 +0x18；同表 +0x10=实例工厂 0x142170500、
+0x08=0x1421c5a50）。该 vtable 由会话构造代码 0x14211e3fc 处 lea 安装至 [session+0x2110]
子对象；[session+0x20f0]=聚合体（rdx 传入）、[session+0x2270]=状态机。世界工厂
0x142186c20 零直接调用方，仅 WORLD vtable +0x60 槽。

### §18.4 v21 钩子清单（只读、防洪水、禁用 .toNumber()）

原则：全部钩子 safeAttach 包裹、坏地址报 hook_fail 不 abort；寄存器读数一律 `.toInt32()`；
高频钩子采样/节流；runner 日志常开句柄（02:11 教训）；新钩子只加本节清单，不得常开
p350_write 类洪水钩子。保留 v20 ctor 链 9 钩子 + v19b 五环（mapping_in/ebx_out 健康已
验）。读序：#3→#4→#2→#1（分发链）→ #5/#6（tick）→ #7/#8（WARN/工厂）→ #9（提交时序）。

1. **世界工厂入口 0x142186c20**：onEnter 记 r8w（toInt32）id 与每 id 计数。判别 A：0x2f7
   对象是否被建。低频（每世界消息一次），可全记。
2. **分发器入口 0x1421343c0**：onEnter 记 [rcx+0x84a] 门字节、[rdx+8] u16 id、队列指针
   [rcx+0x6b0]/[rcx+0x6b8]/[rcx+0x6c8]、returnAddress。判别 B/C：每次分发尝试的门状态与
   队列深度。中频（每次排空逐条），可全记（排空次数有限）。
3. **0x23 handler 入口 0x14212306d**：onEnter 记 [r15+0x20f0] 聚合体指针（会话指针寄存器
   以实测为准）、[agg] vtable qword、[msg+0x1f8] 值。判别 B：0x23 是否运行、+0x1f0 槽
   解析对象。低频。
4. **激活入口/出口 0x14212fd90**：onEnter 记队列 [rcx+0x6b0]/[rcx+0x6b8] 与门字节；
   onLeave 记门字节。判别 B/C：激活是否运行、排空时队列是否含 0x2f7。低频。
5. **世界更新入口 0x142130840 + 排空入口 0x142130360**：仅计数 + 排空入口记门字节与队
   头 stamp 三件套（[msg+0x14]/[msg+0x18]/[msg+0x1a]）。判别 tick 后备路径是否运行。
   更新入口高频（每帧）——只计数，不记详情。
6. **InstMgr tick 内 +0x448 调用点 0x14218c218 / 0x14218c26d**：仅当被调对象 vtable 为
   MAIN 0x14339d1d0 或 WORLD 0x1435083e8 时记（JS 内指针比较），余者只计数。判别世界
   条目是否被 tick。采样比较，防洪水。
7. **行应用入口 0x14140ea70**：记 this.returnAddress + 每返回地址计数（JS 对象累积，进程
   退出/会话末 flush）。判别 19 个调用点中何者发出 WARN。低频（仅 miss 时到），可全记。
8. **工厂 0x1415d7710 返回地址采样**：onEnter 1/1000 采样记 returnAddress；另维护每返回
   地址计数对象，每 1000 次 flush 一次计数快照。判别调用者总体构成，不洪水。
9. **提交入口 0x14167b3f0 + 包装器入口 0x140b99180**：记相对时刻（与 #1/#3/#4 同一时钟）。
   判别提交 vs 0x9a/0x23 的相对时序。低频。
10. **对照**：保留 v20 #11——去 throw 钩子的对照会话，检验 0x13fff544a stale 说（evening17
    遗留）。v21 部署后第一次会话仍带全部钩子；若 07:49 形态复现，#1–#4 即给出 A/B/C
    分野；若形态变化，以当轮钩子读数为准，不得沿用旧形态结论。

### §18.5 网关写法判定：推不出，缺三环

**结论：现有证据推不出任何网关修正写法。不得改 burst 顺序、不得加盲目延迟、不得重发
0x23。** 缺的三环（均为运行时观测，v21 闭合）：

1. **入队环**：0x2f7 是否被世界工厂建对象并入队（v21 #1）。若从未入队，问题在 pump/
   工厂侧，网关无写法可修。
2. **触发环**：0x23 handler 是否运行、[agg] vtable 是否解析至回调、激活是否运行（v21
   #3/#4）。若 0x23 未触发激活，问题在实例分发/聚合体身份，网关无写法可修。
3. **快照环**：激活排空时的队列快照是否含 0x2f7（v21 #2/#4）。若激活跑在入队之前，须
   先定线程/时序模型（静态未证实 pump 线程模型），再论网关侧有无可等待的确定性信号——
   目前线上的信号集合为空（§18.2），故**即使快照环证实为竞态，网关侧仍无确定性写法**，
   只能报告"须客户端侧时序信号"或接受重试语义（重发 0x2f7 的语义未证实：重复 CreateObject
   是否幂等未知，不得猜）。

条件分支（v21 之后）：(a) #1 证实未建对象 → 查 pump（客户端侧）；(b) #3/#4 证实 0x23
未触发激活 → 查实例分发与聚合体 vtable 解析；(c) #2/#4 证实激活快照漏 0x2f7 → 查入队与
排空的线程时序，并评估重发 0x2f7 的幂等性（须静态/实证确认重复 0x2f7 的客户端行为后
才可提议）。三种分支均无网关先行改动。

### 缺口 closure 状态（evening18 更新）

- 缺口 1（ebx 终值）：05:48 已闭合 ebx=0；ebx 输入值未闭合（v19b 修复后 mapping_in 已
  复活，待 v21 五环复核）。
- 缺口 2（P 身份）：未闭合。
- 缺口 3（与网关字段的因果）：未闭合；evening18 证明网关时序不是决定因素，决定因素在
  客户端状态。
- 缺口 4（形态 B stall 点）：前移至**分发之前**——0x2f7 未抵达 handler（07:49 实证）；
  精确子情形 A/B/C 未闭合，v21 #1–#4。
- 缺口 5（探针 bug 致死性）：v19b 后 07:49 映射钩子健康（264/264 配对），bug 干扰已排除
  为当轮主因；07:49 形态变化与探针修复的因果未定。
- 缺口 6（新增，07:49 丢弃决定因素）：未闭合，v21 #1–#4 + #9。
- WARN 证据地位：降级——WARN 不再证明玩家序列运行（§18.3）。
- 0x13fff544a：stale 槽值说维持；最终检验 v20 #11 → v21 #10。

## 2026-11-05 evening19 — world never created（08:17 会话，静态判定）

证据来源：08:17 会话探针 v21 普查（parent 提供，见 trace-0817-v21.txt：wfactory /
dispatcher / h23 / act / drain / tick448 / wupdate / createobj / entity_ctor /
type_lookup / fnC 全为 0；commit 仅 1 次、08:17:12、0x9a 前 24 秒，commitwrap 为 0；
全部 v21 钩子均挂上、仅一已知 hook_fail，零计数真实）；本节静态验证全部在本机
PathOfExile.exe 上新鲜复核（disasm_region.py / find_fn.py / scan_calls.py / .rdata
直接读值 / 字节模式扫描），未改服务器代码。结论分级标注。基址回收（已实证）：
hook_fail 行 VA 0x14140E3CF → 运行时 0x7FF608C8E3CF，镜像基址 0x7ff607880000。

### §19.1 工厂热点调用者定性（已实证，反汇编）

热点返回地址（08:17 会话 fact_ra 采样，45,000+ 次工厂调用）：0x14289cebc 5,896 次、
0x142628260 5,828 次、0x14260133d 5,564 次、0x14289e41c 345 次、0x14260143b 413 次。
各热点均为"定义驱动工厂取用"形态（map/表查 → 取索引 → `call 0x1415d7710(D, index)`），
但分属不同构造系统：

| 热点 | 所在函数 | 形态 | 在构造什么 |
|---|---|---|---|
| 0x14289cebc | 0x14289cbf0 | 逐条目：名长==10 且等于 `bone_group`（串 0x1435a9638，经 0x142cb80a0 比对）才调工厂，edx=[rsi+0x10]、rcx=[rsi+8] | 动画/骨架定义中的 bone_group 对象（推断，强：串证据直接）。零直接调用方 → 经虚表/tail-jump 到达 |
| 0x142628260 | 0x142627df0 | 迭代（16 字节步进）+ 自递归（0x142628025）：条目标签 dword==0x26 且 12 字节二进制键匹配才调工厂，rcx=r12、edx=[rbx+8]（-1 跳过） | 某定义集合的带标签条目（子系统未分类；键为二进制非串，见下）。直接调用方 2 处：外部 0x142627792 + 自递归 |
| 0x14260133d | 0x142601300 | 向量物化循环（见 §19.1a） | 见 §19.1a |
| 0x14289e41c | 0x14289e060 | map 查表（0x1401600c0）后循环 [rsi+0x20..0x28] 向量，逐条目调工厂 | 定义集合批量构建（子系统未分类）。零直接调用方 → 虚表到达 |
| 0x14260143b | 0x1426013e0 | 逆序重建循环（见 §19.1b） | 见 §19.1b |

三热点各 ~5.5–5.9k 次、量级相近：均为数据加载期对数千条定义条目的批量构建（bulk
build），不是玩家实体构造。07:49 的 54,459 次与 08:17 的 45,000+ 次同属此类背景流量
（evening18 §18.3 结论维持并细化）。

**§19.1a 物化器 0x142601300：内部循环已实证。** 0x14260130a：count=([rcx+0x18]−
[rcx+0x10])/8；0x142601320 循环头：[rbx+8] 非空则 `call 0x1421d7070`（释放），
0x142601338 `call 0x1415d7710`（返回地址即热点 0x14260133d），继而虚调用 slot +8
（组件构造）、结果存回向量；0x142601358 每轮重读向量界、比较后回跳。**每次进入循环
数千次工厂调用是结构使然。** 0x142601300 直接调用方 28 处（全 call、无 jmp），含实体
ctor 内 3d 调用点 0x141e708d9 与遍布 0x1401–0x1421 区的各构造系统调用点——它是通用
向量物化器，不专属实体 ctor。会话中 c300 入口仅 3 次却产 5,564 次迭代的唯一自洽读法
（推断，强）：3 次进入均作用于大型/增长中描述符向量（批量构建），而非 10 组件实体向量；
循环每轮重读向量界，向量在构造中增长亦可延长循环。不得以"入口少"反推工厂调用少。

**§19.1b 0x14260143b 不在 0x142601300 内——纠正任务前提。** 0x142601300 在
0x142601373 `ret` 后接 0x142601374–0x14260137f 的 int3 填充，0x142601380 为另一函数，
0x1426013e0 为再一新函数（标准 prologue）。0x1426013e0 为**逆序**重建循环：rsi 自
(count−1) 递减，逐条目（[entry+8]==rbx 才处理）释放 → 工厂调用（返回地址即热点
0x14260143b）→ 虚调用 slot +0x10（刷新回调，evening13 的 +0x10 刷新族）→ 槽位清零。
它是 0x142601300 的逆序刷新孪生函数，非其内部。

hot2 的 12 字节键：0x142627e9d 处 `lea r9,[rip+0xd83e7c]` 目标 0x1434a6520 内容为二
进制（`30d49741…`），非可读串——该 walker 以 (标签 0x26 + 12 字节二进制键) 匹配条目，
键语义未定（推断：定义引用三元组一类，不可指认具体表）。

### §19.2 commit 调用者纠正（已实证）

**直接调用 claim 维持，live 路径纠正。** scan_calls 全 .text：commit 0x14167b3f0 的
直接 call 仅一处——0x140b991d1（包装器 0x140b99180 内）。evening18"仅一直接调用方"
作为直接调用统计是正确的；但 08:17 的 commit 并非经此到达。

**已实证——08:17 的 commit 经虚表 slot +0x1e0 到达。** 返回地址 0x140edf56c 的前一
指令：0x140edf566 `call qword ptr [rax+0x1e0]`，rax=[r15]（r15=r14+0x20，聚合体子对
象），即 MAIN vtable +0x1e0 槽调用。MAIN vtable +0x1e0 = commit 已由 .rdata 新鲜读值
确认（evening18 §18.1）。字节模式扫描（`FF 9x E0 01 00 00`）：全 .text 共 **389 处**
`call [reg+0x1e0]` 候选点——虚表 commit 调用无处不在，包装器只是其中一条（且是默认参数
包装）路径。**"commit 仅一调用方"的印象作废**；同理 +0x1f0（激活回调）候选点 192 处。
（模式扫描不区分 vtable 归属，计数为上限；机制结论不受影响。）

**调用函数 0x140edf340 定性（已实证结构，子系统推断）。** 该函数：取 [rcx] 对象（r14），
两次经 0x140ed8a80 取向量并算 (end−begin)/24（magic 0x6666…67，24 字节条目）；下标钳
制后索引 40 字节条目表（`lea rsi,[rax+rcx*8]`，rcx=rdi*5）；串处理（长度循环）；
调构建器 0x14212f490；随后 `mov rax,[r15]` → `call [rax+0x1e0]`（commit）。直接引用
2 处：call 0x140ed9c9d（函数 0x140ed9640 内）与 jmp 0x140f1be34。**函数 0x140ed9640
同时是聚合体 ctor 的调用方之一**（0x140ed96a9 处 `call 0x14167d470`）——同一组装函数
先建聚合体、后经 0x140edf340 提交它。0x140ed9640 另有调用方 0x14011c1e5 与
0x140effafb（所属相位未分类）。08:17:12 的 commit：登录期聚合体组装/提交（ensure/
commit 模式，[agg+0x1270] 惰性分配，evening6），与区域世界无关的证据：发火时刻为
0x9a 前 24 秒、commitwrap（包装器路径）全程为 0、其后无任何世界活动跟进。分级：组装
路径已实证，登录期定性为强推断。

### §19.3 世界创建触发链与 WORLD 槽真值（已实证）

**WORLD vtable +0x60 槽真值：0x142186c20（.rdata 直接读值确认）。** wfactory=0 不是
钩子挂错地址——槽内确为该工厂，08:17 会话中它从未被经虚表调用。

**WORLD vtable 安装点唯一。** 全 .text RIP-relative lea 扫描：指向 0x1435083e8 的引用
恰 1 处——0x14212f2d6（`lea rax,WORLD_VT; mov [rsi+0x6e0],rax`），位于函数
0x14212ece0（世界对象 ctor/init：清零 [rsi+0x7b0..0x870] 诸域、[rsi+0x848]=0x100、
经 IAT 式间接调用建 +0x7e0 子对象）。**vtable 位于对象 +0x6e0——多 facet 对象的一个
facet 子对象**（与 evening2/3 的 facet/MAIN 双 vtable 教训一致；分发器所见 rcx 为该
facet 指针，+0x84a 等偏移以 facet 为基）。

**世界 ctor 的唯一直接调用方：聚合体 ctor。** scan_calls：0x14212ece0 仅一 call——
0x14167d49b，即聚合体 ctor 0x14167d470 的**首条指令**（无条件，先于一切 facet 安装）。
聚合体 ctor 继而安装 MAIN（[rdi+0x0]，lea 0x14167d4cf 目标 0x14339d1d0）与诸 facet
vtable（+0x250/+0x258/+0x260/+0x880/+0x890…）。聚合体 ctor 直接调用方 3 处：
0x140b97c5a（0x1fb8 字节对象 ctor 族，evening18 的包装器提交路径侧）、0x140ed96a9
（组装函数 0x140ed9640，08:17 commit 路径侧）、0x14100b979。

**推论（已实证链 + 直接推论）："世界从未被创建"一说不成立，应改为"世界从未被驱动"。**
08:17 的 commit 经 MAIN facet vtable 触发，证明载 MAIN vtable 的聚合体对象存在且已提交；
聚合体 ctor 无条件先调世界 ctor，故**世界对象随聚合体一同已被构造**。缺失的不是对象，
而是对象的一切活动：无世界消息对象被建（工厂 0）、无分发（dispatcher 0）、无激活、
无世界更新 tick、无 0x23 处理。缺口在世界机器的上游——实例消息向世界队列的投递/驱动
链，而非世界对象本身。

**0x1e case（0x14212269f，位于实例分发器 0x1421220f0 内的 case）不建世界（已实证
其体）。** u16 [msg+0x1c] 经 0x1423e3f10 查 WorldAreas；查无 → 跳 0x14212580e（失败
分支）；查有 → 写会话/聚合体状态（[r15+0x2180]、聚合体 +0xb8 字段、[msg+0x2d] 各比特
经 0x14013b6b0 写入聚合体 +0xbf/+0xc0/+0xc1/+0xc3/+0xc7、聚合体 +0x200 虚调用）、TLS
注册表取用 0x14218eaf0（ecx=0x2caa235a 哈希键，TLS 惰性单例取用器，取用对象未定）。
case 体内**无世界 ctor 调用、无工厂调用、无入队指令**——0x1e 只记录区域状态。世界驱动
的触发点（区域生成完成 → 提交/ensure → pump 投递）仍未定位：提交链的上游身份未定
（evening18 遗留），InstMgr tick 能否驱动世界条目未定（§18.3 末）。两者均为运行时未
观测环节，不得 claim 0x1e 必然引发世界驱动。

### §19.4 A/B/C 最终分野（08:17 会话）

08:17 不属于 evening18 的 (A)/(B)/(C) 原 framing——三者均预设"建对象→入队→排空"
链已进入世界机器，而 v21 零计数证明失败点在世界机器**上游**。改判为 **(A′) 实例消息
从未抵达世界队列**，分子情形（互斥，v22 前无法区分，待验假设）：

- (A′1) 会话 pump 根本未读/未分发 0x1e/0x2f7/0x23（0x9a 之后 pump 停滞；但 0x9a
  本身由客户端生成，证明 0x1e 之前 pump 曾工作——停滞点须在 0x1e 处理与 0x2f7 抵达
  之间，或 0x1e case 的后续链未走完）；
- (A′2) 实例分发器运行了 0x1e（区域状态已记、0x9a 已生成），但 0x2f7/0x23 的世界侧
  交接（工厂建对象/入队）从未执行（push 点未定位，交接函数未定）。

原 (B)（0x23 未触发激活）与 (C)（快照漏 0x2f7）对 08:17 无意义：0x23 handler 本身
为 0、工厂为 0——排空阶段根本未开始。**07:49 与 08:17 是否同形未定**：07:49 有
createobj_handler 1 次（分发曾抵达），08:17 为 0（分发未抵达）——两会话死在链的不同
高度，不得合并为同一子情形；v22 须以当轮读数为准。

**网关侧缺口：无已证实缺口，不得改网关。** 0x11→0x1e 之间"缺某条消息致世界未建"说
无证据：真实服务器在 0x11→0x1e 之间的消息序列无捕获对照；我方 0x1e 已被接受（5/5 会
话均随后生成 0x9a，区域生成确曾运行）；0x9a 之后线上一无所有（无 0x1c tick、无其他
C→S）在 5/5 会话一致——沉默与 pump 停滞一致，但亦与客户端等待一致，不能据此推网关字
段缺失。决定因素在客户端内部状态（pump/分发/交接），网关无字段可修。禁令维持：不得
重排 burst、不得盲目延迟、不得重发 0x23。

### §19.5 v22 钩子清单（只读、防洪水、禁用 .toNumber()，safeAttach 包裹）

读序：#3→#4（对象存在性）→ #1→#2（消息是否抵达实例分发）→ #5（交接）→ 保留 v21
决定组（#6/#7）→ #8（工厂采样）。新钩子只加本节清单。

1. **实例分发器入口 0x1421220f0**：onEnter 记 args[0..2]、returnAddress、计数；判别
   pump 是否把任何实例消息送入分发。中频可全记（分发次数有限）。
2. **0x1e case 入口 0x14212269f**：onEnter 记 this.context.r13（消息寄存器）与
   [r13+0x1c] u16（guarded）、returnAddress。先由反汇编确认指令边界（本节已验：
   0x14212269f 处 `lea rcx,[rbp-0x58]` 为干净指令首）；safeAttach，hook_fail 则退回
   #1 + case 追踪。判别 0x1e 是否抵达 case 体。
3. **世界 ctor 入口 0x14212ece0**：onEnter/leave 记 args[0]（对象指针）、returnAddress。
   判别世界对象是否构造。低频。
4. **聚合体 ctor 入口 0x14167d470**：onEnter 记 args[0]、returnAddress。判别聚合体是
   否构造（与 #3 配对：世界 ctor 应紧随其后）。低频。
5. **实例工厂入口 0x142170500**：onEnter 记 id 参数（寄存器/args，以实测为准，首版记
   args[0..2] + returnAddress）与计数。判别 pump 是否为每条实例消息建流对象（交接上游）。
   中频可全记。
6. **保留 v21 决定组**：wfactory / dispatcher（门+队列）/ h23 / act / drain+wupdate
   计数 / tick +0x448 点。零读数本身即证据，须保留以确认形态是否复现。
7. **保留 v19b 五环**（mapping_in/ebx_out/sav_range/mapfind/rowapp）与 v20 ctor 链，
   以确认 08:17 的零是否为会话特异（形态漂移）而非探针回归。
8. **工厂返回地址采样**（v21 #8 保留）：1/1000 采样 + 每 1000 次 flush 计数快照；
   判别调用者总体是否漂移。
9. **对照**：保留去 throw 钩子的对照会话（v21 #10 遗留），检验 0x13fff544a stale 说。
   v22 部署后第一次会话仍带全部钩子；若 (A′1)/(A′2) 得分，查向写入 §19.6。

### 缺口 closure 状态（evening19 更新）

- 缺口 1（ebx 终值）：05:48 已闭合 ebx=0；ebx 输入值未闭合（v19b 修复后 mapping_in
  已复活，待 v22 五环复核）。
- 缺口 2（P 身份）：未闭合。
- 缺口 3（与网关字段的因果）：未闭合；evening19 证明决定因素在客户端 pump/分发/交接，
  网关无字段可修（静态证据）；0x11→0x1e 序列对照缺失（无真实服务器捕获）。
- 缺口 4（形态 B stall 点）：前移至**分发之前**——08:17 为 (A′)，07:49 为分发曾抵达的
  更下游形态；精确子情形 (A′1)/(A′2) 未闭合，v22 #1/#2/#5。
- 缺口 5（探针 bug 致死性）：已排除为主因（v19b 后映射钩子健康 264/264 配对；08:17
  形态与探针修复的因果未定，列为弱）。
- 缺口 6（07:49/08:17 丢弃决定因素）：07:49 为链下游形态（分发抵达、ctor 前 stall），
  08:17 为链上游形态（分发未抵达）；决定因素未闭合，v22 #1–#5。
- commit 调用链：已闭合（直接 1 处 + 虚表 389 候选点；08:17 经 0x140edf340 虚调用）。
- 世界对象存在性：已闭合为"随聚合体构造而存在"（静态链）；世界驱动缺失未闭合。
- WARN 证据地位：降级维持——WARN 不证明玩家序列运行（§18.3）。
- 0x13fff544a：stale 槽值说维持；最终检验 v21 #10 → v22 #9。

## 2026-11-05 evening20 — pump stalls after 0x1e（08:49 会话，静态判定）

证据来源：08:49 会话探针 v22 普查（parent 提供，见 trace-0849-v22.txt：0x1e 已分发
并建新区世界——第二聚合体/世界、工厂 id 17 与 30、第二提交驱动、约 230 区域实体登记；
此后 08:49:06–25 内 idispatch/case1e/ifactory/wfactory/dispatcher/h23/act/drain/tick448
全为 0；分发器/0x23 handler/激活/创建包/实体 ctor/fnC 全程为 0；镜像基址
0x7ff669990000）；本节静态验证全部在本机 PathOfExile.exe 上新鲜复核（disasm_region.py /
scan_calls.py / find_fn.py / .rdata 直接读值 / 位移模式扫描），未改服务器代码。结论分级标注。

### §20.1 pump 驱动链：已实证，全链地址

会话消息泵是三层虚表结构（handler-group 族），非单函数直调：

| 层 | 地址 | 签名/形态 | 证据 |
|---|---|---|---|
| tick | 0x142120cf0 | 会话 tick（rcx=session，r8=now 疑）；入口门 `byte [rcx+0x272a]`（见 §20.3）；内含 1 秒节律的 deadline 检查 + 传输重建 + 泵区段 | 直接调用方 2 处：0x141008afa（主循环帧更新函数 0x1410087e0 内）与 0x1421206ca（同簇会话函数内） |
| 泵区段 | 0x142121104（tick 内） | 门：`[session+0x20f8]!=0` 且 `dword [session+0x2270] > 1`（`cmp …,1; jbe 退出`）；每轮先调 fill，再 `call pump0` 循环至返回 0；随后 +0x251 检查 + 空闲向量迭代（edx=0 调各组 slot+8） | 反汇编已实证；三处调用方（登录/实例/第三连接）形态完全相同（0x1420e6f6a / 0x14212113a / 0x142730047） |
| fill | 0x142197bf0 | 填充/解密：仅当 `[stream+0x251]!=0` 才工作（否则立即返回）；ring-buffer 求模 + IAT recv + WSAEWOULDBLOCK（0x2733）处理 + 经 `[stream+0x1b8]`/`[stream+0x150]` slot+0x10 解密；成功清 +0x251；`edi==-1` 且 errno==0x2733 时 `mov word [stream+0x250],0`（连清 +0x250/+0x251） | 反汇编已实证 |
| pump0 | 0x1421c5b90 | 读包头：经 id reader 取 u16 id；查 `[stream+0x252]`（见 §20.2）；遍历 handler-group 向量 `[owner+0x18..0x20]`，逐组调 slot+8（pump1），有组返回 1 即停；无组认领 → 未处理路径（组错误串，含 id 索引 `[owner+8]` 向量）；善后：记 `[stream+0x1a0]=id`、调 `[stream+0x2b0]` 回调（若非空）、走 `[stream+0x1b8]` 门控的游标推进块、末 `[stream+0x268] += [stream+0x278]` | 反汇编已实证；直接调用方 3 处即上表三泵区段 |
| id reader | 0x142197e80 | 读 1 或 2 字节 id（pump0 按 `[owner+0]` 字节选 r8d=1/2）；先查 `[stream+0x252]`，再算可用量 `[0x270]−[0x278]`，不足则**置 `[stream+0x252]=1`** 并返回（不读） | 反汇编已实证 |
| pump1 | 0x1421c5a50 | 逐组分发一包（rcx=组对象，edx=id，r8=stream）：工厂 `call [vtable+0x10]`（r8d=id，rdx=&out）；建出对象且 `[stream+0x252]==0` 才调分发器 `call [[group+8]] slot 0`（r8=&msgptr）；随后经消息对象 vtable slot 0（edx=1）释放；返回 bl（建出对象=1，否则 0） | 反汇编已实证；零直接调用方（虚表 slot+0x08，见下） |
| 分发器 | 0x1421220f0 | 实例分发器（函数入口已验：前有 int3 填充，标准大帧 prologue）；r13=`[r8]`（消息对象指针）；空消息 → 状态机分支（见 §20.4）；非空 → u16 `[obj+8]` 查压缩 switch | 反汇编已实证；零直接调用方（经 `[group+8]` 对象 slot 0） |

**虚表族（.rdata 直接读值，已实证）**：四张 handler-group vtable 共享 slot+0x00=
0x1401072b0、slot+0x08=pump1 0x1421c5a50、slot+0x10=各组工厂——会话组 0x1435078d8
（+0x10=实例工厂 0x142170500，+0x18=分发器 0x1421220f0）、世界组 0x143508438
（+0x10=世界工厂 0x142186c20，+0x18=0x142137b30）、登录组 0x1435063f8（+0x10=登录工厂
0x14214fbe0）、第四组 0x14358d898（+0x10=0x14273c9a0）。分发器 0x1421220f0 在 .rdata
中仅一处指针槽（0x1435078f0，即会话组 vtable +0x18；`[group+8]` 对象持指向该槽的
次级 vtable 指针，slot 0 即分发器——MSVC 次级虚表形态）。**0x1421220f0 本身是真函数
入口，不是跳转表/数据**（纠正任务前提的疑虑；v22 的 idispatch 钩子地址无误）。

**驱动定性（已实证）**：pump 由主循环帧 tick 驱动（tick 函数 0x142120cf0，经主循环
0x1410087e0 每帧调 + 同簇另一调用方），非独立 pump 线程（无线程循环证据；三处泵区段
均在 tick/连接处理函数内同步调用）。停摆门控按检查序为：(i) tick 入口 `[session+0x272a]`
（§20.3）；(ii) 泵区段状态机门 `[session+0x2270]>1`（§20.4）；(iii) fill 门 `[stream+0x251]`
（§20.2）；(iv) reader 饥饿旗 `[stream+0x252]`（§20.2）。四门中任一关闭都表现为
"idispatch 为 0"，v23 须按序区分（§20.6）。

### §20.2 饥饿旗 +0x252 与填充旗 +0x251：已实证机制，置位源未全闭合

- **+0x252（stream 对象 +0x252 字节）**：id reader 的"字节不足"旗。置位仅一处（已实证）：
  0x142197eea `mov byte [rbx+0x252],1`（可用量 `[0x270]−[0x278]` < 请求字节数时）。
  消费三处（均已实证）：pump1 工厂返回后 `cmp [rbx+0x252]`（置位则跳过分发、仍计认领并
  释放对象）；pump0 读 id 后 `cmp [rbx+0x252]`（置位则**清 `[stream+0x278]=0**、清旗、
  返回 0 停止排空）；id reader 入口自查。`[stream+0x278]` 为读游标、`[0x270]` 为写游标
  （ring-buffer 求模见 fill）；饥饿时游标清零是"丢弃当前不完整包头、回绕"的复位语义
  （推断：游标为窗内相对偏移，清零即回窗首；未逐字证实环绕不变量）。
- **+0x251（相邻字节）**：fill 的"需填充"旗。清位两处（已实证）：fill 成功后
  0x142197d08 `mov [rbx+0x251],dil(0)`；WSAEWOULDBLOCK 路径 0x142197d2a
  `mov word [rbx+0x250],0`。读位四处：fill 入口、三处泵区段善后（`cmp [stream+0x251],al(0)`，
  非零则跳过空闲迭代）。**置位源未定位（缺口）**：全 .text 位移 0x251/0x250 扫描未发现
  对 stream 对象的置 1 写（扫描受线性反汇编误同步噪声干扰，结论降级为"未找到"，非
  "不存在"）；最可能属 socket 可读回调/网络层（未逆）。fill 本身做 recv（非阻塞 +
  WSAEWOULDBLOCK），故 +0x251 更像"上次填充后仍有数据待取/需重发 recv"的重臂旗，
  而非数据到达的唯一信号——**即使 +0x251 恒 0，已入缓冲的字节仍可由 pump0 读出**；
  故 +0x251 置位缺失不能单独解释 0x2f7 已达（TCP 层）却未分发，除非 recv 从未把字节
  移入缓冲（即 fill 从未真正跑通——v23 #4 判别）。
- **+0x250 字**：与 +0x251 组成 u16 旗字段（字清零证据）；其余位语义未定。

### §20.3 tick 门 +0x272a：置位者是 0x29 case——网关从未发 0x29，门应常开

全 .text 位移 0x272a 访问仅 8 处（已实证，逐一分类）：读 4 处（0x142105fb2、
0x14211ed9c、0x14211edac、tick 入口 0x142120d28）；原子交换 2 处（下）；其余为
立即数假阳性。交换两处：

- **置位**：分发器内 0x142122d44 `mov eax,1; xchg byte [r15+0x272a],al`——位于
  **0x29 case**（0x142122346–0x142122f41，switch 表定界；case 体含 TLS 注册表取用、
  哈希键 0x2caa229f、继而 `call 0x142125d50`）。该 case 无条件置 +0x272a=1（旧值丢弃，
  不测试）。语义推断（中）：0x29 为区域切换/加载类消息，置旗暂停会话 tick（加载期挂起）。
- **配对翻转**：组函数内 0x14212cbdc `xchg byte [rax+0x272a],sil`（sil 值未溯源，
  极可能为清零路径；所在函数 0x14212cb70 一带为组方法，调用方未分类）。

**结论（已实证机制 + 直接推论）**：网关从未发送 0x29（四包序列无 0x29），故 0x29 置位
路径在我方会话中不运行；+0x272a 在我方会话中应恒为 0，tick 入口门常开。**0x29 置位说
对 08:49 停摆已排除**（待 v23 #1 实测复核：若 tick 钩子读到 +0x272a=1，则存在第三置位
者，扫描结论作废）。

### §20.4 状态机门 +0x2270 与 5 秒握手 deadline：已实证机制，停摆主因强推断

**状态机写点（位移 0x2270 全 .text 扫描，已实证分类）**：初值 1（会话构造
0x14211e550）；连接例程 0x14211eb46 置 esi/r14d（=2，connect issued）并同时置 deadline
（下）；leave 例程两处 0x14211f814/0x14211f9aa 置 1；setter 0x14211f920 内
0x14211fada 置 2；0x23 handler 0x1421232b4 置 3；超时分支 0x142120ffb 置 1（下）。
**0x1e case 体内无 +0x2270 写**（0x14212269f 起全文已读：仅 WorldAreas 查表、会话/
聚合体字段写、TLS 取用；evening19 全文结论一致）——**0x1e 本身不关泵门，已排除**。

**5 秒 deadline（已实证数值与算式）**：连接例程 0x14211eb9c–0x14211ebc7：取时钟
（0x140108860 + 性能计数器）→ 毫秒化（×0x3e8 ÷ 频率）→ **`+ 0x1388`（+5000 ms）** →
`mov [session+0x21a0],rax`。即 deadline = 连接时刻 + 5 秒。**刷新点不存在**：全 .text
位移 0x21a0 写点仅两处——构造清零（0x14211e47a）与连接例程置值（0x14211ebc7）；
无任何消息 handler/成功路径刷新它（已实证扫描）。

**超时检查（已实证）**：tick 内 0x142120fdb 分支：`cmp rsi(now),[session+0x21a0]; jg
0x142120ffb` → 置状态 1 + `[session+0x2208]=0x95`（断线原因码 0x95）+ 向
`[session+0x2210]` 表写 0。检查受 `[session+0x2198]` 节流（初 0；检查后置
now+0x3e8（+1000 ms）；1 秒后传输重建块（0x142121058–0x1421210fb）重建 `[0x2100]`
传输对象并清 [0x2198]，下轮 tick 重新检查）——约 1 秒一次。检查分支在 tick 流中位于
泵区段之前（0x142120fdb → 0x142121027 → 0x142121104），故**超期后的首个 tick 即先置
状态 1、再被泵区段状态门挡住**。检查是否仅 state==2 时可达，静态未完全证实（tick 上游
分支未全追踪；若检查无条件运行，则任何会话都活不过连接后 5 秒——与选角长会话矛盾，
故检查必有状态/阶段门，门条件未定，列为弱点）。

**与 08:49 时序的吻合（强推断，待 v23 实证）**：实例连接 ≈ 0x1e 发送时刻 08:49:02.675
→ deadline ≈ 08:49:07.7。:04 批处理（0x11+0x1e）在 deadline 内（泵正常）；区域生成
耗时 ~4 秒（0x1e→0x9a 08:49:02.675→06.790）；网关 0x2f7+0x23 抵达 08:49:06.794，距
deadline 不足 1 秒；其后泵再未分发。吻合的因果链：deadline 检查（~1 秒节律、位于泵
区段之前）在 0x2f7 抵达后的首个检查 tick 置状态 1 → 泵门永久关闭 → 0x23 永不到达
（状态 3 是唯一取消路径，而 0x23 自身需经泵分发——死锁）。**但以下两点未闭合，推断
不得升格**：(a) 0x2f7 抵达（:06.794）至 deadline（:07.7）之间约 0.9 秒、数十帧 tick，
泵为何一帧都未排空——须 tick 在该窗口内未运行（主循环被区域生成收尾阻塞？）或检查节
律恰在 :06.8 前已运行并已置 1（deadline 实际早于 :07.7：连接早于 0x1e 发送时刻？）；
(b) 检查的状态门条件未定。v23 #1/#2/#3 直接判别。

**附：分发器空消息路径（已实证，旁证）**：分发器入口 `r13=[r8]==0` 且状态 !=1 时，
以 (key=0xf, name="") 调 setter 0x14211f920（evening5 的默认断线原因自造路径）；状态
==1 时跳过。泵区段善后的 edx=0 空闲迭代经 pump1 的 dx==0 支调此路径——空闲向量在我方
会话中是否非空未定；若非空且状态为 2，该路径每轮都调 setter（setter 语义：写 key、
走 leave 共用拆除尾段？evening5 定 setter 与 leave 共享尾段——空闲迭代是否真调到拆除，
未追踪 setter 全体，列为次要疑点，不得据此改网关）。

### §20.5 双 idispatch 之谜：已解——两条消息，非一条两次

08:49:04 的两次 idispatch 参数/返回地址完全相同（a0=同一 `[group+8]` 分发器主对象、
a1=同一 stream、ra=同一 pump1 内调用点 0x1421C5AD5），id0=4384 是 hook 误读
（`[stream+0]` 的 u16，非消息 id——分发器取 id 于 `[msg+8]`，msg 在 r8 指向的指针槽
内，v22 钩子未记 r8）。两次事件实为**两条不同实例消息各走一次 pump1**：

- 每条消息 pump0 先调世界组（vtable 0x143508438）：工厂 `call [rax+0x10]`（返回地址
  0x1421C5A9E）→ 世界工厂入口 `movzx ecx,r8w; cmp 0x181; sub 0x64…` 对 id 17（0x11）
  与 30（0x1e）均落 default → **out=0（已实证工厂头）** → pump1 返回 0；
- 再调会话组（vtable 0x1435078d8）：同一调用点（故同一 ra）→ 实例工厂建出对象 →
  分发器（case 0x11 加密 / case 0x1e 区域）→ 各一次 idispatch。
- 日志序 wfactory→ifactory→idispatch→wfactory→ifactory→idispatch 与 [世界组,会话组]
  × [0x11,0x1e] 完全一致；若为同一消息两次分发，第二次 wfactory 不应插在两次
  idispatch 之间。**"同一消息进两次分发器"说已排除**。

**0x11 在 :04 才分发的含义（推断，中）**：0x11 包在实例连接时即已发送，却与 0x1e
同批在 :04 排空——泵在连接后至 :04 间未排空（或 0x11 在缓冲中等待 0x1e 的解密
上下文；解密在 fill 层，与分发器 0x11 case 的密钥对建立无关——0x1e 在 :02 已解密入
缓冲，故 0x11 滞留是泵未跑，而非解密未就绪）。泵的首次排空在 :04（0x1e 抵达后 1.3 秒），
与"tick/主循环在区域生成前已有停顿"一致，但停顿原因未定（与 §20.4 的 deadline/主循环
阻塞两说共享证据，v23 区分）。

**case1e 跳转形态（已实证）**：0x14212269f 位于分发器函数体内（0x1421220f0–
0x142125c78），经 switch 跳转表 `jmp rcx` 到达，非 call——故 case1e 钩子的
a0/a1/ra 全为垃圾（a0=自身运行时地址系 switch 残留、ra=0），仅"触发过"计数可信。
**v23 的 case 钩子一律只记存在/计数，不得读参**（本节纠正 v22 钩子语义；case 体本身
已由 evening19 逐指令读完，无需再钩其参数）。

### §20.6 第二提交驱动：0x14121fb50 区域数据组装（已实证结构，调用链异常如实记录）

- **返回地址异常（已实证字节）**：commit 钩子的 ra=0x14121FE35 落在 0x14121fb50 尾声
  `add rsp,0x2a0`（0x14121fe2f–0x14121fe35）的**最后一个字节**——中指令地址，不是一
  个干净调用点。字节复核确认该处确为 add 指令（48 81 C4 A0 02 00 00），不存在另一
  种对齐的 `call [reg+0x1e0]` 解码。**调用点归属降级**：commit 经虚表/尾跳链到达，
  栈上返回地址不是干净调用点边界；"调用方 = 0x14121fb50"的认定依据是 ra 落在其尾声 +
  a0（第二聚合体 0x46cdfec6800，与第二 aggctor 的 a0 相同）+ 时刻（wctor 之后、230
  登记之前），**不是**干净调用点证据。确切虚调用指令未定位（缺口）。
- **函数定性（已实证结构）**：0x14121fb50：出参结构清零、16 字节块拷贝、经 0x14107bc10
  构建 + 0x140189bc0 写出（两轮）、引用计数收尾、u16/u32 三元组换位循环（`lea r8d,
  [rbx+rbx*2]` 索引 ×3 的成组换位）、11 字节头结构（0xb + double + u16 + byte）经
  0x14109c6a0 组装、全局计数 `lock add` + 0x142bba4e0 释放。直接调用方仅 3 处，全在
  0x14131xxxx 簇（0x14131170e、0x141312cfe、0x141313e4f——区域生成系统区）。**定性：
  区域生成数据组装（强推断）**，与登录期驱动 0x140edf340（聚合体组装：24 字节条目向量
  + 40 字节表钳制 + 构建器 0x14212f490 + 虚调用 commit，ra 干净）结构完全不同。
  08:49:04 的 commit = 新区世界组装提交（第二聚合体），与 08:17 的登录期 commit 异质。
- **世界工厂 id 17/30 的含义**：即 wire id（0x11/0x1e）原样传入世界工厂（pump1 的
  r8d=dx）；世界工厂 Chunk A 仅 0x64/0x65/0xa3/0x181 有 case，17/30 落 default 返空。
  **92 世界消息目录中无 17/30**——wfactory 日志的 id 不是世界消息目录序号，而是 pump
  试探两组工厂的 wire id（任务前提的"查 92 目录"不适用，已纠正）。

### §20.7 网关缺口判定：无已证实缺口，不得补发消息；唯一候选杠杆是 0x23 时序（待 v23）

**判定（已实证 + 强推断分级）**：

1. **0x11→0x1e 序列无缺口**：0x1e 已被接受（5/5 会话随后生成 0x9a 之前——08:49 会话
   0x1e 已分发、建世界、触发提交与登记）；无真实服务器序列对照，任何"缺前置消息"说均
   无证据。**不得补发任何消息**（尤其不得发 0x29——0x29 case 置 tick 挂起旗，补发只会
   雪上加霜；不得发 0x28/旧序列）。
2. **停摆是纯客户端状态/时序问题（强推断）**：泵链四门中，0x29 门已排除（§20.3），
   0x1e 关门已排除（§20.4），剩余嫌疑按序为：(a) 5 秒 deadline（§20.4，主因候选）；
   (b) tick 在区域生成收尾窗口未运行（主循环阻塞，未证实）；(c) fill/+0x251 字节未入
   缓冲（未证实，置位源未定位）。三者均无网关字段解。
3. **条件杠杆（待验假设，不得先行实施）**：若 v23 证实 deadline 主因，则网关侧唯一确定
   性杠杆是让客户端在连接后 5 秒内抵达状态 3——即 0x23 须在 deadline 前被分发。而
   0x23 触发激活要求提交已完成（S1 教训：[agg+0x1270]=0 时回调崩溃），提交的唯一可
   见信号是 0x9a（区域生成完成，约连接后 4 秒）——** margin 不足 1 秒是结构性的**。
   候选实验（仅 v23 证实后）：(i) 0x2f7 随 0x1e 同发、0x23 仍等 0x9a（0x2f7 早入队不
   改变激活时序，但若泵在 deadline 前只剩一次排空机会，早入队的 0x2f7 仍需 0x23 触发；
   收益未证实）；(ii) 在 0x9a 前以固定短延迟试探 0x23（撞 S1 窗口，须先有提交时序
   证据——目前仅 0x9a 一个信号，不得盲目）；(iii) 接受 deadline 为客户端硬约束，报告
   "须客户端侧时序信号/更快的区域生成"，不改网关。**在 v23 之前，三者一律不实施**；
   禁令维持：不重排 burst、不盲目延迟、不重发 0x23、不补发新消息。

### §20.8 v23 钩子清单（只读、防洪水、禁用 .toNumber()，safeAttach 包裹）

读序：#1→#2（tick/状态）→ #3（泵区段）→ #4（填充/字节）→ #5（分发）→ 保留 v22
决定组（#6）→ #7（工厂采样）→ #8（对照）。新钩子只加本节清单；高频钩子采样 +
状态变化触发全记；case 体钩子只计数不读参（§20.5）。

1. **tick 入口 0x142120cf0**：onEnter 记 `[rcx+0x272a]`、`[rcx+0x2270]`、
   `[rcx+0x21a0]`（deadline）、`[rcx+0x2198]`、r8（now 疑）。采样 1/30 + 状态/
   旗变化时全记（JS 内缓存上次值，变化即记）。判别：tick 是否运行、门是否开、
   deadline/now 相对位置。
2. **超时分支 0x142120ffb**：onEnter 记 `[rdi+0x2270]` 置 1 前的值、now、deadline、
   `[rdi+0x2208]`。罕见，全记。判别：deadline 是否 firing、 firing 时刻 vs 0x2f7 抵达。
3. **泵区段入口 0x142121104**：onEnter 记 `[rdi+0x2270]`、`[rdi+0x20f8]`。采样 1/30 +
   首次到达/状态变化全记。判别：tick 是否走到泵区段。
4. **fill 入口/出口 0x142197bf0**：onEnter 记 `[rcx+0x251]`、`[rcx+0x270]`、`[rcx+0x278]`；
   onLeave 记 `[rcx+0x251]`。采样 1/10。判别：字节是否入缓冲、+0x251 生命周期。
5. **pump0 入口/出口 0x1421c5b90**：onEnter 记 `[rbx+0x252]`（rdx=stream 寄存器以实测
   为准）；onLeave 记返回值 al + `[stream+0x252]`。仅当 id!=0 或旗置位时记详情，
   余者计数（1 秒心跳 flush）。判别：reader 是否饥饿、泵是否空转。
6. **保留 v22 决定组**：idispatch（计数 + ra）、case1e（仅计数）、wctor/aggctor、
   ifactory、wfactory、v21 决定组（wfactory/dispatcher/h23/act/drain/tick448）、
   v19b 五环、v20 ctor 链。零读数本身即证据。
7. **工厂返回地址采样**（v21 #8 保留）：判别调用者构成漂移。
8. **setter 入口 0x14211f920**：记 key（edx.toInt32）+ 调用后 `[rcx+0x2270]`（onLeave
   读）。罕见，全记。判别：空闲迭代/默认断线路径是否真拆除会话（§20.4 附）。
9. **对照**：保留去 throw 钩子的对照会话（v21 #10 / v22 #9 遗留），检验 0x13fff544a
   stale 说。v23 部署后第一次会话仍带全部钩子；若 deadline 主因得证，按 §20.7 议
   实验；若 tick 未运行，查主循环阻塞点（0x1410087e0 帧函数内）；若 fill 未入字节，
   查 +0x251 置位源（socket 层）。

### 缺口 closure 状态（evening20 更新）

- 缺口 1（ebx 终值）：05:48 已闭合 ebx=0；ebx 输入值未闭合。
- 缺口 2（P 身份）：未闭合。
- 缺口 3（与网关字段的因果）：未闭合→收窄：网关无已证实缺口；停摆主因候选为 5 秒
  deadline（强推断，v23 #1/#2/#3 判别）；备选 tick 阻塞 / fill 未入字节。
- 缺口 4（形态 B stall 点）：已定位至**泵链**（tick→fill→pump0→pump1→分发器），
  08:49 形态 = 泵在 0x1e 批处理后停摆；精确门（deadline/阻塞/填充）未闭合，v23。
- 缺口 5（探针 bug 致死性）：已排除为主因。
- 缺口 6（07:49/08:17/08:49 决定因素）：三会话死在链的不同高度（07:49 分发抵达、
  ctor 前 stall；08:17 分发未抵达；08:49 泵停摆）——不得合并；08:49 的泵停摆解释
  不自动适用于前两者（前两者的 tick/deadline 状态未测）。
- commit 调用链：第二驱动 0x14121fb50 已定性（区域数据组装）；其虚调用确切指令未定位
  （ra 中指令异常，如实记录）。
- 世界对象存在性：已闭合（随聚合体构造而存在）；08:49 证实新区世界亦然（第二聚合体/
  世界 + 提交 + 登记）。
- 双 idispatch：已闭合（两条消息，非一条两次）；case1e 跳转形态已闭合（只计数）。
- +0x251 置位源：未闭合（socket 层待查）。
- +0x272a：已闭合为 0x29 case 置位（网关不发 0x29 → 门常开，待 v23 #1 复核）。
- WARN 证据地位：降级维持。
- 0x13fff544a：stale 槽值说维持；最终检验 v23 #9。

## 2026-11-05 evening21 — tick dies, +0x272a flips（09:14 会话，静态判定）

证据来源：09:14 会话探针 v23 普查（parent 提供，见 trace-0914-v23.txt：deadline 值
80378444=连接时钟+5000ms 证实但超时分支 0 次、状态停 2、tick 在 n=60 后停止；泵区段
仅 2 次、pump0 末次 :36、fill 持续到 :39；+0x272a 在无 0x29 时 0→1）；本节静态验证
全部在本机 PathOfExile.exe 上新鲜复核（位移模式扫描 + 开关表解析 + 全函数反汇编 +
scan_calls），未改服务器代码。结论分级标注。

### §21.1 [session+0x272a] 全部写点与语义：仅一置位者（0x29 case），:36 翻转写入者未定位

**全 .text 位移扫描（已实证，模式扫描逐一分类，排除线性反汇编误同步）**：disp32
0x272a 的真实访问仅 6 处（另有 imm32/分支目标假阳性已剔除）；重叠位移 0x2724–0x272c
扫描无覆盖 0x272a 的宽写（仅构造初始化 `mov dword [rsi+0x2728],0xff00`，+0x272a 初值 0）；
别名基址扫描（[session+0x20f0]+0x63a、[+0x20f8]+0x632、[+0x2100]+0x62a、[+0x2108]+0x622）
无字节写。写点清单：

| 地址 | 指令 | 定性 |
|---|---|---|
| 0x142122d44 | `mov eax,1; xchg byte [r15+0x272a],al` | **唯一置 1**。位于 0x29 case（开关表解析已实证：仅 id 0x29 → case 入口 0x142122346，case  span 0x142122346–0x14212269e；第二开关表（id 0x130–0x24f）无目标落入该 range；E8/E9 与 Jcc 全量目标扫描无任何外部跳转/分支进入 case 中段——进入 set 的唯一路径是 0x29 case 入口顺流） |
| 0x14212cbdc | `xchg byte [rax+0x272a],sil` | **清零路径，已实证**：所在组函数 0x14212cb20 入口 `xor esi,esi`，sil=0 经被调函数保持（callee-saved），故恒清 0；该函数同时清 [rcx+0xf0/0xf8/0x100] 映射表、调 0x14211fdb0（下） |
| 构造 0x14211e6f0 | `mov dword [rsi+0x2728],0xff00` | 初值：+0x2728=0,+0x2729=0xff,+0x272a=0,+0x272b=0 |

读点 4 处：tick 入口 0x142120d28（门，§21.2）；0x142105f80（`[[rcx+0x1a8]+0x272a]`，
置位则跳过整段帧更新，§21.3 旁证）；0x14211ed9c/0x14211edac（下）。

**语义（已实证机制 + 直接推论）：+0x272a = 会话挂起旗（suspend）**。置位者 0x29 case
是区域切换/加载类消息 handler（读 [msg+0x8c]、调 0x14211ca90/0x14212ad60 解析消息
体、TLS 注册表 + 哈希键 0x2caa229f、事件 0x14218eaf0、继而 `call 0x142125d50`）；case
体内同时 `xchg [r15+0x272b],al`（换出旧 +0x272b）+ `mov [r15+0x218b],0`（复位 0x9a
已发标记）——即"挂起会话、为下一次区域加载重臂 0x9a"。旗置位后：tick 入口即退
（§21.2，泵/计时器/0x9a 全死）；facet 析构 0x14211ed50（装 4 个 vtable 后）以
`while([rcx+0x272a]) call 0x142b8d6b8` 自旋等待清旗（已实证循环结构）——挂起期间
析构侧阻塞。清旗者组函数 0x14212cb20 零直接调用方（经虚表到达），其调 0x14211fdb0
（亦仅此一调用方）——0x14211fdb0 含 +0x272b 重臂（`xchg [r15+0x272b],al=1`，0x142120176）
与 [agg+0xbc]→[session+0x2728] 拷贝（0x142120135）：同一复位路径"重臂 0x9a + 清挂起"。

**0x29 case 之外还有谁置 1：无（镜像内）**。:36 翻转的写入者**未定位**——残留假设
按序：(1) 0x29 case 经未计数路径运行（见 §21.4 的 v24 判别：idispatch 钩子从未记 id，
"0x11+0x1e" 归属是时序+case1e 计数的推论，非 id 实测；第二条分发消息的 id 从未被
直接观测）；(2) 跨模块写（另一 DLL 触会话对象，exe 内不可证实）；(3) 探针盲区（次级
vtable 槽地址与 0x1421220f0 不一致的组实例）。**evening20"0x29 case 是唯一置位者"
的扫描结论维持，但"网关不发 0x29 → 门常开"的推论被 :36 翻转证伪**——门在无 0x29
时照样翻转，置位源须 v24 实测，不得再以"未发 0x29"排除。

### §21.2 泵区段准入条件：tick 全函数已读，门序完整；pumpsec 钩子读数作废

tick 0x142120cf0 全函数（0x142120cf0–0x142121730）反汇编已实证，流序如下：

1. **入口门（§21.1）**：`movzx eax,[rcx+0x272a]; test; jne 0x14212170f`（epilogue）。
   置位则 tick 整体跳过——计时器、0x9a、传输、deadline、泵区段全不运行。
2. 计时器向量循环（[rcx+0x2780..0x2788]，8 字节条目，float +4，经 0x14014dcb0 更新）。
3. **+0x272b 块（0x9a 发送，§21.3）**：`[rdi+0x272b]!=0` 时：[rdi+0x218b]==0 则置 1 并调
   0x14013bbf0（list 迭代）；全局 dword `[rip+0x25d8e64]!=0` 则**整 tick 退出**
   （0x14212170f，泵区段前第二出口——全局抑制旗，语义未定）；否则组 0x9a 包（id 0x9a
   + [agg+0x114]/[+0x118] 哈希）→ `call 0x14211fa00`（发送）→ `call 0x142198110` →
   `xchg [rdi+0x272b],al(0)` 清旗。
4. 传输块（[rdi+0x2100]）：非空则调 0x142715990；返 0 → 直跳泵区段；返非 0 → 长块
   （0x14218eaf0 事件键 0x91c63e4、[agg+0x661] 检查、[0x20f8] 流交换、旧传输释放、
   [0x23c0] slot+8、0x14211fac0）→ 0x142121027 销毁 [0x2100] → 泵区段。
5. **deadline 检查（0x142120fdb，仅 rsi==0 时可达）**：`cmp rsi(now),[rdi+0x21a0];
   jg 0x142120ffb` → 置状态 1 + `[0x2208]=0x95` + `[0x2210]` 表写 0；否则置
   `[0x2198]=now+0x3e8`（下次检查 +1000ms）。**v23 的 timeout 钩子地址 0x142120ffb
   是真分支入口（本次字节复核确认），其 0 次 firing 有效**——超时确未触发。
   检查后 `jmp 0x142121027` → 泵区段（状态门随即挡住，§20.4 机制维持）。
6. 节流/传输重建块（0x142121058，[0x2100]==0 时）：[0x2198]==0 → 直跳泵区段；
   now<[0x2198] → 直跳泵区段；否则重建 [0x2100]（0x14074a560/0x142bba600/
   0x1427157d0）并清 [0x2198] → 泵区段。
7. **泵区段（0x142121104，tick 内标号，非独立函数）**：`rcx=[rdi+0x20f8]; test;
   je 退出`；**`cmp [rdi+0x2270],1; jbe 退出`**（状态门）；`call fill 0x142197bf0`；
   循环 `call pump0 0x1421c5b90` 至返 0；`[stream+0x251]==0` 时空闲向量迭代
   （[0x2138..0x2140]，slot+8，edx=0 → 分发器空消息路径）。
8. 尾部：两组定时回调（[0x2750]/[0x2760] vs now，经 0x142129dd0）；状态==3 专属块
   （0x14212120f 起）→ epilogue。

**泵区段准入条件（除状态>1 外，完整）**：(i) tick 入口 +0x272a==0；(ii) 全局抑制旗
==0（+0x272b 块内）；(iii) [0x20f8] 流对象非空；(iv) 状态>1；(v) tick 本身被调用
（§21.3）。:36 之后 (i) 变假（+0x272a=1）→ 泵区段不再进入——**与 tick 钩子
sig 变化时序一致，是泵停摆的直接机制（已实证链）**；(ii)(iii)(iv) 在 :36–:39 间
均未观测到变假（状态恒 2；流对象存活，fill 持续工作）。

**pumpsec 钩子读数纠正（重要）**：0x142121104 是 tick 内标号，钩子 onEnter 时的
args[0]=rcx 是到达该标号时的残留寄存器（经 5 条不同入边：fallthrough/je/jmp，
rcx 值各异），**a0/st 读数全为垃圾，仅"进入过 2 次"计数可信**。v23 摘录中
"第 2 次 a0=0x0 st=-1"不是异常调用形态，是同一标号的另一入边——"第 2 次调用形态
不同"说作废。v24 的泵区段钩子只计数，不得读参（与 case 钩子同规）。

### §21.3 tick 停摆：帧循环两调用点；0x9a 由 tick 发出；主线程楔死为首选解释

**tick 调用方（已实证）**：仅 2 处，均在主循环帧函数 0x1410087e0 内：
- 0x141008afa：`rcx=[rsi+0x1a8]`（会话取自 owner 对象 +0x1a8）→ 直调 tick；
- 0x1421206ca：经包装器 0x142120650（TLS 计数检查 + 遥测调用 0x14102dd80，tick
  调用无条件），包装器调用方 0x1410082c3/0x1410082f6（同一帧函数内早段）。
两调用点之间无分支可单独跳过 tick（帧函数内直流）；故 tick 停摆 ⟺ 帧函数不再跑到
这两处，或 [rsi+0x1a8] 被换/清。帧函数本体庞大，早段分支未全追踪——帧循环阻塞的
精确位置未定位。

**0x9a 与 tick 的关系（已实证）**：0x9a 发送路径**在 tick 内**（§21.2 第 3 步），由
+0x272b 旗驱动、+0x272b 由复位路径（组函数→0x14211fdb0）重臂。09:14 的 0x9a
（:39.418）由末批 tick（n≈60–89，采样未记）发出——"泵死后 0x9a 仍发出"不矛盾：
泵（分发）死于 +0x272a 门，而 0x9a 发送块位于同一 tick 内泵区段之前、且 +0x272b
块不受 +0x272a 之外的门控（仅全局抑制旗可拦）。区域生成完成→重臂 +0x272b→tick
发 0x9a 的链成立；**区域生成完成路径与泵分发无关，已闭合**。

**tick 停在 n=60 附近的原因（推断，中）**：首选**主线程楔死于挂起等待**——facet
析构 0x14211ed50 的 `while(+0x272a) yield` 自旋（调用方含主循环区 0x1410072f9/
0x14100762e 与聚合体 walk 区 0x141628dab/0x14162952a）；+0x272a 置位后若某线程
进入该自旋、而清旗者（虚表组函数）需泵/tick 驱动则永不运行 → 死锁 → 帧循环停
→ tick 停（n=60 后无 n=90，速率 ~15–30/秒，:39→:55 应有数百次）。备选：帧循环
阻塞于区域生成收尾同步工作（未定位）；或会话被摘出 tick 表（[rsi+0x1a8] 换空，
未定位）。三说均待 v24（帧函数入口心跳 + 自旋入口计数）区分。**deadline 已双重
证伪**：超时分支 0 次且状态恒 2（§21.2）；tick 在 deadline 到达（:39.77）前已死，
检查无从 firing。

### §21.4 网关缺口再判定：无确定性动作；:36 翻转是唯一未闭合因果

**判定（已实证 + 待验假设分级）**：

1. 网关侧仍无已证实缺口：0x11→0x1e 序列 5/5 被接受并建世界；0x2f7/0x23 字节已
   解密入缓冲（fill 至 :39）；停摆机制在客户端内（+0x272a 门 + tick 停摆）。**不得
   补发任何消息**（尤其不得发 0x29——0x29 case 正是置挂起旗者；不得重排/延迟/重发）。
2. 唯一未闭合因果是 :36 的 +0x272a 翻转写入者（§21.1）。在 v24 证实写入者之前，
   一切网关时序实验（0x2f7 随 0x1e 同发、0x9a 前试探 0x23 等）均属盲目——翻转若
   由 0x29 case 运行导致，则 0x2f7 早发亦无用（tick 门在 :36 已关，0x23 到达时
   泵已死）；翻转若由跨模块/盲区导致，网关更无着力点。**维持禁令，等待 v24**。
3. 接受条件（若 v24 证实 0x29 case 在 :36 运行且源为客户端自合成）：报告"客户端
   在区域加载中自发 0x29 挂起会话，网关无法阻止；须客户端侧证据（合成点）或接受
   为硬约束"，不改网关。

### §21.5 v24 钩子清单（只读、防洪水、禁用 .toNumber()，safeAttach 包裹）

读序：#1→#2（翻转写入者）→ #3（tick 存活）→ #4（自旋/清旗）→ #5（保留决定组）
→ #6（对照）。case/标号钩子只计数不读参（§21.2 纠正）；高频钩子采样 + 变化全记。

1. **0x29 case 入口 0x142122346**：仅计数（每次 firing 记 n）。判别：:36 是否运行。
2. **分发器入口 0x1421220f0 id 实测**：onEnter 记 `[r13+8]` u16（r13=`[r8]`，以
   实测寄存器为准，先验：r8 指向消息指针槽）+ 计数。判别：:36 两条分发消息的真实
   id（0x11+0x1e？或含 0x29？）。低频，全记。
3. **帧函数入口 0x1410087e0 + 包装器入口 0x142120650**：计数 + 1 秒心跳 flush。
   判别：:39 后帧循环是否还跑、包装器是否还调 tick。
4. **自旋入口 0x14211ed50 + 清旗组函数入口 0x14212cb20 + 重臂 xchg 0x142120176**：
   仅计数（xchg 点记旧值 al 亦可，低频）。判别：主线程是否楔死于挂起等待、清旗
   是否运行、+0x272b 何时重臂。
5. **保留决定组**：v23（tick/超时分支/泵区段计数/fill/pump0/setter）+ v22
   （idispatch/case1e 计数/wctor/aggctor/ifactory/wfactory）+ v21/v19b/v20。
   pumpsec 与 case1e 只计数（§21.2）。
6. **对照**：去 throw 钩子会话（v21 #10 遗留）+ 去高频钩子会话，检验 0x13fff544a
   stale 说与钩子致死性。

### 缺口 closure 状态（evening21 更新）

- 缺口 3（与网关字段的因果）：收窄至唯一未闭合因果——:36 的 +0x272a 翻转写入者；
  deadline 主因**证伪**（超时分支 0 次、状态恒 2、tick 死于 deadline 前）；网关无
  确定性动作，禁令维持，待 v24。
- 缺口 4（形态 B stall 点）：已定位至**挂起旗门**（+0x272a=1 → tick 入口即退 →
  泵区段不入）+ **tick 停摆**（帧循环 :39 后不再调 tick）；tick 停摆的精确阻塞点
  未闭合（自旋楔死说为首选推断，v24 #3/#4 判别）。
- +0x272a：写点全闭合（仅 0x29 case 置 1、组函数清 0、构造清 0）；语义闭合为会话
  挂起旗；:36 翻转写入者未闭合（镜像内无第三写点，v24 #1/#2 判别）。
- +0x272b：语义闭合（0x9a 待发旗，复位路径重臂、tick 消费并发送 0x9a）；全局抑制
  旗 [rip+0x25d8e64] 语义未定（次要）。
- 泵区段准入条件：全闭合（tick 门 + 全局旗 + 流非空 + 状态>1 + tick 被调）；pumpsec
  钩子读数纠正（标号钩子只计数）。
- 0x9a 路径：闭合（tick 内 +0x272b 块发送，与泵分发无关；重臂源为组复位路径）。
- +0x251 置位源：仍未闭合（socket 层待查）；已降级为次要（fill 证实工作至 :39）。
- WARN 证据地位：降级维持。0x13fff544a：stale 槽值说维持；最终检验 v24 #6。

## 2026-11-05 evening22 — 0x9a without tick（09:41 会话，静态判定）

证据来源：09:41 会话探针 v24 普查（parent 提供，见 trace-0941-v24.txt：探针挂在正确
pid 34412、钩子全挂上、登录期正常、工厂流量至 09:41:10 后全静默；整个实例期主链事件
全为 0——tick/帧函数/分发器/0x1e case/0x23/激活/创建包/自旋/清旗/重臂一概未跑；客户
端照样完成区域生成并在 09:41:09.611 发出 0x9a（网关实证）；三次同字节会话停摆点各不
相同）；本节静态验证全部在本机 PathOfExile.exe 上新鲜复核（位移模式稳健扫描 + 开关表/
虚表读值 + 全函数反汇编 + scan_calls + .rdata qword 扫描），未改服务器代码。结论分级标注。

### §22.1 0x9a 发送点全枚举：静态仅一处（tick 块）；第二路径未证实，须 v25 运行时判别

**立即数扫描（已实证）**：全 .text `mov eax,0x9a`（B8 9A000000）仅 6 处——3 处为
Animated/AO 变体枚举（0x1414e6532/0x1414e68ee：0x85/0x9a/0xa5 三态选择，与网络消息
无关）、1 处为返回值 0x9a 的小函数（0x1414e4f839，与 0x9b/0x97 并列）、仅 1 处组包
发送：tick 内 0x142120dc0（`mov eax,0x9a; mov [rsp+0x48],ax`，即 struct+8=id）。
寄存器立即数扫描（edx/esi/edi/r8d=0x9a）仅 6 处，均在无关代码（字符串/UI 0x140c2cxxx、
循环计数 0x142c83edc、0x142751274 的 0x9a/0x9b 对）——无第二组包点。

**消息对象虚表指纹扫描（已实证）**：tick 组包的 struct 虚表 = 0x1434e53d8（.rdata 直读；
slot+0=0x14015c940，slot+8/0x10/0x18=0x141f38ae0/0x141f38b80/0x141f38c00，余为消息虚
函数）。全 .text RIP-relative LEA 指向该虚表共 29 处：17 处为内联 C→S 组包发送（id 取
自参数/寄存器/表值，非常量——**运行时可取 0x9a，未证实**）、12 处为固定 id 的消息构造
thunk（id 恒定：0xe6/0xf6/0x100/0x191/0x192/0x193/0x1c0–0x1c4/0x2bb/0x2bc/0x2bf/0x2de/
0x290/0x297/0x2a0/0x2a1/0xe5/0x311/0x339——**无 0x9a**）。故静态上"第二 0x9a 组包点"
不存在；09:41 的 0x9a 若非 tick 所发，唯一静态可能即某参数化发送点在运行时传入
id=0x9a（须 v25 #1 实测 send 入口的 struct+8 id 判别）。

**+0x272b 全访问扫描（已实证，稳健多起点解码）**：仅 4 处——复位函数置 1
（0x142120176/7，§22.3）、tick 读（0x142120d87）、tick 清（0x142120e17）、0x29 case
换出（0x142122c5c）。**+0x272b 的唯一消费者是 tick**——"经旗标的第二 0x9a 路径"已
排除。复位函数 0x14211fdb0 全文已读：commit 调用（虚表 +0x1e0）+ [agg+0xbc]→
[session+0x2728] 拷贝 + 聚合体虚调用 +0x1e8/+0x1b8 + 重臂 +0x272b=1，**体内无发送**
——重臂路径本身不发 0x9a。

**结论（已实证 + 待验假设分级）**：静态上 0x9a 只有 tick 一条发送路径；09:41 的 0x9a
与"tick 从未跑"并存，残留解释按序：(1) 参数化发送点运行时传入 0x9a（区域生成完成
簇直接发送，未证实）；(2) 探针盲区/第二进程（parent 已核 pid 一致，盲区说弱）；(3)
tick 经未建模路径运行（已排除：tick 无虚表槽，见 §22.2）。**"区域生成完成"与"泵分
发"确为两条独立路径（已实证）**：09:41 零分发而区域生成完成并发出 0x9a——0x1e 分发
不是区域生成的必要条件（区域 id/种子可源自登录期存档数据，0x1e 仅为确认）。

### §22.2 tick/帧函数身份复核：tick 仅 2 直调点、无虚表槽；帧驱动是双路分支，任一路注册为空则 tick 零次

**tick 调用链（已实证）**：直接 E8 调用仅 2 处——0x141008afa（帧函数 0x1410087e0
内，`rcx=[rsi+0x1a8]` 直调）与 0x1421206ca（包装器 0x142120650 内）；.rdata/.data
全量 qword 扫描无 0x142120cf0 槽位——**tick 不经虚表/函数指针到达**，2 直调点即全部。
tick 身份维持（evening21 结论不受影响）。

**帧驱动结构（已实证，纠正 evening21 的"主循环帧函数"单一路说）**：帧驱动函数
0x141007d20（仅一调用方，系 0x141007860 的尾跳 jmp；0x141007860 先调 3 个更新函数
0x141667f50/0x1416684a0/0x141669020 再尾跳）内含双路分支：

| 路 | 条件 | tick 调用形态 | 会话来源 |
|---|---|---|---|
| A 0x141008280 | 0x1404fe7a0() != null | 包装器 0x142120650 ×2（0x1410082c3/0x1410082f6），会话取自 `[rax+0x1a8]`（rax 为每次刷新之值）；中段查 `[session+0x2270]==1` | 0x1404fe7a0()：上下文 +0x340 向量首元素 |
| B 0x1410087e0 | 0x1404fe7a0()==null 且 0x14010cda0(0) != null | 直调 tick 0x141008afa（主流程无条件），会话取自 `[rsi+0x1a8]`（rsi=0x14010cda0 返回值）；入口空值即退 | 0x14010cda0(0)：上下文 +0x348 映射查键 0 |

两路查找均经 0x14010cf20 取上下文/TLS 对象。**若两路注册查找同帧返回 null，tick
当帧零次**——这是"某会话 tick 零次运行"的合理解释结构（已实证机制；09:41 是否属此
情形须 v25 #3/#4 实测注册返回值）。v24 的 frame_hb（仅 B 路）与 twrap_hb（仅 A 路）
同为 0，兼容"驱动函数未跑"与"两路注册皆空"两种情形——**v24 数据不能区分二者**，
evening21"帧函数未跑"的表述须降级为"两路 tick 调用均未跑"。

**第三泵驱动（已实证，背景线程）**：另有两处独立泵区段——0x1420e6d40（帧函数内两
处调用 + 0x140efcf33；对象布局 stream +0xec8/组 +0xe98；含 id=1 的流级消息组包，
非 0x9a）与工作线程泵 0x14272fca0（仅一调用方 0x1427389e9，位于任务函数
0x142737860 内；TLS/线程身份检查打头、WSAEINTR 重试循环；对象布局 stream +0x60/
组 +0x20）。三驱动布局各异，分属不同对象类。**实例会话由哪一驱动泵送，静态未定**
——v24 未钩后两者，09:14 的分发未必出自 tick（tick 运行与分发同时发生仅为相关，
非因果已证）；v25 #6 须补钩。

### §22.3 会话对象身份与旗初值：两路注册源、单 +0x1a8 槽；连接例程不复位挂起旗

**会话取源（已实证）**：两路帧分支均读 `[owner+0x1a8]` 得会话（owner 分别为向量首
元素与映射查值）。owner+0x1a8 的写入者未定位（缺口：disp 0x1a8 写入极多，未逐一
分类；会话注册/摘表点待 v25 #4 实测返回值+槽值）。同一进程内登录会话与实例会话的
对象关系静态未定（单对象重连 vs 双对象并存）；连接例程的证据倾向单对象重连模型，
见下。

**连接例程（0x14211eb46 起，全文已读，已实证）**：置状态 `[rsi+0x2270]=2`、重建
[+0x2100] 传输对象（0x68 字节）、写 deadline `[+0x21a0]=时钟毫秒+0x1388`、重建
[+0x20f8] 流对象（0x2b8 字节，经流构造 0x1421975b0）、通知 [+0x23c0] slot+8、查流
+0x250/+0x251 旗、调聚合体 slot +0x1b8。**全程不触 +0x272a/+0x272b/+0x218b**——挂
起旗一旦置位，**重连不复位**，在同一会话对象上永久存活。构造初始化（0x14211e6f0）
`mov dword [rsi+0x2728],0xff00` 证实新会话对象初值 +0x272a=0、+0x272b=0、+0x2728=0、
+0x2729=0xff。会话构造器无直接调用方（经工厂/虚表到达，复用 vs 新建静态未定）。

**+0x272a 写点复核（稳健扫描，已实证，维持 evening21）**：8 原始命中中 2 为分支位移
假阳性（0x140d908a2 的 jne rel32=0x272a、0x1428d2b18 的分支位移），其余 6 处与
evening21 完全一致——读 4 处（0x142105fb2、0x14211ed9c、0x14211edac、tick 入口）、
置 1 仅 0x29 case（0x142122d45）、清 0 仅组函数（0x14212cbdd）。:36 翻转写入者仍未
定位；09:41 会话中旗值从未被观测（tick 零次）——**旗在 09:41 是 0 还是 1，未知**，
不得以 09:41 证伪/证实旗说。

### §22.4 跨会话差异的竞态解释：注册/重臂/自旋三线程交错，停摆点随交错漂移

**三会话对照（已实证，网关字节相同）**：07:49 分发抵达、ctor 前 stall；08:49/09:14
分发运行、泵在 0x1e 批处理后停摆（+0x272a 翻转实测）；09:41 tick/分发从未跑、0x9a
照发。同一网关字节序列产生三个不同停摆高度——**停摆点由客户端侧状态/时序决定，
非网关字节（已实证）**。

**统一解释（推断，中）**：主线程帧驱动（注册查找→tick→泵）与后台线程（区域生成→
提交/重臂组函数→清旗/置旗）与挂起自旋（facet 析构 `while(+0x272a) yield`，调用方
含主循环区）三方交错，交错点决定停摆高度：(i) 注册查找在实例连接前持续为空 →
tick 从未启动（09:41 形）；(ii) 注册完成、泵跑起后 +0x272a 翻转（写入者未定位，
0x29 case 未计数路径仍为首选假设）→ tick 入口即退、泵停摆（08:49/09:14 形）；
(iii) 楔死发生在构造窗口 → ctor 前 stall（07:49 形）。自旋死锁说（evening21）仍为
tick 停摆的首选机制解释，但 09:41 形下自旋是否运行**未观测**（spin24=0）——自旋说
对 09:41 不适用或自旋点在帧驱动之前。

**唯一关键判别变量（待验）**：实例连接建立时刻的 `[owner+0x1a8]` 槽值与两路注册查找
返回值的时间序列（会话是否注册、何时注册）+ 连接时刻的 +0x272a 采样值 + 0x9a 构
造指令（0x142120dc0）是否执行。三者一并实测即可区分"注册为空"（槽空/查找 null）、
"旗预置 1"（连接时旗已 1）、"tick 盲区"（构造指令执行而 tick 入口钩子未记）。

### §22.5 v25 钩子清单（只读、防洪水、禁用 .toNumber()，safeAttach 包裹）

读序：#3→#4（驱动/注册存活）→ #5（连接时旗值）→ #6（另两泵驱动）→ #1→#2
（0x9a 真发送者）→ #7（保留决定组）→ #8（对照）。

1. **send 入口 0x14211fa00**：onEnter 记 `[rdx+8]` u16（消息 id，rdx=消息 struct，
   struct+8=id）+ session（rcx）+ ra。C→S 低频，全记；0x9a 到达时记完整行。判别：
   0x9a 由谁发出（tick 内构造 vs 参数化发送点），及 0x9a 发送时刻 vs tick/分发。
2. **0x9a 构造指令 0x142120dc0**：仅计数（每次 firing 记 n）。判别：tick 内组包块
   是否执行——与 #1 联合：#1 记 0x9a 而 #2 为 0 ⟹ 第二发送路径实锤；#1/#2 同记
   ⟹ tick 路径（tick 入口钩子盲区说成立）。
3. **帧驱动入口 0x141007d20**：计数 + 600 次心跳 flush。判别：帧驱动本身是否运行
   （区分"驱动未跑"与"注册为空"）。
4. **注册查找 0x1404fe7a0 / 0x14010cda0**：onLeave 记返回值 null/非 null（采样
   1/30 + null↔非 null 跃变全记）；非 null 时加记 `[ret+0x1a8]` 会话指针（guarded
   读）。判别：实例会话是否注册、何时注册、槽值是否漂移。
5. **连接例程入口 0x14211eb46**：onEnter 记 `[rsi+0x272a]`、`[rsi+0x272b]`、
   `[rsi+0x2270]`（rsi=会话）。低频，全记。判别：连接时刻旗初值（预置 1 说）。
6. **另两泵驱动入口 0x1420e6d40 / 0x14272fca0**：计数 + 600 次心跳 flush（前者或
   高频）。判别：实例会话是否由帧内/后台驱动泵送。
7. **保留决定组**：v24（case29/idisp_id/帧心跳/自旋/清旗/重臂）+ v23（tick/超时/
   泵区段计数/fill/pump0/setter）+ v22/v21/v19b/v20。pumpsec 与 case1e 只计数。
8. **对照**：去 throw 钩子会话（v21 #10 遗留）+ 去高频钩子会话，检验 0x13fff544a
   stale 说与钩子致死性；本节 #1/#2 为低频钩子，对照会话亦应保留。

### §22.6 网关判定：无确定性动作，禁令维持

**判定（已实证）**：三会话同字节不同停摆点 + 09:41 零分发而 0x9a 照发，停摆根源在
客户端侧注册/同步竞态，网关字节无已证实缺口。**不得补发任何消息**（尤其不得发
0x29——置挂起旗者；不得发 0x28/旧序列）；不重排 burst、不盲目延迟、不重发 0x23、
不试探 0x9a 前 0x23（S1 窗口教训维持）。唯一待验的网关相关变量是 0x9a 发送者的
运行时身份（v25 #1/#2）——若证实第二发送路径且其触发条件含网关可见信号，再议；
此前一切网关时序实验均属盲目。

### 缺口 closure 状态（evening22 更新）

- 缺口 3（与网关字段的因果）：收窄至客户端侧注册/同步竞态；网关无确定性动作，禁令
  维持，待 v25（send id 实测 + 构造指令计数 + 注册序列）。
- 缺口 4（形态 stall 点）：三形态已定位至不同高度（07:49 ctor 前、08:49/09:14 泵停摆、
  09:41 tick/注册未启动）；统一竞态解释为推断（中），判别变量已定（§22.4）。
- +0x272a：写点复核维持（仅 0x29 case 置 1、组函数清 0）；09:41 旗值未观测；连接
  例程不复位旗（已实证）—— stale 旗跨重连存活为待验假设。
- +0x272b：全访问闭合（仅复位函数置 1、tick 读/清、0x29 case 换出）；唯一消费者为
  tick（已实证）。
- 0x9a 路径：静态仅 tick 一处（已实证）；09:41 发送者未闭合（参数化发送点 vs 盲区，
  v25 #1/#2 判别）；区域生成完成与泵分发独立（已实证）。
- tick/帧身份：tick 仅 2 直调点、无虚表槽（已实证）；帧驱动为双路注册分支（已实证，
  纠正单一路说）；另两泵驱动已定位（帧内 0x1420e6d40、后台 0x14272fca0），实例会话
  归属驱动未定（v25 #6）。
- 会话对象：两路注册源 + 单 +0x1a8 槽（已实证）；注册写入者未定位；登录/实例对象
  关系未定（单对象重连倾向，未证实）。
- +0x251 置位源：仍未闭合（次要）。WARN 证据地位：降级维持。0x13fff544a：stale 槽值
  说维持；最终检验 v25 #8。

## 2026-11-05 evening23 — second 0x9a path（10:01 会话，静态判定）

证据来源：10:01 会话探针 v25 普查（parent 提供，严格 10:01 时间戳 recount：
世界建成、区域实体 239 个、0x1e 分发 2 次；玩家对象未建、0x23/激活/排空全 0；
mk9a25=0 但网关实证收到 0x9a；tick 同形状态 0→2、旗 0→1、n=60 停；清旗组函数 :16
跑过 1 次；注册 A 恒非空、B 恒空；send25/idisp_id/conn25 三读点读数失败）。本节静态
验证全部在本机 PathOfExile.exe 上新鲜复核（开关表双级读值 + 全函数反汇编 +
scan_calls + 全镜像位移扫描），未改服务器代码。结论分级标注。

### §23.1 第二 0x9a 发送路径：参数化站点说被证伪；镜像内根本不存在第二 0x9a 构造点

**开关表复核（已实证，纠正本节中段一次误读）**：分发器 0x1421220f0 的 switch
是双级表——先 `movzx eax, word [r13+8]` 取 id，`sub eax, 0xd` 得索引，查字节表
（0x14212593c+idx）得序数，再查 dword 表（0x1421258bc+序数×4）得目标。双级读值
确认：0x29→0x142122346、0x1e→0x14212269f、0x23→0x14212306d、0x11→0x1421221be。
**case29/case1e/h23 三个钩子地址全部正确**——10:01 会话的 case29=0、h23=0 是
有效零值（0x29 未跑、0x23 handler 未跑），不是钩子挂错。本节中段曾因漏算字节表
间接层而误判三地址为错，已自行纠正，特此记录。

**29 构造点全分类（已实证，纠正 evening22 的"17 参数化"说）**：全镜像 LEA 指向
消息虚表 0x1434e53d8 共 30 处（含 tick 自身 + 克隆函数），逐点以函数起点的正向反
汇编核对 id 存储（先前"参数化"结论源于本节初版分类器的正误：capstone 的 op_str
不含 mnemonic，正则误把 `mov eax, imm` 当参数——已修正重跑）：

- tick 0x9a（0x142120dc0，唯一 0x9a）；
- 固定 id：0x1a7、0x1aa、0x70、0x8d、0x24d/0x24e（双分支）、0x59、0x136、0x7a（×2）、
  0x363（×2）、0x206（×2）、0x205（×2）、0x208（×2）、0xfa、0x299、0xe6、0x311、
  0x1c0、0x1c3、0x290、0x2a0、0x191、0x2bb、0x2de；
- 克隆函数 0x141f38c00（虚表 slot+0x18：分配新消息、复制源消息的 id/u8/两 u32，
  不产生新 id）。

**29 点中无一为参数化 id、无一为 0x9a（除 tick）**。故"第二发送路径 = 某参数化
站点运行时传入 0x9a"**已被证伪**。10:01 的 0x9a（mk9a25=0、网关实证收到）残留
解释按序（皆待 v26 实测判别）：(i) **缓存/克隆消息**：0x9a 消息对象在探针挂载
（10:00:57）之前已由 tick 建好并缓存，区域生成完成时经克隆函数（或直接）发出，
全程不再执行 0x142120dc0；(ii) **另一消息类/虚表**：0x9a 由不使用 0x1434e53d8
虚表的另一消息类组包（本节 LEA 扫描只覆盖该虚表）；(iii) **原始流写入**：绕过
send 0x14211fa00 的直接流写。v26 判别：send26 记消息虚表指针 + id + ra（区分
(i)/(ii)与调用方），clone26 记源消息 id（验证(i)）。

**网关可见信号（已实证）**：第二路径无网关可见的前置信号——清旗组函数（:16）
与区域生成线程均为客户端内部事件；网关能看到的第一个完成信号仍是 0x9a 本身
（已在用：0x2f7+0x23 在 0x9a 后 3ms 发出）。故第二路径不给网关任何新的时序点。

### §23.2 清旗后仍停摆：清的是 [group+8] 会话的旗；未阻止停摆的三条可能，时序未定

**清旗组函数 0x14212cb20 全文（已实证）**：rcx=组对象；依次清零组字段
[+0x100]/[+0xf8]/[+0xf0]（旧值存栈）；调 0x14212ae90（组向量操作）；调复位函数
0x14211fdb0（rcx=rdi=[组+8]，rdx=[组+0x44]，r8=[组+0x40]）；最后
`xchg byte [rax+0x272a], sil`（rax=[rbp+8]，sil=0，入口 `xor esi,esi` 保持）——
**清的正是 [组+8] 对象的 +0x272a**。复位函数体内含 commit（虚表 +0x1e0）、
[agg+0xbc]→[session+0x2728] 拷贝与 +0x272b=1 重臂（evening22 已读）。故清旗函数
= 区域组装收尾（提交 + 复位 + 清挂起旗 + 重臂 0x9a）的一环，:16 运行与区域生成
收尾时序吻合。

**为何未阻止停摆（未闭合，三可能并列）**：(a) **时序**：清旗与翻旗同在 :16，
1 秒分辨率日志无法定先后——清在前则翻旗为清后重设（写入者仍未知），清在后则
(b)/(c)；(b) **错对象**：[组+8] 会话 ≠ tick 所读的 [owner+0x1a8] 会话（两指针
从未在同一会话中比对过）；(c) **tick 调用方已停**：n=60 的到达时刻未知，若
tick 在 :16 前已因驱动停调用而停止，清旗无法复活一个不被调用的 tick。v26 判别：
clrflag26 记 ra + 组指针 + [组+8] + 清前/清后旗值，tick26s 逐次记会话指针 + 旗
值 + 状态——对象同一性与先后次序一次闭合。

### §23.3 三个读点修正（已实证，v26 直接可用；含一个探针完整性警告）

**send 入口（v25 用错寄存器）**：send 0x14211fa00 签名为 send(会话 rcx，消息
rdx)：`mov rsi, rdx; mov rbp, rcx; mov rdi, [rcx+0x20f8]`，继而虚调用 [rax+8]
（rcx=消息、rdx=流）。tick 的调用点（0x142120df6：`lea rdx, [rsp+0x40]; mov rcx,
rdi; call send`）证实消息 struct = rsp+0x40，id 在 +8（0x142120dc5 的
`mov [rsp+0x48], ax`）。**v26 正确读法：`u16 @ [args[1]+8]`**（Frida 参数
0 起：args[0]=rcx、args[1]=rdx、args[2]=r8）。v25 读 args[2]（r8）纯属索引错位，
读数 -1/0 作废。

**分发器 id（v25 在 r13 赋值前读取）**：分发器入口先 `mov rbx, r8; mov r15, rcx`，
到 0x142122129 才 `mov r13, [r8]`；switch 头在 0x14212217d：
`movzx eax, word [r13+8]`。**v26 正确读法：钩 0x14212217d，读
`u16 @ [this.context.r13+8]`**（或入口钩读 `[[args[2]]+8]`，r8 为消息槽指针）。

**连接例程（v25 双重错误 + 探针完整性警告）**：连接例程在 0x14211eb45 的真指令
是 `mov [rsi+0x2270], r14d`（REX 前缀 0x44 在 0x14211eb45，操作码在 0x14211eb46）
——**v25 的 conn25 钩子挂在 0x14211eb46，是指令中部**，且读 args[0]（rcx）而
连接例程以 rsi 为会话（满篇 [rsi+0x2100]/[rsi+0x2108]）。中部挂钩的后果：
Frida 在 0x14211eb46 处解出 `mov [rsi+0x2270], esi`（6 字节）并重定位，使状态
字段写入 esi（会话指针低 32 位）而非 r14d——**10:01 会话的连接期状态观测可能
已被探针污染**（tick 随后仍读得状态 0→2，说明状态字段在后文被重写，或 tick 读
的不是同一会话对象——未闭合）。**v26 正确读法：钩 0x14211eb45（已验边界），读
`this.context.rsi` 的 +0x272a/+0x272b/+0x2270；并从脚本中删除 conn25 钩子。**
教训升级：钩子地址须以字节级核对为指令边界（REX 前缀陷阱），不得仅凭反汇编
行号；Frida 参数 0 起索引须复核。

### §23.4 注册 A 活 B 死的修正模型：A→B 是顺序 tick，不是二选一分支

**0x141008280 全文（已实证，纠正 evening22 的"双路分支"说）**：该函数顺序执行
——调 A 查找 0x1404fe7a0，取 [rax+0x1a8] 会话调包装器 tick（**无空值检查**，
故调用方须保证 A 非空）；再调 A 查找（空则跳出）；调 B 查找 0x14010cda0(0)
（空则跳过 B tick）；再调 B 查找取会话调包装器；最后取 A 会话查状态 ==1。
故：09:41（A 空）= 驱动层根本未调 0x141008280，tick 零次；10:01（A 非空、B 空）
= A 会话被 tick（n=60 与之吻合），B tick 被跳过。**实例会话的 tick 驱动落在
A 路**；B 路（映射查键 0）在所观测会话中恒空、从未承载 tick。A 查找返回值的两
个指针（0x29682a30000/0x29686bd2000）：v25 钩子把返回值与 [返回值+0x1a8] 拼
成一串，简报无法区分哪一字段变化——**所有权/会话是否在会话中途更换，未定**；
v26 须分字段记录（见 §23.7）。fdrv/twrap 0 心跳是采样假象（600 次 flush 阈值
高于实际运行次数 ~60 次），不是"驱动未跑"——v26 改 50 次 flush + 首末计数。

### §23.5 翻旗写入者：别名写扫描死刑，剩余三假设；会话切换说因 A 值变化而上升

**别名扫描（已实证）**：全镜像搜索 disp32=0x2728 的 mov 存储形态，仅 4 命中——
会话构造器（dword 0xff00，初值）、0x1415f3af4（立即数 0x2728 作函数参数，假
阳性）、两处 `mov [rdi+0x2728], al`（字节写 +0x2728，不触 +0x272a）。**除构造器
外不存在覆盖 +0x272a 的 dword/qword 写**，别名说死刑。镜像内 +0x272a 置 1 仍
仅 0x29 case 一处，而 case29=0（地址已验，有效零值）。剩余按序：(a) **跨模块写**
（另一 DLL 写会话 +0x272a，静态不可见）；(b) **会话切换**（tick 各次读的不是
同一会话对象——A 查找返回值在会话中变化与此吻合：若 tick 在某次调用后改读一个
早已置旗的旧会话对象，"翻转"实为读数对象切换，无需任何写点）；(c) **计算地址写**
（memcpy/循环写等非字面位移写，静态扫描盲区）。v26 判别：tick26s 逐次记会话
指针——指针在翻转 tick 处变化 ⟹ (b)；指针恒定 ⟹ (a)/(c)。

**tick 入口复核（已实证）**：0x142120cf0 入口 `mov rdi, rcx`，
`movzx eax, byte [rcx+0x272a]; test; jne 0x14212170f`——tick23 的 args[0] 读数
有效，旗门机制维持（置位则 tick 入口即退，但入口钩子仍计数——n=60 只是进入
次数，不是完成次数）。

### §23.6 网关判定：无确定性动作，禁令维持（含早发 0x2f7 的否决）

**判定（已实证）**：翻旗发生在 :16（0x1e :14.4 之后、0x9a :18.5 之前），而网关
在 0x1e 与 0x9a 之间**不发任何消息**——翻旗纯属客户端内部事件，网关无杠杆。
早发 0x2f7（0x1e 后即发、0x9a 前）已议否决：它只能提前玩家创建，救不了 0x23
分发（泵死则 0x23 仍不到达、激活仍不跑），且属 burst 重排（禁令所禁）。第二
0x9a 路径既无网关可见前置信号，也不改变 0x9a 到达后的既有用法。**不得补发任何
消息（尤其 0x29）；不重排 burst、不盲目延迟、不重发 0x23、不试探 0x9a 前 0x23。**
唯一待验的网关相关变量转为 v26 的 send26/clone26 结果——若证实缓存/克隆路径且
其触发含网关可见信号，再议；此前一切网关时序实验均属盲目。

### §23.7 v26 钩子清单（只读、防洪水、禁用 .toNumber()、safeAttach 包裹）

读序：#5→#6（读点修正与会话身份）→ #1→#2（0x9a 真发送者）→ #3→#4（清旗与
注册走向）→ #7（保留决定组）→ #8（对照）。

1. **send26（0x14211fa00 入口）**：记 id=`u16 @ [args[1]+8]`、虚表=`[args[1]]`、
   ra、会话=args[0]；C→S 低频，全记。判别：0x9a 由谁发（ra 定调用函数）、消息
   类是否 0x1434e53d8（区分缓存/克隆 vs 另一消息类）。
2. **clone26（0x141f38c00 入口）**：记源消息 id=`u16 @ [args[0]+8]`、ra。判别：
   缓存/克隆说（克隆源 id=0x9a 即实锤）。
3. **clrflag26（0x14212cb20 出入口）**：入口记 ra + 组=args[0] + 会话=
   `[args[0]+8]` + 清前旗值；出口记清后旗值（this 携 n 配对）。判别：清的会话
   是否 tick 会话、清在翻转前/后。
4. **reg26（0x1404fe7a0 / 0x14010cda0 onLeave）**：分字段记返回值与
   `[返回值+0x1a8]`（不得拼串），采样 1/30 + 跃变全记。判别：所有权/会话是否
   中途更换。
5. **tick26s（0x142120cf0 入口）**：逐次记会话=args[0] + +0x272a + 状态
   +0x2270（tick 低频，全记）。判别：翻转 tick 处会话指针是否变化（会话切换说）。
6. **conn26（0x14211eb45 入口，已验边界）**：记会话=this.context.rsi 的
   +0x272a/+0x272b/+0x2270；并删除中部钩子 conn25（0x14211eb46）。判别：连接时
   旗初值（stale 旗说）。
7. **idisp26（0x14212217d 入口）**：记 id=`u16 @ [this.context.r13+8]`；并删除
   错读钩子 idisp_id（入口 r13）。判别：分发消息 id 实测（0x29 未跑说的最终确认）。
8. **保留决定组**：v25（send 入口除外，以 send26 为准；mk9a25 保留作 tick 路径
   对照）+ v24（case29/spin/rearm）+ v23（tick/超时/泵区段计数/fill/pump0/
   setter）+ v22/v21/v19b/v20；心跳 flush 一律改 50 次；pumpsec 与 case1e 只计数。
9. **对照**：去 throw 钩子会话（v21 #10 遗留）+ 去高频钩子会话。

### v26 部署用钩子代码（待 parent 部署，脚本 master 尚未写入）

```js
// ---- v26: corrected reads + 0x9a sender (evening23) ----
function rU16_26(p, off) { try { return p.add(off).readU16(); } catch (e) { return -1; } }
function rU8_26(p, off) { try { return p.add(off).readU8(); } catch (e) { return -1; } }
function rPtr_26(p, off) { try { return p.add(off).readPointer().toString(); } catch (e) { return 'ERR'; } }
safeAttach('send26', '0x14211fa00', {
  onEnter(args) { send({ ev: 'send26', id: rU16_26(args[1], 8), vt: rPtr_26(args[1], 0), ra: this.returnAddress.toString() }); }
});
safeAttach('clone26', '0x141f38c00', {
  onEnter(args) { send({ ev: 'clone26', srcid: rU16_26(args[0], 8), ra: this.returnAddress.toString() }); }
});
safeAttach('tick26s', '0x142120cf0', {
  onEnter(args) { send({ ev: 'tick26s', sess: args[0].toString(), f272a: rU8_26(args[0], 0x272a), st: rU8_26(args[0], 0x2270) }); }
});
let clrN26 = 0;
safeAttach('clrflag26', '0x14212cb20', {
  onEnter(args) { clrN26++; this.n26 = clrN26; let sess = args[0].add(8).readPointer(); send({ ev: 'clr26', n: clrN26, ra: this.returnAddress.toString(), grp: args[0].toString(), sess: sess.toString(), before: rU8_26(sess, 0x272a) }); },
  onLeave(ret) { send({ ev: 'clr26_out', n: this.n26 }); }
});
safeAttach('regA26', '0x1404fe7a0', {
  onLeave(ret) { send({ ev: 'regA26', ret: ret.toString(), sess: ret.isNull() ? 'null' : rPtr_26(ret, 0x1a8) }); }
});
safeAttach('regB26', '0x14010cda0', {
  onLeave(ret) { send({ ev: 'regB26', ret: ret.toString(), sess: ret.isNull() ? 'null' : rPtr_26(ret, 0x1a8) }); }
});
safeAttach('conn26', '0x14211eb45', {
  onEnter(args) { let s = this.context.rsi; send({ ev: 'conn26', f272a: rU8_26(s, 0x272a), f272b: rU8_26(s, 0x272b), st: rU8_26(s, 0x2270) }); }
});
safeAttach('idisp26', '0x14212217d', {
  onEnter(args) { send({ ev: 'idisp26', id: rU16_26(this.context.r13, 8) }); }
});
send({ ev: 'v26_armed' });
```
注：部署时须同步删除旧钩子 conn25（0x14211eb46，中部挂钩）与 idisp_id
（入口 r13 错读）；心跳 flush 阈值统一改 50。部署后以 node --check + PC 回读
hash 验活（v21 教训：语法检查未过不得传）。

### parent 注（部署时核对，2026-11-05 11:2x）
- **conn25 地址纠正**：本节称 v25 的 conn25 挂在 0x14211eb46（指令中部），与实际部署不符——部署脚本中 conn25 在 **0x14211eb9c**，经反汇编验证为干净指令边界（0x14211eb85 `je 0x14211eb9c` 的跳转目标，首指令 `call 0x140108860`），故“中部挂钩污染 10:01 连接期状态”的警告**不成立、作废**。conn25 读数 -1 的正确解释仅为读错寄存器（rcx 而非 rsi，会话在 rsi；同期反汇编亦证实 deadline 写点用 rsi）。v26 仍以 conn26（0x14211eb45，读 rsi）替换它，取更佳观测点，而非排污。

## 2026-11-05 evening24 — clear never returns

任务来源：v26 会话（2026-11-05 11:23–11:24，摘录 trace-1124-v26.txt）的五个新事实：
清旗进入未返回、0x9a 三路皆否、tick 会话指针同一、旗 0→1 无会话切换、
在跑的泵是帧内 0x1420e6d40。本章逐项闭合，结论分级标注。

### 24.1 清旗链全读：无等待原语，“循环等待”不成立

清旗组函数 0x14212cb20（短体）：prologue 保存 group [+0x100]/[+0xf8]/[+0xf0]，
rdi=[rcx+8]（组会话）；调 0x14212ae90；调复位 0x14211fdb0（rcx=rdi）；
尾 `xchg byte [rax+0x272a], sil`（rax=[rbp+8]，sil=0）后 epilogue + ret。
不返回只能发生在两个 callee 内。

0x14212ae90（向量操作）：纯有界工作——向量拷贝 + 连续重复去重 +
allocator 0x142bbaa10 / transform 0x141fc7380 / memmove 0x142cb75c0 /
溢出时 throw 辅助 0x1401433c0。**无等待、无锁、无自旋，不可能独自挂起。**

复位 0x14211fdb0（0x14211fdb0–0x1421202d6，ret 在 0x1421202d6）：
session rcx=r15；经 aggregate vtable +0x1e0 调 commit 0x14167b3f0（唯一直接
调用者是包装器 0x140b99180 的 0x140b991d1，reset 的调用是虚表调用，
scan_calls 看不见）；两个 u32 向量循环逐元素调 0x1421202e0（per-element ensure：
查 [session+0x2400+idx*8]，缺则 0x142150550 构建，追加到 [session+0x23e8]，
有界）；[agg+0x830/838/840] 三元组处理；[agg+0x98]+0x22e 检查调
0x14252a680；0x42 排序插入；对象向量虚表 +0x10/+0x78 调用；
0x1423cbba0、0x141731e60、memmove；尾部 [session+0x23e8] 循环调虚表 +0x58、
[agg+0xc8/0xd0] 循环调虚表 +0x18；0x142120176 处 `xchg [r15+0x272b], al`
（重臂 0x9a）；两次 free 0x142bba4e0；ret。**全程有界循环，无等待原语。**

commit 0x14167b3f0（头 0x510 字节 + 尾部抽查）：[agg+0x1b4] 类型检查
（0x21/0x23/0x20）、旗标字节 +0x663/+0x664、参数存 +0x4b0/+0x4b4、
0x141d02d20、0x14095efa0；尾部含 **registry 查找 0x141693840**
（0x14167bb22，miss → 经 0x142c14380 抛错，见 evening17）、
0x14161f5c0、0x141e763b0、0x1421d7070、0x140b271d0 等。
**commit 不调用 pump/fill/任何等待原语——“提交需泵”不成立。**
commit 的输入是 aggregate + 向量，全部在场；它不等待泵。

**判定（已实证链 + 推断）：** “清需提交、提交需泵、泵需清旗”的锁循环
**不成立**。清链中不存在等待原语，commit 也不依赖泵。清不返回的自洽
结构只剩两类：
- **(A) 异常死亡（首选，强推断）**：reset/commit 内某点抛 C++ 异常
  （头号嫌疑是 commit 内 registry 查找 miss，或某虚表回调抛错），异常沿
  reset → clear 展开，Frida onLeave 在异常展开时不触发——与“进入 0 次返回”
  的探针签名精确吻合。清线程死亡后旗永为 1，tick 线程继续跑但永远被门挡
  住（v26：tick 到 n=30 后死于门，不是死于主线程楔死——evening21 的
  “主线程楔死于挂起等待”推断需修正：主线程活着循环，死的是清线程）。
- **(B) 虚表回调内阻塞（备选，未排除）**：reset 尾部的 +0x58/+0x18 虚调用、
  commit 的 +0x1e8/+0x1b8/+0x10/+0x78 虚调用，其 callee 身份静态未知，
  其中某个监听回调可能等待。v27 以 throw + 各级 leave 钩子区分 A/B：
  throw 辅助 0x142c14380 在窗口内触发 → A；各级 leave 均无且 throw 无 → B，
  且缺失的 leave 直接定位卡住的函数。

附：clear 函数直接调用者 **0 个**（scan_calls 全镜像）：clear 只能经虚表/
函数指针到达，其调用者身份静态未知——v27 必须记 clrflag 的 returnAddress。
reset 的唯一直接调用者就是 clear 自身（0x14212cbd3），确认 reset 是 clear
的私有帮手。

### 24.2 0x9a 原始写路径：发送解剖 + 唯一可行的旁路

发送入口 0x14211fa00 全读（session rcx，message rdx）：
rdi=[session+0x20f8]（流）；置 [stream+0x240]=1；若 [stream+0x242]≠0 则
取 [stream+0x248] 锁（import 调用）；调 **消息虚表 +0x08**（rcx=msg，
rdx=stream）；释锁；[stream+0x240]=0；调时钟 0x140108860，写
[session+0x2258]=ticks*1000/divisor。

消息虚表 0x1434e53d8（.rdata 直读，已实证）：
+0x00=0x14015c940，**+0x08=0x141f38ae0（serialize）**，+0x10=0x141f38b80，
**+0x18=0x141f38c00（clone，evening23 的槽位说法证实）**。

serialize 0x141f38ae0 全读（rcx=msg，rdx=stream）：
id=word [msg+8] 经 import 字节序交换 → **流追加 0x142197fb0(stream, buf, 2)**；
byte [msg+0x10] → 追加 1 字节；dword [msg+0x18]、[msg+0x1c] 各经交换 →
各追加 4 字节。合计 2+1+4+4=**11 字节**，与网关 0x9a 长度一致。
消息结构：+0x00 vtable，+0x08 id(u16)，+0x10 u8，+0x18 tile，+0x1c doodad
（与 tick 构造器 0x142120dc0 的栈结构逐字段对应：[rsp+0x48]=id，
[rsp+0x50]=byte，[rsp+0x58]=tile，[rsp+0x5c]=doodad）。

tick 构造器 0x142120dc0 全读：`mov eax,0x9a; mov word [rsp+0x48],ax`；
vtable 由 rip+0x13c4602 取 = **0x1434e53d8**（即 0x9a 类虚表）；
tile/doodad 取自 **[agg+0x114]/[agg+0x118]**（区域生成算好存在 aggregate
里）；调 send 0x14211fa00；随后调 **流冲刷 0x142198110(stream, 0, 0)**。
结论：发送 = serialize 进流缓冲（不碰 socket）+ flush 推 socket。
**旁路的关键正在这里：任何绕过 send 的路径只要把 11 字节写进流缓冲
并触发一次 flush，字节就上网了，而 send26/clone26/mk9a 全程静默。**

其余 5 处 `mov eax,0x9a` 全分类（已实证，均非第二构造器）：
- 0x1414e6532 / 0x1414e68ee（成对）：0x9a/0x85 作 dword 字段值 + 字节 1，
  后接对象/字符串操作——是定义记录的枚举值，不是消息 id。
- 0x141e4f839：返回值 stub（`mov eax,0x9a; ret`，邻位 0x9b/0x97）——
  返回常量的小函数族，不是发送器。
- 0x1426982a1：指令中部误解码的假阳性（后续字节为垃圾）。
- 0x142751275：eax=0x9a 作参数调 0x142740a20，随后同函数又以 0x9b 调用
  一次——是按 id 查询/注册类操作，不是发送。
另：`mov word [..],0x9a` 直接写全镜像 **0 处**。故 tick 构造器仍是唯一
0x9a 构造点（evening23 结论维持），v26 的 0x9a 只能是：
- **(i) 直接 serialize 调用**：某区域生成完成函数手建 0x9a 消息
  （vtable 0x1434e53d8，id 0x9a，hash 取 agg+0x114/0x118）后直调
  0x141f38ae0，跳过 send；或
- **(ii) 直接流追加**：手组 11 字节调 0x142197fb0（该函数有数百个直接
  调用者——它是全游戏通用的流追加，静态枚举无用）+ flush 0x142198110；
- 二者都由 v27 的 serialize/append/flush 钩子在运行时区分（见 24.6）。
  另注意：v26 会话的 session 建于探针挂载之后，故“挂载前 tick 已建好
  0x9a 对象、事后发出”的缓存说在本会话**不成立**——发送代码必在挂载后
  跑过，只是没走 send/clone/tick 构造器三条线。

### 24.3 帧内泵驱动 0x1420e6d40 的归属：它泵的不是实例流

驱动本体（已实证）：rdi=会话样对象；[rdi+0xed8] 子对象旗标/引用处理、
字符串构建、hash 0x14218eaf0（种子 0x4f3e4ba1）、[rdi+0xee0]=1、
**[rdi+0xec8] 指针换出（旧者经 0x142197a10 + free 0x142bba570 释放）**、
调 0x1420e7410、[rcx]=r15+0x2710；尾部：rcx=[rdi+0xec8]，非空则
调 fill 0x142197bf0，随后 **循环 `call pump0 0x1421c5b90; test al,al;
jne loop`**；再 [rsi+0x251] 检查、[rdi+0xeb0..0xeb8] 监听向量虚表 +0x08
调用、[rsi+0x240]/[rsi+0x242] 处理 + 栈消息虚调用 [rax+8]、
流状态调 0x142198110、import 调用、[rbx+0x250]=0、帧时间 float 累计
[rdi+0x1080]/[rdi+0x1078]。**它是一个通用的每帧会话更新函数，不受
+0x272a 门控**——这正是它能跑而 tick 泵死的原因：两者根本不是同一泵。

尾部的栈消息解剖（已实证）：vtable 由 rip+0x141f485 取 =
**0x143506450**；其 +0x08 = **0x141f4b8a0**（另一 serialize：仅读
[msg+8] 作 id、交换、追加 2 字节）；+0x10 = 0x14010a080（ret 0 存根）。
栈消息 id 字 = r13w = **1**。故帧内驱动每帧发的是 **2 字节 id 1 消息**，
不是 0x9a（0x9a 需 11 字节）——帧内驱动不是 0x9a 发送者（排除）。

直接调用者 3 处（scan_calls，已实证）：
- 0x141007e59：rcx = **0x14010cea0() 的返回值**（getter，非空才调）；
- 0x141007e71：rcx = **0x141003f00() 的返回值**（另一 getter）；
- 0x140efcf33：rcx = rsi（上下文对象，非空才调，另带 rbx/xmm9）。
即驱动是“调用方给什么会话就泵什么”的通用函数。v26 中它约 4950 次
调用却一次也没分发 0x2f7/0x23（idisp26 仅见 17/30），故其 [rdi+0xec8]
**不是实例会话的流**（若是，pump0 循环必经 dispatcher 分发，idisp26
必见 0x2f7/0x23）。实例会话的流只由 tick 路径泵——tick 被门挡住，
0x2f7/0x23 就永远到不了 dispatcher。两泵不泵同一队列；0x2f7/0x23
没有经帧内泵入队（入队发生在 tick 泵的 fill 阶段，v23 已证字节已进
流缓冲、pump0 再未消费）。

归属待 v27 一锤定音：驱动入口记 rcx 与 [rcx+0xec8]，与 tick 会话指针
（v26 为 0x24630ce7000）及 [session+0x20f8] 比对；getter 0x14010cea0 /
0x141003f00 的返回值身份（登录会话？UI 会话？）亦在 v27 记一笔。
后台泵 0x14272fca0（流 +0x60，TLS 检查 + WSAEINTR 重试，v26 <50 次）
同理记其流参数——它若泵实例流，0x2f7/0x23 也应被分发，实际没有，
故它也不拥有实例流（待 v27 参数确认）。

### 24.4 翻转写入者再收窄：镜像内直接写已穷尽，翻转不在镜像内

v26 定量：tick 读同一会话指针 0x24630ce7000，旗在该对象上 0→1；
连接时旗=0（conn26，stale 旗说在本会话不支持）；0x29 零次；
清旗进入时旗已=1（clrflag26，组会话 = tick 会话，无会话切换）。

本章做的穷尽扫描（.text 全镜像，逐字节，指令形态分类）：
- disp32=0x272a 的 mov/xchg 存储：仅 **2 处**——0x29 case 的
  `xchg byte [r15+0x272a], al`（0x142122d44，al=1）和 clear 的
  `xchg byte [rax+0x272a], sil`（0x14212cbdc，sil=0）。
- 覆盖 +0x272a 的 dword/qword 存储（disp 0x2723–0x272a）：仅
  **1 处真写**——会话构造初始化 `mov dword [rsi+0x2728], 0xff00`
  （0x14211e6f0，字节：+0x2728=0x00，+0x2729=0xff，+0x272a=0x00，
  +0x272b=0x00——即 evening22/23 的“初值 0xff00”，是清零不是置位）；
  另一命中 0x1415f3af4 是指令中部误解码（真指令是 `mov edx, 0x2728`
  作 0x142b2d730 的参数），evening23 的假阳性判定正确。
- 覆盖 +0x272a 的 16 位存储：**0 处**。
- lock 前缀 RMW（or/and/xadd/bts/cmpxchg/inc/dec，disp=0x272a）：
  **0 处**。
- LEA 取 +0x272a 地址（供后续间接写）：**0 处**。
- 0x11 case（0x1421221be–0x142122346）无 272a 写；其内虽有
  `call 0x14211f920`（setter，0x14212228b），但 v26 setter23 零触发——
  该分支在本会话未走，setter 再次排除。
- 0x1e case（0x14212269f，尾部已补读至 0x142122cf7 附近）无 272a 写；
  但尾部有两处值得记：**`xchg [r15+0x272b], al`（0x142122c5c，
  r12d 未定值）与 `mov [r15+0x218b], 0`（0x142122c63）**——0x1e case
  自身就动 0x9a 重臂旗（+0x272b）与重臂目标（+0x218b），与 0x29 case
  的重臂操作同构。r12d 的值（0=解除重臂，1=挂起重臂）待 v27 在该点
  实测；无论哪值，它都不触 +0x272a，故与翻转无关。
- commit 头部无 272a/272b/2728 引用（store 扫描本就与函数无关，
  全镜像覆盖）。

**判定（已实证的排除链）：镜像内不存在第三个直接写点。** 翻转只剩
两类可能：(a) **跨模块写**（另一 DLL 经导出/回调写该字节）；
(b) **计算地址/区间写**（memset/memcpy/REP STOS 覆盖含 +0x272a 的
区间，或运行时算出的指针写——静态不可见）。会话切换说在 v26 已证伪。
v27 的翻转判别不靠静态：以 tick 会话指针为基准，在窗口内每个已挂钩
事件（commit 出入、world_register、wfactory、ifactory、pumpsec、pump0、
clear 入口）采样 [session+0x272a] 并记线程 id——最后一次 0 与第一次 1
之间的事件区间即翻转区间，线程 id 判定翻转线程（主线程 / 区域生成线
程 / 其他）。若翻转区间落在某 commit 内部，则深入该 commit 的虚调用。

### 24.5 网关判定：维持禁令，无确定性动作

- 0x2f7+0x23 的发送时机、顺序、字节在全部会话中一致， stall 点却
  各不相同（07:49 未分发、08:49/09:14 泵停、09:41 tick 未起、
  10:01 玩家未建、11:24 清旗未返）——仍是客户端侧竞态/状态问题，
  不是网关字节问题。
- 清旗未返的根因（commit 内抛错或虚回调阻塞）发生在客户端，与网关
  无关；网关无任何可观测信号能预判或修复它。
- 0x9a 的发送路径（直接 serialize 或直接流追加 + flush）同样是客户端
  内部行为；网关侧收到的 0x9a 字节本身无异常（11 字节，hash 正常）。
- **禁令维持**：不重排 0x9a burst（0x2f7 后 0x23）、不加盲延时、
  不重发 0x23、不发任何新消息（尤其 0x29）、不在 0x9a 前探 0x23、
  不猜 0x9a 发送者的字段修复。下一动作只能是 v27 的一次追踪会话，
  待其判别结果再定。

### 24.6 v27 钩子清单（只读、防洪水、禁用 .toNumber()、safeAttach）

沿用 v26 全部钩子（tick26s、idisp26、send26、clone26、clrflag26、
conn26、regA26/regB26、pdrv1_hb、pdrv2_hb、fdrv_hb、frame_hb、twrap_hb、
case29、setter23、timeout23、spin24、rearm24、throw_probe、v14–v20
遗留的创建链与 Melee 链）。新增/改动如下，**全部 safeAttach 包裹，
全部用 .toInt32()/toString()，不得用 .toNumber()**：

1. **清旗链阻塞点**（区分 A 异常死 / B 虚回调阻塞）：
   - clrflag27：0x14212cb20 入口 + 出口，记 rcx、[rcx+8]、**returnAddress**、
     线程 id。出口缺失 + throw 触发 → A；出口缺失 + throw 无 → B。
   - ae90_27：0x14212ae90 入口 + 出口（应极快返回；出口缺失则卡在此）。
   - reset27：0x14211fdb0 入口 + 出口（记 rcx 会话）。
   - commit27：0x14167b3f0 入口 + 出口（提交稀少，全记；入口有、出口无
     → 卡在 commit 内，再按 24.1 的虚调用点细分）。
   - throw27：0x142c14380 入口，记 returnAddress + 线程 id（实例期应稀少；
     若在 clear 窗口内触发，即 A 的直接证据）。
2. **0x9a 原始写点**（三路 choke 点，C→S 发量小，不洪水）：
   - ser9a27：serialize 0x141f38ae0 入口，记 [rcx+8] 的 id（u16）、rdx 流指针、
     returnAddress。send26 静默而此处 id=0x9a 触发 → 直接 serialize 路径，
     returnAddress 即原始构造器。
   - app9a27：流追加 0x142197fb0 入口，**仅当 r8==11 且 buf 前 2 字节为
     00 9A 时记**（精确 0x9a 签名，零洪水）；触发 → 直接流追加路径，
     returnAddress 即原始组包点。
   - flush27：流冲刷 0x142198110 入口，记 rcx 流指针 + returnAddress，
     上限 5000 行后只计数（帧内驱动若每帧冲刷，此量可控）。
   - ser1_27（对照）：帧内 serialize 0x141f4b8a0 计数（应为 id 1 的 2 字节
     消息，确认帧内驱动与 0x9a 无关）。
3. **帧内泵驱动出入 + 队列**：
   - pdrv27：0x1420e6d40 入口，记 rcx 对象指针、[rcx+0xec8] 流指针、
     returnAddress；**同一 rcx 只记首次**，其余只计数（4950 次不刷屏）。
     与 tick 会话指针、[session+0x20f8] 比对定归属。
   - pdrv2_27：后台泵 0x14272fca0 入口，记流参数 + returnAddress（稀少，全记）。
   - getA27/getB27：0x14010cea0 / 0x141003f00 出口，记返回值（判定帧内
     驱动泵的是哪类会话）。
4. **翻转窗口写点**（采样 brackets + 线程判定）：
   - 以 tick 会话指针为准，在 commit27 出入、world_register、wfactory、
     ifactory、pumpsec23、pump023_out、clrflag27 入口各采样一次
     [session+0x272a] 并记线程 id；最后 0 与首 1 之间的区间即翻转区间。
   - rearm1e27：0x1e case 的重臂点 0x142122c5c 入口，记 al（r12d）与旧
     [r15+0x272b] 值——定 0x1e case 是挂起还是解除 0x9a 重臂（与翻转无关，
     但补齐重臂语义）。
5. **部署门**：node --check 必过才传（v21 教训）；PC 回读 hash；
   runner 验活（WMI 脱离会话，见 02:17 教训）；客户端重进才加载新探针；
   严格时间戳过滤复核（10:01 教训）。

### 24.7 读序

1. throw27 + clrflag27/ae90_27/reset27/commit27 的出入（定 A/B 与卡点）
   → 2. ser9a27/app9a27/flush27（定 0x9a 原始写路径与构造器）
   → 3. pdrv27 + getA27/getB27（定帧内泵归属）
   → 4. 翻转采样 brackets + 线程 id（定翻转区间与线程）
   → 5. rearm1e27（补重臂语义）。
   任一步出确定性结论即停，不必等全量；网关动作仍需等 v27 会话判别。

## 2026-11-05 evening25 — three functions never return

任务来源：v27 会话（2026-11-05 11:42，pid 49588，镜像基址 0x7ff669990000，
摘录 /tmp/q27b.out）的关键矛盾 + 三个探针失误的纠正。结论分级标注。

### 25.0 先纠正：任务简报里的三个返回地址换算错了 0xF0000（已实证）

原始 runtime 地址（trace 原文）+ 基址 0x7ff669990000 的正确换算（Python 复核，
VA = runtime − base + 0x140000000）：

- clear ra 0x7ff66a9ac08f → **0x14101C08F**（与简报一致）
- ae90 ra 0x7ff66babcb8f → **0x14212CB8F**（简报写 0x14121CB8F，低了 0xF0000）
- reset ra 0x7ff66babcbd8 → **0x14212CBD8**（简报写 0x14122CBD8，低了 0xF0000）
- commit ra 0x7ff66baafe35 → **0x14211FE35**（简报写 0x14121FE35，低了 0xF0000）

简报的四个值不可能出自同一基址（clear 要求基址 0x7ff669990000，其余三者
要求基址 0x7ff66a890000）——换算口径不一致，属简报错误，不是探针错误。
连带纠正：evening20 对 commit ra 的“中指令地址”担忧作废——在正确 VA
0x14211FE35 处是 `call r10` 后的 nop，是干净返回点；evening20 当时在错误的
0x14121FE35 处反汇编，恰好落在另一函数的中部，误判。

### 25.1 清旗真实调用图：evening24 的链全部证实，所谓矛盾不存在

clear 0x14212cb20 逐字节复核（与 evening24 一致）：prologue → call ae90
（0x14212cb8a，返回点 0x14212cb8f）→ lea/mov → call reset（0x14212cbd3，
返回点 0x14212cbd8）→ `xchg byte [rax+0x272a], sil`（sil=0）→ ret。

四个 ra 的归属（全部已实证）：

- clear ra 0x14101C08F：`call qword [rax+0x10]`（0x14101c08c）的返回点——
  clear 经虚表 +0x10 被调用（evening24“0 个直接调用者，只能经虚表/函数指针”
  证实）；调用方函数在做 refcount 递减（lock dec）+ 调 0x14101b880，形态为
  facet 析构/清理函数。
- ae90 ra 0x14212CB8F：恰好是 clear 体内 ae90 调用的返回点——
  **clear 确实调了 ae90**。
- reset ra 0x14212CBD8：恰好是 clear 体内 reset 调用的返回点——
  **clear 确实调了 reset**。
- commit ra 0x14211FE35：reset 体内 `mov r10, [rax+0x1e0]`（0x14211fde2，
  rax=[rcx] 即 aggregate 虚表）+ `call r10`（0x14211fe32）的返回点——
  **reset 确实经 aggregate 虚表 +0x1e0 调了 commit**。

结论：调用链 clear → ae90 → reset → commit（虚表 +0x1e0）全部成立，
evening24 无错。任务简报的“矛盾”纯系换算错误。

### 25.2 未返回之谜：不是矛盾，是调用链的必然签名

时序（:47）：clear 进入 → ae90 进入 → **ae90 返回** → reset 进入 → commit
进入 → commit/reset/clear 出事件全 0；tick 随后 n=3（旗 1）→ n=60，
:48 世界实体登记波，:50 全静默、进程死亡（死因未从本 trace 定性；与各会话
0x2f7 后约 17–20 秒断开的 recurring 模式一致，不另立说）。

解释：ae90 在 commit 死亡之前已完成并返回，故 ae90_out 存在；commit 死后，
reset 与 clear 永远等不到返回，故二者出事件缺失——这是“死在链底”的标准
签名，不是矛盾。简报的前提“清旗必先返回”倒置了调用顺序：clear 只有等
reset 返回才能返回，reset 只有等 commit 返回才能返回。

死亡机制再收窄（已实证排除链）：

- **排除 C++ 异常经共享助手 0x142c14380**：throw27 在 :47 窗口为 0；且
  commit（0x14167b3f0 起至少 0xC00 字节内）与 registry 查找 0x141693840
  体内均无对 0x142c14380 的直接调用（scan_calls：该助手共 10501 个直接
  调用点，其中 0x14167/0x14168/0x14169 段内无一落在 commit 或 lookup 范围）。
  故若为异常，必经其他路径。
- **剩余三类**：(a) SEH 捕获的硬件 fault（空/野指针解引用——commit 内多处
  [agg+0x98]/facet 指针解引用，某 facet 缺失即 AV；被上层 SEH 捕获后继续
  执行，与 :48 登记波、tick 继续、进程存活全部吻合）；(b) commit 内自旋/
  死锁（registry 查找入口先调函数指针 0x14009e1e0——带 0x5c47/0x49d3/
  0x49cb ID 的同步原语形态；若该锁被等待旗标的线程持有，即死锁；锁持有者
  未知）；(c) 其他抛错助手（std 异常经 _CxxThrowException 直调，不走
  0x142c14380；ensure 的分配失败属此类）。
- 线程归属未定：v27 未记 ae90/reset/commit 的 tid（探针缺口，v28 已补）——
  :47 的 clear（tid 37228）与 ae90/reset/commit 是否同线程，须 v28/v29 实测。
  但注意：若 clear 与组装在同一线程，则 clear 的 ae90/reset 调用就是观测到的
  那两次（ra 已证实），单线程说更简洁；双线程说要求另有一组 ae90/reset
  调用（ra 应不同），而观测到的 ra 恰好就是 clear 体内的——故**单线程链是
  更优解释（推断）**，v28 的 tid 将一锤定音。

### 25.3 commit 死亡点候选（按嫌疑排序）

commit 0x14167b3f0 已读范围（头 0xC00+ 字节至 0x14167c400+，尾部未定位——
未找到 `add rsp,0x4f0` 式 epilogue，函数很长，确切终点待查；已读部分无
Sleep/Wait/Lock 导入——仅 GetTickCount（导入槽 0x142E89410）与
QueryPerformanceCounter（导入槽 0x142E89420）两个计时导入；无对
0x142c14380 的直接调用）。

候选排序：

1. **registry 查找 0x141693840 的逐元素循环（0x14167bb00–0x14167bb3f）**：
   commit 内唯一“查表”类操作；查找入口先调函数指针 0x14009e1e0（带
   0x5c47/0x49d3/0x49cb ID 的同步原语形态——疑似锁获取）；循环内逐元素调
   lookup + refcount juggling（lock dec/inc at +0x3c）。死法：锁等待
   （死锁）或某元素键缺失后的空解引用（AV → SEH）。**头号嫌疑**。
2. **ensure 0x141681720（0x14167b8ce）**：evening6 的懒分配 ensure；分配失败
   → std bad_alloc（不走共享助手）→ 若被上层捕获则吻合；否则进程应死
   （未死），故次于 (1)。
3. **尾部 0xb0 步长循环（0x14167c15f 起）**：调 0x1411d2150/0x1411d4950/
   0x1411d23f0 + 虚表 +0x1b8（0x14167c2a8）；callee 身份未全定，属开放候选。
4. **已排除/降级**：visitor 段（0x14167b7d1–0x14167b8cb）：所建 functor 的虚表
   0x1433ADD30 的 +0x20 槽 = ret 0 存根、+0x130 槽 = xor al,al;ret（返 false）
   ——可达方法皆为空操作，死于此段的可能性低（但 call rdi 与
   [rax+0x20]/[rax+0x130] 的 rax 身份未全程追踪，留一分余地）。

### 25.4 0x9a 冲刷问题：append 的冲刷是“装不下才冲”，0x9a 走的是无冲刷路径

append 0x142197fb0 全读：缓冲 [stream+0x280]、游标 [stream+0x258]；仅当新
数据装不下时才调 flush（0x142198043，r8b=1），仍装不下则调 0x142198820，
仍失败且 [stream+0x253]==0 时再调 flush（0x14219807d，edx=0xa）；超 2MB
走另路（0x1421980c4）。**11 字节的 0x9a 追加到空缓冲永远不触发 append 内
冲刷**——故 0x9a 的 4 次追加无 flush27 事件是符合设计的，不是探针漏记。

冲刷函数 0x142198110 本体：取 SRW 锁（AcquireSRWLockExclusive，导入槽
0x142E89308）+ 流虚表 +0x10/+8 调用 + OpenMutexA（导入槽 0x142E89518——
该导入出现在冲刷体内不合常理，疑为另一分支的导入，待复核；不影响
flush27 的结论）——直接调用点共 575 处（含 tick 的 0x142120e0f、append 内
3 处、帧内驱动的尾部调用）。

结论链：0x9a 在 :49.906 到达网关，而 :47 后 flush 0x142198110 零调用
（flush27 计数仅 6，远低于 100 的全记上限——零是真零）；ser9a27=0
（0x9a 类 serialize 0x141f38ae0，虚表 0x1434e53d8 的 +0x08 槽，零触发——
直接 serialize 说已证伪；附注：id 15/14 消息用不同虚表，其 serialize 不走
此钩子，故 ser9a27=0 与 send26×2 不矛盾）；tick 的 send/flush
（0x142120dfe/0x142120e0f）在 +0x272b 块内，而 0x1e 尾把 +0x272b 置 0
（rearm1e27：al=0）→ tick 的冲刷路径关闭。故 **0x9a 的发送既不走
send/serialize，也不走 flush**——只剩：(i) 直接 socket 写（WSASend/send
直调，绕过流缓冲与冲刷；HNC 加密须由该路径自行处理或复用流加密函数）；
(ii) 另一流/另一冲刷实现（第二冲刷函数——静态待查：凡调
AcquireSRWLockExclusive 且操作流缓冲的函数）；(iii) app9a28（v28 首块过滤）
若亦为 0，则连 append 都没走，(i) 的权重上升。
注意：socket 层看到的是 HNC 密文，无法以 00 9A 明文过滤——v29 的 socket
钩子须以小长度（≤128 字节）+ 时机（:49.9 附近）+ 返回地址判别。

### 25.5 网关判定：维持禁令

清旗链死亡与 0x9a 旁路发送均为客户端内部行为；网关字节在全部会话一致，
stall 点各异；无可观测信号可预判或修复。禁令维持：不重排 burst、不加盲
延时、不重发 0x23、不发任何新消息（尤其 0x29）、不在 0x9a 前探 0x23、
不猜字段修复。下一动作只能是 v29 的一次追踪会话。

### 25.6 v29 钩子清单（只读、防洪水、禁用 .toNumber()、safeAttach；沿用 v28 全部钩子）

1. commit 死亡定位三件套（均记 tid + 序号；出事件缺失即卡点）：
   - visit29：0x14169c8a0 出入（visitor 段入口；log all，稀少）。
   - ensure29：0x141681720 出入（log all，稀少）。
   - reglookup29：0x141693840 出入 + 序号（逐元素循环——每对出入记 seq；
     entry 无对应 leave 即死在某次查找内；循环有界，不洪水）。
   - unwind29：经 Frida Module.getExportByName('ntdll.dll','RtlUnwindEx')
     入口记 tid + ra（SEH/C++ 展开的直接证据；展开触发 → 25.2(a)；全程无
     → 自旋/死锁 (b) 或线程被杀）。
   - worldreg_tid：给现有 world_register 钩子补 tid（:48 波与 :47 链是否同
     线程，判别“组装继续”与“清线程独死”）。
2. 0x9a 发送路径三件套：
   - 保持 app9a28（首块 len==2 且 buf=00 9A）与 flush28（带 stream 参数）——
     读序先看二者。
   - wsasend29：经 Module.getExportByName('ws2_32.dll','WSASend') 与
     ('ws2_32.dll','send') 入口，仅当总长度 ≤128 字节记（tid + ra + 长度 +
     前 16 字节 hex；密文故不按内容过滤；大流量自动排除）。
   - （静态跟进，非探针）第二冲刷函数搜查：凡调 AcquireSRWLockExclusive
     且读写流缓冲（[stream+0x258]/[stream+0x280] 族偏移）的函数列入 v30 候选。
3. 翻转窗口补点（v28 已有 case1e_tail28；v29 补）：在 0x1e case 尾
   （0x142122c63 之后）到 clear 入口之间，若有已挂钩事件，采样 [tick 会话
   +0x272a]——沿用 v27 的 flipSess 机制，记 tid。
4. 部署门：node --check 必过才传；PC 回读 hash；runner 验活（WMI 脱离会话）；
   客户端重进才加载；严格时间戳过滤复核。

### 25.7 读序

1. visit29/ensure29/reglookup29 的出入 + unwind29（定 commit 死在
   visitor/ensure/查找三段中的哪一段、死法是展开还是自旋）→ 2. app9a28/
   flush28/wsasend29（定 0x9a 是 append+直写、还是另一冲刷、还是连 append
   都没走）→ 3. worldreg_tid + v28 的 ae90/reset/commit tid（定 :47 链与
   :48 波的线程关系）→ 4. 翻转采样（补窗口）。任一步出确定性结论即停。

### 25.8 探针失误登记（我方认领）

1. **app9a27 的 len==11 过滤错误（v27）**：0x9a 由 serialize 的 4 次追加
   （2/1/4/4 字节）建成，不存在一次 len==11 的追加；故 app9a27=0 是探针失误，
   不是“无直接追加”的证据。已在 v28 改为首块过滤（len==2 且 buf 前 2 字节
   为 00 9A）。
2. **getA27/getB27 洪水（v27）**：两 getter 每帧调用，30 次采样仍刷屏；已在
   v28 改为仅变化记（删洪水版）。
3. **ae90/reset/commit 初版未记 tid（v27）**：致 :47 窗口的线程归属未定
   （单线程链 vs 双线程之争本可用 tid 一锤定音）；已在 v28 补 tid。
4. **（本章新增）任务简报的 VA 换算错误**：ae90/reset/commit 三个返回地址各
   低了 0xF0000，制造了并不存在的“调用图矛盾”；本章以原始 runtime 地址 +
   基址重算纠正（见 25.0）。教训：返回地址换算须以原始 runtime 值为准、
   双人复核，凡“落在指令中部”的返回地址先疑换算、再疑代码。

## 2026-11-05 evening26 — the session that never ticked

12:19 会话（pid 35848，探针 v29）悖论裁决 + 第二冲刷搜查 + v30 清单。
换算规矩（evening25 教训）：VA = 0x140000000 + (runtime − 基址)，双锚点复核——
hook_fail（VA 0x14140E3CF → runtime 0x7FF66AD9E3CF）与 evening25 修正值（ae90 ra →
0x14212CB8F）双双通过。本章全部换算均经此复核。

### 26.1 时间归属裁决：区域世界从未建成，tick 从未跑（已实证）

- 挂载干净：12:18:55 一次挂载到 pid 35848（与 Client.txt 一致），全会话唯一
  hook_fail 为已知 melee_vcall_pre；错挂他进程说排除。
- :56 aggctor/wctor/commit：同一 aggregate（0x34407f96020），commit ra → VA
  **0x140EDF56C**（= 08:17/08:49 的登录提交驱动返回点），aggctor ra →
  **0x140ED96AE**（登录区组装调用者，≠ 区域驱动 0x14100B97E）——**登录世界**，
  不是区域世界。
- :58–:06 world_register ×227（tid 17280 = 登录线程，id 0xC0000001–0xC00000DB）
  = 登录世界实体登记波。
- :10 visit29 ×4（seq 1–4）+ ensure29 ×1（seq 5），tid 17280，**无 commit27**——
  登录期遍历（见 26.3 之谜），不是区域提交。
- **区域提交全会话仅 :56 一次（即登录提交）；区域提交从未触发。**
- 12:18:55–12:19:40 窗口内：tick26s/tick23/case1e/idisp26/send26/conn26/clrflag27/
  tickstream29/regA26/regB26/frame24/twrap24/fdrv25/pdrv125/pdrv225 **全为 0**；
  帧驱动、tick 注册、tick、分发、清旗、发送——驱动层**一次未接合**。
- 但工厂洪水（fact_in/out 各 49,731 对）持续到 :22，脚本活着；网关同会话
  0x1e :17.893、0x9a :22.234、0x2f7+0x23 :22.237、Client.txt MeleePlayer WARN :22。
- **裁决：这是比以往更早的新停摆高度——驱动层从未接合**（此前会话均为
  “接合后死于清旗/commit”）。**不是探针局部失效**：钩子在窗口内活着
  （工厂/登记/visit/ensure/ao_attach 均触发）；唯一探针致盲是三个导出钩子
  的 API 错误（见 26.6），而 tick/分发链钩子均为普通 Interceptor.attach 且
  无 hook_fail——它们的零是真零。附注：conn26=0 仅为单指令钩子，证明力
  弱于 tick26s/idisp26/case1e 的联合零值；后者才是“链未接合”的实证。

### 26.2 WARN 来源裁决：rowapp 有 19 个调用点，WARN 从不需要实体构造（已实证）

- rowapp 0x14140ea70 直接调用点共 19 处：仅 4 处为实体路径包装器
  （0x141471cd8、0x141471d00 jmp、0x141471d28、0x141471d68）；其余 15 处
  （含 9 点 0x14157 簇：0x14156b2b0、0x141572e18、0x14157a0f7、0x14157c088、
  0x14157c508、0x14157d038、0x14157db7e、0x14157ee68、0x141597904，及
  0x1413cabd8、0x1413d81b8、0x14145939e、0x14145c6f8、0x1414896b8、
  0x14148a6e0）所在函数均**无直接调用者**——经虚表/函数指针分发的多态
  动作客户端构造系统。
- 三会话（11:42、11:56、12:19）WARN 均在 createobj=0、entity_ctor=0、fnC=0
  下发出——**WARN 从未证明玩家序列进展**（evening18 的降级结论加强为
  实证：WARN 与玩家 blob 构造无关）。
- WARN 时序恒与 0x9a 同秒、与登录无关 → 推断：区域进入时的动作客户端
  构造，最 plausibly 区域生成线程（evening22 已证其独立于分发）。精确
  调用点待 v30b 的 rowapp30（记 ra）一次定点。

### 26.3 :10 visit/ensure 之谜（已实证 + 待判）

- visit 0x14169c8a0 唯一直接调用点 = commit+0x450（0x14167b840）；
  ensure 0x141681720 唯一直接调用点 = commit+0x47e（0x14167b8ce）。
  但 :10 visit×4+ensure×1 发生时 commit27 为 0。
- 候选：(i) 间接/虚表调用（scan_calls 对间接调用盲区；facet/visitor 模式
  正用间接调用）；(ii) commit 中部进入绕过入口钩子。
- 判别（v30b）：commitmid30（0x14167b840 计数+tid）——visit29 发而
  commitmid30 不发 → 间接调用；两者同发而 commit27 不发 → 中部进入。

### 26.4 第二冲刷函数搜查：无确认候选（已实证）

- flush 0x142198110 本体结构：[stream+0x248] SRW 锁、[+0x242] 旗、
  [+0x258]/[+0x260] 缓冲游标、[+0x280] 基、[+0x190] 槽 +0x10 与 [+0x1b8]
  槽 +8 传输虚表调用（即 socket 写经传输虚表，非 flush 直调 WSASend）。
- 锁槽确认：flush 内 `call [rip+0xcf118e]` 目标 = **0x142E89308 =
  KERNEL32.dll AcquireSRWLockExclusive**（IAT 查表证实；附注两次算术
  纠正：PE32+ 数据目录偏移为 112 非 96；rip 目标为 0x142E89308 非
  0x1430A908——凡换算先疑自己，再疑代码）。
- 锁调用字节扫描：1900 处——锁极通用，非有效过滤器。
- 偏移窗口过滤（±0x400 内含 +0x248/+0x258/+0x260）：20 处，含 flush 本身
  （ sanity check 通过）。同对象校验（寄存器别名干扰：flush 本身以 rcx
  取锁、以 rbx 读游标）：
  - 3 处为发送完成型：0x140ed80a0 族——清 [stream+0x240] 后**调已知
    flush**（其一冲刷 [r14+0xec8] 流；+0xec8 与帧内泵驱动的流字段同偏移，
    为“会话→流”字段的另一证据）。此类路径仍会触发 flush28，**不是**
    隐藏路径。
  - 16 处未决（锁参计算超出窗口或别名寄存器，邻函数污染未排除）。
- **结论：无确认的第二冲刷函数。** 且 0x9a 在全部观测会话中均无 flush28
  事件 → 0x9a 不经已知冲刷；直接 socket 写权重最高，待 v30 的 wsasend29
  实证（小长度 + 时机 + ra 三重判别；socket 层为 HNC 密文，不按内容过滤）。

### 26.5 runner 纠正（parent 核实，我方记录）

- **“双开”说不成立**：43756（ppid 7980，venv 启动器）→ 19848（子进程，
  真 Python 解释器），同跑 run_km.py——**同一个 runner 的父子对**。
  pid 变化（7768→2104→40428）= 每次抓到的父子成员不同 + 杀/重启 churn。
- 杀 2644 很可能杀掉了当时工作 runner 的一半（parent 认领）。
- v30 规则：识别 runner 以父子对为准；**不得按单个 pid 杀**；健康检查 =
  对存活 + 日志增长；重启 = WMI 脱离会话 + 验对 + 验 polling。

### 26.6 探针失误登记

1. v29 三导出钩子 API 名错误：`Module.getExportByName` 在 Frida 17.25.1
   里根本不存在 → unwind29/wsasend29/send29 全挂（12:18:55 三条 nohook
   事件证实）。故 12:19 会话中三者为 0 是探针失误，**不是**会话事实。
   v30 已改 `Module.findExportByName` + 空值守卫（parent 部署，PC 回读
   FA78D14A… 一致；截至本章 log 中尚无 v30_armed，即尚未有会话加载）。
2. runner 双开误判 + 误杀 2644（见 26.5，已纠正）。
3. 重申 evening25：VA 换算以原始 runtime 值为准、双锚点复核。

### 26.7 v30 清单

- **已部署（parent，哈希 fa78d14a，PC 回读一致，未加载）**：导出钩子改
  `Module.findExportByName` + 空值守卫。
- **待加 v30b**（只读、防洪水、禁用 .toNumber()、safeAttach）：
  1. 导出延迟重试：若 ws2_32 晚加载导致 find 返回空，定时重查（或模块
     加载触发重挂）。注：ws2_32 启动即加载，空值更可能为 API 误用——
     重试为保险，非主因。
  2. runner 父子对识别（26.5）：健康检查与重启流程按父子对写死进
     runner 运维，不再以单 pid 为准。
  3. 日志轮转（179 万行，读取已很慢）：**不停探针轮转不可行**——runner
     常开句柄跟随重命名后的旧文件，重命名不改变写入目标。正确方案：
     仅在游戏未运行时停 runner → 重命名 km_capture.log →
     km_capture.<date>.log → 起 runner；另降增长：高频钩子只计数
     （工厂洪水每会话约 5 万对尚可，1.79M 主因是多会话累积）。
  4. 新判别钩子：rowapp30（0x14140ea70 入口，ra+tid，前 100 详记后计数）
     ——WARN 精确调用点；commitmid30（0x14167b840 计数+tid）——:10 之谜；
     maindrv30（0x141007860 计数心跳）——主循环是否走到帧驱动分发；
     保留 v29/v28 全部钩子（wsasend29 为 0x9a 首要判别）。
- **读序**：wsasend29/send29（0x9a 是否 socket 直写）→ rowapp30 ra（WARN
  调用点）→ commitmid30 vs visit29 vs commit27（:10 之谜）→ tick/idisp/
  clear 链（驱动层本次是否接合）→ regA/regB（注册是否发生）→ worldreg
  tid（登记波线程）→ 翻转采样；任一步出确定性结论即停。
- 部署门：node --check 必过、PC 回读 hash、runner 父子对验活、客户端
  重进、严格时间戳过滤。

### 26.8 网关判定：禁令维持

- 网关字节全会话一致；12:19 会话无任何网关可见前置信号；停摆纯属
  客户端驱动层接合问题。禁令维持：不重排 burst、不加盲延时、不重发
  0x23、不发任何新消息（尤其 0x29）、不在 0x9a 前探 0x23、不猜字段修复。
  下一动作只能是 v30b 的一次追踪会话。
