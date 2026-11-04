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
