# LocalExile2 — porting the LocalExile PoE1 server emulator to Path of Exile 2

Goal: a local private server for the **Path of Exile 2** Steam client
(`PathOfExileSteam.exe`, installed at
`C:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2\`), keeping the
real client as the renderer — the approach proven by
[LocalExile](https://github.com/LocalExile/LocalExile) for the PoE 3.29.3b client.

## Status snapshot (wave 0 — recon complete, baseline validated)

| Item | State |
|---|---|
| LocalExile baseline clone | done (depth 1, upstream main) |
| .NET 10 SDK | installed via winget |
| `dotnet build GameServer.slnx -c Release` | **passes** |
| `dotnet test tests/GameServer.Core.Tests` | **415/415 pass** |
| PoE2 client recon (login crypto) | **done — see findings** |
| PoE2 client recon (DH groups) | **blocked — needs disassembly** (see next wave) |
| PoE2 gateway/instance protocol | not started |

## Recon findings (2026-10-30, client build of 2026-10-08 install)

1. **Gateway list is a plain file.** `gateway_list.txt` (UTF-16) ships in the
   install dir: `<region>;...;<login host>:<port>;<speedtest host>;false`,
   e.g. `dal.login.pathofexile2.com:21262`. Unlike PoE1 there is no baked-in
   ggpk gateway list to patch — redirect via this file / hosts + DNS.
   Patch server (also plain strings in the exe): `us.patch.pathofexile2.com:13060`.
2. **Login crypto is the same family.** CryptoPP present; `Salsa20`, DH and
   DSA/SHA-1 strings all in the binary.
3. **The DSA verify key blob is findable and structurally identical.** The
   X.509 SubjectPublicKeyInfo DER prefix
   `308203423082023506072a8648ce380401` occurs **exactly once**
   (file offset `0x2f0b650` in the shipping exe) and parses as
   DSA p=2048 / q=224 — the same size class as PoE1, so
   `ClientImage.VerifyKeyLength == 0x346` still holds and
   `ClientImage.FindUnique` works **unchanged**.
4. **But the key blob adjacency changed.** PoE1 layout (see
   `src/GameServer.Core/Protocol/Login/LoginKeys.cs`):
   verify key `+0x000`, client static private `+0x350` (384 B),
   server static public `+0x4d0` (384 B). In PoE2, `+0x350` is **zeroed** and
   `+0x4d0` holds unrelated .rdata pointers (input-device name strings).
   → `ClientStaticPrivateOffset` / `ServerStaticPublicOffset` must be
   re-derived; the DER-prefix locator itself ports as-is.
5. **The PoE1 DH groups are gone.** Neither the 3072-bit static group
   (`cd8fd4b7...`) nor the 1024-bit ephemeral group (`c5d1fff6...`) from
   `LoginGroups.cs` appears in the PoE2 exe. PoE2 ships different DH
   parameters (or a changed handshake). They must be recovered from the
   login crypto object (PoE1: the "Rhoa" ctor `0x140e02170`; PoE2 address TBD)
   by disassembly.

**Implication:** the port's hardest open problem is *one* thing — recovering
PoE2's DH2 static + ephemeral groups (and confirming the Salsa20 key-material
layout `km = SHA-512(Z_static || Z_ephemeral)` and IV split still hold).
Everything else in the login stack is expected to port with small edits.

## Next waves (in order)

1. **DH group recovery.** Disassemble `PathOfExileSteam.exe` (Ghidra 12.1.x +
   JDK, or objdump from msys64 mingw64) around the CryptoPP DH2 / login init;
   extract the static (3072-bit) and ephemeral (1024-bit) group constants and
   verify `p = 2q+1`. Update `LoginGroups.cs` (or load from JSON per client
   version) and the `ClientImage` offsets from wave-0 findings.
2. **Client patcher bring-up.** Run `GameServer.Auth keygen/patch` against the
   PoE2 exe (expects a patched `ClientImage` layout); confirm the client
   accepts a locally signed login handshake.
3. **Redirection.** Point `gateway_list.txt` login entry at 127.0.0.1 (ports
   configurable); stand up the patch-server stub so the client never calls
   `us.patch.pathofexile2.com:13060`.
4. **Login flow.** Account creation + character list. Expect PoE2-specific
   message set changes (new message ids; PoE2 has 12 character classes and
   different league/leagueless structures).
5. **Gateway (instance server) bring-up.** Zone load, player object, movement,
   visibility. PoE1's gateway message catalog is the template; each id must be
   re-verified against PoE2 traffic (sniff live sessions with a Salsa-constant
   memory scan, cf. the exileSniffer approach).
6. **Data layer.** PoE2 uses the same `Bundles2`/`.index.bin` container family;
   `GameServer.Data` readers need PoE2 `.dat` schema updates. (There is already
   local tooling at `C:\PoEPeek\PoeBundlePeek` that reads PoE2 bundles.)
7. **Simulation.** Hideout/town instance flow first (fixed layouts, seed 1),
   then monsters, loot, skills — the long tail.

## Environment notes

- Build: `dotnet build GameServer.slnx -c Release`
  (dotnet at `C:\Program Files\dotnet\dotnet.exe`).
- Tests: `dotnet test tests/GameServer.Core.Tests -c Release`.
- PoE2 install: see header. `logs/Client.txt` confirms the account plays on the
  live servers — when sniffing, avoid touching the live account; prefer a
  throwaway login.
- Client version pinning: record the exe SHA-256
  (`d46f4c27576122afc41a428eef96b3b4c75592a16827ed8c2204508ab06a455d` at recon
  time) and treat every Steam update as a protocol change.

## Repo/push convention

`git push` hangs on this machine — publish via the GitHub REST Git Data API
(blobs → tree → commit → ref) using the PAT for user `Ehco` in
`C:\Users\Administrator\.git-credentials`. Never print the token.
