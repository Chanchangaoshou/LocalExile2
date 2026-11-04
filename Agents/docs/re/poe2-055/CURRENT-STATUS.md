# LocalExile2 — current status & handoff (2026-11-04 17:25 CST)

Cold-start file for any AI picking this project up. Deep evidence lives in
`INSTANCE-RE-NOTES.md` (through evening5), `CLASS-DISPLAY-NOTES.md` (§6),
`POE1-LEFTOVER-MAP.md`, `ITEM-TABLES-REEXPORT.md`; the problem list with
verdict tables is `OPEN-PROBLEMS.md`. Project ground rules: everything
from the 0.5.5 client's own evidence — **no PoE1 code/data**; conclusions
graded 已实证 (proven) / 推断 (inferred) / 待验假设 (hypothesis);
one variable per live session; do not ask the user to test until the
build is deployed and verified (git HEAD + exe timestamp + ports).

## Live builds on the user's PC (D:\LocalExile2, all verified 2026-11-04)

| Component | Commit | Exe built | State |
|---|---|---|---|
| Gateway (6112 + bridge 7010) | `c69313c` | 17:12:01 | **S1 experiment armed** (see below) |
| Auth (21260) | `5fd6fd0` | 17:20:31 | class fingerprint + leftover fixes; Core **424/424** |
| Patch stub 13060 / HTTPS 443 | — | — | listening; watchdog covers restarts |

Services are started detached via WMI runner bats under `Tools\`;
a watchdog (`Tools\le2-watchdog.ps1`, logon + 30-min scheduled tasks)
restores the four `hosts` redirects and any dead listener. Kill switch:
`Tools\watchdog.off`.

## S1 verdict (2026-11-04 17:29 session, probe-proven)

The 0x23 was dispatched, the callback ran, **activation fired for the
first time ever**, and the value 1000 is confirmed in the aggregate
(v11c=1000, area98 non-null, fc8=0). The client then crashed in the
callback's tail: access violation at **0x142ac16b0**, called from
0x1416820bd inside 0x1416820a0, with **[agg+0x1270]=0** — the field
the tail call consumes. Same signature as the 16:16 value-0 crash,
so **the value was never the crash cause**; the blocker is now this
one null field. evening6 RE is dissecting the tail call, the field's
writers, and whether post-generation timing (S2) populates it.
## S2 deployed (2026-11-04 17:39, commit `83b725d`, Core 424/424)

Evening6: the callback calls 0x142ac16b0 on [agg+0x1270] with NO null
check; the field's only non-ctor writer is the ensure inside the
client's local commit method 0x14167b3f0 — no server message reaches
it, and its natural timing is around generation completion. So the
gateway burst is back to `0x11 → 0x1e` only, and the 0x9a handler now
sends `0x2f7` then `0x23` (value 1000). Probe v10 watches agg_commit /
agg_ensure / agg_reload_1270: if commit+ensure fire before the reload
reads a non-null +0x1270, the timing theory is proven either way in
one session. `Identity()` was renamed `DisconnectWithReason` in the
same commit.

## Waiting on the NEXT user login (called when ready)

1. **Blob trace session** — S2 itself is PROVEN (17:44: activation,
   dispatch, type lookup and the entity ctor all fired; the ctor then
   threw Buffer Underflow in the player blob). Evening7 pinned it:
   0.5.5 reads **Stats first**; the fork writes Positioned first, so
   the Stats reader decoded a 327,680-pair map out of the spawn
   coordinates and ate the blob. The v11 trace (18:02) returned: **gate = 1**, and Stats is index **1** -
   Positioned (index 0) consumes **19 B** in 0.5.5 (a third flag byte,
   flagsC, evening8). The blob's idx0/idx1 are now rewritten and
   deployed (c22749f: Positioned 19 B; Stats = fork pair stream +
   6x0 gate + u32/u8/u8 tail; Core 424/424), and probe **v12** dumps
   the full component table at fn C entry plus per-component
   consumption. The follow-up enter (18:25) measured the rest: Stats read fully
   (605 B), Pathfinding 0, Buffs 2 - then Life's 0.5.5 reader consumed
   125 B against the fork's 55 and the Player reader threw on the
   70-byte misalignment (client crash, area rendered, no model).
   Evening9 then derived ALL remaining components statically, and
   **blob v3 + record tail fix (83ca4ad) deployed 20:21, 0.5.5 skill tables live, probe v14 armed; awaiting acceptance enter. Probe v13
   watches the CreateObject handler, world registration and the AO
   attach. Next enter is the acceptance test: no crash, the witch
   model standing at the spawn, controllable.
2. **Class fingerprint (problem 2)**: at the character-select screen,
   note which class the throwaway character **bbbbbb** displays.
   (bbbbbb was deleted by the user on 2026-11-04 14:08 and has been
   restored from `deleted_characters` in saves.db, save included.)
   Fingerprint: B4d=1, B51=2, U40=3, U44=4, U46=5, Level=6, Class=7,
   B4c=8, B4e=9, B4f=10, B50=11 — the displayed Characters row names
   the field. Still row 0 → round 2 varies the 0x15 message-level fields.

## Queued next steps (in order)

1. **S2** (after a proven S1): in the gateway's 0x9a handler send
   `0x2f7` CreateObject first, then `InstanceProtocol.Content()`
   (value 1000). File: `src/GameServer.Gateway/Program.Messages.cs`.
2. Rename `InstanceProtocol.Identity()` → `DisconnectWithReason`
   (evening5: 0x28 is a kick message; the encoder is correct, the name
   is a landmine). Update the golden test name in
   `tests/GameServer.Core.Tests/InstanceProtocolTests.cs`. Ride along
   with the next gateway deploy — do not restart the gateway mid-S1.
3. **Item-table deployment** (problem 3): 32 tables staged
   (`ITEM-TABLES-REEXPORT.md`); 6 small tables being extracted/decoded.
   Deploy only after the S2 readout: back up `D:\LocalExile2\data\tables`
   (timestamp suffix), swap, restart Auth+Gateway, Core/Data tests,
   re-run the StartKit check against the deployed directory.
4. Blob component audit if S2 crashes (OPEN-PROBLEMS problem 1).
5. Backlog: R2 `CharacterClass` enum replacement, Play-Index live
   discrimination, problem 4 pattern-fill (post-M2), problem 6
   Gateway.Tests missing-key list, multi-area test
   (G1_1 → G1_2 → G1_town) once single-area entry works.

## Hard-won facts (do not re-derive)

- `0x28` = disconnect-with-reason. **Never send it in the entry
  sequence.** Its "key" is a reason code looked up in the client's
  error table; its text is echoed verbatim after `Abnormal disconnect:`.
- `0x23` is the activation trigger: handler → world aggregate main
  vtable `0x14339d1d0` +0x1f0 (`0x1416820a0`) → activation `0x14212fd90`.
  The aggregate has TWO vtable pairs; the facet pair misled two evenings.
- World stamp triple = 0 is correct (ctor initial). `0x21`/`0x22` have
  no data flow to activation — do not send them for it.
- Deploy rule: a deploy counts only with git HEAD + exe LastWriteTime
  + listening ports all read back (a silent align failure once sent
  the user into a stale build).
