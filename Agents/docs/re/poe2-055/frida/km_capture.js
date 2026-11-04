// PoE2 0.5.5 instance-key capture v4.
// pair_builder: log VA-tagged caller + km. install_A (0x142198680): log the
// installed pair pointer, dump its object graph for Salsa states, and hook the
// pair process method (vtable +0x10) to log in/out bytes (XOR = true keystream).
const exe = Process.mainModule;
const BASE = exe.base;
const at = va => BASE.add(ptr(va).sub(ptr('0x140000000')));
const vaStr = p => '0x' + p.sub(BASE).add(ptr('0x140000000')).toString(16);
const hex = (p, n) => {
  try {
    const a = new Uint8Array(p.readByteArray(n));
    let s = '';
    for (let i = 0; i < a.length; i++) s += a[i].toString(16).padStart(2, '0');
    return s;
  } catch (e) { return 'ERR'; }
};
const CALLER_VAS = [
  [ptr('0x1420e838d'), 'LOGIN'], [ptr('0x1420e8388'), 'LOGIN'],
  [ptr('0x14212ac57'), 'INSTANCE'], [ptr('0x14212ac52'), 'INSTANCE'],
  [ptr('0x14214126f'), 'SETKEY'], [ptr('0x14214126a'), 'SETKEY'],
  [ptr('0x1421c53fe'), 'HNC'], [ptr('0x1421c53f9'), 'HNC'],
];
function tagOf(retAddr) {
  const va = retAddr.sub(BASE).add(ptr('0x140000000'));
  for (const [v, t] of CALLER_VAS) if (va.equals(v)) return t;
  return '?' + vaStr(retAddr);
}
let processHooked = false;

function scanStates(p, len, tag) {
  const hits = [];
  try {
    const buf = new Uint8Array(p.readByteArray(len));
    const dv = new DataView(buf.buffer);
    for (let off = 0; off + 64 <= len; off += 4) {
      if (dv.getUint32(off, true) === 0x61707865) {
        const words = [];
        for (let w = 0; w < 16; w++) words.push(('0000000' + dv.getUint32(off + w * 4, true).toString(16)).slice(-8));
        hits.push({ ev: 'salsa_state', tag, off, state: words.join(' ') });
      }
    }
  } catch (e) { /* unreadable */ }
  for (const h of hits) send(h);
  return hits.length;
}

function dumpGraph(root, tag) {
  let found = scanStates(root, 0x1c0, tag + ':self');
  const seen = new Set();
  try {
    for (let i = 0; i < 8; i++) {
      const q = root.add(i * 8).readPointer();
      if (q.isNull() || seen.has(q.toString())) continue;
      seen.add(q.toString());
      // only follow pointers into the exe image or heap-looking ranges
      found += scanStates(q, 0x1a0, tag + ':p' + i);
      try {
        const q2 = q.readPointer();
        if (!q2.isNull() && !seen.has(q2.toString())) { seen.add(q2.toString()); found += scanStates(q2, 0x1a0, tag + ':pp' + i); }
      } catch (e) {}
    }
  } catch (e) {}
  send({ ev: 'dump_done', tag, states: found, root: root.toString(), raw: hex(root, 0x40) });
}

function hookProcess(pairPtr) {
  if (processHooked) return;
  try {
    const vt = pairPtr.readPointer();
    const proc = vt.add(0x10).readPointer();
    send({ ev: 'pair_proc', proc: vaStr(proc) });
    processHooked = true;
    let count = 0;
    // v8: crash capture (SOLUTION-PLAN 4.1) — log the faulting VA + registers + backtrace,
// then return false so the client's own handler/minidump still runs.
Process.setExceptionHandler(function (d) {
  try {
    const bt = Thread.backtrace(d.context, Backtracer.ACCURATE)
      .map(a => vaStr(a)).join(' ');
    send({ ev: 'exception', type: d.type, addr: vaStr(d.address),
           rip: vaStr(d.context.rip), rcx: vaStr(d.context.rcx), rdx: vaStr(d.context.rdx),
           r8: vaStr(d.context.r8), bt: bt });
  } catch (e) { send({ ev: 'exception', note: 'handler failed: ' + e }); }
  return false;
});

Interceptor.attach(proc, {
      onEnter(args) {
        this.len = args[3].toInt32();
        this.a = args[1]; this.b = args[2]; this.self = args[0];
        if (this.len >= 4 && this.len <= 8192 && count < 12) {
          this.pre_a = hex(this.a, Math.min(this.len, 48));
          this.pre_b = hex(this.b, Math.min(this.len, 48));
        }
      },
      onLeave() {
        if (this.pre_a !== undefined) {
          count++;
          send({
            ev: 'pair_process', n: count, len: this.len, self: this.self.toString(),
            a_pre: this.pre_a, a_post: hex(this.a, Math.min(this.len, 48)),
            b_pre: this.pre_b, b_post: hex(this.b, Math.min(this.len, 48)),
          });
        }
      },
    });
    send({ ev: 'process_hooked' });
  } catch (e) { send({ ev: 'hook_err', err: String(e) }); }
}

Interceptor.attach(at('0x14219f500'), {
  onEnter(args) {
    const tag = tagOf(this.returnAddress);
    send({ ev: 'pair_builder', caller: tag, flag: args[2].toInt32() & 0xff, km: hex(args[1], 64) });
    if (tag === 'INSTANCE') this.instHolder = args[0];
  },
  onLeave() {
    if (this.instHolder) {
      try {
        const pairPtr = this.instHolder.readPointer();
        send({ ev: 'instance_pair', pair: pairPtr.toString() });
        dumpGraph(pairPtr, 'INSTANCE');
        hookProcess(pairPtr);
      } catch (e) { send({ ev: 'leave_err', err: String(e) }); }
    }
  },
});

// install_A: stream in rcx, &pair in rdx; the pair ptr is the authoritative one
Interceptor.attach(at('0x142198680'), {
  onEnter(args) {
    try {
      const pairPtr = args[1].readPointer();
      send({ ev: 'install', pair: pairPtr.toString(), stream: args[0].toString() });
      dumpGraph(pairPtr, 'INSTALL');
      hookProcess(pairPtr);
    } catch (e) { send({ ev: 'install_err', err: String(e) }); }
  },
});

// ---- v4: HNC / dispatcher diagnostics ----
// Instance dispatcher: log every dispatched message id (obj in r8, id u16 at +8)
let dispCount = 0;
Interceptor.attach(at('0x1421220f0'), {
  onEnter(args) {
    try {
      if (dispCount < 200) {
        dispCount++;
        const obj = args[2];
        send({ ev: 'dispatch', n: dispCount, obj: obj.toString(), id: obj.add(8).readU16() });
      }
    } catch (e) {}
  },
});
// HNC state machine: log each fed byte + state + feeding caller
let hncCount = 0;
Interceptor.attach(at('0x1421c55a0'), {
  onEnter(args) {
    try {
      if (hncCount < 400) {
        hncCount++;
        const ch = args[0];
        send({
          ev: 'hnc_feed', n: hncCount, ch: ch.toString(),
          byte: ch.add(0x5c).readU8(), type: ch.add(0x59).readU8(),
          len: ch.add(0x58).readU8(), bits: ch.add(0x54).readU32(),
          from: vaStr(this.returnAddress),
        });
      }
    } catch (e) {}
  },
});
// Exception throw helper: who throws (expect state machine sites only)
Interceptor.attach(at('0x142c14380'), {
  onEnter() {
    try { send({ ev: 'throw_call', from: vaStr(this.returnAddress) }); } catch (e) {}
  },
});
// The four HNC-feeding readers: entry (with caller) + field values on leave
const READERS = [
  ['R1', '0x141f48a50', [['u8_1c', 0x1c, 'u8'], ['u32_18', 0x18, 'u32']]],
  ['R2', '0x141f48de0', [['u16_18', 0x18, 'u16'], ['u16_1a', 0x1a, 'u16'], ['u32_1c', 0x1c, 'u32']]],
  ['R3', '0x141f49210', [['u32_18', 0x18, 'u32'], ['u32_1c', 0x1c, 'u32']]],
  ['R4', '0x141f49650', [['u32_18', 0x18, 'u32'], ['u32_1c', 0x1c, 'u32']]],
];
for (const [name, va, fields] of READERS) {
  Interceptor.attach(at(va), {
    onEnter(args) {
      this.msg = args[0];
      try { send({ ev: 'reader_in', name, msg: args[0].toString(), stream: args[1].toString(), from: vaStr(this.returnAddress) }); } catch (e) {}
    },
    onLeave() {
      try {
        const vals = {};
        for (const [fname, off, kind] of fields) {
          vals[fname] = kind === 'u8' ? this.msg.add(off).readU8() : kind === 'u16' ? this.msg.add(off).readU16() : this.msg.add(off).readU32();
        }
        send({ ev: 'reader_out', name, vals });
      } catch (e) {}
    },
  });
}
// R1 write fn (0x1c-class send): who composes one
Interceptor.attach(at('0x141f48870'), {
  onEnter(args) {
    try {
      send({ ev: 'r1_write', msg: args[0].toString(), id: args[0].add(8).readU16(), from: vaStr(this.returnAddress) });
    } catch (e) {}
  },
});
send({ ev: 'v4_armed' });

send({ ev: 'armed', base: BASE.toString() });

// ---- v5: world-layer visibility (factory / dispatch / activation / drain / entity ctor / type registry) ----
let wfCount = 0;
Interceptor.attach(at('0x142186c20'), {
  onEnter(args) { this.out = args[1]; this.id = args[2].toInt32() & 0xffff; this.ctx = args[0]; },
  onLeave(retval) {
    if (wfCount++ > 60) return;
    let created = 0;
    try { created = this.out.readPointer().isNull() ? 0 : 1; } catch (e) {}
    const info = { ev: 'world_factory', id: this.id, created };
    try {
      info.stamp678 = this.ctx.add(0x678).readU32();
      info.stamp67c = this.ctx.add(0x67c).readU8();
      info.stamp67e = this.ctx.add(0x67e).readU16();
      info.flag84a = this.ctx.add(0x84a).readU8();
    } catch (e) {}
    send(info);
  }
});
let wdCount = 0;
Interceptor.attach(at('0x1421343c0'), {
  onEnter(args) {
    if (wdCount++ > 200) return;
    let id = -1;
    try { id = args[1].add(8).readU16(); } catch (e) {}
    send({ ev: 'world_dispatch', id });
  }
});
Interceptor.attach(at('0x14212fd90'), {
  onEnter(args) { send({ ev: 'world_activate' }); }
});
let drainCount = 0;
Interceptor.attach(at('0x142130360'), {
  onEnter(args) {
    if (drainCount++ > 40) return;
    let f = -1;
    try { f = args[0].add(0x84a).readU8(); } catch (e) {}
    send({ ev: 'world_drain', flag84a: f });
  }
});
Interceptor.attach(at('0x141e705d0'), {
  onEnter(args) { send({ ev: 'entity_ctor' }); }
});
Interceptor.attach(at('0x141693840'), {
  onEnter(args) { this.out = args[1]; this.key = args[2].toInt32() >>> 0; },
  onLeave(retval) {
    let found = 0;
    try { found = this.out.readPointer().isNull() ? 0 : 1; } catch (e) {}
    send({ ev: 'type_lookup', key: this.key.toString(16), found });
  }
});
send({ ev: 'v5_armed' });

// ---- v6: is the world ticked at all? (world update + InstMgr tick registry + facet callback) ----
let updCount = 0;
Interceptor.attach(at('0x142130840'), {
  onEnter(args) { if (updCount++ < 30) send({ ev: 'world_update' }); }
});
let tickCount = 0;
Interceptor.attach(at('0x14218bf90'), {
  onEnter(args) {
    if (tickCount++ > 30) return;
    const info = { ev: 'instmgr_tick' };
    try {
      const b = args[0].add(0x270).readPointer();
      const e = args[0].add(0x278).readPointer();
      info.span = e.sub(b).toInt32();
      info.begin = b.toString();
    } catch (err) {}
    send(info);
  }
});
Interceptor.attach(at('0x1416820a0'), {
  onEnter(args) {
    // v9 (plan v2 section 3.2): dump the world aggregate's decision fields on entry.
    const agg = this.context.rcx;
    let d = { ev: 'facet_callback', agg: agg.toString() };
    try {
      d.area98 = agg.add(0x98).readPointer().toString();
      d.fc8 = agg.add(0xfc8).readPointer().toString();
      d.f1270 = agg.add(0x1270).readPointer().toString();
      d.v11c = agg.add(0x11c).readU32();
    } catch (e) { d.dumpErr = '' + e; }
    send(d);
  }
});
send({ ev: 'v6_armed' });
send({ ev: 'v9_armed' });

// ---- v7: game state machine + instance identity setter ----
let smCount = 0;
Interceptor.attach(at('0x142810b70'), {
  onEnter(args) { this.self = args[0]; },
  onLeave(retval) {
    if (smCount++ > 80) return;
    let idx = -1;
    try { idx = this.self.add(0x518).readU32(); } catch (e) {}
    send({ ev: 'sm_transition', idx });
  }
});
let sm2Count = 0;
Interceptor.attach(at('0x142812680'), {
  onEnter(args) { if (sm2Count++ < 80) send({ ev: 'sm_select' }); }
});
Interceptor.attach(at('0x14211f920'), {
  onEnter(args) {
    let a1 = -1;
    try { a1 = args[1].toInt32() & 0xffff; } catch (e) {}
    send({ ev: 'identity_set', a1 });
  }
});
send({ ev: 'v7_armed' });

// ---- v10: aggregate commit / ensure / the dangerous reload (evening6) ----
// commit method 0x14167b3f0 (main vtable +0x1e0): the client's local world
// assembly committing area parameters into the aggregate; its tail ensure
// 0x141681720 allocates [agg+0x1270] on first use. If these fire before the
// activation callback's reload at 0x1416820b1, S2's timing is safe.
Interceptor.attach(at('0x14167b3f0'), {
  onEnter(args) { send({ ev: 'agg_commit' }); }
});
Interceptor.attach(at('0x141681720'), {
  onEnter(args) { send({ ev: 'agg_ensure' }); }
});
Interceptor.attach(at('0x1416820b1'), {
  onEnter(args) {
    let v = null;
    try { v = this.context.rbx.add(0x1270).readPointer().toString(); } catch (e) {}
    send({ ev: 'agg_reload_1270', value: v });
  }
});
send({ ev: 'v10_armed' });

// ---- v11: blob component trace (evening7 section 7) ----
// (1) fn C's component-loop virtual call site: per iteration log the index,
//     the component vtable and the span cursor; successive deltas give each
//     component's actual consumption. fn C's exit logs the final cursor.
let lastCursor = null;
Interceptor.attach(at('0x141e71375'), {
  onEnter(args) {
    let idx = -1, vtbl = null, cursor = null;
    try {
      idx = this.context.rsi.toInt32() & 0xffff;
      vtbl = this.context.rcx.readPointer().toString();
      cursor = this.context.rdx.add(0x10).readPointer().toString();
    } catch (e) {}
    send({ ev: 'comp_call', idx, vtbl, cursor, prev: lastCursor });
    lastCursor = cursor;
  }
});
Interceptor.attach(at('0x141e712a0'), {
  onEnter(args) {
    try {
      const ent = this.context.rcx;
      const D = ent.add(8).readPointer().add(0x28).readPointer();
      const count = D.add(0x78).readU64().toNumber();
      const arr = ent.add(0x10).readPointer();
      let comps = [];
      for (let i = 0; i < count && i < 24; i++) {
        const comp = arr.add(i * 8).readPointer();
        let vt = null, rf = null, ow = null, def = null;
        try { vt = comp.readPointer().toString(); rf = comp.readPointer().add(0x98).readPointer().toString(); } catch (e) {}
        try { ow = comp.add(8).readPointer().toString(); } catch (e) {}
        try { def = comp.add(0x158).readPointer().toString(); } catch (e) {}
        comps.push({ i, vt, rf, ow, def });
      }
      let desc = [];
      try {
        const b = D.add(0x298).readPointer(), e = D.add(0x2a0).readPointer();
        const n = e.sub(b).toInt32() / 8;
        for (let i = 0; i < n && i < 24; i++) desc.push(b.add(i * 8).readPointer().toString());
      } catch (e) {}
      send({ ev: 'fnC_table', count, comps, desc });
    } catch (e) { send({ ev: 'fnC_table', err: '' + e }); }
  },
  onLeave(retval) { send({ ev: 'fnC_done', lastCursor }); }
});
// (2) Stats reader B entry: the gate is a byte in the type-definition-side
//     object reached via [rcx+0x158]+0x20 - read it before any consumption.
Interceptor.attach(at('0x142181160'), {
  onEnter(args) {
    let gate = null, vtbl = null;
    try {
      vtbl = this.context.rcx.readPointer().toString();
      gate = this.context.rcx.add(0x158).readPointer().add(0x20).readU8();
    } catch (e) {}
    send({ ev: 'stats_gate', gate, vtbl });
  }
});
send({ ev: 'v12_armed' });

// ---- v13: registration + model attach watch (evening9 section 10) ----
Interceptor.attach(at('0x142134ec7'), { onEnter(args) { send({ ev: 'createobj_handler' }); } });
Interceptor.attach(at('0x141e72a00'), {
  onEnter(args) {
    let id = null, f8d = null;
    try { const ent = this.context.rdx; id = ent.add(0x88).readU32(); f8d = ent.add(0x8d).readU8(); } catch (e) {}
    send({ ev: 'world_register', id, f8d });
  }
});
Interceptor.attach(at('0x141da37e0'), { onEnter(args) { send({ ev: 'ao_attach' }); } });
send({ ev: 'v13_armed' });

// ---- v14: row-zero underflow localization (evening11) ----
function spanCur(p) { try { return p.add(0x10).readU64().toString(); } catch (e) { return 'ERR'; } }
function deltaHook(name, va) {
  Interceptor.attach(at(va), {
    onEnter(args) { this.sp = args[1]; send({ ev: name + '_enter', cur: spanCur(args[1]) }); },
    onLeave(ret) { send({ ev: name + '_leave', cur: spanCur(this.sp) }); }
  });
}
deltaHook('rec', '0x142188D50');       // skill record reader: delta should be 77 with the fix
deltaHook('skilltab', '0x14218A9D0');  // skill table reader: delta should be 84
deltaHook('actor', '0x142147300');     // Actor reader: delta should be 117, must return
Interceptor.attach(at('0x14218971f'), {
  onEnter(args) {
    const c = this.context; const regs = { rax: c.rax, rbx: c.rbx, rcx: c.rcx, rdx: c.rdx, rsi: c.rsi, rdi: c.rdi, r8: c.r8, r9: c.r9, r10: c.r10, r11: c.r11, r12: c.r12, r13: c.r13, r14: c.r14, r15: c.r15 };
    const out = {};
    for (const k in regs) { try { const q = regs[k].add(0x10d).readU64(); out[k] = '10d=' + q.toString(16); } catch (e) {} }
    send({ ev: 'tail_gate', regs: out });
  }
});
Interceptor.attach(at('0x141e71383'), {
  onEnter(args) { send({ ev: 'tasks_read', rcx: spanCur(this.context.rcx), rdx: spanCur(this.context.rdx), rbx: spanCur(this.context.rbx), rsi: spanCur(this.context.rsi) }); }
});
Interceptor.attach(at('0x1421474df'), {
  onEnter(args) { send({ ev: 'seg4_tail', rcx: spanCur(this.context.rcx), rdx: spanCur(this.context.rdx), rbx: spanCur(this.context.rbx), rsi: spanCur(this.context.rsi) }); }
});
send({ ev: 'v14_armed' });

// ---- v15: post-registration AV localization (evening12) ----
function rd(p, off) { try { return p.add(off).readPointer().toString(); } catch (e) { return 'ERR'; } }
function regsDump(c) {
  const r = { rax: c.rax, rbx: c.rbx, rcx: c.rcx, rdx: c.rdx, rsi: c.rsi, rdi: c.rdi, r8: c.r8, r9: c.r9, r12: c.r12, r13: c.r13, r14: c.r14, r15: c.r15 };
  const o = {};
  for (const k in r) { o[k] = r[k].toString(); o[k + '_deref'] = rd(r[k], 0); o[k + '_188'] = rd(r[k], 0x188); }
  return o;
}
Interceptor.attach(at('0x1401506e0'), { onEnter(args) { send({ ev: 'flagset_exp', rcx: this.context.rcx.toString(), rcx0: rd(this.context.rcx, 0), rcx8: rd(this.context.rcx, 8), ret: this.returnAddress.toString() }); } });
Interceptor.attach(at('0x140125e8e'), { onEnter(args) { send({ ev: 'walk_E', regs: regsDump(this.context) }); } });
Interceptor.attach(at('0x1401256d0'), { onEnter(args) { send({ ev: 'agg_walk', rdx: this.context.rdx.toString(), r8: this.context.r8.toString(), rcx: this.context.rcx.toString() }); } });
Interceptor.attach(at('0x1416292a0'), { onEnter(args) { send({ ev: 'refclean', rcx: this.context.rcx.toString(), vt: rd(this.context.rcx, 0), p340: rd(this.context.rcx, 0x340), p348: rd(this.context.rcx, 0x348) }); } });
Interceptor.attach(at('0x14013bbf0'), { onEnter(args) { send({ ev: 'list_iter', rcx: this.context.rcx.toString(), rdx: this.context.rdx.toString() }); } });
Interceptor.attach(at('0x142627440'), { onEnter(args) { send({ ev: 'ctor_throw', regs: regsDump(this.context) }); } });
Interceptor.attach(at('0x141e74740'), { onEnter(args) { send({ ev: 'ctor_tail', rcx: this.context.rcx.toString(), rdx: this.context.rdx.toString() }); } });
Interceptor.attach(at('0x141DA66C0'), { onEnter(args) { send({ ev: 'anim_read', rcx: this.context.rcx.toString() }); } });
Interceptor.attach(at('0x140BC8280'), { onLeave(ret) { send({ ev: 'res_lookup', ret: ret.toString() }); } });
Interceptor.attach(at('0x141D2C750'), { onEnter(args) { send({ ev: 'ao_ctor', rcx: this.context.rcx.toString(), rdx: this.context.rdx.toString() }); } });
Interceptor.attach(at('0x1421232bf'), { onEnter(args) { send({ ev: 'walk_after_23', rcx: this.context.rcx.toString() }); } });
send({ ev: 'v15_armed' });

// ---- v16: model-attach + throw-module localization (evening13) ----
function derefChain(p, n) {
  let cur = p, out = [];
  try { for (let i = 0; i < n; i++) { cur = cur.readPointer(); out.push(cur.toString()); } } catch (e) { out.push('ERR'); }
  return out;
}
Interceptor.attach(at('0x141DA66C0'), {
  onEnter(args) {
    const rcx = this.context.rcx;
    let s350 = 'ERR';
    try { const h = rcx.add(0x350).readPointer(); const s = h.readPointer(); s350 = derefChain(rcx.add(0x350), 2).join('>') + ' str=' + (s.readUtf16String ? (s.readUtf16String(80) || '') : ''); } catch (e) {}
    send({ ev: 'anim_entry', p350: s350, def168: rd(rcx, 0x168), p190: rd(rcx, 0x190), p198: rd(rcx, 0x198) });
  }
});
Interceptor.attach(at('0x140189bc0'), {
  onEnter(args) { send({ ev: 'p350_write', rcx: this.context.rcx.toString(), ret: this.returnAddress.toString() }); }
});
Interceptor.attach(at('0x141da2c30'), {
  onEnter(args) { send({ ev: 'refresh10', rcx: this.context.rcx.toString(), rdx: this.context.rdx.toString() }); },
  onLeave(ret) { send({ ev: 'refresh10_done', ret: ret.toString() }); }
});
Interceptor.attach(at('0x142c14380'), {
  onEnter(args) {
    const mods = [];
    try { Process.enumerateModules().forEach(m => mods.push(m.name + '@' + m.base.toString())); } catch (e) {}
    send({ ev: 'throw_ctx', bt: Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8).map(a => a.toString()), mods: mods });
  }
});
Interceptor.attach(at('0x141DA37E0'), {
  onEnter(args) { send({ ev: 'attach_gate', owner8c: rd(this.context.rcx, 0x8c) }); }
});
send({ ev: 'v16_armed' });
