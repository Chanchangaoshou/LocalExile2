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
  onEnter(args) { send({ ev: 'facet_callback' }); }
});
send({ ev: 'v6_armed' });
