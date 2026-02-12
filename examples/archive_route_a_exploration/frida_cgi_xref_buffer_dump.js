/*
Dump buffer/object context when CGI xref offsets are hit.
Focus on extracting pre-encryption request fragments around mmsnscomment.
*/

'use strict';

const OFFSETS = [
  ptr('0x29de835'),
  ptr('0x29de840'),
  ptr('0x2a10ae4'),
  ptr('0x2a10aef'),
];

const NEEDLES = [
  '/cgi-bin/micromsg-bin/mmsnscomment',
  'mmsnscomment',
  'micromsg-bin',
  'acc-r',
  '/mmtls/',
];

const RECENT_SEND_WINDOW_MS = 2200;
const MAX_EVENTS = 80;
const MAX_SCAN_BYTES = 0x600;
const MAX_STRUCT_SCAN = 0x500;

let budget = MAX_EVENTS;
const recentSendByTid = {};
let lastAnySendMs = 0;
let sendLogBudget = 80;

function nowMs() {
  return (new Date()).getTime();
}

function toAscii(buf) {
  if (!buf) return '';
  const u8 = new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < u8.length; i++) {
    const c = u8[i];
    out += (c >= 32 && c <= 126) ? String.fromCharCode(c) : '.';
  }
  return out;
}

function toHex(buf, maxLen) {
  if (!buf) return '';
  const u8 = new Uint8Array(buf);
  const lim = Math.min(u8.length, maxLen);
  let out = '';
  for (let i = 0; i < lim; i++) out += ('0' + u8[i].toString(16)).slice(-2);
  return out;
}

function safeRead(ptrVal, maxBytes) {
  if (!ptrVal || ptrVal.isNull()) return null;
  let r = null;
  try {
    r = Process.findRangeByAddress(ptrVal);
  } catch (_) {
    r = null;
  }
  if (!r) return null;
  const remain = r.base.add(r.size).sub(ptrVal).toInt32();
  if (remain <= 0) return null;
  const n = Math.min(remain, maxBytes);
  if (n <= 0) return null;
  try {
    return ptrVal.readByteArray(n);
  } catch (_) {
    return null;
  }
}

function findNeedlesAscii(ascii) {
  const out = [];
  const lower = (ascii || '').toLowerCase();
  for (let i = 0; i < NEEDLES.length; i++) {
    const n = NEEDLES[i].toLowerCase();
    const idx = lower.indexOf(n);
    if (idx >= 0) out.push({ needle: NEEDLES[i], index: idx });
  }
  return out;
}

function inspectPtr(name, p) {
  const raw = safeRead(p, MAX_SCAN_BYTES);
  if (!raw) return { name: name, ptr: p.toString(), ascii: '', hits: [] };
  const ascii = toAscii(raw);
  const hits = findNeedlesAscii(ascii);
  const windows = [];
  for (let i = 0; i < hits.length; i++) {
    const h = hits[i];
    const from = Math.max(0, h.index - 72);
    const to = Math.min(ascii.length, h.index + h.needle.length + 96);
    const hxFrom = from * 2;
    const hxTo = to * 2;
    windows.push({
      needle: h.needle,
      index: h.index,
      ascii_window: ascii.slice(from, to),
      hex_window: toHex(raw, MAX_SCAN_BYTES).slice(hxFrom, hxTo),
    });
  }
  return {
    name: name,
    ptr: p.toString(),
    ascii: ascii.slice(0, 220),
    hits: hits,
    hit_windows: windows,
    hex: hits.length > 0 ? toHex(raw, 320) : '',
  };
}

function scanStructPointers(structPtr, mod) {
  const refs = [];
  if (!structPtr || structPtr.isNull()) return refs;
  const raw = safeRead(structPtr, MAX_STRUCT_SCAN);
  if (!raw) return refs;
  const ps = Process.pointerSize;
  const bytes = new Uint8Array(raw);
  for (let off = 0; off + ps <= bytes.length; off += ps) {
    let p = null;
    try {
      p = structPtr.add(off).readPointer();
    } catch (_) {
      continue;
    }
    if (!p || p.isNull()) continue;
    if (p.compare(mod.base) < 0 || p.compare(mod.base.add(mod.size)) >= 0) continue;
    const pr = safeRead(p, 160);
    if (!pr) continue;
    const ascii = toAscii(pr);
    const hits = findNeedlesAscii(ascii);
    if (hits.length === 0) continue;
    refs.push({
      struct_off: '0x' + off.toString(16),
      target_ptr: p.toString(),
      ascii: ascii.slice(0, 120),
      hits: hits,
    });
    if (refs.length >= 10) break;
  }
  return refs;
}

function installSendHooks() {
  const ws = Process.findModuleByName('ws2_32.dll') || Process.findModuleByName('WS2_32.dll');
  if (!ws) return;
  const exps = ws.enumerateExports();
  for (let i = 0; i < exps.length; i++) {
    const e = exps[i];
    if (e.type !== 'function') continue;
    const n = e.name.toLowerCase();
    if (n !== 'send' && n !== 'wsasend') continue;
    Interceptor.attach(e.address, {
      onEnter(args) {
        const tid = Process.getCurrentThreadId();
        const t = nowMs();
        recentSendByTid[tid] = t;
        lastAnySendMs = t;
        if (sendLogBudget <= 0) return;
        sendLogBudget -= 1;
        let preview = '';
        let lenVal = 0;
        try {
          if (n === 'send') {
            const p = args[1];
            lenVal = args[2].toInt32();
            const raw = safeRead(p, Math.min(Math.max(lenVal, 0), 220));
            preview = toAscii(raw).slice(0, 120);
          } else {
            const wsabuf = args[1];
            const count = args[2].toInt32();
            if (count > 0 && !wsabuf.isNull()) {
              const p = wsabuf.readPointer();
              lenVal = wsabuf.add(Process.pointerSize).readU32();
              const raw = safeRead(p, Math.min(Math.max(lenVal, 0), 220));
              preview = toAscii(raw).slice(0, 120);
            }
          }
        } catch (_) {}
        send({
          type: 'ws-send',
          name: e.name,
          tid: tid,
          len: lenVal,
          preview: preview,
        });
      },
    });
  }
}

function installXrefHooks(mod) {
  function toOffset(p) {
    try {
      return '0x' + p.sub(mod.base).toString(16);
    } catch (_) {
      return '';
    }
  }
  for (let i = 0; i < OFFSETS.length; i++) {
    const off = OFFSETS[i];
    const addr = mod.base.add(off);
    Interceptor.attach(addr, {
      onEnter(args) {
        if (budget <= 0) return;
        const tid = Process.getCurrentThreadId();
        const t = nowMs();
        const nearSendThread = (t - (recentSendByTid[tid] || 0)) <= RECENT_SEND_WINDOW_MS;
        const nearSendGlobal = (t - lastAnySendMs) <= RECENT_SEND_WINDOW_MS;
        const nearSend = nearSendThread || nearSendGlobal;

        const regs = {
          rax: this.context.rax,
          rbx: this.context.rbx,
          rcx: this.context.rcx,
          rdx: this.context.rdx,
          rsi: this.context.rsi,
          rdi: this.context.rdi,
          r8: this.context.r8,
          r9: this.context.r9,
        };

        const ptrs = [];
        const regNames = Object.keys(regs);
        for (let k = 0; k < regNames.length; k++) {
          const rn = regNames[k];
          ptrs.push(inspectPtr(rn, regs[rn]));
        }
        for (let k = 0; k < 4; k++) {
          ptrs.push(inspectPtr('arg' + k, args[k]));
        }

        let interesting = false;
        for (let k = 0; k < ptrs.length; k++) {
          if ((ptrs[k].hits || []).length > 0) {
            interesting = true;
            break;
          }
        }
        if (!interesting && !nearSend) return;
        budget -= 1;

        const structRefs = [];
        structRefs.push({ base: 'rax', refs: scanStructPointers(regs.rax, mod) });
        structRefs.push({ base: 'rsi', refs: scanStructPointers(regs.rsi, mod) });
        structRefs.push({ base: 'rbx', refs: scanStructPointers(regs.rbx, mod) });

        let ret0 = ptr('0');
        let ret1 = ptr('0');
        let ret2 = ptr('0');
        try { ret0 = this.context.rsp.readPointer(); } catch (_) {}
        try { ret1 = this.context.rsp.add(Process.pointerSize).readPointer(); } catch (_) {}
        try { ret2 = this.context.rsp.add(Process.pointerSize * 2).readPointer(); } catch (_) {}

        send({
          type: 'xref-buffer-hit',
          offset: off.toString(),
          address: addr.toString(),
          tid: tid,
          near_send: nearSend,
          near_send_thread: nearSendThread,
          near_send_global: nearSendGlobal,
          return_addrs: [
            { ptr: ret0.toString(), offset: toOffset(ret0), symbol: DebugSymbol.fromAddress(ret0).toString() },
            { ptr: ret1.toString(), offset: toOffset(ret1), symbol: DebugSymbol.fromAddress(ret1).toString() },
            { ptr: ret2.toString(), offset: toOffset(ret2), symbol: DebugSymbol.fromAddress(ret2).toString() },
          ],
          ptrs: ptrs,
          struct_refs: structRefs,
          backtrace: Thread.backtrace(this.context, Backtracer.FUZZY)
            .slice(0, 14)
            .map(DebugSymbol.fromAddress)
            .map(x => x.toString()),
        });
      },
    });
  }
}

const mod = Process.findModuleByName('Weixin.dll');
if (!mod) {
  send({ type: 'info', msg: 'Weixin.dll not loaded' });
} else {
  send({
    type: 'info',
    msg: 'cgi xref buffer dump probe loaded',
    pid: Process.id,
    base: mod.base.toString(),
    offsets: OFFSETS.map(x => x.toString()),
  });
  installSendHooks();
  installXrefHooks(mod);
}
