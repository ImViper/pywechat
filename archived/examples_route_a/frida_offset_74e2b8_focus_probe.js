/*
Focused probe for Weixin.dll+0x74e2b8.
Logs only interesting hits (acc-r / mmsnscomment) with deeper context.
*/

'use strict';

const TARGET_OFFSET = ptr('0x74e2b8');
const NEEDLES = ['acc-r', 'mmsnscomment', 'micromsg-bin', 'sns_comment'];
const MAX_EVENTS = 80;
const MAX_SCAN = 0x1200;

let budget = MAX_EVENTS;
let lastSendMs = 0;
let sendBudget = 80;

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

function findNeedles(ascii) {
  const out = [];
  const lower = (ascii || '').toLowerCase();
  for (let i = 0; i < NEEDLES.length; i++) {
    const n = NEEDLES[i].toLowerCase();
    const idx = lower.indexOf(n);
    if (idx >= 0) out.push({ needle: NEEDLES[i], index: idx });
  }
  return out;
}

function inspect(name, p) {
  const raw = safeRead(p, MAX_SCAN);
  if (!raw) return { name: name, ptr: p.toString(), hits: [] };
  const ascii = toAscii(raw);
  const hits = findNeedles(ascii);
  const snippets = [];
  for (let i = 0; i < hits.length; i++) {
    const h = hits[i];
    const a = Math.max(0, h.index - 80);
    const b = Math.min(ascii.length, h.index + h.needle.length + 120);
    snippets.push({
      needle: h.needle,
      index: h.index,
      ascii: ascii.slice(a, b),
      hex: toHex(raw, MAX_SCAN).slice(a * 2, b * 2),
    });
  }
  return {
    name: name,
    ptr: p.toString(),
    hits: hits,
    snippets: snippets,
  };
}

function scanStructPointers(basePtr, wx) {
  const out = [];
  if (!basePtr || basePtr.isNull()) return out;
  const raw = safeRead(basePtr, 0x700);
  if (!raw) return out;
  const ps = Process.pointerSize;
  for (let off = 0; off + ps <= raw.byteLength; off += ps) {
    let p = null;
    try {
      p = basePtr.add(off).readPointer();
    } catch (_) {
      continue;
    }
    if (!p || p.isNull()) continue;
    if (p.compare(wx.base) < 0 || p.compare(wx.base.add(wx.size)) >= 0) continue;
    const rr = safeRead(p, 180);
    if (!rr) continue;
    const s = toAscii(rr);
    const hits = findNeedles(s);
    if (hits.length === 0) continue;
    out.push({
      struct_off: '0x' + off.toString(16),
      ptr: p.toString(),
      ascii: s.slice(0, 140),
      hits: hits,
    });
    if (out.length >= 12) break;
  }
  return out;
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
        const t = nowMs();
        lastSendMs = t;
        if (sendBudget <= 0) return;
        sendBudget -= 1;
        let lenVal = 0;
        let preview = '';
        try {
          if (n === 'send') {
            lenVal = args[2].toInt32();
            const raw = safeRead(args[1], Math.min(Math.max(lenVal, 0), 220));
            preview = toAscii(raw).slice(0, 120);
          }
        } catch (_) {}
        send({
          type: 'send-event',
          t_ms: t,
          name: e.name,
          tid: Process.getCurrentThreadId(),
          len: lenVal,
          preview: preview,
        });
      },
    });
  }
}

const wx = Process.findModuleByName('Weixin.dll');
if (!wx) {
  send({ type: 'info', msg: 'Weixin.dll not loaded' });
} else {
  const addr = wx.base.add(TARGET_OFFSET);
  send({
    type: 'info',
    msg: 'focus probe loaded',
    pid: Process.id,
    base: wx.base.toString(),
    target: addr.toString(),
    offset: TARGET_OFFSET.toString(),
  });
  installSendHooks();

  Interceptor.attach(addr, {
    onEnter(args) {
      if (budget <= 0) return;
      const t = nowMs();
      const items = [];
      items.push(inspect('rdx', this.context.rdx));
      items.push(inspect('arg1', args[1]));
      items.push(inspect('rcx', this.context.rcx));
      items.push(inspect('r8', this.context.r8));
      items.push(inspect('r9', this.context.r9));
      items.push(inspect('rax', this.context.rax));

      let interesting = false;
      for (let i = 0; i < items.length; i++) {
        if ((items[i].hits || []).length > 0) {
          interesting = true;
          break;
        }
      }
      if (!interesting) return;
      budget -= 1;

      let ret0 = ptr('0');
      let ret1 = ptr('0');
      try { ret0 = this.context.rsp.readPointer(); } catch (_) {}
      try { ret1 = this.context.rsp.add(Process.pointerSize).readPointer(); } catch (_) {}

      send({
        type: 'focus-hit',
        t_ms: t,
        tid: Process.getCurrentThreadId(),
        ms_since_last_send: lastSendMs > 0 ? (t - lastSendMs) : -1,
        offset: TARGET_OFFSET.toString(),
        address: addr.toString(),
        return_addrs: [
          { ptr: ret0.toString(), symbol: DebugSymbol.fromAddress(ret0).toString() },
          { ptr: ret1.toString(), symbol: DebugSymbol.fromAddress(ret1).toString() },
        ],
        regs: {
          rcx: this.context.rcx.toString(),
          rdx: this.context.rdx.toString(),
          r8: this.context.r8.toString(),
          r9: this.context.r9.toString(),
          rax: this.context.rax.toString(),
        },
        items: items,
        struct_refs: scanStructPointers(this.context.rdx, wx),
        backtrace: Thread.backtrace(this.context, Backtracer.FUZZY)
          .slice(0, 14)
          .map(DebugSymbol.fromAddress)
          .map(x => x.toString()),
      });
    },
  });
}

