/*
Timeline probe for candidate offsets from token/page access research.
Goal: determine whether candidate hits happen before or after ws send events.
*/

'use strict';

const OFFSETS = [
  ptr('0x74e2b8'),
  ptr('0x1df38d2'),
  ptr('0x1df300e'),
  ptr('0x435900b'),
  ptr('0x5622d7b'),
  ptr('0x49ffaf0'),
  ptr('0x49f95f2'),
];

const NEEDLES = ['acc-r', 'mmsnscomment', 'micromsg-bin', '/mmtls/', 'sns_comment'];
const MAX_EVENTS = 220;
const MAX_PER_OFFSET = 40;
const MAX_SCAN_BYTES = 0x900;

let budget = MAX_EVENTS;
let sendBudget = 120;
let lastSendMs = 0;
const countPerOffset = {};

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

function findHits(ascii) {
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
  if (!raw) return { name: name, ptr: p.toString(), hits: [] };
  const ascii = toAscii(raw);
  const hits = findHits(ascii);
  const snippets = [];
  for (let i = 0; i < hits.length; i++) {
    const h = hits[i];
    const a = Math.max(0, h.index - 60);
    const b = Math.min(ascii.length, h.index + h.needle.length + 80);
    snippets.push({
      needle: h.needle,
      index: h.index,
      ascii: ascii.slice(a, b),
    });
  }
  return {
    name: name,
    ptr: p.toString(),
    hits: hits,
    snippets: snippets,
  };
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

function installOffsetHooks(wx) {
  for (let i = 0; i < OFFSETS.length; i++) {
    const off = OFFSETS[i];
    const key = off.toString();
    const addr = wx.base.add(off);
    countPerOffset[key] = 0;
    Interceptor.attach(addr, {
      onEnter(args) {
        if (budget <= 0) return;
        const c = countPerOffset[key] || 0;
        if (c >= MAX_PER_OFFSET) return;
        countPerOffset[key] = c + 1;
        budget -= 1;

        const t = nowMs();
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
        ptrs.push(inspectPtr('rax', regs.rax));
        ptrs.push(inspectPtr('rbx', regs.rbx));
        ptrs.push(inspectPtr('rsi', regs.rsi));
        ptrs.push(inspectPtr('rcx', regs.rcx));
        ptrs.push(inspectPtr('rdx', regs.rdx));
        ptrs.push(inspectPtr('arg0', args[0]));
        ptrs.push(inspectPtr('arg1', args[1]));
        ptrs.push(inspectPtr('arg2', args[2]));
        ptrs.push(inspectPtr('arg3', args[3]));

        send({
          type: 'offset-event',
          t_ms: t,
          offset: key,
          address: addr.toString(),
          tid: Process.getCurrentThreadId(),
          ms_since_last_send: lastSendMs > 0 ? (t - lastSendMs) : -1,
          ptrs: ptrs,
        });
      },
    });
  }
}

const wx = Process.findModuleByName('Weixin.dll');
if (!wx) {
  send({ type: 'info', msg: 'Weixin.dll not loaded' });
} else {
  send({
    type: 'info',
    msg: 'token offsets timeline probe loaded',
    pid: Process.id,
    base: wx.base.toString(),
    offsets: OFFSETS.map(x => x.toString()),
  });
  installSendHooks();
  installOffsetHooks(wx);
}

