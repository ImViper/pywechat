/*
Runtime probe for static CGI xrefs discovered from Weixin.dll.
Focus: whether these offsets are hit around send()/WSASend() while sending a comment.
*/

'use strict';

const OFFSETS = [
  // mmsnscomment xrefs
  ptr('0x29de835'),
  ptr('0x29de840'),
  ptr('0x2a10ae4'),
  ptr('0x2a10aef'),
  // mmsnstimeline xrefs (for comparison)
  ptr('0x29d0945'),
  ptr('0x29d0950'),
  ptr('0x2a02b14'),
  ptr('0x2a02b1f'),
];

const RECENT_SEND_WINDOW_MS = 1400;
const MAX_LOGS = 120;
const MAX_ASCII_BYTES = 128;
const WATCH_REGS = ['rcx', 'rdx', 'r8', 'r9', 'rsi', 'rdi', 'rax', 'rbx'];
const MAX_LOGS_PER_OFFSET = 8;

let logBudget = MAX_LOGS;
const recentSendByTid = {};
const hitCounts = {};
const loggedPerOffset = {};

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

function safeReadAscii(p, maxBytes) {
  if (!p || p.isNull()) return '';
  try {
    const r = Process.findRangeByAddress(p);
    if (!r) return '';
    const remain = r.base.add(r.size).sub(p).toInt32();
    if (remain <= 0) return '';
    const n = Math.min(remain, maxBytes);
    const raw = p.readByteArray(n);
    const s = toAscii(raw);
    return s.slice(0, 96);
  } catch (_) {
    return '';
  }
}

function collectRegs(ctx) {
  const out = {};
  for (let i = 0; i < WATCH_REGS.length; i++) {
    const rn = WATCH_REGS[i];
    const p = ctx[rn];
    if (!p) continue;
    out[rn] = {
      ptr: p.toString(),
      ascii: safeReadAscii(p, MAX_ASCII_BYTES),
    };
  }
  return out;
}

function installSendHooks() {
  const ws = Process.findModuleByName('ws2_32.dll') || Process.findModuleByName('WS2_32.dll');
  if (!ws) {
    send({ type: 'info', msg: 'ws2_32 not loaded' });
    return;
  }
  const exps = ws.enumerateExports();
  for (let i = 0; i < exps.length; i++) {
    const e = exps[i];
    if (e.type !== 'function') continue;
    const n = e.name.toLowerCase();
    if (n !== 'send' && n !== 'wsasend') continue;
    Interceptor.attach(e.address, {
      onEnter(_args) {
        recentSendByTid[Process.getCurrentThreadId()] = nowMs();
      },
    });
    send({ type: 'info', msg: 'hooked ws export', name: e.name, address: e.address.toString() });
  }
}

function installOffsetHooks(wx) {
  for (let i = 0; i < OFFSETS.length; i++) {
    const off = OFFSETS[i];
    const addr = wx.base.add(off);
    hitCounts[off.toString()] = 0;
    loggedPerOffset[off.toString()] = 0;
    Interceptor.attach(addr, {
      onEnter(args) {
        const tid = Process.getCurrentThreadId();
        const last = recentSendByTid[tid] || 0;
        const nearSend = (nowMs() - last) >= 0 && (nowMs() - last) <= RECENT_SEND_WINDOW_MS;
        const key = off.toString();
        hitCounts[key] = (hitCounts[key] || 0) + 1;
        const localBudget = loggedPerOffset[key] || 0;
        if (localBudget >= MAX_LOGS_PER_OFFSET || logBudget <= 0) return;
        logBudget -= 1;
        loggedPerOffset[key] = localBudget + 1;

        send({
          type: 'xref-hit',
          offset: key,
          address: addr.toString(),
          tid: tid,
          near_send: nearSend,
          hit_count_for_offset: hitCounts[key],
          args: {
            a0: args[0].toString(),
            a1: args[1].toString(),
            a2: args[2].toString(),
            a3: args[3].toString(),
          },
          regs: collectRegs(this.context),
          backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
            .slice(0, 12)
            .map(DebugSymbol.fromAddress)
            .map(x => x.toString()),
        });
      },
    });
  }
  send({ type: 'info', msg: 'xref hooks installed', offsets: OFFSETS.map(x => x.toString()) });
}

const wx = Process.findModuleByName('Weixin.dll');
if (!wx) {
  send({ type: 'info', msg: 'Weixin.dll not loaded' });
} else {
  send({ type: 'info', msg: 'cgi xref runtime probe loaded', pid: Process.id, base: wx.base.toString() });
  installSendHooks();
  installOffsetHooks(wx);
}
