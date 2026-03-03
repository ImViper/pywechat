/*
Search for comment token (e.g. "acc-r") in memory reachable from candidate
call-chain arguments near send().
*/

'use strict';

const OFFSETS = [
  ptr('0x435900b'),
  ptr('0x5622d7b'),
  ptr('0x49ffaf0'),
  ptr('0x49f95f2'),
];

const TOKEN = 'acc-r';
const TOKEN_HEX = Array.from(TOKEN).map(c => ('0' + c.charCodeAt(0).toString(16)).slice(-2)).join('');
const MAX_HITS = 50;
const SCAN_ARGS = 8;
const MAX_BYTES_PER_ARG = 0x1000;
const RECENT_SEND_WINDOW_MS = 900;

let budget = MAX_HITS;
const recentSendByTid = {};

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

function safeRangeRead(ptrVal, maxBytes) {
  if (!ptrVal || ptrVal.isNull()) return null;
  const r = Process.findRangeByAddress(ptrVal);
  if (!r) return null;
  const remain = r.base.add(r.size).sub(ptrVal).toInt32();
  if (remain <= 0) return null;
  const n = Math.min(remain, maxBytes);
  try {
    return ptrVal.readByteArray(n);
  } catch (_) {
    return null;
  }
}

function indexOfHex(hay, needle) {
  if (!hay || !needle) return -1;
  return hay.indexOf(needle);
}

function installSendHooks() {
  const mod = Process.findModuleByName('ws2_32.dll') || Process.findModuleByName('WS2_32.dll');
  if (!mod) return;
  const exports = mod.enumerateExports();
  for (let i = 0; i < exports.length; i++) {
    const ex = exports[i];
    if (ex.type !== 'function') continue;
    const n = ex.name.toLowerCase();
    if (n === 'send' || n === 'wsasend') {
      Interceptor.attach(ex.address, {
        onEnter(_args) {
          recentSendByTid[Process.getCurrentThreadId()] = nowMs();
        },
      });
    }
  }
}

function installOffsetHooks(mod) {
  for (let i = 0; i < OFFSETS.length; i++) {
    const off = OFFSETS[i];
    const addr = mod.base.add(off);
    Interceptor.attach(addr, {
      onEnter(args) {
        if (budget <= 0) return;
        const tid = Process.getCurrentThreadId();
        const nearSend = (nowMs() - (recentSendByTid[tid] || 0)) <= RECENT_SEND_WINDOW_MS;
        if (!nearSend) return;

        for (let k = 0; k < SCAN_ARGS; k++) {
          const p = args[k];
          const raw = safeRangeRead(p, MAX_BYTES_PER_ARG);
          if (!raw) continue;
          const hex = toHex(raw, MAX_BYTES_PER_ARG);
          const idx = indexOfHex(hex, TOKEN_HEX);
          if (idx < 0) continue;

          budget -= 1;
          const byteIdx = Math.floor(idx / 2);
          const ascii = toAscii(raw);
          send({
            type: 'comment-token-hit',
            token: TOKEN,
            offset: off.toString(),
            address: addr.toString(),
            tid: tid,
            arg_index: k,
            arg_ptr: p.toString(),
            hit_byte_index: byteIdx,
            ascii_preview: ascii.slice(Math.max(0, byteIdx - 48), Math.max(0, byteIdx - 48) + 180),
            hex_preview: hex.slice(Math.max(0, idx - 128), Math.max(0, idx - 128) + 400),
            backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
              .slice(0, 10)
              .map(DebugSymbol.fromAddress)
              .map(x => x.toString()),
          });
        }
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
    msg: 'comment token probe loaded',
    pid: Process.id,
    base: mod.base.toString(),
    token: TOKEN,
    offsets: OFFSETS.map(x => x.toString()),
  });
  installSendHooks();
  installOffsetHooks(mod);
}

