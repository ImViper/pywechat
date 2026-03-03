/*
Probe candidate Weixin.dll offsets around send() call chain.
Logs arguments/backtrace for near-send invocations and interesting string buffers.
*/

'use strict';

const OFFSETS = [
  ptr('0x435900b'),
  ptr('0x5622d7b'),
  ptr('0x49ffaf0'),
  ptr('0x49f95f2'),
  ptr('0x1df300e'),
];

const RECENT_SEND_WINDOW_MS = 600;
const MAX_LOGS = 120;
const MAX_ARG_BYTES = 256;
const MAX_ARGS = 8;

let logBudget = MAX_LOGS;
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
  for (let i = 0; i < lim; i++) {
    out += ('0' + u8[i].toString(16)).slice(-2);
  }
  return out;
}

function containsInteresting(s) {
  if (!s) return false;
  const x = s.toLowerCase();
  return (
    x.indexOf('/cgi-bin/') >= 0 ||
    x.indexOf('micromsg-bin') >= 0 ||
    x.indexOf('mmsns') >= 0 ||
    x.indexOf('snscomment') >= 0 ||
    x.indexOf('/mmtls/') >= 0 ||
    x.indexOf('http/1.1') >= 0
  );
}

function tryReadBuffer(ptrVal, maxBytes) {
  if (!ptrVal || ptrVal.isNull()) return null;
  let range = null;
  try {
    range = Process.findRangeByAddress(ptrVal);
  } catch (_) {
    range = null;
  }
  if (!range) return null;
  const base = range.base;
  const end = base.add(range.size);
  const remain = end.sub(ptrVal).toInt32();
  if (remain <= 0) return null;
  const n = Math.min(remain, maxBytes);
  if (n <= 0) return null;
  try {
    return ptrVal.readByteArray(n);
  } catch (_) {
    return null;
  }
}

function inspectArg(argPtr) {
  const out = {
    ptr: argPtr.toString(),
    ascii_preview: '',
    hex_preview: '',
    interesting: false,
  };
  const raw = tryReadBuffer(argPtr, MAX_ARG_BYTES);
  if (!raw) return out;
  const ascii = toAscii(raw);
  out.ascii_preview = ascii.slice(0, 140);
  out.hex_preview = toHex(raw, 96);
  out.interesting = containsInteresting(ascii);
  return out;
}

function installSendHooks() {
  const mod = Process.findModuleByName('ws2_32.dll') || Process.findModuleByName('WS2_32.dll');
  if (!mod) {
    send({ type: 'info', msg: 'ws2_32 not loaded for send hooks' });
    return;
  }
  const exports = mod.enumerateExports();
  let sendAddr = null;
  let wsaSendAddr = null;
  for (let i = 0; i < exports.length; i++) {
    const ex = exports[i];
    if (ex.type !== 'function') continue;
    const n = ex.name.toLowerCase();
    if (!sendAddr && n === 'send') sendAddr = ex.address;
    if (!wsaSendAddr && n === 'wsasend') wsaSendAddr = ex.address;
  }

  if (sendAddr) {
    Interceptor.attach(sendAddr, {
      onEnter(args) {
        const tid = Process.getCurrentThreadId();
        recentSendByTid[tid] = nowMs();
      },
    });
    send({ type: 'info', msg: 'hooked send', address: sendAddr.toString() });
  }

  if (wsaSendAddr) {
    Interceptor.attach(wsaSendAddr, {
      onEnter(args) {
        const tid = Process.getCurrentThreadId();
        recentSendByTid[tid] = nowMs();
      },
    });
    send({ type: 'info', msg: 'hooked WSASend', address: wsaSendAddr.toString() });
  }
}

function installOffsetHooks(mod) {
  for (let i = 0; i < OFFSETS.length; i++) {
    const off = OFFSETS[i];
    const addr = mod.base.add(off);
    Interceptor.attach(addr, {
      onEnter(args) {
        if (logBudget <= 0) return;
        const tid = Process.getCurrentThreadId();
        const t = nowMs();
        const last = recentSendByTid[tid] || 0;
        const nearSend = (t - last) >= 0 && (t - last) <= RECENT_SEND_WINDOW_MS;

        const inspected = [];
        let anyInteresting = false;
        for (let k = 0; k < MAX_ARGS; k++) {
          const info = inspectArg(args[k]);
          if (info.interesting) anyInteresting = true;
          inspected.push(info);
        }

        if (!nearSend && !anyInteresting) {
          return;
        }

        logBudget -= 1;
        send({
          type: 'offset-probe',
          offset: off.toString(),
          address: addr.toString(),
          tid: tid,
          near_send: nearSend,
          args: inspected,
          backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
            .slice(0, 10)
            .map(DebugSymbol.fromAddress)
            .map(x => x.toString()),
        });
      },
    });
  }
  send({
    type: 'info',
    msg: 'offset hooks installed',
    offsets: OFFSETS.map(x => x.toString()),
  });
}

const weixin = Process.findModuleByName('Weixin.dll');
if (!weixin) {
  send({ type: 'info', msg: 'Weixin.dll not loaded' });
} else {
  send({ type: 'info', msg: 'offset args probe loaded', pid: Process.id, base: weixin.base.toString() });
  installSendHooks();
  installOffsetHooks(weixin);
}

