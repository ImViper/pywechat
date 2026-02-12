/*
Lightweight Winsock probe for Weixin.exe.
Hooks send/WSASend and prints buffers that contain URI-like markers.
*/

'use strict';

function safeReadUtf8(ptr, len) {
  try {
    return ptr.readUtf8String(len);
  } catch (_) {
    return '';
  }
}

function findExport(moduleCandidates, exportCandidates) {
  for (let i = 0; i < moduleCandidates.length; i++) {
    const name = moduleCandidates[i];
    const mod = Process.findModuleByName(name);
    if (!mod) continue;
    const exports = mod.enumerateExports();
    for (let j = 0; j < exportCandidates.length; j++) {
      const target = exportCandidates[j].toLowerCase();
      for (let k = 0; k < exports.length; k++) {
        const ex = exports[k];
        if (ex.type === 'function' && ex.name.toLowerCase() === target) {
          return ex.address;
        }
      }
    }
  }
  return null;
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

function looksInteresting(s) {
  if (!s) return false;
  const x = s.toLowerCase();
  return (
    x.indexOf('/cgi-bin/') >= 0 ||
    x.indexOf('micromsg-bin') >= 0 ||
    x.indexOf('mmsns') >= 0 ||
    x.indexOf('snscomment') >= 0 ||
    x.indexOf('timeline') >= 0
  );
}

function logHit(tag, size, ascii, hex, backtrace) {
  send({
    type: 'probe-hit',
    tag: tag,
    size: size,
    ascii_preview: ascii.slice(0, 220),
    hex_preview: hex.slice(0, 512),
    backtrace: backtrace || [],
  });
}

function asciiPrintableRatio(s) {
  if (!s || s.length === 0) return 0.0;
  let p = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 32 && c <= 126) p += 1;
  }
  return p / s.length;
}

let sampleBudget = 24;

function scanAndLog(tag, ptr, len, ctx) {
  const size = Number(len) || 0;
  if (!ptr || size <= 0) return;
  const cap = Math.min(size, 2048);
  let raw = null;
  try {
    raw = ptr.readByteArray(cap);
  } catch (_) {
    return;
  }
  const ascii = toAscii(raw);
  const backtrace = ctx
    ? Thread.backtrace(ctx, Backtracer.ACCURATE)
        .slice(0, 10)
        .map(DebugSymbol.fromAddress)
        .map(x => x.toString())
    : [];
  if (looksInteresting(ascii)) {
    logHit(tag, size, ascii, toHex(raw, 512), backtrace);
    return;
  }

  if (sampleBudget > 0 && size >= 120) {
    sampleBudget -= 1;
    const ratio = asciiPrintableRatio(ascii);
    send({
      type: 'probe-sample',
      tag: tag,
      size: size,
      ascii_ratio: Number(ratio.toFixed(3)),
      ascii_preview: ascii.slice(0, 120),
      hex_preview: toHex(raw, 80),
      backtrace: backtrace,
    });
  }
}

function hookSend() {
  let f = null;
  f = findExport(['ws2_32.dll', 'WS2_32.dll'], ['send', 'send@16']);
  if (!f) return false;
  Interceptor.attach(f, {
    onEnter(args) {
      const buf = args[1];
      const len = args[2].toInt32();
      scanAndLog('send', buf, len, this.context);
    },
  });
  send({ type: 'info', msg: 'hooked ws2_32!send' });
  return true;
}

function hookWSASend() {
  let f = null;
  f = findExport(['ws2_32.dll', 'WS2_32.dll'], ['WSASend', 'WSASend@28']);
  if (!f) return false;
  Interceptor.attach(f, {
    onEnter(args) {
      const bufs = args[1];
      const count = args[2].toInt32();
      const limit = Math.min(Math.max(count, 0), 16);
      for (let i = 0; i < limit; i++) {
        const base = bufs.add(i * Process.pointerSize * 2);
        const ptr = base.readPointer();
        const len = base.add(Process.pointerSize).readU32();
        scanAndLog('WSASend[' + i + ']', ptr, len, this.context);
      }
    },
  });
  send({ type: 'info', msg: 'hooked ws2_32!WSASend' });
  return true;
}

let hookedSend = false;
let hookedWSASend = false;
let tickCount = 0;

function tryHooks() {
  tickCount += 1;
  if (!hookedSend) hookedSend = hookSend();
  if (!hookedWSASend) hookedWSASend = hookWSASend();
  if (hookedSend && hookedWSASend) {
    send({ type: 'info', msg: 'all winsock hooks ready' });
    clearInterval(timerId);
  } else if (tickCount <= 6 || tickCount % 10 === 0) {
    const ws = Process.findModuleByName('ws2_32.dll') || Process.findModuleByName('WS2_32.dll');
    send({
      type: 'info',
      msg: 'waiting hooks',
      tick: tickCount,
      ws2_32_loaded: !!ws,
      ws2_32_base: ws ? ws.base.toString() : '',
    });
  }
}

send({
  type: 'info',
  msg: 'probe script loaded',
  pid: Process.id,
});

const timerId = setInterval(tryHooks, 500);
tryHooks();
