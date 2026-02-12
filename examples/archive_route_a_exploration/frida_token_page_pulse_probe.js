/*
Pulse-style token page monitor.
Re-arms MemoryAccessMonitor periodically so repeated accesses can be captured.
*/

'use strict';

const TOKEN = 'acc-r01-c01';
const TOKEN_HEX = Array.from(TOKEN).map(c => ('0' + c.charCodeAt(0).toString(16)).slice(-2)).join(' ');
const MAX_MATCH = 48;
const MAX_PAGES = 24;
const MAX_EVENTS = 260;
const PULSE_MS = 160;

let budget = MAX_EVENTS;
let monitorOn = false;
let lastSendMs = 0;
let sendBudget = 120;
let wx = null;

function nowMs() {
  return (new Date()).getTime();
}

function pageAlign(p) {
  return p.and(ptr('0xfffffffffffff000'));
}

function toOffset(addr) {
  if (!wx) return '';
  try {
    return '0x' + addr.sub(wx.base).toString(16);
  } catch (_) {
    return '';
  }
}

function inWeixin(addr) {
  let m = null;
  try {
    m = Process.findModuleByAddress(addr);
  } catch (_) {
    m = null;
  }
  if (!m) return false;
  const n = (m.name || '').toLowerCase();
  return n.indexOf('weixin') >= 0;
}

function discoverPages() {
  const pages = {};
  const rawHits = [];
  const ranges = Process.enumerateRanges('rw-');
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    if (r.size <= 0 || r.size > 16 * 1024 * 1024) continue;
    let hits = [];
    try {
      hits = Memory.scanSync(r.base, r.size, TOKEN_HEX);
    } catch (_) {
      continue;
    }
    for (let j = 0; j < hits.length; j++) {
      const a = hits[j].address;
      rawHits.push(a);
      pages[pageAlign(a).toString()] = pageAlign(a);
      if (rawHits.length >= MAX_MATCH) break;
    }
    if (rawHits.length >= MAX_MATCH) break;
  }
  const pageList = Object.keys(pages).slice(0, MAX_PAGES).map(k => pages[k]);
  return { rawHits: rawHits, pageList: pageList };
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
        try {
          if (n === 'send') {
            lenVal = args[2].toInt32();
          } else {
            const wsabuf = args[1];
            if (!wsabuf.isNull()) lenVal = wsabuf.add(Process.pointerSize).readU32();
          }
        } catch (_) {}
        send({
          type: 'send-event',
          t_ms: t,
          name: e.name,
          tid: Process.getCurrentThreadId(),
          len: lenVal,
        });
      },
    });
  }
}

function enableMonitor(pageList) {
  if (monitorOn) {
    try {
      MemoryAccessMonitor.disable();
    } catch (_) {}
    monitorOn = false;
  }
  const ranges = pageList.map(p => ({ base: p, size: 0x1000 }));
  if (ranges.length === 0) return;
  MemoryAccessMonitor.enable(ranges, {
    onAccess(details) {
      if (budget <= 0) return;
      const from = details.from;
      if (!inWeixin(from)) return;
      budget -= 1;
        const t = nowMs();
        let modName = '';
        try {
          const m = Process.findModuleByAddress(from);
          modName = m ? m.name : '';
        } catch (_) {}
        send({
          type: 'token-access',
          t_ms: t,
          tid: Process.getCurrentThreadId(),
          operation: details.operation,
          from: from.toString(),
          from_module: modName,
          from_symbol: DebugSymbol.fromAddress(from).toString(),
          from_offset: toOffset(from),
          ms_since_last_send: lastSendMs > 0 ? (t - lastSendMs) : -1,
      });
    },
  });
  monitorOn = true;
}

function bootstrap() {
  wx = Process.findModuleByName('Weixin.dll');
  if (!wx) {
    send({ type: 'info', msg: 'Weixin.dll not loaded' });
    return;
  }
  send({ type: 'info', msg: 'token page pulse probe loaded', pid: Process.id, base: wx.base.toString(), token: TOKEN });

  installSendHooks();
  const found = discoverPages();
  send({
    type: 'info',
    msg: 'token pages discovered',
    raw_hits: found.rawHits.map(x => x.toString()),
    page_count: found.pageList.length,
    pages: found.pageList.map(x => x.toString()),
  });
  if (found.pageList.length === 0) return;

  enableMonitor(found.pageList);
  setInterval(function () {
    if (budget <= 0) return;
    enableMonitor(found.pageList);
  }, PULSE_MS);
}

bootstrap();
