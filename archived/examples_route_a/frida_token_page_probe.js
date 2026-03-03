/*
Find comment token in process RW memory, then monitor accesses to token pages.
Used to locate callsites consuming plaintext comment before/around encryption.
*/

'use strict';

const TOKEN = 'acc-r01-c01';
const TOKEN_HEX = Array.from(TOKEN).map(c => ('0' + c.charCodeAt(0).toString(16)).slice(-2)).join(' ');
const MAX_MATCH = 32;
const MAX_PAGES = 20;
const MAX_EVENTS = 160;

let eventBudget = MAX_EVENTS;
let monitorEnabled = false;
let weixinMod = null;

function pageAlign(p) {
  return p.and(ptr('0xfffffffffffff000'));
}

function inWeixin(addr) {
  if (!weixinMod) return false;
  return addr.compare(weixinMod.base) >= 0 && addr.compare(weixinMod.base.add(weixinMod.size)) < 0;
}

function toOffset(addr) {
  if (!weixinMod) return '';
  try {
    return '0x' + addr.sub(weixinMod.base).toString(16);
  } catch (_) {
    return '';
  }
}

function discoverTokenPages() {
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
  return {
    rawHits: rawHits,
    pageList: pageList,
  };
}

function enableMonitor(pageList, rawHits) {
  if (monitorEnabled || pageList.length === 0) return;
  const ranges = pageList.map(p => ({ base: p, size: 0x1000 }));
  MemoryAccessMonitor.enable(ranges, {
    onAccess(details) {
      if (eventBudget <= 0) return;
      const from = details.from;
      if (!inWeixin(from)) return;
      eventBudget -= 1;
      send({
        type: 'token-page-access',
        operation: details.operation,
        from: from.toString(),
        from_symbol: DebugSymbol.fromAddress(from).toString(),
        from_offset: toOffset(from),
        address: details.address.toString(),
        range_index: details.rangeIndex,
      });
    },
  });
  monitorEnabled = true;
  send({
    type: 'info',
    msg: 'token monitor enabled',
    token: TOKEN,
    raw_hits: rawHits.map(x => x.toString()),
    page_count: pageList.length,
    pages: pageList.map(x => x.toString()),
  });
}

function bootstrap() {
  weixinMod = Process.findModuleByName('Weixin.dll');
  if (!weixinMod) {
    send({ type: 'info', msg: 'Weixin.dll not loaded' });
    return;
  }
  send({
    type: 'info',
    msg: 'token page probe loaded',
    pid: Process.id,
    token: TOKEN,
    base: weixinMod.base.toString(),
  });

  let attempts = 0;
  const timer = setInterval(function () {
    if (monitorEnabled) {
      clearInterval(timer);
      return;
    }
    attempts += 1;
    const found = discoverTokenPages();
    if (found.pageList.length > 0) {
      enableMonitor(found.pageList, found.rawHits);
      clearInterval(timer);
      return;
    }
    if (attempts <= 5 || attempts % 10 === 0) {
      send({ type: 'info', msg: 'token not found yet', attempts: attempts });
    }
    if (attempts >= 80) {
      clearInterval(timer);
      send({ type: 'info', msg: 'token probe timeout', attempts: attempts });
    }
  }, 600);
}

bootstrap();

