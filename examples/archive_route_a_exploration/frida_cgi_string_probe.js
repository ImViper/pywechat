/*
Track access to Weixin.dll CGI string memory pages.
Goal: find call-sites touching mmsnscomment before transport encryption.
*/

'use strict';

const NEEDLES = [
  '/cgi-bin/micromsg-bin/mmsnscomment',
  '/cgi-bin/micromsg-bin/mmsnstimeline',
  '/cgi-bin/micromsg-bin/mmsnspost',
];

let budget = 120;

function pageAlign(ptrVal) {
  return ptrVal.and(ptr('0xfffffffffffff000'));
}

function findNeedle(mod, needle) {
  const hex = Array.from(needle).map(c => ('0' + c.charCodeAt(0).toString(16)).slice(-2)).join(' ');
  try {
    return Memory.scanSync(mod.base, mod.size, hex);
  } catch (_) {
    return [];
  }
}

function setupMonitor() {
  const mod = Process.findModuleByName('Weixin.dll');
  if (!mod) {
    send({ type: 'info', msg: 'Weixin.dll not loaded yet' });
    return false;
  }

  const ranges = [];
  for (let i = 0; i < NEEDLES.length; i++) {
    const n = NEEDLES[i];
    const matches = findNeedle(mod, n);
    for (let j = 0; j < matches.length; j++) {
      const m = matches[j];
      const base = pageAlign(m.address);
      ranges.push({ base: base, size: 0x1000, needle: n, address: m.address });
    }
  }

  if (ranges.length === 0) {
    send({ type: 'info', msg: 'no needle matches in Weixin.dll' });
    return false;
  }

  // Deduplicate page ranges.
  const dedup = {};
  const memRanges = [];
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    const key = r.base.toString();
    if (dedup[key]) continue;
    dedup[key] = true;
    memRanges.push({ base: r.base, size: r.size });
  }

  send({
    type: 'info',
    msg: 'monitor enabled',
    module_base: mod.base.toString(),
    module_size: mod.size,
    needle_hits: ranges.map(r => ({
      needle: r.needle,
      address: r.address.toString(),
      page: r.base.toString(),
    })),
    monitored_pages: memRanges.length,
  });

  MemoryAccessMonitor.enable(memRanges, {
    onAccess(details) {
      if (budget <= 0) return;
      budget -= 1;
      send({
        type: 'cgi-access',
        operation: details.operation,
        from: details.from.toString(),
        from_symbol: DebugSymbol.fromAddress(details.from).toString(),
        address: details.address.toString(),
        range_base: details.rangeIndex >= 0 && details.rangeIndex < memRanges.length
          ? memRanges[details.rangeIndex].base.toString()
          : '',
      });
    },
  });

  return true;
}

send({ type: 'info', msg: 'cgi string probe loaded', pid: Process.id });

let started = false;
const timer = setInterval(function () {
  if (started) return;
  started = setupMonitor();
  if (started) {
    clearInterval(timer);
  }
}, 600);
