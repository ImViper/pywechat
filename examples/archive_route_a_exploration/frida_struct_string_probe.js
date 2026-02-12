/*
Probe candidate function by scanning argument structures for embedded pointers
to CGI strings (e.g. /cgi-bin/micromsg-bin/mmsnscomment).
*/

'use strict';

const TARGET_OFFSET = ptr('0x1df300e');
const MAX_HITS = 80;
const SCAN_ARGS = [0, 1, 2, 3];
const SCAN_SIZE = 0x600;
const PTR_STEP = Process.pointerSize;

let budget = MAX_HITS;

function containsNeedle(s) {
  if (!s) return false;
  const x = s.toLowerCase();
  return x.indexOf('/cgi-bin/micromsg-bin/') >= 0 || x.indexOf('mmsns') >= 0;
}

function safeReadAscii(p, n) {
  try {
    const raw = p.readByteArray(n);
    if (!raw) return '';
    const u8 = new Uint8Array(raw);
    let out = '';
    for (let i = 0; i < u8.length; i++) {
      const c = u8[i];
      if (c === 0) break;
      out += (c >= 32 && c <= 126) ? String.fromCharCode(c) : '.';
    }
    return out;
  } catch (_) {
    return '';
  }
}

function inModule(ptrVal, mod) {
  if (!ptrVal || ptrVal.isNull()) return false;
  return ptrVal.compare(mod.base) >= 0 && ptrVal.compare(mod.base.add(mod.size)) < 0;
}

function scanStructForCgi(structPtr, mod) {
  const hits = [];
  if (!structPtr || structPtr.isNull()) return hits;
  const r = Process.findRangeByAddress(structPtr);
  if (!r) return hits;
  const maxN = Math.min(SCAN_SIZE, r.base.add(r.size).sub(structPtr).toInt32());
  for (let off = 0; off + PTR_STEP <= maxN; off += PTR_STEP) {
    let p = null;
    try {
      p = structPtr.add(off).readPointer();
    } catch (_) {
      continue;
    }
    if (!inModule(p, mod)) continue;
    const s = safeReadAscii(p, 120);
    if (!containsNeedle(s)) continue;
    hits.push({
      struct_offset: '0x' + off.toString(16),
      target_ptr: p.toString(),
      str: s,
    });
    if (hits.length >= 8) break;
  }
  return hits;
}

const mod = Process.findModuleByName('Weixin.dll');
if (!mod) {
  send({ type: 'info', msg: 'Weixin.dll not loaded' });
} else {
  const addr = mod.base.add(TARGET_OFFSET);
  send({
    type: 'info',
    msg: 'struct probe loaded',
    pid: Process.id,
    base: mod.base.toString(),
    target: addr.toString(),
    offset: TARGET_OFFSET.toString(),
  });

  Interceptor.attach(addr, {
    onEnter(args) {
      if (budget <= 0) return;
      const allHits = [];
      for (let i = 0; i < SCAN_ARGS.length; i++) {
        const ai = SCAN_ARGS[i];
        const p = args[ai];
        const h = scanStructForCgi(p, mod);
        if (h.length > 0) {
          allHits.push({
            arg_index: ai,
            arg_ptr: p.toString(),
            refs: h,
          });
        }
      }
      if (allHits.length === 0) return;
      budget -= 1;
      send({
        type: 'struct-cgi-hit',
        target: addr.toString(),
        hits: allHits,
        backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
          .slice(0, 10)
          .map(DebugSymbol.fromAddress)
          .map(x => x.toString()),
      });
    },
  });
}

