/*
Probe a candidate Weixin.dll callsite observed from CGI string page access.
*/

'use strict';

const CANDIDATE_OFFSETS = [
  ptr('0x1df300e'),
  ptr('0x1df38d2'),
  ptr('0x74e2b8'),
];

let budget = 40;

function tryReadUtf8(p) {
  if (!p) return '';
  try {
    const s = p.readUtf8String();
    return s || '';
  } catch (_) {
    return '';
  }
}

function maybeStr(x) {
  const s = tryReadUtf8(x);
  if (!s) return '';
  if (s.length > 220) return s.slice(0, 220);
  return s;
}

function hasNeedle(s) {
  const x = (s || '').toLowerCase();
  return (
    x.indexOf('/cgi-bin/') >= 0 ||
    x.indexOf('mmsns') >= 0 ||
    x.indexOf('acc-r') >= 0 ||
    x.indexOf('/mmtls/') >= 0
  );
}

function attachCandidate(modBase, off) {
  const addr = modBase.add(off);
  Interceptor.attach(addr, {
    onEnter(args) {
      if (budget <= 0) return;
      const a0 = maybeStr(args[0]);
      const a1 = maybeStr(args[1]);
      const a2 = maybeStr(args[2]);
      const a3 = maybeStr(args[3]);

      budget -= 1;
      send({
        type: 'candidate-hit',
        address: addr.toString(),
        offset: off.toString(),
        args: {
          a0: a0,
          a1: a1,
          a2: a2,
          a3: a3,
          p0: args[0].toString(),
          p1: args[1].toString(),
          p2: args[2].toString(),
          p3: args[3].toString(),
        },
        backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
          .slice(0, 8)
          .map(DebugSymbol.fromAddress)
          .map(x => x.toString()),
      });
    },
  });
}

const mod = Process.findModuleByName('Weixin.dll');
if (!mod) {
  send({ type: 'info', msg: 'Weixin.dll not loaded' });
} else {
  send({ type: 'info', msg: 'candidate probe loaded', base: mod.base.toString(), pid: Process.id });
  for (let i = 0; i < CANDIDATE_OFFSETS.length; i++) {
    attachCandidate(mod.base, CANDIDATE_OFFSETS[i]);
  }
  send({
    type: 'info',
    msg: 'candidate hooks installed',
    offsets: CANDIDATE_OFFSETS.map(x => x.toString()),
  });
}
