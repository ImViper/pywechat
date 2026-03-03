/*
Resolve module info for one absolute address.
Set TARGET_ADDR below before running.
*/

'use strict';

const TARGET_ADDR = ptr('0x7ff8b94f002f');

let m = null;
try {
  m = Process.findModuleByAddress(TARGET_ADDR);
} catch (_) {
  m = null;
}

send({
  type: 'addr-module',
  target: TARGET_ADDR.toString(),
  module: m ? m.name : '',
  base: m ? m.base.toString() : '',
  size: m ? m.size : 0,
  symbol: DebugSymbol.fromAddress(TARGET_ADDR).toString(),
});

