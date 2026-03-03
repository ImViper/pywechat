"use strict";

var mainMod = Process.findModuleByName("Weixin.dll");
if (!mainMod) mainMod = Process.findModuleByName("WeChatWin.dll");
send("[+] Module: " + mainMod.name + " base=" + mainMod.base + " size=" + (mainMod.size/1024/1024).toFixed(1) + "MB");

// Find send/WSASend via export enumeration
var ws2 = Process.getModuleByName("WS2_32.dll");
var sendAddr = null, wsaSendAddr = null;
var exps = ws2.enumerateExports();
for (var i = 0; i < exps.length; i++) {
    if (exps[i].name === "send") sendAddr = exps[i].address;
    if (exps[i].name === "WSASend") wsaSendAddr = exps[i].address;
}
send("[+] send=" + sendAddr + " WSASend=" + wsaSendAddr);

// Scan for /cgi-bin/micromsg-bin/mmsnscomment
var needle = "/cgi-bin/micromsg-bin/mmsnscomment";
var hexPat = [];
for (var c = 0; c < needle.length; c++) {
    hexPat.push(("0" + needle.charCodeAt(c).toString(16)).slice(-2));
}
var results = Memory.scanSync(mainMod.base, mainMod.size, hexPat.join(" "));
send("[scan] mmsnscomment: " + results.length + " matches");
for (var r = 0; r < results.length; r++) {
    send("  " + results[r].address + " (+0x" + results[r].address.sub(mainMod.base).toString(16) + ")");
}

// Scan for SnsCommentRequest
var needle2 = "SnsCommentRequest";
hexPat = [];
for (var c = 0; c < needle2.length; c++) {
    hexPat.push(("0" + needle2.charCodeAt(c).toString(16)).slice(-2));
}
results = Memory.scanSync(mainMod.base, mainMod.size, hexPat.join(" "));
send("[scan] SnsCommentRequest: " + results.length + " matches");
for (var r = 0; r < Math.min(results.length, 5); r++) {
    send("  " + results[r].address + " (+0x" + results[r].address.sub(mainMod.base).toString(16) + ")");
}

function formatStack(ctx) {
    var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    var lines = [];
    for (var i = 0; i < Math.min(bt.length, 20); i++) {
        var addr = bt[i];
        var off = addr.sub(mainMod.base);
        if (off.compare(0) >= 0 && off.compare(mainMod.size) < 0) {
            lines.push("  [" + i + "] Weixin.dll+0x" + off.toString(16));
        } else {
            lines.push("  [" + i + "] " + addr + " " + DebugSymbol.fromAddress(addr));
        }
    }
    return lines.join("\n");
}

// Hook send()
if (sendAddr) {
    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (this.len > 20) {
                try {
                    var arr = new Uint8Array(this.buf.readByteArray(Math.min(this.len, 300)));
                    var ascii = "";
                    for (var i = 0; i < arr.length; i++) {
                        ascii += (arr[i] >= 32 && arr[i] < 127) ? String.fromCharCode(arr[i]) : ".";
                    }
                    var lo = ascii.toLowerCase();
                    if (lo.indexOf("sns") !== -1 || lo.indexOf("comment") !== -1 || lo.indexOf("mmsns") !== -1) {
                        send("\n=== send() " + this.len + " bytes, SNS-related ===");
                        send("preview: " + ascii.substring(0, 200));
                        send(formatStack(this.context));
                    }
                } catch(e) {}
            }
        }
    });
    send("[+] Hooked send()");
}

// Hook WSASend()
if (wsaSendAddr) {
    Interceptor.attach(wsaSendAddr, {
        onEnter: function(args) {
            this.bufs = args[1];
            this.cnt = args[2].toInt32();
            if (this.cnt > 0) {
                this.dlen = this.bufs.readU32();
                this.dptr = this.bufs.add(Process.pointerSize).readPointer();
            }
        },
        onLeave: function(retval) {
            if (this.cnt > 0 && this.dlen > 20) {
                try {
                    var arr = new Uint8Array(this.dptr.readByteArray(Math.min(this.dlen, 300)));
                    var ascii = "";
                    for (var i = 0; i < arr.length; i++) {
                        ascii += (arr[i] >= 32 && arr[i] < 127) ? String.fromCharCode(arr[i]) : ".";
                    }
                    var lo = ascii.toLowerCase();
                    if (lo.indexOf("sns") !== -1 || lo.indexOf("comment") !== -1 || lo.indexOf("mmsns") !== -1) {
                        send("\n=== WSASend() " + this.dlen + " bytes, SNS-related ===");
                        send("preview: " + ascii.substring(0, 200));
                        send(formatStack(this.context));
                    }
                } catch(e) {}
            }
        }
    });
    send("[+] Hooked WSASend()");
}

send("\n[+] READY - Go post a comment in WeChat Moments now!");
