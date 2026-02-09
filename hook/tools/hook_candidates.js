"use strict";

/**
 * 动态 Hook 所有候选评论函数 — 捕获调用顺序和参数
 *
 * 使用: python run_frida_trace.py --pid <PID> --script hook_candidates.js
 * 或:  frida -p <PID> -l hook_candidates.js
 *
 * 然后在微信朋友圈手动发一条评论，观察输出。
 */

var mainMod = Process.findModuleByName("Weixin.dll");
if (!mainMod) mainMod = Process.findModuleByName("WeChatWin.dll");
if (!mainMod) {
    send("[ERROR] Cannot find Weixin.dll or WeChatWin.dll");
    throw new Error("WeChat module not found");
}
send("[+] Module: " + mainMod.name + " base=" + mainMod.base +
     " size=" + (mainMod.size/1024/1024).toFixed(1) + "MB");

// 全局调用序号
var callSeq = 0;

// 候选函数表 (RVA -> 名称)
var candidates = {
    // Protobuf 构造/工厂
    0x04924ff0: "SnsCommentRequest_proto",
    0x04925540: "SnsCommentResponse_proto",
    0x048fb690: "SnsCommentContentRequest_proto",

    // CGI 路径设置
    0x029de330: "mmsnscomment_cgi_A",
    0x02a10a70: "mmsnscomment_cgi_B",

    // SNS 业务逻辑
    0x05af06b0: "SnsComment_logic",

    // mmsnscomment_cgi_A 的调用链
    0x029dc871: "cgi_A_caller_1",
    0x049e9240: "cgi_A_caller_2",
    0x049bdc10: "cgi_A_caller_3_TOP",

    // mmsnscomment_cgi_B 的调用链
    0x02a10630: "cgi_B_caller_1",
    0x02a105a0: "cgi_B_caller_2_TOP",

    // Vtable 邻近函数 (SnsCommentRequest 类)
    0x04934e40: "SnsCommentReq_vtbl_m1",
    0x049248c0: "SnsCommentReq_vtbl_p1",
    0x04924900: "SnsCommentReq_vtbl_p2",
    0x04924f70: "SnsCommentReq_vtbl_p3",
};

function tryReadString(ptr, maxLen) {
    if (ptr.isNull()) return "<null>";
    maxLen = maxLen || 128;
    var results = [];

    // Try UTF-16LE
    try {
        var s = ptr.readUtf16String(maxLen);
        if (s && s.length > 0 && s.length < maxLen) {
            results.push("UTF16: \"" + s.substring(0, 80) + "\"");
        }
    } catch(e) {}

    // Try UTF-8
    try {
        var s = ptr.readUtf8String(maxLen);
        if (s && s.length > 1 && s.length < maxLen && /^[\x20-\x7e\u4e00-\u9fff]/.test(s)) {
            results.push("UTF8: \"" + s.substring(0, 80) + "\"");
        }
    } catch(e) {}

    // Try as pointer (dereference once)
    try {
        var deref = ptr.readPointer();
        if (!deref.isNull()) {
            try {
                var s2 = deref.readUtf16String(64);
                if (s2 && s2.length > 0 && s2.length < 64) {
                    results.push("*UTF16: \"" + s2.substring(0, 60) + "\"");
                }
            } catch(e) {}
            try {
                var s2 = deref.readUtf8String(64);
                if (s2 && s2.length > 1 && s2.length < 64 && /^[\x20-\x7e\u4e00-\u9fff]/.test(s2)) {
                    results.push("*UTF8: \"" + s2.substring(0, 60) + "\"");
                }
            } catch(e) {}
        }
    } catch(e) {}

    return results.length > 0 ? results.join(" | ") : "";
}

function hexPreview(ptr, len) {
    try {
        var bytes = ptr.readByteArray(Math.min(len, 64));
        if (!bytes) return "";
        var arr = new Uint8Array(bytes);
        var hex = [];
        for (var i = 0; i < arr.length; i++) {
            hex.push(("0" + arr[i].toString(16)).slice(-2));
        }
        return hex.join(" ");
    } catch(e) {
        return "";
    }
}

function formatStack(ctx) {
    var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    var lines = [];
    for (var i = 0; i < Math.min(bt.length, 15); i++) {
        var addr = bt[i];
        var off = addr.sub(mainMod.base);
        if (off.compare(0) >= 0 && off.compare(mainMod.size) < 0) {
            var offHex = off.toString(16);
            // Check if this offset matches a known candidate
            var name = "";
            for (var rva in candidates) {
                if (parseInt(rva).toString(16) === offHex ||
                    Math.abs(parseInt(offHex, 16) - parseInt(rva)) < 16) {
                    name = " =" + candidates[rva];
                }
            }
            lines.push("  [" + i + "] " + mainMod.name + "+0x" + offHex + name);
        } else {
            lines.push("  [" + i + "] " + addr + " " + DebugSymbol.fromAddress(addr));
        }
    }
    return lines.join("\n");
}

// Hook each candidate
var hooked = 0;
var failed = 0;

for (var rvaStr in candidates) {
    var rva = parseInt(rvaStr);
    var name = candidates[rvaStr];
    var addr = mainMod.base.add(rva);

    try {
        (function(funcName, funcRva) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    var seq = ++callSeq;
                    this._seq = seq;
                    this._name = funcName;
                    this._time = Date.now();

                    var msg = "\n>>>>>> [" + seq + "] ENTER " + funcName +
                              " (RVA 0x" + funcRva.toString(16) + ") " +
                              "tid=" + Process.getCurrentThreadId();

                    // Dump first 6 args
                    for (var i = 0; i < 6; i++) {
                        var argVal = args[i];
                        var strInfo = tryReadString(argVal);
                        msg += "\n  arg" + i + " = " + argVal;
                        if (strInfo) msg += "  " + strInfo;
                    }

                    // Hex preview of arg0 (might be 'this' pointer / struct)
                    var hex0 = hexPreview(args[0], 64);
                    if (hex0) msg += "\n  arg0 hex: " + hex0;

                    // Stack
                    msg += "\n  Stack:\n" + formatStack(this.context);
                    send(msg);
                },
                onLeave: function(retval) {
                    var elapsed = Date.now() - this._time;
                    send("<<<<<< [" + this._seq + "] LEAVE " + this._name +
                         " ret=" + retval + " (" + elapsed + "ms)");
                }
            });
            hooked++;
        })(name, rva);
    } catch(e) {
        send("[!] Failed to hook " + name + " @ 0x" + rva.toString(16) + ": " + e);
        failed++;
    }
}

send("\n[+] Hooked " + hooked + " functions, " + failed + " failed");
send("[+] Now go to WeChat Moments and post a comment!");
send("[+] The call sequence numbers will show the execution order.\n");
