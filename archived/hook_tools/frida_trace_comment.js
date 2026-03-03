/**
 * Frida 动态追踪脚本 —— 定位 WeChat 朋友圈评论函数
 *
 * 使用方法:
 *   frida -p <wechat_pid> -l frida_trace_comment.js
 *   或通过 run_frida_trace.py 启动
 *
 * 工作原理:
 *   1. Hook WS2_32!send / WS2_32!WSASend 等网络发送函数
 *   2. 在微信中手动发一条朋友圈评论
 *   3. 网络 hook 命中时打印完整调用栈 + 发送数据预览
 *   4. 从调用栈中找到 WeChatWin.dll 内的评论业务函数
 *
 * 步骤:
 *   Phase 1: 运行脚本, 手动发评论, 观察 send 调用栈
 *   Phase 2: 根据调用栈定位 WeChatWin.dll 内的候选函数
 *   Phase 3: 对候选函数设置精确 hook, 分析参数
 */

"use strict";

// =========================================================================
// 配置
// =========================================================================

var CONFIG = {
    // 是否 hook send/WSASend (Phase 1)
    hookNetwork: true,
    // 是否 hook SSL (需要时启用, 微信可能用 SSL)
    hookSSL: true,
    // 网络发送数据预览长度
    dataPreviewLen: 256,
    // 打印调用栈深度
    stackDepth: 30,
    // 只关注包含这些关键字的数据包 (空数组 = 全部)
    dataFilters: [],
    // WeChatWin.dll 基址 (运行时自动获取)
    wechatWinBase: null,
    wechatWinSize: 0,
};

// =========================================================================
// 工具函数
// =========================================================================

function hexdump_short(ptr, len) {
    try {
        var bytes = ptr.readByteArray(Math.min(len, CONFIG.dataPreviewLen));
        if (!bytes) return "<null>";
        var arr = new Uint8Array(bytes);
        var hex = [];
        var ascii = [];
        for (var i = 0; i < arr.length; i++) {
            hex.push(("0" + arr[i].toString(16)).slice(-2));
            ascii.push(arr[i] >= 32 && arr[i] < 127 ? String.fromCharCode(arr[i]) : ".");
        }
        return hex.join(" ") + "\n  ASCII: " + ascii.join("");
    } catch (e) {
        return "<read error: " + e + ">";
    }
}

function formatStack(ctx) {
    var bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    var lines = [];
    for (var i = 0; i < Math.min(bt.length, CONFIG.stackDepth); i++) {
        var addr = bt[i];
        var sym = DebugSymbol.fromAddress(addr);
        var inWeChatWin = false;
        if (CONFIG.wechatWinBase) {
            var offset = addr.sub(CONFIG.wechatWinBase);
            if (offset.compare(0) >= 0 && offset.compare(CONFIG.wechatWinSize) < 0) {
                inWeChatWin = true;
                lines.push("  [" + i + "] " + addr + "  WeChatWin.dll+0x" + offset.toString(16) + "  " + sym.name);
                continue;
            }
        }
        lines.push("  [" + i + "] " + addr + "  " + sym);
    }
    return lines.join("\n");
}

function getModuleInfo(name) {
    var mod = Process.findModuleByName(name);
    if (mod) {
        return { base: mod.base, size: mod.size, path: mod.path };
    }
    return null;
}

// =========================================================================
// 初始化
// =========================================================================

(function init() {
    console.log("[pywechat] Frida tracer loaded");
    console.log("[pywechat] PID: " + Process.id);
    console.log("[pywechat] Arch: " + Process.arch);

    // WeChat 4.0+ renamed WeChatWin.dll to Weixin.dll
    var wechatWin = getModuleInfo("Weixin.dll") || getModuleInfo("WeChatWin.dll");
    if (wechatWin) {
        CONFIG.wechatWinBase = wechatWin.base;
        CONFIG.wechatWinSize = wechatWin.size;
        var modName = wechatWin.path.split("\\").pop();
        console.log("[pywechat] " + modName + " base: " + wechatWin.base +
                    " size: 0x" + wechatWin.size.toString(16) +
                    " (" + (wechatWin.size / 1024 / 1024).toFixed(1) + " MB)");
        console.log("[pywechat] Path: " + wechatWin.path);
    } else {
        console.log("[pywechat] WARNING: Neither Weixin.dll nor WeChatWin.dll found!");
    }

    // 枚举所有已加载模块
    console.log("\n[pywechat] Loaded modules:");
    Process.enumerateModules().forEach(function(m) {
        if (m.name.toLowerCase().indexOf("wechat") !== -1 ||
            m.name.toLowerCase().indexOf("wx") !== -1) {
            console.log("  " + m.name + " @ " + m.base + " size=0x" + m.size.toString(16));
        }
    });
    console.log("");
})();

// =========================================================================
// Phase 1: Hook 网络发送函数
// =========================================================================

if (CONFIG.hookNetwork) {
    // Hook send()
    var sendAddr = Module.findExportByName("WS2_32.dll", "send");
    if (sendAddr) {
        Interceptor.attach(sendAddr, {
            onEnter: function(args) {
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (this.len > 0) {
                    console.log("\n========== WS2_32!send (" + this.len + " bytes) ==========");
                    console.log("  Data: " + hexdump_short(this.buf, this.len));
                    console.log("  Call stack:");
                    console.log(formatStack(this.context));
                }
            }
        });
        console.log("[pywechat] Hooked WS2_32!send @ " + sendAddr);
    }

    // Hook WSASend()
    var wsaSendAddr = Module.findExportByName("WS2_32.dll", "WSASend");
    if (wsaSendAddr) {
        Interceptor.attach(wsaSendAddr, {
            onEnter: function(args) {
                this.socket = args[0];
                this.buffers = args[1]; // LPWSABUF array
                this.bufCount = args[2].toInt32();
                // Read first WSABUF { len, buf }
                if (this.bufCount > 0) {
                    this.dataLen = this.buffers.readU32();
                    this.dataBuf = this.buffers.add(Process.pointerSize).readPointer();
                }
            },
            onLeave: function(retval) {
                if (this.bufCount > 0 && this.dataLen > 0) {
                    console.log("\n========== WS2_32!WSASend (" + this.dataLen + " bytes) ==========");
                    console.log("  Data: " + hexdump_short(this.dataBuf, this.dataLen));
                    console.log("  Call stack:");
                    console.log(formatStack(this.context));
                }
            }
        });
        console.log("[pywechat] Hooked WS2_32!WSASend @ " + wsaSendAddr);
    }
}

// =========================================================================
// Phase 1b: Hook SSL (微信通常走 TLS)
// =========================================================================

if (CONFIG.hookSSL) {
    // 尝试 hook BoringSSL / OpenSSL 的 SSL_write
    var sslModules = ["WeChatWin.dll", "libssl.dll", "ssleay32.dll"];
    var sslWriteNames = ["SSL_write", "ssl_write"];

    sslModules.forEach(function(modName) {
        var mod = Process.findModuleByName(modName);
        if (!mod) return;

        // 搜索导出的 SSL_write
        sslWriteNames.forEach(function(funcName) {
            var addr = Module.findExportByName(modName, funcName);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        this.buf = args[1];
                        this.len = args[2].toInt32();
                    },
                    onLeave: function(retval) {
                        if (this.len > 10) {
                            console.log("\n========== " + modName + "!" + funcName +
                                        " (" + this.len + " bytes) ==========");
                            console.log("  Data: " + hexdump_short(this.buf, this.len));
                            console.log("  Call stack:");
                            console.log(formatStack(this.context));
                        }
                    }
                });
                console.log("[pywechat] Hooked " + modName + "!" + funcName + " @ " + addr);
            }
        });
    });
}

// =========================================================================
// Phase 2: 搜索 WeChatWin.dll 中的 SNS 字符串引用
// =========================================================================

(function scanSNSStrings() {
    if (!CONFIG.wechatWinBase) return;

    console.log("\n[pywechat] Scanning WeChatWin.dll for SNS strings...");
    var keywords = [
        "SnsComment", "sns_comment", "AddComment", "DoComment",
        "snsId", "sns_id", "SnsPost", "SnsObject",
        "/cgi-bin/micromsg-bin/mmsns",
        "mmsnsweb", "SnsTimeLine", "comment"
    ];

    var results = [];
    keywords.forEach(function(kw) {
        var matches = Memory.scanSync(CONFIG.wechatWinBase, CONFIG.wechatWinSize,
            stringToPattern(kw));
        if (matches.length > 0) {
            console.log("  Found '" + kw + "': " + matches.length + " matches");
            matches.forEach(function(m) {
                var offset = m.address.sub(CONFIG.wechatWinBase);
                console.log("    " + m.address + " (WeChatWin.dll+0x" + offset.toString(16) + ")");
                results.push({ keyword: kw, address: m.address, offset: offset });
            });
        }
    });

    if (results.length > 0) {
        console.log("\n[pywechat] Total SNS string matches: " + results.length);
        console.log("[pywechat] Use these addresses for cross-reference in IDA/Ghidra");
    } else {
        console.log("[pywechat] No SNS strings found (try UTF-16 search)");
    }

    // Also try UTF-16LE patterns for Chinese strings
    var utf16Keywords = ["\u8BC4\u8BBA"]; // "评论"
    utf16Keywords.forEach(function(kw) {
        var pattern = utf16ToPattern(kw);
        if (pattern) {
            var matches = Memory.scanSync(CONFIG.wechatWinBase, CONFIG.wechatWinSize, pattern);
            if (matches.length > 0) {
                console.log("  Found UTF-16 '" + kw + "': " + matches.length + " matches");
                matches.slice(0, 10).forEach(function(m) {
                    var offset = m.address.sub(CONFIG.wechatWinBase);
                    console.log("    " + m.address + " (WeChatWin.dll+0x" + offset.toString(16) + ")");
                });
                if (matches.length > 10) {
                    console.log("    ... and " + (matches.length - 10) + " more");
                }
            }
        }
    });
})();

function stringToPattern(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
        bytes.push(("0" + str.charCodeAt(i).toString(16)).slice(-2));
    }
    return bytes.join(" ");
}

function utf16ToPattern(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        bytes.push(("0" + (code & 0xFF).toString(16)).slice(-2));
        bytes.push(("0" + ((code >> 8) & 0xFF).toString(16)).slice(-2));
    }
    return bytes.join(" ");
}

// =========================================================================
// Phase 3: 精确 hook 候选函数 (手动填入地址后启用)
// =========================================================================

/**
 * 在 Phase 1/2 完成后, 从调用栈和字符串交叉引用中识别出候选函数后,
 * 取消注释下面的代码, 填入实际地址:
 */

/*
// 示例: hook WeChatWin.dll+0x1234567 处的候选评论函数
var candidateOffset = 0x1234567;
var candidateAddr = CONFIG.wechatWinBase.add(candidateOffset);

Interceptor.attach(candidateAddr, {
    onEnter: function(args) {
        console.log("\n========== CANDIDATE COMMENT FUNC ==========");
        console.log("  arg0 (this/mgr?): " + args[0]);
        console.log("  arg1 (sns_id?):   " + args[1]);
        console.log("  arg2 (content?):  " + args[2]);
        console.log("  arg3 (reply_to?): " + args[3]);

        // 尝试读取参数为字符串
        try {
            console.log("  arg2 as UTF-16: " + args[2].readUtf16String());
        } catch(e) {}
        try {
            console.log("  arg2 as UTF-8: " + args[2].readUtf8String());
        } catch(e) {}

        // 如果是结构体指针, dump 前 128 字节
        try {
            console.log("  arg1 dump: " + hexdump_short(args[1], 128));
        } catch(e) {}

        console.log("  Call stack:");
        console.log(formatStack(this.context));
    },
    onLeave: function(retval) {
        console.log("  Return value: " + retval);
    }
});
console.log("[pywechat] Hooked candidate @ WeChatWin.dll+0x" + candidateOffset.toString(16));
*/

// =========================================================================
// 交互命令
// =========================================================================

/**
 * 从 Python 端可以通过 script.post() 发送命令:
 *
 *   script.post({"type": "hook_address", "offset": "0x1234567"})
 *   script.post({"type": "scan_xrefs", "string_offset": "0xABCDEF"})
 */

recv("hook_address", function(msg) {
    var offset = parseInt(msg.payload.offset, 16);
    var addr = CONFIG.wechatWinBase.add(offset);
    console.log("[pywechat] Hooking WeChatWin.dll+0x" + offset.toString(16));

    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log("\n========== DYNAMIC HOOK @ +0x" + offset.toString(16) + " ==========");
            for (var i = 0; i < 6; i++) {
                console.log("  arg" + i + ": " + args[i]);
                try { console.log("    -> UTF-16: " + args[i].readUtf16String()); } catch(e) {}
                try { console.log("    -> UTF-8: " + args[i].readUtf8String()); } catch(e) {}
            }
            console.log("  Call stack:");
            console.log(formatStack(this.context));
        },
        onLeave: function(retval) {
            console.log("  Return: " + retval);
        }
    });
});

console.log("\n[pywechat] === READY ===");
console.log("[pywechat] Now manually post a comment in WeChat Moments.");
console.log("[pywechat] Watch for network send events with WeChatWin.dll in the call stack.");
console.log("[pywechat] Those WeChatWin.dll+0x... offsets are your candidate functions.\n");
