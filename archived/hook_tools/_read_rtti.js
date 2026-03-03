"use strict";

/**
 * 从运行中的进程读取 RTTI 类名和关键函数信息
 */

var mainMod = Process.findModuleByName("Weixin.dll");
if (!mainMod) mainMod = Process.findModuleByName("WeChatWin.dll");
send("[+] " + mainMod.name + " base=" + mainMod.base);

function readRTTI(vtableRVA, label) {
    var vtableAddr = mainMod.base.add(vtableRVA);
    send("\n=== RTTI for " + label + " (vtable RVA " + vtableRVA.toString(16) + ") ===");

    // Scan backwards from vtable entry to find COL pointer
    // In MSVC x64, COL is at vtable[-1] relative to the actual vtable start
    // We need to find where the vtable starts (first entry preceded by non-code pointer)

    // Read entries before and at the vtable position
    for (var i = -5; i <= 3; i++) {
        try {
            var ptr = vtableAddr.add(i * 8).readPointer();
            var off = ptr.sub(mainMod.base);
            var isCode = off.compare(0) >= 0 && off.compare(mainMod.size) < 0 && off.compare(0x062b3c6b) < 0;
            send("  [" + (i >= 0 ? "+" : "") + i + "] " + ptr + " (off=" + off.toString(16) + ")" +
                 (isCode ? " [CODE]" : ""));
        } catch(e) {
            send("  [" + i + "] <read error>");
        }
    }

    // Try reading COL: look for the non-CODE entry just before CODE entries
    for (var i = -1; i >= -8; i--) {
        try {
            var ptr = vtableAddr.add(i * 8).readPointer();
            var off = ptr.sub(mainMod.base);
            // Check if NOT in .text (text ends around 0x062b3c6b)
            var isCode = off.compare(0) >= 0 && off.compare(0x062b3c6b) < 0;
            if (!isCode) {
                send("  COL candidate at [" + i + "]: " + ptr);
                try {
                    // x64 COL: signature(4) + offset(4) + cdOffset(4) + pTypeDesc(4) + pCHD(4) + pSelf(4)
                    var colAddr = ptr;
                    var sig = colAddr.readU32();
                    if (sig === 1) {
                        var pTypeDescRVA = colAddr.add(12).readU32();
                        var tdAddr = mainMod.base.add(pTypeDescRVA);
                        // TypeDescriptor: pVFTable(8) + spare(8) + name[]
                        var name = tdAddr.add(16).readCString(256);
                        send("  >>> CLASS: " + name);

                        // Read hierarchy
                        var pCHDrva = colAddr.add(16).readU32();
                        var chdAddr = mainMod.base.add(pCHDrva);
                        var numBases = chdAddr.add(8).readU32();
                        var pBaseArrayRVA = chdAddr.add(12).readU32();
                        var baAddr = mainMod.base.add(pBaseArrayRVA);
                        for (var b = 0; b < Math.min(numBases, 5); b++) {
                            var bcdRVA = baAddr.add(b * 4).readU32();
                            var bcdAddr = mainMod.base.add(bcdRVA);
                            var btdRVA = bcdAddr.readU32();
                            var btdAddr = mainMod.base.add(btdRVA);
                            var bname = btdAddr.add(16).readCString(128);
                            send("    base[" + b + "]: " + bname);
                        }
                    } else {
                        send("  COL sig=" + sig + " (not 1, skipping)");
                    }
                } catch(e) {
                    send("  COL read error: " + e);
                }
                break;
            }
        } catch(e) {}
    }
}

// All vtables we found
readRTTI(0x081e9ef8, "cgi_B_caller_2_TOP (mmsnscomment path B)");
readRTTI(0x0857ed10, "SnsCommentRequest_proto");
readRTTI(0x088f0fe0, "SnsComment_logic");
readRTTI(0x0857d2c0, "SnsCommentContentRequest_proto");
readRTTI(0x0857eda0, "SnsCommentResponse_proto");

// Also read some nearby strings to the functions
send("\n=== String context near key functions ===");

// Read string at 0x0859a1c0 (referenced by cgi_A_caller_3_TOP)
try {
    var s1 = mainMod.base.add(0x0859a1c0).readCString(128);
    send("RVA 0x0859a1c0: " + s1);
} catch(e) {}

try {
    var s2 = mainMod.base.add(0x0859a1f8).readCString(128);
    send("RVA 0x0859a1f8: " + s2);
} catch(e) {}

try {
    var s3 = mainMod.base.add(0x0859a390).readCString(128);
    send("RVA 0x0859a390: " + s3);
} catch(e) {}

// Read the vtable at RVA 0x081eb418 (referenced by cgi_A_caller_2)
try {
    var s4 = mainMod.base.add(0x081eb418).readCString(128);
    send("RVA 0x081eb418 (as string): " + s4);
} catch(e) {}

send("\n[+] Done reading RTTI");
