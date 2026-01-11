// lua_w26_proto_patch.js
// ----------------------
//
// W26 heavy branch: runtime patch of Proto->code[] in libgame.so via Frida.
//
// Goal:
//   - intercept loadFunction(SUndumpState *S, Proto *f, const char *psource)
//     in libgame.so;
//   - when loading combat module combat_api_damageFunc.lua:
//       * find Proto P10 (main damage formula) by (source, code_size, const_count);
//       * replace individual W26 MULK instructions using constant 0.0001,
//         with the same MULK but with constant 0.01 (k[14] instead of k[59]);
//   - patches strictly at 32-bit W26 word level without changing code[] length.
//
// Requirements:
//   - Frida 16+;
//   - target game BLEACH: Soul Resonance, build for which:
//       * luaV_execute @ 0x546660 in libgame.so;
//       * loadFunction    @ 0x5439C4 in libgame.so;
//       * Proto format matches reverse-engineered lua_undump_proto.py:
//           - *(uint32_t*)(Proto + 20) = nConst;
//           - *(uint32_t*)(Proto + 24) = nCode;
//           - *(void**  )(Proto + 56) = k;
//           - *(void**  )(Proto + 64) = code;
//
// Launch:
//   frida -U -f com.bleach.apj -l lua_w26_proto_patch.js --no-pause
//

'use strict';

// ---------------------------
// W26 Patch Configuration
// ---------------------------

// Patch sets by (chunkMatch, codeSize, constCount, protoTag, pc, old, neu).
// chunkMatch  — substring in Lua file name/path (sourceName), e.g. "combat_api_damageFunc".
// codeSize    — expected Proto->code_size (nCode).
// constCount  — expected Proto->const_count (nConst).
// pc          — instruction index inside Proto->code[].
// old / neu   — 32-bit W26 words (little-endian values).

const W26_PATCH_SETS = [
    {
        // Old P10 (577/68) - kept for backward compatibility
        chunkMatch: null,
        codeSize: 577,
        constCount: 68,
        protoTag: "P10_OLD",
        patches: [
            { pc: 461, old: 0x3B0F1598, neu: 0x0E0F1598 },
            { pc: 546, old: 0x3B0F2298, neu: 0x0E0F2298 },
        ],
    },
    {
        // NEW P10 (648/71) - most likely candidate after update
        chunkMatch: null,
        codeSize: 648,
        constCount: 71,
        protoTag: "P10_NEW",
        patches: [
            // PC 481: 0x3C101718 (MULK A=46 B=16 C=60, possibly k[60]=0.0001)
            //  -> 0x0E101718 (MULK A=46 B=16 C=14,  k[14]=0.01)
            { pc: 481, old: 0x3C101718, neu: 0x0E101718 },
            
            // PC 600: 0x3C102418 (MULK A=72 B=16 C=60, possibly k[60]=0.0001)
            //  -> 0x0E102418 (MULK A=72 B=16 C=14,  k[14]=0.01)
            { pc: 600, old: 0x3C102418, neu: 0x0E102418 },
        ],
    },
];

// ---------------------------
// Proto Reading Utilities
// ---------------------------

function u32(ptr) {
    return ptr.readU32();
}

function ptrAdd(ptr, off) {
    return ptr.add(off);
}

function getProtoInfo(protoPtr) {
    // Offsets taken from reverse-engineered loadFunction:
    //   *(DWORD*)(Proto + 20) = nConst;
    //   *(DWORD*)(Proto + 24) = nCode;
    //   *(QWORD*)(Proto + 56) = k;
    //   *(QWORD*)(Proto + 64) = code;
    const constCount = u32(ptrAdd(protoPtr, 20));
    const codeSize = u32(ptrAdd(protoPtr, 24));
    const kPtr = ptrAdd(protoPtr, 56).readPointer();
    const codePtr = ptrAdd(protoPtr, 64).readPointer();
    return {
        constCount,
        codeSize,
        kPtr,
        codePtr,
    };
}

function patchW26Instructions(protoPtr, sourceName) {
    let info;
    try {
        info = getProtoInfo(protoPtr);
    } catch (e) {
        console.error("[W26] failed to read Proto fields:", e);
        return;
    }

    const codeSize = info.codeSize;
    const constCount = info.constCount;
    const codePtr = info.codePtr;
    const kPtr = info.kPtr;

    g_protoStats.total++;
    
    if (codePtr.isNull()) {
        return; // Silently skip Proto without code
    }

    // Filter: only log interesting Proto (large or potentially combat-related)
    const isInteresting = codeSize > 100 || constCount > 20 || 
                          (codeSize > 50 && constCount > 10);
    
    if (isInteresting) {
        g_protoStats.interesting++;
    }
    
    // Check ALL interesting Proto for MULK with C=60 (new constant 0.0001)
    if (isInteresting && !codePtr.isNull()) {
        let mulkC60 = [];
        for (let pc = 0; pc < codeSize; pc++) {
            try {
                const insnPtr = codePtr.add(pc * 4);
                const word = insnPtr.readU32();
                const op = word & 0x7F;
                if (op === 24) { // MULK
                    const C = (word >> 24) & 0xFF;
                    if (C === 60) {
                        const A = (word >> 7) & 0xFF;
                        const B = (word >> 16) & 0xFF;
                        mulkC60.push({ pc: pc, word: word, A: A, B: B });
                    }
                }
            } catch (e) {
                // Skip errors
            }
        }
        // Removed MULK C=60 logging - too much spam
        // if (mulkC60.length > 0) { ... }
    }
    
    // Check ALL interesting Proto for damage strings (not just matching sizes)
    if (isInteresting && !kPtr.isNull()) {
        const DAMAGE_KEYWORDS = [
            "GetDamageValue", "DamageData", "DamageRandom", 
            "CRITRATE_CONST", "CRITFACTOR_CONST", "GetDamageFactor",
            "GetAtk", "GetDef", "DamageType", "DamageSkillType",
            "DamageFunc", "OnDamage", "GetDamageTypeAddPer"
        ];
        
        let foundDamageStrings = [];
        // Quick check of first 50 constants
        for (let i = 0; i < Math.min(50, constCount); i++) {
            try {
                const entry = kPtr.add(i * 16);
                
                // First try reading as pointer directly (new format?)
                try {
                    const ptrTest = entry.readPointer();
                    if (!ptrTest.isNull()) {
                        const ptrVal = ptrTest.toInt32();
                        if (ptrVal > 0x1000 && ptrVal < 0x7FFFFFFF) {
                            try {
                                const testStr = ptrTest.readUtf8String(200);
                                if (testStr && testStr.length > 0 && testStr.length < 200) {
                                    for (const keyword of DAMAGE_KEYWORDS) {
                                        if (testStr.indexOf(keyword) !== -1) {
                                            foundDamageStrings.push(`k[${i}]="${testStr}"`);
                                            break;
                                        }
                                    }
                                    continue; // Found string, move to next
                                }
                            } catch (e) {
                                // Not a string, try further
                            }
                        }
                    }
                } catch (e) {
                    // Ignore
                }
                
                // Standard path: type in byte 0, pointer in bytes 8-15
                try {
                    const type = entry.readU8();
                    if (type === 4 || type === 20) {
                        const strPtr = entry.add(8).readPointer();
                        if (!strPtr.isNull()) {
                            try {
                                const str = strPtr.readUtf8String(200);
                                if (str) {
                                    for (const keyword of DAMAGE_KEYWORDS) {
                                        if (str.indexOf(keyword) !== -1) {
                                            foundDamageStrings.push(`k[${i}]="${str}"`);
                                            break;
                                        }
                                    }
                                }
                            } catch (e) {}
                        }
                    }
                } catch (e) {}
            } catch (e) {}
        }
        
        if (foundDamageStrings.length > 0) {
            console.log(
                "[W26] ⚠⚠⚠ POTENTIAL DAMAGE FORMULA FOUND:",
                "codeSize=" + codeSize,
                "constCount=" + constCount,
                "source=" + (sourceName || "<null>"),
                "strings=" + foundDamageStrings.slice(0, 3).join(", ")
            );
        }
    }

    // Check all patch sets
    let matchedAny = false;
    for (const set of W26_PATCH_SETS) {
        // If chunkMatch is set — filter by substring in sourceName.
        if (set.chunkMatch) {
            if (!sourceName || sourceName.indexOf(set.chunkMatch) === -1) {
                continue;
            }
        }
        
        // Check sizes - DON'T log mismatches (reduce spam)
        if (codeSize !== set.codeSize || constCount !== set.constCount) {
            continue;
        }
        
        matchedAny = true;
        g_protoStats.matched++;

        // Matched by (source/codeSize/constCount) — consider this the target Proto.
        // Check string constants to confirm this is the damage formula
        let damageStrings = [];
        let allStrings = []; // For debugging - all strings
        if (!kPtr.isNull()) {
            const DAMAGE_KEYWORDS = [
                "GetDamageValue", "DamageData", "DamageRandom", 
                "CRITRATE_CONST", "CRITFACTOR_CONST", "GetDamageFactor",
                "GetAtk", "GetDef", "DamageType", "DamageSkillType",
                "DamageFunc", "OnDamage", "GetDamageTypeAddPer"
            ];
            
            // Try to read ALL constants as strings
            // Try different TValue format variants:
            // 1. Standard: type in byte 0, value in bytes 8-15
            // 2. Alternative: type may be in different location
            for (let i = 0; i < constCount; i++) {
                try {
                    const entry = kPtr.add(i * 16);
                    
                    // Try different TValue formats:
                    // 1. Standard: type in byte 0, pointer in bytes 8-15
                    // 2. Alternative: pointer directly (format changed)
                    
                    // First try reading as pointer directly (new format?)
                    try {
                        const ptrTest = entry.readPointer();
                        if (!ptrTest.isNull()) {
                            // Check that this is a valid pointer (not too large)
                            const ptrVal = ptrTest.toInt32();
                            if (ptrVal > 0x1000 && ptrVal < 0x7FFFFFFF) {
                                try {
                                    const testStr = ptrTest.readUtf8String(200);
                                    if (testStr && testStr.length > 0 && testStr.length < 200) {
                                        // This is a string!
                                        allStrings.push(`k[${i}]="${testStr.substring(0, 50)}"`);
                                        for (const keyword of DAMAGE_KEYWORDS) {
                                            if (testStr.indexOf(keyword) !== -1) {
                                                damageStrings.push(`k[${i}]="${testStr}"`);
                                                break;
                                            }
                                        }
                                        continue;
                                    }
                                } catch (e) {
                                    // Not a string, try further
                                }
                            }
                        }
                    } catch (e) {
                        // Ignore
                    }
                    
                    // Standard path: type in byte 0
                    let type = entry.readU8();
                    let strPtr = null;
                    
                    // Standard path for strings
                    if (type === 4 || type === 20) { // LUA_TSTRING
                        strPtr = entry.add(8).readPointer();
                        if (!strPtr.isNull()) {
                            try {
                                const str = strPtr.readUtf8String(200);
                                if (str) {
                                    allStrings.push(`k[${i}]="${str.substring(0, 50)}"`);
                                    for (const keyword of DAMAGE_KEYWORDS) {
                                        if (str.indexOf(keyword) !== -1) {
                                            damageStrings.push(`k[${i}]="${str}"`);
                                            break;
                                        }
                                    }
                                }
                            } catch (e) {
                                // Ignore string reading errors
                            }
                        }
                    }
                } catch (e) {
                    // Skip errors
                }
            }
        }
        
        console.log(
            "[W26] ✓✓✓ HIT Proto",
            set.protoTag,
            "source=" + (sourceName || "<null>"),
            "codeSize=" + codeSize,
            "constCount=" + constCount
        );
        
        // Removed detailed TValue diagnostics logs - too much spam
        // if (damageStrings.length > 0) { ... }

        // Additionally: boost damage multiplier via k[14] (FLOAT 0.01) in P10.
        if ((set.protoTag === "P10_OLD" || set.protoTag === "P10_NEW") && !kPtr.isNull()) {
            const DEFAULT_DAMAGE_MULT = 0.0135; // default value
            const idx = 14; // k[14] = 0.01 per offline analysis
            try {
                const entry = kPtr.add(idx * 16); // sizeof(TValue) ≈ 16 bytes
                const oldVal = entry.readDouble(); // double is at offset 0 (as in guide)
                
                // Save Proto for dynamic modification via menu
                if (!g_foundProtos.has(set.protoTag)) {
                    g_foundProtos.set(set.protoTag, {
                        kPtr: kPtr,
                        kIndex: idx,
                        originalValue: oldVal,
                        currentValue: DEFAULT_DAMAGE_MULT
                    });
                }
                
                // Apply current value (may be changed via menu)
                const currentMult = g_foundProtos.get(set.protoTag).currentValue;
                entry.writeDouble(currentMult);
                console.log(
                    "[W26] patched k[14] float",
                    "old=" + oldVal,
                    "new=" + currentMult
                );
            } catch (e) {
                console.error("[W26] failed to patch k[14]:", e);
            }
        }

        for (const p of set.patches) {
            if (p.pc < 0 || p.pc >= codeSize) {
                console.error(
                    "[W26] pc out of range for",
                    set.protoTag,
                    "pc=" + p.pc,
                    "codeSize=" + codeSize
                );
                continue;
            }
            const insnPtr = codePtr.add(p.pc * 4);
            const cur = insnPtr.readU32();

            if (cur === p.neu >>> 0) {
                // Already patched (Proto reload) — silently skip.
                console.log(
                    "[W26] already patched",
                    set.protoTag,
                    "pc=" + p.pc.toString(),
                    "word=0x" + cur.toString(16)
                );
                continue;
            }

            if (cur !== (p.old >>> 0)) {
                console.error("[W26] word mismatch, skip patch",
                    set.protoTag,
                    "pc=" + p.pc.toString(),
                    "expected=0x" + (p.old >>> 0).toString(16).padStart(8, '0'),
                    "got=0x" + cur.toString(16).padStart(8, '0'));
                continue;
            }

            insnPtr.writeU32(p.neu >>> 0);
            console.log(
                "[W26] patched",
                set.protoTag,
                "pc=" + p.pc.toString(),
                "0x" + (p.old >>> 0).toString(16).padStart(8, '0'),
                "-> 0x" + (p.neu >>> 0).toString(16).padStart(8, '0')
            );
        }
    }
    
    // If no set matched, only log very close sizes
    // (possibly updated P10) and dump them for analysis
    if (!matchedAny) {
        const isVeryClose = W26_PATCH_SETS.some(set => {
            const codeDiff = Math.abs(codeSize - set.codeSize);
            const constDiff = Math.abs(constCount - set.constCount);
            // Only log if very close (within 20% or 50 units)
            return (codeDiff < 50 || codeDiff < set.codeSize * 0.2) &&
                   (constDiff < 10 || constDiff < set.constCount * 0.2);
        });
        
        // Removed potential match logging - too much spam
        // if (isVeryClose) {
        //     dumpProtoForAnalysis(protoPtr, sourceName, codeSize, constCount, codePtr, kPtr);
        // }
    }
}

// ---------------------------
// Proto Dump Function for Analysis
// ---------------------------

function dumpProtoForAnalysis(protoPtr, sourceName, codeSize, constCount, codePtr, kPtr) {
    if (g_dumpCount >= 10) {
        return; // Limit number of dumps
    }
    
    try {
        g_dumpCount++;
        const safeName = (sourceName || "null").replace(/[^0-9a-zA-Z_.-]/g, "_").substring(0, 50);
        const dumpName = `proto_${codeSize}_${constCount}_${safeName}_${g_dumpCount}`;
        
        // Read code[] array
        const codeData = codePtr.readByteArray(codeSize * 4);
        
        // Read first 30 constants from k[] for analysis
        // TValue format: first byte - type, then 8 bytes of data
        // Type 3 = integer, type 19 = float/double, type 4/20 = string
        let constsSample = [];
        if (!kPtr.isNull()) {
            for (let i = 0; i < Math.min(30, constCount); i++) {
                try {
                    const entry = kPtr.add(i * 16);
                    const type = entry.readU8(); // First byte - TValue type
                    let value = null;
                    if (type === 3) { // LUA_TINTEGER
                        value = entry.add(8).readS64().toNumber();
                    } else if (type === 19) { // LUA_TNUMBER (float/double)
                        value = entry.add(8).readDouble();
                    } else if (type === 4 || type === 20) { // LUA_TSTRING
                        const strPtr = entry.add(8).readPointer();
                        if (!strPtr.isNull()) {
                            try {
                                // Read string (first 50 chars for analysis)
                                value = strPtr.readUtf8String(50);
                            } catch (e) {
                                value = "<string>";
                            }
                        }
                    }
                    constsSample.push({ idx: i, type: type, value: value });
                } catch (e) {
                    // Skip constant reading errors
                }
            }
        }
        
        // Send dump via send() for saving on host
        send(
            {
                type: "proto_dump",
                idx: g_dumpCount,
                codeSize: codeSize,
                constCount: constCount,
                name: sourceName || null,
                safeName: dumpName,
                constsSample: constsSample,
            },
            codeData
        );
        
        // Removed dump logging - too much spam
        // console.log("[W26] DUMPED Proto for analysis:", dumpName, ...);
    } catch (e) {
        console.error("[W26] Failed to dump Proto:", e);
    }
}

// ---------------------------
// Finding and Hooking loadFunction
// ---------------------------

let g_hookInstalled = false;
let g_protoStats = {
    total: 0,
    interesting: 0,
    matched: 0,
};
let g_dumpCount = 0;

// Global storage for found Proto for dynamic modification
let g_foundProtos = new Map(); // key: protoTag, value: { kPtr, kIndex, originalValue, currentValue }

function hookLoadFunctionOnce(lib) {
    if (g_hookInstalled) {
        return;
    }
    g_hookInstalled = true;

    // RVA loadFunction from reverse (luaU_undump → loadFunction).
    const loadFunctionRva = 0x5439C4;
    const loadFunctionPtr = lib.base.add(loadFunctionRva);

    console.log("[W26] libgame.so base =", lib.base, "loadFunction =", loadFunctionPtr);
    console.log("[W26] Waiting for Proto loading... (will log only interesting Proto)");

    Interceptor.attach(loadFunctionPtr, {
        onEnter(args) {
            // loadFunction(SUndumpState *S, Proto *f, const char *psource)
            this.proto = args[1];
            this.sourcePtr = args[2];
            this.sourceName = null;
            try {
                if (!this.sourcePtr.isNull()) {
                    // Try reading string different ways
                    try {
                        this.sourceName = this.sourcePtr.readUtf8String();
                    } catch (e1) {
                        // If that didn't work, try readCString
                        try {
                            this.sourceName = this.sourcePtr.readCString();
                        } catch (e2) {
                            this.sourceName = null;
                        }
                    }
                }
            } catch (e) {
                this.sourceName = null;
            }
            
            // Only log interesting calls (with name or for large Proto)
            // Full Proto info will be obtained in onLeave after reading fields
        },

        onLeave(retval) {
            if (!this.proto) {
                return;
            }
            try {
                patchW26Instructions(this.proto, this.sourceName || "");
            } catch (e) {
                console.error("[W26] patchW26Instructions error:", e);
                console.error("[W26] stack:", e.stack);
            }
        },
    });
    
    console.log("[W26] Hook installed on loadFunction successfully");
    
    // Statistics only printed on exit (via process.on('exit'))
}

// Wait for libgame.so to appear in process, instead of single getModuleByName().
function waitForLibgameAndHook() {
    const name = "libgame.so";
    const intervalMs = 200;

    function poll() {
        let lib = null;
        try {
            // Process.getModuleByName throws exception if module not yet loaded.
            lib = Process.getModuleByName(name);
        } catch (e) {
            // Module not yet loaded — try later.
            setTimeout(poll, intervalMs);
            return;
        }

        try {
            hookLoadFunctionOnce(lib);
        } catch (e) {
            console.error("[W26] failed to hook loadFunction after libgame load:", e);
        }
    }

    poll();
}

// ---------------------------
// Additional luaL_loadbufferx hook for dumping combat_api_damageFunc
// ---------------------------

let g_chunkDumpCount = 0;
const MAX_CHUNK_DUMPS = 5;

function hookLuaLoadBufferX(lib) {
    // RVA luaL_loadbufferx from IDA
    const luaL_loadbufferxRva = 0x51bdd0;
    const luaL_loadbufferxPtr = lib.base.add(luaL_loadbufferxRva);
    
    console.log("[W26] Also hooking luaL_loadbufferx @", luaL_loadbufferxPtr, "for chunk dumping");
    
    Interceptor.attach(luaL_loadbufferxPtr, {
        onEnter(args) {
            try {
                const namePtr = args[3]; // const char* name
                let name = null;
                if (!namePtr.isNull()) {
                    try {
                        name = namePtr.readUtf8String();
                    } catch (e) {
                        name = null;
                    }
                }
                
                // Dump combat/api/damageFunc (with slashes) or combat_api_damageFunc (with underscores)
                // Also dump combatLogicReport.lua for anti-cheat check
                const shouldDump = name && (
                    (name.indexOf('combat/api/damageFunc') !== -1 || name.indexOf('combat_api_damageFunc') !== -1) ||
                    (name.indexOf('combatLogicReport') !== -1 || name.indexOf('combat_logic_report') !== -1)
                ) && g_chunkDumpCount < MAX_CHUNK_DUMPS;
                
                if (shouldDump) {
                    const buff = args[1];
                    let size = 0;
                    try {
                        if (args[2] && typeof args[2].toInt32 === 'function') {
                            size = args[2].toInt32();
                        } else {
                            size = parseInt(args[2]);
                        }
                    } catch (e) {
                        size = 0;
                    }
                    
                    if (size > 0 && size < 10 * 1024 * 1024) {
                        g_chunkDumpCount++;
                        const data = buff.readByteArray(size);
                        const safeName = (name || "noname").replace(/[^0-9a-zA-Z_.-]/g, "_");
                        
                        send(
                            {
                                type: "lua_dump",
                                idx: 99900 + g_chunkDumpCount, // Special index for combat_api_damageFunc
                                size: size,
                                name: name,
                                safeName: safeName + "_NEW",
                                source: "luaL_loadbufferx_hook",
                            },
                            data
                        );
                        
                        console.log(
                            "[W26] DUMPED chunk combat_api_damageFunc:",
                            "size=" + size,
                            "name=" + name
                        );
                    }
                }
            } catch (e) {
                // Ignore errors
            }
        },
    });
}

function waitForLibgameAndHook() {
    const name = "libgame.so";
    const intervalMs = 200;

    function poll() {
        let lib = null;
        try {
            lib = Process.getModuleByName(name);
        } catch (e) {
            setTimeout(poll, intervalMs);
            return;
        }

        try {
            hookLoadFunctionOnce(lib);
            // Also hook luaL_loadbufferx for chunk dumping
            hookLuaLoadBufferX(lib);
        } catch (e) {
            console.error("[W26] failed to hook after libgame load:", e);
        }
    }

    poll();
}

setImmediate(function () {
    waitForLibgameAndHook();
});

// ============================================================
// Standalone Mode for Termux (without Python wrapper)
// ============================================================

// Check if script is running in standalone mode
const IS_STANDALONE = typeof Java !== 'undefined' || typeof Process !== 'undefined';

if (IS_STANDALONE) {
    console.log("[W26] Running in standalone mode (Termux/Android)");
    
    // Simple console menu for standalone mode
    setInterval(function() {
        // Periodically output statistics
        try {
            if (g_foundProtos.size > 0) {
                console.log("\n[W26] === Current Status ===");
                for (const [tag, proto] of g_foundProtos.entries()) {
                    console.log(`[W26] ${tag}: multiplier=${proto.currentValue} (original=${proto.originalValue})`);
                }
                console.log("[W26] ======================\n");
            }
        } catch (e) {
            // Ignore errors
        }
    }, 30000); // Every 30 seconds
}

// ---------------------------
// RPC Exports for Console Menu
// ---------------------------

rpc.exports = {
    // Get current damage multiplier
    getDamageMultiplier: function(protoTag) {
        if (!g_foundProtos.has(protoTag)) {
            return { error: "Proto not found: " + protoTag };
        }
        const proto = g_foundProtos.get(protoTag);
        return {
            protoTag: protoTag,
            currentValue: proto.currentValue,
            originalValue: proto.originalValue
        };
    },
    
    // Set new damage multiplier
    setDamageMultiplier: function(protoTag, multiplier) {
        if (!g_foundProtos.has(protoTag)) {
            return { error: "Proto not found: " + protoTag };
        }
        const proto = g_foundProtos.get(protoTag);
        try {
            const entry = proto.kPtr.add(proto.kIndex * 16);
            entry.writeDouble(multiplier);
            proto.currentValue = multiplier;
            console.log("[W26] [MENU] Updated damage multiplier for", protoTag, "to", multiplier);
            return { success: true, newValue: multiplier };
        } catch (e) {
            return { error: "Failed to update: " + e.toString() };
        }
    },
    
    // Get list of all found Proto
    listProtos: function() {
        const list = [];
        for (const [tag, proto] of g_foundProtos.entries()) {
            list.push({
                tag: tag,
                currentValue: proto.currentValue,
                originalValue: proto.originalValue
            });
        }
        return list;
    },
    
    // Get statistics
    getStats: function() {
        return {
            totalProtos: g_protoStats.total,
            interestingProtos: g_protoStats.interesting,
            matchedProtos: g_protoStats.matched,
            foundProtos: g_foundProtos.size
        };
    },
    
    // Check connection
    ping: function() {
        return { status: "ok", hookInstalled: g_hookInstalled };
    }
};



