This is a walkthrough of how I reverse-engineered Roblox's Luau v, from `libroblox.so`, a stripped ARM64 shared library with no debug info, no symbolsy. By the end I had identified 140+ functions, all 88 opcode handlers, the complete opcode shuffle mapping, 10+ data structures at field level, and the bytecode signing system.

Just Ghidra, patience, and an unhealthy amount of time spent staring at decompiled C.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Tools & Setup](#2-tools--setup)
3. [Strategy: The Anchor Point Method](#3-strategy-the-anchor-point-method)
4. [Phase 1: Finding the First Functions](#4-phase-1-finding-the-first-functions)
5. [Phase 2: Cascading Through the Call Graph](#5-phase-2-cascading-through-the-call-graph)
6. [Phase 3: Mapping the Interpreter Loop](#6-phase-3-mapping-the-interpreter-loop)
7. [Phase 4: Cracking the Opcode Shuffle](#7-phase-4-cracking-the-opcode-shuffle)
8. [Phase 5: Bytecode Signing & Verification](#8-phase-5-bytecode-signing--verification)
9. [Phase 6: Data Structure Recovery](#9-phase-6-data-structure-recovery)
10. [Techniques Reference](#10-techniques-reference)
11. [Results Summary](#11-results-summary)

---

## 1. Overview

### What is Luau?

Luau is Roblox's fork of Lua 5.1. It ships with a type-aware bytecode compiler, an optional native codegen (JIT), and a heavily modified VM. The open-source version lives at [github.com/luau-lang/luau](https://github.com/luau-lang/luau), but the version Roblox actually ships has a few extra surprises:

- **Opcode shuffling** - bytecode opcodes are randomly remapped each build, so `LOP_ADD` isn't always opcode 42
- **Bytecode signing** - an HMAC/hash integrity check that rejects unsigned bytecode
- **Roblox engine integration** - property caches, native Instance accessors, ScriptContext wrappers
- **Fast flags** - runtime feature toggles that can silently change VM behavior

### What I Found

| Category | Count | Confidence |
|---|---|---|
| Named functions | 140+ | Mostly HIGH |
| Opcode handlers | 88 / 88 | 100% mapped |
| Data structures | 10+ structs | Field-level |
| Global state offsets | 50+ fields | Verified |
| Bytecode signature system | Complete flow | Documented |

### Target

- **Binary**: `libroblox.so` (ARM64/AArch64)
- **Platform**: Android (Roblox mobile client)
- **Tools**: Ghidra

---

## 2. Tools & Setup

### Ghidra

[Ghidra](https://ghidra-sre.org/) is a free, open-source reverse engineering suite from the NSA - yes, that NSA. It decompiles ARM64 to readable C pseudocode, tracks cross-references, and supports custom Java/Python scripts. It's not IDA Pro, but it's free and it gets the job done.

### Workflow

```
1. Load libroblox.so - let auto-analysis run (grab a coffee, it takes a while)
2. Use string searches to find anchor points
3. Decompile functions and compare against open-source Luau
4. Follow callers and callees outward from each identified function
5. Build up the symbol table incrementally
6. Repeat until you either finish or lose your mind
```

### Key Ghidra Operations

| Operation | How | Purpose |
|---|---|---|
| String search | Search -> For Strings | Find error messages as anchors |
| Xref lookup | Right-click -> References To | Find every caller of a function |
| Decompile | Window -> Decompile | Read C-like pseudocode |
| Data typing | Right-click -> Data -> qword | Interpret raw bytes as pointers |
| Array creation | Right-click -> Data -> Create Array | View dispatch tables |
| Go to address | G -> enter address | Navigate to a known location |

---

## 3. Strategy: The Anchor Point Method

The key insight is that **you don't reverse-engineer a binary linearly**. Reading 100MB of assembly from top to bottom would take several lifetimes. Instead, you find *anchor points* - functions you can identify with certainty - and cascade outward through the call graph.

### Why This Works

**Strings are gold.** Error messages like `"C stack overflow"` or `"attempt to index %s"` appear verbatim in both the binary and the open-source code. They let you pinpoint exact functions without reading a single instruction.

**Function signatures are unique.** A function that accepts a `lua_State*`, checks a counter against 200, and pushes `"C stack overflow"` onto the stack can only be one thing.

**Constants are fingerprints.** `200` (LUAI_MAXCCALLS), `0x28` (sizeof CallInfo), and type tag `7` (LUA_TFUNCTION) show up the same way across every build. They don't get shuffled.

**Open-source is your Rosetta Stone.** Luau's source is public. You're not working blind - you're doing a matching exercise.

### The Process

```
ANCHOR POINT
     │
     ├─-> Identify function by strings / constants / behavior
     ├─-> Match against open-source Luau source
     ├─-> Find functions it calls (callees)
     ├─-> Find functions that call it (callers via xrefs)
     └─-> Each new identification becomes the next anchor point
               └─-> Repeat
```

---

## 4. Phase 1: Finding the First Functions

### Step 1: A Suspicious Function

We started with a decompiled function someone suspected was `luaD_call`. It checked a counter against 200, and on overflow pushed an error:

```c
if (200 < *param_6) {
    // push "C stack overflow"
    return 5;
}
*param_6 = *param_6 + 1;
// ... do the call ...
*param_6 = saved_value;
```

### Step 2: Compare Against Source

From [ldo.cpp](https://github.com/luau-lang/luau/blob/master/VM/src/ldo.cpp):

```cpp
void luaD_callint(lua_State* L, StkId func, int nresults, bool preparereentry) {
    if (++L->nCcalls >= LUAI_MAXCCALLS)  // LUAI_MAXCCALLS = 200
        luaD_checkCstack(L);
    // ...
    L->nCcalls--;
}
```

Close - but not quite.

### Step 3: It's Not luaD_call

Roblox added things that vanilla Luau doesn't have:

| Feature | Open-Source Luau | Decompiled Function |
|---|---|---|
| Parameters | 3–4 | **6** |
| Error strings | Only `"C stack overflow"` | Also `"Not running script because past shutdown deadline"` |
| Timing | None | **Execution time profiling** |
| Shutdown check | None | **Checks a shutdown flag** |

This is `ScriptContext::callWithProtection` - a Roblox engine wrapper that calls the real VM internally.

### Step 4: What We Got For Free

From that one function, we immediately identified:

```
param_2            = lua_State*
param_6            = &nCcalls
FUN_0263e358       = lua_checkstack
FUN_03efa25c       = pushErrorString
FUN_02634d54       = lua_resume  (identified shortly after)
```

Each of those became the next anchor point.

---

## 5. Phase 2: Cascading Through the Call Graph

### The Resume Machinery

Decompiling `FUN_060cc7a8` turned up this:

```c
if (status != YIELD && status != BREAK && (status != 0 || ci == base_ci))
    return resume_error(L, "cannot resume non-suspended coroutine");

L->nCcalls = from ? from->nCcalls : 0;
if (L->nCcalls >= 200)
    return resume_error(L, "C stack overflow");

L->baseCcalls = ++L->nCcalls;
L->isactive = true;
```

The two error strings, the `nCcalls` logic, and the `baseCcalls` assignment together are an unambiguous match for `resume_start` in ldo.cpp. From there:

```
resume_start
  -> lua_resume          (calls resume_start)
  -> resume              (callback into luaD_rawrunprotected)
  -> resume_finish       (called after rawrunprotected returns)
  -> luaD_rawrunprotected (the try/catch wrapper)
```

From `resume`:
```
  -> luau_precall        (sets up call frames)
  -> luau_execute        (the interpreter - found it)
  -> resume_continue     (handles coroutine continuations)
```

One resume function led to the entire execution pipeline. That's the cascade effect in practice.

### Error Functions: Free Anchors

Error-handling functions are uniquely easy to identify because they contain specific format strings:

```c
"attempt to %s a %s value"          -> luaG_typeerror
"attempt to concatenate %s with %s" -> luaG_concaterror
"attempt to perform arithmetic on"  -> luaG_aritherror
"attempt to compare %s %s %s"       -> luaG_ordererror
"'__index' chain too long"          -> luaV_gettable
"'__newindex' chain too long"       -> luaV_settable
```

Each one also calls `luaG_runerror` -> `luaD_throw`, giving you those for free too.

---

## 6. Phase 3: Mapping the Interpreter Loop

### Finding luau_execute

The interpreter was found through the call chain from `lua_resume`. The function at `0x2634eec` turned out to be a thin dispatcher:

```c
void luau_execute(lua_State* L) {
    if (L->singlestep)
        luau_execute_singlestep(L);  // debug / stepping path
    else
        luau_execute_main(L);        // the fast path
}
```

### The Dispatch Table

Inside `luau_execute_main`:

```c
byte opcode = *pc;
(*(code*)DISPATCH_TABLE[opcode])();
```

The dispatch table at `0x6a8f130` is an array of 256 function pointers. Only 88 are non-null - the rest are empty slots for unused opcode values.

### Dumping It

```java
long tableAddr = 0x6a8f130;
for (int i = 0; i < 256; i++) {
    long entry = getQword(tableAddr + i * 8);
    if (entry != 0)
        println(String.format("%3d -> 0x%x", i, entry));
}
```

88 non-null entries. 168 empty slots. Time to figure out which handler does what.

---

## 7. Phase 4: Cracking the Opcode Shuffle

### The Problem

Standard Luau opcodes run from 0 to 83. Roblox shuffles them every build - `LOP_ADD` might be slot 73 this build and something completely different next time. The only way to identify them is by what their handlers actually do.

### Trivial Opcodes - Identified in Seconds

**LOADNIL** - 24 bytes. Sets a type tag to 0 and dispatches:
```c
*(base + A * 0x10 + 0xc) = 0;  // tt = LUA_TNIL
```

**LOADN** - 44 bytes. Converts the instruction's D field to a double:
```c
*(double*)(base + A * 0x10) = (double)(int)(insn >> 16);
*(base + A * 0x10 + 0xc) = 3;  // tt = LUA_TNUMBER
```

**MOVE** - 32 bytes. Copies 16 bytes (one TValue):
```c
dest[0] = src[0];  // value
dest[1] = src[1];  // type tag
```

### Arithmetic Opcodes - Identified by Type Checks

**ADD** - 348 bytes. The type-check chain gives it away immediately:
```c
if (type(B) == 3 && type(C) == 3) {     // both numbers -> fast path
    R(A) = B + C;
} else if (type(B) == 5 && type(C) == 5) {  // both vectors
    R(A).x = B.x + C.x;
    R(A).y = B.y + C.y;
    R(A).z = B.z + C.z;
} else {
    luaV_doadd();  // generic fallback with metamethods
}
```

The component-wise vector addition (type 5) is unique to Luau and confirmed `LUA_TVECTOR = 5`.

### Table Opcodes - Identified by the Roblox Fast Path

**GETTABLEKS** was one of the more interesting finds. It has an Instance property cache that doesn't exist in upstream Luau at all:

```c
if (type(obj) == 9) {  // userdata (Roblox Instance)
    cache = global + tag * 0x48 + 0x7A0;
    if (cache->enabled) {
        return cache->getter(self);  // bypasses the whole Lua table lookup
    }
}
// Cache miss - rewrite this instruction to the slow opcode
*insn = (insn & 0xFFFFFF00) | 0x96;
// fall through to generic path...
```

### Polymorphic Inline Cache: Instruction Rewriting

This was the most interesting Roblox-specific discovery. Several "fast" opcodes rewrite themselves to "slow" opcodes on a cache miss, so subsequent executions skip the cache-check overhead:

| Fast Opcode (slot) | Slow Opcode (slot) | Operation |
|---|---|---|
| 127 (NAMECALL) | 180 | Method call |
| 173 (SETTABLEKS) | 96 | String-key table write |
| 120 (GETTABLEKS) | 150 | String-key table read |

The rewrite is surgical: `*insn = (insn & 0xFFFFFF00) | slow_opcode`. Operands are untouched.

### Validating With Handler Sizes

To make sure identifications were correct, a Ghidra script computed each handler's size as the gap to the next handler in memory. The categories came out clean:

| Size range | Category |
|---|---|
| < 50 bytes | Trivial (NOP, LOADNIL, MOVE) |
| 50–200 bytes | Jumps, simple ops |
| 200–600 bytes | Arithmetic, table ops |
| 600+ bytes | CALL, RETURN, NAMECALL |

No arithmetic handler came in at 20 bytes. No CALL handler came in at 40 bytes. The sizes were self-consistent across all 88 handlers.

---

## 8. Phase 5: Bytecode Signing & Verification

### Finding the Loader

Searching for `"bytecode version mismatch"` led directly to `luau_load` at `0x60e1a40` - a 1000+ line function that deserializes bytecode from a byte stream.

### Bytecode Format

```
byte[0]      version (3–11 accepted)
byte[1]      types version (1–3, if version >= 4)
varint       string count
  [strings]
varint       proto count
  [protos: code, constants, upvalues, debug info]
varint       main proto index
[signature appended at tail]
```

### The Signature System

Before any bytecode is loaded, `luau_verify` at `0x2632a70` runs:

```c
int luau_verify(lua_State* L, ...) {
    CryptoContext* ctx = CryptoContext::getOrInit();  // lazy singleton
    uint result = ctx->verify(data, size);            // compute hash

    // deliberately obfuscated validation
    uint check = OBFUSCATED_TABLE[result] / 7 - 0x9d;

    if (validation_fails)
        global->gc_flags &= ~0x40000000;  // clear "trusted" GC flag

    return result;  // 1 = valid
}
```

Version 0 signatures are 0x28 bytes appended at the end of the bytecode:
```
[payload][key1: 4 bytes][key2: 4 bytes][signature: 32 bytes]
```

Verification XORs `key1` and `key2`, then validates against a hash of the payload. Unsigned bytecode runs with reduced trust - some features are silently disabled.

---

## 9. Phase 6: Data Structure Recovery

### The Method

Structures were recovered by watching how the same pointer is dereferenced across dozens of functions. If `param_1 + 0x48` is compared against 200 in `luaD_callint`, passed into a decrement in `luaD_call`, and called `nCcalls` in the open-source code - you've got your field.

### lua_State Layout

```c
struct lua_State {
    uint8_t  tt;           // +0x00  GCObject header
    uint8_t  marked;       // +0x01
    uint8_t  memcat;       // +0x02
    uint8_t  status;       // +0x03
    uint8_t  singlestep;   // +0x04
    uint8_t  isactive;     // +0x05
    // padding
    StkId    top;          // +0x08
    TValue*  stack;        // +0x10
    global_State* global;  // +0x18
    CallInfo* ci;          // +0x20
    TValue*  stack_last;   // +0x28
    StkId    base;         // +0x30
    // ...
    uint16_t nCcalls;      // +0x48
    uint16_t baseCcalls;   // +0x4a
};
```

### The Floating-Point Type Tag Surprise

Ghidra occasionally decompiled type-tag checks as float comparisons because the tag field sits in a union with the value field. This looked confusing at first:

```c
// Ghidra shows:
if (param_3[3] != 7.00649e-45f)
```

That float's bit pattern is `0x00000005` - which is `LUA_TVECTOR`. Once you recognize the pattern, it's actually a useful second signal: if Ghidra shows a float comparison against a suspiciously small number, it's a type tag check in disguise.

---

## 10. Techniques Reference

### Technique 1: String-Based Anchoring

Best starting point. One string search can anchor an entire subsystem.

```
1. Search -> For Strings -> "C stack overflow"
2. Find the containing function
3. That's luaD_checkCstack (or its caller)
4. Xref to find luaD_callint, then luaD_call
```

### Technique 2: Constant Fingerprinting

Constants survive optimization, inlining, and obfuscation. They're more reliable than code patterns.

| Constant | Meaning | Found In |
|---|---|---|
| 200 | LUAI_MAXCCALLS | `luaD_callint`, `resume_start` |
| 20000 | LUAI_MAXCALLS | `luaD_growCI` |
| 0x28 (40) | sizeof(CallInfo) | Every ci++ / ci-- |
| 0x10 (16) | sizeof(TValue) | Every stack operation |
| 0x20 (32) | sizeof(LuaNode) | Hash table operations |
| 100 | MAXTAGLOOP | `luaV_gettable`, `luaV_settable` |

### Technique 3: Format String Matching

Unique format strings -> unique functions.

```c
"attempt to %s a %s value"                     -> luaG_typeerror
"%s:%d: %s"                                    -> luaG_pusherror
"bytecode version mismatch (expected [%d..%d]" -> luau_load
"table index is NaN"                           -> luaH_newkey_validate
```

### Technique 4: Structural Pattern Matching

If a function accesses `param + 0x20` as a linked list of 0x28-byte structs, and each struct has a base at `+0x00`, a func at `+0x08`, a top at `+0x10`, and a savedpc at `+0x18` - those are CallInfo structs and `param + 0x20` is `L->ci`.

### Technique 5: Behavioral Opcode Identification

```
- Sets type tag to 0?                   -> LOADNIL
- Copies 16 bytes?                      -> MOVE
- Float addition with type checks?      -> ADD
- Calls luau_precall?                   -> CALL
- Calls luau_poscall?                   -> RETURN
- Reads from a constants array?         -> LOADK
- Adjusts PC by a signed offset?        -> JUMP
```

Handler size narrows it down further:
- < 50 bytes -> trivial
- 50–200 -> jump or simple op
- 200–600 -> arithmetic or table
- 600+ -> CALL, RETURN, or NAMECALL

### Technique 6: Cross-Reference Analysis

```
Known: luaD_throw = 0x60cc3c0
  Xrefs TO  -> every error path in the VM
  Xrefs FROM -> the exception/recovery system

Known: luaH_getstr = 0x26330a0
  Xrefs TO  -> GETTABLEKS, SETTABLEKS, metamethod lookups
```

### Technique 7: Dispatch Table Dumping

```java
for (int i = 0; i < 256; i++) {
    long handler = getLong(toAddr(TABLE_BASE + i * 8));
    if (handler != 0)
        println(i + " -> " + toAddr(handler));
}
```

### Technique 8: Handler Size Validation

Sort all handler addresses, compute the gap to the next one, compare against expected ranges. If a handler you labeled NOP is 800 bytes, something is wrong.

---

## 11. Results Summary

### Complete Opcode Shuffle Map (88 Opcodes)

```
SLOT  OPCODE                  │  SLOT  OPCODE
──────────────────────────────┼────────────────────────────
   5  FORNPREP                │  127  NAMECALL (fast)
   6  FASTCALL1               │  132  MODK
  12  JUMPIFLT                │  139  LOADNIL
  13  CONCAT                  │  141  FASTCALL
  15  LOADKX                  │  143  SUBK
  16  FASTCALL2               │  148  NEWTABLE
  19  JUMPIF                  │  150  GETTABLEKS_SLOW
  22  OR                      │  151  JUMPIFEQ
  27  POW                     │  152  JUMPXEQKNIL
  28  FORGLOOP                │  154  JUMPXEQKN
  30  SETLIST                 │  168  CLOSURE
  31  FORGPREP_NEXT           │  173  SETTABLEKS (fast)
  40  DIV                     │  175  CALL2
  41  POWK                    │  176  LOADB
  44  JUMPIFEQ_AUX            │  177  UNM
  45  JUMPIFNOT               │  180  NAMECALL_SLOW
  48  ORK                     │  186  JUMPXEQKS
  51  SETTABLE                │  187  COVERAGE
  53  LOADN                   │  188  LOADK
  54  GETTABLE_NUM            │  190  IDIVK
  57  GETGLOBAL               │  192  RETURN
  62  GETVARARGS              │  199  FORNLOOP
  65  NOT                     │  201  NOP
  66  AND                     │  205  MULK
  67  ANDK                    │  206  PREPVARARGS
  68  ADDK                    │  207  FASTCALL2_AUX
  73  ADD                     │  213  NATIVECALL
  75  FASTCALL2K              │  214  NEWTABLE_HASH
  76  SETGLOBAL               │  215  DUPTABLE
  78  JUMPIFNOTLT             │  216  FORGPREP
  80  JUMPIFLE                │  220  SUB
  81  SETUPVAL                │  223  MOD
  88  DIVK                    │  225  NEWCLOSURE
  89  SETTABLEN               │  226  JUMPIFNOTEQ
  90  IDIVK_REV               │  228  GETTABLEN
  93  MUL                     │  237  CALL
  96  SETTABLEKS_SLOW         │  241  BREAK
  98  JUMPXEQKB               │  242  GETUPVAL
  99  GETIMPORT               │  249  JUMPBACK_INT
 106  IDIV                    │  252  SUBRK
 108  LENGTH                  │
 109  FORGPREP_INEXT          │
 111  JUMPBACK                │
 115  JUMP                    │
 119  MOVE                    │
 120  GETTABLEKS (fast)       │
 126  CLOSEUPVALS             │
```

### Functions Identified by Category

```
VM Core (ldo.cpp)
  luaD_call, luaD_callint, luaD_throw, luaD_rawrunprotected,
  luaD_reallocstack, luaD_growCI, luaD_checkCstack, performcall,
  resume_start, resume, resume_finish, resume_continue,
  resume_handle, resume_error

VM Execution (lvm*.cpp)
  luau_execute, luau_precall, luau_poscall, luaV_gettable,
  luaV_settable, luaV_callTM, luaV_concat, luaV_lessthan,
  luaV_lessequal, luaV_doadd/sub/mul/div/mod/pow/unm,
  luaV_tonumber, luaV_tostring, luaV_getimport

Debug (ldebug.cpp)
  luaG_runerror, luaG_typeerror, luaG_indexerror, luaG_aritherror,
  luaG_ordererror, luaG_concaterror, luaG_methoderror,
  luaG_readonlyerror, luaG_pusherror, luaG_getline, luaG_currentline

Tables (ltable.cpp)
  luaH_get, luaH_getstr, luaH_newkey, luaH_new, luaH_clone,
  luaH_getn, luaH_resizearray

Strings (lstring.cpp)
  luaS_newlstr, luaS_hash, luaS_cmp, luaS_newbuffer, luaS_finishbuffer

Functions (lfunc.cpp)
  luaF_newLclosure, luaF_newproto, luaF_findupval, luaF_close

GC (lgc.cpp)
  luaC_step, luaC_barrierback, luaC_barriertable,
  luaC_threadbarrier, luaC_runstep

Memory (lmem.cpp)
  luaM_realloc, luaM_newgco, luaM_alloc, luaM_newpage,
  luaM_allocfrompage, luaM_toobig

Type System (ltm.cpp)
  luaT_gettm, luaT_gettmbyobj, luaT_objtypename,
  luaT_gettypename, tryfuncTM

Objects (lobject.cpp)
  luaO_pushfstring, luaO_chunkid, luaO_nilobject

API (lapi.cpp)
  lua_pushstring, lua_pushlstring, lua_checkstack,
  lua_rawcheckstack, lua_resume, lua_resumeerror, index2addr

Bytecode (lvmload.cpp)
  luau_load, luau_verify

Roblox Extensions
  ScriptContext::callWithProtection, CryptoContext::verify,
  CryptoContext::getOrInit, pushErrorString, getDataModel
```

---
## Quick-Start: If You're Doing This Yourself

```
1.  Load the binary in Ghidra, let auto-analysis finish (get lunch)
2.  Search for "C stack overflow" -> find luaD_checkCstack
3.  Xref to find luaD_callint -> then luaD_call
4.  From luaD_call, find luau_precall -> find the interpreter
5.  In the interpreter, find the dispatch table (array of 256 qwords)
6.  Dump the dispatch table with a script
7.  Start with trivial handlers: NOP, LOADNIL, MOVE, LOADN (all < 50 bytes)
8.  Move to arithmetic: ADD, SUB - look for type == 3 number checks
9.  Then table ops: look for luaH_getstr calls
10. Then CALL / RETURN: look for CallInfo manipulation
11. Validate all identifications with handler size analysis
12. Repeat until done, or until Roblox ships a new build and reshuffles everything
```
