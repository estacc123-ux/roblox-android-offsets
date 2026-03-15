#pragma once
#include <cstdint>

/*
 * for people who want to learn how to get these offsets (Ghidra, libroblox.so, ARM64)
 *
 * General workflow:
 *   1. Load libroblox.so in Ghidra (ARM64 LE, no base address)
 *   2. Use Windows -> Defined Strings to find anchor strings (listed per-offset below)
 *   3. Click the string row, press Ctrl+Shift+F to get xrefs
 *   4. Navigate to the referencing function and verify the decompile signature
 *   5. The offset = function start address (shown in Listing view top-left of function)
 *
 * All offsets are relative to the start of libroblox.so (rebase before use at runtime).
 */

namespace offsets {

    // confirmed - directly verified

    // HOW TO FIND: Search string "Attempt to load a function from a different Lua VM"
    //   -> 1 xref -> owning function is luau_load
    //   VERIFY: takes (lua_State* L, const char* chunkname, const char* data, size_t size, int env)
    //   signature: int luau_load(lua_State*, const char*, const char*, size_t, int)
    constexpr uint64_t luau_load            = 0x03AE43D4;

    // HOW TO FIND: Search string "C stack overflow"
    //   -> xref lands inside luaD_checkCstack (1-param, short function)
    //   -> luaD_checkCstack calls luaD_call on the nCcalls < 0xe1 path
    //   VERIFY: increments *(short*)(L + 0x50), compares against 199,
    //           calls luaD_checkCstack on overflow, decrements on exit
    //   signature: void luaD_call(lua_State*, StkId, int)
    constexpr uint64_t luaD_call            = 0x059D0FB4;

    // HOW TO FIND: From luaD_pcall (see below), it calls luaD_rawrunprotected directly
    //   -> follow the call to the 3-param setjmp wrapper
    //   VERIFY: exactly 3 params (L, func, ud), body is just (*func)(L, ud) in a try block,
    //           returns 0 on success, nonzero on longjmp unwind
    //   signature: int luaD_rawrunprotected(lua_State*, Pfunc, void*)
    constexpr uint64_t luaD_rawrunprotected = 0x024884F8;

    // HOW TO FIND: Search string "error in error handling"
    //   -> 2 xrefs: one is lua_newthread, the other is luaD_seterrorobj
    //   -> luaD_seterrorobj (3 params) is called from luaD_pcall in its error path
    //   -> xref luaD_seterrorobj -> find the 5-param caller = luaD_pcall
    //   VERIFY: 5 params, calls luaD_rawrunprotected, calls luaD_seterrorobj on error,
    //           restores L->nCcalls and L->nCcalls+2 (shorts at +0x50/+0x52)
    //   signature: int luaD_pcall(lua_State*, Pfunc, void*, ptrdiff_t, ptrdiff_t)
    constexpr uint64_t luaD_pcall           = 0x0249D414;

    // HOW TO FIND: From luaD_call, press Ctrl+Shift+F to get its callers
    //   -> find the caller that checks nCcalls, does stack growth (checks L+0x28 - L+8 < 0x141),
    //      then dispatches via vtable at *(*(func-0x10) + 0x18)
    //   VERIFY: 3 params (L, func_stackidx, nresults), stack extension call present,
    //           vtable call pattern (**(code**)(lVar + 0x18))(L), frame cleanup on exit
    //   signature: void luaD_precall(lua_State*, StkId, int)
    constexpr uint64_t luaD_precall         = 0x024A029C;

    // HOW TO FIND: Search string "cannot resume dead coroutine"
    //   -> 1 xref -> owning function is lua_resume
    //   VERIFY: 2 params (L, nargs), branches on param_2 != 0 for resume-vs-start,
    //           calls luaD_pcall in the resume path, calls luaD_seterrorobj on error
    //   signature: int lua_resume(lua_State*, int)
    constexpr uint64_t lua_resume           = 0x059CA8EC;

    // HOW TO FIND: Search string "C stack overflow"
    //   -> lands in luaD_checkCstack -> that function calls luaG_runerror directly
    //   -> navigate to the called function
    //   VERIFY: variadic (L, fmt, ...), calls vsnprintf into a ~512-byte stack buffer,
    //           then sets error object, then calls luaD_throw(L, 2) - does not return
    //   NOTE: signature is variadic - declare as void(lua_State*, const char*, ...)
    //   signature: void luaG_runerror(lua_State*, const char* fmt, ...)
    constexpr uint64_t luaG_runerror        = 0x059D0490;

    // HOW TO FIND: From luaG_runerror (above), it calls luaD_throw as its last call
    //   -> navigate to that callee
    //   VERIFY: 2 params (L, errcode), allocates a C++ exception object via operator new,
    //           stores errcode, calls __cxa_throw - does not return
    //   signature: void luaD_throw(lua_State*, int)
    constexpr uint64_t luaD_throw           = 0x059D0F3C;

    // not yet confirmed

    constexpr uint64_t lua_pcall            = 0x0; // TODO
    constexpr uint64_t luaV_execute         = 0x0; // TODO
    constexpr uint64_t luaG_typeerror       = 0x0; // TODO
    constexpr uint64_t luaH_newkey          = 0x0; // TODO
    constexpr uint64_t luaF_close           = 0x0; // TODO

} // namespace offsets
