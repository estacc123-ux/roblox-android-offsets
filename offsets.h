#pragma once
#include <cstdint>

namespace offsets {
     // confirmed - directly verified this
    constexpr uint64_t luau_load            = 0x03AE43D4; // confirmed via "Attempt to load a function from a different Lua VM" xref
    constexpr uint64_t luaD_call            = 0x059D0FB4; // confirmed: nCcalls increment at +0x50, 199 check, calls luaD_checkCstack on overflow
    constexpr uint64_t luaD_rawrunprotected = 0x024884F8; // confirmed: 3 params, single (*param_2)(param_1,param_3) in try block, returns 0
    constexpr uint64_t luaD_pcall           = 0x0249D414; // confirmed: 5 params, calls luaD_rawrunprotected + luaD_seterrorobj in error path
    constexpr uint64_t luaD_precall         = 0x024A029C; // confirmed: stack growth check 0x141, luaD_growstack call, vtable dispatch at +0x18, frame teardown
    constexpr uint64_t lua_resume           = 0x059CA8EC; // confirmed: param_2 status branch, calls luaD_pcall in resume path, luaD_seterrorobj on error
    constexpr uint64_t luaG_runerror        = 0x059D0490; // confirmed: variadic (L, fmt, ...) - vsnprintf into buffer, sets error string, calls luaD_throw(L, 2)
    constexpr uint64_t luaD_throw           = 0x059D0F3C; // confirmed: allocates C++ exception, stores errcode, calls __cxa_throw - does not return

    // NOT YET CONFIRMED - needs Ghidra verification

     // lua_pcall: exhausted luaD_pcall/luaD_rawrunprotected caller chains in
    //   059d/024a range; unchecked: FUN_0248ef50, FUN_0248f0d8, FUN_0248f1e4
    constexpr uint64_t lua_pcall            = 0x0; // will do later

    // luaV_execute: not hunted this session yet - try xref on opcode dispatch
    //   table or string "INTERRUPT" / "VM execute"
    constexpr uint64_t luaV_execute         = 0x0; // will do later

    // luaG_typeerror: not hunted - will try string "attempt to perform arithmetic"
    //   or "attempt to index" which are its canonical error messages
    constexpr uint64_t luaG_typeerror       = 0x0; // will do later

    // luaH_newkey: not hunted - will try string "table index is NaN" or
    //   "table index is nil" which are thrown from luaH_newkey
    constexpr uint64_t luaH_newkey          = 0x0; // will do later

    // luaF_close: not hunted - will try xref on upvalue closing logic near
    //   luaD_call callsites, or string "attempt to yield across" (adjacent)
    constexpr uint64_t luaF_close           = 0x0; // will do later
}
