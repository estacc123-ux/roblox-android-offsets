#pragma once
#include <cstdint>

namespace offsets {
    // confirmed - directly verified this session
    constexpr uint64_t luau_load            = 0x03AE43D4; // confirmed: "Attempt to load a function from a different Lua VM" xref

    // identified - function role confirmed when i did decompile analysis, address not verified by string/xref anchor (will treat this as high-confidence)
    constexpr uint64_t luaD_call            = 0x059D0FB4; // increments nCcalls, handles debug hooks, calls luaD_114c
    constexpr uint64_t luaD_rawrunprotected = 0x024884F8; // actual setjmp layer - 3 params (L, func, ud)
    constexpr uint64_t luaD_pcall           = 0x0249D414; // internal protected call engine - 5 params
    constexpr uint64_t luaD_precall         = 0x024A029C; // sets up call frame before dispatch
    constexpr uint64_t lua_resume           = 0x059CA8EC; // resume entry - checks param_2 status, calls luaD_pcall
    constexpr uint64_t luaG_runerror        = 0x059D0490; // (lua_State*, msg) -> does not return - seen in luaD_checkCstack "C stack overflow" path
    constexpr uint64_t luaD_throw           = 0x059D0F3C; // (lua_State*, int errcode) -> does not return - seen in luaD_checkCstack soft limit path

    // -------------------------------------------------------------------------
    // not yet confirmed - old offsets kept for reference only
    // -------------------------------------------------------------------------

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
