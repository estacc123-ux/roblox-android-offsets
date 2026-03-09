#pragma once
#include <cstdint>

namespace offsets {

    constexpr uint64_t luaV_execute         = 0x03a91104;
    constexpr uint64_t luaD_call            = 0x03a8ce6c;
    constexpr uint64_t luaD_precall         = 0x03a7e73c;
    constexpr uint64_t lua_resume           = 0x03a7e81c;
    constexpr uint64_t luaD_rawrunprotected = 0x03a7e348;
    constexpr uint64_t luaD_pcall           = 0x03a7efdc;
    constexpr uint64_t lua_pcall            = 0x03a7aec4;
    constexpr uint64_t luaD_throw           = 0x03a7e2b0;
    constexpr uint64_t luaG_runerror        = 0x03a7d5f8;
    constexpr uint64_t luaG_typeerror       = 0x03a7d604;
    constexpr uint64_t luaH_newkey          = 0x03a894a0;
    constexpr uint64_t luaF_close           = 0x03a7f198;
    constexpr uint64_t luau_load            = 0x03a873b0;

} // namespace offsets
