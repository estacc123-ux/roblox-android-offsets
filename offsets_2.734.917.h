#pragma once

#include <cstdint>
#include <cstddef>
// All of these are verified
// image base is 0x0
namespace config {

    namespace addresses {

        constexpr int OnGameLeave = 0x2bb62f0;
        constexpr int OnGameBegin = 0x2613c98;
        constexpr int ScriptContextResume = 0x25ab8c8;
        constexpr int GetGlobalStateForInstance = 0x4621b5c;
        constexpr int Getluastate = 0x25a4b4c;

        constexpr int JobStart = 0x2247c34;
        constexpr int step_datamodeljob_WHSJ = 0x268a090;
        constexpr int TaskSchedulerTargetFps = 0x204a7f4;

        constexpr int Print = 0x218b5cc;

        constexpr uintptr_t RBXRuntimeErr = 0x61313a8;
        constexpr uintptr_t rbxcrash_death_tail = 0x6131578;
        constexpr uintptr_t resumescript_rbxcrash_site = 0x25abe60;

        constexpr uintptr_t telemetry_logevent_sink = 0x3587e34;
        constexpr uintptr_t telemetry_logcounter_sink = 0x3587e6c;
        constexpr uintptr_t telemetry_logstat_sink = 0x3587ea4;

        constexpr uintptr_t telemetry_eventingest_sender = 0x358888c;
        constexpr uintptr_t telemetry_ingest_descriptor_factory = 0x1d4ef80;
        constexpr uintptr_t telemetry_ingest_descriptor_static = 0x6c729e8;

        constexpr uintptr_t crashpad_init_export = 0x2bba490;
        constexpr uintptr_t crashpad_init_crashpad_export = 0x218ecf8;
        constexpr uintptr_t crashpad_handler_export = 0x2bbae34;

        constexpr int LuaC_Step = 0x5d09d38;
        constexpr uintptr_t luaM_visitgco_roblox = 0x5d0e048;

        constexpr int lua_getthreaddata = 0x22f5eec;
        constexpr int lua_newthread = 0x25a580c;
        constexpr int LuaResume = 0x260a74c;
        constexpr int resume_wrapper = 0x25ac524;
        constexpr int task_spawn = 0x25f6224;

        constexpr int lua_tolstring = 0x25a93f0;
        constexpr int lua_pushcclosurek = 0x254f56c;
        constexpr int lua_setfield = 0x254e69c;

        constexpr uintptr_t luaS_newlstr_roblox = 0x254dd90;

        constexpr int rbx_luau_load = 0x5d200f4;
        constexpr int lua_compile_source = 0x3cd7868;
        constexpr int LuaLoad = 0x25a7cd4;
        constexpr int roblox_build_string = 0x1d29df8;
        constexpr int roblox_wrap_string = 0x24a972c;
        constexpr int roblox_loadsource = 0x25a7bd4;
        constexpr int roblox_string_free = 0x4cb0d24;

        constexpr int bytecode_check = 0x25a7fc0;
        constexpr int roblox_loadstring = 0x3d5278c;

        constexpr int TriggerTouchTransmitter = 0x490c838;

        constexpr int capability_errorfunc = 0x5e82860;
        constexpr uintptr_t resume_ctx_write = 0x230a6e4;

        constexpr uintptr_t get_thread_context = 0x2415b74;
        constexpr uintptr_t set_capabilities = 0x25ad6cc;
        constexpr uintptr_t capability_check3 = 0x25b19d0;
        constexpr uintptr_t capability_validator = 0x3d18e50;

        constexpr uintptr_t sandbox_fire_check = 0x3d19124;
        constexpr uintptr_t sandbox_fire_raiser = 0x3d1908c;

        constexpr uintptr_t namecall_fastflag_data = 0x6c6db70;
        constexpr uintptr_t namecall_fast_gate = 0x507d5ac;
        constexpr uintptr_t namecall_slow_nc_tmcache = 0x5d1af6c;

        constexpr uintptr_t namecall_class_cache_sites[] = {
            0x5d1ea38,
            0x5d1ebb4,
            0x5d1ed38,
        };

        constexpr uintptr_t namecall_dispatch_slow = 0x6543e90;
        constexpr uintptr_t namecall_dispatch_fast = 0x6265b08;
        constexpr uintptr_t namecall_decode_table1 = 0xcfd0ef;

        constexpr uintptr_t settable_newindex_isC_gate = 0x507d8b8;

        constexpr uintptr_t settableks_fast_gate = 0x5d198e8;
        constexpr uintptr_t settableks_fast_fallback = 0x5d19a24;
        constexpr uintptr_t settableks_slow_gate = 0x5d1eb98;
        constexpr uintptr_t settableks_slow_fallback = 0x5d1ecd4;

        constexpr uintptr_t settableks_fast_desc_gate = 0x5d1affc;
        constexpr uintptr_t settableks_fast_desc_fallback = 0x5d1b0f8;

        constexpr uintptr_t reparent_sandbox_check = 0x5e8289c;
        constexpr uintptr_t reparent_caps_check = 0x24e7888;

        constexpr uintptr_t luaC_step_roblox = 0x5d09d38;
        constexpr uintptr_t luaD_throw_roblox = 0x27211b8;
        constexpr uintptr_t luaV_gettable_roblox = 0x254f380;
        constexpr uintptr_t luaV_settable_roblox = 0x254e788;
        constexpr uintptr_t luau_execute_roblox = 0x31d8784;
        constexpr uintptr_t luaC_barriertable_roblox = 0x25bfda4;
        constexpr uintptr_t lua_yield_roblox = 0x25f7c98;

        constexpr uintptr_t lua_pushnil_roblox = 0x255031c;
        constexpr uintptr_t lua_pushnumber_roblox = 0x2550004;
        constexpr uintptr_t lua_pushinteger_roblox = 0x2555b68;
        constexpr uintptr_t lua_pushvalue_roblox = 0x254e5bc;
        constexpr uintptr_t lua_createtable_roblox = 0x254f048;
        constexpr uintptr_t lua_getfield_roblox = 0x254f234;
        constexpr uintptr_t lua_rawgetfield_roblox = 0x5d005a4;
        constexpr uintptr_t lua_gettable_roblox = 0x5d004fc;
        constexpr uintptr_t lua_rawget_roblox = 0x254ee8c;
        constexpr uintptr_t lua_setmetatable_roblox = 0x254fcd4;
        constexpr uintptr_t lua_settable_roblox = 0x254f114;
        constexpr uintptr_t lua_remove_roblox = 0x254f1a0;

        constexpr uintptr_t lua_settop_roblox = 0x254efa0;
        constexpr uintptr_t lua_pushcclosurek_roblox = 0x254f56c;
        constexpr uintptr_t lua_setfield_roblox = 0x254e69c;
        constexpr uintptr_t lua_tolstring_roblox = 0x25a93f0;
        constexpr uintptr_t lua_tonumber_roblox = 0x25af76c;

        constexpr uintptr_t lua_pushboolean_roblox = 0x25af418;
        constexpr uintptr_t lua_pushstring_roblox = 0x254fe14;
        constexpr uintptr_t lua_pushlstring_roblox = 0x5d0038c;

        constexpr uintptr_t lua_type_roblox = 0x254ef34;

        constexpr uintptr_t lua_getupvalue_roblox = 0x5d00fdc;
        constexpr uintptr_t lua_getinfo_roblox = 0x25ac978;
        constexpr uintptr_t lua_getupvalue_resolver_roblox = 0x5d01108;
        constexpr uintptr_t lua_setupvalue_roblox = 0x5d011ac;
        constexpr uintptr_t lua_clonefunction_roblox = 0x25b6fb8;

        constexpr uintptr_t lua_rawgeti_roblox = 0x25ab4b0;
        constexpr uintptr_t lua_rawseti_roblox = 0x255715c;
        constexpr uintptr_t lua_ref_roblox = 0x25579bc;

        constexpr uintptr_t lua_gettop_roblox = 0x25adda4;
        constexpr uintptr_t lua_newuserdatatagged_roblox = 0x2555790;
        constexpr uintptr_t lua_userdatatag_roblox = 0x5d0017c;
        constexpr uintptr_t lua_next_roblox = 0x5d00c68;
        constexpr uintptr_t lua_call_roblox = 0x25ed7d4;
        constexpr uintptr_t lua_insert_roblox = 0x25b693c;
        constexpr uintptr_t lua_replace_roblox = 0x25a62bc;
        constexpr uintptr_t push_instance_roblox = 0x2556c3c;

        constexpr uintptr_t lua_getmetatable_roblox = 0x5d006c0;
        constexpr uintptr_t lua_pcall_roblox = 0x5d00af8;
        constexpr uintptr_t lua_setreadonly_roblox = 0x254fbb8;

        constexpr uintptr_t member_set_dispatcher = 0x227366c;
        constexpr uintptr_t callback_setter_closure = 0x39c2f7c;
        constexpr uintptr_t callback_write_thunk = 0x25ad658;
        constexpr uintptr_t callback_write_dispatch = 0x3d5565c;

        constexpr uintptr_t getfflag_roblox = 0x25df634;
        constexpr uintptr_t setfflag_roblox = 0x21c83cc;
    }

    namespace offsets {

        constexpr int sc_off = 1336;
        constexpr int dm_off = 672;

        constexpr int placeid = 88;
        constexpr int jobid = 8;
        constexpr int job_scriptcontext = 0x1a8;

        constexpr uintptr_t lua_state_extraspace = 0x58;
        constexpr uintptr_t lua_state_top = 0x08;
        constexpr uintptr_t lua_state_base = 0x28;
        constexpr uintptr_t lua_state_ci = 0x18;
        constexpr uintptr_t lua_state_global = 0x20;
        constexpr uintptr_t lua_state_gt = 0x50;
        constexpr uintptr_t lua_state_baseCcalls = 0x60;

        constexpr uintptr_t lua_state_namecall = 0x18;
        constexpr uintptr_t lua_state_nccalls = 0x20;
        constexpr uintptr_t lua_state_baseccalls16 = 0x22;
        constexpr uintptr_t lua_state_ciend = 0x58;
        constexpr uintptr_t lua_state_stacklast = 0x50;
        constexpr uintptr_t lua_state_scriptnode = 0x68;

        constexpr uintptr_t callinfo_stride = 0x30;
        constexpr uintptr_t callinfo_base = 0x00;
        constexpr uintptr_t callinfo_proto = 0x08;
        constexpr uintptr_t callinfo_func = 0x10;
        constexpr uintptr_t callinfo_top = 0x18;
        constexpr uintptr_t callinfo_flags = 0x2c;
        constexpr uint32_t callinfo_flag_transition = 0x4;

        constexpr uintptr_t extraspace_identity = 0x40;
        constexpr uintptr_t extraspace_caps = 0x48;
        constexpr uintptr_t extraspace_script = 0x58;

        constexpr uintptr_t tls_ctx_identity = 0x00;
        constexpr uintptr_t tls_ctx_instance = 0x18;
        constexpr uintptr_t tls_ctx_caps = 0x28;
        constexpr uintptr_t tls_ctx_validator = 0x30;

        constexpr uintptr_t instance_localscript_bytecode = 400;
        constexpr uintptr_t instance_modulescript_bytecode = 312;
        constexpr uintptr_t instance_cap_byte = 0xab;
        constexpr uintptr_t instance_secobj = 0x18;
        constexpr uintptr_t secobj_cap_byte = 400;

        constexpr uintptr_t closure_isC = 0x05;
        constexpr uintptr_t closure_nups = 0x04;
        constexpr uintptr_t closure_env = 0x10;
        constexpr uintptr_t closure_cf = 0x28;
        constexpr uintptr_t closure_cupvals = 0x38;
        constexpr uintptr_t lclosure_uprefs = 0x20;
        constexpr uintptr_t lclosure_proto = 0x18;

        constexpr uintptr_t tstring_len = 0x14;
        constexpr uintptr_t tstring_data = 0x18;

        constexpr uintptr_t gco_tt = 0x01;
        constexpr uintptr_t gco_gclist = 0x08;
        constexpr uintptr_t global_threshold = 0x48;
        constexpr uintptr_t global_gray = 0x10;
        constexpr uintptr_t global_currentwhite = 0x58;
        constexpr uintptr_t global_mt = 0x440;
        constexpr uintptr_t global_class_mt = 0x3430;

        constexpr uintptr_t upval_slot = 0x08;
        constexpr uintptr_t udata_payload = 0x10;
        constexpr uintptr_t udata_metatable = 0x08;

        constexpr uintptr_t table_metatable = 0x10;
        constexpr uintptr_t table_lsizenode = 0x03;
        constexpr uintptr_t table_sizearray = 0x08;
        constexpr uintptr_t table_node = 0x18;
        constexpr uintptr_t table_array = 0x20;
        constexpr uintptr_t table_node_stride = 0x20;
        constexpr uintptr_t table_node_key = 0x10;
        constexpr uintptr_t table_tmcache = 0x05;

        constexpr uintptr_t stdstring_size = 0x08;
        constexpr uintptr_t stdstring_data = 0x10;
        constexpr uintptr_t stdstring_long_size = 0x18;
        constexpr uintptr_t stdstring_long_data = 0x20;

        constexpr uintptr_t sharedstr_bytecode = 0x08;

        constexpr uintptr_t proto_userdata = 0x20;
        constexpr uintptr_t proto_k = 0x50;
        constexpr uintptr_t proto_sizek = 0xa0;
        constexpr uintptr_t proto_code = 0x58;
        constexpr uintptr_t proto_sizecode = 0x90;
        constexpr uintptr_t proto_p = 0x68;
        constexpr uintptr_t proto_sizep = 0x8c;
        constexpr uintptr_t proto_source = 0x60;
        constexpr uintptr_t proto_linedefined = 0xA8;
        constexpr uintptr_t proto_nups = 0x03;
        constexpr uintptr_t proto_isvararg = 0x04;
        constexpr uintptr_t proto_numparams = 0x05;
        constexpr uintptr_t proto_maxstack = 0x07;
        constexpr uintptr_t proto_debugname = 0x08;
        constexpr uintptr_t proto_upvalnames = 0x40;
        constexpr uintptr_t proto_sizeupvals = 0xAC;

        constexpr size_t tvalue_size = 0x10;
        constexpr uintptr_t tvalue_value = 0x00;
        constexpr uintptr_t tvalue_tt = 0x0C;

        constexpr uintptr_t connbridge_islot = 0x00;
        constexpr uintptr_t slot_next = 0x10;
        constexpr uintptr_t slot_sig = 0x20;
        constexpr uintptr_t slot_storage = 0x30;
        constexpr uintptr_t storage_func_ref = 0x70;
        constexpr uintptr_t livethreadref_L = 0x08;
        constexpr uintptr_t livethreadref_refid = 0x14;

        constexpr uintptr_t instance_scriptnode = 368;
        constexpr uintptr_t node_weakthreadref = 0x08;
        constexpr uintptr_t weakthreadref_next = 0x18;
        constexpr uintptr_t weakthreadref_livethreadref = 0x20;

        constexpr uintptr_t loadstring_hash_flag = 0x6bc20a0;
    }
}
