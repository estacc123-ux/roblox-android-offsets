#pragma once
#include <cstdint>

// Target: Android ARM64 Roblox
// Version: 2.720.1167

namespace Structs {
    constexpr std::uintptr_t LuauOpcode                              = 0x687caf8; // [HIGH] VM opcode dispatch table
    constexpr std::uintptr_t LuauOpcode_singlestep                   = 0x687c2f8; // [HIGH] singlestep opcode dispatch table
    constexpr std::uintptr_t RawSchedulerHumanoidParallelManagerCtor = 0x38676f8; // [MED]  "HumanoidParallelManagerTaskQueue"
    constexpr std::uintptr_t luaO_nilobject                          = 0xd8b318;  // [HIGH] nil TValue sentinel, returned by luaH_getstr on miss
    constexpr std::uintptr_t luaH_dummynode                          = 0xd8b328;  // [HIGH] empty table node sentinel, freetable checks against this
    constexpr std::uintptr_t luaT_eventname                          = 0x687be80; // [HIGH] ptr[21] metamethod name strings, luaG_aritherror indexes +2
    constexpr std::uintptr_t coroutine_status_strings                = 0x687b708; // [HIGH] "running","suspended","normal","dead","dead"
    constexpr std::uintptr_t sizeclass_table                         = 0x6c621e0; // [HIGH] int8[1024] maps alloc size to size class index
    constexpr std::uintptr_t sizeOfClass_table                       = 0x6c62140; // [HIGH] int[256] maps size class index to actual byte size
    constexpr std::uintptr_t atomTable                               = 0x6de10b8; // [HIGH] ptr[] string atom lookup, namecall indexes into this
    constexpr std::uintptr_t Vector3_methodTable                     = 0x6a2fec8; // [HIGH] Vector3 namecall dispatch table
    constexpr std::uintptr_t RBXScriptSignal_tag                     = 0x6a2ee40; // [HIGH] userdata tag for RBXScriptSignal
    constexpr std::uintptr_t RBXScriptSignal_name                    = 0x68c3dc8; // [HIGH] ptr to "RBXScriptSignal"
    constexpr std::uintptr_t LazyInit_registry                       = 0x6ed3b00; // [MED]  lazy init registration table
    constexpr std::uintptr_t nilCallback_sentinel                    = 0x6a35f60; // [HIGH] "nil function" sentinel value
}

namespace Functions {
    constexpr std::uintptr_t luaG_runerrorL             = 0x5eed468; // [HIGH] vsnprintf + luaD_throw(2)
    constexpr std::uintptr_t luaG_typeerror             = 0x5eed438; // [HIGH] "attempt to %s a %s value"
    constexpr std::uintptr_t luaG_concaterror           = 0x5eed540; // [HIGH] "attempt to concatenate %s with %s"
    constexpr std::uintptr_t luaG_aritherror            = 0x5eed584; // [HIGH] "attempt to perform arithmetic (%s) on %s"
    constexpr std::uintptr_t luaG_ordererror            = 0x5eed5fc; // [HIGH] "attempt to compare %s %s %s"
    constexpr std::uintptr_t luaG_indexerror            = 0x5eed66c; // [HIGH] "attempt to index %s with %s"
    constexpr std::uintptr_t luaG_toobig                = 0x5ef1d24; // [HIGH] "memory allocation error: block too big"
    constexpr std::uintptr_t pusherror                  = 0x5eed724; // [HIGH] prepends "source:line: " to error
    constexpr std::uintptr_t luaL_errorL                = 0x25f529c; // [HIGH] formatted error, never returns
    constexpr std::uintptr_t luaL_typerrorL             = 0x5ee5db4; // [HIGH] "Expected %s, got %s"
    constexpr std::uintptr_t luaL_argerrorL             = 0x5ee5d10; // [HIGH] "cannot close %s coroutine" etc
    constexpr std::uintptr_t throwCastError             = 0x2b1a60c; // [HIGH] "Unable to cast {} to {}"
    constexpr std::uintptr_t luaVM_crossVMerror         = 0x3e01d08; // [HIGH] "Attempt to load a function from a different Lua VM"
    constexpr std::uintptr_t luaD_precall               = 0x25a49b4; // [HIGH] sets up CallInfo, dispatches C vs Lua
    constexpr std::uintptr_t luau_poscall               = 0x263749c; // [HIGH] copies results, pops CallInfo
    constexpr std::uintptr_t tryfuncTM                  = 0x25c208c; // [HIGH] __call metamethod handler
    constexpr std::uintptr_t luaD_throw                 = 0x5eee0e4; // [HIGH] C++ throw, never returns
    constexpr std::uintptr_t luaD_rawrunprotected       = 0x258eecc; // [HIGH] try/catch wrapper
    constexpr std::uintptr_t luaD_reallocstack          = 0x25a6568; // [HIGH] grows stack, fixes all pointers
    constexpr std::uintptr_t luaD_growstack             = 0x25adf68; // [HIGH] computes new size, calls reallocstack
    constexpr std::uintptr_t luaD_growCI                = 0x25b7198; // [HIGH] doubles CI, caps at 20000/22500
    constexpr std::uintptr_t luaD_reallocCI             = 0x25c200c; // [HIGH] raw CI reallocation
    constexpr std::uintptr_t luaD_checkCstack           = 0x5eee124; // [HIGH] checks nCcalls < 200
    constexpr std::uintptr_t luaD_seterrorobj           = 0x5eee438; // [HIGH] sets error TValue from errcode
    constexpr std::uintptr_t luaD_initstack             = 0x5ef2ab8; // [HIGH] allocates CI array and stack
    constexpr std::uintptr_t resume_continue            = 0x5eeeb48; // [HIGH] post-resume Lua/C continuation loop
    constexpr std::uintptr_t luau_execute               = 0x25a66a8; // [HIGH] dispatcher, checks singlestep
    constexpr std::uintptr_t luaV_execute               = 0x5efd4a8; // [HIGH] luau_execute<false> normal
    constexpr std::uintptr_t luaV_execute_singlestep    = 0x5ef8c3c; // [HIGH] luau_execute<true> debug
    constexpr std::uintptr_t lua_resume                 = 0x25a6514; // [HIGH] public resume wrapper
    constexpr std::uintptr_t resume                     = 0x5eee55c; // [HIGH] inner static resume()
    constexpr std::uintptr_t resume_start               = 0x5eee4c0; // [HIGH] validates state, sets nCcalls
    constexpr std::uintptr_t resume_finish              = 0x5eee66c; // [HIGH] post-resume cleanup
    constexpr std::uintptr_t resume_handle              = 0x5eee810; // [HIGH] protected error continuation
    constexpr std::uintptr_t resume_error               = 0x5eeeab4; // [HIGH] pushes error string, returns ERRRUN
    constexpr std::uintptr_t lua_resumeerror            = 0x5eee794; // [HIGH] resume with error
    constexpr std::uintptr_t lua_yield                  = 0x25d93b8; // [HIGH] sets status=YIELD, base=top-nresults
    constexpr std::uintptr_t lua_isyieldable            = 0x25a63fc; // [HIGH] ci==base_ci && base==top && status==0
    constexpr std::uintptr_t luaC_threadbarrier         = 0x25ac714; // [HIGH] GC barrier for threads
    constexpr std::uintptr_t coclose                    = 0x5eeca94; // [HIGH] coroutine.close implementation
    constexpr std::uintptr_t lua_resetthread            = 0x265c8d8; // [HIGH] resets thread state
    constexpr std::uintptr_t luaE_newstate_init         = 0x5ef2c00; // [HIGH] inits global_State internals
    constexpr std::uintptr_t luaT_init                  = 0x258f3fc; // [HIGH] interns tmname[] and ttname[]
    constexpr std::uintptr_t luaM_realloc_              = 0x2599db4; // [HIGH] general realloc with size class routing
    constexpr std::uintptr_t luaM_new_                  = 0x258ef8c; // [HIGH] alloc via size class or frealloc
    constexpr std::uintptr_t luaM_free_                 = 0x258f374; // [HIGH] free via size class or frealloc
    constexpr std::uintptr_t luaM_toobig                = 0x5ef1d24; // [HIGH] "memory allocation error: block too big"
    constexpr std::uintptr_t luaM_freegco_              = 0x2597d00; // [HIGH] common GCO free by page
    constexpr std::uintptr_t newblock                   = 0x5ef1d38; // [HIGH] paged block allocator
    constexpr std::uintptr_t freeblock                  = 0x5ef1e88; // [HIGH] paged block deallocator
    constexpr std::uintptr_t newclasspage               = 0x5ef206c; // [HIGH] allocates new page for size class
    constexpr std::uintptr_t newpage                    = 0x5ef1df0; // [HIGH] raw page allocation
    constexpr std::uintptr_t luaS_newlstr               = 0x258f4cc; // [HIGH] interns string
    constexpr std::uintptr_t luaS_resize                = 0x258f29c; // [HIGH] rehashes string table
    constexpr std::uintptr_t luaO_chunkid               = 0x25cff74; // [HIGH] formats source name
    constexpr std::uintptr_t luaO_pushvfstring          = 0x25c2a3c; // [HIGH] vsnprintf + push TString
    constexpr std::uintptr_t luaO_pushfstring           = 0x5ef2360; // [HIGH] varargs wrapper
    constexpr std::uintptr_t luaO_log2                  = 0x258f264; // [HIGH] integer log2
    constexpr std::uintptr_t luaH_new                   = 0x258f05c; // [HIGH] creates new table
    constexpr std::uintptr_t luaH_getstr                = 0x25a47dc; // [HIGH] string key lookup
    constexpr std::uintptr_t luaH_resize                = 0x5ef51e0; // [HIGH] resizes array+hash
    constexpr std::uintptr_t luaH_resizearray           = 0x5ef53e0; // [HIGH] resizes array only
    constexpr std::uintptr_t luaH_resizehash            = 0x5ef546c; // [HIGH] resizes hash only
    constexpr std::uintptr_t luaH_set                   = 0x5ef56f8; // [HIGH] finds/creates slot
    constexpr std::uintptr_t luaH_newkey                = 0x5ef5b34; // [HIGH] inserts new key
    constexpr std::uintptr_t luaT_gettmbyobj            = 0x25a4950; // [HIGH] gets TM from object's metatable
    constexpr std::uintptr_t luaT_gettm                 = 0x25a4794; // [HIGH] gets TM from table, sets tmcache
    constexpr std::uintptr_t luaT_objtypename           = 0x25c27a0; // [HIGH] returns type name string
    constexpr std::uintptr_t luaT_getmode               = 0x5eef464; // [HIGH] checks __mode metamethod
    constexpr std::uintptr_t luaF_freeproto             = 0x25ad9bc; // [HIGH] frees all Proto sub-arrays
    constexpr std::uintptr_t luaF_close                 = 0x25ae2a0; // [HIGH] closes open upvalues
    constexpr std::uintptr_t luaC_step                  = 0x5eeed18; // [HIGH] outer GC step with metrics
    constexpr std::uintptr_t luaC_step_inner            = 0x25953bc; // [HIGH] GC state machine
    constexpr std::uintptr_t luaC_barrierf              = 0x5eef2c0; // [HIGH] forward barrier, pushes to gray
    constexpr std::uintptr_t luaC_barrierback           = 0x25ac714; // [HIGH] back barrier, clears black
    constexpr std::uintptr_t luaC_resetthread           = 0x265c8d8; // [MED]  resets thread for GC
    constexpr std::uintptr_t markroot                   = 0x2595af4; // [HIGH] marks mainthread, registry, global MTs
    constexpr std::uintptr_t markmt                     = 0x2595c2c; // [HIGH] marks 12 global metatables
    constexpr std::uintptr_t propagatemark              = 0x2595c74; // [HIGH] traverses one gray object
    constexpr std::uintptr_t freegco                    = 0x2597bf4; // [HIGH] dispatch by type tag
    constexpr std::uintptr_t freestring                 = 0x2597c74; // [HIGH] unhashes, frees len+0x19
    constexpr std::uintptr_t freetable                  = 0x25adae0; // [HIGH] frees node/array, then 0x30
    constexpr std::uintptr_t freeclosure                = 0x2597e00; // [HIGH] frees 0x20/0x30+nup*0x10
    constexpr std::uintptr_t freeudata                  = 0x5ef69bc; // [HIGH] calls destructor, frees
    constexpr std::uintptr_t freethread                 = 0x5ef2b50; // [HIGH] calls cb.userthread, frees 0x80
    constexpr std::uintptr_t freebuffer                 = 0x5ee7c38; // [HIGH] frees max(len+8,0x10)
    constexpr std::uintptr_t freeupval                  = 0x25d1470; // [HIGH] frees 0x28
    constexpr std::uintptr_t freeproto                  = 0x25ad9bc; // [HIGH] frees all sub-arrays + 0xB0
    constexpr std::uintptr_t luaC_freethread            = 0x5eeec28; // [HIGH] unlinks from upval list
    constexpr std::uintptr_t currentline                = 0x5eee090; // [HIGH] luaG_getline inlined
    constexpr std::uintptr_t pseudo2addr                = 0x5ee5b84; // [HIGH] converts pseudo-index to address
    constexpr std::uintptr_t lua_clock                  = 0x258c1b8; // [HIGH] clock_gettime based
    constexpr std::uintptr_t os_clock_precise           = 0x635401c; // [HIGH] ARM cntvct_el0 based
    constexpr std::uintptr_t lua_gettop                 = 0x25a45cc; // [HIGH] returns (top-base)/16
    constexpr std::uintptr_t lua_settop                 = 0x2590270; // [HIGH] sets top relative to base
    constexpr std::uintptr_t lua_checkstack             = 0x25afb48; // [HIGH] ensures N free slots
    constexpr std::uintptr_t lua_rawcheckstack          = 0x2599b24; // [HIGH] unchecked stack ensure
    constexpr std::uintptr_t lua_pushvalue              = 0x2590340; // [HIGH] copies stack slot to top
    constexpr std::uintptr_t lua_pushnil                = 0x2591264; // [HIGH] tag=0, top+=0x10
    constexpr std::uintptr_t lua_pushboolean            = 0x25ab93c; // [HIGH]
    constexpr std::uintptr_t lua_pushinteger            = 0x2590d84; // [HIGH]
    constexpr std::uintptr_t lua_pushstring             = 0x2590dc0; // [HIGH]
    constexpr std::uintptr_t lua_pushlstring            = 0x5ee4be8; // [HIGH] tag=6, calls luaS_newlstr
    constexpr std::uintptr_t lua_pushlightuserdata      = 0x25981f8; // [HIGH]
    constexpr std::uintptr_t lua_pushcclosurename       = 0x25906a4; // [HIGH] named C closure
    constexpr std::uintptr_t lua_tothread               = 0x25c01c8; // [HIGH]
    constexpr std::uintptr_t lua_touserdatatagged       = 0x25a4fa8; // [HIGH]
    constexpr std::uintptr_t lua_costatus               = 0x25e9014; // [HIGH]
    constexpr std::uintptr_t lua_createtable            = 0x25902b4; // [HIGH]
    constexpr std::uintptr_t lua_setfield               = 0x258fa38; // [HIGH]
    constexpr std::uintptr_t lua_rawset                 = 0x258f998; // [HIGH]
    constexpr std::uintptr_t lua_setmetatable           = 0x2590c80; // [HIGH]
    constexpr std::uintptr_t lua_setfenv                = 0x25a31b0; // [HIGH]
    constexpr std::uintptr_t lua_xmove                  = 0x25c0238; // [HIGH]
    constexpr std::uintptr_t lua_error                  = 0x5ee5400; // [HIGH]
    constexpr std::uintptr_t lua_namecallatom           = 0x25a6a44; // [HIGH]
    constexpr std::uintptr_t lua_newuserdatatagged      = 0x25984ec; // [HIGH]
    constexpr std::uintptr_t luau_load                  = 0x25a3740; // [HIGH] protected bytecode load
    constexpr std::uintptr_t luau_load_inner            = 0x5f01e3c; // [HIGH] inner load function
    constexpr std::uintptr_t ScriptContextResume        = 0x25a57bc; // [HIGH] main script resume entry
    constexpr std::uintptr_t ScriptContext_addScript    = 0x259fb54; // [HIGH] full script startup lifecycle
    constexpr std::uintptr_t resume_inner               = 0x3db57d4; // [HIGH] resume with C stack tracking
    constexpr std::uintptr_t pusherrorstring            = 0x3db57ac; // [HIGH] push error string, returns flag
    constexpr std::uintptr_t script_blocked_error       = 0x3db8188; // [MED]  "ScriptResumeBlocked" event
    constexpr std::uintptr_t isShutdownPending          = 0x25a64d0; // [HIGH] checks deadline flag+time
    constexpr std::uintptr_t getScriptContext           = 0x3db5750; // [HIGH] validates facet, returns offset
    constexpr std::uintptr_t getCurrentScriptId         = 0x3e01d30; // [MED]  reads +0x34 from thread context
    constexpr std::uintptr_t createLuaState             = 0x25a1fd0; // [HIGH]
    constexpr std::uintptr_t loadBytecode               = 0x25a2204; // [HIGH]
    constexpr std::uintptr_t loadAndRunScript           = 0x3ddb654; // [HIGH]
    constexpr std::uintptr_t loadAndRunScript_ext       = 0x3ddb39c; // [HIGH]
    constexpr std::uintptr_t registerScript             = 0x25a261c; // [HIGH] adds to tracker + registry
    constexpr std::uintptr_t GetCapabilities            = 0x25a6ab4; // [HIGH] setThreadCapabilities
    constexpr std::uintptr_t IdentityToCaps             = 0x3da7320; // [HIGH] computes caps for lua_State
    constexpr std::uintptr_t GetIdentityStruct          = 0x3da72c8; // [HIGH] gets identity from L
    constexpr std::uintptr_t setIdentityCallback        = 0x25a7d20; // [HIGH] stores callback at +0x30
    constexpr std::uintptr_t getThreadExecContext       = 0x25a6434; // [HIGH]
    constexpr std::uintptr_t print                      = 0x3de417c; // [HIGH] "Current identity is %d"
    constexpr std::uintptr_t isSandboxed                = 0x3d60424; // [HIGH] bit 1 at Instance+0x168
    constexpr std::uintptr_t ScriptContext_resolveIdentity = 0x259e4f0; // [HIGH] parses identity list
    constexpr std::uintptr_t ScriptContext_getIdentity  = 0x259e4f0; // [MED]
    constexpr std::uintptr_t getScriptIdentityContext   = 0x23570b4; // [HIGH] walks parent to root
    constexpr std::uintptr_t getThreadContext           = 0x2b531e4; // [HIGH]
    constexpr std::uintptr_t getluastate                = 0x3cf7e64; // [HIGH] reads *(ctx+0x28)
    constexpr std::uintptr_t isInNativeContext          = 0x2b53098; // [HIGH] returns ctx==0
    constexpr std::uintptr_t getMainThreadFromL         = 0x25a52c4; // [HIGH] returns g->mainthread
    constexpr std::uintptr_t getMainThread              = 0x2599328; // [MED]
    constexpr std::uintptr_t DataModel_isParallelPhase  = 0x25ab980; // [HIGH] *(dm+0x1110)==1
    constexpr std::uintptr_t getScriptContextFromThread = 0x3cf7f00; // [MED]
    constexpr std::uintptr_t Instance_namecall          = 0x25a66b8; // [HIGH]
    constexpr std::uintptr_t Instance_namecall2         = 0x3d4d02c; // [HIGH]
    constexpr std::uintptr_t Vector3_namecall           = 0x3d29a04; // [HIGH]
    constexpr std::uintptr_t Generic_namecall           = 0x260104c; // [MED]
    constexpr std::uintptr_t checkInstance              = 0x3d49d30; // [HIGH]
    constexpr std::uintptr_t checkInstance2             = 0x3d49634; // [HIGH]
    constexpr std::uintptr_t LuaMethodDispatchTableResolve = 0x25a6b1c; // [HIGH]
    constexpr std::uintptr_t HashTable                  = 0x3d42248; // [HIGH] atom-keyed hash lookup
    constexpr std::uintptr_t hashLookup_int             = 0x3d41340; // [HIGH] int-keyed hash lookup
    constexpr std::uintptr_t getClassName               = 0x25c08a4; // [HIGH]
    constexpr std::uintptr_t getCodeExecutionManager    = 0x24ad8e4; // [HIGH] returns 0 on Android
    constexpr std::uintptr_t PushInstance                = 0x25a5240; // [HIGH]
    constexpr std::uintptr_t WeakRef_checkMigration     = 0x25a5240; // [HIGH] "Attempt to migrate WeakObjectRef across VM boundary"
    constexpr std::uintptr_t WeakRef_push               = 0x25a52d0; // [HIGH]
    constexpr std::uintptr_t WeakRef_resolveRef         = 0x25a538c; // [HIGH]
    constexpr std::uintptr_t Event_ConnectParallel      = 0x3d4f814; // [HIGH]
    constexpr std::uintptr_t checkRBXScriptSignal       = 0x3d5087c; // [HIGH]
    constexpr std::uintptr_t createConnection           = 0x25b38b4; // [HIGH]
    constexpr std::uintptr_t addConnectionToSignal      = 0x3d50bd4; // [HIGH]
    constexpr std::uintptr_t castToFunction             = 0x25b3318; // [HIGH] casts to callable
    constexpr std::uintptr_t wrapLuaCallback            = 0x3e0216c; // [HIGH] wraps Lua func for C++
    constexpr std::uintptr_t isValidCallback            = 0x25b3250; // [HIGH]
    constexpr std::uintptr_t getCallbackFromStack       = 0x25b3118; // [HIGH]
    constexpr std::uintptr_t isParallelSafe             = 0x25ab980; // [HIGH]
    constexpr std::uintptr_t Behavior_start             = 0x3d8e0fc; // [HIGH]
    constexpr std::uintptr_t ScriptRef_acquire          = 0x3e019cc; // [HIGH] spinlock + refcount
    constexpr std::uintptr_t ScriptRef_release          = 0x3e01ab8; // [HIGH] atomic dec + destroy
    constexpr std::uintptr_t ScriptRef_destroy          = 0x3e01234; // [MED]
    constexpr std::uintptr_t ScriptRef_get              = 0x3e019cc; // [HIGH]
    constexpr std::uintptr_t ScriptContext_moveThread   = 0x2599f44; // [HIGH]
    constexpr std::uintptr_t LazyInit_acquire           = 0x25b8b08; // [HIGH]
    constexpr std::uintptr_t roblox_abort               = 0x634f53c; // [HIGH]
    constexpr std::uintptr_t shared_ptr_move            = 0x3cf7f00; // [HIGH]
    constexpr std::uintptr_t isAnalyticsEnabled         = 0x25b8af4; // [HIGH]
}

namespace offsets {
    // lua_State
    constexpr std::uintptr_t lua_State_tt               = 0x00;  // [HIGH]
    constexpr std::uintptr_t lua_State_marked           = 0x01;  // [HIGH]
    constexpr std::uintptr_t lua_State_memcat           = 0x02;  // [HIGH]
    constexpr std::uintptr_t lua_State_status           = 0x03;  // [HIGH]
    constexpr std::uintptr_t lua_State_singlestep       = 0x04;  // [HIGH]
    constexpr std::uintptr_t lua_State_isactive         = 0x05;  // [HIGH]
    constexpr std::uintptr_t lua_State_global           = 0x08;  // [HIGH]
    constexpr std::uintptr_t lua_State_stack            = 0x10;  // [HIGH]
    constexpr std::uintptr_t lua_State_top              = 0x18;  // [HIGH]
    constexpr std::uintptr_t lua_State_ci               = 0x20;  // [HIGH]
    constexpr std::uintptr_t lua_State_base             = 0x28;  // [HIGH]
    constexpr std::uintptr_t lua_State_stack_last       = 0x30;  // [HIGH]
    constexpr std::uintptr_t lua_State_stacksize        = 0x38;  // [HIGH]
    constexpr std::uintptr_t lua_State_size_ci          = 0x3C;  // [HIGH]
    constexpr std::uintptr_t lua_State_end_ci           = 0x40;  // [HIGH]
    constexpr std::uintptr_t lua_State_base_ci          = 0x48;  // [HIGH]
    constexpr std::uintptr_t lua_State_namecall         = 0x50;  // [HIGH]
    constexpr std::uintptr_t lua_State_extraspace       = 0x58;  // [HIGH]
    constexpr std::uintptr_t lua_State_openupval        = 0x60;  // [HIGH]
    constexpr std::uintptr_t lua_State_gt               = 0x68;  // [HIGH]
    constexpr std::uintptr_t lua_State_nCcalls          = 0x70;  // [HIGH]
    constexpr std::uintptr_t lua_State_baseCcalls       = 0x72;  // [HIGH]
    constexpr std::uintptr_t lua_State_sizeof           = 0x80;  // [HIGH]

    // CallInfo (sizeof = 0x28)
    constexpr std::uintptr_t CallInfo_base              = 0x00;  // [HIGH]
    constexpr std::uintptr_t CallInfo_func              = 0x08;  // [HIGH]
    constexpr std::uintptr_t CallInfo_savedpc           = 0x10;  // [HIGH]
    constexpr std::uintptr_t CallInfo_top               = 0x18;  // [HIGH]
    constexpr std::uintptr_t CallInfo_nresults          = 0x20;  // [HIGH]
    constexpr std::uintptr_t CallInfo_flags             = 0x24;  // [HIGH]
    constexpr std::uintptr_t CallInfo_sizeof            = 0x28;  // [HIGH]

    // TValue (sizeof = 0x10)
    constexpr std::uintptr_t TValue_value               = 0x00;  // [HIGH]
    constexpr std::uintptr_t TValue_tt                  = 0x0C;  // [HIGH]
    constexpr std::uintptr_t TValue_sizeof              = 0x10;  // [HIGH]

    // Closure
    constexpr std::uintptr_t Closure_tt                 = 0x00;  // [HIGH]
    constexpr std::uintptr_t Closure_marked             = 0x01;  // [HIGH]
    constexpr std::uintptr_t Closure_memcat             = 0x02;  // [HIGH]
    constexpr std::uintptr_t Closure_isC                = 0x03;  // [HIGH]
    constexpr std::uintptr_t Closure_nupvalues          = 0x06;  // [HIGH]
    constexpr std::uintptr_t Closure_stacksize          = 0x07;  // [HIGH]
    constexpr std::uintptr_t Closure_gclist             = 0x08;  // [HIGH]
    constexpr std::uintptr_t Closure_env                = 0x10;  // [HIGH]
    constexpr std::uintptr_t Closure_l_proto            = 0x18;  // [HIGH]
    constexpr std::uintptr_t Closure_c_cont             = 0x20;  // [HIGH]
    constexpr std::uintptr_t Closure_c_f                = 0x28;  // [HIGH]
    constexpr std::uintptr_t Closure_sizeof_C           = 0x30;  // [HIGH]
    constexpr std::uintptr_t Closure_sizeof_L           = 0x20;  // [HIGH]
    constexpr std::uintptr_t Closure_upval_stride       = 0x10;  // [HIGH]

    // Proto
    constexpr std::uintptr_t Proto_tt                   = 0x00;  // [HIGH]
    constexpr std::uintptr_t Proto_marked               = 0x01;  // [HIGH]
    constexpr std::uintptr_t Proto_memcat               = 0x02;  // [HIGH]
    constexpr std::uintptr_t Proto_is_vararg            = 0x04;  // [HIGH]
    constexpr std::uintptr_t Proto_maxstacksize         = 0x05;  // [HIGH]
    constexpr std::uintptr_t Proto_numparams            = 0x06;  // [HIGH]
    constexpr std::uintptr_t Proto_nups                 = 0x07;  // [HIGH]
    constexpr std::uintptr_t Proto_upvalues             = 0x08;  // [HIGH]
    constexpr std::uintptr_t Proto_debuginsn            = 0x10;  // [HIGH]
    constexpr std::uintptr_t Proto_p                    = 0x18;  // [HIGH]
    constexpr std::uintptr_t Proto_gclist               = 0x20;  // [HIGH]
    constexpr std::uintptr_t Proto_k                    = 0x28;  // [HIGH]
    constexpr std::uintptr_t Proto_code                 = 0x30;  // [HIGH]
    constexpr std::uintptr_t Proto_source               = 0x38;  // [HIGH]
    constexpr std::uintptr_t Proto_execdata             = 0x48;  // [HIGH]
    constexpr std::uintptr_t Proto_lineinfo             = 0x58;  // [HIGH]
    constexpr std::uintptr_t Proto_abslineinfo          = 0x60;  // [HIGH]
    constexpr std::uintptr_t Proto_locvars              = 0x70;  // [HIGH]
    constexpr std::uintptr_t Proto_typeinfo             = 0x78;  // [HIGH]
    constexpr std::uintptr_t Proto_sizep                = 0x88;  // [HIGH]
    constexpr std::uintptr_t Proto_sizek                = 0x8C;  // [HIGH]
    constexpr std::uintptr_t Proto_sizelocvars          = 0x90;  // [HIGH]
    constexpr std::uintptr_t Proto_sizetypeinfo         = 0x94;  // [HIGH]
    constexpr std::uintptr_t Proto_sizelineinfo         = 0x98;  // [HIGH]
    constexpr std::uintptr_t Proto_sizecode             = 0x9C;  // [HIGH]
    constexpr std::uintptr_t Proto_linegaplog2          = 0xA0;  // [HIGH]
    constexpr std::uintptr_t Proto_sizeupvalues         = 0xA4;  // [HIGH]
    constexpr std::uintptr_t Proto_sizeof               = 0xB0;  // [HIGH]

    // Table
    constexpr std::uintptr_t Table_tt                   = 0x00;  // [HIGH]
    constexpr std::uintptr_t Table_marked               = 0x01;  // [HIGH]
    constexpr std::uintptr_t Table_memcat               = 0x02;  // [HIGH]
    constexpr std::uintptr_t Table_tmcache              = 0x03;  // [HIGH]
    constexpr std::uintptr_t Table_readonly             = 0x04;  // [HIGH]
    constexpr std::uintptr_t Table_safeenv              = 0x05;  // [HIGH]
    constexpr std::uintptr_t Table_lsizenode            = 0x06;  // [HIGH]
    constexpr std::uintptr_t Table_nodemask8            = 0x07;  // [HIGH]
    constexpr std::uintptr_t Table_sizearray            = 0x08;  // [HIGH]
    constexpr std::uintptr_t Table_nodemask             = 0x0C;  // [HIGH]
    constexpr std::uintptr_t Table_metatable            = 0x10;  // [HIGH]
    constexpr std::uintptr_t Table_array                = 0x18;  // [HIGH]
    constexpr std::uintptr_t Table_node                 = 0x20;  // [HIGH]
    constexpr std::uintptr_t Table_gclist               = 0x28;  // [HIGH]
    constexpr std::uintptr_t Table_sizeof               = 0x30;  // [HIGH]

    // LuaNode (sizeof = 0x20)
    constexpr std::uintptr_t LuaNode_val                = 0x00;  // [HIGH]
    constexpr std::uintptr_t LuaNode_key                = 0x10;  // [HIGH]
    constexpr std::uintptr_t LuaNode_sizeof             = 0x20;  // [HIGH]

    // TString
    constexpr std::uintptr_t TString_tt                 = 0x00;  // [HIGH]
    constexpr std::uintptr_t TString_marked             = 0x01;  // [HIGH]
    constexpr std::uintptr_t TString_memcat             = 0x02;  // [HIGH]
    constexpr std::uintptr_t TString_atom               = 0x04;  // [HIGH]
    constexpr std::uintptr_t TString_next               = 0x08;  // [HIGH]
    constexpr std::uintptr_t TString_hash               = 0x10;  // [HIGH]
    constexpr std::uintptr_t TString_len                = 0x14;  // [HIGH]
    constexpr std::uintptr_t TString_data               = 0x18;  // [HIGH]
    constexpr std::uintptr_t TString_header_size        = 0x19;  // [HIGH]

    // Udata
    constexpr std::uintptr_t Udata_tt                   = 0x00;  // [HIGH]
    constexpr std::uintptr_t Udata_marked               = 0x01;  // [HIGH]
    constexpr std::uintptr_t Udata_memcat               = 0x02;  // [HIGH]
    constexpr std::uintptr_t Udata_tag                  = 0x03;  // [HIGH]
    constexpr std::uintptr_t Udata_len                  = 0x04;  // [HIGH]
    constexpr std::uintptr_t Udata_metatable            = 0x08;  // [HIGH]
    constexpr std::uintptr_t Udata_data                 = 0x10;  // [HIGH]
    constexpr std::uintptr_t Udata_sizeof_base          = 0x10;  // [HIGH]

    // UpVal
    constexpr std::uintptr_t UpVal_tt                   = 0x00;  // [HIGH]
    constexpr std::uintptr_t UpVal_marked               = 0x01;  // [HIGH]
    constexpr std::uintptr_t UpVal_v                    = 0x08;  // [HIGH]
    constexpr std::uintptr_t UpVal_value                = 0x10;  // [HIGH]
    constexpr std::uintptr_t UpVal_open_threadprev      = 0x20;  // [HIGH]
    constexpr std::uintptr_t UpVal_open_threadnext      = 0x28;  // [HIGH]
    constexpr std::uintptr_t UpVal_sizeof               = 0x28;  // [HIGH]

    // Buffer
    constexpr std::uintptr_t Buffer_len                 = 0x04;  // [HIGH]
    constexpr std::uintptr_t Buffer_data                = 0x08;  // [HIGH]
    constexpr std::uintptr_t Buffer_min_alloc           = 0x10;  // [HIGH]

    // global_State
    constexpr std::uintptr_t global_State_gcgoal        = 0x04;  // [HIGH]
    constexpr std::uintptr_t global_State_gcstepmul     = 0x08;  // [HIGH]
    constexpr std::uintptr_t global_State_weak          = 0x10;  // [HIGH]
    constexpr std::uintptr_t global_State_gray          = 0x18;  // [HIGH]
    constexpr std::uintptr_t global_State_grayagain     = 0x20;  // [HIGH]
    constexpr std::uintptr_t global_State_GCthreshold   = 0x28;  // [HIGH]
    constexpr std::uintptr_t global_State_totalbytes    = 0x30;  // [HIGH]
    constexpr std::uintptr_t global_State_frealloc      = 0x38;  // [HIGH]
    constexpr std::uintptr_t global_State_ud            = 0x40;  // [HIGH]
    constexpr std::uintptr_t global_State_currentwhite  = 0x48;  // [HIGH]
    constexpr std::uintptr_t global_State_gcstate       = 0x49;  // [HIGH]
    constexpr std::uintptr_t global_State_strt_hash     = 0x50;  // [HIGH]
    constexpr std::uintptr_t global_State_strt_nuse     = 0x58;  // [HIGH]
    constexpr std::uintptr_t global_State_strt_size     = 0x5C;  // [HIGH]
    constexpr std::uintptr_t global_State_freepages     = 0x1B0; // [HIGH]
    constexpr std::uintptr_t global_State_sweepgcopage  = 0x2F0; // [HIGH]
    constexpr std::uintptr_t global_State_mainthread    = 0x2F8; // [HIGH]
    constexpr std::uintptr_t global_State_uvhead        = 0x300; // [HIGH]
    constexpr std::uintptr_t global_State_uvhead_next   = 0x318; // [HIGH]
    constexpr std::uintptr_t global_State_mt            = 0x328; // [HIGH]
    constexpr std::uintptr_t global_State_tmname        = 0x3E8; // [HIGH]
    constexpr std::uintptr_t global_State_cb_debugstep  = 0x4E8; // [HIGH]
    constexpr std::uintptr_t global_State_registry      = 0x4A0; // [HIGH]
    constexpr std::uintptr_t global_State_registry_tt   = 0x4AC; // [HIGH]
    constexpr std::uintptr_t global_State_cb_interrupt  = 0x500; // [HIGH]
    constexpr std::uintptr_t global_State_cb_userthread = 0x508; // [HIGH]
    constexpr std::uintptr_t global_State_ecb_destroy   = 0x548; // [HIGH]
    constexpr std::uintptr_t global_State_ecb_enter     = 0x550; // [HIGH]
    constexpr std::uintptr_t global_State_memcatbytes   = 0x2B80; // [HIGH]
    constexpr std::uintptr_t global_State_udatagc       = 0x3380; // [HIGH]

    // lua_Page
    constexpr std::uintptr_t lua_Page_prev              = 0x00;  // [HIGH]
    constexpr std::uintptr_t lua_Page_next              = 0x08;  // [HIGH]
    constexpr std::uintptr_t lua_Page_listprev          = 0x10;  // [HIGH]
    constexpr std::uintptr_t lua_Page_listnext          = 0x18;  // [HIGH]
    constexpr std::uintptr_t lua_Page_pageSize          = 0x20;  // [HIGH]
    constexpr std::uintptr_t lua_Page_blockSize         = 0x24;  // [HIGH]
    constexpr std::uintptr_t lua_Page_freeList          = 0x28;  // [HIGH]
    constexpr std::uintptr_t lua_Page_freeNext          = 0x30;  // [HIGH]
    constexpr std::uintptr_t lua_Page_busyBlocks        = 0x34;  // [HIGH]
    constexpr std::uintptr_t lua_Page_data              = 0x38;  // [HIGH]

    // Roblox ExtraSpace
    constexpr std::uintptr_t ExtraSpace_capabilities    = 0x40;  // [HIGH]

    // Roblox ThreadExecContext
    constexpr std::uintptr_t ThreadExecCtx_luaState     = 0x18;  // [HIGH]
    constexpr std::uintptr_t ThreadExecCtx_capabilities = 0x28;  // [HIGH]
    constexpr std::uintptr_t ThreadExecCtx_callback     = 0x30;  // [HIGH]

    // Roblox ScriptContext
    constexpr std::uintptr_t ScriptContext_luaState     = 0x28;  // [HIGH]
    constexpr std::uintptr_t ScriptContext_reentrancy   = 0x8C;  // [HIGH]
    constexpr std::uintptr_t ScriptContext_shutdownDeadline = 0x488; // [HIGH]
    constexpr std::uintptr_t ScriptContext_facet_limit  = 0x9E8; // [HIGH]
    constexpr std::uintptr_t ScriptContext_facet_offset = 0x728; // [HIGH]

    // Roblox ShutdownDeadline
    constexpr std::uintptr_t ShutdownDeadline_time      = 0x38;  // [HIGH]
    constexpr std::uintptr_t ShutdownDeadline_enabled   = 0x40;  // [HIGH]

    // Roblox Instance
    constexpr std::uintptr_t Instance_vtable            = 0x00;  // [HIGH]
    constexpr std::uintptr_t Instance_classDescriptor   = 0x18;  // [HIGH]
    constexpr std::uintptr_t Instance_parent            = 0x70;  // [HIGH]
    constexpr std::uintptr_t Instance_children_start    = 0x78;  // [HIGH]
    constexpr std::uintptr_t Instance_children_end      = 0x80;  // [HIGH]
    constexpr std::uintptr_t Instance_actor             = 0x80;  // [MED]
    constexpr std::uintptr_t Instance_actor_ctrl        = 0x88;  // [MED]
    constexpr std::uintptr_t Instance_name              = 0xB0;  // [HIGH]
    constexpr std::uintptr_t Instance_sandboxFlags      = 0x168; // [HIGH]
    constexpr std::uintptr_t Instance_identityCtx_offset = 0x1C8; // [HIGH]

    // Roblox ClassDescriptor vtable
    constexpr std::uintptr_t ClassDesc_getName          = 0x40;  // [HIGH]
    constexpr std::uintptr_t ClassDesc_getFullName      = 0xC0;  // [HIGH]

    // Roblox RbxString (std::string SSO)
    constexpr std::uintptr_t RbxString_flags            = 0x00;  // [HIGH]
    constexpr std::uintptr_t RbxString_short_data       = 0x01;  // [HIGH]
    constexpr std::uintptr_t RbxString_long_size        = 0x08;  // [HIGH]
    constexpr std::uintptr_t RbxString_long_data        = 0x10;  // [HIGH]

    // Roblox TaskScheduler
    constexpr std::uintptr_t TaskScheduler_jobs_start   = 0xD0;  // [HIGH]
    constexpr std::uintptr_t TaskScheduler_jobs_end     = 0xD8;  // [HIGH]

    // Roblox Job
    constexpr std::uintptr_t Job_name                   = 0x28;  // [HIGH]

    // Roblox shared_ptr
    constexpr std::uintptr_t shared_ptr_ptr             = 0x00;  // [HIGH]
    constexpr std::uintptr_t shared_ptr_ctrl            = 0x08;  // [HIGH]
    constexpr std::uintptr_t ctrl_block_refcount        = 0x08;  // [HIGH]
    constexpr std::uintptr_t ctrl_block_vtable_destroy  = 0x10;  // [HIGH]

    // Roblox Signal/Connection
    constexpr std::uintptr_t Signal_source              = 0x18;  // [HIGH]
    constexpr std::uintptr_t Signal_connections         = 0x20;  // [HIGH]
    constexpr std::uintptr_t Connection_signal          = 0x00;  // [HIGH]
    constexpr std::uintptr_t Connection_ref             = 0x08;  // [HIGH]
    constexpr std::uintptr_t Connection_ctrl            = 0x10;  // [HIGH]

    // Roblox DataModel
    constexpr std::uintptr_t DataModel_parallelPhase    = 0x1110; // [HIGH]

    // Roblox ParallelCheck
    constexpr std::uintptr_t ParallelCheck_flag         = 0x108; // [HIGH]

    // Roblox ScriptRef
    constexpr std::uintptr_t ScriptRef_ptr              = 0x10;  // [HIGH]
    constexpr std::uintptr_t ScriptRef_data             = 0x18;  // [HIGH]
    constexpr std::uintptr_t ScriptRef_refcount         = 0x20;  // [HIGH]

    // Roblox IdentityContext
    constexpr std::uintptr_t IdentityCtx_scriptId       = 0x340; // [HIGH]
    constexpr std::uintptr_t IdentityCtx_type           = 0x360; // [HIGH]
}

namespace fflags {
    constexpr std::uintptr_t fflag_LuauStacklessPcall   = 0x6c620f8; // [HIGH]
    constexpr std::uintptr_t fflag_parallel_dispatch    = 0x6ec1628; // [HIGH]
    constexpr std::uintptr_t analytics_enabled          = 0x6a008c8; // [HIGH]
    constexpr std::uintptr_t lua_clock_invfreq          = 0x6c625e8; // [HIGH]
    constexpr std::uintptr_t lua_clock_initflag         = 0x6c625f0; // [HIGH]
}

namespace constants {
    constexpr uint8_t LUA_OK                = 0x00; // [HIGH]
    constexpr uint8_t LUA_YIELD             = 0x01; // [HIGH]
    constexpr uint8_t LUA_ERRRUN            = 0x02; // [HIGH]
    constexpr uint8_t LUA_ERRSYNTAX         = 0x03; // [HIGH]
    constexpr uint8_t LUA_ERRMEM            = 0x04; // [HIGH]
    constexpr uint8_t LUA_ERRERR            = 0x05; // [HIGH]
    constexpr uint8_t LUA_BREAK             = 0x06; // [HIGH]
    constexpr uint8_t SCHEDULED_REENTRY     = 0x7F; // [HIGH]

    constexpr uint32_t LUA_CALLINFO_RETURN  = 0x01; // [HIGH]
    constexpr uint32_t LUA_CALLINFO_HANDLE  = 0x02; // [HIGH]
    constexpr uint32_t LUA_CALLINFO_NATIVE  = 0x04; // [HIGH]

    constexpr int LUA_TNIL                  = 0;    // [HIGH]
    constexpr int LUA_TBOOLEAN             = 1;    // [HIGH]
    constexpr int LUA_TLIGHTUSERDATA       = 2;    // [HIGH]
    constexpr int LUA_TNUMBER              = 3;    // [HIGH]
    constexpr int LUA_TVECTOR              = 4;    // [HIGH]
    constexpr int LUA_TSTRING              = 6;    // [HIGH]
    constexpr int LUA_TTABLE               = 7;    // [HIGH]
    constexpr int LUA_TFUNCTION            = 8;    // [HIGH]
    constexpr int LUA_TUSERDATA            = 9;    // [HIGH]
    constexpr int LUA_TTHREAD              = 10;   // [HIGH]
    constexpr int LUA_TBUFFER              = 11;   // [HIGH]
    constexpr int LUA_TPROTO               = 12;   // [HIGH]
    constexpr int LUA_TUPVAL               = 13;   // [HIGH]

    constexpr uint8_t GCSpause              = 0;    // [HIGH]
    constexpr uint8_t GCSpropagate          = 1;    // [HIGH]
    constexpr uint8_t GCSpropagateagain     = 2;    // [HIGH]
    constexpr uint8_t GCSatomic             = 3;    // [HIGH]
    constexpr uint8_t GCSsweep              = 4;    // [HIGH]

    constexpr uint8_t WHITE0BIT             = 0x01; // [HIGH]
    constexpr uint8_t WHITE1BIT             = 0x02; // [HIGH]
    constexpr uint8_t WHITEBITS             = 0x03; // [HIGH]
    constexpr uint8_t BLACKBIT              = 0x04; // [HIGH]
    constexpr uint8_t FIXEDBIT              = 0x10; // [HIGH]

    constexpr int TM_INDEX                  = 0;    // [HIGH]
    constexpr int TM_NEWINDEX               = 1;    // [HIGH]
    constexpr int TM_MODE                   = 2;    // [HIGH]
    constexpr int TM_NAMECALL               = 3;    // [HIGH]
    constexpr int TM_CALL                   = 4;    // [HIGH]
    constexpr int TM_ITER                   = 5;    // [HIGH]
    constexpr int TM_LEN                    = 6;    // [HIGH]
    constexpr int TM_EQ                     = 7;    // [HIGH]
    constexpr int TM_ADD                    = 8;    // [HIGH]
    constexpr int TM_SUB                    = 9;    // [HIGH]
    constexpr int TM_MUL                    = 10;   // [HIGH]
    constexpr int TM_DIV                    = 11;   // [HIGH]
    constexpr int TM_IDIV                   = 12;   // [HIGH]
    constexpr int TM_MOD                    = 13;   // [HIGH]
    constexpr int TM_POW                    = 14;   // [HIGH]
    constexpr int TM_UNM                    = 15;   // [HIGH]
    constexpr int TM_LT                     = 16;   // [HIGH]
    constexpr int TM_LE                     = 17;   // [HIGH]
    constexpr int TM_CONCAT                 = 18;   // [HIGH]
    constexpr int TM_TYPE                   = 19;   // [HIGH]
    constexpr int TM_METATABLE              = 20;   // [HIGH]
    constexpr int TM_N                      = 21;   // [HIGH]

    constexpr int LUA_REGISTRYINDEX         = -10000; // [HIGH]
    constexpr int LUA_ENVIRONINDEX          = -10001; // [HIGH]
    constexpr int LUA_GLOBALSINDEX          = -10002; // [HIGH]

    constexpr int LUAI_MAXCALLS             = 20000;    // [HIGH]
    constexpr int LUAI_MAXCALLS_HARD        = 22500;    // [HIGH]
    constexpr int LUAI_MAXCCALLS            = 200;      // [HIGH]
    constexpr int EXTRA_STACK               = 5;        // [HIGH]
    constexpr int LUA_MINSTACK              = 20;       // [HIGH]
    constexpr int BASIC_CI_SIZE             = 8;        // [HIGH]
    constexpr int BASIC_STACK_SIZE          = 40;       // [HIGH]
    constexpr int MAX_STACK_SIZE            = 0x4000000; // [HIGH]
    constexpr int TABLE_MAX_SIZE            = 0x4000000; // [HIGH]

    constexpr int PCRLUA                    = 0;    // [HIGH]
    constexpr int PCRC                      = 1;    // [HIGH]
    constexpr int PCRYIELD                  = 2;    // [HIGH]
    constexpr int C_CALL_YIELD             = -1;   // [HIGH]

    constexpr int IDENTITY_ANONYMOUS        = 0;    // [HIGH]
    constexpr int IDENTITY_LOCALUSER        = 1;    // [HIGH]
    constexpr int IDENTITY_GAMESERVER       = 2;    // [HIGH]
    constexpr int IDENTITY_WEBSERVICE       = 3;    // [HIGH]
    constexpr int IDENTITY_REPLICATOR       = 4;    // [HIGH]
    constexpr int IDENTITY_PLUGIN           = 5;    // [HIGH]
    constexpr int IDENTITY_ROBLOXSCRIPT     = 6;    // [HIGH]
    constexpr int IDENTITY_ROBLOX           = 7;    // [HIGH]
    constexpr int IDENTITY_COMMANDBAR       = 8;    // [HIGH]

    constexpr uint64_t CAP_PLUGIN           = 1ULL << 0;  // [HIGH]
    constexpr uint64_t CAP_LOCAL_USER       = 1ULL << 1;  // [HIGH]
    constexpr uint64_t CAP_WRITE_PLAYER     = 1ULL << 2;  // [HIGH]
    constexpr uint64_t CAP_ROBLOX_SCRIPT    = 1ULL << 3;  // [HIGH]
    constexpr uint64_t CAP_ROBLOX_ENGINE    = 1ULL << 4;  // [HIGH]
    constexpr uint64_t CAP_NOT_ACCESSIBLE   = 1ULL << 5;  // [HIGH]

    constexpr int MAX_REENTRANCY            = 3;    // [HIGH]
}
