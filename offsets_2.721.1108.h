// Credits: estacc123-ux and yellwogreg(he helped a little)
// Platform: Android ARM64 (AArch64)
// Version: 2.721.1108
// Binary: libroblox.so

#pragma once
#include <cstdint>

//  STATIC DATA ADDRESSES
namespace Structs {

// Dispatch Tables
constexpr std::uintptr_t LuauOpcode                  = 0x6a8f130; // [HIGH] VM opcode dispatch table (256 * 8 bytes)
constexpr std::uintptr_t LuauOpcode_singlestep       = 0x6a8e930; // [HIGH] singlestep opcode dispatch table

// Builtin / Fastcall
constexpr std::uintptr_t BuiltinDispatchTable        = 0x6a8d4b0; // [HIGH] fastcall builtin function table

// Sentinels
constexpr std::uintptr_t luaO_nilobject              = 0xddb5f0;  // [HIGH] nil TValue sentinel, returned by luaH_getstr on miss

// GC / Memory
constexpr std::uintptr_t sizeclass_table             = 0x6e8b858; // [HIGH] int8[1024] maps alloc size to size class index
constexpr std::uintptr_t sizeOfClass_table           = 0x6e8b7b8; // [HIGH] int[256] maps size class index to actual byte size

// Roblox Config / FFlag Data Region
constexpr std::uintptr_t roblox_config_region        = 0x6ad66d8; // [HIGH] FFlag/config value region (NOT a dispatch table)
// Contains integer configs, float params, string refs, and crypto tables
// Entry 0 (0x6ad66d8): signature_max_version = 1
// Entries 114-241: AES/crypto lookup tables (S-box) for bytecode verification

// Fast Flags (.bss, runtime-initialized)
constexpr std::uintptr_t fflag_LuauStacklessPcall    = 0x6e8b770; // [HIGH] enables SCHEDULED_REENTRY (0x7F) status
constexpr std::uintptr_t fflag_LuauClosureUsageCounter = 0x6e8bcd0; // [HIGH] tracks closure call counts
constexpr std::uintptr_t fflag_LuauNamcallOptimization = 0x6e8bc88; // [MED] namecall inline fast path
constexpr std::uintptr_t fflag_LuauUserdataIndexOpt  = 0x6e8bca0; // [MED] userdata property cache
constexpr std::uintptr_t fflag_LuauClassIndexOpt     = 0x6e8bcb8; // [MED] class property cache

// JIT / Native Code
constexpr std::uintptr_t JIT_compile_threshold       = 0x6e8b788; // [HIGH] call count before JIT triggers

// Bytecode Verification
constexpr std::uintptr_t CryptoContext_singleton     = 0x6c59c58; // [HIGH] bytecode signature verification context
constexpr std::uintptr_t CryptoContext_onceflag      = 0x6c59ce8; // [HIGH] __cxa_guard for lazy init
constexpr std::uintptr_t signature_max_version       = 0x6ad66d8; // [HIGH] max accepted signature version (value=1)
constexpr std::uintptr_t signature_min_size          = 0x6ad66d4; // [HIGH] min bytecode size for signing (clamped 0x100-0x400)

// Verification Obfuscation Tables
constexpr std::uintptr_t verify_divisor_table        = 0x8aea4c;  // [HIGH] divisors for hash validation
constexpr std::uintptr_t verify_index_table1         = 0x8aea6c;  // [HIGH] index remap table 1
constexpr std::uintptr_t verify_index_table2         = 0x8aea76;  // [HIGH] index remap table 2
constexpr std::uintptr_t verify_result_table         = 0x8aea80;  // [HIGH] result lookup table
constexpr std::uintptr_t verify_result_offsets       = 0x8aeaa8;  // [HIGH] maps result code -> counter offset

// Table Sentinel
constexpr std::uintptr_t luaH_dummynode              = 0xddb600;  // [HIGH] empty table node sentinel (Table->node for empty tables)

// Number Conversion Tables (Ryu/Grisu algorithm)
constexpr std::uintptr_t pow10_significands          = 0xddb3a0;  // [HIGH] power of 10 significand table
constexpr std::uintptr_t pow10_table_lo              = 0xddaff8;  // [HIGH] power of 10 low words
constexpr std::uintptr_t pow10_table_hi              = 0xddb008;  // [HIGH] power of 10 high words
constexpr std::uintptr_t digit_pairs_table           = 0xddb420;  // [HIGH] "00010203...9899" fast digit output

// Roblox Assert
constexpr std::uintptr_t PTR_HardAssert_table        = 0x6ab0aa0; // [HIGH] assertion message string table

} // namespace Structs


//  FUNCTION ADDRESSES

namespace Functions {

// Error Handling (ldebug.cpp)
constexpr std::uintptr_t luaG_runerrorL              = 0x60cb6dc; // [HIGH] vsnprintf + luaD_throw(2)
constexpr std::uintptr_t luaG_typeerror              = 0x60cb6ac; // [HIGH] "attempt to %s a %s value"
constexpr std::uintptr_t luaG_concaterror            = 0x60cb7b4; // [HIGH] "attempt to concatenate %s with %s"
constexpr std::uintptr_t luaG_aritherror             = 0x60cb7f8; // [HIGH] "attempt to perform arithmetic (%s) on %s"
constexpr std::uintptr_t luaG_ordererror             = 0x60cb870; // [HIGH] "attempt to compare %s %s %s"
constexpr std::uintptr_t luaG_indexerror             = 0x60cb8e0; // [HIGH] "attempt to index %s with '%s'"
constexpr std::uintptr_t luaG_indexerror_key         = 0x60cb954; // [HIGH] "this %s does not have a key named '%s'"
constexpr std::uintptr_t luaG_methoderror            = 0x60cb9b8; // [HIGH] "attempt to call missing method '%s' of %s"
constexpr std::uintptr_t luaG_readonlyerror          = 0x60cb9e8; // [HIGH] readonly table modification error
constexpr std::uintptr_t luaG_pusherror              = 0x60cb9fc; // [HIGH] prepends "source:line: " to error
constexpr std::uintptr_t luaG_getline                = 0x60cbc8c; // [HIGH] compressed lineinfo lookup
constexpr std::uintptr_t luaG_currentline            = 0x60cc368; // [HIGH] current executing line number

// VM Core (ldo.cpp)
constexpr std::uintptr_t luaD_rawrunprotected        = 0x261db34; // [HIGH] try/catch wrapper
constexpr std::uintptr_t luaD_throw                  = 0x60cc3c0; // [HIGH] C++ throw, never returns
constexpr std::uintptr_t luaD_checkCstack            = 0x60cc400; // [HIGH] checks nCcalls >= 200
constexpr std::uintptr_t luaD_callint                = 0x60cc438; // [HIGH] internal call with yield handling
constexpr std::uintptr_t performcall                 = 0x60cc5d0; // [HIGH] precall + execute + flags
constexpr std::uintptr_t luaD_call                   = 0x60cc664; // [HIGH] public call entry (wraps callint)
constexpr std::uintptr_t luaD_seterrorobj            = 0x60cc720; // [HIGH] sets error object on stack
constexpr std::uintptr_t luaD_reallocstack           = 0x2634da8; // [HIGH] grows stack, fixes all pointers
constexpr std::uintptr_t luaD_growstack              = 0x263c778; // [HIGH] computes new size, calls reallocstack
constexpr std::uintptr_t luaD_growstack_safe         = 0x60c27c4; // [HIGH] protected stack grow (via rawrunprotected)
constexpr std::uintptr_t luaD_growCI                 = 0x26463c8; // [HIGH] doubles CI array, caps at 20000/22500
constexpr std::uintptr_t luaD_reallocCI              = 0x2651258; // [HIGH] raw CI reallocation
constexpr std::uintptr_t luaD_callhook               = 0x60d72f0; // [HIGH] debug hook invocation

// Resume Machinery (ldo.cpp)
constexpr std::uintptr_t lua_resume                  = 0x2634d54; // [HIGH] public resume wrapper
constexpr std::uintptr_t resume_start                = 0x60cc7a8; // [HIGH] validates state, sets nCcalls
constexpr std::uintptr_t resume                      = 0x60cc844; // [HIGH] inner static resume callback
constexpr std::uintptr_t resume_finish               = 0x60cc954; // [HIGH] post-resume cleanup
constexpr std::uintptr_t resume_continue             = 0x60cce38; // [HIGH] unroll Lua/C continuations
constexpr std::uintptr_t resume_handle               = 0x60ccb00; // [HIGH] protected error continuation
constexpr std::uintptr_t resume_error                = 0x60ccda4; // [HIGH] pushes error string, returns ERRRUN
constexpr std::uintptr_t lua_resumeerror             = 0x60cca84; // [HIGH] resume with error

// VM Execution (lvmexecute.cpp / lvm.cpp)
constexpr std::uintptr_t luau_execute                = 0x2634eec; // [HIGH] dispatcher (singlestep vs main)
constexpr std::uintptr_t luau_execute_singlestep     = 0x60d7494; // [HIGH] debug path with per-insn hooks
constexpr std::uintptr_t luau_execute_main           = 0x60dc324; // [HIGH] fast path, tries native first
constexpr std::uintptr_t luau_precall                = 0x2633300; // [HIGH] sets up CallInfo, dispatches C vs Lua
constexpr std::uintptr_t luau_poscall                = 0x26c6498; // [HIGH] copies results, pops CallInfo
constexpr std::uintptr_t luau_prepareCcall           = 0x60e13a8; // [HIGH] sets up CI for native C call
constexpr std::uintptr_t luau_updatecallstats        = 0x60ccfd4; // [HIGH] JIT hot function detection
constexpr std::uintptr_t tryfuncTM                   = 0x26512d8; // [HIGH] __call metamethod handler

// VM Operations (lvm.cpp)
constexpr std::uintptr_t luaV_gettable               = 0x261f2a8; // [HIGH] generic index with __index chain
constexpr std::uintptr_t luaV_settable               = 0x261e790; // [HIGH] generic newindex with __newindex chain
constexpr std::uintptr_t luaV_callTM                 = 0x2635b2c; // [HIGH] call metamethod from opcode handler
constexpr std::uintptr_t luaV_calltm_index           = 0x60e2fd0; // [HIGH] call __index function, store result
constexpr std::uintptr_t luaV_concat                 = 0x60e18b8; // [HIGH] string concatenation
constexpr std::uintptr_t luaV_concat_impl            = 0x263cd20; // [HIGH] core concat with coercion
constexpr std::uintptr_t luaV_getimport              = 0x263af28; // [HIGH] resolve import chain
constexpr std::uintptr_t luaV_tonumber               = 0x2652438; // [HIGH] coerce to number
constexpr std::uintptr_t luaV_tostring               = 0x26697dc; // [HIGH] number -> string conversion
constexpr std::uintptr_t luaV_prepareFORN            = 0x60e4018; // [HIGH] coerce for-loop variables

// Comparison / Arithmetic Fallbacks
constexpr std::uintptr_t luaV_lessthan               = 0x60e3074; // [HIGH] < with metamethods
constexpr std::uintptr_t luaV_lessequal              = 0x60e31b0; // [HIGH] <= with metamethods
constexpr std::uintptr_t luaV_lessequaltm            = 0x60e30e0; // [HIGH] __le metamethod dispatch
constexpr std::uintptr_t luaV_trybinarytm            = 0x60e3324; // [HIGH] try binary metamethod
constexpr std::uintptr_t luaV_doadd                  = 0x60e33b0; // [HIGH] + fallback (num/vec/meta)
constexpr std::uintptr_t luaV_dosub                  = 0x60e3510; // [HIGH] - fallback
constexpr std::uintptr_t luaV_domul                  = 0x60e3670; // [HIGH] * fallback
constexpr std::uintptr_t luaV_doidiv                 = 0x60e3840; // [HIGH] // fallback
constexpr std::uintptr_t luaV_dodiv                  = 0x60e3a0c; // [HIGH] / fallback
constexpr std::uintptr_t luaV_domod                  = 0x60e3c4c; // [HIGH] % fallback
constexpr std::uintptr_t luaV_dopow                  = 0x60e3d8c; // [HIGH] ^ fallback
constexpr std::uintptr_t luaV_dounm                  = 0x60e3ec0; // [HIGH] unary - fallback
constexpr std::uintptr_t luaV_dolen                  = 0x2669270; // [HIGH] # fallback (metamethod)

// Type System (ltm.cpp)
constexpr std::uintptr_t luaT_gettm                  = 0x2633058; // [HIGH] get metamethod from metatable
constexpr std::uintptr_t luaT_gettmbyobj             = 0x2633218; // [HIGH] get metamethod by object type
constexpr std::uintptr_t luaT_objtypename            = 0x26519ec; // [HIGH] returns type name as C string
constexpr std::uintptr_t luaT_gettypename            = 0x263d810; // [HIGH] returns type name TString*

// Table Operations (ltable.cpp)
constexpr std::uintptr_t luaH_new                    = 0x261dcc4; // [HIGH] create new table
constexpr std::uintptr_t luaH_clone                  = 0x263c37c; // [HIGH] clone/duplicate table
constexpr std::uintptr_t luaH_get                    = 0x261eab0; // [HIGH] generic table lookup
constexpr std::uintptr_t luaH_getstr                 = 0x26330a0; // [HIGH] string-key table lookup
constexpr std::uintptr_t luaH_newkey                 = 0x263c4b8; // [HIGH] insert new key into table
constexpr std::uintptr_t luaH_newkey_internal        = 0x60d3f44; // [HIGH] raw key insertion
constexpr std::uintptr_t luaH_newkey_validate        = 0x261ebd0; // [HIGH] validate key (NaN/nil check)
constexpr std::uintptr_t luaH_getn                   = 0x60d4230; // [HIGH] table length (#t)
constexpr std::uintptr_t luaH_resizearray            = 0x264634c; // [HIGH] resize array part
constexpr std::uintptr_t luaH_resize                 = 0x60d3a2c; // [HIGH] full table resize (array + hash)
constexpr std::uintptr_t luaH_resize_protected       = 0x263cfe0; // [HIGH] protected resize wrapper
constexpr std::uintptr_t luaH_resizearray_grow       = 0x60d3c2c; // [HIGH] grow array part (realloc + nil fill)
constexpr std::uintptr_t luaH_resizehash             = 0x60d3cb8; // [HIGH] resize hash part (alloc nodes, set masks)
constexpr std::uintptr_t luaH_set                    = 0x60d4380; // [HIGH] general table set (array fast path -> hash)

// String Operations (lstring.cpp)
constexpr std::uintptr_t luaS_newlstr                = 0x261e138; // [HIGH] intern string by content
constexpr std::uintptr_t luaS_hash                   = 0x60d15b8; // [HIGH] string hash function
constexpr std::uintptr_t luaS_cmp                    = 0x26f5184; // [HIGH] string comparison (strcmp-like)
constexpr std::uintptr_t luaS_newbuffer              = 0x266be80; // [HIGH] allocate uninitialized TString
constexpr std::uintptr_t luaS_finishbuffer           = 0x266bef8; // [HIGH] intern buffer into string table
constexpr std::uintptr_t luaS_resize                 = 0x261df04; // [HIGH] resize string hash table (rehash all strings)

// Function / Closure (lfunc.cpp)
constexpr std::uintptr_t luaF_newLclosure            = 0x26330fc; // [HIGH] create Lua closure
constexpr std::uintptr_t luaF_newproto               = 0x2632d8c; // [HIGH] allocate Proto (sizeof=0xC0, tt=0x0F)
constexpr std::uintptr_t luaF_findupval              = 0x263c868; // [HIGH] find/create open upvalue
constexpr std::uintptr_t luaF_close                  = 0x263cab0; // [HIGH] close upvalues above level

// GC (lgc.cpp)
constexpr std::uintptr_t luaC_step                   = 0x60cd0c8; // [HIGH] incremental GC step (timing + dispatch)
constexpr std::uintptr_t luaC_fullgc                 = 0x262419c; // [HIGH] full GC cycle — all 5 phases
constexpr std::uintptr_t luaC_markroot               = 0x26248d4; // [HIGH] phase 0: mark root objects
constexpr std::uintptr_t luaC_propagatemark          = 0x2624a8c; // [HIGH] phase 1/2: traverse gray list
constexpr std::uintptr_t luaC_sweeppage              = 0x2626b40; // [HIGH] phase 4: sweep one page
constexpr std::uintptr_t luaC_sweeppage_detail       = 0x2626b48; // [HIGH] sweep page internals
constexpr std::uintptr_t luaC_sweepobject            = 0x2626b94; // [HIGH] sweep single object
constexpr std::uintptr_t luaC_barrierback            = 0x262556c; // [HIGH] write barrier (back)
constexpr std::uintptr_t luaC_barriertable           = 0x263c17c; // [HIGH] write barrier for tables (flip color or barrierfast)
constexpr std::uintptr_t luaC_barrierfast            = 0x60cd680; // [HIGH] fast barrier — type-specific GC list linkage
constexpr std::uintptr_t luaC_threadbarrier          = 0x263af08; // [HIGH] thread GC barrier
constexpr std::uintptr_t luaF_unlinkupval            = 0x60ccf18; // [HIGH] unlink upvalue from open list, optionally close
constexpr std::uintptr_t luaC_upvalbarrier           = 0x263cb28; // [HIGH] GC barrier for closed upvalue
constexpr std::uintptr_t luaS_resize_protected       = 0x60cd8a8; // [HIGH] protected wrapper for luaS_resize

// Memory (lmem.cpp)
constexpr std::uintptr_t luaM_realloc                = 0x2628d94; // [HIGH] general reallocation
constexpr std::uintptr_t luaM_alloc                  = 0x261dbf4; // [HIGH] general allocation (page or direct)
constexpr std::uintptr_t luaM_newgco                 = 0x261dd74; // [HIGH] allocate GC object
constexpr std::uintptr_t luaM_allocfrompage          = 0x60d0584; // [HIGH] page allocator (small objects)
constexpr std::uintptr_t luaM_newpage                = 0x60d063c; // [HIGH] allocate new page
constexpr std::uintptr_t luaM_newclasspage           = 0x60d08b8; // [HIGH] alloc page for size class (reads sizeOfClass_table)
constexpr std::uintptr_t luaM_toobig                 = 0x60d0570; // [HIGH] "memory allocation error: block too big"
constexpr std::uintptr_t luaM_free                   = 0x261dfdc; // [HIGH] free block (page or direct)
constexpr std::uintptr_t luaM_freepage               = 0x60d06d4; // [HIGH] return block to page freelist

// Object / Misc (lobject.cpp)
constexpr std::uintptr_t luaO_pushfstring            = 0x60d0bac; // [HIGH] formatted string push
constexpr std::uintptr_t luaO_pushvfstring           = 0x2651b9c; // [HIGH] vararg formatted string push
constexpr std::uintptr_t luaO_pushvfstring_impl      = 0x2651c88; // [HIGH] core vsnprintf + push
constexpr std::uintptr_t luaO_chunkid                = 0x265f210; // [HIGH] format source name for errors
constexpr std::uintptr_t luaO_num2str                = 0x264a3ac; // [HIGH] double -> string (Ryu/Grisu algorithm)
constexpr std::uintptr_t luaO_rawequalObj            = 0x263c794; // [HIGH] raw equality by type (uses float bit patterns)
constexpr std::uintptr_t luaO_log2                   = 0x261decc; // [HIGH] integer log2 (for hash table sizing)
constexpr std::uintptr_t luaO_nan_handler            = 0x60d0920; // [HIGH] outputs "nan"/"-nan"/"-inf" string

// Lua C API (lapi.cpp)
constexpr std::uintptr_t lua_pushstring              = 0x261fbbc; // [HIGH] push C string to stack
constexpr std::uintptr_t lua_pushlstring             = 0x60c2d90; // [HIGH] push string with length
constexpr std::uintptr_t lua_checkstack              = 0x263e358; // [HIGH] ensure stack space (public API)
constexpr std::uintptr_t lua_rawcheckstack           = 0x2628b04; // [HIGH] ensure + update ci->top
constexpr std::uintptr_t lua_index2addr              = 0x2633aec; // [HIGH] stack index -> TValue* (handles positive/negative/pseudo)
constexpr std::uintptr_t lua_index2addr_pseudo       = 0x60c3e00; // [HIGH] handles pseudo-indices
constexpr std::uintptr_t lua_clock                   = 0x261ac7c; // [HIGH] high-resolution timer

// Bytecode Loading (lvmload.cpp)
constexpr std::uintptr_t luau_load                   = 0x60e1a40; // [HIGH] 
constexpr std::uintptr_t luau_verify                 = 0x2632a70; // [HIGH] bytecode signature verification
constexpr std::uintptr_t loadsafe                    = 0x60e1a40; // [HIGH] bytecode deserializer (1000+ lines)

// Bytecode Verification (Roblox crypto)
constexpr std::uintptr_t CryptoContext_getOrInit     = 0x3ea3b34; // [HIGH] lazy singleton init
constexpr std::uintptr_t CryptoContext_verify        = 0x3ea3bb0; // [HIGH] main signature verification
constexpr std::uintptr_t CryptoContext_getSubContext = 0x3ea3e7c; // [HIGH] returns ctx + 0x2C
constexpr std::uintptr_t CryptoContext_recordResult  = 0x3ea4414; // [HIGH] records verification result
constexpr std::uintptr_t CryptoContext_extractVersion = 0x3ea44c8; // [MED] extract sig version from tail
constexpr std::uintptr_t CryptoContext_verifyV0      = 0x3ea488c; // [MED] version 0 verification
constexpr std::uintptr_t CryptoContext_verifyV1      = 0x3ea4994; // [MED] version 1 verification
constexpr std::uintptr_t CryptoContext_extendedVerify = 0x3ea3e94; // [MED] extended verification
constexpr std::uintptr_t CryptoHash_compute          = 0x6532864; // [MED] hash computation

// Roblox Engine Layer
constexpr std::uintptr_t ScriptContext_callWithProtection = 0x3efa284; // [HIGH] wraps luaD_call with timing/shutdown
constexpr std::uintptr_t ScriptContext_getDataModel  = 0x3efa200; // [HIGH] returns this - 0x730, checks facet at +0x9F0
constexpr std::uintptr_t pushErrorString             = 0x3efa25c; // [HIGH] wraps lua_pushlstring

// Roblox Assert
constexpr std::uintptr_t RBX_hardAssert              = 0x654d324; // [HIGH] maps code -> message, throws
constexpr std::uintptr_t RBX_hardAssert_throw        = 0x654d340; // [HIGH] throws assertion (no return)

// C++ Runtime
constexpr std::uintptr_t __cxa_guard_acquire         = 0x2b1a730; // [HIGH] singleton guard acquire
constexpr std::uintptr_t __cxa_guard_release         = 0x2b1a874; // [HIGH] singleton guard release

} // namespace Functions


//  STRUCTURE FIELD OFFSETS
namespace offsets {

// lua_State
//  NOTE: This layout differs from open-source Luau AND from iOS Roblox.
//  Field ordering is platform/build specific.
constexpr std::uintptr_t lua_State_tt                = 0x00; // [HIGH] uint8  LUA_TTHREAD (10)
constexpr std::uintptr_t lua_State_marked            = 0x01; // [HIGH] uint8  GC mark bits
constexpr std::uintptr_t lua_State_memcat            = 0x02; // [HIGH] uint8  memory category
constexpr std::uintptr_t lua_State_status            = 0x03; // [HIGH] uint8  0=OK,1=YIELD,6=BREAK,0x7F=reentry
constexpr std::uintptr_t lua_State_singlestep        = 0x04; // [HIGH] uint8  debug single-step flag
constexpr std::uintptr_t lua_State_isactive          = 0x05; // [HIGH] uint8  thread is executing
constexpr std::uintptr_t lua_State_top               = 0x08; // [HIGH] StkId  top of stack
constexpr std::uintptr_t lua_State_stack             = 0x10; // [HIGH] TValue* base of stack array
constexpr std::uintptr_t lua_State_global            = 0x18; // [HIGH] global_State*
constexpr std::uintptr_t lua_State_ci                = 0x20; // [HIGH] CallInfo* current call frame
constexpr std::uintptr_t lua_State_stack_last        = 0x28; // [HIGH] TValue* last usable slot
constexpr std::uintptr_t lua_State_base              = 0x30; // [HIGH] StkId  base for current function
constexpr std::uintptr_t lua_State_gclist            = 0x38; // [HIGH] GCObject*
constexpr std::uintptr_t lua_State_openupval         = 0x40; // [HIGH] UpVal* open upvalue list
constexpr std::uintptr_t lua_State_nCcalls           = 0x48; // [HIGH] uint16 C call depth (max 200)
constexpr std::uintptr_t lua_State_baseCcalls        = 0x4a; // [HIGH] uint16 base C calls (for yield)
constexpr std::uintptr_t lua_State_cachedslot        = 0x4c; // [HIGH] int32  opcode inline cache slot
constexpr std::uintptr_t lua_State_gt                = 0x50; // [HIGH] Table* global table (_G environment)
constexpr std::uintptr_t lua_State_extraspace        = 0x58; // [HIGH] void*  extra userdata / Roblox identity context
constexpr std::uintptr_t lua_State_namecall          = 0x60; // [HIGH] TValue NAMECALL method name (16B)
constexpr std::uintptr_t lua_State_end_ci            = 0x68; // [HIGH] CallInfo* end of CI array
constexpr std::uintptr_t lua_State_base_ci           = 0x70; // [HIGH] CallInfo* base of CI array
constexpr std::uintptr_t lua_State_stacksize         = 0x78; // [HIGH] int32  stack size (in TValues)
constexpr std::uintptr_t lua_State_size_ci           = 0x7c; // [HIGH] int32  CI array size
constexpr std::uintptr_t lua_State_sizeof            = 0x80; // [HIGH]

// CallInfo (sizeof = 0x28)
constexpr std::uintptr_t CallInfo_base               = 0x00; // [HIGH] StkId
constexpr std::uintptr_t CallInfo_func               = 0x08; // [HIGH] StkId
constexpr std::uintptr_t CallInfo_top                = 0x10; // [HIGH] StkId
constexpr std::uintptr_t CallInfo_savedpc            = 0x18; // [HIGH] Instruction*
constexpr std::uintptr_t CallInfo_nresults           = 0x20; // [HIGH] int32
constexpr std::uintptr_t CallInfo_flags              = 0x24; // [HIGH] uint32
constexpr std::uintptr_t CallInfo_sizeof             = 0x28; // [HIGH]

// TValue (sizeof = 0x10)
constexpr std::uintptr_t TValue_value                = 0x00; // [HIGH] value union (8 bytes)
constexpr std::uintptr_t TValue_extra                = 0x08; // [HIGH] extra/vec_w (4 bytes)
constexpr std::uintptr_t TValue_tt                   = 0x0C; // [HIGH] type tag (4 bytes)
constexpr std::uintptr_t TValue_sizeof               = 0x10; // [HIGH]

// Closure
constexpr std::uintptr_t Closure_tt                  = 0x00; // [HIGH] uint8  LUA_TFUNCTION (8)
constexpr std::uintptr_t Closure_marked              = 0x01; // [HIGH] uint8
constexpr std::uintptr_t Closure_memcat              = 0x02; // [HIGH] uint8
constexpr std::uintptr_t Closure_isC                 = 0x03; // [HIGH] uint8  0=Lua, 1=C
constexpr std::uintptr_t Closure_stacksize           = 0x04; // [HIGH] uint8
constexpr std::uintptr_t Closure_nupvalues           = 0x05; // [HIGH] uint8
constexpr std::uintptr_t Closure_safeenv             = 0x06; // [HIGH] uint8  safe environment flag
constexpr std::uintptr_t Closure_env                 = 0x08; // [HIGH] Table*
constexpr std::uintptr_t Closure_gclist              = 0x10; // [HIGH] GCObject*
constexpr std::uintptr_t Closure_usage               = 0x18; // [HIGH] int64  usage counter (FFlag gated)
constexpr std::uintptr_t Closure_l_proto             = 0x20; // [HIGH] Proto* (Lua closure)
constexpr std::uintptr_t Closure_c_f                 = 0x20; // [HIGH] lua_CFunction (C closure)
constexpr std::uintptr_t Closure_c_cont              = 0x28; // [HIGH] lua_Continuation
constexpr std::uintptr_t Closure_upvals_start        = 0x28; // [HIGH] Lua: upvalue refs start here

// Proto (sizeof = 0xC0)
constexpr std::uintptr_t Proto_tt                    = 0x00; // [HIGH] uint8  0x0F (internal type)
constexpr std::uintptr_t Proto_marked                = 0x01; // [HIGH] uint8
constexpr std::uintptr_t Proto_memcat                = 0x02; // [HIGH] uint8
constexpr std::uintptr_t Proto_flags                 = 0x03; // [HIGH] uint8
constexpr std::uintptr_t Proto_maxstacksize          = 0x04; // [HIGH] uint8
constexpr std::uintptr_t Proto_is_vararg             = 0x05; // [HIGH] uint8
constexpr std::uintptr_t Proto_nups                  = 0x06; // [HIGH] uint8
constexpr std::uintptr_t Proto_numparams             = 0x07; // [HIGH] uint8
constexpr std::uintptr_t Proto_k                     = 0x48; // [HIGH] TValue* constants array
constexpr std::uintptr_t Proto_source                = 0x50; // [HIGH] TString* source filename
constexpr std::uintptr_t Proto_code_dispatch         = 0x58; // [HIGH] uint8*  first instruction (for dispatch)
constexpr std::uintptr_t Proto_code                  = 0x68; // [HIGH] Instruction* bytecode array
constexpr std::uintptr_t Proto_lineinfo              = 0x10; // [HIGH] uint8*  per-instruction line deltas
constexpr std::uintptr_t Proto_abslineinfo           = 0x70; // [HIGH] int32*  absolute line info
constexpr std::uintptr_t Proto_debuginsn             = 0x78; // [HIGH] void*
constexpr std::uintptr_t Proto_sizecode              = 0x98; // [HIGH] int32
constexpr std::uintptr_t Proto_linegaplog2           = 0x9C; // [HIGH] int32
constexpr std::uintptr_t Proto_debugid               = 0xAC; // [HIGH] int32
constexpr std::uintptr_t Proto_native_entries        = 0xB0; // [HIGH] void*  native code table
constexpr std::uintptr_t Proto_native_count          = 0xB8; // [HIGH] int32
constexpr std::uintptr_t Proto_native_id             = 0xBC; // [HIGH] int32
constexpr std::uintptr_t Proto_sizeof                = 0xC0; // [HIGH]

// Table (sizeof = 0x30)
//  NOTE: Field order at +0x03-0x07 differs from iOS and open-source Luau!
//  Confirmed via luaH_resizehash writing +0x05 (nodemask8), +0x07 (lsizenode)
//  and GETIMPORT checking cl->env+6 (safeenv)
constexpr std::uintptr_t Table_tt                    = 0x00; // [HIGH] uint8  LUA_TTABLE (7)
constexpr std::uintptr_t Table_marked                = 0x01; // [HIGH] uint8  GC mark bits
constexpr std::uintptr_t Table_memcat                = 0x02; // [HIGH] uint8  memory category
constexpr std::uintptr_t Table_tmcache               = 0x03; // [HIGH] uint8  metamethod cache bits
constexpr std::uintptr_t Table_readonly              = 0x04; // [HIGH] uint8  readonly flag
constexpr std::uintptr_t Table_nodemask8             = 0x05; // [HIGH] uint8  ~(-1 << lsizenode) — fast hash mask
constexpr std::uintptr_t Table_safeenv               = 0x06; // [HIGH] uint8  safe environment flag (for GETIMPORT)
constexpr std::uintptr_t Table_lsizenode             = 0x07; // [HIGH] uint8  log2(hash node count)
constexpr std::uintptr_t Table_sizearray             = 0x08; // [HIGH] int32  array part size
constexpr std::uintptr_t Table_nodemask              = 0x0C; // [HIGH] uint32 1 << lsizenode (full mask)
constexpr std::uintptr_t Table_metatable             = 0x10; // [HIGH] Table* metatable
constexpr std::uintptr_t Table_array                 = 0x18; // [HIGH] TValue* array part (also at +0x28 in some refs)
constexpr std::uintptr_t Table_node                  = 0x20; // [HIGH] LuaNode* hash part
constexpr std::uintptr_t Table_array_alt             = 0x28; // [HIGH] TValue* array (alternate/gclist)
constexpr std::uintptr_t Table_sizeof                = 0x30; // [HIGH]

// LuaNode (sizeof = 0x20)
constexpr std::uintptr_t LuaNode_val                 = 0x00; // [HIGH] TValue (16 bytes)
constexpr std::uintptr_t LuaNode_key_value           = 0x10; // [HIGH] key value (8 bytes)
constexpr std::uintptr_t LuaNode_key_extra           = 0x18; // [HIGH] key extra (4 bytes)
constexpr std::uintptr_t LuaNode_key_tt_next         = 0x1C; // [HIGH] packed: tt(4 bits) + next(28 bits)
constexpr std::uintptr_t LuaNode_sizeof              = 0x20; // [HIGH]

// TString
constexpr std::uintptr_t TString_tt                  = 0x00; // [HIGH] uint8  LUA_TSTRING (6)
constexpr std::uintptr_t TString_marked              = 0x01; // [HIGH] uint8
constexpr std::uintptr_t TString_memcat              = 0x02; // [HIGH] uint8
constexpr std::uintptr_t TString_atom                = 0x04; // [HIGH] int16  atom index (-1 = not atom)
constexpr std::uintptr_t TString_next                = 0x08; // [HIGH] TString* hash chain
constexpr std::uintptr_t TString_hash                = 0x10; // [HIGH] uint32
constexpr std::uintptr_t TString_len                 = 0x14; // [HIGH] uint32
constexpr std::uintptr_t TString_data                = 0x18; // [HIGH] char[] (null-terminated)

// Udata (userdata)
constexpr std::uintptr_t Udata_tt                    = 0x00; // [HIGH] uint8  LUA_TUSERDATA (9)
constexpr std::uintptr_t Udata_marked                = 0x01; // [HIGH] uint8
constexpr std::uintptr_t Udata_memcat                = 0x02; // [HIGH] uint8
constexpr std::uintptr_t Udata_tag                   = 0x03; // [HIGH] uint8  userdata type tag
constexpr std::uintptr_t Udata_len                   = 0x04; // [HIGH] int32
constexpr std::uintptr_t Udata_metatable             = 0x08; // [HIGH] Table*
constexpr std::uintptr_t Udata_data                  = 0x10; // [HIGH] user data starts here

// UpVal
constexpr std::uintptr_t UpVal_v                     = 0x08; // [HIGH] TValue* points to value
constexpr std::uintptr_t UpVal_value                 = 0x10; // [HIGH] TValue  closed value

// global_State
//  Core memory
constexpr std::uintptr_t global_totalbytes           = 0x00; // [HIGH] size_t  total allocated
constexpr std::uintptr_t global_GCthreshold          = 0x08; // [HIGH] size_t  GC trigger point
constexpr std::uintptr_t global_alloc_func           = 0x10; // [HIGH] lua_Alloc
constexpr std::uintptr_t global_alloc_ud             = 0x18; // [HIGH] void*   allocator userdata

//  GC lists
constexpr std::uintptr_t global_gray                 = 0x20; // [HIGH] GCObject* all GC pages head
constexpr std::uintptr_t global_grayagain            = 0x28; // [HIGH] GCObject* secondary gray list
constexpr std::uintptr_t global_sweephead            = 0x30; // [HIGH] GCObject* current sweep position

//  String table
constexpr std::uintptr_t global_strt_size            = 0x38; // [HIGH] uint32  bucket count (power of 2)
constexpr std::uintptr_t global_strt_nuse            = 0x3C; // [HIGH] uint32  number of interned strings
constexpr std::uintptr_t global_strt_hash            = 0x40; // [HIGH] TString** bucket array

//  GC parameters
constexpr std::uintptr_t global_gcstepmul            = 0x4C; // [HIGH] int32   GC step multiplier
constexpr std::uintptr_t global_currentwhite         = 0x54; // [HIGH] uint8   current white bit
constexpr std::uintptr_t global_gcstate              = 0x55; // [HIGH] uint8   0-4 (pause..sweep)

//  GC sentinel & upvalue list
constexpr std::uintptr_t global_gc_sentinel          = 0x58; // [HIGH] 16 bytes dummy anchor
constexpr std::uintptr_t global_uvhead               = 0x70; // [HIGH] UpVal*  upvalue list head
constexpr std::uintptr_t global_allgcopage_alt       = 0x80; // [HIGH] GCObject*
constexpr std::uintptr_t global_sweepgcopage         = 0x88; // [HIGH] GCObject* current sweep page

//  Main thread & type system
constexpr std::uintptr_t global_mainthread_alt       = 0x318;// [HIGH] lua_State* (referenced in GC atomic)
constexpr std::uintptr_t global_tmname               = 0x320;// [HIGH] TString*[21] metamethod names
constexpr std::uintptr_t global_ttname               = 0x3C8;// [HIGH] TString*[12] type names
constexpr std::uintptr_t global_mt                   = 0x438;// [HIGH] Table*[12] per-type metatables

//  GC flags & proto tracking
constexpr std::uintptr_t global_gc_flags             = 0x4C8;// [HIGH] uint32 (bit 30=verify, bit 28=meta cache)
constexpr std::uintptr_t global_proto_counter        = 0x44F8;// [HIGH] int32

//  Callbacks
constexpr std::uintptr_t global_cb_interrupt         = 0x530;// [HIGH] void(*)(L, int) VM interrupt
constexpr std::uintptr_t global_cb_debugstep         = 0x538;// [HIGH] void(*)(L) debug step hook
constexpr std::uintptr_t global_ecb_enter            = 0x568;// [HIGH] int(*)(L, Proto*) native entry
constexpr std::uintptr_t global_ecb_userdataremap    = 0x580;// [HIGH] void(*) userdata type remap (used in luau_load)
constexpr std::uintptr_t global_ecb_compile          = 0x590;// [HIGH] void(*)(L) JIT compilation trigger

//  Memory categories
constexpr std::uintptr_t global_memcatbytes          = 0x2C30;// [HIGH] size_t[256] per-category usage

//  GC timing / statistics (used in luaC_step and atomic phase)
constexpr std::uintptr_t global_gc_atomic_time_start = 0x4640;// [HIGH] double
constexpr std::uintptr_t global_gc_atomic_bytes_start= 0x4648;// [HIGH] size_t
constexpr std::uintptr_t global_gc_mark_time         = 0x4658;// [HIGH] double  accumulated mark time
constexpr std::uintptr_t global_gc_remark_time       = 0x4660;// [HIGH] double  accumulated remark time
constexpr std::uintptr_t global_gc_sweep_time        = 0x4668;// [HIGH] double  accumulated sweep time
constexpr std::uintptr_t global_gc_table_time        = 0x4670;// [HIGH] double  table sweep time
constexpr std::uintptr_t global_gc_bytes_prev        = 0x46A0;// [HIGH] size_t  bytes at prev cycle
constexpr std::uintptr_t global_gc_bytes_current     = 0x46A8;// [HIGH] size_t  current bytes
constexpr std::uintptr_t global_gc_threshold_target  = 0x46B0;// [HIGH] size_t  target threshold
constexpr std::uintptr_t global_gc_debt              = 0x46B8;// [HIGH] size_t  gc debt
constexpr std::uintptr_t global_gc_cycle_start_time  = 0x44E8;// [HIGH] double
constexpr std::uintptr_t global_gc_cycle_start_bytes = 0x44C8;// [HIGH] size_t

// Roblox Instance Property Cache (per userdata tag at global + tag*0x48)
constexpr std::uintptr_t PropCache_getter_func       = 0x7A0;// [HIGH]
constexpr std::uintptr_t PropCache_getter_aux        = 0x7A8;// [HIGH]
constexpr std::uintptr_t PropCache_getter_enabled    = 0x7AC;// [HIGH]
constexpr std::uintptr_t PropCache_setter_func       = 0x7B0;// [HIGH]
constexpr std::uintptr_t PropCache_setter_aux        = 0x7B8;// [HIGH]
constexpr std::uintptr_t PropCache_setter_enabled    = 0x7BC;// [HIGH]
constexpr std::uintptr_t PropCache_namecall_func     = 0x7C0;// [HIGH]
constexpr std::uintptr_t PropCache_namecall_aux      = 0x7C8;// [HIGH]
constexpr std::uintptr_t PropCache_namecall_enabled  = 0x7CC;// [HIGH]
constexpr std::uintptr_t PropCache_getter2_func      = 0x7D0;// [HIGH]
constexpr std::uintptr_t PropCache_setter2_func      = 0x7D8;// [HIGH]
constexpr std::uintptr_t PropCache_namecall2_func    = 0x7E0;// [HIGH]

// Roblox ScriptContext
constexpr std::uintptr_t ScriptContext_exectime      = 0x28; // [HIGH] double  accumulated execution time
constexpr std::uintptr_t ScriptContext_shutdown_area = 0x480;// [HIGH] shutdown deadline check area
constexpr std::uintptr_t ScriptContext_facet_limit   = 0x9F0;// [HIGH] int     facet access counter (checked > 2)
constexpr std::uintptr_t ScriptContext_dm_offset     = 0x730;// [HIGH] DataModel = ScriptContext - this

} // namespace offsets


//  OPCODE SHUFFLE MAP (88 active opcodes)
//
//  Roblox shuffles opcode numbers per build. This maps shuffled -> canonical.
//  The dispatch table at 0x6a8f130 has 256 entries (168 null, 88 active).
//
//  Fast-path opcodes rewrite themselves to slow-path on cache miss:
//    127 (NAMECALL)    -> 180 (NAMECALL_SLOW)
//    173 (SETTABLEKS)  ->  96 (SETTABLEKS_SLOW)
//    120 (GETTABLEKS)  -> 150 (GETTABLEKS_SLOW)

namespace opcodes {

// Shuffled opcode -> handler address
constexpr std::uintptr_t LOP_NOP                     =   201; // 0x60dc3c0
constexpr std::uintptr_t LOP_LOADNIL                 =   139; // 0x60dc3cc
constexpr std::uintptr_t LOP_LOADB                   =   176; // 0x60dc3e4
constexpr std::uintptr_t LOP_LOADN                   =    53; // 0x60dc418
constexpr std::uintptr_t LOP_LOADK                   =   188; // 0x60dc444
constexpr std::uintptr_t LOP_LOADKX                  =    15; // 0x60e0664
constexpr std::uintptr_t LOP_MOVE                    =   119; // 0x60dc468
constexpr std::uintptr_t LOP_GETGLOBAL               =    57; // 0x60dc488
constexpr std::uintptr_t LOP_SETGLOBAL               =    76; // 0x60dc534
constexpr std::uintptr_t LOP_GETUPVAL                =   242; // 0x60dc614
constexpr std::uintptr_t LOP_SETUPVAL                =    81; // 0x60dc654
constexpr std::uintptr_t LOP_CLOSEUPVALS             =   126; // 0x60dc6b0
constexpr std::uintptr_t LOP_GETIMPORT               =    99; // 0x60dc6e8
constexpr std::uintptr_t LOP_GETTABLEKS              =   120; // 0x60e0dac (fast -> 150)
constexpr std::uintptr_t LOP_GETTABLEKS_SLOW         =   150; // 0x60dc75c (rewrite target)
constexpr std::uintptr_t LOP_SETTABLEKS              =   173; // 0x60e0f44 (fast -> 96)
constexpr std::uintptr_t LOP_SETTABLEKS_SLOW         =    96; // 0x60dccb4 (rewrite target)
constexpr std::uintptr_t LOP_GETTABLE                =    54; // 0x60dcf44
constexpr std::uintptr_t LOP_SETTABLE                =    51; // 0x60dcfe4
constexpr std::uintptr_t LOP_GETTABLEN               =   228; // 0x60dd0bc
constexpr std::uintptr_t LOP_SETTABLEN               =    89; // 0x60dd148
constexpr std::uintptr_t LOP_NEWCLOSURE              =   225; // 0x60dd20c
constexpr std::uintptr_t LOP_CLOSURE                 =   168; // 0x60e03f8
constexpr std::uintptr_t LOP_NAMECALL                =   127; // 0x60e10dc (fast -> 180)
constexpr std::uintptr_t LOP_NAMECALL_SLOW           =   180; // 0x60dd324 (rewrite target)
constexpr std::uintptr_t LOP_CALL                    =   237; // 0x60dd938 (with native cache)
constexpr std::uintptr_t LOP_CALL2                   =   175; // 0x60dd6a0 (interrupt variant)
constexpr std::uintptr_t LOP_RETURN                  =   192; // 0x60ddc18
constexpr std::uintptr_t LOP_JUMP                    =   115; // 0x60ddd78
constexpr std::uintptr_t LOP_JUMPIF                  =    19; // 0x60dddc8
constexpr std::uintptr_t LOP_JUMPIFNOT               =    45; // 0x60ddd8c
constexpr std::uintptr_t LOP_JUMPIFEQ                =   151; // 0x60de12c
constexpr std::uintptr_t LOP_JUMPIFEQ_AUX            =    44; // 0x60e12f0
constexpr std::uintptr_t LOP_JUMPIFNOTEQ             =   226; // 0x60dde08
constexpr std::uintptr_t LOP_JUMPIFLT                =    12; // 0x60de690
constexpr std::uintptr_t LOP_JUMPIFLE                =    80; // 0x60de518
constexpr std::uintptr_t LOP_JUMPIFNOTLT             =    78; // 0x60de5d4
constexpr std::uintptr_t LOP_JUMPBACK                =   111; // 0x60e0684
constexpr std::uintptr_t LOP_JUMPBACK_INT            =   249; // 0x60e061c
constexpr std::uintptr_t LOP_JUMPXEQKNIL             =   152; // 0x60e0bf8
constexpr std::uintptr_t LOP_JUMPXEQKB               =    98; // 0x60e0c30
constexpr std::uintptr_t LOP_JUMPXEQKN               =   154; // 0x60e0c88
constexpr std::uintptr_t LOP_JUMPXEQKS               =   186; // 0x60e0d0c
constexpr std::uintptr_t LOP_ADD                     =    73; // 0x60de74c
constexpr std::uintptr_t LOP_SUB                     =   220; // 0x60de8a8
constexpr std::uintptr_t LOP_MUL                     =    93; // 0x60dea04
constexpr std::uintptr_t LOP_DIV                     =    40; // 0x60dec14
constexpr std::uintptr_t LOP_IDIV                    =   106; // 0x60dee2c
constexpr std::uintptr_t LOP_MOD                     =   223; // 0x60defd8
constexpr std::uintptr_t LOP_POW                     =    27; // 0x60df05c
constexpr std::uintptr_t LOP_ADDK                    =    68; // 0x60df0dc
constexpr std::uintptr_t LOP_SUBK                    =   143; // 0x60df154
constexpr std::uintptr_t LOP_MULK                    =   205; // 0x60df1cc
constexpr std::uintptr_t LOP_IDIVK                   =   190; // 0x60df310
constexpr std::uintptr_t LOP_DIVK                    =    88; // 0x60df458
constexpr std::uintptr_t LOP_MODK                    =   132; // 0x60df5c0
constexpr std::uintptr_t LOP_POWK                    =    41; // 0x60df644
constexpr std::uintptr_t LOP_SUBRK                   =   252; // 0x60e07cc (K(B) - R(C))
constexpr std::uintptr_t LOP_IDIVK_REV               =    90; // 0x60e0840 (K(B) // R(C))
constexpr std::uintptr_t LOP_NOT                     =    65; // 0x60df8e8
constexpr std::uintptr_t LOP_UNM                     =   177; // 0x60df950
constexpr std::uintptr_t LOP_LENGTH                  =   108; // 0x60dfa60
constexpr std::uintptr_t LOP_AND                     =    66; // 0x60df78c
constexpr std::uintptr_t LOP_OR                      =    22; // 0x60df73c
constexpr std::uintptr_t LOP_ANDK                    =    67; // 0x60df830
constexpr std::uintptr_t LOP_ORK                     =    48; // 0x60df7dc
constexpr std::uintptr_t LOP_CONCAT                  =    13; // 0x60e0d70
constexpr std::uintptr_t LOP_NEWTABLE                =   148; // 0x60df884
constexpr std::uintptr_t LOP_NEWTABLE_HASH           =   214; // 0x60dfb28
constexpr std::uintptr_t LOP_DUPTABLE                =   215; // 0x60dfb9c
constexpr std::uintptr_t LOP_SETLIST                 =    30; // 0x60dfc04
constexpr std::uintptr_t LOP_FORNPREP                =     5; // 0x60dfcc8
constexpr std::uintptr_t LOP_FORNLOOP                =   199; // 0x60dfd54
constexpr std::uintptr_t LOP_FORGPREP                =   216; // 0x60dfde8
constexpr std::uintptr_t LOP_FORGLOOP                =    28; // 0x60dff94
constexpr std::uintptr_t LOP_FORGPREP_INEXT          =   109; // 0x60e01c8
constexpr std::uintptr_t LOP_FORGPREP_NEXT           =    31; // 0x60e024c
constexpr std::uintptr_t LOP_NATIVECALL              =   213; // 0x60e02c0
constexpr std::uintptr_t LOP_GETVARARGS              =    62; // 0x60e02e8
constexpr std::uintptr_t LOP_PREPVARARGS             =   206; // 0x60e0598
constexpr std::uintptr_t LOP_FASTCALL                =   141; // 0x60e06d0
constexpr std::uintptr_t LOP_FASTCALL1               =     6; // 0x60e08ec
constexpr std::uintptr_t LOP_FASTCALL2               =    16; // 0x60e0a34
constexpr std::uintptr_t LOP_FASTCALL2K              =    75; // 0x60e0ae4
constexpr std::uintptr_t LOP_FASTCALL2_AUX           =   207; // 0x60e0988
constexpr std::uintptr_t LOP_COVERAGE                =   187; // 0x60e079c
constexpr std::uintptr_t LOP_BREAK                   =   241; // 0x60e0ba4

} // namespace opcodes


//  CONSTANTS

namespace constants {

// Status Codes
constexpr uint8_t LUA_OK                             = 0x00; // [HIGH]
constexpr uint8_t LUA_YIELD                          = 0x01; // [HIGH]
constexpr uint8_t LUA_ERRRUN                         = 0x02; // [HIGH]
constexpr uint8_t LUA_ERRSYNTAX                      = 0x03; // [HIGH]
constexpr uint8_t LUA_ERRMEM                         = 0x04; // [HIGH]
constexpr uint8_t LUA_ERRERR                         = 0x05; // [HIGH]
constexpr uint8_t LUA_BREAK                          = 0x06; // [HIGH]
constexpr uint8_t SCHEDULED_REENTRY                  = 0x7F; // [HIGH] Roblox stackless pcall

// CallInfo Flags
constexpr uint32_t LUA_CALLINFO_RETURN               = 0x01; // [HIGH]
constexpr uint32_t LUA_CALLINFO_HANDLE               = 0x02; // [HIGH]
constexpr uint32_t LUA_CALLINFO_NATIVE               = 0x04; // [HIGH]

// Type Tags
constexpr int LUA_TNIL                               = 0;    // [HIGH]
constexpr int LUA_TBOOLEAN                           = 1;    // [HIGH]
constexpr int LUA_TLIGHTUSERDATA                     = 2;    // [HIGH]
constexpr int LUA_TNUMBER                            = 3;    // [HIGH]
constexpr int LUA_TVECTOR                            = 5;    // [HIGH]
constexpr int LUA_TSTRING                            = 6;    // [HIGH]
constexpr int LUA_TTABLE                             = 7;    // [HIGH]
constexpr int LUA_TFUNCTION                          = 8;    // [HIGH]
constexpr int LUA_TUSERDATA                          = 9;    // [HIGH]
constexpr int LUA_TTHREAD                            = 10;   // [HIGH]
constexpr int LUA_TBUFFER                            = 11;   // [HIGH]
constexpr int LUA_TPROTO                             = 12;   // [HIGH] internal
constexpr int LUA_TUPVAL                             = 13;   // [HIGH] internal

// Metamethod Indices
constexpr int TM_INDEX                               = 0;    // [HIGH] "__index"
constexpr int TM_NEWINDEX                            = 1;    // [HIGH] "__newindex"
constexpr int TM_MODE                                = 2;    // [HIGH] "__mode"
constexpr int TM_NAMECALL                            = 3;    // [HIGH] "__namecall"
constexpr int TM_CALL                                = 4;    // [HIGH] "__call"
constexpr int TM_ITER                                = 5;    // [HIGH] "__iter"
constexpr int TM_LEN                                 = 6;    // [HIGH] "__len"
constexpr int TM_EQ                                  = 7;    // [HIGH] "__eq"
constexpr int TM_ADD                                 = 8;    // [HIGH]
constexpr int TM_SUB                                 = 9;    // [HIGH]
constexpr int TM_MUL                                 = 10;   // [HIGH]
constexpr int TM_DIV                                 = 11;   // [HIGH]
constexpr int TM_IDIV                                = 12;   // [HIGH]
constexpr int TM_MOD                                 = 13;   // [HIGH]
constexpr int TM_POW                                 = 14;   // [HIGH]
constexpr int TM_UNM                                 = 15;   // [HIGH]
constexpr int TM_LT                                  = 16;   // [HIGH]
constexpr int TM_LE                                  = 17;   // [HIGH]
constexpr int TM_CONCAT                              = 18;   // [HIGH]
constexpr int TM_TYPE                                = 19;   // [HIGH] "__type"
constexpr int TM_METATABLE                           = 20;   // [HIGH] "__metatable"
constexpr int TM_N                                   = 21;   // [HIGH] total count

// Limits
constexpr int LUAI_MAXCALLS                          = 20000;    // [HIGH]
constexpr int LUAI_MAXCALLS_HARD                     = 22500;    // [HIGH]
constexpr int LUAI_MAXCCALLS                         = 200;      // [HIGH]
constexpr int EXTRA_STACK                            = 5;        // [HIGH]
constexpr int LUA_MINSTACK                           = 20;       // [HIGH]
constexpr int BASIC_CI_SIZE                          = 8;        // [HIGH]
constexpr int MAX_STACK_SIZE                         = 0x4000000;// [HIGH]
constexpr int MAXTAGLOOP                             = 100;      // [HIGH]

// Pseudo-Indices
constexpr int LUA_REGISTRYINDEX                      = -10000;   // [HIGH]
constexpr int LUA_ENVIRONINDEX                       = -10001;   // [HIGH]
constexpr int LUA_GLOBALSINDEX                       = -10002;   // [HIGH]

// Precall Results
constexpr int PCRLUA                                 = 0;        // [HIGH] Lua function
constexpr int PCRC                                   = 1;        // [HIGH] C function completed
constexpr int PCRYIELD                               = 2;        // [HIGH] C function yielded

// GC States
constexpr uint8_t GCSpause                           = 0;        // [HIGH]
constexpr uint8_t GCSpropagate                       = 1;        // [HIGH]
constexpr uint8_t GCSpropagateagain                  = 2;        // [HIGH]
constexpr uint8_t GCSatomic                          = 3;        // [HIGH]
constexpr uint8_t GCSsweep                           = 4;        // [HIGH]

// GC Mark Bits
constexpr uint8_t WHITE0BIT                          = 0x01;     // [HIGH]
constexpr uint8_t WHITE1BIT                          = 0x02;     // [HIGH]
constexpr uint8_t WHITEBITS                          = 0x03;     // [HIGH]
constexpr uint8_t BLACKBIT                           = 0x04;     // [HIGH]
constexpr uint8_t FIXEDBIT                           = 0x10;     // [HIGH]

// Bytecode
constexpr int BYTECODE_VERSION_MIN                   = 3;        // [HIGH]
constexpr int BYTECODE_VERSION_MAX                   = 11;       // [HIGH]
constexpr int BYTECODE_TYPES_VERSION_MIN             = 1;        // [HIGH]
constexpr int BYTECODE_TYPES_VERSION_MAX             = 3;        // [HIGH]

} // namespace constants
