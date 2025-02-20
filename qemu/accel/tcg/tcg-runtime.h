DEF_HELPER_FLAGS_2(div_i32, TCG_CALL_NO_RWG_SE, s32, s32, s32)
DEF_HELPER_FLAGS_2(rem_i32, TCG_CALL_NO_RWG_SE, s32, s32, s32)
DEF_HELPER_FLAGS_2(divu_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)
DEF_HELPER_FLAGS_2(remu_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)

DEF_HELPER_FLAGS_2(div_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)
DEF_HELPER_FLAGS_2(rem_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)
DEF_HELPER_FLAGS_2(divu_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(remu_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(shl_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(shr_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(sar_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)

DEF_HELPER_FLAGS_2(mulsh_i64, TCG_CALL_NO_RWG_SE, s64, s64, s64)
DEF_HELPER_FLAGS_2(muluh_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_2(clz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)
DEF_HELPER_FLAGS_2(ctz_i32, TCG_CALL_NO_RWG_SE, i32, i32, i32)
DEF_HELPER_FLAGS_2(clz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(ctz_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_1(clrsb_i32, TCG_CALL_NO_RWG_SE, i32, i32)
DEF_HELPER_FLAGS_1(clrsb_i64, TCG_CALL_NO_RWG_SE, i64, i64)
DEF_HELPER_FLAGS_1(ctpop_i32, TCG_CALL_NO_RWG_SE, i32, i32)
DEF_HELPER_FLAGS_1(ctpop_i64, TCG_CALL_NO_RWG_SE, i64, i64)

DEF_HELPER_FLAGS_1(lookup_tb_ptr, TCG_CALL_NO_WG_SE, ptr, env)

DEF_HELPER_FLAGS_1(exit_atomic, TCG_CALL_NO_WG, noreturn, env)

#ifdef CONFIG_SOFTMMU

DEF_HELPER_FLAGS_5(atomic_cmpxchgb, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgw_be, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgw_le, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgl_be, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgl_le, TCG_CALL_NO_WG,
                   i32, env, tl, i32, i32, i32)
#ifdef CONFIG_ATOMIC64
DEF_HELPER_FLAGS_5(atomic_cmpxchgq_be, TCG_CALL_NO_WG,
                   i64, env, tl, i64, i64, i32)
DEF_HELPER_FLAGS_5(atomic_cmpxchgq_le, TCG_CALL_NO_WG,
                   i64, env, tl, i64, i64, i32)
#endif

#ifdef CONFIG_ATOMIC64
#define GEN_ATOMIC_HELPERS(NAME)                                  \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), b),              \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), w_le),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), w_be),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), l_le),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), l_be),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), q_le),           \
                       TCG_CALL_NO_WG, i64, env, tl, i64, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), q_be),           \
                       TCG_CALL_NO_WG, i64, env, tl, i64, i32)
#else
#define GEN_ATOMIC_HELPERS(NAME)                                  \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), b),              \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), w_le),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), w_be),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), l_le),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)    \
    DEF_HELPER_FLAGS_4(glue(glue(atomic_, NAME), l_be),           \
                       TCG_CALL_NO_WG, i32, env, tl, i32, i32)
#endif /* CONFIG_ATOMIC64 */

#else

DEF_HELPER_FLAGS_4(atomic_cmpxchgb, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
DEF_HELPER_FLAGS_4(atomic_cmpxchgw_be, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
DEF_HELPER_FLAGS_4(atomic_cmpxchgw_le, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
DEF_HELPER_FLAGS_4(atomic_cmpxchgl_be, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
DEF_HELPER_FLAGS_4(atomic_cmpxchgl_le, TCG_CALL_NO_WG, i32, env, tl, i32, i32)
#ifdef CONFIG_ATOMIC64
DEF_HELPER_FLAGS_4(atomic_cmpxchgq_be, TCG_CALL_NO_WG, i64, env, tl, i64, i64)
DEF_HELPER_FLAGS_4(atomic_cmpxchgq_le, TCG_CALL_NO_WG, i64, env, tl, i64, i64)
#endif

#ifdef CONFIG_ATOMIC64
#define GEN_ATOMIC_HELPERS(NAME)                             \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), b),         \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), w_le),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), w_be),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), l_le),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), l_be),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), q_le),      \
                       TCG_CALL_NO_WG, i64, env, tl, i64)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), q_be),      \
                       TCG_CALL_NO_WG, i64, env, tl, i64)
#else
#define GEN_ATOMIC_HELPERS(NAME)                             \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), b),         \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), w_le),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), w_be),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), l_le),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)    \
    DEF_HELPER_FLAGS_3(glue(glue(atomic_, NAME), l_be),      \
                       TCG_CALL_NO_WG, i32, env, tl, i32)
#endif /* CONFIG_ATOMIC64 */

#endif /* CONFIG_SOFTMMU */

GEN_ATOMIC_HELPERS(fetch_add)
GEN_ATOMIC_HELPERS(fetch_and)
GEN_ATOMIC_HELPERS(fetch_or)
GEN_ATOMIC_HELPERS(fetch_xor)
GEN_ATOMIC_HELPERS(fetch_smin)
GEN_ATOMIC_HELPERS(fetch_umin)
GEN_ATOMIC_HELPERS(fetch_smax)
GEN_ATOMIC_HELPERS(fetch_umax)

GEN_ATOMIC_HELPERS(add_fetch)
GEN_ATOMIC_HELPERS(and_fetch)
GEN_ATOMIC_HELPERS(or_fetch)
GEN_ATOMIC_HELPERS(xor_fetch)
GEN_ATOMIC_HELPERS(smin_fetch)
GEN_ATOMIC_HELPERS(umin_fetch)
GEN_ATOMIC_HELPERS(smax_fetch)
GEN_ATOMIC_HELPERS(umax_fetch)

GEN_ATOMIC_HELPERS(xchg)

#undef GEN_ATOMIC_HELPERS

DEF_HELPER_FLAGS_3(gvec_mov, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_dup8, TCG_CALL_NO_RWG, void, ptr, i32, i32)
DEF_HELPER_FLAGS_3(gvec_dup16, TCG_CALL_NO_RWG, void, ptr, i32, i32)
DEF_HELPER_FLAGS_3(gvec_dup32, TCG_CALL_NO_RWG, void, ptr, i32, i32)
DEF_HELPER_FLAGS_3(gvec_dup64, TCG_CALL_NO_RWG, void, ptr, i32, i64)

DEF_HELPER_FLAGS_4(gvec_add8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_add16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_add32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_add64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_adds8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_adds16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_adds32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_adds64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_sub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_subs8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_subs16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_subs32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_subs64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_mul8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_mul16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_mul32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_mul64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_muls8, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_muls16, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_muls32, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_muls64, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_4(gvec_ssadd8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ssadd16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ssadd32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ssadd64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_sssub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sssub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sssub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_sssub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_usadd8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_usadd16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_usadd32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_usadd64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ussub8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ussub16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ussub32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ussub64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_neg8, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_neg16, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_neg32, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_neg64, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_not, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_and, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_or, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_xor, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_andc, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_orc, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ands, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_xors, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)
DEF_HELPER_FLAGS_4(gvec_ors, TCG_CALL_NO_RWG, void, ptr, ptr, i64, i32)

DEF_HELPER_FLAGS_3(gvec_shl8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shl16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shl32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shl64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_shr8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shr16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shr32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_shr64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_3(gvec_sar8i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_sar16i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_sar32i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)
DEF_HELPER_FLAGS_3(gvec_sar64i, TCG_CALL_NO_RWG, void, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_eq8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_eq16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_eq32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_eq64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ne8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ne16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ne32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ne64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_lt8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_lt16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_lt32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_lt64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_le8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_le16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_le32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_le64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_ltu8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ltu16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ltu32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_ltu64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

DEF_HELPER_FLAGS_4(gvec_leu8, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_leu16, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_leu32, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)
DEF_HELPER_FLAGS_4(gvec_leu64, TCG_CALL_NO_RWG, void, ptr, ptr, ptr, i32)

#ifdef QASAN

#ifdef CONFIG_USER_ONLY
DEF_HELPER_FLAGS_2(qasan_load1, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qasan_load2, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qasan_load4, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qasan_load8, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qasan_store1, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qasan_store2, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qasan_store4, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qasan_store8, TCG_CALL_NO_RWG, void, env, tl)
#else
DEF_HELPER_FLAGS_3(qasan_load1, TCG_CALL_NO_RWG, void, env, tl, i32)
DEF_HELPER_FLAGS_3(qasan_load2, TCG_CALL_NO_RWG, void, env, tl, i32)
DEF_HELPER_FLAGS_3(qasan_load4, TCG_CALL_NO_RWG, void, env, tl, i32)
DEF_HELPER_FLAGS_3(qasan_load8, TCG_CALL_NO_RWG, void, env, tl, i32)
DEF_HELPER_FLAGS_3(qasan_store1, TCG_CALL_NO_RWG, void, env, tl, i32)
DEF_HELPER_FLAGS_3(qasan_store2, TCG_CALL_NO_RWG, void, env, tl, i32)
DEF_HELPER_FLAGS_3(qasan_store4, TCG_CALL_NO_RWG, void, env, tl, i32)
DEF_HELPER_FLAGS_3(qasan_store8, TCG_CALL_NO_RWG, void, env, tl, i32)
#endif
#endif

DEF_HELPER_FLAGS_5(qasan_fake_instr, TCG_CALL_NO_RWG, ptr, env, ptr, ptr, ptr, ptr)
DEF_HELPER_FLAGS_2(qasan_shadow_stack_push, TCG_CALL_NO_RWG, void, tl, tl)
DEF_HELPER_FLAGS_2(qasan_shadow_stack_pop, TCG_CALL_NO_RWG, void, tl, tl)

#ifdef MSAN_GIOVESE
DEF_HELPER_FLAGS_1(qmsan_call, TCG_CALL_NO_RWG, void, tl)
DEF_HELPER_FLAGS_1(qmsan_ret, TCG_CALL_NO_RWG, void, tl)
DEF_HELPER_FLAGS_1(qmsan_set_sp, TCG_CALL_NO_RWG, void, tl)
DEF_HELPER_FLAGS_2(qmsan_check_ret_from_lib, TCG_CALL_NO_RWG, void, i64, tl)
DEF_HELPER_FLAGS_2(qmsan_check_call_from_lib, TCG_CALL_NO_RWG, void, i64, tl)

DEF_HELPER_FLAGS_2(qmsan_store1, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qmsan_store2, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qmsan_store4, TCG_CALL_NO_RWG, void, env, tl)
DEF_HELPER_FLAGS_2(qmsan_store8, TCG_CALL_NO_RWG, void, env, tl)

/*TODO: use macro to delete the not used ones*/
//no taint mode
DEF_HELPER_FLAGS_3(qmsan_load1, TCG_CALL_NO_RWG, void, env, tl, tl)
DEF_HELPER_FLAGS_3(qmsan_load2, TCG_CALL_NO_RWG, void, env, tl, tl)
DEF_HELPER_FLAGS_3(qmsan_load4, TCG_CALL_NO_RWG, void, env, tl, tl)
DEF_HELPER_FLAGS_3(qmsan_load8, TCG_CALL_NO_RWG, void, env, tl, tl)

#ifdef MSAN_TEST_LOAD
DEF_HELPER_FLAGS_3(qmsan_load_log, TCG_CALL_NO_RWG, void, env, tl, tl)
#endif
#ifdef MSAN_TEST_STORE
DEF_HELPER_FLAGS_3(qmsan_store_log, TCG_CALL_NO_RWG, void, env, tl, tl)
#endif

//taint mode
DEF_HELPER_FLAGS_4(qmsan_check_taint_tmp_mem, TCG_CALL_NO_RWG, void, i64, i32, tl, i32)
DEF_HELPER_FLAGS_4(qmsan_check_taint_reg_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_check_taint_tmp_reg, TCG_CALL_NO_RWG, void, i64, i32, i32, i32)
DEF_HELPER_FLAGS_2(qmsan_check_taint_tmp_flag, TCG_CALL_NO_RWG, void, i64, i32)
DEF_HELPER_FLAGS_5(qmsan_check_taint_tmp_tmp_reg, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_check_taint_tmp_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_check_test, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_1(qmsan_check_taint_flags, TCG_CALL_NO_RWG, void, i64)
DEF_HELPER_FLAGS_2(qmsan_restore_temp, TCG_CALL_NO_RWG, void, i64, i32)
DEF_HELPER_FLAGS_2(qmsan_check_temp, TCG_CALL_NO_RWG, void, i64, i32)
DEF_HELPER_FLAGS_5(qmsan_check_math_reg_tmp_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_check_math_tmp_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_5(qmsan_check_math_reg_reg_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i32)
DEF_HELPER_FLAGS_6(qmsan_check_math_reg_reg_reg_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_zero_N_if_taint_tmp, TCG_CALL_NO_RWG, void, i64, tl, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_zero_N_if_taint_reg, TCG_CALL_NO_RWG, void, i64, tl, i32, i32)
DEF_HELPER_FLAGS_2(qmsan_check_syscall, TCG_CALL_NO_RWG, void, i64, i64)

DEF_HELPER_FLAGS_6(qmsan_check_taint_and_tmp_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32, i64, i64, i32)
DEF_HELPER_FLAGS_6(qmsan_check_taint_or_tmp_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32, i64, i64, i32)
DEF_HELPER_FLAGS_6(qmsan_check_taint_xor_tmp_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32, i64, i64, i32)
DEF_HELPER_FLAGS_6(qmsan_check_taint_cmp_tmp_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32, i64, i64, i32)
DEF_HELPER_FLAGS_5(qmsan_check_shift, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_check_shift_tmp_imm, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_widening_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_5(qmsan_check_rot, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i32)

//to manage movcc operations
DEF_HELPER_FLAGS_3(qmsan_save_t0, TCG_CALL_NO_RWG, void, i64, i64, i32)
DEF_HELPER_FLAGS_2(qmsan_check_t0, TCG_CALL_NO_RWG, void, i64, i64)

//mmx lifters
DEF_HELPER_FLAGS_3(qmsan_check_taint_xmm_tmp, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_check_taint_reg_xmm, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_check_taint_xmm_mem_l, TCG_CALL_NO_RWG, void, i64, i32, tl)
DEF_HELPER_FLAGS_3(qmsan_check_taint_xmm_mem_d, TCG_CALL_NO_RWG, void, i64, i32, tl)
DEF_HELPER_FLAGS_3(qmsan_check_taint_xmm_mem, TCG_CALL_NO_RWG, void, i64, i32, tl)
DEF_HELPER_FLAGS_3(qmsan_check_taint_xmm_xmm, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_check_math_xmm_xmm, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_check_math_xmm_xmm_size, TCG_CALL_NO_RWG, void, i64, i32, i32, i32)
DEF_HELPER_FLAGS_5(qmsan_check_xmm_xmm_xmm_size, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_check_xmm_xmm_size, TCG_CALL_NO_RWG, void, i64, i32, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_check_xmm_reg_size, TCG_CALL_NO_RWG, void, i64, i32, i32, i32)
DEF_HELPER_FLAGS_3(qmsan_restore_xmm_partial, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_zero_N_if_taint_xmm, TCG_CALL_NO_RWG, void, i64, tl, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_and_reg_imm, TCG_CALL_NO_RWG, void, i64, i32, i64, i32)

//mostly arm64 lifters
DEF_HELPER_FLAGS_3(qmsan_check_taint_reg_reg, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_check_taint_reg_reg_mask, TCG_CALL_NO_RWG, void, i64, i32, i32, i64)
DEF_HELPER_FLAGS_6(qmsan_check_taint_and_reg_reg_reg, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i64, i64)
DEF_HELPER_FLAGS_4(qmsan_check_taint_reg_reg_reg, TCG_CALL_NO_RWG, void, i64, i32, i32, i32)
DEF_HELPER_FLAGS_5(qmsan_check_taint_reg_reg_reg_reg, TCG_CALL_NO_RWG, void, i64, i32, i32, i32, i32)
DEF_HELPER_FLAGS_2(qmsan_restore_reg, TCG_CALL_NO_RWG, void, i64, i32)
DEF_HELPER_FLAGS_2(qmsan_check_reg, TCG_CALL_NO_RWG, void, i64, i32)
DEF_HELPER_FLAGS_3(qmsan_check_reg_pos, TCG_CALL_NO_RWG, void, i64, i32, i64)
DEF_HELPER_FLAGS_2(qmsan_check_flags_reg, TCG_CALL_NO_RWG, void, i64, i32)
DEF_HELPER_FLAGS_3(qmsan_check_flags_reg_reg, TCG_CALL_NO_RWG, void, i64, i32, i32)
DEF_HELPER_FLAGS_4(qmsan_check_taint_reg_mem, TCG_CALL_NO_RWG, void, i64, i32, tl, i32)

DEF_HELPER_FLAGS_0(qmsan_main, TCG_CALL_NO_RWG, void)

DEF_HELPER_FLAGS_1(qmsan_debug_print_instr, TCG_CALL_NO_RWG, void, i64)
DEF_HELPER_FLAGS_1(qmsan_debug_print_sp, TCG_CALL_NO_RWG, void, i64)
#endif