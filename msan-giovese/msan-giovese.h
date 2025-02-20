#pragma once
#include "stdint.h"
#include "stdlib.h"

#include "msan-giovese-debug.h"


#define MSAN_SHADOW_ADDR    ((void*)0x200000000000LL)
#define MSAN_SHADOW_SIZE    (0x1fffffffffffLL)
#define MSAN_SHADOW_MASK    (0x400000000000LL)

//debugging purposes
#define MSAN_INS            "\n"
#define MSAN_INFO           "\t"

#define MSAN_64             0xffffffffffffffff
#define MSAN_32             0xffffffff
#define MSAN_16             0xffff
#define MSAN_8              0xff
#define MSAN_8A             0xaa

#define QMSAN_AFL_UNTOUCHED             0
#define QMSAN_AFL_CLEAN                 1 << 0
#define QMSAN_AFL_ERROR                 1 << 1
#define QMSAN_AFL_MEMORY                1 << 2
#define QMSAN_AFL_PC_EDGE               1 << 3
#define QMSAN_AFL_CS                    1 << 4
#define QMSAN_AFL_CS_EDGE               1 << 5

#define MSAN_SIZE(ot)       (ot & MO_SIZE)

//compilers add exotic checks to perform things like strlen, strcmp etc
//this checks use black magic constants that can be spotted to catch these
//behaviors. More infos in https://valgrind.org/docs/memcheck2005.pdf and
//in valgrind's source code (e.g. isBogusAtom() function)
#define MSAN_IS_BOGUS(val)  /*32*/   (((unsigned) (val)) == 0xFEFEFEFFULL               \
                            /*32*/ || ((unsigned) (val)) == 0x80808080ULL               \
                            /*32*/ || ((unsigned) (val)) == 0x7F7F7F7FULL               \
                            /*32*/ || ((unsigned) (val)) == 0x7EFEFEFFULL               \
                            /*32*/ || ((unsigned) (val)) == 0x81010100ULL               \
                            /*64*/ || ((unsigned long) (val)) == 0xFFFFFFFFFEFEFEFFULL       \
                            /*64*/ || ((unsigned long) (val)) == 0xFEFEFEFEFEFEFEFFULL       \
                            /*64*/ || ((unsigned long) (val)) == 0x0000000000008080ULL       \
                            /*64*/ || ((unsigned long) (val)) == 0x8080808080808080ULL       \
                            /*64*/ || ((unsigned long) (val)) == 0x0101010101010101ULL)

//used to populate msan's initial context from QEMU
struct elf_segment_info{
    uintptr_t load_addr;
    uintptr_t start_code;
    uintptr_t end_code;
    uintptr_t start_data;
    uintptr_t end_data;
    uintptr_t arg_start;
    uintptr_t arg_end;
    uintptr_t saved_auxv;
    uintptr_t auxv_len;
    uintptr_t start_stack;
    uintptr_t stack_limit;
    uintptr_t arg_strings;
    uintptr_t env_strings;
    uintptr_t file_string;
};

extern uintptr_t app_start;
extern uintptr_t app_end;
extern uintptr_t load_addr;

extern uintptr_t qmsan_start_addr;
extern uintptr_t qmsan_end_addr;

extern uintptr_t ld_start;
extern uintptr_t ld_end;

extern uint64_t qmsan_ptr_main;

//ptr to the dispatcher needed for qmsan's patching
extern uintptr_t dispatcher_ptr;

extern long unsigned instr_counter;
extern __thread int target_area;
extern int main_called;


//to use relative addresses with both persistent and deferred mode
#define MSAN_GIOVESE_AFL

/*in case we do not want to intstrument libraries, we avoid
creating some lifters based on the program counter*/
#ifdef MSAN_NO_LIB
//do our things only if we are in the app
#define CHECK_BOUNDARIES_RETURN(pc)\
    if((pc < app_start || pc > app_end) /*&& (pc < ld_start || pc > ld_end)*/) return;
#define CHECK_BOUNDARIES_BREAK(pc)\
    if((pc < app_start || pc > app_end) /*&& (pc < ld_start || pc > ld_end)*/) break;
#define CHECK_BOUNDARIES_IF(pc)\
    if((pc >= app_start && pc <= app_end) /*|| (pc >= ld_start && pc <= ld_end)*/)
#else
//make the statement useless
#define CHECK_BOUNDARIES_RETURN(pc) ;
#define CHECK_BOUNDARIES_BREAK(pc) ;
#define CHECK_BOUNDARIES_IF(pc) if(1)
#endif

void msan_giovese_init(struct elf_segment_info*);

void msan_giovese_report(uintptr_t, size_t, uintptr_t);
void msan_giovese_report_arg(uintptr_t, int, int);
void msan_giovese_report_reg(uintptr_t, int, int);
void msan_giovese_report_tmp(uintptr_t);
void msan_giovese_report_flags(uintptr_t);
void msan_giovese_report_syscall(uintptr_t, uint32_t, uint32_t);

//store and load
int msan_giovese_store1(uintptr_t);
int msan_giovese_store2(uintptr_t);
int msan_giovese_store4(uintptr_t);
int msan_giovese_store8(uintptr_t);
int msan_giovese_storeN(uintptr_t, int);

uint8_t msan_giovese_load1(uintptr_t);
uint16_t msan_giovese_load2(uintptr_t);
uint32_t msan_giovese_load4(uintptr_t);
uint64_t msan_giovese_load8(uintptr_t);
int msan_giovese_loadN(uintptr_t, int);

int msan_giovese_zeroN(uintptr_t, int);
void msan_giovese_propagate(uintptr_t, uintptr_t, int);
void msan_propagate_xmm(uintptr_t, int, uint32_t);
void msan_propagate_to_xmm(int, uintptr_t);
void msan_giovese_set_mem_to_regval(uintptr_t, unsigned long, uint32_t);

int msan_giovese_check_addr(uintptr_t);
int msan_giovese_check_addr_stack(uintptr_t);
int msan_giovese_check_callstack(uintptr_t);
void print_callstack(uintptr_t);

void msan_giovese_set_ld(uintptr_t, uintptr_t);
int msan_giovese_check_ld(uintptr_t);

void msan_giovese_add_mmap(uintptr_t, uintptr_t);
void msan_giovese_remove_mmap(uintptr_t, uint64_t);

uintptr_t get_sp(void);
void msan_giovese_set_sp(uintptr_t);
void msan_compare_sp(uintptr_t);

void msan_giovese_call(void);
void msan_giovese_ret(void);


//regs tainting
void msan_taint_tmp(int, unsigned long);
void msan_restore_tmp(int);
unsigned long msan_check_tmp(int);

void msan_taint_reg(int, unsigned long);
void msan_restore_reg(int);
unsigned long msan_check_reg(int);

void msan_taint_flags(void);
void msan_restore_flags(void);
int msan_check_flags(void);

void msan_taint_xmm(int);
void msan_taint_xmm_size(int, uint32_t);
void msan_restore_xmm(int);
void msan_restore_xmm_partial(int, uint32_t);
unsigned long msan_check_xmm(int);
unsigned long msan_check_xmm_size(int, uint32_t);

extern uintptr_t msan_callstack;