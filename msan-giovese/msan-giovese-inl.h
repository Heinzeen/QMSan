#include "stdio.h"
#include <sys/mman.h>
#include <assert.h>
#include <signal.h>

#include "msan-giovese.h"
#include "msan-lists.h"
#include "msan-giovese-afl.h"

#include <sys/types.h>
#include <sys/shm.h>

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1U << MAP_SIZE_POW2)

//we include this to get the callstack info for free
//TODO: to be removed when we will detatch msan from asan
#include "../asan-giovese/asan-giovese.h"

#include <string.h>


void* __shadow_addr = MSAN_SHADOW_ADDR;
size_t __shadow_size = MSAN_SHADOW_SIZE;
long long __shadow_addr_mask = MSAN_SHADOW_MASK;

struct elf_segment_info* info;

struct stack_list_head* stack_list;

__thread uintptr_t _sp = 0;

int counter = 0;
__thread uintptr_t last;

int flag_ld_done = 0;

uintptr_t ld_start = 0;
uintptr_t ld_end = 0;

uintptr_t app_start = 0;
uintptr_t app_end = 0;
uintptr_t load_addr = 0;


uintptr_t qmsan_start_addr;
uintptr_t qmsan_end_addr;
int no_exit;
__thread int target_area = 0;
int main_called = 0;

//taint propagation through registers
//x86: [T0, T1, tmp0, A0, other]
__thread unsigned long temp_regs[5] = {MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                       MSAN_64};
__thread unsigned long regs[32] = {MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64};
//every xmm register is 2 unsigned long
__thread unsigned long xmm[64] = {MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64,
                                    MSAN_64, MSAN_64, MSAN_64, MSAN_64};
__thread int flags;

/* Guest to shadow addresses, in case we are below the shadow mask we have to
 * increase it (it happens in ARM)*/
//TODO: a few things changed since the last check on arm, check that it works!
#define  G2S(ptr) ((ptr <= MSAN_SHADOW_MASK) ? ((ptr + MSAN_SHADOW_MASK/2) & ~ __shadow_addr_mask) : (ptr & ~ __shadow_addr_mask) )


void msan_giovese_init(struct elf_segment_info* msan_info){

    void* shadow_addr = mmap(__shadow_addr, __shadow_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE | MAP_ANON, -1,
                0);

    assert(shadow_addr != MAP_FAILED);

#ifdef MSAN_DEBUG_START_INFO
    fprintf(stderr, "mapped at %p with len = %lx\n", shadow_addr, __shadow_size);
#endif
    
    info = msan_info;

    app_start = info->start_code;
    app_end = info->end_code;
    load_addr = info->load_addr;

    last = info->start_stack;
    _sp = info->start_stack;

#ifdef MSAN_DEBUG_START_INFO
    fprintf(stderr, "load_addr   0x%lx\n", info->load_addr);
    fprintf(stderr, "start_code  0x%lx\n", info->start_code);
    fprintf(stderr, "end_code    0x%lx\n", info->end_code);
    fprintf(stderr, "start_data  0x%lx\n", info->start_data);
    fprintf(stderr, "end_data    0x%lx\n", info->end_data);
    fprintf(stderr, "arg_start   0x%lx\n", info->arg_start);
    fprintf(stderr, "arg_end     0x%lx\n", info->arg_end + (uintptr_t)sizeof(uintptr_t));
    fprintf(stderr, "auxv_start  0x%lx\n", info->saved_auxv);
    fprintf(stderr, "auxv_len    0x%lx\n", info->auxv_len);
    fprintf(stderr, "start_stack 0x%lx\n", info->start_stack);
    fprintf(stderr, "stack_limit 0x%lx\n", info->stack_limit);
    fprintf(stderr, "arg_strings 0x%lx\n", info->arg_strings);
    fprintf(stderr, "env_strings 0x%lx\n", info->env_strings);
    fprintf(stderr, "file_string 0x%lx\n", info->file_string);
#endif

    //initialize boundaries for verbose mode, if needed
#ifdef MSAN_DEBUG_PRINT

  char *verbose_start = getenv("VERBOSE_START");

  if (verbose_start) {
    qmsan_start_addr = load_addr + strtoul(verbose_start, NULL, 16);
    MSAN_PRINT("Verbose will start at %lx\n", qmsan_start_addr);
  }
  else
    MSAN_PRINT("Verbose will start at main\n");

  char *verbose_end = getenv("VERBOSE_END");

  if (verbose_end) {
    qmsan_end_addr = load_addr + strtoul(verbose_end, NULL, 16);
    MSAN_PRINT("Verbose will end at %lx\n", qmsan_end_addr);
  }

#endif

#ifdef MSAN_TAINT_ANALYSIS
  char *keep_going = getenv("QMSAN_NO_EXIT_ON_ERROR");
  if (keep_going)
    no_exit = 1;
#endif

//check if we are using taint to validate a testcase.
//we reuse the same shared memory we use for AFL++
#if defined MSAN_TAINT_ANALYSIS && !defined MSAN_AFL

  char *msan_id_str = getenv(MSAN_SHM_ENV_VAR);

  if (msan_id_str) {

    fprintf(stderr, "Validation attempt detected\n");

    int msan_shm_id = atoi(msan_id_str);
    msan_area_ptr = shmat(msan_shm_id, NULL, 0);

    if (msan_area_ptr == (void *)-1 || !msan_area_ptr) exit(10);

    //set it to 0, we will set it to 1 in case of TP
    msan_area_ptr[MAP_SIZE - 1] = 0;
    fprintf(stderr, "ptr = %p\n", msan_area_ptr);
  }

#endif

}

/*================================
  |     auxiliary functions      |
  ================================
pointer checking, ld tracking*/

//Returns 0 if we have to ignore the load operation, i.e. the address is safe (e.g. previous mmap of a file)
int msan_giovese_check_addr(uintptr_t ptr){

    return ! ((ptr>= info->start_code && ptr<=info->end_code) ||
        (ptr>= info->start_data && ptr<=info->end_data) ||
        (ptr>= info->arg_start && ptr<=info->arg_end + (uintptr_t)sizeof(uintptr_t)) ||
        (ptr>= info->saved_auxv && ptr<=info->saved_auxv + info->auxv_len + (uintptr_t)sizeof(uintptr_t)) || 
        (ptr>= info->start_stack && ptr<=info->start_stack + (uintptr_t)sizeof(uintptr_t)) ||
        (ptr>= info->arg_strings && ptr<=info->file_string + (uintptr_t)sizeof(uintptr_t)) ||
        check_addr_mmap_list(ptr));
}



void msan_giovese_set_ld(uintptr_t start, uintptr_t end){

    //fprintf(stderr, "setting ld boundaries from %p to %p\n", start, end);

    ld_start = start;
    ld_end = end;
}

int msan_giovese_check_ld(uintptr_t addr){
    //fprintf(stderr, "checking %p, res = %d\n", addr, (addr >= ld_start) && (addr <= ld_end) );
    return (addr >= ld_start) && (addr <= ld_end);
}

//Check if, in the callstack, we have something related to the binary.
//If we don't, then we are either in the loader or in something that is
//happening later, i.e. we are not interested.

//UPDATE: we should not need this anymore. Let's keep this in case we need it
//          again in the future (though we should think about it)
int msan_giovese_check_callstack(uintptr_t pc){
    return 1;
    // struct call_context ctx;
    // asan_giovese_populate_context(&ctx, pc);
    // size_t i;
    // for (i = 0; i < ctx.size; ++i) {
    //     if(ctx.addresses[i] >= info->start_code && ctx.addresses[i] <=info->end_code)
    //         return 1;

    // }
    // return 0 || (pc >= app_start && pc <= app_end);//second part needed to manage AFL with no context
}



int msan_giovese_check_addr_stack(uintptr_t ptr){
    if(ptr <= info->start_stack && ptr >= info->stack_limit)
        return 1;
    return 0;

}

void msan_giovese_add_mmap(uintptr_t start, uintptr_t end){

    MSAN_MMAP_INFO(MSAN_INFO "mmapping from %lx to %lx \n", start, end);

    manage_new_mmap_list(start, end);

    //the function is only defined if we need it
#ifdef MSAN_DEBUG_MMAP_INFO
    print_mmap_list();
#endif

}

void msan_giovese_remove_mmap(uintptr_t start, uint64_t len){

    MSAN_MMAP_INFO(MSAN_INFO "removing map from %lx len %lx \n", start, len);

    remove_mmap_list(start, len);

    //the function is only defined if we need it
#ifdef MSAN_DEBUG_MMAP_INFO
    print_mmap_list();
#endif

}


/*================================
  |    violations management     |
  ================================
reports, process ending, callstack printing*/

static void stop_execution(){

#ifdef MSAN_TAINT_ANALYSIS
    if(no_exit)
        return;
#endif

#if defined MSAN_AFL && !defined MSAN_TAINT_ANALYSIS
    return;
#endif
#if defined MSAN_AFL && defined MSAN_TAINT_ANALYSIS
    signal(SIGABRT, SIG_DFL);
    abort();
#endif
    free(info);

#if defined MSAN_TAINT_ANALYSIS && !defined MSAN_AFL
    //are we validating a testcase?
    if(msan_area_ptr)
        msan_area_ptr[MAP_SIZE - 1] = 1;
#endif
    //dump the mappings info
    //char cmd[64];
    //sprintf(cmd, "cat /proc/%d/maps", getpid());
    //system(cmd);

    exit(89);

}

void print_callstack(uintptr_t pc){

#ifdef MSAN_TAINT_ANALYSIS
    if(no_exit)
        return;
#endif

    fprintf(stderr, "Callstack:\n");
    struct call_context ctx;
    asan_giovese_populate_context(&ctx, pc);
    size_t i;
    for (i = 0; i < ctx.size; ++i) {

    char* printable = asan_giovese_printaddr(ctx.addresses[i]);
    if (printable)
        fprintf(stderr, "    #%lu 0x%012" PRIxPTR "%s\n", i, ctx.addresses[i],
                printable);
    else
        fprintf(stderr, "    #%lu 0x%012" PRIxPTR "\n", i, ctx.addresses[i]);

    }
}

long unsigned instr_counter = 0;
uintptr_t last_edge = 0;
uintptr_t last_cs_edge = 0;

#ifdef MSAN_AFL
void msan_update_map(uintptr_t ptr, uintptr_t pc){
    //TODO: (pc - load_addr) assumes that we are using no_lib mode
    //i.e. we only find candidates in the binary and not in the libraries

    //edges between instructions
    uint32_t idx = ((msan_callstack^(pc-load_addr))^(last_cs_edge >> 1)) % MAP_SIZE;
    last_cs_edge = msan_callstack^(pc-load_addr);

#ifdef AFL_ONLY_EDGES
    //if we are only looking for edges, we don't need to use bitfields
    if(!msan_area_ptr[idx]){
        msan_area_ptr[idx] = QMSAN_AFL_CS_EDGE;
        last_cs_edge = msan_callstack^(pc-load_addr);
        msan_area_ptr[MAP_SIZE - 1] = 0xff;
    }
    return;
#endif

    //instruction
    msan_area_ptr[(pc - load_addr) % MAP_SIZE] |= QMSAN_AFL_ERROR;

    //edges between instructions
    msan_area_ptr[((last_edge >> 1) ^ (pc - load_addr) ) % MAP_SIZE]
                    |= QMSAN_AFL_PC_EDGE;
    last_edge = pc - load_addr;


    //instruction and memory
    //msan_area_ptr[((pc - load_addr)^ptr) % MAP_SIZE] |= QMSAN_AFL_MEMORY;


    //callstack
    msan_area_ptr[(msan_callstack^(pc-load_addr)) % MAP_SIZE] |= QMSAN_AFL_CS;

    //edges between whole callstacks
    msan_area_ptr[idx]
                     |= QMSAN_AFL_CS_EDGE;
    //last_cs_edge = msan_callstack^(pc-load_addr);


    //lastly, set this to 0xff so that AFL knows we found something
    msan_area_ptr[MAP_SIZE - 1] = 0xff;

}
#endif

void msan_giovese_report(uintptr_t ptr, size_t dim, uintptr_t pc){

#ifdef MSAN_IGNORE_ERRORS
    return;
#endif

    //if we are in AFL and we detect a crash in load/store mode, keep going
    //and let AFL decide whether to check it or not with taint analysis
#ifdef MSAN_AFL_DEBUG
    fprintf(stderr, "Error while reading a value of size %zu in 0x%lx at pc 0x%lx\n", dim, ptr, pc);
    fprintf(stderr, "\tInstruction: 0x%lx\n", (pc - load_addr) % MAP_SIZE);
    fprintf(stderr, "\tEdge: 0x%lx\n", ((last_edge >> 1) ^ (pc - load_addr) ) % MAP_SIZE);
    last_edge = pc - load_addr;
    fprintf(stderr, "\tCallstack: 0x%lx\n", (msan_callstack^(pc-load_addr)) % MAP_SIZE);
    fprintf(stderr, "\tCallstack edge: 0x%lx\n\n", ((msan_callstack^(pc-load_addr))^(last_cs_edge >> 1)) % MAP_SIZE);
    last_cs_edge = msan_callstack^(pc-load_addr);
    fprintf(stderr, "\tLast edge:%lx, last cs edge: %lx\n\n", last_edge, last_cs_edge);
    return;
#endif

#ifdef MSAN_AFL
    msan_update_map(ptr, pc);
    return;
#endif

    uintptr_t h = G2S(ptr);

    //fprintf(stderr, "[%d]Error while reading a value of size %zu in %lx at pc 0x%lx\n", gettid(), dim, ptr, pc);
    fprintf(stderr, "[]Error while reading a value of size %zu in %lx at pc 0x%lx\n"/*, gettid()*/, dim, ptr, pc);
    fprintf(stderr, "Value of shadow map =");
    int i;
    int8_t* p = (int8_t*) h;
    for (i = -64; i < (int) (dim<64 ? 64 : dim); i++){
        if(i%8 == 0){
            if(!i)
                fprintf(stderr, "\n 0x%lx:==>", ptr + i);
            else
                fprintf(stderr, "\n 0x%lx:   ", ptr + i);
        }
        fprintf(stderr, "%.2hhx ", p[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "Content of memory locations=");
    p = (int8_t*) ptr;
    for (i = -64; i < (int) (dim<64 ? 64 : dim); i++){
        if(i%8 == 0){
            if(!i)
                fprintf(stderr, "\n 0x%lx:==>", ptr + i);
            else
                fprintf(stderr, "\n 0x%lx:   ", ptr + i);
        }
        fprintf(stderr, "%.2hhx ", p[i]);
    }
    fprintf(stderr, "\n");
    
    fprintf(stderr, "instruction counter: %lu\n", instr_counter);
    if(ptr < info->start_stack && ptr> info->stack_limit)
        fprintf(stderr, "----it is on stack----\n");

    //add callstack

    print_callstack(pc);
    
    stop_execution();
}

//computed as the opposite of the one used for the translation
//arch specific, filled with -1
int reg_arg[] = {-1, 3, 2, -1, -1, -1, 1, 0, 4, 5};

void msan_giovese_report_arg(uintptr_t pc, int arg, int xmm){

    //if the loader does something bad, it is not our concern
    if(!msan_giovese_check_callstack(pc))
        return;

    if(!xmm)
        fprintf(stderr, "Argument %d uninitialized for call at addr 0x%lx\n", reg_arg[arg], pc);
    else
        fprintf(stderr, "XMM Argument %d uninitialized for call at addr 0x%lx\n", arg, pc);

    //add callstack

    print_callstack(pc);

    stop_execution();
}

void msan_giovese_report_reg(uintptr_t pc, int reg, int xmm){

    //if the loader does something bad, it is not our concern
    if(!msan_giovese_check_callstack(pc))
        return;

    if(!xmm)
        fprintf(stderr, "Use of tainted register %d at address 0x%lx\n", reg, pc);
    else
        fprintf(stderr, "Use of tainted XMM register %d at address 0x%lx\n", reg, pc);

    //add callstack

    print_callstack(pc);

    stop_execution();
}

void msan_giovese_report_tmp(uintptr_t pc){

    //if the loader does something bad, it is not our concern
    if(!msan_giovese_check_callstack(pc))
        return;

    fprintf(stderr, "Use of tainted pointer at address 0x%lx\n", pc);

    //add callstack

    print_callstack(pc);

    stop_execution();
}

void msan_giovese_report_flags(uintptr_t pc){

    //if the loader does something bad, it is not our concern
    if(!msan_giovese_check_callstack(pc))
        return;

    if(pc>=app_start && pc <= app_end)
        fprintf(stderr, "Use of tainted flag register at address 0x%lx\n", pc-load_addr);
    else
        fprintf(stderr, "Use of tainted flag register at address 0x%lx\n", pc);

    //add callstack

    print_callstack(pc);

    stop_execution();
}

void msan_giovese_report_syscall(uintptr_t pc, uint32_t sysnum, uint32_t regnum){

    //if the loader does something bad, it is not our concern
    if(!msan_giovese_check_callstack(pc))
        return;

    fprintf(stderr, "Use of tainted register %u for syscall num %u"
                    " at address 0x%lx\n", regnum, sysnum, pc);

    //add callstack

    print_callstack(pc);

    stop_execution();
}


/*================================
  |    shadow mem management     |
  ================================
load, store, zeroing, propagation*/

uint8_t msan_giovese_load1(uintptr_t ptr) {
    MSAN_DEBUG_INFO(MSAN_INFO "Loading 1 from addr %lx\n", ptr);
    uintptr_t temp_ptr = ptr;
    uintptr_t h = G2S(temp_ptr);
    uint8_t res = * ((uint8_t*)h);
    MSAN_DEBUG_INFO(MSAN_INFO "res=%hhx\n", res);

#ifdef MSAN_ALL_INIT
    return 0;
#endif

#ifdef MSAN_TAINT_ANALYSIS
    if(((~res & MSAN_8)!=0) && msan_giovese_check_addr(ptr))
        return res;
    else
        return MSAN_8;
#else
    return ((~res & MSAN_8)!=0) && msan_giovese_check_addr(ptr);
#endif
}

uint16_t msan_giovese_load2(uintptr_t ptr) {
    MSAN_DEBUG_INFO(MSAN_INFO "Loading 2 from addr %lx\n", ptr);
    uintptr_t temp_ptr = ptr;
    uintptr_t h = G2S(temp_ptr);
    uint16_t res = * ((uint16_t*)h);

#ifdef MSAN_ALL_INIT
    return 0;
#endif

#ifdef MSAN_TAINT_ANALYSIS
    if(((~res & MSAN_16)!=0) && msan_giovese_check_addr(ptr))
        return res;
    else
        return MSAN_16;
#else
    return ((~res & MSAN_16)!=0) && msan_giovese_check_addr(ptr);
#endif
}

uint32_t msan_giovese_load4(uintptr_t ptr) {
MSAN_DEBUG_INFO(MSAN_INFO "Loading 4 from addr %lx\n", ptr);
    uintptr_t temp_ptr = ptr;
    uintptr_t h = G2S(temp_ptr);
    uint32_t res = * ((uint32_t*)h);

#ifdef MSAN_ALL_INIT
    return 0;
#endif

#ifdef MSAN_TAINT_ANALYSIS
    if(((~res & MSAN_32)!=0) && msan_giovese_check_addr(ptr))
        return res;
    else
        return MSAN_32;
#else
    return ((~res & MSAN_32)!=0) && msan_giovese_check_addr(ptr);
#endif
}

uint64_t msan_giovese_load8(uintptr_t ptr) {
MSAN_DEBUG_INFO(MSAN_INFO "Loading 8 from addr %lx\n", ptr);
    uintptr_t temp_ptr = ptr;
    uintptr_t h = G2S(temp_ptr);
    uint64_t res = * ((uint64_t*)h);

#ifdef MSAN_ALL_INIT
    return 0;
#endif

#ifdef MSAN_TAINT_ANALYSIS
    if(((~res & MSAN_64)!=0) && msan_giovese_check_addr(ptr))
        return res;
    else
        return MSAN_64;
#else
    return ((~res & MSAN_64)!=0) && msan_giovese_check_addr(ptr);
#endif
}


int msan_giovese_loadN(uintptr_t ptr, int length) {
MSAN_DEBUG_INFO(MSAN_INFO "LoadingN %d from addr %lx\n", length, ptr);
    uintptr_t temp_ptr = ptr;  
    uintptr_t h = G2S(temp_ptr);
    //uint64_t res = * ((uint64_t*)h);

#ifdef MSAN_ALL_INIT
    return 0;
#endif

    int count;
    for(count=0; count<(length/8)*8; count+=8){
        uint64_t res = * ((uint64_t*)(h + count));
        if ((~res) && msan_giovese_check_addr(ptr + count))
            return 1;
    }
    
    for(; count<length; count++){
        uint8_t res = * ((uint8_t*)(h + count));
        if ((!res) && msan_giovese_check_addr(ptr + count))
            return 1;
    }  
    return 0;
}

int msan_giovese_store1(uintptr_t ptr) {
MSAN_DEBUG_INFO(MSAN_INFO "Storing 1 in addr %lx\n", ptr);
    uintptr_t h = G2S(ptr);
    *((uint8_t*)h) = MSAN_8;

    if(msan_giovese_check_addr_stack(ptr) && ptr < last)
        last = ptr;

    return 0;

}

int msan_giovese_store2(uintptr_t ptr) {
MSAN_DEBUG_INFO(MSAN_INFO "Storing 2 in addr %lx\n", ptr);
    uintptr_t h = G2S(ptr);
    *((uint16_t*)h) = MSAN_16;

    if(msan_giovese_check_addr_stack(ptr) && ptr < last)
        last = ptr;
        
    return 0;
}

int msan_giovese_store4(uintptr_t ptr) {
MSAN_DEBUG_INFO(MSAN_INFO "Storing 4 in addr %lx\n", ptr);
    uintptr_t h = G2S(ptr);
    *((uint32_t*)h) = MSAN_32;

    if(msan_giovese_check_addr_stack(ptr) && ptr < last)
        last = ptr;
        
    return 0;

}

int msan_giovese_store8(uintptr_t ptr) {
MSAN_DEBUG_INFO(MSAN_INFO "Storing 8 in addr %lx\n", ptr);
    uintptr_t h = G2S(ptr);
    *((uint64_t*)h) = MSAN_64;

    if(msan_giovese_check_addr_stack(ptr) && ptr < last)
        last = ptr;

    return 0;

}

int msan_giovese_storeN(uintptr_t ptr, int length) {
MSAN_DEBUG_INFO(MSAN_INFO "StoringN %d in addr %lx\n", length, ptr);
    //FIXME: storen is called also before the map is initialized
    //      this is a quick workaround, consider fixing this decently
    if(!_sp)
        return 0;
    uintptr_t h = G2S(ptr);
    int count;
    for(count=0; count<(length/8)*8; count+=8)
        *((uint64_t*)(h + count)) = MSAN_64;
    
    for(;count<length; count++)
        *((uint8_t*)(h + count)) = MSAN_8;

    if(msan_giovese_check_addr_stack(ptr) && ptr < last)
        last = ptr;
        
    return 0;

}


int msan_giovese_zeroN(uintptr_t ptr, int length) {
MSAN_DEBUG_INFO(MSAN_INFO "ZeroingN %d in addr %lx\n", length, ptr);
    uintptr_t h = G2S(ptr);
    int count;
    for(count=0; count<(length/8)*8; count+=8)
        *((uint64_t*)(h + count)) = 0;
    
    for(;count<length; count++)
        *((uint8_t*)(h + count)) = 0;
        
    return 0;

}

void msan_giovese_propagate(uintptr_t dst, uintptr_t src, int len){
    uint8_t *d = (uint8_t*) G2S(dst);
    uint8_t *s = (uint8_t*) G2S(src);
MSAN_DEBUG_INFO(MSAN_INFO "Propagating (0x%lx-0x%lx) -> (0x%lx-0x%lx) len = %d\n", dst, src, d, s, len);
    if(!msan_giovese_check_addr(src)){
        msan_giovese_storeN(dst, len);
        return;
    }
    memcpy(d, s, len);
}

void msan_propagate_xmm(uintptr_t dst, int num, uint32_t dim){
    uint64_t *d = (uint64_t*) G2S(dst);
    MSAN_DEBUG_INFO(MSAN_INFO "Propagating xmm %d [%lx-%lx] to %p dim %u\n", num, xmm[2 * num], xmm[2 * num + 1], d, dim);
    switch (dim)
    {
    case 8:
        d[0] = xmm[2 * num];        
        break;
    
    case 16:
        d[0] = xmm[2 * num];
        d[1] = xmm[2 * num + 1];
        break;
    
    default:
        MSAN_DEBUG_INFO(MSAN_INFO "mmmmh, this should not be possible...\n");
        d[0] = xmm[2 * num];
        d[1] = xmm[2 * num + 1];
    break;
    }

}

void msan_propagate_to_xmm(int num, uintptr_t src){
    uint64_t *d = (uint64_t*) G2S(src);
    MSAN_DEBUG_INFO(MSAN_INFO "Propagating src %p to %d\n", d, num);
    xmm[2 * num] = d[0];
    xmm[2 * num + 1] = d[1];
    MSAN_DEBUG_INFO(MSAN_INFO "New value for %d: %.16lx %.16lx\n", num, xmm[2 * num], xmm[2 * num + 1]);

}

void msan_giovese_set_mem_to_regval(uintptr_t dst, unsigned long val, uint32_t len){
    uint64_t* d = (uint64_t*) G2S(dst);
    switch(len){
      case 1:
        *((uint8_t*)d) = (uint8_t) (val & MSAN_8);
      break;
      case 2:
        *((uint16_t*)d) = (uint8_t) (val & MSAN_16);
      break;
      case 4:
        *((uint32_t*)d) = (uint32_t) (val & MSAN_32);
      break;
      case 8:
        *d = (uint64_t) (val & MSAN_64);
      break;
    }
}

/*================================
  |      call/ret tracking       |
  ================================*/

void msan_giovese_call(){
    MSAN_FUN_INFO(MSAN_INFO "Calling, sp = 0x%lx\n", _sp);
    if(_sp>last && last){
        MSAN_STACK_INFO(MSAN_INFO "[call]zero from %lx, to %lx size: %lx\n", last, _sp, _sp-last );
        memset((void*) (G2S(last)), 0, (_sp - last));
    }
    last = _sp;
}

void msan_giovese_ret(){
    MSAN_FUN_INFO(MSAN_INFO "Returning, sp = 0x%lx\n", _sp);
    if(_sp - 8>last && last){
        MSAN_STACK_INFO(MSAN_INFO "[ret] zero from %lx, to %lx size: %lx\n", last, _sp - 8, _sp - 8 -last );
        memset((void*) (G2S(last)), 0, (_sp - 8 - last));
    }
    last = _sp;
}

/*================================
  |    stack pointer tracking     |
  ================================*/

void msan_giovese_set_sp(uintptr_t sp){
    _sp = sp;
    if(_sp>last && last){
        //MSAN_STACK_INFO(MSAN_INFO "[%d-set sp]zero from %lx, to %lx size: %lx\n", gettid(), last, _sp, _sp-last );
        MSAN_STACK_INFO(MSAN_INFO "[-set sp]zero from %lx, to %lx size: %lx\n"/*, gettid()*/, last, _sp, _sp-last );
        memset((void*) (G2S(last)), 0, (_sp - last));
    }
    last = _sp;
}

void msan_compare_sp(uintptr_t sp){
    if(sp != _sp && _sp){           //new thread ==> _sp == 0
        MSAN_PRINT(MSAN_INFO "sp = 0x%lx, _sp = 0x%lx\n", sp, _sp);
        MSAN_PRINT(MSAN_INFO "start = 0x%lx end = 0x%lx\n", app_start, app_end);
        //exit(1);
    }
}

/*================================
  |      tainting helpers        |
  ================================*/

void msan_taint_tmp(int tmp, unsigned long val){
    temp_regs[tmp] = val;
}

void msan_restore_tmp(int tmp){
    temp_regs[tmp] = MSAN_64;
}

unsigned long msan_check_tmp(int tmp){
    return temp_regs[tmp];
}

void msan_taint_reg(int reg, unsigned long val){
    regs[reg] = val;
}

void msan_restore_reg(int reg){
    regs[reg] = MSAN_64;
}

unsigned long msan_check_reg(int reg){
    return regs[reg];
}

void msan_taint_xmm(int num){
    xmm[2 * num] = 0;
    xmm[2 * num + 1] = 0;
}

void msan_taint_xmm_size(int num, uint32_t size){
    switch (size)
    {
    case 16:
        xmm[2 * num] &= 0xffffffffffff0000;
        break;

    case 32:
        xmm[2 * num] &= 0xffffffff00000000;
        break;

    case 64:
        xmm[2 * num] = (unsigned long) 0 ;
        break;

    case 128:
        xmm[2 * num] = (unsigned long) 0 ;
        xmm[2 * num + 1] = (unsigned long) 0 ;
        break;
    }     
}

void msan_restore_xmm(int num){
    xmm[2 * num] = MSAN_64;
    xmm[2 * num + 1] = MSAN_64;
}

void msan_restore_xmm_partial(int num, uint32_t size){
    switch (size)
    {
    case 16:
        xmm[2 * num] |= MSAN_16;
        break;

    case 32:
        xmm[2 * num] |= MSAN_32;
        break;

    case 64:
        xmm[2 * num] |= MSAN_64;
        break;

    case 128:
        xmm[2 * num] |= MSAN_64;
        xmm[2 * num + 1] |= MSAN_64;
        break;
    }    
}

unsigned long msan_check_xmm(int num){
    MSAN_TAINT_PRINT(pc, MSAN_INFO " xmm[%d] = %lx %lx\n", num, xmm[num], xmm[2 * num + 1]);
    return (xmm[2 * num] == MSAN_64) && (xmm[2 * num + 1] == MSAN_64);
}

unsigned long msan_check_xmm_size(int num, uint32_t size){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[%u] xmm[%d] = %lx %lx\n",size, num, xmm[2 * num], xmm[2 * num + 1]);
    switch (size)
    {
    case 32:
        return ((xmm[2 * num] & MSAN_32) == MSAN_32);
        break;

    case 64:
        return (xmm[2 * num] == MSAN_64);
        break;

    case 128:
        return (xmm[2 * num] == MSAN_64) && (xmm[2 * num + 1] == MSAN_64);
        break;
    
    default:
        fprintf(stderr, "[QMSAN] unknown xmm size %u.", size);
        return 1;
    }   
}

void msan_taint_flags(){
    flags = 1;
}

void msan_restore_flags(){
    flags = 0;
}

int msan_check_flags(){
    return flags;
}

uintptr_t get_sp(){
    return _sp;
}