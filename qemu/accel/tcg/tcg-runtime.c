/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu/host-utils.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "exec/exec-all.h"
#include "exec/tb-lookup.h"
#include "disas/disas.h"
#include "exec/log.h"

/* 32-bit helpers */

int32_t HELPER(div_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 / arg2;
}

int32_t HELPER(rem_i32)(int32_t arg1, int32_t arg2)
{
    return arg1 % arg2;
}

uint32_t HELPER(divu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 / arg2;
}

uint32_t HELPER(remu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 % arg2;
}

/* 64-bit helpers */

uint64_t HELPER(shl_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 << arg2;
}

uint64_t HELPER(shr_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(sar_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 >> arg2;
}

int64_t HELPER(div_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 / arg2;
}

int64_t HELPER(rem_i64)(int64_t arg1, int64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(divu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 / arg2;
}

uint64_t HELPER(remu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 % arg2;
}

uint64_t HELPER(muluh_i64)(uint64_t arg1, uint64_t arg2)
{
    uint64_t l, h;
    mulu64(&l, &h, arg1, arg2);
    return h;
}

int64_t HELPER(mulsh_i64)(int64_t arg1, int64_t arg2)
{
    uint64_t l, h;
    muls64(&l, &h, arg1, arg2);
    return h;
}

uint32_t HELPER(clz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? clz32(arg) : zero_val;
}

uint32_t HELPER(ctz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? ctz32(arg) : zero_val;
}

uint64_t HELPER(clz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? clz64(arg) : zero_val;
}

uint64_t HELPER(ctz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? ctz64(arg) : zero_val;
}

uint32_t HELPER(clrsb_i32)(uint32_t arg)
{
    return clrsb32(arg);
}

uint64_t HELPER(clrsb_i64)(uint64_t arg)
{
    return clrsb64(arg);
}

uint32_t HELPER(ctpop_i32)(uint32_t arg)
{
    return ctpop32(arg);
}

uint64_t HELPER(ctpop_i64)(uint64_t arg)
{
    return ctpop64(arg);
}

void *HELPER(lookup_tb_ptr)(CPUArchState *env)
{
    CPUState *cpu = ENV_GET_CPU(env);
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, curr_cflags());
    if (tb == NULL) {
        return tcg_ctx->code_gen_epilogue;
    }
    qemu_log_mask_and_addr(CPU_LOG_EXEC, pc,
                           "Chain %d: %p ["
                           TARGET_FMT_lx "/" TARGET_FMT_lx "/%#x] %s\n",
                           cpu->cpu_index, tb->tc.ptr, cs_base, pc, flags,
                           lookup_symbol(pc));
    return tb->tc.ptr;
}

void HELPER(exit_atomic)(CPUArchState *env)
{
    cpu_loop_exit_atomic(ENV_GET_CPU(env), GETPC());
}

/////////////////////////////////////////////////
//                   QASAN
/////////////////////////////////////////////////

#include "qasan-qemu.h"

// options
int qasan_max_call_stack = 32; // QASAN_MAX_CALL_STACK
int qasan_symbolize = 1; // QASAN_SYMBOLIZE

__thread int qmsan_start = 0;
uint64_t qmsan_ptr_main = 0;

#ifndef CONFIG_USER_ONLY

__thread CPUState* qasan_cpu;
#define g2h(x) \
  ({ \
    void *_a; \
    if (!qasan_addr_to_host(qasan_cpu, (x), &_a)) {\
      /* fprintf(stderr, "QASan error: virtual address translation for %p failed!\n", (x)); */ \
      return 0;\
    } \
    _a; \
  })

// h2g must not be defined
// #define h2g(x) (x)

#endif

int qasan_addr_to_host(CPUState* cpu, target_ulong addr, void** host_addr);

int __qasan_debug;
__thread int qasan_disabled;

__thread struct shadow_stack qasan_shadow_stack;

#ifdef MSAN_GIOVESE
#include "../../msan-giovese/msan-giovese-inl.h"
#endif

#ifdef ASAN_GIOVESE

#include "../../asan-giovese/interval-tree/rbtree.c"
#include "../../asan-giovese/asan-giovese-inl.h"

#include <sys/types.h>
#include <sys/syscall.h>

void asan_giovese_populate_context(struct call_context* ctx, target_ulong pc) {

  ctx->size = MIN(qasan_shadow_stack.size, qasan_max_call_stack -1) +1;
  ctx->addresses = calloc(sizeof(void*), ctx->size);
  
#ifdef __NR_gettid
  ctx->tid = (uint32_t)syscall(__NR_gettid);
#else
  pthread_id_np_t tid;
  pthread_t self = pthread_self();
  pthread_getunique_np(&self, &tid);
  ctx->tid = (uint32_t)tid;
#endif

  ctx->addresses[0] = pc;
  
  if (qasan_shadow_stack.size <= 0) return; //can be negative when pop does not find nothing
  
  int i, j = 1;
  for (i = qasan_shadow_stack.first->index -1; i >= 0 && j < qasan_max_call_stack; --i)
    ctx->addresses[j++] = qasan_shadow_stack.first->buf[i].pc;

  struct shadow_stack_block* b = qasan_shadow_stack.first->next;
  while (b && j < qasan_max_call_stack) {
  
    for (i = SHADOW_BK_SIZE-1; i >= 0; --i)
      ctx->addresses[j++] = b->buf[i].pc;
  
  }

}

#ifdef CONFIG_USER_ONLY

static void addr2line_cmd(char* lib, uintptr_t off, char** function, char** line) {
  
  if (!qasan_symbolize) goto addr2line_cmd_skip;
  
  FILE *fp;

  size_t cmd_siz = 128 + strlen(lib);
  char* cmd = malloc(cmd_siz);
  snprintf(cmd, cmd_siz, "addr2line -f -e '%s' 0x%lx", lib, off);

  fp = popen(cmd, "r");
  free(cmd);
  
  if (fp == NULL) goto addr2line_cmd_skip;

  *function = malloc(PATH_MAX + 32);
  
  if (!fgets(*function, PATH_MAX + 32, fp) || !strncmp(*function, "??", 2)) {

    free(*function);
    *function = NULL;

  } else {

    size_t l = strlen(*function);
    if (l && (*function)[l-1] == '\n')
      (*function)[l-1] = 0;
      
  }
  
  *line = malloc(PATH_MAX + 32);
  
  if (!fgets(*line, PATH_MAX + 32, fp) || !strncmp(*line, "??:", 3) ||
      !strncmp(*line, ":?", 2)) {

    free(*line);
    *line = NULL;

  } else {

    size_t l = strlen(*line);
    if (l && (*line)[l-1] == '\n')
      (*line)[l-1] = 0;
      
  }
  
  pclose(fp);
  
  return;

addr2line_cmd_skip:
  *line = NULL;
  *function = NULL;
  
}

char* asan_giovese_printaddr(target_ulong guest_addr) {

  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen("/proc/self/maps", "r");
  if (fp == NULL)
      return NULL;
  
  uint64_t img_min = 0, img_max = 0;
  char img_path[512] = {0};

  while ((read = getline(&line, &len, fp)) != -1) {
  
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line, "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d"
                    " %512s", &min, &max, &flag_r, &flag_w, &flag_x,
                    &flag_p, &offset, &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11))
        continue;

    if (h2g_valid(min)) {

      int flags = page_get_flags(h2g(min));
      max = h2g_valid(max - 1) ? max : (uintptr_t)g2h(GUEST_ADDR_MAX) + 1;
      if (page_check_range(h2g(min), max - min, flags) == -1)
          continue;
      
      if (img_min && !strcmp(img_path, path)) {
        img_max = max;
      } else {
        img_min = min;
        img_max = max;
        strncpy(img_path, path, 512);
      }

      if (guest_addr >= h2g(min) && guest_addr < h2g(max - 1) + 1) {
      
        uintptr_t off = guest_addr - h2g(img_min);
      
        char* s;
        char * function = NULL;
        char * codeline = NULL;
        if (strlen(path)) {
          addr2line_cmd(path, off, &function, &codeline);
          if (!function)
            addr2line_cmd(path, guest_addr, &function, &codeline);
        }

        if (function) {
        
          if (codeline) {
          
            size_t l = strlen(function) + strlen(codeline) + 32;
            s = malloc(l);
            snprintf(s, l, " in %s %s", function, codeline);
            free(codeline);
            
          } else {

            size_t l = strlen(function) + strlen(path) + 32;
            s = malloc(l);
            snprintf(s, l, " in %s (%s+0x%lx)", function, path,
                     off);

          }
          
          free(function);
        
        } else {

          size_t l = strlen(path) + 32;
          s = malloc(l);
          snprintf(s, l, " (%s+0x%lx)", path, off);

        }

        free(line);
        fclose(fp);
        return s;
        
      }

    }

  }

  free(line);
  fclose(fp);

  return NULL;

}
#else
char* asan_giovese_printaddr(TARGET_ULONG guest_addr) {

  return NULL;

}
#endif

#endif

#ifdef MSAN_GIOVESE
uintptr_t msan_callstack;
#endif

#ifdef MSAN_GIOVESE

void sanitizer_check_callstack(target_ulong sp){


  struct shadow_stack_block* cur_bk = qasan_shadow_stack.first;
  if (unlikely(cur_bk == NULL)) return;

  //FIXME: we are assuming everything is in a single block
  //if(cur_bk->index>0)
  //  fprintf(stderr, "checking %d %p\n", cur_bk->index, sp);
  while(cur_bk->index>0 && sp > cur_bk->buf[cur_bk->index].sp){
    //fprintf(stderr, "\t%p\n", cur_bk->buf[cur_bk->index].sp);
    cur_bk->index--;
    qasan_shadow_stack.size--;
  }
  //if(cur_bk->index>0)
  //  fprintf(stderr, "size : %d\n", cur_bk->index);
  //exit(0);
}

#endif

void HELPER(qasan_shadow_stack_push)(target_ulong ptr, target_ulong sp) {

#if defined(TARGET_ARM)
  ptr &= ~1;
#endif

  if (unlikely(!qasan_shadow_stack.first)) {
    
    qasan_shadow_stack.first = malloc(sizeof(struct shadow_stack_block));
    qasan_shadow_stack.first->index = 0;
    qasan_shadow_stack.size = 0; // may be negative due to last pop
    qasan_shadow_stack.first->next = NULL;

  }
    
  qasan_shadow_stack.first->buf[qasan_shadow_stack.first->index++].pc = ptr;
  qasan_shadow_stack.first->buf[qasan_shadow_stack.first->index].sp = sp;
  qasan_shadow_stack.size++;

  if (qasan_shadow_stack.first->index >= SHADOW_BK_SIZE) {

      struct shadow_stack_block* ns = malloc(sizeof(struct shadow_stack_block));
      ns->next = qasan_shadow_stack.first;
      ns->index = 0;
      qasan_shadow_stack.first = ns;
  }
  #ifdef MSAN_GIOVESE
    msan_callstack ^= ptr;
    MSAN_STACK_INFO(MSAN_INFO "[%d]\tCall, pc:%p callstack:%lx\n",qasan_shadow_stack.size, ptr, msan_callstack);
  #endif

}

void HELPER(qasan_shadow_stack_pop)(target_ulong ptr, target_ulong sp) {

#if defined(TARGET_ARM)
  ptr &= ~1;
#endif

  struct shadow_stack_block* cur_bk = qasan_shadow_stack.first;
  if (unlikely(cur_bk == NULL)) return;

  if (cur_bk->index == 0) {

    struct shadow_stack_block* ns = cur_bk->next;
    if (!ns) return;
    if (ns->buf[ns->index -1].pc != ptr) return;

    free(cur_bk);
    qasan_shadow_stack.first = ns;
    ns->index--;

   } //else if (cur_bk->buf[cur_bk->index -1].pc == ptr) {
    
  //   cur_bk->index--;

  // } else return;

  //qasan_shadow_stack.size--;

  
  do {
      
      cur_bk->index--;
      qasan_shadow_stack.size--;
      #ifdef MSAN_GIOVESE
        msan_callstack ^= ptr;
        MSAN_STACK_INFO(MSAN_INFO "[%d]\tRet, pc:%p callstack:%lx\n",qasan_shadow_stack.size, ptr, msan_callstack);
      #endif
      
      if (cur_bk->index < 0) {
          
          struct shadow_stack_block* ns = cur_bk->next;
          free(cur_bk);
          cur_bk = ns;
          if (!cur_bk) break;
          cur_bk->index--;
      }
  
  } while(cur_bk->buf[cur_bk->index].pc != ptr);
  
  qasan_shadow_stack.first = cur_bk;
  

}


target_long qasan_actions_dispatcher(void *cpu_env,
                                     target_long action, target_long arg1,
                                     target_long arg2, target_long arg3) {

    CPUArchState *env = cpu_env;
#ifndef CONFIG_USER_ONLY
    qasan_cpu = ENV_GET_CPU(env);
#endif

    int ret;

    switch(action) {
#ifdef QASAN
#ifdef ASAN_GIOVESE
        case QASAN_ACTION_CHECK_LOAD:
        // fprintf(stderr, "CHECK LOAD: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
        if (asan_giovese_guest_loadN(arg1, arg2)) {
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, arg1, arg2, PC_GET(env), BP_GET(env), SP_GET(env));
        }
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        // fprintf(stderr, "CHECK STORE: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
        if (asan_giovese_guest_storeN(arg1, arg2)) {
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, arg1, arg2, PC_GET(env), BP_GET(env), SP_GET(env));
        }
        break;
        
        case QASAN_ACTION_POISON:
        // fprintf(stderr, "POISON: %p [%p] %ld %x\n", arg1, g2h(arg1), arg2, arg3);
        asan_giovese_poison_guest_region(arg1, arg2, arg3);
        break;
        
        case QASAN_ACTION_USER_POISON:
        //fprintf(stderr, "USER POISON: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
        asan_giovese_user_poison_guest_region(arg1, arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        //fprintf(stderr, "UNPOISON: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
        asan_giovese_unpoison_guest_region(arg1, arg2);
        break;
        
        case QASAN_ACTION_IS_POISON:
        return asan_giovese_guest_loadN(arg1, arg2);
        
        case QASAN_ACTION_ALLOC: {
          //fprintf(stderr, "ALLOC: %p - %p\n", arg1, arg2);
          struct call_context* ctx = calloc(sizeof(struct call_context), 1);
          asan_giovese_populate_context(ctx, PC_GET(env));
          asan_giovese_alloc_insert(arg1, arg2, ctx);
          break;
        }
        
        case QASAN_ACTION_DEALLOC: {
          //fprintf(stderr, "DEALLOC: %p\n", arg1);
          struct chunk_info* ckinfo = asan_giovese_alloc_search(arg1);
          if (ckinfo) {
            if (ckinfo->start != arg1)
              asan_giovese_badfree(arg1, PC_GET(env));
            ckinfo->free_ctx = calloc(sizeof(struct call_context), 1);
            asan_giovese_populate_context(ckinfo->free_ctx, PC_GET(env));
          } else {
            asan_giovese_badfree(arg1, PC_GET(env));
          }
#ifdef MSAN_GIOVESE
          msan_giovese_zeroN(ckinfo->start, ckinfo->end - ckinfo->start);
#endif
          break;
        }
#else
        case QASAN_ACTION_CHECK_LOAD:
        __asan_loadN(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        __asan_storeN(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_POISON:
        __asan_poison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_USER_POISON:
        __asan_poison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        __asan_unpoison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_IS_POISON:
        return __asan_region_is_poisoned(g2h(arg1), arg2) != NULL;
        
        case QASAN_ACTION_ALLOC:
          break;
        
        case QASAN_ACTION_DEALLOC:
          break;
#endif
#endif
        case QASAN_ACTION_ENABLE:
        qasan_disabled = 0;
        break;
        
        case QASAN_ACTION_DISABLE:
        qasan_disabled = 1;
        break;

        case QASAN_ACTION_SWAP_STATE: {
          int r = qasan_disabled;
          qasan_disabled = arg1;
          return r;
        }

#ifdef MSAN_GIOVESE
        //adding cases for QMSAN.

        case QMSAN_ACTION_SET_MAIN:
#ifdef MSAN_TAINT_ANALYSIS
          fprintf(stderr, "[QMSan]main at %lx\n", arg1 - load_addr);
#endif
          qmsan_start = 1;
          qmsan_ptr_main = (uint64_t) arg1;
#ifdef TARGET_ARM
        /* The least significant bit indicates Thumb mode. */
        qmsan_ptr_main = qmsan_ptr_main & ~(uint64_t)1;
#endif
#ifdef MSAN_DEBUG_PRINT
        if(!qmsan_start_addr)
          qmsan_start_addr = qmsan_ptr_main;
#endif
        char *dump = getenv("QMSAN_DUMP_MAPPINGS");

        //dump the mappings info
        if (dump) {
          char cmd[64];
          sprintf(cmd, "cat /proc/%d/maps", getpid());
          system(cmd);
        }
        break;

        case QMSAN_ACTION_MALLOC:
          //fprintf(stderr, "checking malloc %p\n", arg1);

          check_mmap_list(arg1);

        break;

        case QMSAN_ACTION_ENABLE:
          //fprintf(stderr, "enabling qmsan with %lx\n", (int) arg1);
          if((int) arg1)
            qmsan_start = 1;
        break;

        case QMSAN_ACTION_DEBUG:
          fprintf(stderr, "prummmmm \n");
        break;

        case QMSAN_ACTION_DISABLE:
          //fprintf(stderr, "disabling qmsan %d \n", qmsan_start);
          ret = qmsan_start;
          qmsan_start = 0;
          return ret;
        break;
        
        case QMSAN_ACTION_CHECK_LOAD:
        //  fprintf(stderr, "MSAN LOAD: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
          if(qmsan_start && msan_giovese_loadN(arg1, arg2))
            msan_giovese_report(arg1, arg2, arg3);
#ifdef QMSAN_FLAGGING
          //we executed a load instruction that had no previous error on this run
          //so we mark it as clean (so far).
          else
            msan_area_ptr[(PC_GET(env) - load_addr) % MAP_SIZE] |= QMSAN_AFL_CLEAN;
#endif
        break;

        case QMSAN_ACTION_CHECK_STORE:
        //  fprintf(stderr, "MSAN STORE: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
          msan_giovese_storeN(arg1, arg2);
        break;
  
        case QMSAN_ACTION_DEALLOC:
        //  fprintf(stderr, "MSAN DEALLOC: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
          msan_giovese_zeroN(arg1, arg2);
        break;
  
        case QMSAN_ACTION_CHECK_REG:
          if(~msan_check_reg(arg2)){
            msan_giovese_report_arg(arg1, (int) arg2, 0);
          }
        break;

        case QMSAN_ACTION_CHECK_XMM:
          if(!msan_check_xmm(arg2)){
            msan_giovese_report_arg(arg1, (int) arg2, 1);
          }
        break;

        case QMSAN_ACTION_PROPAGATE:
          //fprintf(stderr, "propagating from 0x%lx to 0x%lx len 0x%x\n", arg2, arg1, (int)arg3);
          msan_giovese_propagate((uintptr_t)arg1, (uintptr_t)arg2, (int)arg3);
        break;

        case QMSAN_ACTION_RESTORE_RETVAL:
          msan_restore_reg(0);
        break;

        case QMSAN_ACTION_THREAD:
          //MSAN_PRINT("Spawning new thread in %lx\n", (uintptr_t) arg1);
          qmsan_start = 1;
          //target_area = 1;
        break;

        case QMSAN_ACTION_SILENCE:
          //MSAN_PRINT("Silencing thread\n");
          target_area = 0;
        break;
#endif

        default:
        fprintf(stderr, "Invalid QASAN action %ld\n", action);
        abort();
    }

    return 0;
}

void* HELPER(qasan_fake_instr)(CPUArchState *env, void* action, void* arg1,
                               void* arg2, void* arg3) {

  return (void*)qasan_actions_dispatcher(env,
                                         (target_long)action, (target_long)arg1,
                                         (target_long)arg2, (target_long)arg3);

}

#ifndef CONFIG_USER_ONLY

//----------------------------------
// Full system helpers for TLB walk
//----------------------------------

/* Macro to call the above, with local variables from the use context.  */
#define VICTIM_TLB_HIT(TY, ADDR) \
  victim_tlb_hit(env, mmu_idx, index, offsetof(CPUTLBEntry, TY), \
                 (ADDR) & TARGET_PAGE_MASK)

bool victim_tlb_hit(CPUArchState *env, size_t mmu_idx, size_t index,
                           size_t elt_ofs, target_ulong page);

void qasan_page_loadN(CPUArchState *env, target_ulong addr, size_t size, uintptr_t mmu_idx)
{
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;
    
    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_loadN((void*)haddr, size)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, size, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_loadN((void*)haddr, size);
#endif
}

void qasan_page_storeN(CPUArchState *env, target_ulong addr, size_t size, uintptr_t mmu_idx)
{
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;
    
    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_storeN((void*)haddr, size)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, size, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_storeN((void*)haddr, size);
#endif
}

void HELPER(qasan_load1)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_load1((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 1, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_load1((void*)haddr);
#endif
}

void HELPER(qasan_load2)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK) + 2 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(2 - 1);
        addr2 = addr1 + 2;
        
        size_t span = addr2 - addr;
        haddr = addr + entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_loadN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_loadN((void*)haddr, span);
#endif
        
        qasan_page_loadN(env, addr2, 2 - span, mmu_idx);
        return;
    }

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_load2((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 2, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_load2((void*)haddr);
#endif
}

void HELPER(qasan_load4)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;

    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;
    
    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK) + 4 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(4 - 1);
        addr2 = addr1 + 4;
        
        size_t span = addr2 - addr;
        haddr = addr + entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_loadN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_loadN((void*)haddr, span);
#endif
        
        qasan_page_loadN(env, addr2, 4 - span, mmu_idx);
        return;
    }

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_load4((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 4, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_load4((void*)haddr);
#endif
}

void HELPER(qasan_load8)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;

    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK) + 8 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(8 - 1);
        addr2 = addr1 + 8;
        
        size_t span = addr2 - addr;
        haddr = addr + entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_loadN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_loadN((void*)haddr, span);
#endif
        
        qasan_page_loadN(env, addr2, 8 - span, mmu_idx);
        return;
    }

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_load8((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 8, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_load8((void*)haddr);
#endif
}

void HELPER(qasan_store1)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_store1((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 1, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_store1((void*)haddr);
#endif
}

void HELPER(qasan_store2)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK) + 2 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(2 - 1);
        addr2 = addr1 + 2;
        
        size_t span = addr2 - addr;
        haddr = addr + entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_storeN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_storeN((void*)haddr, span);
#endif
        
        qasan_page_storeN(env, addr2, 2 - span, mmu_idx);
        return;
    }

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_store2((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 2, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_store2((void*)haddr);
#endif
}

void HELPER(qasan_store4)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK) + 4 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(4 - 1);
        addr2 = addr1 + 4;
        
        size_t span = addr2 - addr;
        haddr = addr + entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_storeN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_storeN((void*)haddr, span);
#endif
        
        qasan_page_storeN(env, addr2, 4 - span, mmu_idx);
        return;
    }

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_store4((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 4, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_store4((void*)haddr);
#endif
}

void HELPER(qasan_store8)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK) + 8 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(8 - 1);
        addr2 = addr1 + 8;
        
        size_t span = addr2 - addr;
        haddr = addr + entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_storeN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_storeN((void*)haddr, span);
#endif
        
        qasan_page_storeN(env, addr2, 8 - span, mmu_idx);
        return;
    }

    haddr = addr + entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_store8((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 8, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_store8((void*)haddr);
#endif
}

#else

//----------------------------------
// Usermode helpers
//----------------------------------

void HELPER(qasan_load1)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef QASAN
#ifdef ASAN_GIOVESE
  if (asan_giovese_load1(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 1, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_load1(ptr);
#endif
#endif

}

void HELPER(qasan_load2)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;

  void* ptr = (void*)g2h(addr);

#ifdef QASAN
#ifdef ASAN_GIOVESE
  if (asan_giovese_load2(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 2, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_load2(ptr);
#endif
#endif

}

void HELPER(qasan_load4)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef QASAN
#ifdef ASAN_GIOVESE
  if (asan_giovese_load4(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 4, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_load4(ptr);
#endif
#endif

}

void HELPER(qasan_load8)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef QASAN
#ifdef ASAN_GIOVESE
  if (asan_giovese_load8(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 8, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_load8(ptr);
#endif
#endif

}

void HELPER(qasan_store1)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef QASAN
#ifdef ASAN_GIOVESE
  if (asan_giovese_store1(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 1, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_store1(ptr);
#endif
#endif

}

void HELPER(qasan_store2)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);
  
#ifdef QASAN
#ifdef ASAN_GIOVESE
  if (asan_giovese_store2(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 2, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_store2(ptr);
#endif
#endif

}

void HELPER(qasan_store4)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef QASAN
#ifdef ASAN_GIOVESE
  if (asan_giovese_store4(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 4, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_store4(ptr);
#endif
#endif

}

void HELPER(qasan_store8)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;

  void* ptr = (void*)g2h(addr);

#ifdef QASAN
#ifdef ASAN_GIOVESE
  if (asan_giovese_store8(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 8, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_store8(ptr);
#endif
#endif

}

#endif

#ifdef MSAN_GIOVESE

#define nBITS(size)                 (size == 3 ? MSAN_64 : ((1L << ((1L << size) * 8)) -1L))
#define PROPAGATE_REG(r, v, sz)     ((size >= 2 ? MSAN_64 & ~ nBITS(sz) : msan_check_reg(r) & ~ nBITS(sz)) | (v & nBITS(sz)))
#define PROPAGATE_TMP(r, v, sz)     ((size >= 2 ? MSAN_64 & ~ nBITS(sz) : msan_check_tmp(r) & ~ nBITS(sz)) | (v & nBITS(sz)))

/*================================
  |        store helpers         |
  ================================*/
void HELPER(qmsan_store1)(CPUArchState *env, target_ulong addr) {

  uintptr_t ptr = (uintptr_t)g2h(addr);

  msan_giovese_store1(ptr);

}

void HELPER(qmsan_store2)(CPUArchState *env, target_ulong addr) {

  uintptr_t ptr = (uintptr_t)g2h(addr);

  msan_giovese_store2(ptr);

}

void HELPER(qmsan_store4)(CPUArchState *env, target_ulong addr) {

  uintptr_t ptr = (uintptr_t)g2h(addr);

  msan_giovese_store4(ptr);

}

void HELPER(qmsan_store8)(CPUArchState *env, target_ulong addr) {

  uintptr_t ptr = (uintptr_t)g2h(addr);

  msan_giovese_store8(ptr);

}

/*================================
  |         load helpers         |
  ================================*/
void HELPER(qmsan_load1)(CPUArchState *env, target_ulong pc, target_ulong addr) {

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if ( msan_giovese_load1(ptr))
    msan_giovese_report(ptr, 1, pc);
#ifdef QMSAN_FLAGGING
  //we executed a load instruction that had no previous error on this run
  //so we mark it as clean (so far).
  else
    msan_area_ptr[(pc - load_addr) % MAP_SIZE] |= QMSAN_AFL_CLEAN;
#endif

}

void HELPER(qmsan_load2)(CPUArchState *env, target_ulong pc, target_ulong addr) {

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if ( msan_giovese_load2(ptr))
    msan_giovese_report(ptr, 2, pc);
#ifdef QMSAN_FLAGGING
  //we executed a load instruction that had no previous error on this run
  //so we mark it as clean (so far).
  else
    msan_area_ptr[(pc - load_addr) % MAP_SIZE] |= QMSAN_AFL_CLEAN;
#endif

}

void HELPER(qmsan_load4)(CPUArchState *env, target_ulong pc, target_ulong addr) {

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if ( msan_giovese_load4(ptr))
    msan_giovese_report(ptr, 4, pc);
#ifdef QMSAN_FLAGGING
  //we executed a load instruction that had no previous error on this run
  //so we mark it as clean (so far).
  else
    msan_area_ptr[(pc - load_addr) % MAP_SIZE] |= QMSAN_AFL_CLEAN;
#endif

}

void HELPER(qmsan_load8)(CPUArchState *env, target_ulong pc, target_ulong addr) {

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if ( msan_giovese_load8(ptr))
    msan_giovese_report(ptr, 8, pc);
#ifdef QMSAN_FLAGGING
  //we executed a load instruction that had no previous error on this run
  //so we mark it as clean (so far).
  else
    msan_area_ptr[(pc - load_addr) % MAP_SIZE] |= QMSAN_AFL_CLEAN;
#endif

}

/*================================
  |         load helpers         |
  ================================*/
#ifdef MSAN_TEST_LOAD
void HELPER(qmsan_load_log)(CPUArchState *env, target_ulong pc, target_ulong addr) {

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if(pc >= app_start && pc < app_end){
    fprintf(stderr, "LOAD 0x%lx 0x%lx\n", pc-load_addr, addr);
  }
  else{
    fprintf(stderr, "LOAD 0x%lx 0x%lx\n", pc, addr);
  }

}
#endif

#ifdef MSAN_TEST_STORE
void HELPER(qmsan_store_log)(CPUArchState *env, target_ulong pc, target_ulong addr) {

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if(pc >= app_start && pc < app_end){
    fprintf(stderr, "STORE 0x%lx 0x%lx\n", pc-load_addr, addr);
  }
  else{
    fprintf(stderr, "STORE 0x%lx 0x%lx\n", pc, addr);
  }

}
#endif
/*================================
  |    stack pointer helpers     |
  ================================*/

void HELPER(qmsan_set_sp)(target_ulong sp) {

  MSAN_STACK_INFO(MSAN_INFO "manually setting the sp to 0x%lx\n", sp);
#ifdef MSAN_TAINT_ANALYSIS
  sanitizer_check_callstack(sp);
#endif
  msan_giovese_set_sp(sp);  
}

/*================================
  |      call/ret helpers        |
  ================================*/

void HELPER(qmsan_call)(target_ulong sp) {
  if(unlikely(!get_sp()))
    msan_giovese_set_sp(sp); 

  msan_giovese_call();
#ifdef TARGET_x86_64
  msan_giovese_store8((uintptr_t) sp - 8);
#endif
  //comment
  msan_compare_sp(sp);

}

void HELPER(qmsan_ret)(target_ulong sp) {
  if(unlikely(!get_sp()))
    msan_giovese_set_sp(sp); 

  msan_giovese_ret();

}

//check if we are returning from library to code, in such case update sp
void  HELPER(qmsan_check_ret_from_lib)(uint64_t target, target_ulong sp){
  
  CHECK_BOUNDARIES_IF(target){
  MSAN_STACK_INFO(MSAN_INFO "[ret-from-lib]manually setting the sp to 0x%lx\n", sp);
    msan_giovese_set_sp(sp); 
  }

}

//check if we are calling from library to code, in such case update sp (-8 because of the push)
void  HELPER(qmsan_check_call_from_lib)(uint64_t target, target_ulong sp){
  
  CHECK_BOUNDARIES_IF(target){
#ifdef MSAN_LIGHT_NO_LIB
    MSAN_STACK_INFO(MSAN_INFO "[call-from-lib]manually setting the sp to 0x%lx\n", sp);
    msan_giovese_set_sp(sp);
#else
    MSAN_STACK_INFO(MSAN_INFO "[call-from-lib-nl]manually setting the sp to 0x%lx\n", sp );
    msan_giovese_set_sp(sp);
    msan_giovese_store8(sp);
#endif
  }

}

/*================================
  |        debug helpers         |
  ================================*/

void HELPER(qmsan_debug_print_instr)(uint64_t addr) {
  instr_counter++;
  if(addr == qmsan_start_addr){
    MSAN_PRINT("Switching on debug info at 0x%lx\n", addr);
    target_area = 1;
  }
  else if(addr == qmsan_end_addr){
    MSAN_PRINT("Switching off debug info at 0x%lx\n", addr);
    target_area = 0;
  }
  if(addr >= app_start && addr < app_end){
    MSAN_INSTR_INFO(MSAN_INS "addr = 0x%lx (main module + 0x%lx)\n", addr, addr - load_addr);
  }
  else{
    MSAN_INSTR_INFO(MSAN_INS "addr = 0x%lx\n", addr);
  }
}

void HELPER(qmsan_debug_print_sp)(uint64_t sp) {

  MSAN_INSTR_INFO(MSAN_INFO "real sp = 0x%lx\n", sp);
  msan_compare_sp(sp);
}

void HELPER(qmsan_main)() {

  fprintf(stderr, "main function called!\n");
  main_called = 1;
}


/*================================
  |      tainting helpers        |
  ================================*/

uint64_t t0;
int target_reg;
unsigned long saved_reg_taint;

void HELPER(qmsan_save_t0)(uint64_t pc, uint64_t val, uint32_t reg){
  t0 = val;
  target_reg = reg;
  saved_reg_taint = msan_check_reg(reg);
}

void HELPER(qmsan_check_t0)(uint64_t pc, uint64_t val){
  if(val==t0)       //we indeed loaded from memory, keep the taint
    return;
  
  //else, we did not load from memory, but we kept the content of reg
  MSAN_TAINT_PRINT(pc, MSAN_INFO "resetting the content of reg %d with previous value 0x%lx\n", target_reg, saved_reg_taint);
  msan_taint_reg(target_reg, saved_reg_taint);

}


void HELPER(qmsan_check_taint_reg_tmp)(uint64_t pc, uint32_t reg,
            uint32_t temp, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to reg %d from tmp %d"
                  " of size %u\n", reg, temp, size);

  if(~msan_check_tmp(temp) & nBITS(size)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rt]Tainting reg %u\n", reg);
    msan_taint_reg(reg, PROPAGATE_REG(reg, msan_check_tmp(temp), size));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg);
    msan_taint_reg(reg, PROPAGATE_REG(reg, MSAN_64, size));
  }

}


void HELPER(qmsan_check_taint_xmm_tmp)(uint64_t pc, uint32_t xmm, uint32_t tmp){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to xmm %d from tmp %d\n", xmm, tmp);

  if(~msan_check_tmp(tmp)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[t]Tainting xmm %u\n", xmm);
    msan_taint_xmm(xmm);
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u\n", xmm);
    msan_restore_xmm(xmm);
  }
}



void HELPER(qmsan_zero_N_if_taint_xmm)(uint64_t pc, target_ulong addr, uint32_t xmm, uint32_t dim){

  uintptr_t ptr = (uintptr_t)g2h(addr);


  if(msan_giovese_check_ld(pc))
    return;
  
  dim = 1 << dim;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[xmm] do I have to propagate xmm to memory %lx dim %d?\n", addr, dim);

  if(!msan_check_xmm(xmm)){
    //msan_giovese_zeroN(ptr, dim);
    msan_propagate_xmm(ptr, xmm, dim);
    MSAN_TAINT_PRINT(pc, MSAN_INFO "propagating xmm %u to %lx dim %d\n", xmm, addr, dim);
  }

}

void HELPER(qmsan_check_taint_reg_xmm)(uint64_t pc, uint32_t reg, uint32_t xmm){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to reg %d from xmm %d\n", reg, xmm);

  if(!msan_check_xmm(xmm)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[t]Tainting reg %u\n", reg);
    msan_taint_reg(reg, 0);
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg);
    msan_restore_reg(reg);
  }
}

void HELPER(qmsan_check_taint_xmm_xmm)(uint64_t pc, uint32_t xmm, uint32_t xmm2){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to xmm %d from xmm %d\n", xmm, xmm2);

  if(!msan_check_xmm(xmm2)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[xx]Tainting xmm %u\n", xmm);
    msan_taint_xmm(xmm);
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u\n", xmm);
    msan_restore_xmm(xmm);
  }

}

void HELPER(qmsan_check_taint_xmm_mem_l)(uint64_t pc, uint32_t xmm, target_ulong addr){

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint for xmm %u on addr %lx, 32 bit\n", xmm, addr);

  //fix the length
  if ( msan_giovese_loadN(ptr, 4)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "xmm [%u] is now tainted!\n", xmm);
    msan_taint_xmm(xmm);
  }
  
  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u\n", xmm);
    msan_restore_xmm(xmm);
  }

}

void HELPER(qmsan_check_taint_xmm_mem_d)(uint64_t pc, uint32_t xmm, target_ulong addr){

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint for xmm %u on addr %lx, 64 bit\n", xmm, addr);

  //fix the length
  if ( msan_giovese_loadN(ptr, 8)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "xmm [%u] is now tainted!\n", xmm);
    msan_taint_xmm(xmm);
  }
  
  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u\n", xmm);
    msan_restore_xmm(xmm);
  }

}

void HELPER(qmsan_check_taint_xmm_mem)(uint64_t pc, uint32_t xmm, target_ulong addr){

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint for xmm %u on addr %lx, 128 bit\n", xmm, addr);

  //fix the length
  if ( msan_giovese_loadN(ptr, 16)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "xmm [%u] is now tainted!\n", xmm);
    msan_propagate_to_xmm(xmm, ptr);
  }
  
  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u\n", xmm);
    msan_restore_xmm(xmm);
  }

}

void HELPER(qmsan_restore_xmm_partial)(uint64_t pc, uint32_t xmm, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
  size = 1 << size;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u's first %u bytes\n", xmm, size);
  msan_restore_xmm_partial(xmm, size);

}

void HELPER(qmsan_check_math_xmm_xmm)(uint64_t pc, uint32_t xmm1, uint32_t xmm2){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

//TODO: the policy right now is to set xmm to 0 if we have an out bound, but it needs to be changed
//      this can happen if rm in translate.c was not properly set but we are using it anyway
//      in such cases, we should manage it differently (i.e. check what is being used instead of rm)
  MSAN_TAINT_PRINT(pc, MSAN_INFO "Checking flags from xmm %u and xmm %u \n", xmm1, xmm2);
  if(xmm1 > 31 ){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "xmm1 out of range, %u \n", xmm1);
    xmm1 = 0;
  }

  if(xmm2 > 31 ){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "xmm2 out of range, %u \n", xmm2);
    xmm2 = 0;
  }
  
  if(!msan_check_xmm(xmm1) || !msan_check_xmm(xmm2)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction unreliable\n");
    msan_taint_flags();
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction okay\n");
    msan_restore_flags();
  }

}

void HELPER(qmsan_check_math_xmm_xmm_size)(uint64_t pc, uint32_t xmm1, uint32_t xmm2, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

//TODO: the policy right now is to set xmm to 0 if we have an out bound, but it needs to be changed
//      this can happen if rm in translate.c was not properly set but we are using it anyway
//      in such cases, we should manage it differently (i.e. check what is being used instead of rm)
  MSAN_TAINT_PRINT(pc, MSAN_INFO "Checking flags from xmm %u and xmm %u of size %u \n", xmm1, xmm2, size);
  if(xmm1 > 31 ){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "xmm1 out of range, %u \n", xmm1);
    xmm1 = 0;
  }

  if(xmm2 > 31 ){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "xmm2 out of range, %u \n", xmm2);
    xmm2 = 0;
  }
  size = 1 << size;
  if(!msan_check_xmm_size(xmm1, size) || !msan_check_xmm_size(xmm2, size)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction unreliable\n");
    msan_taint_flags();
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction okay\n");
    msan_restore_flags();
  }

}

void HELPER(qmsan_check_xmm_xmm_xmm_size)(uint64_t pc, uint32_t xmm1, uint32_t xmm2, uint32_t xmm3, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "Checking xmm %u from xmm %u and xmm %u of size %u \n", xmm1, xmm2, xmm3, size);
  size = 1 << size;
  if(!msan_check_xmm_size(xmm2, size) || !msan_check_xmm_size(xmm3, size)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[t]Tainting xmm %u size %u\n", xmm1, size);
    msan_taint_xmm_size(xmm1, size);
  }
  
  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u size %u\n", xmm1, size);
    msan_restore_xmm_partial(xmm1, size);
  }

}

void HELPER(qmsan_check_xmm_xmm_size)(uint64_t pc, uint32_t xmm1, uint32_t xmm2, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "Checking xmm %u from xmm %u of size %u \n", xmm1, xmm2,  size);
  size = 1 << size;
  if(!msan_check_xmm_size(xmm2, size)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[t]Tainting xmm %u size %u\n", xmm1, size);
    msan_taint_xmm_size(xmm1, size);
  }
  
  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u size %u\n", xmm1, size);
    msan_restore_xmm_partial(xmm1, size);
  }

}

void HELPER(qmsan_check_xmm_reg_size)(uint64_t pc, uint32_t xmm, uint32_t reg, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "Checking xmm %u from reg %u of size %u \n", xmm, reg,  size);
  size = 1 << size;
  unsigned long mask;
  switch (size){
    case 32:
      mask = MSAN_32;
    break;
    case 64:
      mask = MSAN_64;
    break;
    default:
      mask = MSAN_32;
      fprintf(stderr, "[QMSAN] unsupported size %u reg to xmm\n", size);
  }
  if(~msan_check_reg(reg)&mask){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[t]Tainting xmm %u size %u\n", xmm, size);
    msan_taint_xmm_size(xmm, size);
  }
  
  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring xmm %u size %u\n", xmm, size);
    msan_restore_xmm_partial(xmm, size);
  }

}

void HELPER(qmsan_check_taint_tmp_reg)(uint64_t pc, uint32_t temp, uint32_t reg, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to tmp %d from reg %d (%lx) "
                  "of size %u\n", temp, reg, msan_check_reg(reg), size);


  if(~msan_check_reg(reg) & nBITS(size)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Tainting tmp %u\n", temp);
    msan_taint_tmp(temp, msan_check_reg(reg));

  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[tr]restoring tmp %u\n", temp);
    msan_restore_tmp(temp);
  }

}

void HELPER(qmsan_check_taint_tmp_flag)(uint64_t pc, uint32_t temp){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to tmp %d from flags", temp);


  if(msan_check_flags()){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Tainting tmp %u\n", temp);
    msan_taint_tmp(temp, 0x0);

  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[tr]restoring tmp %u\n", temp);
    msan_restore_tmp(temp);
  }

}

void HELPER(qmsan_check_taint_tmp_tmp_reg)(uint64_t pc, uint32_t temp,
              uint32_t temp2, uint32_t reg, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to tmp %d from reg %d"
                  " and temp %d (%lx, %lx) of size %u\n", temp, reg, temp2,
                  msan_check_reg(reg), msan_check_tmp(temp2), size);

  if((~msan_check_reg(reg) | ~msan_check_tmp(temp2)) & nBITS(size)){
    msan_taint_tmp(temp, PROPAGATE_TMP(temp, msan_check_reg(reg) & msan_check_tmp(temp2), size));
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Tainting tmp %u (%lx)\n", temp, msan_check_tmp(temp));

  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[tr]restoring tmp %u\n", temp);
    msan_taint_tmp(temp, PROPAGATE_TMP(temp, MSAN_64, size));
    MSAN_TAINT_PRINT(pc, MSAN_INFO "tmp %u (%lx)\n", temp, msan_check_tmp(temp));
  }

}

void HELPER(qmsan_check_taint_tmp_tmp)(uint64_t pc, uint32_t temp, uint32_t temp2){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to tmp %d from tmp %d\n", temp, temp2);

  if(~msan_check_tmp(temp2)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Tainting tmp %u\n", temp);
    msan_taint_tmp(temp, msan_check_tmp(temp2));

  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[tt]restoring tmp %u\n", temp);
    msan_restore_tmp(temp);
  }

}

void HELPER(qmsan_check_taint_tmp_mem)(uint64_t pc, uint32_t temp, target_ulong addr, uint32_t dim){

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint for temp %u on addr %lx\n", temp, addr);
  MSAN_TAINT_PRINT(pc, MSAN_INFO "temp is now %d\n", msan_check_tmp(temp));
  unsigned long ret, mask;
  switch (dim){
    case 0:
      ret = (unsigned long) msan_giovese_load1(ptr);
      mask = MSAN_8;
    break;
    case 1:
      ret = (unsigned long) msan_giovese_load2(ptr);
      mask = MSAN_16;
    break;
    case 2:
      ret = (unsigned long) msan_giovese_load4(ptr);
      mask = MSAN_32;
    break;
    case 3:
      ret = (unsigned long) msan_giovese_load8(ptr);
      mask = MSAN_64;
    break;
    default:
      ret = (unsigned long) msan_giovese_load1(ptr);
      mask = MSAN_8;
  }
  if (~ret&mask ){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "temp [%u] is now tainted! (%lx), mask = %lx\n", temp, ret, mask);
    //keep the first bits unchanged and update the other ones
    msan_taint_tmp(temp, (msan_check_tmp(temp) & ~mask) | (ret & mask));
  }
  else
    msan_restore_tmp(temp);

}

void HELPER(qmsan_restore_temp)(uint64_t pc, uint32_t temp){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
    
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[-]restoring tmp %u\n", temp);
    msan_restore_tmp(temp);

}

void HELPER(qmsan_check_temp)(uint64_t pc, uint32_t temp){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
    
    MSAN_TAINT_PRINT(pc, MSAN_INFO "checking tmp %u\n", temp);
    if(~msan_check_tmp(temp))
      msan_giovese_report_tmp(pc);
}

void HELPER(qmsan_check_test)(uint64_t pc, uint32_t val0, uint32_t val1){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uint64_t res = ((~msan_check_tmp(0) & ~msan_check_tmp(1))
                  | (val0 & ~msan_check_tmp(1))
                  | (~msan_check_tmp(0) & val1));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[and] checking test instruction between "
                    "%u and %u, shadows = (%lx, %lx). ~res=%lx\n",
                    val0, val1, msan_check_tmp(0), msan_check_tmp(1), ~res);

  if(res){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Test instruction unreliable!!!\n");
    msan_taint_flags();
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Test instruction okay\n");
    msan_restore_flags();
  }

}

void HELPER(qmsan_check_math_reg_tmp_tmp)(uint64_t pc, uint32_t reg,
                      uint32_t temp1, uint32_t temp2, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
  if((~msan_check_tmp(temp1) || ~msan_check_tmp(temp2)) & nBITS(size)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction on reg unreliable\n");
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rtt]Tainting reg %u\n", reg);
    msan_taint_flags();
    msan_taint_reg(reg, PROPAGATE_REG(reg, msan_check_tmp(temp1) & msan_check_tmp(temp2), size));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction on reg okay\n");
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg);
    msan_restore_flags();
    msan_taint_reg(reg, PROPAGATE_REG(reg, MSAN_64, size));
  }

}

void HELPER(qmsan_check_math_tmp_tmp)(uint64_t pc, uint32_t temp1, uint32_t temp2){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction (tmp %u and tmp %u)\n",
                      temp1, temp2);

  if(~msan_check_tmp(temp1) || ~msan_check_tmp(temp2)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction unreliable\n");
    msan_taint_flags();
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction okay\n");
    msan_restore_flags();
  }

  msan_taint_tmp(temp1, msan_check_tmp(temp1) & msan_check_tmp(temp2));
  MSAN_TAINT_PRINT(pc, MSAN_INFO "Setting temp %u shadow to %lx\n", temp1,
                    msan_check_tmp(temp1));


}

void HELPER(qmsan_check_math_reg_reg_tmp)(uint64_t pc, uint32_t reg1,
              uint32_t reg2, uint32_t temp, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
  if((~msan_check_reg(reg2) || ~msan_check_tmp(temp)) & nBITS(size)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction on reg unreliable\n");
    MSAN_TAINT_PRINT(pc, MSAN_INFO "reg %u = %x\n", reg2, (unsigned)msan_check_reg(reg2));
    MSAN_TAINT_PRINT(pc, MSAN_INFO "tmp %u = %x\n", temp, (unsigned)msan_check_tmp(temp));
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rrt]Tainting reg %u\n", reg1);
    msan_taint_flags();
    msan_taint_reg(reg1, PROPAGATE_REG(reg1, msan_check_reg(reg2) & msan_check_tmp(temp), size));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction on reg okay\n");
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg1);
    msan_restore_flags();
    msan_taint_reg(reg1, PROPAGATE_REG(reg1, MSAN_64, size));
  }

}

void HELPER(qmsan_check_math_reg_reg_reg_tmp)(uint64_t pc, uint32_t reg1,
               uint32_t reg2, uint32_t reg3, uint32_t temp, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "Checking math operations on reg %u "
                  "from reg %u, reg %u and tmp %u (%lx, %lx, %lx) "
                  "of size %u", reg1, reg2, reg3, temp,
                  msan_check_reg(reg2), msan_check_reg(reg3),
                  msan_check_tmp(temp), size);
  
  if((~msan_check_reg(reg2) | ~msan_check_reg(reg3) | ~msan_check_tmp(temp)) 
      /*& nBITS(size)*/){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction on reg unreliable\n");
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rrrt]Tainting reg %u\n", reg1);
    msan_taint_flags();
    msan_taint_reg(reg1, PROPAGATE_REG(reg1, msan_check_reg(reg2)
                  & msan_check_reg(reg3) & msan_check_tmp(temp), size));
    MSAN_TAINT_PRINT(pc, MSAN_INFO "reg %u is now %lx\n", reg1, msan_check_reg(reg1));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "Math instruction on reg okay\n");
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg1);
    msan_restore_flags();
    msan_taint_reg(reg1, PROPAGATE_REG(reg1, MSAN_64, size));
  }

}

void HELPER(qmsan_restore_reg)(uint64_t pc, uint32_t reg){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
    
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[]restoring reg %u\n", reg);
    msan_restore_reg(reg);

}

void HELPER(qmsan_check_reg)(uint64_t pc, uint32_t reg){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
    
    MSAN_TAINT_PRINT(pc, MSAN_INFO "checking reg %u\n", reg);
    if(~msan_check_reg(reg))
      msan_giovese_report_reg(pc, reg, 0);
}

//mainly arm stuff, instructions like tb** only test one bit
void HELPER(qmsan_check_reg_pos)(uint64_t pc, uint32_t reg, uint64_t pos){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
    
    MSAN_TAINT_PRINT(pc, MSAN_INFO "checking reg %u with position %lx\n", reg, pos);
    if(~msan_check_reg(reg) & pos)
      msan_giovese_report_reg(pc, reg, 0);
}

void HELPER(qmsan_check_taint_reg_reg)(uint64_t pc, uint32_t reg, uint32_t reg2){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to reg %d from reg %d\n", reg, reg2);

  if(~msan_check_reg(reg2)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rt]Tainting reg %u\n", reg);
    msan_taint_reg(reg, msan_check_reg(reg2));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg);
    msan_restore_reg(reg);
  }

}

void HELPER(qmsan_check_shift)(uint64_t pc, uint32_t reg, uint32_t src, uint32_t shift, uint32_t is_right){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[shift]checking shift to reg %u of val %u"
                    " (src = %u, right = %u)\n", reg, shift, src, is_right);

  MSAN_TAINT_PRINT(pc, MSAN_INFO "reg %u current shadow: %lx\n",
                    reg, msan_check_reg(reg));

  //shift amount is in a tainted reg: the result is completely undefined
  if(src && (~msan_check_tmp(src))){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[shift]tainting reg %u (src shadow=%lx)\n",
                    reg, msan_check_tmp(src));
    msan_taint_reg(reg, 0);
    return;
  }

  if(is_right)
    msan_taint_reg(reg, ~(~msan_check_reg(reg) >> shift));
  else
    msan_taint_reg(reg, ~(~msan_check_reg(reg) << shift));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "Setting reg to %lx\n", msan_check_reg(reg));

}

void HELPER(qmsan_check_shift_tmp_imm)(uint64_t pc, uint32_t shift, uint32_t is_right){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "shift to tmp 0 of val %u (is_right = %u\n",
                  shift, is_right);

  if(is_right)
    msan_taint_tmp(0, ~(~msan_check_tmp(0) >> shift));
  else
    msan_taint_tmp(0, ~(~msan_check_tmp(0) << shift));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "Setting tmp 0 to %lx\n", msan_check_tmp(0));

}

//next two aux functions from https://stackoverflow.com/a/10134877
static unsigned int _rotl(const unsigned int value, int shift) {
    if ((shift &= sizeof(value)*8 - 1) == 0)
      return value;
    return (value << shift) | (value >> (sizeof(value)*8 - shift));
}

static unsigned int _rotr(const unsigned int value, int shift) {
    if ((shift &= sizeof(value)*8 - 1) == 0)
      return value;
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}

void HELPER(qmsan_check_rot)(uint64_t pc, uint32_t reg, uint32_t ecx, uint32_t rot, uint32_t is_right){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking rotation to reg %u of val %u (ecx = %u, right = %u)\n", reg, rot, ecx, is_right);

  if(ecx && msan_check_reg(ecx)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rot]Tainting reg %u\n", reg);
    msan_taint_reg(reg, MSAN_64);
    return;
  }

  if(is_right)
    msan_taint_reg(reg, _rotr(msan_check_reg(reg), rot));
  else
    msan_taint_reg(reg, _rotl(msan_check_reg(reg), rot));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "Setting reg to %lx\n", msan_check_reg(reg));

}

void HELPER(qmsan_widening_tmp)(uint64_t pc, uint32_t tmp, uint32_t sz){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "widening tmp %u size %u\n", tmp, sz);

  switch(sz){
    case MO_8:
      msan_taint_tmp(tmp, msan_check_tmp(tmp) | ~ MSAN_8);
    break;
    case MO_16:
      msan_taint_tmp(tmp, msan_check_tmp(tmp) | ~ MSAN_16);
    break;
    default:
      MSAN_TAINT_PRINT(pc, MSAN_INFO "Invalid size %u\n", sz);
    break;
  }
  MSAN_TAINT_PRINT(pc, MSAN_INFO "tmp %u = %lx\n", tmp, msan_check_tmp(tmp));
}

void HELPER(qmsan_check_taint_reg_reg_mask)(uint64_t pc, uint32_t reg, uint32_t reg2, uint64_t mask){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to reg %d from reg %d and mask %lx\n", reg, reg2, mask);

  if(~msan_check_reg(reg2) & mask){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rt]Tainting reg %u\n", reg);
    msan_taint_reg(reg, msan_check_reg(reg2));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg);
    msan_restore_reg(reg);
  }

}

void HELPER(qmsan_and_reg_imm)(uint64_t pc, uint32_t reg, uint64_t mask, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
  MSAN_TAINT_PRINT(pc, MSAN_INFO "AND reg %d (%lx), %lx of size %u\n",
                  reg, msan_check_reg(reg), mask, size);
  
  switch (size){
    case 0:
      mask = (~mask) & MSAN_8;
    break;
    case 1:
      mask = (~mask) & MSAN_16;
    break;
    case 2:
      mask = (~mask) & MSAN_32;
    break;
    case 3:
      mask = (~mask) & MSAN_64;
    break;
    default:
      mask = (~mask) & MSAN_64;
  }

  uint64_t res = msan_check_reg(reg) | (mask);

  MSAN_TAINT_PRINT(pc, MSAN_INFO "setting reg %d to %lx\n", reg, res);

  msan_taint_reg(reg, msan_check_reg(reg) | (mask));

}

void HELPER(qmsan_check_taint_and_reg_reg_reg)(uint64_t pc, uint32_t reg1,
             uint32_t reg2, uint32_t reg3, uint64_t val2, uint64_t val3){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  //propagation rules are meant for init = 0 and uninit = 1; remember to negate
  uint64_t res = ((~msan_check_reg(reg2) & ~msan_check_reg(reg3))
                  | (val2 & ~msan_check_reg(reg3))
                  | (~msan_check_reg(reg2) & val3));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[and] checking taint to reg %u from reg %u "
                    "and reg %u (%lx & %lx), shadows = (%lx, %lx). ~res=%lx\n",
                    reg1, reg2, reg3, val2, val3,
                    msan_check_reg(reg2), msan_check_reg(reg3), ~res);

  if(res){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[and]Tainting reg %u with %lx\n", reg1, ~res);
    msan_taint_reg(reg1, ~res);
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg1);
    msan_restore_reg(reg1);
  }

}

/*  The next 4 lifters DO NOT set flags to uninitialized if the result would
 *  be initialized regardless. For instance, consider a reg containing
 *  0xcafecafe00000001 being put in an AND with an immediate 0xff.
 *  this will ALWAYS results in flags being properlyinitialized if the last
 *  byte of 0xcafecafe00000001 (i.e. 0x01) is initialized. Tricks like this
 *  are commonly used and must be allowed (e.g. applying bitmasks with AND,
 *  inlining strcmp and similar functions that consist in MOV and CMP etc)
*/

void HELPER(qmsan_check_taint_and_tmp_tmp)(uint64_t pc, uint32_t tmp0, 
                  uint32_t tmp1, uint64_t val0, uint64_t val1, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  //propagation rules are meant for init = 0 and uninit = 1; remember to negate
  uint64_t res = ((~msan_check_tmp(tmp0) & ~msan_check_tmp(tmp1))
                  | (val0 & ~msan_check_tmp(tmp1))
                  | (~msan_check_tmp(tmp0) & val1));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[and] checking taint to tmp 0 from tmp %u "
                    "and tmp %u (%lx & %lx), shadows = (%lx, %lx). ~res=%lx\n",
                    tmp0, tmp1, val0, val1,
                    msan_check_tmp(tmp0), msan_check_tmp(tmp1), ~res);

  if(res){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[and]Tainting tmp 0 with %lx\n", ~res);
    msan_taint_tmp(0, PROPAGATE_TMP(0, ~res, size));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring tmp 0\n");
    msan_taint_tmp(0, PROPAGATE_TMP(0, MSAN_64, size));
  }

  //update ZF accordingly
  //right now we are not really shadowing each flag
  //FIXME: change this if needed
  if((val0 & msan_check_tmp(tmp0)) & (val1 & msan_check_tmp(tmp1))){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring flags\n");
    msan_restore_flags();
  }
  else if(~msan_check_tmp(tmp0) || ~msan_check_tmp(tmp1)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "tainting flags\n");
    msan_taint_flags();
  }

}

void HELPER(qmsan_check_taint_or_tmp_tmp)(uint64_t pc, uint32_t tmp0, 
             uint32_t tmp1, uint64_t val0, uint64_t val1, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  //propagation rules are meant for init = 0 and uninit = 1; remember to negate
  uint64_t res = ((~msan_check_tmp(tmp0) & ~msan_check_tmp(tmp1))
                  | (~val0 & ~msan_check_tmp(tmp1))
                  | (~msan_check_tmp(tmp0) & ~val1));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[or] checking taint to tmp 0 from tmp %u "
                    "and tmp %u (%lx | %lx), shadows = (%lx, %lx). ~res=%lx\n",
                    tmp0, tmp1, val0, val1,
                    msan_check_tmp(tmp0), msan_check_tmp(tmp1), ~res);

  if(res){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[or]Tainting tmp 0 with %lx\n", ~res);
    msan_taint_tmp(0, PROPAGATE_TMP(0, ~res, size));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring tmp 0\n");
    msan_taint_tmp(0, PROPAGATE_TMP(0, MSAN_64, size));
  }

  //update ZF accordingly
  //right now we are not really shadowing each flag
  //FIXME: change this if needed
  if((val0 & msan_check_tmp(tmp0)) | (val1 & msan_check_tmp(tmp1))){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring flags\n");
    msan_restore_flags();
  }
  else if(~msan_check_tmp(tmp0) || ~msan_check_tmp(tmp1)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "tainting flags\n");
    msan_taint_flags();
  }

}

void HELPER(qmsan_check_taint_xor_tmp_tmp)(uint64_t pc, uint32_t tmp0, 
             uint32_t tmp1, uint64_t val0, uint64_t val1, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uint64_t res = (msan_check_tmp(tmp0) & msan_check_tmp(tmp1));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[xor] checking taint to tmp 0 from tmp %u "
                    "and tmp %u (%lx | %lx), shadows = (%lx, %lx). res=%lx\n",
                    tmp0, tmp1, val0, val1,
                    msan_check_tmp(tmp0), msan_check_tmp(tmp1), res);

  if(~res){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[xor]Tainting tmp 0 with %lx\n", res);
    msan_taint_tmp(0, PROPAGATE_TMP(0, res, size));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring tmp 0\n");
    msan_taint_tmp(0, PROPAGATE_TMP(0, MSAN_64, size));
  }

  //update ZF accordingly
  //right now we are not really shadowing each flag
  //FIXME: change this if needed
  if((val0 & msan_check_tmp(tmp0)) ^ (val1 & msan_check_tmp(tmp1))){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring flags\n");
    msan_restore_flags();
  }
  else if(~msan_check_tmp(tmp0) || ~msan_check_tmp(tmp1)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "tainting flags\n");
    msan_taint_flags();
  }


}

void HELPER(qmsan_check_taint_cmp_tmp_tmp)(uint64_t pc, uint32_t tmp0, 
             uint32_t tmp1, uint64_t val0, uint64_t val1, uint32_t size){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  uint64_t res = (msan_check_tmp(tmp0) & msan_check_tmp(tmp1));

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[cmp] checking taint to tmp 0 from tmp %u "
                    "and tmp %u (%lx | %lx), shadows = (%lx, %lx). res=%lx\n",
                    tmp0, tmp1, val0, val1,
                    msan_check_tmp(tmp0), msan_check_tmp(tmp1), res);

  if(~res){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[cmp]Tainting tmp 0 with %lx\n", res);
    msan_taint_tmp(0, PROPAGATE_TMP(0, res, size));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring tmp 0\n");
    msan_taint_tmp(0, PROPAGATE_TMP(0, MSAN_64, size));
  }

  //update ZF accordingly
  //right now we are not really shadowing each flag
  //FIXME: change this if needed

  //old method: take into account values; it causes false negatives!!!
  // if(!(~res) || (res & (val0 - val1))){
  //   MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring flags\n");
  //   msan_restore_flags();
  // }
  // else if(~res){
  //   MSAN_TAINT_PRINT(pc, MSAN_INFO "tainting flags\n");
  //   msan_taint_flags();
  // }

  //new method: do not take into account values. If it is uninit then taint it.
  if(!(~res)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring flags\n");
    msan_restore_flags();
  }
  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "tainting flags\n");
    msan_taint_flags();
  }

}

void HELPER(qmsan_check_taint_reg_mem)(uint64_t pc, uint32_t reg, target_ulong addr, uint32_t size){

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint for reg %u on addr %lx of size %u\n", reg, addr, (1 << size));


  unsigned long ret, mask;
  switch (size){
    case 0:
      ret = (unsigned long) msan_giovese_load1(ptr);
      mask = MSAN_8;
    break;
    case 1:
      ret = (unsigned long) msan_giovese_load2(ptr);
      mask = MSAN_16;
    break;
    case 2:
      ret = (unsigned long) msan_giovese_load4(ptr);
      mask = MSAN_32;
    break;
    case 3:
      ret = (unsigned long) msan_giovese_load8(ptr);
      mask = MSAN_64;
    break;
    default:
      ret = (unsigned long) msan_giovese_load1(ptr);
      mask = MSAN_8;
  }

  if ( ~ret & mask ){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "reg [%u] is now tainted!\n", reg);
    msan_taint_reg(reg, (msan_check_reg(reg) & ~mask) | (ret & mask));
    MSAN_TAINT_PRINT(pc, MSAN_INFO "reg [%u] = %lx \n", reg, msan_check_reg(reg));
  }
  
  else
    msan_restore_reg(reg);

}

void HELPER(qmsan_check_taint_reg_reg_reg)(uint64_t pc, uint32_t reg, uint32_t reg2, uint32_t reg3){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to reg %d from reg %d and reg %d\n", reg, reg2, reg3);

  if(~msan_check_reg(reg2) || ~msan_check_reg(reg3)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rt]Tainting reg %u\n", reg);
    msan_taint_reg(reg, msan_check_reg(reg2) & msan_check_reg(reg3));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg);
    msan_restore_reg(reg);
  }

}

void HELPER(qmsan_check_taint_reg_reg_reg_reg)(uint64_t pc, uint32_t reg, uint32_t reg2, uint32_t reg3, uint32_t reg4){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "checking taint to reg %d from reg %d and reg %d and reg %d\n", reg, reg2, reg3, reg4);

  if(~msan_check_reg(reg2) || ~msan_check_reg(reg3) || ~msan_check_reg(reg4)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "[rt]Tainting reg %u\n", reg);
    msan_taint_reg(reg, msan_check_reg(reg2) & msan_check_reg(reg3) & msan_check_reg(reg4));
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "restoring reg %u\n", reg);
    msan_restore_reg(reg);
  }

}

void HELPER(qmsan_check_flags_reg)(uint64_t pc, uint32_t reg){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
  if(~msan_check_reg(reg)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "flag reg unreliable\n");
    msan_taint_flags();
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "flag reg okay\n");
    msan_restore_flags();
  }

}

void HELPER(qmsan_check_flags_reg_reg)(uint64_t pc, uint32_t reg, uint32_t reg2){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
  if(~msan_check_reg(reg) || ~msan_check_reg(reg)){
    MSAN_TAINT_PRINT(pc, MSAN_INFO "flag reg unreliable\n");
    msan_taint_flags();
  }

  else{
    MSAN_TAINT_PRINT(pc, MSAN_INFO "flag reg okay\n");
    msan_restore_flags();
  }

}

void HELPER(qmsan_check_taint_flags)(uint64_t pc){

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
    MSAN_TAINT_PRINT(pc, MSAN_INFO "checking flag reg\n");

  if(msan_check_flags())
    msan_giovese_report_flags(pc);

}

void HELPER(qmsan_zero_N_if_taint_tmp)(uint64_t pc, target_ulong addr, uint32_t temp, uint32_t dim){

  uintptr_t ptr = (uintptr_t)g2h(addr);


  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
  //is this even possible?
  if(dim > 3)
    dim = 3;
  
  dim = 1 << dim;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[tmp] do I have to zero memory %lx dim %d?\n", ptr, dim);

  if(~msan_check_tmp(temp)){
    uint64_t mask;
    switch(dim){
      case 1:
        mask = MSAN_8;
      break;
      case 2:
        mask = MSAN_16;
      break;
      case 4:
        mask = MSAN_32;
      break;
      case 8:
        mask = MSAN_64;
      break;
      default:
        MSAN_PRINT("how did you even end up here [%u]?\n", dim);
        mask = MSAN_8;
      break;
    }
    // msan_giovese_zeroN(ptr, 1);
    // MSAN_TAINT_PRINT(pc, MSAN_INFO "zeroing 0x%lx dim %d\n", addr, dim);
    msan_giovese_set_mem_to_regval((uint64_t) ptr, msan_check_tmp(temp) & mask, dim);
    MSAN_TAINT_PRINT(pc, MSAN_INFO "setting %lx to %lx [%lx & %lx]\n", ptr, msan_check_tmp(temp) & mask, msan_check_tmp(temp), mask);
  }

}

void HELPER(qmsan_zero_N_if_taint_reg)(uint64_t pc, target_ulong addr, uint32_t reg, uint32_t dim){

  uintptr_t ptr = (uintptr_t)g2h(addr);

  if(!qmsan_start || msan_giovese_check_ld(pc))
    return;
  
  //is this even possible?
  if(dim > 3)
    dim = 3;
  
  dim = 1 << dim;

  MSAN_TAINT_PRINT(pc, MSAN_INFO "[reg] do I have to zero memory %lx? dim %d?\n", ptr, dim);
  
  if(~msan_check_reg(reg)){
    uint64_t mask;
    switch(dim){
      case 1:
        mask = MSAN_8;
      break;
      case 2:
        mask = MSAN_16;
      break;
      case 4:
        mask = MSAN_32;
      break;
      case 8:
        mask = MSAN_64;
      break;
      default:
        MSAN_PRINT("how did you even end up here [%u]?\n", dim);
        mask = MSAN_8;
      break;
    }
    // msan_giovese_zeroN(ptr, 1);
    // MSAN_TAINT_PRINT(pc, MSAN_INFO "zeroing %lu dim %d\n", addr, dim);
    msan_giovese_set_mem_to_regval((uint64_t) ptr, msan_check_reg(reg) & mask, dim);
    MSAN_TAINT_PRINT(pc, MSAN_INFO "setting %lx to %lx [%lx & %lx]\n", ptr, msan_check_reg(reg) & mask, msan_check_reg(reg), mask);
  }

}

//it's not the best to define macros here, but since this is going to
//be a long function, it's better to have everything close.
//we check that the registers are not tainted here.
#ifdef TARGET_X86_64

#define SYS_REG_0 R_EDI
#define SYS_REG_1 R_ESI
#define SYS_REG_2 R_EDX
#define SYS_REG_3 R_R10
#define SYS_REG_4 R_R8
#define SYS_REG_5 R_R9

#else

#define SYS_REG_0 0
#define SYS_REG_1 1
#define SYS_REG_2 2
#define SYS_REG_3 3
#define SYS_REG_4 4
#define SYS_REG_5 5

#endif


#define CHECK_PARAMS6 \
  if(~msan_check_reg(SYS_REG_0))\
    msan_giovese_report_syscall(pc, num, SYS_REG_0);\
  // if(~msan_check_reg(SYS_REG_1))\
  //   msan_giovese_report_syscall(pc, num, SYS_REG_1);\
  // if(~msan_check_reg(SYS_REG_2))\
  //   msan_giovese_report_syscall(pc, num, SYS_REG_2);\
  // if(~msan_check_reg(SYS_REG_3))\
  //   msan_giovese_report_syscall(pc, num, SYS_REG_3);\
  // if(~msan_check_reg(SYS_REG_4))\
  //   msan_giovese_report_syscall(pc, num, SYS_REG_4);\
  // if(~msan_check_reg(SYS_REG_5))\
  //   msan_giovese_report_syscall(pc, num, SYS_REG_5);\
  

//the helper used to manage syscalls, maybe a long one

//the old method was not working, changing arch will change the
//syscall numbers!!! ATM just check all the regs (might lead to false positive)
void HELPER(qmsan_check_syscall)(uint64_t pc, uint64_t num){

  if(msan_giovese_check_ld(pc))
    return;

  MSAN_DEBUG_INFO(MSAN_INFO "called syscall %d\n", num);
    CHECK_PARAMS6

}

#endif