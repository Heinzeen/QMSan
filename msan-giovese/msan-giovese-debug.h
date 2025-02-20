/*macros previously used to debug; they can now
all be used by compiling with --mverbose
#define MSAN_NO_LIB

#define MSAN_DEBUG_PRINT
#define MSAN_DEBUG_STACK
#define MSAN_DEBUG_FUN
#define MSAN_DEBUG_START_INFO
#define MSAN_DEBUG_MMAP_INFO
#define MSAN_INSTR
#define MSAN_TAINT
*/

//define some macros to ease debugging, specially when we have taint and long programs
#define MSAN_PRINT(...)                         fprintf(stderr, __VA_ARGS__);


#ifdef MSAN_TAINT 
#define MSAN_TAINT_PRINT(pc, ...)               if(target_area)\
                                                    MSAN_PRINT(__VA_ARGS__)
#else
#define MSAN_TAINT_PRINT(pc, ...)               ;
#endif


#ifdef MSAN_DEBUG_PRINT
#define MSAN_DEBUG_INFO(...)                    if(target_area)\
                                                    MSAN_PRINT(__VA_ARGS__)
#else
#define MSAN_DEBUG_INFO(...)                    ;
#endif


#ifdef MSAN_DEBUG_MMAP_INFO
#define MSAN_MMAP_INFO(...)                     if(target_area)\
                                                    MSAN_PRINT(__VA_ARGS__)
#else
#define MSAN_MMAP_INFO(...)                     ;
#endif


#ifdef MSAN_DEBUG_FUN
#define MSAN_FUN_INFO(...)                      if(target_area)\
                                                    MSAN_PRINT(__VA_ARGS__)
#else
#define MSAN_FUN_INFO(...)                      ;
#endif


#ifdef MSAN_DEBUG_STACK
#define MSAN_STACK_INFO(...)                    if(target_area)\
                                                    MSAN_PRINT(__VA_ARGS__)
#else
#define MSAN_STACK_INFO(...)                    ;
#endif


#ifdef MSAN_INSTR
#define MSAN_INSTR_INFO(...)                    if(target_area)\
                                                    MSAN_PRINT(__VA_ARGS__)
#else
#define MSAN_INSTR_INFO(...)                    ;
#endif
