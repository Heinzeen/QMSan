/*******************************************************************************
Copyright (c) 2019-2020, Andrea Fioraldi


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#include "libqasan.h"

#ifdef DEBUG
int __qasan_debug;
#endif
int __qasan_log;

void __libqasan_print_maps(void) {

  int  fd = open("/proc/self/maps", O_RDONLY);
  char buf[4096] = {0};

  read(fd, buf, 4095);
  close(fd);

  size_t len = strlen(buf);

  QASAN_LOG("Guest process maps:\n");
  int   i;
  char *line = NULL;
  for (i = 0; i < len; i++) {

    if (!line) line = &buf[i];
    if (buf[i] == '\n') {

      buf[i] = 0;
      QASAN_LOG("%s\n", line);
      line = NULL;

    }

  }

  if (line) QASAN_LOG("%s\n", line);
  QASAN_LOG("\n");

}

/*__attribute__((constructor))*/ void __libqasan_init() {

  __libqasan_init_hooks();

#ifdef DEBUG
  __qasan_debug = getenv("QASAN_DEBUG") != NULL;
#endif
  __qasan_log = getenv("QASAN_LOG") != NULL;

  QASAN_LOG("QEMU-AddressSanitizer (v%s)\n", QASAN_VERSTR);
  QASAN_LOG(
      "Copyright (C) 2019-2021 Andrea Fioraldi <andreafioraldi@gmail.com>\n");
  QASAN_LOG("\n");

  if (__qasan_log) __libqasan_print_maps();

}

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      int (*init)(int, char **, char **), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {

  typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

  __libqasan_init();

  /* if we are not in NO_LIB mode, we still need hotpatching 
    to remove the use of optimized functions that cause
    (controlled) accesses to uninitialized memory*/
#if defined MSAN_GIOVESE && !defined MSAN_NO_LIB
  __libqasan_hotpatch();
#else
  if (getenv("AFL_INST_LIBS")) __libqasan_hotpatch();
#endif

#ifdef MSAN_GIOVESE
  QMSAN_SET_MAIN(main);
#endif
  return orig(main, argc, argv, init, fini, rtld_fini, stack_end);

}

