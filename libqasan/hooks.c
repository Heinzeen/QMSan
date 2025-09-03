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
#include "map_macro.h"
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/resource.h>
//#include <stdio.h>


#include <../msan-giovese/msan-giovese.h>

//change this
#define QMSAN_LOCATION  "/home/heinzeen/Desktop/sanitizer/taint/qasan"

int (*ptr_execve) (const char *pathname, char *const argv[],
                  char *const envp[]);

int execve(const char *pathname, char *const argv[],
                  char *const envp[]){

  //count argv
  int i = 0;
  while(argv[i])
    i++;

  //alloc argv
  char** qargv = (char**) malloc((i + 1) * sizeof(char*));

  //copy qmsan path
  qargv[0] = (char*) malloc(sizeof(QMSAN_LOCATION));
  strcpy(qargv[0], QMSAN_LOCATION);
  qargv[0][sizeof(QMSAN_LOCATION)] = 0;

  fprintf(stderr, "QMSan, execve detected\n");
  fprintf(stderr, "%s ", qargv[0]);
  //populate qargv
  for(i=0; argv[i]; i++){
    qargv[i+1] = argv[i];
    fprintf(stderr, "%s ", qargv[i+1]);
  }
  qargv[i+1] = NULL;
  fprintf(stderr, "\n");

  REAL(execve);

  return ptr_execve(QMSAN_LOCATION, qargv, envp);

}

char *(*__lq_libc_fgets)(char *, int, FILE *);
int (*__lq_libc_atoi)(const char *);
long (*__lq_libc_atol)(const char *);
long long (*__lq_libc_atoll)(const char *);
long (*__lq_libc_strtol)(const char*, char**, int );
long long (*__lq_libc_strtoll)(const char*, char**, int );
double (*__lq_libc_strtod)(const char*, char**);
char* (*__lq_libc_strtok)(char *, const char *);
unsigned long (*__lq_libc_strtoul)(const char*, char**, int);

void __libqasan_init_hooks(void) {

  __libqasan_init_malloc();

  __lq_libc_fgets = ASSERT_DLSYM(fgets);
  __lq_libc_atoi = ASSERT_DLSYM(atoi);
  __lq_libc_atol = ASSERT_DLSYM(atol);
  __lq_libc_atoll = ASSERT_DLSYM(atoll);
  __lq_libc_strtol = ASSERT_DLSYM(strtol);
  __lq_libc_strtoll = ASSERT_DLSYM(strtoll);
  __lq_libc_strtod = ASSERT_DLSYM(strtod);
  __lq_libc_strtok = ASSERT_DLSYM(strtok);
  __lq_libc_strtoul = ASSERT_DLSYM(strtoul);

}

#ifdef __ANDROID__
size_t malloc_usable_size(const void *ptr) {

#else
size_t malloc_usable_size(void *ptr) {

#endif

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: malloc_usable_size(%p)\n", rtv, ptr);
  size_t r = __libqasan_malloc_usable_size((void *)ptr);
  QASAN_DEBUG("\t\t = %ld\n", r);

  return r;

}

void *malloc(size_t size) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: malloc(%ld)\n", rtv, size);
  void *r = __libqasan_malloc(size);
  
  QASAN_DEBUG("\t\t = %p\n", r);

#if defined MSAN_NO_LIB && defined MSAN_TAINT_ANALYSIS
  QMSAN_RESTORE_RETVAL();
#endif

  return r;

}

void *calloc(size_t nmemb, size_t size) {

  int flag = QMSAN_DISABLE();

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: calloc(%ld, %ld)\n", rtv, nmemb, size);
  void *r = __libqasan_calloc(nmemb, size);
  QASAN_DEBUG("\t\t = %p\n", r);

  QMSAN_ENABLE(flag);
  if(r)
    QMSAN_STORE(r, nmemb * size);

  return r;

}

void *realloc(void *ptr, size_t size) {

  int flag = QMSAN_DISABLE();

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: realloc(%p, %ld)\n", rtv, ptr, size);
  void *r = __libqasan_realloc(ptr, size);
  QASAN_DEBUG("\t\t = %p\n", r);

  QMSAN_ENABLE(flag);

  return r;

}

int posix_memalign(void **memptr, size_t alignment, size_t size) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: posix_memalign(%p, %ld, %ld)\n", rtv, memptr, alignment,
              size);
  int r = __libqasan_posix_memalign(memptr, alignment, size);
  QASAN_DEBUG("\t\t = %d [*memptr = %p]\n", r, *memptr);

  return r;

}

void *memalign(size_t alignment, size_t size) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memalign(%ld, %ld)\n", rtv, alignment, size);
  void *r = __libqasan_memalign(alignment, size);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

void *aligned_alloc(size_t alignment, size_t size) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: aligned_alloc(%ld, %ld)\n", rtv, alignment, size);
  void *r = __libqasan_aligned_alloc(alignment, size);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

void *valloc(size_t size) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: valloc(%ld)\n", rtv, size);
  void *r = __libqasan_memalign(sysconf(_SC_PAGESIZE), size);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

void *pvalloc(size_t size) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: pvalloc(%ld)\n", rtv, size);
  size_t page_size = sysconf(_SC_PAGESIZE);
  size = (size & (page_size - 1)) + page_size;
  void *r = __libqasan_memalign(page_size, size);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

void free(void *ptr) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: free(%p)\n", rtv, ptr);
  __libqasan_free(ptr);

}

char *fgets(char *s, int size, FILE *stream) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: fgets(%p, %d, %p)\n", rtv, s, size, stream);
  QASAN_STORE(s, size);

#ifdef MSAN_NO_LIB 
  QMSAN_LOAD(stream, sizeof(FILE), rtv);
  QMSAN_STORE(s, __libqasan_strlen(s) + 1);
#endif
  
#ifndef __ANDROID__
  QASAN_LOAD(stream, sizeof(FILE));
#endif
  char *r = __lq_libc_fgets(s, size, stream);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

int memcmp(const void *s1, const void *s2, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memcmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  QASAN_LOAD(s1, n);
  QASAN_LOAD(s2, n);
#ifdef MSAN_NO_LIB 
  QMSAN_LOAD(s1, n, rtv);
  QMSAN_LOAD(s2, n, rtv);
#endif
  int r = __libqasan_memcmp(s1, s2, n);
  QASAN_DEBUG("\t\t = %d\n", r);

  return r;

}

void *memcpy(void *dest, const void *src, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memcpy(%p, %p, %ld)\n", rtv, dest, src, n);
  QASAN_LOAD(src, n);
  QASAN_STORE(dest, n);
#ifdef MSAN_NO_LIB
  QMSAN_CHECK_PROPAGATE(dest, src, n);
#endif
  void *r = __libqasan_memcpy(dest, src, n);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

void *memccpy(void *dest, const void *src, int c, size_t n){

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memccpy(%p, %p, %c, %ld)\n", rtv, dest, src, c, n);

  void *r = __libqasan_memccpy(dest, src, c, n);
  QASAN_DEBUG("\t\t = %p\n", r);
#ifdef MSAN_NO_LIB
  if(r){ //c found
    QMSAN_LOAD(src, r - src, rtv);
    QMSAN_STORE(dest, r - src);
  }
#endif

  return r;
}


void *mempcpy(void *dest, const void *src, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: mempcpy(%p, %p, %ld)\n", rtv, dest, src, n);
  QASAN_LOAD(src, n);
  QASAN_STORE(dest, n);
#ifdef MSAN_NO_LIB
  QMSAN_CHECK_PROPAGATE(dest, src, n);
#endif
  void *r = (uint8_t *)__libqasan_memcpy(dest, src, n) + n;
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

void *memmove(void *dest, const void *src, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memmove(%p, %p, %ld)\n", rtv, dest, src, n);
  QASAN_LOAD(src, n);
  QASAN_STORE(dest, n);
#ifdef MSAN_NO_LIB
  QMSAN_CHECK_PROPAGATE(dest, src, n);
#endif
  void *r = __libqasan_memmove(dest, src, n);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

//according to the glibc source code, bcopy just calls memmove
//i.e. we don't need to define anything new
void bcopy (const void *src, void *dest, size_t len){
  memmove (dest, src, len);
}

void *memset(void *s, int c, size_t n) {

  int flag = QMSAN_DISABLE();

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memset(%p, %d, %ld)\n", rtv, s, c, n);
  QASAN_STORE(s, n);
  void * r;
  //Heinzeen: we use this trick to avoid being stuck on anomalies
  //          while using memset. Found this in nvdisasm-12.3 where
  //          10GB+ memory locations were tried to be set to 0
  //          resulting in the process getting stuck. Valgrind manages
  //          it in some way, we should investigate.
  //          Note how this is not a qmsan's problem. Allowing such a
  //          memset will freeze the process even if MSan is disabled.
#ifdef MSAN_GIOVESE
  if(n > 1000000000)    //1 GB
    r = s;
  else 
# endif
  {
  QMSAN_STORE(s, n);  
  r = __libqasan_memset(s, c, n);
  QASAN_DEBUG("\t\t = %p\n", r);

  }
  QMSAN_ENABLE(flag);

  return r;

}

void *memchr(const void *s, int c, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memchr(%p, %d, %ld)\n", rtv, s, c, n);
  void *r = __libqasan_memchr(s, c, n);
  if (r == NULL){
    QASAN_LOAD(s, n);
#ifdef MSAN_NO_LIB
    QMSAN_LOAD(s, n, rtv);
#endif
  }
  else {
    QASAN_LOAD(s, r - s);
#ifdef MSAN_NO_LIB
    QMSAN_LOAD(s, r - s, rtv);
#endif
  }
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

void *memrchr(const void *s, int c, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memrchr(%p, %d, %ld)\n", rtv, s, c, n);
  QASAN_LOAD(s, n);
#ifdef MSAN_NO_LIB
    QMSAN_LOAD(s, n, rtv);
#endif
  void *r = __libqasan_memrchr(s, c, n);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

void *memmem(const void *haystack, size_t haystacklen, const void *needle,
             size_t needlelen) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: memmem(%p, %ld, %p, %ld)\n", rtv, haystack, haystacklen,
              needle, needlelen);
  QASAN_LOAD(haystack, haystacklen);
  QASAN_LOAD(needle, needlelen);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(haystack, haystacklen, rtv);
  QMSAN_LOAD(needle, needlelen, rtv);
#endif
  void *r = __libqasan_memmem(haystack, haystacklen, needle, needlelen);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

#ifndef __BIONIC__
void bzero(void *s, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: bzero(%p, %ld)\n", rtv, s, n);
  QASAN_STORE(s, n);
#ifdef MSAN_NO_LIB
  QMSAN_STORE(s, n);
#endif
  __libqasan_memset(s, 0, n);

}
#endif

void explicit_bzero(void *s, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: bzero(%p, %ld)\n", rtv, s, n);
  QASAN_STORE(s, n);
#ifdef MSAN_NO_LIB
  QMSAN_STORE(s, n);
#endif
  __libqasan_memset(s, 0, n);

}

int bcmp(const void *s1, const void *s2, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: bcmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  QASAN_LOAD(s1, n);
  QASAN_LOAD(s2, n);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s1, n, rtv);
  QMSAN_LOAD(s2, n, rtv);
#endif
  int r = __libqasan_bcmp(s1, s2, n);
  QASAN_DEBUG("\t\t = %d\n", r);

  return r;

}

char *strchr(const char *s, int c) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strchr(%p, %d)\n", rtv, s, c);
  size_t l = __libqasan_strlen(s);
  QASAN_LOAD(s, l + 1);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s, l + 1, rtv);
#endif
  void *r = __libqasan_strchr(s, c);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

char *strrchr(const char *s, int c) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strrchr(%p, %d)\n", rtv, s, c);
  size_t l = __libqasan_strlen(s);
  QASAN_LOAD(s, l + 1);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s, l + 1, rtv);
#endif
  void *r = __libqasan_strrchr(s, c);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

int strcasecmp(const char *s1, const char *s2) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strcasecmp(%p, %p)\n", rtv, s1, s2);
  size_t l1 = __libqasan_strlen(s1);
  QASAN_LOAD(s1, l1 + 1);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s1, l1 + 1, rtv);
#endif
  size_t l2 = __libqasan_strlen(s2);
  QASAN_LOAD(s2, l2 + 1);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s2, l2 + 1, rtv);
#endif
  int r = __libqasan_strcasecmp(s1, s2);
  QASAN_DEBUG("\t\t = %d\n", r);

  return r;

}

int strncasecmp(const char *s1, const char *s2, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strncasecmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  size_t l1 = __libqasan_strnlen(s1, n);
  QASAN_LOAD(s1, l1);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s1, l1, rtv);
#endif
  size_t l2 = __libqasan_strnlen(s2, n);
  QASAN_LOAD(s2, l2);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s2, l2, rtv);
#endif
  int r = __libqasan_strncasecmp(s1, s2, n);
  QASAN_DEBUG("\t\t = %d\n", r);

  return r;

}

char *strcat(char *dest, const char *src) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strcat(%p, %p)\n", rtv, dest, src);
  size_t l2 = __libqasan_strlen(src);
  QASAN_LOAD(src, l2 + 1);
  size_t l1 = __libqasan_strlen(dest);
  QASAN_STORE(dest, l1 + l2 + 1);
#ifdef MSAN_NO_LIB
  //appending to dest means reading dest
  QMSAN_LOAD(dest, l1 + 1, rtv);
  QMSAN_CHECK_PROPAGATE(dest + l1, src, l2 + 1);
#endif
  __libqasan_memcpy(dest + l1, src, l2);
  dest[l1 + l2] = 0;
  void *r = dest;
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

int strcmp(const char *s1, const char *s2) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strcmp(%p, %p)\n", rtv, s1, s2);
  size_t l1 = __libqasan_strlen(s1);
  QASAN_LOAD(s1, l1 + 1);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s1, l1 + 1, rtv);
#endif
  size_t l2 = __libqasan_strlen(s2);
  QASAN_LOAD(s2, l2 + 1);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s2, l2 + 1, rtv);
#endif
  int r = __libqasan_strcmp(s1, s2);
  QASAN_DEBUG("\t\t = %d\n", r);

  return r;

}

int strncmp(const char *s1, const char *s2, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strncmp(%p, %p, %ld)\n", rtv, s1, s2, n);
  int flag = (int) QMSAN_DISABLE();
  size_t l1 = __libqasan_strnlen(s1, n);
  QASAN_LOAD(s1, l1);
  size_t l2 = __libqasan_strnlen(s2, n);
  QASAN_LOAD(s2, l2);
  QMSAN_ENABLE(flag);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s1, l1, rtv);
  QMSAN_LOAD(s2, l2, rtv);
#endif
  int r = __libqasan_strncmp(s1, s2, n);
  QASAN_DEBUG("\t\t = %d\n", r);

  return r;

}

char *strcpy(char *dest, const char *src) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strcpy(%p, %p)\n", rtv, dest, src);
  size_t l = __libqasan_strlen(src) + 1;
  QASAN_LOAD(src, l);
  QASAN_STORE(dest, l);
#ifdef MSAN_NO_LIB
  QMSAN_CHECK_PROPAGATE(dest, src, __libqasan_strlen(src) + 1);
#endif
  void *r = __libqasan_memcpy(dest, src, l);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

char *strncpy(char *dest, const char *src, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strncpy(%p, %p, %ld)\n", rtv, dest, src, n);
  size_t l = __libqasan_strnlen(src, n);
  QASAN_STORE(dest, n);
  void *r;
  if (l < n) {

    QASAN_LOAD(src, l + 1);
#ifdef MSAN_NO_LIB
  QMSAN_CHECK_PROPAGATE(dest, src, l+1);
#endif
    r = __libqasan_memcpy(dest, src, l + 1);

  } else {

    QASAN_LOAD(src, n);
#ifdef MSAN_NO_LIB
  QMSAN_CHECK_PROPAGATE(dest, src, n);
#endif
    r = __libqasan_memcpy(dest, src, n);

  }

  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

char *stpcpy(char *dest, const char *src) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: stpcpy(%p, %p)\n", rtv, dest, src);
  size_t l = __libqasan_strlen(src) + 1;
  QASAN_LOAD(src, l);
  QASAN_STORE(dest, l);
#ifdef MSAN_NO_LIB
    QMSAN_CHECK_PROPAGATE(dest, src, l);
#endif
  char *r = __libqasan_memcpy(dest, src, l) + (l - 1);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

char *strdup(const char *s) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strdup(%p)\n", rtv, s);
  size_t l = __libqasan_strlen(s);
  QASAN_LOAD(s, l + 1);
  void *r = __libqasan_malloc(l + 1);
#ifdef MSAN_NO_LIB
    if(r && s)
    QMSAN_CHECK_PROPAGATE(r, s, l+1);
#endif
  __libqasan_memcpy(r, s, l + 1);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

size_t strlen(const char *s) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strlen(%p)\n", rtv, s);
  size_t r = __libqasan_strlen(s);
  QASAN_LOAD(s, r + 1);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s, r + 1, rtv);
#endif
  QASAN_DEBUG("\t\t = %ld\n", r);

  return r;

}

size_t strnlen(const char *s, size_t n) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strnlen(%p, %ld)\n", rtv, s, n);
  size_t r = __libqasan_strnlen(s, n);
  QASAN_LOAD(s, r);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s, r, rtv);
#endif
  QASAN_DEBUG("\t\t = %ld\n", r);

  return r;

}

char *strstr(const char *haystack, const char *needle) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strstr(%p, %p)\n", rtv, haystack, needle);
  size_t l = __libqasan_strlen(haystack) + 1;
  QASAN_LOAD(haystack, l);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(haystack, l, rtv);
#endif
  l = __libqasan_strlen(needle) + 1;
  QASAN_LOAD(needle, l);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(needle, l, rtv);
#endif
  void *r = __libqasan_strstr(haystack, needle);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

char *strcasestr(const char *haystack, const char *needle) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: strcasestr(%p, %p)\n", rtv, haystack, needle);
  size_t l = __libqasan_strlen(haystack) + 1;
  QASAN_LOAD(haystack, l);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(haystack, l, rtv);
#endif
  l = __libqasan_strlen(needle) + 1;
  QASAN_LOAD(needle, l);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(needle, l, rtv);
#endif
  void *r = __libqasan_strcasestr(haystack, needle);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

int atoi(const char *nptr) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: atoi(%p)\n", rtv, nptr);
  size_t l = __libqasan_strlen(nptr) + 1;
  QASAN_LOAD(nptr, l);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(nptr, l, rtv);
#endif
  int r = __lq_libc_atoi(nptr);
  QASAN_DEBUG("\t\t = %d\n", r);

  return r;

}

long atol(const char *nptr) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: atol(%p)\n", rtv, nptr);
  size_t l = __libqasan_strlen(nptr) + 1;
  QASAN_LOAD(nptr, l);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(nptr, l, rtv);
#endif
  long r = __lq_libc_atol(nptr);
  QASAN_DEBUG("\t\t = %ld\n", r);

  return r;

}

long long atoll(const char *nptr) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: atoll(%p)\n", rtv, nptr);
  size_t l = __libqasan_strlen(nptr) + 1;
  QASAN_LOAD(nptr, l);
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(nptr, l, rtv);
#endif
  long long r = __lq_libc_atoll(nptr);
  QASAN_DEBUG("\t\t = %lld\n", r);

  return r;

}

size_t wcslen(const wchar_t *s) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: wcslen(%p)\n", rtv, s);
  size_t r = __libqasan_wcslen(s);
  QASAN_LOAD(s, sizeof(wchar_t) * (r + 1));
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s, sizeof(wchar_t) * (r + 1), rtv);
#endif
  QASAN_DEBUG("\t\t = %ld\n", r);

  return r;

}

wchar_t *wcscpy(wchar_t *dest, const wchar_t *src) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: wcscpy(%p, %p)\n", rtv, dest, src);
  size_t l = __libqasan_wcslen(src) + 1;
  QASAN_LOAD(src, l * sizeof(wchar_t));
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(src, l * sizeof(wchar_t), rtv);
#endif
  QASAN_STORE(dest, l * sizeof(wchar_t));
#ifdef MSAN_NO_LIB
  QMSAN_STORE(dest, l * sizeof(wchar_t));
#endif
  void *r = __libqasan_wcscpy(dest, src);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

int wcscmp(const wchar_t *s1, const wchar_t *s2) {

  void *rtv = __builtin_return_address(0);

  QASAN_DEBUG("%14p: wcscmp(%p, %p)\n", rtv, s1, s2);
  size_t l1 = __libqasan_wcslen(s1);
  QASAN_LOAD(s1, sizeof(wchar_t) * (l1 + 1));
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s1, sizeof(wchar_t) * (l1 + 1), rtv);
#endif
  size_t l2 = __libqasan_wcslen(s2);
  QASAN_LOAD(s2, sizeof(wchar_t) * (l2 + 1));
#ifdef MSAN_NO_LIB
  QMSAN_LOAD(s2, sizeof(wchar_t) * (l2 + 1), rtv);
#endif
  int r = __libqasan_wcscmp(s1, s2);
  QASAN_DEBUG("\t\t = %d\n", r);

  return r;

}



#ifdef MSAN_TAINT_ANALYSIS
typeof(&pthread_join) ptr_pthread_join;
int pthread_join(pthread_t thread, void **retval){

  int flag = (int) QMSAN_DISABLE();
  
  REAL(pthread_join);
  int r = ptr_pthread_join(thread, retval);

  QMSAN_STORE(retval, sizeof(void*));

  QMSAN_ENABLE(flag);
  return r;
  }
#endif

#if defined MSAN_NO_LIB || defined MSAN_TAINT_ANALYSIS

typedef struct wrapper_arg {
        void* (*start_routine)(void *args);
        void *args;
} wrapper_arg;

void* wrapper (void* args){
  void * ret;
  struct wrapper_arg* m = (struct wrapper_arg *) args;

  QMSAN_THREAD(m->start_routine);
  ret = m->start_routine(m->args);
  free(m);

  return ret;

}

typeof(&pthread_create) ptr_pthread_create;
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg){

  int flag = (int) QMSAN_DISABLE();

  //QMSAN_SILENCE();

  void *rtv = __builtin_return_address(0);
  //fprintf(stderr, "[%p]creating thread at address %p\n", rtv, start_routine);
  
  ptr_pthread_create = ASSERT_DLSYM(pthread_create);
  //REAL(pthread_create);
  struct wrapper_arg * a = (struct wrapper_arg *) malloc(sizeof(struct wrapper_arg));
  a->start_routine = start_routine;
  a->args = arg;
  QMSAN_STORE(a, sizeof(struct wrapper_arg));
  int r = ptr_pthread_create(thread, attr, wrapper, a);

  QMSAN_STORE(thread, sizeof(pthread_t));

  QMSAN_ENABLE(flag);
  return r;
  }


typeof(&popen) ptr_popen;
FILE *popen(const char *command, const char *type){

  int flag = (int) QMSAN_DISABLE();
  void *rtv = __builtin_return_address(0);

  // fprintf(stderr, "[%p]popen(%p, %p)\n", rtv, command, type);
  // if(command)
  //   fprintf(stderr, "\t\tCommand = %s\n", command);
  
  REAL(popen);
  FILE * ret = ptr_popen(command, type);

  QMSAN_ENABLE(flag);

  return ret;
}

typeof(&exit) ptr_exit;
void exit(int status){

  int flag = (int) QMSAN_DISABLE();
  
  REAL(exit);
  ptr_exit(status);

  //actually, the code down here is not going to be executed 

  QMSAN_ENABLE(flag);

}

typeof (&pthread_cond_wait) ptr_pthread_cond_wait;
int pthread_cond_wait(pthread_cond_t *restrict cond,pthread_mutex_t *restrict mutex){

  void *rtv = __builtin_return_address(0);

  int flag = (int) QMSAN_DISABLE();
  
  REAL(pthread_cond_wait);


  int res = ptr_pthread_cond_wait(cond, mutex);


  QMSAN_ENABLE(flag);
  
  QMSAN_LOAD(cond, sizeof(pthread_cond_t), rtv);
  QMSAN_LOAD(mutex, sizeof(pthread_mutex_t), rtv);

  return res;

}

#endif

//memory sanitizer specific interceptors
//we only use these in NO_LIB mode

#ifdef MSAN_NO_LIB



/*
typeof(&getenv) ptr_getenv;

char *getenv(const char *name) {

  REAL(getenv);

  void *rtv = __builtin_return_address(0);
  fprintf(stderr, "getenv\n");

  char *r = ptr_getenv(name);
  
  return r;

}*/
typeof(&fread) ptr_fread;

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *file) {

  REAL(fread);

  void *rtv = __builtin_return_address(0);

  size_t r = ptr_fread(ptr, size, nmemb, file);

  if(r>0)
    QMSAN_STORE(ptr, r*size);

  return r;

}

typeof(&wmemset) ptr_wmemset;

wchar_t *wmemset(wchar_t *wcs, wchar_t wc, size_t n) {

  REAL(wmemset);

  void *rtv = __builtin_return_address(0);

  wchar_t *r = ptr_wmemset(wcs, wc, n);

  QMSAN_STORE(wcs,  n);

  return r;

}

typeof(&wcsrtombs) ptr_wcsrtombs;
size_t wcsrtombs(char *dest, const wchar_t **src, size_t len, mbstate_t *ps){


  REAL(wcsrtombs);

  void *rtv = __builtin_return_address(0);

  if(*src)
    QMSAN_LOAD(*src, sizeof(wchar_t) * (__libqasan_wcslen(*src) + 1), rtv);

  size_t r = ptr_wcsrtombs(dest, src, len, ps);
  //fprintf(stderr, "[%p]wcsrtombs(%p, %p, %lu, %p)=%u\n", rtv, dest, src, len, ps, r);

  if(r > 0)
    QMSAN_STORE(dest, r + 1);
  
  return r;

}

typeof(&wmemmove) ptr_wmemmove;

wchar_t *wmemmove(wchar_t *dest, const wchar_t *src, size_t n) {

  REAL(wmemmove);

  void *rtv = __builtin_return_address(0);

  wchar_t *r = ptr_wmemmove(dest, src, n);

  QMSAN_CHECK_PROPAGATE(dest, *src, sizeof(wchar_t) * (__libqasan_wcslen(src) + 1));

  return r;

}

typeof(&readlink) ptr_readlink;

ssize_t readlink(const char *__restrict pathname, char *buf, size_t bufsiz) {

  REAL(readlink);

  void *rtv = __builtin_return_address(0);

  int r = ptr_readlink(pathname, buf, bufsiz);

  QMSAN_LOAD(pathname, __libqasan_strlen(pathname), rtv);

  if(r>0)
    QMSAN_STORE(buf, r);
  
  return r;

}
int __xstat64(int ver, const char * path, struct stat64 * stat_buf);
typeof(&__xstat64) ptr___xstat64;

int __xstat64(int ver, const char * path, struct stat64 * stat_buf) {

  REAL(__xstat64);

  void *rtv = __builtin_return_address(0);

  int r = ptr___xstat64(ver, path, stat_buf);

  QMSAN_LOAD(path, __libqasan_strlen(path), rtv);
  QMSAN_STORE(stat_buf, sizeof(struct stat64));

  return r;

}



void* (*ptr___memcpy_chk) (void*, const void*, size_t, size_t);

void * __memcpy_chk(void * dest, const void * src, size_t len, size_t destlen) {

  REAL(__memcpy_chk);

  QMSAN_CHECK_PROPAGATE(dest, src, len);

  void *rtv = __builtin_return_address(0);

  void *r = ptr___memcpy_chk(dest, src, len, destlen);

  return r;

}

char* (*ptr___strcat_chk)(char*, const char*, size_t);

char * __strcat_chk(char * dest, const char * src, size_t destlen) {

  REAL(__strcat_chk);

  void *rtv = __builtin_return_address(0);

  char *r = ptr___strcat_chk(dest, src, destlen);

  //appending to dest means reading dest
  QMSAN_LOAD(dest, __libqasan_strlen(dest) + 1, rtv);
  QMSAN_CHECK_PROPAGATE(dest + __libqasan_strlen(dest), src,
                        __libqasan_strlen(src) + 1);

  return r;

}

int (*ptr___sprintf_chk) (char*, int, size_t, const char*, ...);

int __sprintf_chk(char * str, int flag, size_t strlen, const char * format, ...) {

  int _flag = (int) QMSAN_DISABLE();

  REAL(__sprintf_chk);

  void *rtv = __builtin_return_address(0);
  //fprintf(stderr, "[%p]sprintf_chk(%p, %p)\n", rtv, str, format);

  int r = ptr___sprintf_chk(str, flag, strlen, format);

  QMSAN_STORE(str, r + 1);
  QMSAN_ENABLE(_flag);
  
  return r;

}

void* (*ptr___memset_chk) (void*, int, size_t, size_t);

void * __memset_chk(void * dest, int c, size_t len, size_t destlen) {

  REAL(__memset_chk);

  void *rtv = __builtin_return_address(0);

  void *r = ptr___memset_chk(dest, c, len, destlen);

  QMSAN_STORE(dest, len);

  return r;

}

typeof(&read) ptr_read;
ssize_t read(int fd, void *buf, size_t count){

  REAL(read);

  //fprintf(stderr, "read %p\n", buf);
  ssize_t ret = ptr_read(fd, buf, count);

  QMSAN_STORE(buf, ret);

  return ret;

}

void* (*ptr___memmove_chk) (void*, const void*, size_t, size_t);

void * __memmove_chk(void * dest, const void * src, size_t len, size_t destlen){

  REAL(__memmove_chk);

  void *rtv = __builtin_return_address(0);
  //fprintf(stderr, "[%p]memmove_chk(%p, %d, %lu)\n", rtv,  dest, src, n);

  void *r = ptr___memmove_chk(dest, src, len, destlen);

  QMSAN_CHECK_PROPAGATE(dest, src, len);

  return r;

}

char* (*ptr___strcpy_chk) (char*, const char*, size_t);

char * __strcpy_chk(char * dest, const char * src, size_t destlen) {

  REAL(__strcpy_chk);

  void *rtv = __builtin_return_address(0);
  //fprintf(stderr, "[%p]strcpy_chk(%p, %p)\n", rtv, dest, src);

  char *r = ptr___strcpy_chk(dest, src, destlen);

  QMSAN_CHECK_PROPAGATE(dest, src, __libqasan_strlen(src) + 1);

  return r;

}

char* (*ptr___strncpy_chk) (char*, const char*, size_t, size_t);

char * __strncpy_chk(char * s1, const char * s2, size_t n, size_t s1len) {

  REAL(__strncpy_chk);

  size_t l = __libqasan_strnlen(s2, n);

  if(l<n)
    QMSAN_CHECK_PROPAGATE(s1, s2, l+1);
  else
    QMSAN_CHECK_PROPAGATE(s1, s2, n);

  void *rtv = __builtin_return_address(0);
  //fprintf(stderr, "[%p]strncpy_chk(%p, %p, %zu, %zu)\n", rtv, s1, s2, n, s1len);

  char *r = ptr___strncpy_chk(s1, s2, n, s1len);

  return r;

}

char* (*ptr___stpcpy_chk) (char*, const char*, size_t);

char *__stpcpy_chk(char * dest, const char * src, size_t destlen) {

  void *rtv = __builtin_return_address(0);

  REAL(__stpcpy_chk);

  //fprintf(stderr, "%14p: stpcpy_chk(%p, %p, %zu)\n", rtv, dest, src, destlen);
  size_t l = __libqasan_strlen(src) + 1;
#ifdef MSAN_NO_LIB
    QMSAN_CHECK_PROPAGATE(dest, src, l);
#endif
  char *r = ptr___stpcpy_chk(dest, src, destlen);
  QASAN_DEBUG("\t\t = %p\n", r);

  return r;

}

// char *__strdup_chk(const char *s) {

//   void *rtv = __builtin_return_address(0);

//   fprintf(stderr, "%14p: strdup(%p)\n", rtv, s);
//   size_t l = __libqasan_strlen(s);
//   QASAN_LOAD(s, l + 1);
// #ifdef MSAN_NO_LIB
//   QMSAN_LOAD(s, l + 1, rtv);
// #endif
//   void *r = __libqasan_malloc(l + 1);
// #ifdef MSAN_NO_LIB
//     //if(r && s)
//     //QMSAN_CHECK_PROPAGATE(r, s, l+1);
// #endif
//   __libqasan_memcpy(r, s, l + 1);
//   QASAN_DEBUG("\t\t = %p\n", r);

//   return r;

// }


long strtol(const char *nptr, char **endptr, int base) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "%14p: strtol(%p, %p, %d)\n", rtv, nptr, endptr, base);

  size_t l = __libqasan_strlen(nptr) + 1;
  QMSAN_LOAD(nptr, l, rtv);

  long r = __lq_libc_strtol(nptr, endptr, base);
  QASAN_DEBUG("\t\t = %lld\n", r);

  return r;

}

long long strtoll(const char *nptr, char **endptr, int base) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "%14p: strtoll(%p, %p, %d)\n", rtv, nptr, endptr, base);
  
  size_t l = __libqasan_strlen(nptr) + 1;
  QMSAN_LOAD(nptr, l, rtv);

  long long r = __lq_libc_strtoll(nptr, endptr, base);
  QASAN_DEBUG("\t\t = %lld\n", r);

  return r;

}

unsigned long strtoul(const char *nptr, char **endptr, int base) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "%14p: strtoul(%p, %p, %d)\n", rtv, nptr, endptr, base);
  
  size_t l = __libqasan_strlen(nptr) + 1;
  QMSAN_LOAD(nptr, l, rtv);

  unsigned long r = __lq_libc_strtoul(nptr, endptr, base);
  QASAN_DEBUG("\t\t = %lld\n", r);

  return r;

}

double strtod(const char *nptr, char **endptr) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "%14p: strtoll(%p, %p)\n", rtv, nptr, endptr);
  
  size_t l = __libqasan_strlen(nptr) + 1;
  QMSAN_LOAD(nptr, l, rtv);

  double r = __lq_libc_strtod(nptr, endptr);
  QASAN_DEBUG("\t\t = %lld\n", r);

  return r;

}

char* strtok(char *str, const char *delim) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "%14p: strtok(%p, %p)\n", rtv, str, delim);
  
  size_t l = __libqasan_strlen(str) + 1;
  QMSAN_LOAD(str, l, rtv);

  char* r = __lq_libc_strtok(str, delim);
  QASAN_DEBUG("\t\t = %lld\n", r);

  return r;

}


typeof(&mbsrtowcs) ptr_mbsrtowcs;

size_t mbsrtowcs(wchar_t *dest, const char **src,
                         size_t len, mbstate_t *ps) {

  void *rtv = __builtin_return_address(0);
  size_t l = 0;
  if(*src){
    l = __libqasan_strlen(*src) + 1;
    QMSAN_LOAD(*src, (l + 1), rtv);
  }

  REAL(mbsrtowcs);
  size_t r = ptr_mbsrtowcs(dest, src, len, ps);
  //fprintf(stderr, "mbsrtowcs(%p, %p, %lu, %p) = %lu\n", dest, src, len, ps, r);

  if(l)
    QMSAN_STORE(dest, l * sizeof(wchar_t));

  return r;

}

size_t (*ptr___mbsrtowcs_chk) (wchar_t*, const char**, size_t, mbstate_t*, size_t);

size_t __mbsrtowcs_chk(wchar_t *dest, const char **src,
                          size_t len, mbstate_t *ps, size_t destlen){

  void *rtv = __builtin_return_address(0);
  size_t l = 0;
  if(*src){
    l = __libqasan_strlen(*src) + 1;
    QMSAN_LOAD(*src, (l + 1), rtv);
  }

  REAL(__mbsrtowcs_chk);
  size_t r = ptr___mbsrtowcs_chk(dest, src, len, ps, destlen);
  //fprintf(stderr, "__mbsrtowcs_chk(%p, %p, %lu, %p, %lu) = %lu\n", dest, src, len, ps, destlen, r);
  
  if(l)
    QMSAN_STORE(dest, l * sizeof(wchar_t));

  return r;

}

wchar_t* (*ptr___fgetws_chk) (wchar_t*, size_t, int, FILE*);

wchar_t * __fgetws_chk(wchar_t * ws, size_t size, int strsize, FILE * stream){


  REAL(__fgetws_chk);
  wchar_t* r = ptr___fgetws_chk(ws, size, strsize, stream);
  //fprintf(stderr, "__fgetws_chk(%p, %u, %d, %p) = %lu\n", ws, size, strsize, stream, r);

  size_t l = __libqasan_wcslen(r) + 1;
  QMSAN_STORE(r, l * sizeof(wchar_t));

  return r;

}

wchar_t* (*ptr___wcscat_chk) (wchar_t*, const wchar_t*, size_t);

wchar_t * __wcscat_chk(wchar_t * dest, const wchar_t * src, size_t destlen) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "__wcscat_chk(%p, %p)\n", dest, src);

  size_t l = __libqasan_wcslen(src) + 1;
  REAL(__wcscat_chk)

  wchar_t *r = ptr___wcscat_chk(dest, src, destlen);
  
  size_t dlen = __libqasan_wcslen(dest);
  size_t slen = __libqasan_wcslen(src);
  QMSAN_LOAD(dest, sizeof(wchar_t) * (dlen + 1), rtv);
  QMSAN_CHECK_PROPAGATE(dest + (sizeof(wchar_t) * dlen), src, sizeof(wchar_t) * slen);

  return r;

}

wchar_t* (*ptr___wcsncpy_chk) (wchar_t*, const wchar_t*, size_t, size_t);

wchar_t * __wcsncpy_chk(wchar_t * dest, const wchar_t * src, size_t n, size_t destlen) {

  //fprintf(stderr, "__wcsncpy_chk(%p, %p, %lu)\n", dest, src, n);

  void *rtv = __builtin_return_address(0);

  size_t l = wcsnlen(src, n) + 1;
  QMSAN_LOAD(src, l * sizeof(wchar_t), rtv);
  QMSAN_STORE(dest, (l+1) * sizeof(wchar_t));
  REAL(__wcsncpy_chk);
  wchar_t *r = ptr___wcsncpy_chk(dest, src, n, destlen);

  return r;

}

wchar_t* (*ptr___wcscpy_chk) (wchar_t*, const wchar_t*, size_t);

wchar_t * __wcscpy_chk(wchar_t * dest, const wchar_t * src, size_t n) {

  size_t l = __libqasan_wcslen(src) + 1;

  //fprintf(stderr, "__wcscpy_chk(%p, %p)\n", dest, src);

  QMSAN_STORE(dest, l * sizeof(wchar_t));

  REAL(__wcscpy_chk);
  wchar_t *r = ptr___wcscpy_chk(dest, src, n);

  return r;

}

typeof(&wcsdup) ptr_wcsdup;

wchar_t *wcsdup(const wchar_t *s) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "wcsdup(%p)\n", s);

  size_t l = __libqasan_wcslen(s) + 1;
  QMSAN_LOAD(s, l * sizeof(wchar_t), rtv);
  REAL(wcsdup)
  wchar_t *r = ptr_wcsdup(s);
  QMSAN_STORE(r, l * sizeof(wchar_t));

  return r;

}

typeof(&wcsncpy) ptr_wcsncpy;

wchar_t *wcsncpy(wchar_t *dest, const wchar_t *src, size_t n) {

  void *rtv = __builtin_return_address(0);
  size_t l = wcsnlen(src, n) + 1;
  //fprintf(stderr, "wcsncpy(%p, %p, %lu), len(src) = %lu\n", dest, src, n, l);

  QMSAN_LOAD(src, l * sizeof(wchar_t), rtv);
  //from the documentation:
  //If  the  length wcslen(src) is smaller than n, the remaining wide characters
  // in the array pointed to by dest are filled with null wide characters
  // i.e. we initialize n bytes
  QMSAN_STORE(dest, n * sizeof(wchar_t));
  REAL(wcsncpy);
  wchar_t *r = ptr_wcsncpy(dest, src, n);

  return r;

}


typeof(&wcscat) ptr_wcscat;

wchar_t *wcscat(wchar_t *dest, const wchar_t *src) {

  void *rtv = __builtin_return_address(0);
  
  //fprintf(stderr, "wcscat(%p, %p)\n", dest, src);

  size_t l = __libqasan_wcslen(src) + 1;
  REAL(wcscat);
  wchar_t *r = ptr_wcscat(dest, src);
  
  size_t dlen = __libqasan_wcslen(dest);
  size_t slen = __libqasan_wcslen(src);
  QMSAN_LOAD(dest, sizeof(wchar_t) * (dlen + 1), rtv);
  QMSAN_CHECK_PROPAGATE(dest + (sizeof(wchar_t) * dlen), src, sizeof(wchar_t) * slen);

  return r;

}

typeof(&wcsncat) ptr_wcsncat;

wchar_t *wcsncat(wchar_t *dest, const wchar_t *src, size_t n) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "wcsncat(%p, %p, %lu)\n", dest, src, n);

  size_t l = wcsnlen(src, n) + 1;
  REAL(wcsncat);
  wchar_t *r = ptr_wcsncat(dest, src, n);

  size_t dlen = __libqasan_wcslen(dest);
  size_t slen = __libqasan_wcslen(src);
  if (slen > n)
    slen = n;
  QMSAN_LOAD(dest, sizeof(wchar_t) * (dlen + 1), rtv);
  QMSAN_CHECK_PROPAGATE(dest + (sizeof(wchar_t) * dlen), src, sizeof(wchar_t) * slen);

  return r;

}

typeof(&wcsrchr) ptr_wcsrchr;

wchar_t *wcsrchr(const wchar_t *wcs, wchar_t wc) {

  void *rtv = __builtin_return_address(0);

  //fprintf(stderr, "wcsrchr(%p, %x)\n", wcs, wc);
  
  REAL(wcsrchr);
  void *r = ptr_wcsrchr(wcs, wc);

  size_t len = __libqasan_wcslen(wcs);
  QMSAN_LOAD(wcs, sizeof(wchar_t) * (len + 1), rtv);

  return r;

}

//new set of interceptors, directly from msan_interceptors.cc



typeof(&fread_unlocked) ptr_fread_unlocked;

size_t fread_unlocked(void *ptr, size_t size, size_t nmemb, FILE *file ){
  REAL(fread_unlocked)
  size_t res = ptr_fread_unlocked(ptr, size, nmemb, file);
  if (res > 0)
    QMSAN_STORE(ptr, res *size);
  return res;
}

typeof(&strdup) ptr___strdup;

char *__strdup(char *src ){

  void *rtv = __builtin_return_address(0);

  REAL(__strdup)
  char *dest = strdup(src);
  
  size_t slen = __libqasan_strlen(src);
  size_t dlen = __libqasan_strlen(dest);
  QMSAN_LOAD(src, slen + 1, rtv);
  QMSAN_CHECK_PROPAGATE(dest , src, slen + 1);

  return dest;
}

typeof(&strndup) ptr_strndup;

char *strndup(const char *src, size_t n ){
  REAL(strndup)
  size_t copy_size = __libqasan_strnlen(src, n);
  char *res = ptr_strndup(src, n);
  QMSAN_CHECK_PROPAGATE(res, src, copy_size);
  QMSAN_STORE(res, copy_size + 1); // \0
  return res;
}

typeof(&strndup) ptr___strndup;


char *__strndup(const char *src, size_t n ){
  REAL(__strndup)
  size_t copy_size = __libqasan_strnlen(src, n);
  char *res = ptr___strndup(src, n);
  QMSAN_CHECK_PROPAGATE(res, src, copy_size);
  QMSAN_STORE(res, copy_size + 1); // \0
  return res;
}

typeof(&gcvt) ptr_gcvt;

char *gcvt(double number, int ndigit, char *buf ){
  REAL(gcvt)
  char *res = ptr_gcvt(number, ndigit, buf);
  size_t n = __libqasan_strlen(buf);
  QMSAN_STORE(buf, n + 1);
  return res;
}

typeof(&strncat) ptr_strncat;


char *strncat(char *dest, const char *src, size_t n ){

  void *rtv = __builtin_return_address(0);

  REAL(strncat)
  size_t dest_size = __libqasan_strlen(dest);
  size_t copy_size = __libqasan_strnlen(src, n);
  __libqasan_memcpy(dest + dest_size, src, n);
  
  size_t dlen = __libqasan_strlen(dest);
  size_t slen = __libqasan_strlen(src);
  if(slen > n)
    slen = n;
  QMSAN_LOAD(dest, dlen + 1, rtv);
  QMSAN_CHECK_PROPAGATE(dest + dlen, src, slen);
  return dest + dest_size;
}

typeof(&vswprintf) ptr_vswprintf;

int vswprintf(wchar_t *str, size_t size, const wchar_t *format, va_list ap ){
  REAL(vswprintf)
  int res = ptr_vswprintf(str, size, format, ap);
  //fprintf(stderr, "vswprintf(%p, %p)=%d\n", str, format, res);
  if (res >= 0) {
    QMSAN_STORE(str, sizeof(wchar_t) * (res + 1));
  }
  return res;
}

typeof(&vsprintf) ptr_vsprintf;

int vsprintf(char *str, const char *format, va_list ap){
  REAL(vsprintf)
  int res = ptr_vsprintf(str, format, ap);
  //fprintf(stderr, "vsprintf(%p, %p)=%d\n", str, format, res);
  if (res >= 0) {
    QMSAN_STORE(str, (res + 1));
  }
  return res;
}

typeof(&vsnprintf) ptr_vsnprintf;

int vsnprintf(char *str, size_t size, const char *format, va_list ap){
  REAL(vsnprintf)
  int res = ptr_vsnprintf(str, size, format, ap);
  if (res >= 0) {
    QMSAN_STORE(str, (res + 1));
  }
  //fprintf(stderr, "vsnprintf(%p, %p)=%d\n", str, format, res);
  return res;
}

typeof(&swprintf) ptr_swprintf;

// int swprintf(wchar_t *str, size_t size, const wchar_t *format, ... ){
//   REAL(swprintf)
//   va_list ap;
//   va_start(ap, format);
//   int res = ptr_vswprintf(str, size, format, ap);
//   //fprintf(stderr, "swprintf(%p, %p)=%d\n", str, format, res);
//   va_end(ap);
//   if (res >= 0) {
//     QMSAN_STORE(str, sizeof(wchar_t) * (res + 1));
//   }
//   return res;
// }

typeof(&sprintf) ptr_sprintf;

int sprintf(char *str, const char *format, ...){
  REAL(vsprintf)
  va_list ap;
  va_start(ap, format);
  int res = ptr_vsprintf(str, format, ap);
  //fprintf(stderr, "sprintf_chk(%p, %p)=%d\n", str, format, res);
  va_end(ap);
  if (res >= 0) {
    QMSAN_STORE(str, (res + 1));
  }
  return res;
}

typeof(&snprintf) ptr_snprintf;

int snprintf(char *str, size_t size, const char *format, ...){
  REAL(vsnprintf)
  va_list ap;
  va_start(ap, format);
  int res = ptr_vsnprintf(str, size, format, ap);
  //fprintf(stderr, "snprintf(%p, %p)=%d\n", str, format, res);
  va_end(ap);
  if (res >= 0) {
    QMSAN_STORE(str, (res + 1));
  }
  return res;
}

typeof(&strxfrm) ptr_strxfrm;

size_t strxfrm(char *dest, const char *src, size_t n ){

  void *rtv = __builtin_return_address(0);

  REAL(strxfrm)
  QMSAN_LOAD(src, __libqasan_strlen(src) + 1, rtv);
  size_t res = ptr_strxfrm(dest, src, n);
  if (res < n) QMSAN_STORE(dest, res + 1);
  return res;
}

typeof(&strxfrm_l) ptr_strxfrm_l;

size_t strxfrm_l(char *dest, const char *src, size_t n, struct __locale_struct *loc ){

  void *rtv = __builtin_return_address(0);

  REAL(strxfrm_l)
  QMSAN_LOAD(src, __libqasan_strlen(src) + 1, rtv);
  size_t res = ptr_strxfrm_l(dest, src, n, loc);
  if (res < n) QMSAN_STORE(dest, res + 1);
  return res;
}

typeof(&mbtowc) ptr_mbtowc;


int mbtowc(wchar_t *dest, const char *src, size_t n ){

  void *rtv = __builtin_return_address(0);

  REAL(mbtowc)
  int res = ptr_mbtowc(dest, src, n);
  if(src)
    QMSAN_LOAD(src, __libqasan_strnlen(src, n), rtv);
  if (res != -1 && dest) QMSAN_STORE(dest, sizeof(wchar_t));
  return res;
}

typeof(&mbrtowc) ptr_mbrtowc;

size_t mbrtowc(wchar_t *dest, const char *src, size_t n, mbstate_t *ps ){

  void *rtv = __builtin_return_address(0);

  REAL(mbrtowc)
  size_t res = ptr_mbrtowc(dest, src, n, ps);
  //fprintf(stderr, "mvrtowc(%p %p, %d, %p)=%u\n", dest, src, n, ps, res);
  if(src)
    QMSAN_LOAD(src, __libqasan_strnlen(src, n), rtv);
  if (res != (size_t)-1 && dest) QMSAN_STORE(dest, sizeof(wchar_t));
  return res;
}

typeof(&wcschr) ptr_wcschr;
wchar_t *wcschr(const wchar_t *s, wchar_t wc){

  void *rtv = __builtin_return_address(0);

  REAL(wcschr)
  wchar_t *res = ptr_wcschr(s, wc);
  QMSAN_LOAD(s, sizeof(wchar_t) * __libqasan_wcslen(s), rtv);
  return res;
}

typeof(&wmemcpy) ptr_wmemcpy;

wchar_t *wmemcpy(wchar_t *dest, const wchar_t *src, size_t n ){
  REAL(wmemcpy)
  wchar_t *res = ptr_wmemcpy(dest, src, n);
  QMSAN_CHECK_PROPAGATE(dest, src, n * sizeof(wchar_t));
  return res;
}

typeof(&wmempcpy) ptr_wmempcpy;

wchar_t *wmempcpy(wchar_t *dest, const wchar_t *src, size_t n ){
  REAL(wmempcpy)
  wchar_t *res = ptr_wmempcpy(dest, src, n);
  QMSAN_CHECK_PROPAGATE(dest, src, n * sizeof(wchar_t));
  return res;
}

typeof(&gettimeofday) ptr_gettimeofday;

int gettimeofday(struct timeval *tv, void *tz ){
  REAL(gettimeofday)
  int res = ptr_gettimeofday(tv, tz);
  if (tv)
    QMSAN_STORE(tv, 16);
  if (tz)
    QMSAN_STORE(tz, 8);
  return res;
}

typeof(&fcvt) ptr_fcvt;

char *fcvt(double x, int a, int *b, int *c ){
  REAL(fcvt)
  char *res = ptr_fcvt(x, a, b, c);
  QMSAN_STORE(b, sizeof(*b));
  QMSAN_STORE(c, sizeof(*c));
  if (res) QMSAN_STORE(res, __libqasan_strlen(res) + 1);
  return res;
}

typeof(&pipe) ptr_pipe;

int pipe(int pipefd[2] ){
  REAL(pipe)
  int res = ptr_pipe(pipefd);
  if (!res)
    QMSAN_STORE(pipefd, sizeof(int[2]));
  return res;
}

typeof(&pipe2) ptr_pipe2;

int pipe2(int pipefd[2], int flags ){
  REAL(pipe2)
  int res = ptr_pipe2(pipefd, flags);
  if (!res)
    QMSAN_STORE(pipefd, sizeof(int[2]));
  return res;
}

typeof(&socketpair) ptr_socketpair;

int socketpair(int domain, int type, int protocol, int sv[2] ){
  REAL(socketpair)
  int res = ptr_socketpair(domain, type, protocol, sv);
  if (!res)
    QMSAN_STORE(sv, sizeof(int[2]));
  return res;
}

typeof(&fgets_unlocked) ptr_fgets_unlocked;

char *fgets_unlocked(char *s, int size, FILE *stream ){
  REAL(fgets_unlocked)
  char *res = ptr_fgets_unlocked(s, size, stream);
  if (res)
    QMSAN_STORE(s, __libqasan_strlen(s) + 1);
  return res;
}

typeof(&getrlimit) ptr_getrlimit;

int getrlimit(__rlimit_resource_t resource, struct rlimit *rlim ){
  REAL(getrlimit)
  int res = ptr_getrlimit(resource, rlim);
  if (!res)
    QMSAN_STORE(rlim, sizeof(struct rlimit));
  return res;
}

typeof(&getrlimit64) ptr_getrlimit64;

int getrlimit64(__rlimit_resource_t resource, struct rlimit64 *rlim ){
  REAL(getrlimit64)
  int res = ptr_getrlimit64(resource, rlim);
  if (!res)
    QMSAN_STORE(rlim, sizeof(struct rlimit64));
  return res;
}

typeof(&uname) ptr_uname;

int uname(struct utsname *utsname ){
  REAL(uname)
  int res = ptr_uname(utsname);
  if (!res)
    QMSAN_STORE(utsname, sizeof(struct utsname));
  return res;
}

typeof(&gethostname) ptr_gethostname;

int gethostname(char *name, size_t len ){
  REAL(gethostname)
  int res = ptr_gethostname(name, len);
  if (!res) {
    size_t real_len = __libqasan_strnlen(name, len);
    if (real_len < len)
      ++real_len;
    QMSAN_STORE(name, real_len);
  }
  return res;
}

typeof(&recv) ptr_recv;

ssize_t recv(int fd, void *buf, size_t len, int flags ){
  REAL(recv)
  ssize_t res = ptr_recv(fd, buf, len, flags);
  if (res > 0)
    QMSAN_STORE(buf, res);
  return res;
}

typeof(&recvfrom) ptr_recvfrom;

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *srcaddr,
                 socklen_t *addrlen ){
  REAL(recvfrom)
  size_t srcaddr_sz;
  if (srcaddr) srcaddr_sz = *addrlen;
  ssize_t res = ptr_recvfrom(fd, buf, len, flags, srcaddr, addrlen);
  if (res > 0) {
    QMSAN_STORE(buf, res);
    if (srcaddr) {
      size_t sz = *addrlen;
      QMSAN_STORE(srcaddr, (sz < srcaddr_sz) ? sz : srcaddr_sz);
    }
  }
  return res;
}

typeof(&dladdr) ptr_dladdr;;

int dladdr(const void *addr, Dl_info *info ){
  REAL(dladdr)
  int res = ptr_dladdr(addr, info);
  if (res != 0) {
    QMSAN_STORE(info, sizeof(*info));
    if (info->dli_fname)
      QMSAN_STORE(info->dli_fname, __libqasan_strlen(info->dli_fname) + 1);
    if (info->dli_sname)
      QMSAN_STORE(info->dli_sname, __libqasan_strlen(info->dli_sname) + 1);
  }
  return res;
}

typeof(&dlerror) ptr_dlerror;

char *dlerror(){
  REAL(dlerror)
  char *res = ptr_dlerror();
  if (res != 0) QMSAN_STORE(res, __libqasan_strlen(res) + 1);
  return res;
}


#endif