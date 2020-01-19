#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ipc.h>
#include <sys/time.h>
#include <sched.h>
#include "android-ashmem.h"

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define MAX_ALLOC           0x40000000

#define SAYF(x...)    printf(x)

#define PFATAL(x...) do { \
    fflush(stdout); \
    SAYF("\n[-]  SYSTEM ERROR : " x); \
    SAYF("\n    Stop location : %s(), %s:%u\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    SAYF("       OS message : %s\n", strerror(errno)); \
    exit(1); \
  } while (0)

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

static s32 shm_id;
static s32 forksrv_pid,
           child_pid = -1;
static u8* trace_bits;
static u8* target_path;
static s32 out_fd,
           fsrv_ctl_fd,
           fsrv_st_fd;

#define ALLOC_MAGIC_C1  0xFF00FF00 /* Used head (dword)  */
#define ALLOC_MAGIC_F   0xFE00FE00 /* Freed head (dword) */
#define ALLOC_MAGIC_C2  0xF0       /* Used tail (byte)   */

#define ALLOC_C1(_ptr)  (((u32*)(_ptr))[-2])
#define ALLOC_S(_ptr)   (((u32*)(_ptr))[-1])
#define ALLOC_C2(_ptr)  (((u8*)(_ptr))[ALLOC_S(_ptr)])

#define ALLOC_OFF_HEAD  8
#define ALLOC_OFF_TOTAL (ALLOC_OFF_HEAD + 1)

#define ABORT(x...) do { \
    SAYF("\n[-] PROGRAM ABORT : " x); \
    SAYF("\n    Stop location : %s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    abort(); \
  } while (0)

#define FATAL(x...) do { \
    SAYF("\n[-] PROGRAM ABORT : " x); \
    SAYF("\n         Location : %s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } while (0)

#define CHECK_PTR(_p) do { \
    if (_p) { \
      if (ALLOC_C1(_p) ^ ALLOC_MAGIC_C1) {\
        if (ALLOC_C1(_p) == ALLOC_MAGIC_F) \
          ABORT("Use after free."); \
        else ABORT("Corrupted head alloc canary."); \
      } \
      if (ALLOC_C2(_p) ^ ALLOC_MAGIC_C2) \
        ABORT("Corrupted tail alloc canary."); \
    } \
  } while (0)

#define ALLOC_CHECK_SIZE(_s) do { \
    if ((_s) > MAX_ALLOC) \
      ABORT("Bad alloc request: %u bytes", (_s)); \
  } while (0)

#define ALLOC_CHECK_RESULT(_r, _s) do { \
    if (!(_r)) \
      ABORT("Out of memory: can't allocate %u bytes", (_s)); \
  } while (0)

static inline void* DFL_ck_alloc_nozero(u32 size) {

  void* ret;

  if (!size) return NULL;

  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + ALLOC_OFF_TOTAL);
  ALLOC_CHECK_RESULT(ret, size);

  ret += ALLOC_OFF_HEAD;

  ALLOC_C1(ret) = ALLOC_MAGIC_C1;
  ALLOC_S(ret)  = size;
  ALLOC_C2(ret) = ALLOC_MAGIC_C2;

  return ret;

}

static inline void* DFL_ck_alloc(u32 size) {

  void* mem;

  if (!size) return NULL;
  mem = DFL_ck_alloc_nozero(size);

  return memset(mem, 0, size);

}

#define ck_alloc          DFL_ck_alloc
#define ck_free           DFL_ck_free

static inline void DFL_ck_free(void* mem) {

  if (!mem) return;

  CHECK_PTR(mem);

#ifdef DEBUG_BUILD

  /* Catch pointer issues sooner. */
  memset(mem, 0xFF, ALLOC_S(mem));

#endif /* DEBUG_BUILD */

  ALLOC_C1(mem) = ALLOC_MAGIC_F;

  free(mem - ALLOC_OFF_HEAD);

}

void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);

}

#define alloc_printf(_str...) ({ \
    u8* _tmp; \
    s32 _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

void setup_shm(void) {
  u8* shm_str;

  if (!getenv(SHM_ENV_VAR)) {
    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) PFATAL("shmget() failed");
    atexit(remove_shm);

    shm_str = alloc_printf("%d", shm_id);
    if (!getenv("AFL_DUMB_MODE")) setenv(SHM_ENV_VAR, shm_str, 1);

    ck_free(shm_str);
  } else {
    shm_str = getenv(SHM_ENV_VAR);
    shm_id = atoi(shm_str);
  }

  trace_bits = shmat(shm_id, NULL, 0);

  if (!trace_bits) PFATAL("shmat() failed");
}

void set_affinity(int cpu) {
  pid_t pid = getpid();
  cpu_set_t c;

  CPU_ZERO(&c);
  CPU_SET(cpu, &c);

  if (sched_setaffinity(pid, sizeof(cpu_set_t), &c) == -1) {
    printf("%s: sched_setaffinity failed\n", __func__);
  }
}
