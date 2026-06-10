#ifndef SIGBP_H
#define SIGBP_H

#define _GNU_SOURCE
#include <signal.h>
#include <ucontext.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*BpCallback)(ucontext_t *ctx, siginfo_t *info);

// callFirst: non-zero to save/chain previous SIGTRAP handler
int   SigBp_Init(int callFirst);
void  SigBp_Uninit(void);

// Returns handle (>= 0) on success, -1 on failure
int   SigBp_Set(void *address, BpCallback callback);
int   SigBp_Remove(int handle);

void  SigBp_Disable(int handle);
void  SigBp_Enable(int handle);

#ifdef __cplusplus
}
#endif

#endif
