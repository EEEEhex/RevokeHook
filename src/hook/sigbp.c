#define _GNU_SOURCE
#include "sigbp.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

// -----------------------------------------------------------------------
// Internal data structures
// -----------------------------------------------------------------------

#define MAX_BREAKPOINTS 64

struct Breakpoint {
    void       *address;
    uint8_t     originalByte;
    BpCallback  callback;
    int         active;
    int         enabled;
};

static struct Breakpoint g_bp[MAX_BREAKPOINTS];
static int               g_bpCount      = 0;
static int               g_initialized  = 0;
static struct sigaction   g_oldSigaction;

static pthread_key_t     g_tlsKey;
static int               g_tlsKeyCreated = 0;

// -----------------------------------------------------------------------
// TLS helpers: per-thread pending single-step tracking
// Store (index + 1) so that NULL (0) means "no pending"
// -----------------------------------------------------------------------

static int SetPendingSingleStepForThread(int idx)
{
    if (!g_tlsKeyCreated)
        return 0;
    return pthread_setspecific(g_tlsKey, (void *)(intptr_t)(idx + 1)) == 0;
}

static int GetPendingSingleStepForThread(void)
{
    if (!g_tlsKeyCreated)
        return -1;
    intptr_t value = (intptr_t)pthread_getspecific(g_tlsKey);
    return value == 0 ? -1 : (int)(value - 1);
}

static void ClearPendingSingleStepForThread(void)
{
    if (g_tlsKeyCreated)
        pthread_setspecific(g_tlsKey, NULL);
}

// -----------------------------------------------------------------------
// WriteByte: temporarily make page rwx, write one byte, restore to r-x
// mprotect is async-signal-safe (POSIX), safe to call from signal handler
// -----------------------------------------------------------------------

static int WriteByte(void *addr, uint8_t val)
{
    long pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(pagesize - 1);

    if (mprotect((void *)page, (size_t)pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return 0;

    *(volatile uint8_t *)addr = val;
    __builtin___clear_cache((char *)addr, (char *)addr + 1);

    mprotect((void *)page, (size_t)pagesize, PROT_READ | PROT_EXEC);
    return 1;
}

// -----------------------------------------------------------------------
// FindBpByAddr
// -----------------------------------------------------------------------

static int FindBpByAddr(void *addr)
{
    for (int i = 0; i < g_bpCount; i++) {
        if (g_bp[i].active && g_bp[i].address == addr)
            return i;
    }
    return -1;
}

// -----------------------------------------------------------------------
// SIGTRAP handler (replaces VEHHandler)
//
// Both INT3 and single-step (TF) deliver SIGTRAP on Linux.
// We disambiguate by checking the per-thread TLS state first:
//   - If a single-step is pending -> Phase 2 (re-arm breakpoint)
//   - Otherwise, look up address  -> Phase 1 (breakpoint hit)
// -----------------------------------------------------------------------

static void SigTrapHandler(int sig, siginfo_t *info, void *context)
{
    ucontext_t *uc = (ucontext_t *)context;

    // -- Phase 2: single-step completed, re-arm the breakpoint -----------
    int pendingIdx = GetPendingSingleStepForThread();
    if (pendingIdx >= 0 && pendingIdx < g_bpCount && g_bp[pendingIdx].active) {
        ClearPendingSingleStepForThread();

        uc->uc_mcontext.gregs[REG_EFL] &= ~0x100UL;

        WriteByte(g_bp[pendingIdx].address, 0xCC);
        return;
    }

    // -- Phase 1: INT3 breakpoint hit ------------------------------------
    // RIP points one byte past the INT3 opcode
    void *bpAddr = (void *)((uintptr_t)uc->uc_mcontext.gregs[REG_RIP] - 1);

    int idx = FindBpByAddr(bpAddr);
    if (idx < 0) {
        // Not ours — chain to previous handler
        if (g_oldSigaction.sa_flags & SA_SIGINFO) {
            if (g_oldSigaction.sa_sigaction)
                g_oldSigaction.sa_sigaction(sig, info, context);
        } else if (g_oldSigaction.sa_handler != SIG_DFL &&
                   g_oldSigaction.sa_handler != SIG_IGN) {
            g_oldSigaction.sa_handler(sig);
        }
        return;
    }

    struct Breakpoint *bp = &g_bp[idx];

    // Restore the original byte so the CPU can execute the real instruction
    WriteByte(bpAddr, bp->originalByte);

    // Rewind RIP to the breakpoint address
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)bpAddr;

    // Invoke user callback (may modify registers freely)
    if (bp->enabled && bp->callback)
        bp->callback(uc, info);

    // Arm single-step: execute one instruction, then trap again
    uc->uc_mcontext.gregs[REG_EFL] |= 0x100;
    SetPendingSingleStepForThread(idx);
}

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

int SigBp_Init(int callFirst)
{
    if (g_initialized)
        return 1;

    if (!g_tlsKeyCreated) {
        if (pthread_key_create(&g_tlsKey, NULL) != 0)
            return 0;
        g_tlsKeyCreated = 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = SigTrapHandler;
    sa.sa_flags     = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTRAP, &sa, callFirst ? &g_oldSigaction : NULL) != 0) {
        pthread_key_delete(g_tlsKey);
        g_tlsKeyCreated = 0;
        return 0;
    }

    g_initialized = 1;
    return 1;
}

void SigBp_Uninit(void)
{
    if (!g_initialized)
        return;

    for (int i = 0; i < g_bpCount; i++) {
        if (g_bp[i].active) {
            WriteByte(g_bp[i].address, g_bp[i].originalByte);
            g_bp[i].active = 0;
        }
    }
    g_bpCount = 0;

    // Restore previous SIGTRAP handler
    sigaction(SIGTRAP, &g_oldSigaction, NULL);
    g_initialized = 0;

    if (g_tlsKeyCreated) {
        pthread_key_delete(g_tlsKey);
        g_tlsKeyCreated = 0;
    }
}

int SigBp_Set(void *address, BpCallback callback)
{
    if (!g_initialized || !address)
        return -1;

    if (FindBpByAddr(address) >= 0)
        return -1;

    if (g_bpCount >= MAX_BREAKPOINTS)
        return -1;

    int idx = g_bpCount++;
    struct Breakpoint *bp = &g_bp[idx];
    bp->address      = address;
    bp->originalByte = *(uint8_t *)address;
    bp->callback     = callback;
    bp->active       = 1;
    bp->enabled      = 1;

    if (!WriteByte(address, 0xCC)) {
        bp->active = 0;
        g_bpCount--;
        return -1;
    }

    return idx;
}

int SigBp_Remove(int handle)
{
    if (handle < 0 || handle >= g_bpCount)
        return 0;

    struct Breakpoint *bp = &g_bp[handle];
    if (!bp->active)
        return 0;

    WriteByte(bp->address, bp->originalByte);
    bp->active  = 0;
    bp->enabled = 0;
    return 1;
}

void SigBp_Disable(int handle)
{
    if (handle >= 0 && handle < g_bpCount && g_bp[handle].active)
        g_bp[handle].enabled = 0;
}

void SigBp_Enable(int handle)
{
    if (handle >= 0 && handle < g_bpCount && g_bp[handle].active)
        g_bp[handle].enabled = 1;
}
