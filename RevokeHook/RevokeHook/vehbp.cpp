#include "vehbp.h"
#include <intrin.h>

// -----------------------------------------------------------------------
// 内部数据结构
// -----------------------------------------------------------------------

#define MAX_BREAKPOINTS 64

struct Breakpoint {
    LPVOID      address;        // 断点地址
    BYTE        originalByte;   // 被 0xCC 替换掉的原字节
    BpCallback  callback;       // 用户回调
    BOOL        active;         // 已安装且未被 Remove
    BOOL        enabled;        // FALSE 时命中后跳过回调(仍单步恢复)
};

static Breakpoint   g_bp[MAX_BREAKPOINTS] = {};
static int          g_bpCount = 0;
static PVOID        g_vehHandle = nullptr;

// 单步恢复期间记录正在等待恢复的断点索引(-1 表示无)
// 注意：多线程场景下每条线程各自触发，此处用 TLS 更严谨;
//       若目标是单线程或已有外部序列化, 简单 volatile int 足够.
static volatile LONG g_pendingSingleStep = -1;

// -----------------------------------------------------------------------
// 内部辅助：强制可写后写一个字节，再还原保护
// -----------------------------------------------------------------------
static BOOL WriteByte(LPVOID addr, BYTE val)
{
    DWORD oldProt = 0;
    if (!VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;

    *(volatile BYTE*)addr = val;
    FlushInstructionCache(GetCurrentProcess(), addr, 1);

    VirtualProtect(addr, 1, oldProt, &oldProt);
    return TRUE;
}

// -----------------------------------------------------------------------
// 内部辅助：按地址查找断点表项索引
// -----------------------------------------------------------------------
static int FindBpByAddr(LPVOID addr)
{
    for (int i = 0; i < g_bpCount; i++)
    {
        if (g_bp[i].active && g_bp[i].address == addr)
            return i;
    }
    return -1;
}

// -----------------------------------------------------------------------
// VEH 核心处理函数
// -----------------------------------------------------------------------
static LONG CALLBACK VEHHandler(PEXCEPTION_POINTERS pExInfo)
{
    PEXCEPTION_RECORD exRec = pExInfo->ExceptionRecord;
    PCONTEXT          ctx = pExInfo->ContextRecord;

    // ── 1. 软断点命中 ──────────────────────────────────────────────────
    if (exRec->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        // ExceptionAddress 就是触发 INT3 的地址（Rip/Eip 此时已经+1）
        // 所以断点地址 = ExceptionAddress
        LPVOID bpAddr = exRec->ExceptionAddress;

        int idx = FindBpByAddr(bpAddr);
        if (idx < 0)
            return EXCEPTION_CONTINUE_SEARCH; // 不是我们的断点

        Breakpoint& bp = g_bp[idx];

        // 恢复原字节, 准备让 CPU 真正执行原始指令
        WriteByte(bpAddr, bp.originalByte);

        // 把 IP 拨回断点地址, 让 CPU 重新执行原始指令
        // (Windows 的 EXCEPTION_BREAKPOINT 时 Rip 已经指向 INT3 后一字节, 
        //   所以要回退 1 字节)
#ifdef _WIN64
        ctx->Rip = (ULONG64)bpAddr;
#else
        ctx->Eip = (DWORD)(ULONG_PTR)bpAddr;
#endif

        // 调用用户回调
        if (bp.enabled && bp.callback)
            bp.callback(ctx, exRec);

        // 设置单步标志 TF, 原始指令执行完后立刻再次触发异常
        ctx->EFlags |= 0x100;
        InterlockedExchange(&g_pendingSingleStep, (LONG)idx);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ── 2. 单步命中：重装断点 ───────────────────────────────────────────
    if (exRec->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        LONG idx = InterlockedExchange(&g_pendingSingleStep, -1);
        if (idx >= 0 && idx < g_bpCount && g_bp[idx].active)
        {
            // 清除 TF，避免连续单步
            ctx->EFlags &= ~0x100UL;

            // 重新写入 0xCC
            WriteByte(g_bp[idx].address, 0xCC);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // 不是我们引发的单步，交给后续处理器
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// -----------------------------------------------------------------------
// 公开 API 实现
// -----------------------------------------------------------------------

BOOL VehBp_Init(BOOL callFirst)
{
    if (g_vehHandle)
        return TRUE; // 已初始化

    g_vehHandle = AddVectoredExceptionHandler(callFirst ? 1 : 0, VEHHandler);
    return g_vehHandle != nullptr;
}

void VehBp_Uninit(void)
{
    if (!g_vehHandle)
        return;

    // 先移除所有断点，恢复原始字节
    for (int i = 0; i < g_bpCount; i++)
    {
        if (g_bp[i].active)
        {
            WriteByte(g_bp[i].address, g_bp[i].originalByte);
            g_bp[i].active = FALSE;
        }
    }
    g_bpCount = 0;

    RemoveVectoredExceptionHandler(g_vehHandle);
    g_vehHandle = nullptr;
}

int VehBp_Set(LPVOID address, BpCallback callback)
{
    if (!g_vehHandle || !address)
        return -1;

    // 不允许在同一地址重复安装
    if (FindBpByAddr(address) >= 0)
        return -1;

    if (g_bpCount >= MAX_BREAKPOINTS)
        return -1;

    int idx = g_bpCount++;
    Breakpoint& bp = g_bp[idx];
    bp.address = address;
    bp.originalByte = *(BYTE*)address;   // 读取原始字节
    bp.callback = callback;
    bp.active = TRUE;
    bp.enabled = TRUE;

    // 写入 INT3
    if (!WriteByte(address, 0xCC))
    {
        bp.active = FALSE;
        g_bpCount--;
        return -1;
    }

    return idx;
}

BOOL VehBp_Remove(int handle)
{
    if (handle < 0 || handle >= g_bpCount)
        return FALSE;

    Breakpoint& bp = g_bp[handle];
    if (!bp.active)
        return FALSE;

    WriteByte(bp.address, bp.originalByte);
    bp.active = FALSE;
    bp.enabled = FALSE;
    return TRUE;
}

void VehBp_Disable(int handle)
{
    if (handle >= 0 && handle < g_bpCount && g_bp[handle].active)
        g_bp[handle].enabled = FALSE;
}

void VehBp_Enable(int handle)
{
    if (handle >= 0 && handle < g_bpCount && g_bp[handle].active)
        g_bp[handle].enabled = TRUE;
}
