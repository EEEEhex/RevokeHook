#include "framework.h"
#include <wincrypt.h>

#include <tchar.h>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <share.h>
#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>

#include "vehbp.h"

//用于读取ini配置
#include "inicpp.h"

//用于计算MD5
#pragma comment(lib, "crypt32.lib")

// ---------------------------------------------------------------------------
// 文件日志系统 (仿照 Linux 版 revokehook.cpp)
// 日志路径: %USERPROFILE%\Documents\RevokeHook\revokehook.log
// 可通过环境变量 REVOKEHOOK_LOG 覆盖
// ---------------------------------------------------------------------------

// Forward declarations for globals used by log functions
extern bool g_output_debeug_msg;

static FILE* g_logfile = nullptr;

static void LogInit()
{
    if (g_logfile) return;

    char log_path[MAX_PATH] = { 0 };
    const char* env_path = nullptr;

    // 优先使用环境变量指定的路径
    char env_buf[MAX_PATH] = { 0 };
    DWORD env_len = GetEnvironmentVariableA("REVOKEHOOK_LOG", env_buf, MAX_PATH);
    if (env_len > 0 && env_len < MAX_PATH)
        env_path = env_buf;

    if (env_path && env_path[0])
    {
        strcpy_s(log_path, env_path);
    }
    else
    {
        // 默认路径: %USERPROFILE%\Documents\RevokeHook\revokehook.log
        char user_profile[MAX_PATH] = { 0 };
        DWORD len = GetEnvironmentVariableA("USERPROFILE", user_profile, MAX_PATH);
        if (len > 0)
        {
            snprintf(log_path, MAX_PATH, "%s\\Documents\\RevokeHook\\revokehook.log", user_profile);
            // 确保目录存在
            char dir_path[MAX_PATH];
            snprintf(dir_path, MAX_PATH, "%s\\Documents\\RevokeHook", user_profile);
            CreateDirectoryA(dir_path, NULL);
        }
        else
        {
            // 最终回退
            GetTempPathA(MAX_PATH, log_path);
            strcat_s(log_path, "revokehook.log");
        }
    }

    // 使用 _fsopen 允许其他进程同时读取日志文件
    g_logfile = _fsopen(log_path, "a", _SH_DENYWR);
    if (g_logfile)
    {
        time_t now = time(nullptr);
        char time_buf[64];
        ctime_s(time_buf, sizeof(time_buf), &now);
        fprintf(g_logfile, "=== RevokeHook Log Start: %s", time_buf);
        fflush(g_logfile);
    }
}

static void LogPrintf(const char* fmt, ...)
{
    if (!g_logfile) return;

    time_t now = time(nullptr);
    char time_buf[64];
    ctime_s(time_buf, sizeof(time_buf), &now);
    // 去掉 ctime_s 末尾的换行符
    for (int i = 0; i < 64; i++) { if (time_buf[i] == '\n') { time_buf[i] = ' '; break; } }

    fprintf(g_logfile, "%s", time_buf);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_logfile, fmt, ap);
    va_end(ap);
    fprintf(g_logfile, "\n");
    fflush(g_logfile);
}

// Note: DebugPrintf functionality is merged into OutputDebugPrintf
// g_output_debeug_msg is checked inside OutputDebugPrintf

// 实际使用的 DebugPrintf - 由OutputDebugPrintf替换
#define OUT_DEBUG_BUF_LEN   512

static void OutputDebugPrintf(const char* strOutputString, ...)
{
    if (!g_output_debeug_msg) return;

    char strBuffer[OUT_DEBUG_BUF_LEN] = { 0 };
    va_list vlArgs;
    va_start(vlArgs, strOutputString);
    _vsnprintf_s(strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);
    va_end(vlArgs);

    // 同时输出到 DebugView 和日志文件
    OutputDebugStringA(strBuffer);

    if (g_logfile)
    {
        time_t now = time(nullptr);
        char time_buf[64];
        ctime_s(time_buf, sizeof(time_buf), &now);
        for (int i = 0; i < 64; i++) { if (time_buf[i] == '\n') { time_buf[i] = ' '; break; } }
        fprintf(g_logfile, "%s[Debug] %s\n", time_buf, strBuffer);
        fflush(g_logfile);
    }
}

static void LogClose()
{
    if (g_logfile)
    {
        time_t now = time(nullptr);
        char time_buf[64];
        ctime_s(time_buf, sizeof(time_buf), &now);
        fprintf(g_logfile, "=== RevokeHook Log End: %s\n", time_buf);
        fclose(g_logfile);
        g_logfile = nullptr;
    }
}

//VEH + INT3断点
static void* g_bpDelMsg = nullptr;
static void* g_bpAdd2DB = nullptr;

static DWORD g_tlsThreadState = TLS_OUT_OF_INDEXES;
struct ThreadState
{
    uint8_t last_org_srvid[8];      //真实的srvid 防止插入两条撤回提醒
    uint8_t anti_revoke_cur_msg;    //是否防撤回当前这条消息
    // 撤回提醒追踪
    uint8_t last_sender_hash[8];    // 上一个撤回者的MD5(用于计数去重)
    int revoke_count;               // 连续撤回计数
    DWORD last_revoke_tick;         // 上次撤回时间(GetTickCount)
};

static ThreadState* GetThreadState()
{
    if (g_tlsThreadState == TLS_OUT_OF_INDEXES)
        return nullptr;

    ThreadState* state = reinterpret_cast<ThreadState*>(TlsGetValue(g_tlsThreadState));
    if (state != nullptr)
        return state;

    state = reinterpret_cast<ThreadState*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadState)));
    if (state == nullptr)
        return nullptr;

    if (!TlsSetValue(g_tlsThreadState, state))
    {
        HeapFree(GetProcessHeap(), 0, state);
        return nullptr;
    }

    return state;
}

static void FreeCurrentThreadState()
{
    if (g_tlsThreadState == TLS_OUT_OF_INDEXES)
        return;

    ThreadState* state = reinterpret_cast<ThreadState*>(TlsGetValue(g_tlsThreadState));
    if (state != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, state);
        TlsSetValue(g_tlsThreadState, nullptr);
    }
}

static bool InitThreadStateTls()
{
    if (g_tlsThreadState != TLS_OUT_OF_INDEXES)
        return true;

    g_tlsThreadState = TlsAlloc();
    return g_tlsThreadState != TLS_OUT_OF_INDEXES;
}

static void UninitThreadStateTls()
{
    FreeCurrentThreadState();

    if (g_tlsThreadState != TLS_OUT_OF_INDEXES)
    {
        TlsFree(g_tlsThreadState);
        g_tlsThreadState = TLS_OUT_OF_INDEXES;
    }
}

//配置信息
struct BASICINFO
{
    uint64_t imgbase;           // Weixin.dll的基址
	uint64_t add2db_offset;     // 将撤回消息添加到数据库的函数偏移
	uint64_t delmsg_offset;     // 删除要撤回消息函数的偏移
};

struct DELMSGINFO
{
    bool initialized;
    int arg_msg_index;      // 哪个参数(2/3/4)指向包含revoke_xml的结构体
    int offset_revoke_xml;  // StdString在结构体中的偏移
    int arg_notify_index;   // 哪个参数是notify标志(值为0的那个)
    int string_layout;      // StdString的内存布局类型
};

struct ADD2DBINFO
{
    bool initialized;
    int arg_bool_index;     // 哪个参数是bool标志(值为0的那个)
    int offset_srvid;       // srvid在r8结构体中的偏移
    int offset_revoke_xml;  // revoke_xml StdString在r8结构体中的偏移
    int string_layout;      // StdString的内存布局类型
};

struct CONFIGINFO
{
	BASICINFO basic_info;
	DELMSGINFO delmsg_info;
	ADD2DBINFO add2db_info;
}g_config_info;

//std::string的内存布局
struct StdString
{
    const char data_ptr[16];
    int64_t size;
    int64_t capability;
};

ini::IniFile g_config;      //ini配置

bool g_anti_revoke_self_msg = false; //是否防止自己撤回消息
bool g_output_debeug_msg = false; //是否输出调试信息
bool g_fallback_mode = false;     // 降级模式: 不解析消息内容, 直接跳过撤回
static int g_total_hit_count = 0; // 断点命中总次数（心跳用）
static int g_delmsg_search_fail_count = 0; // DelMsg 搜索失败次数

/**
 * @brief 计算字节数据的MD5值.
 * @param data 要计算的数据
 * @return MD5 16位
 */
std::vector<uint8_t> CalculateMD5(const std::vector<uint8_t>& data) {
    // 获取加密上下文
    HCRYPTPROV hCryptProv = NULL;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    // 创建MD5哈希对象
    HCRYPTPROV hHash = NULL;
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        return {};
    }

    // 输入数据
    if (!CryptHashData(hHash, data.data(), data.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return {};
    }

    //获取哈希值大小
    DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize, &dwCount, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return {};
    }

    // 获取哈希值
    std::vector<uint8_t> md5Hash(cbHashSize);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(&md5Hash[0]), &cbHashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return {};
    }

    // 清理
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);

    //取中间8个字节
    auto middle_start = md5Hash.begin() + 4;    //从第5个字节开始
    auto middle_end = middle_start + 8;         //取8个字节
    std::vector<uint8_t> md5Hash16(middle_start, middle_end);
    return md5Hash16;
}

/**
 * @brief 使用MD5计算出一个唯一的正数.
 * @return 字节序列
 */
std::vector<uint8_t> GetUniquePositiveValue()
{
    // 获取当前时间戳(毫秒级别)
    auto currentTime = std::chrono::high_resolution_clock::now().time_since_epoch().count();

    // 生成一个随机数(加盐)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    uint8_t randomValue = dis(gen);

    std::vector<uint8_t> uniqueData;//要MD5的数据
    uniqueData.push_back(static_cast<uint8_t>(currentTime & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 8) & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 16) & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 24) & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 32) & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 40) & 0xFF));
    uniqueData.push_back(randomValue);//加盐确保唯一

    std::vector<uint8_t> md5Result = CalculateMD5(uniqueData);
    if (md5Result.size() == 0) return {};

    //将0x123456第一个字节的最高位变为0, 确保是正数, 小端序实际存储中是最后一个字节
    uint8_t littleEndByte = md5Result.back();
    md5Result.back() = littleEndByte & 0x7F;// 0111 1111
    return md5Result;
}

/**
 * @brief 读取配置信息.
 */
bool ReadExternalConfig(char* ini_path)
{
    std::string ini_path_str = ini_path;

    //判断ini文件是否存在
    struct stat buffer;
    if (stat(ini_path, &buffer) != 0) {
        //从'文档'目录下读取配置文件
        char user_profile[MAX_PATH] = { 0 };  // 获取环境变量 USERPROFILE
        DWORD length = GetEnvironmentVariableA("USERPROFILE", user_profile, MAX_PATH);
        if (length == 0) {
            LogPrintf("[RevokeHook] GetEnvVar USERPROFILE Failed!");
            OutputDebugString(TEXT("[ReovkeHook] GetEnvVar USERPROFILE Failed!"));
            return false;
        }

        // 拼接 Documents 目录
        std::string documents_path = std::string(user_profile) + "\\Documents";
        std::string ini_path_str = documents_path + "\\RevokeHook\\RevokeHook.ini";
        if (stat(ini_path_str.c_str(), &buffer) != 0) {
            LogPrintf("[RevokeHook] Not Find ini file (tried: %s and %s)", ini_path, ini_path_str.c_str());
            OutputDebugString(TEXT("[ReovkeHook] Not Find ini file!"));
            return false;
        }
    }

    g_config.load(ini_path_str);
    LogPrintf("[RevokeHook] INI loaded: %s", ini_path_str.c_str());

    HMODULE weixin_dll_base = NULL;
    //加载当前dll的时候 Weixin.dll很可能还没有被加载
    for (int try_num = 0; try_num < 100; try_num++)
    {   //多次尝试 一共尝试100次 每次间隔300毫秒 即30秒
        weixin_dll_base = GetModuleHandle(_T("Weixin.dll"));
        if (weixin_dll_base != NULL)
            break;
        Sleep(300);
    }
    if (weixin_dll_base == NULL) {
        LogPrintf("[RevokeHook] Get Weixin.dll Base Failed after 30s!");
        OutputDebugString(TEXT("[RevokeHook] Get Weixin.dll Base Failed!"));
        return false;
    }

    g_config_info.basic_info.imgbase = (uint64_t)weixin_dll_base;
    g_config_info.basic_info.delmsg_offset = g_config["KeyFunc"]["DelMsgOffset"].as<int>();
    g_config_info.basic_info.add2db_offset = g_config["KeyFunc"]["Add2DBOffset"].as<int>();

    g_anti_revoke_self_msg = g_config["Setting"]["AntiRevokeSelf"].as<bool>();
    g_output_debeug_msg = g_config["Setting"]["OutputDebugMsg"].as<bool>();
    g_fallback_mode = g_config["Setting"]["FallbackMode"].as<bool>();

    LogPrintf("[RevokeHook] Weixin.dll base: %p", (void*)weixin_dll_base);
    LogPrintf("[RevokeHook] DelMsgOffset=0x%llX, Add2DBOffset=0x%llX",
        g_config_info.basic_info.delmsg_offset,
        g_config_info.basic_info.add2db_offset);
    LogPrintf("[RevokeHook] Settings: AntiRevokeSelf=%d, DebugMsg=%d, FallbackMode=%d",
        g_anti_revoke_self_msg, g_output_debeug_msg, g_fallback_mode);

    OutputDebugPrintf("[RevokeHook] Use ini: %s", ini_path_str.c_str());
    return true;
}

/**
 * @brief 获取第index个参数的值.
 * 
 * @param ctx 上下文信息
 * @param index 第几个参数, 从1开始
 * @return 寄存器/栈上的值
 */
uint64_t GetArgValue(PCONTEXT ctx, int index)
{
    uint64_t* stack_args;
    if (ctx == NULL || index <= 0)
    {
        return 0;
    }

    switch (index)
    {
    case 1:
        return ctx->Rcx;
    case 2:
        return ctx->Rdx;
    case 3:
        return ctx->R8;
    case 4:
        return ctx->R9;
    default:
        /*
         * MSVC x64 调用约定:
         * [RSP + 0x00] = shadow space slot 1
         * [RSP + 0x08] = shadow space slot 2
         * [RSP + 0x10] = shadow space slot 3
         * [RSP + 0x18] = shadow space slot 4
         * [RSP + 0x20] = 第5个参数
         */
        stack_args = (uint64_t*)(ctx->Rsp + 0x20);
        return stack_args[index - 5];
    }
}

int SetArgValue(PCONTEXT ctx, int index, uint64_t value)
{
    uint64_t* stack_args;

    if (ctx == NULL || index <= 0)
    {
        return 0;
    }

    switch (index)
    {
    case 1:
        ctx->Rcx = value;
        return 1;
    case 2:
        ctx->Rdx = value;
        return 1;
    case 3:
        ctx->R8 = value;
        return 1;
    case 4:
        ctx->R9 = value;
        return 1;
    default:
        stack_args = (uint64_t*)(ctx->Rsp + 0x20);
        stack_args[index - 5] = value;
        return 1;
    }
}

static bool IsMemoryReadable(const void* addr, size_t size)
{
    if (addr == nullptr || size == 0) return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return false;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        return false;

    uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return ((uintptr_t)addr + size) <= region_end;
}

// std::string 可能存在的两种内存布局
enum ProgramStringLayout {
    PROGRAM_STRING_UNKNOWN  = 0,
    PROGRAM_STRING_MSVC     = 1,   // [data_ptr(16), size(8), capacity(8)] — MSVC std::string
    PROGRAM_STRING_SIZE_PTR = 2,   // [size(8), data_ptr(8)] — 替代布局
};

// 归一化的字符串表示
struct ProgramString {
    uint64_t data_addr;
    uint64_t size;
};

static_assert(sizeof(ProgramString) == 16, "Unexpected ProgramString layout");

// 根据布局读取 ProgramString
static bool ReadProgramString(uint64_t addr, int layout, ProgramString* out)
{
    if (out == nullptr) return false;

    switch (layout)
    {
    case PROGRAM_STRING_MSVC:
    {
        // [data_ptr(16), size(8), capacity(8)]
        if (!IsMemoryReadable((void*)addr, 32)) return false;
        uint64_t data_ptr = *(uint64_t*)addr; // data_ptr 的前8字节即指针
        uint64_t size = *(uint64_t*)(addr + 16);
        uint64_t capacity = *(uint64_t*)(addr + 24);
        if (size > 0x10000 || capacity < size || capacity > 0x100000) return false;
        out->data_addr = data_ptr;
        out->size = size;
        return true;
    }
    case PROGRAM_STRING_SIZE_PTR:
    {
        // [size(8), data_ptr(8)]
        if (!IsMemoryReadable((void*)addr, 16)) return false;
        uint64_t size = *(uint64_t*)addr;
        uint64_t data_ptr = *(uint64_t*)(addr + 8);
        if (size == 0 || size > 0x10000 || data_ptr == 0) return false;
        out->data_addr = data_ptr;
        out->size = size;
        return true;
    }
    default:
        return false;
    }
}

// 双布局 StdString 搜索 — 参考 Linux 版 FindProgramStringWithSig
static bool FindProgramStringWithSig(uint64_t base_addr, size_t scan_range,
    const uint8_t* sig, size_t sig_len,
    uint64_t* found_addr, ProgramString* found_string, int* found_layout)
{
    if (base_addr == 0 || found_addr == nullptr ||
        found_string == nullptr || found_layout == nullptr)
        return false;

    for (size_t offset = 0; offset + 24 <= scan_range; offset += 8)
    {
        uint64_t addr = base_addr + offset;

        // 尝试两种布局
        for (int layout = PROGRAM_STRING_MSVC; layout <= PROGRAM_STRING_SIZE_PTR; layout++)
        {
            ProgramString ps = {};
            if (!ReadProgramString(addr, layout, &ps))
                continue;

            if (ps.data_addr == 0 || ps.size < sig_len ||
                !IsMemoryReadable((void*)ps.data_addr, (size_t)ps.size))
                continue;

            // 搜索签名
            for (int64_t i = 0; i <= (int64_t)ps.size - (int64_t)sig_len; i++)
            {
                if (memcmp((void*)(ps.data_addr + i), sig, sig_len) == 0)
                {
                    *found_addr = addr;
                    *found_string = ps;
                    *found_layout = layout;
                    return true;
                }
            }
        }
    }
    return false;
}

// 保留旧版单布局搜索作为回退 (在双布局搜索失败时使用)
static StdString* FindStdStringWithSig(uint64_t base_addr, size_t scan_range,
    const uint8_t* sig, size_t sig_len)
{
    if (base_addr == 0)
        return nullptr;

    for (size_t offset = 0; offset + sizeof(StdString) <= scan_range; offset += 8)
    {
        uint64_t addr = base_addr + offset;
        if (!IsMemoryReadable((void*)addr, sizeof(StdString)))
            break;

        StdString* ss = (StdString*)addr;

        if (ss->size <= 16 || ss->size > 0x10000 ||
            ss->capability < ss->size || ss->capability > 0x100000)
            continue;

        uint64_t str_addr = *((uint64_t*)(ss->data_ptr));
        if (str_addr == 0 || !IsMemoryReadable((void*)str_addr, (size_t)ss->size))
            continue;

        for (int64_t i = 0; i <= (int64_t)ss->size - (int64_t)sig_len; i++)
        {
            if (memcmp((void*)(str_addr + i), sig, sig_len) == 0)
                return ss;
        }
    }
    return nullptr;
}

static int FindZeroArgIndex(PCONTEXT ctx, int start_idx, int end_idx)
{
    // 输出所有参数值用于诊断
    if (g_output_debeug_msg && g_logfile)
    {
        char arg_log[512];
        int off = 0;
        for (int i = start_idx; i <= end_idx; i++)
        {
            uint64_t v = GetArgValue(ctx, i);
            off += snprintf(arg_log + off, sizeof(arg_log) - off,
                "arg%d=0x%llX ", i, v);
            if (off >= (int)sizeof(arg_log) - 30) break;
        }
        OutputDebugPrintf("[Debug] FindZeroArg args[%d..%d]: %s", start_idx, end_idx, arg_log);
    }

    // Pass 1: 64-bit == 0
    for (int i = start_idx; i <= end_idx; i++)
    {
        if (GetArgValue(ctx, i) == 0)
        {
            OutputDebugPrintf("[Debug] FindZeroArg Pass1: arg%d == 0", i);
            return i;
        }
    }
    // Pass 2: low 32 bits == 0 (upper 32 might be garbage)
    for (int i = start_idx; i <= end_idx; i++)
    {
        uint64_t val = GetArgValue(ctx, i);
        if (val != 0 && (val & 0xFFFFFFFF) == 0)
        {
            OutputDebugPrintf("[Debug] FindZeroArg Pass2: arg%d low32 == 0", i);
            return i;
        }
    }
    // Pass 3: low byte == 0, and is a valid user-mode pointer
    for (int i = start_idx; i <= end_idx; i++)
    {
        uint64_t val = GetArgValue(ctx, i);
        if (val != 0 && (val & 0xFF) == 0 &&
            (val >= 0x10000 && val <= 0x00007FFFFFFFFFFF))
        {
            OutputDebugPrintf("[Debug] FindZeroArg Pass3: arg%d low8 == 0", i);
            return i;
        }
    }
    // Pass 4: small non-zero values (1-15) that could be boolean false flags
    // (新版微信编译器优化可能导致 false 表现为1而非0)
    for (int i = start_idx; i <= end_idx; i++)
    {
        uint64_t val = GetArgValue(ctx, i);
        if (val > 0 && val <= 15)
        {
            OutputDebugPrintf("[Debug] FindZeroArg Pass4: arg%d == %llu (small, treating as bool false)", i, val);
            return i;
        }
    }
    OutputDebugPrintf("[Debug] FindZeroArg ALL PASSES FAILED for args[%d..%d]", start_idx, end_idx);
    return -1;
}

static uint64_t FindSrvId(uint64_t base_addr, size_t scan_limit)
{
    for (size_t offset = 0; offset + 16 <= scan_limit; offset += 8)
    {
        uint8_t* candidate = (uint8_t*)(base_addr + offset);
        if (!IsMemoryReadable(candidate, 16))
            break;

        if (candidate[14] != 0x00 || candidate[15] != 0x00)
            continue;
        if (candidate[12] == 0x00 && candidate[13] == 0x00)
            continue;

        int non_zero_count = 0;
        for (int i = 0; i < 14; i++)
        {
            if (candidate[i] != 0) non_zero_count++;
        }
        if (non_zero_count == 14)
            return (uint64_t)candidate;
    }
    return 0;
}


static void OnTargetHit(PCONTEXT ctx, PEXCEPTION_RECORD /*pExc*/)
{
    uint64_t rip = ctx->Rip;

    // 断点命中计数
    g_total_hit_count++;

    ThreadState* thread_state = GetThreadState();
    if (thread_state == nullptr) {
        LogPrintf("[RevokeHook] OnTargetHit: GetThreadState Failed! rip=%p", (void*)rip);
        OutputDebugString(TEXT("[RevokeHook] GetThreadState Failed!"));
        return;
    }

    // 寄存器dump用于诊断
    if (g_output_debeug_msg)
    {
        OutputDebugPrintf("[Debug] BP Hit #%d at rip=%p | RCX=%p RDX=%p R8=%p R9=%p RSP=%p",
            g_total_hit_count, (void*)rip,
            (void*)ctx->Rcx, (void*)ctx->Rdx, (void*)ctx->R8, (void*)ctx->R9, (void*)ctx->Rsp);
    }

    if (rip == (uint64_t)g_bpDelMsg)
    {
        uint8_t revoke_sig[] = { 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; //'撤回'
        uint8_t self_revoke_sig[] = { 0xe4, 0xbd, 0xa0, 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; //'你撤回'

        // ── 降级模式: 不解析消息内容, 直接跳过调用 ──
        if (g_fallback_mode || g_delmsg_search_fail_count >= 3)
        {
            if (g_delmsg_search_fail_count >= 3 && !g_fallback_mode)
            {
                LogPrintf("[RevokeHook] DelMsg: entering fallback mode (3 search failures)");
                g_fallback_mode = true;
            }

            thread_state->anti_revoke_cur_msg = 1;

            if (g_config_info.delmsg_info.arg_notify_index > 0)
            {
                SetArgValue(ctx, g_config_info.delmsg_info.arg_notify_index, 1);
            }
            else
            {
                int idx = FindZeroArgIndex(ctx, 3, 8);
                if (idx > 0)
                {
                    g_config_info.delmsg_info.arg_notify_index = idx;
                    SetArgValue(ctx, idx, 1);
                }
            }
            ctx->Rip += 5;
            OutputDebugPrintf("[Debug] DelMsg fallback: Skip Call, New RIP: %p", (void*)ctx->Rip);
            return;
        }

        ProgramString revoke_xml_ps = {};
        uint64_t revoke_xml_addr = 0;
        int revoke_xml_layout = PROGRAM_STRING_UNKNOWN;

        if (!g_config_info.delmsg_info.initialized)
        {
            // 首次命中: 使用双布局搜索定位 revoke_xml
            uint64_t candidates[] = { ctx->Rdx, ctx->R8, ctx->R9 };
            int candidate_indices[] = { 2, 3, 4 };

            for (int c = 0; c < 3 && revoke_xml_addr == 0; c++)
            {
                if (FindProgramStringWithSig(candidates[c], 0x2000,
                    revoke_sig, sizeof(revoke_sig),
                    &revoke_xml_addr, &revoke_xml_ps, &revoke_xml_layout))
                {
                    g_config_info.delmsg_info.arg_msg_index = candidate_indices[c];
                    g_config_info.delmsg_info.offset_revoke_xml = (int)(revoke_xml_addr - candidates[c]);
                    g_config_info.delmsg_info.string_layout = revoke_xml_layout;
                }
            }

            // 双布局搜索失败, 尝试旧版单布局回退
            if (revoke_xml_addr == 0)
            {
                StdString* ss = nullptr;
                for (int c = 0; c < 3 && ss == nullptr; c++)
                {
                    ss = FindStdStringWithSig(candidates[c], 0x2000,
                        revoke_sig, sizeof(revoke_sig));
                    if (ss)
                    {
                        g_config_info.delmsg_info.arg_msg_index = candidate_indices[c];
                        g_config_info.delmsg_info.offset_revoke_xml = (int)((uint64_t)ss - candidates[c]);
                        g_config_info.delmsg_info.string_layout = PROGRAM_STRING_MSVC;
                        revoke_xml_addr = (uint64_t)ss;
                        revoke_xml_ps.data_addr = *((uint64_t*)ss->data_ptr);
                        revoke_xml_ps.size = ss->size;
                        revoke_xml_layout = PROGRAM_STRING_MSVC;
                    }
                }
            }

            if (revoke_xml_addr == 0 || revoke_xml_ps.size == 0)
            {
                g_delmsg_search_fail_count++;
                LogPrintf("[RevokeHook] DelMsg: Cannot find revoke_xml (attempt %d/3)",
                    g_delmsg_search_fail_count);
                OutputDebugPrintf("[Debug] DelMsg: Cannot find revoke_xml (attempt %d/3)",
                    g_delmsg_search_fail_count);
                return;
            }

            g_config_info.delmsg_info.arg_notify_index = FindZeroArgIndex(ctx, 3, 8);
            g_config_info.delmsg_info.initialized = true;
            OutputDebugPrintf("[Debug] DelMsg cached: msg_idx=%d, xml_off=0x%X, notify_idx=%d, layout=%d",
                g_config_info.delmsg_info.arg_msg_index,
                g_config_info.delmsg_info.offset_revoke_xml,
                g_config_info.delmsg_info.arg_notify_index,
                g_config_info.delmsg_info.string_layout);
            LogPrintf("[RevokeHook] DelMsg first-hit cached: msg_idx=%d, xml_off=0x%X, notify_idx=%d, layout=%d",
                g_config_info.delmsg_info.arg_msg_index,
                g_config_info.delmsg_info.offset_revoke_xml,
                g_config_info.delmsg_info.arg_notify_index,
                g_config_info.delmsg_info.string_layout);
        }
        else
        {
            // 后续命中: 使用缓存的偏移和布局
            uint64_t arg_msg = GetArgValue(ctx, g_config_info.delmsg_info.arg_msg_index);
            revoke_xml_addr = arg_msg + g_config_info.delmsg_info.offset_revoke_xml;
            revoke_xml_layout = g_config_info.delmsg_info.string_layout;

            if (!ReadProgramString(revoke_xml_addr, revoke_xml_layout, &revoke_xml_ps) ||
                revoke_xml_ps.size == 0)
            {
                OutputDebugPrintf("[Debug] DelMsg: revoke_xml invalid (cached path)");
                return;
            }
        }

        uint64_t revoke_xml_str_addr = revoke_xml_ps.data_addr;
        if (revoke_xml_str_addr == 0 || !IsMemoryReadable((void*)revoke_xml_str_addr, (size_t)revoke_xml_ps.size))
        {
            OutputDebugPrintf("[Debug] DelMsg: revoke_xml str invalid");
            return;
        }

        bool is_self = false;
        for (int64_t i = 0; i <= (int64_t)revoke_xml_ps.size - (int64_t)sizeof(self_revoke_sig); i++)
        {
            if (memcmp((void*)(revoke_xml_str_addr + i), self_revoke_sig, sizeof(self_revoke_sig)) == 0)
            {
                is_self = true;
                break;
            }
        }

        if (is_self && !g_anti_revoke_self_msg)
        {
            thread_state->anti_revoke_cur_msg = 0;
            OutputDebugPrintf("[Debug] DelMsg: self revoke, skipping");
            return;
        }
        if (is_self)
            OutputDebugPrintf("[Debug] Anti Revoke SELF Msg...");

        thread_state->anti_revoke_cur_msg = 1;

        if (g_config_info.delmsg_info.arg_notify_index > 0)
        {
            SetArgValue(ctx, g_config_info.delmsg_info.arg_notify_index, 1);
            OutputDebugPrintf("[Debug] Set notify arg %d to 1", g_config_info.delmsg_info.arg_notify_index);
        }

        ctx->Rip += 5;
        OutputDebugPrintf("[Debug] Skip Call, New RIP: %p", (void*)ctx->Rip);
    }
    else if (rip == (uint64_t)g_bpAdd2DB)
    {
        if (thread_state->anti_revoke_cur_msg == 0) return;

        if (!g_config_info.add2db_info.initialized)
        {
            int arg_bool_index = FindZeroArgIndex(ctx, 3, 8);
            if (arg_bool_index < 0)
            {
                LogPrintf("[RevokeHook] Add2DB: Cannot find arg_bool (0 param)");
                OutputDebugPrintf("[Debug] Add2DB: Cannot find arg_bool (0 param)");
                return;
            }

            uint64_t arg_msg = GetArgValue(ctx, 3);
            if (arg_msg == 0 || !IsMemoryReadable((void*)arg_msg, 0x100))
            {
                LogPrintf("[RevokeHook] Add2DB: arg_msg=0x%llX is invalid", arg_msg);
                OutputDebugPrintf("[Debug] Add2DB: arg_msg is invalid");
                return;
            }

            uint8_t anchor[] = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 }; //'一条' utf-8
            ProgramString rx_ps = {};
            uint64_t rx_addr = 0;
            int rx_layout = PROGRAM_STRING_UNKNOWN;

            // 双布局搜索
            if (!FindProgramStringWithSig(arg_msg, 0x1000,
                anchor, sizeof(anchor),
                &rx_addr, &rx_ps, &rx_layout))
            {
                // 回退到旧版单布局
                StdString* ss = FindStdStringWithSig(arg_msg, 0x1000, anchor, sizeof(anchor));
                if (ss)
                {
                    rx_addr = (uint64_t)ss;
                    rx_ps.data_addr = *((uint64_t*)ss->data_ptr);
                    rx_ps.size = ss->size;
                    rx_layout = PROGRAM_STRING_MSVC;
                }
            }

            if (rx_addr == 0 || rx_ps.size == 0)
            {
                LogPrintf("[RevokeHook] Add2DB: Cannot find revoke_xml");
                OutputDebugPrintf("[Debug] Add2DB: Cannot find revoke_xml");
                return;
            }

            int xml_offset = (int)(rx_addr - arg_msg);
            uint64_t mem_srvid_addr = FindSrvId(arg_msg, (size_t)xml_offset);
            if (mem_srvid_addr == 0)
            {
                LogPrintf("[RevokeHook] Add2DB: Cannot find srvid");
                OutputDebugPrintf("[Debug] Add2DB: Cannot find srvid");
                return;
            }

            g_config_info.add2db_info.arg_bool_index = arg_bool_index;
            g_config_info.add2db_info.offset_revoke_xml = xml_offset;
            g_config_info.add2db_info.offset_srvid = (int)(mem_srvid_addr - arg_msg);
            g_config_info.add2db_info.string_layout = rx_layout;
            g_config_info.add2db_info.initialized = true;
            OutputDebugPrintf("[Debug] Add2DB cached: bool_idx=%d, xml_off=0x%X, srvid_off=0x%X, layout=%d",
                g_config_info.add2db_info.arg_bool_index,
                g_config_info.add2db_info.offset_revoke_xml,
                g_config_info.add2db_info.offset_srvid,
                g_config_info.add2db_info.string_layout);
            LogPrintf("[RevokeHook] Add2DB first-hit cached: bool_idx=%d, xml_off=0x%X, srvid_off=0x%X, layout=%d",
                g_config_info.add2db_info.arg_bool_index,
                g_config_info.add2db_info.offset_revoke_xml,
                g_config_info.add2db_info.offset_srvid,
                g_config_info.add2db_info.string_layout);
        }

        int arg_bool_index = g_config_info.add2db_info.arg_bool_index;
        uint64_t arg_msg = GetArgValue(ctx, 3);
        if (arg_msg == 0 || !IsMemoryReadable((void*)arg_msg, 0x100))
        {
            OutputDebugPrintf("[Debug] Add2DB: arg_msg invalid");
            return;
        }

        // 使用缓存的布局读取 revoke_xml
        ProgramString revoke_xml_ps = {};
        uint64_t revoke_xml_addr = arg_msg + g_config_info.add2db_info.offset_revoke_xml;
        if (!ReadProgramString(revoke_xml_addr,
            g_config_info.add2db_info.string_layout, &revoke_xml_ps) ||
            revoke_xml_ps.size == 0 || revoke_xml_ps.size > 0x10000)
        {
            OutputDebugPrintf("[Debug] Add2DB: revoke_xml invalid (cached path)");
            return;
        }

        uint64_t mem_srvid_addr = arg_msg + g_config_info.add2db_info.offset_srvid;

        uint64_t revoke_xml_str_addr = revoke_xml_ps.data_addr;
        OutputDebugPrintf("[Debug] %p | Revoke XML addr=%p len=%llu | bool_idx: %d",
            (void*)revoke_xml_addr, (void*)revoke_xml_str_addr,
            revoke_xml_ps.size, arg_bool_index);

        uint8_t org_srvid[8] = { 0 };
        memcpy(org_srvid, (void*)mem_srvid_addr, 8);
        OutputDebugPrintf("[Debug] Org srvid: %p | Last srvid: %p",
            (void*)(*(uint64_t*)org_srvid), (void*)(*(uint64_t*)thread_state->last_org_srvid));
        if (memcmp(thread_state->last_org_srvid, org_srvid, 8) == 0)
        {
            return;
        }
        memcpy(thread_state->last_org_srvid, org_srvid, 8);
        OutputDebugPrintf("[Debug] Update last srvid: %p", (void*)(*(uint64_t*)thread_state->last_org_srvid));

        std::vector<uint8_t> rand_srvid = GetUniquePositiveValue();
        if (rand_srvid.size() != 8) {
            LogPrintf("[RevokeHook] GetUniquePositiveValue Err!");
            OutputDebugString(TEXT("[RevokeHook] GetUniquePositiveValue Err!"));
            return;
        }
        OutputDebugPrintf("[Debug] Original SrvID: %p [%X %X...]", (void*)mem_srvid_addr,
            ((uint8_t*)mem_srvid_addr)[0], ((uint8_t*)mem_srvid_addr)[1]);
        memcpy((void*)mem_srvid_addr, rand_srvid.data(), rand_srvid.size());

        // ── 撤回提醒: 提取用户名 + 连续撤回计数 ──
        uint8_t revoke_utf8[] = { 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; // '撤回'
        uint8_t anchor[] = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 };       // '一条'
        uint8_t as_above[] = { 0xe5, 0xa6, 0x82, 0xe4, 0xb8, 0x8a };     // '如上'

        int64_t revoke_pos = -1;
        int64_t anchor_pos = -1;

        // 定位 "撤回" 和 "一条" 在文本中的位置
        for (int64_t i = 0; i <= (int64_t)revoke_xml_ps.size - 6; i++)
        {
            if (revoke_pos < 0 && memcmp((void*)(revoke_xml_str_addr + i), revoke_utf8, sizeof(revoke_utf8)) == 0)
                revoke_pos = i;
            if (anchor_pos < 0 && memcmp((void*)(revoke_xml_str_addr + i), anchor, sizeof(anchor)) == 0)
                anchor_pos = i;
            if (revoke_pos >= 0 && anchor_pos >= 0) break;
        }

        if (anchor_pos < 0)
        {
            OutputDebugPrintf("[Debug] Add2DB: anchor '一条' not found in revoke_xml");
            // 回退: 至少尝试替换
            anchor_pos = 0;
        }
        if (revoke_pos < 0)
        {
            OutputDebugPrintf("[Debug] Add2DB: '撤回' not found, using basic replace only");
            // 仅替换 "一条" → "如上"
            if (anchor_pos >= 0)
                memcpy((void*)(revoke_xml_str_addr + anchor_pos), as_above, sizeof(as_above));
        }
        else
        {
            // 定位 <content> 标签边界, 只在标签内替换文本
            // XML 格式: ...<content>"用户名" 撤回了一条消息</content>...
            const char content_tag[] = "<content>";
            const char content_end[] = "</content>";
            int64_t content_start = -1, content_end_pos = -1;

            for (int64_t i = 0; i <= (int64_t)revoke_xml_ps.size - 9; i++)
            {
                if (content_start < 0 &&
                    memcmp((void*)(revoke_xml_str_addr + i), content_tag, 8) == 0)
                    content_start = i + 9; // 跳过 "<content>"
                if (content_end_pos < 0 &&
                    memcmp((void*)(revoke_xml_str_addr + i), content_end, 9) == 0)
                    content_end_pos = i;
                if (content_start >= 0 && content_end_pos >= 0) break;
            }

            if (content_start < 0 || content_end_pos < 0)
            {
                // 找不到 content 标签, 回退: 仅替换 "一条" → "如上"
                OutputDebugPrintf("[Debug] Add2DB: content tag not found, fallback replace");
                if (anchor_pos >= 0)
                    memcpy((void*)(revoke_xml_str_addr + anchor_pos), as_above, sizeof(as_above));
            }
            else
            {
                // 提取发送者用户名: content 文本中 "撤回" 之前的部分
                // 去掉开头的引号和空格
                int64_t name_start = content_start;
                while (name_start < revoke_pos)
                {
                    uint8_t c = *(uint8_t*)(revoke_xml_str_addr + name_start);
                    if (c == '"' || c == '\'' || c == ' ' || c == '\t')
                        name_start++;
                    else
                        break;
                }
                int64_t name_end = revoke_pos;
                while (name_end > name_start)
                {
                    uint8_t c = *(uint8_t*)(revoke_xml_str_addr + name_end - 1);
                    if (c == '"' || c == '\'' || c == ' ' || c == '\t')
                        name_end--;
                    else
                        break;
                }

                int64_t actual_name_len = name_end - name_start;
                const char* sender_name = (const char*)(revoke_xml_str_addr + name_start);

                // 计算发送者哈希用于计数
                std::vector<uint8_t> name_bytes(sender_name, sender_name + actual_name_len);
                std::vector<uint8_t> sender_hash = CalculateMD5(name_bytes);

                // 连续撤回计数 (5秒超时窗口)
                DWORD now_tick = GetTickCount();
                bool same_sender = (sender_hash.size() == 8 &&
                    memcmp(thread_state->last_sender_hash, sender_hash.data(), 8) == 0);
                bool within_window = (now_tick - thread_state->last_revoke_tick) < 5000;

                if (same_sender && within_window && thread_state->revoke_count > 0)
                    thread_state->revoke_count++;
                else
                    thread_state->revoke_count = 1;

                if (sender_hash.size() == 8)
                    memcpy(thread_state->last_sender_hash, sender_hash.data(), 8);
                thread_state->last_revoke_tick = now_tick;

                // 构造新文本, 只在 <content>...</content> 范围内写入
                // 格式: 用户名撤回如上N条消息
                char new_text[512];
                int new_len = snprintf(new_text, sizeof(new_text),
                    "%.*s\xe6\x92\xa4\xe5\x9b\x9e\xe5\xa6\x82\xe4\xb8\x8a%d\xe6\x9d\xa1\xe6\xb6\x88\xe6\x81\xaf",
                    (int)actual_name_len, sender_name, thread_state->revoke_count);

                uint64_t max_content_len = (uint64_t)(content_end_pos - content_start);
                if (new_len > 0 && (uint64_t)new_len <= max_content_len)
                {
                    // 新文本放入 content 区间, 多余部分用空格填充
                    size_t write_len = (size_t)new_len;
                    memcpy((void*)(revoke_xml_str_addr + content_start), new_text, write_len);
                    // 填充剩余空间
                    if (write_len < (size_t)max_content_len)
                        memset((void*)(revoke_xml_str_addr + content_start + write_len), ' ',
                            (size_t)(max_content_len - write_len));

                    OutputDebugPrintf("[Debug] Revoke notify: count=%d, sender=%.*s",
                        thread_state->revoke_count, (int)actual_name_len, sender_name);
                    LogPrintf("[RevokeHook] Revoke #%d by '%.*s'",
                        thread_state->revoke_count, (int)actual_name_len, sender_name);
                }
                else
                {
                    // 文本过长, 回退: 仅替换 "一条" → "如上"
                    if (anchor_pos >= 0)
                    {
                        memcpy((void*)(revoke_xml_str_addr + anchor_pos), as_above, sizeof(as_above));
                        // 追加用户名提示在末尾
                        int suffix_len = snprintf(new_text, sizeof(new_text),
                            " (%.*s)", (int)actual_name_len, sender_name);
                        uint64_t end_pos = (uint64_t)(content_end_pos - suffix_len);
                        if (suffix_len > 0 && end_pos >= (uint64_t)content_start)
                            memcpy((void*)(revoke_xml_str_addr + end_pos), new_text, suffix_len);
                    }
                    OutputDebugPrintf("[Debug] Fallback: content too small (need=%d, max=%llu)",
                        new_len, max_content_len);
                }
            }
        }

        if (SetArgValue(ctx, arg_bool_index, 1))
            OutputDebugPrintf("[Debug] Set Arg %d to 1", arg_bool_index);
        else
            OutputDebugPrintf("[Debug] Set Arg %d Failed!", arg_bool_index);
    }
}
// 断点地址验证: 检查目标地址是否为有效的call指令
// ---------------------------------------------------------------------------
static bool ValidateBreakpointAddress(void* addr, char* log_buf, size_t log_buf_size)
{
    if (!IsMemoryReadable(addr, 16))
    {
        snprintf(log_buf, log_buf_size, "BP addr %p is NOT readable (CRITICAL: offset may be wrong)", addr);
        return false;
    }

    uint8_t* code = (uint8_t*)addr;

    // Check for direct call (E8) — most common case
    if (code[0] == 0xE8)
    {
        snprintf(log_buf, log_buf_size, "BP at %p: E8 call (valid)", addr);
        return true;
    }

    // Check for indirect call / jump (FF)
    if (code[0] == 0xFF)
    {
        snprintf(log_buf, log_buf_size, "BP at %p: FF indirect call/jmp (valid)", addr);
        return true;
    }

    // Check for near jump (E9) — might be a thunk/trampoline
    if (code[0] == 0xE9)
    {
        snprintf(log_buf, log_buf_size, "BP at %p: E9 jmp (possible thunk, valid)", addr);
        return true;
    }

    // Scan nearby for E8 within +/- 16 bytes
    for (int d = -16; d <= 16; d++)
    {
        if (d == 0) continue;
        uint8_t* probe = (uint8_t*)addr + d;
        if (IsMemoryReadable(probe, 5) && probe[0] == 0xE8)
        {
            snprintf(log_buf, log_buf_size,
                "BP at %p: nearest E8 at offset %+d, bytes: %02X %02X %02X %02X %02X (WARNING: offset may be off by %d)",
                addr, d, code[0], code[1], code[2], code[3], code[4], d);
            return true; // Accept but log warning
        }
    }

    // Completely invalid — no call-like instruction nearby
    snprintf(log_buf, log_buf_size,
        "BP at %p: NO call instruction nearby! Bytes: %02X %02X %02X %02X %02X %02X %02X %02X (CRITICAL: offsets likely wrong for this WeChat version)",
        addr, code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7]);
    return false;
}

// ---------------------------------------------------------------------------
// 心跳线程: 每30秒输出存活信息, 2分钟无断点命中则警告
// ---------------------------------------------------------------------------
static HANDLE g_heartbeat_thread = nullptr;
static volatile bool g_heartbeat_running = false;

static DWORD WINAPI HeartbeatThread(LPVOID)
{
    DWORD start_time = GetTickCount();
    while (g_heartbeat_running)
    {
        Sleep(30000); // 30 seconds
        if (!g_heartbeat_running) break;

        DWORD elapsed = (GetTickCount() - start_time) / 1000;
        LogPrintf("[Heartbeat] DLL alive for %u seconds, breakpoints hit: %d",
            elapsed, g_total_hit_count);

        if (g_total_hit_count == 0 && elapsed > 120)
        {
            LogPrintf("[Heartbeat] WARNING: No breakpoint hits in %u seconds! "
                "Offsets may be wrong for this WeChat version. "
                "DelMsg=0x%llX Add2DB=0x%llX WeixinBase=%p",
                elapsed,
                g_config_info.basic_info.delmsg_offset,
                g_config_info.basic_info.add2db_offset,
                (void*)g_config_info.basic_info.imgbase);
        }
    }
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LogInit(); // 初始化文件日志 (最先执行, 确保后续操作可记录)
        LogPrintf("[RevokeHook] DLL loaded, PID=%d, TID=%d",
            GetCurrentProcessId(), GetCurrentThreadId());

        if (!InitThreadStateTls()) {
            LogPrintf("[RevokeHook] InitThreadStateTls Failed!");
            OutputDebugString(TEXT("[RevokeHook] InitThreadStateTls Failed!"));
            break;
        }

        LogPrintf("[RevokeHook] Reading Config from lpReserved=%p...", lpReserved);
        OutputDebugString(TEXT("[RevokeHook] Reading Config..."));
        if (!ReadExternalConfig((char*)lpReserved)) {
            LogPrintf("[RevokeHook] ReadExternalConfig FAILED!");
            break;   //ini路径通过第三个参数传进来
        }
        LogPrintf("[RevokeHook] Begin Install VEH & Set Bp!");
        OutputDebugString(TEXT("[RevokeHook] Begin Install VEH & Set Bp!"));

        if (!VehBp_Init(TRUE))
        {
            LogPrintf("[RevokeHook] VEHBp Init failed!");
            OutputDebugString(_T("[RevokeHook] VEHBp Init failed!"));
            return TRUE;
        }

        g_bpDelMsg = (void*)(g_config_info.basic_info.imgbase + g_config_info.basic_info.delmsg_offset);
        g_bpAdd2DB = (void*)(g_config_info.basic_info.imgbase + g_config_info.basic_info.add2db_offset);

        // 断点地址验证
        {
            char bp_log[256];
            ValidateBreakpointAddress(g_bpDelMsg, bp_log, sizeof(bp_log));
            LogPrintf("[RevokeHook] Validate DelMsg: %s", bp_log);

            char bp_log2[256];
            ValidateBreakpointAddress(g_bpAdd2DB, bp_log2, sizeof(bp_log2));
            LogPrintf("[RevokeHook] Validate Add2DB: %s", bp_log2);
        }

        if (VehBp_Set(g_bpDelMsg, OnTargetHit) == -1)
        {
            LogPrintf("[RevokeHook] AddBp DelMsg %p Error", g_bpDelMsg);
            OutputDebugPrintf("[RevokeHook] AddBp %p Error", g_bpDelMsg);
        }
        else
        {
            LogPrintf("[RevokeHook] AddBp DelMsg %p OK", g_bpDelMsg);
            OutputDebugPrintf("[RevokeHook] AddBp %p OK", g_bpDelMsg);
        }

        if (VehBp_Set(g_bpAdd2DB, OnTargetHit) == -1)
        {
            LogPrintf("[RevokeHook] AddBp Add2DB %p Error", g_bpAdd2DB);
            OutputDebugPrintf("[RevokeHook] AddBp %p Error", g_bpAdd2DB);
        }
        else
        {
            LogPrintf("[RevokeHook] AddBp Add2DB %p OK", g_bpAdd2DB);
            OutputDebugPrintf("[RevokeHook] AddBp %p OK", g_bpAdd2DB);
        }

        // 启动心跳线程
        g_heartbeat_running = true;
        g_heartbeat_thread = CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);
        LogPrintf("[RevokeHook] Heartbeat thread started, hooks ready.");
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        LogPrintf("[RevokeHook] DLL unloading (total breakpoint hits: %d)...", g_total_hit_count);
        OutputDebugString(TEXT("[RevokeHook] Uninstall VEH & Cancel Bp!"));

        // 停心跳线程
        g_heartbeat_running = false;
        if (g_heartbeat_thread)
        {
            WaitForSingleObject(g_heartbeat_thread, 5000);
            CloseHandle(g_heartbeat_thread);
            g_heartbeat_thread = nullptr;
        }

        VehBp_Uninit();
        FreeCurrentThreadState();
        UninitThreadStateTls();
        LogPrintf("[RevokeHook] DLL unloaded cleanly.");
        LogClose();
        break;
    }
    return TRUE;
}


