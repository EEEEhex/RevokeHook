#include "framework.h"
#include <wincrypt.h>

#include <tchar.h>
#include <cstdint>
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

//VEH + INT3断点
static void* g_bpDelMsg = nullptr;
static void* g_bpAdd2DB = nullptr;

static DWORD g_tlsThreadState = TLS_OUT_OF_INDEXES;
struct ThreadState
{
    uint8_t last_org_srvid[8];      //真实的srvid 防止插入两条撤回提醒
    uint8_t anti_revoke_cur_msg;    //是否防撤回当前这条消息
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
};

struct ADD2DBINFO
{
    bool initialized;
    int arg_bool_index;     // 哪个参数是bool标志(值为0的那个)
    int offset_srvid;       // srvid在r8结构体中的偏移
    int offset_revoke_xml;  // revoke_xml StdString在r8结构体中的偏移
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

void OutputDebugPrintf(const char* strOutputString, ...)
{
#define OUT_DEBUG_BUF_LEN   512
    if (!g_output_debeug_msg) return;

    char strBuffer[OUT_DEBUG_BUF_LEN] = { 0 };
    va_list vlArgs;
    va_start(vlArgs, strOutputString);
    _vsnprintf_s(strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);  //_vsnprintf_s  _vsnprintf
    va_end(vlArgs);
    OutputDebugStringA(strBuffer);  //OutputDebugString    // OutputDebugStringW
}

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
            OutputDebugString(TEXT("[ReovkeHook] GetEnvVar USERPROFILE Failed!"));
            return false;
        }

        // 拼接 Documents 目录
        std::string documents_path = std::string(user_profile) + "\\Documents";
        std::string ini_path_str = documents_path + "\\RevokeHook\\RevokeHook.ini";
        if (stat(ini_path_str.c_str(), &buffer) != 0) {
            OutputDebugString(TEXT("[ReovkeHook] Not Find ini file!"));
            return false;
        }
    }

    g_config.load(ini_path_str);

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
        OutputDebugString(TEXT("[RevokeHook] Get Weixin.dll Base Failed!"));
        return false;
	}

	g_config_info.basic_info.imgbase = (uint64_t)weixin_dll_base;
	g_config_info.basic_info.delmsg_offset = g_config["KeyFunc"]["DelMsgOffset"].as<int>();
	g_config_info.basic_info.add2db_offset = g_config["KeyFunc"]["Add2DBOffset"].as<int>();

	g_anti_revoke_self_msg = g_config["Setting"]["AntiRevokeSelf"].as<bool>();
	g_output_debeug_msg = g_config["Setting"]["OutputDebugMsg"].as<bool>();

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
    // Pass 1: 64-bit == 0
    for (int i = start_idx; i <= end_idx; i++)
    {
        if (GetArgValue(ctx, i) == 0)
            return i;
    }
    // Pass 2: low 32 bits == 0 (upper 32 might be garbage)
    for (int i = start_idx; i <= end_idx; i++)
    {
        uint64_t val = GetArgValue(ctx, i);
        if (val != 0 && (val & 0xFFFFFFFF) == 0)
            return i;
    }
    // Pass 3: low byte == 0, but not a valid user-mode pointer
    for (int i = start_idx; i <= end_idx; i++)
    {
        uint64_t val = GetArgValue(ctx, i);
        if (val != 0 && (val & 0xFF) == 0 &&
            !(val >= 0x10000 && val <= 0x00007FFFFFFFFFFF))
            return i;
    }
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
    ThreadState* thread_state = GetThreadState();
    if (thread_state == nullptr) {
        OutputDebugString(TEXT("[RevokeHook] GetThreadState Failed!"));
        return;
    }
  
    if (rip == (uint64_t)g_bpDelMsg) 
    {
        uint8_t revoke_sig[] = { 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; //'撤回'
        uint8_t self_revoke_sig[] = { 0xe4, 0xbd, 0xa0, 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; //'你撤回'

        StdString* revoke_xml = nullptr;

        if (!g_config_info.delmsg_info.initialized)
        {
            uint64_t candidates[] = { ctx->Rdx, ctx->R8, ctx->R9 };
            int candidate_indices[] = { 2, 3, 4 };

            for (int c = 0; c < 3 && revoke_xml == nullptr; c++)
            {
                revoke_xml = FindStdStringWithSig(candidates[c], 0x2000,
                    revoke_sig, sizeof(revoke_sig));
                if (revoke_xml) {
                    g_config_info.delmsg_info.arg_msg_index = candidate_indices[c];
                    g_config_info.delmsg_info.offset_revoke_xml = (int)((uint64_t)revoke_xml - candidates[c]);
                }
            }

            if (revoke_xml == nullptr || revoke_xml->size <= 0)
            {
                OutputDebugPrintf("[Debug] DelMsg: Cannot find revoke_xml in registers");
                return;
            }

            g_config_info.delmsg_info.arg_notify_index = FindZeroArgIndex(ctx, 3, 8);
            g_config_info.delmsg_info.initialized = true;
            OutputDebugPrintf("[Debug] DelMsg cached: msg_idx=%d, xml_off=0x%X, notify_idx=%d",
                g_config_info.delmsg_info.arg_msg_index,
                g_config_info.delmsg_info.offset_revoke_xml,
                g_config_info.delmsg_info.arg_notify_index);
        }
        else
        {
            uint64_t arg_msg = GetArgValue(ctx, g_config_info.delmsg_info.arg_msg_index);
            revoke_xml = (StdString*)(arg_msg + g_config_info.delmsg_info.offset_revoke_xml);
            if (!IsMemoryReadable(revoke_xml, sizeof(StdString)) || revoke_xml->size <= 0)
            {
                OutputDebugPrintf("[Debug] DelMsg: revoke_xml invalid (cached path)");
                return;
            }
        }

        uint64_t revoke_xml_str_addr = *((uint64_t*)(revoke_xml->data_ptr));
        if (revoke_xml_str_addr == 0 || !IsMemoryReadable((void*)revoke_xml_str_addr, (size_t)revoke_xml->size))
        {
            OutputDebugPrintf("[Debug] DelMsg: revoke_xml str invalid");
            return;
        }

        bool is_self = false;
        for (int64_t i = 0; i <= (int64_t)revoke_xml->size - (int64_t)sizeof(self_revoke_sig); i++)
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
        OutputDebugPrintf("[Debug] Skip Call, New RIP: %p", ctx->Rip);
    }
    else if (rip == (uint64_t)g_bpAdd2DB) 
    {
		if (thread_state->anti_revoke_cur_msg == 0) return;

        if (!g_config_info.add2db_info.initialized)
        {
            int arg_bool_index = FindZeroArgIndex(ctx, 3, 8);
            if (arg_bool_index < 0)
            {
                OutputDebugPrintf("[Debug] Add2DB: Cannot find arg_bool (0 param)");
                return;
            }

            uint64_t arg_msg = GetArgValue(ctx, 3);
            if (arg_msg == 0 || !IsMemoryReadable((void*)arg_msg, 0x100))
            {
                OutputDebugPrintf("[Debug] Add2DB: arg_msg is invalid");
                return;
            }

            uint8_t anchor[] = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 }; //'一条' utf-8
            StdString* revoke_xml = FindStdStringWithSig(arg_msg, 0x1000, anchor, sizeof(anchor));
            if (revoke_xml == nullptr || revoke_xml->size <= 0)
            {
                OutputDebugPrintf("[Debug] Add2DB: Cannot find revoke_xml");
                return;
            }

            int xml_offset = (int)((uint64_t)revoke_xml - arg_msg);
            uint64_t mem_srvid_addr = FindSrvId(arg_msg, (size_t)xml_offset);
            if (mem_srvid_addr == 0)
            {
                OutputDebugPrintf("[Debug] Add2DB: Cannot find srvid");
                return;
            }

            g_config_info.add2db_info.arg_bool_index = arg_bool_index;
            g_config_info.add2db_info.offset_revoke_xml = xml_offset;
            g_config_info.add2db_info.offset_srvid = (int)(mem_srvid_addr - arg_msg);
            g_config_info.add2db_info.initialized = true;
            OutputDebugPrintf("[Debug] Add2DB cached: bool_idx=%d, xml_off=0x%X, srvid_off=0x%X",
                g_config_info.add2db_info.arg_bool_index,
                g_config_info.add2db_info.offset_revoke_xml,
                g_config_info.add2db_info.offset_srvid);
        }

        int arg_bool_index = g_config_info.add2db_info.arg_bool_index;
        uint64_t arg_msg = GetArgValue(ctx, 3);
        if (arg_msg == 0 || !IsMemoryReadable((void*)arg_msg, 0x100))
        {
            OutputDebugPrintf("[Debug] Add2DB: arg_msg invalid");
            return;
        }

        StdString* revoke_xml = (StdString*)(arg_msg + g_config_info.add2db_info.offset_revoke_xml);
        if (!IsMemoryReadable(revoke_xml, sizeof(StdString)) || revoke_xml->size <= 0)
        {
            OutputDebugPrintf("[Debug] Add2DB: revoke_xml invalid");
            return;
        }

        uint64_t mem_srvid_addr = arg_msg + g_config_info.add2db_info.offset_srvid;

        uint64_t revoke_xml_str_addr = *((uint64_t*)(revoke_xml->data_ptr));
        OutputDebugPrintf("[Debug] %p | Revoke XML: %s | bool_idx: %d", revoke_xml, (char*)revoke_xml_str_addr, arg_bool_index);

        uint8_t org_srvid[8] = { 0 };
        memcpy(org_srvid, (void*)mem_srvid_addr, 8);
        OutputDebugPrintf("[Debug] Org srvid: %p | Last srvid: %p", *((uint64_t*)org_srvid), *((uint64_t*)thread_state->last_org_srvid));
        if (memcmp(thread_state->last_org_srvid, org_srvid, 8) == 0)
        {
            return;
        }
        memcpy(thread_state->last_org_srvid, org_srvid, 8);
        OutputDebugPrintf("[Debug] Update last srvid: %p", *((uint64_t*)thread_state->last_org_srvid));

        std::vector<uint8_t> rand_srvid = GetUniquePositiveValue();
        if (rand_srvid.size() != 8) {
            OutputDebugString(TEXT("[RevokeHook] GetUniquePositiveValue Err!"));
            return;
        }
        OutputDebugPrintf("[Debug] Original SrvID: %p [%X %X...]", mem_srvid_addr, ((uint8_t*)mem_srvid_addr)[0], ((uint8_t*)mem_srvid_addr)[1]);
        memcpy((void*)mem_srvid_addr, rand_srvid.data(), rand_srvid.size());

        uint8_t anchor[] = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 }; //'一条' utf-8
        for (int64_t i = 0; i <= (int64_t)revoke_xml->size - (int64_t)sizeof(anchor); i++)
        {
            if (memcmp((void*)(revoke_xml_str_addr + i), anchor, sizeof(anchor)) == 0)
            {
                uint8_t replace[] = { 0xe5, 0xa6, 0x82, 0xe4, 0xb8, 0x8a }; //'如上' utf-8
                memcpy((void*)(revoke_xml_str_addr + i), replace, sizeof(replace));
                OutputDebugPrintf("[Debug] Replace Revoke XML Success! | New XML: %s", (char*)revoke_xml_str_addr);
                break;
            }
        }

        if (SetArgValue(ctx, arg_bool_index, 1))
            OutputDebugPrintf("[Debug] Set Arg %d to 1", arg_bool_index);
        else
            OutputDebugPrintf("[Debug] Set Arg %d Failed!", arg_bool_index);
    }
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (!InitThreadStateTls()) {
            OutputDebugString(TEXT("[RevokeHook] InitThreadStateTls Failed!"));
            break;
        }

        OutputDebugString(TEXT("[RevokeHook] Reading Config..."));
        if (!ReadExternalConfig((char*)lpReserved)) break;   //ini路径通过第三个参数传进来
        OutputDebugString(TEXT("[RevokeHook] Begin Install VEH & Set Bp!"));

        if (!VehBp_Init(TRUE))
        {
            OutputDebugString(_T("[RevokeHook] VEHBp Init failed!"));
            return TRUE;
        }

		g_bpDelMsg = (void*)(g_config_info.basic_info.imgbase + g_config_info.basic_info.delmsg_offset);
		g_bpAdd2DB = (void*)(g_config_info.basic_info.imgbase + g_config_info.basic_info.add2db_offset);

        if (VehBp_Set(g_bpDelMsg, OnTargetHit) == -1)
            OutputDebugPrintf("[RevokeHook] AddBp %p Error", g_bpDelMsg);
        else
            OutputDebugPrintf("[RevokeHook] AddBp %p OK", g_bpDelMsg);
        
        if (VehBp_Set(g_bpAdd2DB, OnTargetHit) == -1)
            OutputDebugPrintf("[RevokeHook] AddBp %p Error", g_bpAdd2DB);
        else
            OutputDebugPrintf("[RevokeHook] AddBp %p OK", g_bpAdd2DB);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OutputDebugString(TEXT("[RevokeHook] Uninstall VEH & Cancel Bp!"));
        VehBp_Uninit();
        FreeCurrentThreadState();
        UninitThreadStateTls();
        break;
    }
    return TRUE;
}


