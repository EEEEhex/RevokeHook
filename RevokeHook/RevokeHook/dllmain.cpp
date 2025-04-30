#include "framework.h"
#include <wincrypt.h>

#include <tchar.h>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>  
#include <random>
#include <algorithm>

//用于读取ini配置
#include "inicpp.h" 

//x64汇编
#include "wrapper.h"

//用于计算MD5
#pragma comment(lib, "crypt32.lib")

// 劫持ilink2.dll -> ilink2Org.dll
#pragma comment(linker, "/EXPORT:CreateIlinkNetwork=ilink2Org.CreateIlinkNetwork,@1")
#pragma comment(linker, "/EXPORT:CreateNetworkManager=ilink2Org.CreateNetworkManager,@2")
#pragma comment(linker, "/EXPORT:CreateNetworkManagerBridge=ilink2Org.CreateNetworkManagerBridge,@3")
#pragma comment(linker, "/EXPORT:CreateNetworkManagerNoSTL=ilink2Org.CreateNetworkManagerNoSTL,@4")
#pragma comment(linker, "/EXPORT:CreateTdiManager=ilink2Org.CreateTdiManager,@5")
#pragma comment(linker, "/EXPORT:DeleteIlinkNetwork=ilink2Org.DeleteIlinkNetwork,@6")
#pragma comment(linker, "/EXPORT:DestroyNetworkManager=ilink2Org.DestroyNetworkManager,@7")
#pragma comment(linker, "/EXPORT:DestroyNetworkManagerBridge=ilink2Org.DestroyNetworkManagerBridge,@8")
#pragma comment(linker, "/EXPORT:DestroyNetworkManagerNoSTL=ilink2Org.DestroyNetworkManagerNoSTL,@9")
#pragma comment(linker, "/EXPORT:DestroyTdiManager=ilink2Org.DestroyTdiManager,@10")
#pragma comment(linker, "/EXPORT:GetContext=ilink2Org.GetContext,@11")
#pragma comment(linker, "/EXPORT:GetContextBridge=ilink2Org.GetContextBridge,@12")
#pragma comment(linker, "/EXPORT:GetContextNoSTL=ilink2Org.GetContextNoSTL,@13")
#pragma comment(linker, "/EXPORT:GetIlinkDeviceInterface=ilink2Org.GetIlinkDeviceInterface,@14")
#pragma comment(linker, "/EXPORT:GetIlinkXlogInterface=ilink2Org.GetIlinkXlogInterface,@15")
#pragma comment(linker, "/EXPORT:GetLogManager=ilink2Org.GetLogManager,@16")
#pragma comment(linker, "/EXPORT:GetLogManagerBridge=ilink2Org.GetLogManagerBridge,@17")
#pragma comment(linker, "/EXPORT:GetLogManagerNoSTL=ilink2Org.GetLogManagerNoSTL,@18")
#pragma comment(linker, "/EXPORT:__ASSERT=ilink2Org.__ASSERT,@19")

extern "C" uint64_t HijackLogic(uint64_t key_class);    //劫持逻辑
extern "C" uint64_t g_imgbase = 0;                      //Weixin.dll的基址
extern "C" uint64_t g_hook_offset = 0;                  //要hook的偏移
extern "C" uint64_t g_delmsg_offset = 0;                //DeleteMessage函数的偏移 需要Patch为Nop
extern "C" uint8_t* g_transfer_zone = 0;                //中转指令内存


uint64_t g_last_org_srvid = 0;                          //真实的srvid 防止插入两条撤回提醒
std::vector<uint8_t> g_last_unique_id = {};             //上一次生成的

//配置信息 包括关键类中成员的偏移信息
struct CONFIGINFO
{
    int srvid;
    int revoke_msg;
    int wxid_sender;
    int wxid_receiver;
}g_config_info;

//std::string的内存布局
struct StdString
{
    const char data_ptr[16];
    int64_t size;
    int64_t capability;
};

struct OrgInfo
{
    uint64_t     addr;              //地址
    size_t      org_size;           //原始机器码长度
    uint8_t     org_opcodes[256];   //被HOOK之前原始的机器码
};
std::vector<OrgInfo> g_org_info;

ini::IniFile g_config; //ini配置

void OutputDebugPrintf(const char* strOutputString, ...)
{
#define OUT_DEBUG_BUF_LEN   512
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
 * @brief 恢复HOOK写入的字节.
 */
void HookEnd()
{
    //写入原机器码
    if (g_org_info.size() != 0) {
        for (auto& org_info : g_org_info)
        {
            if (org_info.addr == 0) {
                OutputDebugString(TEXT("[RevokeHook] Hook Addr is 0"));
                continue;
            }
            BOOL bRet = WriteProcessMemory(GetCurrentProcess(), (LPVOID)org_info.addr, org_info.org_opcodes, org_info.org_size, NULL);
            if (bRet == NULL)
                OutputDebugPrintf("[RevokeHook] Write Hook Org Bytes Failed! [%d]", GetLastError());
        }
    }
    if (g_transfer_zone) {
        if (!VirtualFree(g_transfer_zone, 0, MEM_RELEASE)) {
            OutputDebugPrintf("[RevokeHook] Free Transfer Mem Failed! [%d]", GetLastError());
            return;
        }
    }
}

/**
 * @brief 劫持逻辑 修改KeyClass类的成员变量.
 * @param a3 即r8, 父函数的第三个参数(关键内存)
 * @return 返回值无用
 */
uint64_t HijackLogic(uint64_t a3/*r8*/)
{
    int srvid_offset = g_config_info.srvid;
    int revoke_msg_offset = g_config_info.revoke_msg;
    uint64_t key_class = a3;

    //修改srvid为随机的
    std::vector<uint8_t> rand_srvid = GetUniquePositiveValue();
    if (rand_srvid.size() != 8) {
        OutputDebugString(TEXT("[RevokeHook] GetUniquePositiveValue Err!"));
        return 0;
    }

    uint64_t mem_srvid_addr = key_class + srvid_offset, org_srvid = 0;
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)mem_srvid_addr, &org_srvid, 8, NULL); //读取原SrvID
    if (g_last_org_srvid == org_srvid) {
        rand_srvid = g_last_unique_id;
    }
    else {
        g_last_unique_id = rand_srvid;
        g_last_org_srvid = org_srvid;//更新
    }

    BOOL bRet = WriteProcessMemory(GetCurrentProcess(), (LPVOID)mem_srvid_addr , rand_srvid.data(), rand_srvid.size(), NULL);
    if (bRet == NULL)
    {
        OutputDebugPrintf("[RevokeHook] Hijack Write SrvID Bytes Failed! [%d]", GetLastError());
        return 0;
    }

    //修改撤回提醒字符串 (构造成sysmsg的)
    uint64_t mem_revoke_msg_str_addr = key_class + revoke_msg_offset;
    StdString* mem_revoke_msg_str = (StdString*)mem_revoke_msg_str_addr;
    uint64_t revoke_msg_addr = mem_revoke_msg_str_addr;
    if (mem_revoke_msg_str->capability >= 0x10) {//大于16个字节的另申请内存
        revoke_msg_addr = *((uint64_t*)revoke_msg_addr);
    }
    std::vector<uint8_t> revoke_msg_utf8(mem_revoke_msg_str->size);//读取原撤回提醒字符串的数据
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)revoke_msg_addr, revoke_msg_utf8.data(), mem_revoke_msg_str->size, NULL);

    size_t anchor_pos = -1; //'一条'的位置 将其修改为'如上'
    std::vector<uint8_t> anchor = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 }; //'一条' utf-8
    auto it = std::search(revoke_msg_utf8.begin(), revoke_msg_utf8.end(), anchor.begin(), anchor.end());
    if (it != revoke_msg_utf8.end()) {
        anchor_pos = std::distance(revoke_msg_utf8.begin(), it);
    }
    if (anchor_pos == -1) {
        OutputDebugPrintf("[RevokeHook] Hijack Get Revoke Msg Pos Failed! [%d]", GetLastError());
        return 0;
    }
    std::vector<uint8_t> replace = { 0xe5, 0xa6, 0x82, 0xe4, 0xb8, 0x8a }; //'如上' utf-8
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)(revoke_msg_addr + anchor_pos), replace.data(), replace.size(), NULL);
    return 0;
}

/**
 * @brief Hook逻辑 执行完HijackLogic后再执行原逻辑.
 * @param hModule 当前dll的句柄
 */
void HookStart(HMODULE hModule)
{
    HMODULE weixin_dll_base = GetModuleHandle(_T("Weixin.dll"));
    if (weixin_dll_base == NULL)
    {
        OutputDebugPrintf("[RevokeHook] Get Weixin.dll's ImgBase Failed! [%d]", GetLastError());
        return;
    }
    g_imgbase = (uint64_t)weixin_dll_base;

    //更改Hook逻辑: 1. 先Patch DeleteMsg函数为Nop 2. 修改CoAddMessageToDB最后一个参数为True(1) 3. 再在插入到数据库之前修改srvid
    //要劫持的这个地方是在call CoAddMessageToDB指令之前
    //前三条指令共12个字节, 且不涉及重定位操作, 所以HOOK逻辑是把这些指令改为mov rax, HijackLogicWarpper; + jmp rax;
    //然后执行完HijackLogic后, jmp 中转区; 在这块内存里执行原先三条汇编指令(最后一条指令改为mov *, 1) + jmp next_insn;
    //即|jmp hijack| -> |hijack_logic + jmp transfer_zone| -> |org_logic + jmp org_next_insn| -> |...|

    //Patch Call DeleteMessage -> Nops
    uint64_t delmsg_addr = g_imgbase + g_delmsg_offset;
    uint8_t patch_opcode[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };  //call占5个字节
    size_t patch_size = sizeof(patch_opcode); //5个字节
   
    OrgInfo delmsg_org_info;// 记录原始字节信息
    delmsg_org_info.addr = delmsg_addr;         //记录地址   
    delmsg_org_info.org_size = patch_size;      //记录要写多少个字节
    BOOL bRet = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)delmsg_addr, delmsg_org_info.org_opcodes, patch_size, NULL);
    if (bRet == NULL)
    {
        OutputDebugPrintf("[RevokeHook] Read Patch Org Bytes Failed! [%d]", GetLastError());
        return;
    }
    g_org_info.push_back(delmsg_org_info); //记录

    bRet = WriteProcessMemory(GetCurrentProcess(), (LPVOID)delmsg_addr, patch_opcode, patch_size, NULL);
    if (bRet == NULL)
    {
        OutputDebugPrintf("[RevokeHook] Write Patch Nop Bytes Failed! [%d]", GetLastError());
        return;
    }

    //读取Hook点原机器码
    uint64_t hook_addr = g_imgbase + g_hook_offset;//rax没用
    uint8_t hook_opcode[] = {/*mov rax, 地址*/0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*jmp rax*/0xFF, 0xE0 };
    size_t hook_size = sizeof(hook_opcode); //12个字节

    OrgInfo hook_org_info;// 记录原始字节信息
    hook_org_info.addr = hook_addr;         //记录地址
    hook_org_info.org_size = hook_size;     //记录要写多少个字节
    bRet = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hook_addr, hook_org_info.org_opcodes, hook_size, NULL);
    if (bRet == NULL)
    {
        OutputDebugPrintf("[RevokeHook] Read Hook Org Bytes Failed! [%d]", GetLastError());
        return;
    }
    g_org_info.push_back(hook_org_info); //记录

    //构造中转区机器码 原指令 + jmp far
    size_t org_insns_len = 12;  //暂时先写死
    g_transfer_zone = (uint8_t*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_transfer_zone) {
        OutputDebugPrintf("[RevokeHook] Alloc Transfer Mem Failed! [%d]", GetLastError());
        return;
    }

    bRet = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hook_addr, g_transfer_zone, org_insns_len, NULL);
    if (bRet == NULL)
    {
        OutputDebugPrintf("[RevokeHook] Read Transfer Zone Org Bytes Failed! [%d]", GetLastError());
        return;
    }
    //修改mov [rsp+38h+a5], 0为mov [rsp+38h+a5], 1
    g_transfer_zone[org_insns_len - 1] = 1;         //CoAddMessageToDB最后一个参数 这个参数应该是控制着是否可以插入新local_id

    uint8_t jmp_org_opcode[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
    uint64_t next_insn_addr = hook_addr + org_insns_len;
    for (size_t i = 0; i < sizeof(uint64_t); i++) //跳回去
        jmp_org_opcode[i + 2] = *((uint8_t*)(&next_insn_addr) + i);
    memcpy(g_transfer_zone + org_insns_len, jmp_org_opcode, sizeof(jmp_org_opcode));
   
    //写入劫持机器码 跳转到HijackLogicWarpper函数处
    uint64_t hijacklogic_addr = (uint64_t)(&HijackLogicWarpper);
    for (size_t i = 0; i < sizeof(uint64_t); i++)
    {
        hook_opcode[i + 2] = *((uint8_t*)(&hijacklogic_addr) + i);
    }
    bRet = WriteProcessMemory(GetCurrentProcess(), (LPVOID)hook_addr, hook_opcode, hook_size, NULL);
    if (bRet == NULL)
    {
        OutputDebugPrintf("[RevokeHook] Write Hook Bytes Failed! [%d]", GetLastError());
        return;
    }
}

/**
 * @brief 从运行目录下的RevokeHook.ini读取配置.
 */
void ReadExternalConfig()
{
    // 设置工作目录为当前运行目录
    char sBuf[MAX_PATH], *ptr;
    if (GetModuleFileNameA(NULL, sBuf, sizeof(sBuf)))
    {
        ptr = strrchr(sBuf, '\\');
        if (ptr)
            *ptr = '\0';
        SetCurrentDirectoryA(sBuf);
    }
    OutputDebugPrintf("[RevokeHook] Current Dir: %s", sBuf);

    g_config.load("RevokeHook.ini");
    g_hook_offset = g_config["Hook"]["Offset"].as<int>();
    g_delmsg_offset = g_config["Hook"]["DelMsg"].as<int>();
    g_config_info.srvid = g_config["Class"]["SrvID"].as<int>();
    g_config_info.revoke_msg = g_config["Class"]["RevokeMsg"].as<int>();
    g_config_info.wxid_sender = g_config["Class"]["WxIDS"].as<int>();
    g_config_info.wxid_receiver = g_config["Class"]["WxIDR"].as<int>();
    OutputDebugPrintf("[RevokeHook] Use Offset: 0x%llX...", g_hook_offset);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule); //防止多次调用
        //不知道为什么不会自动加载ilink2Org.dll 直接手动加载
        OutputDebugPrintf("[RevokeHook] Load ilink2Org.dll: 0x%llX...", LoadLibrary(TEXT("ilink2Org.dll")));
        OutputDebugString(TEXT("[RevokeHook] Reading Config [RevokeHook.ini]..."));
        ReadExternalConfig();
        OutputDebugString(TEXT("[RevokeHook] Begin Hook and Hijack!"));
        HookStart(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        OutputDebugString(TEXT("[RevokeHook] Restore Hook Bytes!"));
        HookEnd();
        break;
    }
    return TRUE;
}


