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
#include "add2db_args.h"
#include "message_notification.h"

//用于读取ini配置
#include "inicpp.h" 

//用于计算MD5
#pragma comment(lib, "crypt32.lib")

//打印日志
static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;

//VEH + INT3断点
static void* g_bpDelMsg = nullptr;
static void* g_bpAdd2DB = nullptr;
static void* g_bpPostAdd2DB = nullptr;
static void* g_bpAdd2DBResult = nullptr;
using MessageAddedSignal = void(__fastcall*)(void*, const revokehook::MessageVectorView*);
static MessageAddedSignal g_messageAddedSignal = nullptr;
static bool g_notification_profile_enabled = false;
static volatile LONG g_notification_dispatch_disabled = 0;
static SRWLOCK g_notification_lock = SRWLOCK_INIT;
static revokehook::PendingNotificationTable g_pending_notifications = {};

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
    bool insert_flag_callsite_matched; // Only set a flag for a verified call layout.
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

	// 同时写入到文件log中
    if (g_hLogFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
		strBuffer[strlen(strBuffer)] = '\n';  // 添加换行符
        WriteFile(g_hLogFile, strBuffer, (DWORD)strlen(strBuffer), &dwWritten, NULL);
    }
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

static revokehook::NotificationBytes ReadNotificationProfileBytes(
    uintptr_t base, uint32_t image_size, uint32_t rva, size_t size)
{
    if (rva > image_size || size > image_size - rva ||
        base > (std::numeric_limits<uintptr_t>::max)() - image_size)
        return {};
    const auto* bytes = reinterpret_cast<const uint8_t*>(base + rva);
    return IsMemoryReadable(bytes, size)
        ? revokehook::NotificationBytes{ bytes, size }
        : revokehook::NotificationBytes{};
}

static bool ReadNotificationImageIdentity(uintptr_t base, uint32_t& timestamp,
    uint32_t& image_size)
{
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!IsMemoryReadable(dos, sizeof(*dos)) || dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew < static_cast<LONG>(sizeof(*dos)) || dos->e_lfanew > 0x10000)
        return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (!IsMemoryReadable(nt, sizeof(*nt)) || nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return false;
    timestamp = nt->FileHeader.TimeDateStamp;
    image_size = nt->OptionalHeader.SizeOfImage;
    return true;
}

static void InitMessageNotificationProfile()
{
    g_notification_profile_enabled = false;
    g_bpPostAdd2DB = nullptr;
    g_bpAdd2DBResult = nullptr;
    g_messageAddedSignal = nullptr;
    const auto base = static_cast<uintptr_t>(g_config_info.basic_info.imgbase);
    revokehook::NotificationProfileView profile = {};
    if (g_config_info.add2db_info.insert_flag_callsite_matched &&
        ReadNotificationImageIdentity(base, profile.timestamp, profile.image_size))
    {
        profile.delete_call_rva = g_config_info.basic_info.delmsg_offset;
        profile.add_call_rva = g_config_info.basic_info.add2db_offset;
        profile.delete_call = ReadNotificationProfileBytes(base, profile.image_size,
            revokehook::kNotifyDeleteWindowRva, sizeof(revokehook::kNotifyDeleteBytes));
        profile.add_call = ReadNotificationProfileBytes(base, profile.image_size,
            revokehook::kNotifyAddCallRva - revokehook::kAdd2DbCallPrefixSize,
            sizeof(revokehook::kNotifyAddBytes));
        profile.post_call = ReadNotificationProfileBytes(base, profile.image_size,
            revokehook::kNotifyPostWindowRva, sizeof(revokehook::kNotifyPostBytes));
        profile.signal_entry = ReadNotificationProfileBytes(base, profile.image_size,
            revokehook::kNotifySignalRva, sizeof(revokehook::kNotifySignalBytes));
        profile.worker_result = ReadNotificationProfileBytes(base, profile.image_size,
            revokehook::kNotifyWorkerWindowRva, sizeof(revokehook::kNotifyWorkerBytes));
        if (revokehook::MatchesNotificationProfile(profile))
        {
            g_bpPostAdd2DB = reinterpret_cast<void*>(base + revokehook::kNotifyPostRva);
            g_bpAdd2DBResult = reinterpret_cast<void*>(base + revokehook::kNotifyWorkerResultRva);
            g_messageAddedSignal = reinterpret_cast<MessageAddedSignal>(
                base + revokehook::kNotifySignalRva);
            OutputDebugPrintf("[RevokeHook] Message notification profile verified (4.1.15.50)");
            return;
        }
    }
    OutputDebugStringA("[RevokeHook] Message notification disabled: unsupported image or call layout.");
    OutputDebugPrintf("[RevokeHook] Message notification profile not matched; no notification hook");
}

static bool HasRevokeXml(const StdString* text)
{
    if (!IsMemoryReadable(text, sizeof(*text)) || text->size <= 0 ||
        text->size > 0x10000 || text->capability < text->size || text->capability > 0x100000)
        return false;
    const char* data = text->data_ptr;
    if (text->capability >= sizeof(text->data_ptr))
        memcpy(&data, text->data_ptr, sizeof(data));
    return IsMemoryReadable(data, static_cast<size_t>(text->size)) &&
        revokehook::ContainsRevokeXml(data, static_cast<size_t>(text->size));
}

static bool ReadNotificationMessage(uintptr_t message, uint32_t& local_id,
    uint32_t& message_type, bool& has_revoke_xml)
{
    if (!g_config_info.add2db_info.initialized ||
        !IsMemoryReadable(reinterpret_cast<void*>(message), revokehook::kNotifyMessageSize))
        return false;
    const int xml_offset = g_config_info.add2db_info.offset_revoke_xml;
    if (xml_offset < 0 || static_cast<size_t>(xml_offset) >
        revokehook::kNotifyMessageSize - sizeof(StdString))
        return false;
    memcpy(&local_id, reinterpret_cast<void*>(message + revokehook::kNotifyLocalIdOffset),
        sizeof(local_id));
    memcpy(&message_type, reinterpret_cast<void*>(message + revokehook::kNotifyMessageTypeOffset),
        sizeof(message_type));
    has_revoke_xml = HasRevokeXml(reinterpret_cast<const StdString*>(message + xml_offset));
    return true;
}

static void ClearNotificationForFrame(PCONTEXT ctx)
{
    AcquireSRWLockExclusive(&g_notification_lock);
    revokehook::ClearNotificationFrame(g_pending_notifications, ctx->Rbp, ctx->Rsp);
    ReleaseSRWLockExclusive(&g_notification_lock);
}

static void CaptureNotificationForFrame(PCONTEXT ctx)
{
    const auto now = GetTickCount64();
    AcquireSRWLockExclusive(&g_notification_lock);
    const auto result = revokehook::CapturePendingNotification(g_pending_notifications,
        ctx->Rcx, ctx->Rbp, ctx->Rsp, now);
    ReleaseSRWLockExclusive(&g_notification_lock);
    if (result == revokehook::CaptureNotificationResult::Full)
        OutputDebugPrintf("[RevokeHook] Notification table full; skip this notification");
    else if (result != revokehook::CaptureNotificationResult::Captured)
        OutputDebugPrintf("[RevokeHook] Notification frame rejected");
}

static bool FindNotificationForMessage(uintptr_t message,
    revokehook::PendingNotification& snapshot)
{
    const auto now = GetTickCount64();
    AcquireSRWLockExclusive(&g_notification_lock);
    const bool found = revokehook::FindPendingNotification(
        g_pending_notifications, message, now, snapshot);
    ReleaseSRWLockExclusive(&g_notification_lock);
    return found;
}

static void ArmNotificationForMessage(const revokehook::PendingNotification& snapshot,
    uint32_t previous_local_id, const uint8_t* random_srvid)
{
    const auto now = GetTickCount64();
    AcquireSRWLockExclusive(&g_notification_lock);
    const bool armed = revokehook::ArmPendingNotification(
        g_pending_notifications, snapshot, previous_local_id,
        g_config_info.add2db_info.offset_srvid, random_srvid, now);
    ReleaseSRWLockExclusive(&g_notification_lock);
    OutputDebugPrintf(armed ? "[Debug] Message notification armed" :
        "[Debug] Message notification not armed (layout, expiry, replacement, or duplicate)");
}

static void RecordInsertedMessageResult(PCONTEXT ctx)
{
    if (ctx->Rbp < revokehook::kNotifyWorkerFrameMessageOffset ||
        g_config_info.add2db_info.offset_srvid != revokehook::kNotifySrvIdOffset)
        return;
    const uintptr_t message = ctx->Rbp - revokehook::kNotifyWorkerFrameMessageOffset;
    uint32_t local_id = 0, message_type = 0;
    bool has_revoke_xml = false;
    if (!ReadNotificationMessage(message, local_id, message_type, has_revoke_xml) ||
        message_type != revokehook::kNotifySystemMessageType || !has_revoke_xml)
        return;
    uint8_t random_srvid[8] = {};
    memcpy(random_srvid, reinterpret_cast<void*>(message + revokehook::kNotifySrvIdOffset),
        sizeof(random_srvid));
    const bool succeeded = (ctx->Rax & 0xFF) != 0;
    const auto now = GetTickCount64();
    AcquireSRWLockExclusive(&g_notification_lock);
    const auto result = revokehook::RecordNotificationCommit(g_pending_notifications,
        random_srvid, succeeded, local_id, now);
    ReleaseSRWLockExclusive(&g_notification_lock);
    if (result == revokehook::CommitNotificationResult::Recorded)
        OutputDebugPrintf(succeeded ? "[Debug] Message transaction success observed" :
            "[Debug] Message transaction failure observed; no notification");
    else if (result == revokehook::CommitNotificationResult::Ambiguous)
        OutputDebugPrintf("[RevokeHook] Ambiguous notification token; notification rejected");
}

static bool InvokeMessageAddedSignal(void* signal, const revokehook::MessageVectorView* view)
{
    __try
    {
        g_messageAddedSignal(signal, view);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void NotifyStoredMessage(PCONTEXT ctx)
{
    revokehook::NotificationRequest request = {};
    const auto now = GetTickCount64();
    AcquireSRWLockExclusive(&g_notification_lock);
    const bool taken = revokehook::TakePendingNotification(g_pending_notifications,
        ctx->Rbp, ctx->Rsp, now, request);
    ReleaseSRWLockExclusive(&g_notification_lock);
    if (!taken || InterlockedCompareExchange(&g_notification_dispatch_disabled, 0, 0) != 0)
        return;

    // No table lock is held while inspecting the message or calling subscribers.
    uint32_t local_id = 0, message_type = 0;
    bool has_revoke_xml = false;
    if (!ReadNotificationMessage(request.message, local_id, message_type, has_revoke_xml))
    {
        OutputDebugPrintf("[Debug] Notification skipped: message unavailable");
        return;
    }
    uint8_t random_srvid[8] = {};
    memcpy(random_srvid, reinterpret_cast<void*>(request.message + revokehook::kNotifySrvIdOffset),
        sizeof(random_srvid));
    if (!revokehook::IsStoredRevokeNotification(request, local_id, message_type,
        has_revoke_xml, random_srvid))
    {
        OutputDebugPrintf("[Debug] Notification skipped: transaction, identity, or XML not verified");
        return;
    }
    if (ctx->Rbp > (std::numeric_limits<uintptr_t>::max)() -
        revokehook::kNotifyFrameManagerOffset - sizeof(uintptr_t))
        return;
    const auto* manager_slot = reinterpret_cast<const uintptr_t*>(
        ctx->Rbp + revokehook::kNotifyFrameManagerOffset);
    uintptr_t current_manager = 0;
    if (!IsMemoryReadable(manager_slot, sizeof(*manager_slot)))
        return;
    memcpy(&current_manager, manager_slot, sizeof(current_manager));
    if (!revokehook::MatchesNotificationManager(request, current_manager))
    {
        OutputDebugPrintf("[Debug] Notification skipped: manager strong reference changed");
        return;
    }
    auto* signal = reinterpret_cast<uint8_t*>(request.manager + revokehook::kNotifySignalOffset);
    if (!IsMemoryReadable(signal, 2 * sizeof(void*)))
    {
        OutputDebugPrintf("[Debug] Notification skipped: manager signal unavailable");
        return;
    }
    void* signal_state = nullptr;
    memcpy(&signal_state, signal + sizeof(void*), sizeof(signal_state));
    if (!IsMemoryReadable(signal_state, sizeof(void*)))
    {
        OutputDebugPrintf("[Debug] Notification skipped: signal state unavailable");
        return;
    }
    revokehook::MessageVectorView view = {};
    if (!revokehook::BuildMessageVectorView(request.message, view) ||
        g_messageAddedSignal == nullptr)
        return;
    const bool delivered = InvokeMessageAddedSignal(signal, &view);
    if (delivered)
        OutputDebugPrintf("[Debug] Added-message signal dispatched");
    else
    {
        InterlockedExchange(&g_notification_dispatch_disabled, 1);
        OutputDebugStringA("[RevokeHook] Added-message signal raised an exception; further notifications disabled. Core hooks remain active.");
        OutputDebugPrintf("[RevokeHook] Added-message signal exception; subsequent dispatch disabled");
    }
}

static void InstallMessageNotificationBreakpoints(BpCallback callback)
{
    if (g_bpPostAdd2DB == nullptr || g_bpAdd2DBResult == nullptr || g_messageAddedSignal == nullptr)
        return;
    const int post_handle = VehBp_Set(g_bpPostAdd2DB, callback);
    const int result_handle = post_handle == -1 ? -1 : VehBp_Set(g_bpAdd2DBResult, callback);
    if (post_handle == -1 || result_handle == -1)
    {
        if (post_handle != -1)
            VehBp_Remove(post_handle);
        if (result_handle != -1)
            VehBp_Remove(result_handle);
        g_bpPostAdd2DB = nullptr;
        g_bpAdd2DBResult = nullptr;
        g_messageAddedSignal = nullptr;
        OutputDebugPrintf("[RevokeHook] Notification breakpoints unavailable; core hooks retained");
        return;
    }
    g_notification_profile_enabled = true;
    OutputDebugPrintf("[RevokeHook] Transaction-result and post-insert notification hooks enabled");
}

static void InitAdd2DbArgumentLayout(const void* call_address)
{
    auto& info = g_config_info.add2db_info;
    info.insert_flag_callsite_matched = false;
    const uintptr_t address = reinterpret_cast<uintptr_t>(call_address);
    if (address >= revokehook::kAdd2DbCallPrefixSize)
    {
        const auto* window = reinterpret_cast<const uint8_t*>(
            address - revokehook::kAdd2DbCallPrefixSize);
        if (IsMemoryReadable(window, revokehook::kAdd2DbCallWindowSize))
            info.insert_flag_callsite_matched = revokehook::MatchesKnownAdd2DbCall(
                window, revokehook::kAdd2DbCallWindowSize);
    }

    if (info.insert_flag_callsite_matched)
        OutputDebugPrintf("[RevokeHook] Add2DB arguments: verified byte flag at caller RSP+0x20");
    else
    {
        OutputDebugStringA("[RevokeHook] Unknown Add2DB call layout; argument bytes will be preserved.");
        OutputDebugPrintf("[RevokeHook] Add2DB arguments: unknown layout, no argument writes");
    }
}

static bool TrySetAdd2DbInsertFlag(PCONTEXT ctx)
{
    if (ctx == nullptr || !g_config_info.add2db_info.insert_flag_callsite_matched)
        return false;

    auto* stack = reinterpret_cast<uint8_t*>(ctx->Rsp);
    auto* flag = stack + revokehook::kAdd2DbInsertFlagStackOffset;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(flag, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
        !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;

    return revokehook::WriteAdd2DbInsertFlag(true, stack,
        revokehook::kAdd2DbInsertFlagStackOffset + 1);
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
    // Pass 3: low byte == 0, and is a valid user-mode pointer
    for (int i = start_idx; i <= end_idx; i++)
    {
        uint64_t val = GetArgValue(ctx, i);
        if (val != 0 && (val & 0xFF) == 0 &&
            (val >= 0x10000 && val <= 0x00007FFFFFFFFFFF))
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
    if (g_notification_profile_enabled && rip == reinterpret_cast<uint64_t>(g_bpAdd2DBResult))
    {
        RecordInsertedMessageResult(ctx);
        return;
    }
    if (g_notification_profile_enabled && rip == reinterpret_cast<uint64_t>(g_bpPostAdd2DB))
    {
        NotifyStoredMessage(ctx);
        return;
    }
    if (g_notification_profile_enabled && rip == reinterpret_cast<uint64_t>(g_bpDelMsg))
        ClearNotificationForFrame(ctx);
    ThreadState* thread_state = GetThreadState();
    if (thread_state == nullptr) {
        OutputDebugString(TEXT("[RevokeHook] GetThreadState Failed!"));
        return;
    }
  
    if (rip == (uint64_t)g_bpDelMsg) 
    {
        uint8_t revoke_sig[] = { 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; //'撤回'
        uint8_t self_revoke_sig[] = { 0xe4, 0xbd, 0xa0, 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; //'你撤回'
        uint8_t revoke_sig_english[] = { 0x72, 0x65, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64 }; //'recalled'
		uint8_t self_revoke_sig_english[] = { 0x59, 0x6f, 0x75, 0x20, 0x72, 0x65, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64 }; //'You recalled'

        StdString* revoke_xml = nullptr;

        if (!g_config_info.delmsg_info.initialized)
        {
            uint64_t candidates[] = { ctx->Rdx, ctx->R8, ctx->R9 };
            int candidate_indices[] = { 2, 3, 4 };

            for (int c = 0; c < 3 && revoke_xml == nullptr; c++)
            {
                revoke_xml = FindStdStringWithSig(candidates[c], 0x2000,
                    revoke_sig, sizeof(revoke_sig));
                if (revoke_xml == nullptr)
                {
                    revoke_xml = FindStdStringWithSig(candidates[c], 0x2000,
                        revoke_sig_english, sizeof(revoke_sig_english));
                }
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
        for (int64_t i = 0; i < (int64_t)revoke_xml->size; i++)
        {
            bool matches_chinese =
                i <= (int64_t)revoke_xml->size - (int64_t)sizeof(self_revoke_sig) &&
                memcmp((void*)(revoke_xml_str_addr + i),
                    self_revoke_sig, sizeof(self_revoke_sig)) == 0;
            bool matches_english =
                i <= (int64_t)revoke_xml->size - (int64_t)sizeof(self_revoke_sig_english) &&
                memcmp((void*)(revoke_xml_str_addr + i),
                    self_revoke_sig_english, sizeof(self_revoke_sig_english)) == 0;
            if (matches_chinese || matches_english)
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
        if (g_notification_profile_enabled && HasRevokeXml(revoke_xml))
            CaptureNotificationForFrame(ctx);

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
        const uint64_t arg_msg = GetArgValue(ctx, 3);
        if (!g_config_info.add2db_info.insert_flag_callsite_matched)
        {
            OutputDebugPrintf("[Debug] Add2DB skipped: unsupported call layout; message preserved");
            return;
        }
        const bool notification_profile = g_notification_profile_enabled;
        revokehook::PendingNotification notification_snapshot = {};
        if (notification_profile)
        {
            if (!FindNotificationForMessage(arg_msg, notification_snapshot))
                return;
        }
        else if (thread_state->anti_revoke_cur_msg == 0)
            return;

        if (!g_config_info.add2db_info.initialized)
        {
            if (arg_msg == 0 || !IsMemoryReadable((void*)arg_msg, 0x100))
            {
                OutputDebugPrintf("[Debug] Add2DB: arg_msg is invalid");
                return;
            }

            uint8_t anchor[] = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 }; //'一条' utf-8
			uint8_t anchor_english[] = { 0x61, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65 }; //'a message' ascii
            StdString* revoke_xml = FindStdStringWithSig(arg_msg, 0x1000, anchor, sizeof(anchor));
            if (revoke_xml == nullptr)
            {
                revoke_xml = FindStdStringWithSig(arg_msg, 0x1000,
                    anchor_english, sizeof(anchor_english));
            }
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

            g_config_info.add2db_info.offset_revoke_xml = xml_offset;
            g_config_info.add2db_info.offset_srvid = (int)(mem_srvid_addr - arg_msg);
            g_config_info.add2db_info.initialized = true;
            OutputDebugPrintf("[Debug] Add2DB cached: xml_off=0x%X, srvid_off=0x%X, flag_layout=%s",
                g_config_info.add2db_info.offset_revoke_xml,
                g_config_info.add2db_info.offset_srvid,
                g_config_info.add2db_info.insert_flag_callsite_matched ? "verified" : "unknown");
        }

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

        if (notification_profile &&
            g_config_info.add2db_info.offset_srvid != revokehook::kNotifySrvIdOffset)
        {
            OutputDebugPrintf("[Debug] Add2DB skipped: server ID offset differs from verified profile");
            return;
        }
        uint32_t previous_local_id = 0;
        if (notification_profile)
        {
            uint32_t message_type = 0;
            bool has_revoke_xml = false;
            if (!ReadNotificationMessage(arg_msg, previous_local_id, message_type, has_revoke_xml) ||
                message_type != revokehook::kNotifySystemMessageType || !has_revoke_xml)
            {
                OutputDebugPrintf("[Debug] Add2DB notification message rejected (type or XML)");
                return;
            }
        }
        uint64_t mem_srvid_addr = arg_msg + g_config_info.add2db_info.offset_srvid;

        uint64_t revoke_xml_str_addr = *((uint64_t*)(revoke_xml->data_ptr));
        OutputDebugPrintf("[Debug] %p | Revoke XML: %s", revoke_xml, (char*)revoke_xml_str_addr);

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
		uint8_t anchor_english[] = { 0x61, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65 }; //'a message' ascii
        uint8_t replace[] = { 0xe5, 0xa6, 0x82, 0xe4, 0xb8, 0x8a }; //'如上' utf-8
		uint8_t replace_english[] = { 0x61, 0x62, 0x6f, 0x76, 0x65, 0x20, 0x6d, 0x73, 0x67 }; //'above msg' ascii
        for (int64_t i = 0; i < (int64_t)revoke_xml->size; i++)
        {
            if (i <= (int64_t)revoke_xml->size - (int64_t)sizeof(anchor) &&
                memcmp((void*)(revoke_xml_str_addr + i), anchor, sizeof(anchor)) == 0)
            {
                memcpy((void*)(revoke_xml_str_addr + i), replace, sizeof(replace));
                OutputDebugPrintf("[Debug] Replace Revoke XML Success! | New XML: %s", (char*)revoke_xml_str_addr);
                break;
            }
            if (i <= (int64_t)revoke_xml->size - (int64_t)sizeof(anchor_english) &&
                memcmp((void*)(revoke_xml_str_addr + i),
                    anchor_english, sizeof(anchor_english)) == 0)
            {
                memcpy((void*)(revoke_xml_str_addr + i),
                    replace_english, sizeof(replace_english));
                memset((void*)(revoke_xml_str_addr + i + sizeof(replace_english)), ' ',
                    sizeof(anchor_english) - sizeof(replace_english));
                OutputDebugPrintf("[Debug] Replace English Revoke XML Success! | New XML: %s",
                    (char*)revoke_xml_str_addr);
                break;
            }
        }

        if (g_config_info.add2db_info.insert_flag_callsite_matched)
        {
            if (TrySetAdd2DbInsertFlag(ctx))
            {
                OutputDebugPrintf("[Debug] Add2DB: set argument 5 low byte to 1");
                if (notification_profile)
                    ArmNotificationForMessage(notification_snapshot, previous_local_id,
                        rand_srvid.data());
            }
            else
                OutputDebugPrintf("[Debug] Add2DB: argument 5 is not writable; preserved");
        }
    }
}

void InitLog()
{
    if (g_hLogFile != INVALID_HANDLE_VALUE)
        return;

    char tempPath[MAX_PATH] = { 0 };
    if (GetTempPathA(MAX_PATH, tempPath) == 0)
    {
        OutputDebugStringA("[RevokeHook] GetTempPath For Log Failed!");
        return;
    }

    std::string logPath = std::string(tempPath) + "RevokeHook.log";

    g_hLogFile = CreateFileA(
        logPath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, // 允许其他程序打开
        nullptr,
        CREATE_ALWAYS,                    // 每次打开时清空旧日志
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (g_hLogFile == INVALID_HANDLE_VALUE)
    {
        OutputDebugStringA("[RevokeHook] CreateFile Log Failed!");
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

        if (g_output_debeug_msg) InitLog(); // 初始化日志文件

        if (!VehBp_Init(TRUE))
        {
            OutputDebugString(_T("[RevokeHook] VEHBp Init failed!"));
            return TRUE;
        }

		g_bpDelMsg = (void*)(g_config_info.basic_info.imgbase + g_config_info.basic_info.delmsg_offset);
		g_bpAdd2DB = (void*)(g_config_info.basic_info.imgbase + g_config_info.basic_info.add2db_offset);
        // Inspect the original CALL bytes before VehBp_Set writes INT3.
        InitAdd2DbArgumentLayout(g_bpAdd2DB);
        InitMessageNotificationProfile();

        if (VehBp_Set(g_bpDelMsg, OnTargetHit) == -1)
            OutputDebugPrintf("[RevokeHook] AddBp %p Error", g_bpDelMsg);
        else
            OutputDebugPrintf("[RevokeHook] AddBp %p OK", g_bpDelMsg);
        
        if (VehBp_Set(g_bpAdd2DB, OnTargetHit) == -1)
            OutputDebugPrintf("[RevokeHook] AddBp %p Error", g_bpAdd2DB);
        else
            OutputDebugPrintf("[RevokeHook] AddBp %p OK", g_bpAdd2DB);

        InstallMessageNotificationBreakpoints(OnTargetHit);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OutputDebugString(TEXT("[RevokeHook] Uninstall VEH & Cancel Bp!"));
        VehBp_Uninit();
        FreeCurrentThreadState();
        UninitThreadStateTls();
        if (g_hLogFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_hLogFile);
            g_hLogFile = INVALID_HANDLE_VALUE;
		}
        break;
    }
    return TRUE;
}


