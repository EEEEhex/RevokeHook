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

uint8_t thread_local g_last_org_srvid[8] = {0}; //真实的srvid 防止插入两条撤回提醒
uint8_t thread_local g_anti_revoke_cur_msg = 0; //是否防撤回当前这条消息

//配置信息
struct BASICINFO
{
    uint64_t imgbase;           // Weixin.dll的基址
	uint64_t add2db_offset;     // 将撤回消息添加到数据库的函数偏移
	uint64_t delmsg_offset;     // 删除要撤回消息函数的偏移
};

struct DELMSGINFO
{
    int arg_msg_index;
    int offset_wxid_first;
    int offset_wxid_second;
    int offset_wxid_third;
};

struct ADD2DBINFO
{
    int arg_msg_index;
    int arg_bool_index;
    int offset_srvid;
    int offset_revoke_xml;
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
    
	g_config_info.delmsg_info.arg_msg_index = g_config["DelMsg"]["ArgMsgIndex"].as<int>();
	g_config_info.delmsg_info.offset_wxid_first = g_config["DelMsg"]["OffsetWxIDFirst"].as<int>();
	g_config_info.delmsg_info.offset_wxid_second = g_config["DelMsg"]["OffsetWxIDSecond"].as<int>();
	g_config_info.delmsg_info.offset_wxid_third = g_config["DelMsg"]["OffsetWxIDThird"].as<int>();

	g_config_info.add2db_info.arg_msg_index = g_config["Add2DB"]["ArgMsgIndex"].as<int>();
	g_config_info.add2db_info.arg_bool_index = g_config["Add2DB"]["ArgBoolIndex"].as<int>();
	g_config_info.add2db_info.offset_revoke_xml = g_config["Add2DB"]["OffsetRevokeXML"].as<int>();
	g_config_info.add2db_info.offset_srvid = g_config["Add2DB"]["OffsetSrvID"].as<int>();

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

static void OnTargetHit(PCONTEXT ctx, PEXCEPTION_RECORD /*pExc*/)
{
    uint64_t rip = ctx->Rip;
  
    if (rip == (uint64_t)g_bpDelMsg) 
    {
        uint64_t arg_msg = GetArgValue(ctx, g_config_info.delmsg_info.arg_msg_index);
        StdString* wxid_first = (StdString*)(arg_msg + g_config_info.delmsg_info.offset_wxid_first);
        StdString* wxid_second = (StdString*)(arg_msg + g_config_info.delmsg_info.offset_wxid_second);
        if ((wxid_first->size > 0) && (wxid_second->size > 0)) {
			char* wxid_first_str = (char*)(*((uint64_t*)(wxid_first->data_ptr)));
			char* wxid_second_str = (char*)(*((uint64_t*)(wxid_second->data_ptr)));
            
            OutputDebugPrintf("[Debug] %p | wxid 1: %s", wxid_first, wxid_first_str);
            OutputDebugPrintf("[Debug] %p | wxid 2: %s", wxid_second, wxid_second_str);

			// 相等说明是自己撤回的消息, 不执行防撤回
            if (!g_anti_revoke_self_msg && (strcmp(wxid_first_str, wxid_second_str) == 0)) {
				g_anti_revoke_cur_msg = 0; //重置状态
            }
            else {
				g_anti_revoke_cur_msg = 1; //标记当前这条消息是需要防撤回的

                ctx->Rip += 5; // 跳过call
                OutputDebugPrintf("[Debug] Skip Call, New RIP: %p", ctx->Rip);
            }
        }
        else {
			OutputDebugPrintf("[Debug] WxID is empty!");
        }
    }
    else if (rip == (uint64_t)g_bpAdd2DB) 
    {
		if (g_anti_revoke_cur_msg == 0) return; //如果当前消息不需要防撤回 直接返回

		int arg_bool_index = g_config_info.add2db_info.arg_bool_index;
		uint64_t arg_bool = GetArgValue(ctx, arg_bool_index);
		uint64_t arg_msg = GetArgValue(ctx, g_config_info.add2db_info.arg_msg_index);
        StdString* revoke_xml = (StdString*)(arg_msg + g_config_info.add2db_info.offset_revoke_xml);
        if (revoke_xml->size > 0) {
            OutputDebugPrintf("[Debug] %p | Revoke XML: %s | bool: %d", revoke_xml, *((uint64_t*)(revoke_xml->data_ptr)), arg_bool);

            if (SetArgValue(ctx, arg_bool_index, 1)) {
				OutputDebugPrintf("[Debug] Set Arg %d to 1", arg_bool_index);
            }
            else {
				OutputDebugPrintf("[Debug] Set Arg %d Failed!", arg_bool_index);
            }

			uint64_t mem_srvid_addr = arg_msg + g_config_info.add2db_info.offset_srvid;

			uint8_t org_srvid[8] = { 0 };
            memcpy(org_srvid, (void*)mem_srvid_addr, 8);//读取原SrvID
            OutputDebugPrintf("[Debug] Org srvid: %p | Last srvid: %p", *((uint64_t*)org_srvid), *((uint64_t*)g_last_org_srvid));
            if (memcmp(g_last_org_srvid, org_srvid, 8) == 0) {
				return; //防止插入两条撤回提醒
            }
			memcpy(g_last_org_srvid, org_srvid, 8);//更新全局记录的最后一个srvid
			OutputDebugPrintf("[Debug] Update last srvid: %p", *((uint64_t*)g_last_org_srvid));


            //修改srvid为随机的
            std::vector<uint8_t> rand_srvid = GetUniquePositiveValue();
            if (rand_srvid.size() != 8) {
                OutputDebugString(TEXT("[RevokeHook] GetUniquePositiveValue Err!"));
                return;
            }
			OutputDebugPrintf("[Debug] Original SrvID: %p [%X %X...]", mem_srvid_addr, ((uint8_t*)mem_srvid_addr)[0], ((uint8_t*)mem_srvid_addr)[1]);

        
			memcpy((void*)mem_srvid_addr, rand_srvid.data(), rand_srvid.size());

            //修改撤回提醒字符串 (构造成sysmsg的)
            uint64_t revoke_xml_str_addr = *((uint64_t*)(revoke_xml->data_ptr));
            uint8_t anchor[] = {0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1}; //'一条' utf-8
            for (int i = 0; i <= revoke_xml->size - 6; i++) {

				int equal_count = 0;
                for (int j = 0; j < 6; j++) {
                    if (((uint8_t*)revoke_xml_str_addr)[i + j] == anchor[j])
                        equal_count++;
                    else
						break;
                }
                if (equal_count == 6) {
                    uint8_t replace[] = {0xe5, 0xa6, 0x82, 0xe4, 0xb8, 0x8a}; //'如上' utf-8
                    memcpy((void*)(revoke_xml_str_addr + i), replace, sizeof(replace));
					OutputDebugPrintf("[Debug] Replace Revoke XML Success! | New XML: %s", (char*)revoke_xml_str_addr);
                    break;
                }            
            }
        }
        else {
            OutputDebugPrintf("[Debug] Revoke XML is empty! | [%p, %p]", arg_msg, revoke_xml);
        }
    
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
    case DLL_PROCESS_DETACH:
        OutputDebugString(TEXT("[RevokeHook] Uninstall VEH & Cancel Bp!"));
        VehBp_Uninit();
        break;
    }
    return TRUE;
}


