#include <iostream>
#include <string>

#include <Windows.h>
#include <psapi.h>

#include "Utils.h"
extern "C" {
#include "ReflectiveInject.h"
}//不进行名称修饰

#include "inicpp.h"     //ini解析
#include "args.hxx"     //命令行解析
#include "logger.h"     //日志模块 
using namespace MyLogger;
#include "DbgConsole.h"

//不显示控制台窗口
#pragma comment(linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
#pragma comment (lib, "Psapi.lib")

#define INI_FILE "RevokeHook.ini"
#define DLL_FILE "RevokeHook.dll"

ini::IniFile g_setting;      //ini配置

bool GetProcessIdByName(const std::string& processName, DWORD& pid) {
    DWORD processIds[1024], bytesReturned;
    if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        return false;
    }

    unsigned int processCount = bytesReturned / sizeof(DWORD);
    for (unsigned int i = 0; i < processCount; ++i) {
        DWORD processId = processIds[i];
        if (processId == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess != NULL) {
            char szProcessName[MAX_PATH] = "<unknown>";

            // 获取进程名称
            if (GetModuleFileNameExA(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(char))) {
                if (processName == szProcessName) {
                    pid = processId;
                    CloseHandle(hProcess);
                    return true;
                }
            }
            CloseHandle(hProcess);
        }
    }
    return false;
}

bool PopUpTip(std::string msg, std::string title) {
    // 设置WinToast参数
    std::string command = "RevokeHookUI.exe --msg-title \"[" + title + "]\" --msg-content \"" + msg + "\"";
	std::wstring command_w = RIUtils::Utf8ToWide(command);

    // 创建进程
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(
        NULL,                            // 应用程序名
        &command_w[0],                   // 命令行
        NULL,                            // 进程安全属性
        NULL,                            // 线程安全属性
        FALSE,                           // 继承句柄
        0,                               // 进程创建标志
        NULL,                            // 环境变量
        NULL,                            // 当前目录
        &si,                             // 启动信息
        &pi)) {                          // 进程信息
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// 创建一个每天切割日志的日志记录器 文件名格式：log_YYYY-MM-DD.txt
Logger& logger = Logger::getInstance();
void logOut(std::string txt, bool err = false) {
    if (err) {
        logger.error(txt);
        PopUpTip(txt, "RevokeInject Error");
        return;
    }
    logger.info(txt);
}

int main(int argc, char** argv)
{
    //解析命令行参数
    args::ArgumentParser parser("Reflective Dll Inject Launcher.", "version [3.4.0].");
    args::HelpFlag help(parser, "help", "Display this help menu", { 'h', "help" });
    args::Flag out_console(parser, "console", "Out the log info to console", { 'c', "console" });
    args::Flag no_ver_check(parser, "nocheck", "Not check the versions in reg and ini", { 'n', "nocheck" });
    args::ValueFlag<std::string> wxpath(parser, "wxpath", "Input the weixin path", { 'w', "wxpath"});
    try
    {
        parser.ParseCLI(argc, argv);
    }
    catch (args::Help)
    {
        DbgConsole::getInstance();  //显示窗口
        std::cout << parser;
        return 0;
    }
    catch (args::ParseError e)
    {
        DbgConsole::getInstance();  //显示窗口
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return 1;
    }
    catch (args::ValidationError e)
    {
        DbgConsole::getInstance();  //显示窗口
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return 1;
    }

    // 设置工作目录为当前运行目录
    char sBuf[MAX_PATH], * ptr;
    if (GetModuleFileNameA(NULL, sBuf, sizeof(sBuf)))
    {
        ptr = strrchr(sBuf, '\\');
        if (ptr)
            *ptr = '\0';
        SetCurrentDirectoryA(sBuf);
    }

    //设置日志到文件
    if (out_console) {
        DbgConsole::getInstance();  //显示窗口
        logger.setLogLevel(LogLevel::LDEBUG);
        logger.setOutputToFile(false);  //日志输出到控制台
    }
    else {
        logger.setOutputToFile(true);   //日志输出到文件
        logger.setLogLevel(LogLevel::LINFO);
        logger.setLogFilePath("./logs");
    }

    g_setting.load(INI_FILE);           //读取ini配置文件
    bool injectover_tip = g_setting["Setting"]["OverTip"].as<bool>();

    //启动微信并进行反射dll注入
    logOut("[=] -------------------------------------");
    if (!no_ver_check) { //验证配置中的偏移版本和当前微信版本是否一致
        std::string use_version = g_setting["Setting"]["Ver"].as<std::string>();
		std::string wx_path = wxpath ? args::get(wxpath) : "";  //参数不为空 从参数中获取微信版本
        std::string install_version = RIUtils::GetWeixinVerion(wx_path);
        logOut("[+] Get ini version [" + use_version + "] and install version [" + install_version + "].");
        if (!install_version.empty() && (install_version != "0.0.0.0")) {
            if (use_version != install_version) {
                logOut("[-] version in ini and install NOT EQUAL!", true);
                int result = MessageBoxW(NULL, L"检测到配置与本地微信版本不同, 是否打开RevokeHookUI进行更新?", L"提示", MB_OKCANCEL);
                if (result == IDOK) {
                    HINSTANCE hInst = ShellExecuteA(NULL, "open", "RevokeHookUI.exe", NULL, NULL, SW_SHOW);
                    if ((int)hInst <= 32) {                    // 判断是否成功打开
                        PopUpTip("启动 [RevokeHookUI.exe] 失败!", "提示");
                    }
                    else {
                        Sleep(400); //等待程序启动
                        HWND hwnd = FindWindowA(NULL, "RevokeHookUI");  // 查找程序窗口句柄
                        if (hwnd) {// 将窗口置于最前
                            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
                        }
                    }
                    return 0;
                }
            }
        }
    }
    else {
        logOut("[-] Skip version check...");
    }

    // 1. 获取微信路径
    std::string weixin_path = wxpath ? args::get(wxpath) : RIUtils::GetWeixinPath();
    if (weixin_path.empty()) {
        logOut("[-] Can't auto get weixin install path...", true);
        return 0;
    }
    logOut("[+] Get weixin path: " + weixin_path);

    // 2. 读入要反射注入的DLL文件
    HANDLE hFile = CreateFileA(DLL_FILE, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        logOut("[-] Failed to open the DLL file", true);
        return 0;
    }

    DWORD dwLength = GetFileSize(hFile, NULL);
    if (dwLength == INVALID_FILE_SIZE || dwLength == 0) {
        logOut("[-] Failed to get the DLL file size", true);
        return 0;
    }

    LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
    if (!lpBuffer) {
        logOut("[-] Failed to alloc a buffer!", true);
        return 0;
    }

    DWORD dwBytesRead = 0;
    if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE) {
        logOut("[-] Failed to read the dll!", true);
        return 0;
    }
    logOut("[+] Read Dll: " + std::string(DLL_FILE) + " OK!");
    
    // 3. 提权
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES priv = { 0 };
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
            AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

        CloseHandle(hToken);
    }
    else {
        logOut("[-] Failed to AdjustTokenPrivileges!");
    }
    logOut("[+] AdjustTokenPrivileges Succeed!");

    // 4. 启动微信进程并获取句柄
    std::string weixin_exe = (weixin_path + "\\Weixin.exe"); //Weixin.exe路径

    bool isInjectRunning = false; //是否是注入到已运行的微信中
    DWORD dwPid = 0;
    HANDLE hProcess = 0;
    if (GetProcessIdByName(weixin_exe, dwPid)) {//判断微信是否已启动
        logOut("[+] GetWeixinPidByName: " + std::to_string(dwPid));
        hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwPid);
        isInjectRunning = true;
    }

    if (hProcess == 0) {
        SHELLEXECUTEINFOA sei = { 0 };
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;                    // 通过此标志 返回值包含进程句柄
        sei.hwnd = NULL;                                        // 所有者窗口的句柄
        sei.lpVerb = "open";                                    // 操作类型
        sei.lpFile = weixin_exe.c_str();                        // 可执行文件路径
        sei.lpParameters = NULL;
        sei.lpDirectory = weixin_path.c_str();
        sei.nShow = SW_SHOWNORMAL;

        if (!ShellExecuteExA(&sei)) {
            logOut("[-] Failed to launch [Weixin.exe]!: " + std::to_string(GetLastError()), true);
            return 0;
        }

        hProcess = sei.hProcess;                                 //进程句柄
        logOut("[+] Launch [Weixin.exe] pid: " + std::to_string(GetProcessId(hProcess)));
    }

    logOut("[+] Get Handle: " + std::to_string((DWORD64)hProcess));
    // 再次验证防止注入到错误的进程中
    char process_name[MAX_PATH] = { 0 };
    if (GetModuleFileNameExA(hProcess, NULL, process_name, sizeof(process_name) / sizeof(char)) == 0) {
        logOut("[-] Failed to get current handle process name!");
    }
    else {
        if (std::string(process_name).find("Weixin.exe") == std::string::npos) {
            logOut("[-] The Process IS NOT Weixin.exe!", true);
            return 0;
        }
        logOut("[+] Get Process: " + std::string(process_name));
    }

    // 5. 远程写入dll字节并反射注入
    std::string ini_path = RIUtils::GetCurrentPath() + "\\" + INI_FILE; // 写入参数: ini路径
    LPVOID lpRemoteDllMainArg = VirtualAllocEx(hProcess, NULL, ini_path.length() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!lpRemoteDllMainArg) {
        logOut("[-] Failed to Alloc DllMain Arg!: " + std::to_string(GetLastError()), true);
        return 0;
    }
    if (!WriteProcessMemory(hProcess, lpRemoteDllMainArg, ini_path.c_str(), ini_path.length() + 1, NULL)) {
        logOut("[-] Failed to Write DllMain Arg!: " + std::to_string(GetLastError()), true);
        return 0;
    }
#ifdef _DEBUG
    std::cout << "[D] Alloc DllMain Arg at: 0x" << std::hex << lpRemoteDllMainArg << std::endl;
#endif

    HANDLE hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, lpRemoteDllMainArg);
    if (!hModule) {
        logOut("[-] Failed to LoadRemoteLibrary!", true);
        return 0;
    }
    WaitForSingleObject(hModule, -1);
    logOut("[+] Reflective Injected the DLL into process OK.");
    if (isInjectRunning || injectover_tip) PopUpTip("反射注入防撤回dll完毕!", "提示");

    // 6. 释放资源
    if (lpRemoteDllMainArg) {
        std::string zeroBytes(ini_path.length() + 1, '\0'); //将写入的ini路径字符串置为0 防止被扫描到
        if (!WriteProcessMemory(hProcess, lpRemoteDllMainArg, zeroBytes.data(), zeroBytes.size(), NULL)) {
            logOut("[-] Failed to Clear DllMain Arg!: " + std::to_string(GetLastError()));
        }
    }
    if (lpBuffer)
        HeapFree(GetProcessHeap(), 0, lpBuffer);
    if (hProcess)
        CloseHandle(hProcess);

    DbgConsole::freeInstance();
	return 0;
}


