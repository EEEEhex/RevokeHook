#include "Utils.h"

#include <io.h>
#include <sstream>
#include <iomanip>
#include <Windows.h>


std::string RIUtils::int2hex(int val)
{
	std::stringstream ss;
	ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << val;
	return ss.str();
}

int RIUtils::hex2int(std::string val)
{
	int num = 0;
	std::istringstream iss(val);
	iss >> std::hex >> num;
	return num;
}

std::string RIUtils::GetTempDirPath()
{
    // 用于存储TEMP目录的字符串
    char tempPath[MAX_PATH] = { 0 };

    // 获取TEMP环境变量的值
    DWORD length = GetEnvironmentVariableA("TEMP", tempPath, MAX_PATH);
    if (length > 0) return tempPath;
    return std::string();
}

bool RIUtils::IsFileExists(const std::string& filename)
{
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

std::string RIUtils::GetCurrentPath()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH); 	// 获取程序的完整路径
	 
	// 获取文件所在的目录
	std::string path = buffer;
	size_t pos = path.find_last_of("\\/");
	std::string directory = path.substr(0, pos);
	return directory;
}

std::string RIUtils::GetWeixinPath()
{
	HKEY hKey;//HKEY_CURRENT_USER\Software\Tencent\Weixin
	std::string szRegPath = "Software\\Tencent\\Weixin";
	if (RegOpenKeyExA(HKEY_CURRENT_USER, szRegPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		DWORD nLength = MAX_PATH;
		char szPath[MAX_PATH] = { 0 };
		long result = RegGetValueA(hKey, NULL, "InstallPath", RRF_RT_REG_SZ, NULL, szPath, &nLength);
		if (result == ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return szPath;
		}
	}
	return std::string();
}

std::vector<std::string> GetSubDirsA(std::string target_dir)
{
	if (!RIUtils::IsFileExists(target_dir)) return std::vector<std::string>();

	std::vector<std::string> sub_dirs;
	intptr_t  hFile;//用于查找的句柄
	struct _finddata_t fileinfo;//文件信息的结构体
	hFile = _findfirst(target_dir.append("/*").c_str(), &fileinfo);//第一次查找/*不可缺
	while (0 == _findnext(hFile, &fileinfo))//循环查找其他文件夹
	{
		if ((fileinfo.attrib & _A_SUBDIR))
		{
			if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
				std::string dir_name = fileinfo.name;
				sub_dirs.push_back(dir_name);
			}
		}
	}
	_findclose(hFile);//关闭句柄
	return sub_dirs;
}

std::string RIUtils::GetWeixinVerion(std::string wx_path)
{
	if (!wx_path.empty()) {
		std::string weixin_path = wx_path;
		if (!weixin_path.empty()) {
			std::vector<std::string> subdirs = GetSubDirsA(weixin_path);
			if (subdirs.size() == 1) {
				if (subdirs.front().find('.') != std::string::npos) {
					return subdirs.front();
				}
			}
		}
	}

	DWORD version = 0;	//version的数值
	DWORD bufferSize = sizeof(version);

	HKEY hKey;//HKEY_CURRENT_USER\Software\Tencent\WeChat
	std::wstring szRegPath = L"Software\\Tencent\\Weixin";
	if (RegOpenKeyExW(HKEY_CURRENT_USER, szRegPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		long result = RegGetValueW(hKey, NULL, L"Version", RRF_RT_REG_DWORD, NULL, &version, &bufferSize);
		if (result == ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
		}
		else {	//获取失败
			return std::string();
		}
	}

	std::string version_str;
	if (version == 0) {	//从注册表中获取值失败
		std::string weixin_path = GetWeixinPath();
		if (!weixin_path.empty()) {
			std::vector<std::string> subdirs = GetSubDirsA(weixin_path);
			if (subdirs.size() == 1) {
				if (subdirs.front().find('.') != std::string::npos) {
					version_str = subdirs.front();
				}
			}
		}
	}
	else {
		//将数值转为目录字符串格式 0xf254032b -> 4.0.3.43
		BYTE main_v = (version >> 16) & 0xF;
		BYTE sub_v = (version >> 12) & 0xF;
		BYTE sub_sub_v = (version >> 8) & 0xF;
		BYTE sub_sub_sub_v = version & 0xFF;

		version_str = std::to_string(main_v) + "." + std::to_string(sub_v) + "." + std::to_string(sub_sub_v) + "." + std::to_string(sub_sub_sub_v);
	}

	return version_str;
}

void RIUtils::split(const std::string& s, std::vector<std::string>& tokens, const std::string& delimiters)
{
	tokens.clear();//清空容器
	std::string::size_type start = s.find_first_not_of(delimiters, 0);
	std::string::size_type pos = s.find_first_of(delimiters, 0);
	while (pos != std::string::npos || start != std::string::npos)
	{
		tokens.emplace_back(s.substr(start, pos - start));
		start = s.find_first_not_of(delimiters, pos);
		pos = s.find_first_of(delimiters, start);
	}
}

std::wstring RIUtils::Utf8ToWide(const std::string& str)
{
	if (str.empty()) return L"";

	int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
	if (len <= 0) return L"";

	std::wstring result(len - 1, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, (LPWSTR)(result.data()), len);
	return result;
}
