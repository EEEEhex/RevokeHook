#pragma once
#include <string>
#include <vector>

namespace RIUtils
{
	std::string int2hex(int val);
	int hex2int(std::string val);

	/**
	 * @brief 获取临时文件夹的目录路径.
	 * @return 路径 C:\Users\**\AppData\Local\Temp
	 */
	std::string GetTempDirPath();

	/**
	 * @brief 判断文件/目录是否存在.
	 * @param filename 文件名
	 * @return 是否存在
	 */
	bool IsFileExists(const std::string& filename);

	/**
	 * @brief 获取进程当前运行目录.
	 * @return 目录字符串
	 */
	std::string GetCurrentPath();

	/**
	 * @brief 从注册表中获取微信路径.
	 * @return 微信安装目录路径
	 */
	std::string GetWeixinPath();

	/**
	 * @brief 获取微信版本字符串.
	 * @param wx_path 微信路径字符串 如果此参数不如空则从字符串中提取
	 * @return 当前安装的微信版本
	 */
	std::string GetWeixinVerion(std::string wx_path = "");

	void split(const std::string& s, std::vector<std::string>& tokens, const std::string& delimiters);

	std::wstring Utf8ToWide(const std::string& str);
}