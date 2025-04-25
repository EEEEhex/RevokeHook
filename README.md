# RevokeHook
QT版微信4.0 防撤回 + 提醒

## 原理
文章: [微信4.0防撤回+提醒 (符号恢复+字符串解密)](https://bbs.kanxue.com/thread-286611.htm)

## 使用方法
1. 从[Release](https://github.com/EEEEhex/RevokeHook/releases)下载RevokeHookUI(这个软件只是使用WTL封装了一个GUI, 用于特征码搜索和DLL替换).
2. 点击'搜索', 去搜索偏移, 复制偏移+8到Hook的Offset处:  
![image](https://github.com/user-attachments/assets/45f7e86c-d615-4912-95d2-3b75eee97c59)  
如果搜不到就用010editor等工具打开Weixin.dll搜一下, 我用的特征码搜索代码是网上找的SunDay算法, 有点小问题.
3. 点击'保存'将配置数据更新到RevokeHook.ini中.
4. 点击'替换'将配置ini复制到微信目录下,并将劫持Dll替换到微信版本目录下.  


