# RevokeHook
QT版微信4.0 防撤回 + 提醒, 请在[Discussions](https://github.com/EEEEhex/RevokeHook/discussions/12)处反馈使用过程中出现的警告等问题  

## 原理
文章: [微信4.0防撤回+提醒 (符号恢复+字符串解密)](https://bbs.kanxue.com/thread-286611.htm)

## 使用方法
### 1. 搜索偏移
* 打开RevokeHookUI, 点击'搜索全部', 函数地址偏移将自动填充, 然后点击'保存配置'
* 或点击'云端配置'使用云端已经设置好的版本偏移, 然后点击'保存配置' **(推荐)**
  
<img src="https://raw.githubusercontent.com/EEEEhex/RevokeHook/43849530dc2e95f47913f131879424156c8b0804/Assets/using.png" width="600" alt="usage" />

### 2. 注入Hook逻辑
* 运行RevokeInject, 将自动反射注入Hook逻辑到微信进程中, 并抹去部分特征
* 微信为启动或未启动状态都可, 若微信未运行RevokeInject会自动启动微信

### 3. 其他
* RevokeHookUI中的'创建快捷方式'将创建'RevokeInject'的快捷方式到桌面, 方便运行.  
* RevokeInject可以添加命令行参数, 通过-h查看详细信息
* 若RevokeInject找不到Weixin路径, 请通过.\RevokeInject.exe -w "你的微信目录", 手动指定Weixin路径
