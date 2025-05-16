# RevokeHook
QT版微信4.0 防撤回 + 提醒
  
❗**请使用[v3.0](https://github.com/EEEEhex/RevokeHook/releases)以上的版本, 自此版本后不再使用dll劫持, 改为反射注入, 不会破坏本地文件完整性**❗

## 原理
文章: [微信4.0防撤回+提醒 (符号恢复+字符串解密)](https://bbs.kanxue.com/thread-286611.htm)

## 使用方法
### 1. 搜索偏移
* 打开RevokeHookUI, 点击搜索, 将两个 \[√\] \[0x...\] 偏移分别填入到Offset和DelMsg处, 然后点击'保存'
* 或点击'云端'使用云端已经设置好的版本偏移, 然后点击'保存'  
![image](https://github.com/user-attachments/assets/5aedde9d-9631-484a-9a53-96a986388782)


### 2. 注入Hook逻辑
* 运行RevokeInject, 将自动反射注入Hook逻辑到微信进程中, 并抹去部分特征
* 微信为运行或未运行状态都可, 若微信未运行RevokeInject会自动启动微信

