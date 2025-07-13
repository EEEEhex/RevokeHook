# RevokeHook
QT版微信4.0 防撤回 + 提醒, 请在[Discussions](https://github.com/EEEEhex/RevokeHook/discussions/12)处反馈使用过程中出现的警告等问题  
  
❗**请使用[v3.0](https://github.com/EEEEhex/RevokeHook/releases)以上的版本, 自此版本后不再使用dll劫持, 改为反射注入, 不会破坏本地文件完整性**❗

## 原理
文章: [微信4.0防撤回+提醒 (符号恢复+字符串解密)](https://bbs.kanxue.com/thread-286611.htm)

## 使用方法
### 1. 搜索偏移
* 打开RevokeHookUI, 点击搜索, 将两个 \[√\] \[0x...\] 偏移分别填入到Offset和DelMsg处, 然后点击'保存'
* 或点击'云端配置'使用云端已经设置好的版本偏移, 然后点击'保存' (**推荐**)
![image](https://github.com/user-attachments/assets/bbde8796-f834-4364-bbe2-2eaa50b772ae)


### 2. 注入Hook逻辑
* 运行RevokeInject, 将自动反射注入Hook逻辑到微信进程中, 并抹去部分特征  
* 微信为运行或未运行状态都可, 若微信未运行RevokeInject会自动启动微信  

### 3. 其他
* RevokeHookUI中的'创建快捷方式'将创建'RevokeInject'的快捷方式到桌面, 方便运行.  
* RevokeInject可以添加命令行参数, 通过-h查看详细信息  
* 若RevokeInject找不到Weixin路径, 请通过.\RevokeInject.exe -w "你的微信目录", 手动指定Weixin路径
* 'Config自动更新'功能为, 每次启动RevokeInject, 都会检测本地安装的微信版本与ini配置中的偏移版本信息是否相同. 若不相同则会自动从github下载Config.josn, 并在解析后将偏移信息写入到ini中.  
(注意: 因网络原因, 自动下载Config.json可能会失败, 请打开代理后再次尝试. 若Config.json中没有本地微信版本的偏移信息则也会更新失败.)
