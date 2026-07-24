# 字符串解密脚本 + 新版微信适配指南

## 依赖安装
依赖unicorn, 需要pip安装unicorn库
```
pip install unicorn
```

## 使用方式
### 自动解密函数
使用dec func:  
![image](https://github.com/user-attachments/assets/22056d24-110d-4540-98b3-d2095ebea88a)

### 自动解密一段汇编
使用dec select:  
![image](https://github.com/user-attachments/assets/cd2bb072-083b-43b9-a86d-d3184df2951d)  
选择一块汇编, 进行模拟执行并Patch

---

## 新版微信适配步骤 (以 4.1.12.22 为例)

### 方法一: 使用 CallChainSearchService (推荐)
如果加密字符串特征未变, RevokeHookUI 可以自动完成大部分工作:

1. 找到新版微信的 `Weixin.dll` 路径 (通常在 `C:\Program Files\Tencent\WeChat\[版本号]\`)
2. 打开 RevokeHookUI, 选择 `Weixin.dll`
3. 从云端下载最新 Config3.json (如果云端已更新) 或手动输入加密字符串 hex
4. 点击"搜索"按钮, 等待搜索完成
5. 点击"保存配置"写入 RevokeHook.ini
6. 运行 RevokeInject 注入测试

### 方法二: 手动提取加密字符串 (当方法一失败时)

**步骤 1: 用 IDA Pro 打开 Weixin.dll**
- 等待 IDA 完成初始自动分析

**步骤 2: 运行 destring.py 解密字符串**
- 在 IDA 中: File → Script file → 选择 `destring.py`
- 该脚本会使用 Unicorn 模拟执行微信的字符串解密函数, 自动 patch 解密后的字符串到 IDA 数据库中
- 等待脚本执行完成 (可能需要几分钟)

**步骤 3: 在 .rdata 段搜索关键字符串**
在 IDA 中搜索以下三个字符串的字节:
- `CoReplaceOriginMessageByRevoke` — 这是包含撤回逻辑的"原始"函数
- `DeleteMessages` — 删除消息的函数
- `CoAddMessageToDB` — 将撤回提示写入数据库的函数

记下每个字符串在 .rdata 中的原始 hex 字节序列。

**步骤 4: 更新 Config3.json**
将搜索到的 hex 值填入 `RevokeHookUI/RevokeHookUI/Config3.json`:
```json
{
  "4.1.12.22": {
    "sig1": "<CoReplaceOriginMessageByRevoke 的 hex>",
    "sig2": "<DeleteMessages 的 hex>",
    "sig3": "<CoAddMessageToDB 的 hex>"
  }
}
```

**步骤 5: 用 RevokeHookUI 搜索偏移**
- 重新打开 RevokeHookUI
- 确认 Config3.json 已加载新版本的 sig1/sig2/sig3
- 点击"搜索"按钮
- 搜索完成后, 点击"保存配置"
- 运行 RevokeInject 测试

### 方法三: 手动定位函数偏移 (当方法一和二都失败时)

**步骤 1: 用 IDA Pro 手动定位**
- 使用 `emulate.py` 辅助分析关键函数的调用关系
- 手动追踪 `CoReplaceOriginMessageByRevoke` 中的 call 指令
- 找到调用 `DeleteMessages` 和 `CoAddMessageToDB` 的 call 指令地址

**步骤 2: 更新 Config2.json**
将手动定位的偏移和结构体字段偏移填入 `Config2.json` 的 `specific` 部分。

**步骤 3: 直接写入 RevokeHook.ini**
```ini
[KeyFunc]
DelMsgOffset=0x<DeleteMessages call 的 RVA>
Add2DBOffset=0x<CoAddMessageToDB call 的 RVA>

[Setting]
AntiRevokeSelf=false
OutputDebugMsg=true
LogToFile=true
FallbackMode=false
Ver=4.1.12.22
```

### 调试技巧
- 注入后检查 `%USERPROFILE%\Documents\RevokeHook\revokehook.log` 查看 DLL 运行日志
- 如果日志显示 "No breakpoint hits" → 偏移错误, 需要重新搜索
- 如果日志显示 "Cannot find revoke_xml" → StdString 布局可能变了, DLL 会自动进入降级模式(3次失败后)
- 如果日志显示 "entering fallback mode" → 降级模式激活, 基本的防撤回功能应该仍能工作
- 设置 `OutputDebugMsg=true` + `LogToFile=true` 可获得最详细的诊断信息
