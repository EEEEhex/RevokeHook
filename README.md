---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: 'c37c35e2-9199-43d9-a771-090f87c04ab4'
  PropagateID: 'c37c35e2-9199-43d9-a771-090f87c04ab4'
  ReservedCode1: '6f23835d-41ef-457c-b8e5-9047ac2130fd'
  ReservedCode2: '6f23835d-41ef-457c-b8e5-9047ac2130fd'
---

# RevokeHook

Linux 版微信 4.0 防撤回 + 提醒。通过特征码在微信二进制中定位关键函数，注入 Hook 库实现消息防撤回、撤回消息保留与入库替换。

> 本仓库已整合为 **仅支持 Linux**。如需 Windows 版本请查看上游 [EEEEhex/RevokeHook](https://github.com/EEEEhex/RevokeHook)。

## 目录结构

```
RevokeHook/
├── Makefile                    # 顶层构建入口
├── Config3.json                # 各版本微信的字符串特征码
├── src/
│   ├── hook/                   # C++ Hook 库 (librevokehook.so + 断点引擎)
│   ├── injector/               # C 注入器 (ptrace 注入)
│   ├── tui/                    # C# 终端 UI (搜索偏移 + 生成配置 + 创建快捷方式)
│   └── searchoffsets/          # C# 命令行偏移搜索工具
├── scripts/
│   ├── launch-wechat.sh        # 启动微信并自动注入
│   ├── update-offsets.sh       # 一键重算偏移并更新 RevokeHook.ini
│   └── wechat-tray.py          # 系统托盘注入状态指示器
└── tools/
    └── ida/                    # IDA 字符串解密脚本
```

## 原理

文章: [微信4.0防撤回+提醒 (符号恢复+字符串解密)](https://bbs.kanxue.com/thread-286611.htm)

## 编译方法

依赖: `gcc`/`g++`、`make`、OpenSSL 头文件；C# 部分需要 `dotnet SDK 8`。

```bash
make                    # 编译 C/C++: librevokehook.so + injector
make tui                # 编译 C# TUI
make offsets            # 编译 C# 偏移搜索工具
```

## 使用方法

### 1. 搜索偏移

```bash
# 自动搜索微信二进制中的偏移并更新 ~/.config/RevokeHook/RevokeHook.ini
./scripts/update-offsets.sh [版本号]
```

或用 C# 工具手动搜索：

```bash
dotnet run --project src/searchoffsets -- <微信二进制路径> [版本号] [Config3.json]
```

### 2. 注入 Hook 逻辑

原生安装（`/opt/wechat/wechat`）:

```bash
./scripts/launch-wechat.sh
# 内部等效于: sudo src/injector/injector -p <pid> src/hook/librevokehook.so
```

flatpak 安装:

```bash
src/injector/injector -f com.tencent.WeChat -s src/hook/librevokehook.so --env=REVOKEHOOK_INI=$PWD/src/tui/RevokeHook.ini
```

### 3. 托盘指示器

```bash
./scripts/wechat-tray.py
```

在系统托盘显示微信防撤回注入状态，左键可快速重新注入。

### 4. 配置

Hook 库通过 `RevokeHook.ini` 读取偏移与开关，路径优先级：

1. 环境变量 `REVOKEHOOK_INI` 指定的路径
2. `~/.config/RevokeHook/RevokeHook.ini`

```ini
[KeyFunc]
DelMsgOffset=0x...
Add2DBOffset=0x...

[Setting]
AntiRevokeSelf=false
OutputDebugMsg=false
```

## 日志排查

- 原生版日志: `$HOME/.cache/revokehook.log`
- flatpak 版日志: `~/.var/app/com.tencent.WeChat/cache/revokehook.log`