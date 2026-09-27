# RevokeHook Linux — 顶层构建入口
#
# 用法:
#   make            # 编译 C/C++ 组件 (librevokehook.so + injector)
#   make all        # 同 make
#   make clean      # 清理 C/C++ 产物
#   make tui        # 编译 C# TUI (RevokeHookTUI)
#   make offsets    # 编译 C# 偏移搜索工具 (searchoffsets)
#
# 说明:
#   - C/C++ 部分需要 gcc/g++ + openssl 头文件
#   - C# 部分需要 dotnet SDK 8.0 (Terminal.Gui + capstone 通过 NuGet 自动还原)

.PHONY: all clean hook injector tui offsets

all: hook injector

hook:
	$(MAKE) -C src/hook

injector:
	$(MAKE) -C src/injector

tui:
	dotnet build -c Release src/tui/RevokeHookTUI.csproj

offsets:
	dotnet build -c Release src/searchoffsets/searchoffsets.csproj

clean:
	$(MAKE) -C src/hook clean
	$(MAKE) -C src/injector clean