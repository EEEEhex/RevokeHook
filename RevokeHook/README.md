# 防撤回劫持dll源码

## 编译方式
1. 在项目上右键->生成依赖性->生成自定义->勾选上 masm
2. 在wrapper.asm上右键->属性->项类型->Microsoft Macro Assembler
3. 编译成Release

## 使用方式
1. 使用RevokeHookUI进行操作
2. 或 手动复制RevokeHook.ini至微信安装目录下, 并将版本目录里的ilink2.dll重命名为ilink2Org.dll, 把RevokeHook.dll重命名为ilink2.dll
