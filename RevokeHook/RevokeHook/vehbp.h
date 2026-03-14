#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

	// -----------------------------------------------------------------------
	// 每个软断点触发时的回调原型
	//   pCtx  - 当前寄存器上下文, 可直接修改
	//   pExc  - 异常记录, 包含触发地址
	// -----------------------------------------------------------------------
	typedef void (*BpCallback)(PCONTEXT pCtx, PEXCEPTION_RECORD pExc);

	// -----------------------------------------------------------------------
	// 公开 API
	// -----------------------------------------------------------------------

	// 初始化: 注册 VEH, 必须在所有 bp 操作之前调用
	// callFirst: TRUE  => 插到 VEH 链最前端(优先处理)
	//            FALSE => 插到末尾
	BOOL  VehBp_Init(BOOL callFirst);

	// 卸载: 移除所有断点并注销 VEH
	void  VehBp_Uninit(void);

	// 在 address 处安装软断点, 触发时调用 callback
	// 返回断点句柄(>= 0), 失败返回 -1
	int   VehBp_Set(LPVOID address, BpCallback callback);

	// 通过句柄移除断点(恢复原字节, 取消激活)
	BOOL  VehBp_Remove(int handle);

	// 临时禁用/启用某个断点(不恢复原字节, 仅跳过回调)
	void  VehBp_Disable(int handle);
	void  VehBp_Enable(int handle);

#ifdef __cplusplus
}
#endif
