EXTERN HijackLogic: PROC		; 引用外部函数

EXTERN g_transfer_zone: QWORD	; 引用外部变量

.CODE

; 栈对齐：在 64 位模式下，调用函数时栈必须是 16 字节对齐的
HijackLogicWarpper PROC
    push rbx                                ; 压入通用寄存器
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq                                  ; 压入eflags

	sub rsp, 28h							; 栈对齐
    mov rcx, r8                             ; 传参 参数为父函数的arg3
	call HijackLogic						; 调用HijackLogic 修改KeyClass内存
    add rsp, 28h							; 恢复栈
	
    popfq                                   ; 恢复eflags
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp  
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx                                 ; 恢复通用寄存器   

    mov rax, qword ptr [g_transfer_zone]	; rax赋值g_transfer_zone
    jmp rax                                 ; 跳转中转内存执行原指令
HijackLogicWarpper ENDP
 
END