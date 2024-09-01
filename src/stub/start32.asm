.MODEL flat, c   ; 指定内存模型为平坦模型并使用 stdcall 调用约定
.STACK 4096            ; 定义堆栈大小

extern _main : proc 
extern gep : DWORD

.code

START proc
    pushad
    call _main           
    popad
    jmp gep
START endp

end
