extern _main : proc 
extern gep : QWORD
.code

START proc
    push rcx
    push rdx
    push rsp            ; 由于栈指针变化，手动保存并恢复
    push r8
    push r9
   
    call _main           
  
    pop r9
    pop r8
    pop rsp
    pop rdx
    pop rcx
    jmp gep
START endp

end