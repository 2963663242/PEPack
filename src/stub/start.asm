extern _main : proc 
extern gep : QWORD
.code

START proc
    push rcx
    push rdx
    push rsp            ; ����ջָ��仯���ֶ����沢�ָ�
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