.MODEL flat, c   ; ָ���ڴ�ģ��Ϊƽ̹ģ�Ͳ�ʹ�� stdcall ����Լ��
.STACK 4096            ; �����ջ��С

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
