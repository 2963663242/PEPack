// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <Windows.h>
#include "stub.h"

BOOL  APIENTRY DllMain(HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved
                     )
{
     
   
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

