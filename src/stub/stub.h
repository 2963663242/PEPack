#pragma once

#include <Windows.h>
#include <cstdint>
typedef struct _GlobalParam {
	uint64_t OEP;
	uint64_t importHeaderRva;
	uint64_t RelocHeaderRva;
	uint64_t imageBase;
	uint64_t startAddr;
}GlobalParam,* PGlobalParam;


extern "C" {
	extern __declspec(dllexport) GlobalParam globalParam;
}

void fixIAT();
void fixReloc();
