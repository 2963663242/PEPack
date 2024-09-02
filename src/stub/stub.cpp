#include "stub.h"
#include <iostream>
#include <vector>
extern "C" void START();
GlobalParam globalParam = { 0,0,0,0,(uint64_t)START };



extern "C" void* _main();
extern "C" void(*gep)();
void(*gep)();


typedef struct
{
	WORD Offset : 12;  // 大小为12Bit的重定位偏移 
	WORD Type : 4;   // 大小为4Bit的重定位信息类型值 
}TypeOffset, * PTypeOffset;         // 这个结构体是A1Pass总结的
void* GetCurrentModuleBaseAddress() {
	MEMORY_BASIC_INFORMATION mbi = {};
	VirtualQuery(GetCurrentModuleBaseAddress, &mbi, sizeof(mbi));
	return static_cast<void*>(mbi.AllocationBase);
}
void fixIAT() {

	uint64_t hModule = (uint64_t)GetCurrentModuleBaseAddress();
	PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)((uint64_t)hModule + globalParam.importHeaderRva);

	while (imports->Name != 0) {
		std::string dllname = (const char *)(imports->Name + hModule);
		HMODULE dllModule = LoadLibraryA(dllname.c_str());
		//std::cout <<"import dllname : " << dllname << std::endl;
		PIMAGE_THUNK_DATA INT_ = (PIMAGE_THUNK_DATA)(imports->OriginalFirstThunk + hModule);
		PIMAGE_THUNK_DATA IAT_ = (PIMAGE_THUNK_DATA)(imports->FirstThunk + hModule);
		while (INT_->u1.ForwarderString != 0) {
			PIMAGE_IMPORT_BY_NAME IBN = PIMAGE_IMPORT_BY_NAME(INT_->u1.ForwarderString + hModule);
			FARPROC proc= 0;
			if ((INT_->u1.Ordinal >> (sizeof(INT_->u1.Ordinal) * 8 - 1)) == 0) {
				std::cout << "import " << dllname << "!" << IBN->Name << std::endl;
				proc = GetProcAddress(dllModule, IBN->Name);
			}
			else {
				std::cout << "import " << dllname << "!0x" <<std::hex << (INT_->u1.Ordinal << 1 >> 1) << std::endl;
				proc = GetProcAddress(dllModule, (LPCSTR)(INT_->u1.Ordinal<<1>>1));
			}
			DWORD oldProtect;
			VirtualProtect(IAT_, sizeof(IAT_->u1.Function), PAGE_READWRITE, &oldProtect);
			IAT_->u1.Function = (ULONGLONG)proc;
			VirtualProtect(IAT_, sizeof(IAT_->u1.Function), oldProtect, &oldProtect);
			INT_++;
			IAT_++;
		}

		imports++;
	}

}

void fixReloc()
{
	if (globalParam.RelocHeaderRva == 0) //若源程序的重定位目录不存在，则跳过
		return;
	uint64_t hModule = (uint64_t)GetCurrentModuleBaseAddress();
	PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)(hModule + globalParam.RelocHeaderRva);

	while (Reloc->SizeOfBlock != 0) {

		int itemCount = (Reloc->SizeOfBlock - 8) / 2;
		TypeOffset* item = (TypeOffset*)(Reloc + 1);
		for (int i = 0; i < itemCount; i++) {
			if (item[i].Type != IMAGE_REL_BASED_ABSOLUTE) {
				uint64_t** global = (uint64_t**)(item[i].Offset + Reloc->VirtualAddress + hModule);
				DWORD oldProtect;
				VirtualProtect(global, sizeof(uint64_t**), PAGE_READWRITE, &oldProtect);
				*global = (uint64_t*)((uint64_t)(*global) - globalParam.imageBase + hModule);
				VirtualProtect(global, sizeof(uint64_t**), oldProtect, &oldProtect);
			}

		}
		Reloc = (PIMAGE_BASE_RELOCATION)((uint64_t)Reloc + itemCount * 2);
		Reloc++;
	}

}

void encryptIAT() {

	uint64_t hModule = (uint64_t)GetCurrentModuleBaseAddress();
	PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)((uint64_t)hModule + globalParam.importHeaderRva);

	while (imports->Name != 0) {
		std::string dllname = (const char*)(imports->Name + hModule);
		HMODULE dllModule = LoadLibraryA(dllname.c_str());
		//std::cout <<"import dllname : " << dllname << std::endl;
		PIMAGE_THUNK_DATA INT_ = (PIMAGE_THUNK_DATA)(imports->OriginalFirstThunk + hModule);
		PIMAGE_THUNK_DATA IAT_ = (PIMAGE_THUNK_DATA)(imports->FirstThunk + hModule);
		while (INT_->u1.ForwarderString != 0) {
			PIMAGE_IMPORT_BY_NAME IBN = PIMAGE_IMPORT_BY_NAME(INT_->u1.ForwarderString + hModule);
			FARPROC proc = 0;
			if ((INT_->u1.Ordinal >> (sizeof(INT_->u1.Ordinal) * 8 - 1)) == 0) {
				std::cout << "import " << dllname << "!" << IBN->Name << std::endl;
				proc = GetProcAddress(dllModule, IBN->Name);
			}
			else {
				std::cout << "import " << dllname << "!0x" << std::hex << (INT_->u1.Ordinal << 1 >> 1) << std::endl;
				proc = GetProcAddress(dllModule, (LPCSTR)(INT_->u1.Ordinal << 1 >> 1));
			}
			DWORD oldProtect3;
			VirtualProtect(INT_, sizeof(INT_), PAGE_READWRITE, &oldProtect3);
			*INT_ = {0};

			DWORD oldProtect, oldProtect2;
			VirtualProtect(IAT_, sizeof(IAT_->u1.Function), PAGE_READWRITE, &oldProtect);
			ULONGLONG procEncrypt = (ULONGLONG)proc ^ 1;
			procEncrypt = procEncrypt ^ 2;
#ifdef _WIN64
			std::vector<unsigned char > encryptCall = {
							OBFUSBYTE,0x50,
							OBFUSBYTE,0x48, 0xB8, 0x23, 0x41, 0x31, 0x01, 0x52, 0x00, 0x00, 0x00,
							OBFUSBYTE,0x48, 0x83, 0xF0, 0x02,
							OBFUSBYTE,0x48, 0x83, 0xF0, 0x01,
							OBFUSBYTE,0x48, 0x87, 0x04, 0x24,
							OBFUSBYTE,0xC3
			};
			for (int i = 0; i < encryptCall.size(); i++) {
				if (*((ULONGLONG*)&encryptCall[i]) == 0x5201314123)
					*((ULONGLONG*)&encryptCall[i]) = procEncrypt;
		}
#else
			std::vector<unsigned char > encryptCall = {
							OBFUSBYTE,0x50,
							OBFUSBYTE,0xB8, 0x14, 0x13, 0x20, 0x05,
							OBFUSBYTE,0x83, 0xF0, 0x02,
							OBFUSBYTE,0x83, 0xF0, 0x01,
							OBFUSBYTE,0x87, 0x04, 0x24,
							OBFUSBYTE,0xC3
			};
			for (int i = 0; i < encryptCall.size(); i++) {
				if (*((ULONG*)&encryptCall[i]) == 0x5201314)
					*((ULONG*)&encryptCall[i]) = procEncrypt;
			}
#endif
			
			
			unsigned char* protectAddr = new unsigned char[encryptCall.size()];
			VirtualProtect(protectAddr, encryptCall.size(), PAGE_EXECUTE_READWRITE, &oldProtect2);
			memcpy_s(protectAddr, encryptCall.size(), encryptCall.data(), encryptCall.size());
			IAT_->u1.Function = (ULONGLONG)protectAddr;
			VirtualProtect(IAT_, sizeof(IAT_->u1.Function), oldProtect, &oldProtect);
			INT_++;
			IAT_++;
		}

		imports++;
	}
}

void* _main() {
	fixIAT();
	fixReloc();
	encryptIAT();
	HMODULE hModule = (HMODULE)GetCurrentModuleBaseAddress();
	gep= (void(*)())((uint64_t)hModule + globalParam.OEP);
	return gep;
}