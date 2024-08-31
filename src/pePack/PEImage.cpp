#include "PEImage.h"
#include <Windows.h>
#include <psapi.h>
#include <iostream>

bool PEImage::init(std::string dllName, GlobalParam gp)
{
    this->strFileName = dllName;
    HMODULE module =  LoadLibraryA(dllName.c_str());
    MODULEINFO modinfo = { 0 };
	PGlobalParam g_gp = (PGlobalParam)::GetProcAddress(module, "globalParam");
	if (g_gp->startAddr != 0) {
		startRva = g_gp->startAddr - (uint64_t)module;
	}
	*g_gp = { 0, };
	*g_gp = gp;
    GetModuleInformation(GetCurrentProcess(), module, &modinfo, sizeof(MODULEINFO));
    images.resize(modinfo.SizeOfImage);
    std::memcpy(images.data(), module, modinfo.SizeOfImage);
	*g_gp = { 0 };
	IMAGE_DOS_HEADER* dosHeader = getDosHeader();
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Error: Not a valid PE file (invalid DOS header)" << std::endl;
		return false;
	}
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Error: Not a valid PE file (invalid NT header)" << std::endl;
		return false;
	}

	IMAGE_SECTION_HEADER* sectionHeaders = getSectionHeaders();


	this->SectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
	this->FileAlignment = ntHeaders->OptionalHeader.FileAlignment;
    return true;
}

IMAGE_IMPORT_DESCRIPTOR* PEImage::getImportHeader()
{
	return (IMAGE_IMPORT_DESCRIPTOR*)&images[getImportHeaderRva()];
}

PIMAGE_THUNK_DATA PEImage::getINT(IMAGE_IMPORT_DESCRIPTOR* stubImport)
{
	return (PIMAGE_THUNK_DATA)&images[stubImport->OriginalFirstThunk];
}

PIMAGE_BASE_RELOCATION PEImage::getRelocHeader()
{
	return (PIMAGE_BASE_RELOCATION)&images[getRelocHeaderRva()];
}

uint64_t PEImage::getEPRva()
{
	if (startRva != 0)
		return startRva;
	else
		return PEfile::getEPRva();
}



