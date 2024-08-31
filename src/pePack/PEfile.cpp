#include "PEfile.h"
#include <fstream>
#include <iostream>



bool PEfile::init(std::string fileName)
{
	this->strFileName = fileName;

	std::ifstream targetFile;
	targetFile.open(this->strFileName, std::ios::binary);
	if(!targetFile.is_open()){
		std::cerr << "Error: Could not open the file " << this->strFileName << std::endl;
	}
	targetFile.seekg(0, std::ios::end);
	uint64_t fileSize = targetFile.tellg();
	targetFile.seekg(0, std::ios::beg);
	this->images.resize(fileSize);

	if (!targetFile.read(reinterpret_cast<char*>(images.data()), fileSize)) {
		std::cerr << "Error: Could not read the file " << this->strFileName << std::endl;
		return false;
	}

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

	IMAGE_SECTION_HEADER*  sectionHeaders = getSectionHeaders();
	
	
	this->SectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
	this->FileAlignment = ntHeaders->OptionalHeader.FileAlignment;

	return true;
}

bool PEfile::addSection(PEfile& file)
{
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	IMAGE_SECTION_HEADER* sectionHeaders = getSectionHeaders();
	IMAGE_SECTION_HEADER newSection = { 0 };
	memcpy(newSection.Name, ".newsec", 7); // Section name
	newSection.Misc.VirtualSize = file.getfileSize(); // Size of the section in memory
	newSection.SizeOfRawData = file.getfileSize(); // Size of the section in the file
	IMAGE_SECTION_HEADER& lastSection = sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1];
	newSection.VirtualAddress = align(lastSection.VirtualAddress + lastSection.Misc.VirtualSize, this->SectionAlignment);
	newSection.PointerToRawData = align(lastSection.PointerToRawData + lastSection.SizeOfRawData, this->FileAlignment);
	newSection.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

	  

	// Adjust the NT headers
	ntHeaders->FileHeader.NumberOfSections += 1;
	ntHeaders->OptionalHeader.SizeOfImage = align(newSection.VirtualAddress + newSection.Misc.VirtualSize, ntHeaders->OptionalHeader.SectionAlignment);


	std::memcpy(&sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1], &newSection, sizeof(IMAGE_SECTION_HEADER));

	images.resize(newSection.PointerToRawData + newSection.SizeOfRawData);

	std::memcpy(&images.data()[newSection.PointerToRawData], file.getDosHeader(), file.getfileSize());

	return true;
}

uint64_t PEfile::getfileSize()
{
	return this->images.size();
}

unsigned PEfile::align(unsigned value, unsigned alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
	
}

bool PEfile::save()
{
	// Write the modified PE file to disk
	std::ofstream outputFile(strFileName+".exe", std::ios::binary);
	if (!outputFile) {
		std::cerr << "Error: Could not create the file " << strFileName << std::endl;
		return 1;
	}
	outputFile.write((const char *)images.data(), images.size());
	outputFile.close();

	std::cout << "New section added successfully!" << std::endl;
	return true;
}

bool PEfile::chanageNewEP(PEfile& file)
{
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	uint64_t newEPRva = stubRva2TargetRva(file, file.getEPRva());
	ntHeaders->OptionalHeader.AddressOfEntryPoint = newEPRva;
	return true;
}

bool PEfile::fixImports(PEfile& file)
{
	IMAGE_NT_HEADERS*  stubNtHeaders = file.getNtHeaders();
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	uint64_t stubImportRva = stubNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	uint64_t ImportRva = stubRva2TargetRva(file, stubImportRva);
	ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = ImportRva;
	IMAGE_IMPORT_DESCRIPTOR* stubImport = file.getImportHeader();
	IMAGE_IMPORT_DESCRIPTOR* Import = getImportHeader();
	while (stubImport->Name != 0) {
		Import->Name = stubRva2TargetRva(file, stubImport->Name);
		Import->FirstThunk = stubRva2TargetRva(file, stubImport->FirstThunk);
		Import->OriginalFirstThunk = stubRva2TargetRva(file, stubImport->OriginalFirstThunk);
		PIMAGE_THUNK_DATA stubINT_ = file.getINT(stubImport);
		PIMAGE_THUNK_DATA INT_ = getINT(Import);
		while ((stubINT_->u1.ForwarderString) != 0) {
			INT_->u1.ForwarderString = stubRva2TargetRva(file, stubINT_->u1.ForwarderString);
			stubINT_++;
			INT_++;
		}
		stubImport++;
		Import++;
	}

	
	return true;
}

bool PEfile::fixReloc(PEfile& file)
{
	IMAGE_NT_HEADERS* stubNtHeaders = file.getNtHeaders();
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	uint64_t stubRelocRva = stubNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	uint64_t RelocRva = stubRva2TargetRva(file, stubRelocRva);
	ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = RelocRva;
	PIMAGE_BASE_RELOCATION stubReloc = file.getRelocHeader();
	PIMAGE_BASE_RELOCATION Reloc = getRelocHeader();

	while (stubReloc->SizeOfBlock != 0) {
		Reloc->VirtualAddress = stubRva2TargetRva(file,stubReloc->VirtualAddress);
		//计算子项的数量
		int itemCount = (stubReloc->SizeOfBlock - 8) / 2;
		//获取子项的偏移
		 TypeOffset* item = ( TypeOffset*)(Reloc + 1);
		 TypeOffset* stubItem = ( TypeOffset*)(stubReloc + 1);
		//计算全局地址
		 for (int i = 0; i < itemCount; i++) {
			 if (item[i].Type != IMAGE_REL_BASED_ABSOLUTE) {
			 uint64_t stubGlobAddr = file.getPointer(stubItem[i].Offset + stubReloc->VirtualAddress);
			 uint64_t stubGlobRva = stubGlobAddr - file.getImageBase();
			 uint64_t globalRva = stubRva2TargetRva(file, stubGlobRva);
			 uint64_t globalAddr = globalRva + getImageBase();
			 uint64_t offset = rva2raw(item[i].Offset + Reloc->VirtualAddress);
			 uint64_t** global = (uint64_t**)&images[offset];
			 *global = (uint64_t*)globalAddr;
			}
		 }

		Reloc = (PIMAGE_BASE_RELOCATION)(((uint64_t)Reloc) + Reloc->SizeOfBlock);
		stubReloc = (PIMAGE_BASE_RELOCATION)(((uint64_t)stubReloc) + stubReloc->SizeOfBlock);
	}

	return false;
}

GlobalParam PEfile::getOriginGlobalParam()
{

	return GlobalParam{getEPRva(),getImportHeaderRva(),getRelocHeaderRva(),getImageBase()};
}



uint64_t PEfile::getEPRva()
{
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	return ntHeaders->OptionalHeader.AddressOfEntryPoint;;
}

uint64_t PEfile::rva2raw(uint64_t rva)
{
	IMAGE_SECTION_HEADER* sectionHeaders = getSectionHeaders();
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (rva >= sectionHeaders[i].VirtualAddress && rva < align(sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize, SectionAlignment)) {

			return rva - sectionHeaders[i].VirtualAddress + sectionHeaders[i].PointerToRawData;
		}

	}
	return 0;
}

uint64_t PEfile::raw2rva(uint64_t raw)
{
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	IMAGE_SECTION_HEADER* sectionHeaders = getSectionHeaders();
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (raw >= sectionHeaders[i].PointerToRawData && raw <= align(sectionHeaders[i].PointerToRawData + sectionHeaders[i].SizeOfRawData, FileAlignment)) {

			return raw - sectionHeaders[i].PointerToRawData + sectionHeaders[i].VirtualAddress;
		}

	}
	return 0;
}

IMAGE_DOS_HEADER* PEfile::getDosHeader()
{

	return reinterpret_cast<IMAGE_DOS_HEADER*>(this->images.data());
}

IMAGE_NT_HEADERS* PEfile::getNtHeaders()
{
	return reinterpret_cast<IMAGE_NT_HEADERS*>(this->images.data() + getDosHeader()->e_lfanew);;
}

IMAGE_SECTION_HEADER* PEfile::getSectionHeaders()
{
	return IMAGE_FIRST_SECTION(getNtHeaders());
}

IMAGE_IMPORT_DESCRIPTOR* PEfile::getImportHeader()
{
	return (IMAGE_IMPORT_DESCRIPTOR*)&images[rva2raw(getImportHeaderRva())];
}

uint64_t PEfile::getImportHeaderRva()
{
	IMAGE_NT_HEADERS* stubNtHeaders = getNtHeaders();
	return stubNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
}

PIMAGE_BASE_RELOCATION PEfile::getRelocHeader()
{
	return (PIMAGE_BASE_RELOCATION)&images[rva2raw(getRelocHeaderRva())];
}
uint64_t PEfile::getRelocHeaderRva() {
	IMAGE_NT_HEADERS* stubNtHeaders = getNtHeaders();
	return stubNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
}

PIMAGE_THUNK_DATA PEfile::getINT(IMAGE_IMPORT_DESCRIPTOR* stubImport)
{
	return (PIMAGE_THUNK_DATA) & images[rva2raw(stubImport->OriginalFirstThunk)];
}

uint64_t PEfile::stubRva2TargetRva(PEfile& file,uint64_t rva)
{
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();
	IMAGE_SECTION_HEADER* sectionHeaders = getSectionHeaders();
	IMAGE_SECTION_HEADER& lastSection = sectionHeaders[ntHeaders->FileHeader.NumberOfSections - 1];
	uint64_t lastSecRva = lastSection.VirtualAddress;
	uint64_t newRva = rva + lastSecRva;
	return newRva;
}

uint64_t PEfile::getPointer(uint64_t offset)
{
	uint64_t ** addr = (uint64_t**) & images[offset];

	return (uint64_t)*addr;
}

uint64_t PEfile::getImageBase()
{
	IMAGE_NT_HEADERS* ntHeaders = getNtHeaders();

	return ntHeaders->OptionalHeader.ImageBase;
}


