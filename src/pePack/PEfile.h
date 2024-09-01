#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include <stub.h>
class PEfile
{
public:
	virtual bool init(std::string fileName);
	bool addSection(PEfile & file);
	uint64_t getfileSize();
	unsigned align(unsigned value,unsigned alignment);
	bool save();
	bool chanageNewEP(PEfile& file);
	bool fixImports(PEfile& file);
	bool fixReloc(PEfile& file);
	GlobalParam getOriginGlobalParam();
	virtual uint64_t getEPRva();
	uint64_t rva2raw(uint64_t rva);
	uint64_t raw2rva(uint64_t raw);
	IMAGE_DOS_HEADER* getDosHeader();
	IMAGE_NT_HEADERS* getNtHeaders();
	IMAGE_SECTION_HEADER* getSectionHeaders();
	virtual IMAGE_IMPORT_DESCRIPTOR* getImportHeader();
	uint64_t getImportHeaderRva();
	virtual PIMAGE_BASE_RELOCATION getRelocHeader();
	uint64_t getRelocHeaderRva();
	virtual PIMAGE_THUNK_DATA getINT(IMAGE_IMPORT_DESCRIPTOR* stubImport);
	virtual uint64_t stubRva2TargetRva(PEfile& file,uint64_t rva);
	uint64_t getPointer(uint64_t offset);
	uint64_t getImageBase();
protected:
	std::string strFileName;
	std::vector<unsigned char> images;
	unsigned SectionAlignment;
	unsigned FileAlignment;
};

typedef struct
{
	WORD Offset : 12;  // 大小为12Bit的重定位偏移 
	WORD Type : 4;   // 大小为4Bit的重定位信息类型值 
}TypeOffset,* PTypeOffset;         // 这个结构体是A1Pass总结的

#ifdef _WIN64
// 64-bit Windows specific code
#else
//花指令代码
#define OBFUSBYTE 0xEB, 0x01, 0xA0, 0x83, 0xEC, 0x20, 0x9C, 0xEB,\
	0x01, 0xA0, 0x60, 0xE8, 0x01, 0x00, 0x00, 0x00,\
	0xA0, 0x58, 0xEB, 0x01, 0xA0, 0x83, 0xC0, 0x22,\
	0xEB, 0x01, 0xA0, 0x60, 0xEB, 0x01, 0xA0, 0x83,\
	0xF0, 0x12, 0xEB, 0x01, 0xA0, 0x83, 0xF0, 0x12,\
	0xEB, 0x01, 0xA0, 0x50, 0xEB, 0x01, 0xA0, 0xC2,\
	0x20, 0x00, 0x61, 0xEB, 0x01, 0xA0, 0x9D, 0xEB,\
	0x01, 0xA0, 0x83, 0xC4, 0x20, 0xEB, 0x01, 0xE8,\
	0x90  
#endif

