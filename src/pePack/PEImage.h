#pragma once
#include "PEfile.h"
class PEImage:public PEfile
{
public:
	virtual bool init(std::string dllName, GlobalParam gp);
	virtual IMAGE_IMPORT_DESCRIPTOR* getImportHeader();
	virtual PIMAGE_THUNK_DATA getINT(IMAGE_IMPORT_DESCRIPTOR* stubImport);
	virtual PIMAGE_BASE_RELOCATION getRelocHeader();
	virtual uint64_t getEPRva();
private:
	uint64_t startRva =0;
};

