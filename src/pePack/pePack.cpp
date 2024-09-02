// pePack.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <fstream>
#include <vector>
#include "PEfile.h"
#include "PEImage.h"
int main()
{
#ifdef _WIN64
	std::string targetName = R"(D:\leidian\vmp.kanxue\2\hello\build\Release\hello.exe)";
#else
	std::string targetName = R"(D:\Downloads\example\example\01\02\bin\HelloWorld.exe)";
#endif
	std::string stubName = "stub.dll";

	PEfile tarFile;
	PEImage stubFile;
	tarFile.init(targetName);
	stubFile.init(stubName,tarFile.getOriginGlobalParam());
	tarFile.addSection(stubFile);
	tarFile.chanageNewEP(stubFile);
	tarFile.fixImports(stubFile);
	tarFile.fixReloc(stubFile);
	tarFile.save();
	return 0;
}


