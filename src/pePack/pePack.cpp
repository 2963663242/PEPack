// pePack.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <fstream>
#include <vector>
#include "PEfile.h"
#include "PEImage.h"
int main()
{
	std::string targetName = R"(D:\Downloads\example\example\01\01\bin\HelloWorld.exe)";
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


