#include <iostream>
#include <windows.h>
#include "CMyDebug.h"

using namespace std;


//const char* buffer = "\x55\x8b\xec\x81\xec\x24\x03\x00\x00\x6a\x17\x90\x90\x90";

int main()
{
    /*char* buffer = (char*)"\x55\x8b\xec\x81\xec\x24\x03\x00\x00\x6a\x17\x90\x90\x90";
    DisassembleCode(buffer, 14,1);*/
    CMyDebug debuger;
    string ProcessPath;
    getline(cin, ProcessPath);
    if (!debuger.BeginDebug(ProcessPath.c_str()))
    {
        std::cout << "进程创建失败！" << endl;

    }

    debuger.OnDebug();
    
    return 0;
}
	


