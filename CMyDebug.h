#pragma once
#include <windows.h>
#include "BeaEngine.h"
#include <sstream>
#include <string>
#include <algorithm>
using namespace std;
#pragma warning(disable:4996)
class CMyDebug
{
public:
	CMyDebug():IsSystemBreakPoint(TRUE), Is_Debug_Singgle_Step(FALSE),Is_Hard_Break_Point(FALSE), Memory_Bp_Alive(FALSE){}
	DEBUG_EVENT dbgEvent;
	DWORD continueStatus;
	INT BeginDebug(const char* LpName);
	INT OnDebug();
	VOID OnCreateThread();
	VOID OnCreateProcess();
	VOID OnDllLoad();
	VOID OnDllUnload();
	VOID OnOutPutString();
	VOID OnThreadExit();
	VOID OnProcessExit();
	VOID OnDebugEvent();
	INT GetCommand();
	VOID DisassembleCode(char* start_offset, int size, int length);
	VOID GetContext();
	VOID SetStep();
	VOID Exception_BreakPoint(); 
	VOID Exception_SingleStep();
	DWORD Memory_Break_Point_Exception();
	VOID ShowRegister();
	VOID SetHardBreakPoint(LPVOID Addr, string Hard_Break_Point_Option, DWORD Hard_Break_Point_Length);

public:
	BOOL IsSystemBreakPoint;
	CONTEXT m_context;
	STARTUPINFO startupInfo = { sizeof(startupInfo) };
	PROCESS_INFORMATION processInfo = { 0 };
	DWORD Exception_Addr;
	CHAR Old_Char;
	DWORD Break_Point_Addr;
	CHAR Process_Buffer[0x1000];
	DWORD Old_Proc;//存放原来内存属性
	BOOL Is_Debug_Singgle_Step;
	string Authority;
	DWORD Memory_Bp_Alive; //内存断点是否启动
	DWORD Memory_Bp_Addr;//内存断点地址记录
	DWORD Memory_Bp_Length;//内存断点检测长度
	DWORD Old_Memory_Attribute;//原来的内存属性
	DWORD Is_Hard_Break_Point;//判断是否为硬件断点
	DWORD Hard_Break_Point_Addr;//硬件断点的地址
	string Hard_Break_Point_Option;//硬件断点的选项
	DWORD Hard_Break_Point_Length;//硬件断点的长度，如果是执行断点，那么长度必须要填0



	struct DR7_Register {
		
			/*
			// 局部断点(L0~3)与全局断点(G0~3)的标记位
			*/
			unsigned L0 : 1;  // 对Dr0保存的地址启用 局部断点
			unsigned G0 : 1;  // 对Dr0保存的地址启用 全局断点
			unsigned L1 : 1;  // 对Dr1保存的地址启用 局部断点
			unsigned G1 : 1;  // 对Dr1保存的地址启用 全局断点
			unsigned L2 : 1;  // 对Dr2保存的地址启用 局部断点
			unsigned G2 : 1;  // 对Dr2保存的地址启用 全局断点
			unsigned L3 : 1;  // 对Dr3保存的地址启用 局部断点
			unsigned G3 : 1;  // 对Dr3保存的地址启用 全局断点
											  /*
											  // 【以弃用】用于降低CPU频率，以方便准确检测断点异常
											  */
			unsigned LE : 1;
			unsigned GE : 1;
			/*
			// 保留字段
			*/
			unsigned Reserve1 : 3;
			/*
			// 保护调试寄存器标志位，如果此位为1，则有指令修改条是寄存器时会触发异常
			*/
			unsigned GD : 1;
			/*
			// 保留字段
			*/
			unsigned Reserve2 : 2;

			unsigned RW0 : 2;  // 设定Dr0指向地址的断点类型 
			unsigned LEN0 : 2;  // 设定Dr0指向地址的断点长度
			unsigned RW1 : 2;  // 设定Dr1指向地址的断点类型
			unsigned LEN1 : 2;  // 设定Dr1指向地址的断点长度
			unsigned RW2 : 2;  // 设定Dr2指向地址的断点类型
			unsigned LEN2 : 2;  // 设定Dr2指向地址的断点长度
			unsigned RW3 : 2;  // 设定Dr3指向地址的断点类型
			unsigned LEN3 : 2;  // 设定Dr3指向地址的断点长度
		
	};	//DR7位段结构体

};

