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
	DWORD Old_Proc;//���ԭ���ڴ�����
	BOOL Is_Debug_Singgle_Step;
	string Authority;
	DWORD Memory_Bp_Alive; //�ڴ�ϵ��Ƿ�����
	DWORD Memory_Bp_Addr;//�ڴ�ϵ��ַ��¼
	DWORD Memory_Bp_Length;//�ڴ�ϵ��ⳤ��
	DWORD Old_Memory_Attribute;//ԭ�����ڴ�����
	DWORD Is_Hard_Break_Point;//�ж��Ƿ�ΪӲ���ϵ�
	DWORD Hard_Break_Point_Addr;//Ӳ���ϵ�ĵ�ַ
	string Hard_Break_Point_Option;//Ӳ���ϵ��ѡ��
	DWORD Hard_Break_Point_Length;//Ӳ���ϵ�ĳ��ȣ������ִ�жϵ㣬��ô���ȱ���Ҫ��0



	struct DR7_Register {
		
			/*
			// �ֲ��ϵ�(L0~3)��ȫ�ֶϵ�(G0~3)�ı��λ
			*/
			unsigned L0 : 1;  // ��Dr0����ĵ�ַ���� �ֲ��ϵ�
			unsigned G0 : 1;  // ��Dr0����ĵ�ַ���� ȫ�ֶϵ�
			unsigned L1 : 1;  // ��Dr1����ĵ�ַ���� �ֲ��ϵ�
			unsigned G1 : 1;  // ��Dr1����ĵ�ַ���� ȫ�ֶϵ�
			unsigned L2 : 1;  // ��Dr2����ĵ�ַ���� �ֲ��ϵ�
			unsigned G2 : 1;  // ��Dr2����ĵ�ַ���� ȫ�ֶϵ�
			unsigned L3 : 1;  // ��Dr3����ĵ�ַ���� �ֲ��ϵ�
			unsigned G3 : 1;  // ��Dr3����ĵ�ַ���� ȫ�ֶϵ�
											  /*
											  // �������á����ڽ���CPUƵ�ʣ��Է���׼ȷ���ϵ��쳣
											  */
			unsigned LE : 1;
			unsigned GE : 1;
			/*
			// �����ֶ�
			*/
			unsigned Reserve1 : 3;
			/*
			// �������ԼĴ�����־λ�������λΪ1������ָ���޸����ǼĴ���ʱ�ᴥ���쳣
			*/
			unsigned GD : 1;
			/*
			// �����ֶ�
			*/
			unsigned Reserve2 : 2;

			unsigned RW0 : 2;  // �趨Dr0ָ���ַ�Ķϵ����� 
			unsigned LEN0 : 2;  // �趨Dr0ָ���ַ�Ķϵ㳤��
			unsigned RW1 : 2;  // �趨Dr1ָ���ַ�Ķϵ�����
			unsigned LEN1 : 2;  // �趨Dr1ָ���ַ�Ķϵ㳤��
			unsigned RW2 : 2;  // �趨Dr2ָ���ַ�Ķϵ�����
			unsigned LEN2 : 2;  // �趨Dr2ָ���ַ�Ķϵ㳤��
			unsigned RW3 : 2;  // �趨Dr3ָ���ַ�Ķϵ�����
			unsigned LEN3 : 2;  // �趨Dr3ָ���ַ�Ķϵ㳤��
		
	};	//DR7λ�νṹ��

};

