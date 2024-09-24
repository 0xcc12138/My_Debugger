#include "CMyDebug.h"
#include <iostream>
#include "include/platform.h"
#include "include/capstone/x86.h"
#include "include/windowsce/intrin.h"
#include "include/windowsce/stdint.h"
#include "capstone/capstone.h"

#pragma comment(lib,"E:\\viusal studio document\\����\\������\\SingleStep_AntiDebug\\capstone.lib")
using namespace std;


#pragma comment(lib,"BeaEngine.lib")


VOID CMyDebug::GetContext()
{
    memset(&m_context, 0, sizeof(CONTEXT));
    m_context.ContextFlags = CONTEXT_ALL;
    HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
    GetThreadContext(hThread, &m_context);
}

VOID CMyDebug::SetStep()
{
    GetContext();
    m_context.EFlags |= 0x100;//TF��־λ��Ϊ1
    
    
    DWORD RESULT=SetThreadContext(processInfo.hThread, &m_context);
}

VOID CMyDebug::Exception_BreakPoint()
{
    GetContext();
    cout << "�쳣�ķ���ipΪ" << hex<<m_context.Eip << endl;
    if (!IsSystemBreakPoint)
    {
        if (dbgEvent.u.Exception.dwFirstChance&&m_context.Eip== Exception_Addr+1)
        {
            m_context.Eip -= 1;
            CHAR Buffer[100];
            SetThreadContext(processInfo.hThread, &m_context);
            ReadProcessMemory(processInfo.hProcess, (LPCVOID)(m_context.Eip), Buffer, 0x40, NULL);
            WriteProcessMemory(processInfo.hProcess, (LPVOID)m_context.Eip, &Old_Char, 0x1, NULL);
            ReadProcessMemory(processInfo.hProcess, (LPCVOID)(m_context.Eip), Buffer, 0x40, NULL);
            continueStatus = DBG_CONTINUE;
           
        }
        else
        {
            CHAR Buffer[100];
            ReadProcessMemory(processInfo.hProcess, (LPCVOID)(m_context.Eip), Buffer, 0x40, NULL);
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            
        }
    }


    if (IsSystemBreakPoint)
        IsSystemBreakPoint = FALSE;
    printf("Breakpoint\t");
    cout << "��ʱEIPΪ" << hex << m_context.Eip << endl;
   

    
}

DWORD CMyDebug::Memory_Break_Point_Exception()
{
    //ִ���굱ǰָ�Ҫ�ָ�ԭ�����ڴ�����
    
    if (Authority == "w")
        VirtualProtectEx(processInfo.hProcess, (LPVOID)Memory_Bp_Addr, Memory_Bp_Length, PAGE_EXECUTE_READ, &Old_Memory_Attribute);
    else if (Authority == "r")
        VirtualProtectEx(processInfo.hProcess, (LPVOID)Memory_Bp_Addr, Memory_Bp_Length, PAGE_EXECUTE_WRITECOPY, &Old_Memory_Attribute);
    GetContext();
    m_context.EFlags &= 0xFEFF;
    SetThreadContext(processInfo.hThread, &m_context);
    cout <<hex<< m_context.Eip << endl;
   // m_context.EFlags |= 0x100;
    //SetThreadContext(processInfo.hThread, &m_context);
    cout << "�ڴ�ϵ����¼���" << endl;
    continueStatus = DBG_CONTINUE;
    return 0;


}

VOID CMyDebug::Exception_SingleStep()
{
    

   
   /* if(dbgEvent.u.Exception.dwFirstChance)
        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    else
    {*/
        continueStatus = DBG_CONTINUE;
        /*DisassembleCode((char*)Process_Buffer, 1000, 1);
    }*/

    //continueStatus=DBG_
    
    return ;
}


void CMyDebug::DisassembleCode(char* start_offset, int size, int length)
{
    csh handle;
    cs_insn* insn;
    size_t count;



    // �򿪾��
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
        return;
    }
    DWORD m_ip = m_context.Eip;
    count = cs_disasm(handle, (unsigned char*)start_offset, size, m_ip, 0, &insn);
    count = length;
    
    if (count > 0)
    {
        size_t index;
        for (index = 0; index < count; index++)
        {
            printf("��ַ: 0x%x  �����: %s %s \n", m_ip, insn[index].mnemonic, insn[index].op_str);
            m_ip += insn[index].size;
        }

        cs_free(insn, count);
    }
    else
    {
        printf("����෵�س���Ϊ�� \n");
    }

    cs_close(&handle);
}


INT CMyDebug::GetCommand()
{
    string szCmd;
    GetContext();
    while (true)
    {
        printf("cmd:");
        getline(cin, szCmd);
        std::transform(szCmd.begin(), szCmd.end(), szCmd.begin(), ::tolower);
        string m_order = szCmd.substr(0, 2);
        if (szCmd == "u")
        {
            
            memset(&m_context, 0, sizeof(CONTEXT));
            m_context.ContextFlags = CONTEXT_FULL;

            GetThreadContext(processInfo.hThread, &m_context);
            GetContext();
            ReadProcessMemory(processInfo.hProcess, (LPCVOID)m_context.Eip, Process_Buffer, 0x1000, NULL);
            cout << "��ǰeip��ַΪ" << hex << m_context.Eip << endl;
            DisassembleCode((char*)Process_Buffer, 1000, 20);
        }
        else if (szCmd=="g")
        {
            
            break;
        }
        else if (szCmd=="t")
        {
            //˵������Ϊ���ڵ��������µ����쳣�ϵ�
            Is_Debug_Singgle_Step = TRUE;
            
            //�޸�tf��־λ
            SetStep();
            
            //cout << "��ǰeip��ַΪ" << hex << m_context.Eip << endl;
            ReadProcessMemory(processInfo.hProcess, (LPCVOID)m_context.Eip, Process_Buffer, 0x1000, NULL);
            break;
            
        }
        
        else if (m_order == "bm")
        {

            Memory_Bp_Alive = TRUE;
            string str(szCmd);
            stringstream ss;
            ss << szCmd;
            string Order;
            
            string Memory_Addr;
            string Length;
            ss >> Order;
            ss >> Authority;

            ss >> Memory_Addr;
            ss >> Length;
            Memory_Bp_Addr = static_cast<DWORD>(std::stoul(&Memory_Addr[2], nullptr, 16));
            Memory_Bp_Length = std::stoul(Length);
            if (Authority == "w")
                VirtualProtectEx(processInfo.hProcess, (LPVOID)Memory_Bp_Addr, Memory_Bp_Length, PAGE_EXECUTE_READ, &Old_Memory_Attribute);
            else if (Authority == "r")
                VirtualProtectEx(processInfo.hProcess, (LPVOID)Memory_Bp_Addr, Memory_Bp_Length, PAGE_EXECUTE_READ, &Old_Memory_Attribute);
            
            
        }


        else if (m_order == "bh")
        {
            //DWORD Hard_Break_Point_Addr;//Ӳ���ϵ�ĵ�ַ
            //DWORD Hard_Break_Point_Option;//Ӳ���ϵ��ѡ��
            //DWORD Hard_Break_Point_Length;

            string str(szCmd);
            stringstream ss;
            ss << szCmd;
            string Temp;
            ss >> Temp;
            ss >> Temp;
            Hard_Break_Point_Option = Temp;


            ss >> Temp;
            Hard_Break_Point_Addr = ::stoul(&Temp[2], nullptr, 16);

            ss >> Temp;
            Hard_Break_Point_Length = ::stoul(Temp, nullptr, 10);

            SetHardBreakPoint((LPVOID)Hard_Break_Point_Addr,Hard_Break_Point_Option,Hard_Break_Point_Length);
            Is_Hard_Break_Point = TRUE;
        }

        else if (szCmd[0]=='b' )
        {
            string str(szCmd);
            stringstream ss;
            ss << szCmd;
            string temp;
            ss >> temp;
            ss >> temp;
            DWORD Bp_Addr = static_cast<DWORD>(std::stoul(&temp[2], nullptr, 16));
            Exception_Addr = Bp_Addr;
            CHAR Buffer[100];
            ReadProcessMemory(processInfo.hProcess, (LPCVOID)Bp_Addr, Buffer, 0x40, NULL);
            ReadProcessMemory(processInfo.hProcess, (LPCVOID)Bp_Addr, &Old_Char, 0x1, NULL);
            WriteProcessMemory(processInfo.hProcess, (LPVOID)Bp_Addr, "\xcc", 0x1, NULL);
            ReadProcessMemory(processInfo.hProcess, (LPCVOID)Bp_Addr, Buffer, 0x40, NULL);
            
        }
        

        else if (szCmd[0] == 'r')
        {
            ShowRegister();
            
        }


        

        else
        {
            break;
        }
    }
    return 0;
}

 
VOID CMyDebug::SetHardBreakPoint(LPVOID Addr,string Hard_Break_Point_Option, DWORD Hard_Break_Point_Length)
{

    //�м�������Ӳ���ϵ�󣬵�����ָ��λ���Ժ�Ҫ��Dr7��գ������һֱ��ɵ����쳣
    //�������Ӳ���ϵ�������쳣��DR6�Ĵ�������Ӧλ�ᱻ��λ������ͨ�������Щλ��ȷ���쳣�Ƿ�����Ӳ���ϵ�����ġ�

    if (Hard_Break_Point_Option == "e")
    {
        GetContext();

        DR7_Register* m_dr7_register = (DR7_Register*)&m_context.Dr7;
        m_context.Dr0 = (DWORD)Addr;   //����Dr0�Ĵ�����ŵ�ַ
        m_dr7_register->RW0 = 0;       //Dr7�Ĵ����е�RW0��������
        m_dr7_register->LEN0 = 0;                //Dr7�Ĵ����е�LEN0���ó���
        m_dr7_register->L0 = 1;



        HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
        SetThreadContext(hThread, &m_context);
    }

    else if (Hard_Break_Point_Option == "w")
    {
        GetContext();

        DR7_Register* m_dr7_register = (DR7_Register*)&m_context.Dr7;
        m_context.Dr0 = (DWORD)Addr;   //����Dr0�Ĵ�����ŵ�ַ
        m_dr7_register->RW0 = 0b01;       //Dr7�Ĵ����е�RW0��������
        m_dr7_register->LEN0 = Hard_Break_Point_Length;                //Dr7�Ĵ����е�LEN0���ó���
        m_dr7_register->L0 = 1;



        HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
        SetThreadContext(hThread, &m_context);
    }


    else if (Hard_Break_Point_Option == "r")
    {
        GetContext();

        DR7_Register* m_dr7_register = (DR7_Register*)&m_context.Dr7;
        m_context.Dr0 = (DWORD)Addr;   //����Dr0�Ĵ�����ŵ�ַ
        m_dr7_register->RW0 = 0b11;       //Dr7�Ĵ����е�RW0��������
        m_dr7_register->LEN0 = Hard_Break_Point_Length;                //Dr7�Ĵ����е�LEN0���ó���
        m_dr7_register->L0 = 1;



        HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
        SetThreadContext(hThread, &m_context);
    }
    
}


VOID CMyDebug::ShowRegister()
{
    printf("EIP:0x%08x\tESP:0x%08x\tEBP:0x%08x\tEAX:0x%08x\tEBX:0x%08x\tECX:0x%08x\tEDX:0x%08x\tESI:0x%08x\tEDI:0x%08x\t\n",
        m_context.Eip, m_context.Esp, m_context.Ebp, m_context.Eax, m_context.Ebx, m_context.Ecx,
        m_context.Edx, m_context.Esi, m_context.Edi);
}

INT CMyDebug::BeginDebug(const char* LpName)
{
	
	ZeroMemory(&processInfo, sizeof(processInfo));
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	if (CreateProcess(
		LpName,
		NULL,
		NULL,
		NULL,
		FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&startupInfo,
		&processInfo
	))
	{
		std::cout << "�������Խ��̳ɹ���" << std::endl;
		return 1;
	}

	else
	{
		std::cout << "�������Խ���ʧ�ܣ�" << std::endl;
		return 0;
	}
	
}

VOID CMyDebug::OnCreateThread()
{
	// �����̴߳����¼�
	printf("Create Thread Debug Event\t");
	continueStatus = DBG_CONTINUE;
	CREATE_THREAD_DEBUG_INFO Thread_Info = dbgEvent.u.CreateThread;
	HANDLE Thread_Handle = Thread_Info.hThread;
	DWORD Thread_Proc_Addr = (DWORD)Thread_Info.lpStartAddress;
	DWORD Thread_TEB = (DWORD)Thread_Info.lpThreadLocalBase;
	cout << "���߳̾��Ϊ0x" << hex << (DWORD)Thread_Handle << "   �ص������ĵ�ַ��0x" << hex << Thread_Proc_Addr << "      TEB��ַ��0x" << hex << Thread_TEB << endl;
	//fs �Ĵ������û�ģʽ��ͨ�����ڷ����̻߳����飨TEB��Thread Environment Block���ĵ�ַ��FS�Ĵ�����ֵ���������õģ��ǲ���ϵͳ���ߵ�
	continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    
}

VOID CMyDebug::OnCreateProcess()
{
    printf("Create Process Debug Event\t");
    // ������̴����¼�
    _CREATE_PROCESS_DEBUG_INFO Process_Info = { 0 };
    Process_Info = dbgEvent.u.CreateProcessInfo;
    cout << "�������ģ���ַ�ǣ�0x" << hex << Process_Info.lpBaseOfImage << endl;
    cout << "������ڵ���:0x" << hex << Process_Info.lpStartAddress << endl;

    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    
}

VOID CMyDebug::OnDllLoad()
{
    // �������DLL�¼�
    printf("Load DLL Debug Event\t");
    _LOAD_DLL_DEBUG_INFO Dll_Info = dbgEvent.u.LoadDll;
    DWORD BaseOfDll = (DWORD)Dll_Info.lpBaseOfDll;
    cout << "���ص�Dll��ַΪ��0x" << hex << BaseOfDll << endl;
    PVOID NamePtr = Dll_Info.lpImageName;
    HANDLE Son_Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbgEvent.dwProcessId);
    CHAR Buffer[0x1000] = { 0 };
    DWORD ReadNum = 0;
    ReadProcessMemory(Son_Process, NamePtr, Buffer, 0x1000, &ReadNum);
    ReadProcessMemory(Son_Process, (LPVOID)(*(DWORD*)Buffer), Buffer, 0x1000, &ReadNum);
    //wcout << (wchar_t*)Buffer<<endl;
    wprintf(L"%ls\n", (WCHAR*)Buffer);
    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
}

VOID CMyDebug::OnDllUnload()
{
    printf("Unload DLL Debug Event\t");
    UNLOAD_DLL_DEBUG_INFO Dll_Unload_Info = dbgEvent.u.UnloadDll;
    DWORD Unload_Addr = (DWORD)Dll_Unload_Info.lpBaseOfDll;
    cout << "Dll��ж�أ���ַΪ��" << hex << Unload_Addr;
    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
}

VOID CMyDebug::OnOutPutString()
{
    // ������������ַ����¼�
    printf("Output Debug String Event\t");
    //��ȡ�����Գ����OutPutString������ַ���
    OUTPUT_DEBUG_STRING_INFO Output_String_Info = dbgEvent.u.DebugString;
    BOOL IsUnicode = Output_String_Info.fUnicode;
    DWORD Addr = (DWORD)Output_String_Info.lpDebugStringData;
    DWORD Lenth = Output_String_Info.nDebugStringLength;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbgEvent.dwProcessId);
    if (IsUnicode)
    {
        WCHAR Buffer[0x1000];
        DWORD Num = 0;
        ReadProcessMemory(hProcess, (LPCVOID)Addr, Buffer, 0x1000, &Num);
        wcout << Buffer << endl;
    }
    else
    {
        CHAR Buffer[0x1000];
        DWORD Num = 0;
        ReadProcessMemory(hProcess, (LPCVOID)Addr, Buffer, 0x1000, &Num);
        cout << Buffer << endl;
    }
    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
}

VOID CMyDebug::OnThreadExit()
{
    printf("Exit Thread Debug Event\t");
    EXIT_THREAD_DEBUG_INFO Thread_Exit_Info = dbgEvent.u.ExitThread;
    cout << "�߳��˳���Ϊ" << hex << Thread_Exit_Info.dwExitCode << endl;
    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
}

VOID CMyDebug::OnProcessExit()
{
    printf("Exit Process Debug Event\t");
    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    EXIT_PROCESS_DEBUG_INFO Process_Exit_Info = dbgEvent.u.ExitProcess;
    cout << "���̵��˳���Ϊ:" << hex << Process_Exit_Info.dwExitCode << endl;
    exit(0);
}

VOID CMyDebug::OnDebugEvent()
{
    //printf("Exception Debug Event\t");
    // ��ȡ�쳣��Ϣ
    EXCEPTION_DEBUG_INFO exceptInfo = dbgEvent.u.Exception;
    //Exception_Addr = (DWORD)exceptInfo.ExceptionRecord.ExceptionAddress;
    // �����쳣�����һ������
    if (exceptInfo.dwFirstChance == TRUE)
    {
        cout << "���ǵ�һ���쳣" << endl;
    }
    else
    {
        cout << "���ǵڶ����쳣" << endl;
    }
    //cout << exceptInfo.ExceptionRecord.ExceptionInformation[1] << endl;
    memset(&m_context, 0, sizeof(CONTEXT));
    m_context.ContextFlags = CONTEXT_FULL;

    GetThreadContext(processInfo.hThread, &m_context);
    GetContext();

    switch (exceptInfo.ExceptionRecord.ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION: //Υ�����
        printf("Access Violation\t");
        cout << "Υ����ʵ�EipΪ" << hex << m_context.Eip << endl;
        if (m_context.Dr6&0xf)
        {
            SetStep();
            DWORD Temp;
            VirtualProtectEx(processInfo.hProcess, (LPVOID)Memory_Bp_Addr, Memory_Bp_Length, Old_Memory_Attribute, &Temp);
            continueStatus = DBG_CONTINUE;
            break;
        }

        if (!exceptInfo.dwFirstChance)
        {
            continueStatus = DBG_CONTINUE;
        }
        else
        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        break;
    case EXCEPTION_BREAKPOINT:  //�ϵ��쳣
        Exception_BreakPoint();
        break;
    case EXCEPTION_SINGLE_STEP: //�����쳣
        GetContext();
        if (Is_Hard_Break_Point&& ((DWORD)m_context.Eip>=Hard_Break_Point_Addr&& (DWORD)exceptInfo.ExceptionRecord.ExceptionInformation[1]<=Hard_Break_Point_Addr+6))
        {
            //���һ��DR7
            GetContext();
            m_context.Dr7 = 0;
            HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
            SetThreadContext(hThread, &m_context);
            Is_Hard_Break_Point = FALSE;
            continueStatus = DBG_CONTINUE;
        }
        if(Memory_Bp_Alive)
            Memory_Break_Point_Exception();
        if (Is_Debug_Singgle_Step)
            Exception_SingleStep();
        
        Is_Debug_Singgle_Step = FALSE;
        cout <<"��ʱ��Eip�쳣��"<< hex << m_context.Eip << endl;
        break;
    case DBG_CONTROL_C: //ctrl+c����̨ǿ���˳�
        break;
        // ��������쳣���͵Ĵ���

    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        printf("Div Zero Exception!");
        if (!exceptInfo.dwFirstChance)
        {
            continueStatus = DBG_CONTINUE;
        }
        else
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        break;

    default:
        printf("Unknown Exception\t");
        cout << "�쳣�룺" << hex << exceptInfo.ExceptionRecord.ExceptionCode << endl;
        cout << "�쳣�ĵ�ַ��" << exceptInfo.ExceptionRecord.ExceptionAddress << endl;
        continueStatus = DBG_CONTINUE;
        break;
    }
    cout << "�쳣�룺" << hex << exceptInfo.ExceptionRecord.ExceptionCode << endl;
   // cout << "�쳣�ĵ�ַ��" << exceptInfo.ExceptionRecord.ExceptionAddress << endl;
    
}


INT CMyDebug::OnDebug()
{
    while (1) {
        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        // �ȴ������¼�
        if (!WaitForDebugEvent(&dbgEvent, INFINITE))//���޵ȴ���û���¼����Ͳ���
        {
            printf("WaitForDebugEvent failed\n");
            break;
        }
        GetContext();
        // ��������¼�
        switch (dbgEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
        {
            
            OnDebugEvent();
            GetCommand();
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: //�̴߳����¼�
        {
            OnCreateThread();
            break;
        }

        case CREATE_PROCESS_DEBUG_EVENT: //���̴����¼�
        {
            OnCreateProcess();
            break;
        }

        case EXIT_THREAD_DEBUG_EVENT:
            // �����߳��˳��¼�
            OnThreadExit();
            break;


        case EXIT_PROCESS_DEBUG_EVENT:
            // ��������˳��¼�
            OnProcessExit();
            break;

        case LOAD_DLL_DEBUG_EVENT:
        {
            // �������DLL�¼�
            OnDllLoad();
            break;
        }

        case UNLOAD_DLL_DEBUG_EVENT:
        {
            // ����ж��DLL�¼�
            OnDllUnload();
            break;
        }

        case OUTPUT_DEBUG_STRING_EVENT:
        {
            // ������������ַ����¼�
            OnOutPutString();

            break;

        }



        case RIP_EVENT:
            printf("RIP Event\t");
            // ����RIP�¼�
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            break;

        default:
            printf("Unknown Debug Event\t");
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }

        // ����ִ�е���
        //

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
    
       
    }

    return 0;
}
