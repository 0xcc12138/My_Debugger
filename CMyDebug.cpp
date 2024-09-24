#include "CMyDebug.h"
#include <iostream>
#include "include/platform.h"
#include "include/capstone/x86.h"
#include "include/windowsce/intrin.h"
#include "include/windowsce/stdint.h"
#include "capstone/capstone.h"

#pragma comment(lib,"E:\\viusal studio document\\科锐\\调试器\\SingleStep_AntiDebug\\capstone.lib")
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
    m_context.EFlags |= 0x100;//TF标志位置为1
    
    
    DWORD RESULT=SetThreadContext(processInfo.hThread, &m_context);
}

VOID CMyDebug::Exception_BreakPoint()
{
    GetContext();
    cout << "异常的发生ip为" << hex<<m_context.Eip << endl;
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
    cout << "此时EIP为" << hex << m_context.Eip << endl;
   

    
}

DWORD CMyDebug::Memory_Break_Point_Exception()
{
    //执行完当前指令，要恢复原来的内存属性
    
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
    cout << "内存断点重新激活" << endl;
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



    // 打开句柄
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
            printf("地址: 0x%x  反汇编: %s %s \n", m_ip, insn[index].mnemonic, insn[index].op_str);
            m_ip += insn[index].size;
        }

        cs_free(insn, count);
    }
    else
    {
        printf("反汇编返回长度为空 \n");
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
            cout << "当前eip地址为" << hex << m_context.Eip << endl;
            DisassembleCode((char*)Process_Buffer, 1000, 20);
        }
        else if (szCmd=="g")
        {
            
            break;
        }
        else if (szCmd=="t")
        {
            //说明是人为的在调试器在下单步异常断点
            Is_Debug_Singgle_Step = TRUE;
            
            //修改tf标志位
            SetStep();
            
            //cout << "当前eip地址为" << hex << m_context.Eip << endl;
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
            //DWORD Hard_Break_Point_Addr;//硬件断点的地址
            //DWORD Hard_Break_Point_Option;//硬件断点的选项
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

    //切记设置完硬件断点后，当到达指定位置以后，要将Dr7清空，否则会一直造成单步异常
    //如果是由硬件断点引起的异常，DR6寄存器的相应位会被置位，可以通过检查这些位来确定异常是否是由硬件断点引起的。

    if (Hard_Break_Point_Option == "e")
    {
        GetContext();

        DR7_Register* m_dr7_register = (DR7_Register*)&m_context.Dr7;
        m_context.Dr0 = (DWORD)Addr;   //利用Dr0寄存器存放地址
        m_dr7_register->RW0 = 0;       //Dr7寄存器中的RW0设置类型
        m_dr7_register->LEN0 = 0;                //Dr7寄存器中的LEN0设置长度
        m_dr7_register->L0 = 1;



        HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
        SetThreadContext(hThread, &m_context);
    }

    else if (Hard_Break_Point_Option == "w")
    {
        GetContext();

        DR7_Register* m_dr7_register = (DR7_Register*)&m_context.Dr7;
        m_context.Dr0 = (DWORD)Addr;   //利用Dr0寄存器存放地址
        m_dr7_register->RW0 = 0b01;       //Dr7寄存器中的RW0设置类型
        m_dr7_register->LEN0 = Hard_Break_Point_Length;                //Dr7寄存器中的LEN0设置长度
        m_dr7_register->L0 = 1;



        HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
        SetThreadContext(hThread, &m_context);
    }


    else if (Hard_Break_Point_Option == "r")
    {
        GetContext();

        DR7_Register* m_dr7_register = (DR7_Register*)&m_context.Dr7;
        m_context.Dr0 = (DWORD)Addr;   //利用Dr0寄存器存放地址
        m_dr7_register->RW0 = 0b11;       //Dr7寄存器中的RW0设置类型
        m_dr7_register->LEN0 = Hard_Break_Point_Length;                //Dr7寄存器中的LEN0设置长度
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
		std::cout << "创建调试进程成功！" << std::endl;
		return 1;
	}

	else
	{
		std::cout << "创建调试进程失败！" << std::endl;
		return 0;
	}
	
}

VOID CMyDebug::OnCreateThread()
{
	// 处理线程创建事件
	printf("Create Thread Debug Event\t");
	continueStatus = DBG_CONTINUE;
	CREATE_THREAD_DEBUG_INFO Thread_Info = dbgEvent.u.CreateThread;
	HANDLE Thread_Handle = Thread_Info.hThread;
	DWORD Thread_Proc_Addr = (DWORD)Thread_Info.lpStartAddress;
	DWORD Thread_TEB = (DWORD)Thread_Info.lpThreadLocalBase;
	cout << "该线程句柄为0x" << hex << (DWORD)Thread_Handle << "   回调函数的地址是0x" << hex << Thread_Proc_Addr << "      TEB基址是0x" << hex << Thread_TEB << endl;
	//fs 寄存器在用户模式下通常用于访问线程环境块（TEB，Thread Environment Block）的地址。FS寄存器的值就是这样拿的，是操作系统告诉的
	continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    
}

VOID CMyDebug::OnCreateProcess()
{
    printf("Create Process Debug Event\t");
    // 处理进程创建事件
    _CREATE_PROCESS_DEBUG_INFO Process_Info = { 0 };
    Process_Info = dbgEvent.u.CreateProcessInfo;
    cout << "程序的主模块基址是：0x" << hex << Process_Info.lpBaseOfImage << endl;
    cout << "程序入口点是:0x" << hex << Process_Info.lpStartAddress << endl;

    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    
}

VOID CMyDebug::OnDllLoad()
{
    // 处理加载DLL事件
    printf("Load DLL Debug Event\t");
    _LOAD_DLL_DEBUG_INFO Dll_Info = dbgEvent.u.LoadDll;
    DWORD BaseOfDll = (DWORD)Dll_Info.lpBaseOfDll;
    cout << "加载的Dll地址为：0x" << hex << BaseOfDll << endl;
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
    cout << "Dll被卸载，地址为：" << hex << Unload_Addr;
    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
}

VOID CMyDebug::OnOutPutString()
{
    // 处理输出调试字符串事件
    printf("Output Debug String Event\t");
    //获取被调试程序的OutPutString的输出字符串
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
    cout << "线程退出码为" << hex << Thread_Exit_Info.dwExitCode << endl;
    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
}

VOID CMyDebug::OnProcessExit()
{
    printf("Exit Process Debug Event\t");
    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    EXIT_PROCESS_DEBUG_INFO Process_Exit_Info = dbgEvent.u.ExitProcess;
    cout << "进程的退出码为:" << hex << Process_Exit_Info.dwExitCode << endl;
    exit(0);
}

VOID CMyDebug::OnDebugEvent()
{
    //printf("Exception Debug Event\t");
    // 获取异常信息
    EXCEPTION_DEBUG_INFO exceptInfo = dbgEvent.u.Exception;
    //Exception_Addr = (DWORD)exceptInfo.ExceptionRecord.ExceptionAddress;
    // 根据异常代码进一步处理
    if (exceptInfo.dwFirstChance == TRUE)
    {
        cout << "这是第一次异常" << endl;
    }
    else
    {
        cout << "这是第二次异常" << endl;
    }
    //cout << exceptInfo.ExceptionRecord.ExceptionInformation[1] << endl;
    memset(&m_context, 0, sizeof(CONTEXT));
    m_context.ContextFlags = CONTEXT_FULL;

    GetThreadContext(processInfo.hThread, &m_context);
    GetContext();

    switch (exceptInfo.ExceptionRecord.ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION: //违规访问
        printf("Access Violation\t");
        cout << "违规访问的Eip为" << hex << m_context.Eip << endl;
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
    case EXCEPTION_BREAKPOINT:  //断点异常
        Exception_BreakPoint();
        break;
    case EXCEPTION_SINGLE_STEP: //单步异常
        GetContext();
        if (Is_Hard_Break_Point&& ((DWORD)m_context.Eip>=Hard_Break_Point_Addr&& (DWORD)exceptInfo.ExceptionRecord.ExceptionInformation[1]<=Hard_Break_Point_Addr+6))
        {
            //清空一下DR7
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
        cout <<"此时的Eip异常点"<< hex << m_context.Eip << endl;
        break;
    case DBG_CONTROL_C: //ctrl+c控制台强制退出
        break;
        // 添加其他异常类型的处理

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
        cout << "异常码：" << hex << exceptInfo.ExceptionRecord.ExceptionCode << endl;
        cout << "异常的地址是" << exceptInfo.ExceptionRecord.ExceptionAddress << endl;
        continueStatus = DBG_CONTINUE;
        break;
    }
    cout << "异常码：" << hex << exceptInfo.ExceptionRecord.ExceptionCode << endl;
   // cout << "异常的地址是" << exceptInfo.ExceptionRecord.ExceptionAddress << endl;
    
}


INT CMyDebug::OnDebug()
{
    while (1) {
        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        // 等待调试事件
        if (!WaitForDebugEvent(&dbgEvent, INFINITE))//无限等待，没有事件来就不走
        {
            printf("WaitForDebugEvent failed\n");
            break;
        }
        GetContext();
        // 处理调试事件
        switch (dbgEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
        {
            
            OnDebugEvent();
            GetCommand();
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: //线程创建事件
        {
            OnCreateThread();
            break;
        }

        case CREATE_PROCESS_DEBUG_EVENT: //进程创建事件
        {
            OnCreateProcess();
            break;
        }

        case EXIT_THREAD_DEBUG_EVENT:
            // 处理线程退出事件
            OnThreadExit();
            break;


        case EXIT_PROCESS_DEBUG_EVENT:
            // 处理进程退出事件
            OnProcessExit();
            break;

        case LOAD_DLL_DEBUG_EVENT:
        {
            // 处理加载DLL事件
            OnDllLoad();
            break;
        }

        case UNLOAD_DLL_DEBUG_EVENT:
        {
            // 处理卸载DLL事件
            OnDllUnload();
            break;
        }

        case OUTPUT_DEBUG_STRING_EVENT:
        {
            // 处理输出调试字符串事件
            OnOutPutString();

            break;

        }



        case RIP_EVENT:
            printf("RIP Event\t");
            // 处理RIP事件
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            break;

        default:
            printf("Unknown Debug Event\t");
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }

        // 继续执行调试
        //

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
    
       
    }

    return 0;
}
