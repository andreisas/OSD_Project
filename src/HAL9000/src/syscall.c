#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "iomu.h"
#include "thread_internal.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
            case SyscallIdIdentifyVersion:
                status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
                break;
            case SyscallIdThreadExit:
                status = SyscallThreadExit(
                    (STATUS)pSyscallParameters[0]
                );
                break;
            case SyscallIdThreadCreate:
                status = SyscallThreadCreate(
                    (PFUNC_ThreadStart)pSyscallParameters[0],
                    (PVOID)pSyscallParameters[1],
                    (UM_HANDLE*)pSyscallParameters[2]
                );
                break;
            case SyscallIdThreadCloseHandle:
                status = SyscallThreadCloseHandle(
                    (UM_HANDLE)pSyscallParameters[0]
                );
                break;
            case SyscallIdThreadGetTid:;
                status = SyscallThreadGetTid(
                    (UM_HANDLE)pSyscallParameters[0],
                    (TID*)pSyscallParameters[1]
                );
                break;
            case SyscallIdThreadWaitForTermination:
                status = SyscallThreadWaitForTermination(
                    (UM_HANDLE)pSyscallParameters[0],
                    (STATUS*)pSyscallParameters[1]
                );
                break;
            case SyscallVirtualAlloc:
                status = SyscallVirtualAlloc(
                    (PVOID) pSyscallParameters[0],
                    (QWORD) pSyscallParameters[1],
                    (VMM_ALLOC_TYPE) pSyscallParameters[2],
                    (PAGE_RIGHTS) pSyscallParameters[3],
                    (UM_HANDLE) pSyscallParameters[4],
                    (QWORD)  pSyscallParameters[5],
                    (PVOID*) pSyscallParameters[6]
                );
                break;
            case SyscallVirtualFree:
                status = SyscallVirtualFree(
                    (PVOID)pSyscallParameters[0],
                    (QWORD)pSyscallParameters[1],
                    (VMM_FREE_TYPE)pSyscallParameters[2]
                );
                break;
            default:
                LOG_ERROR("Unimplemented syscall called from User-space!\n");
                status = STATUS_UNSUPPORTED;
                break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallThreadGetTid(
    IN_OPT  UM_HANDLE               ThreadHandle,
    OUT     TID* ThreadId
)
{
    PPROCESS process = GetCurrentProcess();
    PTHREAD pThread = process->ThreadHandleList[ThreadHandle];
    if (UM_INVALID_HANDLE_VALUE == ThreadHandle)
    {
        *ThreadId = ThreadGetId(GetCurrentThread());
        return STATUS_SUCCESS;
    }
    TID tid = ThreadGetId(pThread);
    *ThreadId = tid;
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadWaitForTermination(
    IN      UM_HANDLE               ThreadHandle,
    OUT     STATUS* TerminationStatus
)
{
    PPROCESS process = GetCurrentProcess();
    PTHREAD pThread = process->ThreadHandleList[ThreadHandle];

    if (UM_INVALID_HANDLE_VALUE == ThreadHandle)
    {
        return STATUS_UNSUCCESSFUL;
    }
    if (pThread == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS status = MmuIsBufferValid(TerminationStatus, sizeof(STATUS), PAGE_RIGHTS_READWRITE, process);
    if (!SUCCEEDED(status))
    {
        return status;
    }

    ThreadWaitForTermination(pThread, TerminationStatus);

    return STATUS_SUCCESS;
}


STATUS
SyscallThreadCreate(
    IN      PFUNC_ThreadStart       StartFunction,
    IN_OPT  PVOID                   Context,
    OUT     UM_HANDLE* ThreadHandle
)
{
    PTHREAD thread;
    PPROCESS process = GetCurrentProcess();
    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER2;
    }
    if (ThreadHandle == NULL) {
        return STATUS_INVALID_PARAMETER3;
    }
    if (StartFunction == NULL) {
        return STATUS_INVALID_PARAMETER1;
    }

    STATUS status = MmuIsBufferValid(ThreadHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_WRITE, process);

    if (!SUCCEEDED(status)) {
        return STATUS_INVALID_BUFFER;
    }

    status = ThreadCreateEx("Thread", ThreadPriorityDefault, StartFunction, Context, &thread, process);

    if (!SUCCEEDED(status)) {
        return status;
    }

    QWORD newThreadHandle = ++(process->NewThreadHandle);
    process->ThreadHandleList[newThreadHandle] = thread;
    *ThreadHandle = (UM_HANDLE)newThreadHandle;

    return STATUS_SUCCESS;
};


STATUS
SyscallThreadExit(
    IN   STATUS     ExitStatus
)
{
    PTHREAD pThread = GetCurrentThread();
    PPROCESS process = GetCurrentProcess();
    STATUS status = STATUS_UNSUCCESSFUL;
    if (process != NULL) {
        QWORD list_size = process->NewThreadHandle;
        for (QWORD i = 1; i < list_size; i++) {
            if (process->ThreadHandleList[i] == pThread) {
                process->ThreadHandleList[i] = NULL;
                status = STATUS_SUCCESS;
            }
        }
    }
    ThreadExit(ExitStatus);
    return status;
}

STATUS
SyscallThreadCloseHandle(
    IN      UM_HANDLE               ThreadHandle
)
{
    if (UM_INVALID_HANDLE_VALUE == ThreadHandle)
    {
        return STATUS_UNSUCCESSFUL;
    }

    PPROCESS process = GetCurrentProcess();
    PTHREAD pThread = process->ThreadHandleList[ThreadHandle];

    if (pThread == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    process->ThreadHandleList[ThreadHandle] = NULL;
    ThreadCloseHandle(pThread);
    return STATUS_SUCCESS;
};

STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    UNREFERENCED_PARAMETER(ExitStatus);

    ProcessTerminate(GetCurrentProcess());

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
    char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
    char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE* ProcessHandle
)
{
    if (!ProcessPath) {
        return STATUS_INVALID_POINTER;
    }
    PPROCESS currentProcess = GetCurrentProcess();

    if (!SUCCEEDED(MmuIsBufferValid((PVOID)ProcessPath, PathLength, PAGE_RIGHTS_ALL, currentProcess)))
    {
        return STATUS_INVALID_BUFFER;
    }

    const char* systemPartition = IomuGetSystemPartitionPath();

    char fullPath[MAX_PATH];

    if (ProcessPath[1] != ':')
    {
        snprintf(fullPath, MAX_PATH, "%s%s\\%s", systemPartition, "APPLICATIONS", ProcessPath);
    }
    else {
        strcpy(fullPath, ProcessPath);
    }

    PPROCESS createdProcess = NULL;
    STATUS status;

    if (ArgLength > 0)
    {
        status = ProcessCreate(fullPath, Arguments, &createdProcess);
    }
    else
    {
        status = ProcessCreate(fullPath, NULL, &createdProcess);
    }

    if (!SUCCEEDED(status))
    {
        return STATUS_INVALID_POINTER;
    }

    PUM_HANDLE_DATA Handle = ExAllocatePoolWithTag(
        PoolAllocateZeroMemory,
        1 * sizeof(UM_HANDLE_DATA),
        HEAP_TEMP_TAG,
        0
    );

    status = UmHandleInit(Handle);

    Handle->pResource = createdProcess;

    INTR_STATE dummyState;

    LockAcquire(&currentProcess->ProcessHandleListLock, &dummyState);
    InsertTailList(&currentProcess->ProcessHandleList, &Handle->listResource);
    LockRelease(&currentProcess->ProcessHandleListLock, dummyState);

    *ProcessHandle = Handle->Handle;

    return STATUS_SUCCESS;

}

STATUS
SyscallProcessGetPid(
    IN_OPT  UM_HANDLE               ProcessHandle,
    OUT     PID* ProcessId
)
{
    PPROCESS processFromHandle = NULL;

    STATUS status = GetProcessFromUmHandle(ProcessHandle, GetCurrentProcess(), &processFromHandle);

    if (!SUCCEEDED(status))
    {
        *ProcessId = (PID)0;
        return STATUS_SUCCESS;
    }

    if (processFromHandle != NULL) {

        *ProcessId = processFromHandle->Id;

        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_POINTER;
}


STATUS
SyscallProcessWaitForTermination(
    IN      UM_HANDLE               ProcessHandle,
    OUT     STATUS* TerminationStatus
)
{
    if (TerminationStatus == NULL)
    {
        return STATUS_INVALID_BUFFER;
    }

    if (UM_INVALID_HANDLE_VALUE == ProcessHandle)
    {
        *TerminationStatus = STATUS_UNSUCCESSFUL;
        return STATUS_SUCCESS;
    }

    PPROCESS processFromHandle = NULL;

    STATUS status = GetProcessFromUmHandle(ProcessHandle, GetCurrentProcess(), &processFromHandle);

    if (!SUCCEEDED(status))
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (processFromHandle != NULL)
    {
        ProcessWaitForTermination(processFromHandle, TerminationStatus);

        return STATUS_SUCCESS;
    }
    return STATUS_ELEMENT_NOT_FOUND;
}


STATUS
SyscallProcessCloseHandle(
    IN      UM_HANDLE               ProcessHandle
)
{
    STATUS status = ProcessCloseUmHandle(ProcessHandle, GetCurrentProcess());

    if (!SUCCEEDED(status))                 
    {
        return STATUS_INVALID_PARAMETER1;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallFileCreate(
    IN_READS_Z(PathLength)
    char* Path,
    IN          QWORD                   PathLength,
    IN          BOOLEAN                 Directory,
    IN          BOOLEAN                 Create,
    OUT         UM_HANDLE* FileHandle
)
{
    const char* systemPartition = IomuGetSystemPartitionPath();

    char fullPath[MAX_PATH];
    if (!SUCCEEDED(MmuIsBufferValid((PVOID)Path, PathLength, PAGE_RIGHTS_ALL, GetCurrentProcess())))
    {
        return STATUS_INVALID_PARAMETER1;
    }


    if (Path[1] != ':')
    {
        snprintf(fullPath, MAX_PATH, "%s%s", systemPartition, Path);
    }
    else {
        strcpy(fullPath, Path);
    }

    PPROCESS currentProcess = GetCurrentProcess();

    /// <summary>
    /// Quotas
    /// </summary>

    if (currentProcess->NrOfFiles >= PROCESS_MAX_OPEN_FILES) {
        return STATUS_UNSUCCESSFUL;
    }


    PFILE_OBJECT createFileObject = NULL;

    STATUS status = IoCreateFile(&createFileObject, fullPath, Directory, Create, FALSE);

    if (!SUCCEEDED(status))
    {
        return STATUS_INVALID_FILE_NAME;
    }

    PUM_HANDLE_DATA Handle = ExAllocatePoolWithTag(
        PoolAllocateZeroMemory,
        1 * sizeof(UM_HANDLE_DATA),
        HEAP_TEMP_TAG,
        0
    );

    
    status = UmHandleInit(Handle);

    Handle->pResource = createFileObject;

    INTR_STATE dummyState;

    LockAcquire(&currentProcess->FileHandleListLock, &dummyState);
    InsertTailList(&currentProcess->FileHandleList, &Handle->listResource);
    LockRelease(&currentProcess->FileHandleListLock, dummyState);

    *FileHandle = Handle->Handle;

    /// <summary>
    /// Quotas
    /// </summary>

    currentProcess->NrOfFiles++;

    return STATUS_SUCCESS;
}

STATUS
SyscallFileClose(
    IN          UM_HANDLE               FileHandle
)
{
    PPROCESS currentProcess = GetCurrentProcess();

    if (FileHandle == UM_FILE_HANDLE_STDOUT)
    {
        if (currentProcess->StdOut == FALSE) {
            return STATUS_UNSUCCESSFUL;
        }
        else {
            currentProcess->StdOut = FALSE;
            return STATUS_SUCCESS;
        }

    }

    if (UM_INVALID_HANDLE_VALUE == FileHandle)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    STATUS status = FileCloseUmHandle(FileHandle, GetCurrentProcess());

    /// <summary>
    /// Quotas
    /// </summary>
    
    currentProcess->NrOfFiles--;

    if (!SUCCEEDED(status))
    {
        return STATUS_INVALID_PARAMETER1;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallFileRead(
    IN  UM_HANDLE                   FileHandle,
    OUT_WRITES_BYTES(BytesToRead)
    PVOID                       Buffer,
    IN  QWORD                       BytesToRead,
    OUT QWORD* BytesRead
)
{
    if (!SUCCEEDED(MmuIsBufferValid((PVOID)Buffer, sizeof(PVOID), PAGE_RIGHTS_WRITE, GetCurrentProcess())))
    {
        return STATUS_INVALID_PARAMETER2;
    }

    PFILE_OBJECT fileFromHandle = NULL;

    STATUS status = GetFileFromUmHandle(FileHandle, GetCurrentProcess(), &fileFromHandle);

    if (!SUCCEEDED(status))
    {
        return status;
    }

    if (fileFromHandle != NULL)
    {

        status = IoReadFile(fileFromHandle, BytesToRead, (QWORD*)0, Buffer, BytesRead);

        if (!SUCCEEDED(status))
        {
            return status;
        }

        return STATUS_SUCCESS;
    }
    return STATUS_ELEMENT_NOT_FOUND;
}

STATUS
SyscallVirtualAlloc(
    IN          PVOID                   BaseAddress,
    IN          QWORD                   Size,
    IN          VMM_ALLOC_TYPE          AllocType,
    IN          PAGE_RIGHTS             PageRights,
    IN_OPT      UM_HANDLE               FileHandle,
    IN_OPT      QWORD                   Key,
    OUT         PVOID*                  AllocatedAddress
)
{
    UNREFERENCED_PARAMETER(Key);
    if (BaseAddress == NULL) 
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (Size <= 0)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    if (!IsFlagOn(AllocType, VMM_ALLOC_TYPE_COMMIT | VMM_ALLOC_TYPE_RESERVE))
    {
        return STATUS_INVALID_PARAMETER3;
    }

    if (PageRights == PAGE_RIGHTS_ALL)
    {
        return STATUS_INVALID_PARAMETER4;
    }

    PPROCESS process = GetCurrentProcess();
    PFILE_OBJECT file;

    STATUS status = GetFileFromUmHandle(FileHandle, process, &file);

    status = MmuIsBufferValid(BaseAddress, Size, PageRights, process);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid BaseAddress", status);
        return status;
    }

    status = MmuIsBufferValid(AllocatedAddress, sizeof(PVOID), PageRights, process);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid AllocatedAddress", status);
        return status;
    }

    *AllocatedAddress = VmmAllocRegionEx(BaseAddress, Size, AllocType, PageRights, FALSE, NULL, process->VaSpace, process->PagingData, NULL);
    return STATUS_SUCCESS;
}

SyscallVirtualFree(
    IN          PVOID                   Address,
    IN          QWORD                   Size,
    IN          VMM_FREE_TYPE           FreeType
)
{
    if (Address == NULL)
    {
        return STATUS_INVALID_PARAMETER1;
    }
    if (Size <= 0)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    STATUS status;
    PPROCESS process = GetCurrentProcess();

    status = MmuIsBufferValid(Address, Size, PAGE_RIGHTS_READWRITE, process);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("MmuIsBufferValid Address", status);
        return status;
    }

    VmmFreeRegionEx(Address, Size, FreeType, TRUE, process->VaSpace, process->PagingData);
    return STATUS_SUCCESS;
}