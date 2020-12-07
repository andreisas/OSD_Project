#include "um_handle_manager.h"

#define UM_INCREMENT               4

static
UM_HANDLE _RetriveNextUmHandle(
	void
)
{
    static volatile UM_HANDLE __currentUmHandle = 4;

    return _InterlockedExchangeAdd64(&__currentUmHandle, UM_INCREMENT);
}

static
STATUS _InitUmHandle(
	OUT_PTR	PUM_HANDLE_DATA*	Handle
)
{
    LOG_FUNC_START;

    ASSERT(Handle != NULL);

    memzero(Handle, sizeof(UM_HANDLE_DATA));

    InitializeListHead(&(*Handle)->listResource);
    (*Handle)->Handle = _RetriveNextUmHandle();

    return STATUS_SUCCESS;
}

STATUS UmHandleInit(
    OUT	PUM_HANDLE_DATA	Handle
)
{
    ASSERT(Handle != NULL);

    memzero(Handle, sizeof(UM_HANDLE_DATA));

    InitializeListHead(&Handle->listResource);
    Handle->Handle = _RetriveNextUmHandle();

    return STATUS_SUCCESS;
}

STATUS
GetProcessFromUmHandle(
	IN		UM_HANDLE		Handle,
	IN		PPROCESS		CurrentProcess,
	OUT		PPROCESS*		ProcessFromHandle
)
{
    INTR_STATE dummyState;

    LockAcquire(&CurrentProcess->ProcessHandleListLock,&dummyState);

    DWORD size = ListSize(&CurrentProcess->ProcessHandleList);
    if (size > 0)
    {
       
        for (PLIST_ENTRY currentEntry = (&CurrentProcess->ProcessHandleList)->Flink; currentEntry != (&CurrentProcess->ProcessHandleList); currentEntry = currentEntry->Flink)
        {
            PUM_HANDLE_DATA currentHandle = CONTAINING_RECORD(currentEntry, UM_HANDLE_DATA, listResource);

            if (currentHandle->Handle == Handle)
            {
                *ProcessFromHandle = currentHandle->pResource;
                LockRelease(&CurrentProcess->ProcessHandleListLock, dummyState);
                return STATUS_SUCCESS;
            }
        }
    }
    LockRelease(&CurrentProcess->ProcessHandleListLock, dummyState);
    return STATUS_INVALID_PARAMETER1;
}


STATUS
GetFileFromUmHandle(
	IN		UM_HANDLE			Handle,
	IN		PPROCESS			CurrentProcess,
	OUT		PFILE_OBJECT*		FileFromHandle
)
{
    INTR_STATE dummyState;

    LockAcquire(&CurrentProcess->FileHandleListLock, &dummyState);
    DWORD size = ListSize(&CurrentProcess->FileHandleList);

    if (size > 0) {
        for (PLIST_ENTRY currentEntry = (&CurrentProcess->FileHandleList)->Flink; currentEntry != (&CurrentProcess->FileHandleList); currentEntry = currentEntry->Flink)
        {
            PUM_HANDLE_DATA currentHandle = CONTAINING_RECORD(currentEntry, UM_HANDLE_DATA, listResource);

            if (currentHandle->Handle == Handle)
            {
                *FileFromHandle = currentHandle->pResource;
                LockRelease(&CurrentProcess->FileHandleListLock, dummyState);
                return STATUS_SUCCESS;
            }
        }
    }
    LockRelease(&CurrentProcess->FileHandleListLock, dummyState);
    return STATUS_INVALID_PARAMETER1;
}


STATUS
ProcessCloseUmHandle(
    IN		UM_HANDLE			Handle,
    IN		PPROCESS			CurrentProcess
)
{
    INTR_STATE dummyState,dummyStateProcess,dummyStateFile;
    PPROCESS pProcess = NULL;

    LockAcquire(&CurrentProcess->ProcessHandleListLock, &dummyState);
    DWORD size = ListSize(&CurrentProcess->ProcessHandleList);
    if (size > 0) {
        for (PLIST_ENTRY currentEntry = (&CurrentProcess->ProcessHandleList)->Flink; currentEntry != (&CurrentProcess->ProcessHandleList); currentEntry = currentEntry->Flink)
        {
            PUM_HANDLE_DATA currentHandle = CONTAINING_RECORD(currentEntry, UM_HANDLE_DATA, listResource);

            if (currentHandle->Handle == Handle)
            {
                RemoveEntryList(&currentHandle->listResource);
                pProcess = currentHandle->pResource;

                LockAcquire(&pProcess->ProcessHandleListLock, &dummyStateProcess);
                for (PLIST_ENTRY c = (&pProcess->ProcessHandleList)->Flink; c != (&pProcess->ProcessHandleList); c = c->Flink)
                {
                    PUM_HANDLE_DATA h = CONTAINING_RECORD(c, UM_HANDLE_DATA, listResource);
                    RemoveEntryList(&h->listResource);

                    LockRelease(&pProcess->ProcessHandleListLock, dummyStateProcess);

                    ProcessCloseHandle(h->pResource);
                    ExFreePoolWithTag(h, HEAP_TEMP_TAG);

                    LockAcquire(&pProcess->ProcessHandleListLock, &dummyStateProcess);
                }
                LockRelease(&pProcess->ProcessHandleListLock, dummyStateProcess);

                LockAcquire(&pProcess->FileHandleListLock, &dummyStateFile);
                for (PLIST_ENTRY c = (&pProcess->FileHandleList)->Flink; c != (&pProcess->FileHandleList); c = c->Flink)
                {
                    PUM_HANDLE_DATA h = CONTAINING_RECORD(c, UM_HANDLE_DATA, listResource);
                    RemoveEntryList(&h->listResource);

                    LockRelease(&pProcess->FileHandleListLock, dummyStateFile);

                    IoCloseFile(h->pResource);
                    ExFreePoolWithTag(h, HEAP_TEMP_TAG);

                    LockAcquire(&pProcess->FileHandleListLock, &dummyStateFile);
                }
                LockRelease(&pProcess->FileHandleListLock, dummyStateFile);

                MutexAcquire(&pProcess->ThreadHandlesListLock);
                for (PLIST_ENTRY c = (&pProcess->ThreadHandlesList)->Flink; c != (&pProcess->ThreadHandlesList); c = c->Flink)
                {
                    PUM_HANDLE_DATA h = CONTAINING_RECORD(c, UM_HANDLE_DATA, listResource);
                    RemoveEntryList(&h->listResource);

                    MutexRelease(&pProcess->ThreadHandlesListLock);
                    ThreadCloseHandle(h->pResource);
                    ExFreePoolWithTag(h, HEAP_TEMP_TAG);

                    MutexAcquire(&pProcess->ThreadHandlesListLock);
                }
                MutexRelease(&pProcess->ThreadHandlesListLock);

                LockRelease(&CurrentProcess->ProcessHandleListLock, dummyState);

                ProcessCloseHandle(currentHandle->pResource);
                ExFreePoolWithTag(currentHandle, HEAP_TEMP_TAG);
                return STATUS_SUCCESS;
            }
        }
    }
    LockRelease(&CurrentProcess->ProcessHandleListLock, dummyState);

    return STATUS_INVALID_PARAMETER1;
}

STATUS
FileCloseUmHandle(
    IN		UM_HANDLE			Handle,
    IN		PPROCESS			CurrentProcess
)
{
    INTR_STATE dummyState;

    LockAcquire(&CurrentProcess->FileHandleListLock, &dummyState);
    DWORD size = ListSize(&CurrentProcess->FileHandleList);
    if (size > 0) {
        for (DWORD i = 0; i < size; i = i + 1)
        {
            PLIST_ENTRY currentEntry = GetListElemByIndex(&CurrentProcess->FileHandleList, i);

            PUM_HANDLE_DATA currentHandle = CONTAINING_RECORD(currentEntry, UM_HANDLE_DATA, listResource);

            if (currentHandle->Handle == Handle)
            {
                RemoveEntryList(&currentHandle->listResource);
                LockRelease(&CurrentProcess->FileHandleListLock, dummyState);

                IoCloseFile(currentHandle->pResource);
                ExFreePoolWithTag(currentHandle, HEAP_TEMP_TAG);
                return STATUS_SUCCESS;
            }
        }
    }
    LockRelease(&CurrentProcess->FileHandleListLock, dummyState);

    return STATUS_INVALID_PARAMETER1;
}


static
__forceinline
BOOLEAN
_ValidateListEntry(
    IN  PLIST_ENTRY Entry
)
{
    // check that the backward element points to this entry
    if (Entry->Flink->Blink != Entry)
    {
        return FALSE;
    }

    // check that the forward element points to this entry
    if (Entry->Blink->Flink != Entry)
    {
        return FALSE;
    }

    return TRUE;
}

/*
STATUS
GetThreadFromUmHandle(
    IN		UM_HANDLE			Handle,
    IN      BOOLEAN             WaitForTermination,
    IN      BOOLEAN             CloseHandle,
    OUT		PTHREAD*		        ThreadFromHandle,
    OUT     STATUS* TerminationStatus
) {
    PPROCESS pProcess = GetCurrentProcess();
    DWORD size = ListSize(&pProcess->ThreadHandlesList);
    MutexAcquire(&pProcess->ThreadHandlesListLock);
    for (DWORD i = 0; i < size; i = i + 1) {
        PLIST_ENTRY currentEntry = GetListElemByIndex(&pProcess->ThreadHandlesList, i);
        PUM_HANDLE_DATA pCurrentHandle = CONTAINING_RECORD(currentEntry, UM_HANDLE_DATA, listResource);
        if (Handle == pCurrentHandle->Handle) {
            *ThreadFromHandle = pCurrentHandle->pResource;
            if (CloseHandle) {
                RemoveEntryList(&pCurrentHandle->listResource);
                ThreadCloseHandle((PTHREAD)pCurrentHandle->pResource);
                ExFreePoolWithTag(pCurrentHandle, HEAP_TEMP_TAG);
            }
            if (WaitForTermination) {
                ThreadWaitForTermination((PTHREAD)pCurrentHandle->pResource, TerminationStatus);
            }
            MutexRelease(&pProcess->ThreadHandlesListLock);
            return STATUS_SUCCESS;
        }
    }
    MutexRelease(&pProcess->ThreadHandlesListLock);
    return STATUS_ELEMENT_NOT_FOUND;
}
*/

static
STATUS
(__cdecl _IterateThreadHandleList)(
    IN       PLIST_ENTRY     ListEntry,
    IN_OPT   PVOID           Context
    ) {

    ASSERT(Context != NULL);
    ASSERT(NULL != ListEntry);

    PUM_HANDLE_DATA pCurrentHandle = CONTAINING_RECORD(ListEntry, UM_HANDLE_DATA, listResource);

    UM_HANDLE_DATA* pHandle = Context;

    if (pHandle[0].Handle == pCurrentHandle->Handle) {
        pHandle[1].pResource = (PVOID)((PTHREAD)pCurrentHandle->pResource);
        pHandle[2].pResource = &pCurrentHandle->listResource;
    }

    return STATUS_SUCCESS;
}


STATUS
GetThreadFromUmHandle(
    IN		UM_HANDLE			Handle,
    IN      BOOLEAN             DeleteHandleFromList,
    OUT		PTHREAD* ThreadFromHandle
) {

    UM_HANDLE_DATA* handles = ExAllocatePoolWithTag(
        PoolAllocateZeroMemory,
        3 * sizeof(UM_HANDLE_DATA),
        HEAP_TEMP_TAG,
        0
    );

    handles[0].Handle = Handle;
    handles[1].pResource = NULL;
    handles[2].pResource = NULL;
    PPROCESS pProcess = GetCurrentProcess();

    MutexAcquire(&pProcess->ThreadHandlesListLock);
    STATUS status = ForEachElementExecute(&pProcess->ThreadHandlesList,
        _IterateThreadHandleList,
        handles,
        FALSE
    );
    MutexRelease(&pProcess->ThreadHandlesListLock);

    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("_IterateThreadHandleList", status);
    }

    if (handles[1].pResource != NULL) {
        *ThreadFromHandle = (PTHREAD)handles[1].pResource;
        PLIST_ENTRY ResourceListElem = (PLIST_ENTRY)handles[2].pResource;
        if (DeleteHandleFromList) {
            MutexAcquire(&pProcess->ThreadHandlesListLock);
            RemoveEntryList(ResourceListElem);
            MutexRelease(&pProcess->ThreadHandlesListLock);

            PUM_HANDLE_DATA handleToDelete = CONTAINING_RECORD(ResourceListElem, UM_HANDLE_DATA, listResource);
            ExFreePoolWithTag(handleToDelete, HEAP_TEMP_TAG);
        }

        ExFreePoolWithTag(handles, HEAP_TEMP_TAG);
        return STATUS_SUCCESS;
    }

    ExFreePoolWithTag(handles, HEAP_TEMP_TAG);
    return STATUS_ELEMENT_NOT_FOUND;
}