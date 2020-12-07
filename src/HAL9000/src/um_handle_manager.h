#pragma once
#include "HAL9000.h"
#include "syscall_defs.h"
#include "data_type.h"
#include "list.h"
#include "process_internal.h"
#include "process.h"
#include "filesystem.h"
#include "thread_internal.h"
#include "io.h"


typedef struct _UM_HANDLE_DATA {
	UM_HANDLE	Handle;

	//it could point to a process, file or thread
	PVOID		pResource;

	//elem in list of processes, files or threads handles
	LIST_ENTRY	listResource;
}UM_HANDLE_DATA, *PUM_HANDLE_DATA;


STATUS UmHandleInit(
	OUT	PUM_HANDLE_DATA	Handle
);

STATUS
GetProcessFromUmHandle(
	IN		UM_HANDLE		Handle,
	IN		PPROCESS		CurrentProcess,
	OUT		PPROCESS*		ProcessFromHandle
);

STATUS
GetFileFromUmHandle(
	IN		UM_HANDLE			Handle,
	IN		PPROCESS			CurrentProcess,
	OUT		PFILE_OBJECT*		FileFromHandle
);

STATUS
GetThreadFromUmHandle(
	IN		UM_HANDLE			Handle,
    IN      BOOLEAN             DeleteHandleFromList,
	OUT		PTHREAD*		    ThreadFromHandle
);

STATUS
FileCloseUmHandle(
	IN		UM_HANDLE			Handle,
	IN		PPROCESS			CurrentProcess
);

STATUS
ProcessCloseUmHandle(
	IN		UM_HANDLE			Handle,
	IN		PPROCESS			CurrentProcess
);

