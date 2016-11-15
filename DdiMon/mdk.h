#include <fltKernel.h>


#define __MprotectDevelopmentKit 

#define IOCTL_MPROTECT_MDK_OPENPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_MDK_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_MDK_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct _MDK_OPENPROCESS
{


}MDK_OPENPROCESS, *PMDK_OPENPROCESS;

typedef struct _MDK_READ_MEMORY
{
	ULONG uProcessId;
	ULONG uAddrBase;
	ULONG Length;
}MDK_READ_MEMORY, *PMDK_READ_MEMORY;

typedef struct _MDK_WRITE_MEMORY
{
	ULONG uProcessId;
	ULONG uAddrBase;
	char Value[512];
	ULONG Length;
}MDK_WRITE_MEMORY, *PMDK_WRITE_MEMORY;

typedef struct _MDK_READWRITE_RET
{
	char Value[1024];
	ULONG ValueLen;
	ULONG Error;
}MDK_READWRITE_RET, *PMDK_READWRITE_RET;

//__MprotectDevelopmentKit bool mdk_ReadProcessMemory(
//	IN PEPROCESS Process,
//	IN PVOID Address,
//	IN ULONG Length,
//	OUT PVOID Buffer);
//
//__MprotectDevelopmentKit bool mdk_WriteProcessMemory(
//	IN PEPROCESS Process,
//	IN PVOID Address,
//	IN PVOID Value,
//	IN ULONG Length);

//__MprotectDevelopmentKit bool mdk_OpenProcess(
//	IN PHANDLE ProcessHandle,
//	OUT PEPROCESS EProcess);

_Use_decl_annotations_ bool Mdk_Dispatch(
	IN ULONG IoControlCode, 
	IN PIRP pIrp, 
	IN PMDK_READWRITE_RET pRet);

enum MdkError
{
	OpenProcessFail = 1,
	ReadProcessFail = 2,
	WriteProcessFail = 4,
	Try = 8
};