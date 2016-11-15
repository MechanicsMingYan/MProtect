#include "mdk.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include <ntddk.h>
#include <ntifs.h>
#include <WinDef.h>
#include <intrin.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"


NTSTATUS
KernelVmRead(
	IN PEPROCESS Process,
	IN PVOID Address,
	IN ULONG Length,
	IN PVOID OutBuffer
)
{
	KAPC_STATE *ka_state = NULL;
	ka_state = new KAPC_STATE;
	KeStackAttachProcess(Process, ka_state);
	PMDL mdl;
	PVOID *pMappedMemory;

	mdl = MmCreateMdl(NULL, Address, Length);
	if (!mdl)
		return false;

	MmBuildMdlForNonPagedPool(mdl);
	mdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
	pMappedMemory = (PVOID*)MmMapLockedPages(mdl, KernelMode);

	if (!pMappedMemory) {
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(ka_state);
		return false;
	}

	RtlCopyMemory(OutBuffer, pMappedMemory, Length);

	MmUnmapLockedPages(pMappedMemory, mdl);
	IoFreeMdl(mdl);
	KeUnstackDetachProcess(ka_state);
	delete ka_state;
	return true;
}

NTSTATUS
KernelVmWrite(
	IN PEPROCESS Process,
	IN PVOID WriteAddress,
	IN PVOID InputBuffer,
	IN ULONG WriteLength
)
{
	KAPC_STATE *ka_state = NULL;
	ka_state = new KAPC_STATE;//ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC_STATE), 'trak');
	KeStackAttachProcess(Process, ka_state);
	PMDL mdl;
	PVOID *pMappedMemory;

	mdl = MmCreateMdl(NULL, WriteAddress, WriteLength);
	if (!mdl)
		return false;

	MmBuildMdlForNonPagedPool(mdl);
	mdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
	pMappedMemory = (PVOID*)MmMapLockedPages(mdl, KernelMode);

	if (!pMappedMemory){
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(ka_state);
		return false;
	}

	RtlCopyMemory(pMappedMemory, InputBuffer, WriteLength);

	MmUnmapLockedPages(pMappedMemory, mdl);
	IoFreeMdl(mdl);
	KeUnstackDetachProcess(ka_state);
	delete ka_state;
	return true;
}

__MprotectDevelopmentKit bool mdk_OpenProcess(
	IN PHANDLE ProcessHandle,
	OUT PEPROCESS *EProcess
)
{
	PEPROCESS pEProcess;

	auto nStatus = PsLookupProcessByProcessId(*ProcessHandle, &pEProcess);
	if (!NT_SUCCESS(nStatus)) {
		HYPERPLATFORM_LOG_INFO("mdk_OpenProcess(%d) Failed~!\n", *ProcessHandle);
		return false;
	}

	*EProcess = pEProcess;
	return true;
}


_Use_decl_annotations_ bool Mdk_Dispatch(IN ULONG IoControlCode, IN PIRP pIrp ,IN PMDK_READWRITE_RET pRet)
{
	auto stack = IoGetCurrentIrpStackLocation(pIrp);
	auto BufferLenth = stack->Parameters.DeviceIoControl.InputBufferLength;
	auto uIoControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	auto IrpBuffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
	MDK_READWRITE_RET ret = { 0 };
	char MemBuff[1024] = { 0 };
	PEPROCESS EProcess = NULL;
	__try {
		switch (IoControlCode)
		{

		case IOCTL_MPROTECT_MDK_OPENPROCESS:

			break;
		case IOCTL_MPROTECT_MDK_READ_MEMORY: {
			auto p = (PMDK_READ_MEMORY)pIrp->AssociatedIrp.SystemBuffer;

			do {

				if (!mdk_OpenProcess((PHANDLE)&p->uProcessId, &EProcess)) {
					ret.Error = MdkError::OpenProcessFail;
					break;
				}

				if (!KernelVmRead(EProcess, (PVOID)p->uAddrBase, p->Length, MemBuff)) {
					ret.Error = MdkError::ReadProcessFail;
					break;
				}
			} while (false);

			ret.ValueLen = p->Length;
			RtlCopyMemory(ret.Value, MemBuff, p->Length);
			RtlCopyMemory(pRet, &ret, sizeof(ret));
			return true;
		}
		case IOCTL_MPROTECT_MDK_WRITE_MEMORY: {
			auto p = (PMDK_WRITE_MEMORY)pIrp->AssociatedIrp.SystemBuffer;

			do {

				if (!mdk_OpenProcess((PHANDLE)&p->uProcessId, &EProcess)) {
					ret.Error = MdkError::OpenProcessFail;
					break;
				}

				if (!KernelVmWrite(EProcess, (PVOID)p->uAddrBase, (PVOID)p->Value, p->Length)) {
					ret.Error = MdkError::WriteProcessFail;
					break;
				}
			} while (false);

			ret.ValueLen = sizeof(ULONG);
			*(PULONG)ret.Value = true;
			
			return true;
		}

		}
	}
	__except (1) {
		ret.Error = MdkError::Try;
		ret.ValueLen = 0;
		RtlCopyMemory(pRet, &ret, sizeof(ret));

	}

	return false;
}