// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements DdiMon functions.

#include "ddi_mon.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
//#include <Ntddk.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#undef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#include <array>
#include <vector>
#include <string>
#include "shadow_hook.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// A helper type for parsing a PoolTag value
union PoolTag {
  ULONG value;
  UCHAR chars[4];
};

// A callback type for EnumExportedSymbols()
using EnumExportedSymbolsCallbackType = bool (*)(
    ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
    ULONG_PTR directory_base, ULONG_PTR directory_end, void* context);
using EnumRegeditSymbolsCallbackType = bool(*)(
	ULONG index, ULONG_PTR export_address, std::wstring FunName, void*context);

// For SystemProcessInformation
enum SystemInformationClass {
  kSystemProcessInformation = 5,
};


// For NtQuerySystemInformation
struct SystemProcessInformation {
  ULONG next_entry_offset;
  ULONG number_of_threads;
  LARGE_INTEGER working_set_private_size;
  ULONG hard_fault_count;
  ULONG number_of_threads_high_watermark;
  ULONG64 cycle_time;
  LARGE_INTEGER create_time;
  LARGE_INTEGER user_time;
  LARGE_INTEGER kernel_time;
  UNICODE_STRING image_name;
  // omitted. see ole32!_SYSTEM_PROCESS_INFORMATION
};


////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//
struct Protection {
	std::wstring wcProcessName;
	//std::string cProcessName;
	unsigned long dwProcessId;
};


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,                 //  0 Y N     
	SystemProcessorInformation,             //  1 Y N     
	SystemPerformanceInformation,           //  2 Y N     
	SystemTimeOfDayInformation,             //  3 Y N     
	SystemNotImplemented1,                  //  4 Y N     
	SystemProcessesAndThreadsInformation,   //  5 Y N     
	SystemCallCounts,                       //  6 Y N     
	SystemConfigurationInformation,         //  7 Y N     
	SystemProcessorTimes,                   //  8 Y N     
	SystemGlobalFlag,                       //  9 Y Y     
	SystemNotImplemented2,                  // 10 Y N     
	SystemModuleInformation,                // 11 Y N     
	SystemLockInformation,                  // 12 Y N     
	SystemNotImplemented3,                  // 13 Y N     
	SystemNotImplemented4,                  // 14 Y N     
	SystemNotImplemented5,                  // 15 Y N     
	SystemHandleInformation,                // 16 Y N     
	SystemObjectInformation,                // 17 Y N     
	SystemPagefileInformation,              // 18 Y N     
	SystemInstructionEmulationCounts,       // 19 Y N     
	SystemInvalidInfoClass1,                // 20     
	SystemCacheInformation,                 // 21 Y Y     
	SystemPoolTagInformation,               // 22 Y N     
	SystemProcessorStatistics,              // 23 Y N     
	SystemDpcInformation,                   // 24 Y Y     
	SystemNotImplemented6,                  // 25 Y N     
	SystemLoadImage,                        // 26 N Y     
	SystemUnloadImage,                      // 27 N Y     
	SystemTimeAdjustment,                   // 28 Y Y     
	SystemNotImplemented7,                  // 29 Y N     
	SystemNotImplemented8,                  // 30 Y N     
	SystemNotImplemented9,                  // 31 Y N     
	SystemCrashDumpInformation,             // 32 Y N     
	SystemExceptionInformation,             // 33 Y N     
	SystemCrashDumpStateInformation,        // 34 Y Y/N     
	SystemKernelDebuggerInformation,        // 35 Y N     
	SystemContextSwitchInformation,         // 36 Y N     
	SystemRegistryQuotaInformation,         // 37 Y Y     
	SystemLoadAndCallImage,                 // 38 N Y     
	SystemPrioritySeparation,               // 39 N Y     
	SystemNotImplemented10,                 // 40 Y N     
	SystemNotImplemented11,                 // 41 Y N     
	SystemInvalidInfoClass2,                // 42     
	SystemInvalidInfoClass3,                // 43     
	SystemTimeZoneInformation,              // 44 Y N     
	SystemLookasideInformation,             // 45 Y N     
	SystemSetTimeSlipEvent,                 // 46 N Y     
	SystemCreateSession,                    // 47 N Y     
	SystemDeleteSession,                    // 48 N Y     
	SystemInvalidInfoClass4,                // 49     
	SystemRangeStartInformation,            // 50 Y N     
	SystemVerifierInformation,              // 51 Y Y     
	SystemAddVerifier,                      // 52 N Y     
	SystemSessionProcessesInformation       // 53 Y N     
} SYSTEM_INFORMATION_CLASS;


typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
//专为WoW64准备;
typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	unsigned char  Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID SubSystemData;
} PEB, *PPEB;

extern "C" {
	NTKERNELAPI PEB *NTAPI PsGetProcessPeb(_In_ PEPROCESS process);
	NTKERNELAPI UCHAR *NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);
	NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		_In_       SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Inout_    PVOID SystemInformation,
		_In_       ULONG SystemInformationLength,
		_Out_opt_  PULONG ReturnLength
	);
}


_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    static void DdimonpFreeAllocatedTrampolineRegions();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C static NTSTATUS
    DdimonpEnumExportedSymbols(_In_ ULONG_PTR base_address,
                               _In_ EnumExportedSymbolsCallbackType callback,
                               _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    static bool DdimonpEnumExportedSymbolsCallback(
        _In_ ULONG index, _In_ ULONG_PTR base_address,
        _In_ PIMAGE_EXPORT_DIRECTORY directory, _In_ ULONG_PTR directory_base,
        _In_ ULONG_PTR directory_end, _In_opt_ void* context);

_Use_decl_annotations_ EXTERN_C 
static NTSTATUS DdimonpEnumRegeditSymbols(
	EnumRegeditSymbolsCallbackType callback, void * context);

_Use_decl_annotations_ EXTERN_C 
static bool DdimonpEnumRegeditSymbolsCallback(
	ULONG index, ULONG_PTR export_address, std::wstring FunName, void * context);

static std::array<char, 5> DdimonpTagToString(_In_ ULONG tag_value);

template <typename T>
static T DdimonpFindOrignal(_In_ T handler);

static VOID DdimonpHandleExQueueWorkItem(_Inout_ PWORK_QUEUE_ITEM work_item,
                                         _In_ WORK_QUEUE_TYPE queue_type);

static PVOID DdimonpHandleExAllocatePoolWithTag(_In_ POOL_TYPE pool_type,
                                                _In_ SIZE_T number_of_bytes,
                                                _In_ ULONG tag);

static VOID DdimonpHandleExFreePool(_Pre_notnull_ PVOID p);

static VOID DdimonpHandleExFreePoolWithTag(_Pre_notnull_ PVOID p,
                                           _In_ ULONG tag);

static NTSTATUS DdimonpHandleNtQuerySystemInformation(
    _In_ SystemInformationClass SystemInformationClass,
    _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);
static NTSTATUS DdimonpHandleNtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DdimonInitialization)
#pragma alloc_text(INIT, DdimonpEnumExportedSymbols)
#pragma alloc_text(INIT, DdimonpEnumExportedSymbolsCallback)
#pragma alloc_text(PAGE, DdimonTermination)
#pragma alloc_text(PAGE, DdimonpFreeAllocatedTrampolineRegions)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// Defines where to install shadow hooks and their handlers
//
// Because of simplified implementation of DdiMon, DdiMon is unable to handle any
// of following exports properly:
//  - already unmapped exports (eg, ones on the INIT section) because it no
//    longer exists on memory
//  - exported data because setting 0xcc does not make any sense in this case
//  - functions does not comply x64 calling conventions, for example Zw*
//    functions. Because contents of stack do not hold expected values leading
//    handlers to failure of parameter analysis that may result in bug check.
//
// Also the following care should be taken:
//  - Function parameters may be an user-address space pointer and not
//    trusted. Even a kernel-address space pointer should not be trusted for
//    production level security. Verity and capture all contents from user
//    supplied address to VMM, then use them.
static ShadowHookTarget g_ddimonp_hook_targets[] = {
    {
        RTL_CONSTANT_STRING(L"EXQUEUEWORKITEM"), DdimonpHandleExQueueWorkItem,
        nullptr,
    },
	{
        RTL_CONSTANT_STRING(L"EXALLOCATEPOOLWITHTAG"),
        DdimonpHandleExAllocatePoolWithTag, nullptr,
    },
    {
        RTL_CONSTANT_STRING(L"EXFREEPOOL"), DdimonpHandleExFreePool, nullptr,
    },
	{
        RTL_CONSTANT_STRING(L"EXFREEPOOLWITHTAG"),
        DdimonpHandleExFreePoolWithTag, nullptr,
    },
	{
        RTL_CONSTANT_STRING(L"NTQUERYSYSTEMINFORMATION"),
        DdimonpHandleNtQuerySystemInformation, nullptr,
    },
	{
		RTL_CONSTANT_STRING(L"NTOPENPROCESS"),
		DdimonpHandleNtOpenProcess, nullptr,
	},
};
//NtOpenProcess
////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

//进程隐藏名单
std::vector<Protection> ProcessHideList;
//进程保护名单
std::vector<Protection> lProtectionList;

bool DdimonpAddHide(TRY_SOKE &soke)
{
	UNICODE_STRING ucStrFile;
	//ANSI_STRING cStrFile;
	Protection pin;
	RtlInitUnicodeString(&ucStrFile, soke.ProcessName);
	//if (RtlUnicodeStringToAnsiString(&cStrFile, &ucStrFile, TRUE) != STATUS_SUCCESS)
	//	return false;
	pin.wcProcessName = soke.ProcessName;
	//pin.cProcessName = cStrFile.Buffer;
	pin.dwProcessId = soke.ProcessId;
	ProcessHideList.push_back(pin);
	HYPERPLATFORM_LOG_INFO("ProcessHideListAdd %ws\n", soke.ProcessName);
	return true;
}

bool DdimonpResetHide()
{
	ProcessHideList.clear();
	HYPERPLATFORM_LOG_INFO("ProcessHideList.clear");
	return true;
}

bool DdimonpAddProtection(TRY_SOKE &soke)
{
	UNICODE_STRING ucStrFile;
	//ANSI_STRING cStrFile;
	Protection pin;
	RtlInitUnicodeString(&ucStrFile, soke.ProcessName);
	//if (RtlUnicodeStringToAnsiString(&cStrFile, &ucStrFile, TRUE) != STATUS_SUCCESS)
	//	return false;
	pin.wcProcessName = soke.ProcessName;
	//pin.cProcessName = cStrFile.Buffer;
	pin.dwProcessId = soke.ProcessId;
	lProtectionList.push_back(pin);
	HYPERPLATFORM_LOG_INFO("lProtectionListAdd %ws\n", soke.ProcessName);
	return true;
}

bool DdimonpResetProtection()
{
	lProtectionList.clear();
	HYPERPLATFORM_LOG_INFO("lProtectionList.clear");
	return true;
}

_Use_decl_annotations_ bool DdiDispatch(IN PIRP pIrp)
{
	auto stack = IoGetCurrentIrpStackLocation(pIrp);
	auto BufferLenth = stack->Parameters.DeviceIoControl.InputBufferLength;
	auto uIoControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	auto IrpBuffer = (unsigned char*)pIrp->AssociatedIrp.SystemBuffer;
	char MemBuff[1024] = { 0 };
	unsigned long uPass = FALSE;
	PUCHAR Buffer = 0;
	TRY_SOKE * pSoke = 0;
	PEPROCESS EProcess = NULL;
	__try {
		if (IOCTL_MPROTECT_ADD_PROTECTION_HIDE == uIoControlCode) {
			HYPERPLATFORM_LOG_INFO("IOCTL_MPROTECT_ADD_PROTECTION_HIDE\n");
			if (BufferLenth < sizeof(TRY_SOKE)) {
				pIrp->IoStatus.Status = STATUS_SUCCESS;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return false;
			}
			Buffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
			pSoke = (TRY_SOKE*)Buffer;
			
			DdimonpAddHide(*pSoke);
			
			pSoke = nullptr;
			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = sizeof(ULONG);
			RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &uPass, sizeof(ULONG));

			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return true;
		}
		else if (IOCTL_MPROTECT_RESET_PROCESS_HIDE == uIoControlCode) {

			HYPERPLATFORM_LOG_INFO("IOCTL_MPROTECT_RESET_PROCESS_HIDE\n");
			DdimonpResetHide();

			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = sizeof(ULONG);
			RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &uPass, sizeof(ULONG));

			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return true;
		}
		else if (IOCTL_MPROTECT_ADD_PROCESS_POTECT == uIoControlCode) {
			HYPERPLATFORM_LOG_INFO("IOCTL_MPROTECT_ADD_PROCESS_POTECT\n");
			if (BufferLenth < sizeof(TRY_SOKE)) {
				pIrp->IoStatus.Status = STATUS_SUCCESS;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return false;
			}
			Buffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
			pSoke = (TRY_SOKE*)Buffer;

			DdimonpAddProtection(*pSoke);

			pSoke = nullptr;
			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = sizeof(ULONG);
			RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &uPass, sizeof(ULONG));

			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return true;
		}
		else if (IOCTL_MPROTECT_RESET_PROCESS_POTECT == uIoControlCode) {

			HYPERPLATFORM_LOG_INFO("IOCTL_MPROTECT_RESET_PROCESS_POTECT\n");
			DdimonpResetProtection();

			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = sizeof(ULONG);
			RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &uPass, sizeof(ULONG));

			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return true;
		}
	}
	__except (1) {

	}

	return false;
}
// Initializes DdiMon
_Use_decl_annotations_ EXTERN_C NTSTATUS
DdimonInitialization(SharedShadowHookData* shared_sh_data) {
  // Get a base address of ntoskrnl
  auto nt_base = UtilPcToFileHeader(KdDebuggerEnabled);
  if (!nt_base) {
    return STATUS_UNSUCCESSFUL;
  }

  // Install hooks by enumerating exports of ntoskrnl, but not activate them yet
  auto status = DdimonpEnumExportedSymbols(reinterpret_cast<ULONG_PTR>(nt_base),
                                           DdimonpEnumExportedSymbolsCallback,
                                           shared_sh_data);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = DdimonpEnumRegeditSymbols(DdimonpEnumRegeditSymbolsCallback, shared_sh_data);
  if (!NT_SUCCESS(status)) {
	  return status;
  }

  // Activate installed hooks
  status = ShEnableHooks();
  if (!NT_SUCCESS(status)) {
    DdimonpFreeAllocatedTrampolineRegions();
    return status;
  }

  HYPERPLATFORM_LOG_INFO("DdiMon has been initialized.");
  return status;
}

// Terminates DdiMon
_Use_decl_annotations_ EXTERN_C void DdimonTermination() {
  PAGED_CODE();

  ShDisableHooks();
  UtilSleep(1000);
  DdimonpFreeAllocatedTrampolineRegions();
  HYPERPLATFORM_LOG_INFO("DdiMon has been terminated.");
}

// Frees trampoline code allocated and stored in g_ddimonp_hook_targets by
// DdimonpEnumExportedSymbolsCallback()
_Use_decl_annotations_ EXTERN_C static void
DdimonpFreeAllocatedTrampolineRegions() {
  PAGED_CODE();

  for (auto& target : g_ddimonp_hook_targets) {
    if (target.original_call) {
      ExFreePoolWithTag(target.original_call, kHyperPlatformCommonPoolTag);
      target.original_call = nullptr;
    }
  }
}

// Enumerates all exports in a module specified by base_address.
_Use_decl_annotations_ EXTERN_C static NTSTATUS DdimonpEnumExportedSymbols(
    ULONG_PTR base_address, EnumExportedSymbolsCallbackType callback,
    void* context) {
  PAGED_CODE();

  auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
  auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
  auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(
      &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
  if (!dir->Size || !dir->VirtualAddress) {
    return STATUS_SUCCESS;
  }

  auto dir_base = base_address + dir->VirtualAddress;
  auto dir_end = base_address + dir->VirtualAddress + dir->Size - 1;
  auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address +
                                                           dir->VirtualAddress);
  for (auto i = 0ul; i < exp_dir->NumberOfNames; i++) {
    if (!callback(i, base_address, exp_dir, dir_base, dir_end, context)) {
      return STATUS_SUCCESS;
    }
  }
  return STATUS_SUCCESS;
}

// Checks if the export is listed as a hook target, and if so install a hook.
_Use_decl_annotations_ EXTERN_C static bool DdimonpEnumExportedSymbolsCallback(
    ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
    ULONG_PTR directory_base, ULONG_PTR directory_end, void* context) {
  PAGED_CODE();

  if (!context) {
    return false;
  }

  auto functions =
      reinterpret_cast<ULONG*>(base_address + directory->AddressOfFunctions);
  auto ordinals = reinterpret_cast<USHORT*>(base_address +
                                            directory->AddressOfNameOrdinals);
  auto names =
      reinterpret_cast<ULONG*>(base_address + directory->AddressOfNames);

  auto ord = ordinals[index];
  auto export_address = base_address + functions[ord];
  auto export_name = reinterpret_cast<const char*>(base_address + names[index]);

  // Check if an export is forwarded one? If so, ignore it.
  if (UtilIsInBounds(export_address, directory_base, directory_end)) {
    return true;
  }

  // convert the name to UNICODE_STRING
  wchar_t name[100];
  auto status =
      RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"%S", export_name);
  if (!NT_SUCCESS(status)) {
    return true;
  }

  //HYPERPLATFORM_LOG_INFO("def api at %d %x %s.", index, export_address, export_name);

  UNICODE_STRING name_u = {};
  RtlInitUnicodeString(&name_u, name);

  for (auto& target : g_ddimonp_hook_targets) {
    // Is this export listed as a target
    if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr)) {
      continue;
    }

    // Yes, install a hook to the export
    if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context),
                       reinterpret_cast<void*>(export_address), &target)) {
      // This is an error which should not happen
      DdimonpFreeAllocatedTrampolineRegions();
      return false;
    }
    HYPERPLATFORM_LOG_INFO("Hook has been installed at %p %s.", export_address,
                           export_name);
  }
  return true;
}


_Use_decl_annotations_ EXTERN_C static NTSTATUS DdimonpEnumRegeditSymbols(
	EnumRegeditSymbolsCallbackType callback,void * context) {
	PAGED_CODE();
	ULONG ulSize = 0;
	HANDLE key_handle;
	HANDLE key_handle2;
	OBJECT_ATTRIBUTES obj_attrib;
	UNICODE_STRING reg_path;
	UNICODE_STRING ustrKeyName;
	UNICODE_STRING ValueName;

	RtlInitUnicodeString(&ValueName, L"FunAdder");
	RtlInitUnicodeString(&reg_path, L"\\Registery\\Machine\\SYSTEM\\CurrentControlSet\\Services\\MProtect\\ShadowSSDT");
	InitializeObjectAttributes(&obj_attrib, &reg_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
	auto status = ZwOpenKey(&key_handle, KEY_READ, &obj_attrib);
	if (!NT_SUCCESS(status)){
		return STATUS_SUCCESS;
	}

	status = ZwQueryKey(key_handle, KeyFullInformation, NULL, 0, &ulSize);
	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	auto pfi = (PKEY_FULL_INFORMATION)ExAllocatePool(PagedPool, ulSize);
	status = ZwQueryKey(key_handle, KeyFullInformation, pfi, ulSize, &ulSize);
	if (!NT_SUCCESS(status)) {
		ExFreePool(pfi);
		return STATUS_SUCCESS;
	}

	for (int i = 0; i < pfi->SubKeys; i++){
		status = ZwEnumerateKey(key_handle, i, KeyBasicInformation, NULL, 0, &ulSize);
		if (!NT_SUCCESS(status)) {
			continue;
		}

		auto pbi = (PKEY_BASIC_INFORMATION)ExAllocatePool(PagedPool, ulSize);
		status = ZwEnumerateKey(key_handle, i, KeyBasicInformation, pbi, ulSize, &ulSize);
		if (!NT_SUCCESS(status)) {
			ExFreePool(pbi);
			continue;
		}
		std::wstring KeyName = pbi->Name;
		std::wstring KeyPatn = reg_path.Buffer;
		KeyPatn = KeyPatn + L"\\" + KeyName;
		ustrKeyName.Length = KeyPatn.length();
		ustrKeyName.Buffer = (wchar_t *)KeyPatn.c_str();

		InitializeObjectAttributes(&obj_attrib, &ustrKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = ZwOpenKey(&key_handle2, KEY_READ, &obj_attrib);
		if (!NT_SUCCESS(status)) {
			ExFreePool(pbi);
			continue;
		}
		status = ZwQueryValueKey(key_handle2, &ValueName, KeyValuePartialInformation, NULL, 0, &ulSize);
		if (!NT_SUCCESS(status)) {
			ExFreePool(pbi);
			continue;
		}
		auto pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(PagedPool, ulSize);
		status = ZwQueryValueKey(key_handle2, &ValueName, KeyValuePartialInformation, pvpi, ulSize, &ulSize);
		if (!NT_SUCCESS(status)) {
			ExFreePool(pvpi);
			ExFreePool(pbi);
			continue;
		}
		if (pvpi->Type != REG_QWORD){
			ExFreePool(pvpi);
			ExFreePool(pbi);
			continue;
		}

		callback(i, (ULONGLONG)pvpi->Data, KeyName, context);
		ZwClose(key_handle2);
		ExFreePool(pvpi);
		ExFreePool(pbi);
	}
	ExFreePool(pfi);
	ZwClose(key_handle);
	return STATUS_SUCCESS;
}


_Use_decl_annotations_ EXTERN_C static bool DdimonpEnumRegeditSymbolsCallback(
	ULONG index, ULONG_PTR export_address, std::wstring FunName, void * context)
{
	if (!context) {
		return false;
	}

	UNICODE_STRING name_u = {};
	RtlInitUnicodeString(&name_u, FunName.c_str());

	for (auto& target : g_ddimonp_hook_targets) {
		// Is this export listed as a target
		if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr)) {
			continue;
		}

		// Yes, install a hook to the export
		if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context),
			reinterpret_cast<void*>(export_address), &target)) {
			// This is an error which should not happen
			DdimonpFreeAllocatedTrampolineRegions();
			return false;
		}
		HYPERPLATFORM_LOG_INFO("Hook has been installed at %p %ws.", export_address,
			name_u.Buffer);
	}
	return true;
}


// Converts a pool tag in integer to a printable string
_Use_decl_annotations_ static std::array<char, 5> DdimonpTagToString(
    ULONG tag_value) {
  PoolTag tag = {tag_value};
  for (auto& c : tag.chars) {
    if (!c && isspace(c)) {
      c = ' ';
    }
    if (!isprint(c)) {
      c = '.';
    }
  }

  std::array<char, 5> str;
  auto status =
      RtlStringCchPrintfA(str.data(), str.size(), "%c%c%c%c", tag.chars[0],
                          tag.chars[1], tag.chars[2], tag.chars[3]);
  NT_VERIFY(NT_SUCCESS(status));
  return str;
}

// Finds a handler to call an original function
template <typename T>
static T DdimonpFindOrignal(T handler) {
  for (const auto& target : g_ddimonp_hook_targets) {
    if (target.handler == handler) {
      NT_ASSERT(target.original_call);
      return reinterpret_cast<T>(target.original_call);
    }
  }
  NT_ASSERT(false);
  return nullptr;
}

// The hook handler for ExFreePool(). Logs if ExFreePool() is called from where
// not backed by any image
_Use_decl_annotations_ static VOID DdimonpHandleExFreePool(PVOID p) {
  const auto original = DdimonpFindOrignal(DdimonpHandleExFreePool);
  original(p);

  // Is inside image?
  auto return_addr = _ReturnAddress();
  if (UtilPcToFileHeader(return_addr)) {
    return;
  }

  HYPERPLATFORM_LOG_INFO_SAFE("%p: ExFreePool(P= %p)", return_addr, p);
}

// The hook handler for ExFreePoolWithTag(). Logs if ExFreePoolWithTag() is
// called from where not backed by any image.
_Use_decl_annotations_ static VOID DdimonpHandleExFreePoolWithTag(PVOID p,
                                                                  ULONG tag) {
  const auto original = DdimonpFindOrignal(DdimonpHandleExFreePoolWithTag);
  original(p, tag);

  // Is inside image?
  auto return_addr = _ReturnAddress();
  if (UtilPcToFileHeader(return_addr)) {
    return;
  }

  HYPERPLATFORM_LOG_INFO_SAFE("%p: ExFreePoolWithTag(P= %p, Tag= %s)",
                              return_addr, p, DdimonpTagToString(tag).data());
}

// The hook handler for ExQueueWorkItem(). Logs if a WorkerRoutine points to
// where not backed by any image.
_Use_decl_annotations_ static VOID DdimonpHandleExQueueWorkItem(
    PWORK_QUEUE_ITEM work_item, WORK_QUEUE_TYPE queue_type) {
  const auto original = DdimonpFindOrignal(DdimonpHandleExQueueWorkItem);

  // Is inside image?
  if (UtilPcToFileHeader(work_item->WorkerRoutine)) {
    // Call an original after checking parameters. It is common that a work
    // routine frees a work_item object resulting in wrong analysis.
    original(work_item, queue_type);
    return;
  }

  auto return_addr = _ReturnAddress();
  HYPERPLATFORM_LOG_INFO_SAFE(
      "%p: ExQueueWorkItem({Routine= %p, Parameter= %p}, %d)", return_addr,
      work_item->WorkerRoutine, work_item->Parameter, queue_type);

  original(work_item, queue_type);
}

// The hook handler for ExAllocatePoolWithTag(). Logs if ExAllocatePoolWithTag()
// is called from where not backed by any image.
_Use_decl_annotations_ static PVOID DdimonpHandleExAllocatePoolWithTag(
    POOL_TYPE pool_type, SIZE_T number_of_bytes, ULONG tag) {
  const auto original = DdimonpFindOrignal(DdimonpHandleExAllocatePoolWithTag);
  const auto result = original(pool_type, number_of_bytes, tag);

  // Is inside image?
  auto return_addr = _ReturnAddress();
  if (UtilPcToFileHeader(return_addr)) {
    return result;
  }

  HYPERPLATFORM_LOG_INFO_SAFE(
      "%p: ExAllocatePoolWithTag(POOL_TYPE= %08x, NumberOfBytes= %08X, Tag= "
      "%s) => %p",
      return_addr, pool_type, number_of_bytes, DdimonpTagToString(tag).data(),
      result);
  return result;
}

// The hook handler for NtQuerySystemInformation(). Removes an entry for cmd.exe
// and hides it from being listed.
_Use_decl_annotations_ static NTSTATUS DdimonpHandleNtQuerySystemInformation(
    SystemInformationClass system_information_class, PVOID system_information,
    ULONG system_information_length, PULONG return_length) {
  const auto original =
      DdimonpFindOrignal(DdimonpHandleNtQuerySystemInformation);
  const auto result = original(system_information_class, system_information,
                               system_information_length, return_length);
  if (!NT_SUCCESS(result)) {
    return result;
  }
  if (system_information_class != kSystemProcessInformation) {
    return result;
  }

  auto next = reinterpret_cast<SystemProcessInformation*>(system_information);
  while (next->next_entry_offset) {
    auto curr = next;
    next = reinterpret_cast<SystemProcessInformation*>(
        reinterpret_cast<UCHAR*>(curr) + curr->next_entry_offset);
	std::vector<Protection>::iterator it;
	for (it = ProcessHideList.begin(); it != ProcessHideList.end(); it++){
		if (_wcsnicmp(next->image_name.Buffer, it->wcProcessName.c_str(), next->image_name.Length) == 0) {
			if (next->next_entry_offset){
				curr->next_entry_offset += next->next_entry_offset;
			}
			else{
				curr->next_entry_offset = 0;
			}
			next = curr;
		}
	}
	/*if (_wcsnicmp(next->image_name.Buffer, L"cmd.exe", 7) == 0) {
		if (next->next_entry_offset) {
			curr->next_entry_offset += next->next_entry_offset;
		}
		else {
			curr->next_entry_offset = 0;
		}
		next = curr;
	}*/
  }
  return result;
}

_Use_decl_annotations_ static NTSTATUS DdimonpHandleNtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId) {
	const auto original =
		DdimonpFindOrignal(DdimonpHandleNtOpenProcess);
	const auto result = original(ProcessHandle,DesiredAccess,
		ObjectAttributes, ClientId);
	if (!NT_SUCCESS(result)) {
		return result;
	}

	PEPROCESS EProcess = nullptr;
	auto status = ObReferenceObjectByHandle(*ProcessHandle, FILE_READ_DATA, 0, KernelMode, (PVOID*)&EProcess, 0);


	auto * FileName = PsGetProcessImageFileName(EProcess);
	if (!FileName) {
		return result;
	}

	auto return_addr = _ReturnAddress();
	std::vector<Protection>::iterator it;
	UNICODE_STRING ucStrFile;
	ANSI_STRING cStrFile;

	for (it = lProtectionList.begin(); it != lProtectionList.end(); it++) {
		RtlInitUnicodeString(&ucStrFile, it->wcProcessName.c_str());

		if (RtlUnicodeStringToAnsiString(&cStrFile, &ucStrFile, TRUE) != STATUS_SUCCESS) {
			return false;
		}
		std::string cmp_str = cStrFile.Buffer;

		if (cmp_str.find((char*)FileName) != std::string::npos ||
			(HANDLE)it->dwProcessId == ClientId->UniqueProcess) {

			HYPERPLATFORM_LOG_INFO_SAFE("%p: NtOpenProcess(ProcessHandle= %d, DesiredAccess= %d,Pid= %d ,filename:%s)",
				return_addr, ProcessHandle, DesiredAccess, ClientId->UniqueProcess, FileName);

			ClientId->UniqueProcess = (HANDLE)-1;
			return STATUS_ACCESS_DENIED;
		}
	}

	if (!NT_SUCCESS(result)) {
		return result;
	}
	return result;

	return result;
}
