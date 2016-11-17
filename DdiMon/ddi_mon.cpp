// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements DdiMon functions.

#include "ddi_mon.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include <ntifs.h>
#include <WinDef.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <array>
#include <vector>
#include <string>
#include "shadow_hook.h"
#include "ksocket.h"
#include "../../DdiMon/VMProtectDDK.h"

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

//枚举导出符号的回调类型（）
using EnumExportedSymbolsCallbackType = bool (*)(
    ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
    ULONG_PTR directory_base, ULONG_PTR directory_end, void* context, BOOLEAN ssdt);
//枚举进程模块回调类型（）
using DdimonpEnumProcessModuleCallbackType = bool(*)(
	ULONG index, PVOID LdrDataEntry, BOOL Wow64);


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


typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

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
//专为WoW64准备;
typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG/*PPEB_LDR_DATA32*/ Ldr;
} PEB32, *PPEB32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
	PVOID ContextInformation;
	PVOID OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
//专为WoW64准备;
typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	ULONG LoadedImports;
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;
	ULONG ContextInformation;
	ULONG OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;


typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY {
	ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX，参见MSDN中UpdateProcThreadAttribute的说明
	SIZE_T Size;        // Value的大小
	ULONG_PTR Value;    // 保存4字节数据（比如一个Handle）或数据指针
	ULONG Unknown;      // 总是0，可能是用来返回数据给调用者
} PROC_THREAD_ATTRIBUTE_ENTRY, *PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST {
	ULONG Length;       // 结构总大小
	PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;

//保护表
struct Protection {
	std::wstring wcProcessName;
	std::string cProcessName;
	DWORD dwProcessId;
};

//模块黑名单
struct Module {
	std::wstring wcModuleName;
	std::string Info;
};

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
	SYSTEM_SERVICE_TABLE ntoskrnl;  // ntoskrnl.exe (native api)
	SYSTEM_SERVICE_TABLE win32k;    // win32k.sys   (gdi/user)
	SYSTEM_SERVICE_TABLE Table3;    // not used
	SYSTEM_SERVICE_TABLE Table4;    // not used
}SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	PULONG_PTR Base;	// 服务表地址
	PULONG Count;		// 服务表中服务被调用次数的计数器  
	ULONG Limit;			// 服务个数，即有多少个函数了 
	PUCHAR Number;		// 服务参数表  
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG    WaitTime;
	PVOID    StartAddress;
	CLIENT_ID   ClientID;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
	ULONG    ContextSwitchCount;
	ULONG    ThreadState;
	KWAIT_REASON  WaitReason;
	ULONG    Reserved; //Add  
}SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	VM_COUNTERS             VirtualMemoryCounters;
	IO_COUNTERS             IoCounters;
	SYSTEM_THREADS           Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


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

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

typedef PPEB32(__stdcall * pfn_PsGetProcessWow64Process) (PEPROCESS Process);
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
        _In_ ULONG_PTR directory_end, _In_opt_ void* context,BOOLEAN ssdt);

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
	_Out_    PHANDLE            ProcessHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_     POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID         ClientId
);
static NTSTATUS DdimonpHandleNtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG CreateProcessFlags,
	IN ULONG CreateThreadFlags,
	IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PVOID Parameter9,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
);
static NTSTATUS DdimonpHandleNtCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE InheritFromProcessHandle,
	IN BOOLEAN InheritHandles,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN HANDLE Unknown);



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

//定义在哪里安装影子钩子及其处理程序
//
//因为DdiMon的简化实现，DdiMon无法处理任何
//正确导出以下导出：
// - 已经未映射的导出（例如，INIT部分的导出），因为它没有
//存在于内存中
// - 导出数据，因为设置0xcc在这种情况下没有任何意义
// - 函数不符合x64调用约定，例如Zw *
// 功能。 因为堆栈的内容不能保持期望值领先
//处理程序失败的参数分析，可能导致错误检查。
//
//也应该注意以下几点：
// - 函数参数可以是用户地址空间指针，而不是
//信任。 甚至不应该信任一个内核地址空间指针
//生产级安全。 验证并捕获用户的所有内容
//提供给VMM的地址，然后使用它们。

#ifdef _WIN64
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable = NULL;
#else
extern "C"  PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;
#endif




static ShadowHookTarget g_ddimonp_hook_targets[] = {
	{
		RTL_CONSTANT_STRING(L"EXQUEUEWORKITEM"), DdimonpHandleExQueueWorkItem,
		nullptr, FALSE
	},
	{
		RTL_CONSTANT_STRING(L"EXALLOCATEPOOLWITHTAG"),
		DdimonpHandleExAllocatePoolWithTag, nullptr, FALSE
	},
	{
		RTL_CONSTANT_STRING(L"EXFREEPOOL"), DdimonpHandleExFreePool, nullptr, FALSE
	},
	{
		RTL_CONSTANT_STRING(L"EXFREEPOOLWITHTAG"),
		DdimonpHandleExFreePoolWithTag, nullptr, FALSE
	},
	{
		RTL_CONSTANT_STRING(L"NTQUERYSYSTEMINFORMATION"),
		DdimonpHandleNtQuerySystemInformation, nullptr, FALSE
	},
	{
		RTL_CONSTANT_STRING(L"NTOPENPROCESS"),
		DdimonpHandleNtOpenProcess, nullptr, FALSE
	},
	{
		RTL_CONSTANT_STRING(L"NTCREATEUSERPROCESS"),
		DdimonpHandleNtCreateUserProcess, nullptr, TRUE
	},
	{
		RTL_CONSTANT_STRING(L"NTCREATEPROCESSEX"),
		DdimonpHandleNtCreateProcessEx, nullptr, TRUE
	},
};

NOTIFY_HANDLE g_NotifyHandle;
TRY_SOKE g_uUserChoice;
//被保护名单
std::vector<Protection> lProtectionList = {
	{ L"notepad.exe","notepad.exe",0},
	/*{ L"控制端.vshost.exe","控制端.vshost.exe",0 },
	{ L"控制端.exe","控制端.exe",0 },
	{ L"lulujxjs.vshost.exe","lulujxjs.vshost.exe",0 },
	{ L"lulujxjs.exe","lulujxjs.exe",0 },
	{ L"devenv.exe","devenv.exe",0 },*/
};
std::vector<Module> lModuleList = {
	{ L"XueTr.exe", "内核查看工具"},
	{ L"PCHunter32.exe", "内核查看工具" },
	{ L"PCHunter64.exe", "内核查看工具" },
	{ L"SRSniffer.exe", "封包工具" },
	{ L"WpeSpy.dll", "封包工具" },
	{ L"psvince,1.dll", "PE工具" },
	{ L"libgcc_s_dw2-1.dll", "反编译工具" },
	{ L"ida.wll", "反编译工具" },
	{ L"dbgmsgcfg.dll", "驱动工具" },
	{ L"x32dbg.dll", "调试工具" },
	{ L"x64dbg.dll", "调试工具" },
	{ L"API_Break.dll", "调试工具" },
	{ L"OllyPath.dll", "调试工具" },
	{ L"StrongOD.dll", "调试工具" },
	{ L"allochook-x86_64.dll", "内存工具" },
	{ L"allochook-i386.dll", "内存工具" },
	{ L"krnln.fne", "开发工具" },
};

bool DdimonpAddProtection(TRY_SOKE &soke)
{
	UNICODE_STRING ucStrFile;
	ANSI_STRING cStrFile;
	Protection pin;
	RtlInitUnicodeString(&ucStrFile, soke.ProcessInfo);
	if (RtlUnicodeStringToAnsiString(&cStrFile, &ucStrFile, TRUE) != STATUS_SUCCESS)
		return false;
	pin.wcProcessName = soke.ProcessInfo;
	pin.cProcessName = cStrFile.Buffer;
	lProtectionList.push_back(pin);
	HYPERPLATFORM_LOG_INFO("DdimonpAddProtection %ws\n", soke.ProcessInfo);
	return true;
}

bool DdimonpResetProtection()
{
	lProtectionList.clear();
	HYPERPLATFORM_LOG_INFO("lProtectionList.clear");
	return true;
}

_Use_decl_annotations_ EXTERN_C static bool DdimonpEnumProcessModuleCallback(
	ULONG index, PVOID LdrDataEntry, BOOL Wow64) {
	PAGED_CODE();
	wchar_t *FunDllName = NULL;
	size_t NameLen = NULL;
	if (Wow64){
		auto Ldr = (PLDR_DATA_TABLE_ENTRY32)LdrDataEntry;
		FunDllName = (wchar_t *)Ldr->FullDllName.Buffer;
		NameLen = Ldr->FullDllName.Length;
		//HYPERPLATFORM_LOG_INFO("Wow64 %d %ws \n", index, FunDllName);
	}
	else {
		auto Ldr = (PLDR_DATA_TABLE_ENTRY)LdrDataEntry;
		FunDllName = (wchar_t *)Ldr->FullDllName.Buffer;
		NameLen = Ldr->FullDllName.Length;
		//HYPERPLATFORM_LOG_INFO("8086 %d %ws \n", index, FunDllName);
	}
	std::vector<Module>::iterator it;
	__try{
		for (it = lModuleList.begin(); it != lModuleList.end(); it++){
			if (_wcsnicmp(FunDllName, it->wcModuleName.c_str(), NameLen) == 0) {
				HYPERPLATFORM_LOG_INFO("Try %ws  dd:%ws\n", FunDllName, it->Info.c_str());
				return false;
			}
		}
	}
	__except (1){

	}
	return true;
}

_Use_decl_annotations_ NTSTATUS EmumProcessModules
(HANDLE ulProcessId , DdimonpEnumProcessModuleCallbackType back)
{
	PEPROCESS  pEProcess = NULL;
	KAPC_STATE KAPC = { 0 };
	static pfn_PsGetProcessWow64Process PsGetProcessWow64Process = NULL;

	auto nStatus = PsLookupProcessByProcessId((HANDLE)ulProcessId, &pEProcess);
	if (!NT_SUCCESS(nStatus)){
		HYPERPLATFORM_LOG_INFO("Get EProcess Failed~!\n");
		return STATUS_UNSUCCESSFUL;
	}

	auto pPEB = PsGetProcessPeb(pEProcess);
	if (pPEB == NULL){
		HYPERPLATFORM_LOG_INFO("Get pPEB Failed~!\n");
		return STATUS_UNSUCCESSFUL;
	}
	//附加到进程  
	KeStackAttachProcess(pEProcess, &KAPC);
	auto bIsAttached = TRUE;

	__try
	{
		auto pPebLdrData = pPEB->Ldr;
		auto pListEntryStart = pPebLdrData->InMemoryOrderModuleList.Flink;
		auto pListEntryEnd = pListEntryStart;
		int i = 0;
		do {
			//通过_LIST_ENTRY的Flink成员获取_LDR_DATA_TABLE_ENTRY结构    
			auto pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			//输出DLL全路径  
			if (!back(i, pLdrDataEntry, false)) {
				break;
			}
			pListEntryStart = pListEntryStart->Flink;
		} while (pListEntryStart != pListEntryEnd);
	}
	__except (1){
		HYPERPLATFORM_LOG_INFO("bt __except \n");
	}
	
#ifdef _WIN64
	if (!PsGetProcessWow64Process) {
		UNICODE_STRING uniFunctionName;
		RtlInitUnicodeString(&uniFunctionName, L"PsGetProcessWow64Process");
		PsGetProcessWow64Process = (pfn_PsGetProcessWow64Process)(SIZE_T)MmGetSystemRoutineAddress(&uniFunctionName);
	}
	__try
	{
		auto pPEB32 = PsGetProcessWow64Process(pEProcess);
		if (pPEB32){
			auto pListEntryStart32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)pPEB32->Ldr)->InMemoryOrderModuleList.Flink);
			auto pListEntryEnd32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)pPEB32->Ldr)->InMemoryOrderModuleList.Flink);
			int i = 0;
			do {
				auto pLdrDataEntry32 = (PLDR_DATA_TABLE_ENTRY32)CONTAINING_RECORD(pListEntryStart32, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);
				if (!back(i, pLdrDataEntry32, true)) {
					break;
				}
				pListEntryStart32 = (PLIST_ENTRY32)pListEntryStart32->Flink;
			} while (pListEntryStart32 != pListEntryEnd32);
		}
	}
	__except (1){
		HYPERPLATFORM_LOG_INFO("32bt __except \n");
	}
#endif // _WIN64

	if (bIsAttached != FALSE){
		KeUnstackDetachProcess(&KAPC);
	}

	if (pEProcess != NULL){
		ObDereferenceObject(pEProcess);
		pEProcess = NULL;
	}

	return STATUS_SUCCESS;
}

_Use_decl_annotations_ EXTERN_C NTSTATUS
ThreadProc()
{
	VMProtectBegin("Driver_Dispatch");

	NTSTATUS                                status;
	ULONG                                   retusize;
	UNICODE_STRING                          ZwFunName;
	PVOID                                   AllSize = 0;
	SYSTEM_PROCESS_INFORMATION*             ProcessInfo;
	RtlInitUnicodeString(&ZwFunName, L"ZwQuerySystemInformation");

	status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, 0, 0, &retusize);

	if (retusize == 0){
		HYPERPLATFORM_LOG_INFO("retu size is null");
		PsTerminateSystemThread(STATUS_SUCCESS);
		return STATUS_SUCCESS;
	}

	AllSize = ExAllocatePool(NonPagedPool, retusize);
	if (AllSize == 0){
		HYPERPLATFORM_LOG_INFO("AllSize size is null");
		PsTerminateSystemThread(STATUS_SUCCESS);
		return STATUS_SUCCESS;
	}

	status = ZwQuerySystemInformation(SystemProcessesAndThreadsInformation, AllSize, (ULONG)retusize, &retusize);

	if (!NT_SUCCESS(status)){
		HYPERPLATFORM_LOG_INFO("ZwQuerySystemInformation is faild!");
		ExFreePool(AllSize);
		return STATUS_SUCCESS;
	}

	ProcessInfo = (SYSTEM_PROCESS_INFORMATION*)AllSize;
	int i = 0;
	while (ProcessInfo->NextEntryOffset){
		HYPERPLATFORM_LOG_INFO("%d ProcessId:%d------ProcessName:%wZ",(i++,i), ProcessInfo->ProcessId, &ProcessInfo->ImageName);
		EmumProcessModules(ProcessInfo->ProcessId, DdimonpEnumProcessModuleCallback);
		ProcessInfo = (SYSTEM_PROCESS_INFORMATION*)((ULONGLONG)ProcessInfo + ProcessInfo->NextEntryOffset);
	}

	ExFreePool(AllSize);

	PsTerminateSystemThread(STATUS_SUCCESS);
	VMProtectEnd();
	return STATUS_SUCCESS;
}

_Use_decl_annotations_ EXTERN_C NTSTATUS
GetKeServiceDescriptorTable64()
{
	VMProtectBegin("GetKeServiceDescriptorTable64");
#ifdef _WIN64
	
	PUCHAR StartSearchAddress = (PUCHAR)UtilReadMsr64(Msr::kIa32Lstar);// (PUCHAR)__readmsr(0xc0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;

	//地址效验
	if (!MmIsAddressValid(EndSearchAddress)) { 
		return false;
	}

	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;

	for (i = StartSearchAddress; i < EndSearchAddress; i++){
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2)){
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)  /*4c8d15*/			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	if (addr){
		KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)addr;
		HYPERPLATFORM_LOG_INFO("PSYSTEM_SERVICE_TABLE %x", KeServiceDescriptorTable);
	}
#endif // _WIN64
	VMProtectEnd();
	return true;
}

// Initializes DdiMon
_Use_decl_annotations_ EXTERN_C NTSTATUS
DdimonInitialization(SharedShadowHookData* shared_sh_data) {
	// Get a base address of ntoskrnl
  auto nt_base = UtilPcToFileHeader(KdDebuggerEnabled);
  if (!nt_base) {
    return STATUS_UNSUCCESSFUL;
  }
  VMProtectBegin("DdimonInitialization");

  GetKeServiceDescriptorTable64();

  // Install hooks by enumerating exports of ntoskrnl, but not activate them yet
  // 通过枚举ntoskrnl的导出安装钩子，但是不激活它们
  auto status = DdimonpEnumExportedSymbols(reinterpret_cast<ULONG_PTR>(nt_base),
                                           DdimonpEnumExportedSymbolsCallback,
                                           shared_sh_data);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Activate installed hooks
  // 激活已安装的挂钩
  status = ShEnableHooks();
  if (!NT_SUCCESS(status)) {
    DdimonpFreeAllocatedTrampolineRegions();
    return status;
  }
  //创建进程检测线程
  HANDLE threadHandle = NULL;
  auto lstatus = PsCreateSystemThread(&threadHandle,
	  0,
	  NULL, //或者THREAD_ALL_ACCESS  
	  NtCurrentProcess(),
	  NULL,
	  (PKSTART_ROUTINE)ThreadProc,
	  NULL);



  HYPERPLATFORM_LOG_INFO("DdiMon has been initialized.");
  VMProtectEnd();
  return status;
}

// Terminates DdiMon
// 终止DiMon
_Use_decl_annotations_ EXTERN_C void DdimonTermination() {
  PAGED_CODE();

  ShDisableHooks();
  UtilSleep(1000);
  DdimonpFreeAllocatedTrampolineRegions();
  HYPERPLATFORM_LOG_INFO("DdiMon has been terminated.");
}

// Frees trampoline code allocated and stored in g_ddimonp_hook_targets by
// 释放分配并存储在g_ddimonp_hook_targets中的蹦床代码
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
// 枚举由基地址指定的模块中的所有导出。
_Use_decl_annotations_ EXTERN_C static NTSTATUS DdimonpEnumExportedSymbols(
    ULONG_PTR base_address, EnumExportedSymbolsCallbackType callback,
    void* context) {
  PAGED_CODE();
  //定义变量
  NTSTATUS status;
  SIZE_T Size = 0;
  HANDLE hSection, hFile;
  OBJECT_ATTRIBUTES oa;
  IO_STATUS_BLOCK iosb;
  UNICODE_STRING pDllName;
  ULONG_PTR BaseAddress = NULL;

  VMProtectBegin("DdimonpEnumExportedSymbols");
  

  auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
  auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
  auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
  if (!dir->Size || !dir->VirtualAddress) {
    return STATUS_SUCCESS;
  }
  
  auto dir_base = base_address + dir->VirtualAddress;
  auto dir_end = base_address + dir->VirtualAddress + dir->Size - 1;
  auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address +
                                                           dir->VirtualAddress);
  for (auto i = 0ul; i < exp_dir->NumberOfNames; i++) {
    if (!callback(i, base_address, exp_dir, dir_base, dir_end, context, FALSE)) {
      return STATUS_SUCCESS;
    }
  }
  
  RtlInitUnicodeString(&pDllName, L"\\SystemRoot\\System32\\ntdll.dll");
  InitializeObjectAttributes(&oa, &pDllName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwOpenFile(&hFile, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
  if (NT_SUCCESS(status)){
	  oa.ObjectName = 0;
	  status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_READONLY, 0x01000000, hFile);
	  if (NT_SUCCESS(status)){
		  BaseAddress = NULL;
		  status = ZwMapViewOfSection(hSection, NtCurrentProcess(), (PVOID*)&BaseAddress, 0, 0, 0, &Size, ViewShare, MEM_TOP_DOWN, PAGE_READONLY);
		  if (NT_SUCCESS(status)){
			  dos = (PIMAGE_DOS_HEADER)BaseAddress;
			  nt = (PIMAGE_NT_HEADERS)(BaseAddress + dos->e_lfanew);
			  dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
			  if (!dir->Size || !dir->VirtualAddress) {
				  return STATUS_SUCCESS;
			  }
			  dir_base = BaseAddress + dir->VirtualAddress;
			  dir_end = BaseAddress + dir->VirtualAddress + dir->Size - 1;
			  exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(BaseAddress + dir->VirtualAddress);
			  for (ULONG i = 0; i < exp_dir->NumberOfNames; i++){
				  if (!callback(i, BaseAddress, exp_dir, dir_base, dir_end, context, TRUE)) {
					  return STATUS_SUCCESS;
				  }
			  }
			  ZwUnmapViewOfSection(NtCurrentProcess(), (PVOID)BaseAddress);
		  }
		  ZwClose(hSection);
	  }
	  ZwClose(hFile);
  }
  VMProtectEnd();
  return STATUS_SUCCESS;
}

// Checks if the export is listed as a hook target, and if so install a hook.
// 检查导出是否列为钩子目标，如果是这样安装钩子。
_Use_decl_annotations_ EXTERN_C static bool DdimonpEnumExportedSymbolsCallback(
    ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
    ULONG_PTR directory_base, ULONG_PTR directory_end, void* context, BOOLEAN ssdt) {
  PAGED_CODE();

  VMProtectBegin("DdimonpEnumExportedSymbolsCallback");

  if (!context) {
    return false;
  }
  static auto ssdt_index = -1;
  auto functions =
      reinterpret_cast<ULONG*>(base_address + directory->AddressOfFunctions);
  auto ordinals = reinterpret_cast<USHORT*>(base_address +
                                            directory->AddressOfNameOrdinals);
  auto names =
      reinterpret_cast<ULONG*>(base_address + directory->AddressOfNames);

  auto export_address = base_address + 0;
  auto export_name = reinterpret_cast<const char*>(base_address + names[index]);
  char export_str[256] = { 0 };
  if (ssdt) {
	  
	  if (!KeServiceDescriptorTable) {
		  return false;
	  }
	
	  if (export_name[0] != 'Z' || export_name[1] != 'w') {
		  return true;
	  }
	  ssdt_index++;
#ifdef _WIN64
	  export_address = PULONG(KeServiceDescriptorTable->ServiceTableBase)[ssdt_index];
	  export_address = export_address >> 4;
	  export_address = export_address + (ULONGLONG)KeServiceDescriptorTable->ServiceTableBase;
		 
#else
	  export_address = KeServiceDescriptorTable[0].Base[ssdt_index];
#endif

	  if (export_name){
		  strcpy_s(export_str, 256, export_name);
		  export_str[0] = 'N';
		  export_str[1] = 't';
		  export_name = reinterpret_cast<const char*>(export_str);
	  }
	  //HYPERPLATFORM_LOG_INFO("ssdt api at %d %x %s.", ssdt_index, export_address, export_name);
  }
  else {
	  auto ord = ordinals[index];
	  export_address = base_address + functions[ord];
	  //HYPERPLATFORM_LOG_INFO("def api at %d %x %s.", index, export_address, export_name);
  }

  // 检查导出是否转发？ 如果是，请忽略它。
  if (UtilIsInBounds(export_address, directory_base, directory_end)) {
    return true;
  }

  // 将名称转换为UNICODE_STRING
  wchar_t name[100];
  auto status =
      RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"%S", export_name);
  if (!NT_SUCCESS(status)) {
    return true;
  }

  

  UNICODE_STRING name_u = {};
  RtlInitUnicodeString(&name_u, name);

  for (auto& target : g_ddimonp_hook_targets) {
	  // Is this export listed as a target
	  if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr)) {
		  continue;
	  }
	  if (target.SSDT != ssdt) {
		  return true;
	  }

	// 是的，安装一个钩子到导出
    if (!ShInstallHook(reinterpret_cast<SharedShadowHookData*>(context),
                       reinterpret_cast<void*>(export_address), &target)) {
	  // 这是一个不应该发生的错误
      DdimonpFreeAllocatedTrampolineRegions();
      return false;
    }
    HYPERPLATFORM_LOG_INFO("Hook has been installed at %p %s.", export_address,
                           export_name);
  }
  VMProtectEnd();
  return true;
}

// 将整数中的池标记转换为可打印的字符串
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

// 查找调用原始函数的处理程序
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


// ExFreePool（）的钩子处理程序。 日志，ExFreePool（）从哪里调用
// 不支持任何图像
_Use_decl_annotations_ static VOID DdimonpHandleExFreePool(PVOID p) {
  const auto original = DdimonpFindOrignal(DdimonpHandleExFreePool);
  original(p);

  // Is inside image?
  // 内部图像？
  auto return_addr = _ReturnAddress();
  if (UtilPcToFileHeader(return_addr)) {
    return;
  }

  /*HYPERPLATFORM_LOG_INFO_SAFE("%p: ExFreePool(P= %p)", return_addr, p);*/
}


// ExFreePoolWithTag（）的钩子处理程序。 如果ExFreePoolWithTag（）是日志
// 从哪里不被任何图像支持。
_Use_decl_annotations_ static VOID DdimonpHandleExFreePoolWithTag(PVOID p,
                                                                  ULONG tag) {
  const auto original = DdimonpFindOrignal(DdimonpHandleExFreePoolWithTag);
  original(p, tag);

  // Is inside image?
  auto return_addr = _ReturnAddress();
  if (UtilPcToFileHeader(return_addr)) {
    return;
  }

  /*HYPERPLATFORM_LOG_INFO_SAFE("%p: ExFreePoolWithTag(P= %p, Tag= %s)",
                              return_addr, p, DdimonpTagToString(tag).data());*/
}


// ExQueueWorkItem（）的钩子处理程序。 如果工作程序指向的日志
// 其中不支持任何图像。
_Use_decl_annotations_ static VOID DdimonpHandleExQueueWorkItem(
    PWORK_QUEUE_ITEM work_item, WORK_QUEUE_TYPE queue_type) {
  const auto original = DdimonpFindOrignal(DdimonpHandleExQueueWorkItem);

  // Is inside image?
  if (UtilPcToFileHeader(work_item->WorkerRoutine)) {
    // Call an original after checking parameters. It is common that a work
    // routine frees a work_item object resulting in wrong analysis.
	// 检查参数后调用原件。 通常，工作
	// 例程释放工作项对象，导致错误的分析。
    original(work_item, queue_type);
    return;
  }

//  auto return_addr = _ReturnAddress();
  /*HYPERPLATFORM_LOG_INFO_SAFE(
      "%p: ExQueueWorkItem({Routine= %p, Parameter= %p}, %d)", return_addr,
      work_item->WorkerRoutine, work_item->Parameter, queue_type);*/

  original(work_item, queue_type);
}


// ExAllocatePoolWithTag（）的钩子处理程序。 记录ExAllocatePoolWithTag（）
// 从不支持任何图像的地方调用。
_Use_decl_annotations_ static PVOID DdimonpHandleExAllocatePoolWithTag(
    POOL_TYPE pool_type, SIZE_T number_of_bytes, ULONG tag) {
  const auto original = DdimonpFindOrignal(DdimonpHandleExAllocatePoolWithTag);
  const auto result = original(pool_type, number_of_bytes, tag);

  // Is inside image?
  // 内部图像？
  auto return_addr = _ReturnAddress();
  if (UtilPcToFileHeader(return_addr)) {
    return result;
  }

  /*HYPERPLATFORM_LOG_INFO_SAFE(
      "%p: ExAllocatePoolWithTag(POOL_TYPE= %08x, NumberOfBytes= %08X, Tag= "
      "%s) => %p",
      return_addr, pool_type, number_of_bytes, DdimonpTagToString(tag).data(),
      result);*/
  return result;
}


// NtQuerySystemInformation（）的钩子处理程序。 删除cmd.exe的条目
// 并隐藏它被列出。
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
  if (system_information_class != kSystemProcessInformation) 
  {
    return result;
  }

  auto next = reinterpret_cast<SystemProcessInformation*>(system_information);
  while (next->next_entry_offset) 
  {
    auto curr = next;
    next = reinterpret_cast<SystemProcessInformation*>(reinterpret_cast<UCHAR*>(curr) + curr->next_entry_offset);
	std::vector<Protection>::iterator it;
	for (it = lProtectionList.begin(); it != lProtectionList.end(); it++)
	{
		if (_wcsnicmp(next->image_name.Buffer, it->wcProcessName.c_str(), next->image_name.Length) == 0) {
			if (next->next_entry_offset)
			{
				curr->next_entry_offset += next->next_entry_offset;
			}
			else
			{
				curr->next_entry_offset = 0;
			}
			next = curr;
		}
	}
	
  }
  return result;
}

NTSTATUS DdimonpHandleNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	VMProtectBegin("DdimonpHandleNtOpenProcess");
	PEPROCESS EProcess;
	const auto original = DdimonpFindOrignal(DdimonpHandleNtOpenProcess);
	auto return_addr = _ReturnAddress();
	const auto result = original(ProcessHandle, DesiredAccess,
		ObjectAttributes, ClientId);

	auto status = ObReferenceObjectByHandle(*ProcessHandle, FILE_READ_DATA, 0, KernelMode, (PVOID*)&EProcess, 0);
	if (status == STATUS_SUCCESS)
	{
		auto * FileName = PsGetProcessImageFileName(EProcess);
		if (FileName)
		{
			std::vector<Protection>::iterator it;
			for (it = lProtectionList.begin(); it != lProtectionList.end(); it++)
			{
				if (!strcmp((char*)FileName, it->cProcessName.c_str()) ||
					(HANDLE)it->dwProcessId == ClientId->UniqueProcess)
				{
					HYPERPLATFORM_LOG_INFO_SAFE("%p: NtOpenProcess(ProcessHandle= %d, DesiredAccess= %d,Pid= %d ,filename:%s)",
						return_addr, ProcessHandle, DesiredAccess, ClientId->UniqueProcess, FileName);
					ClientId->UniqueProcess = (HANDLE)-1;
					return STATUS_ACCESS_DENIED;
				}
			}
			
		}

		//ZwClose(ProcessHandle);
	}
	if (!NT_SUCCESS(result)) {
		return result;
	}
	
	VMProtectEnd();
	return result;
}

NTSTATUS DdimonpHandleNtCreateUserProcess(OUT PHANDLE ProcessHandle, OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess, IN ACCESS_MASK ThreadDesiredAccess, IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL, IN ULONG CreateProcessFlags, IN ULONG CreateThreadFlags, 
	IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters, IN PVOID Parameter9, IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList)
{
	VMProtectBegin("DdimonpHandleNtCreateUserProcess");
	PEPROCESS EProcess;
	const auto original = DdimonpFindOrignal(DdimonpHandleNtCreateUserProcess);
	auto return_addr = _ReturnAddress();
	const auto hProcessID = PsGetCurrentProcessId();
	const auto result = original(ProcessHandle, ThreadHandle,
		ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes,
		ThreadObjectAttributes,CreateProcessFlags, CreateThreadFlags,
		ProcessParameters, Parameter9, AttributeList);

	HYPERPLATFORM_LOG_INFO_SAFE("%p: NtCreateUserProcess:(ProcessHandle= %d)",
		return_addr, ProcessHandle);
	return result;
}

NTSTATUS DdimonpHandleNtCreateProcessEx(
	OUT PHANDLE ProcessHandle, 
	IN ACCESS_MASK DesiredAccess, 
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN HANDLE InheritFromProcessHandle, 
	IN BOOLEAN InheritHandles, 
	IN HANDLE SectionHandle OPTIONAL, 
	IN HANDLE DebugPort OPTIONAL, 
	IN HANDLE ExceptionPort OPTIONAL, 
	IN HANDLE Unknown)
{
	VMProtectBegin("DdimonpHandleNtCreateProcessEx");
	PEPROCESS EProcess;
	const auto original = DdimonpFindOrignal(DdimonpHandleNtCreateProcessEx);
	auto return_addr = _ReturnAddress();
	const auto hProcessID = PsGetCurrentProcessId();
	const auto result = original(ProcessHandle, DesiredAccess,
		ObjectAttributes, InheritFromProcessHandle, InheritHandles,
		SectionHandle, DebugPort, ExceptionPort, Unknown);
	
	HYPERPLATFORM_LOG_INFO_SAFE("%p: NtCreateProcessEx:(ProcessHandle= %d)",
		return_addr, ProcessHandle);
	VMProtectEnd();
	return result;
}
