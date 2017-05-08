#include <ntddk.h>
#include <stdlib.h>
#include <wchar.h>
/*
#define DEVICE_NAME_PROCESS				L"\\Device\\MProtect"		//ProtectProgram
#define SYMBOLINK_NAME_PROCESS			L"\\??\\MProtect"			//ProtectProgram
*/
#define MAX_PROCESS_ARRARY_LENGTH		1024
/*#define MAXPATHLEN                      1024
#define MAXBUF							1024
#define MAXPROCESSCOUNT                 100
#define EPROCESS_SIZE					1
#define PEB_OFFSET						2  
#define FILE_NAME_OFFSET				3  
#define PROCESS_LINK_OFFSET				4  
#define PROCESS_ID_OFFSET				5  
#define EXIT_TIME_OFFSET				6 

#define	SSDT01_DEVICE_TYPE				FILE_DEVICE_UNKNOWN
//定义用于应用程序和驱动程序通信的宏，这里使用的是缓冲区读写方式
#define IOCTL_MPROTECT_RESET_PROCESS_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_ADD_PROTECTION_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_RESET_PROCESS_POTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_ADD_PROCESS_POTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define IOCTL_PROTECT_FILEFOLDER			(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_REGISTRY_VALUEKEY		(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_REGISTRY_DIRECTORY	(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define NtSuspendProcess_XP		253  
#define NtSuspendProcess_WIN7	366

#define OP_NONE           0x00
#define OP_MODRM          0x01
#define OP_DATA_I8        0x02
#define OP_DATA_I16       0x04
#define OP_DATA_I32       0x08
#define OP_DATA_PRE66_67  0x10
#define OP_WORD           0x20
#define OP_REL32          0x40


#define REGISTRY_DATA_MAXLEN	1024
#define REGISTRY_MAX_PATH		700 //要保护的注册表路径的个数以及注册表具体键值的个数， 在这里我把它们分别限制在1000个以内
#define PATHCOUNT				15  //要保护的文件路径的个数  在这里我设定为最多不超过15个

typedef struct _SYSTEM_THREAD_INFORMATION 
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;

} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
*/

typedef struct _SYSTEM_PROCESS_INFORMATION 
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime; 
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;//进程名
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId; //进程ID号
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;

} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef enum _SYSTEM_INFORMATION_CLASS 
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass

} SYSTEM_INFORMATION_CLASS;

/*
UCHAR OpcodeFlags[256] = 
{
	OP_MODRM,                      // 00
	OP_MODRM,                      // 01
	OP_MODRM,                      // 02
	OP_MODRM,                      // 03
	OP_DATA_I8,                    // 04
	OP_DATA_PRE66_67,              // 05
	OP_NONE,                       // 06
	OP_NONE,                       // 07
	OP_MODRM,                      // 08
	OP_MODRM,                      // 09
	OP_MODRM,                      // 0A
	OP_MODRM,                      // 0B
	OP_DATA_I8,                    // 0C
	OP_DATA_PRE66_67,              // 0D
	OP_NONE,                       // 0E
	OP_NONE,                       // 0F
	OP_MODRM,                      // 10
	OP_MODRM,                      // 11
	OP_MODRM,                      // 12
	OP_MODRM,                      // 13
	OP_DATA_I8,                    // 14
	OP_DATA_PRE66_67,              // 15
	OP_NONE,                       // 16
	OP_NONE,                       // 17
	OP_MODRM,                      // 18
	OP_MODRM,                      // 19
	OP_MODRM,                      // 1A
	OP_MODRM,                      // 1B
	OP_DATA_I8,                    // 1C
	OP_DATA_PRE66_67,              // 1D
	OP_NONE,                       // 1E
	OP_NONE,                       // 1F
	OP_MODRM,                      // 20
	OP_MODRM,                      // 21
	OP_MODRM,                      // 22
	OP_MODRM,                      // 23
	OP_DATA_I8,                    // 24
	OP_DATA_PRE66_67,              // 25
	OP_NONE,                       // 26
	OP_NONE,                       // 27
	OP_MODRM,                      // 28
	OP_MODRM,                      // 29
	OP_MODRM,                      // 2A
	OP_MODRM,                      // 2B
	OP_DATA_I8,                    // 2C
	OP_DATA_PRE66_67,              // 2D
	OP_NONE,                       // 2E
	OP_NONE,                       // 2F
	OP_MODRM,                      // 30
	OP_MODRM,                      // 31
	OP_MODRM,                      // 32
	OP_MODRM,                      // 33
	OP_DATA_I8,                    // 34
	OP_DATA_PRE66_67,              // 35
	OP_NONE,                       // 36
	OP_NONE,                       // 37
	OP_MODRM,                      // 38
	OP_MODRM,                      // 39
	OP_MODRM,                      // 3A
	OP_MODRM,                      // 3B
	OP_DATA_I8,                    // 3C
	OP_DATA_PRE66_67,              // 3D
	OP_NONE,                       // 3E
	OP_NONE,                       // 3F
	OP_NONE,                       // 40
	OP_NONE,                       // 41
	OP_NONE,                       // 42
	OP_NONE,                       // 43
	OP_NONE,                       // 44
	OP_NONE,                       // 45
	OP_NONE,                       // 46
	OP_NONE,                       // 47
	OP_NONE,                       // 48
	OP_NONE,                       // 49
	OP_NONE,                       // 4A
	OP_NONE,                       // 4B
	OP_NONE,                       // 4C
	OP_NONE,                       // 4D
	OP_NONE,                       // 4E
	OP_NONE,                       // 4F
	OP_NONE,                       // 50
	OP_NONE,                       // 51
	OP_NONE,                       // 52
	OP_NONE,                       // 53
	OP_NONE,                       // 54
	OP_NONE,                       // 55
	OP_NONE,                       // 56
	OP_NONE,                       // 57
	OP_NONE,                       // 58
	OP_NONE,                       // 59
	OP_NONE,                       // 5A
	OP_NONE,                       // 5B
	OP_NONE,                       // 5C
	OP_NONE,                       // 5D
	OP_NONE,                       // 5E
	OP_NONE,                       // 5F
	OP_NONE,                       // 60
	OP_NONE,                       // 61
	OP_MODRM,                      // 62
	OP_MODRM,                      // 63
	OP_NONE,                       // 64
	OP_NONE,                       // 65
	OP_NONE,                       // 66
	OP_NONE,                       // 67
	OP_DATA_PRE66_67,              // 68
	OP_MODRM | OP_DATA_PRE66_67,   // 69
	OP_DATA_I8,                    // 6A
	OP_MODRM | OP_DATA_I8,         // 6B
	OP_NONE,                       // 6C
	OP_NONE,                       // 6D
	OP_NONE,                       // 6E
	OP_NONE,                       // 6F
	OP_DATA_I8,                    // 70
	OP_DATA_I8,                    // 71
	OP_DATA_I8,                    // 72
	OP_DATA_I8,                    // 73
	OP_DATA_I8,                    // 74
	OP_DATA_I8,                    // 75
	OP_DATA_I8,                    // 76
	OP_DATA_I8,                    // 77
	OP_DATA_I8,                    // 78
	OP_DATA_I8,                    // 79
	OP_DATA_I8,                    // 7A
	OP_DATA_I8,                    // 7B
	OP_DATA_I8,                    // 7C
	OP_DATA_I8,                    // 7D
	OP_DATA_I8,                    // 7E
	OP_DATA_I8,                    // 7F
	OP_MODRM | OP_DATA_I8,         // 80
	OP_MODRM | OP_DATA_PRE66_67,   // 81
	OP_MODRM | OP_DATA_I8,         // 82
	OP_MODRM | OP_DATA_I8,         // 83
	OP_MODRM,                      // 84
	OP_MODRM,                      // 85
	OP_MODRM,                      // 86
	OP_MODRM,                      // 87
	OP_MODRM,                      // 88
	OP_MODRM,                      // 89
	OP_MODRM,                      // 8A
	OP_MODRM,                      // 8B
	OP_MODRM,                      // 8C
	OP_MODRM,                      // 8D
	OP_MODRM,                      // 8E
	OP_MODRM,                      // 8F
	OP_NONE,                       // 90
	OP_NONE,                       // 91
	OP_NONE,                       // 92
	OP_NONE,                       // 93
	OP_NONE,                       // 94
	OP_NONE,                       // 95
	OP_NONE,                       // 96
	OP_NONE,                       // 97
	OP_NONE,                       // 98
	OP_NONE,                       // 99
	OP_DATA_I16 | OP_DATA_PRE66_67,// 9A
	OP_NONE,                       // 9B
	OP_NONE,                       // 9C
	OP_NONE,                       // 9D
	OP_NONE,                       // 9E
	OP_NONE,                       // 9F
	OP_DATA_PRE66_67,              // A0
	OP_DATA_PRE66_67,              // A1
	OP_DATA_PRE66_67,              // A2
	OP_DATA_PRE66_67,              // A3
	OP_NONE,                       // A4
	OP_NONE,                       // A5
	OP_NONE,                       // A6
	OP_NONE,                       // A7
	OP_DATA_I8,                    // A8
	OP_DATA_PRE66_67,              // A9
	OP_NONE,                       // AA
	OP_NONE,                       // AB
	OP_NONE,                       // AC
	OP_NONE,                       // AD
	OP_NONE,                       // AE
	OP_NONE,                       // AF
	OP_DATA_I8,                    // B0
	OP_DATA_I8,                    // B1
	OP_DATA_I8,                    // B2
	OP_DATA_I8,                    // B3
	OP_DATA_I8,                    // B4
	OP_DATA_I8,                    // B5
	OP_DATA_I8,                    // B6
	OP_DATA_I8,                    // B7
	OP_DATA_PRE66_67,              // B8
	OP_DATA_PRE66_67,              // B9
	OP_DATA_PRE66_67,              // BA
	OP_DATA_PRE66_67,              // BB
	OP_DATA_PRE66_67,              // BC
	OP_DATA_PRE66_67,              // BD
	OP_DATA_PRE66_67,              // BE
	OP_DATA_PRE66_67,              // BF
	OP_MODRM | OP_DATA_I8,         // C0
	OP_MODRM | OP_DATA_I8,         // C1
	OP_DATA_I16,                   // C2
	OP_NONE,                       // C3
	OP_MODRM,                      // C4
	OP_MODRM,                      // C5
	OP_MODRM   | OP_DATA_I8,       // C6
	OP_MODRM   | OP_DATA_PRE66_67, // C7
	OP_DATA_I8 | OP_DATA_I16,      // C8
	OP_NONE,                       // C9
	OP_DATA_I16,                   // CA
	OP_NONE,                       // CB
	OP_NONE,                       // CC
	OP_DATA_I8,                    // CD
	OP_NONE,                       // CE
	OP_NONE,                       // CF
	OP_MODRM,                      // D0
	OP_MODRM,                      // D1
	OP_MODRM,                      // D2
	OP_MODRM,                      // D3
	OP_DATA_I8,                    // D4
	OP_DATA_I8,                    // D5
	OP_NONE,                       // D6
	OP_NONE,                       // D7
	OP_WORD,                       // D8
	OP_WORD,                       // D9
	OP_WORD,                       // DA
	OP_WORD,                       // DB
	OP_WORD,                       // DC
	OP_WORD,                       // DD
	OP_WORD,                       // DE
	OP_WORD,                       // DF
	OP_DATA_I8,                    // E0
	OP_DATA_I8,                    // E1
	OP_DATA_I8,                    // E2
	OP_DATA_I8,                    // E3
	OP_DATA_I8,                    // E4
	OP_DATA_I8,                    // E5
	OP_DATA_I8,                    // E6
	OP_DATA_I8,                    // E7
	OP_DATA_PRE66_67 | OP_REL32,   // E8
	OP_DATA_PRE66_67 | OP_REL32,   // E9
	OP_DATA_I16 | OP_DATA_PRE66_67,// EA
	OP_DATA_I8,                    // EB
	OP_NONE,                       // EC
	OP_NONE,                       // ED
	OP_NONE,                       // EE
	OP_NONE,                       // EF
	OP_NONE,                       // F0
	OP_NONE,                       // F1
	OP_NONE,                       // F2
	OP_NONE,                       // F3
	OP_NONE,                       // F4
	OP_NONE,                       // F5
	OP_MODRM,                      // F6
	OP_MODRM,                      // F7
	OP_NONE,                       // F8
	OP_NONE,                       // F9
	OP_NONE,                       // FA
	OP_NONE,                       // FB
	OP_NONE,                       // FC
	OP_NONE,                       // FD
	OP_MODRM,                      // FE
	OP_MODRM | OP_REL32            // FF
};


UCHAR OpcodeFlagsExt[256] =
{
	OP_MODRM,                      // 00
	OP_MODRM,                      // 01
	OP_MODRM,                      // 02
	OP_MODRM,                      // 03
	OP_NONE,                       // 04
	OP_NONE,                       // 05
	OP_NONE,                       // 06
	OP_NONE,                       // 07
	OP_NONE,                       // 08
	OP_NONE,                       // 09
	OP_NONE,                       // 0A
	OP_NONE,                       // 0B
	OP_NONE,                       // 0C
	OP_MODRM,                      // 0D
	OP_NONE,                       // 0E
	OP_MODRM | OP_DATA_I8,         // 0F
	OP_MODRM,                      // 10
	OP_MODRM,                      // 11
	OP_MODRM,                      // 12
	OP_MODRM,                      // 13
	OP_MODRM,                      // 14
	OP_MODRM,                      // 15
	OP_MODRM,                      // 16
	OP_MODRM,                      // 17
	OP_MODRM,                      // 18
	OP_NONE,                       // 19
	OP_NONE,                       // 1A
	OP_NONE,                       // 1B
	OP_NONE,                       // 1C
	OP_NONE,                       // 1D
	OP_NONE,                       // 1E
	OP_NONE,                       // 1F
	OP_MODRM,                      // 20
	OP_MODRM,                      // 21
	OP_MODRM,                      // 22
	OP_MODRM,                      // 23
	OP_MODRM,                      // 24
	OP_NONE,                       // 25
	OP_MODRM,                      // 26
	OP_NONE,                       // 27
	OP_MODRM,                      // 28
	OP_MODRM,                      // 29
	OP_MODRM,                      // 2A
	OP_MODRM,                      // 2B
	OP_MODRM,                      // 2C
	OP_MODRM,                      // 2D
	OP_MODRM,                      // 2E
	OP_MODRM,                      // 2F
	OP_NONE,                       // 30
	OP_NONE,                       // 31
	OP_NONE,                       // 32
	OP_NONE,                       // 33
	OP_NONE,                       // 34
	OP_NONE,                       // 35
	OP_NONE,                       // 36
	OP_NONE,                       // 37
	OP_NONE,                       // 38
	OP_NONE,                       // 39
	OP_NONE,                       // 3A
	OP_NONE,                       // 3B
	OP_NONE,                       // 3C
	OP_NONE,                       // 3D
	OP_NONE,                       // 3E
	OP_NONE,                       // 3F
	OP_MODRM,                      // 40
	OP_MODRM,                      // 41
	OP_MODRM,                      // 42
	OP_MODRM,                      // 43
	OP_MODRM,                      // 44
	OP_MODRM,                      // 45
	OP_MODRM,                      // 46
	OP_MODRM,                      // 47
	OP_MODRM,                      // 48
	OP_MODRM,                      // 49
	OP_MODRM,                      // 4A
	OP_MODRM,                      // 4B
	OP_MODRM,                      // 4C
	OP_MODRM,                      // 4D
	OP_MODRM,                      // 4E
	OP_MODRM,                      // 4F
	OP_MODRM,                      // 50
	OP_MODRM,                      // 51
	OP_MODRM,                      // 52
	OP_MODRM,                      // 53
	OP_MODRM,                      // 54
	OP_MODRM,                      // 55
	OP_MODRM,                      // 56
	OP_MODRM,                      // 57
	OP_MODRM,                      // 58
	OP_MODRM,                      // 59
	OP_MODRM,                      // 5A
	OP_MODRM,                      // 5B
	OP_MODRM,                      // 5C
	OP_MODRM,                      // 5D
	OP_MODRM,                      // 5E
	OP_MODRM,                      // 5F
	OP_MODRM,                      // 60
	OP_MODRM,                      // 61
	OP_MODRM,                      // 62
	OP_MODRM,                      // 63
	OP_MODRM,                      // 64
	OP_MODRM,                      // 65
	OP_MODRM,                      // 66
	OP_MODRM,                      // 67
	OP_MODRM,                      // 68
	OP_MODRM,                      // 69
	OP_MODRM,                      // 6A
	OP_MODRM,                      // 6B
	OP_MODRM,                      // 6C
	OP_MODRM,                      // 6D
	OP_MODRM,                      // 6E
	OP_MODRM,                      // 6F
	OP_MODRM | OP_DATA_I8,         // 70
	OP_MODRM | OP_DATA_I8,         // 71
	OP_MODRM | OP_DATA_I8,         // 72
	OP_MODRM | OP_DATA_I8,         // 73
	OP_MODRM,                      // 74
	OP_MODRM,                      // 75
	OP_MODRM,                      // 76
	OP_NONE,                       // 77
	OP_NONE,                       // 78
	OP_NONE,                       // 79
	OP_NONE,                       // 7A
	OP_NONE,                       // 7B
	OP_MODRM,                      // 7C
	OP_MODRM,                      // 7D
	OP_MODRM,                      // 7E
	OP_MODRM,                      // 7F
	OP_DATA_PRE66_67 | OP_REL32,   // 80
	OP_DATA_PRE66_67 | OP_REL32,   // 81
	OP_DATA_PRE66_67 | OP_REL32,   // 82
	OP_DATA_PRE66_67 | OP_REL32,   // 83
	OP_DATA_PRE66_67 | OP_REL32,   // 84
	OP_DATA_PRE66_67 | OP_REL32,   // 85
	OP_DATA_PRE66_67 | OP_REL32,   // 86
	OP_DATA_PRE66_67 | OP_REL32,   // 87
	OP_DATA_PRE66_67 | OP_REL32,   // 88
	OP_DATA_PRE66_67 | OP_REL32,   // 89
	OP_DATA_PRE66_67 | OP_REL32,   // 8A
	OP_DATA_PRE66_67 | OP_REL32,   // 8B
	OP_DATA_PRE66_67 | OP_REL32,   // 8C
	OP_DATA_PRE66_67 | OP_REL32,   // 8D
	OP_DATA_PRE66_67 | OP_REL32,   // 8E
	OP_DATA_PRE66_67 | OP_REL32,   // 8F
	OP_MODRM,                      // 90
	OP_MODRM,                      // 91
	OP_MODRM,                      // 92
	OP_MODRM,                      // 93
	OP_MODRM,                      // 94
	OP_MODRM,                      // 95
	OP_MODRM,                      // 96
	OP_MODRM,                      // 97
	OP_MODRM,                      // 98
	OP_MODRM,                      // 99
	OP_MODRM,                      // 9A
	OP_MODRM,                      // 9B
	OP_MODRM,                      // 9C
	OP_MODRM,                      // 9D
	OP_MODRM,                      // 9E
	OP_MODRM,                      // 9F
	OP_NONE,                       // A0
	OP_NONE,                       // A1
	OP_NONE,                       // A2
	OP_MODRM,                      // A3
	OP_MODRM | OP_DATA_I8,         // A4
	OP_MODRM,                      // A5
	OP_NONE,                       // A6
	OP_NONE,                       // A7
	OP_NONE,                       // A8
	OP_NONE,                       // A9
	OP_NONE,                       // AA
	OP_MODRM,                      // AB
	OP_MODRM | OP_DATA_I8,         // AC
	OP_MODRM,                      // AD
	OP_MODRM,                      // AE
	OP_MODRM,                      // AF
	OP_MODRM,                      // B0
	OP_MODRM,                      // B1
	OP_MODRM,                      // B2
	OP_MODRM,                      // B3
	OP_MODRM,                      // B4
	OP_MODRM,                      // B5
	OP_MODRM,                      // B6
	OP_MODRM,                      // B7
	OP_NONE,                       // B8
	OP_NONE,                       // B9
	OP_MODRM | OP_DATA_I8,         // BA
	OP_MODRM,                      // BB
	OP_MODRM,                      // BC
	OP_MODRM,                      // BD
	OP_MODRM,                      // BE
	OP_MODRM,                      // BF
	OP_MODRM,                      // C0
	OP_MODRM,                      // C1
	OP_MODRM | OP_DATA_I8,         // C2
	OP_MODRM,                      // C3
	OP_MODRM | OP_DATA_I8,         // C4
	OP_MODRM | OP_DATA_I8,         // C5
	OP_MODRM | OP_DATA_I8,         // C6 
	OP_MODRM,                      // C7
	OP_NONE,                       // C8
	OP_NONE,                       // C9
	OP_NONE,                       // CA
	OP_NONE,                       // CB
	OP_NONE,                       // CC
	OP_NONE,                       // CD
	OP_NONE,                       // CE
	OP_NONE,                       // CF
	OP_MODRM,                      // D0
	OP_MODRM,                      // D1
	OP_MODRM,                      // D2
	OP_MODRM,                      // D3
	OP_MODRM,                      // D4
	OP_MODRM,                      // D5
	OP_MODRM,                      // D6
	OP_MODRM,                      // D7
	OP_MODRM,                      // D8
	OP_MODRM,                      // D9
	OP_MODRM,                      // DA
	OP_MODRM,                      // DB
	OP_MODRM,                      // DC
	OP_MODRM,                      // DD
	OP_MODRM,                      // DE
	OP_MODRM,                      // DF
	OP_MODRM,                      // E0
	OP_MODRM,                      // E1
	OP_MODRM,                      // E2
	OP_MODRM,                      // E3
	OP_MODRM,                      // E4
	OP_MODRM,                      // E5
	OP_MODRM,                      // E6
	OP_MODRM,                      // E7
	OP_MODRM,                      // E8
	OP_MODRM,                      // E9
	OP_MODRM,                      // EA
	OP_MODRM,                      // EB
	OP_MODRM,                      // EC
	OP_MODRM,                      // ED
	OP_MODRM,                      // EE
	OP_MODRM,                      // EF
	OP_MODRM,                      // F0
	OP_MODRM,                      // F1
	OP_MODRM,                      // F2
	OP_MODRM,                      // F3
	OP_MODRM,                      // F4
	OP_MODRM,                      // F5
	OP_MODRM,                      // F6
	OP_MODRM,                      // F7 
	OP_MODRM,                      // F8
	OP_MODRM,                      // F9
	OP_MODRM,                      // FA
	OP_MODRM,                      // FB
	OP_MODRM,                      // FC
	OP_MODRM,                      // FD
	OP_MODRM,                      // FE
	OP_NONE                        // FF
};
*/

#pragma pack(1)	//SSDT表的结构
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;	

//这个是查询某个函数的地址的一个宏
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[*(PULONG)((PUCHAR)_function+1)]

PUCHAR PsGetProcessImageFileName(__in PEPROCESS Process);

typedef NTSTATUS (* NTQUERYSYSTEMINFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

/*typedef struct _processInfo
{
	long pid;			 //进程的ID号
	//char psPath[1024];  //进程的路径
	WCHAR psPath[1024];

}PROCESSINFO, *LPPROCESSINFO;


typedef struct _PROCESS_INFO 
{   
	LONG    dwProcessId ;   
	PUCHAR   pImageFileName ;   
} PROCESS_INFO, *PPROCESS_INFO ;  

//用于DeviceIoControl传入缓冲区
typedef struct
{
	ULONG ProcessId;
	WCHAR ProcessInfo[260];
	WCHAR VisitInfo[5][260];
}TRY_SOKE;*/

////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////下面是要被Hook掉的内核函数的声明以及自定义的Hook函数的声明///////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////

typedef NTSTATUS (* ZWTERMINATEPROCESS)(IN HANDLE ProcessHandle,IN NTSTATUS ExitStatus);


/*
//
//这里是ZwOpenProcess函数的相关声明
NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(OUT PHANDLE ProcessHandle,
									  IN ACCESS_MASK DesiredAccess,
									  IN POBJECT_ATTRIBUTES ObjectAttributes,
									  IN PCLIENT_ID ClientId OPTIONAL);

typedef NTSTATUS (*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle,
								  IN ACCESS_MASK DesiredAccess,
								  IN POBJECT_ATTRIBUTES ObjectAttributes,
								  IN PCLIENT_ID ClientId OPTIONAL);

ZWOPENPROCESS RealZwOpenProcess;


//这里是ZwSetValueKey函数的相关声明
NTSYSAPI NTSTATUS NTAPI
ZwSetValueKey(IN HANDLE  KeyHandle,
			  IN PUNICODE_STRING  ValueName,
			  IN ULONG  TitleIndex  OPTIONAL,
			  IN ULONG  Type,
			  IN PVOID  Data,
			  IN ULONG  DataSize);

typedef NTSTATUS (*ZWSETVALUEKEY)(IN HANDLE  KeyHandle,
								  IN PUNICODE_STRING  ValueName,
								  IN ULONG  TitleIndex  OPTIONAL,
								  IN ULONG  Type,
								  IN PVOID  Data,
								  IN ULONG  DataSize);
ZWSETVALUEKEY RealZwSetValueKey;


//
//这里是ZwDeleteValueKey函数的相关声明
NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteValueKey(IN HANDLE KeyHandle,PUNICODE_STRING ValueName);
typedef NTSTATUS(*ZWDELETEVALUEKEY)(IN HANDLE KeyHandle,PUNICODE_STRING ValueName); 
ZWDELETEVALUEKEY RealZwDeleteValueKey;


//
//这里是ZwDeleteKey函数的相关声明
NTSYSAPI NTSTATUS NTAPI ZwDeleteKey(IN HANDLE KeyHandle);
typedef NTSTATUS(*ZWDELETEKEY)(IN HANDLE KeyHandle); 
ZWDELETEKEY RealZwDeleteKey;


//
//这里是ZwCreateKey函数的相关声明
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateKey(
			OUT PHANDLE  KeyHandle,
			IN ACCESS_MASK  DesiredAccess,
			IN POBJECT_ATTRIBUTES  ObjectAttributes,
			IN ULONG  TitleIndex,
			IN PUNICODE_STRING  Class  OPTIONAL,
			IN ULONG  CreateOptions,
			OUT PULONG  Disposition  OPTIONAL
			);

typedef NTSTATUS(*ZWCREATEKEY)(
							   OUT PHANDLE  KeyHandle,
							   IN ACCESS_MASK  DesiredAccess,
							   IN POBJECT_ATTRIBUTES  ObjectAttributes,
							   IN ULONG  TitleIndex,
							   IN PUNICODE_STRING  Class  OPTIONAL,
							   IN ULONG  CreateOptions,
							   OUT PULONG  Disposition  OPTIONAL
							   );

ZWCREATEKEY RealZwCreateKey;

//
//这里是ZwSetInformationFile函数的相关声明
NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationFile(
					 IN HANDLE  FileHandle,
					 OUT PIO_STATUS_BLOCK  IoStatusBlock,
					 IN PVOID  FileInformation,
					 IN ULONG  Length,
					 IN FILE_INFORMATION_CLASS  FileInformationClass
					 );

typedef NTSTATUS (*ZWSETINFORMATIONFILE)(
										IN HANDLE  FileHandle,
										OUT PIO_STATUS_BLOCK  IoStatusBlock,
										IN PVOID  FileInformation,
										IN ULONG  Length,
										IN FILE_INFORMATION_CLASS  FileInformationClass
										);

ZWSETINFORMATIONFILE RealZwSetInformationFile;


//
//这里是ZwCreateFile函数的相关声明
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateFile(
			 OUT PHANDLE FileHandle,
			 IN ACCESS_MASK DesiredAccess,
			 IN POBJECT_ATTRIBUTES ObjectAttributes,
			 OUT PIO_STATUS_BLOCK IoStatusBlock,
			 IN PLARGE_INTEGER AllocationSize  OPTIONAL,
			 IN ULONG FileAttributes,
			 IN ULONG ShareAccess,
			 IN ULONG CreateDisposition,
			 IN ULONG CreateOptions,
			 IN PVOID EaBuffer  OPTIONAL,
			 IN ULONG EaLength
			 );

typedef NTSTATUS (*ZWCREATEFILE)(
								 OUT PHANDLE FileHandle,
								 IN ACCESS_MASK DesiredAccess,
								 IN POBJECT_ATTRIBUTES ObjectAttributes,
								 OUT PIO_STATUS_BLOCK IoStatusBlock,
								 IN PLARGE_INTEGER AllocationSize  OPTIONAL,
								 IN ULONG FileAttributes,
								 IN ULONG ShareAccess,
								 IN ULONG CreateDisposition,
								 IN ULONG CreateOptions,
								 IN PVOID EaBuffer  OPTIONAL,
								 IN ULONG EaLength
								 );

ZWCREATEFILE RealZwCreateFile;



//这里是ZwCreateThread函数的相关声明
NTSYSAPI 
NTSTATUS 
NTAPI
ZwCreateThread(
				OUT  PHANDLE              ThreadHandle,
				IN   ACCESS_MASK          DesiredAccess,
				IN   POBJECT_ATTRIBUTES   ObjectAttributes,
				IN   HANDLE               ProcessHandle,
				OUT  PCLIENT_ID           ClientId,
				IN   PCONTEXT             ThreadContext,
				IN   PVOID				  UserStack,
				IN   BOOLEAN              CreateSuspended
				);

typedef NTSTATUS (*ZWCREATETHREAD)(
	OUT  PHANDLE              ThreadHandle,
	IN   ACCESS_MASK          DesiredAccess,
	IN   POBJECT_ATTRIBUTES   ObjectAttributes,
	IN   HANDLE               ProcessHandle,
	OUT  PCLIENT_ID           ClientId,
	IN   PCONTEXT             ThreadContext,
	IN   PVOID				  UserStack,
	IN   BOOLEAN              CreateSuspended
	);

ZWCREATETHREAD RealZwCreateThread;

//这里是ZwCreateThreadEx函数的相关声明
//typedef ULONG( *LPTHREAD_START_ROUTINE) (PVOID lpThreadParameter);
//typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY {
//    ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX，参见MSDN中UpdateProcThreadAttribute的说明
//    SIZE_T Size;        // Value的大小
//    ULONG_PTR Value;    // 保存4字节数据（比如一个Handle）或数据指针
//    ULONG Unknown;      // 总是0，可能是用来返回数据给调用者
//} PROC_THREAD_ATTRIBUTE_ENTRY, *PPROC_THREAD_ATTRIBUTE_ENTRY;
//
NTSYSAPI
NTSTATUS
NTAPI
ZwCreateThreadEx(
	  OUT PHANDLE ThreadHandle,
	  IN ACCESS_MASK DesiredAccess,
	  IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	  IN HANDLE ProcessHandle,
	  IN PVOID StartRoutine,
	  IN PVOID StartContext,
	  IN ULONG CreateThreadFlags,
	  IN SIZE_T ZeroBits OPTIONAL,
	  IN SIZE_T StackSize OPTIONAL,
	  IN SIZE_T MaximumStackSize OPTIONAL,
	  IN PVOID AttributeList
			 );
typedef NTSTATUS (NTAPI *ZWCREATETHREADEX)(
	  OUT PHANDLE ThreadHandle,
	  IN ACCESS_MASK DesiredAccess,
	  IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	  IN HANDLE ProcessHandle,
	  IN PVOID StartRoutine,
	  IN PVOID StartContext,
	  IN ULONG CreateThreadFlags,
	  IN SIZE_T ZeroBits OPTIONAL,
	  IN SIZE_T StackSize OPTIONAL,
	  IN SIZE_T MaximumStackSize OPTIONAL,
	  IN PVOID AttributeList
  );
ZWCREATETHREADEX RealZwCreateThreadEx;
*/

//这里是ZwQuerySystemInformation函数的相关声明
NTSYSAPI NTSTATUS NTAPI 
	ZwQuerySystemInformation (
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

NTSTATUS HookNtQuerySystemInformation (
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

//
//这里是ZwTerminateProcess函数的相关声明
NTSYSAPI NTSTATUS NTAPI  
	ZwTerminateProcess(IN HANDLE  ProcessHandle,IN NTSTATUS  ExitStatus);

NTSTATUS HookZwTerminateProcess(
	IN HANDLE ProcessHandle,
	IN NTSTATUS ExitStatus
	);

int HookProcessProtect();
void UnHookProcessProtect();
/*
NTSYSAPI
NTSTATUS
NTAPI 
PsLookupProcessByProcessId(
	__in   HANDLE ProcessId,
	__out  PEPROCESS *pEProcess);

typedef NTSTATUS (*PPsSuspendProcess) (__in PEPROCESS Process);

NTSYSAPI
NTSTATUS
NTAPI 
ObQueryNameString( 
				  IN PVOID Object, 
				  PUNICODE_STRING Name, 
				  ULONG MaximumLength, 
				  PULONG ActualLength 
				  );
*/

//往隐藏进程列表中插入 uPID
ULONG InsertHideProcess(ULONG uPID);

//从隐藏进程列表中移除 uPID
ULONG RemoveHideProcess(ULONG uPID);

//验证 uPID 所代表的进程是否存在于隐藏进程列表中，即判断 uPID 这个进程是否需要隐藏
ULONG ValidateProcessNeedHide(ULONG uPID);

//往保护进程列表中插入 uPID
ULONG InsertProtectProcess(ULONG uPID);

//从隐藏进程列表中移除 uPID
ULONG RemoveProtectProcess(ULONG uPID);

//验证 uPID 所代表的进程是否存在于保护进程列表中，即判断 uPID 这个进程是否需要保护
ULONG ValidateProcessNeedProtect(ULONG uPID);
/*
//VOID SystemThread(IN PVOID PContext);

void DriverUnload(IN PDRIVER_OBJECT pDriverObject);
NTSTATUS DispatcherGeneral(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherDeviceIoControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

// NTSTATUS PsGetProcessPathByPid( IN ULONG Pid ,char* FilePath);

ULONG PsGetProcessPathByPid( IN ULONG Pid ,	WCHAR FilePath[MAXPATHLEN]);

unsigned long __fastcall SizeOfCode(void *Code, unsigned char **pOpcode);
*/
