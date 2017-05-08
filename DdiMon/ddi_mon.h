// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to DdiMon functions.

#ifndef DDIMON_DDI_MON_H_
#define DDIMON_DDI_MON_H_

#include <fltKernel.h>

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

struct SharedShadowHookData;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS
    DdimonInitialization(_In_ SharedShadowHookData* shared_sh_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void DdimonTermination();

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
//定义与应用程序通讯的接口
#define IOCTL_MPROTECT_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_UNEVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_USERCHOICE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_GET_TRY_SOKE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MPROTECT_RESET_PROCESS_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_ADD_PROTECTION_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_RESET_PROCESS_POTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_ADD_PROCESS_POTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRY_SOKE 0x80000000

typedef struct
{
	ULONGLONG m_dwEvent;
	ULONGLONG m_dwNotify;
	ULONGLONG m_uPass;
}NOTIFY_HANDLE;

typedef struct
{
	ULONG ProcessId;
	WCHAR ProcessName[260];
	WCHAR VisitInfo[5][260];
}TRY_SOKE;

_Use_decl_annotations_ bool DdiDispatch(IN PIRP pIrp);

#endif  // DDIMON_DDI_MON_H_
