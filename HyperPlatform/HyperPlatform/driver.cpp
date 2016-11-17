// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "driver.h"
#include "common.h"
#include "global_object.h"
#include "hotplug_callback.h"
#include "log.h"
#include "power_callback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"
#include "../../DdiMon/ddi_mon.h"
#include "../../DdiMon/mdk.h"
#include "../../DdiMon/VMProtectDDK.h"

extern "C" {


DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverpDriverUnload;

_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();


#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

UNICODE_STRING g_SymLinkName;



_Use_decl_annotations_ static NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDriverObject)
{
	VMProtectBegin("CreateDevice");
	PDEVICE_OBJECT pDevObj = 0;

	UNICODE_STRING devName;

	RtlInitUnicodeString(&devName, L"\\Device\\MProtect");

	auto status = IoCreateDevice(pDriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);

	if (!NT_SUCCESS(status)) {
		HYPERPLATFORM_LOG_INFO("CreateDevice Error:%x %x\n", NT_SUCCESS(status), status);
		return status;
	}

	pDevObj->Flags |= DO_BUFFERED_IO;

	RtlInitUnicodeString(&g_SymLinkName, L"\\??\\MProtect");

	status = IoCreateSymbolicLink(&g_SymLinkName, &devName);
	if (!NT_SUCCESS(status)) {
		HYPERPLATFORM_LOG_INFO("CreateDevice Error:%x %x\n", NT_SUCCESS(status), status);
		IoDeleteDevice(pDevObj);
		return status;
	}

	HYPERPLATFORM_LOG_INFO("Create Device Sucess");
	VMProtectEnd();

	return STATUS_SUCCESS;
}

_Use_decl_annotations_ EXTERN_C NTSTATUS PassiveSoke(){
	VMProtectBegin("Driver_Dispatch");



	VMProtectEnd();
	return STATUS_SUCCESS;
}

_Use_decl_annotations_ static NTSTATUS Driver_Dispatch(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	VMProtectBegin("Driver_Dispatch");
	HYPERPLATFORM_LOG_INFO("My::Driver_Dispatch\n");
	auto stack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG uPass = FALSE;
	PUCHAR Buffer = 0;
	HANDLE hOtherBrowserEvent = 0;
	HANDLE hNotifyUserEvent = 0;
	NOTIFY_HANDLE* pNotifyHandle32 = 0;
	TRY_SOKE * pSoke = 0;
	auto AllowRemove = 0;
	PUNICODE_STRING strOperater = 0;
	MDK_READWRITE_RET ret = { 0 };
	if (IRP_MJ_DEVICE_CONTROL == stack->MajorFunction) {
		auto BufferLenth = stack->Parameters.DeviceIoControl.InputBufferLength;
		auto uIoControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
		/*初始化事件以及引用,进程ID等内容*/
		if (IOCTL_MPROTECT_EVENT == uIoControlCode) {
			HYPERPLATFORM_LOG_INFO("IOCTL_KBGUARD_EVENT\n");
			if (BufferLenth < sizeof(NOTIFY_HANDLE)) {
				pIrp->IoStatus.Status = STATUS_SUCCESS;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}
			Buffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
			pNotifyHandle32 = (NOTIFY_HANDLE*)Buffer;
			if (g_NotifyHandle.m_dwEvent || g_NotifyHandle.m_dwNotify) {
				//如果以前此事件被设置过，那么应该先解除引用
				ObDereferenceObject((PVOID)g_NotifyHandle.m_dwEvent);
				g_NotifyHandle.m_dwEvent = 0;
				ObDereferenceObject((PVOID)g_NotifyHandle.m_dwNotify);
				g_NotifyHandle.m_dwNotify = 0;
				g_NotifyHandle.m_uPass = 0;
			}
			hOtherBrowserEvent = (HANDLE)pNotifyHandle32->m_dwEvent;
			hNotifyUserEvent = (HANDLE)pNotifyHandle32->m_dwNotify;
			ObReferenceObjectByHandle(hOtherBrowserEvent, EVENT_MODIFY_STATE, *ExEventObjectType, pIrp->RequestorMode, (PVOID *)&g_NotifyHandle.m_dwEvent, NULL);
			ObReferenceObjectByHandle(hNotifyUserEvent, EVENT_MODIFY_STATE, *ExEventObjectType, pIrp->RequestorMode, (PVOID *)&g_NotifyHandle.m_dwNotify, NULL);

			//HANDLE threadHandle = NULL;
			//auto lstatus = PsCreateSystemThread(&threadHandle,
			//	0,
			//	NULL, //或者THREAD_ALL_ACCESS  
			//	NtCurrentProcess(),
			//	NULL,
			//	(PKSTART_ROUTINE)PassiveSoke,
			//	NULL);
		}
		else if (IOCTL_MPROTECT_USERCHOICE == uIoControlCode) {
			if (BufferLenth < true) {
				pIrp->IoStatus.Status = STATUS_SUCCESS;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}
			Buffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
			g_NotifyHandle.m_uPass = *Buffer;
		}
		else if (IOCTL_MPROTECT_ADD_PROTECTION == uIoControlCode) {
			HYPERPLATFORM_LOG_INFO("IOCTL_MPROTECT_ADD_PROTECTION\n");
			if (BufferLenth < sizeof(TRY_SOKE)) {
				pIrp->IoStatus.Status = STATUS_SUCCESS;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}

			Buffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
			pSoke = (TRY_SOKE*)Buffer;
			DdimonpAddProtection(*pSoke);
			pSoke = nullptr;

			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = sizeof(ULONG);
			RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &uPass, sizeof(ULONG));

			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}
		else if (IOCTL_MPROTECT_RESET_PROTECTION == uIoControlCode) {

			HYPERPLATFORM_LOG_INFO("IOCTL_MPROTECT_RESET_PROTECTION\n");
			DdimonpResetProtection();

			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = sizeof(ULONG);
			RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &uPass, sizeof(ULONG));

			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}
		else if (Mdk_Dispatch(uIoControlCode, pIrp, &ret)) {

			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = sizeof(ret);
			RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &ret, sizeof(ret));
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return STATUS_SUCCESS;
		}
		else {
			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = 0;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			return STATUS_INVALID_VARIANT;
		}
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	VMProtectEnd();
	return STATUS_SUCCESS;
}


_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();
  VMProtectBegin("DriverEntry");
  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\MProtect.log";
  static const auto kLogLevel =
      (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
                         : kLogPutLevelDebug | kLogOptDisableFunctionName;

  auto status = STATUS_UNSUCCESSFUL;
  driver_object->DriverUnload = DriverpDriverUnload;
  driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Driver_Dispatch;
  driver_object->MajorFunction[IRP_MJ_CREATE] = Driver_Dispatch;
  driver_object->MajorFunction[IRP_MJ_CLOSE] = Driver_Dispatch;
  HYPERPLATFORM_COMMON_DBG_BREAK();
  
  status = CreateDevice(driver_object);
  if (!NT_SUCCESS(status)) {
	  HYPERPLATFORM_LOG_INFO("CreateDevice Error\n");
	  return status;
  }
  

  // Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  // Initialize log functions
  bool need_reinitialization = false;
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
    need_reinitialization = true;
  } else if (!NT_SUCCESS(status)) {
    return status;
  }

  // Test if the system is supported
  if (!DriverpIsSuppoetedOS()) {
    LogTermination();
    return STATUS_CANCELLED;
  }

  // Initialize global variables
  status = GlobalObjectInitialization();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization(driver_object);
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize power callback
  status = PowerCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize hot-plug callback
  status = HotplugCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Virtualize all processors
  status = VmInitialization();
  if (!NT_SUCCESS(status)) {
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }


  
  // Register re-initialization for the log functions if needed
  if (need_reinitialization) {
    LogRegisterReinitialization(driver_object);
  }
  HYPERPLATFORM_LOG_INFO("The VMM has been installed.");
  VMProtectEnd();
  return status;
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(
    PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();
  VMProtectBegin("DriverpDriverUnload");
  HYPERPLATFORM_COMMON_DBG_BREAK();


  VmTermination();
  HotplugCallbackTermination();
  PowerCallbackTermination();
  UtilTermination();
  PerfTermination();
  GlobalObjectTermination();
  LogTermination();
  VMProtectEnd();
}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();
  VMProtectBegin("DriverEntry");
  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  VMProtectEnd();
  return true;
}



}  // extern "C"
