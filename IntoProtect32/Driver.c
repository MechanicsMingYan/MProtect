//#include "stdafx.h"
#include "Driver.h"
#include "HookProtect.h"
/*
#define IOCTL_MPROTECT_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_USERCHOICE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_GET_TRY_SOKE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MPROTECT_RESET_PROCESS_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_ADD_PROTECTION_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_RESET_PROCESS_POTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_ADD_PROCESS_POTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)*/
#define IOCTL_MPROTECT_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_UNEVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_USERCHOICE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_GET_TRY_SOKE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MPROTECT_RESET_PROCESS_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_ADD_PROTECTION_HIDE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_RESET_PROCESS_POTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_ADD_PROCESS_POTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRY_SOKE 0x80000000

#define DEVICE_NAME_PROCESS				L"\\Device\\IntoProtect"		//ProtectProgram
#define SYMBOLINK_NAME_PROCESS			L"\\??\\IntoProtect"			//ProtectProgram

typedef struct  
{
	unsigned long ProcessId;
	WCHAR ProcessInfo[260];
	WCHAR VisitInfo[5][260];
}TRY_SOKE;

PDEVICE_OBJECT  g_pDriverObject=NULL;//保存全局设备
KSPIN_LOCK  HideSpinLock;
KIRQL HideIrql;
KSPIN_LOCK  PotectSpinLock;
KIRQL PotectIrql;


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING  pRegistryPath)
{
	ULONG i;
	NTSTATUS status;
	NTSTATUS rc;

	UNICODE_STRING strDeviceName;
	UNICODE_STRING strSymbolLinkName;

	UNICODE_STRING	FileEventString;
	UNICODE_STRING	FileAppEventString;

	PDEVICE_OBJECT pDeviceObject;

	pDeviceObject = NULL;

	RtlInitUnicodeString(&strDeviceName, DEVICE_NAME_PROCESS);
	RtlInitUnicodeString(&strSymbolLinkName, SYMBOLINK_NAME_PROCESS);

	DbgPrint("*********Enter DriverEntry()*********\n");

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DispatcherGeneral;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatcherCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatcherClose;
	pDriverObject->MajorFunction[IRP_MJ_READ] = DispatcherRead;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = DispatcherWrite;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatcherDeviceIoControl;

	pDriverObject->DriverUnload =DriverUnload;

	status = IoCreateDevice(pDriverObject, 0, &strDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	if (!pDeviceObject)
	{
		return STATUS_UNEXPECTED_IO_ERROR;
	}

	status = IoCreateSymbolicLink(&strSymbolLinkName, &strDeviceName);

	g_pDriverObject=pDeviceObject;


	InitGlobalVar();
	
	HookProcessProtect();
	DbgPrint("*********Leave DriverEntry()*********\n");

	return STATUS_SUCCESS;
}

void InitGlobalVar()
{
	KeInitializeSpinLock(&HideSpinLock);
	KeInitializeSpinLock(&PotectSpinLock);
}

void DriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING strSymbolLinkName;
	NTSTATUS status;
	PDEVICE_OBJECT DeviceObjectTemp1=NULL;
	PDEVICE_OBJECT DeviceObjectTemp2=NULL;

	DbgPrint("*********Enter DriverUnload()*********");

	RtlInitUnicodeString(&strSymbolLinkName, SYMBOLINK_NAME_PROCESS);
	IoDeleteSymbolicLink(&strSymbolLinkName);

	DbgPrint("停止进程的监控操作\r\n");
	DbgPrint("调用 PsSetCreateProcessNotifyRoutine\r\n");

	/*status = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);	//取消进程的创建和进程的退出 回调函数
	if (!NT_SUCCESS(status))
	{
		DbgPrint("调用 PsSetCreateProcessNotifyRoutine 失败!\r\n");
		DbgPrint("Status Code: 0x%08X", status);
	}*/

	if(pDriverObject)
	{
		DeviceObjectTemp1=pDriverObject->DeviceObject;
		while(DeviceObjectTemp1)
		{
			DeviceObjectTemp2=DeviceObjectTemp1;
			DeviceObjectTemp1=DeviceObjectTemp1->NextDevice;
			IoDeleteDevice(DeviceObjectTemp2);
		}
	}

	UnHookProcessProtect();

	DbgPrint("*********Leave DriverUnload()*********\n");
}


//=====================================================================================//
//Name: NTSTATUS DispatcherCreate()										               //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS DispatcherCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


//=====================================================================================//
//Name: NTSTATUS DispatcherClose()										               //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS DispatcherClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


//=====================================================================================//
//Name: NTSTATUS DispatcherGeneral()										           //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS DispatcherGeneral(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}


//=====================================================================================//
//Name: NTSTATUS DispatcherRead()											           //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS DispatcherRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS rtStatus;

	rtStatus = STATUS_NOT_SUPPORTED;

	return rtStatus;
}


//=====================================================================================//
//Name: NTSTATUS DispatcherWrite()										               //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS DispatcherWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS rtStatus;

	rtStatus = STATUS_NOT_SUPPORTED;

	return rtStatus;
}


//=====================================================================================//
//Name: NTSTATUS DispatcherDeviceIoControl()								           //
//                                                                                     //
//Descripion: 分发函数																   //
//            				                            						       //
//=====================================================================================//
NTSTATUS DispatcherDeviceIoControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS rtStatus=STATUS_SUCCESS;
	PIO_STACK_LOCATION pStack;

	//ULONG uPID=0;
	ULONG uInLen;
	ULONG uOutLen;
	ULONG uCtrlCode;

	PCHAR pInBuffer;
	//PWSTR pInBufferRegistry;
	//PWSTR pInBufferFileFolder;
	
	//PUCHAR Buffer = 0;
	//TRY_SOKE * pSoke = 0;
	TRY_SOKE Soke;
	//unsigned long uPass = FALSE;
	
	pStack = IoGetCurrentIrpStackLocation(pIrp);

	uInLen = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutLen = pStack->Parameters.DeviceIoControl.OutputBufferLength;
	uCtrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	DbgPrint("*********Enter DispatcherDeviceIoControl()*********");

	switch(uCtrlCode)
	{
		case IOCTL_MPROTECT_ADD_PROTECTION_HIDE: //把进程隐藏起来
			{
				DbgPrint("现在是正在处理从应用层传递下来的 HIDE PROCESS值\n");

				/*Buffer = (PUCHAR)pIrp->AssociatedIrp.SystemBuffer;
				pSoke = (TRY_SOKE*)Buffer;*/
				if (uInLen < sizeof(TRY_SOKE)) 
				{
					rtStatus = STATUS_UNSUCCESSFUL;
					//rtStatus = STATUS_PROCESS_IS_TERMINATING;
					break;
				}
				else
				{
					RtlZeroMemory(&Soke,sizeof(TRY_SOKE));
					pInBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
					RtlCopyMemory(&Soke,pInBuffer,sizeof(TRY_SOKE));
				}
				
				KeAcquireSpinLock(&HideSpinLock,&HideIrql);
				if(InsertHideProcess(Soke.ProcessId) == FALSE)
				{
					//rtStatus = STATUS_PROCESS_IS_TERMINATING;
					rtStatus = STATUS_UNSUCCESSFUL;
				}
				else
				{
					rtStatus = STATUS_SUCCESS;
				}
				KeReleaseSpinLock(&HideSpinLock,HideIrql);

				//pSoke = nullptr;
				/*pIrp->IoStatus.Status = STATUS_SUCCESS;
				pIrp->IoStatus.Information = sizeof(ULONG);
				RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &uPass, sizeof(ULONG));
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);*/

				break;
			}
		case IOCTL_MPROTECT_RESET_PROCESS_HIDE: //消除隐藏的进程
			{
				DbgPrint("现在是正在处理从应用层传递下来的 IO_REMOVE_HIDE_PROCESS值\n");

				//pInBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
				//uPID = atol(pInBuffer);
				//uPID = 1;

				if (uInLen < sizeof(TRY_SOKE)) 
				{
					rtStatus = STATUS_UNSUCCESSFUL;
					//rtStatus = STATUS_PROCESS_IS_TERMINATING;
					break;
				}
				else
				{
					RtlZeroMemory(&Soke,sizeof(TRY_SOKE));
					pInBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
					RtlCopyMemory(&Soke,pInBuffer,sizeof(TRY_SOKE));
				}

				KeAcquireSpinLock(&HideSpinLock,&HideIrql);
				if(RemoveHideProcess(Soke.ProcessId) == FALSE)
				{
					rtStatus = STATUS_UNSUCCESSFUL;
				}
				else
				{
					rtStatus = STATUS_SUCCESS;
				}
				KeReleaseSpinLock(&HideSpinLock,HideIrql);

				DbgPrint("REMOVE_HIDE_PROCESS值已经处理完毕\n");

				break;
			}
		case IOCTL_MPROTECT_ADD_PROCESS_POTECT: //保护进程，防止它被用户结束
			{
				DbgPrint("现在是正在处理从应用层传递下来的 IO_INSERT_PROTECT_PROCESS值\n");
				
				if (uInLen < sizeof(TRY_SOKE)) 
				{
					rtStatus = STATUS_UNSUCCESSFUL;
					//rtStatus = STATUS_PROCESS_IS_TERMINATING;
					break;
				}
				else
				{
					RtlZeroMemory(&Soke,sizeof(TRY_SOKE));
					pInBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
					RtlCopyMemory(&Soke,pInBuffer,sizeof(TRY_SOKE));
				}

				KeAcquireSpinLock(&PotectSpinLock,&PotectIrql);
				if(InsertProtectProcess(Soke.ProcessId) == FALSE)
				{
					//rtStatus = STATUS_PROCESS_IS_TERMINATING;
					rtStatus = STATUS_UNSUCCESSFUL;
				}
				else
				{
					rtStatus = STATUS_SUCCESS;
				}
				KeReleaseSpinLock(&PotectSpinLock,PotectIrql);

				DbgPrint("PROTECT_PROCESS值已经处理完毕\n");

				break;
			}
		case IOCTL_MPROTECT_RESET_PROCESS_POTECT: //消除保护的进程
			{
				DbgPrint("现在是正在处理从应用层传递下来的 IO_REMOVE_PROTECT_PROCESS值\n");
				/*
				pInBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
				uPID = atol(pInBuffer);*/

				if (uInLen < sizeof(TRY_SOKE)) 
				{
					rtStatus = STATUS_UNSUCCESSFUL;
					//rtStatus = STATUS_PROCESS_IS_TERMINATING;
					break;
				}
				else
				{
					RtlZeroMemory(&Soke,sizeof(TRY_SOKE));
					pInBuffer = (PCHAR)pIrp->AssociatedIrp.SystemBuffer;
					RtlCopyMemory(&Soke,pInBuffer,sizeof(TRY_SOKE));
				}

				KeAcquireSpinLock(&PotectSpinLock,&PotectIrql);
				if(RemoveProtectProcess(Soke.ProcessId) == FALSE)
				{
					//rtStatus = STATUS_PROCESS_IS_TERMINATING;
					rtStatus = STATUS_UNSUCCESSFUL;
				}
				else
				{
					rtStatus = STATUS_SUCCESS;
				}
				KeReleaseSpinLock(&PotectSpinLock,PotectIrql);

			
				DbgPrint("REMOVE_PROTECT_PROCESS值已经处理完毕\n");

				break; 
			}/*
		case IOCTL_PROTECT_FILEFOLDER: //保护应用程序指定的文件夹 防止这个文件夹被删除、防止在这个文件夹下面创建文件或文件夹
			{
				pInBufferFileFolder = (PWSTR)pIrp->AssociatedIrp.SystemBuffer;

				wcscpy(ProtectFilePath,pInBufferFileFolder);
				_wcsupr(ProtectFilePath);

				if(iCountFilePath<PATHCOUNT)//不能大于所能保护的文件夹的个数
				{ 
					wcscpy(ProtectFilePathArray[iCountFilePath++],ProtectFilePath);//保存文件路径到全局数组
				}
				else
				{
					iCountFilePath=PATHCOUNT;
				}

				DbgPrint("要保护的文件夹是 ProtectFilePath=%S\n",ProtectFilePath);			
				DbgPrint("=========================================\n");
				DbgPrint("IOCTL_PROTECT_FILEFOLDER 被调用,通讯成功!\n");			
				DbgPrint("=========================================\n");	

				rtStatus = STATUS_SUCCESS;
				pIrp->IoStatus.Information = uOutLen;		

				break;
			}
		case IOCTL_PROTECT_REGISTRY_VALUEKEY: //保护注册表的键值
			{
				pInBufferRegistry = (PWSTR)pIrp->AssociatedIrp.SystemBuffer;
				wcscpy(ProtectKey,pInBufferRegistry);

				if(iCountRegistryKey < REGISTRY_MAX_PATH)//不大于文件夹所能保护的个数
				{ 
					wcscpy(ProtectKeyArray[iCountRegistryKey++],ProtectKey);//保存注册表键值到全局数组
				}
				else
				{
					iCountRegistryKey=REGISTRY_MAX_PATH;
				}

				DbgPrint("ProtectKey的值是:   %S\n",ProtectKey);
				DbgPrint("*------------------------------------------------*\n");
				DbgPrint("*IOCTL_PROTECT_REGISTRY_VALUEKEY 被调用,通讯成功!*\n");			
				DbgPrint("*------------------------------------------------*\n");	

				break;
			}
		case IOCTL_PROTECT_REGISTRY_DIRECTORY: //保护指定的注册表目录
			{
				pInBufferRegistry = (PWSTR)pIrp->AssociatedIrp.SystemBuffer;
				wcscpy(ProtectKeyDirectory,pInBufferRegistry);

				if(iCountRegistryPath < REGISTRY_MAX_PATH)
				{
					wcscpy(ProtectKeyDirectoryArray[iCountRegistryPath++],ProtectKeyDirectory);//保存注册表的路径到全局数组
				}
				else
				{
					iCountRegistryPath=REGISTRY_MAX_PATH;
				}

				DbgPrint("ProtectKeyDirectory的值是:   %S\n",ProtectKeyDirectory);
				DbgPrint("*-------------------------------------------------*\n");
				DbgPrint("*IOCTL_PROTECT_REGISTRY_DIRECTORY 被调用,通讯成功!*\n");			
				DbgPrint("*-------------------------------------------------*\n");	

				break;
			}*/
		default:
			{
				rtStatus = STATUS_SUCCESS;

				DbgPrint("现在是正在处理default情况\n");
				break;
			}
	}

	pIrp->IoStatus.Status = rtStatus;
	pIrp->IoStatus.Information =uOutLen;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	
	DbgPrint("*********Leave DispatcherDeviceIoControl()*********\n");

	return rtStatus;
}

