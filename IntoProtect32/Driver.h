#define INITGUID

#include <ntddk.h>
#include <wdf.h>
#include <stdlib.h>
#include <wchar.h>
#include "trace.h"

EXTERN_C_START

void DriverUnload(IN PDRIVER_OBJECT pDriverObject);
NTSTATUS DispatcherCreate(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherGeneral(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherRead(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherWrite(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);
NTSTATUS DispatcherDeviceIoControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

void InitGlobalVar();

EXTERN_C_END
