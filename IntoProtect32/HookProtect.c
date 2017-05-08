/**********************************************************************************************
 *    代码说明：																				  *
 *                                                                                            *
 * 本程序主要实现了：                                                                          *
 * 进程保护、进程隐藏、文件目录保护、注册表相关键和值的保护、进程的监控、挂起其它运行的进程。      *
 *																						      *
 *																							  *
 *                                                                               *
 *																							   *
 * 代码开发时间： 												   *
 *																							   *
 ***********************************************************************************************/

//#ifndef _WIN32_WINNT				                  
//#define _WIN32_WINNT 0x0501	 //Windows操作系统的版本号
//#endif						
#include "HookProtect.h"

extern KSPIN_LOCK  HideSpinLock;
extern KIRQL HideIrql;

extern KSPIN_LOCK  PotectSpinLock;
extern KIRQL PotectIrql;


/*
PROCESSINFO  psInfo;
PROCESSINFO  processInfoArray[MAXPROCESSCOUNT]={ 0 };//保存进程信息的数组

ULONG countProcessID=0;//统计进程的个数
ULONG CurrentProcessCount=0;//记录下当前系统中有多少个进程在运行

PDEVICE_OBJECT  g_pDriverObject;//保存全局设备
*/
ULONG g_PIDHideArray[MAX_PROCESS_ARRARY_LENGTH];
ULONG g_PIDProtectArray[MAX_PROCESS_ARRARY_LENGTH];
ULONG g_currHideArrayLen = 0;
ULONG g_currProtectArrayLen = 0;/*
ULONG g_OffsetEprocessName = NULL;

WCHAR ProtectFilePath[MAXBUF]={0};//定义要保护的文件目录，这个值是由应用层传递下来的
WCHAR ProtectFilePathArray[PATHCOUNT][MAXBUF] = {0}; //保存多个文件目录的二维数组，每个文件目录就是ProtectFilePath

ULONG iCountFilePath=0;		 //iCountFilePath用来统计要保护的文件目录个数，它必须不大于PATHCOUNT   
ULONG iCountRegistryKey=0;	 //统计注册表具体键值的个数
ULONG iCountRegistryPath=0;  //统计注册表的具体路径的个数

WCHAR ProtectKey[REGISTRY_DATA_MAXLEN] ={0}; //定义一个我们要保护的键名  这个值是应用层传递下来的
WCHAR ProtectKeyArray[REGISTRY_MAX_PATH][REGISTRY_DATA_MAXLEN]={0}; //定义一组键名 它是ProtectKey的集合

WCHAR ProtectKeyDirectory[REGISTRY_DATA_MAXLEN]={0}; //定义一个注册表的路径， 这个值是应用层传递下来的
WCHAR ProtectKeyDirectoryArray[REGISTRY_MAX_PATH][REGISTRY_DATA_MAXLEN]={0}; //定义一组注册表的路径  它是ProtectKeyDirectory的集合
*/
NTQUERYSYSTEMINFORMATION pOldNtQuerySystemInformation;
ZWTERMINATEPROCESS pOldNtTerminateProcess;
PMDL          pMdl=NULL;
PULONG        plMapped=NULL;
#define        SSDT_INDEX(_Func)                (*(PULONG)((PUCHAR)_Func + 1))

int HookProcessProtect()
{
	/*DbgPrint("在DriverEntry函数中我们获取到的进程个数是: %d\n",countProcessID);

	DbgPrint("调用 PsSetCreateProcessNotifyRoutine函数来监控进程的创建和进程的退出\r\n");

	rc = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);  //设置进程的创建和进程的退出 回调函数
	if (!NT_SUCCESS(rc))
	{
		DbgPrint("调用 PsSetCreateProcessNotifyRoutine 失败!\r\n");
		DbgPrint("Status Code: 0x%08X", rc);
		return rc;
	}

	rc = GetProcessNameOffset(&g_OffsetEprocessName);
	if (!NT_SUCCESS(rc))
	{
		KdPrint(("调用 GetProcessNameOffset失败!\r\n"));
		KdPrint(("Status Code: 0x%08X", rc));
		return rc;
	}
	KdPrint(("g_OffsetEprocessName的值为：0x%X\r\n", g_OffsetEprocessName));*/

	KIRQL Irql;
	DbgPrint("修改SSDT表....\n");
	//_asm 
	//{
	//	cli
	//	mov eax,cr0
	//	and eax,not 10000h  //清除cr0的WP位
	//	mov cr0,eax
	//}
	///////////////////////////////////
	pMdl = IoAllocateMdl(KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices * 4,
		FALSE, FALSE, NULL);
	if (pMdl == NULL)
	{
		return 0;
	}

	MmBuildMdlForNonPagedPool(pMdl);
	pMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;        //Write SSDT

	plMapped = (PULONG)MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (plMapped == NULL)
	{
		IoFreeMdl(pMdl);
		return 0;
	}
	///////////////////////////////////
	//提升IRQL中断级
	//Irql = KeRaiseIrqlToDpcLevel();
	//保存原始的内核函数 ZwQuerySystemInformation的地址,并用我们自定义的函数来填充
	//用户指定的、正在Windows系统运行的进程 将被隐藏
	pOldNtQuerySystemInformation=(NTQUERYSYSTEMINFORMATION)(SYSTEMSERVICE(ZwQuerySystemInformation));
	//(NTQUERYSYSTEMINFORMATION)(SYSTEMSERVICE(ZwQuerySystemInformation)) = HookNtQuerySystemInformation;
	plMapped[SSDT_INDEX(ZwQuerySystemInformation)] = (ULONG)HookNtQuerySystemInformation;
	
	//保存原始的内核函数 ZwTerminateProcess的地址,并用我们自定义的函数来填充
	//用户指定的、正在Windows系统运行的进程 将被保护起来，禁止结束
	pOldNtTerminateProcess=(ZWTERMINATEPROCESS)(SYSTEMSERVICE(ZwTerminateProcess));
	//(ZWTERMINATEPROCESS)(SYSTEMSERVICE(ZwTerminateProcess)) = HookZwTerminateProcess;
	plMapped[SSDT_INDEX(ZwTerminateProcess)] = (ULONG)HookZwTerminateProcess;

	//保存原始的内核函数 ZwSetValueKey的地址,并用我们自定义的函数来填充
	//在公司的软件产品所对应的注册表项下面，禁止用户修改注册表的表项以及键值
//	RealZwSetValueKey =(ZWSETVALUEKEY)(SYSTEMSERVICE(ZwSetValueKey));
//	(ZWSETVALUEKEY)(SYSTEMSERVICE(ZwSetValueKey)) = HookZwSetValueKey;

	
	//保存原始的内核函数 ZwDeleteValueKey的地址,并用我们自定义的函数来填充
	//在公司的软件产品所对应的注册表项下面，禁止用户删除注册表键值
//	RealZwDeleteValueKey=(ZWDELETEVALUEKEY)(SYSTEMSERVICE(ZwDeleteValueKey));
//	(ZWDELETEVALUEKEY)(SYSTEMSERVICE(ZwDeleteValueKey)) = HookZwDeleteValueKey;

	
	//保存原始的内核函数 ZwDeleteKey的地址,并用我们自定义的函数来填充
	//在公司的软件产品所对应的注册表项下面，禁止用户删除注册表的表项
//	RealZwDeleteKey=(ZWDELETEKEY)(SYSTEMSERVICE(ZwDeleteKey));
//	(ZWDELETEKEY)(SYSTEMSERVICE(ZwDeleteKey)) = HookZwDeleteKey;

	
	//保存原始的内核函数 ZwCreateKey的地址,并用我们自定义的函数来填充
	//在公司的软件产品所对应的注册表项下面，禁止用户创建注册表项、键值
//	RealZwCreateKey=(ZWCREATEKEY)(SYSTEMSERVICE(ZwCreateKey));
//	(ZWCREATEKEY)(SYSTEMSERVICE(ZwCreateKey)) = HookZwCreateKey;

	
	//保存原始的内核函数 ZwSetInformationFile的地址,并用我们自定义的函数来填充
	//禁止用户删除文件、文件夹、重命名，起到文件保护的作用
	//RealZwSetInformationFile=(ZWSETINFORMATIONFILE)(SYSTEMSERVICE(ZwSetInformationFile));
	//(ZWSETINFORMATIONFILE)(SYSTEMSERVICE(ZwSetInformationFile)) = HookZwSetInformationFile;

	
	//保存原始的内核函数 ZwCreateFile的地址,并用我们自定义的函数来填充
	//在受保护的文件目录下  不允许用户创建文件、文件夹、复制、粘贴、剪切
	//RealZwCreateFile=(ZWCREATEFILE)(SYSTEMSERVICE(ZwCreateFile));
	//(ZWCREATEFILE)(SYSTEMSERVICE(ZwCreateFile)) = HookZwCreateFile;

	
	//保存原始的内核函数 ZwOpenProcess的地址,并用我们自定义的函数来填充
	//获取用户正在Windows系统运行的进程的ID号和进程的路径,把它们传递给应用层
//	RealZwOpenProcess=(ZWOPENPROCESS)(SYSTEMSERVICE(ZwOpenProcess));
//	(ZWOPENPROCESS)(SYSTEMSERVICE(ZwOpenProcess))=HookZwOpenProcess;

	//保存原始的内核函数 ZwCreateThread的地址,并用我们自定义的函数来填充
	//防止远程注入，Hook掉应用层的CreateRemoteThread函数
	//RealZwCreateThreadEx=(ZWCREATETHREADEX)(KeServiceDescriptorTable.ServiceTableBase[0x58]);//Windows 7 32  ZwCreateThreadEx-->0x58
	//(ZWCREATETHREADEX)(KeServiceDescriptorTable.ServiceTableBase[0x58]) = HookZwCreateThreadEx;
//	RealZwCreateThread=(ZWCREATETHREAD)(KeServiceDescriptorTable.ServiceTableBase[0x35]);//windowsXP ZwCreateThread--->0x35
//	(ZWCREATETHREAD)(KeServiceDescriptorTable.ServiceTableBase[0x35]) = HookZwCreateThread;
	//KeLowerIrql(Irql);
	/*_asm
	{
		mov eax,cr0
		or eax,not 10000h  //恢复cr0的WP位
		mov cr0,eax
		sti
	}*/
	MmUnmapLockedPages(plMapped, pMdl);
	IoFreeMdl(pMdl);
	pMdl = NULL;

	DbgPrint("*********Leave DriverEntry()*********\n");

	return 1;
}

void UnHookProcessProtect()
{
	/*
	这里做if判断，这样确保了：
		(1)当应用层的EXE文件没有运行的时候，或者，
		(2)当应用层没有调用DeviceIoControl函数来传递事件对象到驱动程序的时候，	
		Windows系统不会蓝屏。
	*/
	/*_asm
	{
	cli
	mov eax,cr0
	and eax,not 10000h  //清除cr0的WP位
	mov cr0,eax
	}*/

	DbgPrint("修复SSDT表\n");

	pMdl = IoAllocateMdl(KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices * 4,
		FALSE, FALSE, NULL);
	if (pMdl == NULL)
	{
		return ;
	}

	MmBuildMdlForNonPagedPool(pMdl);
	pMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;        

	plMapped = (PULONG)MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (plMapped == NULL)
	{
		IoFreeMdl(pMdl);
		return ;
	}
	//下面开始恢复Windows内核原始的ZwXXX函数
	//(NTQUERYSYSTEMINFORMATION)(SYSTEMSERVICE(ZwQuerySystemInformation))=pOldNtQuerySystemInformation;
	plMapped[SSDT_INDEX(ZwQuerySystemInformation)] = (ULONG)pOldNtQuerySystemInformation;
	//(ZWTERMINATEPROCESS)(SYSTEMSERVICE(ZwTerminateProcess))=pOldNtTerminateProcess;
	plMapped[SSDT_INDEX(ZwTerminateProcess)] = (ULONG)pOldNtTerminateProcess;
	//	(ZWSETVALUEKEY)(SYSTEMSERVICE(ZwSetValueKey))=RealZwSetValueKey;
	//	(ZWDELETEVALUEKEY)(SYSTEMSERVICE(ZwDeleteValueKey))=RealZwDeleteValueKey;
	//	(ZWDELETEKEY)(SYSTEMSERVICE(ZwDeleteKey))=RealZwDeleteKey;
	//	(ZWCREATEKEY)(SYSTEMSERVICE(ZwCreateKey))=RealZwCreateKey; 
	//	(ZWSETINFORMATIONFILE)(SYSTEMSERVICE(ZwSetInformationFile)) =RealZwSetInformationFile;
	//	(ZWCREATEFILE)(SYSTEMSERVICE(ZwCreateFile))=RealZwCreateFile;
	//	(ZWOPENPROCESS)(SYSTEMSERVICE(ZwOpenProcess)) = RealZwOpenProcess;
	//	(ZWCREATETHREAD)(KeServiceDescriptorTable.ServiceTableBase[0x35]) = RealZwCreateThread;	//windows XP
	//	(ZWCREATETHREADEX)(KeServiceDescriptorTable.ServiceTableBase[0x58]) = RealZwCreateThreadEx;	//windows 7	
	
	//_asm
	//{
	//	mov eax,cr0
	//	or eax,not 10000h  //恢复cr0的WP位
	//	mov cr0,eax
	//	sti
	//}
	MmUnmapLockedPages(plMapped, pMdl);
	IoFreeMdl(pMdl);
	pMdl = NULL;
	DbgPrint("*********修复SSDT表完成*********\n");
}

//=========================================================================================================//
//Name: ULONG ValidateProcessNeedHide()											                           //
//                                                                                                         //
//Descripion: 返回 uPID进程在隐藏列表中的索引，如果该进程在隐藏列表中不存在，则返回-1                      //
//            				                            						                           //
//=========================================================================================================//

ULONG ValidateProcessNeedHide(ULONG uPID)
{
	ULONG i = 0;

	if(uPID == 0)
	{
		return -1;
	}

	for(i=0; i<g_currHideArrayLen && i<MAX_PROCESS_ARRARY_LENGTH; i++)
	{
		if(g_PIDHideArray[i] == uPID)
		{
			return i;
		}
	}
	return -1;
}


//=========================================================================================================//
//Name: ULONG ValidateProcessNeedProtect()										                           //
//                                                                                                         //
//Descripion: 返回uPID进程在保护列表中的索引，如果该进程在保护列表中不存在，则返回 -1                      //
//            				                            						                           //
//=========================================================================================================//
ULONG ValidateProcessNeedProtect(ULONG uPID)
{
	ULONG i = 0;

	if(uPID == 0)
	{
		return -1;
	}

	for(i=0; i<g_currProtectArrayLen && i<MAX_PROCESS_ARRARY_LENGTH;i++)
	{
		if(g_PIDProtectArray[i] == uPID)
		{
			return i;
		}
	}
	return -1;
}


//=========================================================================================================//
//Name: ULONG InsertHideProcess()												                           //
//                                                                                                         //
//Descripion: 在进程隐藏列表中插入新的进程 ID										                       //
//            				                            						                           //
//=========================================================================================================//
ULONG InsertHideProcess(ULONG uPID)
{
	if(ValidateProcessNeedHide(uPID) == -1 && g_currHideArrayLen < MAX_PROCESS_ARRARY_LENGTH)
	{
		g_PIDHideArray[g_currHideArrayLen] = uPID;
		g_currHideArrayLen++;
		return TRUE;
	}

	return FALSE;
}


//=========================================================================================================//
//Name: ULONG RemoveHideProcess()												                           //
//                                                                                                         //
//Descripion: 从进程隐藏列表中移除进程 ID											                       //
//            				                            						                           //
//=========================================================================================================//
ULONG RemoveHideProcess(ULONG uPID)
{
	ULONG uIndex = ValidateProcessNeedHide(uPID);
	ULONG i=uIndex;
	if(uIndex != -1)
	{
		//g_PIDHideArray[uIndex] = g_PIDHideArray[g_currHideArrayLen--];
		for(i=uIndex;i<g_currHideArrayLen;i++)
		{
			g_PIDHideArray[i] = g_PIDHideArray[i+1];
		}
		g_currHideArrayLen--;
		return TRUE;
	}
	
	return FALSE;
}


//=========================================================================================================//
//Name: ULONG InsertProtectProcess()											                           //
//                                                                                                         //
//Descripion: 在进程保护列表中插入新的进程 ID										                       //
//            				                            						                           //
//=========================================================================================================//
ULONG InsertProtectProcess(ULONG uPID)
{
	if(ValidateProcessNeedProtect(uPID) == -1 && g_currProtectArrayLen < MAX_PROCESS_ARRARY_LENGTH)
	{
		g_PIDProtectArray[g_currProtectArrayLen] = uPID;
		g_currProtectArrayLen++;
		return TRUE;
	}
	return FALSE;
}


//=========================================================================================================//
//Name: ULONG RemoveProtectProcess()											                           //
//                                                                                                         //
//Descripion: 在进程保护列表中移除一个进程ID                                                               //
//            				                            						                           //
//=========================================================================================================//
ULONG RemoveProtectProcess(ULONG uPID)
{
	ULONG uIndex = ValidateProcessNeedProtect(uPID);
	if(uIndex != -1)
	{
		g_PIDProtectArray[uIndex] = g_PIDProtectArray[g_currProtectArrayLen--];

		return TRUE;
	}
	return FALSE;
}


///////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////        下面是各个Hook函数的具体代码实现            ////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////
/*
PVOID GetPointer( HANDLE handle )
{

	PVOID         pKey;
	DbgPrint("*******Enter GetPointer()*******\n");

	if(!handle) return NULL;
	//取得指针
	if( ObReferenceObjectByHandle( handle, 0, NULL, KernelMode, &pKey, NULL ) != STATUS_SUCCESS ) 
	{
		pKey = NULL;
	} 

	DbgPrint("*******Leave GetPointer()*******\n");
	return pKey;
}




 //我在这里进行监控进程，来获取进程的完整路径



//=============================================================================================//
//Name: ULONG PsGetProcessPathByPid()														   //
//                                                                                             //
//Descripion: 根据进程的ID号来获取进程路径				                                       //
//            				                            						               //
//=============================================================================================//
ULONG PsGetProcessPathByPid( IN ULONG Pid ,WCHAR FilePath[MAXPATHLEN])
{
	NTSTATUS       status;

	UNICODE_STRING		uni_path;
	UNICODE_STRING		uni_disk;

	PEPROCESS			pEprocess;
	PFILE_OBJECT		FileObject;
	PVOID				Object;

	ULONG current_build;    
	ULONG ans = 0;    


	DbgPrint("Enter  PsGetProcessPathByPid()函数\n");

	status = PsLookupProcessByProcessId(Pid,&pEprocess);

	if(!NT_SUCCESS(status))
	{
		DbgPrint("EPROCESS Error");
		return 0;
	} 
	
	DbgPrint("EPROCESS 0x%0.8X",pEprocess);

	PsGetVersion(NULL, NULL, &current_build, NULL); 

	// if (current_build == 2195)  ans = 0; 当前不支持Windows 2000   
	if (current_build == 2600)  ans = 0x138;   //Windows XP
	if (current_build == 3790)  ans = 0x124;   //Windows 2003

	if( !MmIsAddressValid( (PULONG)( (ULONG)pEprocess+ans ) ) )//EPROCESS+0x138 -> SectionObject

	{   DbgPrint("SectionObject Error");
		return 0;
	} 
	
	Object = (PVOID)(*(PULONG)((ULONG)pEprocess+ans));

	if( !MmIsAddressValid( (PULONG)( (ULONG)Object+0x014 ) ) )//SectionObject+0x014 -> Segment
	{
		DbgPrint("Segment Error");
		return 0;
	} 
	
	Object = (PVOID)(*(PULONG)( (ULONG)Object+0x014 ));

	if( !MmIsAddressValid( (PULONG)((ULONG)Object+0x000) ) )//Segment+0x000 -> ControlAera
	{
		DbgPrint("ControlAera Error");
		return 0;
	} 
	
	Object = (PVOID)(*(PULONG)( (ULONG)Object+0x000 ));

	if( !MmIsAddressValid( (PULONG)( (ULONG)Object+0x024 ) ) )//ControlAera+0x024 -> FilePointer(FileObject)
	{
		DbgPrint("FilePointer Error");
		return 0;
	} 
	
	DbgPrint("++++++++++PsGetProcessPathByPid函数已经成功执行了最重要的那部分\n");

	Object = (PVOID)(*(PULONG)( (ULONG)Object+0x024 ));

	FileObject = Object;
	ObReferenceObjectByPointer((PVOID)FileObject,0,NULL,KernelMode);

	RtlInitUnicodeString(&uni_path,FileObject->FileName.Buffer); //获取路径名
	RtlVolumeDeviceToDosName(FileObject->DeviceObject,&uni_disk); //获取盘符名
	ObDereferenceObject(FileObject);

	if( wcslen(uni_path.Buffer)+wcslen(uni_disk.Buffer) < MAXPATHLEN+10  )
	{
		wcscat(FilePath,uni_disk.Buffer);
		wcscat(FilePath,uni_path.Buffer);

	}
	else 
	{
		wcscat(FilePath,uni_disk.Buffer);
		wmemcpy(FilePath,uni_path.Buffer,MAXPATHLEN-wcslen(uni_disk.Buffer)-1);

		*(FilePath + MAXPATHLEN) = 0;
	}

	DbgPrint("Leave  PsGetProcessPathByPid()函数\n");

	return 1;
}




ULONG GetPlantformDependentInfo(ULONG dwFlag)   
{    
	ULONG current_build;    
	ULONG ans = 0;    

	PsGetVersion(NULL, NULL, &current_build, NULL);    

	
	switch ( dwFlag )   
	{    
	case EPROCESS_SIZE:    
		if (current_build == 2195) ans = 0 ;        // Windows 2000，当前不支持2000，下同   
		if (current_build == 2600) ans = 0x25C;     // Windows XP   
		if (current_build == 3790) ans = 0x270;     // Windows 2003   
		break;    
	case PEB_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x1b0;    
		if (current_build == 3790)  ans = 0x1a0;   
		break;    
	case FILE_NAME_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x174;    
		if (current_build == 3790)  ans = 0x164;   
		break;    
	case PROCESS_LINK_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x088;    
		if (current_build == 3790)  ans = 0x098;   
		break;    
	case PROCESS_ID_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x084;    
		if (current_build == 3790)  ans = 0x094;   
		break;    
	case EXIT_TIME_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x078;    
		if (current_build == 3790)  ans = 0x088;   
		break;    
	}    
	return ans;    
}



//=============================================================================================//
//Name: NTSTATUS GetProcessPath()													           //
//                                                                                             //
//Descripion: 根据Windows内核进程的数据结构体EPROCESS来获取进程路径				               //
//            				                            						               //
//=============================================================================================//
VOID GetProcessPath(ULONG eprocess, PUNICODE_STRING pFilePath)
{
	ULONG object;
	ULONG current_build;    
	ULONG ans = 0;  

	PFILE_OBJECT	FilePointer;
	UNICODE_STRING	name;  //盘符

	DbgPrint("Enter GetProcessPath函数\n");

	PsGetVersion(NULL, NULL, &current_build, NULL);    

	// if (current_build == 2195)  ans = 0; 当前不支持Windows2000   
	 if (current_build == 2600)  ans = 0x138; //Windows XP   
	 if (current_build == 3790)  ans = 0x124; //Windows 7 


	if(MmIsAddressValid((PULONG)(eprocess + ans)))// EPROCESS -> SectionObject
	{
		object = (*(PULONG)(eprocess + ans));
		
		if(MmIsAddressValid((PULONG)((ULONG)object + 0x014)))// SECTION_OBJECT -> Segment
		{
			object = *(PULONG)((ULONG)object + 0x014);
				
			if(MmIsAddressValid((PULONG)((ULONG)object + 0x0)))// SEGMENT_OBJECT -> ControlArea 不是0x018
			{
				object = *(PULONG)((ULONG_PTR)object + 0x0);
				
				if(MmIsAddressValid((PULONG)((ULONG)object + 0x024)))// CONTROL_AREA -> FilePointer
				{
					object=*(PULONG)((ULONG)object + 0x024);
				}
				else 
				{ 
					DbgPrint("Leave GetProcessPath函数\n");
					return;
				}
				
			}
			else
			{
				DbgPrint("Leave GetProcessPath函数\n");
				return;
			} 
		}
		else 
		{
			DbgPrint("Leave GetProcessPath函数\n");
			return;
		}
	}
	else
	{
		DbgPrint("Leave GetProcessPath函数\n");
		return;

	} 
	FilePointer = (PFILE_OBJECT)object;

	ObReferenceObjectByPointer((PVOID)FilePointer,0,NULL,KernelMode);
	RtlVolumeDeviceToDosName(FilePointer->DeviceObject, &name); //获取盘符名
	RtlCopyUnicodeString(pFilePath, &name); //盘符连接
	RtlAppendUnicodeStringToString(pFilePath, &FilePointer->FileName); //路径连接
	ObDereferenceObject(FilePointer);		//关闭对象引用

	DbgPrint("Leave GetProcessPath函数\n");

}



//==================================================================================================//
//Name: VOID ProcessNotifyRoutine()													                //
//                                                                                                  //
//Descripion: 用来监控，在Windows系统运行的时候，有哪些新的进程被创建，以及有哪些进程被退出		    //
//            				                            						                    //
//==================================================================================================//
VOID ProcessNotifyRoutine(
						  IN HANDLE	ParentId,
						  IN HANDLE	ProcessId,
						  IN BOOLEAN	Create
						  )
{
	NTSTATUS		status = STATUS_SUCCESS;
	PEPROCESS		pEprocess = NULL;
	UNICODE_STRING 	uniPath;
	ULONG  i,j,uPid;

	uniPath.Length = 0;
	uniPath.MaximumLength = MAXPATHLEN * 2;
	uniPath.Buffer = (PWSTR)ExAllocatePool(NonPagedPool, uniPath.MaximumLength);


	DbgPrint("Enter ProcessNotifyRoutine函数\n");

	// 创建进程
	if (Create)
	{
		DbgPrint("*******----有----新----进----程----创----建----*******\r\n");
		// 父进程
		// DbgPrint("父进程信息\r\n");
		// DbgPrint("        PID:  %d\r\n", ParentId);
		// status = PsLookupProcessByProcessId(ParentId, &pEprocess);
		// if (NT_SUCCESS(status))
		// {
		// GetProcessPath(pEprocess, &uniPath);
		// DbgPrint("        路径: %wZ\r\n", &uniPath);
		// }
		
		DbgPrint("创建进程信息\r\n");
		DbgPrint("        进程PID:  %d\r\n", ProcessId);
		status = PsLookupProcessByProcessId(ProcessId, &pEprocess);
		if (NT_SUCCESS(status))
		{
			GetProcessPath((ULONG)pEprocess, &uniPath);
			DbgPrint("        进程路径: %wZ\r\n", &uniPath);
		}
	}
	// 结束进程
	else
	{
		DbgPrint("*******----有----旧----进----程----退----出----*******\r\n");
		// 父进程
		//DbgPrint("父进程信息\r\n");
		//DbgPrint("        PID:  %d\r\n", ParentId);
		//status = PsLookupProcessByProcessId(ParentId, &pEprocess);
		//if (NT_SUCCESS(status))
		//{
		//	GetProcessPath(pEprocess, &uniPath);
		//	DbgPrint("        路径: %wZ\r\n", &uniPath);
		//}
		// 进程
		DbgPrint("退出进程信息\r\n");
		DbgPrint("        进程PID:  %d\r\n", ProcessId);
		status = PsLookupProcessByProcessId(ProcessId, &pEprocess);
		if (NT_SUCCESS(status))
		{
			GetProcessPath(pEprocess, &uniPath);
			DbgPrint("        进程路径: %wZ\r\n", &uniPath);
		}

		for(i=0;i<CurrentProcessCount;i++)
		{
			uPid=processInfoArray[i].pid;

			if(uPid ==ProcessId)
			{
				//这里要删除processInfoArray数组里面对应的元素
				for(j=i;j<CurrentProcessCount-1;j++)
				{
					//数组中的每一个元素往前移动
					processInfoArray[j].pid=processInfoArray[j+1].pid;
					wcscpy(processInfoArray[j].psPath,processInfoArray[j+1].psPath);
					//strcpy(processInfoArray[j].psPath,processInfoArray[j+1].psPath);
				}

				//数组最后一个元素的值设置为空值
				processInfoArray[j].pid=0;
				//memset(processInfoArray[j].psPath,0,sizeof(processInfoArray[j].psPath));
				wmemset(processInfoArray[j].psPath,0,sizeof(processInfoArray[j].psPath)/sizeof(WCHAR));

				CurrentProcessCount--;
				DbgPrint("-----退出一个进程后剩下的进程还有-----\n");
				for(j=0;j<CurrentProcessCount;j++)
				{
					DbgPrint("进程ID %d\n",processInfoArray[j].pid);
					DbgPrint("进程路径 %S\n",processInfoArray[j].psPath);
				}
				break;
			}
		}
	}
	ExFreePool(uniPath.Buffer);

	DbgPrint("Leave ProcessNotifyRoutine函数\n");
}



ULONG EnumProcessList()
{
	PROCESS_INFO     ProcessInfo = {0};
	ULONG            EProcess;
	ULONG            FirstProcess;
	ULONG            dwCount = 0;
	LIST_ENTRY*      ActiveProcessLinks;

	ULONG    dwPIdOffset = GetPlantformDependentInfo(PROCESS_ID_OFFSET);
	ULONG    dwPNameOffset = GetPlantformDependentInfo(FILE_NAME_OFFSET);
	ULONG    dwPLinkOffset = GetPlantformDependentInfo(PROCESS_LINK_OFFSET);

	DbgPrint("Enter EnumProcessList函数\n");

	DbgPrint("PidOff=0x%X  NameOff=0x%X  LinkOff=0x%X", dwPIdOffset, dwPNameOffset, dwPLinkOffset);



	// 获取当前进程的地址
	FirstProcess = EProcess = (ULONG)PsGetCurrentProcess();

	do
	{
		ProcessInfo.dwProcessId = *((ULONG *)(EProcess + dwPIdOffset));
		ProcessInfo.pImageFileName= (PUCHAR)(EProcess + dwPNameOffset);

		dwCount++;


		if(ProcessInfo.dwProcessId<=0 || ProcessInfo.dwProcessId==4) //不统计进程号是0或者进程号是4的进程
		{ 
			dwCount--;

			ActiveProcessLinks = (LIST_ENTRY *)(EProcess + dwPLinkOffset);		
			EProcess = (ULONG)ActiveProcessLinks->Flink - dwPLinkOffset;

		} 
		else
		{
			DbgPrint("[Pid=%6d] %s ", ProcessInfo.dwProcessId, ProcessInfo.pImageFileName);

			ActiveProcessLinks = (LIST_ENTRY *)(EProcess + dwPLinkOffset);		
			EProcess = (ULONG)ActiveProcessLinks->Flink - dwPLinkOffset;

		}


		if (EProcess == FirstProcess)
		{
			break;
		}
	}while (EProcess != 0);


	return dwCount;
}


unsigned long __fastcall SizeOfCode(void *Code, unsigned char **pOpcode)
{
	PUCHAR cPtr;
	UCHAR Flags;
	BOOLEAN PFX66, PFX67;
	BOOLEAN SibPresent;
	UCHAR iMod, iRM, iReg;
	UCHAR OffsetSize, Add;
	UCHAR Opcode;
	if (!MmIsAddressValid(Code)) return 0;
	OffsetSize = 0;
	PFX66 = FALSE;
	PFX67 = FALSE;
	cPtr = (PUCHAR)Code;
	while ( (*cPtr == 0x2E) || (*cPtr == 0x3E) || (*cPtr == 0x36) ||
		(*cPtr == 0x26) || (*cPtr == 0x64) || (*cPtr == 0x65) || 
		(*cPtr == 0xF0) || (*cPtr == 0xF2) || (*cPtr == 0xF3) ||
		(*cPtr == 0x66) || (*cPtr == 0x67) ) 
	{
		if (*cPtr == 0x66) PFX66 = TRUE;
		if (*cPtr == 0x67) PFX67 = TRUE;
		cPtr++;
		if (cPtr > (PUCHAR)Code + 16) return 0; 
	}
	Opcode = *cPtr;
	if (pOpcode) *pOpcode = cPtr; 
	if (*cPtr == 0x0F)
	{
		cPtr++;
		Flags = OpcodeFlagsExt[*cPtr];
	} else 
	{
		Flags = OpcodeFlags[Opcode];
		if (Opcode >= 0xA0 && Opcode <= 0xA3) PFX66 = PFX67;
	}
	cPtr++;
	if (Flags & OP_WORD) cPtr++;	
	if (Flags & OP_MODRM)
	{
		iMod = *cPtr >> 6;
		iReg = (*cPtr & 0x38) >> 3;  
		iRM  = *cPtr &  7;
		cPtr++;
		if ((Opcode == 0xF6) && !iReg) Flags |= OP_DATA_I8;    
		if ((Opcode == 0xF7) && !iReg) Flags |= OP_DATA_PRE66_67; 
		SibPresent = !PFX67 & (iRM == 4);
		switch (iMod)
		{
		case 0: 
			if ( PFX67 && (iRM == 6)) OffsetSize = 2;
			if (!PFX67 && (iRM == 5)) OffsetSize = 4; 
			break;
		case 1: OffsetSize = 1;
			break; 
		case 2: if (PFX67) OffsetSize = 2; else OffsetSize = 4;
			break;
		case 3: SibPresent = FALSE;
		}
		if (SibPresent)
		{
			if (((*cPtr & 7) == 5) && ( (!iMod) || (iMod == 2) )) OffsetSize = 4;
			cPtr++;
		}
		cPtr = (PUCHAR)(ULONG)cPtr + OffsetSize;
	}
	if (Flags & OP_DATA_I8)  cPtr++;
	if (Flags & OP_DATA_I16) cPtr += 2;
	if (Flags & OP_DATA_I32) cPtr += 4;
	if (PFX66) Add = 2; else Add = 4;
	if (Flags & OP_DATA_PRE66_67) cPtr += Add;
	return (ULONG)cPtr - (ULONG)Code;
}



//得到PsSuspendProcess的地址
ULONG process_getPsSuspendProcessAddress()
{
	UCHAR *cPtr, *pOpcode;
	ULONG ulLength;
	ULONG ulCallCount = 1;

	ULONG ulNtSuspendProcess,ulPsSuspendProcessAddr;

	DbgPrint("******Enter process_getPsSuspendProcessAddress函数******\n");

	__try
	{
        //winXP                                
		//获得ulNtSuspendProcess的地址
		ulNtSuspendProcess = *((PULONG)(KeServiceDescriptorTable.ServiceTableBase) + NtSuspendProcess_XP);

		//调试
		DbgPrint("process_getPsSuspendProcessAddress  ulNtSuspendProcess :%08X",ulNtSuspendProcess);

		/*
		kd> uf nt!NtSuspendProcess
		nt!NtSuspendProcess:
		83ef88d7 8bff            mov     edi,edi
		83ef88d9 55              push    ebp
		83ef88da 8bec            mov     ebp,esp
		83ef88dc 51              push    ecx
		83ef88dd 51              push    ecx
		83ef88de 64a124010000    mov     eax,dword ptr fs:[00000124h]
		83ef88e4 8a803a010000    mov     al,byte ptr [eax+13Ah]
		83ef88ea 56              push    esi
		83ef88eb 6a00            push    0
		83ef88ed 8845f8          mov     byte ptr [ebp-8],al
		83ef88f0 8d45fc          lea     eax,[ebp-4]
		83ef88f3 50              push    eax
		83ef88f4 ff75f8          push    dword ptr [ebp-8]
		83ef88f7 ff350431d883    push    dword ptr [nt!PsProcessType (83d83104)]
		83ef88fd 6800080000      push    800h
		83ef8902 ff7508          push    dword ptr [ebp+8]
		83ef8905 e8fa34f4ff      call    nt!ObReferenceObjectByHandle (83e3be04)
		83ef890a 8bf0            mov     esi,eax
		83ef890c 85f6            test    esi,esi
		83ef890e 7c12            jl      nt!NtSuspendProcess+0x4b (83ef8922)

		nt!NtSuspendProcess+0x39:
		83ef8910 ff75fc          push    dword ptr [ebp-4]
		83ef8913 e837feffff      call    nt!PsSuspendProcess (83ef874f)
		83ef8918 8b4dfc          mov     ecx,dword ptr [ebp-4]
		83ef891b 8bf0            mov     esi,eax
		83ef891d e8a1a3d9ff      call    nt!ObfDereferenceObject (83c92cc3)
		*/
/*
		//获得PsSuspendProcess的地址
		for (cPtr = (PUCHAR)ulNtSuspendProcess; cPtr < (PUCHAR)ulNtSuspendProcess + PAGE_SIZE;) 
		{
			//获得被反汇编的字节数
			ulLength = SizeOfCode(cPtr, &pOpcode);

			//如果反汇编失败的话
			if (ulLength == 0)
			{
				return NULL;
			}

			//机器码E8表示call指令
			if (*pOpcode == 0xE8)
			{
				//第二次调用call指令
				if (ulCallCount == 2)
				{
					ulPsSuspendProcessAddr = (*(PULONG)(pOpcode + 1) + (ULONG)cPtr + 5);
					break;
				}

				ulCallCount ++;
			}

			//迭代
			cPtr = cPtr + ulLength;
		}

		//调试
		DbgPrint("process_getPsSuspendProcessAddress  ulPsSuspendProcessAddr :%08X",ulPsSuspendProcessAddr);

		DbgPrint("******Leave process_getPsSuspendProcessAddress函数******\n");

		//返回地址
		return ulPsSuspendProcessAddr;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("process_getPsSuspendProcessAddress EXCEPTION_EXECUTE_HANDLER error!");
		return NULL;
	}
}



//=========================================================================================================//
//Name: BOOLEAN process_suspendProcess()										                           //
//                                                                                                         //
//Descripion: Hook掉函数NtSuspendProcess，根据进程的ID号来挂起进程                                         //
//            				                            						                           //
//=========================================================================================================//
//挂起进程
BOOLEAN process_suspendProcess(ULONG ulPID)
{
	NTSTATUS status;
	PEPROCESS pEpr;

	DbgPrint("******Enter process_suspendProcess函数******\n");
	__try
	{
		PPsSuspendProcess PsSuspendProcess = (PPsSuspendProcess)process_getPsSuspendProcessAddress();

		if (!PsSuspendProcess)
		{
			DbgPrint("process_suspendProcess process_getPsSuspendProcessAddress error!");
			return FALSE;
		}

		status = PsLookupProcessByProcessId((HANDLE)ulPID,&pEpr);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("process_suspendProcess PsLookupProcessByProcessId error!");
			return FALSE;
		}

		status = PsSuspendProcess(pEpr);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("process_suspendProcess PsSuspendProcess error!");
			return FALSE;
		}


		DbgPrint("******Leave process_suspendProcess函数******\n");

		return TRUE;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("process_suspendProcess EXCEPTION_EXECUTE_HANDLER error!");
		return FALSE;
	}
}

//=========================================================================================================//
//Name: NTSTATUS HookZwCreateFile()                                                                        //
//											                                                               //        
//Descripion: 在受保护的文件目录下  不允许用户创建文件、文件夹、复制、粘贴、剪切                           //
//            				                            						                           //
//=========================================================================================================//
NTSTATUS HookZwCreateFile(
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
						  IN ULONG EaLength)
{

	ANSI_STRING ansiDirName;
	PUNICODE_STRING uniFileName;
	UNICODE_STRING uDirName;

	NTSTATUS rc;
	ULONG i;

	DbgPrint("*********Enter HookZwCreateFile()************\n");

	//将用户操作的路径保存在变量ansiDirName中
	RtlUnicodeStringToAnsiString( &ansiDirName, ObjectAttributes->ObjectName, TRUE);
	_strupr(ansiDirName.Buffer);
	DbgPrint("AnsiDirNameBuffer=%s\n",ansiDirName.Buffer);

	RtlAnsiStringToUnicodeString(&uDirName,&ansiDirName,TRUE); //把ansiDirName转换成UNICODE_STRING类型
	DbgPrint("UnicodeDirName= %wZ\n",&uDirName);

	for(i=0;i<iCountFilePath;i++)
	{
		if(ProtectFilePathArray[i][0]!=NULL && ProtectFilePathArray[i][0]!=0x0)
		{	 	        
			DbgPrint("使用wcsstr函数执行了和数组元素ProtectFilePathArray[i]的比较\n");

			if(wcsstr(uDirName.Buffer,ProtectFilePathArray[i]))//判断ProtectFilePathArray[i]是否是uDirName.Buffer的子串
			{
				DbgPrint("**即将执行return STATUS_ACCESS_DENIED语句，将要离开HookZwCreateFile函数\n");   
				return STATUS_ACCESS_DENIED; 
			}   
		}

	}

	//如果这个不是我们要保护的目录，那么就调用Windows内核自己的ZwCreateFile函数来实现创建文件的过程

	DbgPrint("执行 RealZwCreateFile\n");

	return RealZwCreateFile(
			FileHandle,
			DesiredAccess,
			ObjectAttributes,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength);

}


//=========================================================================================================//
//Name: NTSTATUS HookZwSetInformationFile()                                                                //
//											                                                               //
//Descripion: 禁止用户删除文件、文件夹、重命名，起到文件保护的作用                                         //
//            				                            						                           //
//=========================================================================================================//
NTSTATUS HookZwSetInformationFile(
								  IN HANDLE  FileHandle,
								  OUT PIO_STATUS_BLOCK  IoStatusBlock,
								  IN PVOID  FileInformation,
								  IN ULONG  Length,
								  IN FILE_INFORMATION_CLASS  FileInformationClass
								  )

{
	PFILE_OBJECT pFileObject;
	NTSTATUS ret;
	ULONG i;

	UNICODE_STRING uDosName={0};
	UNICODE_STRING pFilePath={0};

	pFilePath.MaximumLength=MAXPATHLEN*2;
	pFilePath.Buffer=(PWSTR)ExAllocatePool(PagedPool,MAXPATHLEN*2);

	uDosName.MaximumLength=40;
	uDosName.Buffer=(PWSTR)ExAllocatePool(PagedPool,40);

	ret = ObReferenceObjectByHandle(FileHandle, GENERIC_READ,*IoFileObjectType,
									KernelMode, (PVOID*)&pFileObject, 0);

	DbgPrint("*********Enter HookZwSetInformationFile()*********\n");

	if (NT_SUCCESS(ret))
	{
		ret=IoVolumeDeviceToDosName(pFileObject->DeviceObject, &uDosName); //获取盘符名
		RtlCopyUnicodeString(&pFilePath, &uDosName); //连接盘符    
		RtlAppendUnicodeStringToString(&pFilePath,&(pFileObject->FileName));//连接盘符和路径

		DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		DbgPrint("pFilePath: %wZ\n",&pFilePath); 
		DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

		if (NT_SUCCESS(ret))
		{
			RtlUpcaseUnicodeString(&pFilePath,&pFilePath,FALSE);
			DbgPrint("转换成大写后的pFilePath:  %wZ\n",&pFilePath);
			DbgPrint("ProtectFilePath: %S\n",ProtectFilePath);

			for(i=0;i<iCountFilePath;i++)
			{
				if(ProtectFilePathArray[i][0]!=NULL && ProtectFilePathArray[i][0]!=0x0)
				{
					if(wcsstr(pFilePath.Buffer,ProtectFilePathArray[i]))//判断ProtectFilePathArray[i]是否是pFilePath.Buffer的子串
					{  
						RtlFreeUnicodeString(&pFilePath);
						RtlFreeUnicodeString(&uDosName);

						DbgPrint("**即将执行return STATUS_ACCESS_DENIED语句，将要离开Leave HookZwSetInformationFile()\n");
						return STATUS_ACCESS_DENIED;
					}
				}
			} 
		}
	}

	if (pFileObject)
	{
		ObDereferenceObject(pFileObject);
	}

	if(pFilePath.Buffer[0]!=NULL && pFilePath.Buffer[0]!=0x0)
	{
		RtlFreeUnicodeString(&pFilePath);
	}

	if(uDosName.Buffer[0]!=NULL && uDosName.Buffer[0]!=0x0)
	{
		RtlFreeUnicodeString(&uDosName);
	}

	DbgPrint("*********Leave HookZwSetInformationFile()*********\n");

	return RealZwSetInformationFile(FileHandle, 
			IoStatusBlock,
			FileInformation,
			Length,
			FileInformationClass);

}


//=========================================================================================================//
//Name: NTSTATUS HookZwCreateKey()                                                                         //
//											                                                               //
//Descripion:在公司的软件产品所对应的注册表项下面，禁止用户创建注册表项、键值                              //
//            				                            						                           //
//=========================================================================================================//

NTSTATUS HookZwCreateKey(
						 OUT PHANDLE  KeyHandle,
						 IN ACCESS_MASK  DesiredAccess,
						 IN POBJECT_ATTRIBUTES  ObjectAttributes,
						 IN ULONG  TitleIndex,
						 IN PUNICODE_STRING  Class  OPTIONAL,
						 IN ULONG  CreateOptions,
						 OUT PULONG  Disposition  OPTIONAL
						 )

{

	ULONG i;
	ULONG actualLen;
	UNICODE_STRING *pUniName; 
	NTSTATUS rc;
	PVOID Object;
	WCHAR str[REGISTRY_DATA_MAXLEN]={0}; //这个WCHAR类型变量str是用来存放我们建立的注册表的表项

	DbgPrint("******Enter HookZwCreateKey()******\n");

	//ObjectAttributes->ObjectName是新建立的注册表 表项的路径，但它不是完整的路径，它只是路径的后半部分
	DbgPrint("你新建立的注册表的表项的路径是:   %wZ\n",ObjectAttributes->ObjectName); 
	
	RtlUpcaseUnicodeString(ObjectAttributes->ObjectName,ObjectAttributes->ObjectName,FALSE);
	DbgPrint("ObjectName转换成大写后的值是:   %wZ\n",ObjectAttributes->ObjectName);
	DbgPrint("-- RootDirectory 0x%X\n", ObjectAttributes->RootDirectory);

	pUniName = ExAllocatePool( NonPagedPool, 512*2+2*sizeof(ULONG));
	pUniName->MaximumLength = 512*2;


	if(ObjectAttributes->RootDirectory != 0) 
	{
		rc=ObReferenceObjectByHandle(ObjectAttributes->RootDirectory,0,0,KernelMode,&Object,NULL);
		if (rc==STATUS_SUCCESS) 
		{
			if( NT_SUCCESS( ObQueryNameString(Object, pUniName, MAXPATHLEN, &actualLen)))
			{
				DbgPrint("In CreateKey Path is  %wZ\n",pUniName); //这是路径的前半部分
			}
			ObDereferenceObject(Object);
			wcscpy(str,pUniName->Buffer);
			wcscat(str,"\\");
			wcscat(str,ObjectAttributes->ObjectName->Buffer);
			_wcsupr(str);
			DbgPrint("合并后的注册表路径是    %S\n",str); 

			//接下来在for循环体里面做2个注册表路径的比较操作。
			//其中一个路径是：应用层里面通过DeviceioControl函数传递下来的。另外一个路径是：我在这里保存的字符串str里面的值。
			//在这里我应该对它们做strstr或wcsstr的比较操作。

			for(i=0;i<iCountRegistryPath;i++)
			{
				if(ProtectKeyDirectoryArray[i]!=NULL && ProtectKeyDirectoryArray[i][0]!=0x0)
				{
					if(wcsstr(str,ProtectKeyDirectoryArray[i]))
					{
						DbgPrint("这里调用了 return STATUS_ACCESS_DENIED语句 即将离开HookZwCreateKey()\n");
						DbgPrint("*******Leave HookZwCreateKey()*******\n");
						ExFreePool(pUniName);
						return STATUS_ACCESS_DENIED;
					}
				}
			}//end for

		}//end  if(rc==STATUS_SUCCESS)
	}

	ExFreePool(pUniName);

	DbgPrint("******Leave HookZwCreateKey()******\n");

	return  RealZwCreateKey(
				KeyHandle,
				DesiredAccess,
				ObjectAttributes,
				TitleIndex,
				Class,
				CreateOptions,
				Disposition 
				);
	
}


//=========================================================================================================//
//Name: NTSTATUS HookZwDeleteValueKey()                                                                    //
//											                                                               //
//Descripion:在公司的软件产品所对应的注册表项下面，禁止用户删除注册表键值                                  //
//            				                            						                           //
//=========================================================================================================//
NTSTATUS HookZwDeleteValueKey(IN HANDLE KeyHandle,PUNICODE_STRING ValueName)
{      
	NTSTATUS nStatus = STATUS_SUCCESS;
	UNICODE_STRING yyo;
	UNICODE_STRING dut;
	ANSI_STRING tbb;
	ULONG i;

	DbgPrint("*******Enter HookZwDeleteValueKey()*******\n");

	RtlUnicodeStringToAnsiString(&tbb,ValueName,TRUE); //把截获系统要删除的注册表的键名给字符串
	RtlAnsiStringToUnicodeString(&dut,&tbb,TRUE);      //把 tbb 转换为UNICODE_STRING 
	for(i=0;i<iCountRegistryKey;i++)
	{
		if(ProtectKeyArray[i][0]!=NULL && ProtectKeyArray[i][0]!=0x0 )
		{
			RtlInitUnicodeString(&yyo,ProtectKeyArray[i]); //初始化字符串赋予 

			if(RtlEqualUnicodeString(&yyo,&dut,TRUE))  //判断系统要删除的键名是否是我们要保护的
			{
				DbgPrint("这里调用了 return STATUS_ACCESS_DENIED语句 即将离开HookZwDeleteValueKey()\n");
				DbgPrint("*******Leave HookZwDeleteValueKey()*******\n");
				return STATUS_ACCESS_DENIED; 
			}

		}
	}

	//如果这个不是我们保护的目录，那么就调用Windows内核自己的ZwDeleteValueKey函数	  
	DbgPrint("调用 RealZwDeleteValueKey()\n");
	nStatus = RealZwDeleteValueKey(KeyHandle,ValueName); 

	DbgPrint("*******Leave HookZwDeleteValueKey()*******\n");

	return nStatus;
}


//=========================================================================================================//
//Name: NTSTATUS HookZwDeleteKey()                                                                         //
//											                                                               //
//Descripion:在公司的软件产品所对应的注册表项下面，禁止用户删除注册表的表项                                //
//            				                            						                           //
//=========================================================================================================//
NTSTATUS HookZwDeleteKey(IN HANDLE KeyHandle)
{
	NTSTATUS rc;
	UNICODE_STRING *pUniName;  //定义得到修改注册表的UNI路径
	ULONG actualLen;   
	ULONG i;  
	PVOID pKey;
	UNICODE_STRING  KeyValueData={0};//它是当前获取到的注册表目录

	DbgPrint("*******Enter HookZwDeleteKey()*******\n");

	KeyValueData.Buffer=(PWSTR)ExAllocatePool(NonPagedPool,512*2+2*sizeof(ULONG));
	KeyValueData.MaximumLength = 512*2;

	pKey = GetPointer( KeyHandle);

	if(pKey)
	{
		pUniName = ExAllocatePool( NonPagedPool, 512*2+2*sizeof(ULONG));
		pUniName->MaximumLength = 512*2;

		if( NT_SUCCESS( ObQueryNameString( pKey, pUniName, MAXPATHLEN, &actualLen)))
		{	
			RtlCopyUnicodeString(&KeyValueData,pUniName);

			for(i=0;i<iCountRegistryPath;i++)
			{
				if(ProtectKeyDirectoryArray[i]!=NULL && ProtectKeyDirectoryArray[i][0]!=0x0)
				{
					//比较当前获取到的注册表目录是否 等于 从应用层传递下来的注册表目录
					DbgPrint("===这里调用_wcsicmp函数用来比较注册表的目录是否等于从应用层传递下来的注册表目录\n");

					if(_wcsicmp(KeyValueData.Buffer,ProtectKeyDirectoryArray[i])==0)
					{
						DbgPrint("这里调用了 return STATUS_ACCESS_DENIED语句 即将离开HookZwDeleteKey()\n");
						DbgPrint("*******Leave HookZwDeleteKey()*******\n");
						ExFreePool(pUniName);
						RtlFreeUnicodeString(&KeyValueData);
						return STATUS_ACCESS_DENIED;
					}
				}
			}//end for
		}

	} //end if(pKey)

	ExFreePool(pUniName);
	//RtlFreeUnicodeString(pUniName);
	RtlFreeUnicodeString(&KeyValueData);

	if(pKey)  
	{
		ObDereferenceObject(pKey);
	}

	DbgPrint("调用 RealZwDeleteKey()\n");

	rc=RealZwDeleteKey(KeyHandle);

	DbgPrint("*******Leave HookZwDeleteKey()*******\n");

	return rc;

}


//=========================================================================================================//
//Name: NTSTATUS HookZwSetValueKey()                                                                       //
//											                                                               //
//Descripion:在公司的软件产品所对应的注册表项下面，禁止用户修改注册表的表项以及键值                        //
//            				                            						                           //
//=========================================================================================================//
NTSTATUS HookZwSetValueKey( IN HANDLE  KeyHandle,
						   IN PUNICODE_STRING  ValueName,
						   IN ULONG  TitleIndex  OPTIONAL,
						   IN ULONG  Type,
						   IN PVOID  Data,
						   IN ULONG  DataSize)

{
	
	NTSTATUS rc;
	UNICODE_STRING *pUniName;  //定义得到修改注册表的UNI路径
	ULONG actualLen;
	ULONG i;
	PVOID pKey;
	UNICODE_STRING  keyname={0};

	DbgPrint("*******Enter HookZwSetValueKey()*******\n");

	keyname.Buffer=(PWSTR)ExAllocatePool(NonPagedPool,512*2+2*sizeof(ULONG));
	keyname.MaximumLength = 512*2;

	pKey = GetPointer( KeyHandle);

	if(pKey)
	{
		pUniName = ExAllocatePool( NonPagedPool, 512*2+2*sizeof(ULONG));
		pUniName->MaximumLength = 512*2;

		if( NT_SUCCESS( ObQueryNameString( pKey, pUniName, MAXPATHLEN, &actualLen)))
		{
			RtlCopyUnicodeString( &keyname, pUniName, TRUE);
			DbgPrint("===在这里调用_wcsicmp函数用来比较注册表的键值是否等于从应用层传递下来的键值 \n");

			for(i=0;i<iCountRegistryPath;i++)
			{
				if(ProtectKeyDirectoryArray[i]!=NULL && ProtectKeyDirectoryArray[i][0]!=0x0)
				{  
					if(_wcsicmp(keyname.Buffer,ProtectKeyDirectoryArray[i]) == 0)
					{
						DbgPrint("这里调用了 return STATUS_ACCESS_DENIED语句 即将离开HookZwSetValueKey()\n");
						DbgPrint("*******Leave HookZwSetValueKey()*******\n");
						ExFreePool(pUniName);
						RtlFreeUnicodeString(&keyname); 
						return STATUS_ACCESS_DENIED;    
					}
				}
			}
		}

	}//end if(pKey)

	if(pKey)  
	{
		ObDereferenceObject(pKey);
	}

	ExFreePool(pUniName);
	RtlFreeUnicodeString(&keyname); 

	DbgPrint("调用 RealZwSetValueKey()\n");
	rc=RealZwSetValueKey(KeyHandle,ValueName,TitleIndex,Type,Data,DataSize);

	DbgPrint("*******Leave HookZwSetValueKey()*******\n");

	return rc;
	
}*/



//=========================================================================================================//
//Name: NTSTATUS HookNtQuerySystemInformation()                                                            //
//											                                                               //
//Descripion: 用户指定的、正在Windows系统运行的进程 将被隐藏                                               //
//            				                            						                           //
//=========================================================================================================//
NTSTATUS HookNtQuerySystemInformation (
									   __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
									   __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
									   __in ULONG SystemInformationLength,
									   __out_opt PULONG ReturnLength
									   )
{
	
	NTSTATUS rtStatus=STATUS_SUCCESS;
	NTSTATUS hThreadStatus;
	HANDLE hSystemHandle;
	ULONG ulSize = 0x1000;
	PVOID pBuffer;
	NTSTATUS status;
	//保存进程信息的结构体指针
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation;

	ULONG uPID; 
	UNICODE_STRING ProcessName;
	int inRt=-1;

	DbgPrint("*********Enter HookNtQuerySystemInformation()*********\n");

	rtStatus = pOldNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if(NT_SUCCESS(rtStatus))
	{
		if(SystemProcessInformation== SystemInformationClass)
		{
			PSYSTEM_PROCESS_INFORMATION pPrevProcessInfo = NULL;
			PSYSTEM_PROCESS_INFORMATION pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation; 

			while(pCurrProcessInfo != NULL)
			{
				//获取当前遍历的 SYSTEM_PROCESS_INFORMATION 节点的进程名称和进程 ID
			
				 uPID = (ULONG)pCurrProcessInfo->UniqueProcessId;

				// RtlInitUnicodeString(&ProcessName, L"HavkAv.exe");
				// if(!RtlCompareUnicodeString(&ProcessName, &(pCurrProcessInfo->ImageName), TRUE))
				//{
				//	KdPrint(("HookNtQuerySystemInformation------------------>>>>>>>>>>>\n"));
				//	//ZwTerminateProcess((HANDLE)uPID,0);
			
				//	return STATUS_ACCESS_DENIED;
				//}

				//hThreadStatus=PsCreateSystemThread(&hSystemHandle,0,NULL,NULL,NULL,SystemThread, (PVOID)uPID);

				//判断当前遍历的这个进程是否为需要隐藏的进程
				KeAcquireSpinLock(&HideSpinLock,&HideIrql);
				inRt=ValidateProcessNeedHide(uPID);
				KeReleaseSpinLock(&HideSpinLock,HideIrql);

				if(inRt != -1)
				{
					if(pPrevProcessInfo)
					{
						if(pCurrProcessInfo->NextEntryOffset)
						{
							//将当前这个进程(即要隐藏的进程)从 SystemInformation 中摘除(更改链表偏移指针实现)
							pPrevProcessInfo->NextEntryOffset += pCurrProcessInfo->NextEntryOffset;
						}
						else
						{
							//说明当前要隐藏的这个进程是进程链表中的最后一个
							pPrevProcessInfo->NextEntryOffset = 0;
						}
					}
					else
					{
						//第一个遍历到得进程就是需要隐藏的进程
						if(pCurrProcessInfo->NextEntryOffset)
						{
							(PCHAR)SystemInformation += pCurrProcessInfo->NextEntryOffset;
						}
						else
						{
							SystemInformation = NULL;
						}
					}
				}

				//遍历下一个 SYSTEM_PROCESS_INFORMATION 节点
				pPrevProcessInfo = pCurrProcessInfo;

				//遍历结束
				if(pCurrProcessInfo->NextEntryOffset)
				{
					pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)(((PCHAR)pCurrProcessInfo) + pCurrProcessInfo->NextEntryOffset);
				}
				else
				{
					pCurrProcessInfo = NULL;
				}
			}//End while
		}
	}

	DbgPrint("*********Leave HookNtQuerySystemInformation()*********\n");

	return rtStatus;
}



/*
//====================================================================================================//
//Name: NTSTATUS HookZwOpenProcess()                                                                  //
//											                                                          //
//Descripion: 获取用户正在Windows系统运行的进程的ID号和进程的路径,把它们传递给应用层                  //
//            				                            						                      //
//====================================================================================================//
NTSTATUS HookZwOpenProcess(OUT PHANDLE ProcessHandle,
						   IN ACCESS_MASK DesiredAccess,
						   IN POBJECT_ATTRIBUTES ObjectAttributes,
						   IN PCLIENT_ID ClientId OPTIONAL)

{

	/* Windows内核结构的定义
	typedef struct _CLIENT_ID
	{
	PVOID UniqueProcess;
	PVOID UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;
	*/
/*
	NTSTATUS nStatus = STATUS_SUCCESS;
    WCHAR    fullname[MAXPATHLEN]={0};
	ULONG uPID;
	ULONG rt;

	ULONG i;
    ULONG flag=0;

//	DbgPrint("*********Enter HookZwOpenProcess()*********\n");

	nStatus = RealZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
	
	if(ClientId!=NULL)  //保存一个进程的ID
	{
		uPID=(long)ClientId->UniqueProcess;
	}

// 	DbgPrint("在HookZwOpenProcess里面进程的ID是：%d\n",uPID);

	if((uPID!=0)  &&  (uPID!=4))
	{
		rt=PsGetProcessPathByPid(uPID, fullname); //根据进程的ID号uPID来获取这个进程的路径
	
		if(!rt){ goto label; }


		//全局变量CurrentProcessCount保存了当前系统中有多少个进程在运行

		if(CurrentProcessCount==0) //表示Windows系统第一次进入HookZwOpenProcess函数的代码体里面
		{
			processInfoArray[CurrentProcessCount].pid=uPID;
			wcscpy(processInfoArray[CurrentProcessCount].psPath,fullname);
		}

		for( i=0; (i<CurrentProcessCount) && (CurrentProcessCount<MAXPROCESSCOUNT); i++)
		{
			
			//如果预先保存在数组processInfoArray里面的信息和刚刚抓取出来的信息相同
			//那么就 执行break语句，来退出for循环体。
			if( (processInfoArray[i].pid == uPID) &&				 
				(_wcsicmp(processInfoArray[i].psPath,fullname) == 0) 				
			  )

			{
				
				 //在for循环里面进行信息比对判断以后，若都没有发现相等的值，那么会执行CurrentProcessCount++
				 //因此，我这里做自减操作，是为了保持平衡。
				
				CurrentProcessCount--;
				break;
			}
			else 
			{
				if(i==(CurrentProcessCount-1)) //比较到了processInfoArray数组的最后一个元素
				{
				  
				//我在这里设置了flag=1，表示的是: 在数组processInfoArray里面一直都没有找到相同的值，于是就退出了for循环体
					flag=1; 
				}
				else  continue;
			}

		}

		if(flag==1) 
		{
			//把新获得的进程ID号和进程路径保存到全局数组里面
			processInfoArray[CurrentProcessCount].pid=uPID;
			wcscpy(processInfoArray[CurrentProcessCount].psPath,fullname);
		}

		//计数器累加
		CurrentProcessCount++;

		for(i=0;i<CurrentProcessCount;i++)
		{
			DbgPrint("进程的ID号processInfoArrayPid： %d\n",processInfoArray[i].pid);
			DbgPrint("$$$$$$$$$$$$进程的Full Path Name 是: %S\n", processInfoArray[i].psPath);
		}

		if(CurrentProcessCount==MAXPROCESSCOUNT) //数组元素个数超过许可的最大值
		{
			CurrentProcessCount=0;
		}

		
		
		//路径的最大长度我在代码里面限定为1024个字节，当每一次在获取路径时，都是使用strcat函数来连接，
		//这样不停地使用strcat函数来连接字符串可能会超过1024字节。因此使用memset函数来清空fullname数组里面的值。
		
		wmemset(fullname,0,sizeof(fullname)/sizeof(WCHAR));
		//memset(fullname,0,sizeof(fullname));
	}


label:

//	DbgPrint("*********Leave HookZwOpenProcess()*********\n");

	return nStatus;
}
*/


//=========================================================================================================//
//Name: NTSTATUS HookZwTerminateProcess()                                                                  //
//											                                                               //
//Descripion: 用户指定的、正在Windows系统运行的进程 将被保护起来，禁止结束                                 //
//            				                            						                           //
//=========================================================================================================//
NTSTATUS HookZwTerminateProcess(
								IN HANDLE ProcessHandle,
								IN NTSTATUS ExitStatus
								)
{
	ULONG uPID;
	NTSTATUS rtStatus;
	PCHAR pStrProcName;
	PEPROCESS pEProcess;
	ANSI_STRING strProcName;

	//	DbgPrint("*********Enter HookZwTerminateProcess()*********\n");
	
	//通过进程句柄来获得该进程所对应 FileObject对象，由于这里是进程对象，自然获得的是 EPROCESS 对象
	rtStatus = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, &pEProcess, NULL);
	if(!NT_SUCCESS(rtStatus))
	{
		rtStatus = pOldNtTerminateProcess(ProcessHandle, ExitStatus);
		return rtStatus;
	}

	//通过该函数可以获取到进程名称和进程 ID，该函数在内核中实质是导出的(在 WRK 中可以看到)
	//但是 ntddk.h 中并没有到处，所以需要自己声明才能使用
	uPID = (ULONG)PsGetProcessId(pEProcess);
	//pStrProcName = (PCHAR)PsGetProcessImageFileName(pEProcess);
	//通过进程名来初始化一个 ASCII 字符串
	//RtlInitAnsiString(&strProcName, pStrProcName);

	KeAcquireSpinLock(&PotectSpinLock,&PotectIrql);
	if(ValidateProcessNeedProtect(uPID) != -1)
	{
		//确保调用者进程能够结束(这里主要是指 taskmgr.exe)
		if(uPID != (ULONG)PsGetProcessId(PsGetCurrentProcess()))
		{
			//如果该进程是所保护的进程，则返回权限不够的异常即可
			KeReleaseSpinLock(&PotectSpinLock,PotectIrql);
			return STATUS_ACCESS_DENIED;
		}
	}
	KeReleaseSpinLock(&PotectSpinLock,PotectIrql);
	
	//对于非保护的进程可以直接调用原来 SSDT 中的 NtTerminateProcess 来结束进程
	rtStatus = pOldNtTerminateProcess(ProcessHandle, ExitStatus);

	//	DbgPrint("*********Leave HookZwTerminateProcess()*********\n");

	return rtStatus;
}

/*
//======================================================================================================//
//Name: NTSTATUS HookZwCreateThread()                                                                   //
//											                                                            //
//Descripion: 防止远程注入，Hook掉应用层的CreateRemoteThread函数                                        //
//            				                            						                        //
//======================================================================================================//
NTSTATUS HookZwCreateThread(
							 OUT PHANDLE             ThreadHandle,
							 IN  ACCESS_MASK         DesiredAccess,
							 IN  POBJECT_ATTRIBUTES  ObjectAttributes,
							 IN  HANDLE              ProcessHandle,//它是宿主进程句柄
							 OUT PCLIENT_ID          ClientId,
							 IN  PCONTEXT            ThreadContext,
							 IN  PVOID				UserStack,
							 IN  BOOLEAN             CreateSuspended
							 )
{
	ULONG uPID;
//	ULONG uInjectPid;
	ULONG k;
	PEPROCESS pEProcess;
	NTSTATUS rc;

	rc=STATUS_SUCCESS;

	DbgPrint("*******Enter HookZwCreateThread函数*******----------------------------->\n");
	DbgPrint("存取权限DesiredAccess的值是:    %x\n",DesiredAccess);
	DbgPrint("ProcessHandle的值是:  %x\n",ProcessHandle);
	DbgPrint("ThreadContext是一个上下文参数\n");
	DbgPrint("UserStack的值是:    %x\n",UserStack);


	//通过进程句柄来获得该进程所对应 FileObject对象，由于这里是进程对象，自然获得的是 EPROCESS 对象
	rc = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, &pEProcess, NULL);
	if(!NT_SUCCESS(rc))
	{
		DbgPrint("****ObReferenceObjectByHandle函数调用不成功，即将退出HookZwCreateThread函数****\n");
		return rc;
	}

	uPID = (ULONG)PsGetProcessId(pEProcess); //根据宿主进程的句柄ProcessHandle来得到它的进程ID
	DbgPrint("宿主进程的进程ID:%d", &uPID);

	if(!_stricmp("HavkAv.exe", (PCHAR) pEProcess + g_OffsetEprocessName))			//windows xp 0x174
	{
		KdPrint(("-------------------------------->>>>>>>>>>>"));
		ZwTerminateProcess(ProcessHandle,0);
			
		return STATUS_ACCESS_DENIED;
	}
	if(ValidateProcessNeedProtect(uPID) != -1)		//如果宿主进程uPID 在指定保护进程g_PIDProtectArray中，那么直接返回
	{
		//确保调用者进程能够创建线程
		if(uPID != (ULONG)PsGetProcessId(PsGetCurrentProcess()))
		{
			KdPrint(("-----有恶意程序想要注入保护的进程---"));

			//如果该进程是所保护的进程，则返回权限不够的异常即可
			return STATUS_ACCESS_DENIED;
		}
	}

	//for(k=0; k<g_currProtectArrayLen; k++)		
	//{
	//	if(uPID == g_PIDProtectArray[k++])
	//	{
	//		KdPrint(("-----有恶意程序想要注入保护的进程---"));
	//		return STATUS_ACCESS_DENIED;
	//	}
	//}

	DbgPrint("*******Leave HookZwCreateThread函数*******------------------------------->\n");

	rc=RealZwCreateThread(ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		ClientId,
		ThreadContext,
		UserStack,
		CreateSuspended
		);

	return  rc;
}


//======================================================================================================//
//Name: NTSTATUS HookZwCreateThreadEx() windows 7                                                       //
//											                                                            //
//Descripion: 防止远程注入，Hook掉应用层的CreateRemoteThread函数                                        //
//            				                            						                        //
//======================================================================================================//
NTSTATUS HookZwCreateThreadEx(
								  OUT PHANDLE ThreadHandle,
								  IN ACCESS_MASK DesiredAccess,
								  IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
								  IN HANDLE ProcessHandle,		//它是宿主进程句柄
								  IN PVOID StartRoutine,
								  IN PVOID StartContext,
								  IN ULONG CreateThreadFlags,
								  IN SIZE_T ZeroBits OPTIONAL,
								  IN SIZE_T StackSize OPTIONAL,
								  IN SIZE_T MaximumStackSize OPTIONAL,
								  IN PVOID AttributeList
							 )
{
	ULONG uPID;
//	ULONG uInjectPid;
	ULONG k;
	PEPROCESS pEProcess;
	NTSTATUS rc;

	rc=STATUS_SUCCESS;

	DbgPrint("*******Enter HookZwCreateThreadEx函数*******----------------------------->\n");
	//DbgPrint("存取权限DesiredAccess的值是:    %x\n",DesiredAccess);
	//DbgPrint("ProcessHandle的值是:  %x\n",ProcessHandle);
	//DbgPrint("ThreadContext是一个上下文参数\n");
	//DbgPrint("UserStack的值是:    %x\n",UserStack);


	//通过进程句柄来获得该进程所对应 FileObject对象，由于这里是进程对象，自然获得的是 EPROCESS 对象
	rc = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, &pEProcess, NULL);
	if(!NT_SUCCESS(rc))
	{
		DbgPrint("****ObReferenceObjectByHandle函数调用不成功，即将退出HookZwCreateThread函数****\n");
		return rc;
	}

	uPID = (ULONG)PsGetProcessId(pEProcess); //根据宿主进程的句柄ProcessHandle来得到它的进程ID
	DbgPrint("宿主进程的进程ID:%d\n", &uPID);

	//if( !strncmp( "HavkAv.exe", (PCHAR) pEProcess + 0x16c, strlen("HavkAv.exe") ))
	//{
	//	KdPrint(("-------------------------------->>>>>>>>>>>"));
	//	ZwTerminateProcess(ProcessHandle,0);
	//		
	//	return STATUS_ACCESS_DENIED;
	//}

	if(!_stricmp("HavkAv.exe", (PCHAR) pEProcess + g_OffsetEprocessName))					//windows 7  0x16c
	{
		KdPrint(("-------------------------------->>>>>>>>>>>\n"));
		ZwTerminateProcess(ProcessHandle,0);
			
		return STATUS_ACCESS_DENIED;
	}

	if(ValidateProcessNeedProtect(uPID) != -1)		//如果宿主进程uPID 在指定保护进程g_PIDProtectArray中，那么直接返回
	{
		//确保调用者进程能够创建线程
		if(uPID != (ULONG)PsGetProcessId(PsGetCurrentProcess()))
		{
			KdPrint(("-----有恶意程序想要注入保护的进程---\n"));

			//如果该进程是所保护的进程，则返回权限不够的异常即可
			return STATUS_ACCESS_DENIED;
		}
	}

	//for(k=0; k<g_currProtectArrayLen; k++)		//如果宿主进程uPID 在指定保护进程g_PIDProtectArray中，那么直接返回
	//{
	//	if(uPID == g_PIDProtectArray[k++])
	//	{
	//		KdPrint(("-----有恶意程序想要注入保护的进程---"));
	//		return STATUS_ACCESS_DENIED;
	//	}
	//}

	DbgPrint("*******Leave HookZwCreateThreadEx函数*******------------------------------->\n");

	rc=RealZwCreateThreadEx(ThreadHandle,
							DesiredAccess,
							ObjectAttributes ,
							ProcessHandle,		//它是宿主进程句柄
							StartRoutine,
							StartContext,
							CreateThreadFlags,
							ZeroBits,
							StackSize,
							MaximumStackSize,
							AttributeList
		);

	return  rc;
}

//======================================================================================================//
//Name: NTSTATUS GetProcessNameOffset()																    //
//											                                                            //
//Descripion: 动态获取EPROCESS结构中进程名字偏移，兼容Windows版本                                       //
//            				                            						                        //
//======================================================================================================//
NTSTATUS GetProcessNameOffset(
	OUT PULONG	Offset OPTIONAL )
{
	NTSTATUS	status;
	PEPROCESS	curproc;
	ULONG			i;

	if (!MmIsAddressValid((PVOID)Offset))
	{
		status = STATUS_INVALID_PARAMETER;
		return status;
	}

	curproc = PsGetCurrentProcess();

	//
	// 然后搜索KPEB，得到ProcessName相对KPEB的偏移量
	// 偏移174h的位置，这里存的是进程的短文件名，少数地方用，
	// 比如SoftIce的addr和proc命令，如果名称超过16个字符直接截断

	// Scan for 12KB, hopping the KPEB never grows that big!
	//
	for( i = 0; i < 3 * PAGE_SIZE; i++ ) {

		if(!strncmp( "System", (PCHAR) curproc + i, strlen("System"))) {
			*Offset = i;
			status = STATUS_SUCCESS;
			break;
		}
	}
	return status;
}*/


