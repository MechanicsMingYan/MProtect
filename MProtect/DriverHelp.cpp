/************************************************************************/
/* Copyright(C)2015
 * All rights reserved
 * 名  称：DriverHelp.h
 * 摘  要：定义CDriverHelp类的所有功能，
            CDriverHelp主要用于为驱动程序创建服务，
			并且提供与驱动的通信
 * 版  本：v1.0
 * 作  者: Run
 * 创建时间：2015.03.06
 * 修改记录：无
*/
/************************************************************************/
#include "stdafx.h"
#include "DriverHelp.h"
#include <tchar.h>
#include <stdio.h>

const int OPEN_SC_MANAGER = 1;
const int CLOSE_SC_MANAGER = 0;

#define DRIVER_HELP "DriverHelp"


CDriverHelp::CDriverHelp(void)
{
	m_nRefcount = 0;
    m_hScManager = NULL;
	m_hDevice = ((HANDLE)-1);
}


CDriverHelp::~CDriverHelp(void)
{
	if(m_hScManager&&!InterlockedDecrement(&m_nRefcount))
	{
		CloseServiceHandle(m_hScManager);
		m_hScManager = NULL;
	}

	if ( ((HANDLE)-1) != m_hDevice )
	{
		CloseHandle(m_hDevice);
		m_hDevice = (HANDLE)-1;
	}

}



/**************************************************
函  数:drvOpenScManager@4
功  能:打开服务控制管理器
参  数:open - !0:打开,0:关闭
返回值:成功:0;失败:返回GetLastError错误码
说  明:内部调用
2013-02-17:

**************************************************/
DWORD CDriverHelp::DrvOpenScManager(int v_nOpen)
{
	DWORD nRet = 0;

	switch (v_nOpen)
	{
	case OPEN_SC_MANAGER:
		//如果服务管理句柄不为空说明已经打开,直接返回
		if(m_hScManager)
		{
			InterlockedIncrement(&m_nRefcount);    
			break;
		}

		//打开服务管理句柄
		m_hScManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if(m_hScManager == NULL)
		{
			nRet = GetLastError();
			break;
		}

		InterlockedIncrement(&m_nRefcount);
		break;

	case CLOSE_SC_MANAGER://关闭服务管理句柄
		if(m_hScManager&&!InterlockedDecrement(&m_nRefcount))
		{
			CloseServiceHandle(m_hScManager);
			m_hScManager = NULL;
		}

		break;
	default:
		break;
	}

	return nRet;
}

/**************************************************
函  数:drvCreateService@16
功  能:创建新服务,并返回服务句柄(if succeeded)
参  数:	DriverAbsolutePath - 驱动文件的绝对路径
ServiceName - 服务名
ServiceDisplayName - 服务的显示名
*phService - 返回的服务句柄
返回值:成功:0;失败:返回GetLastError错误码
说  明:内部调用
**************************************************/
DWORD CDriverHelp::DrvCreateService(const TCHAR* v_szDriverAbsolutePath, const TCHAR* v_szServiceName, 
								 const TCHAR* v_szServiceDispalyName, SC_HANDLE* v_phService)
{

	SC_HANDLE hService = NULL;

	hService = CreateService(
			m_hScManager,			    //服务控制器管理器句柄
			v_szServiceName,			//服务的名称
			v_szServiceDispalyName,		//服务的显示名称
			SERVICE_ALL_ACCESS,		    //对该服务的访问权限
			SERVICE_FILE_SYSTEM_DRIVER,	    //服务的类型:内核驱动
			SERVICE_DEMAND_START,	    //启动类型:SERVICE_DEMAND_START手动启动 //SERVICE_AUTO_START,自动启动
			0,	    //服务错误控制:正常
			v_szDriverAbsolutePath,		//服务文件的绝对路径
			NULL,					    //没有启动组
			NULL,					    //不更改默认的标签ID
			NULL,					    //没有服务依赖项
			NULL,					    //使用默认对象名称
			NULL					    //没有密码
			);

	DWORD dwLastError = GetLastError();

	//如果是服务已经存在,直接打开服务
	if(dwLastError == ERROR_SERVICE_EXISTS)
	{
		dwLastError = 0;
		//打开服务
		hService = OpenService(
			m_hScManager,
			v_szServiceName,
			SERVICE_ALL_ACCESS
			);

		if (NULL == hService)
		{
			dwLastError = GetLastError();
		}
	}

	*v_phService = hService;
	return dwLastError;
}

/**************************************************
函  数:drvDeleteService@4
功  能:删除指定服务名的的服务
参  数:ServiceName - 服务名
返回值:成功:0;失败:返回GetLastError错误码
说  明:	内部调用
对不存在的服务返回-1(成功)
**************************************************/
DWORD CDriverHelp::DrvDeleteService(const TCHAR* v_szServiceName)
{
	SERVICE_STATUS ServiceStatus;
	SC_HANDLE hService=NULL;
	DWORD dwLastError = 0;

	__try{
		hService=OpenService(m_hScManager, v_szServiceName, SERVICE_ALL_ACCESS);
		if(hService==NULL)
		{
			dwLastError = GetLastError();
			//如果服务本身不存在，那我们认为删除成功
			if(dwLastError==ERROR_SERVICE_DOES_NOT_EXIST)
			{
				dwLastError = 0;
			}

			__leave;
		}

		if(!ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus))
		{//停止控制失败
			dwLastError = GetLastError();
			if(dwLastError != ERROR_SERVICE_NOT_ACTIVE)
			{//并不是因为没有启动而出错
				__leave;
			}

			//如果服务本来就没有启动，我们认为本次操作也是成功的
			dwLastError = 0;
		}

		if(!DeleteService(hService))
		{
			dwLastError = GetLastError();
			__leave;
		}

	}
	__finally{
		if(hService)
		{
			CloseServiceHandle(hService);
			hService=NULL;
		}
	}
	return dwLastError;
}

/**************************************************
函  数:drvAddService@12
功  能:添加指定的服务
参  数:	DriverAbsPath - 驱动程序绝对路径
ServiceName - 服务名
DisplayName - 服务显示名
1:删除并重新创建
0:不再继续,返回-1(成功)
-1:提示是否继续
返回值:成功:0;失败:返回GetLastError错误码
说  明:	内部调用
若选择了不再继续,返回-1(成功)
**************************************************/
DWORD CDriverHelp::DrvAddService(const TCHAR* v_szDriverAbsPath, 
							  const TCHAR* v_szServiceName, 
							  const TCHAR* v_szDisplayName)
{
	SC_HANDLE hService = NULL;		//创建/打开的服务句柄
	DWORD dwErrCode = 0;
	__try{
		//假定服务不存在并创建，如果已经存在则打开

		dwErrCode = DrvCreateService(v_szDriverAbsPath, v_szServiceName, 
			                         v_szDisplayName, &hService);
		if(dwErrCode)
		{
			__leave;
		}
		//服务成功创建来到这里
		if(!StartService(hService,0,NULL))
		{
			dwErrCode = GetLastError();
			//如果是服务已启动
			if(dwErrCode == ERROR_SERVICE_ALREADY_RUNNING)
			{
				dwErrCode = 0;
			}

			__leave;

		}

	}
	__finally{
		if(hService){
			CloseServiceHandle(hService);
			hService=NULL;
		}
	}
	return dwErrCode;
}

/**************************************************
函  数:LoadDriver@12
功  能:加载指定驱动
参  数:	DriverAbsPath - 驱动程序绝对路径
        ServiceName - 服务名
        DisplayName - 服务显示名

返回值:成功:0;失败:返回GetLastError错误码
说  明:	外部函数
**************************************************/
DWORD CDriverHelp::DrvLoadDriver(const TCHAR* v_szDriverAbsPath, 
							   const TCHAR* v_szServiceName, 
							  const TCHAR* v_szDisplayName)
{
	//打开服务管理器
	DWORD dwErr = DrvOpenScManager(OPEN_SC_MANAGER);

	//打开成功则仅需创建服务
	if(!dwErr)
	{
		dwErr = DrvAddService(v_szDriverAbsPath, v_szServiceName, v_szDisplayName);
	}
		
	return dwErr;
}

/**************************************************
函  数:UnloadDriver@4
功  能:卸载指定名称的驱动服务
参  数:ServiceName - 服务的名称
返回值:成功:0;失败:返回GetLastError错误码
说  明:	外部函数
对不存在的服务返回-1(成功)
**************************************************/
DWORD CDriverHelp::DrvUnloadDriver(const TCHAR* v_szServiceName)
{
	DWORD ret = 0;

	DrvOpenScManager(OPEN_SC_MANAGER);
	ret = DrvDeleteService(v_szServiceName);
	DrvOpenScManager(CLOSE_SC_MANAGER);
	return ret;
}

/**************************************************
函  数:DrvOpenDriver
功  能:打开驱动通信
参  数:v_szDeviceName -设备名称
返回值:成功:0;失败:返回GetLastError错误码
说  明:	外部函数
**************************************************/
BOOL CDriverHelp::DrvOpenDriver(const TCHAR* v_szDeviceName)
{
//	TCHAR    completeDeviceName[64] = {0};

	if ( ((HANDLE)-1) == m_hDevice && v_szDeviceName)
	{
		/*
		if( (GetVersion() & 0xFF) >= 5 ) 
		{
			_stprintf_s( completeDeviceName, 64*sizeof(TCHAR), TEXT("\\\\.\\Global\\%s"), v_szDeviceName );
		} 
		else 
		{
			_stprintf_s( completeDeviceName, 64*sizeof(TCHAR), TEXT("\\\\.\\%s"), v_szDeviceName );
		}*/

		m_hDevice = CreateFile( v_szDeviceName,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
			);
		if ( ((HANDLE)-1) == m_hDevice)
		{
			return FALSE;
		}

	}
	
	return TRUE;
}




/**************************************************
函  数:DrvCloseDriver
功  能:关闭驱动通信
参  数:
返回值:成功:TRUE; 失败:FALSE
说  明:	外部函数
**************************************************/
BOOL CDriverHelp::DrvCloseDriver()
{
	BOOL bRet = FALSE;
	if ( ((HANDLE)-1) != m_hDevice )
	{
		CloseHandle(m_hDevice);
		m_hDevice = (HANDLE)-1;
		bRet = TRUE;
	}

	return bRet;
}




/**************************************************
函  数:DrvSendCommand
功  能:向驱动层发送数据
参  数:v_nCtrlCode  - 驱动控制命令
        v_szData     - 发送到驱动的数据
		v_iDataLen   - 发送数据长度
		v_szResult   - 驱动返回结果
        v_iResultLen - 驱动返回结果长度

返回值:成功:TRUE; 失败:FALSE
说  明:	外部函数
**************************************************/
BOOL CDriverHelp::DrvSendCommand(const DWORD v_nCtrlCode, 
						   const char*    v_szData, 
						   const DWORD    v_iDataLen, 
						   char*          v_szResult, 
						   DWORD&         v_iResultLen)
{
	BOOL	bResult = FALSE;
	DWORD	dwInBufLen = v_iDataLen;
	DWORD	dwOutBufLen = v_iResultLen;

	if (((HANDLE)-1) != m_hDevice)
	{
		bResult = DeviceIoControl(
			m_hDevice,
			v_nCtrlCode,
			(void *)v_szData,
			dwInBufLen,
			v_szResult,
			dwOutBufLen,
			&dwOutBufLen,
			NULL
			);

		v_iResultLen = dwOutBufLen;
		bResult = TRUE;
	}
	
	return bResult;
}
