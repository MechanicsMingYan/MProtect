/************************************************************************/
/* Copyright(C)2015,
* All rights reserved
* 名  称：DriverHelp.h
* 摘  要：申明CDriverHelp类
* 版  本：v1.0
* 作  者: Run
* 创建时间：2015.03.06
* 修改记录：无
*/
/************************************************************************/


#pragma once


class CDriverHelp
{
public:
	CDriverHelp(void);
	~CDriverHelp(void);


	/**************************************************
	函  数:LoadDriver@12
	功  能:加载指定驱动
	参  数:	DriverAbsPath - 驱动程序绝对路径
	ServiceName - 服务名
	DisplayName - 服务显示名
	返回值:成功:0;失败:返回GetLastError错误码
	说  明:	外部函数
	**************************************************/
	DWORD DrvLoadDriver(const TCHAR* v_szDriverAbsPath, 
		              const TCHAR* v_szServiceName, 
		              const TCHAR* v_szDisplayName);

	/**************************************************
	函  数:UnloadDriver@4
	功  能:卸载指定名称的驱动服务
	参  数:ServiceName - 服务的名称
	返回值:成功:0;失败:返回GetLastError错误码
	说  明:	外部函数
	对不存在的服务返回-1(成功)
	**************************************************/
	DWORD DrvUnloadDriver(const TCHAR* v_szServiceName);

	/**************************************************
	函  数:DrvOpenDriver
	功  能:打开驱动通信
	参  数:v_szDeviceName -设备名称
	返回值:成功:TRUE; 失败:FALSE
	说  明:	外部函数
	**************************************************/
	BOOL DrvOpenDriver(const TCHAR* v_szDeviceName);

	/**************************************************
	函  数:DrvCloseDriver
	功  能:关闭驱动通信
	参  数:
	返回值:成功:TRUE; 失败:FALSE
	说  明:	外部函数
	**************************************************/
	BOOL DrvCloseDriver();

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
	BOOL DrvSendCommand(const DWORD v_nCtrlCode, 
		const char*    v_szData, 
		const DWORD    v_iDataLen, 
		char*          v_szResult, 
		DWORD&         v_iResultLen);


protected:

private:

	SC_HANDLE m_hScManager;  //服务控制管理器句柄
	long      m_nRefcount;
	HANDLE    m_hDevice;     //设备句柄

	//打开服务管理器
	DWORD DrvOpenScManager(int open);
	//创建服务
	DWORD DrvCreateService(const TCHAR* v_szDriverAbsolutePath, 
	const TCHAR* ServiceName,const TCHAR* ServiceDispalyName,SC_HANDLE* phService);
    //添加服务
	DWORD DrvAddService(const TCHAR* DriverAbsPath, const TCHAR* ServiceName, 
		const TCHAR* DisplayName);
	//删除服务
	DWORD DrvDeleteService(const TCHAR* ServiceName);


};
