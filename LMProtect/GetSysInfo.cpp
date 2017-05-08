#include "stdafx.h"
#include "GetSysInfo.h"


#define  DFP_RECEIVE_DRIVE_DATA   CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
// ATA/ATAPI指令
#define  IDE_ATA_IDENTIFY           0xEC     // ATA的ID指令(IDENTIFY DEVICE)

GetSysInfo::GetSysInfo()
{
}


GetSysInfo::~GetSysInfo()
{
}

// 将串中的字符两两颠倒
// 原因是ATA/ATAPI中的WORD，与Windows采用的字节顺序相反
// 驱动程序中已经将收到的数据全部反过来，我们来个负负得正
void GetSysInfo::AdjustString(char* str, int len)
{
	char ch;
	int i;

	// 两两颠倒
	for (i = 0; i < len; i += 2)
	{
		ch = str[i];
		str[i] = str[i + 1];
		str[i + 1] = ch;
	}

	// 若是右对齐的，调整为左对齐 (去掉左边的空格)
	i = 0;
	while ((i < len) && (str[i] == ' ')) i++;

	::memmove(str, &str[i], len - i);

	// 去掉右边的空格
	i = len - 1;
	while ((i >= 0) && (str[i] == ' '))
	{
		str[i] = '/0';
		i--;
	}
}

bool GetSysInfo::InitializeCpuInfo()
{
	{//制造商
		char str[13] = { 0 };
		unsigned int cpu_info[4] = {};
		__cpuidex(reinterpret_cast<int *>(cpu_info), 0, 0);
		memcpy_s(str, sizeof(str), &cpu_info[1], 4 * 3);
		strcpy(cpu_.Constructor, str);
	}
	{//商标
		char str[49] = { 0 };
		unsigned int cpu_info[4] = {};
		for (unsigned long i = 0; i < 3; i++) {
			__cpuidex(reinterpret_cast<int *>(cpu_info), 0x80000002 + i, 0);
			memcpy(str + i * 16, cpu_info, sizeof(cpu_info));
		}
		strcpy(cpu_.Trademarks, str);
	}
	{//缓存
		unsigned char str[16] = { 0 };
		unsigned int cpu_info[4] = {};
		__cpuidex(reinterpret_cast<int *>(cpu_info), 2, 0);
		memcpy_s(str, sizeof(str), cpu_info, sizeof(cpu_info));
	}
	{//CPU序列号
		char str[200] = { 0 };
		unsigned int cpu_info[4] = {};
		__cpuidex(reinterpret_cast<int *>(cpu_info), 1, 0);
		sprintf_s(str, "%08X%08X", cpu_info[3], cpu_info[0]);
		__cpuidex(reinterpret_cast<int *>(cpu_info), 3, 0);
		sprintf_s(str, "%s%08X%08X", str, cpu_info[3], cpu_info[0]);
		strcpy(cpu_.SerialNumber, str);
	}
	return true;
}

#define INTERFACE_DETAIL_SIZE (1024) 
bool GetSysInfo::InitialazeDiskInfo()
{
	SP_DEVICE_INTERFACE_DATA ifdata;
	PSENDCMDINPARAMS pSCIP;      // 输入数据结构指针
	PSENDCMDOUTPARAMS pSCOP;     // 输出数据结构指针
	unsigned long dwOutBytes;            // IOCTL输出数据长度
	bool bResult;                // IOCTL返回值
	LPGUID lpGuid = (LPGUID)&DiskClassGuid;

	auto hDevInfoSet = ::SetupDiGetClassDevs(lpGuid,
		/* class GUID*/  NULL,
		/* 无关键字 */ NULL,
		/* 不指定父窗口句柄 */ DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	// 目前存在的设备 
	// 失败... 
	if (hDevInfoSet == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	auto pDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)::GlobalAlloc(LMEM_ZEROINIT, INTERFACE_DETAIL_SIZE);
	pDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
	auto nCount = 0;
	bResult = false;
	// 设备序号=0,1,2... 逐一测试设备接口，到失败为止 
	while (!bResult){
		ifdata.cbSize = sizeof(ifdata);
		// 枚举符合该GUID的设备接口 
		bResult = ::SetupDiEnumDeviceInterfaces(hDevInfoSet,
			/* 设备信息集句柄*/ NULL,
			/* 不需额外的设备描述*/ lpGuid,
			/* GUID */(ULONG)nCount,
			/* 设备信息集里的设备序号 */&ifdata);

		if (!bResult) {
			break;
		}

		// 取得该设备接口的细节(设备路径) 
		bResult = SetupDiGetInterfaceDeviceDetail(hDevInfoSet,
			/* 设备信息集句柄*/ &ifdata,
			/* 设备接口信息*/ pDetail,
			/* 设备接口细节(设备路径)*/ INTERFACE_DETAIL_SIZE,
			/* 输出缓冲区大小*/ NULL,
			/* 不需计算输出缓冲区大小(直接用设定值)*/ NULL);
		if (!bResult) {
			nCount++;
			continue;
		}

		if (IdentifyDevice(pDetail->DevicePath)) {
			break;
		}
		bResult = false;
		nCount++;
	}

	::GlobalFree(pDetail);
	// 关闭设备信息集句柄 
	::SetupDiDestroyDeviceInfoList(hDevInfoSet);
	return bResult;
}

// 向驱动发“IDENTIFY DEVICE”命令，获得设备信息
bool GetSysInfo::IdentifyDevice(wchar_t* szFileName)
{
	PSENDCMDINPARAMS pSCIP;      // 输入数据结构指针
	PSENDCMDOUTPARAMS pSCOP;     // 输出数据结构指针
	DWORD dwOutBytes;            // IOCTL输出数据长度
	BOOL bResult;                // IOCTL返回值

	auto hDevice = ::CreateFileW(szFileName, // 文件名
		GENERIC_READ | GENERIC_WRITE,          // 读写方式
		FILE_SHARE_READ | FILE_SHARE_WRITE,    // 共享方式
		NULL,                    // 默认的安全描述符
		OPEN_EXISTING,           // 创建方式
		0,                       // 不需设置文件属性
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return false;
	}
								 // 申请输入/输出数据结构空间
	pSCIP = (PSENDCMDINPARAMS)::GlobalAlloc(LMEM_ZEROINIT, sizeof(SENDCMDINPARAMS) - 1);
	pSCOP = (PSENDCMDOUTPARAMS)::GlobalAlloc(LMEM_ZEROINIT, sizeof(SENDCMDOUTPARAMS) + sizeof(IDINFO) - 1);

	// 指定ATA/ATAPI命令的寄存器值
	//    pSCIP->irDriveRegs.bFeaturesReg = 0;
	//    pSCIP->irDriveRegs.bSectorCountReg = 0;
	//    pSCIP->irDriveRegs.bSectorNumberReg = 0;
	//    pSCIP->irDriveRegs.bCylLowReg = 0;
	//    pSCIP->irDriveRegs.bCylHighReg = 0;
	//    pSCIP->irDriveRegs.bDriveHeadReg = 0;
	pSCIP->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;

	// 指定输入/输出数据缓冲区大小
	pSCIP->cBufferSize = 0;
	pSCOP->cBufferSize = sizeof(IDINFO);

	// IDENTIFY DEVICE
	bResult = ::DeviceIoControl(hDevice,        // 设备句柄
		DFP_RECEIVE_DRIVE_DATA,                 // 指定IOCTL
		pSCIP, sizeof(SENDCMDINPARAMS) - 1,     // 输入数据缓冲区
		pSCOP, sizeof(SENDCMDOUTPARAMS) + sizeof(IDINFO) - 1,    // 输出数据缓冲区
		&dwOutBytes,                // 输出数据长度
		(LPOVERLAPPED)NULL);        // 用同步I/O

									// 复制设备参数结构
	::memcpy(&disk_, pSCOP->bBuffer, sizeof(IDINFO));

	// 释放输入/输出数据空间
	::GlobalFree(pSCOP);
	::GlobalFree(pSCIP);

	return bResult;
}