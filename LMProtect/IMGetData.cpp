#include "stdafx.h"
#include "IMGetData.h"
#include "GetSysInfo.h"

using namespace std;



GetSysInfo GetSysInfo_;
CpuFeaturesInfo1 ecx_;
CpuFeaturesInfo2 edx_;
IMGetData::IMGetData()
{
	GetSysInfo_.InitializeCpuInfo();
	GetSysInfo_.InitialazeDiskInfo();
	unsigned int cpu_info[4] = {};
	__cpuidex(reinterpret_cast<int *>(cpu_info), 1, 0);
	ecx_ = { static_cast<unsigned long>(cpu_info[2]) };
	edx_ = { static_cast<unsigned long>(cpu_info[3]) };
}


IMGetData::~IMGetData()
{

}

std::string IMGetData::GetCpuInfo(GETINFOTYPE GetDataType)
{
	string str = "";

	switch (GetDataType)
	{
	case Constructor:
		str = GetSysInfo_.cpu_.Constructor;
		break;
	case Trademarks:
		str = GetSysInfo_.cpu_.Trademarks;
		break;
	case SerialNumber:
		str = GetSysInfo_.cpu_.SerialNumber;
		break;
	default:
		break;
	}

	return str;
}

CpuFeaturesInfo1 IMGetData::GetCpuFeaturesInfo1()
{
	return ecx_;
}

CpuFeaturesInfo2 IMGetData::GetCpuFeaturesInfo2()
{
	return edx_;
}

std::string IMGetData::GetDiskInfo(GETINFOTYPE GetDataType)
{
	string str = "";
	char cstr[128] = { 0 };
	switch (GetDataType)
	{
	case ModelNumber:
		memcpy(cstr, GetSysInfo_.disk_.sModelNumber, 40);
		break;
	case FirmwareRev:
		memcpy(cstr, GetSysInfo_.disk_.sFirmwareRev, 8);
		break;
	case SerialNumber:
		memcpy(cstr, GetSysInfo_.disk_.sSerialNumber, 20);
		break;
	default:
		break;
	}
	str = cstr;
	return str;
}
