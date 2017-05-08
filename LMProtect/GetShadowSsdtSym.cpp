#include "stdafx.h"
#include "GetShadowSsdtSym.h"
#include <tchar.h>


GetShadowSsdtSym::GetShadowSsdtSym()
{
	std::string strMod;
	LPSTR chDrvName[MAX_PATH];
	DWORD dwcbNeeded = 0;

	if (!EnumDeviceDrivers(DriverBaseTab_, 2048 * sizeof(void*), &dwcbNeeded)){
		return;
	}

	for (unsigned int i = 0; i<(dwcbNeeded / sizeof(void*)); i++) {
		GetDeviceDriverBaseNameA(DriverBaseTab_[i], (LPSTR)chDrvName, MAX_PATH);
		Win32kBase_ = (unsigned long long)DriverBaseTab_[i];
		strMod = std::string((char*)chDrvName);

		if (strMod == "win32k.sys") {
			GetWin32kBaseSuccess_ = true;
			return;
		}
	}

	Win32kBase_ = 0;
	
}


GetShadowSsdtSym::~GetShadowSsdtSym()
{

}


BOOL CALLBACK EnumSymCallBack(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
{
	std::string Filter = pSymInfo->Name;
	std::string RegPath;
	int site = 0;
	if (Filter.find("_imp_") != -1) {
		Filter = Filter.substr(6, Filter.length() - 6);
	}
	site = Filter.find("@");
	if (site != -1) {
		Filter = Filter.substr(0, site);
	}
	if (Filter[0] == '_' || Filter[0] == '?') {
		Filter = Filter.substr(1, Filter.length() - 1);
	}

	if (!(Filter.length() > 3 && Filter[0] == 'N' && Filter[1] == 't')) {
		return true;
	}
	
	RegPath = "SYSTEM\\CurrentControlSet\\Services\\MProtect\\ShadowSSDT\\"+ Filter;
	SHSetValueA(HKEY_LOCAL_MACHINE, RegPath.c_str(), "FunName", REG_SZ, Filter.c_str(), Filter.length() + 1);
	SHSetValueA(HKEY_LOCAL_MACHINE, RegPath.c_str(), "FunAdder", REG_QWORD, &pSymInfo->Address, 8);

	return TRUE;
}


bool GetShadowSsdtSym::Init()
{
	auto hProcess = GetCurrentProcess();
	std::string strSymbolPath = "srv*C:\\Windows\\symbols*http://msdl.microsoft.com/download/symbols";
	std::string strSystemPath = "C:\\Windows\\System32\\win32k.sys";

	if (!Win32kBase_ || !GetWin32kBaseSuccess_){
		return false;
	}

	SymSetOptions(SYMOPT_DEFERRED_LOADS);
	if (!SymInitialize(hProcess, 0, false)){
		return false;
	}

	if (!SymSetSearchPath(hProcess, strSymbolPath.c_str())) {
		return false;
	}
	
	auto hSystemFile = CreateFileA(strSystemPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL);

	if (hSystemFile <= 0){
		return false;
	}

	auto dwFileSize = GetFileSize(hSystemFile, NULL);

	if (dwFileSize <= 0) {
		return false;
	}

	auto dwBase = SymLoadModule64(hProcess, NULL, strSystemPath.c_str(), NULL, Win32kBase_, dwFileSize);

	if (dwBase <= 0) {
		return false;
	}

	if (!SymEnumSymbols(hProcess, dwBase, 0, EnumSymCallBack, 0)) {
		return false;
	}

	SymUnloadModule64(hProcess, dwBase);
	SymCleanup(hProcess);

	/*SymSetOptions(SYMOPT_DEFERRED_LOADS);
	HANDLE hProcess = GetCurrentProcess();
	SymInitialize(hProcess, 0, FALSE);
	std::string strSymbolPath = "srv*C:\\Windows\\symbols*http://msdl.microsoft.com/download/symbols";
	std::string strSystemPath = "C:\\Windows\\System32\\win32k.sys";
	SymSetSearchPath(hProcess, strSymbolPath.c_str());
	HANDLE hSystemFile = CreateFileA(strSystemPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL);
	DWORD dwFileSize = GetFileSize(hSystemFile, NULL);
	DWORD64 dwBase = SymLoadModule64(hProcess, NULL, strSystemPath.c_str(), NULL, Win32kBase_, dwFileSize);
	SymEnumSymbols(hProcess, dwBase, 0, EnumSymCallBack, 0);
	SymUnloadModule64(hProcess, dwBase);
	SymCleanup(hProcess);*/
	return true;
}

bool GetShadowSsdtSym::Is64Bit_OS()
{
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);

	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		return true;
	else
		return false;
}