#pragma once

class IMProtect
{
public:
	IMProtect();
	~IMProtect();
	bool LoadDriver();
	bool ProcessProtectionRemoval();
	bool ProcessProtectionAdd(const wchar_t * ProcessFileName, unsigned long ProcessId);
	bool ProcessHideRemoval();
	bool ProcessHideAdd(const wchar_t * ProcessFileName, unsigned long ProcessId);
	bool UnloadNTDriver();   //shupb

private:
	bool LoadNTDriver(const wchar_t* lpDriverName, const wchar_t* lpDriverPathName);
	bool Close();
	void* m_hMProtect;
};

