#pragma once
class GetShadowSsdtSym
{
public:
	GetShadowSsdtSym();
	~GetShadowSsdtSym();
	bool Init();
	bool Is64Bit_OS();

private:
	unsigned long long Win32kBase_ = 0;
	void* DriverBaseTab_[2048];
	bool GetWin32kBaseSuccess_ = false;
};



