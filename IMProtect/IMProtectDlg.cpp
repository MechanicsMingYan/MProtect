
// IMProtectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "IMProtect.h"
#include "IMProtectDlg.h"
#include "afxdialogex.h"
#include <tlhelp32.h>



#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
#define VNAME(name,name2) AddExtensionInfo(#name,name2,name)
#define VNAME2(name,name2) AddExtensionInfo2(#name,name2,name)
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CIMProtectDlg 对话框



CIMProtectDlg::CIMProtectDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_IMPROTECT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CIMProtectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, list_process_protect_);
	DDX_Control(pDX, IDC_COMBO1, combox_processlist_);
	DDX_Control(pDX, IDC_LIST2, list_process_hide_);
	DDX_Control(pDX, IDC_COMBO2, combox_processlist2_);
	DDX_Control(pDX, IDC_LIST3, list_infoshow_);
}

BEGIN_MESSAGE_MAP(CIMProtectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_DROPDOWN(IDC_COMBO1, &CIMProtectDlg::OnCbnDropdownCombo1)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CIMProtectDlg::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDC_BUTTON1, &CIMProtectDlg::OnBnClickedButton1)
	ON_CBN_DROPDOWN(IDC_COMBO2, &CIMProtectDlg::OnCbnDropdownCombo2)
	ON_BN_CLICKED(IDC_BUTTON3, &CIMProtectDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON2, &CIMProtectDlg::OnBnClickedButton2)
	ON_NOTIFY(NM_RCLICK, IDC_LIST1, &CIMProtectDlg::OnNMRClickList1)
	ON_BN_CLICKED(IDC_BUTTON4, &CIMProtectDlg::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON_GET_CPUINO, &CIMProtectDlg::OnBnClickedButtonGetCpuino)
	ON_BN_CLICKED(IDC_BUTTON_GET_DISKINFO, &CIMProtectDlg::OnBnClickedButtonGetDiskinfo)
END_MESSAGE_MAP()


// CIMProtectDlg 消息处理程序

BOOL CIMProtectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	
	DWORD dwStyle = list_process_protect_.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;//选中某行使整行高亮（只适用与report风格的listctrl）
	dwStyle |= LVS_EX_GRIDLINES;//网格线（只适用与report风格的listctrl）

	list_process_protect_.SetExtendedStyle(dwStyle); //设置扩展风格
	list_process_protect_.InsertColumn(0, L"ProcessName", LVCFMT_LEFT, 140);
	list_process_hide_.SetExtendedStyle(dwStyle); //设置扩展风格
	list_process_hide_.InsertColumn(0, L"ProcessName", LVCFMT_LEFT, 140);

	dwStyle = list_infoshow_.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;// 选中某行使整行高亮（只适用与report 风格的listctrl ） 
	dwStyle |= LVS_EX_GRIDLINES;// 网格线（只适用与report 风格的listctrl ） 
								//dwStyle |= LVS_EX_CHECKBOXES;//item 前生成checkbox 控件 
	dwStyle |= LVS_EX_SUBITEMIMAGES;
	list_infoshow_.SetExtendedStyle(dwStyle); // 设置扩展风格 
	list_infoshow_.InsertColumn(0, L"English", LVCFMT_LEFT, 125);
	list_infoshow_.InsertColumn(1, L"Chinese", LVCFMT_LEFT, 200);
	list_infoshow_.InsertColumn(2, L"Support", LVCFMT_LEFT, 250);

	MessageBox(L"", NULL);

	Improtect_ = new IMProtect;
	Imgetdata_ = new IMGetData;
	GetShadowSsdtSym_ = new GetShadowSsdtSym;

	//如果64位系统使用32位客户端则报错退出
	if (GetShadowSsdtSym_->Is64Bit_OS() && sizeof(void*) == 4){
		MessageBox(L"64位系统请使用64位客户端程序！", NULL);
		exit(0);
	}

	if (!GetShadowSsdtSym_->Init()){
		auto error = GetLastError();
		if (error) {
			wchar_t ser[125];
			_itow(error, ser, 10);
			CString s = L"Win32k.sys的符号下载失败：";
			s += ser;
			MessageBox(s, NULL);
		}
		exit(0);
	}
	

	MessageBox(L"", NULL);
	if (!Improtect_->LoadDriver()){
		auto error = GetLastError();
		if (error) {
			wchar_t ser[125];
			_itow(error, ser, 10);
			CString s = L"加载驱动错误：";
			s += ser;
			MessageBox(s, NULL);
		}
	}
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CIMProtectDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CIMProtectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CIMProtectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CIMProtectDlg::OnCbnDropdownCombo1()
{
	// 定义进程信息结构  
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	auto hProcessShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessShot == INVALID_HANDLE_VALUE) {
		return;
	}

	combox_processlist_.ResetContent();

	if (Process32First(hProcessShot, &pe32)) {
		do {
			if (combox_processlist_.FindString(-1, pe32.szExeFile) == CB_ERR) {
				combox_processlist_.AddString(pe32.szExeFile);
			}

		} while (Process32Next(hProcessShot, &pe32));
	}
	CloseHandle(hProcessShot);
}


void CIMProtectDlg::OnCbnSelchangeCombo1()
{
	
}


void CIMProtectDlg::OnBnClickedButton1()
{
	LVFINDINFO info;
	CString str;
	combox_processlist_.GetLBText(combox_processlist_.GetCurSel(), str);
	if (str != L"") {
		info.flags = LVFI_PARTIAL | LVFI_STRING;
		info.psz = str;
		if (list_process_protect_.FindItem(&info) == CB_ERR) {
			list_process_protect_.InsertItem(0, str);
		}
	}
}


void CIMProtectDlg::OnCbnDropdownCombo2()
{
	// 定义进程信息结构  
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	auto hProcessShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessShot == INVALID_HANDLE_VALUE) {
		return;
	}

	combox_processlist2_.ResetContent();

	if (Process32First(hProcessShot, &pe32)) {
		do {
			if (combox_processlist2_.FindString(-1, pe32.szExeFile) == CB_ERR) {
				combox_processlist2_.AddString(pe32.szExeFile);
			}

		} while (Process32Next(hProcessShot, &pe32));
	}
	CloseHandle(hProcessShot);
}


void CIMProtectDlg::OnBnClickedButton3()
{
	LVFINDINFO info;
	CString str;
	combox_processlist2_.GetLBText(combox_processlist2_.GetCurSel(), str);
	if (str != L"") {
		info.flags = LVFI_PARTIAL | LVFI_STRING;
		info.psz = str;
		if (list_process_hide_.FindItem(&info) == CB_ERR) {
			list_process_hide_.InsertItem(0, str);
		}
	}
}


void CIMProtectDlg::OnBnClickedButton2()
{
	//发送事件给r0
	if (Improtect_->ProcessHideRemoval() ||
		Improtect_->ProcessProtectionRemoval() ){
		auto error = GetLastError();
		AfxMessageBox(L"应用失败!");
		return;
	}

	int Num = list_process_hide_.GetItemCount();
	for (int i = 0; i < Num; i++) {
		auto Text = list_process_hide_.GetItemText(i, 0);
		if (Improtect_->ProcessHideAdd(Text.GetBuffer(0), 0))
		{
			AfxMessageBox(L"数据传输失败!");
			return;
		}
	}

	Num = list_process_protect_.GetItemCount();
	for (int i = 0; i < Num; i++) {
		auto Text = list_process_protect_.GetItemText(i, 0);
		if (Improtect_->ProcessProtectionAdd(Text.GetBuffer(0), 0))
		{
			AfxMessageBox(L"数据传输失败!");
			return;
		}
	}
	AfxMessageBox(L"应用成功!");
}



void CIMProtectDlg::OnNMRClickList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	
	CMenu menu; //定义下面要用到的cmenu对象
	menu.LoadMenu(IDR_MENU1); //装载自定义的右键菜单 
	CMenu *pPopup = menu.GetSubMenu(0); //获取第一个弹出菜单，所以第一个菜单必须有子菜单
	CPoint point1;//定义一个用于确定光标位置的位置 
	GetCursorPos(&point1);//获取当前光标的位置，以便使得菜单可以跟随光标 
	pPopup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point1.x, point1.y, GetParent());//在指定位置显示弹出菜单

	*pResult = 0;
}


void CIMProtectDlg::OnBnClickedButton4()
{
	if (Improtect_->UnloadNTDriver()){
		AfxMessageBox(L"卸载成功!");
	}
	else {
		AfxMessageBox(L"卸载失败!");
	}
}


void CIMProtectDlg::AddExtensionInfo(char *English, char* Chinese, bool Support)
{
	CString s;
	s = English;
	auto Index = list_infoshow_.InsertItem(list_infoshow_.GetItemCount(), s);
	s = Chinese;
	list_infoshow_.SetItemText(Index, 1, s);
	if (Support) {
		list_infoshow_.SetItemText(Index, 2, L"yes");
	}
	else {
		list_infoshow_.SetItemText(Index, 2, L"no");
	}
}

void CIMProtectDlg::AddExtensionInfo2(char *English, char* Chinese, ULONGLONG Support)
{
	char cs[100];
	CString s;

	s = English;
	auto Index = list_infoshow_.InsertItem(list_infoshow_.GetItemCount(), s);
	s = Chinese;
	list_infoshow_.SetItemText(Index, 1, s);
	itoa(Support, cs, 10);
	s = cs;
	list_infoshow_.SetItemText(Index, 2, s);
}

void CIMProtectDlg::OnBnClickedButtonGetCpuino()
{
	CStringW aTow;
	list_infoshow_.DeleteAllItems();
	auto ecx = Imgetdata_->GetCpuFeaturesInfo1();
	auto edx = Imgetdata_->GetCpuFeaturesInfo2();
	aTow = Imgetdata_->GetCpuInfo(GETINFOTYPE::Constructor).c_str();
	auto Index = list_infoshow_.InsertItem(list_infoshow_.GetItemCount(), L"Constructor");
	list_infoshow_.SetItemText(Index, 1, L"制造商");
	list_infoshow_.SetItemText(Index, 2, aTow);

	aTow = Imgetdata_->GetCpuInfo(GETINFOTYPE::SerialNumber).c_str();
	Index = list_infoshow_.InsertItem(list_infoshow_.GetItemCount(), L"SerialNumber");
	list_infoshow_.SetItemText(Index, 1, L"序列号");
	list_infoshow_.SetItemText(Index, 2, aTow);

	aTow = Imgetdata_->GetCpuInfo(GETINFOTYPE::Trademarks).c_str();
	Index = list_infoshow_.InsertItem(list_infoshow_.GetItemCount(), L"Trademarks");
	list_infoshow_.SetItemText(Index, 1, L"商标");
	list_infoshow_.SetItemText(Index, 2, aTow);

	VNAME(ecx.fields.sse3, "simd流技术扩展3(SSE3) ");
	VNAME(ecx.fields.pclmulqdq, "PCLMULQDQ ");
	VNAME(ecx.fields.dtes64, "64位DS区域");
	VNAME(ecx.fields.monitor, "显示器/等");
	VNAME(ecx.fields.ds_cpl, "CPL合格的调试存储");
	VNAME(ecx.fields.vmx, "虚拟机技术");
	VNAME(ecx.fields.smx, "安全模式扩展");
	VNAME(ecx.fields.est, "增强型英特尔Speedstep技术");
	VNAME(ecx.fields.tm2, "散热监控2");
	VNAME(ecx.fields.ssse3, "附加simd流技术扩展3");
	VNAME(ecx.fields.cid, "L1上下文ID");
	VNAME(ecx.fields.sdbg, "IA32_DEBUG_INTERFACE MSR");
	VNAME(ecx.fields.fma, "使用YMM状态FMA扩展");
	VNAME(ecx.fields.cx16, "CMPXCHG16B");
	VNAME(ecx.fields.xtpr, "xTPR更新控制");
	VNAME(ecx.fields.pdcm, "性能/调试能力MSR");
	VNAME(ecx.fields.reserved, "保留");
	VNAME(ecx.fields.pcid, "程序的上下文标识符");
	VNAME(ecx.fields.dca, "回迁从内存映射设备");
	VNAME(ecx.fields.sse4_1, "SSE4.1");
	VNAME(ecx.fields.sse4_2, "SSE4.2");
	VNAME(ecx.fields.x2_apic, "x2APIC功能");
	VNAME(ecx.fields.movbe, "MOVBE指令");
	VNAME(ecx.fields.popcnt, "POPCNT指令");
	VNAME(ecx.fields.reserved3, "使用TSC期限一次性操作");
	VNAME(ecx.fields.aes, "AESNI指令");
	VNAME(ecx.fields.xsave, "XSAVE/XRSTOR功能");
	VNAME(ecx.fields.osxsave, "使XSETBV/XGETBV说明");
	VNAME(ecx.fields.avx, "AVX指令扩展");
	VNAME(ecx.fields.f16c, "16位浮点转换");
	VNAME(ecx.fields.rdrand, "RDRAND指令");
	VNAME(ecx.fields.not_used, "0(a.k.一。 HypervisorPresent)");


	VNAME(edx.fields.fpu, "浮点单元的片上");
	VNAME(edx.fields.vme, "虚拟8086模式增强");
	VNAME(edx.fields.de, "调试扩展程序");
	VNAME(edx.fields.pse, "页大小扩展");
	VNAME(edx.fields.tsc, "时间戳计数器");
	VNAME(edx.fields.msr, "RDMSR和WRMSR说明");
	VNAME(edx.fields.mce, "机器检查异常");
	VNAME(edx.fields.cx8, "散热监控2");
	VNAME(edx.fields.apic, "APIC片上");
	VNAME(edx.fields.reserved1, "保留");
	VNAME(edx.fields.sep, "SYSENTER和SYSEXIT说明");
	VNAME(edx.fields.mtrr, "内存范围寄存器");
	VNAME(edx.fields.pge, "页全球位");
	VNAME(edx.fields.mca, "机器检查架构");
	VNAME(edx.fields.cmov, "有条件的移动指令");
	VNAME(edx.fields.pat, "页属性表");
	VNAME(edx.fields.pse36, "36位页面大小扩展");
	VNAME(edx.fields.psn, "处理器序列号");
	VNAME(edx.fields.clfsh, "CLFLUSH指令");
	VNAME(edx.fields.reserved2, "保留");
	VNAME(edx.fields.ds, "的调试存储");
	VNAME(edx.fields.acpi, "TM和软件控制时钟");
	VNAME(edx.fields.mmx, "英特尔MMX技术");
	VNAME(edx.fields.fxsr, "FXSAVE和FXRSTOR说明");
	VNAME(edx.fields.sse, "SSE");
	VNAME(edx.fields.sse2, "SSE2");
	VNAME(edx.fields.ss, "自探听");
	VNAME(edx.fields.htt, "保留的最大APIC id字段有效");
	VNAME(edx.fields.tm, "散热监控");
	VNAME(edx.fields.reserved3, "保留");
	VNAME(edx.fields.pbe, "挂起的分行符启用");
}


void CIMProtectDlg::OnBnClickedButtonGetDiskinfo()
{
	CStringW aTow;
	list_infoshow_.DeleteAllItems();

	aTow = Imgetdata_->GetDiskInfo(GETINFOTYPE::FirmwareRev).c_str();
	auto Index = list_infoshow_.InsertItem(list_infoshow_.GetItemCount(), L"Constructor");
	list_infoshow_.SetItemText(Index, 1, L"固件版本");
	list_infoshow_.SetItemText(Index, 2, aTow);

	aTow = Imgetdata_->GetDiskInfo(GETINFOTYPE::SerialNumber).c_str();
	Index = list_infoshow_.InsertItem(list_infoshow_.GetItemCount(), L"SerialNumber");
	list_infoshow_.SetItemText(Index, 1, L"序列号");
	list_infoshow_.SetItemText(Index, 2, aTow);

	aTow = Imgetdata_->GetDiskInfo(GETINFOTYPE::ModelNumber).c_str();
	Index = list_infoshow_.InsertItem(list_infoshow_.GetItemCount(), L"Trademarks");
	list_infoshow_.SetItemText(Index, 1, L"内部型号");
	list_infoshow_.SetItemText(Index, 2, aTow);
}