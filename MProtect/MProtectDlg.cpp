
// MProtectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MProtect.h"
#include "MProtectDlg.h"
#include "afxdialogex.h"
#include "VAuthLib.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

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


CString CMProtectDlg::GetAppFolder()
{
	char moduleName[MAX_PATH];
	GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
	std::string strPath = moduleName;
	int pos = strPath.rfind("\\");
	if (!(pos == std::string::npos || pos == strPath.length() - 1))
		strPath = strPath.substr(0, pos);
	strPath += "\\";
	return (CString)strPath.c_str();
}

std::string GetAppFolder(bool string)
{
	char moduleName[MAX_PATH];
	GetModuleFileNameA(NULL, moduleName, sizeof(moduleName));
	std::string strPath = moduleName;
	int pos = strPath.rfind("\\");
	if (!(pos == std::string::npos || pos == strPath.length() - 1))
		strPath = strPath.substr(0, pos);
	strPath += "\\";
	return strPath;
}

CMProtectDlg::CMProtectDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MPROTECT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	char key[512] = { 0 };
	char hwid[512] = { 0 };
	/*
	机器码效验
	*/
	g_IniPathA = ::GetAppFolder(true) + "Config.ini";
	g_VdPath = GetAppFolder() + L"VAuth.dll";
	GetPrivateProfileStringA("INI", "KEY", 0, key, 512, g_IniPathA.c_str());
	CopyFile(g_VdPath, L"C:\\Windows\\VAuth.dll", true);
	::Initialize("{06415CFF-552B-4202-9673-85231E98B4E7}");
	int a_reg = ::Auth(key);
	switch (a_reg)
	{
	case 0:
		goto goto_en;
	case -1:
		AfxMessageBox(L"不存在此注册码");
		break;
	case -2:
		AfxMessageBox(L"注册码被禁用");
		break;
	case -3:
		AfxMessageBox(L"绑定机器超限");
		break;
	case -4:
		AfxMessageBox(L"注册码已在线");
		break;
	case -5:
		AfxMessageBox(L"已过期");
		break;
	default:
		break;
	}
	exit(0);



goto_en:
	DWORD dwRetBytes = 0;
	m_DriverPath = GetAppFolder() + L"DdiMon.sys";
	if (_waccess(m_DriverPath, 0) == -1){
		AfxMessageBox(L"My::缺少驱动文件\n");
	}

	DriverHelp.DrvLoadDriver(m_DriverPath, L"MProtect", L"MProtect");
	m_hMProtect = CreateFile(L"\\\\.\\MProtect", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (INVALID_HANDLE_VALUE == m_hMProtect){
		Sleep(200);
		m_hMProtect = CreateFile(L"\\\\.\\MProtect", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ |
			FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (INVALID_HANDLE_VALUE == m_hMProtect) {
			AfxMessageBox(L"My::驱动加载失败\n");
			return;
		}
	}

	m_NotifyHandle.m_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	m_NotifyHandle.m_hNotify = CreateEvent(NULL, FALSE, FALSE, NULL);
	m_NotifyHandle.m_uPass = FALSE;
	//发送事件给r0
	if (0 == DeviceIoControl(m_hMProtect, IOCTL_MPROTECT_EVENT, &m_NotifyHandle, sizeof(NOTIFY_HANDLE), NULL, 0, &dwRetBytes, NULL))
	{
		CloseHandle(m_hMProtect);
		CloseHandle((HANDLE)m_NotifyHandle.m_hEvent);
		CloseHandle((HANDLE)m_NotifyHandle.m_hNotify);
		Wow64RevertWow64FsRedirectionFun Wow64RevertWow64FsRedirection = (Wow64RevertWow64FsRedirectionFun)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "Wow64RevertWow64FsRedirection");
		if (Wow64RevertWow64FsRedirection)
			Wow64RevertWow64FsRedirection(&m_pOldValue);
		AfxMessageBox(L"My::创建事件同步失败\n");
	}
	/*
	创建通讯线程
	*/
	AfxBeginThread(ThreadSockDriverFunc, this);
}

void CMProtectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB, m_tab);
}

BEGIN_MESSAGE_MAP(CMProtectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CMProtectDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CMProtectDlg::OnBnClickedCancel)
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB, &CMProtectDlg::OnTcnSelchangeTab)
END_MESSAGE_MAP()


UINT CMProtectDlg::ThreadSockDriverFunc(LPVOID pParam)
{
	CMProtectDlg *pObj = (CMProtectDlg *)pParam;
	TRY_SOKE soke;
	DWORD dwRetBytes = 0;
	UINT Pass = FALSE;
	int Index = 0, Indexb = 0;
	CString bbV, bbP;
	CString exdude;
	CString indude;
	BOOL bOk = TRUE;
	/*
	通讯部分代码...
	等待信息
	*/
	do
	{
		WaitForSingleObject((HANDLE)pObj->m_NotifyHandle.m_hEvent, INFINITE);
		if (0 == DeviceIoControl(pObj->m_hMProtect, IOCTL_MPROTECT_EVENT, NULL, NULL, &soke, sizeof(TRY_SOKE), &dwRetBytes, NULL))
		{
			CloseHandle(pObj->m_hMProtect);
			CloseHandle((HANDLE)pObj->m_NotifyHandle.m_hEvent);
			CloseHandle((HANDLE)pObj->m_NotifyHandle.m_hNotify);

			Wow64RevertWow64FsRedirectionFun Wow64RevertWow64FsRedirection = (Wow64RevertWow64FsRedirectionFun)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "Wow64RevertWow64FsRedirection");
			if (Wow64RevertWow64FsRedirection)
				Wow64RevertWow64FsRedirection(&pObj->m_pOldValue);
			
			AfxMessageBox(L"My::链接驱动失败\n");
			
			goto goto_error;
		}
		


		DeviceIoControl(pObj->m_hMProtect, IOCTL_MPROTECT_USERCHOICE, &Pass, sizeof(UINT), NULL, 0, &dwRetBytes, NULL);
		SetEvent((HANDLE)pObj->m_NotifyHandle.m_hNotify);  //告诉RING0处理完毕
	} while (true);
	/*
	关闭驱动通讯
	*/
	CloseHandle(pObj->m_hMProtect);
	CloseHandle((HANDLE)pObj->m_NotifyHandle.m_hEvent);
	CloseHandle((HANDLE)pObj->m_NotifyHandle.m_hNotify);
	Wow64RevertWow64FsRedirectionFun Wow64RevertWow64FsRedirection = (Wow64RevertWow64FsRedirectionFun)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "Wow64RevertWow64FsRedirection");
	if (Wow64RevertWow64FsRedirection)
		Wow64RevertWow64FsRedirection(&pObj->m_pOldValue);
	return true;
goto_error:
	//AfxMessageBox(L"");
	return false;
}

BOOL CMProtectDlg::OnInitDialog()
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

	m_tab.InsertItem(0, L"进程保护", 50);
	m_tab.InsertItem(1, L"进程隔离", 50);

	m_dProcessProtect.Create(IDD_DIALOG_PROCESS_PROTECT, &m_tab);
	m_dProcessIsolate.Create(IDD_DIALOG_PROCESS_ISOLATE, &m_tab);
	//设定在Tab内显示的范围
	CRect rc;
	m_tab.GetClientRect(rc);
	rc.top += 20;
	rc.bottom -= 0;
	rc.left += 0;
	rc.right -= 0;
	m_dProcessProtect.MoveWindow(&rc);
	m_dProcessIsolate.MoveWindow(&rc);
	//把对话框对象指针保存起来
	pDialog[0] = &m_dProcessProtect;
	pDialog[1] = &m_dProcessIsolate;
	//显示初始页面
	pDialog[0]->ShowWindow(SW_SHOW);
	pDialog[1]->ShowWindow(SW_HIDE);
	//保存当前选择
	m_CurSelTab = 0;
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMProtectDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CMProtectDlg::OnPaint()
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
HCURSOR CMProtectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMProtectDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	//CDialogEx::OnOK();
}


void CMProtectDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnCancel();
}


void CMProtectDlg::OnTcnSelchangeTab(NMHDR *pNMHDR, LRESULT *pResult)
{
	//把当前的页面隐藏起来
	pDialog[m_CurSelTab]->ShowWindow(SW_HIDE);
	//得到新的页面索引
	m_CurSelTab = m_tab.GetCurSel();
	//把新的页面显示出来
	pDialog[m_CurSelTab]->ShowWindow(SW_SHOW);
	*pResult = 0;
}
