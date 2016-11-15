// dlgProcessIsolate.cpp : 实现文件
//

#include "stdafx.h"
#include "MProtect.h"
#include "dlgProcessIsolate.h"
#include "afxdialogex.h"


// dlgProcessIsolate 对话框

IMPLEMENT_DYNAMIC(dlgProcessIsolate, CDialogEx)

dlgProcessIsolate::dlgProcessIsolate(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_PROCESS_ISOLATE, pParent)
{

}

dlgProcessIsolate::~dlgProcessIsolate()
{
}

void dlgProcessIsolate::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_PROTCT_PROCESS_LIST, m_combox_processlist);
	DDX_Control(pDX, IDC_BUTTON_READ, m_button_read);
	DDX_Control(pDX, IDC_BUTTON_WRITE, m_button_write);
	DDX_Control(pDX, IDC_STATIC_PID, m_static_pid);
	DDX_Control(pDX, IDC_EDIT_AddrBase, m_edit_addr);
	DDX_Control(pDX, IDC_EDIT_VALUE, m_edit_value);
}


BEGIN_MESSAGE_MAP(dlgProcessIsolate, CDialogEx)
	ON_CBN_DROPDOWN(IDC_COMBO_PROTCT_PROCESS_LIST, &dlgProcessIsolate::OnCbnDropdownComboProtctProcessList)
	ON_CBN_SELCHANGE(IDC_COMBO_PROTCT_PROCESS_LIST, &dlgProcessIsolate::OnCbnSelchangeComboProtctProcessList)
	ON_BN_CLICKED(IDC_BUTTON_READ, &dlgProcessIsolate::OnBnClickedButtonRead)
	ON_BN_CLICKED(IDC_BUTTON_WRITE, &dlgProcessIsolate::OnBnClickedButtonWrite)
END_MESSAGE_MAP()


// dlgProcessIsolate 消息处理程序


void dlgProcessIsolate::OnCbnDropdownComboProtctProcessList()
{
	// 定义进程信息结构  
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	auto hProcessShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessShot == INVALID_HANDLE_VALUE) {
		return;
	}

	m_combox_processlist.ResetContent();

	if (Process32First(hProcessShot, &pe32)) {
		do {
			if (m_combox_processlist.FindString(-1, pe32.szExeFile) == CB_ERR) {
				m_combox_processlist.AddString(pe32.szExeFile);
			}

		} while (Process32Next(hProcessShot, &pe32));
	}
	CloseHandle(hProcessShot);
}


void dlgProcessIsolate::OnCbnSelchangeComboProtctProcessList()
{
	CString str;
	char Value[100] = { 0 };
	wchar_t pwText[100] = { 0 };
	m_combox_processlist.GetLBText(m_combox_processlist.GetCurSel(), str);
	


	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	auto hProcessShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessShot == INVALID_HANDLE_VALUE) {
		return;
	}

	//m_combox_processlist.ResetContent();

	if (Process32First(hProcessShot, &pe32)) {
		do {
			if (!wcscmp(pe32.szExeFile, str)) {
				itoa(pe32.th32ProcessID, Value, 10);
				m_CurlProcessId = pe32.th32ProcessID;
				DWORD dwNum = MultiByteToWideChar(CP_ACP, 0, Value, -1, NULL, 0);
				MultiByteToWideChar(CP_ACP, 0, Value, -1, pwText, dwNum);

				m_static_pid.SetWindowText(pwText);
				m_button_read.EnableWindow();
				m_button_write.EnableWindow();
				return;
			}

		} while (Process32Next(hProcessShot, &pe32));
	}
	CloseHandle(hProcessShot);

	
}

typedef struct _MDK_READ_MEMORY
{
	ULONG uProcessId;
	ULONG uAddrBase;
	ULONG Length;
}MDK_READ_MEMORY, *PMDK_READ_MEMORY;

typedef struct _MDK_WRITE_MEMORY
{
	ULONG uProcessId;
	ULONG uAddrBase;
	char Value[512];
	ULONG Length;
}MDK_WRITE_MEMORY, *PMDK_WRITE_MEMORY;

typedef struct _MDK_READWRITE_RET
{
	char Value[1024];
	ULONG ValueLen;
	ULONG Error;
}MDK_READWRITE_RET, *PMDK_READWRITE_RET;

#define IOCTL_MPROTECT_MDK_OPENPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_MDK_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MPROTECT_MDK_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)

enum MdkError
{
	OpenProcessFail = 1,
	ReadProcessFail = 2,
	WriteProcessFail = 4,
	Try = 8
};

void dlgProcessIsolate::OnBnClickedButtonRead()
{
	CString addr;
	CString value;
	MDK_READ_MEMORY read;
	MDK_READWRITE_RET ret;
	DWORD dwRetBytes = 0;
	wchar_t wvl[512] = { 0 };

	m_edit_addr.GetWindowTextW(addr);
	read.uAddrBase = _wtoi(addr.GetBuffer(0));
	read.Length = 4;
	read.uProcessId = m_CurlProcessId;
	if (0 == DeviceIoControl(theApp.dlg.m_hMProtect, IOCTL_MPROTECT_MDK_READ_MEMORY, &read, sizeof(read), &ret, sizeof(ret),&dwRetBytes, NULL)) {
		AfxMessageBox(L"驱动通讯失败!");
	}
	if (ret.Error){
		AfxMessageBox(L"执行失败 返回Error：");
	}
	else
	{
		_itow(*(PDWORD)ret.Value, wvl, 10);
		AfxMessageBox(wvl);
	}
}


void dlgProcessIsolate::OnBnClickedButtonWrite()
{
	
}
