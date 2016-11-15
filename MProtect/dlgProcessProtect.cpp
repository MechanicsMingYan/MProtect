// dlgProcessProtect.cpp : 实现文件
//

#include "stdafx.h"
#include "MProtect.h"
#include "dlgProcessProtect.h"
#include "afxdialogex.h"


// dlgProcessProtect 对话框

IMPLEMENT_DYNAMIC(dlgProcessProtect, CDialogEx)

dlgProcessProtect::dlgProcessProtect(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_PROCESS_PROTECT, pParent)
{

}

dlgProcessProtect::~dlgProcessProtect()
{
}

void dlgProcessProtect::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_PROTCT_PROCESS_LIST, m_combox_processlist);
	DDX_Control(pDX, IDC_BUTTON_PROCESS_PROTECT_ADD, m_button_add);
	DDX_Control(pDX, IDC_LIST_PROCESS_PROTECT_LIST, m_list_process);
}


BEGIN_MESSAGE_MAP(dlgProcessProtect, CDialogEx)
	ON_CBN_DROPDOWN(IDC_COMBO_PROTCT_PROCESS_LIST, &dlgProcessProtect::OnCbnDropdownComboProtctProcessList)
	ON_CBN_SELCHANGE(IDC_COMBO_PROTCT_PROCESS_LIST, &dlgProcessProtect::OnCbnSelchangeComboProtctProcessList)
	ON_BN_CLICKED(IDC_BUTTON_PROCESS_PROTECT_ADD, &dlgProcessProtect::OnBnClickedButtonProcessProtectAdd)
	ON_BN_CLICKED(IDC_BUTTON_PROCESS_PROTECT_CONFIRM, &dlgProcessProtect::OnBnClickedButtonProcessProtectConfirm)
END_MESSAGE_MAP()


// dlgProcessProtect 消息处理程序


void dlgProcessProtect::OnCbnDropdownComboProtctProcessList()
{
	// 定义进程信息结构  
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	auto hProcessShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessShot == INVALID_HANDLE_VALUE){
		return ;
	}

	m_combox_processlist.ResetContent();
	
	if (Process32First(hProcessShot, &pe32)){
		do {
			if (m_combox_processlist.FindString(-1, pe32.szExeFile) == CB_ERR){
				m_combox_processlist.AddString(pe32.szExeFile);
			}
			
		} while (Process32Next(hProcessShot, &pe32));
	}
	CloseHandle(hProcessShot);
}


void dlgProcessProtect::OnCbnSelchangeComboProtctProcessList()
{
	m_button_add.EnableWindow();
}


void dlgProcessProtect::OnBnClickedButtonProcessProtectAdd()
{
	LVFINDINFO info;
	CString str;
	m_combox_processlist.GetLBText(m_combox_processlist.GetCurSel(), str);
	if (str != L"") {
		info.flags = LVFI_PARTIAL | LVFI_STRING;
		info.psz = str;
		if (m_list_process.FindItem(&info) == CB_ERR) {
			m_list_process.InsertItem(0, str);
		}
	}
}


BOOL dlgProcessProtect::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	DWORD dwStyle = m_list_process.GetExtendedStyle();
	dwStyle |= LVS_EX_FULLROWSELECT;//选中某行使整行高亮（只适用与report风格的listctrl）
	dwStyle |= LVS_EX_GRIDLINES;//网格线（只适用与report风格的listctrl）

	m_list_process.SetExtendedStyle(dwStyle); //设置扩展风格
	m_list_process.SetExtendedStyle(dwStyle); //设置扩展风格
	m_list_process.InsertColumn(0, L"ProcessName", LVCFMT_LEFT, 160);
	return TRUE; 
}



void dlgProcessProtect::OnBnClickedButtonProcessProtectConfirm()
{

	DWORD dwRetBytes = 0;
	UINT Pass = FALSE;
	TRY_SOKE soke;
	soke.ProcessId = NULL;
	wcscpy(soke.VisitInfo[0], L"");
	//发送事件给r0
	
	if (0 == DeviceIoControl(theApp.dlg.m_hMProtect, IOCTL_MPROTECT_RESET_PROTECTION, &Pass, sizeof(UINT), NULL, 0, &dwRetBytes, NULL)){
		AfxMessageBox(L"应用失败!");
		return;
	}

	int Num = m_list_process.GetItemCount();
	for (int i = 0; i < Num ; i++){
		auto Text = m_list_process.GetItemText(i, 0);
		wcscpy(soke.ProcessInfo, Text.GetBuffer(0));
		if (0 == DeviceIoControl(theApp.dlg.m_hMProtect, IOCTL_MPROTECT_ADD_PROTECTION, &soke, sizeof(TRY_SOKE), NULL, 0, &dwRetBytes, NULL)) {
			AfxMessageBox(L"数据传输失败!");
			return;
		}
	}
	AfxMessageBox(L"应用成功!");
}
