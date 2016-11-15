
// MProtectDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "dlgProcessProtect.h"
#include "dlgProcessIsolate.h"
#include "DriverHelp.h"

// CMProtectDlg 对话框
class CMProtectDlg : public CDialogEx
{
// 构造
public:
	CMProtectDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MPROTECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	CString GetAppFolder();
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	int m_CurSelTab; 
	CString g_VdPath;
	std::string g_IniPathA;
	CString m_DriverPath;
	HANDLE m_hMProtect;
	NOTIFY_HANDLE m_NotifyHandle;
	PVOID m_pOldValue;
	CTabCtrl m_tab;
	CDialog* pDialog[10];
	dlgProcessProtect m_dProcessProtect;
	dlgProcessIsolate m_dProcessIsolate;
	CDriverHelp DriverHelp;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnTcnSelchangeTab(NMHDR *pNMHDR, LRESULT *pResult);
	static UINT ThreadSockDriverFunc(LPVOID pParam);
};
