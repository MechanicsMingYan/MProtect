
// IMProtectDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include "..\LMProtect\IMProtect.h"
#include "..\LMProtect\IMGetData.h"
#include "..\LMProtect\GetShadowSsdtSym.h"

#pragma comment(lib,"LMProtect.lib")
// CIMProtectDlg 对话框
class CIMProtectDlg : public CDialogEx
{
// 构造
public:
	CIMProtectDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_IMPROTECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	IMProtect * Improtect_;
	IMGetData * Imgetdata_;
	GetShadowSsdtSym * GetShadowSsdtSym_;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListCtrl list_process_protect_;
	afx_msg void OnCbnDropdownCombo1();
	afx_msg void OnCbnSelchangeCombo1();
	CComboBox combox_processlist_;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnCbnDropdownCombo2();
	afx_msg void OnBnClickedButton3();
	CListCtrl list_process_hide_;
	CComboBox combox_processlist2_;
	afx_msg void OnBnClickedButton2();
	afx_msg void OnNMRClickList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButton4();
	void AddExtensionInfo(char *English, char* Chinese, bool Support);
	void AddExtensionInfo2(char *English, char* Chinese, ULONGLONG Support);
	CListCtrl list_infoshow_;
	afx_msg void OnBnClickedButtonGetCpuino();
	afx_msg void OnBnClickedButtonGetDiskinfo();
};
