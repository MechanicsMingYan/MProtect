#pragma once
#include "afxwin.h"


// dlgProcessIsolate 对话框

class dlgProcessIsolate : public CDialogEx
{
	DECLARE_DYNAMIC(dlgProcessIsolate)

public:
	dlgProcessIsolate(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~dlgProcessIsolate();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PROCESS_ISOLATE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnCbnDropdownComboProtctProcessList();
	CComboBox m_combox_processlist;
	afx_msg void OnCbnSelchangeComboProtctProcessList();
	CButton m_button_read;
	CButton m_button_write;
	CStatic m_static_pid;
	afx_msg void OnBnClickedButtonRead();
	afx_msg void OnBnClickedButtonWrite();
	CEdit m_edit_addr;
	CEdit m_edit_value;
	DWORD m_CurlProcessId;
};
