// fireView.cpp : implementation of the CFireView class
//

#include "stdafx.h"
#include "fire.h"
#include "fireDoc.h"
#include "fireView.h"
#include "Sockutil.h"
#include "AddRuleDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CFireView

IMPLEMENT_DYNCREATE(CFireView, CFormView)

BEGIN_MESSAGE_MAP(CFireView, CFormView)
	ON_BN_CLICKED(IDC_ADDRULE, OnAddrule)
	ON_BN_CLICKED(IDC_START, OnStart)
	ON_BN_CLICKED(IDC_BLOCKPING, OnBlockping)
	ON_BN_CLICKED(IDC_BLOCKALL, OnBlockall)
	ON_BN_CLICKED(IDC_ALLOWALL, OnAllowall)
	ON_WM_CTLCOLOR()
	ON_BN_CLICKED(IDC_VIEWRULES, OnViewrules)
	ON_WM_SHOWWINDOW()
	ON_UPDATE_COMMAND_UI(ID_Start, OnUpdateStart)
	ON_COMMAND(ID_STOP, OnStop)
	ON_UPDATE_COMMAND_UI(ID_STOP, OnUpdateStop)
	ON_UPDATE_COMMAND_UI(ID_ALLOWALL, OnUpdateAllowall)
	ON_UPDATE_COMMAND_UI(ID_BLOCKALL, OnUpdateBlockall)
	ON_COMMAND(ID_Start, OnStart)
	ON_COMMAND(ID_BLOCKALL, OnBlockall)
	ON_COMMAND(ID_ALLOWALL, OnAllowall)
	ON_COMMAND(ID_BLOCKPING, OnBlockping)
	ON_UPDATE_COMMAND_UI(ID_BLOCKPING, OnUpdateBlockping)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CFireView construction/destruction
//初始化界面状态
CFireView::CFireView()
	: CFormView(CFireView::IDD)
{
	//********************************************************
	m_pBrush = new CBrush;
	ASSERT(m_pBrush);
	m_clrBk = RGB(0x00,0x66,0x99);
	m_clrText = RGB(0xff,0xff,0x00);
	m_pBrush->CreateSolidBrush(m_clrBk);
	m_pColumns = new CStringList;
	ASSERT(m_pColumns);
	_rows = 1;
	start = TRUE;
	block = TRUE;
	allow = TRUE;
	ping = TRUE;
}

CFireView::~CFireView()
{
	if (m_pBrush)
		delete m_pBrush;
}

void CFireView::DoDataExchange(CDataExchange* pDX)
{
	CFormView::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_RESULT, m_cResult);
	DDX_Control(pDX, IDC_VIEWRULES, m_cvrules);
	DDX_Control(pDX, IDC_BLOCKPING, m_cping);
	DDX_Control(pDX, IDC_BLOCKALL, m_cblockall);
	DDX_Control(pDX, IDC_START, m_cstart);
}

BOOL CFireView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: Modify the Window class or styles here by modifying
	//  the CREATESTRUCT cs
	//*****************************************************************
	
	m_filterDriver.LoadDriver("IpFilterDriver", "System32\\Drivers\\IpFltDrv.sys", NULL, TRUE);

	//we don't deregister the driver at destructor
	m_filterDriver.SetRemovable(FALSE);

	//we load the Filter-Hook Driver
	m_ipFltDrv.LoadDriver("DrvFltIp", NULL, NULL, TRUE);
	//****************************************************************
	return CFormView::PreCreateWindow(cs);
}

void CFireView::OnInitialUpdate()
{
	CFormView::OnInitialUpdate();
	GetParentFrame()->RecalcLayout();
	ResizeParentToFit();
	m_parent = (CMainFrame*)GetParent();
	ShowHeaders();
}

/////////////////////////////////////////////////////////////////////////////
// CFireView diagnostics

#ifdef _DEBUG
void CFireView::AssertValid() const
{
	CFormView::AssertValid();
}

void CFireView::Dump(CDumpContext& dc) const
{
	CFormView::Dump(dc);
}

#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CFireView message handlers

void CFireView::OnAddrule() 
{
	// TODO: Add your control notification handler code here
	m_Addrule.DoModal ();	
}


void CFireView::OnStart() 
{
	CString		_text;
	m_cstart.GetWindowText(_text);
	
	//Start响应事件
	if(_text != "Stop" )
	{
		if(m_ipFltDrv.WriteIo(START_IP_HOOK, NULL, 0) != DRV_ERROR_IO)
		{
			MessageBox("Firewall Started Sucessfully");
			start = FALSE;
			m_cstart.SetWindowText("Stop");
			m_parent ->SetOnlineLed(TRUE);
			m_parent ->SetOfflineLed(FALSE);
			
		}
	}

	//Stop响应事件
	else
	{
		if(m_ipFltDrv.WriteIo(STOP_IP_HOOK, NULL, 0) != DRV_ERROR_IO)
		{
			MessageBox("Firewall Stopped Succesfully");
			m_cstart.SetWindowText("Start");
			start = TRUE;
			m_parent ->SetOnlineLed(FALSE);
			m_parent ->SetOfflineLed(TRUE);
			block = TRUE;
			allow = TRUE;
			ping = TRUE;
		}
	}	
}

//禁用所有的ICMP包
void CFireView::OnBlockping() 
{
	int result = MessageBox(TEXT("Blocking ICMP Packets ? "), NULL, MB_ICONINFORMATION|MB_YESNO);
    switch(result)/*注意！使用Unicode应用TEXT包围字串*/
	{
		case IDYES: 
			//声明icmp过滤器ICMPflt
			IPFilter ICMPflt;
			//指定过滤器属性
			ICMPflt.protocol = 1;	// ICMP协议
			ICMPflt.sourceIp = 0;	// 指定所有源ip的包
			ICMPflt.destinationIp = 0;// 指定所有目的ip的包
			ICMPflt.sourceMask = 0; //所有源ip子网掩码的包
			ICMPflt.destinationMask = 0;//所有目的ip子网掩码的包
			ICMPflt.sourcePort = 0;	// 所有源端口的包
			ICMPflt.destinationPort	= 0;		// 所有目的端口的包	
			ICMPflt.drop = TRUE; //指定丢包
			m_Addrule.AddFilter(ICMPflt);
			allow = TRUE;
			ping = FALSE;

			break;

		case IDNO: 
			
			break;
	}

}

//禁用所有包
void CFireView::OnBlockall() 
{
	int result = MessageBox(TEXT("Blocking All Packets ? "), NULL, MB_ICONINFORMATION|MB_YESNO);
    switch(result)/*注意！使用Unicode应用TEXT包围字串*/
	{
		case IDYES: 
			//声明ip过滤器IPflt
			IPFilter IPflt;
			//指定过滤器属性
			IPflt.protocol = 0;	// 所有协议
			IPflt.sourceIp = 0;	// 指定所有源ip的包
			IPflt.destinationIp = 0;// 指定所有目的ip的包
			IPflt.sourceMask = 0; //所有源ip子网掩码的包
			IPflt.destinationMask = 0;//所有目的ip子网掩码的包
			IPflt.sourcePort = 0;	// 所有源端口的包
			IPflt.destinationPort	= 0;		// 所有目的端口的包	
			IPflt.drop = TRUE; //指定丢包
			//添加过滤器ICMPflt到Addrule
			m_Addrule.AddFilter(IPflt);
			block = FALSE;
			allow = TRUE;

			break;

		case IDNO: 
			
			break;
	}
}

//启用所有包
void CFireView::OnAllowall() 
{
	int result = MessageBox(TEXT("Receiving All Packets ? "), NULL, MB_ICONINFORMATION|MB_YESNO);
    switch(result)/*注意！使用Unicode应用TEXT包围字串*/
	{
		case IDYES: 
			if(m_ipFltDrv.WriteIo(CLEAR_FILTER,NULL,0) != DRV_ERROR_IO)
			{
				MessageBox("All Rules have been cleared");
				//把列单里的规则删掉，并把行数归为1
				m_cResult.DeleteAllItems();
				_rows = 1;
				block = TRUE;
				allow = FALSE;
				ping = TRUE;
			}

			break;

		case IDNO: 
			
			break;
	}
}

//使用指定过滤规则
BOOL CFireView::ImplementRule(void)
{
	HANDLE hfile;
	//打开文件
	hfile = CreateFile("saved.rul",
							GENERIC_READ | GENERIC_WRITE,
							FILE_SHARE_READ | FILE_SHARE_WRITE,        //读写共享文件
							NULL,						
							OPEN_EXISTING,			// 打开文件，且文件必须已经存在
							NULL,
							NULL);
	if(hfile == INVALID_HANDLE_VALUE){
		MessageBox("Can not open the file");
		CloseHandle(hfile);
		return FALSE;
	}
	else{
		int result;
		DWORD nbytesRead;
		char ipBuff;
		CString	_buff = "";
		//每次读取一个字符nbytesRead，暂存为ipBuff
		result = ReadFile(hfile, &ipBuff, 1, &nbytesRead, NULL);
		while(result && nbytesRead != 0){
			//将每行数据存为_buff
			if(ipBuff != '\n')
				_buff += ipBuff;
			else{
				//MessageBox(_buff);
				ParseToIp(_buff);
				_buff = "";
			}
			result = ReadFile(hfile, &ipBuff, 1, &nbytesRead, NULL);
		}
		CloseHandle(hfile);
		return TRUE;
	}	
}


void CFireView:: ParseToIp(CString str)
{
	// Your code, please pay attention to the form of IP address and port!
	//把每一行的字符串根据逗号分隔开
	CString strTmp[8];
	for(int i = 0; i < 8; i ++){
		AfxExtractSubString(strTmp[i], (LPCTSTR)str, i, ',');
	}
	//将每行数据添加在Item列表里的首行（第0行）
	AddItem(0,0,(LPCTSTR)strTmp[0]);
	AddItem(0,1,(LPCTSTR)strTmp[1]);
	AddItem(0,2,(LPCTSTR)strTmp[2]);
	AddItem(0,3,(LPCTSTR)strTmp[3]);
	AddItem(0,4,(LPCTSTR)strTmp[4]);
	AddItem(0,5,(LPCTSTR)strTmp[5]);
	int	_proto = atoi((LPCTSTR)strTmp[6]);
	CString	proto;
	if(_proto == 0)
		proto = "ANY";
	else if(_proto == 1)
		proto = "ICMP";
	else if(_proto == 6)
		proto = "TCP";
	else if(_proto == 17)
		proto = "UDP";
	AddItem(0,6,((LPCTSTR)proto));
	int _action = atoi((LPCTSTR)strTmp[7]);
	if(_action == 0)
		AddItem(0,7,"ALLOW");
	if(_action == 1)
		AddItem(0,7,"DENY");
	//对应行数增加1
	_rows ++;
	
}


//增加过滤规则表列
BOOL CFireView::AddColumn(LPCTSTR strItem,int nItem,int nSubItem,int nMask,int nFmt)
{
	LV_COLUMN lvc;
	lvc.mask = nMask;
	lvc.fmt = nFmt;
	lvc.pszText = (LPTSTR) strItem;
	lvc.cx = m_cResult.GetStringWidth(lvc.pszText) + 25;
	if(nMask & LVCF_SUBITEM)
	{
		if(nSubItem != -1)
			lvc.iSubItem = nSubItem;
		else
			lvc.iSubItem = nItem;
	}
	return m_cResult.InsertColumn(nItem,&lvc);
}

//增加过滤规则表一个元素
BOOL CFireView::AddItem(int nItem, int nSubItem, LPCTSTR strItem, int nImageIndex)
{
	LV_ITEM lvItem;
	lvItem.mask = LVIF_TEXT;
	lvItem.iItem = nItem;
	lvItem.iSubItem = nSubItem;
	lvItem.pszText = (LPTSTR) strItem;

	if(nImageIndex != -1)
	{
		lvItem.mask |= LVIF_IMAGE;
		lvItem.iImage |= LVIF_IMAGE;
	}
	if(nSubItem == 0)
		return m_cResult.InsertItem(&lvItem);

	return m_cResult.SetItem(&lvItem);
}

void CFireView::AddHeader(LPTSTR hdr)
{
	if (m_pColumns)
		m_pColumns->AddTail(hdr);
}

void CFireView::ShowHeaders()
{
	int nIndex = 0;
	POSITION pos = m_pColumns->GetHeadPosition();
	while (pos)
	{
		CString hdr = (CString)m_pColumns->GetNext(pos);
		AddColumn(hdr,nIndex++);
	}
}

void CFireView::OnShowWindow(BOOL bShow, UINT nStatus) 
{
	CFormView::OnShowWindow(bShow, nStatus);
	AddHeader(_T("Dest IP"));
	AddHeader(_T("Dest MASK"));
	AddHeader(_T("Dest PORT"));
	AddHeader(_T("Source IP"));
	AddHeader(_T("Source MASK"));
	AddHeader(_T("Source PORT"));
	AddHeader(_T("PROTOCOL"));
	AddHeader(_T("ACTION"));
}

void CFireView::OnStop() 
{
	OnStart();	
}

void CFireView::OnUpdateStart(CCmdUI* pCmdUI) 
{	
	// TODO: Add your command update UI handler code here
	pCmdUI ->Enable(start);	
}

void CFireView::OnUpdateStop(CCmdUI* pCmdUI) 
{
	// TODO: Add your command update UI handler code here
	pCmdUI ->Enable(!start);
}

void CFireView::OnUpdateAllowall(CCmdUI* pCmdUI) 
{
	// TODO: Add your command update UI handler code here
	pCmdUI ->Enable(allow);
}

void CFireView::OnUpdateBlockall(CCmdUI* pCmdUI) 
{
	// TODO: Add your command update UI handler code here
	pCmdUI ->Enable(block);
}

void CFireView::OnUpdateBlockping(CCmdUI* pCmdUI) 
{
	// TODO: Add your command update UI handler code here
	pCmdUI ->Enable(ping);	
}

BOOL CFireView::Create(LPCTSTR lpszClassName, LPCTSTR lpszWindowName, DWORD dwStyle, const RECT& rect, CWnd* pParentWnd, UINT nID, CCreateContext* pContext) 
{
	return CFormView::Create(lpszClassName, lpszWindowName, dwStyle, rect, pParentWnd, nID, pContext);
}
//***********************************************************************

HBRUSH CFireView::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor) 
{
	HBRUSH hbr = CFormView::OnCtlColor(pDC, pWnd, nCtlColor);
	switch(nCtlColor)
	{
	case CTLCOLOR_BTN:
	case CTLCOLOR_STATIC:
		pDC->SetBkColor(m_clrBk);
		pDC->SetTextColor(m_clrText);
	case CTLCOLOR_DLG:
		return static_cast<HBRUSH>(m_pBrush->GetSafeHandle());
	}
	return CFormView::OnCtlColor(pDC,pWnd,nCtlColor);
}

void CFireView::OnViewrules() 
{
	ImplementRule();	
}
