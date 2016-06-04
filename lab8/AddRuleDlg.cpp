// AddRuleDlg.cpp : implementation file
//

#include "stdafx.h"
#include "fire.h"
#include "AddRuleDlg.h"
//********************************************************
#include <winsock2.h>
#include <string.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CAddRuleDlg dialog


CAddRuleDlg::CAddRuleDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CAddRuleDlg::IDD, pParent)
{
	m_sdadd = _T("");
	m_sdport = _T("");
	m_ssadd = _T("");
	m_ssport = _T("");
	ipFltDrv.LoadDriver("DrvFltIp", NULL, NULL, TRUE);	
}


void CAddRuleDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAddRuleDlg)
	DDX_Control(pDX, IDC_COMBO2, m_protocol);
	DDX_Control(pDX, IDC_COMBO1, m_action);
	DDX_Text(pDX, IDC_DADD, m_sdadd);
	DDV_MaxChars(pDX, m_sdadd, 15);
	DDX_Text(pDX, IDC_DPORT, m_sdport);
	DDX_Text(pDX, IDC_SADD, m_ssadd);
	DDV_MaxChars(pDX, m_ssadd, 15);
	DDX_Text(pDX, IDC_SPORT, m_ssport);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CAddRuleDlg, CDialog)
	//{{AFX_MSG_MAP(CAddRuleDlg)
	//ON_BN_CLICKED(IDC_ADD, OnAdd)
	ON_EN_KILLFOCUS(IDC_SADD, OnKillfocusSadd)
	ON_EN_KILLFOCUS(IDC_DADD, OnKillfocusDadd)
	ON_BN_CLICKED(IDC_ADDSAVE, OnAddsave)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////

//**************************************************************************
//�����IPFilter������ָ��������
DWORD CAddRuleDlg::AddFilter(IPFilter pf)
{

	DWORD result = ipFltDrv.WriteIo(ADD_FILTER, &pf, sizeof(pf));
	if (result != DRV_SUCCESS) 
	{
		AfxMessageBox("Unable to add rule to the driver");
		return FALSE;
	}

	else
		return TRUE;
}

//*************************************************************************
//��������IP��ַ�Ƿ�Ƿ�

BOOL CAddRuleDlg::Verify(CString str)
{
	//MessageBox("�˹�����Ҫ����ʵ�֣�");
	// Your code
	//return TRUE;
	BOOL flag = TRUE;
	int len = str.GetLength();
	int dot = 0;
	int session = 0;
	for(int i = 0; i < len; i ++){
		if(str[i] == '.'){
			if(session >= 0 && session <= 255){
				session = 0;
				continue;
			}
			else{
				flag = FALSE;
				break;
			}
		}
		else if(i == len-1){
			int d = str[i] - '0';
			if(d <= 9 && d >= 0){
				session = session * 10 + d;
			}
			else{
				flag = FALSE;
				break;
			}
			if(session >= 0 && session <= 255){
				continue;
			}
			else{
				flag = FALSE;
				break;
			}

		}
		else{
			int d = str[i] - '0';
			if(d <= 9 && d >= 0){
				session = session * 10 + d;
			}
			else{
				flag = FALSE;
				break;
			}
		}
	}
	return flag;
}

//*****************************************************************

void CAddRuleDlg::OnKillfocusSadd() 
{
	// TODO: Add your control notification handler code here
	UpdateData();
	BOOL bresult = Verify(m_ssadd);
	if(bresult == FALSE)
		MessageBox("Invalid IP Address");	
}

void CAddRuleDlg::OnKillfocusDadd() 
{
	// TODO: Add your control notification handler code here
	// This will check wether the IP address you had given
	// corresponds to a valid IP address or not. If not it
	// will prompt you for a valid IP address.

	UpdateData();
    BOOL bresult = Verify(m_sdadd);
	if(bresult == FALSE)
		MessageBox("Invalid IP Address");
	
}

//��������Ĺ���
DWORD CAddRuleDlg::OnAdd() 
{
	//��ʼ���Ի����е�����
	UpdateData();
	BOOL Drop;
	int	Proto;
	int action = m_action.GetCurSel();
	char ch0[30];
	if(action == 0)//allow
		Drop = FALSE; 
	else//deny
		Drop = TRUE;
	int proto = m_protocol.GetCurSel();
	if(proto == 0)//ICMP��Э���
		Proto = 1;
	else if(proto == 1)//IP(UDP��Э���)
		Proto = 17;
	else if(proto == 2)//TCP��Э���
		Proto = 6;
	wsprintf(ch0,"Action: %d, Protocol Number: %d", action, Proto);
	MessageBox(ch0);

	IPFilter ip;
	ip.sourceIp = inet_addr((LPCTSTR)m_ssadd);
	ip.destinationIp = inet_addr((LPCTSTR)m_sdadd);
	ip.sourceMask = inet_addr("255.255.255.255");
	ip.destinationMask = inet_addr("255.255.255.255");
	ip.sourcePort = htons(atoi((LPCTSTR)m_ssport));
	ip.destinationPort = htons(atoi((LPCTSTR)m_sdport));
	ip.protocol = Proto;
	ip.drop = Drop;
	DWORD result = AddFilter(ip);
	return result;
}
//�������Ĺ���д���ļ�,
//����OnAdd������ӹ����ٵ���SaveFile������saved.rul�ļ���
void CAddRuleDlg::OnAddsave() 
{
	// Your code
	//�������Ĺ���ӽ�filter��
	if(OnAdd() == FALSE)
		return;
	else{
		//�������Ĺ��򱣴���saved.rul�ļ���
		int	Proto;
		BOOL Drop;
		if(m_action.GetCurSel() == 0)//allow
			Drop = FALSE; 
		else//deny
			Drop = TRUE;
		if(m_protocol.GetCurSel() == 0)//ICMP��Э���
			Proto = 1;
		else if(m_protocol.GetCurSel() == 1)//UDP��Э���
			Proto = 17;
		else if(m_protocol.GetCurSel() == 2)//TCP��Э���
			Proto = 6;
		char ch1[100];
		wsprintf(ch1,"%s,%s,%s,%s,%s,%s,%d,%d\n",
				 m_sdadd,
				 "255.255.255.255",
				 m_sdport,
				 m_ssadd,
				 "255.255.255.255",
				 m_ssport,
				 Proto,
				 Drop);
		//��saved.rul
		if( NewFile() == FALSE)
			MessageBox("Can not create a file");				//create a new file		
		//�������Ĺ����ַ���д��saved.rul
		GotoEnd();
		if( SaveFile(ch1) == FALSE)
			MessageBox("Can not save the file");
		//�ر�saved.rul
		if(CloseFile() == FALSE)
			MessageBox("Can not close the file");
	}
	
}
BOOL CAddRuleDlg::NewFile(void)
{
/* This will open an existing file or open a new file if the file
   doesnot exists
*/
	_hFile = CreateFile("saved.rul",
						GENERIC_WRITE | GENERIC_READ,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL,
						OPEN_ALWAYS,
						NULL,
						NULL);

	/* If unable to obtain the handle values*/
	if(_hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	return TRUE;		// File has been opened succesfully
}
//******************************************************
// This will move the file pointer to the end of the file so that 
// it can be easily added to the file

DWORD CAddRuleDlg::GotoEnd(void)
{
	DWORD val;

	DWORD size = GetFileSize(_hFile,NULL);
	if(size == 0)
		return size;
	val = SetFilePointer(_hFile,0,NULL,FILE_END);

	/* If unable to set the file pointer to the end of the file */
 	if(val == 0)
	{
		MessageBox("Unable to set file pointer");
		return GetLastError();
	}
	return val;
}

/* This code will save the data into the file which is given by the parameter*/

DWORD CAddRuleDlg::SaveFile(char*  str)
{
	DWORD   bytesWritten;
	/* Try to write the string passed as parameter to the file and if any 
		error occurs return the appropriate values
	*/
	DWORD	_len =  strlen(str);
	if(WriteFile(_hFile, str, _len, &bytesWritten, NULL) == 0)
	{
		MessageBox("Unalbe to write to the file\n");
		return FALSE;
	}
	return TRUE;
}

/* This function will close the existing file */
BOOL CAddRuleDlg::CloseFile()
{
	if(!_hFile)
	{
	//	MessageBox("File handle does not exist");
		return FALSE;
	}

// if there is an appropriate handle then close it and return app values
    else{
		if(CloseHandle(_hFile) != 0)
		{
			return TRUE;
		}
		else 
			return FALSE;
	}
}