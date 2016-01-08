#include "stdafx.h"
#include <winsock2.h> 
#include <cstring>
#include <iostream>

#include "MD5.h"
#include "ras.h"
#include "rdial.h"

#pragma comment(lib, "ws2_32") 
#pragma comment(lib, "RASAPI32.LIB")


Rdial::Rdial(CString username, INT ver, long lasttimec)
:m_username(username),RADIUS("cqxinliradius002"),LR("\r\n")
{
	m_ver = ver;
	m_lasttimec = lasttimec;
}


CString Rdial::Realusername()
{
	time_t m_time = 0;						//得到系统时间，从1970.01.01.00:00:00 开始的秒数
	long m_time1c = 0;						//时间初处理m_time1c为结果,经过时间计算出的第一次加密
	long temp = 0;
	int i = 0, j = 0, k = 0;
	unsigned int lenth = 0;

	unsigned char ss[4] = {0};		//源数据1,对m_time1convert进行计算得到格式符源数据
	unsigned char pad1[4] = {0};

	//格式符初加密
	unsigned char pp[4] = {0};
	unsigned char pf[6] = {0};
	char temp1[100];

	CString strS1;						//md5加密参数的一部分,ss2的整体形式
	CString strInput;
	CString m_formatsring;				//由m_timece算出的字符串,一般为可视字符
	CString m_md5;						//对初加密(m_timec字符串表示+m_username+radius)的MD5加密
	CString m_md5use;					//md5 Lower模式的前两位


	//取得系统时间m_time
	time(&m_time);
	//时间初处理m_time1c为结果,经过时间计算出的第一次加密
	//子函数////////////////////////////

	m_time1c = (m_time * 0x66666667) >> 0x21;

	//5秒内动态用户名一致处理
	if (m_time1c <= m_lasttimec)
	{
		m_time1c = m_lasttimec + 1;
	}
	m_lasttimec = m_time1c;

	temp = htonl(m_time1c);
	memcpy(pad1, &temp, 4);

	for (int i = 0; i < 4; i++)
	{
		strS1 += pad1[i];
	}

	memcpy(ss, &m_time1c, 4);

	//子函数////////////////////////////

	for (i = 0; i < 32; i++)
	{
		j = i / 8;
		k = 3 - (i % 4);
		pp[k] *= 2;
		if (ss[j] % 2 == 1)
		{
			pp[k]++;
		}
		ss[j] /= 2;
	}
	

	pf[0] = pp[3] / 0x4;
	pf[1] = (pp[2] / 0x10) | ((pp[3] & 0x3) * 0x10);
	pf[2] = (pp[1] / 0x40) | (pp[2] & 0x0F) * 0x04;
	pf[3] = pp[1] & 0x3F;
	pf[4] = pp[0] / 0x04;
	pf[5] = (pp[0] & 0x03) * 0x10;

	/////////////////////////////////////

	for (i = 0; i < 6; i++)
	{
		pf[i] += 0x20;
		if ((pf[i]) >= 0x40)
		{
			pf[i]++;
		}
	}
	 
	for (i = 0; i < 6; i++)
	{
		m_formatsring += pf[i];
	}
	
	/////////////////////////////////////

	strInput = strS1 + m_username.Left(m_username.FindOneOf("@")) + RADIUS;
	lenth = 20 + m_username.FindOneOf("@");
	memcpy(temp1, strInput.GetBuffer(100), 100);
	m_md5 = MD5String(temp1, lenth);
	m_md5use = m_md5.Left(2);
	m_realusername = LR + m_formatsring + m_md5use + m_username;

// #define _debug	
// #ifdef _debug
// cout<<"m_username.FindOneOf(\"@\"):"<<m_username.FindOneOf("@")<<"\nm_username.left():"<<m_username.Left(m_username.FindOneOf("@"))<<endl;	
// cout<<"sizeof(int):"<<sizeof(int)<<",m_formatsring:"<<m_formatsring<<endl<<"temp1:"<<temp1<<",m_md5:"<<m_md5<<endl<<"m_realusername:"<<m_realusername<<", m_md5use:"<< m_md5use<<endl;
// #endif
	return m_realusername;
}


bool  Rdial::CreateRASLink()
{
	LPRASENTRY lpRasEntry = NULL;
	DWORD cb = sizeof(RASENTRY);
	DWORD dwBufferSize = 0;
	DWORD dwRet = 0;

	//  取得entry的大小,这句也不知道是不是必须的,因为sizeof(RASENTRY)和这里取到的dwBufferSize是一样的,不过还是Get一下安全点 
	RasGetEntryProperties(NULL, "", NULL, &dwBufferSize, NULL, NULL); 
	if (dwBufferSize == 0)
		return false ;

	lpRasEntry = (LPRASENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
	if (lpRasEntry == NULL)
		return false ;

	ZeroMemory(lpRasEntry, sizeof(RASENTRY));
	lpRasEntry->dwSize		= dwBufferSize;
	lpRasEntry->dwfOptions  = RASEO_RemoteDefaultGateway|RASEO_PreviewPhoneNumber|RASEO_PreviewUserPw;  // 这里的几个选项挺重要的， RASEO_RemoteDefaultGateway这个选项把创建的连接设置为默认连接， RASEO_PreviewPhoneNumber 对应选项中的提示输入电话号码，RASEO_PreviewUserPw对应选项中的提示用户名和密码 
	lpRasEntry->dwType		= RASET_Internet;

	lstrcpy(lpRasEntry->szDeviceType, RASDT_PPPoE);
	lstrcpy(lpRasEntry->szDeviceName, "connect");
	lpRasEntry->dwfNetProtocols   = RASNP_Ip;
	lpRasEntry->dwFramingProtocol = RASFP_Ppp;

	dwRet = RasSetEntryProperties(NULL, "connect", lpRasEntry, dwBufferSize, NULL, 0);  //  创建连接 
	// The RasSetEntryProperties function changes the connection information for an entry in the phone book or creates a new phone-book entry.（reference MSDN）
	HeapFree(GetProcessHeap(), 0, (LPVOID)lpRasEntry);

	if (dwRet != 0)
		return false;
	return true;
}


void banner()
{
	printf("\
 ____     _ _       _ \n\
|  _ \\ __| (_) __ _| |\n\
| |_) / _` | |/ _` | |\n\
|  _ < (_| | | (_| | |\n\
|_| \\_\\__,_|_|\\__,_|_|\t(alpha-1.1)\n\n\
    Author: Purpleroc@0xfa.club		\n\
    Url:    http://purpleroc.com    |\n\
    Email:  admin@0xfa.club         |\n\
    Update: 2016-01-08              |\n\
------------------------------------|\n");
}


int main (int argc,char **argv)
{
	banner();
	if (argc != 3)
	{
		printf("Parameter Error!\nUseage:rdial [username] [password]\n");
		system("pause");
		exit(0);
	}

	Rdial real(argv[1]);

	// 创建名为connect的拨号实体
	if (!real.CreateRASLink())
	{
		printf("Create Entry Failed!\n");
		exit(0);
	}

	// 同步调用方式
	RASDIALPARAMS RasDialParams;
	HRASCONN m_hRasconn;
	// 总是设置dwSize 为RASDIALPARAMS结构的大小
	RasDialParams.dwSize = sizeof(RASDIALPARAMS);
	m_hRasconn = NULL; 

	// 设置szEntryName为空字符串将允许RasDial使用缺省拨号属性
	_tcscpy(RasDialParams.szEntryName, _T("connect")); 
	RasDialParams.szPhoneNumber[0] =  _T('\0');
	RasDialParams.szCallbackNumber[0] = _T('\0');
	_tcscpy(RasDialParams.szUserName, _T(real.Realusername()));
	_tcscpy(RasDialParams.szPassword, _T(argv[2]));
	RasDialParams.szDomain[0] =  _T('\0');

	// 同步方式调用RasDial(第五个参数为NULL)
	DWORD Ret = RasDial(NULL, NULL, &RasDialParams, 0, NULL, &m_hRasconn);
	if (Ret != 0) 
	{ 
		TCHAR szBuff[MAX_PATH];
		_stprintf(szBuff,_T("RasDial失败: Error = %d\n"), Ret);
		OutputDebugString(szBuff);
		printf (szBuff);
		return 1;
	}
	else
	{
		printf("使用 %s 连接成功\n",argv[1]);
		return 0;
	}
}
