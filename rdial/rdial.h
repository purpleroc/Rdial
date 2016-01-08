
#include <string>
#include <iostream>

using namespace std;
typedef int INT;
 
typedef __int64   LONG64;

class Rdial
{
public:
	Rdial (CString username, INT ver = 18, long lasttimec = 0); 
	CString Realusername();
	bool CreateRASLink();
	int dial();
private:
	INT m_ver;				//星空的版本，V12和V18两种
	long m_lasttimec;		//上次成功的时间处理
	CString m_username;		//原始用户名
	CString m_realusername;	//真正的用户名
	CString RADIUS;
	CString LR;
};

