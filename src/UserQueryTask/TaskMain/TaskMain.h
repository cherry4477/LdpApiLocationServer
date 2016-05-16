/*
 * TaskMain.h

 */

#ifndef __TASK_MAIN__
#define __TASK_MAIN__

#include "../UserQueryTask.h"
#include "../../CommonTools/Conf/Conf.h"

class CTaskMain : public CUserQueryTask {

public:
	CTaskMain();
	CTaskMain(CTcpSocket* pclSock);
	virtual ~CTaskMain();
	
	UESRQUERYRPORT_S m_st;

	virtual int BdxRunTask(BDXREQUEST_S& stRequestInfo, BDXRESPONSE_S& stResponseInfo);
//protected:

	int BdxGetHttpPacket(BDXREQUEST_S& stRequestInfo,BDXRESPONSE_S &stResponseInfo,std::string &strAccessKeyId,std::string &retKey,std::string &retKeyType,std::string &retUser,std::string &errorMsg);
	int BdxParseHttpPacket(char*& pszBody, u_int& uiBodyLen, const u_int uiParseLen);
	int BdxParseBody(char *pszBody, u_int uiBodyLen, BDXREQUEST_S& stRequestInfo);
	int BdxSendEmpyRespones(std::string errorMsg);
	int BdxSendRespones(BDXREQUEST_S& stRequestInfo, BDXRESPONSE_S& stAdxRes,std::string errorMsg);
	std::string BdxTaskMainGetDate(const time_t ttime = 0);
	std::string BdxTaskMainGetLastTwoMonth(const time_t ttime = 0);
	string   BdxTaskMainReplace_All(string    str,   string   old_value,   string   new_value);
	std::string BdxTaskMainGetTime(const time_t ttime = 0);
	std::string BdxTaskMainGetMinute(const time_t ttime = 0);
	std::string BdxTaskMainGetFullTime(const time_t ttime=0);
	std::string BdxTaskMainGetUCTime(const time_t ttime = 0);
	std::string BdxGenNonce(int length);
	std::vector<DATAHUB_ORDER_INFO_S> BdxApiGetUserOrder(std::string repo,std::string item,std::string user,std::string apitoken);
	bool BdxApiSetUserOrderStatus(std::string user,std::string subid,std::string repo,std::string item,std::string token);
	std::string BdxApiUpdateUserOrder(std::string user,std::string subid,std::string repo,std::string item,std::string token,long used) ;
	std::string BdxGetDatafromDataHub(std::string AuthUser,std::string AuthToken,std::string repo,std::string item,std::string subid,long used,int type);
	int BdxVerifyDataHubToken(std::string AuthUser,std::string AuthToken);
	std::string BdxApiGateWayGetDataHubToken(std::string AuthUser="",std::string PassWord="") ;
	std::string GenPasswordDigest(std::string utcTime, std::string nonce, std::string appSecret);
	std::string BdxGetParamSign(const std::string& strParam, const std::string& strSign);
private:
	char m_pszAdxBuf[_8KBLEN];
	static const char* m_pszHttpHeaderEnd;
	static const char* m_pszHttpLineEnd;
	static const std::string keyEdcpMd5Sign;
	std::string ssCountKeyReq;
	std::string ssCountKeyRes;
	std::string ssCountKeyEmptyRes;
	CMd5 mdSHA1;
	CMd5 md5;
	int m_httpType ;
	CConf  mConf;	
	std::map<std::string,std::string> map_UserValueKey;
	std::map<std::string,std::string> m_mapUserValue;
	//CTime m_cTime;
	


	
	
};

#endif /* __TASK_MAIN__ */
