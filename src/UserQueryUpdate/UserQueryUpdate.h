/*
 * UserQueryUpdate.h
 *
*/

#ifndef __USERQUERYUPDATE__
#define __USERQUERYUPDATE__


#include "../UserQueryStruct/UserQueryStruct.h"
#include "../CommonTools/Conf/Conf.h"
#include "../CommonTools/Mysql/mysqlClient.h"
#include "../CommonTools/Thread/Thread.h"
#include "../redisCommon/data_adapter.h"
#include "../../include/json/json.h"
#include "../CommonTools/Socket/TcpSocket.h"
#include "../CommonTools/Socket/UdpSocket.h"
#include "../CommonTools/Base64Encode/Base64.h"
#include "../CommonTools/Base64Encode/Base64_2.h"
#include "../UserQueryTask/TaskMain/TaskMain.h"



class CUserQueryUpdate {
public:
	CUserQueryUpdate(const IPPORT_S &stTokenServer,const MYSQL_SERVERINFO_S &mySqlInfo );
	virtual ~CUserQueryUpdate();
	void MonitorRemoteApiHuaWei();
	void MonitorRemoteApiWangGuan();
	std::string BdxUserGetCurrentDate(const time_t ttime=0);
	std::string BdxApiUpdateUserOrder(std::string user,std::string subid,std::string repo,std::string item,std::string token,long used) ;
	std::string BdxApiGateWayGetDataHubToken(std::string AuthUser="",std::string PassWord="") ;
	std::string BdxGetDatafromDataHub(std::string AuthUser,std::string AuthToken,std::string repo,std::string item,std::string subid,long used,int type);
	bool MapIsEqual(std::map<std::string,BDXPERMISSSION_S> &srcMap,std::map<std::string,BDXPERMISSSION_S> &destMap);
	void SwapMap(std::map<std::string,BDXPERMISSSION_S> &srcMap,std::map<std::string,BDXPERMISSSION_S> &destMap);
	void GetMysqlFieldsUserInfo(std::string strUserInfo,BDXPERMISSSION_S &mVecFieldsUser,std::string &mUserName);

	void Core();
protected:

private:
	LOGPRMS_S m_stLogPrms;
	SERVERINFO_S m_stServerInfo;
	CMYSQL *m_stMysqlServerInfo;
	MYSQL_ROW mysqlRow;
	std::vector<std::string> m_vecDevices;
	CDataAdapter *m_pTokenRedis;
	u_int m_uiThreadsNum;
	CThreads m_cThreads;
	CTcpSocket* sslMonitorSocket;
	CTcpSocket* sendEmailSocket;
	CTaskMain *cTaskMonitorHuaWei;

};

#endif /* __USERQUERYUPDATE__ */
