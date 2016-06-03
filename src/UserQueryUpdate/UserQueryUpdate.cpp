/*
 * UserQueryUpdate.cpp
 */

#include "UserQueryUpdate.h"

#include "../UserQueryWorkThreads/UserQueryWorkThreads.h"
#include "../UserQueryServer/UserQueryServer.h"


extern CLog *gp_log;
extern std::string strServerName;
extern std::string strConfigFileName;
pthread_rwlock_t p_rwlock;
pthread_rwlockattr_t p_rwlock_attr;
pthread_mutex_t mutex;
std::string g_strTokenString = "";
u_int  g_iNeedUpdateToken = 0;
extern u_int  InitSSLFlag ;



extern	IPPORT_S m_stMonitorApi;
extern	IPPORT_S m_stEmailServer;
extern	string m_strUserName;
extern	string m_strPassWord;
extern	string m_strMailFrom;
extern	string m_strRcptTo;
extern	string m_strSubject;
extern	string m_strErrorMsg;

extern std::string g_strDataHubToken;
std::string g_strCurrentDate ;



std::map<std::string,BDXPERMISSSION_S> g_mapUserInfo;



CUserQueryUpdate::CUserQueryUpdate(const IPPORT_S &stTokenServer,const MYSQL_SERVERINFO_S &mySqlInfo ) {
	// TODO Auto-generated constructor stub


	char chCount[10];
	char chPort [10];
	char chIdx  [10];
    m_pTokenRedis = new CDataAdapter;
    //cTaskMonitorHuaWei = new CTaskMain;
    //m_stMysqlServerInfo = new CMYSQL;
	sprintf(chCount,"%d",stTokenServer.m_count);
	sprintf(chPort,"%d",stTokenServer.m_uiPort);
	sprintf(chIdx,"%d",stTokenServer.m_idx);
	string strServerList = string(chCount)+";"+string(stTokenServer.m_pchIp)+":"+string(chPort)+","+string(chIdx)+";";
	
  	printf("Line:%d,Redis Server=%s\n",__LINE__,strServerList.c_str());
	m_pTokenRedis->Init(strServerList.c_str());
  
	printf("==============mysql info==============\n");
	printf("%s\n",mySqlInfo.m_stMysqlLinkInfo.m_pchIp);
	printf("%d\n",mySqlInfo.m_stMysqlLinkInfo.m_uiPort);
	printf("%s\n",mySqlInfo.pchUserName);
	printf("%s\n",mySqlInfo.pchPassWord);
	printf("%s\n",mySqlInfo.pchDbName);

	LOG(DEBUG,"mySqlInfo.m_stMysqlLinkInfo.m_pchIp=%s",mySqlInfo.m_stMysqlLinkInfo.m_pchIp);
	LOG(DEBUG,"mySqlInfo.m_stMysqlLinkInfo.m_uiPort=%d",mySqlInfo.m_stMysqlLinkInfo.m_uiPort);
	LOG(DEBUG,"mySqlInfo.pchUserName=%s",mySqlInfo.pchUserName);
	LOG(DEBUG,"mySqlInfo.pchPassWord=%s",mySqlInfo.pchPassWord);
	LOG(DEBUG,"mySqlInfo.pchDbName=%s",mySqlInfo.pchDbName);
	printf("======================================\n");
	//m_stMysqlServerInfo->InitMysql(mySqlInfo.m_stMysqlLinkInfo.m_pchIp,mySqlInfo.m_stMysqlLinkInfo.m_uiPort,mySqlInfo.pchUserName,mySqlInfo.pchPassWord,mySqlInfo.pchDbName);

}

CUserQueryUpdate::~CUserQueryUpdate() {
	// TODO Auto-generated destructor stub
	delete m_pTokenRedis ;
    //delete m_stMysqlServerInfo ;
}

void CUserQueryUpdate::GetMysqlFieldsUserInfo(std::string strUserInfo,BDXPERMISSSION_S &mVecFieldsUser,std::string &mUserName) 
{
	char *buf;
	int  index = 0;
	char bufTemp[PACKET];
	char *outer_ptr = NULL;  
	char *inner_ptr = NULL;  
	char *temp[PACKET]; 
	
	memset(temp,0,PACKET);
	memset(bufTemp,0,PACKET);
	mVecFieldsUser.mVecFields.clear();
					printf("strUserInfo=%s\n",strUserInfo.c_str());
					buf = const_cast<char*>(strUserInfo.c_str());
					while((temp[index] = strtok_r(buf,";", &outer_ptr))!=NULL)   
					{  	
					    buf=temp[index];
					    while((temp[index]=strtok_r(buf,"|", &inner_ptr))!=NULL)   
					    {   			    
					    	if(index >= 5)
					        {
					            //g_vecUrlAPIS[temp[index-1]]=temp[index];
					            mVecFieldsUser.mVecFields.push_back(temp[index]);
					        }					     	       					        
					        index++;
					        buf=NULL;  
					    }  
					    buf=NULL;  
					}  
					mUserName =	std::string(temp[0]);
					mVecFieldsUser.mResToken =	temp[1];
					mVecFieldsUser.mIntQueryTimes =	atoi(temp[2]);
					mVecFieldsUser.mIntGoodsTimes =	atoi(temp[3]);
					mVecFieldsUser.mGoodsFields =	std::string(temp[4]);
					std::vector<std::string>::iterator itr;
					#if 0
					for(itr=mVecFieldsUser.mVecFields.begin();itr!=mVecFieldsUser.mVecFields.end();itr++)
					{
						printf("=====%s\n",(*itr).c_str());
					}
					#endif


}


std::string CUserQueryUpdate::BdxApiGateWayGetDataHubToken(std::string AuthUser,std::string PassWord) 
{
		std::string retDataHub;
		retDataHub = BdxGetDatafromDataHub(AuthUser,PassWord,"","","",0,2);
		//printf("Line:%d,BdxApiGateWayGetDataHubToken retDataHub=%s",__LINE__,retDataHub.c_str());
		if(retDataHub.find("\"msg\": \"OK\"")!=-1)
		{
			retDataHub = retDataHub.substr(retDataHub.find("token")+ 9 ,32);
			//retDataHub = retDataHub;
		}
		else
		{
			retDataHub = "";
		}
		return retDataHub;   
}

std::string CUserQueryUpdate::BdxApiUpdateUserOrder(std::string user,std::string subid,std::string repo,std::string item,std::string token,long used) 
{
		std::string retDataHub;
		retDataHub = BdxGetDatafromDataHub(user,token,repo,item,subid,used,5);
		printf("Line:%d,BdxApiGateWayGetDataHubToken retDataHub=%s",__LINE__,retDataHub.c_str());
		if(retDataHub.find("\"msg\": \"OK\"")!=-1)
		{
			retDataHub = retDataHub.substr(retDataHub.find("token")+ 9 ,32);
			//retDataHub = retDataHub;
		}
		else
		{
			retDataHub = "";
		}
		return retDataHub;   
}

std::string CUserQueryUpdate::BdxGetDatafromDataHub(std::string AuthUser,std::string AuthToken,std::string repo,std::string item,std::string subid,long used,int type)
{
	//type 1 verifytoken 2 get token 3 get order 4 update order
	char m_httpReqVerifyToken[_8KBLEN];
	char sslReadBuffer[_8KBLEN];
	char tempBuffer[PACKET];
	std::string strReadBuffer;
	std::string datahubIP = "10.1.235.98";
	uint16_t 	datahubPort = 443;
	CTcpSocket* sslLocalSocket; 	
	sslLocalSocket=new CTcpSocket(datahubPort,datahubIP);
	string strType;
	memset(m_httpReqVerifyToken,0,sizeof(m_httpReqVerifyToken));
	if( type == 1 )
	{
		strType ="verify user token";
		sprintf(m_httpReqVerifyToken,"GET /api/valid HTTP/1.1\r\nHost: %s\r\nAuthorization:Token %s\r\nAuthuser: %s\r\n\r\n",datahubIP.c_str(),AuthToken.c_str(),AuthUser.c_str());
		//printf("Line:%d,BdxVerifyDataHubToken\n",__LINE__);
	}
	if( type == 2 )
	{
		strType ="get gateway token";
		sprintf(m_httpReqVerifyToken,"GET /api/ HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic Y2hlbnlnQGFzaWFpbmZvLmNvbToxYmJkODg2NDYwODI3MDE1ZTVkNjA1ZWQ0NDI1MjI1MQ==\r\n\r\n",datahubIP.c_str());
	}
	if( type == 3 )
	{
		strType ="get order info";
		sprintf(m_httpReqVerifyToken,"GET /api/subscriptions/pull/%s/%s?username=%s HTTP/1.1\r\nHost: %s\r\nAccept: application/json; charset=utf-8\r\nAuthorization: Token %s\r\n\r\n",repo.c_str(),item.c_str(),AuthUser.c_str(),datahubIP.c_str(),AuthToken.c_str());
	}
	if( type == 4 )
	{
		strType ="set_retrieved";
		memset(tempBuffer,0,sizeof(tempBuffer));
		sprintf(tempBuffer,"{\"action\":\"set_retrieved\",\"repname\":\"%s\",\"itemname\":\"%s\",\"username\":\"%s\"}",repo.c_str(),item.c_str(),AuthUser.c_str());
	    //std::string putValue = std::string(tempBuffer);
		sprintf(m_httpReqVerifyToken,"PUT /api/subscription/%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Token %s\r\nContent-Length: %d\r\nAccept: application/json; charset=utf-8\r\n\r\n%s",subid.c_str(),datahubIP.c_str(),AuthToken.c_str(),std::string(tempBuffer).length(),std::string(tempBuffer).c_str());
		//printf("Line:%d,m_httpReqVerifyToken=%s\n",__LINE__,m_httpReqVerifyToken);


	}
	if( type == 5 )
	{
		strType ="set_plan_used";
		memset(tempBuffer,0,sizeof(tempBuffer));
		sprintf(tempBuffer,"{\"action\":\"set_plan_used\",\"used\":%ld,\"repname\":\"%s\",\"itemname\":\"%s\",\"username\":\"%s\"}",used,repo.c_str(),item.c_str(),AuthUser.c_str());
	    //std::string putValue = std::string(tempBuffer);
		sprintf(m_httpReqVerifyToken,"PUT /api/subscription/%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Token %s\r\nContent-Length: %d\r\nAccept: application/json; charset=utf-8\r\n\r\n%s",subid.c_str(),datahubIP.c_str(),AuthToken.c_str(),std::string(tempBuffer).length(),std::string(tempBuffer).c_str());
		//printf("Line:%d,m_httpReqVerifyToken=%s\n",__LINE__,m_httpReqVerifyToken);

	}

	if(sslLocalSocket->TcpConnect()==0)
	{
		pthread_mutex_lock (&mutex);
		if ( InitSSLFlag == 0 )
		{
			sslLocalSocket->TcpSslInitParams();
			InitSSLFlag = 1;
			
		}
		pthread_mutex_unlock(&mutex);
		if(sslLocalSocket->TcpSslInitEnv()==0)
		{
			if(sslLocalSocket->TcpSslConnect())
			{
				if(sslLocalSocket->TcpSslWriteLen(m_httpReqVerifyToken,strlen(m_httpReqVerifyToken))!=0)
				{
					memset(sslReadBuffer,0,sizeof(sslReadBuffer));
					sslLocalSocket->TcpSslReadLen(sslReadBuffer,sizeof(sslReadBuffer));
					if( strlen(sslReadBuffer)>0 )
					{
						strReadBuffer = std::string(sslReadBuffer);
						if(strReadBuffer.find("Transfer-Encoding: chunked")!=-1)
						{
							int itrunkStart = strReadBuffer.find("\r\n",strReadBuffer.find("\r\n\r\n")+4);
							int itrunkEnd = strReadBuffer.find("\r\n",itrunkStart + 1);
							strReadBuffer=strReadBuffer.substr(itrunkStart + 2 ,itrunkEnd - itrunkStart -1);
						}
						else
						{
							if(strReadBuffer.find("\r\n\r\n")!=std::string::npos)
							{
							  int lenStrTemp = strReadBuffer.length();
							  strReadBuffer = strReadBuffer.substr(strReadBuffer.find("\r\n\r\n")+4,lenStrTemp -(strReadBuffer.find("\r\n\r\n")+4));
							}
						}
						printf("Line:%d,receive from datahub type[%d] [%s] sslReadBuffer=%s\n",__LINE__,type,strType.c_str(),strReadBuffer.c_str());
					}
	
				}
	
			}
		}
	}
	sslLocalSocket->TcpSslDestroy();
	return strReadBuffer;
}


#if 0
bool CUserQueryUpdate::VectorIsEqual(std::vector<std::string> srcVector,std::vector<std::string> destVector) 
{
	std::vector<std::string>::iterator itrSrcVec;
	std::vector<std::string>::iterator itrDestVec;
	std::vector<std::string>::iterator itr2;

	if( srcVector.size() != srcVector.size())
	{
		return false;
	}
	for(itrSrcVec=srcVector.begin();itrSrcVec!=srcVector.end();itrSrcVec++)
	{
		itrDestVec = destVector.find(*itrSrcVec);
		if(itrDestVec !=itrDestVec.end())
		{
			continue;
		}
		else
		{
			return false;
		}

	}
	
return true;
}

#endif

bool CUserQueryUpdate::MapIsEqual(std::map<std::string,BDXPERMISSSION_S> &srcMap,std::map<std::string,BDXPERMISSSION_S> &destMap) 
{
	std::map<std::string,BDXPERMISSSION_S>::iterator itrSrcMap;
	std::map<std::string,BDXPERMISSSION_S>::iterator itrDestMap;
	std::vector<std::string>::iterator itr2;

	if( srcMap.size() != destMap.size())
	{
		return false;
	}
	
	for(itrSrcMap=srcMap.begin();itrSrcMap!=srcMap.end();itrSrcMap++)
	{
		itrDestMap = destMap.find(itrSrcMap->first);
		if(itrDestMap !=destMap.end())
		{
				if(itrSrcMap->second.mResToken!=itrDestMap->second.mResToken||
				itrSrcMap->second.mIntQueryTimes!=itrDestMap->second.mIntQueryTimes||
				itrSrcMap->second.mVecFields!=itrDestMap->second.mVecFields||
				itrSrcMap->second.mGoodsFields!=itrDestMap->second.mGoodsFields||
				itrSrcMap->second.mIntGoodsTimes!=itrDestMap->second.mIntGoodsTimes)
				//VectorIsEqual(itrSrcMap->second.mVecFields,)
				{
					return false;

				}
				

		}
		else
		{
			return false;
		}

	}

return true;
}

void CUserQueryUpdate::SwapMap(std::map<std::string,BDXPERMISSSION_S> &srcMap,std::map<std::string,BDXPERMISSSION_S> &destMap) 
{
	std::map<std::string,BDXPERMISSSION_S>::iterator itrSrcMap;
	BDXPERMISSSION_S mUserInfoVecFields;
	std::vector<std::string>::iterator itrSrcVector;

	destMap.clear();
	for(itrSrcMap=srcMap.begin();itrSrcMap!=srcMap.end();itrSrcMap++)
	{
		mUserInfoVecFields.mVecFields.clear();
		mUserInfoVecFields.mVecFields 		= itrSrcMap->second.mVecFields;
		mUserInfoVecFields.mResToken  		= itrSrcMap->second.mResToken;
		mUserInfoVecFields.mIntQueryTimes   = itrSrcMap->second.mIntQueryTimes;
		mUserInfoVecFields.mIntGoodsTimes   = itrSrcMap->second.mIntGoodsTimes;
		mUserInfoVecFields.mGoodsFields   = itrSrcMap->second.mGoodsFields;
		destMap.insert(std::pair<std::string,BDXPERMISSSION_S>(itrSrcMap->first,mUserInfoVecFields));

	}
	
}

std::string CUserQueryUpdate::BdxUserGetCurrentDate(const time_t ttime)
{
	time_t tmpTime;
	if(ttime == 0)
		tmpTime = time(0);
	else
		tmpTime = ttime;
	struct tm* timeinfo = localtime(&tmpTime);
	char dt[20];
	memset(dt, 0, 20);
	sprintf(dt, "%4d%02d%02d", timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday);
	//return (timeinfo->tm_year + 1900) * 10000 + (timeinfo->tm_mon + 1) * 100 + timeinfo->tm_mday;
	return std::string(dt);
}

void CUserQueryUpdate::MonitorRemoteApiHuaWei()
{
	int monitorFlag,lenStrTemp ;
	string strEncrpytKey,mResValueRemote,errorMsg,tempRcptTo,monitorValue="[{\"name\":\"0\",\"value\":\"0\",\"typeid\":\"0\"}]";
	//string strIpPort="210.14.129.121:8443";
	//string strIpPort=m_stMonitorApi.m_pchIp + 
	//string errorMsg="There is some problem in API Service,please check it";
	char m_httpReq[_8KBLEN],sslBuffer[_8KBLEN];
	memset(m_httpReq, 0, _8KBLEN);
	memset(sslBuffer, 0, _8KBLEN);
		
		monitorFlag = 0;
		strEncrpytKey="/dg/rtb/tag?&key=JSQkdnFjfm4pfXF5fTJgeGF1cnFwKXB6e3cydWB1cGx9eSlxeXV6S2RncBQ=";
		printf("monitor strEncrpytKey=%s\n",strEncrpytKey.c_str());
		
		std::string strAppSecret = "5543131e56e6a10d";
		std::string strHost = "dacp.sdp.com";
		//std::string strHost = "dacp.test.sdp.com";
		std::string strUcTime = cTaskMonitorHuaWei->BdxTaskMainGetUCTime();						
		std::string strNonce =  cTaskMonitorHuaWei->BdxGenNonce(25);
		printf("strUcTime=%s\n",strUcTime.c_str());
		printf("strNonce=%s\n",strNonce.c_str());	

		std::string strPwdDigest =  cTaskMonitorHuaWei->GenPasswordDigest(strUcTime,strNonce,strAppSecret);
		printf("strPwdDigest=%s\n",strPwdDigest.c_str());
		
		std::string XWSSEHeader = "UsernameToken Username=\"f2b98698400e4ace9926f83f0d063a57\",PasswordDigest=\""+strPwdDigest + "\", Nonce=\""+strNonce + "\", Created=\""+ strUcTime+ "\"";
		sprintf(m_httpReq,"GET %s HTTP/1.1\r\nAuthorization: WSSE realm=\"SDP\",profile=\"UsernameToken\",type=\"AppKey\"\r\nHost: %s\r\nX-WSSE: %s\r\nAccept-Encoding: identity\r\n\r\n",strEncrpytKey.c_str(),strHost.c_str(),XWSSEHeader.c_str());
		printf("%s\n",m_httpReq);
		LOG(ERROR,"m_httpReq=%s",m_httpReq);
		string tempMonitor="JSQkdnFjfm4pfXF5fTJgeGF1cnFwKXB6e3cydWB1cGx9eSlxeXV6S2RncBQ=";
		printf("tempMonitor+++++++++++++++++++++=%s\n",tempMonitor.c_str());
		tempMonitor=Decrypt_2(tempMonitor);
		printf("tempMonitor======================%s\n",tempMonitor.c_str());
	  //sslMonitorSocket=new CTcpSocket(8000,"218.205.68.67");
	  //sslMonitorSocket=new CTcpSocket(8443,"210.14.129.121");
	  printf("m_stMonitorApi.m_uiPort=%d\n",m_stMonitorApi.m_uiPort);
	  printf("m_stMonitorApi.m_pchIp=%s\n",string(m_stMonitorApi.m_pchIp).c_str());
	  sslMonitorSocket=new CTcpSocket(m_stMonitorApi.m_uiPort,string(m_stMonitorApi.m_pchIp));
	  errorMsg = m_strErrorMsg;
	  if(sslMonitorSocket->TcpConnect()!=0)
	  {	
			printf("sslMonitorSocket connect error\n");
			monitorFlag = 1;
	  }

	  printf("m_strRcptTo.c_str()=%s\n",m_strRcptTo.c_str());

		#if 0
		pthread_mutex_lock (&mutex);
		if ( InitSSLFlag == 0 )
		{
			sslMonitorSocket->TcpSslInitParams();
			InitSSLFlag = 1;
			}
		pthread_mutex_unlock(&mutex);
		if(sslMonitorSocket->TcpSslInitEnv()!=0)
		{
			printf("TcpSslInitEnv error\n");
			monitorFlag = 1;							
		}
		if(!sslMonitorSocket->TcpSslConnect())
		{
			printf("TcpSslConnect error\n");
			sslMonitorSocket->TcpSslDestroy();
			monitorFlag = 1;
		}
		#endif
		if(monitorFlag == 0)
		{
			printf("m_httpReq=%s\n",m_httpReq);
			if(sslMonitorSocket->TcpWrite(m_httpReq,strlen(m_httpReq))!=0)
			{
				memset(sslBuffer,0,_8KBLEN);
				sslMonitorSocket->TcpReadAll(sslBuffer,_8KBLEN);
				printf("Monitor sslBuffer=%s\n",sslBuffer); 
				LOG(ERROR,"Monitor sslBuffer=%s",sslBuffer);  

				if(strlen(sslBuffer) > 0 )
				{
					mResValueRemote = std::string(sslBuffer);
					LOG(ERROR,"Monitor mResValueRemote=%s",mResValueRemote.c_str());  
					sslMonitorSocket->TcpClose();
				}
				else
				{
					sslMonitorSocket->TcpClose();
					monitorFlag =  2;				

				}
			}		
			else 
			{	
				sslMonitorSocket->TcpClose();
				monitorFlag =  1;
			}

			lenStrTemp = mResValueRemote.length();

			if( mResValueRemote.find("\r\n\r\n")!=std::string::npos )
			{
				mResValueRemote = mResValueRemote.substr(mResValueRemote.find("\r\n\r\n")+4,lenStrTemp -(mResValueRemote.find("\r\n\r\n")+4));
			}
			printf("before decrypt mResValueRemote=%s\n",mResValueRemote.c_str());
			LOG(ERROR,"before decrypt mResValueRemote=%s",mResValueRemote.c_str()); 
			if(!mResValueRemote.empty())
			{
			   printf("mResValueRemote=%s\n",mResValueRemote.c_str());
			   if((mResValueRemote.at(0)!='{')&&(mResValueRemote.at(0)!='<')&&(mResValueRemote.find("description")==std::string::npos))
			   {
					mResValueRemote = Decrypt_2(mResValueRemote);
			   }
			   
			}
			LOG(ERROR,"after decrypt mResValueRemote=%s",mResValueRemote.c_str()); 
			printf("after decrypt mResValueRemote=%s\n",mResValueRemote.c_str());
			printf("monitorValue=%s\n",monitorValue.c_str());
			
			if( monitorFlag==2 )
			{
				errorMsg+="  \nError Massage: Read data empty\n";

			}
			else
			{
				errorMsg+="  \nError Massage: \n"+mResValueRemote;
			}
			if( mResValueRemote.compare(monitorValue)!= 0 )
			{
				#if 1
				//sendEmailSocket = new  CTcpSocket(25,"114.255.20.23");
				sendEmailSocket = new  CTcpSocket(m_stEmailServer.m_uiPort,string(m_stEmailServer.m_pchIp));
				if( sendEmailSocket->TcpConnect()==0 )
				{
					sendEmailSocket->TcpSendEmail(m_stEmailServer.m_pchIp,m_stEmailServer.m_uiPort,const_cast<char*>(m_strUserName.c_str()),const_cast<char*>(m_strPassWord.c_str()),const_cast<char*>(m_strMailFrom.c_str()),const_cast<char*>(m_strRcptTo.c_str()),const_cast<char*>(m_strSubject.c_str()),const_cast<char*>(errorMsg.c_str()));
				}
				sendEmailSocket->TcpClose();
				#endif
			}
		}
		else
		{
			#if 1
			mResValueRemote = "The Client can't connect to Api server!";
		    errorMsg+="  \nError Massage: \n"+mResValueRemote;
			sendEmailSocket = new  CTcpSocket(m_stEmailServer.m_uiPort,string(m_stEmailServer.m_pchIp));
			if( sendEmailSocket->TcpConnect()==0 )
			{
				sendEmailSocket->TcpSendEmail(m_stEmailServer.m_pchIp,m_stEmailServer.m_uiPort,const_cast<char*>(m_strUserName.c_str()),const_cast<char*>(m_strPassWord.c_str()),const_cast<char*>(m_strMailFrom.c_str()),const_cast<char*>(m_strRcptTo.c_str()),const_cast<char*>(m_strSubject.c_str()),const_cast<char*>(errorMsg.c_str()));
			}
			sendEmailSocket->TcpClose();
			#endif
		}
		



}
void CUserQueryUpdate::MonitorRemoteApiWangGuan()
{
	int monitorFlag,lenStrTemp ;
	string strEncrpytKey,mResValueRemote,errorMsg,monitorValue="[{\"name\":\"0\",\"value\":\"0\",\"typeid\":\"0\"}]";
	//string strIpPort="210.14.129.121:8443";
	//string strIpPort=m_stMonitorApi.m_pchIp + 
	//string errorMsg="There is some problem in API Service,please check it";
	char m_httpReq[_8KBLEN],sslBuffer[_8KBLEN];
	memset(m_httpReq, 0, _8KBLEN);
	memset(sslBuffer, 0, _8KBLEN);

	  monitorFlag = 0;
	  strEncrpytKey="/dg/api/query/rtbtag2?token="+g_strTokenString+"&appkey=f2b98698400e4ace9926f83f0d063a57&key=JSQkdnFjfm4pfXF5fTJgeGF1cnFwKXB6e3cydWB1cGx9eSlxeXV6S2RncBQ=";
	  printf("monitor strEncrpytKey=%s\n",strEncrpytKey.c_str());
	  sprintf(m_httpReq,"GET %s HTTP/1.1\r\nHost: %s:%d\r\nAccept-Encoding: identity\r\n\r\n",strEncrpytKey.c_str(),m_stMonitorApi.m_pchIp,m_stMonitorApi.m_uiPort);

	  //sslMonitorSocket=new CTcpSocket(8000,"218.205.68.67");
	  //sslMonitorSocket=new CTcpSocket(8443,"210.14.129.121");
	  sslMonitorSocket=new CTcpSocket(m_stMonitorApi.m_uiPort,string(m_stMonitorApi.m_pchIp));
	  errorMsg = m_strErrorMsg;
	  if(sslMonitorSocket->TcpConnect()!=0)
	  {	
			printf("sslMonitorSocket connect error\n");
			monitorFlag = 1;
	  }

		pthread_mutex_lock (&mutex);
		if ( InitSSLFlag == 0 )
		{
			sslMonitorSocket->TcpSslInitParams();
			InitSSLFlag = 1;
			}
		pthread_mutex_unlock(&mutex);
		if(sslMonitorSocket->TcpSslInitEnv()!=0)
		{
			printf("TcpSslInitEnv error\n");
			monitorFlag = 1;							
		}
		if(!sslMonitorSocket->TcpSslConnect())
		{
			printf("TcpSslConnect error\n");
			sslMonitorSocket->TcpSslDestroy();
			monitorFlag = 1;
		}
		if(monitorFlag == 0)
		{
			printf("m_httpReq=%s\n",m_httpReq);
			if(sslMonitorSocket->TcpSslWriteLen(m_httpReq,strlen(m_httpReq))!=0)
			{
				memset(sslBuffer,0,_8KBLEN);
				sslMonitorSocket->TcpSslReadLen(sslBuffer,_8KBLEN);
				printf("Monitor sslBuffer=%s\n",sslBuffer); 
				LOG(DEBUG,"Monitor sslBuffer=%s",sslBuffer);  

				if(strlen(sslBuffer) > 0 )
				{
					mResValueRemote = std::string(sslBuffer);
					LOG(DEBUG,"Monitor mResValueRemote=%s",mResValueRemote.c_str());  
					sslMonitorSocket->TcpSslDestroy();
				}
				else
				{
					sslMonitorSocket->TcpSslDestroy();
					monitorFlag =  1;				

				}
			}		
			else 
			{	
				sslMonitorSocket->TcpSslDestroy();
				monitorFlag =  1;
			}

			lenStrTemp = mResValueRemote.length();

			if( mResValueRemote.find("\r\n\r\n")!=std::string::npos )
			{
				mResValueRemote = mResValueRemote.substr(mResValueRemote.find("\r\n\r\n")+4,lenStrTemp -(mResValueRemote.find("\r\n\r\n")+4));
			}
			printf("before decrypt mResValueRemote=%s\n",mResValueRemote.c_str());
			if(!mResValueRemote.empty())
			{
			   mResValueRemote = Decrypt_2(mResValueRemote);
			}
			printf("after decrypt mResValueRemote=%s\n",mResValueRemote.c_str());
			printf("monitorValue=%s\n",monitorValue.c_str());
			errorMsg+="  \nError Massage: \n"+mResValueRemote;
			if( mResValueRemote.compare(monitorValue)!= 0 )
			{
				#if 1
				//sendEmailSocket = new  CTcpSocket(25,"114.255.20.23");
				sendEmailSocket = new  CTcpSocket(m_stEmailServer.m_uiPort,string(m_stEmailServer.m_pchIp));
				if( sendEmailSocket->TcpConnect()==0 )
				{
					//sendEmailSocket->TcpSendEmail("114.255.20.23",25,"dmp-message","MIX@asiainfo","dmp-message@asiainfo.com","BDX-DMS-Data@asiainfo.com","Monitor Api",const_cast<char*>(errorMsg.c_str()));
					sendEmailSocket->TcpSendEmail(m_stEmailServer.m_pchIp,m_stEmailServer.m_uiPort,const_cast<char*>(m_strUserName.c_str()),const_cast<char*>(m_strPassWord.c_str()),const_cast<char*>(m_strMailFrom.c_str()),const_cast<char*>(m_strRcptTo.c_str()),const_cast<char*>(m_strSubject.c_str()),const_cast<char*>(errorMsg.c_str()));
				}
				sendEmailSocket->TcpClose();
				#endif
			}
		}
		else
		{
			#if 1
			mResValueRemote = "The Client can't connect to Api server!";
		    //sendEmailSocket = new  CTcpSocket(25,"114.255.20.23");
		    errorMsg+="  \nError Massage: \n"+mResValueRemote;
			sendEmailSocket = new  CTcpSocket(m_stEmailServer.m_uiPort,string(m_stEmailServer.m_pchIp));
			if( sendEmailSocket->TcpConnect()==0 )
			{
				//sendEmailSocket->TcpSendEmail("114.255.20.23",25,"dmp-message","MIX@asiainfo","dmp-message@asiainfo.com","dmp-message@asiainfo.com","Monitor Api",const_cast<char*>(errorMsg.c_str()));
				sendEmailSocket->TcpSendEmail(m_stEmailServer.m_pchIp,m_stEmailServer.m_uiPort,const_cast<char*>(m_strUserName.c_str()),const_cast<char*>(m_strPassWord.c_str()),const_cast<char*>(m_strMailFrom.c_str()),const_cast<char*>(m_strRcptTo.c_str()),const_cast<char*>(m_strSubject.c_str()),const_cast<char*>(errorMsg.c_str()));
			}
			sendEmailSocket->TcpClose();
			#endif
		}
		



}
void CUserQueryUpdate::Core()
{

	std::string strToken,strTokenValue;
	Json::Value jValue,jRoot,jResult;
	Json::Reader jReader;
	Json::FastWriter jFastWriter;


	std::string strMysqlRecord;
	const char *pchSqlPermissions = "select access_keyid,secret_privatekey,query_count,goods_count,goods_perm,permissions from dmp_user_permissions";
	BDXPERMISSSION_S mUserInfoVecFields;
	std::string strUserName;
	int times = 0;
	std::map<std::string,BDXPERMISSSION_S> temp_mapUserInfo;
	std::string tempCurrentDate;
	deque<string> setMembers;
	std::string needUpdateOrder="need_updated_datahub_order";
	std::string alreadyUpdateOrder="already_updated_datahub_order";
	deque<string>::iterator itSetMembers;
	std::string statusOrder,countOrder;
	std::string mid_statusOrder= "order_status";
	std::string mid_countOrder = "order_count";
	std::string ssmoidValue,ssmoidValue2;
	int iLimitOrderId,iCountOrderId;
	std::string startOrderID = KEY_startOrderID;
	std::string startToken = KEY_startToken;
	std::string apiGateWayAdmin = KEY_apiGateWayAdmin;
	std::string startOrderCount  = KEY_startOrderCount;
	std::string startOrderLimit  = KEY_startOrderLimit;
	std::string startOrderStatus = KEY_startOrderStatus;
	std::string startOrderExpire = KEY_startOrderExpire;
	std::string strCountOrderId,strLimitOrderId,strStatusOrderId,strExpireOrderId,strTempSubID;


	std::string sModValue,updatedmember,strUserOrderId;
	std::string keyValue,strAuthUser,strRepo,strItem,strSubid;
	int orderUsed;
	g_strCurrentDate = BdxUserGetCurrentDate();
	
	mid_statusOrder += KEY_DELIMITER;
	mid_countOrder  += KEY_DELIMITER;
	while(true)
	{
		times=1;	
		int first_row = 1;
		#if 1

		
		tempCurrentDate = BdxUserGetCurrentDate();
		if( tempCurrentDate.compare(g_strCurrentDate)!=0 )
		{
			g_strCurrentDate = tempCurrentDate;
			setMembers.clear();
	        if(m_pTokenRedis->UserSmembers(needUpdateOrder,setMembers))
	        {
	        	if(!setMembers.empty())
	        	{
	        		for(itSetMembers = setMembers.begin();itSetMembers!=setMembers.end();itSetMembers++)
	        		{
						sModValue.clear();
						keyValue = *itSetMembers;
						statusOrder = mid_statusOrder + *itSetMembers;
						countOrder  = mid_countOrder  + *itSetMembers;
						
						if( m_pTokenRedis ->UserGet(statusOrder,sModValue))
						{
							printf("Line:%d,get sModValue=%s\n",__LINE__,sModValue.c_str());
							if( atoi(sModValue.c_str()) == 0 )
							{//update datahub order 

								int userStart = keyValue.find(KEY_DELIMITER);
								strAuthUser = keyValue.substr(0,userStart);
								
								int repoStart = keyValue.find(KEY_DELIMITER,userStart+1);
								strRepo = keyValue.substr(userStart + 1,repoStart - (userStart+1));

								int itemStart = keyValue.find(KEY_DELIMITER,repoStart+1);
								strItem = keyValue.substr(repoStart + 1,itemStart - (repoStart+1));

								int subIdStart = keyValue.find(KEY_DELIMITER,itemStart+1);
								strSubid= keyValue.substr(itemStart + 1,subIdStart - (itemStart+1));
								ssmoidValue.clear();
								ssmoidValue2.clear();
								

								updatedmember = strAuthUser+KEY_DELIMITER + strRepo+KEY_DELIMITER+strItem+KEY_DELIMITER+strSubid;
								strUserOrderId =  strAuthUser +std::string(KEY_DELIMITER + startOrderID ); 
								strCountOrderId = startOrderCount + KEY_DELIMITER + updatedmember;
								strLimitOrderId = startOrderLimit + KEY_DELIMITER + updatedmember;
								strExpireOrderId =  startOrderExpire + KEY_DELIMITER + updatedmember;
								printf("Line:%d,strCountOrderId=%s\n",__LINE__,strCountOrderId.c_str());
								printf("Line:%d,strLimitOrderId=%s\n",__LINE__,strLimitOrderId.c_str());
								if((m_pTokenRedis->UserGet(strCountOrderId,ssmoidValue))&&(m_pTokenRedis->UserGet(strLimitOrderId,ssmoidValue2)))
								{
									
									iCountOrderId = atoi(ssmoidValue.c_str());
									iLimitOrderId = atoi(ssmoidValue2.c_str());
									printf("Line:%d,iCountOrderId=%d\n",__LINE__,iCountOrderId);
									printf("Line:%d,iLimitOrderId=%d\n",__LINE__,iLimitOrderId);									
									if(( iCountOrderId >= iLimitOrderId )&&(!m_pTokenRedis->UserGet(strExpireOrderId,ssmoidValue)))
									{
										m_pTokenRedis->UserPut(statusOrder,std::string("1"));
										m_pTokenRedis->UserSmove(needUpdateOrder,alreadyUpdateOrder,updatedmember);
										m_pTokenRedis->UserRemoveSortedSet(strUserOrderId,ssmoidValue);
									}
									if(g_strDataHubToken.empty())
									{
										g_strDataHubToken = BdxApiGateWayGetDataHubToken();
									}
									BdxApiUpdateUserOrder(strAuthUser,strSubid,strRepo,strItem,g_strDataHubToken,iCountOrderId);
								}								
								//printf("Line:%d,strAuthUser=%s,strRepo=%s\n",__LINE__,strAuthUser.c_str(),strRepo.c_str());
								//printf("Line:%d,strItem=%s,strRepo=%s\n",__LINE__,strItem.c_str(),strSubid.c_str());
								printf("Line:%d,keyValue=%s\n",__LINE__,keyValue.c_str());
							}
						}
					}
				}
	        }
		}
		

        #endif
        //st_emrtb_ip_port_weight_flag = 0;
	 	#define __MONITOR_API__
	  	#ifdef __MONITOR_API__

		//MonitorRemoteApiWangGuan();
		//MonitorRemoteApiHuaWei();
									
		#endif //__MONITOR_API__

		#if 0
		while(times--)
		{
				temp_mapUserInfo.clear();
				if(m_stMysqlServerInfo->GetMysqlInitState())
				{
					if(m_stMysqlServerInfo->ExecuteMySql(pchSqlPermissions))
					{

						if(m_stMysqlServerInfo->MysqlUseResult())
						{	
							//m_stMysqlServerInfo->DisplayHeader();
							while(m_stMysqlServerInfo->MysqlFetchRow())
							{			
								//if(!first_row)
								{	
									strMysqlRecord = m_stMysqlServerInfo->GetColumnValue();
									//printf("strMysqlRecord = %s\n",strMysqlRecord.c_str());
									GetMysqlFieldsUserInfo(strMysqlRecord,mUserInfoVecFields,strUserName);
									temp_mapUserInfo.insert(std::pair<std::string,BDXPERMISSSION_S>(strUserName,mUserInfoVecFields));
									
								}
								first_row = 0;
							}

							std::map<std::string,BDXPERMISSSION_S>::iterator itr;
							std::vector<std::string>::iterator itr2;
							#if 1
							printf("===================temp_mapUserInfo========================\n");
							for(itr=temp_mapUserInfo.begin();itr!=temp_mapUserInfo.end();itr++)
							{	
								printf("%s ",itr->first.c_str());
								printf("%s ",itr->second.mResToken.c_str());
								printf("%d ",itr->second.mIntQueryTimes);
								printf("%d ",itr->second.mIntGoodsTimes);
								printf("%s ",itr->second.mGoodsFields.c_str());
								
								//LOG(DEBUG,"itr->first.c_str()=%s",itr->first.c_str());
								//LOG(DEBUG,"itr->second.mResToken.c_str()=%s",itr->second.mResToken.c_str());
								//LOG(DEBUG,"itr->second.mIntQueryTimes=%d",itr->second.mIntQueryTimes);
								//LOG(DEBUG,"itr->second.mIntGoodsTimes=%d",itr->second.mIntGoodsTimes);
								//LOG(DEBUG,"itr->second.mGoodsFields.c_str()=%s",itr->second.mGoodsFields.c_str());
								for(itr2=itr->second.mVecFields.begin();itr2!=itr->second.mVecFields.end();itr2++)
								{
									printf("%s ",(*itr2).c_str());
									
								}
								printf("\n");
							}
							#endif
							#if 1
							printf("===================g_mapUserInfo========================\n");
							for(itr=g_mapUserInfo.begin();itr!=g_mapUserInfo.end();itr++)
							{	
								printf("%s ",itr->first.c_str());
								printf("%s ",itr->second.mResToken.c_str());
								printf("%d ",itr->second.mIntQueryTimes);
								printf("%d ",itr->second.mIntGoodsTimes);
								printf("%s ",itr->second.mGoodsFields.c_str());
								//LOG(DEBUG,"itr->first.c_str()=%s",itr->first.c_str());
								//LOG(DEBUG,"itr->second.mResToken.c_str()=%s",itr->second.mResToken.c_str());
								//LOG(DEBUG,"itr->second.mIntQueryTimes=%d",itr->second.mIntQueryTimes);
								//LOG(DEBUG,"itr->second.mIntGoodsTimes=%d",itr->second.mIntGoodsTimes);
								//LOG(DEBUG,"itr->second.mGoodsFields.c_str()=%s",itr->second.mGoodsFields.c_str());
								for(itr2=itr->second.mVecFields.begin();itr2!=itr->second.mVecFields.end();itr2++)
								{
									printf("%s ",(*itr2).c_str());
								}
								printf("\n");
							}
							#endif
							if( !MapIsEqual(temp_mapUserInfo,g_mapUserInfo) )
							{
							//	g_mapUserInfo = temp_mapUserInfo;
								
								SwapMap(temp_mapUserInfo,g_mapUserInfo);
								printf("\nswap map g_mapUserInfo\n\n");				
							}
						}	
					}
				}	
		}	
		#endif
		sleep(600);
	}

}

