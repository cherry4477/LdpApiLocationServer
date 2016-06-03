/*
 * TaskMain.cpp
 */

#include "TaskMain.h"
#include "../../CommonTools/UrlEncode/UrlEncode.h"
#include "../../UserQueryWorkThreads/UserQueryWorkThreads.h"

#include "../../CommonTools/Base64Encode/Base64.h"
#include "../../CommonTools/Base64Encode/Base64_2.h"
#include "../../../include/json/json.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>



extern CLog *gp_log;
const char* CTaskMain::m_pszHttpHeaderEnd = "\r\n\r\n";
const char* CTaskMain::m_pszHttpLineEnd = "\r\n";
const std::string CTaskMain::keyEdcpMd5Sign="edc_543_key_155&";
extern std::map<std::string,BDXPERMISSSION_S> g_mapUserInfo;
extern std::map<std::string,int> g_mapUserQueryLimit;
extern std::map<std::string,QUERYAPIINFO_S> g_vecUrlAPIS;


extern pthread_rwlock_t p_rwlock;
extern pthread_rwlockattr_t p_rwlock_attr;
extern pthread_mutex_t mutex;
extern std::string g_strTokenString ;
extern std::string ssToken;
extern u_int  g_iNeedUpdateToken ;
extern int iAPIQpsLimit;
extern std::map<int,std::string>mapIntStringOperator;

int InitSSLFlag = 0;
std::string g_strDataHubToken;

static const string http=" HTTP/1.1";

static const char http200ok[] = "HTTP/1.1 200 OK\r\nServer: Bdx DMP/0.1.0\r\nCache-Control: must-revalidate\r\nExpires: Thu, 01 Jan 1970 00:00:00 GMT\r\nPragma: no-cache\r\nConnection: Keep-Alive\r\nContent-Type: application/json;charset=UTF-8\r\nDate: ";
//static const char http200ok[] = "";
static const char httpReq[]="GET %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: identity\r\n\r\n";


#define __NOLOCAL__
#define __MD5__
#define __LOCAL_STORE__
#define __HTTPS__


CTaskMain::CTaskMain(CTcpSocket* pclSock):CUserQueryTask(pclSock)
{
	// TODO Auto-generated constructor stub
	m_piKLVLen = (int*)m_pszKLVBuf;
	m_piKLVContent = m_pszKLVBuf + sizeof(int);
	*m_piKLVLen = 0;
}

CTaskMain::CTaskMain()
{

}

CTaskMain::~CTaskMain() {
	// TODO Auto-generated destructor stub

}

int CTaskMain::BdxRunTask(BDXREQUEST_S& stRequestInfo, BDXRESPONSE_S& stResponseInfo)
{
	string keyReq = "Req_"+BdxTaskMainGetTime();
	string keyEmptyRes = "EmptyRes_"+BdxTaskMainGetTime();
	string strErrorMsg,errValue;
	string retKey,retKeyType,retUser,retAccessKeyID;
    HIVELOCALLOG_S stHiveEmptyLog;
	int iRes = 0;
	if(!m_pclSock) {
		LOG(ERROR, "[thread: %d]m_pclSock is NULL.", m_uiThreadId);
		return LINKERROR;
	}

	iRes = 	BdxGetHttpPacket(stRequestInfo,stResponseInfo,retAccessKeyID,retKey,retKeyType,retUser,strErrorMsg);	
	LOG(DEBUG,"BdxGetHttpPacket iRes=%d",iRes);
	if(iRes == SUCCESS )//&& !stRequestInfo.m_strUserID.empty() /*&& m_bSend*/) 
	{
		return BdxSendRespones( stRequestInfo, stResponseInfo,strErrorMsg);
	}
	else
	{

		if( iRes != LINKERROR )
		{
			errValue = "{\r\n\"code\":\""+strErrorMsg+"\",\r\n\"msg\":\"search data failure\",\r\n\"data\":\"\"\r\n}";		
			stHiveEmptyLog.strValue=strErrorMsg;
			if(retKey.empty())
			{
				stHiveEmptyLog.strTelNo="Empty";
			}
			else
			{	
				stHiveEmptyLog.strTelNo=retKey;
			}
			if(retKeyType.empty())
			{
				stHiveEmptyLog.strAction="Empty";
			}
			else
			{	
				stHiveEmptyLog.strAction=retKeyType;
			}
			if(retUser.empty())
			{
				stHiveEmptyLog.strReqParams="Empty";
			}
			else
			{	
				stHiveEmptyLog.strReqParams=retUser;
			}
			if(retAccessKeyID.empty())
			{
				stHiveEmptyLog.strAccessKeyId="Empty";
			}
			else
			{	
				stHiveEmptyLog.strAccessKeyId=retAccessKeyID;
			}
			
			if(stResponseInfo.mResValue.empty())
			{
				stHiveEmptyLog.strValue=strErrorMsg;
			}
			else
			{
				stHiveEmptyLog.strValue=stResponseInfo.mResValue;
			}
			stHiveEmptyLog.strAuthId="Empty";
			stHiveEmptyLog.strCustName="Empty";
			stHiveEmptyLog.strQuerytime=BdxTaskMainGetFullTime();
			
			stHiveEmptyLog.iSource = -1;//unknow
			stHiveEmptyLog.strSinature="Empty";
			stHiveEmptyLog.strDayId=BdxTaskMainGetDate();
			stHiveEmptyLog.strHourId=stHiveEmptyLog.strQuerytime.substr(8,2);
			if( stHiveEmptyLog.strTelNo!="Empty" )
			{
				CUserQueryWorkThreads::m_vecHiveLog[m_uiThreadId].push(stHiveEmptyLog);
			}
			
			
			//if ( iRes == OTHERERROR)
			//{		
				if(CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo.find(stResponseInfo.ssUserName)	
					!=	CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo.end())
				{

					m_pDataRedis->UserIncr(stResponseInfo.ssUserCountKeyEmptyRes); 
					CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssUserName].m_ullEmptyResNum++;

				}
				//if(CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo.find(stResponseInfo.ssOperatorName)	
				//	!=	CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo.end())

				if( stResponseInfo.ssOperatorName !="" )
				{
					CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssOperatorName].m_ullEmptyResNum++;
				}
				
			//	printf("ssUserCountKeyEmptyRes=%s\n",stResponseInfo.ssUserCountKeyEmptyRes.c_str());
				#if 0
				if( stResponseInfo.queryType==2 )
				{
					m_pGoodsRedis->UserIncr(stResponseInfo.ssUserCountKeyEmptyRes);
				}
				else
				{
					m_pDataRedis->UserIncr(stResponseInfo.ssUserCountKeyEmptyRes);
				}
				#endif
				
				//return BdxSendEmpyRespones(stResponseInfo);
			//}
			//if ( iRes == EXCEEDLIMIT)
			//{
			//	CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssUserName].m_ullEmptyResNum++;
			//	m_pDataRedis->UserIncr(stResponseInfo.ssUserCountKeyEmptyRes);
			//}
	/*
			else
			{		
				CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[""].m_ullReqNum++;
				CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[""].m_ullEmptyResNum++;
				m_pDataRedis->UserIncr(keyReq);
				m_pDataRedis->UserIncr(keyEmptyRes);
			}

	*/			
				return BdxSendEmpyRespones(errValue);
		 }
		return BdxSendEmpyRespones(strErrorMsg);
	}
	return iRes;
}


int CTaskMain::BdxGetHttpPacket(BDXREQUEST_S& stRequestInfo,BDXRESPONSE_S &stResponseInfo,std::string &retAccessKeyID,std::string &retKey,std::string &retKeyType,std::string &retUser,std::string &errorMsg)
{

	int iRes = 0;//,istrRemoteValueLength=0;
	//int iQueryCategory = 0,isError=0;
	int iQueryCategory = -1;
	m_httpType = 0;
	//bool bUpdateDatabase = false;
	//bool bQueryUser = false;
	//bool bQueryGoods = false;
	//bool bUserIdentity = false;
	//int iIdentity=0; //10001 begin with 1 is verity,20002 beginwith 2 is query
	//int iQueryInfo=0;//
	//bool bTelVerify = false;
	int iNoDataFlag = 0;//,isQueryAction = 0,
	int strSource = 9999;
	char chSource[30];

	std::string startOrderID = KEY_startOrderID;
	std::string startToken = KEY_startToken;
	std::string apiGateWayAdmin = KEY_apiGateWayAdmin;
	std::string startOrderCount  = KEY_startOrderCount;
	std::string startOrderLimit  = KEY_startOrderLimit;
	std::string startOrderStatus = KEY_startOrderStatus;
	std::string startOrderExpire = KEY_startOrderExpire;
	std::string startUserRepoItemSubid,valueUserRepoItemSubid;

	std::string needUpdateOrder="need_updated_datahub_order";
	std::string alreadyUpdateOrder="already_updated_datahub_order";
	std::vector<DATAHUB_ORDER_INFO_S> vecDataHubOrder;
	std::string strCountOrderId,strLimitOrderId,strStatusOrderId,strExpireOrderId,strTempSubID;
	std::string strMidCountOrderId,strMidLimitOrderId,strMidStatusOrderId,strMidExpireOrderId,strMidTempSubID;


	
	std::string strPrivateKey="a1b2c3";
	std::string	strMobile,strSign,strParams,strSelect,
	ssUser,ssValue,ssKey,ssmoidValue,ssmoidValue2,strUser,filterDate,strToken,strAccessKeyID,strKey,strMd5Key,strKeyType,strCST,strAccuracy,strLng,strLat,strKeyFilter,tempstrKeyFilter,strShopId,strGoodsId,strProvince,strOperator,strMoId,strRepo,strItem,strDataHubToken;
	std::string strID = "null";
	std::string strProvinceReq,strProvinceRes,strProvinceEmptyRes,strProvinceResTag,strOperatorName;
	std::string 
	strTimeStamp,strApiName,strLiveTime,strAccessKeyId,strUserToken,strUserOrderId,strApiGateWayToken,strAccessPrivatekey,strSinature,strTelNo,strMonth,strTelNoTemp,strCertType,strCertCode,strUserName,strAuthId,strCustName,strUserIdentity,strUserTelVerity,strHost,strRemoteValue;
	std::map<std::string,std::string> map_UserValueKey;

	std::map<std::string,std::string>::iterator iter2;
	std::map<std::string,BDXPERMISSSION_S>::iterator iter;
	std::vector<std::string>::iterator itRights;
	//int inUseTime;//iIncludeNoFields = 0;
	//int mapActionFilterSize;
	std::map<std::string,int> mapActionFilter;
	std::string mResUserAttributes,mResUserAttributes2,strTempValue;
	Json::Value jValue,jRoot,jResult,jTemp;
	
	int lenStrTemp,iLimitOrderId,iCountOrderId;
	Json::FastWriter jFastWriter;
	//int isExpire = 0, iIsLocal=0,iRemoteApiFlag = 0;
	//int iOperator = 0;
	string strCreateTime,strFirst3Bit,strCreateTime2,strAction,strLastDataTime,strLastDataTime2,mResValueLocal,mResValueRemote;
	std::string str_urlDecode;
	//struct tm ts;
	//time_t timetNow,timetCreateTime,timetCreateTime2;
	//Json::Reader jReader;
	//Json::Reader *jReader= new Json::Reader(Json::Features::strictMode()); // turn on strict verify mode
	//Json::Reader *jReader= new Json::Reader(Json::Features::all());
	//Json::Reader *jReader;
	char chHostName[30];
	char *temp[PACKET]; 
	int  index = 0;
	char bufTemp[PACKET];
	char *buf;
	char *outer_ptr = NULL;  
	char *inner_ptr = NULL;  
	char m_httpReq[_8KBLEN];
	char m_httpResValueE20003[_8KBLEN];
	memset(chHostName, 0,30);
	memset(m_pszAdxBuf, 0, _8KBLEN);
	memset(m_httpReq, 0, _8KBLEN);
	memset(m_httpResValueE20003, 0, _8KBLEN);
	//memset(buf, 0, _8KBLEN);
	memset(bufTemp, 0, PACKET);
	

	iRes = m_pclSock->TcpRead(m_pszAdxBuf, _8KBLEN);

  	LOG(DEBUG,"Requrest= %s\n",m_pszAdxBuf);  
	printf("ThreadID: %d,Line%d,Requrest= %s\n",m_uiThreadId,__LINE__,m_pszAdxBuf);  
	str_urlDecode=url_decode((char*)m_pszAdxBuf);
	memset(m_pszAdxBuf, 0, _8KBLEN);
	sprintf(m_pszAdxBuf,"%s",str_urlDecode.c_str());

	
	printf("ThreadID: %d,Line%d,Requrest= %s\n",m_uiThreadId,__LINE__,m_pszAdxBuf);  
	if(iRes <= (int)http.length()) 
	{		
		LOG(DEBUG, "[thread: %d]Read Socket Error [%d].", m_uiThreadId, iRes);
		printf("[thread: %d]Read Socket Error [%d].\n", m_uiThreadId, iRes);
		errorMsg="1101";
		return LINKERROR;
	}

	std::string ssContent = std::string(m_pszAdxBuf);
	std::string tempssContent,strActionUrl,strReqParams;
	unsigned int ipos = ssContent.find(CTRL_N,0);
	unsigned int jpos = ssContent.find(REQ_TYPE,0);
	
	if( std::string::npos !=jpos )
	{
		m_httpType = 1;
	}
	if(m_httpType )
	{
		ssContent = ssContent.substr(jpos+4,ipos-http.length()-(jpos+4));
		int ibegin = ssContent.find(SEC_Q,0);
		int iend =   ssContent.find(BLANK,0);
		strActionUrl =  ssContent.substr(0,ssContent.find(SEC_Q,0));

		if(strcasecmp(strActionUrl.substr(0,strActionUrl.find(SEC_Q,0)).c_str(),KEY_QUERY_USER)!= 0)
		{
			errorMsg="1101";
			printf("Line:%d,request action is error \n",__LINE__);
			return LINKERROR;
		}
		
		if (ibegin!=-1 && iend !=-1)
		{

				ssContent = ssContent.substr(ibegin+1,iend - ibegin-1);	
				strReqParams = ssContent;
				memcpy(bufTemp,ssContent.c_str(),ssContent.length());
				buf=bufTemp;
				while((temp[index] = strtok_r(buf, STRING_AND, &outer_ptr))!=NULL)   
				{  	
				    buf=temp[index];  
				    while((temp[index]=strtok_r(buf, STRING_EQUAL, &inner_ptr))!=NULL)   
				    {   if(index%2==1)
				        {
				            map_UserValueKey[temp[index-1]]=temp[index];
				            
				            
				        }
				        index++;
				        buf=NULL;  
				    }  
				    buf=NULL;  
				}  
				
				if(map_UserValueKey.find(KEY_ACCESS_KEY_ID)!=map_UserValueKey.end()/*&&map_UserValueKey.find(KEY_API_NAME)!=map_UserValueKey.end()*/&&map_UserValueKey.find(KEY_SIGNATURE)!=map_UserValueKey.end()&&map_UserValueKey.find(KEY_OPERATOR)!=map_UserValueKey.end()&&map_UserValueKey.find(KEY_CST)!=map_UserValueKey.end()&&map_UserValueKey.find(KEY_ACCURACY)!=map_UserValueKey.end()&&map_UserValueKey.find(KEY_LATITUDE)!=map_UserValueKey.end()&&map_UserValueKey.find(KEY_LONGTITUDE)!=map_UserValueKey.end()&&map_UserValueKey.find(KEY_REPOSITIRY)!=map_UserValueKey.end()&&map_UserValueKey.find(KEY_ITEM)!=map_UserValueKey.end())
				{	
					strAccessKeyId = map_UserValueKey.find(KEY_ACCESS_KEY_ID)->second;
					//strApiName = map_UserValueKey.find(KEY_API_NAME)->second;
					strSinature = map_UserValueKey.find(KEY_SIGNATURE)->second;
					strKeyType= map_UserValueKey.find(KEY_OPERATOR)->second; //query type
					strCST= map_UserValueKey.find(KEY_CST)->second;
					strAccuracy= map_UserValueKey.find(KEY_ACCURACY)->second;
					strLat =  map_UserValueKey.find(KEY_LATITUDE)->second;
					strLng =  map_UserValueKey.find(KEY_LONGTITUDE)->second;
					strRepo = map_UserValueKey.find(KEY_REPOSITIRY)->second;
					strItem = map_UserValueKey.find(KEY_ITEM)->second;

					if(atoi(strKeyType.c_str())==2)
					{	
						if(map_UserValueKey.find(KEY_KEY_ID)!=map_UserValueKey.end())
						{
							strID= map_UserValueKey.find(KEY_KEY_ID)->second;
						}
						else
						{
							errorMsg ="1100"; //param missing or error
							LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
							printf("line %d,s Error: %s\n",__LINE__,errorMsg.c_str());
							return OTHERERROR;
						}
					}


						strUserToken = strAccessKeyId +std::string(KEY_DELIMITER + startToken);
						m_pDataRedis->UserGet(strUserToken,ssmoidValue);
				    	printf("Line:%d,strSinature=%s\n",__LINE__,strSinature.c_str());
						printf("Line:%d,ssmoidValue=%s\n",__LINE__,ssmoidValue.c_str());
				    	if( strSinature.compare(ssmoidValue.c_str())!= 0 )
				    	{	
				    		#ifdef __HTTPS__
				    		if (BdxVerifyDataHubToken(strAccessKeyId,strSinature)==1)
							#endif
				    		{	
				    			m_pDataRedis->UserPutExpire(strUserToken,strSinature,3*3600);
							}
							else
							{
								errorMsg ="8001"; //user token is error
								printf("line %d,s Error: %s\n",__LINE__,errorMsg.c_str());
								return OTHERERROR;
							}
				    		//get local token,if verify is not ok,then get new token
							//BdxGetNewDataHubToken(authUser,authToken);						
						}

						
						strApiGateWayToken = apiGateWayAdmin +std::string(KEY_DELIMITER + startToken);
						if(m_pDataRedis->UserGet(strApiGateWayToken,ssmoidValue))
						{
							strDataHubToken  =  ssmoidValue;
							printf("Line:%d,Local strDataHubToken =%s\n",__LINE__,strDataHubToken.c_str());
						}
				    	else
				    	{	
							#ifdef __HTTPS__
							strDataHubToken = BdxApiGateWayGetDataHubToken();
							#endif
							if(strDataHubToken.empty())
							{
								errorMsg ="8002"; //gateway token is error
								printf("line %d,s Error: %s\n",__LINE__,errorMsg.c_str());
								return OTHERERROR;
							}
							printf("Line:%d,datahub strDataHubToken =%s\n",__LINE__,strDataHubToken.c_str());
				    		m_pDataRedis->UserPutExpire(strApiGateWayToken,strDataHubToken,3*3600);					
						}

					g_strDataHubToken = strDataHubToken;
					printf("Line:%d,g_strDataHubToken=%s\n",__LINE__,g_strDataHubToken.c_str());
					strUserOrderId =  strAccessKeyId +std::string(KEY_DELIMITER + startOrderID );

					ssmoidValue = "";
					startUserRepoItemSubid = strAccessKeyId + KEY_DELIMITER + strRepo + KEY_DELIMITER + strItem  + KEY_DELIMITER;
					strMidCountOrderId   = startOrderCount  + KEY_DELIMITER + startUserRepoItemSubid;
					strMidLimitOrderId   = startOrderLimit  + KEY_DELIMITER + startUserRepoItemSubid;
					strMidStatusOrderId  = startOrderStatus + KEY_DELIMITER + startUserRepoItemSubid;
					strMidExpireOrderId  = startOrderExpire + KEY_DELIMITER + startUserRepoItemSubid;
					printf("Line:%d,strUserOrderId=%s\n",__LINE__,strUserOrderId.c_str());
					if(m_pDataRedis->UserGetSortedSet(strUserOrderId,ssmoidValue))
					{
						strCountOrderId = strMidCountOrderId + ssmoidValue;
						strLimitOrderId = strMidLimitOrderId + ssmoidValue;
						strStatusOrderId = strMidStatusOrderId + ssmoidValue;
						strExpireOrderId = strMidExpireOrderId + ssmoidValue;
						valueUserRepoItemSubid = startUserRepoItemSubid + ssmoidValue;
						strTempSubID = ssmoidValue;
						

						printf("Line:%d,Order is  =%s\n",__LINE__,ssmoidValue.c_str());
					}
					else
					{	
						printf("Line:%d,get datahub Order\n",__LINE__);
						//get user order
						vecDataHubOrder = BdxApiGetUserOrder(strRepo,strItem,strAccessKeyId,strDataHubToken);
						printf("Line:%d,vecDataHubOrder size=%d\n",__LINE__,vecDataHubOrder.size());

						//local store order info to redis
						for(int i=0;i<vecDataHubOrder.size();i++)
						{
							m_pDataRedis->UserPutOrderSet(strUserOrderId,vecDataHubOrder[i].m_subscriptionID,vecDataHubOrder[i].m_subscriptionID);

							valueUserRepoItemSubid = startUserRepoItemSubid + vecDataHubOrder[i].m_subscriptionID;
							m_pDataRedis->UserSadd(needUpdateOrder,valueUserRepoItemSubid);
							printf("Line:%d,vecDataHubOrder[%d].m_subscriptionID=%s\n",__LINE__,i,vecDataHubOrder[i].m_subscriptionID.c_str());
							strCountOrderId = strMidCountOrderId + vecDataHubOrder[i].m_subscriptionID;
							strLimitOrderId = strMidLimitOrderId + vecDataHubOrder[i].m_subscriptionID;
							strStatusOrderId = strMidStatusOrderId + vecDataHubOrder[i].m_subscriptionID;
							strExpireOrderId = strMidExpireOrderId + vecDataHubOrder[i].m_subscriptionID;
							strTempSubID = vecDataHubOrder[i].m_subscriptionID;
							m_pDataRedis->UserPut(strCountOrderId,std::string("0"));
							m_pDataRedis->UserPutExpire(strExpireOrderId,vecDataHubOrder[i].m_subscriptionID,atol(vecDataHubOrder[i].m_expireTime.c_str())*86400);
							m_pDataRedis->UserPut(strLimitOrderId,vecDataHubOrder[i].m_units);
							m_pDataRedis->UserPut(strStatusOrderId,std::string("0"));							
							if(!BdxApiSetUserOrderStatus(strAccessKeyId,strTempSubID,strRepo,strItem,strDataHubToken))
							{	
								//update datahub status retrieve faild,then jump it
								printf("Line:%d,BdxApiSetUserOrderStatus\n",__LINE__);
								m_pDataRedis->UserRemoveSortedSet(strUserOrderId,ssmoidValue);
								//m_pDataRedis->UserDel(strCountOrderId,std::string("0"));
								//m_pDataRedis->UserDel(strExpireOrderId,vecDataHubOrder[i].m_subscriptionID);
								//m_pDataRedis->UserDel(strLimitOrderId,vecDataHubOrder[i].m_units);
								//m_pDataRedis->UserDel(strStatusOrderId,std::string("0"));	
								continue;
							}

						}
						ssmoidValue.clear();
						m_pDataRedis->UserGetSortedSet(strUserOrderId,ssmoidValue);
						strCountOrderId = strMidCountOrderId + ssmoidValue;
						strLimitOrderId = strMidLimitOrderId + ssmoidValue;
						strStatusOrderId = strMidStatusOrderId + ssmoidValue;
						strExpireOrderId = strMidExpireOrderId + ssmoidValue;
						valueUserRepoItemSubid = startUserRepoItemSubid + ssmoidValue;
						strTempSubID = ssmoidValue;
						printf("Line:%d,valueUserRepoItemSubid=%s\n",__LINE__,valueUserRepoItemSubid.c_str());

			
					}

					#if 0
					if(strApiName != "location")
					{
						errorMsg ="1100"; //param missing or error
						LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
						printf("line %d,s Error: %s\n",__LINE__,errorMsg.c_str());
						return OTHERERROR;
					}
					#endif
					stResponseInfo.ssUserName=strAccessKeyId+"_"+strKeyType;//+"_"+strSinature;
					//stResponseInfo.ssUserCountKeyUserLimitReq = "Limit_"+BdxTaskMainGetDate()+"_"+strAccessKeyId+"_"+strAction;
					stResponseInfo.ssUserCountKeyUserLimitReq = "Limit_"+strAccessKeyId;
					stResponseInfo.ssOperatorNameKeyLimit = "Limit_"+BdxTaskMainGetTime()+"_"+strAccessKeyId;//+"_"+strAction;


					stResponseInfo.ssUserCountKeyReq = "Req_" + BdxTaskMainGetTime()+"_"+strAccessKeyId;//+"_"+strAction;
					stResponseInfo.ssUserCountKeyRes = "Res_" + BdxTaskMainGetTime()+"_"+strAccessKeyId;//"_"+strAction;
					stResponseInfo.ssUserCountKeyEmptyRes ="EmptyRes_"+BdxTaskMainGetTime()+"_"+ strAccessKeyId;//+"_"+strAction;
					//stResponseInfo.ssUserName = strUser+"_"+strKeyType;//map_UserValueKey.find(KEY_USER)->second ;

					
					m_pDataRedis->UserIncr(stResponseInfo.ssUserCountKeyReq); //req++
					CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssUserName].m_ullReqNum++;

					m_pDataRedis->UserIncr(stResponseInfo.ssUserCountKeyUserLimitReq);
					CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssUserName].m_ullResTagNum++;
				
					printf("Line:%d,ssmoidValue=%s\n",__LINE__,ssmoidValue.c_str());
					ssmoidValue.clear();
					ssmoidValue2.clear();
					printf("Line:%d,strCountOrderId=%s\n",__LINE__,strCountOrderId.c_str());
					if((m_pDataRedis->UserGet(strCountOrderId,ssmoidValue))&&(m_pDataRedis->UserGet(strLimitOrderId,ssmoidValue2)))
					{	
						iCountOrderId = atoi(ssmoidValue.c_str());
						iLimitOrderId = atoi(ssmoidValue2.c_str());

						printf("Line:%d,iCountOrderId==%d\n",__LINE__,iCountOrderId);
						printf("Line:%d,iLimitOrderId==%d\n",__LINE__,iLimitOrderId);
						printf("Line:%d,strExpireOrderId=%s\n",__LINE__,strExpireOrderId.c_str());

						if(( iCountOrderId >= iLimitOrderId )||(!m_pDataRedis->UserGet(strExpireOrderId,ssmoidValue)))
						{
							printf("Line:%d,over order limit\n",__LINE__);
							//delete order
							ssmoidValue.clear();
							printf("Line:%d,################################\n",__LINE__);
							m_pDataRedis->UserRemoveSortedSet(strUserOrderId,ssmoidValue);

							ssmoidValue.clear();
							if(m_pDataRedis->UserGet(strStatusOrderId,ssmoidValue))
							{
								if(atoi(ssmoidValue.c_str())==0)
								{
									//update datahub order used
									BdxApiUpdateUserOrder(strAccessKeyId,strTempSubID,strRepo,strItem,strDataHubToken,iCountOrderId);
									//update local order status 
									m_pDataRedis->UserSmove(needUpdateOrder,alreadyUpdateOrder,valueUserRepoItemSubid);
									m_pDataRedis->UserPut(strStatusOrderId,std::string("1"));
								}
							
							}		
							errorMsg = "8003";//over quato limit or order is expired
							LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
							return OTHERERROR;
						}
					}
					else
					{
							errorMsg = "8004";//can't get order info
							LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
							return OTHERERROR;

					}

					#if 0
					else
					{
						//ssmoidValue = "";
						ssmoidValue.clear();
						if(m_pDataRedis->UserGet(strStatusOrderId,ssmoidValue))
						{
							if(atoi(ssmoidValue.c_str())==0)
							{
								//update datahub order
							}

						}
						errorMsg = "8003";//over quato limit
						LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
						return OTHERERROR;
					}
					#endif
						
					//CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssUserName].m_ullTotalReqNum++;
					#if 0
					if(m_pDataRedis->UserGet(stResponseInfo.ssUserCountKeyUserLimitReq,ssmoidValue)&&(g_mapUserInfo.find(map_UserValueKey.find(KEY_ACCESS_KEY_ID)->second)->second.mIntQueryTimes>=0))
				    {	
				    	printf("Line:%d,g_mapUserInfo.find(KEY_ACCESS_KEY_ID)->second.mIntQueryTimes=%d\n",__LINE__,g_mapUserInfo.find(strAccessKeyId)->second.mIntQueryTimes);
				    	LOG(DEBUG,"g_mapUserInfo.find(KEY_ACCESS_KEY_ID)->second.mIntQueryTimes=%d",g_mapUserInfo.find(strAccessKeyId)->second.mIntQueryTimes);
						if(atoi(ssmoidValue.c_str())> g_mapUserInfo.find(strAccessKeyId)->second.mIntQueryTimes)
						{
							errorMsg = "4000";//user query times limit
							LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
							return OTHERERROR;
						}

					}
					//m_pDataRedis->UserIncr(stResponseInfo.ssUserCountKeyUserLimitReq);
					//CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssUserName].m_ullResTagNum++;

					#endif
					
					//verify time ,verify signature	
					
				 }
				 else
				 {
						errorMsg ="1100"; //param missing or error
						LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
						printf("line %d,s Error: %s\n",__LINE__,errorMsg.c_str());
						return OTHERERROR;
				 }

				printf("Line:%d,strKeyType=%d\n",__LINE__,atoi(strKeyType.c_str()));
				LOG(DEBUG,"strKeyType=%s",strKeyType.c_str());

				//strSelect = ;
				// 1 here 2 info 3 nearby
				switch(atoi(strKeyType.c_str()))
				{
					case 1://userIdentity
						{
							strKey = ACTION_HERE +strPrivateKey + "&accuracy=" +strAccuracy + "&lat=" + strLat+"&lng=" + strLng +"&cst=" + strCST;
							strMd5Key = strAccuracy + "_" + strCST + "_" + strLat+ "_" + strLng;
						}
						break;
					case 2:
						{
							strKey = ACTION_INFO +strPrivateKey + "&id=" +strID;//"&accuracy=" +strAccuracy + "&lat=" + strLat+"&lng=" + strLng +"&cst=" + strCST;
							strMd5Key = strAccuracy + "_" + strCST + "_" + strLat+ "_" + strLng+"_"+strID;
						}
						break;
					case 3:
						{
							strKey = ACTION_NEARBY +strPrivateKey + "&accuracy=" +strAccuracy + "&lat=" + strLat+"&lng=" + strLng +"&cst=" + strCST;
							strMd5Key = strAccuracy + "_" + strCST + "_" + strLat+ "_" + strLng;
						}
						break;

					default:
						printf("default\n");
						break;


				}

				
				ssContent = ssContent.substr(0,ipos);

				#ifdef __NOLOCAL__
				{		

						LOG(DEBUG,"ssContent=%s",ssContent.c_str());
						ssContent = strMd5Key ;
						LOG(DEBUG,"ssContent=%s",ssContent.c_str());
						
						#ifdef __MD5__
						ssContent = BdxGetParamSign(ssContent,std::string(""));
						#endif
						LOG(DEBUG,"ssContent Key=%s",ssContent.c_str());
						printf("Line:%d,ssContent=%s\n",__LINE__,ssContent.c_str());
						if(m_pDataRedis->UserGet(ssContent,ssmoidValue))
						{	
							LOG(DEBUG,"ssmoidValue=%s",ssmoidValue.c_str());
							printf("ssmoidValue=%s\n",ssmoidValue.c_str());
							stResponseInfo.mResValue = ssmoidValue;
							iQueryCategory = 0;
							m_pDataRedis->UserIncr(stResponseInfo.ssUserCountKeyRes);
							CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssUserName].m_ullResNum++;
							LOG(DEBUG,"stResponseInfo.mResValue=%s",stResponseInfo.mResValue.c_str());
							printf("stResponseInfo.mResValue=%s\n",stResponseInfo.mResValue.c_str());
							
						}
						else 
						{
							//when no data in local redis,then query remote api
							iNoDataFlag = 1;
							memset(chSource, 0,30);
							sprintf(chSource,"%d",strSource);
							stResponseInfo.ssOperatorName=strAccessKeyId + "_Remote_" + string(chSource) + "_" + strAction;//+"_"+strSinature;
							//return ERRORNODATA;
						}
						
						
				 }
				#endif //__NOLOCAL__
			
			printf("Line:%d,iNoDataFlag=%d\n",__LINE__,iNoDataFlag);
			LOG(DEBUG,"iNoDataFlag=%d",iNoDataFlag); 

			char remoteBuffer[_8KBLEN];
			CTcpSocket* remoteSocket;
			std::string remoteIp;
			uint16_t remotePort;
			
			string key;
			//printf("Line:%d,strProvince=%s\n",__LINE__,strProvince.c_str());
			if( iNoDataFlag == 1 )
			{
				for( std::map<std::string,QUERYAPIINFO_S>::iterator itr=g_vecUrlAPIS.begin();itr!=g_vecUrlAPIS.end();itr++)
				{
					if(atoi(itr->second.mParam) == strSource)  //????
					{
						printf("9999999999999999\n");
						strHost=itr->first;
						remoteIp.assign(itr->first,0,itr->first.find(":",0));
						remotePort = atoi(itr->first.substr(itr->first.find(":",0)+1).c_str());
						printf("sslIp=%s,sslPort=%d\n",remoteIp.c_str(),remotePort);
						remoteSocket=new CTcpSocket(remotePort,remoteIp);
						if(remoteSocket->TcpConnect()!=0)
						{
							errorMsg = "2001";
							LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
							return OTHERERROR;
						}
						break;
					}

				}
				

					
					//sprintf(m_httpReq,"GET %s HTTP/1.1\r\nAccept: */*\r\nAccept-Language: zh-cn\r\ntoken: %s\r\nhost: %s\r\n\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection:keep-alive\r\n",strUserIdentity.c_str(),strToken.c_str(),strHost.c_str(),istrRemoteValueLength,strRemoteValue.c_str());
					if(strSource==9999)
					{
						iQueryCategory = 1; // remote
						sprintf(m_httpReq,"GET %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: identity\r\n\r\n",strKey.c_str(),string("bapi.caiyun001.net").c_str());
					}

					printf("Line:%d,%s\n",__LINE__,m_httpReq);
					LOG(DEBUG,"m_httpReq=%s",m_httpReq);
					printf("Line:%d,remoteSocket->TcpGetSockfd()=%d\n",__LINE__,remoteSocket->TcpGetSockfd());
					if(remoteSocket->TcpWrite(m_httpReq,strlen(m_httpReq))!=0)
					{
							CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssOperatorName].m_ullReqNum++;
							memset(remoteBuffer,0,_8KBLEN);
							//remoteSocket->TcpReadAll(remoteBuffer,_8KBLEN);
							remoteSocket->TcpRead(remoteBuffer,_8KBLEN);
							
							printf("Line:%d,remoteBuffer=%s\n",__LINE__,remoteBuffer);
							LOG(DEBUG,"remoteBuffer=%s",remoteBuffer);
							if( strlen(remoteBuffer) > 0 )
							{
								stResponseInfo.mResValue = std::string(remoteBuffer);
								mResValueRemote = stResponseInfo.mResValue;
								remoteSocket->TcpClose();
								delete remoteSocket;
							}
							else
							{
								remoteSocket->TcpClose();
								delete remoteSocket;
								errorMsg = "2003";
								return OTHERERROR;
							}
					}
					else
					{
						remoteSocket->TcpClose();
						delete remoteSocket;
						errorMsg = "2002";
						printf("Line:%d,remoteSocket->TcpGetSockfd()=%d\n",__LINE__,remoteSocket->TcpGetSockfd());
						return OTHERERROR;
					}

			}

		}
		else
		{
			 errorMsg = "1100";	// request param is error
			 LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
			 return OTHERERROR;
		}
	}
	else
	{
		errorMsg = "1101";	// request type  is error ( GET )
		LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
		return OTHERERROR;
	}

	LOG(DEBUG,"mResValueRemote=%s",mResValueRemote.c_str());
	printf("Line:%d,stResponseInfo.mResValue=%s\n",__LINE__,stResponseInfo.mResValue.c_str());
	if( iNoDataFlag == 1 )
	{		
		if(mResValueRemote.empty())//&&isExpire == 1)
		{			
			errorMsg = "5000";  // data is not exists
			LOG(DEBUG,"errorMsg=%s,stResponseInfo.mResValue=%s",errorMsg.c_str(),stResponseInfo.mResValue.c_str());
			printf("line %d,s Error: %s,value %s\n",__LINE__,errorMsg.c_str(),stResponseInfo.mResValue.c_str());
			return OTHERERROR;
		}

		lenStrTemp = mResValueRemote.length();
		if( mResValueRemote.find("\r\n\r\n")!=std::string::npos )
		{
			mResValueRemote = mResValueRemote.substr(mResValueRemote.find("\r\n\r\n")+4,lenStrTemp -(mResValueRemote.find("\r\n\r\n")+4));
		}
		
		lenStrTemp =  mResValueRemote.length();
		stResponseInfo.mResValue = mResValueRemote;
		
		int ipos1=stResponseInfo.mResValue.find("{",0);
		int ipos2=stResponseInfo.mResValue.rfind("}",stResponseInfo.mResValue.length());
		printf("Line:%d,ipos1=%d,ipos2=%d\n",__LINE__,ipos1,ipos2);

		if( ipos1 < 0 || ipos2 <= 0 )
		{
			errorMsg = "5000";  // data is not exists
			LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
			printf("line %d,s Error: %s,value %s\n",__LINE__,errorMsg.c_str(),stResponseInfo.mResValue.c_str());
			return OTHERERROR;
		}
		
		stResponseInfo.mResValue = stResponseInfo.mResValue.substr(ipos1,ipos2-ipos1+1);
		printf("Line:%d,stResponseInfo.mResValue=%s\n",__LINE__,stResponseInfo.mResValue.c_str());

		
	}

	HIVELOCALLOG_S stHiveLog;
	//stHiveLog.logtime=logtime;
	stHiveLog.strAccessKeyId=strAccessKeyId;
	stHiveLog.iSource = iQueryCategory;
	stHiveLog.strTelNo=strKeyType;
	stHiveLog.strTimeStamp=strTimeStamp;
	stHiveLog.strLiveTime=strLiveTime;
	stHiveLog.strSinature=strSinature;
	stHiveLog.strAuthId=strCST;
	stHiveLog.strCustName=strLat;
	stHiveLog.strAction=strLng;
	stHiveLog.strMd5Key=strMd5Key;
	stHiveLog.strReqParams=strReqParams;
	stHiveLog.strValue=stResponseInfo.mResValue;
	stHiveLog.strQuerytime=BdxTaskMainGetFullTime();
	stHiveLog.strDayId=BdxTaskMainGetDate();
	stHiveLog.strHourId=stHiveLog.strQuerytime.substr(8,2);	
	CUserQueryWorkThreads::m_vecHiveLog[m_uiThreadId].push(stHiveLog);

	//stResponseInfo.mResValue="{\"resCode\":\"0000\",\"resMsg\":\"«Î«Û≥…π¶\",\"sign\":\"DEA501DC38718AE61EF0033684AC1759\",\"data\":[{\"resCode\":\"0000\",\"resMsg\":\"«Î«Û≥…π¶\",\"quotaInfo\":{\"quotaValuePercent\":0,\"quotaID\":\"Z0003\",\"quotaName\":\" ÷ª˙∫≈¬Î‘⁄Õ¯ ±≥§\",\"quotaType\":1,\"quotaValue\":\"[36,+)\",\"quotaPrice\":100,\"quotaValueType\":2}}]}";
	LOG(DEBUG,"stResponseInfo.mResValue=%s",stResponseInfo.mResValue.c_str());
	printf("Line:%d,stResponseInfo.mResValue=%s\n",__LINE__,stResponseInfo.mResValue.c_str());

	Json::Reader *jReader= new Json::Reader(Json::Features::all());
	if( strSource == 9999)
	{
		if(!jReader->parse(stResponseInfo.mResValue, jValue,true))
		{ 
			errorMsg = "5000";
			LOG(DEBUG,"errorMsg=%s",errorMsg.c_str());
			printf("line %d,s Error: %s\n",__LINE__,errorMsg.c_str());
			delete jReader;
			return	OTHERERROR;
		}
		delete jReader;
		/*
		if(jValue[string("resCode").c_str()].asString()!="0000")
		{
			errorMsg = "5000";
			return OTHERERROR;
		}
		*/
		#ifdef __LOCAL_STORE__
		  if( iNoDataFlag == 1 )
		  {
			m_pDataRedis->UserIncr(stResponseInfo.ssUserCountKeyRes); 
			CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssUserName].m_ullResNum++;
			CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stResponseInfo.ssOperatorName].m_ullResNum++;
			//strTelNo=strTelNo+"_"+strAction;
			strTelNo = strMd5Key;
			#ifdef __MD5__
			strTelNo = BdxGetParamSign(strTelNo,std::string(""));	
			#endif
			LOG(DEBUG,"Local Store strTelNo=%s",strTelNo.c_str());
			printf("line %d,strTelNo: %s\n",__LINE__,strTelNo.c_str());
			//if(!m_pDataRedis->UserPut(strTelNo,mResValueLocal))
			if(!m_pDataRedis->UserPutExpire(strTelNo,stResponseInfo.mResValue,1825*86400))//expired 5 years
			{		
				 	LOG(ERROR, "[thread: %d]Set HotKey Error.", m_uiThreadId);								
			}

		  }
		#endif
	}

	m_pDataRedis->UserIncr(strCountOrderId);
	printf("Line:%d,add order count\n",__LINE__);	

    return SUCCESS;
	
}

int CTaskMain::BdxParseHttpPacket(char*& pszBody, u_int& uiBodyLen, const u_int uiParseLen)
{
	u_int uiHeadLen = 0;

	char* pszTmp = NULL;
	char* pszPacket = m_pszAdxBuf;
	if(strncmp(m_pszAdxBuf, "GET", strlen("GET"))) {
//		LOG(ERROR, "[thread: %d]It is not POST request.", m_uiThreadId);
		return PROTOERROR;
	}

	//find body
	pszTmp = strstr(pszPacket, m_pszHttpHeaderEnd);
	if(pszTmp == NULL) {
		LOG(ERROR, "[thread: %d]can not find Header End.", m_uiThreadId);
		return PROTOERROR;
	}
	pszBody = pszTmp + strlen(m_pszHttpHeaderEnd);
	uiHeadLen = pszBody - m_pszAdxBuf;

	return SUCCESS;
	//return OTHERERROR;
}

int CTaskMain::BdxParseBody(char *pszBody, u_int uiBodyLen, BDXREQUEST_S& stRequestInfo)
{

    LOG(DEBUG,"SUCCESS");
	return SUCCESS;
}



int CTaskMain::BdxSendEmpyRespones(std::string errorMsg)
{
	m_clEmTime.TimeOff();
	std::string strOutput=errorMsg;	
	char pszDataBuf[_8KBLEN];
	memset(pszDataBuf, 0, _8KBLEN);
	sprintf((char *)pszDataBuf, "%s%sContent-Length: %d\r\n\r\n", http200ok,BdxGetHttpDate().c_str(),(int)strOutput.length());
	int iHeadLen = strlen(pszDataBuf);
	
	memcpy(pszDataBuf + iHeadLen, strOutput.c_str(), strOutput.length());
	//printf("Line:%d,AdAdxSendEmpyRespones=%s\n",__LINE__,pszDataBuf);
	LOG(DEBUG,"Thread : %d ,AdAdxSendEmpyRespones=%s\n",m_uiThreadId,pszDataBuf);
	if(!m_pclSock->TcpWrite(pszDataBuf, iHeadLen + strOutput.length())) {
		LOG(ERROR, "[tread: %d]write empty response data error.", m_uiThreadId);
		return LINKERROR;
	}

	return SUCCESS;
}

int CTaskMain::BdxSendRespones(BDXREQUEST_S& stRequestInfo, BDXRESPONSE_S& stAdxRes,std::string errorMsg)
{
	memset(m_pszAdxResponse, 0, _64KBLEN);
	if( stAdxRes.mResValue.empty())
	{		
		std::string strOutput=errorMsg;
	}
	if(m_httpType)
	{
		sprintf((char *)m_pszAdxResponse, "%s%sContent-Length: %d\r\n\r\n", http200ok,BdxGetHttpDate().c_str(),(int)stAdxRes.mResValue.length());
		int iHeadLen = strlen(m_pszAdxResponse);
		memcpy(m_pszAdxResponse + iHeadLen, stAdxRes.mResValue.c_str(),stAdxRes.mResValue.length());
	}
	else
	{
		sprintf((char *)m_pszAdxResponse,"%s",stAdxRes.mResValue.c_str());
	}
	
	int iBodyLength = strlen(m_pszAdxResponse);
	iBodyLength=strlen(m_pszAdxResponse);



	if(!m_pclSock->TcpWrite(m_pszAdxResponse, iBodyLength)) 
	{
		CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stAdxRes.ssUserName].m_ullEmptyResNum++;
		CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stAdxRes.ssUserName].m_ullTotalEmptyResNum++;
		if(stAdxRes.queryType==1)// 1 query user index ,2 query goods 
		{
			m_pDataRedis->UserIncr(stAdxRes.ssUserCountKeyRes);

		}
		LOG(ERROR, "[thread: %d]write  response error.", m_uiThreadId);
		return LINKERROR;
	}

	//CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stAdxRes.ssUserName].m_ullResNum++;
	//CUserQueryWorkThreads::m_vecReport[m_uiThreadId].m_strUserInfo[stAdxRes.ssUserName].m_ullTotalResNum++;
	
	if(stAdxRes.queryType==1)// 1 query user index ,2 query goods 
	{
		m_pDataRedis->UserIncr(stAdxRes.ssUserCountKeyRes);

	}
	
	LOG(DEBUG, "[thread: %d]write response iBodyLength=%d.",m_uiThreadId,iBodyLength);
	
    return SUCCESS;
}

std::string CTaskMain::BdxTaskMainGetTime(const time_t ttime)
{

	time_t tmpTime;
	if(ttime == 0)
		tmpTime = time(0);
	else
		tmpTime = ttime;
	struct tm* timeinfo = localtime(&tmpTime);
	char dt[20];
	memset(dt, 0, 20);
	sprintf(dt, "%4d%02d%02d%02d", timeinfo->tm_year + 1900,timeinfo->tm_mon+1,timeinfo->tm_mday,timeinfo->tm_hour);
	//sprintf(dt, "%4d%02d%02d%02d%02d%02d", timeinfo->tm_year + 1900, timeinfo->tm_mon+1,timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);
	//return (timeinfo->tm_year + 1900) * 10000 + (timeinfo->tm_mon + 1) * 100 + timeinfo->tm_mday;
	return std::string(dt);
}

std::string CTaskMain::BdxTaskMainGetMinute(const time_t ttime)
{

	time_t tmpTime;
	if(ttime == 0)
		tmpTime = time(0);
	else
		tmpTime = ttime;
	struct tm* timeinfo = localtime(&tmpTime);
	char dt[20];
	memset(dt, 0, 20);
	sprintf(dt, "%4d%02d%02d%02d%02d", timeinfo->tm_year + 1900,timeinfo->tm_mon+1,timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min);
	//sprintf(dt, "%4d%02d%02d%02d%02d%02d", timeinfo->tm_year + 1900, timeinfo->tm_mon+1,timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);
	//return (timeinfo->tm_year + 1900) * 10000 + (timeinfo->tm_mon + 1) * 100 + timeinfo->tm_mday;
	return std::string(dt);
}

std::string CTaskMain::BdxTaskMainGetFullTime(const time_t ttime)
{

	time_t tmpTime;
	if(ttime == 0)
		tmpTime = time(0);
	else
		tmpTime = ttime;
	struct tm* timeinfo = localtime(&tmpTime);
	char dt[20];
	memset(dt, 0, 20);
	sprintf(dt, "%4d%02d%02d%02d%02d%02d", timeinfo->tm_year + 1900,timeinfo->tm_mon+1,timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);
	//sprintf(dt, "%4d%02d%02d%02d%02d%02d", timeinfo->tm_year + 1900, timeinfo->tm_mon+1,timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);
	//return (timeinfo->tm_year + 1900) * 10000 + (timeinfo->tm_mon + 1) * 100 + timeinfo->tm_mday;
	return std::string(dt);
}
std::string CTaskMain::BdxTaskMainGetUCTime(const time_t ttime)
{

	time_t tmpTime;
	if(ttime == 0)
	{
		tmpTime = time(0);
	}
	else
	{
		tmpTime = ttime;
	}
	tmpTime -= 8*3600;
	struct tm* timeinfo = localtime(&tmpTime);
	char dt[20];
	memset(dt, 0, 20);

	sprintf(dt, "%4d-%02d-%02dT%02d:%02d:%02dZ", timeinfo->tm_year + 1900,timeinfo->tm_mon+1,timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);
	//sprintf(dt, "%4d%02d%02d%02d%02d%02d", timeinfo->tm_year + 1900, timeinfo->tm_mon+1,timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);
	//return (timeinfo->tm_year + 1900) * 10000 + (timeinfo->tm_mon + 1) * 100 + timeinfo->tm_mday;
	return std::string(dt);
}

std::string CTaskMain::BdxTaskMainGetDate(const time_t ttime)
{

	time_t tmpTime;
	if(ttime == 0)
		tmpTime = time(0);
	else
		tmpTime = ttime;
	struct tm* timeinfo = localtime(&tmpTime);
	char dt[20];
	memset(dt, 0, 20);
	sprintf(dt, "%4d%02d%02d", timeinfo->tm_year + 1900, timeinfo->tm_mon+1,timeinfo->tm_mday);
	//return (timeinfo->tm_year + 1900) * 10000 + (timeinfo->tm_mon + 1) * 100 + timeinfo->tm_mday;
	return std::string(dt);
}

std::string CTaskMain::BdxTaskMainGetLastTwoMonth(const time_t ttime)
{

	time_t tmpTime;
	if(ttime == 0)
		tmpTime = time(0);
	else
		tmpTime = ttime;
	tmpTime -= 86400*61;
	struct tm* timeinfo = localtime(&tmpTime);
	char dt[20];
	memset(dt, 0, 20);
	sprintf(dt, "%4d%02d", timeinfo->tm_year + 1900, timeinfo->tm_mon+1);
	//return (timeinfo->tm_year + 1900) * 10000 + (timeinfo->tm_mon + 1) * 100 + timeinfo->tm_mday;
	return std::string(dt);
}

std::string CTaskMain::BdxGenNonce(int length) 
{
        char CHAR_ARRAY[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b','c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x','y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H','I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T','U', 'V', 'W', 'X', 'Y', 'Z'};
        srand((int)time(0));
         
        std::string strBuffer ;
        //int nextPos = strlen(CHAR_ARRAY);
        int nextPos = sizeof(CHAR_ARRAY);
        //printf("nextPos=%d\n",nextPos);
        int tmp = 0;
        for (int i = 0; i < length; ++i) 
        { 
            tmp = rand()%nextPos;
            
            strBuffer.append(std::string(1,CHAR_ARRAY[tmp]));
        }
        return strBuffer;
}

std::string CTaskMain::BdxGetDatafromDataHub(std::string AuthUser,std::string AuthToken,std::string repo,std::string item,std::string subid,long used,int type)
{
	//type 1 verifytoken 2 get token 3 get order 4 update order
	char m_httpReqVerifyToken[_8KBLEN];
	char sslReadBuffer[_8KBLEN];
	char tempBuffer[PACKET];
	std::string strReadBuffer;
	//#define __TEST__
	#ifdef __TEST__
	std::string datahubIP = "10.1.235.98";
	std::string datahubHost = "10.1.235.98";
	#else
	std::string datahubIP = "54.223.214.188";
	std::string datahubHost = "hub.dataos.io";
	#endif
	uint16_t 	datahubPort = 443;
	CTcpSocket* sslLocalSocket; 	
	string strType;
	sslLocalSocket=new CTcpSocket(datahubPort,datahubIP);
	memset(m_httpReqVerifyToken,0,sizeof(m_httpReqVerifyToken));
	if( type == 1 )
	{
		strType ="verify user token";
		sprintf(m_httpReqVerifyToken,"GET /api/valid HTTP/1.1\r\nHost: %s\r\nAuthorization:Token %s\r\nAuthuser: %s\r\n\r\n",datahubHost.c_str(),AuthToken.c_str(),AuthUser.c_str());
		printf("Line:%d,BdxVerifyDataHubToken\n",__LINE__);
		printf("Line:%d,m_httpReqVerifyToken=%s\n",__LINE__,m_httpReqVerifyToken);
	}
	if( type == 2 )
	{
		strType ="get gateway token";
		#ifdef __TEST__
		sprintf(m_httpReqVerifyToken,"GET /api/ HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic Y2hlbnlnQGFzaWFpbmZvLmNvbToxYmJkODg2NDYwODI3MDE1ZTVkNjA1ZWQ0NDI1MjI1MQ==\r\n\r\n",datahubIP.c_str());
		#else
		sprintf(m_httpReqVerifyToken,"GET /api/ HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic YWRtaW5fY2hlbnlnQGFzaWFpbmZvLmNvbTo4ZGRjZmYzYTgwZjQxODljYTFjOWQ0ZDkwMmMzYzkwOQ==\r\n\r\n",datahubIP.c_str());
		#endif


	}
	if( type == 3 )
	{
		strType ="get gateway token";
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
int CTaskMain::BdxVerifyDataHubToken(std::string AuthUser,std::string AuthToken) 
{
		int verifyOK = 0;
		std::string retDataHub;

		retDataHub = BdxGetDatafromDataHub(AuthUser,AuthToken,"","","",0,1);

		printf("Line:%d,BdxVerifyDataHubToken retDataHub=%s\n",__LINE__,retDataHub.c_str());
		if(retDataHub.find("\"msg\": \"OK\"")!=-1)
		{
			verifyOK = 1;
		}
		return verifyOK;      
}

std::string CTaskMain::BdxApiGateWayGetDataHubToken(std::string AuthUser,std::string PassWord) 
{
		std::string retDataHub;
		retDataHub = BdxGetDatafromDataHub(AuthUser,PassWord,"","","",0,2);
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

std::vector<DATAHUB_ORDER_INFO_S> CTaskMain::BdxApiGetUserOrder(std::string repo,std::string item,std::string user,std::string apitoken) 
{
		std::string retDataHub;
		std::vector<DATAHUB_ORDER_INFO_S> vecDataHubOrder;
		DATAHUB_ORDER_INFO_S dataHubInfo;
		//Json::Reader *jReader = new Json::Reader(Json::Features::strictMode()); // turn on strict verify mode
		Json::Reader *jReader = new Json::Reader();
		Json::Value jValue,jValue2,jRoot,jResult,jTemp;
		Json::FastWriter jFastWriter;
		int lenStrTemp;
		int jsonFormatValid = 0;
		char tempSubid[50];

		retDataHub = BdxGetDatafromDataHub(user,apitoken,repo,item,"",0,3);
		if(retDataHub.find("\"msg\":\"OK\"")!=-1)
		{
			//retDataHub = retDataHub.substr(retDataHub.find("token")+ 9 ,32);
			if(jReader->parse(retDataHub,jValue))
			{ 
				if(jReader->parse(jValue["data"].toStyledString(), jValue))
				{
					if(jReader->parse(jValue["results"].toStyledString(), jValue))
					{						
							for(unsigned int i=0;i<jValue.size();i++)
							{
								//printf("Line:%d,i=%d,jValue[i][\"phase\"]=%s\n",__LINE__,i,jValue[i]["phase"].toStyledString().c_str());
								
								if(jValue[i]["phase"].toStyledString()=="1\n")
								{

									memset(tempSubid,0,50);
									sprintf(tempSubid,"%ld",atol(jValue[i]["subscriptionid"].toStyledString().c_str()));
									//dataHubInfo.m_subscriptionID= jValue[i]["subscriptionid"].toStyledString();
									dataHubInfo.m_subscriptionID = std::string(tempSubid);
					
									if(jReader->parse(jValue[i]["plan"].toStyledString(), jValue2))
									{
										jsonFormatValid = 1;
										memset(tempSubid,0,50);
										sprintf(tempSubid,"%ld",atol(jValue2["units"].toStyledString().c_str()));
										dataHubInfo.m_units= std::string(tempSubid);

										memset(tempSubid,0,50);
										sprintf(tempSubid,"%ld",atol(jValue2["expire"].toStyledString().c_str()));
										dataHubInfo.m_expireTime= std::string(tempSubid);
										
										printf("Line:%d,dataHubInfo.m_units=%s",__LINE__,dataHubInfo.m_units.c_str());
										printf("Line:%d,dataHubInfo.m_expireTime=%s",__LINE__,dataHubInfo.m_expireTime.c_str());
										printf("Line:%d,dataHubInfo.m_subscriptionID=%s\n",__LINE__,dataHubInfo.m_subscriptionID.c_str());

										vecDataHubOrder.push_back(dataHubInfo);

									}
								}
							}
						
					}
				 }
			}
			if( !jsonFormatValid )
			{
				retDataHub = "";
			}			
		  //retDataHub = retDataHub;
		}

		delete jReader; 
		return vecDataHubOrder;   
}

bool CTaskMain::BdxApiSetUserOrderStatus(std::string user,std::string subid,std::string repo,std::string item,std::string token) 
{
		std::string retDataHub;
		bool status = false;
		retDataHub = BdxGetDatafromDataHub(user,token,repo,item,subid,0,4);
		if(retDataHub.find("\"msg\":\"OK\"")!=-1)
		{
			status = true;
		}
		return status;   
}
std::string CTaskMain::BdxApiUpdateUserOrder(std::string user,std::string subid,std::string repo,std::string item,std::string token,long used) 
{
		std::string retDataHub;
		retDataHub = BdxGetDatafromDataHub(user,token,repo,item,subid,used,5);
		printf("Line:%d,BdxApiUpdateUserOrder retDataHub=%s",__LINE__,retDataHub.c_str());
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

std::string CTaskMain::GenPasswordDigest(std::string utcTime, std::string nonce, std::string appSecret)
{
		std::string strDigest;

		std::string strValue = nonce + utcTime + appSecret;

        unsigned char *dmg = mdSHA1.SHA1_Encode(strValue.c_str());
        const  char *pchTemp = (const  char *)(char*)dmg;
        //std::string strDmg = base64_encode((const unsigned char*)pchTemp,strlen(pchTemp));
        std::string strDmg = base64_encode((const unsigned char*)pchTemp,SHA_DIGEST_LENGTH);
		//std::string strDmg = base64_encode(reinterpret_cast<const char *>(static_cast<void*>(dmg)),strlen(dmg));
        return strDmg;
}

string   CTaskMain::BdxTaskMainReplace_All(string    str,   string   old_value,   string   new_value)   
{   
    while(true)   {   
        string::size_type   pos(0);   
        if(   (pos=str.find(old_value))!=string::npos   )   
            	str.replace(pos,old_value.length(),new_value);   
        else   break;   
    }   
    return   str;   
}   

std::string CTaskMain::BdxGetParamSign(const std::string& strParam, const std::string& strSign)
{
	char pszMd5Hex[33];
	std::string strParamKey = strParam + strSign;
	printf("Line:%d,strParamKey=%s\n",__LINE__,strParamKey.c_str());

    //ËÆ°ÁÆóÂèÇÊï∞‰∏≤ÁöÑ128‰ΩçMD5
    m_clMd5.Md5Init();
    m_clMd5.Md5Update((u_char*)strParamKey.c_str(), strParamKey.length());

    u_char pszParamSign[16];
    m_clMd5.Md5Final(pszParamSign);

    //‰ª•16ËøõÂà∂Êï∞Ë°®Á§∫
    for (unsigned char i = 0; i < sizeof(pszParamSign); i++) {
    	sprintf(&pszMd5Hex[i * 2], "%c", to_hex(pszParamSign[i] >> 4));
    	sprintf(&pszMd5Hex[i * 2 + 1], "%c", to_hex((pszParamSign[i] << 4) >> 4));
    }
    pszMd5Hex[32] = '\0';
    return std::string(pszMd5Hex);
}
