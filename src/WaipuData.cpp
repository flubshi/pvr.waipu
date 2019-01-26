/*
 *      Copyright (C) 2019 flubshi
 *      https://github.com/flubshi
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/copyleft/gpl.html
 *
 */

#include "WaipuData.h"
#include "p8-platform/util/StringUtils.h"
#include "Utils.h"
#include "Base64.h"
#include "rapidjson/document.h"
#include <ctime>

using namespace std;
using namespace ADDON;
using namespace rapidjson;


// BEGIN CURL helpers from zattoo addon:
string WaipuData::HttpGet(const string& url)
{
  return HttpRequest("GET", url, "");
}

string WaipuData::HttpDelete(const string& url, const string& postData)
{
  return HttpRequest("DELETE", url, postData);
}

string WaipuData::HttpPost(const string& url, const string& postData)
{
  return HttpRequest("POST", url, postData);
}

string WaipuData::HttpRequest(const string& action, const string& url, const string& postData)
{
  Curl curl;
  int statusCode;

  curl.AddHeader("User-Agent","waipu-2.29.2-c0f220b-9446 (Android 8.1.0)");
  curl.AddHeader("Authorization","Bearer "+m_apiToken.accessToken);

  if (action == "DELETE"){
	  curl.AddHeader("Content-Type","application/vnd.waipu.pvr-recording-ids-v2+json");
  }

  string content = HttpRequestToCurl(curl, action, url, postData, statusCode);

  return content;
}

string WaipuData::HttpRequestToCurl(Curl &curl, const string& action, const string& url,
                                  const string& postData, int &statusCode)
{
  XBMC->Log(LOG_DEBUG, "Http-Request: %s %s.", action.c_str(), url.c_str());
  string content;
  if (action == "POST")
  {
    content = curl.Post(url, postData, statusCode);
  }
  else if (action == "DELETE")
  {
    content = curl.Delete(url, postData, statusCode);
  }
  else
  {
    content = curl.Get(url, statusCode);
  }
  return content;

}
// END CURL helpers from zattoo addon

// returns true if m_apiToken contains valid session
bool WaipuData::ApiLogin()
{
  XBMC->Log(LOG_DEBUG, "[login check] start...");

  time_t currTime;
  time(&currTime);
  XBMC->Log(LOG_DEBUG, "[token] current time %i", currTime);
  XBMC->Log(LOG_DEBUG, "[token] expire  time %i", m_apiToken.expires);
  if(!m_apiToken.accessToken.empty() && (m_apiToken.expires - 10 * 60 ) > currTime)
  {
    // API token exists and is valid, more than x in future
    XBMC->Log(LOG_DEBUG, "[login check] old token still valid");
    return true;
  }
  
  string jsonString;
  if(m_apiToken.expires < currTime && false){
    // refresh API token
    XBMC->Log(LOG_DEBUG, "[login check] refresh API token");
    // NOT IMPLEMENTED YET
  }else{
    // get API by login user/pw
    XBMC->Log(LOG_DEBUG, "[login check] get API by login user/pw");

    ostringstream dataStream;
    // {'username': username, 'password': password, 'grant_type': 'password'}
    dataStream << "username=" << Utils::UrlEncode(username) << "&password=" << Utils::UrlEncode(password) << "&grant_type=password";
    XBMC->Log(LOG_DEBUG, "[login check] Login-Request: %s;", dataStream.str().c_str());

    // curl request
    Curl curl;
    int statusCode;
    curl.AddHeader("User-Agent","waipu-2.29.2-c0f220b-9446 (Android 8.1.0)");
    curl.AddHeader("Authorization","Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
    curl.AddHeader("Content-Type","application/x-www-form-urlencoded");
    jsonString = HttpRequestToCurl(curl, "POST", "https://auth.waipu.tv/oauth/token", dataStream.str(), statusCode);

    XBMC->Log(LOG_DEBUG, "[login check] Login-response: %s;", jsonString.c_str());
  }

  if(!jsonString.empty()){
    Document doc;
    doc.Parse(jsonString.c_str());
    
    m_apiToken.accessToken = doc["access_token"].GetString();
    XBMC->Log(LOG_DEBUG, "[login check] accessToken: %s;", m_apiToken.accessToken.c_str());
    m_apiToken.refreshToken = doc["refresh_token"].GetString();
    XBMC->Log(LOG_DEBUG, "[login check] refreshToken: %s;", m_apiToken.refreshToken.c_str());
    m_apiToken.expires = currTime + doc["expires_in"].GetUint64();
    XBMC->Log(LOG_DEBUG, "[login check] expires: %i;", m_apiToken.expires);
    // convert access token to license
    // userHandle is part of jwt token
    std::vector<std::string> jwt_arr = Utils::SplitString(m_apiToken.accessToken,'.',3);
    if(jwt_arr.size() == 3){
    	XBMC->Log(LOG_DEBUG, "[jwt] middle: %s", jwt_arr.at(1).c_str());
    	string jwt_payload = base64_decode(jwt_arr.at(1));
    	XBMC->Log(LOG_DEBUG, "[jwt] payload: %s", jwt_payload.c_str());
        Document jwt_doc;
        jwt_doc.Parse(jwt_payload.c_str());
        string userHandle = jwt_doc["userHandle"].GetString();
        XBMC->Log(LOG_DEBUG, "[jwt] userHandle: %s", userHandle.c_str());
        string license_plain = "{\"merchant\" : \"exaring\", \"sessionId\" : \"default\", \"userId\" : \""+userHandle+"\"}";
        XBMC->Log(LOG_DEBUG, "[jwt] license_plain: %s", license_plain.c_str());
        m_license = base64_encode(license_plain.c_str(),license_plain.length());
        XBMC->Log(LOG_DEBUG, "[jwt] license: %s", m_license.c_str());
    }
    return true;
  }
  // no valid session
  return false;
}

WaipuData::WaipuData(const string& user, const string& pass)
{

  username = user;
  password = pass;
  //XBMC->Log(LOG_DEBUG, "[start] user: %s..", user.c_str());
  //XBMC->Log(LOG_DEBUG, "[start] pass %s..", pass.c_str());

  LoadChannelData();
}

WaipuData::~WaipuData(void)
{
  m_channels.clear();
}

bool WaipuData::LoadChannelData(void)
{

  if(!ApiLogin()){
    // no valid accessToken
    XBMC->Log(LOG_DEBUG, "[load data] ERROR - Login invalid");
    XBMC->QueueNotification(QUEUE_ERROR, "Invalid login credentials?");
    return false;
  }

  XBMC->Log(LOG_DEBUG, "[load data] Login valid -> GET CHANNELS");

  string jsonChannels = HttpGet("https://epg.waipu.tv/api/channels");
  if(jsonChannels.size() == 0){
	  XBMC->Log(LOG_ERROR, "[channels] ERROR - empty response");
	  return PVR_ERROR_SERVER_ERROR;
  }
  jsonChannels = "{\"result\": "+jsonChannels+"}";
  XBMC->Log(LOG_DEBUG, "[channels] length: %i;",jsonChannels.length());
  XBMC->Log(LOG_DEBUG, "[channels] %s;",jsonChannels.c_str());
  XBMC->Log(LOG_DEBUG, "[channels] %s;",jsonChannels.substr(jsonChannels.size() - 40).c_str());

  // parse channels
  XBMC->Log(LOG_DEBUG, "[channels] parse channels");
  Document channelsDoc;
  channelsDoc.Parse(jsonChannels.c_str());
  XBMC->Log(LOG_DEBUG, "[channels] iterate channels");

  const Value& channelArray = channelsDoc["result"];
  XBMC->Log(LOG_DEBUG, "[channels] size: %i;",channelArray.Size());

  for (SizeType i = 0; i < channelArray.Size(); i++) {
    WaipuChannel channel;
    channel.iUniqueId = i;//our id
    XBMC->Log(LOG_DEBUG, "[channel] id: %i;",channel.iUniqueId);
    
    string waipuid = channelArray[i]["id"].GetString();
    channel.waipuID = waipuid; // waipu[id]
    XBMC->Log(LOG_DEBUG, "[channel] waipuid: %s;",channel.waipuID.c_str());

    int orderindex = channelArray[i]["orderIndex"].GetUint();
    channel.iChannelNumber = orderindex; //waipu[orderIndex]
    XBMC->Log(LOG_DEBUG, "[channel] channelnr: %i;",channel.iChannelNumber);

    string displayName = channelArray[i]["displayName"].GetString();
    channel.strChannelName = displayName; //waipu[displayName]
    XBMC->Log(LOG_DEBUG, "[channel] name: %s;",channel.strChannelName.c_str());

    //iterate links
    const Value& linksArray = channelArray[i]["links"];
    string icon = "";
    string icon_sd = "";
    string icon_hd = "";
    for (SizeType j = 0; j < linksArray.Size(); j++) {
      string rel = linksArray[j]["rel"].GetString();
      string href = linksArray[j]["href"].GetString();
      if(rel == "icon"){
    	 icon = href;
    	 continue;
      }else if(rel == "iconsd"){
    	  icon_sd = href;
    	  continue;
      }else if(rel == "iconhd"){
    	  icon_hd = href;
      	  continue;
      }else if(rel == "livePlayout"){
        channel.strStreamURL = href; // waipu[links][rel=livePlayout]
        continue;
      }
      if(icon_sd.size() > 0){
    	  channel.strIconPath =  icon_sd + "?width=300&height=300" ;
      }else if(icon_hd.size() > 0){
    	  channel.strIconPath =  icon_hd + "?width=300&height=300" ;
      }else if(icon.size() > 0){
    	  channel.strIconPath =  icon + "?width=300&height=300" ;
      }
      XBMC->Log(LOG_DEBUG, "[channel] link: %s -> %s;",rel.c_str(),href.c_str());
    }
    m_channels.push_back(channel);
  }

  /* load EPG entries */


  return true;
}

int WaipuData::GetChannelsAmount(void)
{
  return m_channels.size();
}

PVR_ERROR WaipuData::GetChannels(ADDON_HANDLE handle, bool bRadio)
{
	if (!ApiLogin()){
		return PVR_ERROR_SERVER_ERROR;
	}
	for (const auto& channel : m_channels) {
		if (!bRadio) {
			PVR_CHANNEL xbmcChannel;
			memset(&xbmcChannel, 0, sizeof(PVR_CHANNEL));

			xbmcChannel.iUniqueId = channel.iUniqueId;
			xbmcChannel.bIsRadio = false;
			xbmcChannel.iChannelNumber = channel.iChannelNumber;
			strncpy(xbmcChannel.strChannelName, channel.strChannelName.c_str(),
					sizeof(xbmcChannel.strChannelName) - 1);
			strncpy(xbmcChannel.strIconPath, channel.strIconPath.c_str(),
					sizeof(xbmcChannel.strIconPath) - 1);
			xbmcChannel.bIsHidden = false;

			PVR->TransferChannelEntry(handle, &xbmcChannel);
		}
	}
	return PVR_ERROR_NO_ERROR;
}

string WaipuData::GetChannelStreamUrl(int uniqueId)
{

  for (const auto& thisChannel : m_channels)
  {
    if (thisChannel.iUniqueId == (int) uniqueId)
    {
      XBMC->Log(LOG_DEBUG, "Get live url for channel %s", thisChannel.strChannelName.c_str());

      if(!ApiLogin()){
        // invalid
        XBMC->Log(LOG_DEBUG, "No stream login");
        return "";
      }
      string playoutURL = thisChannel.strStreamURL;
      XBMC->Log(LOG_DEBUG, "URL source: %s", playoutURL.c_str());

      string jsonStreams = HttpGet(playoutURL.c_str());
      XBMC->Log(LOG_DEBUG, "Stream result: %s", jsonStreams.c_str()); 

      Document streamsDoc;
      XBMC->Log(LOG_DEBUG, "Stream result: %s", jsonStreams.c_str()); 
      streamsDoc.Parse(jsonStreams.c_str());

      const Value& streamsArray = streamsDoc["streams"];
      for (SizeType i = 0; i < streamsArray.Size(); i++) {        
        string protocol = streamsArray[i]["protocol"].GetString();
        XBMC->Log(LOG_DEBUG, "[stream] protocol: %s;",protocol.c_str());
        if(protocol == "mpeg-dash"){
          const Value& linksArray = streamsArray[i]["links"];
          for (SizeType j = 0; j < linksArray.Size(); j++) {  
            string href = linksArray[j]["href"].GetString();
            XBMC->Log(LOG_DEBUG, "[stream] href: %s;",href.c_str());
            if(!href.empty()){
              return href;
            }
          }
        }
      }
    }
  }
  return "";
}

int WaipuData::GetChannelGroupsAmount(void)
{
  return -1;
}

PVR_ERROR WaipuData::GetChannelGroups(ADDON_HANDLE handle, bool bRadio)
{
  return PVR_ERROR_NOT_IMPLEMENTED;
}

PVR_ERROR WaipuData::GetChannelGroupMembers(ADDON_HANDLE handle, const PVR_CHANNEL_GROUP &group)
{
  return PVR_ERROR_NOT_IMPLEMENTED;
}

PVR_ERROR WaipuData::GetEPGForChannel(ADDON_HANDLE handle, const PVR_CHANNEL &channel, time_t iStart, time_t iEnd)
{
  if (!ApiLogin()){
	return PVR_ERROR_SERVER_ERROR;
  }
  for (unsigned int iChannelPtr = 0; iChannelPtr < m_channels.size(); iChannelPtr++)
  {
    WaipuChannel &myChannel = m_channels.at(iChannelPtr);
    if (myChannel.iUniqueId != (int) channel.iUniqueId)
      continue;

    char startTime[100];
    std::tm * pstm = std::localtime(&iStart);
	//2019-01-20T23:59:59
    std::strftime(startTime, 32, "%Y-%m-%dT%H:%M:%S", pstm);

    char endTime[100];
    std::tm * petm = std::localtime(&iEnd);
	//2019-01-20T23:59:59
    std::strftime(endTime, 32, "%Y-%m-%dT%H:%M:%S", petm);

    string jsonEpg = HttpGet("https://epg.waipu.tv/api/channels/"+myChannel.waipuID+"/programs?startTime="+string(startTime)+"&stopTime="+string(endTime));
    XBMC->Log(LOG_DEBUG, "[epg-all] %s",jsonEpg.c_str());
    if(jsonEpg.size() == 0){
    	XBMC->Log(LOG_ERROR, "[epg] empty server response");
    	return PVR_ERROR_SERVER_ERROR;
    }
    jsonEpg = "{\"result\": "+jsonEpg+"}";

    Document epgDoc;
    epgDoc.Parse(jsonEpg.c_str());
    XBMC->Log(LOG_DEBUG, "[epg] iterate entries");

    const Value& epgArray = epgDoc["result"];
    XBMC->Log(LOG_DEBUG, "[epg] size: %i;",epgArray.Size());

    for (SizeType i = 0; i < epgArray.Size(); i++) {
    	//epgArray[i]["id"].GetString();

    	XBMC->Log(LOG_DEBUG, "[epg] get entry: %i;",i);

        EPG_TAG tag;
        memset(&tag, 0, sizeof(EPG_TAG));

        // generate a unique boadcast id
        string epg_bid = epgArray[i]["id"].GetString();
		WaipuEPGMappingEntry map;
		map.iBroadcastId = i;
		map.iUniqueChannelId = myChannel.iUniqueId;
		map.waipuId =epg_bid;
		m_epgIdMapping.push_back(map);
        tag.iUniqueBroadcastId = map.iBroadcastId;

        // channel ID
        tag.iUniqueChannelId   = myChannel.iUniqueId;

        // set title
        tag.strTitle           = epgArray[i]["title"].GetString();
        XBMC->Log(LOG_DEBUG, "[epg] title: %s;",epgArray[i]["title"].GetString());

        // set startTime -- "2019-01-20T15:40:00+0100"
        string e_startTime = epgArray[i]["startTime"].GetString();
        struct tm stm;
        strptime(e_startTime.c_str(), "%Y-%m-%dT%H:%M:%S%z", &stm);
        time_t start_t = mktime(&stm);  // t is now your desired time_t
        tag.startTime          = start_t;

        // set endTime -- "2019-01-20T15:40:00+0100"
        string e_endTime = epgArray[i]["stopTime"].GetString();
        struct tm etm;
        strptime(e_endTime.c_str(), "%Y-%m-%dT%H:%M:%S%z", &etm);
        time_t end_t = mktime(&etm);  // t is now your desired time_t
        tag.endTime          = end_t;

        //tag.strPlotOutline     = myTag.strPlotOutline.c_str();

        // set description
        if(epgArray[i].HasMember("description") && !epgArray[i]["description"].IsNull()){
        	tag.strPlot            = epgArray[i]["description"].GetString();
        	XBMC->Log(LOG_DEBUG, "[epg] description: %s;",epgArray[i]["description"].GetString());
        }

        //tag.strIconPath        = myTag.strIconPath.c_str();

        tag.iFlags             = EPG_TAG_FLAG_UNDEFINED;

        // iSeriesNumber
        if(epgArray[i].HasMember("season") && !epgArray[i]["season"].IsNull()){
        	tag.iSeriesNumber            = stoi(epgArray[i]["season"].GetString());
        }

        // episodeNumber
        if(epgArray[i].HasMember("episode") && !epgArray[i]["episode"].IsNull()){
        	tag.iEpisodeNumber            = stoi(epgArray[i]["episode"].GetString());
        }

        // episodeName
        if(epgArray[i].HasMember("episodeTitle") && !epgArray[i]["episodeTitle"].IsNull()){
        	tag.strEpisodeName            = epgArray[i]["episodeTitle"].GetString();
        }

        // year
        if(epgArray[i].HasMember("year") && !epgArray[i]["year"].IsNull()){
        	tag.iYear            = stoi(epgArray[i]["year"].GetString());
        }

        PVR->TransferEpgEntry(handle, &tag);
      }
  }
  return PVR_ERROR_NO_ERROR;
}

int WaipuData::GetRecordingsAmount(bool bDeleted)
{
  return -1;
}

PVR_ERROR WaipuData::GetRecordings(ADDON_HANDLE handle, bool bDeleted)
{
	if (!ApiLogin()) {
		return PVR_ERROR_SERVER_ERROR;
	}

    string jsonRecordings = HttpGet("https://recording.waipu.tv/api/recordings");
    XBMC->Log(LOG_DEBUG, "[recordings] %s",jsonRecordings.c_str());

    jsonRecordings = "{\"result\": "+jsonRecordings+"}";

    Document recordingsDoc;
    recordingsDoc.Parse(jsonRecordings.c_str());
    XBMC->Log(LOG_DEBUG, "[recordings] iterate entries");

    const Value& recordingsArray = recordingsDoc["result"];
    XBMC->Log(LOG_DEBUG, "[recordings] size: %i;",recordingsArray.Size());

	for (SizeType i = 0; i < recordingsArray.Size(); i++) {

		XBMC->Log(LOG_DEBUG, "[recording] get entry: %i;", i);

		// skip not FINISHED entries
		string status = recordingsArray[i]["status"].GetString();
		if(status != "FINISHED") continue;

		// new tag
		PVR_RECORDING tag;
		memset(&tag, 0, sizeof(PVR_RECORDING));
		tag.bIsDeleted = false;

		// set recording id
		string rec_id = recordingsArray[i]["id"].GetString();
		strncpy(tag.strRecordingId,rec_id.c_str(),sizeof(tag.strRecordingId)-1);

		const Value& epgData = recordingsArray[i]["epgData"];

		// set recording title
		string rec_title = epgData["title"].GetString();
		strncpy(tag.strTitle,rec_title.c_str(),sizeof(tag.strTitle)-1);

		// set image
		if(epgData.HasMember("previewImages") && epgData["previewImages"].IsArray()){
			string rec_img = epgData["previewImages"][0].GetString();
			rec_img = rec_img + "?width=300&height=200";
			strncpy(tag.strIconPath,rec_img.c_str(),sizeof(tag.strIconPath)-1);
			strncpy(tag.strThumbnailPath,rec_img.c_str(),sizeof(tag.strThumbnailPath)-1);
		}

		// duration
		if(epgData.HasMember("duration") && !epgData["duration"].IsNull()){
			string rec_dur = epgData["duration"].GetString();
			tag.iDuration = stoi(rec_dur) * 60;
		}

        // iSeriesNumber
        if(epgData.HasMember("season") && !epgData["season"].IsNull()){
        	tag.iSeriesNumber            = stoi(epgData["season"].GetString());
        }

        // episodeNumber
        if(epgData.HasMember("episode") && !epgData["episode"].IsNull()){
        	tag.iEpisodeNumber            = stoi(epgData["episode"].GetString());
        }

        // episodeName
        if(epgData.HasMember("episodeTitle") && !epgData["episodeTitle"].IsNull()){
        	string rec_episodename =  epgData["episodeTitle"].GetString();
        	strncpy(tag.strEpisodeName,rec_episodename.c_str(),sizeof(tag.strEpisodeName)-1);
        }

		// year
		if(epgData.HasMember("year") && !epgData["year"].IsNull()){
			string rec_year = epgData["year"].GetString();
			tag.iYear = stoi(rec_year);
		}

		// get recording time
		if (recordingsArray[i].HasMember("startTime") && !recordingsArray[i]["startTime"].IsNull()) {
			// set startTime -- "2019-01-20T15:40:00+0100"
			string e_startTime = recordingsArray[i]["startTime"].GetString();
			struct tm stm;
			strptime(e_startTime.c_str(), "%Y-%m-%dT%H:%M:%S%z", &stm);
			time_t rec_t = mktime(&stm);  // t is now your desired time_t
			tag.recordingTime = rec_t;
		}

		// get plot
		if (epgData.HasMember("description") && !epgData["description"].IsNull()) {
			string rec_plot = epgData["description"].GetString();
			strncpy(tag.strPlot,rec_plot.c_str(),sizeof(tag.strPlot)-1);
		}

		PVR->TransferRecordingEntry(handle, &tag);
	}
	return PVR_ERROR_NO_ERROR;
}

std::string WaipuData::GetRecordingURL(const PVR_RECORDING &recording)
{
	ApiLogin();

	string recording_id = recording.strRecordingId;
	XBMC->Log(LOG_DEBUG, "play recording -> %s", recording_id.c_str());

	string rec_resp = HttpGet("https://recording.waipu.tv/api/recordings/" + recording_id);
	XBMC->Log(LOG_DEBUG, "recording resp -> %s", rec_resp.c_str());

	Document recordingDoc;
	recordingDoc.Parse(rec_resp.c_str());
	XBMC->Log(LOG_DEBUG, "[recording] streams");
	// check if streams there
	if(!recordingDoc.HasMember("streamingDetails") || !recordingDoc["streamingDetails"].HasMember("streams")){
		return "";
	}

	const Value& streamsArray = recordingDoc["streamingDetails"]["streams"];
	XBMC->Log(LOG_DEBUG, "[recordings] size: %i;", streamsArray.Size());

	for (SizeType i = 0; i < streamsArray.Size(); i++) {
		XBMC->Log(LOG_DEBUG, "[stream] get entry: %i;", i);
		string protocol = streamsArray[i]["protocol"].GetString();
		XBMC->Log(LOG_DEBUG, "[stream] protocol: %s;", protocol);
		if(protocol == "MPEG_DASH"){
			string href = streamsArray[i]["href"].GetString();
			XBMC->Log(LOG_DEBUG, "[stream] selected href: %s;", href);
			return href;
		}
	}
	return "";
}

PVR_ERROR WaipuData::DeleteRecording(const PVR_RECORDING &recording){

	if(recording.strRecordingId && ApiLogin()){
		string recording_id = recording.strRecordingId;
		string request_data = "{\"ids\":[\""+recording_id+"\"]}";
		XBMC->Log(LOG_DEBUG, "[delete recording] req: %s;", request_data.c_str());
		//string deleted = HttpDelete("https://recording.waipu.tv/api/recordings",request_data);
		string deleted = HttpDelete("https://recording.waipu.tv/api/recordings",request_data);
		XBMC->Log(LOG_DEBUG, "[delete recording] response: %s;", deleted.c_str());
		return PVR_ERROR_NO_ERROR;
	}
	return PVR_ERROR_FAILED;
}

int WaipuData::GetTimersAmount(void)
{
  return -1;
}

PVR_ERROR WaipuData::GetTimers(ADDON_HANDLE handle)
{
  return PVR_ERROR_NOT_IMPLEMENTED;
}

std::string WaipuData::GetLicense(void){
	// ensure that userHandle is valid
	ApiLogin();
	return m_license;
}
