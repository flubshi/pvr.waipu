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

#include "Base64.h"
#include "Utils.h"
#include "p8-platform/util/StringUtils.h"
#include "rapidjson/document.h"

#include <algorithm>
#include <ctime>
#include <regex>

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

  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  curl.AddHeader("Authorization", "Bearer " + m_apiToken.accessToken);

  if (action == "DELETE")
  {
    curl.AddHeader("Content-Type", "application/vnd.waipu.pvr-recording-ids-v2+json");
  }
  else
  {
    curl.AddHeader("Content-Type", "application/vnd.waipu.start-recording-v2+json");
  }

  string content = HttpRequestToCurl(curl, action, url, postData, statusCode);

  return content;
}

string WaipuData::HttpRequestToCurl(
    Curl& curl, const string& action, const string& url, const string& postData, int& statusCode)
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

WAIPU_LOGIN_STATUS WaipuData::GetLoginStatus()
{
  return m_login_status;
}

// returns true if m_apiToken contains valid session
bool WaipuData::ApiLogin()
{
  if(m_login_failed_counter > 3){
      // more than 3 consecutive failed login attempts
      // block login attempt
      m_login_status = WAIPU_LOGIN_STATUS_INVALID_CREDENTIALS;
      return false;
  }

  bool login_result;
  if (provider == WAIPU_PROVIDER_WAIPU)
  {
    return WaipuLogin();
    login_result = WaipuLogin();
  }
  else
  {
    return O2Login();
    login_result = O2Login();
  }
  if(login_result){
      // login okay, reset counter
      m_login_failed_counter = 0;
  }else{
      // login failed, increase counter
      m_login_failed_counter = m_login_failed_counter + 1;
  }

  return login_result;
}

bool WaipuData::ParseAccessToken(void)
{
  std::vector<std::string> jwt_arr = Utils::SplitString(m_apiToken.accessToken, '.', 3);
  if (jwt_arr.size() == 3)
  {
    XBMC->Log(LOG_DEBUG, "[jwt] middle: %s", jwt_arr.at(1).c_str());
    string jwt_payload = base64_decode(jwt_arr.at(1));
    XBMC->Log(LOG_DEBUG, "[jwt] payload: %s", jwt_payload.c_str());

    Document jwt_doc;
    jwt_doc.Parse(jwt_payload.c_str());

    if (jwt_doc.HasParseError())
    {
      m_login_status = WAIPU_LOGIN_STATUS_UNKNOWN;
      XBMC->Log(LOG_ERROR, "[jwt_doc] ERROR: error while parsing json");
      return false;
    }

    string userHandle = jwt_doc["userHandle"].GetString();
    XBMC->Log(LOG_DEBUG, "[jwt] userHandle: %s", userHandle.c_str());
    // generate the license
    string license_plain = "{\"merchant\" : \"exaring\", \"sessionId\" : \"default\", "
                           "\"userId\" : \"" +
                           userHandle + "\"}";
    XBMC->Log(LOG_DEBUG, "[jwt] license_plain: %s", license_plain.c_str());
    m_license = base64_encode(license_plain.c_str(), license_plain.length());
    XBMC->Log(LOG_DEBUG, "[jwt] license: %s", m_license.c_str());
    // get user channels
    m_user_channels.clear();
    for (const auto& user_channel : jwt_doc["userAssets"]["channels"]["SD"].GetArray())
    {
      string user_channel_s = user_channel.GetString();
      XBMC->Log(LOG_DEBUG, "[jwt] SD channel: %s", user_channel_s.c_str());
      m_user_channels.push_back(user_channel_s);
    }
    for (const auto& user_channel : jwt_doc["userAssets"]["channels"]["HD"].GetArray())
    {
      string user_channel_s = user_channel.GetString();
      m_user_channels.push_back(user_channel_s);
      XBMC->Log(LOG_DEBUG, "[jwt] HD channel: %s", user_channel_s.c_str());
    }
  }
  m_login_status = WAIPU_LOGIN_STATUS_OK;
  return true;
}


bool WaipuData::WaipuLogin()
{
  XBMC->Log(LOG_DEBUG, "[login check] WAIPU.TV LOGIN...");

  time_t currTime;
  time(&currTime);
  XBMC->Log(LOG_DEBUG, "[token] current time %i", currTime);
  XBMC->Log(LOG_DEBUG, "[token] expire  time %i", m_apiToken.expires);
  if (!m_apiToken.accessToken.empty() && (m_apiToken.expires - 20 * 60) > currTime)
  {
    // API token exists and is valid, more than x in future
    XBMC->Log(LOG_DEBUG, "[login check] old token still valid");
    return true;
  }

  ostringstream dataStream;
  if (!m_apiToken.refreshToken.empty())
  {
    // Since the refresh token is valid for a long time, we do not check expiration for now
    // refresh API token
    dataStream << "refresh_token=" << Utils::UrlEncode(m_apiToken.refreshToken)
               << "&grant_type=refresh_token";
    XBMC->Log(LOG_DEBUG, "[login check] Login-Request (refresh): %s;", dataStream.str().c_str());
  }
  else
  {
    // get API by login user/pw
    dataStream << "username=" << Utils::UrlEncode(username)
               << "&password=" << Utils::UrlEncode(password) << "&grant_type=password";
    XBMC->Log(LOG_DEBUG, "[login check] Login-Request (user/pw): %s;", dataStream.str().c_str());
  }
  string jsonString;
  // curl request
  Curl curl;
  int statusCode = 0;
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  curl.AddHeader("Authorization", "Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
  curl.AddHeader("Content-Type", "application/x-www-form-urlencoded");
  jsonString = HttpRequestToCurl(curl, "POST", "https://auth.waipu.tv/oauth/token",
                                 dataStream.str(), statusCode);

  XBMC->Log(LOG_DEBUG, "[login check] Login-response: (HTTP %i) %s;", statusCode,
            jsonString.c_str());

  if (jsonString.length() == 0 && statusCode == -1)
  {
    // no network connection?
    m_login_status = WAIPU_LOGIN_STATUS_NO_NETWORK;
    XBMC->Log(LOG_ERROR, "[Login] no network connection");
    return false;
  }
  else if (statusCode == 401)
  {
    // invalid credentials
    m_login_status = WAIPU_LOGIN_STATUS_INVALID_CREDENTIALS;
    return false;
  }

  if (!jsonString.empty())
  {
    Document doc;
    doc.Parse(jsonString.c_str());
    if (doc.GetParseError())
    {
      XBMC->Log(LOG_ERROR, "[Login] ERROR: error while parsing json");
      m_login_status = WAIPU_LOGIN_STATUS_UNKNOWN;
      return false;
    }

    if (doc.HasMember("error") && doc["error"] == "invalid_request")
    {
      XBMC->Log(LOG_ERROR, "[Login] ERROR: invalid credentials?");
      m_login_status = WAIPU_LOGIN_STATUS_INVALID_CREDENTIALS;
      return false;
    }
    else if (doc.HasMember("error"))
    {
      // unhandled error -> handle if known
      string err = doc["error"].GetString();
      XBMC->Log(LOG_ERROR, "[Login] ERROR: (%s)", err.c_str());
      m_login_status = WAIPU_LOGIN_STATUS_UNKNOWN;
      return false;
    }

    m_apiToken.accessToken = doc["access_token"].GetString();
    XBMC->Log(LOG_DEBUG, "[login check] accessToken: %s;", m_apiToken.accessToken.c_str());
    m_apiToken.refreshToken = doc["refresh_token"].GetString();
    XBMC->Log(LOG_DEBUG, "[login check] refreshToken: %s;", m_apiToken.refreshToken.c_str());
    m_apiToken.expires = currTime + doc["expires_in"].GetUint64();
    XBMC->Log(LOG_DEBUG, "[login check] expires: %i;", m_apiToken.expires);

    return ParseAccessToken();
  }
  // no valid session?
  m_login_status = WAIPU_LOGIN_STATUS_UNKNOWN;
  return false;
}

bool WaipuData::O2Login()
{
  XBMC->Log(LOG_DEBUG, "[login check] O2 TV LOGIN...");
  time_t currTime;
  time(&currTime);

  if (!m_apiToken.accessToken.empty() && (m_apiToken.expires - 10 * 60) > currTime)
  {
    // API token exists and is valid, more than x in future
    XBMC->Log(LOG_DEBUG, "[login check] old token still valid");
    return true;
  }

  m_login_status = WAIPU_LOGIN_STATUS_OK;

  // curl request
  Curl curl;
  int statusCode = 0;
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  curl.AddHeader("authority", "o2api.waipu.tv");
  string respForm =
      HttpRequestToCurl(curl, "GET",
                        "https://o2api.waipu.tv/api/o2/login/"
                        "token?redirectUri=https%3A%2F%2Fo2tv.waipu.tv%2F&inWebview=true",
                        "", statusCode);

  string postData = "";

  // get the form:
  regex formPattern("<form[^>]*name=\"Login\"[^>]*action=\"([^\"]*)\"[^>]*>([\\s\\S]*)</form>");
  smatch matches;
  if (regex_search(respForm, matches, formPattern))
  {
    string form_action = matches[1];
    string form_content = matches[2];
    XBMC->Log(LOG_DEBUG, "[form action] %s;", form_action.c_str());

    regex inputPattern("<input[^>]*name=\"([^\"]*)\"[^>]*value=\"([^\"]*)\"[^>]*>");
    // finding all the match.
    for (sregex_iterator it =
             sregex_iterator(form_content.begin(), form_content.end(), inputPattern);
         it != sregex_iterator(); it++)
    {
      smatch match;
      match = *it;
      string input_name = match.str(1);
      string input_value = match.str(2);
      // we need to dirty HTML-decode &#x3d; to = for base64 padding:
      input_value = Utils::ReplaceAll(input_value, "&#x3d;", "=");

      XBMC->Log(LOG_DEBUG, "[form input] %s -> %s;", input_name.c_str(), input_value.c_str());

      if (input_name == "IDToken2")
      {
        // input for password
        input_value = password;
      }

      postData =
          postData + Utils::UrlEncode(input_name) + "=" + Utils::UrlEncode(input_value) + "&";
    }
    // if parameters available: add username
    if (postData.length() > 0)
      postData = postData + "IDToken1=" + Utils::UrlEncode(username) + "&";
  }
  else
  {
    XBMC->Log(LOG_ERROR, "O2 Login Form not found");
    m_login_status = WAIPU_LOGIN_STATUS_UNKNOWN;
    return false;
  }


  XBMC->Log(LOG_DEBUG, "[O2] POST params: %s", postData.c_str());

  string resp = HttpRequestToCurl(curl, "POST", "https://login.o2online.de/sso/UI/Login",
                                  postData.c_str(), statusCode);
  XBMC->Log(LOG_DEBUG, "[login check] Login-response 2: (HTTP %i) %s;", statusCode, resp.c_str());

  string cookie = curl.GetCookie("user_token");
  if (cookie.size() == 0)
  {
    // invalid credentials ?
    m_login_status = WAIPU_LOGIN_STATUS_INVALID_CREDENTIALS;
    return false;
  }

  m_apiToken.accessToken = cookie;
  XBMC->Log(LOG_DEBUG, "[login O2] access_token: %s;", cookie.c_str());
  m_apiToken.refreshToken = "";
  XBMC->Log(LOG_DEBUG, "[login check] refreshToken: empty");
  m_apiToken.expires = currTime + 3600; // expires after 1h; TODO: find real value
  XBMC->Log(LOG_DEBUG, "[login check] expires: %i;", m_apiToken.expires);

  return ParseAccessToken();
}


WaipuData::WaipuData(const string& user, const string& pass, const WAIPU_PROVIDER provider_p)
{
  username = user;
  password = pass;
  provider = provider_p;
  m_recordings_count = 0;
  m_active_recordings_update = false;

  LoadChannelData();
}

WaipuData::~WaipuData(void)
{
  m_channels.clear();
  m_epgEntries.clear();
  m_channelGroups.clear();
  m_apiToken = {};
}

bool WaipuData::LoadChannelData(void)
{
  if (!ApiLogin())
  {
    // no valid session
    return false;
  }

  XBMC->Log(LOG_DEBUG, "[load data] Login valid -> GET CHANNELS");

  string jsonChannels = HttpGet("https://epg.waipu.tv/api/channels");
  if (jsonChannels.size() == 0)
  {
    XBMC->Log(LOG_ERROR, "[channels] ERROR - empty response");
    return PVR_ERROR_SERVER_ERROR;
  }
  jsonChannels = "{\"result\": " + jsonChannels + "}";
  XBMC->Log(LOG_DEBUG, "[channels] length: %i;", jsonChannels.length());
  XBMC->Log(LOG_DEBUG, "[channels] %s;", jsonChannels.c_str());
  XBMC->Log(LOG_DEBUG, "[channels] %s;", jsonChannels.substr(jsonChannels.size() - 40).c_str());

  // parse channels
  XBMC->Log(LOG_DEBUG, "[channels] parse channels");
  Document channelsDoc;
  channelsDoc.Parse(jsonChannels.c_str());
  if (channelsDoc.GetParseError())
  {
    XBMC->Log(LOG_ERROR, "[LoadChannelData] ERROR: error while parsing json");
    return PVR_ERROR_SERVER_ERROR;
  }
  XBMC->Log(LOG_DEBUG, "[channels] iterate channels");
  XBMC->Log(LOG_DEBUG, "[channels] size: %i;", channelsDoc["result"].Size());


  WaipuChannelGroup favgroup;
  favgroup.name = "Favoriten";

  int i = 0;
  for (const auto& channel : channelsDoc["result"].GetArray())
  {
    string waipuid = channel["id"].GetString();
    // check if channel is part of user channels:
    if (find(m_user_channels.begin(), m_user_channels.end(), waipuid.c_str()) ==
        m_user_channels.end())
      continue;

    bool tvfuse = false;
    // check if user has hidden this channel
    if (channel.HasMember("properties") && channel["properties"].IsArray())
    {
      bool skipChannel = false;
      for (auto& prop : channel["properties"].GetArray())
      {
        skipChannel |= (prop.GetString() == string("UserSetHidden"));
        tvfuse |= (prop.GetString() == string("tvfuse"));
      }
      if (skipChannel)
        continue;
    }

    ++i;
    WaipuChannel waipu_channel;
    waipu_channel.iChannelNumber = i; // position
    XBMC->Log(LOG_DEBUG, "[channel] channelnr(pos): %i;", waipu_channel.iChannelNumber);

    waipu_channel.tvfuse = tvfuse;
    XBMC->Log(LOG_DEBUG, "[channel] tvfuse: %i;", waipu_channel.tvfuse);

    waipu_channel.waipuID = waipuid; // waipu[id]
    XBMC->Log(LOG_DEBUG, "[channel] waipuid: %s;", waipu_channel.waipuID.c_str());

    int uniqueId = Utils::GetChannelId(waipuid.c_str());
    waipu_channel.iUniqueId = uniqueId;
    XBMC->Log(LOG_DEBUG, "[channel] id: %i;", uniqueId);

    string displayName = channel["displayName"].GetString();
    waipu_channel.strChannelName = displayName; // waipu[displayName]
    XBMC->Log(LOG_DEBUG, "[channel] name: %s;", waipu_channel.strChannelName.c_str());

    // iterate links
    string icon = "";
    string icon_sd = "";
    string icon_hd = "";
    for (const auto& link : channel["links"].GetArray())
    {
      string rel = link["rel"].GetString();
      string href = link["href"].GetString();
      if (rel == "icon")
      {
        icon = href;
        continue;
      }
      else if (rel == "iconsd")
      {
        icon_sd = href;
        continue;
      }
      else if (rel == "iconhd")
      {
        icon_hd = href;
        continue;
      }
      else if (rel == "livePlayout")
      {
        waipu_channel.strStreamURL = href; // waipu[links][rel=livePlayout]
        continue;
      }
      XBMC->Log(LOG_DEBUG, "[channel] link: %s -> %s;", rel.c_str(), href.c_str());
    }
    if (icon_sd.size() > 0)
    {
      waipu_channel.strIconPath = icon_sd + "?width=256&height=256";
    }
    else if (icon_hd.size() > 0)
    {
      waipu_channel.strIconPath = icon_hd + "?width=256&height=256";
    }
    else if (icon.size() > 0)
    {
      waipu_channel.strIconPath = icon + "?width=256&height=256";
    }
    XBMC->Log(LOG_DEBUG, "[channel] selected channel logo: %s", waipu_channel.strIconPath.c_str());

    bool isFav = channel["faved"].GetBool();
    if (isFav)
      favgroup.channels.push_back(waipu_channel);

    m_channels.push_back(waipu_channel);
  }

  m_channelGroups.push_back(favgroup);

  return true;
}

int WaipuData::GetChannelsAmount(void)
{
  return m_channels.size();
}

PVR_ERROR WaipuData::GetChannels(ADDON_HANDLE handle, bool bRadio)
{
  for (const auto& channel : m_channels)
  {
    if (!bRadio)
    {
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

string WaipuData::GetChannelStreamUrl(int uniqueId, const string& protocol)
{
  for (const auto& thisChannel : m_channels)
  {
    if (thisChannel.iUniqueId == (int)uniqueId)
    {
      XBMC->Log(LOG_DEBUG, "Get live url for channel %s", thisChannel.strChannelName.c_str());

      if (!ApiLogin())
      {
        // invalid
        XBMC->Log(LOG_DEBUG, "No stream login");
        return "";
      }

      string postData = "{\"stream\": { \"station\": \""+thisChannel.waipuID+"\", \"protocol\": \""+protocol+"\", \"requestMuxInstrumentation\": false}}";

      Curl curl;
      int statusCode;
      curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
      curl.AddHeader("Authorization", "Bearer " + m_apiToken.accessToken);
      curl.AddHeader("Content-Type", "application/vnd.streamurlprovider.stream-url-request-v1+json");

      string jsonStreamURL = HttpRequestToCurl(curl, "POST", "https://stream-url-provider.waipu.tv/api/stream-url", postData, statusCode);

      Document streamURLDoc;
      streamURLDoc.Parse(jsonStreamURL.c_str());
      if (streamURLDoc.GetParseError())
      {
	  XBMC->Log(LOG_ERROR, "[GetStreamURL] ERROR: error while parsing json");
          return "";
      }

      if(!streamURLDoc.HasMember("streamUrl"))
      {
	  XBMC->Log(LOG_ERROR, "[GetStreamURL] ERROR: missing param streamUrl");
          return "";
      }

      return streamURLDoc["streamUrl"].GetString();

    }
  }
  return "";
}

int WaipuData::GetChannelGroupsAmount(void)
{
  return static_cast<int>(m_channelGroups.size());
}

PVR_ERROR WaipuData::GetChannelGroups(ADDON_HANDLE handle)
{
  std::vector<WaipuChannelGroup>::iterator it;
  for (it = m_channelGroups.begin(); it != m_channelGroups.end(); ++it)
  {
    PVR_CHANNEL_GROUP xbmcGroup;
    memset(&xbmcGroup, 0, sizeof(PVR_CHANNEL_GROUP));
    xbmcGroup.iPosition = 0; /* not supported  */
    xbmcGroup.bIsRadio = false; /* is radio group */
    strncpy(xbmcGroup.strGroupName, it->name.c_str(), sizeof(xbmcGroup.strGroupName) - 1);

    PVR->TransferChannelGroup(handle, &xbmcGroup);
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannelGroupMembers(ADDON_HANDLE handle, const PVR_CHANNEL_GROUP& group)
{
  for (const auto& cgroup : m_channelGroups)
  {
    if (cgroup.name != group.strGroupName)
      continue;

    for (const auto& channel : cgroup.channels)
    {
      PVR_CHANNEL_GROUP_MEMBER xbmcGroupMember;
      memset(&xbmcGroupMember, 0, sizeof(PVR_CHANNEL_GROUP_MEMBER));

      strncpy(xbmcGroupMember.strGroupName, group.strGroupName,
              sizeof(xbmcGroupMember.strGroupName) - 1);
      xbmcGroupMember.iChannelUniqueId = static_cast<unsigned int>(channel.iUniqueId);
      xbmcGroupMember.iChannelNumber = static_cast<unsigned int>(channel.iChannelNumber);

      PVR->TransferChannelGroupMember(handle, &xbmcGroupMember);
    }
    return PVR_ERROR_NO_ERROR;
  }

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetEPGForChannel(ADDON_HANDLE handle,
                                      int iChannelUid,
                                      time_t iStart,
                                      time_t iEnd)
{
  if (!ApiLogin())
  {
    return PVR_ERROR_SERVER_ERROR;
  }
  for (unsigned int iChannelPtr = 0; iChannelPtr < m_channels.size(); iChannelPtr++)
  {
    WaipuChannel& myChannel = m_channels.at(iChannelPtr);
    if (myChannel.iUniqueId != iChannelUid)
      continue;

    char startTime[100];
    std::tm* pstm = std::localtime(&iStart);
    // 2019-01-20T23:59:59
    std::strftime(startTime, 32, "%Y-%m-%dT%H:%M:%S", pstm);

    char endTime[100];
    std::tm* petm = std::localtime(&iEnd);
    // 2019-01-20T23:59:59
    std::strftime(endTime, 32, "%Y-%m-%dT%H:%M:%S", petm);

    string jsonEpg =
        HttpGet("https://epg.waipu.tv/api/channels/" + myChannel.waipuID +
                "/programs?startTime=" + string(startTime) + "&stopTime=" + string(endTime));
    XBMC->Log(LOG_DEBUG, "[epg-all] %s", jsonEpg.c_str());
    if (jsonEpg.size() == 0)
    {
      XBMC->Log(LOG_ERROR, "[epg] empty server response");
      return PVR_ERROR_SERVER_ERROR;
    }
    jsonEpg = "{\"result\": " + jsonEpg + "}";

    Document epgDoc;
    epgDoc.Parse(jsonEpg.c_str());
    if (epgDoc.GetParseError())
    {
      XBMC->Log(LOG_ERROR, "[GetEPG] ERROR: error while parsing json");
      return PVR_ERROR_SERVER_ERROR;
    }
    XBMC->Log(LOG_DEBUG, "[epg] iterate entries");

    XBMC->Log(LOG_DEBUG, "[epg] size: %i;", epgDoc["result"].Size());

    for (const auto& epgData : epgDoc["result"].GetArray())
    {
      EPG_TAG tag;
      WaipuEPGEntry epgEntry;
      memset(&tag, 0, sizeof(EPG_TAG));

      // generate a unique boadcast id
      string epg_bid = epgData["id"].GetString();
      XBMC->Log(LOG_DEBUG, "[epg] epg_bid: %s;", epg_bid.c_str());
      int dirtyID = Utils::GetIDDirty(epg_bid);
      XBMC->Log(LOG_DEBUG, "[epg] epg_bid dirty: %i;", dirtyID);
      tag.iUniqueBroadcastId = dirtyID;
      epgEntry.iUniqueBroadcastId = dirtyID;

      // channel ID
      tag.iUniqueChannelId = myChannel.iUniqueId;
      epgEntry.iUniqueChannelId = myChannel.iUniqueId;

      // add streamUrlProvider if it is video on demand
      if (myChannel.tvfuse && epgData.HasMember("streamUrlProvider") && !epgData["streamUrlProvider"].IsNull())
      {
        string streamUrlProvider = epgData["streamUrlProvider"].GetString();
        XBMC->Log(LOG_DEBUG, "[epg] streamUrlProvider: %s;", streamUrlProvider.c_str());
        epgEntry.streamUrlProvider = streamUrlProvider;
      }

      // is recordable
      bool isRecordable = !epgData["recordingForbidden"].GetBool();
      XBMC->Log(LOG_DEBUG, "[epg] recordable: %i;", isRecordable);
      epgEntry.isRecordable = isRecordable;
      m_epgEntries.push_back(epgEntry);

      // set title
      tag.strTitle = epgData["title"].GetString();
      XBMC->Log(LOG_DEBUG, "[epg] title: %s;", epgData["title"].GetString());

      // set startTime
      string startTime = epgData["startTime"].GetString();
      tag.startTime = Utils::StringToTime(startTime);

      // set endTime
      string endTime = epgData["stopTime"].GetString();
      tag.endTime = Utils::StringToTime(endTime);

      // tag.strPlotOutline     = myTag.strPlotOutline.c_str();

      // set description
      if (epgData.HasMember("description") && !epgData["description"].IsNull())
      {
        tag.strPlot = epgData["description"].GetString();
        XBMC->Log(LOG_DEBUG, "[epg] description: %s;", epgData["description"].GetString());
      }

      // tag.strIconPath        = myTag.strIconPath.c_str();

      tag.iFlags = EPG_TAG_FLAG_UNDEFINED;

      // iSeriesNumber
      if (epgData.HasMember("season") && !epgData["season"].IsNull())
      {
        tag.iSeriesNumber = Utils::stoiDefault(epgData["season"].GetString(), 0);
      }

      // episodeNumber
      if (epgData.HasMember("episode") && epgData["episode"].IsString())
      {
        tag.iEpisodeNumber = Utils::stoiDefault(epgData["episode"].GetString(), 0);
      }

      // episodeName
      if (epgData.HasMember("episodeTitle") && !epgData["episodeTitle"].IsNull())
      {
        tag.strEpisodeName = epgData["episodeTitle"].GetString();
      }

      // year
      if (epgData.HasMember("year") && !epgData["year"].IsNull())
      {
        tag.iYear = Utils::stoiDefault(epgData["year"].GetString(), 1970);
      }

      // genre
      if (epgData.HasMember("genreDisplayName") && !epgData["genreDisplayName"].IsNull())
      {
        tag.iGenreType = EPG_GENRE_USE_STRING;
        tag.strGenreDescription = epgData["genreDisplayName"].GetString();
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
  if (!ApiLogin())
  {
    return PVR_ERROR_SERVER_ERROR;
  }
  m_active_recordings_update = true;

  Curl curl;
  int statusCode;
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  curl.AddHeader("Authorization", "Bearer " + m_apiToken.accessToken);
  curl.AddHeader("Accept", "application/vnd.waipu.recordings-v2+json");
  string jsonRecordings =
      HttpRequestToCurl(curl, "GET", "https://recording.waipu.tv/api/recordings", "", statusCode);
  XBMC->Log(LOG_DEBUG, "[recordings] %s", jsonRecordings.c_str());

  jsonRecordings = "{\"result\": " + jsonRecordings + "}";

  Document recordingsDoc;
  recordingsDoc.Parse(jsonRecordings.c_str());
  if (recordingsDoc.GetParseError())
  {
    XBMC->Log(LOG_ERROR, "[GetRecordings] ERROR: error while parsing json");
    return PVR_ERROR_SERVER_ERROR;
  }
  XBMC->Log(LOG_DEBUG, "[recordings] iterate entries");

  XBMC->Log(LOG_DEBUG, "[recordings] size: %i;", recordingsDoc["result"].Size());

  int recordings_count = 0;

  for (const auto& recording : recordingsDoc["result"].GetArray())
  {
    // skip not FINISHED entries
    string status = recording["status"].GetString();
    if (status != "FINISHED")
      continue;

    // new tag
    PVR_RECORDING tag;
    memset(&tag, 0, sizeof(PVR_RECORDING));
    tag.bIsDeleted = false;

    // set recording id
    string rec_id = recording["id"].GetString();
    strncpy(tag.strRecordingId, rec_id.c_str(), sizeof(tag.strRecordingId) - 1);

    // playcount
    if (recording.HasMember("watched") && recording["watched"].GetBool())
    {
      tag.iPlayCount = 1;
    }
    else
    {
      tag.iPlayCount = 0;
    }

    const Value& epgData = recording["epgData"];

    // set recording title
    string rec_title = epgData["title"].GetString();
    strncpy(tag.strTitle, rec_title.c_str(), sizeof(tag.strTitle) - 1);
    // set folder; test
    strncpy(tag.strDirectory, rec_title.c_str(), sizeof(tag.strTitle) - 1);

    // set image
      if (epgData.HasMember("previewImages")
	  && epgData["previewImages"].IsArray()
	  && epgData["previewImages"].Size() > 0)
    {
      string rec_img = epgData["previewImages"][0].GetString();
      rec_img = rec_img + "?width=256&height=256";
      strncpy(tag.strIconPath, rec_img.c_str(), sizeof(tag.strIconPath) - 1);
      strncpy(tag.strThumbnailPath, rec_img.c_str(), sizeof(tag.strThumbnailPath) - 1);
    }

    // duration
    if (epgData.HasMember("duration") && !epgData["duration"].IsNull())
    {
      string rec_dur = epgData["duration"].GetString();
      tag.iDuration = Utils::stoiDefault(rec_dur, 0) * 60;
    }

    // iSeriesNumber
    if (epgData.HasMember("season") && !epgData["season"].IsNull())
    {
      tag.iSeriesNumber = Utils::stoiDefault(epgData["season"].GetString(), 0);
    }

    // episodeNumber
    if (epgData.HasMember("episode") && !epgData["episode"].IsNull())
    {
      tag.iEpisodeNumber = Utils::stoiDefault(epgData["episode"].GetString(), 0);
    }

    // episodeName
    if (epgData.HasMember("episodeTitle") && !epgData["episodeTitle"].IsNull())
    {
      string rec_episodename = epgData["episodeTitle"].GetString();
      strncpy(tag.strEpisodeName, rec_episodename.c_str(), sizeof(tag.strEpisodeName) - 1);
    }

    // year
    if (epgData.HasMember("year") && !epgData["year"].IsNull())
    {
      string rec_year = epgData["year"].GetString();
      tag.iYear = Utils::stoiDefault(rec_year, 1970);
    }

    // get recording time
    if (recording.HasMember("startTime") && !recording["startTime"].IsNull())
    {
      string recordingTime = recording["startTime"].GetString();
      tag.recordingTime = Utils::StringToTime(recordingTime);
    }

    // get plot
    if (epgData.HasMember("description") && !epgData["description"].IsNull())
    {
      string rec_plot = epgData["description"].GetString();
      strncpy(tag.strPlot, rec_plot.c_str(), sizeof(tag.strPlot) - 1);
    }

    // genre
    if (epgData.HasMember("genreDisplayName") && !epgData["genreDisplayName"].IsNull())
    {
      tag.iGenreType = EPG_GENRE_USE_STRING;
      string genre = epgData["genreDisplayName"].GetString();
      strncpy(tag.strGenreDescription, genre.c_str(), sizeof(tag.strGenreDescription) - 1);
    }

    // epg mapping
    if (epgData.HasMember("id") && !epgData["id"].IsNull())
    {
      string epg_id = epgData["id"].GetString();
      int dirtyID = Utils::GetIDDirty(epg_id);
      tag.iEpgEventId = dirtyID;
    }

    ++recordings_count;
    PVR->TransferRecordingEntry(handle, &tag);
  }
  m_recordings_count = recordings_count;
  m_active_recordings_update = false;

  return PVR_ERROR_NO_ERROR;
}

std::string WaipuData::GetRecordingURL(const PVR_RECORDING& recording, const string& protocol)
{
  ApiLogin();

  string recording_id = recording.strRecordingId;
  XBMC->Log(LOG_DEBUG, "play recording -> %s", recording_id.c_str());

  string rec_resp = HttpGet("https://recording.waipu.tv/api/recordings/" + recording_id);
  XBMC->Log(LOG_DEBUG, "recording resp -> %s", rec_resp.c_str());

  Document recordingDoc;
  recordingDoc.Parse(rec_resp.c_str());
  if (recordingDoc.GetParseError())
  {
    XBMC->Log(LOG_ERROR, "[getRecordingURL] ERROR: error while parsing json");
    return "";
  }
  XBMC->Log(LOG_DEBUG, "[recording] streams");
  // check if streams there
  if (!recordingDoc.HasMember("streamingDetails") ||
      !recordingDoc["streamingDetails"].HasMember("streams"))
  {
    return "";
  }

  XBMC->Log(LOG_DEBUG, "[recordings] size: %i;",
            recordingDoc["streamingDetails"]["streams"].Size());

  for (const auto& stream : recordingDoc["streamingDetails"]["streams"].GetArray())
  {
    string current_protocol = stream["protocol"].GetString();
    XBMC->Log(LOG_DEBUG, "[stream] protocol: %s;", current_protocol.c_str());
    if (current_protocol == protocol)
    {
      string href = stream["href"].GetString();
      XBMC->Log(LOG_DEBUG, "[stream] selected href: %s;", href.c_str());
      return href;
    }
  }
  return "";
}

string WaipuData::GetEPGTagURL(const EPG_TAG& tag, const string& protocol)
{
  ApiLogin();

  for (const auto& epgEntry : m_epgEntries)
  {
    if (epgEntry.iUniqueChannelId != tag.iUniqueChannelId)
      continue;
    if (epgEntry.iUniqueBroadcastId != tag.iUniqueBroadcastId)
      continue;

    string url = epgEntry.streamUrlProvider;
    XBMC->Log(LOG_DEBUG, "play epgTAG -> %s", tag.strTitle);
    XBMC->Log(LOG_DEBUG, "play url -> %s", url.c_str());

    string tag_resp = HttpGet(url);
    XBMC->Log(LOG_DEBUG, "tag resp -> %s", tag_resp.c_str());

    Document tagDoc;
    tagDoc.Parse(tag_resp.c_str());
    if (tagDoc.GetParseError())
    {
      XBMC->Log(LOG_ERROR, "[getEPGTagURL] ERROR: error while parsing json");
      return "";
    }
    XBMC->Log(LOG_DEBUG, "[tag] streams");
    // check if streams there
    if (tagDoc.HasMember("player") && tagDoc["player"].HasMember("mpd"))
    {
      string mpdUrl = tagDoc["player"]["mpd"].GetString();
      XBMC->Log(LOG_DEBUG, "mpd url -> %s", mpdUrl.c_str());
      return mpdUrl;
    }
  }
  return "";
}

PVR_ERROR WaipuData::DeleteRecording(const PVR_RECORDING& recording)
{
  if (ApiLogin())
  {
    string recording_id = recording.strRecordingId;
    string request_data = "{\"ids\":[\"" + recording_id + "\"]}";
    XBMC->Log(LOG_DEBUG, "[delete recording] req: %s;", request_data.c_str());
    string deleted = HttpDelete("https://recording.waipu.tv/api/recordings", request_data.c_str());
    XBMC->Log(LOG_DEBUG, "[delete recording] response: %s;", deleted.c_str());
    PVR->TriggerRecordingUpdate();
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
  if (!ApiLogin())
  {
    return PVR_ERROR_SERVER_ERROR;
  }

  Curl curl;
  int statusCode;
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  curl.AddHeader("Authorization", "Bearer " + m_apiToken.accessToken);
  curl.AddHeader("Accept", "application/vnd.waipu.recordings-v2+json");
  string jsonRecordings =
      HttpRequestToCurl(curl, "GET", "https://recording.waipu.tv/api/recordings", "", statusCode);
  XBMC->Log(LOG_DEBUG, "[Timers] %s", jsonRecordings.c_str());

  jsonRecordings = "{\"result\": " + jsonRecordings + "}";

  Document timersDoc;
  timersDoc.Parse(jsonRecordings.c_str());
  if (timersDoc.GetParseError())
  {
    XBMC->Log(LOG_ERROR, "[timers] ERROR: error while parsing json");
    return PVR_ERROR_SERVER_ERROR;
  }
  XBMC->Log(LOG_DEBUG, "[timers] iterate entries");
  XBMC->Log(LOG_DEBUG, "[timers] size: %i;", timersDoc["result"].Size());

  int recordings_count = 0;

  for (const auto& timer : timersDoc["result"].GetArray())
  {
    // skip not FINISHED entries
    string status = timer["status"].GetString();
    if (status != "SCHEDULED" && status != "RECORDING")
    {
      ++recordings_count;
      continue;
    }

    // new tag
    PVR_TIMER tag;
    memset(&tag, 0, sizeof(PVR_TIMER));
    if (status == "SCHEDULED")
    {
      tag.state = PVR_TIMER_STATE_SCHEDULED;
    }
    else if (status == "RECORDING")
    {
      tag.state = PVR_TIMER_STATE_RECORDING;
    }
    tag.iLifetime = 0;
    tag.iTimerType = 1; // not the best way to do it...

    // set recording id
    string rec_id = timer["id"].GetString();
    tag.iClientIndex = Utils::stoiDefault(rec_id, 0);
    tag.iEpgUid = Utils::stoiDefault(rec_id, 0);

    // channelid
    if (timer.HasMember("channelId") && !timer["channelId"].IsNull())
    {
      string channel_name = timer["channelId"].GetString();
      for (unsigned int iChannelPtr = 0; iChannelPtr < m_channels.size(); iChannelPtr++)
      {
        WaipuChannel& myChannel = m_channels.at(iChannelPtr);
        if (myChannel.waipuID != channel_name)
          continue;
        tag.iClientChannelUid = myChannel.iUniqueId;
        break;
      }
    }

    const Value& epgData = timer["epgData"];

    // set recording title
    string rec_title = epgData["title"].GetString();
    XBMC->Log(LOG_DEBUG, "[timers] Add: %s;", rec_title.c_str());
    strncpy(tag.strTitle, rec_title.c_str(), sizeof(tag.strTitle) - 1);

    // get recording time
    if (timer.HasMember("startTime") && !timer["startTime"].IsNull())
    {
      string startTime = timer["startTime"].GetString();
      tag.startTime = Utils::StringToTime(startTime);
    }
    if (timer.HasMember("stopTime") && !timer["stopTime"].IsNull())
    {
      string endTime = timer["stopTime"].GetString();
      tag.endTime = Utils::StringToTime(endTime);
    }

    // get plot
    if (epgData.HasMember("description") && !epgData["description"].IsNull())
    {
      string rec_plot = epgData["description"].GetString();
      strncpy(tag.strSummary, rec_plot.c_str(), sizeof(tag.strSummary) - 1);
    }

    // epg mapping
    if (epgData.HasMember("id") && !epgData["id"].IsNull())
    {
      string epg_id = epgData["id"].GetString();
      int dirtyID = Utils::GetIDDirty(epg_id);
      tag.iEpgUid = dirtyID;
    }

    PVR->TransferTimerEntry(handle, &tag);
  }

  if (recordings_count != m_recordings_count && !m_active_recordings_update)
  {
    // we detected another amount of recordings.
    // tell kodi about it
    m_active_recordings_update = true;
    PVR->TriggerRecordingUpdate();
  }

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::DeleteTimer(const PVR_TIMER& timer)
{
  if (ApiLogin())
  {
    int timer_id = timer.iClientIndex;
    string request_data = "{\"ids\":[\"" + to_string(timer_id) + "\"]}";
    XBMC->Log(LOG_DEBUG, "[delete timer] req: %s;", request_data.c_str());
    string deleted = HttpDelete("https://recording.waipu.tv/api/recordings", request_data.c_str());
    XBMC->Log(LOG_DEBUG, "[delete timer] response: %s;", deleted.c_str());
    PVR->TriggerTimerUpdate();
    return PVR_ERROR_NO_ERROR;
  }
  return PVR_ERROR_FAILED;
}

PVR_ERROR WaipuData::AddTimer(const PVR_TIMER& timer)
{
  if (ApiLogin())
  {
    // {"programId":"_1051966761","channelId":"PRO7","startTime":"2019-02-03T18:05:00.000Z","stopTime":"2019-02-03T19:15:00.000Z"}
    for (const auto& channel : m_channels)
    {
      if (channel.iUniqueId != timer.iClientChannelUid)
        continue;
      string postData = "{\"programId\":\"_" + to_string(timer.iEpgUid) + "\",\"channelId\":\"" +
                        channel.waipuID + "\"" + "}";
      string recordResp = HttpPost("https://recording.waipu.tv/api/recordings", postData);
      XBMC->Log(LOG_DEBUG, "[add timer] response: %s;", recordResp.c_str());
      PVR->TriggerTimerUpdate();
      return PVR_ERROR_NO_ERROR;
    }
  }
  return PVR_ERROR_FAILED;
}

std::string WaipuData::GetLicense(void)
{
  // ensure that userHandle is valid
  ApiLogin();
  return m_license;
}

PVR_ERROR WaipuData::IsEPGTagRecordable(const EPG_TAG* tag, bool* bIsRecordable)
{
  time_t current_time;
  time(&current_time);
  if (tag->endTime < current_time)
  {
    // if tag is in past, no recording is possible
    *bIsRecordable = false;
    return PVR_ERROR_NO_ERROR;
  }

  for (const auto& epgEntry : m_epgEntries)
  {
    if (epgEntry.iUniqueBroadcastId != tag->iUniqueBroadcastId)
      continue;
    if (epgEntry.iUniqueChannelId != tag->iUniqueChannelId)
      continue;
    *bIsRecordable = epgEntry.isRecordable;
    return PVR_ERROR_NO_ERROR;
  }

  *bIsRecordable = false;
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::IsEPGTagPlayable(const EPG_TAG* tag, bool* bIsPlayable)
{
  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId != tag->iUniqueChannelId)
      continue;
    *bIsPlayable = channel.tvfuse;
    return PVR_ERROR_NO_ERROR;
  }

  *bIsPlayable = false;
  return PVR_ERROR_NO_ERROR;
}
