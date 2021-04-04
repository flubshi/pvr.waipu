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
#include "kodi/General.h"
#include "rapidjson/document.h"

#include <algorithm>
#include <ctime>
#include <regex>

using namespace std;
using namespace rapidjson;

// BEGIN CURL helpers from zattoo addon:
string WaipuData::HttpGet(const string& url, const map<string,string>& headers)
{
  return HttpRequest("GET", url, "", headers);
}

string WaipuData::HttpDelete(const string& url, const string& postData, const map<string,string>& headers)
{
  return HttpRequest("DELETE", url, postData, headers);
}

string WaipuData::HttpPost(const string& url, const string& postData, const map<string,string>& headers)
{
  return HttpRequest("POST", url, postData, headers);
}

string WaipuData::HttpRequest(const string& action, const string& url, const string& postData, const map<string,string>& headers)
{
  Curl curl;
  int statusCode;

  for (auto const& header : headers)
  {
    curl.AddHeader(header.first, header.second);
  }

  //curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  curl.AddHeader("Authorization", "Bearer " + m_apiToken.accessToken);

  return HttpRequestToCurl(curl, action, url, postData, statusCode);
}

string WaipuData::HttpRequestToCurl(
    Curl& curl, const string& action, const string& url, const string& postData, int& statusCode)
{
  kodi::Log(ADDON_LOG_DEBUG, "Http-Request: %s %s.", action.c_str(), url.c_str());
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
  if(m_login_failed_counter > WAIPU_LOGIN_FAILED_LOCK_LIMIT){
     // more than x consecutive failed login attempts
     // check time limit
     time_t currTime;
     time(&currTime);
     if(m_login_failed_locktime + 3*60 < currTime)
     {
       kodi::Log(ADDON_LOG_ERROR, "[API LOGIN] Reset login lock due to timer");
       m_login_failed_counter = 0;
     }else{
       // block login attempt
       kodi::Log(ADDON_LOG_ERROR, "[API LOGIN] Locked due to invalid attempts");
       m_login_status = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
       return false;
     }
  }

  bool login_result;
  if (m_provider == WAIPU_PROVIDER_WAIPU)
  {
    login_result = WaipuLogin();
  }
  else
  {
    login_result = O2Login();
  }
  if(login_result){
      // login okay, reset counter
      m_login_failed_counter = 0;
  }else{
      if(m_login_failed_counter == WAIPU_LOGIN_FAILED_LOCK_LIMIT)
	{
	  time_t currTime;
	  time(&currTime);
	  m_login_failed_locktime = currTime;
	}
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
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] middle: %s", jwt_arr.at(1).c_str());
    string jwt_payload = base64_decode(jwt_arr.at(1));
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] payload: %s", jwt_payload.c_str());

    Document jwt_doc;
    jwt_doc.Parse(jwt_payload.c_str());

    if (jwt_doc.HasParseError())
    {
      m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
      kodi::Log(ADDON_LOG_ERROR, "[jwt_doc] ERROR: error while parsing json");
      return false;
    }

    m_userhandle = jwt_doc["userHandle"].GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] userHandle: %s", m_userhandle.c_str());
    // generate the license
    string license_plain = "{\"merchant\" : \"exaring\", \"sessionId\" : \"default\", "
                           "\"userId\" : \"" +
                           m_userhandle + "\"}";
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] license_plain: %s", license_plain.c_str());
    m_license = base64_encode(license_plain.c_str(), license_plain.length());
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] license: %s", m_license.c_str());
    // get user channels
    m_user_channels_sd.clear();
    m_user_channels_hd.clear();
    for (const auto& user_channel : jwt_doc["userAssets"]["channels"]["SD"].GetArray())
    {
      string user_channel_s = user_channel.GetString();
      kodi::Log(ADDON_LOG_DEBUG, "[jwt] SD channel: %s", user_channel_s.c_str());
      m_user_channels_sd.push_back(user_channel_s);
    }
    for (const auto& user_channel : jwt_doc["userAssets"]["channels"]["HD"].GetArray())
    {
      string user_channel_s = user_channel.GetString();
      m_user_channels_hd.push_back(user_channel_s);
      kodi::Log(ADDON_LOG_DEBUG, "[jwt] HD channel: %s", user_channel_s.c_str());
    }
    if(jwt_doc["userAssets"].HasMember("instantRestart")){
	m_account_replay_allowed = jwt_doc["userAssets"]["instantRestart"].GetBool();
	kodi::Log(ADDON_LOG_DEBUG, "[jwt] Account InstantStart: %i", m_account_replay_allowed);
    }
    if(jwt_doc["userAssets"].HasMember("hoursRecording")){
	m_account_hours_recording = jwt_doc["userAssets"]["hoursRecording"].GetInt();
	kodi::Log(ADDON_LOG_DEBUG, "[jwt] Account HoursReording: %i", m_account_hours_recording);
    }
  }
  m_login_status = WAIPU_LOGIN_STATUS::OK;
  return true;
}


bool WaipuData::WaipuLogin()
{
  kodi::Log(ADDON_LOG_DEBUG, "[login check] WAIPU.TV LOGIN...");

  time_t currTime;
  time(&currTime);
  kodi::Log(ADDON_LOG_DEBUG, "[token] current time %i", currTime);
  kodi::Log(ADDON_LOG_DEBUG, "[token] expire  time %i", m_apiToken.expires);
  if (!m_apiToken.accessToken.empty() && (m_apiToken.expires - 20 * 60) > currTime)
  {
    // API token exists and is valid, more than x in future
    kodi::Log(ADDON_LOG_DEBUG, "[login check] old token still valid");
    return true;
  }

  ostringstream dataStream;
  if (!m_apiToken.refreshToken.empty())
  {
    // Since the refresh token is valid for a long time, we do not check expiration for now
    // refresh API token
    dataStream << "refresh_token=" << Utils::UrlEncode(m_apiToken.refreshToken)
               << "&grant_type=refresh_token";
    kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-Request (refresh): %s;", dataStream.str().c_str());
  }
  else
  {
    // get API by login user/pw
    dataStream << "username=" << Utils::UrlEncode(m_username)
               << "&password=" << Utils::UrlEncode(m_password) << "&grant_type=password";
    kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-Request (user/pw): %s;",
              dataStream.str().c_str());
  }
  string jsonString;
  // curl request
  Curl curl;
  int statusCode = 0;
  //curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  curl.AddHeader("Authorization", "Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
  curl.AddHeader("Content-Type", "application/x-www-form-urlencoded");
  jsonString = HttpRequestToCurl(curl, "POST", "https://auth.waipu.tv/oauth/token",
                                 dataStream.str(), statusCode);

  kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-response: (HTTP %i) %s;", statusCode,
            jsonString.c_str());

  if (jsonString.length() == 0 && statusCode == -1)
  {
    // no network connection?
    m_login_status = WAIPU_LOGIN_STATUS::NO_NETWORK;
    kodi::Log(ADDON_LOG_ERROR, "[Login] no network connection");
    return false;
  }
  else if (statusCode == 401)
  {
    // invalid credentials
    m_login_status = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
    return false;
  }

  if (!jsonString.empty())
  {
    Document doc;
    doc.Parse(jsonString.c_str());
    if (doc.GetParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[Login] ERROR: error while parsing json");
      m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
      return false;
    }

    if (doc.HasMember("error") && doc["error"] == "invalid_request")
    {
      kodi::Log(ADDON_LOG_ERROR, "[Login] ERROR: invalid credentials?");
      m_login_status = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
      return false;
    }
    else if (doc.HasMember("error"))
    {
      // unhandled error -> handle if known
      string err = doc["error"].GetString();
      kodi::Log(ADDON_LOG_ERROR, "[Login] ERROR: (%s)", err.c_str());
      m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
      return false;
    }

    m_apiToken.accessToken = doc["access_token"].GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[login check] accessToken: %s;", m_apiToken.accessToken.c_str());
    m_apiToken.refreshToken = doc["refresh_token"].GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[login check] refreshToken: %s;", m_apiToken.refreshToken.c_str());
    m_apiToken.expires = currTime + doc["expires_in"].GetUint64();
    kodi::Log(ADDON_LOG_DEBUG, "[login check] expires: %i;", m_apiToken.expires);

    return ParseAccessToken();
  }
  // no valid session?
  m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
  return false;
}

bool WaipuData::O2Login()
{
  kodi::Log(ADDON_LOG_DEBUG, "[login check] O2 TV LOGIN...");
  time_t currTime;
  time(&currTime);

  if (!m_apiToken.accessToken.empty() && (m_apiToken.expires - 10 * 60) > currTime)
  {
    // API token exists and is valid, more than x in future
    kodi::Log(ADDON_LOG_DEBUG, "[login check] old token still valid");
    return true;
  }

  m_login_status = WAIPU_LOGIN_STATUS::OK;

  // curl request
  Curl curl;
  int statusCode = 0;
  //curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
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
    kodi::Log(ADDON_LOG_DEBUG, "[form action] %s;", form_action.c_str());

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

      kodi::Log(ADDON_LOG_DEBUG, "[form input] %s -> %s;", input_name.c_str(), input_value.c_str());

      if (input_name == "IDToken2")
      {
        // input for password
        input_value = m_password;
      }

      postData =
          postData + Utils::UrlEncode(input_name) + "=" + Utils::UrlEncode(input_value) + "&";
    }
    // if parameters available: add username
    if (postData.length() > 0)
      postData = postData + "IDToken1=" + Utils::UrlEncode(m_username) + "&";
  }
  else
  {
    kodi::Log(ADDON_LOG_ERROR, "O2 Login Form not found");
    m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
    return false;
  }


  kodi::Log(ADDON_LOG_DEBUG, "[O2] POST params: %s", postData.c_str());

  string resp = HttpRequestToCurl(curl, "POST", "https://login.o2online.de/sso/UI/Login",
                                  postData.c_str(), statusCode);
  kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-response 2: (HTTP %i) %s;", statusCode,
            resp.c_str());

  string cookie = curl.GetCookie("user_token");
  if (cookie.size() == 0)
  {
    // invalid credentials ?
    m_login_status = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
    return false;
  }

  m_apiToken.accessToken = cookie;
  kodi::Log(ADDON_LOG_DEBUG, "[login O2] access_token: %s;", cookie.c_str());
  m_apiToken.refreshToken = "";
  kodi::Log(ADDON_LOG_DEBUG, "[login check] refreshToken: empty");
  m_apiToken.expires = currTime + 3600; // expires after 1h; TODO: find real value
  kodi::Log(ADDON_LOG_DEBUG, "[login check] expires: %i;", m_apiToken.expires);

  return ParseAccessToken();
}

bool WaipuData::RefreshDeviceCapabiltiesToken()
{
  kodi::Log(ADDON_LOG_DEBUG, "%s - Creating the waipu.tv PVR add-on", __FUNCTION__);

  time_t currTime;
  time(&currTime);
  kodi::Log(ADDON_LOG_DEBUG, "[device token] current time %i", currTime);
  kodi::Log(ADDON_LOG_DEBUG, "[device token] expire  time %i", m_deviceCapabilitiesToken.expires);
  if (!m_deviceCapabilitiesToken.token.empty() && (m_deviceCapabilitiesToken.expires - 5 * 60) > currTime)
  {
    // device token exists and is valid, more than x in future
    kodi::Log(ADDON_LOG_DEBUG, "[device token] old token still valid, no need to refresh");
    return true;
  }

  // Get new device token
  kodi::Log(ADDON_LOG_DEBUG, "[device token] New deviceToken required...");

  // \"sdpalp25\": false, \"sdpalp50\": false, \"hd720p25\": false, \"hd720p50\": false,
  string appVersion;
  GetBackendVersion(appVersion);

  bool cap_audio_aac = kodi::GetSettingBoolean("streaming_capabilities_audio_aac",false);

  string capabilitesData = "{\"type\": \"receiver\", \"model\": \"Kodi 19\", \"manufacturer\": \"Team Kodi\", \"platform\": \"Kodi 19-pvr.waipu\", \"appVersion\": \""+appVersion+"\", \"capabilities\": {\"audio\": {\"aac\": "+(cap_audio_aac ? "true" : "false")+"},\"video\": { ";

  vector<string> video_cap_options = { "sdpalp25", "sdpalp50", "hd720p25", "hd720p50", "hd1080p25", "hd1080p50", "hevc1080p50", "hevc2160p50" };
  bool first = true;
  for (const std::string& cap_option : video_cap_options)
  {
    bool cap_value = kodi::GetSettingBoolean("streaming_capabilities_video_"+cap_option, false);
    capabilitesData += string(first ? "" : ",")+ "\""+cap_option+"\": " + (cap_value ? "true" : "false");
    first = false;
  }
  capabilitesData += "}}}";

  string jsonDeviceToken = HttpPost("https://device-capabilities.waipu.tv/api/device-capabilities", capabilitesData, {{"Content-Type", "application/vnd.dc.device-info-v1+json"},{"X-USERCONTEXT-USERHANDLE",m_userhandle.c_str()}});

  kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] response: %s", jsonDeviceToken.c_str());

  string deviceToken = "";

  Document deviceTokenDoc;
  deviceTokenDoc.Parse(jsonDeviceToken.c_str());
  if (deviceTokenDoc.GetParseError())
  {
      kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] parse error :(");
      return false;
  }

  if(deviceTokenDoc.HasMember("token"))
  {
    m_deviceCapabilitiesToken.token = deviceTokenDoc["token"].GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] discovered token: %s", m_deviceCapabilitiesToken.token.c_str());

    if(deviceTokenDoc.HasMember("expiresIn")){
	m_deviceCapabilitiesToken.expires = currTime + deviceTokenDoc["expiresIn"].GetUint64();
	kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] expires: %i;", m_deviceCapabilitiesToken.expires);
    }else{
	m_apiToken.expires = currTime + 5 * 60;
    }
    return true;
  }

  kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] unknown error :(");
  return false;
}


ADDON_STATUS WaipuData::Create()
{
  kodi::Log(ADDON_LOG_DEBUG, "%s - Creating the waipu.tv PVR add-on", __FUNCTION__);

  ReadSettings();

  ADDON_STATUS curStatus = ADDON_STATUS_UNKNOWN;

  if (!m_username.empty() && !m_password.empty())
  {
    LoadChannelData();

    switch (m_login_status)
    {
    case WAIPU_LOGIN_STATUS::OK:
      curStatus = ADDON_STATUS_OK;
      break;
    case WAIPU_LOGIN_STATUS::NO_NETWORK:
      kodi::Log(ADDON_LOG_ERROR, "[load data] Network issue");
      kodi::QueueNotification(QUEUE_ERROR, "", kodi::GetLocalizedString(30031));
      curStatus = ADDON_STATUS_NEED_RESTART;
      break;
    case WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS:
      kodi::Log(ADDON_LOG_ERROR, "[load data] Login invalid");
      kodi::QueueNotification(QUEUE_ERROR, "", kodi::GetLocalizedString(30032));
      curStatus = ADDON_STATUS_NEED_SETTINGS;
      break;
    case WAIPU_LOGIN_STATUS::UNKNOWN:
      kodi::Log(ADDON_LOG_ERROR, "[login status] unknown state");
      curStatus = ADDON_STATUS_UNKNOWN;
      break;
    default:
      kodi::Log(ADDON_LOG_ERROR, "[login status] unhandled state");
      curStatus = ADDON_STATUS_UNKNOWN;
      break;
    }
  }
  else
  {
    kodi::QueueNotification(QUEUE_ERROR, "", kodi::GetLocalizedString(30033));
    curStatus = ADDON_STATUS_NEED_SETTINGS;
  }

  return curStatus;
}

void WaipuData::ReadSettings(void)
{
  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);

  m_username = kodi::GetSettingString("username");
  m_password = kodi::GetSettingString("password");
  m_protocol = kodi::GetSettingString("protocol", "dash");
  m_provider = kodi::GetSettingEnum<WAIPU_PROVIDER>("provider_select", WAIPU_PROVIDER_WAIPU);

  kodi::Log(ADDON_LOG_DEBUG, "End Readsettings");
}

ADDON_STATUS WaipuData::SetSetting(const std::string& settingName,
                                   const kodi::CSettingValue& settingValue)
{
  if (settingName == "username")
  {
    std::string username = settingValue.GetString();
    if (username != m_username)
    {
      m_username = username;
      m_login_failed_counter = 0;
      return ADDON_STATUS_NEED_RESTART;
    }
  }

  else if (settingName == "password")
  {
    std::string password = settingValue.GetString();
    if (password != m_password)
    {
      m_login_failed_counter = 0;
      m_password = password;
      return ADDON_STATUS_NEED_RESTART;
    }
  }

  else if (settingName == "protocol")
  {
    std::string protocol = settingValue.GetString();
    if (protocol != m_protocol)
    {
      m_protocol = protocol;
      return ADDON_STATUS_OK;
    }
  }

  else if (settingName == "provider_select")
  {
    WAIPU_PROVIDER tmpProvider = settingValue.GetEnum<WAIPU_PROVIDER>();
    if (tmpProvider != m_provider)
    {
      m_login_failed_counter = 0;
      m_provider = tmpProvider;
      return ADDON_STATUS_NEED_RESTART;
    }
  }else if (settingName.rfind("streaming_capabilities_", 0) == 0)
  {
    // settings name begins with "streaming_capabilities_"
    // reset capabilities to force refresh
    m_deviceCapabilitiesToken.token = "";
  }

  return ADDON_STATUS_OK;
}

PVR_ERROR WaipuData::GetCapabilities(kodi::addon::PVRCapabilities& capabilities)
{
  capabilities.SetSupportsEPG(true);
  capabilities.SetSupportsTV(true);
  capabilities.SetSupportsRecordings(true);
  capabilities.SetSupportsTimers(true);
  capabilities.SetSupportsChannelGroups(true);

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetBackendName(std::string& name)
{
  name = "waipu.tv PVR add-on";
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetBackendVersion(std::string& version)
{
  version = STR(IPTV_VERSION);
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetConnectionString(std::string& connection)
{
  connection = "connected";
  return PVR_ERROR_NO_ERROR;
}

std::string WaipuData::GetLicense(void)
{
  // ensure that userHandle is valid
  ApiLogin();
  return m_license;
}

void WaipuData::SetStreamProperties(std::vector<kodi::addon::PVRStreamProperty>& properties,
                                    const std::string& url,
                                    bool realtime, bool playTimeshiftBuffer)
{
  kodi::Log(ADDON_LOG_DEBUG, "[PLAY STREAM] url: %s", url.c_str());

  properties.emplace_back(PVR_STREAM_PROPERTY_STREAMURL, url);
  properties.emplace_back(PVR_STREAM_PROPERTY_INPUTSTREAM, "inputstream.adaptive");
  properties.emplace_back(PVR_STREAM_PROPERTY_ISREALTIMESTREAM, realtime ? "true" : "false");

  if (m_protocol == "dash")
  {
    // MPEG DASH
    kodi::Log(ADDON_LOG_DEBUG, "[PLAY STREAM] dash");
    properties.emplace_back("inputstream.adaptive.manifest_type", "mpd");
    properties.emplace_back(PVR_STREAM_PROPERTY_MIMETYPE, "application/xml+dash");

    if (playTimeshiftBuffer)
    {
       properties.emplace_back("inputstream.adaptive.play_timeshift_buffer","true");
    }

    // get widevine license
    string license = GetLicense();
    properties.emplace_back("inputstream.adaptive.license_type", "com.widevine.alpha");
    properties.emplace_back("inputstream.adaptive.license_key",
                            "https://drm.wpstr.tv/license-proxy-widevine/cenc/"
                            "|Content-Type=text%2Fxml&x-dt-custom-data=" +
                                license + "|R{SSM}|JBlicense");

    properties.emplace_back("inputstream.adaptive.manifest_update_parameter", "full");
  }
  else if (m_protocol == "hls")
  {
    // HLS
    kodi::Log(ADDON_LOG_DEBUG, "[PLAY STREAM] hls");
    properties.emplace_back("inputstream.adaptive.manifest_type", "hls");
    properties.emplace_back(PVR_STREAM_PROPERTY_MIMETYPE, "application/x-mpegURL");
    properties.emplace_back("inputstream.adaptive.manifest_update_parameter", "full");
  }
  else
  {
    kodi::Log(ADDON_LOG_ERROR, "[SetStreamProperties] called with invalid protocol '%s'", m_protocol.c_str());
  }
}

bool WaipuData::LoadChannelData(void)
{
  if (!ApiLogin())
  {
    // no valid session
    return false;
  }

  kodi::Log(ADDON_LOG_DEBUG, "[load data] Login valid -> GET CHANNELS");

  string jsonChannels = HttpGet("https://epg.waipu.tv/api/channels");
  if (jsonChannels.size() == 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "[channels] ERROR - empty response");
    return PVR_ERROR_SERVER_ERROR;
  }
  jsonChannels = "{\"result\": " + jsonChannels + "}";
  kodi::Log(ADDON_LOG_DEBUG, "[channels] length: %i;", jsonChannels.length());
  kodi::Log(ADDON_LOG_DEBUG, "[channels] %s;", jsonChannels.c_str());
  kodi::Log(ADDON_LOG_DEBUG, "[channels] %s;",
            jsonChannels.substr(jsonChannels.size() - 40).c_str());

  // parse channels
  kodi::Log(ADDON_LOG_DEBUG, "[channels] parse channels");
  Document channelsDoc;
  channelsDoc.Parse(jsonChannels.c_str());
  if (channelsDoc.GetParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[LoadChannelData] ERROR: error while parsing json");
    return PVR_ERROR_SERVER_ERROR;
  }
  kodi::Log(ADDON_LOG_DEBUG, "[channels] iterate channels");
  kodi::Log(ADDON_LOG_DEBUG, "[channels] size: %i;", channelsDoc["result"].Size());


  WaipuChannelGroup cgroup_fav;
  cgroup_fav.name = "Favoriten";

  WaipuChannelGroup cgroup_live;
  cgroup_live.name = "Live TV";

  WaipuChannelGroup cgroup_vod;
  cgroup_vod.name = "VoD";

  int i = 0;
  for (const auto& channel : channelsDoc["result"].GetArray())
  {
    string waipuid = channel["id"].GetString();
    // check if channel is part of user channels:
    bool isHD = false;
    if (find(m_user_channels_sd.begin(), m_user_channels_sd.end(), waipuid.c_str()) !=
        m_user_channels_sd.end())
    {
      isHD = false;
    }
    else if (find(m_user_channels_hd.begin(), m_user_channels_hd.end(), waipuid.c_str()) !=
             m_user_channels_hd.end())
    {
      isHD = true;
    }
    else
    {
      continue;
    }

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
    kodi::Log(ADDON_LOG_DEBUG, "[channel] channelnr(pos): %i;", waipu_channel.iChannelNumber);

    waipu_channel.tvfuse = tvfuse;
    kodi::Log(ADDON_LOG_DEBUG, "[channel] tvfuse: %i;", waipu_channel.tvfuse);

    waipu_channel.waipuID = waipuid; // waipu[id]
    kodi::Log(ADDON_LOG_DEBUG, "[channel] waipuid: %s;", waipu_channel.waipuID.c_str());

    int uniqueId = Utils::GetChannelId(waipuid.c_str());
    waipu_channel.iUniqueId = uniqueId;
    kodi::Log(ADDON_LOG_DEBUG, "[channel] id: %i;", uniqueId);

    string displayName = channel["displayName"].GetString();
    waipu_channel.strChannelName = displayName; // waipu[displayName]
    kodi::Log(ADDON_LOG_DEBUG, "[channel] name: %s;", waipu_channel.strChannelName.c_str());

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
      kodi::Log(ADDON_LOG_DEBUG, "[channel] link: %s -> %s;", rel.c_str(), href.c_str());
    }
    if (icon_hd.size() > 0 && isHD)
    {
      waipu_channel.strIconPath = icon_hd + "?width=256&height=256";
    }
    else if (icon_sd.size() > 0)
    {
      waipu_channel.strIconPath = icon_sd + "?width=256&height=256";
    }
    else if (icon.size() > 0)
    {
      waipu_channel.strIconPath = icon + "?width=256&height=256";
    }
    kodi::Log(ADDON_LOG_DEBUG, "[channel] selected channel logo: %s",
              waipu_channel.strIconPath.c_str());

    bool isFav = channel["faved"].GetBool();
    if (isFav)
    {
      // user added channel to favorites
      cgroup_fav.channels.push_back(waipu_channel);
    }
    if (tvfuse)
    {
      // Video on Demand channel
      cgroup_vod.channels.push_back(waipu_channel);
    }
    else
    {
      // Not VoD -> Live TV
      cgroup_live.channels.push_back(waipu_channel);
    }

    m_channels.push_back(waipu_channel);
  }

  m_channelGroups.push_back(cgroup_fav);
  m_channelGroups.push_back(cgroup_live);
  m_channelGroups.push_back(cgroup_vod);

  return true;
}

PVR_ERROR WaipuData::GetChannelsAmount(int& amount)
{
  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);

  amount = m_channels.size();
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannels(bool radio, kodi::addon::PVRChannelsResultSet& results)
{
  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);

  for (const auto& channel : m_channels)
  {
    if (!radio)
    {
      kodi::addon::PVRChannel kodiChannel;

      kodiChannel.SetUniqueId(channel.iUniqueId);
      kodiChannel.SetIsRadio(false);
      kodiChannel.SetChannelNumber(channel.iChannelNumber);
      kodiChannel.SetChannelName(channel.strChannelName);
      kodiChannel.SetIconPath(channel.strIconPath);
      kodiChannel.SetIsHidden(false);

      results.Add(kodiChannel);
    }
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannelStreamProperties(
    const kodi::addon::PVRChannel& channel, std::vector<kodi::addon::PVRStreamProperty>& properties)
{

  string strUrl = GetChannelStreamUrl(channel.GetUniqueId(), m_protocol, "");
  kodi::Log(ADDON_LOG_DEBUG, "Stream URL -> %s", strUrl.c_str());
  PVR_ERROR ret = PVR_ERROR_FAILED;
  if (!strUrl.empty())
  {
    SetStreamProperties(properties, strUrl, true, false);
    ret = PVR_ERROR_NO_ERROR;
  }
  return ret;
}

string WaipuData::GetChannelStreamUrl(int uniqueId, const string& protocol, const string& startTime)
{
  for (const auto& thisChannel : m_channels)
  {
    if (thisChannel.iUniqueId == (int)uniqueId)
    {
      kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] Get live url for channel %s", thisChannel.strChannelName.c_str());

      if (!ApiLogin())
      {
        // invalid
        kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] No stream login");
        return "";
      }

      // ensure device token is fresh
      RefreshDeviceCapabiltiesToken();

      string postData = "{\"stream\": { \"station\": \""+thisChannel.waipuID+"\", \"protocol\": \""+protocol+"\", \"requestMuxInstrumentation\": false";
      if (!startTime.empty())
      {
	  postData += ", \"startTime\": "+startTime;
      }
      postData += "}}";
      kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] Post data: %s", postData.c_str());

      string jsonStreamURL = HttpPost("https://stream-url-provider.waipu.tv/api/stream-url", postData, {{"Content-Type", "application/vnd.streamurlprovider.stream-url-request-v1+json"}, {"X-Device-Token", m_deviceCapabilitiesToken.token.c_str()}});

      Document streamURLDoc;
      streamURLDoc.Parse(jsonStreamURL.c_str());
      if (streamURLDoc.GetParseError())
      {
          kodi::Log(ADDON_LOG_ERROR, "[GetStreamURL] ERROR: error while parsing json");
          return "";
      }

      if(!streamURLDoc.HasMember("streamUrl"))
      {
          kodi::Log(ADDON_LOG_ERROR, "[GetStreamURL] ERROR: missing param streamUrl");
          return "";
      }

      return streamURLDoc["streamUrl"].GetString();
    }
  }
  return "";
}

PVR_ERROR WaipuData::GetChannelGroupsAmount(int& amount)
{
  amount = static_cast<int>(m_channelGroups.size());
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannelGroups(bool radio, kodi::addon::PVRChannelGroupsResultSet& results)
{
  std::vector<WaipuChannelGroup>::iterator it;
  for (it = m_channelGroups.begin(); it != m_channelGroups.end(); ++it)
  {
    kodi::addon::PVRChannelGroup kodiGroup;

    kodiGroup.SetPosition(0); /* not supported  */
    kodiGroup.SetIsRadio(false); /* is radio group */
    kodiGroup.SetGroupName(it->name);

    results.Add(kodiGroup);
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannelGroupMembers(const kodi::addon::PVRChannelGroup& group,
                                            kodi::addon::PVRChannelGroupMembersResultSet& results)
{
  for (const auto& cgroup : m_channelGroups)
  {
    if (cgroup.name != group.GetGroupName())
      continue;

    for (const auto& channel : cgroup.channels)
    {
      kodi::addon::PVRChannelGroupMember kodiGroupMember;

      kodiGroupMember.SetGroupName(group.GetGroupName());
      kodiGroupMember.SetChannelUniqueId(static_cast<unsigned int>(channel.iUniqueId));
      kodiGroupMember.SetChannelNumber(static_cast<unsigned int>(channel.iChannelNumber));

      results.Add(kodiGroupMember);
    }
    return PVR_ERROR_NO_ERROR;
  }

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetEPGForChannel(int channelUid,
                                      time_t start,
                                      time_t end,
                                      kodi::addon::PVREPGTagsResultSet& results)
{
  if (!ApiLogin())
  {
    return PVR_ERROR_SERVER_ERROR;
  }
  for (unsigned int iChannelPtr = 0; iChannelPtr < m_channels.size(); iChannelPtr++)
  {
    WaipuChannel& myChannel = m_channels.at(iChannelPtr);
    if (myChannel.iUniqueId != channelUid)
      continue;

    char startTime[100];
    std::tm* pstm = std::localtime(&start);
    // 2019-01-20T23:59:59
    std::strftime(startTime, 32, "%Y-%m-%dT%H:%M:%S", pstm);

    char endTime[100];
    std::tm* petm = std::localtime(&end);
    // 2019-01-20T23:59:59
    std::strftime(endTime, 32, "%Y-%m-%dT%H:%M:%S", petm);

    string jsonEpg =
        HttpGet("https://epg.waipu.tv/api/channels/" + myChannel.waipuID +
                "/programs?startTime=" + string(startTime) + "&stopTime=" + string(endTime));
    kodi::Log(ADDON_LOG_DEBUG, "[epg-all] %s", jsonEpg.c_str());
    if (jsonEpg.size() == 0)
    {
      kodi::Log(ADDON_LOG_ERROR, "[epg] empty server response");
      return PVR_ERROR_SERVER_ERROR;
    }
    jsonEpg = "{\"result\": " + jsonEpg + "}";

    Document epgDoc;
    epgDoc.Parse(jsonEpg.c_str());
    if (epgDoc.GetParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[GetEPG] ERROR: error while parsing json");
      return PVR_ERROR_SERVER_ERROR;
    }
    kodi::Log(ADDON_LOG_DEBUG, "[epg] iterate entries");

    kodi::Log(ADDON_LOG_DEBUG, "[epg] size: %i;", epgDoc["result"].Size());

    for (const auto& epgData : epgDoc["result"].GetArray())
    {
      kodi::addon::PVREPGTag tag;
      WaipuEPGEntry epgEntry;

      // generate a unique boadcast id
      string epg_bid = epgData["id"].GetString();
      kodi::Log(ADDON_LOG_DEBUG, "[epg] epg_bid: %s;", epg_bid.c_str());
      int dirtyID = Utils::GetIDDirty(epg_bid);
      kodi::Log(ADDON_LOG_DEBUG, "[epg] epg_bid dirty: %i;", dirtyID);
      tag.SetUniqueBroadcastId(dirtyID);
      epgEntry.iUniqueBroadcastId = dirtyID;

      // channel ID
      tag.SetUniqueChannelId(myChannel.iUniqueId);
      epgEntry.iUniqueChannelId = myChannel.iUniqueId;

      // add streamUrlProvider if it is video on demand
      if (myChannel.tvfuse && epgData.HasMember("streamUrlProvider") && !epgData["streamUrlProvider"].IsNull())
      {
        string streamUrlProvider = epgData["streamUrlProvider"].GetString();
        kodi::Log(ADDON_LOG_DEBUG, "[epg] streamUrlProvider: %s;", streamUrlProvider.c_str());
        epgEntry.streamUrlProvider = streamUrlProvider;
      }

      // is recordable
      bool isRecordable = !epgData["recordingForbidden"].GetBool();
      kodi::Log(ADDON_LOG_DEBUG, "[epg] recordable: %i;", isRecordable);
      epgEntry.isRecordable = isRecordable;

      // instantRestartAllowed
      bool instantRestartAllowed = !epgData["instantRestartForbidden"].GetBool();
      kodi::Log(ADDON_LOG_DEBUG, "[epg] instantRestartAllowed: %i;", instantRestartAllowed);
      epgEntry.instantRestartAllowed = instantRestartAllowed;

      m_epgEntries.push_back(epgEntry);

      // set title
      tag.SetTitle(epgData["title"].GetString());
      kodi::Log(ADDON_LOG_DEBUG, "[epg] title: %s;", epgData["title"].GetString());

      // set startTime
      string startTime = epgData["startTime"].GetString();
      tag.SetStartTime(Utils::StringToTime(startTime));

      // set endTime
      string endTime = epgData["stopTime"].GetString();
      tag.SetEndTime(Utils::StringToTime(endTime));

      // tag.SetPlotOutline(myTag.strPlotOutline);

      // set description
      if (epgData.HasMember("description") && !epgData["description"].IsNull())
      {
        tag.SetPlot(epgData["description"].GetString());
        kodi::Log(ADDON_LOG_DEBUG, "[epg] description: %s;", epgData["description"].GetString());
      }

      // tag.SetIconPath(myTag.strIconPath);

      tag.SetFlags(EPG_TAG_FLAG_UNDEFINED);

      // iSeriesNumber
      if (epgData.HasMember("season") && !epgData["season"].IsNull())
      {
        tag.SetSeriesNumber(
            Utils::stoiDefault(epgData["season"].GetString(), EPG_TAG_INVALID_SERIES_EPISODE));
      }
      else
      {
        tag.SetSeriesNumber(EPG_TAG_INVALID_SERIES_EPISODE);
      }
      // episodeNumber
      if (epgData.HasMember("episode") && epgData["episode"].IsString())
      {
        tag.SetEpisodeNumber(
            Utils::stoiDefault(epgData["episode"].GetString(), EPG_TAG_INVALID_SERIES_EPISODE));
      }
      else
      {
        tag.SetEpisodeNumber(EPG_TAG_INVALID_SERIES_EPISODE);
      }
      tag.SetEpisodePartNumber(EPG_TAG_INVALID_SERIES_EPISODE);

      // episodeName
      if (epgData.HasMember("episodeTitle") && !epgData["episodeTitle"].IsNull())
      {
        tag.SetEpisodeName(epgData["episodeTitle"].GetString());
      }

      // year
      if (epgData.HasMember("year") && !epgData["year"].IsNull())
      {
        tag.SetYear(Utils::stoiDefault(epgData["year"].GetString(), 1970));
      }

      // genre
      if (epgData.HasMember("genreDisplayName") && !epgData["genreDisplayName"].IsNull())
      {
        string genreStr = epgData["genreDisplayName"].GetString();
        int genre = m_categories.Category(genreStr);
        if (genre)
        {
          tag.SetGenreSubType(genre & 0x0F);
          tag.SetGenreType(genre & 0xF0);
        }
        else
        {
          tag.SetGenreType(EPG_GENRE_USE_STRING);
          tag.SetGenreSubType(0); /* not supported */
          tag.SetGenreDescription(genreStr);
        }
      }

      results.Add(tag);
    }
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::IsEPGTagRecordable(const kodi::addon::PVREPGTag& tag, bool& isRecordable)
{
  if (m_account_hours_recording == 0)
  {
    // recording option not available
    isRecordable = false;
    return PVR_ERROR_NO_ERROR;
  }

  time_t current_time;
  time(&current_time);
  if (tag.GetEndTime() < current_time)
  {
    // if tag is in past, no recording is possible
    isRecordable = false;
    return PVR_ERROR_NO_ERROR;
  }

  for (const auto& epgEntry : m_epgEntries)
  {
    if (epgEntry.iUniqueBroadcastId != tag.GetUniqueBroadcastId())
      continue;
    if (epgEntry.iUniqueChannelId != tag.GetUniqueChannelId())
      continue;
    isRecordable = epgEntry.isRecordable;
    return PVR_ERROR_NO_ERROR;
  }

  isRecordable = false;
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::IsEPGTagPlayable(const kodi::addon::PVREPGTag& tag, bool& isPlayable)
{
  isPlayable = false;

  // check if channel is onDemand and allows playback
  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId != tag.GetUniqueChannelId())
      continue;
    isPlayable = channel.tvfuse;
    if (isPlayable) {
      return PVR_ERROR_NO_ERROR;
    }
  }

  // check if program is running and replay allowed
  auto current_time = time(NULL);
  if (m_account_replay_allowed && current_time > tag.GetStartTime() && current_time < tag.GetEndTime())
  {
      // tag is now running, check if epg tag allows replay
      for (const auto& epgEntry : m_epgEntries)
      {
        if (epgEntry.iUniqueBroadcastId != tag.GetUniqueBroadcastId())
          continue;
        if (epgEntry.iUniqueChannelId != tag.GetUniqueChannelId())
          continue;
        isPlayable = epgEntry.instantRestartAllowed;
        return PVR_ERROR_NO_ERROR;
      }
  }

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetEPGTagStreamProperties(
    const kodi::addon::PVREPGTag& tag, std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  kodi::Log(ADDON_LOG_DEBUG, "[EPG TAG] play it...");

  string strUrl = GetEPGTagURL(tag, m_protocol);
  if (strUrl.empty())
  {
    return PVR_ERROR_FAILED;
  }

  SetStreamProperties(properties, strUrl, true, true);

  return PVR_ERROR_NO_ERROR;
}

string WaipuData::GetEPGTagURL(const kodi::addon::PVREPGTag& tag, const string& protocol)
{
  ApiLogin();

  for (const auto& epgEntry : m_epgEntries)
  {
    if (epgEntry.iUniqueChannelId != tag.GetUniqueChannelId())
      continue;
    if (epgEntry.iUniqueBroadcastId != tag.GetUniqueBroadcastId())
      continue;

    string url = epgEntry.streamUrlProvider;
    if (!url.empty())
    {
      kodi::Log(ADDON_LOG_DEBUG, "play epgTAG -> %s", tag.GetTitle().c_str());
      kodi::Log(ADDON_LOG_DEBUG, "play url -> %s", url.c_str());

      string tag_resp = HttpGet(url);
      kodi::Log(ADDON_LOG_DEBUG, "tag resp -> %s", tag_resp.c_str());

      Document tagDoc;
      tagDoc.Parse(tag_resp.c_str());
      if (tagDoc.GetParseError())
      {
        kodi::Log(ADDON_LOG_ERROR, "[getEPGTagURL] ERROR: error while parsing json");
        return "";
      }
      kodi::Log(ADDON_LOG_DEBUG, "[tag] streams");
      // check if streams there
      if (tagDoc.HasMember("player") && tagDoc["player"].HasMember("mpd"))
      {
        string mpdUrl = tagDoc["player"]["mpd"].GetString();
        kodi::Log(ADDON_LOG_DEBUG, "mpd url -> %s", mpdUrl.c_str());
        return mpdUrl;
      }
    }

    // fallback to replay playback
    string startTime = std::to_string(tag.GetStartTime());
    return GetChannelStreamUrl(tag.GetUniqueChannelId(), protocol, startTime);
  }
  return "";
}

PVR_ERROR WaipuData::GetRecordingsAmount(bool deleted, int& amount)
{
  amount = m_recordings_count;
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetRecordings(bool deleted, kodi::addon::PVRRecordingsResultSet& results)
{
  if (!ApiLogin())
  {
    return PVR_ERROR_SERVER_ERROR;
  }
  m_active_recordings_update = true;

  string jsonRecordings = HttpGet("https://recording.waipu.tv/api/recordings",{{"Accept", "application/vnd.waipu.recordings-v2+json"}});
  kodi::Log(ADDON_LOG_DEBUG, "[recordings] %s", jsonRecordings.c_str());

  jsonRecordings = "{\"result\": " + jsonRecordings + "}";

  Document recordingsDoc;
  recordingsDoc.Parse(jsonRecordings.c_str());
  if (recordingsDoc.GetParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[GetRecordings] ERROR: error while parsing json");
    return PVR_ERROR_SERVER_ERROR;
  }
  kodi::Log(ADDON_LOG_DEBUG, "[recordings] iterate entries");

  kodi::Log(ADDON_LOG_DEBUG, "[recordings] size: %i;", recordingsDoc["result"].Size());

  int recordings_count = 0;

  for (const auto& recording : recordingsDoc["result"].GetArray())
  {
    // skip not FINISHED entries
    string status = recording["status"].GetString();
    if (status != "FINISHED")
      continue;

    // new tag
    kodi::addon::PVRRecording tag;

    tag.SetIsDeleted(false);

    // set recording id
    string rec_id = recording["id"].GetString();
    tag.SetRecordingId(rec_id);

    // playcount
    if (recording.HasMember("watched") && recording["watched"].GetBool())
    {
      tag.SetPlayCount(1);
    }
    else
    {
      tag.SetPlayCount(0);
    }

    const Value& epgData = recording["epgData"];

    // set recording title
    string rec_title = epgData["title"].GetString();
    tag.SetTitle(rec_title);
    // set folder; test
    tag.SetDirectory(rec_title);

    // set image
    if (epgData.HasMember("previewImages") && epgData["previewImages"].IsArray() &&
        epgData["previewImages"].Size() > 0)
    {
      string rec_img = epgData["previewImages"][0].GetString();
      rec_img = rec_img + "?width=256&height=256";
      tag.SetIconPath(rec_img);
      tag.SetThumbnailPath(rec_img);
    }

    // duration
    if (epgData.HasMember("duration") && !epgData["duration"].IsNull())
    {
      string rec_dur = epgData["duration"].GetString();
      tag.SetDuration(Utils::stoiDefault(rec_dur, 0) * 60);
    }

    // iSeriesNumber
    if (epgData.HasMember("season") && !epgData["season"].IsNull())
    {
      tag.SetSeriesNumber(
          Utils::stoiDefault(epgData["season"].GetString(), PVR_RECORDING_INVALID_SERIES_EPISODE));
    }
    else
    {
      tag.SetSeriesNumber(PVR_RECORDING_INVALID_SERIES_EPISODE);
    }

    // episodeNumber
    if (epgData.HasMember("episode") && !epgData["episode"].IsNull())
    {
      tag.SetEpisodeNumber(
          Utils::stoiDefault(epgData["episode"].GetString(), PVR_RECORDING_INVALID_SERIES_EPISODE));
    }
    else
    {
      tag.SetEpisodeNumber(PVR_RECORDING_INVALID_SERIES_EPISODE);
    }

    // episodeName
    if (epgData.HasMember("episodeTitle") && !epgData["episodeTitle"].IsNull())
    {
      string rec_episodename = epgData["episodeTitle"].GetString();
      tag.SetEpisodeName(rec_episodename);
    }

    // year
    if (epgData.HasMember("year") && !epgData["year"].IsNull())
    {
      string rec_year = epgData["year"].GetString();
      tag.SetYear(Utils::stoiDefault(rec_year, 1970));
    }

    // get recording time
    if (recording.HasMember("startTime") && !recording["startTime"].IsNull())
    {
      string recordingTime = recording["startTime"].GetString();
      tag.SetRecordingTime(Utils::StringToTime(recordingTime));
    }

    // get plot
    if (epgData.HasMember("description") && !epgData["description"].IsNull())
    {
      string rec_plot = epgData["description"].GetString();
      tag.SetPlot(rec_plot);
    }

    // genre
    if (epgData.HasMember("genreDisplayName") && !epgData["genreDisplayName"].IsNull())
    {
      string genreStr = epgData["genreDisplayName"].GetString();
      int genre = m_categories.Category(genreStr);
      if (genre)
      {
        tag.SetGenreSubType(genre & 0x0F);
        tag.SetGenreType(genre & 0xF0);
      }
      else
      {
        tag.SetGenreType(EPG_GENRE_USE_STRING);
        tag.SetGenreSubType(0); /* not supported */
        tag.SetGenreDescription(genreStr);
      }
    }

    // epg mapping
    if (epgData.HasMember("id") && !epgData["id"].IsNull())
    {
      string epg_id = epgData["id"].GetString();
      int dirtyID = Utils::GetIDDirty(epg_id);
      tag.SetEPGEventId(dirtyID);
    }

    ++recordings_count;
    results.Add(tag);
  }
  m_recordings_count = recordings_count;
  m_active_recordings_update = false;

  return PVR_ERROR_NO_ERROR;
}

std::string WaipuData::GetRecordingURL(const kodi::addon::PVRRecording& recording,
                                       const string& protocol)
{
  ApiLogin();

  string recording_id = recording.GetRecordingId();
  kodi::Log(ADDON_LOG_DEBUG, "play recording -> %s", recording_id.c_str());

  string rec_resp = HttpGet("https://recording.waipu.tv/api/recordings/" + recording_id);
  kodi::Log(ADDON_LOG_DEBUG, "recording resp -> %s", rec_resp.c_str());

  Document recordingDoc;
  recordingDoc.Parse(rec_resp.c_str());
  if (recordingDoc.GetParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[getRecordingURL] ERROR: error while parsing json");
    return "";
  }
  kodi::Log(ADDON_LOG_DEBUG, "[recording] streams");
  // check if streams there
  if (!recordingDoc.HasMember("streamingDetails") ||
      !recordingDoc["streamingDetails"].HasMember("streams"))
  {
    return "";
  }

  kodi::Log(ADDON_LOG_DEBUG, "[recordings] size: %i;",
            recordingDoc["streamingDetails"]["streams"].Size());

  string protocol_fix = protocol == "dash" ? "MPEG_DASH" : "HLS";

  for (const auto& stream : recordingDoc["streamingDetails"]["streams"].GetArray())
  {
    string current_protocol = stream["protocol"].GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[stream] protocol: %s;", current_protocol.c_str());
    if (current_protocol == protocol_fix)
    {
      string href = stream["href"].GetString();
      kodi::Log(ADDON_LOG_DEBUG, "[stream] selected href: %s;", href.c_str());
      return href;
    }
  }
  return "";
}

PVR_ERROR WaipuData::DeleteRecording(const kodi::addon::PVRRecording& recording)
{
  if (ApiLogin())
  {
    string recording_id = recording.GetRecordingId();
    string request_data = "{\"ids\":[\"" + recording_id + "\"]}";
    kodi::Log(ADDON_LOG_DEBUG, "[delete recording] req: %s;", request_data.c_str());
    string deleted = HttpDelete("https://recording.waipu.tv/api/recordings", request_data.c_str(), {{"Content-Type","application/vnd.waipu.pvr-recording-ids-v2+json"}});
    kodi::Log(ADDON_LOG_DEBUG, "[delete recording] response: %s;", deleted.c_str());
    kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
    return PVR_ERROR_NO_ERROR;
  }
  return PVR_ERROR_FAILED;
}

PVR_ERROR WaipuData::GetRecordingStreamProperties(
    const kodi::addon::PVRRecording& recording,
    std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  kodi::Log(ADDON_LOG_DEBUG, "[recordings] play it...");

  string strUrl = GetRecordingURL(recording, m_protocol);
  if (strUrl.empty())
  {
    return PVR_ERROR_FAILED;
  }

  SetStreamProperties(properties, strUrl, true, false);

  return PVR_ERROR_NO_ERROR;
}

void WaipuData::AddTimerType(std::vector<kodi::addon::PVRTimerType>& types, int id, int attributes)
{
  kodi::addon::PVRTimerType type;
  type.SetId(static_cast<unsigned int>(id));
  type.SetAttributes(static_cast<unsigned int>(attributes));
  types.emplace_back(type);
}

PVR_ERROR WaipuData::GetTimerTypes(std::vector<kodi::addon::PVRTimerType>& types)
{
  //AddTimerType(types, 1, PVR_TIMER_TYPE_ATTRIBUTE_NONE);
  AddTimerType(types, 1,
               PVR_TIMER_TYPE_SUPPORTS_READONLY_DELETE | PVR_TIMER_TYPE_SUPPORTS_CHANNELS |
                   PVR_TIMER_TYPE_SUPPORTS_START_TIME | PVR_TIMER_TYPE_SUPPORTS_END_TIME);
  //AddTimerType(types, 2, PVR_TIMER_TYPE_IS_MANUAL);
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetTimersAmount(int& amount)
{
  amount = m_timers_count;
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetTimers(kodi::addon::PVRTimersResultSet& results)
{
  if (!ApiLogin())
  {
    return PVR_ERROR_SERVER_ERROR;
  }

  string jsonRecordings = HttpGet("https://recording.waipu.tv/api/recordings", {{"Accept", "application/vnd.waipu.recordings-v2+json"}});
  kodi::Log(ADDON_LOG_DEBUG, "[Timers] %s", jsonRecordings.c_str());

  jsonRecordings = "{\"result\": " + jsonRecordings + "}";

  Document timersDoc;
  timersDoc.Parse(jsonRecordings.c_str());
  if (timersDoc.GetParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[timers] ERROR: error while parsing json");
    return PVR_ERROR_SERVER_ERROR;
  }
  kodi::Log(ADDON_LOG_DEBUG, "[timers] iterate entries");
  kodi::Log(ADDON_LOG_DEBUG, "[timers] size: %i;", timersDoc["result"].Size());

  int recordings_count = 0;
  int timers_count = 0;

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
    kodi::addon::PVRTimer tag;
    ++timers_count;

    if (status == "SCHEDULED")
    {
      tag.SetState(PVR_TIMER_STATE_SCHEDULED);
    }
    else if (status == "RECORDING")
    {
      tag.SetState(PVR_TIMER_STATE_RECORDING);
    }
    tag.SetLifetime(0);
    tag.SetTimerType(1); // not the best way to do it...

    // set recording id
    string rec_id = timer["id"].GetString();
    tag.SetClientIndex(Utils::stoiDefault(rec_id, 0));
    tag.SetEPGUid(Utils::stoiDefault(rec_id, 0));

    // channelid
    if (timer.HasMember("channelId") && !timer["channelId"].IsNull())
    {
      string channel_name = timer["channelId"].GetString();
      for (unsigned int iChannelPtr = 0; iChannelPtr < m_channels.size(); iChannelPtr++)
      {
        WaipuChannel& myChannel = m_channels.at(iChannelPtr);
        if (myChannel.waipuID != channel_name)
          continue;
        tag.SetClientChannelUid(myChannel.iUniqueId);
        break;
      }
    }

    const Value& epgData = timer["epgData"];

    // set recording title
    string rec_title = epgData["title"].GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[timers] Add: %s;", rec_title.c_str());
    tag.SetTitle(rec_title);

    // get recording time
    if (timer.HasMember("startTime") && !timer["startTime"].IsNull())
    {
      string startTime = timer["startTime"].GetString();
      tag.SetStartTime(Utils::StringToTime(startTime));
    }
    if (timer.HasMember("stopTime") && !timer["stopTime"].IsNull())
    {
      string endTime = timer["stopTime"].GetString();
      tag.SetEndTime(Utils::StringToTime(endTime));
    }

    // get plot
    if (epgData.HasMember("description") && !epgData["description"].IsNull())
    {
      string rec_plot = epgData["description"].GetString();
      tag.SetSummary(rec_plot);
    }

    // epg mapping
    if (epgData.HasMember("id") && !epgData["id"].IsNull())
    {
      string epg_id = epgData["id"].GetString();
      int dirtyID = Utils::GetIDDirty(epg_id);
      tag.SetEPGUid(dirtyID);
    }

    results.Add(tag);
  }

  if (recordings_count != m_recordings_count && !m_active_recordings_update)
  {
    // we detected another amount of recordings.
    // tell kodi about it
    m_active_recordings_update = true;
    kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
  }
  m_timers_count = timers_count;

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::DeleteTimer(const kodi::addon::PVRTimer& timer, bool forceDelete)
{
  if (ApiLogin())
  {
    int timer_id = timer.GetClientIndex();
    string request_data = "{\"ids\":[\"" + to_string(timer_id) + "\"]}";
    kodi::Log(ADDON_LOG_DEBUG, "[delete timer] req: %s;", request_data.c_str());
    string deleted = HttpDelete("https://recording.waipu.tv/api/recordings", request_data.c_str(),{{"Content-Type", "application/vnd.waipu.pvr-recording-ids-v2+json"}});
    kodi::Log(ADDON_LOG_DEBUG, "[delete timer] response: %s;", deleted.c_str());
    kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
    return PVR_ERROR_NO_ERROR;
  }
  return PVR_ERROR_FAILED;
}

PVR_ERROR WaipuData::AddTimer(const kodi::addon::PVRTimer& timer)
{
  if (timer.GetEPGUid() <= EPG_TAG_INVALID_UID)
  {
    // we currently only support epg based
    return PVR_ERROR_REJECTED;
  }

  if (ApiLogin())
  {
    // {"programId":"_1051966761","channelId":"PRO7","startTime":"2019-02-03T18:05:00.000Z","stopTime":"2019-02-03T19:15:00.000Z"}
    for (const auto& channel : m_channels)
    {
      if (channel.iUniqueId != timer.GetClientChannelUid())
        continue;
      string postData = "{\"programId\":\"_" + to_string(timer.GetEPGUid()) +
                        "\",\"channelId\":\"" + channel.waipuID + "\"" + "}";
      string recordResp = HttpPost("https://recording.waipu.tv/api/recordings", postData, {{"Content-Type", "application/vnd.waipu.start-recording-v2+json"}});
      kodi::Log(ADDON_LOG_DEBUG, "[add timer] response: %s;", recordResp.c_str());
      kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
      return PVR_ERROR_NO_ERROR;
    }
  }
  return PVR_ERROR_FAILED;
}

PVR_ERROR WaipuData::GetDriveSpace(uint64_t& total, uint64_t& used)
{
  total = m_account_hours_recording * 1024 * 1024;
  used =  0;
  return PVR_ERROR_NO_ERROR;
}

ADDONCREATOR(WaipuData)
