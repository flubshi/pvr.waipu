/*
 *      Copyright (C) 2019 - 2021 flubshi
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
#include "kodi/tools/StringUtils.h"
#include "kodi/General.h"
#include <kodi/gui/dialogs/Progress.h>

#include "rapidjson/document.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <regex>
#include <thread>

std::mutex WaipuData::mutex;

// BEGIN CURL helpers from zattoo addon:
std::string WaipuData::HttpGet(const std::string& url, const std::map<std::string,std::string>& headers)
{
  return HttpRequest("GET", url, "", headers);
}

std::string WaipuData::HttpDelete(const std::string& url, const std::string& postData, const std::map<std::string,std::string>& headers)
{
  return HttpRequest("DELETE", url, postData, headers);
}

std::string WaipuData::HttpPost(const std::string& url, const std::string& postData, const std::map<std::string,std::string>& headers)
{
  return HttpRequest("POST", url, postData, headers);
}

std::string WaipuData::HttpRequest(const std::string& action, const std::string& url, const std::string& postData, const std::map<std::string,std::string>& headers)
{
  Curl curl;
  int statusCode;

  for (auto const& header : headers)
  {
    curl.AddHeader(header.first, header.second);
  }

  curl.AddHeader("Authorization", "Bearer " + m_accessToken.getToken());


  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  kodi::Log(ADDON_LOG_DEBUG, "HTTP User-Agent: %s.", WAIPU_USER_AGENT.c_str());

  return HttpRequestToCurl(curl, action, url, postData, statusCode);
}

std::string WaipuData::HttpRequestToCurl(
    Curl& curl, const std::string& action, const std::string& url, const std::string& postData, int& statusCode)
{
  kodi::Log(ADDON_LOG_DEBUG, "Http-Request: %s %s.", action.c_str(), url.c_str());
  std::string content;
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
  if (statusCode >= 200 && statusCode < 300)
    return content;

  kodi::Log(ADDON_LOG_ERROR, "[Http-GET-Request] error. status: %i, body: %s", statusCode,
            content.c_str());
  return "";
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
  else if (m_provider == WAIPU_PROVIDER_O2)
  {
    login_result = DeviceLogin("o2");
  }else
  {
    // waipu oauth device workflow
    login_result = DeviceLogin("waipu");
  }
  if(login_result){
    // login okay, reset counter
    m_login_failed_counter = 0;
  }else if (m_login_status != WAIPU_LOGIN_STATUS::NO_NETWORK) {
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

bool WaipuData::ParseAccessToken()
{
  if(!m_accessToken.isInitialized() || m_accessToken.isExpired())
  {
    m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
    kodi::Log(ADDON_LOG_ERROR, "[jwt_doc] ERROR: error while parsing json (error/expired)");
    return false;
  }

  m_userhandle = m_accessToken.parsedToken["userHandle"].GetString();
  kodi::Log(ADDON_LOG_DEBUG, "[jwt] userHandle: %s", m_userhandle.c_str());
  // generate the license
  std::string license_plain = "{\"merchant\" : \"exaring\", \"sessionId\" : \"default\", "
                         "\"userId\" : \"" +
                         m_userhandle + "\"}";
  kodi::Log(ADDON_LOG_DEBUG, "[jwt] license_plain: %s", license_plain.c_str());
  m_license = base64_encode(license_plain.c_str(), license_plain.length());
  kodi::Log(ADDON_LOG_DEBUG, "[jwt] license: %s", m_license.c_str());
  // get user channels
  m_user_channels_sd.clear();
  m_user_channels_hd.clear();
  for (const auto& user_channel : m_accessToken.parsedToken["userAssets"]["channels"]["SD"].GetArray())
  {
    std::string user_channel_s = user_channel.GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] SD channel: %s", user_channel_s.c_str());
    m_user_channels_sd.emplace_back(user_channel_s);
  }
  for (const auto& user_channel : m_accessToken.parsedToken["userAssets"]["channels"]["HD"].GetArray())
  {
    std::string user_channel_s = user_channel.GetString();
    m_user_channels_hd.emplace_back(user_channel_s);
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] HD channel: %s", user_channel_s.c_str());
  }
  if(m_accessToken.parsedToken["userAssets"].HasMember("instantRestart")){
    m_account_replay_allowed = m_accessToken.parsedToken["userAssets"]["instantRestart"].GetBool();
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] Account InstantStart: %i", m_account_replay_allowed);
  }
  if(m_accessToken.parsedToken["userAssets"].HasMember("hoursRecording")){
    m_account_hours_recording = m_accessToken.parsedToken["userAssets"]["hoursRecording"].GetInt();
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] Account HoursReording: %i", m_account_hours_recording);
  }

  m_login_status = WAIPU_LOGIN_STATUS::OK;
  return true;
}

const std::map<std::string,std::string> WaipuData::GetOAuthDeviceCode(const std::string& tenant)
{
  kodi::Log(ADDON_LOG_DEBUG, "[device] GetOAuthDeviceCode, tenant '%s'", tenant.c_str());
  std::string jsonString;
  std::map<std::string,std::string> result;
  // curl request
  Curl curl;
  int statusCode = 0;
  curl.AddHeader("Authorization", "Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
  curl.AddHeader("Content-Type", "application/json");
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  jsonString = HttpRequestToCurl(curl, "POST", "https://auth.waipu.tv/oauth/device_authorization",
                               "{\"client_id\":\""+tenant+"\", \"waipu_device_id\":\""+m_device_id+"\"}", statusCode);

  kodi::Log(ADDON_LOG_DEBUG, "[login check] GetOAuthDeviceCode-response: (HTTP %i) %s;", statusCode, jsonString.c_str());

  if (jsonString.empty() && statusCode == -1)
  {
    // no network connection?
    kodi::Log(ADDON_LOG_ERROR, "[GetOAuthDeviceCode] no network connection");
    return result;
  }


  if (!jsonString.empty())
  {
    rapidjson::Document doc;
    doc.Parse(jsonString.c_str());
    if (doc.GetParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[GetOAuthDeviceCode] ERROR: error while parsing json");
      return result;
    }
    for(const std::string key : {"verification_uri", "user_code", "device_code", "verification_uri_complete"})
    {
      if (doc.HasMember(key.c_str()))
      {
	const std::string value = doc[key.c_str()].GetString();
	kodi::Log(ADDON_LOG_DEBUG, "[GetOAuthDeviceCode] found %s: %s", key.c_str(), value.c_str());
	result[key] = value;
      }
    }
  }
    return result;
}

const std::map<std::string,std::string> WaipuData::CheckOAuthState(const std::string& device_code)
{
  kodi::Log(ADDON_LOG_DEBUG, "[device] CheckOAuthState");
  std::string jsonString;
  std::map<std::string,std::string> result;
  // curl request
  Curl curl;
  int statusCode = 0;
  curl.AddHeader("Authorization", "Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  jsonString = HttpRequestToCurl(curl, "POST", "https://auth.waipu.tv/oauth/token",
                               "device_code="+device_code+"&grant_type=urn:ietf:params:oauth:grant-type:device_code&waipu_device_id="+m_device_id, statusCode);

  kodi::Log(ADDON_LOG_DEBUG, "[login check] CheckOAuthState-response: (HTTP %i) %s;", statusCode, jsonString.c_str());

  if (jsonString.empty() && statusCode == -1)
  {
    // no network connection?
    kodi::Log(ADDON_LOG_ERROR, "[CheckOAuthState] no network connection");
    return result;
  }


  if (!jsonString.empty())
  {
    rapidjson::Document doc;
    doc.Parse(jsonString.c_str());
    if (doc.GetParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[CheckOAuthState] ERROR: error while parsing json");
      return result;
    }
    for(const std::string key : {"access_token", "refresh_token", "token_type"})
    {
      if (doc.HasMember(key.c_str()))
      {
	const std::string value = doc[key.c_str()].GetString();
	kodi::Log(ADDON_LOG_DEBUG, "[CheckOAuthState] found %s: %s", key.c_str(), value.c_str());
	result[key] = value;
      }
    }
  }
    return result;
}

bool WaipuData::OAuthRequest(const std::string& postData)
{
  kodi::Log(ADDON_LOG_DEBUG, "[OAuthRequest] Body: %s;", postData.c_str());
  std::string jsonString;
  // curl request
  Curl curl;
  int statusCode = 0;
  curl.AddHeader("Authorization", "Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
//  curl.AddHeader("Content-Type", "application/x-www-form-urlencoded");
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  jsonString = HttpRequestToCurl(curl, "POST", "https://auth.waipu.tv/oauth/token", postData, statusCode);

  kodi::Log(ADDON_LOG_DEBUG, "[OAuthRequest] Login-response: (HTTP %i) %s;", statusCode,
            jsonString.c_str());

  if (jsonString.empty() && statusCode == -1)
  {
    // no network connection?
    m_login_status = WAIPU_LOGIN_STATUS::NO_NETWORK;
    kodi::Log(ADDON_LOG_ERROR, "[OAuthRequest] no network connection");
    return false;
  }
  else if (statusCode == 401)
  {
    if (m_refreshToken.isInitialized() && !m_refreshToken.isExpired())
    {
      // we used invalid refresh token, delete it
      m_refreshToken = JWT();
      m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
      return false;
    }
    // invalid credentials
    m_login_status = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
    return false;
  }

  if (!jsonString.empty())
  {
    rapidjson::Document doc;
    doc.Parse(jsonString.c_str());
    if (doc.GetParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[OAuthRequest] ERROR: error while parsing json");
      m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
      return false;
    }

    if (doc.HasMember("error") && doc["error"] == "invalid_request")
    {
      kodi::Log(ADDON_LOG_ERROR, "[OAuthRequest] ERROR: invalid credentials?");
      m_login_status = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
      return false;
    }
    else if (doc.HasMember("error"))
    {
      // unhandled error -> handle if known
      std::string err = doc["error"].GetString();
      kodi::Log(ADDON_LOG_ERROR, "[OAuthRequest] ERROR: (%s)", err.c_str());
      m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
      return false;
    }

    m_accessToken = JWT(doc["access_token"].GetString());
    kodi::Log(ADDON_LOG_DEBUG, "[OAuthRequest] accessToken: %s;", m_accessToken.getToken().c_str());
    std::string refresh_token = doc["refresh_token"].GetString();
    if (!refresh_token.empty())
    {
      m_refreshToken = JWT(refresh_token);
      kodi::addon::SetSettingString("refresh_token", refresh_token);
      kodi::Log(ADDON_LOG_DEBUG, "[OAuthRequest] refreshToken: %s;", refresh_token.c_str());
    }

    return ParseAccessToken();
  }
  // no valid session?
  m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
  return false;
}


bool WaipuData::DeviceLogin(const std::string& tenant)
{
  kodi::Log(ADDON_LOG_DEBUG, "[DeviceLogin] waipu.tv DeviceLogin, tenant '%s' ...", tenant.c_str());

  time_t currTime;
  time(&currTime);
  kodi::Log(ADDON_LOG_DEBUG, "[token] current time %i", currTime);
  kodi::Log(ADDON_LOG_DEBUG, "[token] expire  time %i", m_accessToken.getExp());
  std::lock_guard<std::mutex> lock(mutex);
  if (m_accessToken.isInitialized() && !m_accessToken.isExpired(20 * 60))
  {
    // API token exists and is valid, more than x in future
    kodi::Log(ADDON_LOG_DEBUG, "[login check] old token still valid");
    return true;
  }

  if (m_refreshToken.isInitialized() && !m_refreshToken.isExpired())
  {
    // Since the refresh token is valid for a long time, we do not check expiration for now
    // refresh API token
    std::string req = "refresh_token=" + Utils::UrlEncode(m_refreshToken.getToken())
               + "&grant_type=refresh_token"
               + "&waipu_device_id=" + m_device_id;
    kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-Request (refresh): %s;", req.c_str());
    return OAuthRequest(req);
  }

  const std::map<std::string,std::string> deviceCodeMap = GetOAuthDeviceCode(tenant);
  if (!deviceCodeMap.count("verification_uri") || !deviceCodeMap.count("user_code") || !deviceCodeMap.count("device_code"))
  {
	kodi::Log(ADDON_LOG_DEBUG, "OAuth missing response");
	return false;
  }
  std::string code_req = "device_code="+deviceCodeMap.find("device_code")->second+"&grant_type=urn:ietf:params:oauth:grant-type:device_code&waipu_device_id="+m_device_id;
  kodi::Log(ADDON_LOG_DEBUG, "Create Login Progress");
  kodi::gui::dialogs::CProgress *progress = new kodi::gui::dialogs::CProgress;
  progress->SetHeading("pvr.waipu - "+tenant+" Login");
  progress->SetLine(1, "1) "+kodi::addon::GetLocalizedString(30039)+" "+deviceCodeMap.find("verification_uri")->second);
  progress->SetLine(2, "2) "+kodi::addon::GetLocalizedString(30040));
  progress->SetLine(3, "3) "+kodi::addon::GetLocalizedString(30041)+" "+deviceCodeMap.find("user_code")->second);
  progress->SetCanCancel(true);
  progress->ShowProgressBar(true);
  progress->Open();
  for (unsigned int i = 0; i < 100; i += 1)
  {
    progress->SetPercentage(i);
    if(OAuthRequest(code_req))
    {
      delete progress;
      kodi::Log(ADDON_LOG_DEBUG, "OAuth success!");
      return true;
    }

    kodi::Log(ADDON_LOG_DEBUG, "OAuth pending");

    if (progress->IsCanceled())
    {
	progress->Abort();
	delete progress;
	m_login_status = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
        kodi::Log(ADDON_LOG_DEBUG, "OAuth login canceled");
        return false;
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));
  }
  m_login_status = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
  progress->Abort();
  delete progress;
  return false;
}


bool WaipuData::WaipuLogin()
{
  kodi::Log(ADDON_LOG_DEBUG, "[login check] WAIPU.TV LOGIN...");

  time_t currTime;
  time(&currTime);
  kodi::Log(ADDON_LOG_DEBUG, "[token] current time %i", currTime);
  kodi::Log(ADDON_LOG_DEBUG, "[token] expire  time %i", m_accessToken.getExp());
  std::lock_guard<std::mutex> lock(mutex);
  if (m_accessToken.isInitialized() && !m_accessToken.isExpired(20 * 60))
  {
    // API token exists and is valid, more than x in future
    kodi::Log(ADDON_LOG_DEBUG, "[login check] old token still valid");
    return true;
  }

  if (m_refreshToken.isInitialized() && !m_refreshToken.isExpired())
  {
    // Since the refresh token is valid for a long time, we do not check expiration for now
    // refresh API token
    std::string req = "refresh_token=" + Utils::UrlEncode(m_refreshToken.getToken())
               + "&grant_type=refresh_token"
               + "&waipu_device_id=" + m_device_id;
    kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-Request (refresh): %s;", req.c_str());
    return OAuthRequest(req);
  }
  else
  {
    // get API by login user/pw
      std::string req = "username=" + Utils::UrlEncode(m_username)
               + "&password=" + Utils::UrlEncode(m_password)
               + "&grant_type=password"
               + "&waipu_device_id=" + m_device_id;
    kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-Request (user/pw)");
    return OAuthRequest(req);
  }
}


bool WaipuData::RefreshDeviceCapabiltiesToken()
{
  kodi::Log(ADDON_LOG_DEBUG, "%s - Creating the waipu.tv PVR add-on", __FUNCTION__);

  kodi::Log(ADDON_LOG_DEBUG, "[device token] expire time %i", m_deviceCapabilitiesToken.getExp());
  if (m_deviceCapabilitiesToken.isInitialized() && !m_deviceCapabilitiesToken.isExpired(5*60))
  {
    // device token exists and is valid, more than x in future
    kodi::Log(ADDON_LOG_DEBUG, "[device token] old token still valid, no need to refresh");
    return true;
  }

  // Get new device token
  kodi::Log(ADDON_LOG_DEBUG, "[device token] New deviceToken required...");

  // \"sdpalp25\": false, \"sdpalp50\": false, \"hd720p25\": false, \"hd720p50\": false,
  std::string appVersion;
  GetBackendVersion(appVersion);

  bool cap_audio_aac = kodi::addon::GetSettingBoolean("streaming_capabilities_audio_aac", false);

  std::string capabilitesData = "{\"type\": \"receiver\", \"model\": \"Kodi 19\", \"manufacturer\": \"Team Kodi\", \"platform\": \"Kodi 19-pvr.waipu\", \"appVersion\": \""+appVersion+"\", \"capabilities\": {\"audio\": {\"aac\": "+(cap_audio_aac ? "true" : "false")+"},\"video\": { ";

  std::vector<std::string> video_cap_options = { "sdpalp25", "sdpalp50", "hd720p25", "hd720p50", "hd1080p25", "hd1080p50", "hevc1080p50", "hevc2160p50" };
  bool first = true;
  for (const std::string& cap_option : video_cap_options)
  {
    bool cap_value =
        kodi::addon::GetSettingBoolean("streaming_capabilities_video_" + cap_option, false);
    capabilitesData += std::string(first ? "" : ",")+ "\""+cap_option+"\": " + (cap_value ? "true" : "false");
    first = false;
  }
  capabilitesData += "}}}";

  std::string jsonDeviceToken = HttpPost("https://device-capabilities.waipu.tv/api/device-capabilities", capabilitesData, {{"Content-Type", "application/vnd.dc.device-info-v1+json"},{"X-USERCONTEXT-USERHANDLE",m_userhandle.c_str()}});

  kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] response: %s", jsonDeviceToken.c_str());

  std::string deviceToken;

  rapidjson::Document deviceTokenDoc;
  deviceTokenDoc.Parse(jsonDeviceToken.c_str());
  if (deviceTokenDoc.GetParseError())
  {
      kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] parse error :(");
      return false;
  }

  if(deviceTokenDoc.HasMember("token"))
  {
    m_deviceCapabilitiesToken = JWT(deviceTokenDoc["token"].GetString());
    kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] discovered token: %s", m_deviceCapabilitiesToken.getToken().c_str());
    return true;
  }

  kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] unknown error :(");
  return false;
}


ADDON_STATUS WaipuData::Create()
{
  kodi::Log(ADDON_LOG_DEBUG, "%s - Creating the waipu.tv PVR add-on", __FUNCTION__);

  // set User-Agent
  std::string ua = kodi::network::GetUserAgent();
  // use our replace, since kodi utils replaces all occurrences
  WAIPU_USER_AGENT = Utils::Replace(ua, " ", std::string(" pvr.waipu/").append(STR(IPTV_VERSION)).append(" "));

  ReadSettings();

  if (m_provider == WAIPU_PROVIDER_WAIPU && (m_username.empty() || m_password.empty()))
  {
      kodi::QueueNotification(QUEUE_ERROR, "", kodi::addon::GetLocalizedString(30033));
      return ADDON_STATUS_NEED_SETTINGS;
  }
  kodi::addon::CInstancePVRClient::TriggerChannelUpdate();
  kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
  kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
  return ADDON_STATUS_OK;
}

void WaipuData::ReadSettings()
{
  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);

  m_username = kodi::addon::GetSettingString("username");
  m_password = kodi::addon::GetSettingString("password");
  m_protocol = kodi::addon::GetSettingString("protocol", "auto");
  m_provider = kodi::addon::GetSettingEnum<WAIPU_PROVIDER>("provider_select", WAIPU_PROVIDER_WAIPU);
  m_refreshToken = JWT(kodi::addon::GetSettingString("refresh_token", ""));

  m_device_id = kodi::addon::GetSettingString("device_id_uuid4");
  if (m_device_id.empty())
  {
    m_device_id = Utils::CreateUUID();
    kodi::addon::SetSettingString("device_id_uuid4", m_device_id);
    // new device id -> force new login
    m_refreshToken = JWT();
  }

  kodi::Log(ADDON_LOG_DEBUG, "End Readsettings");
}

ADDON_STATUS WaipuData::SetSetting(const std::string& settingName,
                                   const kodi::addon::CSettingValue& settingValue)
{
  if (settingName == "username")
  {
    std::string username = settingValue.GetString();
    if (username != m_username)
    {
      m_username = username;
      m_login_failed_counter = 0;
      kodi::addon::SetSettingString("refresh_token", "");
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
      kodi::addon::SetSettingString("refresh_token", "");
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
      kodi::addon::SetSettingString("refresh_token", "");
      return ADDON_STATUS_NEED_RESTART;
    }
  }else if (settingName.rfind("streaming_capabilities_", 0) == 0)
  {
    // settings name begins with "streaming_capabilities_"
    // reset capabilities to force refresh
    m_deviceCapabilitiesToken = JWT();
  }else if( settingName == "refresh_reset" && settingValue.GetBoolean())
    {
      kodi::addon::SetSettingBoolean("refresh_reset", false);
      kodi::addon::SetSettingString("refresh_token", "");
      return ADDON_STATUS_NEED_RESTART;
    }

  return ADDON_STATUS_OK;
}

PVR_ERROR WaipuData::GetCapabilities(kodi::addon::PVRCapabilities& capabilities)
{
  capabilities.SetSupportsEPG(true);
  capabilities.SetSupportsTV(true);
  capabilities.SetSupportsRecordings(true);
  capabilities.SetSupportsRecordingsDelete(true);
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

std::string WaipuData::GetLicense()
{
  // ensure that userHandle is valid
  ApiLogin();
  return m_license;
}

void WaipuData::SetStreamProperties(std::vector<kodi::addon::PVRStreamProperty>& properties,
                                    const std::string& url,
                                    bool realtime, bool playTimeshiftBuffer,
                                    const std::string& protocol)
{
  kodi::Log(ADDON_LOG_DEBUG, "[PLAY STREAM] url: %s", url.c_str());

  properties.emplace_back(PVR_STREAM_PROPERTY_STREAMURL, url);
  properties.emplace_back(PVR_STREAM_PROPERTY_INPUTSTREAM, "inputstream.adaptive");
  properties.emplace_back(PVR_STREAM_PROPERTY_ISREALTIMESTREAM, realtime ? "true" : "false");

  if (protocol == "dash")
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
    std::string license = GetLicense();
    properties.emplace_back("inputstream.adaptive.license_type", "com.widevine.alpha");
    properties.emplace_back("inputstream.adaptive.license_key",
                            "https://drm.wpstr.tv/license-proxy-widevine/cenc/"
                            "|Content-Type=text%2Fxml&x-dt-custom-data=" +
                                license + "|R{SSM}|JBlicense");

    properties.emplace_back("inputstream.adaptive.manifest_update_parameter", "full");
  }
  else if (protocol == "hls")
  {
    // HLS
    kodi::Log(ADDON_LOG_DEBUG, "[PLAY STREAM] hls");
    properties.emplace_back("inputstream.adaptive.manifest_type", "hls");
    properties.emplace_back(PVR_STREAM_PROPERTY_MIMETYPE, "application/x-mpegURL");
    properties.emplace_back("inputstream.adaptive.manifest_update_parameter", "full");
  }
  else
  {
    kodi::Log(ADDON_LOG_ERROR, "[SetStreamProperties] called with invalid protocol '%s'", protocol.c_str());
  }
}

bool WaipuData::LoadChannelData()
{
  if (m_channels.size() > 0) return true;

  if (!ApiLogin())
  {
    // no valid session
    return false;
  }
  std::lock_guard<std::mutex> lock(mutex);
  kodi::Log(ADDON_LOG_DEBUG, "[load data] Get channels");

  std::string jsonChannels = HttpGet("https://epg.waipu.tv/api/channels");
  if (jsonChannels.empty())
  {
    kodi::Log(ADDON_LOG_ERROR, "[channels] ERROR - empty response");
    m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
    return false;
  }
  jsonChannels = "{\"result\": " + jsonChannels + "}";
  kodi::Log(ADDON_LOG_DEBUG, "[channels] length: %i;", jsonChannels.size());
  kodi::Log(ADDON_LOG_DEBUG, "[channels] %s;", jsonChannels.c_str());
  kodi::Log(ADDON_LOG_DEBUG, "[channels] %s;",
            jsonChannels.substr(jsonChannels.size() - 40).c_str());

  // parse channels
  kodi::Log(ADDON_LOG_DEBUG, "[channels] parse channels");
  rapidjson::Document channelsDoc;
  channelsDoc.Parse(jsonChannels.c_str());
  if (channelsDoc.GetParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[LoadChannelData] ERROR: error while parsing json");
    return false;
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
    const std::string waipuid = channel["id"].GetString();
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
        skipChannel |= (prop.GetString() == std::string("UserSetHidden"));
        tvfuse |= (prop.GetString() == std::string("tvfuse"));
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

    const int uniqueId = Utils::Hash(waipuid);
    waipu_channel.iUniqueId = uniqueId;
    kodi::Log(ADDON_LOG_DEBUG, "[channel] id: %i;", uniqueId);

    const std::string displayName = channel["displayName"].GetString();
    waipu_channel.strChannelName = displayName; // waipu[displayName]
    kodi::Log(ADDON_LOG_DEBUG, "[channel] name: %s;", waipu_channel.strChannelName.c_str());

    // iterate links
    std::string icon;
    std::string icon_sd;
    std::string icon_hd;
    for (const auto& link : channel["links"].GetArray())
    {
      const std::string rel = link["rel"].GetString();
      const std::string href = link["href"].GetString();
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

    std::string channel_url = "";
    if (icon_hd.size() > 0 && isHD)
    {
      channel_url = icon_hd + "?width=256&height=256";
    }
    else if (icon_sd.size() > 0)
    {
      channel_url = icon_sd + "?width=256&height=256";
    }
    else if (icon.size() > 0)
    {
      channel_url = icon + "?width=256&height=256";
    }

    std::string iconPath = "special://home/addons/pvr.waipu/resources/channel_icons/" + waipu_channel.waipuID + ".png";
    if (!kodi::vfs::FileExists(iconPath, true))
    {
      kodi::Log(ADDON_LOG_DEBUG, "[channel] download channel logo: %s -> %s", channel_url, iconPath);
      Utils::FileDownload(channel_url, iconPath);
    }
    waipu_channel.strIconPath = iconPath;

    kodi::Log(ADDON_LOG_DEBUG, "[channel] selected channel logo: %s", waipu_channel.strIconPath.c_str());

    bool isFav = channel["faved"].GetBool();
    if (isFav)
    {
      // user added channel to favorites
      cgroup_fav.channels.emplace_back(waipu_channel);
    }
    if (tvfuse)
    {
      // Video on Demand channel
      cgroup_vod.channels.emplace_back(waipu_channel);
    }
    else
    {
      // Not VoD -> Live TV
      cgroup_live.channels.emplace_back(waipu_channel);
    }

    m_channels.emplace_back(waipu_channel);
  }

  m_channelGroups.emplace_back(cgroup_fav);
  m_channelGroups.emplace_back(cgroup_live);
  m_channelGroups.emplace_back(cgroup_vod);

  return true;
}

PVR_ERROR WaipuData::GetChannelsAmount(int& amount)
{
  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
  LoadChannelData();

  amount = static_cast<int>(m_channels.size());
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannels(bool radio, kodi::addon::PVRChannelsResultSet& results)
{
  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
  LoadChannelData();

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
  LoadChannelData();
  PVR_ERROR ret = PVR_ERROR_FAILED;
  std::string protocol = m_protocol;
  if (protocol == "auto")
  {
    // use hls where possible, fallback to dash
    protocol = "dash";
    for (const auto& thisChannel : m_channels)
    {
      if (thisChannel.iUniqueId == channel.GetUniqueId())
      {
        if (m_hls_allowlist.contains(thisChannel.waipuID))
        {
          protocol = "hls";
          break;
        }
      }
    }
    kodi::Log(ADDON_LOG_DEBUG, "protocol auto select: %s", protocol.c_str());
  }

  std::string strUrl = GetChannelStreamURL(channel.GetUniqueId(), protocol, "");
  kodi::Log(ADDON_LOG_DEBUG, "Stream URL -> %s", strUrl.c_str());

  if (!strUrl.empty())
  {
    SetStreamProperties(properties, strUrl, true, false, protocol);
    ret = PVR_ERROR_NO_ERROR;
  }
  return ret;
}

std::string WaipuData::GetChannelStreamURL(int uniqueId, const std::string& protocol, const std::string& startTime)
{
  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId == uniqueId)
    {
      kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] Get live URL for channel %s", channel.strChannelName.c_str());

      if (!ApiLogin())
      {
        // invalid
        kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] No stream login");
        return {};
      }

      // ensure device token is fresh
      RefreshDeviceCapabiltiesToken();

      std::string postData = "{\"stream\": { \"station\": \""+channel.waipuID+"\", \"protocol\": \""+protocol+"\", \"requestMuxInstrumentation\": false";
      if (!startTime.empty())
      {
	  postData += ", \"startTime\": "+startTime;
      }
      postData += "}}";
      kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] Post data: %s", postData.c_str());

      std::string jsonStreamURL = HttpPost("https://stream-url-provider.waipu.tv/api/stream-url", postData, {{"Content-Type", "application/vnd.streamurlprovider.stream-url-request-v1+json"}, {"X-Device-Token", m_deviceCapabilitiesToken.getToken().c_str()}});

      rapidjson::Document streamURLDoc;
      streamURLDoc.Parse(jsonStreamURL.c_str());
      if (streamURLDoc.GetParseError())
      {
          kodi::Log(ADDON_LOG_ERROR, "[GetStreamURL] ERROR: error while parsing json");
          return {};
      }

      if(!streamURLDoc.HasMember("streamUrl"))
      {
          kodi::Log(ADDON_LOG_ERROR, "[GetStreamURL] ERROR: missing param streamUrl");
          return {};
      }

      return streamURLDoc["streamUrl"].GetString();
    }
  }
  return {};
}

PVR_ERROR WaipuData::GetChannelGroupsAmount(int& amount)
{
  LoadChannelData();
  amount = static_cast<int>(m_channelGroups.size());
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannelGroups(bool radio, kodi::addon::PVRChannelGroupsResultSet& results)
{
  LoadChannelData();
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
  LoadChannelData();
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
  LoadChannelData();

  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId != channelUid)
      continue;

    std::string startTime = Utils::TimeToString(start);
    std::string endTime = Utils::TimeToString(end);

    std::string jsonEpg =
        HttpGet("https://epg.waipu.tv/api/channels/" + channel.waipuID +
                "/programs?startTime=" + std::string(startTime) + "&stopTime=" + std::string(endTime));
    kodi::Log(ADDON_LOG_DEBUG, "[epg-all] %s", jsonEpg.c_str());
    if (jsonEpg.empty())
    {
      kodi::Log(ADDON_LOG_ERROR, "[epg] empty server response");
      return PVR_ERROR_SERVER_ERROR;
    }
    jsonEpg = "{\"result\": " + jsonEpg + "}";

    rapidjson::Document epgDoc;
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

      // generate a unique boadcast id
      const std::string epg_bid = epgData["id"].GetString();
      kodi::Log(ADDON_LOG_DEBUG, "[epg] epg_bid: %s;", epg_bid.c_str());
      int dirtyID = Utils::GetIDDirty(epg_bid);
      kodi::Log(ADDON_LOG_DEBUG, "[epg] epg_bid dirty: %i;", dirtyID);
      tag.SetUniqueBroadcastId(dirtyID);

      // channel ID
      tag.SetUniqueChannelId(channel.iUniqueId);

      /*// add streamUrlProvider if it is video on demand
      if (myChannel.tvfuse && epgData.HasMember("streamUrlProvider") && !epgData["streamUrlProvider"].IsNull())
      {
        string streamUrlProvider = epgData["streamUrlProvider"].GetString();
        kodi::Log(ADDON_LOG_DEBUG, "[epg] streamUrlProvider: %s;", streamUrlProvider.c_str());
      }*/

      unsigned int flags = EPG_TAG_FLAG_UNDEFINED;

      // is recordable
      bool isRecordable = !epgData["recordingForbidden"].GetBool();
      kodi::Log(ADDON_LOG_DEBUG, "[epg] recordable: %i;", isRecordable);
      if (isRecordable){flags |= EPG_TAG_FLAG_IS_RECORDABLE_WAIPU; }

      // instantRestartAllowed
      bool instantRestartAllowed = !epgData["instantRestartForbidden"].GetBool();
      kodi::Log(ADDON_LOG_DEBUG, "[epg] instantRestartAllowed: %i;", instantRestartAllowed);
      if (isRecordable){flags |= EPG_TAG_FLAG_INSTANT_RESTART_ALLOWED_WAIPU; }

      // set title
      tag.SetTitle(epgData["title"].GetString());
      kodi::Log(ADDON_LOG_DEBUG, "[epg] title: %s;", epgData["title"].GetString());

      // set startTime
      const std::string startTime = epgData["startTime"].GetString();
      tag.SetStartTime(Utils::StringToTime(startTime));

      // set endTime
      const std::string endTime = epgData["stopTime"].GetString();
      tag.SetEndTime(Utils::StringToTime(endTime));

      // tag.SetPlotOutline(myTag.strPlotOutline);

      // set description
      if (epgData.HasMember("description") && !epgData["description"].IsNull())
      {
        tag.SetPlot(epgData["description"].GetString());
        kodi::Log(ADDON_LOG_DEBUG, "[epg] description: %s;", epgData["description"].GetString());
      }

      // epg preview image
      //if(epgData.HasMember("previewImages") && epgData["previewImages"].IsArray() && epgData["previewImages"].Size() > 0){
      //    std::string tmp_img = epgData["previewImages"][0].GetString();
      //    tmp_img += "?width=480&height=270";
      //    tag.SetIconPath(tmp_img);
      //    kodi::Log(ADDON_LOG_DEBUG, "[epg] previewImage: %s;", tmp_img.c_str());
      //}

      // iSeriesNumber
      if (epgData.HasMember("season") && !epgData["season"].IsNull())
      {
        tag.SetSeriesNumber(
            Utils::StringToInt(epgData["season"].GetString(), EPG_TAG_INVALID_SERIES_EPISODE));
        flags |= EPG_TAG_FLAG_IS_SERIES;
      }
      else
      {
        tag.SetSeriesNumber(EPG_TAG_INVALID_SERIES_EPISODE);
      }
      // episodeNumber
      if (epgData.HasMember("episode") && epgData["episode"].IsString())
      {
        tag.SetEpisodeNumber(
            Utils::StringToInt(epgData["episode"].GetString(), EPG_TAG_INVALID_SERIES_EPISODE));
      }
      else
      {
        tag.SetEpisodeNumber(EPG_TAG_INVALID_SERIES_EPISODE);
      }

      // episodeName
      if (epgData.HasMember("episodeTitle") && !epgData["episodeTitle"].IsNull())
      {
        tag.SetEpisodeName(epgData["episodeTitle"].GetString());
      }

      // year
      if (epgData.HasMember("year") && !epgData["year"].IsNull())
      {
        tag.SetYear(Utils::StringToInt(epgData["year"].GetString(), 1970));
      }

      // genre
      if (epgData.HasMember("genreDisplayName") && !epgData["genreDisplayName"].IsNull())
      {
	const std::string genreStr = epgData["genreDisplayName"].GetString();
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

      tag.SetFlags(flags);
      results.Add(tag);
    }
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::IsEPGTagRecordable(const kodi::addon::PVREPGTag& tag, bool& isRecordable)
{
  LoadChannelData();
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

  isRecordable = (tag.GetFlags() & EPG_TAG_FLAG_IS_RECORDABLE_WAIPU);
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::IsEPGTagPlayable(const kodi::addon::PVREPGTag& tag, bool& isPlayable)
{
  LoadChannelData();
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
      isPlayable = (tag.GetFlags() & EPG_TAG_FLAG_INSTANT_RESTART_ALLOWED_WAIPU);
  }

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetEPGTagStreamProperties(
    const kodi::addon::PVREPGTag& tag, std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  kodi::Log(ADDON_LOG_DEBUG, "[EPG TAG] play it...");
  LoadChannelData();

  std::string protocol = m_protocol;
  if (protocol == "auto") protocol = "dash";  //fallback to dash

  std::string strUrl = GetEPGTagURL(tag, protocol);
  if (strUrl.empty())
  {
    return PVR_ERROR_FAILED;
  }

  SetStreamProperties(properties, strUrl, true, true, protocol);

  return PVR_ERROR_NO_ERROR;
}

std::string WaipuData::GetEPGTagURL(const kodi::addon::PVREPGTag& tag, const std::string& protocol)
{
  ApiLogin();
  LoadChannelData();

  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId == tag.GetUniqueChannelId())
    {
      std::string startTime = Utils::TimeToString(tag.GetStartTime());
      std::string endTime = Utils::TimeToString(tag.GetEndTime());

      std::string jsonEpg =
	  HttpGet("https://epg.waipu.tv/api/channels/" + channel.waipuID +
	          "/programs?includeRunningAtStartTime=false&startTime=" + std::string(startTime) + "&stopTime=" + std::string(endTime));
      kodi::Log(ADDON_LOG_DEBUG, "[epg-single-tag] %s", jsonEpg.c_str());
      if (jsonEpg.empty())
      {
        kodi::Log(ADDON_LOG_ERROR, "[epg-single-tag] empty server response");
        return {};
      }
      jsonEpg = "{\"result\": " + jsonEpg + "}";

      rapidjson::Document epgDoc;
      epgDoc.Parse(jsonEpg.c_str());

      if (epgDoc.GetParseError() || epgDoc["result"].Empty() || !epgDoc["result"][0].HasMember("streamUrlProvider") || epgDoc["result"][0]["streamUrlProvider"].IsNull())
      {
        // fallback to replay playback
        kodi::Log(ADDON_LOG_DEBUG, "[play epg tag] streamUrlProvider not found -> fallback to replay!");
        std::string startTime = std::to_string(tag.GetStartTime());
        return GetChannelStreamURL(tag.GetUniqueChannelId(), protocol, startTime);
      }

      std::string url = epgDoc["result"][0]["streamUrlProvider"].GetString();

      if (!url.empty())
      {
        kodi::Log(ADDON_LOG_DEBUG, "play url -> %s", url.c_str());

        std::string tag_resp = HttpGet(url);
        kodi::Log(ADDON_LOG_DEBUG, "tag resp -> %s", tag_resp.c_str());

        rapidjson::Document tagDoc;
        tagDoc.Parse(tag_resp.c_str());
        if (tagDoc.GetParseError())
        {
          kodi::Log(ADDON_LOG_ERROR, "[getEPGTagURL] ERROR: error while parsing json");
          return {};
        }
        kodi::Log(ADDON_LOG_DEBUG, "[tag] streams");
        // check if streams there
        if (tagDoc.HasMember("player") && tagDoc["player"].HasMember("mpd"))
        {
            std::string mpdUrl = tagDoc["player"]["mpd"].GetString();
          kodi::Log(ADDON_LOG_DEBUG, "mpd url -> %s", mpdUrl.c_str());
          return mpdUrl;
        }
      }
    }
  }
  kodi::Log(ADDON_LOG_DEBUG, "[play epg tag] channel or tag not found!");
  return {};
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

  std::string jsonRecordings = HttpGet("https://recording.waipu.tv/api/recordings",{{"Accept", "application/vnd.waipu.recordings-v2+json"}});
  kodi::Log(ADDON_LOG_DEBUG, "[recordings] %s", jsonRecordings.c_str());

  jsonRecordings = "{\"result\": " + jsonRecordings + "}";

  rapidjson::Document recordingsDoc;
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
    std::string status = recording["status"].GetString();
    if (status != "FINISHED")
      continue;

    // new tag
    kodi::addon::PVRRecording tag;

    tag.SetIsDeleted(false);

    // set recording id
    std::string rec_id = recording["id"].GetString();
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

    const rapidjson::Value& epgData = recording["epgData"];

    // set recording title
    const std::string rec_title = epgData["title"].GetString();
    tag.SetTitle(rec_title);
    // set folder; test
    tag.SetDirectory(rec_title);

    // set image
    if (epgData.HasMember("previewImages") && epgData["previewImages"].IsArray() &&
        epgData["previewImages"].Size() > 0)
    {
      std::string rec_img = epgData["previewImages"][0].GetString();
      rec_img = rec_img + "?width=256&height=256";
      tag.SetIconPath(rec_img);
      tag.SetThumbnailPath(rec_img);
    }

    // duration
    if (epgData.HasMember("duration") && !epgData["duration"].IsNull())
    {
      const std::string rec_dur = epgData["duration"].GetString();
      tag.SetDuration(Utils::StringToInt(rec_dur, 0) * 60);
    }

    // iSeriesNumber
    if (epgData.HasMember("season") && !epgData["season"].IsNull())
    {
      tag.SetSeriesNumber(
          Utils::StringToInt(epgData["season"].GetString(), PVR_RECORDING_INVALID_SERIES_EPISODE));
    }
    else
    {
      tag.SetSeriesNumber(PVR_RECORDING_INVALID_SERIES_EPISODE);
    }

    // episodeNumber
    if (epgData.HasMember("episode") && !epgData["episode"].IsNull())
    {
      tag.SetEpisodeNumber(
          Utils::StringToInt(epgData["episode"].GetString(), PVR_RECORDING_INVALID_SERIES_EPISODE));
    }
    else
    {
      tag.SetEpisodeNumber(PVR_RECORDING_INVALID_SERIES_EPISODE);
    }

    // episodeName
    if (epgData.HasMember("episodeTitle") && !epgData["episodeTitle"].IsNull())
    {
      std::string rec_episodename = epgData["episodeTitle"].GetString();
      tag.SetEpisodeName(rec_episodename);
    }

    // year
    if (epgData.HasMember("year") && !epgData["year"].IsNull())
    {
      const std::string rec_year = epgData["year"].GetString();
      tag.SetYear(Utils::StringToInt(rec_year, 1970));
    }

    // get recording time
    if (recording.HasMember("startTime") && !recording["startTime"].IsNull())
    {
      const std::string recordingTime = recording["startTime"].GetString();
      tag.SetRecordingTime(Utils::StringToTime(recordingTime));
    }

    // get plot
    if (epgData.HasMember("description") && !epgData["description"].IsNull())
    {
      const std::string rec_plot = epgData["description"].GetString();
      tag.SetPlot(rec_plot);
    }

    // genre
    if (epgData.HasMember("genreDisplayName") && !epgData["genreDisplayName"].IsNull())
    {
      std::string genreStr = epgData["genreDisplayName"].GetString();
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
      std::string epg_id = epgData["id"].GetString();
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
                                       const std::string& protocol)
{
  ApiLogin();

  std::string recording_id = recording.GetRecordingId();
  kodi::Log(ADDON_LOG_DEBUG, "play recording -> %s", recording_id.c_str());

  std::string rec_resp = HttpGet("https://recording.waipu.tv/api/recordings/" + recording_id);
  kodi::Log(ADDON_LOG_DEBUG, "recording resp -> %s", rec_resp.c_str());

  rapidjson::Document recordingDoc;
  recordingDoc.Parse(rec_resp.c_str());
  if (recordingDoc.GetParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[getRecordingURL] ERROR: error while parsing json");
    return {};
  }
  kodi::Log(ADDON_LOG_DEBUG, "[recording] streams");
  // check if streams there
  if (!recordingDoc.HasMember("streamingDetails") ||
      !recordingDoc["streamingDetails"].HasMember("streams"))
  {
    return {};
  }

  kodi::Log(ADDON_LOG_DEBUG, "[recordings] size: %i;",
            recordingDoc["streamingDetails"]["streams"].Size());

  std::string protocol_fix = protocol == "dash" ? "MPEG_DASH" : "HLS";

  for (const auto& stream : recordingDoc["streamingDetails"]["streams"].GetArray())
  {
    std::string current_protocol = stream["protocol"].GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[stream] protocol: %s;", current_protocol.c_str());
    if (current_protocol == protocol_fix)
    {
      std::string href = stream["href"].GetString();
      kodi::Log(ADDON_LOG_DEBUG, "[stream] selected href: %s;", href.c_str());
      return href;
    }
  }
  return {};
}

PVR_ERROR WaipuData::DeleteRecording(const kodi::addon::PVRRecording& recording)
{
  if (ApiLogin())
  {
    std::string recording_id = recording.GetRecordingId();
    std::string request_data = "{\"ids\":[\"" + recording_id + "\"]}";
    kodi::Log(ADDON_LOG_DEBUG, "[delete recording] req: %s;", request_data.c_str());
    std::string deleted = HttpDelete("https://recording.waipu.tv/api/recordings", request_data.c_str(), {{"Content-Type","application/vnd.waipu.pvr-recording-ids-v2+json"}});
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
  LoadChannelData();

  std::string protocol = m_protocol;
  if (protocol == "auto") protocol = "dash"; //fallback to dash

  std::string strUrl = GetRecordingURL(recording, protocol);
  if (strUrl.empty())
  {
    return PVR_ERROR_FAILED;
  }

  SetStreamProperties(properties, strUrl, true, false, protocol);

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
  AddTimerType(types, 1, PVR_TIMER_TYPE_REQUIRES_EPG_TAG_ON_CREATE);
  AddTimerType(types, 2, PVR_TIMER_TYPE_REQUIRES_EPG_SERIES_ON_CREATE | PVR_TIMER_TYPE_IS_REPEATING );

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
  LoadChannelData();

  std::string jsonRecordings = HttpGet("https://recording.waipu.tv/api/recordings", {{"Accept", "application/vnd.waipu.recordings-v2+json"}});
  kodi::Log(ADDON_LOG_DEBUG, "[Timers] %s", jsonRecordings.c_str());

  jsonRecordings = "{\"result\": " + jsonRecordings + "}";

  rapidjson::Document timersDoc;
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

  std::vector<int> timerGroups;

  for (const auto& timer : timersDoc["result"].GetArray())
  {
    // skip not FINISHED entries
    std::string status = timer["status"].GetString();
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

    const rapidjson::Value& epgData = timer["epgData"];

    // set recording title
    std::string rec_title = epgData["title"].GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[timers] Add: %s;", rec_title.c_str());
    tag.SetTitle(rec_title);

    int tag_channel;
    // channelid
    if (timer.HasMember("channelId") && !timer["channelId"].IsNull())
    {
      std::string channel_name = timer["channelId"].GetString();
      for (const auto& channel : m_channels)
      {
        if (channel.waipuID != channel_name)
          continue;
        tag_channel = channel.iUniqueId;
        tag.SetClientChannelUid(tag_channel);
        break;
      }
    }

    if (timer.HasMember("recordingGroup"))
    {

	int group = timer["recordingGroup"].GetInt();
	tag.SetRecordingGroup(group);
	if (std::find(timerGroups.begin(), timerGroups.end(), group) == timerGroups.end())
	{
	  // add group
	  kodi::addon::PVRTimer tagGroup;
	  tagGroup.SetTimerType(2);
	  tagGroup.SetTitle(rec_title);
	  tagGroup.SetClientIndex(group);
	  tagGroup.SetClientChannelUid(tag_channel);
	  tag.SetRecordingGroup(group);
	  kodi::Log(ADDON_LOG_DEBUG, "[add timer group] group: %i;", group);

	  results.Add(tagGroup);
	  timerGroups.emplace_back(group);
	}
    }

    tag.SetTimerType(1);

    // set recording id
    std::string rec_id = timer["id"].GetString();
    tag.SetClientIndex(Utils::StringToInt(rec_id, 0));
    tag.SetEPGUid(Utils::StringToInt(rec_id, 0));

    // get recording time
    if (timer.HasMember("startTime") && !timer["startTime"].IsNull())
    {
      std::string startTime = timer["startTime"].GetString();
      tag.SetStartTime(Utils::StringToTime(startTime));
    }
    if (timer.HasMember("stopTime") && !timer["stopTime"].IsNull())
    {
      std::string endTime = timer["stopTime"].GetString();
      tag.SetEndTime(Utils::StringToTime(endTime));
    }

    // get plot
    if (epgData.HasMember("description") && !epgData["description"].IsNull())
    {
      std::string rec_plot = epgData["description"].GetString();
      tag.SetSummary(rec_plot);
    }

    // epg mapping
    if (epgData.HasMember("id") && !epgData["id"].IsNull())
    {
      std::string epg_id = epgData["id"].GetString();
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
      LoadChannelData();
    if (timer.GetTimerType() == 1)
    {
      // single tag
      int timer_id = timer.GetClientIndex();
      std::string request_data = "{\"ids\":[\"" + std::to_string(timer_id) + "\"]}";
      kodi::Log(ADDON_LOG_DEBUG, "[delete single timer] req: %s;", request_data.c_str());
      std::string deleted = HttpDelete("https://recording.waipu.tv/api/recordings", request_data.c_str(),{{"Content-Type", "application/vnd.waipu.pvr-recording-ids-v2+json"}});
      kodi::Log(ADDON_LOG_DEBUG, "[delete single timer] response: %s;", deleted.c_str());
      kodi::QueueNotification(QUEUE_INFO, "Recording", "Recording Deleted");
      kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
      kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
      return PVR_ERROR_NO_ERROR;
    }else{
      // delete record series
      int groupID = timer.GetClientIndex();
      std::string request_data = "{\"serialRecordings\":[{\"id\":" + std::to_string(groupID) + ",\"deleteFutureRecordings\":true,\"deleteFinishedRecordings\":false,\"deleteRunningRecordingss\":false}]}";
      kodi::Log(ADDON_LOG_DEBUG, "[delete multi timer] req (group: %i): %s;", groupID, request_data.c_str());
      std::string deleted = HttpPost("https://recording-scheduler.waipu.tv/api/delete-requests", request_data.c_str(),{{"Content-Type", "application/vnd.waipu.recording-scheduler-delete-serial-recordings-v1+json"}});
      kodi::Log(ADDON_LOG_DEBUG, "[delete multi timer] response: %s;", deleted.c_str());
      kodi::QueueNotification(QUEUE_INFO, "Recording", "Rule Deleted");
      kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
      kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
      return PVR_ERROR_NO_ERROR;
    }
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
      LoadChannelData();
    for (const auto& channel : m_channels)
    {
      if (channel.iUniqueId != timer.GetClientChannelUid())
        continue;

      if (timer.GetTimerType() == 1)
      {
        // record single element
        kodi::Log(ADDON_LOG_DEBUG, "[add timer] Record single tag;");
        // {"programId":"_1051966761","channelId":"PRO7","startTime":"2019-02-03T18:05:00.000Z","stopTime":"2019-02-03T19:15:00.000Z"}
        std::string postData = "{\"programId\":\"_" + std::to_string(timer.GetEPGUid()) +
                          "\",\"channelId\":\"" + channel.waipuID + "\"" + "}";
        std::string recordResp = HttpPost("https://recording.waipu.tv/api/recordings", postData, {{"Content-Type", "application/vnd.waipu.start-recording-v2+json"}});
        kodi::Log(ADDON_LOG_DEBUG, "[add timer] single response: %s;", recordResp.c_str());
        kodi::QueueNotification(QUEUE_INFO, "Recording", "Recording Created");
        kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
        return PVR_ERROR_NO_ERROR;
      }else{
        // record series
        kodi::Log(ADDON_LOG_DEBUG, "[add timer] Record single tag;");
        // {"title":"Das A-Team","channel":"RTLNITRO"}
        std::string postData = "{\"title\": \"" + timer.GetTitle() +
                          "\",\"channel\":\"" + channel.waipuID + "\"" + "}";
        std::string recordResp = HttpPost("https://recording-scheduler.waipu.tv/api/serials", postData, {{"Content-Type", "application/vnd.waipu.recording-scheduler-serials-v1+json"}});
        kodi::Log(ADDON_LOG_DEBUG, "[add timer] repeating response: %s;", recordResp.c_str());
        kodi::QueueNotification(QUEUE_INFO, "Recording", "Rule Created");
        kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
        kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
        return PVR_ERROR_NO_ERROR;
      }
    }
  }
  return PVR_ERROR_FAILED;
}

PVR_ERROR WaipuData::GetDriveSpace(uint64_t& total, uint64_t& used)
{
  ApiLogin();
  total = m_account_hours_recording * 1024 * 1024;
  used =  0;
  return PVR_ERROR_NO_ERROR;
}

ADDONCREATOR(WaipuData)
