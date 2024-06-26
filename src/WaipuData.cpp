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
#include "kodi/General.h"
#include "kodi/tools/StringUtils.h"
#include "rapidjson/document.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <regex>
#include <set>
#include <thread>

#include <kodi/gui/dialogs/Progress.h>

std::mutex WaipuData::mutex;

// BEGIN CURL helpers from zattoo addon:
std::string WaipuData::HttpGet(const std::string& url,
                               const std::map<std::string, std::string>& headers)
{
  return HttpRequest("GET", url, "", headers);
}

std::string WaipuData::HttpDelete(const std::string& url,
                                  const std::string& postData,
                                  const std::map<std::string, std::string>& headers)
{
  return HttpRequest("DELETE", url, postData, headers);
}

std::string WaipuData::HttpPost(const std::string& url,
                                const std::string& postData,
                                const std::map<std::string, std::string>& headers)
{
  return HttpRequest("POST", url, postData, headers);
}

std::string WaipuData::HttpRequest(const std::string& action,
                                   const std::string& url,
                                   const std::string& postData,
                                   const std::map<std::string, std::string>& headers)
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

std::string WaipuData::HttpRequestToCurl(Curl& curl,
                                         const std::string& action,
                                         const std::string& url,
                                         const std::string& postData,
                                         int& statusCode)
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
  else if (action == "PUT")
  {
    content = curl.Put(url, postData, statusCode);
  }
  else
  {
    content = curl.Get(url, statusCode);
  }
  if ((statusCode >= 200 && statusCode < 300) or statusCode == 403)
    return content;

  kodi::Log(ADDON_LOG_ERROR, "[Http-GET-Request] error. status: %i, body: %s", statusCode,
            content.c_str());
  return "";
}
// END CURL helpers from zattoo addon

// returns true if m_apiToken contains valid session
bool WaipuData::IsConnected()
{
  return m_login_status == WAIPU_LOGIN_STATUS::OK;
}

WAIPU_LOGIN_STATUS WaipuData::Login()
{
  kodi::Log(ADDON_LOG_DEBUG, "[token] current time %i", std::time(0));
  kodi::Log(ADDON_LOG_DEBUG, "[token] expire  time %i", m_accessToken.getExp());
  if (m_accessToken.isInitialized() && !m_accessToken.isExpired(20 * 60))
  {
    // API token exists and is valid, more than x in future
    kodi::Log(ADDON_LOG_DEBUG, "[login check] old token still valid");
    return WAIPU_LOGIN_STATUS::OK;
  }

  if (m_refreshToken.isInitialized() && !m_refreshToken.isExpired())
  {
    // Since the refresh token is valid for a long time, we do not check expiration for now
    // refresh API token
    std::string req = "refresh_token=" + Utils::UrlEncode(m_refreshToken.getToken()) +
                      "&grant_type=refresh_token" + "&waipu_device_id=" + m_device_id;
    kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-Request (refresh): %s;", req.c_str());
    return OAuthRequest(req);
  }

  if (m_provider == WAIPU_PROVIDER_WAIPU)
  {
    kodi::Log(ADDON_LOG_DEBUG, "[login check] WAIPU.TV LOGIN...");

    // get API by login user/pw
    std::string req = "username=" + Utils::UrlEncode(m_username) +
                      "&password=" + Utils::UrlEncode(m_password) + "&grant_type=password" +
                      "&waipu_device_id=" + m_device_id;
    kodi::Log(ADDON_LOG_DEBUG, "[login check] Login-Request (user/pw)");
    return OAuthRequest(req);
  }
  else if (m_provider == WAIPU_PROVIDER_O2)
  {
    return DeviceLogin("o2");
  }

  // waipu oauth device workflow
  return DeviceLogin("waipu");
}

void WaipuData::LoginThread()
{
  while (true)
  {
    if (!m_loginThreadRunning)
      return;

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (m_nextLoginAttempt > std::time(0) ||
        m_login_status == WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS)
      continue;

    if (m_login_failed_counter >= WAIPU_LOGIN_FAILED_LOCK_LIMIT)
    {
      kodi::Log(ADDON_LOG_ERROR, "[API LOGIN] Reset login lock due to timer");
      m_login_failed_counter = 0;
    }

    auto previousStatus = m_login_status;
    m_login_status = Login();

    m_nextLoginAttempt = std::time(0) + 1;
    if (m_login_status == WAIPU_LOGIN_STATUS::OK)
    {
      // login okay, reset counter
      m_login_failed_counter = 0;

      kodi::addon::CInstancePVRClient::ConnectionStateChange("Connected",
                                                             PVR_CONNECTION_STATE_CONNECTED, "");
      m_nextLoginAttempt = std::time(0) + 60;

      if (previousStatus != m_login_status || m_lastUpdate < std::time(0) - 30 * 60)
      {
        m_lastUpdate = std::time(0);
        kodi::addon::CInstancePVRClient::TriggerChannelUpdate();
        kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
        kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
      }

      continue;
    }

    kodi::addon::CInstancePVRClient::ConnectionStateChange("Connecting",
                                                           PVR_CONNECTION_STATE_CONNECTING, "");

    if (m_login_status == WAIPU_LOGIN_STATUS::NO_NETWORK)
      continue;

    if (++m_login_failed_counter >= WAIPU_LOGIN_FAILED_LOCK_LIMIT)
      m_nextLoginAttempt = std::time(0) + 180;
  }
}

bool WaipuData::ParseAccessToken()
{
  if (!m_accessToken.isInitialized() || m_accessToken.isExpired())
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
  for (const auto& user_channel :
       m_accessToken.parsedToken["userAssets"]["channels"]["SD"].GetArray())
  {
    std::string user_channel_s = user_channel.GetString();
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] SD channel: %s", user_channel_s.c_str());
    m_user_channels_sd.emplace_back(user_channel_s);
  }
  for (const auto& user_channel :
       m_accessToken.parsedToken["userAssets"]["channels"]["HD"].GetArray())
  {
    std::string user_channel_s = user_channel.GetString();
    m_user_channels_hd.emplace_back(user_channel_s);
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] HD channel: %s", user_channel_s.c_str());
  }
  if (m_accessToken.parsedToken["userAssets"].HasMember("instantRestart"))
  {
    m_account_replay_allowed = m_accessToken.parsedToken["userAssets"]["instantRestart"].GetBool();
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] Account InstantStart: %i", m_account_replay_allowed);
  }
  if (m_accessToken.parsedToken["userAssets"].HasMember("hoursRecording"))
  {
    m_account_hours_recording = m_accessToken.parsedToken["userAssets"]["hoursRecording"].GetInt();
    kodi::Log(ADDON_LOG_DEBUG, "[jwt] Account HoursReording: %i", m_account_hours_recording);
  }

  m_login_status = WAIPU_LOGIN_STATUS::OK;
  return true;
}

const std::map<std::string, std::string> WaipuData::GetOAuthDeviceCode(const std::string& tenant)
{
  kodi::Log(ADDON_LOG_DEBUG, "[device] GetOAuthDeviceCode, tenant '%s'", tenant.c_str());
  std::string jsonString;
  std::map<std::string, std::string> result;
  // curl request
  Curl curl;
  int statusCode = 0;
  curl.AddHeader("Authorization", "Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
  curl.AddHeader("Content-Type", "application/json");
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  jsonString = HttpRequestToCurl(curl, "POST", "https://auth.waipu.tv/oauth/device_authorization",
                                 "{\"client_id\":\"" + tenant + "\", \"waipu_device_id\":\"" +
                                     m_device_id + "\"}",
                                 statusCode);

  kodi::Log(ADDON_LOG_DEBUG, "[login check] GetOAuthDeviceCode-response: (HTTP %i) %s;", statusCode,
            jsonString.c_str());

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
    if (doc.HasParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[GetOAuthDeviceCode] ERROR: error while parsing json");
      return result;
    }
    for (const std::string key :
         {"verification_uri", "user_code", "device_code", "verification_uri_complete"})
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

const std::map<std::string, std::string> WaipuData::CheckOAuthState(const std::string& device_code)
{
  kodi::Log(ADDON_LOG_DEBUG, "[device] CheckOAuthState");
  std::string jsonString;
  std::map<std::string, std::string> result;
  // curl request
  Curl curl;
  int statusCode = 0;
  curl.AddHeader("Authorization", "Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  jsonString = HttpRequestToCurl(
      curl, "POST", "https://auth.waipu.tv/oauth/token",
      "device_code=" + device_code +
          "&grant_type=urn:ietf:params:oauth:grant-type:device_code&waipu_device_id=" + m_device_id,
      statusCode);

  kodi::Log(ADDON_LOG_DEBUG, "[login check] CheckOAuthState-response: (HTTP %i) %s;", statusCode,
            jsonString.c_str());

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
    if (doc.HasParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[CheckOAuthState] ERROR: error while parsing json");
      return result;
    }
    for (const std::string key : {"access_token", "refresh_token", "token_type"})
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

WAIPU_LOGIN_STATUS WaipuData::OAuthRequest(const std::string& postData)
{
  kodi::Log(ADDON_LOG_DEBUG, "[OAuthRequest] Body: %s;", postData.c_str());
  std::string jsonString;
  // curl request
  Curl curl;
  int statusCode = 0;
  curl.AddHeader("Authorization", "Basic YW5kcm9pZENsaWVudDpzdXBlclNlY3JldA==");
  //  curl.AddHeader("Content-Type", "application/x-www-form-urlencoded");
  curl.AddHeader("User-Agent", WAIPU_USER_AGENT);
  jsonString =
      HttpRequestToCurl(curl, "POST", "https://auth.waipu.tv/oauth/token", postData, statusCode);

  kodi::Log(ADDON_LOG_DEBUG, "[OAuthRequest] Login-response: (HTTP %i) %s;", statusCode,
            jsonString.c_str());

  if (statusCode == -1)
  {
    // no network connection?
    kodi::Log(ADDON_LOG_ERROR, "[OAuthRequest] no network connection");
    return WAIPU_LOGIN_STATUS::NO_NETWORK;
  }
  else if (statusCode == 401)
  {
    if (m_refreshToken.isInitialized() && !m_refreshToken.isExpired())
    {
      // we used invalid refresh token, delete it
      m_refreshToken = JWT();
      return WAIPU_LOGIN_STATUS::UNKNOWN;
    }
    // invalid credentials
    return WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
  }

  if (jsonString.empty())
    return WAIPU_LOGIN_STATUS::UNKNOWN;

  rapidjson::Document doc;
  doc.Parse(jsonString.c_str());
  if (doc.HasParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[OAuthRequest] ERROR: error while parsing json");
    return WAIPU_LOGIN_STATUS::UNKNOWN;
  }

  if (doc.HasMember("error"))
  {
    if (doc["error"] == "invalid_request")
    {
      kodi::Log(ADDON_LOG_ERROR, "[OAuthRequest] ERROR: invalid credentials?");
      return WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
    }

    // unhandled error -> handle if known
    std::string err = doc["error"].GetString();
    kodi::Log(ADDON_LOG_ERROR, "[OAuthRequest] ERROR: (%s)", err.c_str());
    return WAIPU_LOGIN_STATUS::UNKNOWN;
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

  return ParseAccessToken() ? WAIPU_LOGIN_STATUS::OK : WAIPU_LOGIN_STATUS::UNKNOWN;
}

WAIPU_LOGIN_STATUS WaipuData::DeviceLogin(const std::string& tenant)
{
  WAIPU_LOGIN_STATUS ret = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;

  kodi::Log(ADDON_LOG_DEBUG, "[DeviceLogin] waipu.tv DeviceLogin, tenant '%s' ...", tenant.c_str());

  const std::map<std::string, std::string> deviceCodeMap = GetOAuthDeviceCode(tenant);
  if (!deviceCodeMap.count("verification_uri") || !deviceCodeMap.count("user_code") ||
      !deviceCodeMap.count("device_code"))
  {
    kodi::Log(ADDON_LOG_DEBUG, "OAuth missing response");
    return ret;
  }
  std::string code_req =
      "device_code=" + deviceCodeMap.find("device_code")->second +
      "&grant_type=urn:ietf:params:oauth:grant-type:device_code&waipu_device_id=" + m_device_id;
  kodi::Log(ADDON_LOG_DEBUG, "Create Login Progress");
  kodi::gui::dialogs::CProgress* progress = new kodi::gui::dialogs::CProgress;
  progress->SetHeading("pvr.waipu - " + tenant + " Login");
  progress->SetLine(1, "1) " + kodi::addon::GetLocalizedString(30039) + " " +
                           deviceCodeMap.find("verification_uri")->second);
  progress->SetLine(2, "2) " + kodi::addon::GetLocalizedString(30040));
  progress->SetLine(3, "3) " + kodi::addon::GetLocalizedString(30041) + " " +
                           deviceCodeMap.find("user_code")->second);
  progress->SetCanCancel(true);
  progress->ShowProgressBar(true);
  progress->Open();
  for (unsigned int i = 0; i < 100; i += 1)
  {
    progress->SetPercentage(i);
    if (OAuthRequest(code_req) == WAIPU_LOGIN_STATUS::OK)
    {
      ret = WAIPU_LOGIN_STATUS::OK;
      kodi::Log(ADDON_LOG_DEBUG, "OAuth success!");
      break;
    }

    kodi::Log(ADDON_LOG_DEBUG, "OAuth pending");

    if (progress->IsCanceled())
    {
      progress->Abort();
      ret = WAIPU_LOGIN_STATUS::INVALID_CREDENTIALS;
      kodi::Log(ADDON_LOG_DEBUG, "OAuth login canceled");
      break;
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));
  }

  progress->Abort();
  delete progress;

  return ret;
}

bool WaipuData::RefreshDeviceCapabiltiesToken()
{
  kodi::Log(ADDON_LOG_DEBUG, "%s - Creating the waipu.tv PVR add-on", __FUNCTION__);

  kodi::Log(ADDON_LOG_DEBUG, "[device token] expire time %i", m_deviceCapabilitiesToken.getExp());
  if (m_deviceCapabilitiesToken.isInitialized() && !m_deviceCapabilitiesToken.isExpired(5 * 60))
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

  kodi_version_t kodi_version;
  kodi::KodiVersion(kodi_version);

  bool cap_audio_aac = kodi::addon::GetSettingBoolean("streaming_capabilities_audio_aac", false);

  std::string capabilitesData =
      "{\"type\": \"receiver\", \"model\": \"Kodi " + std::to_string(kodi_version.major) + "." +
      std::to_string(kodi_version.minor) +
      "\", \"manufacturer\": \"Team Kodi\", "
      "\"platform\": \"Kodi " +
      std::to_string(kodi_version.major) + "." + std::to_string(kodi_version.minor) +
      "-pvr.waipu\", \"appVersion\": \"" + appVersion +
      "\", \"capabilities\": {\"audio\": {\"aac\": " + (cap_audio_aac ? "true" : "false") +
      "},\"video\": { ";

  std::vector<std::string> video_cap_options = {"sdpalp25",    "sdpalp50",   "hd720p25",
                                                "hd720p50",    "hd1080p25",  "hd1080p50",
                                                "hevc1080p50", "hevc2160p50"};
  bool first = true;
  for (const std::string& cap_option : video_cap_options)
  {
    bool cap_value =
        kodi::addon::GetSettingBoolean("streaming_capabilities_video_" + cap_option, false);
    capabilitesData +=
        std::string(first ? "" : ",") + "\"" + cap_option + "\": " + (cap_value ? "true" : "false");
    first = false;
  }
  capabilitesData += "}}}";

  std::string jsonDeviceToken =
      HttpPost("https://device-capabilities.waipu.tv/api/device-capabilities", capabilitesData,
               {{"Content-Type", "application/vnd.dc.device-info-v1+json"},
                {"X-USERCONTEXT-USERHANDLE", m_userhandle.c_str()}});

  kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] response: %s", jsonDeviceToken.c_str());

  std::string deviceToken;

  rapidjson::Document deviceTokenDoc;
  deviceTokenDoc.Parse(jsonDeviceToken.c_str());
  if (deviceTokenDoc.HasParseError())
  {
    kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] parse error :(");
    return false;
  }

  if (deviceTokenDoc.HasMember("token"))
  {
    m_deviceCapabilitiesToken = JWT(deviceTokenDoc["token"].GetString());
    kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] discovered token: %s",
              m_deviceCapabilitiesToken.getToken().c_str());
    return true;
  }

  kodi::Log(ADDON_LOG_DEBUG, "[X-Device-Token] unknown error :(");
  return false;
}

void WaipuData::ReadSettings()
{
  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);

  m_username = kodi::addon::GetSettingString("username");
  m_password = kodi::addon::GetSettingString("password");
  m_protocol = kodi::addon::GetSettingString("protocol", "auto");
  m_provider = kodi::addon::GetSettingEnum<WAIPU_PROVIDER>("provider_select", WAIPU_PROVIDER_WAIPU);
  m_channel_filter = kodi::addon::GetSettingEnum<WAIPU_CHANNEL_IMPORT_FILTER>(
      "channel_import_filter", CHANNEL_FILTER_ALL_VISIBLE);
  m_epg_show_preview_images = kodi::addon::GetSettingBoolean("epg_show_preview_images");
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
    m_protocol = settingValue.GetString();
    return ADDON_STATUS_OK;
  }
  else if (settingName == "epg_show_preview_images")
  {
    m_epg_show_preview_images = settingValue.GetBoolean();
    return ADDON_STATUS_OK;
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
  }
  else if (settingName == "channel_import_filter")
  {
    WAIPU_CHANNEL_IMPORT_FILTER tmpFilter = settingValue.GetEnum<WAIPU_CHANNEL_IMPORT_FILTER>();
    if (tmpFilter != m_channel_filter)
    {
      m_channel_filter = tmpFilter;
      // we need to restart plugin for now, to LoadChannelData()
      //kodi::addon::CInstancePVRClient::TriggerChannelUpdate();
      //return ADDON_STATUS_OK;
      return ADDON_STATUS_NEED_RESTART;
    }
  }
  else if (settingName.rfind("streaming_capabilities_", 0) == 0)
  {
    // settings name begins with "streaming_capabilities_"
    // reset capabilities to force refresh
    m_deviceCapabilitiesToken = JWT();
  }
  else if (settingName == "refresh_reset" && settingValue.GetBoolean())
  {
    kodi::addon::SetSettingBoolean("refresh_reset", false);
    kodi::addon::SetSettingString("refresh_token", "");
    return ADDON_STATUS_NEED_RESTART;
  }
  else if (settingName == "recordings_additional_infos")
  {
    kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
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
  capabilities.SetSupportsLastPlayedPosition(true);

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
  return m_license;
}

void WaipuData::SetStreamProperties(std::vector<kodi::addon::PVRStreamProperty>& properties,
                                    const std::string& url,
                                    bool realtime,
                                    bool playTimeshiftBuffer,
                                    const std::string& protocol)
{
  kodi::Log(ADDON_LOG_DEBUG, "[PLAY STREAM] url: %s", url.c_str());

  properties.emplace_back(PVR_STREAM_PROPERTY_STREAMURL, url);
  properties.emplace_back(PVR_STREAM_PROPERTY_ISREALTIMESTREAM, realtime ? "true" : "false");

  if (protocol == "dash" && Utils::CheckInputstreamInstalledAndEnabled("inputstream.adaptive"))
  {
    // MPEG DASH
    kodi::Log(ADDON_LOG_DEBUG, "[PLAY STREAM] dash");
    properties.emplace_back(PVR_STREAM_PROPERTY_INPUTSTREAM, "inputstream.adaptive");
    properties.emplace_back("inputstream.adaptive.manifest_type", "mpd");
    properties.emplace_back(PVR_STREAM_PROPERTY_MIMETYPE, "application/xml+dash");

    if (playTimeshiftBuffer)
    {
      properties.emplace_back("inputstream.adaptive.play_timeshift_buffer", "true");
    }

    // get widevine license
    std::string license = GetLicense();
    properties.emplace_back("inputstream.adaptive.license_type", "com.widevine.alpha");
    properties.emplace_back("inputstream.adaptive.license_key",
                            "https://drm.wpstr.tv/license-proxy-widevine/cenc/"
                            "|Content-Type=text%2Fxml&x-dt-custom-data=" +
                                license + "|R{SSM}|JBlicense");
  }
  else if (protocol == "hls" && kodi::addon::GetSettingBoolean("streaming_use_ffmpegdirect", false))
  {
    if (!Utils::CheckInputstreamInstalledAndEnabled("inputstream.ffmpegdirect"))
    {
      kodi::addon::SetSettingBoolean("streaming_use_ffmpegdirect", false);
      return;
    }
    // HLS
    kodi::Log(ADDON_LOG_DEBUG, "[PLAY STREAM] hls using inputstream.ffmpegdirect");
    properties.emplace_back(PVR_STREAM_PROPERTY_INPUTSTREAM, "inputstream.ffmpegdirect");
    properties.emplace_back("inputstream.ffmpegdirect.manifest_type", "hls");
    properties.emplace_back(PVR_STREAM_PROPERTY_MIMETYPE, "application/x-mpegURL");
    properties.emplace_back("inputstream.ffmpegdirect.is_realtime_stream",
                            realtime ? "true" : "false");
  }
  else if (protocol == "hls" && Utils::CheckInputstreamInstalledAndEnabled("inputstream.adaptive"))
  {
    kodi::Log(ADDON_LOG_DEBUG,
              "[SetStreamProperties] play protocol '%s' using inputstream adaptive",
              protocol.c_str());

    properties.emplace_back(PVR_STREAM_PROPERTY_INPUTSTREAM, "inputstream.adaptive");
    properties.emplace_back("inputstream.adaptive.manifest_type", "hls");
    properties.emplace_back(PVR_STREAM_PROPERTY_MIMETYPE, "application/x-mpegURL");

    if (playTimeshiftBuffer)
    {
      properties.emplace_back("inputstream.adaptive.play_timeshift_buffer", "true");
    }
  }
  else
  {
    kodi::Log(
        ADDON_LOG_ERROR,
        "[SetStreamProperties] called with invalid protocol '%s' or missing inputstream addon.",
        protocol.c_str());
  }
}

bool WaipuData::LoadChannelData()
{
  if (m_channels.size() > 0)
    return true;

  // no valid session
  if (!IsConnected())
    return false;

  std::lock_guard<std::mutex> lock(mutex);

  std::string stationConfigJson = HttpGet("https://web-proxy.waipu.tv/station-config");
  kodi::Log(ADDON_LOG_DEBUG, "[%s] Station config JSON: %s", __FUNCTION__,
            stationConfigJson.c_str());

  rapidjson::Document stationConfigDoc;
  stationConfigDoc.Parse(stationConfigJson.c_str());
  if (stationConfigDoc.HasParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[%s] Error while parsing station config JSON", __FUNCTION__);
    m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
    return false;
  }
  const auto& stationConfigs = stationConfigDoc["stations"].GetArray();

  std::string userStationsJson =
      HttpGet("https://user-stations.waipu.tv/api/stations?omitted=false");
  kodi::Log(ADDON_LOG_DEBUG, "[%s] User stations JSON: %s", __FUNCTION__, userStationsJson.c_str());

  rapidjson::Document doc;
  doc.Parse(userStationsJson.c_str());
  if (doc.HasParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[%s] Error while parsing user stations JSON", __FUNCTION__);
    m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;
    return false;
  }

  WaipuChannelGroup cgroup_fav;
  cgroup_fav.name = "Favoriten";

  WaipuChannelGroup cgroup_live;
  cgroup_live.name = "Live TV";

  WaipuChannelGroup cgroup_vod;
  cgroup_vod.name = "VoD";

  for (rapidjson::SizeType i = 0; i < doc.Size(); i++)
  {
    const auto& channel = doc[i];
    const std::string waipuId = channel["stationId"].GetString();

    const auto& stationConfig =
        std::find_if(stationConfigs.begin(), stationConfigs.end(),
                     [waipuId](const auto& v) { return v["id"].GetString() == waipuId; });
    if (stationConfig == stationConfigs.end())
      continue;

    WaipuChannel waipuChannel;

    waipuChannel.iChannelNumber = i + 1; // position
    waipuChannel.waipuID = waipuId; // waipu[id]
    // workaround: transform Station ID to uppercase, since old API (for recordings/timers) needs this
    std::transform(waipuChannel.waipuID.begin(), waipuChannel.waipuID.end(),
                   waipuChannel.waipuID.begin(), ::toupper);
    waipuChannel.iUniqueId = Utils::Hash(waipuId);
    waipuChannel.strChannelName = channel["displayName"].GetString(); // waipu[displayName]

    std::string iconUrl = (*stationConfig)["logoTemplateUrl"].GetString();
    iconUrl = std::regex_replace(iconUrl, std::regex("\\$\\{streamQuality\\}"),
                                 channel["streamQuality"].GetString());
    iconUrl = std::regex_replace(iconUrl, std::regex("\\$\\{shape\\}"), "standard");
    iconUrl = std::regex_replace(iconUrl, std::regex("\\$\\{resolution\\}"), "320x180");

    std::string iconPath =
        "special://home/addons/pvr.waipu/resources/channel_icons/" + waipuChannel.waipuID + ".png";
    if (!kodi::vfs::FileExists(iconPath, true))
    {
      kodi::Log(ADDON_LOG_DEBUG, "[%s] Downloading channel logo %s to %s", __FUNCTION__,
                iconUrl.c_str(), iconPath.c_str());
      Utils::FileDownload(iconUrl, iconPath);
    }
    waipuChannel.strIconPath = iconPath;

    const auto& userSettings = channel["userSettings"].GetObject();
    bool isFav = userSettings["favorite"].GetBool();
    bool isVisible = userSettings["visible"].GetBool();
    waipuChannel.tvfuse = (*stationConfig)["newTv"].GetBool();

    // skip if we do not enforce to show all
    if (m_channel_filter != CHANNEL_FILTER_ALL && !isVisible)
      continue;

    // Apply LiveTV filter (=!tvfuse)
    if (m_channel_filter == CHANNEL_FILTER_LIVE && waipuChannel.tvfuse)
      continue;

    // Apply Favourites filter
    if (m_channel_filter == CHANNEL_FILTER_FAVOURITES && !isFav)
      continue;

    // user added channel to favorites
    if (isFav)
      cgroup_fav.channels.emplace_back(waipuChannel);

    if (waipuChannel.tvfuse) // Video on Demand channel
      cgroup_vod.channels.emplace_back(waipuChannel);
    else // Not VoD -> Live TV
      cgroup_live.channels.emplace_back(waipuChannel);

    kodi::Log(ADDON_LOG_DEBUG,
              "[channel] number: %i, tvfuse: %i, waipuId: %s, id: %i, name: %s, logo: %s",
              waipuChannel.iChannelNumber, waipuChannel.tvfuse, waipuChannel.waipuID.c_str(),
              waipuChannel.iUniqueId, waipuChannel.strChannelName.c_str(),
              waipuChannel.strIconPath.c_str());

    m_channels.emplace_back(waipuChannel);
  }

  if (!cgroup_fav.channels.empty())
    m_channelGroups.emplace_back(cgroup_fav);
  if (!cgroup_live.channels.empty())
    m_channelGroups.emplace_back(cgroup_live);
  if (!cgroup_vod.channels.empty())
    m_channelGroups.emplace_back(cgroup_vod);

  return true;
}

PVR_ERROR WaipuData::GetChannelsAmount(int& amount)
{
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
  LoadChannelData();

  amount = static_cast<int>(m_channels.size());
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannels(bool radio, kodi::addon::PVRChannelsResultSet& results)
{
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  if (radio)
  {
    kodi::Log(ADDON_LOG_ERROR,
              "[%s] ERROR: Function was called with invalid parameter 'radio: true'", __FUNCTION__);
    return PVR_ERROR_INVALID_PARAMETERS;
  }

  kodi::Log(ADDON_LOG_DEBUG, "waipu.tv function call: [%s]", __FUNCTION__);
  LoadChannelData();

  for (const auto& channel : m_channels)
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
        }
        break;
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

std::string WaipuData::GetChannelStreamURL(int uniqueId,
                                           const std::string& protocol,
                                           const std::string& startTime)
{
  if (!IsConnected())
  {
    kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] No stream login");
    return "";
  }

  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId == uniqueId)
    {
      kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] Get live URL for channel %s",
                channel.strChannelName.c_str());

      // ensure device token is fresh
      RefreshDeviceCapabiltiesToken();

      std::string postData = "{\"stream\": { \"station\": \"" + channel.waipuID +
                             "\", \"protocol\": \"" + protocol +
                             "\", \"requestMuxInstrumentation\": false";
      if (!startTime.empty())
      {
        postData += ", \"startTime\": " + startTime;
      }
      postData += "}}";
      kodi::Log(ADDON_LOG_DEBUG, "[GetStreamURL] Post data: %s", postData.c_str());

      std::string jsonStreamURL = HttpPost(
          "https://stream-url-provider.waipu.tv/api/stream-url", postData,
          {{"Content-Type", "application/vnd.streamurlprovider.stream-url-request-v1+json"},
           {"X-Device-Token", m_deviceCapabilitiesToken.getToken().c_str()}});

      rapidjson::Document streamURLDoc;
      streamURLDoc.Parse(jsonStreamURL.c_str());
      if (streamURLDoc.HasParseError())
      {
        kodi::Log(ADDON_LOG_ERROR, "[GetStreamURL] ERROR: error while parsing json");
        return "";
      }

      if (streamURLDoc.HasMember("status") && streamURLDoc["status"].GetInt() == 403)
      {
        if (streamURLDoc.HasMember("type"))
        {
          std::string error_type = streamURLDoc["type"].GetString();
          kodi::Log(ADDON_LOG_ERROR, "[GetStreamURL] ERROR 403: %s", error_type.c_str());
          if (error_type == "stream-url-provider/channel-forbidden")
          {
            m_channels.clear();
            kodi::addon::CInstancePVRClient::TriggerChannelUpdate();
          }
          return "";
        }
      }

      if (!streamURLDoc.HasMember("streamUrl"))
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
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  LoadChannelData();
  amount = static_cast<int>(m_channelGroups.size());
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetChannelGroups(bool radio, kodi::addon::PVRChannelGroupsResultSet& results)
{
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  if (radio)
  {
    kodi::Log(ADDON_LOG_ERROR,
              "[%s] ERROR: Function was called with invalid parameter 'radio: true'", __FUNCTION__);
    return PVR_ERROR_INVALID_PARAMETERS;
  }

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
  if (group.GetIsRadio())
  {
    kodi::Log(ADDON_LOG_ERROR, "[%s] ERROR: Function was called with a group having 'radio: true'",
              __FUNCTION__);
    return PVR_ERROR_INVALID_PARAMETERS;
  }

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
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  LoadChannelData();

  bool has_results = false;
  bool epg_experimental = kodi::addon::GetSettingBoolean("epg_experimental");

  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId != channelUid)
      continue;

    std::string startTime = Utils::TimeToString(start);
    std::string endTime = Utils::TimeToString(end);

    std::string jsonEpg = HttpGet("https://epg.waipu.tv/api/channels/" + channel.waipuID +
                                  "/programs?startTime=" + std::string(startTime) +
                                  "&stopTime=" + std::string(endTime));
    kodi::Log(ADDON_LOG_DEBUG, "[epg-all] %s", jsonEpg.c_str());
    if (jsonEpg.empty())
    {
      kodi::Log(ADDON_LOG_DEBUG, "%s - Empty server response", __FUNCTION__);
      return PVR_ERROR_SERVER_ERROR;
    }
    jsonEpg = "{\"result\": " + jsonEpg + "}";

    rapidjson::Document epgDoc;
    epgDoc.Parse(jsonEpg.c_str());
    if (epgDoc.HasParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[%s] Error while parsing JSON", __FUNCTION__);
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
      if (isRecordable)
      {
        flags |= EPG_TAG_FLAG_IS_RECORDABLE_WAIPU;
      }

      // instantRestartAllowed
      bool instantRestartAllowed = !epgData["instantRestartForbidden"].GetBool();
      kodi::Log(ADDON_LOG_DEBUG, "[epg] instantRestartAllowed: %i;", instantRestartAllowed);
      if (isRecordable)
      {
        flags |= EPG_TAG_FLAG_INSTANT_RESTART_ALLOWED_WAIPU;
      }

      // set title
      tag.SetTitle(epgData["title"].GetString());
      kodi::Log(ADDON_LOG_DEBUG, "[epg] title: %s;", epgData["title"].GetString());

      // set startTime
      const std::string entryStartTime = epgData["startTime"].GetString();
      tag.SetStartTime(Utils::StringToTime(entryStartTime));

      // set endTime
      const std::string entryEndTime = epgData["stopTime"].GetString();
      tag.SetEndTime(Utils::StringToTime(entryEndTime));

      // tag.SetPlotOutline(myTag.strPlotOutline);

      // set description
      if (epgData.HasMember("description") && !epgData["description"].IsNull())
      {
        tag.SetPlot(epgData["description"].GetString());
        kodi::Log(ADDON_LOG_DEBUG, "[epg] description: %s;", epgData["description"].GetString());
      }

      // epg preview image
      if (m_epg_show_preview_images && epgData.HasMember("previewImages") &&
          epgData["previewImages"].IsArray() && epgData["previewImages"].Size() > 0)
      {
        std::string tmp_img = epgData["previewImages"][0].GetString();
        tmp_img += "?width=480&height=270";
        tag.SetIconPath(tmp_img);
        kodi::Log(ADDON_LOG_DEBUG, "[epg] previewImage: %s;", tmp_img.c_str());
      }

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
        const int year = Utils::StringToInt(epgData["year"].GetString(), 1970);
        if (year > 1970)
          tag.SetYear(year);
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
      has_results = true;
      tag.SetFlags(flags);
      results.Add(tag);
    }
    if (epg_experimental && !has_results)
    {
      return GetEPGForChannelNew(channelUid, start, end, results);
    }
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetEPGForChannelNew(int channelUid,
                                         time_t start,
                                         time_t end,
                                         kodi::addon::PVREPGTagsResultSet& results)
{
  const int grid_align_hours = 4; // align 4h

  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId != channelUid)
      continue;

    std::string channelid = channel.waipuID;

    std::transform(channelid.begin(), channelid.end(), channelid.begin(), ::tolower);

    kodi::Log(ADDON_LOG_DEBUG, "[epg-new] channel: %s", channelid.c_str());
    std::string endTime = Utils::TimeToString(end);

    int limit = 32;

    while (start < end)
    {
      limit--;

      struct tm* tm = std::gmtime(&start);
      tm->tm_hour -= tm->tm_hour % grid_align_hours; // align to grid window
      kodi::Log(ADDON_LOG_DEBUG, "[epg-new] tm %d", tm->tm_hour);

      char startTimeBuf[30];
      // 2024-05-17T17:00:00.000Z
      strftime(startTimeBuf, 30, "%Y-%m-%dT%H:00:00.000Z", tm);

      std::string jsonEpg =
          HttpGet("https://epg-cache.waipu.tv/api/grid/" + channelid + "/" + startTimeBuf);
      kodi::Log(ADDON_LOG_DEBUG, "[epg-new] %s", jsonEpg.c_str());
      if (jsonEpg.empty())
      {
        kodi::Log(ADDON_LOG_ERROR, "[epg-new] empty server response");
        return PVR_ERROR_SERVER_ERROR;
      }
      jsonEpg = "{\"result\": " + jsonEpg + "}";

      rapidjson::Document epgDoc;
      epgDoc.Parse(jsonEpg.c_str());
      if (epgDoc.HasParseError())
      {
        kodi::Log(ADDON_LOG_ERROR, "[GetEPG] ERROR: error while parsing json");
        return PVR_ERROR_SERVER_ERROR;
      }

      kodi::Log(ADDON_LOG_DEBUG, "[epg-new] size: %i;", epgDoc["result"].Size());

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

        unsigned int flags = EPG_TAG_FLAG_UNDEFINED;

        // is recordable
        bool isRecordable = !epgData["recordingForbidden"].GetBool();
        kodi::Log(ADDON_LOG_DEBUG, "[epg-new] recordable: %i;", isRecordable);
        if (isRecordable)
        {
          flags |= EPG_TAG_FLAG_IS_RECORDABLE_WAIPU;
          flags |= EPG_TAG_FLAG_INSTANT_RESTART_ALLOWED_WAIPU;
        }

        // set title
        tag.SetTitle(epgData["title"].GetString());
        kodi::Log(ADDON_LOG_DEBUG, "[epg] title: %s;", epgData["title"].GetString());

        // set startTime
        const std::string entryStartTime = epgData["startTime"].GetString();
        tag.SetStartTime(Utils::StringToTime(entryStartTime));

        // set endTime
        const std::string entryEndTime = epgData["stopTime"].GetString();
        tag.SetEndTime(Utils::StringToTime(entryEndTime));

        // epg preview image
        if (m_epg_show_preview_images && epgData.HasMember("previewImage"))
        {
          std::string tmp_img = epgData["previewImage"].GetString();
          tag.SetIconPath(tmp_img);
          kodi::Log(ADDON_LOG_DEBUG, "[epg] previewImage: %s;", tmp_img.c_str());
        }

        if (epgData.HasMember("seriesId") && !epgData["seriesId"].IsNull())
        {
          flags |= EPG_TAG_FLAG_IS_SERIES;
          tag.SetSeriesNumber(EPG_TAG_INVALID_SERIES_EPISODE);
        }

        // episodeName
        if (epgData.HasMember("episodeTitle") && !epgData["episodeTitle"].IsNull())
        {
          tag.SetEpisodeName(epgData["episodeTitle"].GetString());
        }

        // genre
        if (epgData.HasMember("genre") && !epgData["genre"].IsNull())
        {
          const std::string genreStr = epgData["genre"].GetString();
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
      start = start + grid_align_hours * 60 * 60;
      if (limit < 1)
        break;
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
    if (isPlayable)
    {
      return PVR_ERROR_NO_ERROR;
    }
  }

  // check if program is running and replay allowed
  auto current_time = time(NULL);
  if (m_account_replay_allowed && current_time > tag.GetStartTime() &&
      (current_time < tag.GetEndTime() || current_time - 60 * 60 < tag.GetStartTime()))
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
  if (protocol == "auto")
    protocol = "dash"; //fallback to dash

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
  for (const auto& channel : m_channels)
  {
    if (channel.iUniqueId == tag.GetUniqueChannelId())
    {
      std::string startTime = Utils::TimeToString(tag.GetStartTime());
      std::string endTime = Utils::TimeToString(tag.GetEndTime());

      std::string jsonEpg =
          HttpGet("https://epg.waipu.tv/api/channels/" + channel.waipuID +
                  "/programs?includeRunningAtStartTime=false&startTime=" + std::string(startTime) +
                  "&stopTime=" + std::string(endTime));
      kodi::Log(ADDON_LOG_DEBUG, "[epg-single-tag] %s", jsonEpg.c_str());
      if (jsonEpg.empty())
      {
        kodi::Log(ADDON_LOG_ERROR, "[epg-single-tag] empty server response");
        return "";
      }
      jsonEpg = "{\"result\": " + jsonEpg + "}";

      rapidjson::Document epgDoc;
      epgDoc.Parse(jsonEpg.c_str());

      if (epgDoc.HasParseError() || epgDoc["result"].Empty() ||
          !epgDoc["result"][0].HasMember("streamUrlProvider") ||
          epgDoc["result"][0]["streamUrlProvider"].IsNull())
      {
        // fallback to replay playback
        kodi::Log(ADDON_LOG_DEBUG,
                  "[play epg tag] streamUrlProvider not found -> fallback to replay!");
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
        if (tagDoc.HasParseError())
        {
          kodi::Log(ADDON_LOG_ERROR, "[getEPGTagURL] ERROR: error while parsing json");
          return "";
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
  return "";
}

PVR_ERROR WaipuData::GetRecordingsAmount(bool deleted, int& amount)
{
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  amount = m_recordings_count;
  return PVR_ERROR_NO_ERROR;
}

kodi::addon::PVRRecording WaipuData::ParseRecordingEntry(const rapidjson::Value& recordingEntry)
{

  kodi::addon::PVRRecording tag;
  bool isSeries = false;

  tag.SetIsDeleted(false);
  std::string recordingId = recordingEntry["id"].GetString();
  tag.SetRecordingId(recordingId);
  tag.SetPlayCount(recordingEntry.HasMember("fullyWatchedCount") &&
                   recordingEntry["fullyWatchedCount"].GetInt());

  const std::string rec_title = recordingEntry["title"].GetString();
  tag.SetTitle(rec_title);

  if (recordingEntry.HasMember("previewImage") && !recordingEntry["previewImage"].IsNull())
  {
    std::string rec_img = recordingEntry["previewImage"].GetString();
    rec_img = std::regex_replace(rec_img, std::regex("\\$\\{resolution\\}"), "320x180");
    tag.SetIconPath(rec_img);
    tag.SetThumbnailPath(rec_img);
  }

  if (recordingEntry.HasMember("durationSeconds") && !recordingEntry["durationSeconds"].IsNull())
    tag.SetDuration(recordingEntry["durationSeconds"].GetInt());

  if (recordingEntry.HasMember("positionPercentage") &&
      !recordingEntry["positionPercentage"].IsNull())
  {
    int positionPercentage = recordingEntry["positionPercentage"].GetInt();
    int position = tag.GetDuration() * positionPercentage / 100;
    tag.SetLastPlayedPosition(position);
  }

  if (recordingEntry.HasMember("recordingStartTime") &&
      !recordingEntry["recordingStartTime"].IsNull())
    tag.SetRecordingTime(Utils::StringToTime(recordingEntry["recordingStartTime"].GetString()));

  if (recordingEntry.HasMember("genreDisplayName") && !recordingEntry["genreDisplayName"].IsNull())
  {
    std::string genreStr = recordingEntry["genreDisplayName"].GetString();
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

  if (recordingEntry.HasMember("episodeTitle") && !recordingEntry["episodeTitle"].IsNull())
  {
    tag.SetEpisodeName(recordingEntry["episodeTitle"].GetString());
    isSeries = true;
  }

  if (recordingEntry.HasMember("season") && !recordingEntry["season"].IsNull())
    tag.SetSeriesNumber(Utils::StringToInt(recordingEntry["season"].GetString(),
                                           PVR_RECORDING_INVALID_SERIES_EPISODE));

  if (recordingEntry.HasMember("episode") && !recordingEntry["episode"].IsNull())
    tag.SetEpisodeNumber(Utils::StringToInt(recordingEntry["episode"].GetString(),
                                            PVR_RECORDING_INVALID_SERIES_EPISODE));

  // epg mapping
  if (recordingEntry.HasMember("programId") && !recordingEntry["programId"].IsNull())
  {
    std::string epg_id = recordingEntry["programId"].GetString();
    int dirtyID = Utils::GetIDDirty(epg_id);
    tag.SetEPGEventId(dirtyID);
  }

  // not every series is correctly tagged - lets assume recording groups are also series
  if (recordingEntry.HasMember("recordingGroup"))
    isSeries = true;

  if (isSeries)
  {
    tag.SetFlags(PVR_RECORDING_FLAG_IS_SERIES);
    tag.SetDirectory(rec_title);
  }

  // Additional program details like year or plot are on available in an additional details request. Maybe we should provide this as settings option?
  if (kodi::addon::GetSettingBoolean("recordings_additional_infos", false))
  {

    std::string json = HttpGet("https://recording.waipu.tv/api/recordings/" + recordingId,
                               {{"Accept", "application/vnd.waipu.recording-v4+json"}});
    kodi::Log(ADDON_LOG_DEBUG, "[recordings] %s", json.c_str());

    rapidjson::Document doc;
    doc.Parse(json.c_str());
    if (!doc.HasParseError())
    {
      if (doc.HasMember("programDetails"))
      {
        if (doc["programDetails"].HasMember("textContent"))
        {
          if (doc["programDetails"]["textContent"].HasMember("descLong"))
          {
            std::string descr = doc["programDetails"]["textContent"]["descLong"].GetString();
            tag.SetPlot(descr);
            tag.SetPlotOutline(descr);
          }
          else if (doc["programDetails"]["textContent"].HasMember("descShort"))
          {
            std::string descr = doc["programDetails"]["textContent"]["descShort"].GetString();
            tag.SetPlot(descr);
            tag.SetPlotOutline(descr);
          }
        }
        if (doc["programDetails"].HasMember("production"))
        {
          if (doc["programDetails"]["production"].HasMember("year"))
          {
            std::string year = doc["programDetails"]["production"]["year"].GetString();
            tag.SetYear(Utils::StringToInt(year, 1970));
          }
        }
      }
    }
  }
  return tag;
}

PVR_ERROR WaipuData::GetRecordings(bool deleted, kodi::addon::PVRRecordingsResultSet& results)
{
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  m_active_recordings_update = true;

  {
    std::string recordingGroupsJSON =
        HttpGet("https://recording.waipu.tv/api/recordings",
                {{"Accept", "application/vnd.waipu.recordings-v4+json"}});
    kodi::Log(ADDON_LOG_DEBUG, "[recordingGroupsJSON] %s", recordingGroupsJSON.c_str());

    rapidjson::Document recordingGroupsDoc;
    recordingGroupsDoc.Parse(recordingGroupsJSON.c_str());
    if (recordingGroupsDoc.HasParseError())
    {
      kodi::Log(ADDON_LOG_ERROR, "[GetRecordings] ERROR: error while parsing recordingGroupsJSON");
      return PVR_ERROR_SERVER_ERROR;
    }
    kodi::Log(ADDON_LOG_DEBUG, "[recordings] getGroups");
    std::set<int> recordingGroups;
    int recordings_count = 0;

    for (const auto& recordingEntry : recordingGroupsDoc.GetArray())
    {
      // skip not FINISHED entries
      std::string status = recordingEntry["status"].GetString();

      if (recordingEntry.HasMember("recordingGroup") && recordingEntry["recordingGroup"].IsInt())
      {
        int recordingGroup = recordingEntry["recordingGroup"].GetInt();
        kodi::Log(ADDON_LOG_DEBUG, "[recordings] found group: %i;", recordingGroup);
        recordingGroups.insert(recordingGroup);
      }
      else if (status == "FINISHED" || status == "RECORDING")
      {
        recordings_count++;
        results.Add(ParseRecordingEntry(recordingEntry));
      }
    }

    for (const int& recordingGroup : recordingGroups)
    {
      std::string json = HttpGet("https://recording.waipu.tv/api/recordings?recordingGroup=" +
                                     std::to_string(recordingGroup),
                                 {{"Accept", "application/vnd.waipu.recordings-v4+json"}});
      kodi::Log(ADDON_LOG_DEBUG, "[recordings] %s", json.c_str());

      rapidjson::Document doc;
      doc.Parse(json.c_str());
      if (doc.HasParseError())
      {
        kodi::Log(ADDON_LOG_ERROR, "[GetRecordings] ERROR: error while parsing json");
        return PVR_ERROR_SERVER_ERROR;
      }
      kodi::Log(ADDON_LOG_DEBUG, "[recordings] iterate entries");
      kodi::Log(ADDON_LOG_DEBUG, "[recordings] size: %i;", doc.Size());

      for (const rapidjson::Value& recordingEntry : doc.GetArray())
      {
        // skip not FINISHED entries
        std::string status = recordingEntry["status"].GetString();
        if (status != "FINISHED" && status != "RECORDING")
          continue;

        recordings_count++;
        results.Add(ParseRecordingEntry(recordingEntry));
      }
    }
    m_recordings_count = recordings_count;
  }

  {
    std::string json = HttpGet("https://recording.waipu.tv/api/recordings/summary",
                               {{"Accept", "application/vnd.waipu.recording-summary-v2+json"}});
    kodi::Log(ADDON_LOG_DEBUG, "[recordings summary] %s", json.c_str());
    rapidjson::Document doc;
    doc.Parse(json.c_str());
    if (!doc.HasParseError() && doc.HasMember("finishedRecordingsSeconds"))
    {
      m_finishedRecordingsSeconds = doc["finishedRecordingsSeconds"].GetInt();
    }
  }

  m_active_recordings_update = false;

  return PVR_ERROR_NO_ERROR;
}

std::string WaipuData::GetRecordingURL(const kodi::addon::PVRRecording& recording,
                                       const std::string& protocol)
{
  std::string recording_id = recording.GetRecordingId();
  kodi::Log(ADDON_LOG_DEBUG, "play recording -> %s", recording_id.c_str());

  std::string rec_resp = HttpGet("https://recording.waipu.tv/api/recordings/" + recording_id);
  kodi::Log(ADDON_LOG_DEBUG, "recording resp -> %s", rec_resp.c_str());

  rapidjson::Document recordingDoc;
  recordingDoc.Parse(rec_resp.c_str());
  if (recordingDoc.HasParseError())
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
  return "";
}

PVR_ERROR WaipuData::DeleteRecording(const kodi::addon::PVRRecording& recording)
{
  if (!IsConnected())
    return PVR_ERROR_FAILED;

  std::string recording_id = recording.GetRecordingId();
  std::string request_data = "{\"ids\":[\"" + recording_id + "\"]}";
  kodi::Log(ADDON_LOG_DEBUG, "[delete recording] req: %s;", request_data.c_str());
  std::string deleted =
      HttpDelete("https://recording.waipu.tv/api/recordings", request_data.c_str(),
                 {{"Content-Type", "application/vnd.waipu.pvr-recording-ids-v2+json"}});
  kodi::Log(ADDON_LOG_DEBUG, "[delete recording] response: %s;", deleted.c_str());
  kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetRecordingStreamProperties(
    const kodi::addon::PVRRecording& recording,
    std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  kodi::Log(ADDON_LOG_DEBUG, "[recordings] play it...");
  LoadChannelData();

  std::string protocol = m_protocol;
  if (protocol == "auto")
    protocol = "dash"; //fallback to dash

  std::string strUrl = GetRecordingURL(recording, protocol);
  if (strUrl.empty())
  {
    return PVR_ERROR_FAILED;
  }

  SetStreamProperties(properties, strUrl, true, true, protocol);

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
  AddTimerType(types, 2,
               PVR_TIMER_TYPE_REQUIRES_EPG_SERIES_ON_CREATE | PVR_TIMER_TYPE_IS_REPEATING);

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetTimersAmount(int& amount)
{
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  amount = m_timers_count;
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetTimers(kodi::addon::PVRTimersResultSet& results)
{
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  LoadChannelData();

  std::string jsonRecordings = HttpGet("https://recording.waipu.tv/api/recordings",
                                       {{"Accept", "application/vnd.waipu.recordings-v2+json"}});
  kodi::Log(ADDON_LOG_DEBUG, "[Timers] %s", jsonRecordings.c_str());

  jsonRecordings = "{\"result\": " + jsonRecordings + "}";

  rapidjson::Document timersDoc;
  timersDoc.Parse(jsonRecordings.c_str());
  if (timersDoc.HasParseError())
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
  if (!IsConnected())
    return PVR_ERROR_FAILED;

  if (timer.GetTimerType() == 1)
  {
    // single tag
    int timer_id = timer.GetClientIndex();
    std::string request_data = "{\"ids\":[\"" + std::to_string(timer_id) + "\"]}";
    kodi::Log(ADDON_LOG_DEBUG, "[delete single timer] req: %s;", request_data.c_str());
    std::string deleted =
        HttpDelete("https://recording.waipu.tv/api/recordings", request_data.c_str(),
                   {{"Content-Type", "application/vnd.waipu.pvr-recording-ids-v2+json"}});
    kodi::Log(ADDON_LOG_DEBUG, "[delete single timer] response: %s;", deleted.c_str());
    kodi::QueueNotification(QUEUE_INFO, "Recording", "Recording Deleted");
    kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
    kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
    return PVR_ERROR_NO_ERROR;
  }
  else
  {
    // delete record series
    int groupID = timer.GetClientIndex();
    std::string request_data = "{\"serialRecordings\":[{\"id\":" + std::to_string(groupID) +
                               ",\"deleteFutureRecordings\":true,\"deleteFinishedRecordings\":"
                               "false,\"deleteRunningRecordingss\":false}]}";
    kodi::Log(ADDON_LOG_DEBUG, "[delete multi timer] req (group: %i): %s;", groupID,
              request_data.c_str());
    std::string deleted =
        HttpPost("https://recording-scheduler.waipu.tv/api/delete-requests", request_data.c_str(),
                 {{"Content-Type",
                   "application/vnd.waipu.recording-scheduler-delete-serial-recordings-v1+json"}});
    kodi::Log(ADDON_LOG_DEBUG, "[delete multi timer] response: %s;", deleted.c_str());
    kodi::QueueNotification(QUEUE_INFO, "Recording", "Rule Deleted");
    kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
    kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
    return PVR_ERROR_NO_ERROR;
  }
}

PVR_ERROR WaipuData::AddTimer(const kodi::addon::PVRTimer& timer)
{
  // we currently only support epg based
  if (timer.GetEPGUid() <= EPG_TAG_INVALID_UID)
    return PVR_ERROR_REJECTED;

  if (!IsConnected())
    return PVR_ERROR_FAILED;

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
      std::string recordResp =
          HttpPost("https://recording.waipu.tv/api/recordings", postData,
                   {{"Content-Type", "application/vnd.waipu.start-recording-v2+json"}});
      kodi::Log(ADDON_LOG_DEBUG, "[add timer] single response: %s;", recordResp.c_str());
      kodi::QueueNotification(QUEUE_INFO, "Recording", "Recording Created");
      kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
    }
    else
    {
      // record series
      kodi::Log(ADDON_LOG_DEBUG, "[add timer] Record single tag;");
      // {"title":"Das A-Team","channel":"RTLNITRO"}
      std::string postData =
          "{\"title\": \"" + timer.GetTitle() + "\",\"channel\":\"" + channel.waipuID + "\"" + "}";
      std::string recordResp =
          HttpPost("https://recording-scheduler.waipu.tv/api/serials", postData,
                   {{"Content-Type", "application/vnd.waipu.recording-scheduler-serials-v1+json"}});
      kodi::Log(ADDON_LOG_DEBUG, "[add timer] repeating response: %s;", recordResp.c_str());
      kodi::QueueNotification(QUEUE_INFO, "Recording", "Rule Created");
      kodi::addon::CInstancePVRClient::TriggerRecordingUpdate();
      kodi::addon::CInstancePVRClient::TriggerTimerUpdate();
    }
  }
  return PVR_ERROR_NO_ERROR;
}

WaipuData::~WaipuData()
{
  m_loginThreadRunning = false;
  if (m_loginThread.joinable())
    m_loginThread.join();
}

ADDON_STATUS WaipuData::Create()
{
  kodi::Log(ADDON_LOG_DEBUG, "%s - Creating the waipu.tv PVR add-on", __FUNCTION__);

  // set User-Agent
  std::string ua = kodi::network::GetUserAgent();
  // use our replace, since kodi utils replaces all occurrences
  WAIPU_USER_AGENT =
      Utils::Replace(ua, " ", std::string(" pvr.waipu/").append(STR(IPTV_VERSION)).append(" "));

  ReadSettings();

  if (m_provider == WAIPU_PROVIDER_WAIPU && (m_username.empty() || m_password.empty()))
  {
    kodi::QueueNotification(QUEUE_ERROR, "", kodi::addon::GetLocalizedString(30033));
    return ADDON_STATUS_NEED_SETTINGS;
  }

  m_loginThreadRunning = true;
  m_loginThread = std::thread([&] { LoginThread(); });

  kodi::addon::CInstancePVRClient::ConnectionStateChange("Initializing",
                                                         PVR_CONNECTION_STATE_CONNECTING, "");

  return ADDON_STATUS_OK;
}

PVR_ERROR WaipuData::GetDriveSpace(uint64_t& total, uint64_t& used)
{
  if (!IsConnected())
    return PVR_ERROR_SERVER_ERROR;

  total = m_account_hours_recording * 1024 * 1024;
  used = m_finishedRecordingsSeconds > 0 ? m_finishedRecordingsSeconds * 1024 * 1024 / 3600 : 0;

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::OnSystemWake()
{
  m_accessToken = JWT();
  m_deviceCapabilitiesToken = JWT();
  m_nextLoginAttempt = 0;
  m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::GetRecordingLastPlayedPosition(const kodi::addon::PVRRecording& recording,
                                                    int& position)
{
  if (!IsConnected())
    return PVR_ERROR_FAILED;

  std::string responseJSON =
      HttpGet("https://stream-position.waipu.tv/api/stream-positions/" + recording.GetRecordingId(),
              {{"Content-Type", "application/json"}});

  if (responseJSON.empty())
  {
    kodi::Log(ADDON_LOG_DEBUG, "%s - Empty StreamPosition retrieved - start from beginning.",
              __FUNCTION__);
    position = 0;
    return PVR_ERROR_NO_ERROR;
  }

  kodi::Log(ADDON_LOG_DEBUG, "%s - Response: %s", __FUNCTION__, responseJSON.c_str());

  rapidjson::Document recordingPosDoc;
  recordingPosDoc.Parse(responseJSON.c_str());
  if (recordingPosDoc.HasParseError())
  {
    kodi::Log(ADDON_LOG_ERROR, "[%s] ERROR: Parsing StreamPosition JSON", __FUNCTION__);
    return PVR_ERROR_SERVER_ERROR;
  }
  // {"streamId":"1036499352","position":5040,"changed":"2024-06-21T17:54:52.000+00:00"}
  if (recordingPosDoc.HasMember("position") && recordingPosDoc["position"].IsInt())
    position = recordingPosDoc["position"].GetInt();

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR WaipuData::SetRecordingLastPlayedPosition(const kodi::addon::PVRRecording& recording,
                                                    int lastplayedposition)
{
  if (!IsConnected())
    return PVR_ERROR_FAILED;

  if (lastplayedposition == -1)
    lastplayedposition = 0;

  std::string request_data = "{\"position\":" + std::to_string(lastplayedposition) + "}";
  std::string response = HttpRequest(
      "PUT", "https://stream-position.waipu.tv/api/stream-positions/" + recording.GetRecordingId(),
      request_data.c_str(),
      {{"Content-Type", "application/vnd.waipu.stream-position-request.v1+json"}});
  kodi::Log(ADDON_LOG_DEBUG, "%s - Response: %s", __FUNCTION__, response.c_str());

  return PVR_ERROR_NO_ERROR;
}

ADDONCREATOR(WaipuData)
