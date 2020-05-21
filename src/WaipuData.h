#pragma once
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

#include "Curl.h"
#include "client.h"
#include "p8-platform/os.h"

#include <vector>

/**
 * User Agent for HTTP Requests
 * Let's try to be honest, otherwise we have to fallback to "waipu-2.29.2-c0f220b-9446 (Android 8.1.0)"
 */
static const std::string WAIPU_USER_AGENT = "kodi plugin for waipu (pvr.waipu)";

enum class WAIPU_LOGIN_STATUS
{
  OK,
  INVALID_CREDENTIALS,
  NO_NETWORK,
  UNKNOWN
};

class WaipuData
{
public:
  WaipuData(const std::string& username, const std::string& password, const WAIPU_PROVIDER provider);
  WaipuData(const WaipuData&) = delete;
  WaipuData(WaipuData&&) = delete;
  WaipuData& operator=(const WaipuData&) = delete;
  WaipuData& operator=(WaipuData&&) = delete;

  int GetChannelsAmount(void);
  PVR_ERROR GetChannels(ADDON_HANDLE handle, bool bRadio);

  int GetChannelGroupsAmount(void);
  PVR_ERROR GetChannelGroups(ADDON_HANDLE handle);
  PVR_ERROR GetChannelGroupMembers(ADDON_HANDLE handle, const PVR_CHANNEL_GROUP& group);

  std::string GetChannelStreamUrl(int uniqueId, const std::string& protocol);

  PVR_ERROR GetEPGForChannel(ADDON_HANDLE handle, int iChannelUid, time_t iStart, time_t iEnd);

  int GetRecordingsAmount(bool bDeleted);
  PVR_ERROR GetRecordings(ADDON_HANDLE handle, bool bDeleted);
  std::string GetRecordingURL(const PVR_RECORDING& recording, const std::string& protocol);
  std::string GetEPGTagURL(const EPG_TAG& tag, const std::string& protocol);
  PVR_ERROR DeleteRecording(const PVR_RECORDING& recording);

  int GetTimersAmount(void);
  PVR_ERROR GetTimers(ADDON_HANDLE handle);
  PVR_ERROR DeleteTimer(const PVR_TIMER& timer);
  PVR_ERROR AddTimer(const PVR_TIMER& timer);

  std::string GetLicense(void);
  WAIPU_LOGIN_STATUS GetLoginStatus(void);
  PVR_ERROR IsEPGTagRecordable(const EPG_TAG* tag, bool* bIsRecordable);
  PVR_ERROR IsEPGTagPlayable(const EPG_TAG* tag, bool* bIsPlayable);

private:
  struct WaipuApiToken
  {
    std::string accessToken;
    std::string refreshToken;
    time_t expires;
  };

  struct WaipuChannel
  {
    int iUniqueId;
    std::string waipuID; // waipu[id]
    int iChannelNumber; //position
    std::string strChannelName; //waipu[displayName]
    std::string strIconPath; // waipu[links][rel=iconlargehd]
    std::string strStreamURL; // waipu[links][rel=livePlayout]
    bool tvfuse; // tvfuse is on demand channel
  };

  struct WaipuChannelGroup
  {
    std::string name;
    std::vector<WaipuChannel> channels;
  };

  struct WaipuEPGEntry
  {
    int iUniqueBroadcastId;
    int iUniqueChannelId;
    bool isRecordable;
    std::string streamUrlProvider;
  };

  const std::string m_username;
  const std::string m_password;
  const WAIPU_PROVIDER m_provider;

  std::vector<WaipuChannel> m_channels;
  std::vector<WaipuEPGEntry> m_epgEntries;
  std::vector<WaipuChannelGroup> m_channelGroups;

  WaipuApiToken m_apiToken;
  std::string m_license;
  int m_recordings_count;
  bool m_active_recordings_update;
  std::vector<std::string> m_user_channels_sd;
  std::vector<std::string> m_user_channels_hd;
  WAIPU_LOGIN_STATUS m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;

  bool ParseAccessToken(void);

  std::string HttpGet(const std::string& url);
  std::string HttpDelete(const std::string& url, const std::string& postData);
  std::string HttpPost(const std::string& url, const std::string& postData);
  std::string HttpRequest(const std::string& action, const std::string& url, const std::string& postData);
  std::string HttpRequestToCurl(
      Curl& curl, const std::string& action, const std::string& url, const std::string& postData, int& statusCode);
  bool ApiLogin();
  bool WaipuLogin();
  bool O2Login();
  bool LoadChannelData(void);
};
