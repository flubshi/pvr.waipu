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
#include "kodi/addon-instance/PVR.h"

#include <vector>

/**
 * User Agent for HTTP Requests
 * Let's try to be honest, otherwise we have to fallback to "waipu-2.29.2-c0f220b-9446 (Android 8.1.0)"
 */
static const std::string WAIPU_USER_AGENT = "kodi plugin for waipu (pvr.waipu)";

enum WAIPU_PROVIDER
{
  WAIPU_PROVIDER_WAIPU = 0,
  WAIPU_PROVIDER_O2
};

enum class WAIPU_LOGIN_STATUS
{
  OK,
  INVALID_CREDENTIALS,
  NO_NETWORK,
  UNKNOWN
};

class ATTRIBUTE_HIDDEN WaipuData : public kodi::addon::CAddonBase,
                                   public kodi::addon::CInstancePVRClient
{
public:
  WaipuData() = default;
  WaipuData(const WaipuData&) = delete;
  WaipuData(WaipuData&&) = delete;
  WaipuData& operator=(const WaipuData&) = delete;
  WaipuData& operator=(WaipuData&&) = delete;

  ADDON_STATUS Create() override;
  ADDON_STATUS SetSetting(const std::string& settingName,
                          const kodi::CSettingValue& settingValue) override;

  PVR_ERROR GetCapabilities(kodi::addon::PVRCapabilities& capabilities) override;
  PVR_ERROR GetBackendName(std::string& name) override;
  PVR_ERROR GetBackendVersion(std::string& version) override;
  PVR_ERROR GetConnectionString(std::string& connection) override;

  PVR_ERROR GetChannelsAmount(int& amount) override;
  PVR_ERROR GetChannels(bool radio, kodi::addon::PVRChannelsResultSet& results) override;

  PVR_ERROR GetChannelGroupsAmount(int& amount) override;
  PVR_ERROR GetChannelGroups(bool radio, kodi::addon::PVRChannelGroupsResultSet& results) override;
  PVR_ERROR GetChannelGroupMembers(const kodi::addon::PVRChannelGroup& group,
                                   kodi::addon::PVRChannelGroupMembersResultSet& results) override;
  PVR_ERROR GetChannelStreamProperties(
      const kodi::addon::PVRChannel& channel,
      std::vector<kodi::addon::PVRStreamProperty>& properties) override;

  PVR_ERROR GetEPGForChannel(int channelUid,
                             time_t start,
                             time_t end,
                             kodi::addon::PVREPGTagsResultSet& results) override;
  PVR_ERROR IsEPGTagRecordable(const kodi::addon::PVREPGTag& tag, bool& isRecordable) override;
  PVR_ERROR IsEPGTagPlayable(const kodi::addon::PVREPGTag& tag, bool& isPlayable) override;
  PVR_ERROR GetEPGTagStreamProperties(
      const kodi::addon::PVREPGTag& tag,
      std::vector<kodi::addon::PVRStreamProperty>& properties) override;

  PVR_ERROR GetRecordingsAmount(bool deleted, int& amount) override;
  PVR_ERROR GetRecordings(bool deleted, kodi::addon::PVRRecordingsResultSet& results) override;
  PVR_ERROR DeleteRecording(const kodi::addon::PVRRecording& recording) override;
  PVR_ERROR GetRecordingStreamProperties(
      const kodi::addon::PVRRecording& recording,
      std::vector<kodi::addon::PVRStreamProperty>& properties) override;

  PVR_ERROR GetTimerTypes(std::vector<kodi::addon::PVRTimerType>& types) override;
  PVR_ERROR GetTimersAmount(int& amount) override;
  PVR_ERROR GetTimers(kodi::addon::PVRTimersResultSet& results) override;
  PVR_ERROR DeleteTimer(const kodi::addon::PVRTimer& timer, bool forceDelete) override;
  PVR_ERROR AddTimer(const kodi::addon::PVRTimer& timer) override;
  PVR_ERROR GetDriveSpace(uint64_t& total, uint64_t& used) override;

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
    bool instantRestartAllowed;
    std::string streamUrlProvider;
  };

  std::string m_username;
  std::string m_password;
  std::string m_protocol;
  WAIPU_PROVIDER m_provider;

  std::vector<WaipuChannel> m_channels;
  std::vector<WaipuEPGEntry> m_epgEntries;
  std::vector<WaipuChannelGroup> m_channelGroups;

  WaipuApiToken m_apiToken;
  std::string m_license;
  int m_recordings_count = 0;
  int m_timers_count = 0;
  int m_login_failed_counter = 0;
  bool m_active_recordings_update = false;
  bool m_account_replay_allowed = false;
  int m_account_hours_recording = 0;
  std::vector<std::string> m_user_channels_sd;
  std::vector<std::string> m_user_channels_hd;
  WAIPU_LOGIN_STATUS m_login_status = WAIPU_LOGIN_STATUS::UNKNOWN;

  void ReadSettings(void);
  bool ParseAccessToken(void);

  void AddTimerType(std::vector<kodi::addon::PVRTimerType>& types, int idx, int attributes);

  std::string GetChannelStreamUrl(int uniqueId, const std::string& protocol, const std::string& startTime);
  std::string GetRecordingURL(const kodi::addon::PVRRecording& recording,
                              const std::string& protocol);
  std::string GetEPGTagURL(const kodi::addon::PVREPGTag& tag, const std::string& protocol);
  std::string GetLicense(void);
  void SetStreamProperties(std::vector<kodi::addon::PVRStreamProperty>& properties,
                           const std::string& url,
                           bool realtime, bool playTimeshiftBuffer);

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
